// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Runtime boundary for destructive storage-recovery workflows.
//!
//! The scenario runners own sequencing. This module owns the narrower trust
//! boundary: a run-owned Kubernetes generation, its two exclusive locks, the
//! immediately-current observation required before mutation, and the closed
//! set of operations an adapter may perform.

use std::{process::Stdio, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    process::{Child, ChildStdin, ChildStdout},
};

use crate::{
    fault::{
        storage_recovery::{
            HealMode, StorageRecoveryArtifactIdentity, StorageRecoveryCase, StorageVolumeIdentity,
        },
        storage_recovery_helper::{StorageHelperSessionRequest, StorageHelperSessionResponse},
        storage_recovery_lease::{
            StorageRecoveryCleanupProof, release_owned_lease, require_current_lease,
        },
    },
    framework::{
        command::CommandSpec, config::ClusterTestConfig, kube_client::client_for_context,
        kubectl::Kubectl,
    },
};

pub const STORAGE_RECOVERY_HOST_LOCK_DIRECTORY: &str = "/var/lock/s3chaos";
pub const STORAGE_RECOVERY_HELPER_PROGRAM: &str = "/usr/local/bin/s3chaos-storage-helper";
pub const STORAGE_RECOVERY_CONTEXT_MAX_AGE_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesResourceVersions {
    pub tenant: String,
    pub pod: String,
    pub persistent_volume_claim: String,
    pub persistent_volume: String,
    pub node: String,
    pub helper_pod: String,
}

impl KubernetesResourceVersions {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("Tenant", self.tenant.as_str()),
            ("Pod", self.pod.as_str()),
            ("PVC", self.persistent_volume_claim.as_str()),
            ("PV", self.persistent_volume.as_str()),
            ("node", self.node.as_str()),
            ("helper Pod", self.helper_pod.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage-recovery {field} resourceVersion is empty"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesLeaseProof {
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub holder_identity: String,
    pub scope_sha256: String,
    pub acquired_at_ms: u64,
    pub renew_at_ms: u64,
    pub expires_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostFlockProof {
    pub node: String,
    pub node_uid: String,
    pub path: String,
    pub device_id: String,
    pub inode: u64,
    pub scope_sha256: String,
    pub acquired_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRecoveryExclusiveAccess {
    pub kubernetes_lease: KubernetesLeaseProof,
    pub host_flock: HostFlockProof,
}

impl StorageRecoveryExclusiveAccess {
    fn validate_for(
        &self,
        run_id: &str,
        attempt_id: &str,
        volume: &StorageVolumeIdentity,
        scope_sha256: &str,
        observed_at_ms: u64,
    ) -> Result<()> {
        let expected_holder = format!("{run_id}/{attempt_id}");
        let expected_lease_name = storage_lease_name(scope_sha256)?;
        let expected_lock_path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope_sha256}.lock");
        ensure!(
            self.kubernetes_lease.name == expected_lease_name
                && !self.kubernetes_lease.uid.trim().is_empty()
                && !self.kubernetes_lease.resource_version.trim().is_empty()
                && self.kubernetes_lease.holder_identity == expected_holder
                && self.kubernetes_lease.scope_sha256 == scope_sha256
                && self.kubernetes_lease.acquired_at_ms > 0
                && self.kubernetes_lease.renew_at_ms >= self.kubernetes_lease.acquired_at_ms
                && self.kubernetes_lease.expires_at_ms > observed_at_ms,
            "storage-recovery Kubernetes Lease is not current and run-owned"
        );
        ensure!(
            self.host_flock.node == volume.node
                && self.host_flock.node_uid == volume.node_uid
                && self.host_flock.path == expected_lock_path
                && !self.host_flock.device_id.trim().is_empty()
                && self.host_flock.inode > 0
                && self.host_flock.scope_sha256 == scope_sha256
                && self.host_flock.acquired_at_ms >= self.kubernetes_lease.acquired_at_ms
                && self.host_flock.acquired_at_ms <= observed_at_ms,
            "storage-recovery host flock is not bound to the target node and fixed lock path"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnedStorageContext {
    pub identity: StorageRecoveryArtifactIdentity,
    pub case: StorageRecoveryCase,
    pub attempt_id: String,
    pub cluster_context: String,
    pub tenant_uid: String,
    pub scope_sha256: String,
    pub volume: StorageVolumeIdentity,
    pub resource_versions: KubernetesResourceVersions,
    pub host_generation: HostGenerationIdentity,
    pub exclusive_access: StorageRecoveryExclusiveAccess,
    pub helper_pod_name: String,
    pub helper_pod_uid: String,
    pub observed_at_ms: u64,
}

impl OwnedStorageContext {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.identity.scenario == self.case.scenario(),
            "storage-recovery case is bound to the wrong scenario"
        );
        ensure!(
            !self.identity.run_id.trim().is_empty()
                && !self.identity.case_name.trim().is_empty()
                && !self.identity.bucket.trim().is_empty()
                && !self.attempt_id.trim().is_empty()
                && !self.cluster_context.trim().is_empty()
                && !self.tenant_uid.trim().is_empty()
                && !self.helper_pod_name.trim().is_empty()
                && !self.helper_pod_uid.trim().is_empty()
                && self.observed_at_ms > 0,
            "storage-recovery context has an empty identity or timestamp"
        );
        self.volume.validate()?;
        ensure!(
            self.volume.observed_at_ms <= self.observed_at_ms
                && self.observed_at_ms - self.volume.observed_at_ms
                    <= STORAGE_RECOVERY_CONTEXT_MAX_AGE_MS,
            "storage-recovery context does not contain a fresh volume identity"
        );
        self.resource_versions.validate()?;
        self.host_generation.validate_for(&self.volume)?;
        validate_sha256(&self.scope_sha256)?;
        ensure!(
            self.scope_sha256 == storage_scope_sha256(self),
            "storage-recovery scope digest does not match cluster/Tenant/volume identity"
        );
        self.exclusive_access.validate_for(
            &self.identity.run_id,
            &self.attempt_id,
            &self.volume,
            &self.scope_sha256,
            self.observed_at_ms,
        )
    }

    /// Revalidates every mutable Kubernetes/host identity immediately before a
    /// destructive operation. A replacement result must be captured as a new
    /// context after the operation; generation drift is never accepted here.
    pub fn require_current(&self, current: &CurrentStorageObservation) -> Result<()> {
        self.validate()?;
        current.validate()?;
        ensure!(
            current.observed_at_ms >= self.observed_at_ms
                && current.observed_at_ms - self.observed_at_ms
                    <= STORAGE_RECOVERY_CONTEXT_MAX_AGE_MS,
            "storage-recovery pre-mutation observation is stale"
        );
        ensure!(
            current.volume == self.volume
                && current.resource_versions == self.resource_versions
                && current.cluster_context == self.cluster_context
                && current.tenant_uid == self.tenant_uid
                && current.scope_sha256 == self.scope_sha256
                && current.host_generation == self.host_generation
                && current.helper_pod_name == self.helper_pod_name
                && current.helper_pod_uid == self.helper_pod_uid
                && current.kubernetes_lease_uid == self.exclusive_access.kubernetes_lease.uid
                && current.kubernetes_lease_resource_version
                    == self.exclusive_access.kubernetes_lease.resource_version
                && current.kubernetes_lease_holder
                    == self.exclusive_access.kubernetes_lease.holder_identity
                && current.host_lock_device_id == self.exclusive_access.host_flock.device_id
                && current.host_lock_inode == self.exclusive_access.host_flock.inode,
            "storage-recovery identity or exclusive access drifted before mutation"
        );
        ensure!(
            current.observed_at_ms < self.exclusive_access.kubernetes_lease.expires_at_ms,
            "storage-recovery Kubernetes Lease expired before mutation"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentStorageObservation {
    pub cluster_context: String,
    pub tenant_uid: String,
    pub scope_sha256: String,
    pub volume: StorageVolumeIdentity,
    pub resource_versions: KubernetesResourceVersions,
    pub host_generation: HostGenerationIdentity,
    pub helper_pod_name: String,
    pub helper_pod_uid: String,
    pub kubernetes_lease_uid: String,
    pub kubernetes_lease_resource_version: String,
    pub kubernetes_lease_holder: String,
    pub host_lock_device_id: String,
    pub host_lock_inode: u64,
    pub observed_at_ms: u64,
}

impl CurrentStorageObservation {
    fn validate(&self) -> Result<()> {
        self.volume.validate()?;
        self.resource_versions.validate()?;
        self.host_generation.validate_for(&self.volume)?;
        validate_sha256(&self.scope_sha256)?;
        for (field, value) in [
            ("cluster context", self.cluster_context.as_str()),
            ("Tenant UID", self.tenant_uid.as_str()),
            ("helper Pod name", self.helper_pod_name.as_str()),
            ("helper Pod UID", self.helper_pod_uid.as_str()),
            ("Kubernetes Lease UID", self.kubernetes_lease_uid.as_str()),
            (
                "Kubernetes Lease resourceVersion",
                self.kubernetes_lease_resource_version.as_str(),
            ),
            (
                "Kubernetes Lease holder",
                self.kubernetes_lease_holder.as_str(),
            ),
            ("host lock device", self.host_lock_device_id.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "current {field} is empty");
        }
        ensure!(
            self.host_lock_inode > 0 && self.observed_at_ms >= self.volume.observed_at_ms,
            "current storage observation has an invalid lock inode or timestamp"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostGenerationIdentity {
    pub mount_id: String,
    pub mount_namespace_id: String,
    pub device_major_minor: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_mapper_uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_mapper_table_sha256: Option<String>,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
}

impl HostGenerationIdentity {
    fn validate_for(&self, volume: &StorageVolumeIdentity) -> Result<()> {
        for (field, value) in [
            ("mount id", self.mount_id.as_str()),
            ("mount namespace id", self.mount_namespace_id.as_str()),
            ("device major:minor", self.device_major_minor.as_str()),
            ("filesystem UUID", self.filesystem_uuid.as_str()),
            ("RustFS drive UUID", self.rustfs_drive_uuid.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage-recovery {field} is empty"
            );
        }
        match (
            self.device_mapper_uuid.as_deref(),
            self.device_mapper_table_sha256.as_deref(),
        ) {
            (Some(uuid), Some(table)) => {
                ensure!(
                    !uuid.trim().is_empty(),
                    "storage-recovery device-mapper UUID is empty"
                );
                validate_sha256(table)?;
            }
            (None, None) => {}
            _ => bail!("storage-recovery device-mapper identity is partial"),
        }
        ensure!(
            self.mount_namespace_id == volume.target_mount_namespace_id
                && self.filesystem_uuid == volume.filesystem_uuid
                && self.rustfs_drive_uuid == volume.rustfs_drive_uuid,
            "host generation does not match the proven RustFS volume"
        );
        let Some((major, minor)) = self.device_major_minor.split_once(':') else {
            bail!("storage-recovery device major:minor is malformed")
        };
        ensure!(
            major.parse::<u32>().is_ok() && minor.parse::<u32>().is_ok(),
            "storage-recovery device major:minor is malformed"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum StorageRecoveryHostOperation {
    InspectXlMeta {
        object_directory: String,
        bucket: String,
        object_key: String,
        object_sha256: String,
        version_id: String,
        selected_part_number: u32,
        expected_mount_device_id: String,
        expected_drive_uuid: String,
    },
    MutateShard {
        inspection_operation_id: String,
        part_number: u32,
        byte_offset: u64,
    },
    PrepareFreshVolume {
        replacement_persistent_volume: String,
        replacement_persistent_volume_claim: String,
    },
    DetachDeviceMapper {
        mapping_name: String,
        expected_generation_sha256: String,
        recovery_table: String,
        isolation_table: String,
    },
    ReattachDeviceMapper {
        mapping_name: String,
        expected_generation_sha256: String,
        recovery_table: String,
        isolation_table: String,
    },
    RestoreShard {
        mutation_operation_id: String,
    },
    VerifySupersededShard {
        mutation_operation_id: String,
        post_inspection_operation_id: String,
    },
}

impl StorageRecoveryHostOperation {
    pub fn is_destructive(&self) -> bool {
        !matches!(self, Self::InspectXlMeta { .. })
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::InspectXlMeta {
                object_directory,
                bucket,
                object_key,
                object_sha256,
                version_id,
                selected_part_number,
                expected_mount_device_id,
                expected_drive_uuid,
            } => {
                validate_relative_path("object directory", object_directory)?;
                validate_explicit_version(version_id)?;
                validate_sha256(object_sha256)?;
                ensure!(
                    !bucket.trim().is_empty()
                        && !object_key.trim().is_empty()
                        && *selected_part_number > 0
                        && !expected_mount_device_id.trim().is_empty()
                        && !expected_drive_uuid.trim().is_empty(),
                    "offline XL2 inspection must bind the opened root and format.json drive identity"
                );
                Ok(())
            }
            Self::MutateShard {
                inspection_operation_id,
                part_number,
                byte_offset: _,
            } => {
                uuid::Uuid::parse_str(inspection_operation_id)
                    .context("storage-recovery inspection operation id is not a UUID")?;
                ensure!(
                    *part_number > 0,
                    "storage-recovery selected part number is zero"
                );
                Ok(())
            }
            Self::PrepareFreshVolume {
                replacement_persistent_volume,
                replacement_persistent_volume_claim,
            } => {
                ensure!(
                    !replacement_persistent_volume.trim().is_empty()
                        && !replacement_persistent_volume_claim.trim().is_empty(),
                    "fresh-volume replacement PVC/PV identity is empty"
                );
                Ok(())
            }
            Self::DetachDeviceMapper {
                mapping_name,
                expected_generation_sha256,
                recovery_table,
                isolation_table,
            }
            | Self::ReattachDeviceMapper {
                mapping_name,
                expected_generation_sha256,
                recovery_table,
                isolation_table,
            } => {
                ensure!(
                    !mapping_name.trim().is_empty()
                        && mapping_name
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
                    "device-mapper operation has an unsafe mapping name"
                );
                validate_sha256(expected_generation_sha256)?;
                StaleDeviceMapperPlan::new(
                    mapping_name,
                    expected_generation_sha256,
                    recovery_table,
                    isolation_table,
                )?;
                Ok(())
            }
            Self::RestoreShard {
                mutation_operation_id,
            } => {
                uuid::Uuid::parse_str(mutation_operation_id)
                    .context("storage-recovery restore operation id is not a UUID")?;
                Ok(())
            }
            Self::VerifySupersededShard {
                mutation_operation_id,
                post_inspection_operation_id,
            } => {
                uuid::Uuid::parse_str(mutation_operation_id)
                    .context("storage-recovery mutation operation id is not a UUID")?;
                uuid::Uuid::parse_str(post_inspection_operation_id)
                    .context("storage-recovery post-inspection operation id is not a UUID")?;
                ensure!(
                    mutation_operation_id != post_inspection_operation_id,
                    "superseded-shard verification requires distinct receipts"
                );
                Ok(())
            }
        }
    }
}

/// Closed device-mapper transition used only by stale-disk-return. The
/// isolation table retains the exact linear extent and backing device while
/// forcing both reads and writes to EIO. It is deliberately distinct from the
/// crash/drop-writes and periodic flakey policies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDeviceMapperPlan {
    pub mapping_name: String,
    pub expected_generation_sha256: String,
    pub recovery_table: String,
    pub recovery_table_sha256: String,
    pub isolation_table: String,
    pub isolation_table_sha256: String,
}

impl StaleDeviceMapperPlan {
    pub fn new(
        mapping_name: &str,
        expected_generation_sha256: &str,
        recovery_table: &str,
        isolation_table: &str,
    ) -> Result<Self> {
        ensure!(
            !mapping_name.is_empty()
                && mapping_name
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')),
            "stale device-mapper plan has an unsafe mapping name"
        );
        validate_sha256(expected_generation_sha256)?;
        ensure!(
            !recovery_table.contains('\n') && !isolation_table.contains('\n'),
            "stale device-mapper plan must contain one table line"
        );
        let recovery = recovery_table.split_whitespace().collect::<Vec<_>>();
        let isolation = isolation_table.split_whitespace().collect::<Vec<_>>();
        ensure!(
            recovery.len() == 5
                && recovery[0].parse::<u64>().is_ok()
                && recovery[1].parse::<u64>().is_ok_and(|sectors| sectors > 0)
                && recovery[2] == "linear"
                && recovery[3].starts_with("/dev/")
                && recovery[4].parse::<u64>().is_ok(),
            "stale device-mapper recovery table is not one non-empty linear extent"
        );
        ensure!(
            isolation.len() == 10
                && isolation[0] == recovery[0]
                && isolation[1] == recovery[1]
                && isolation[2] == "flakey"
                && isolation[3] == recovery[3]
                && isolation[4] == recovery[4]
                && isolation[5] == "0"
                && isolation[6] == "86400"
                && isolation[7] == "2"
                && isolation[8] == "error_reads"
                && isolation[9] == "error_writes",
            "stale device-mapper isolation table must preserve the linear extent and force continuous read/write EIO"
        );
        Ok(Self {
            mapping_name: mapping_name.to_string(),
            expected_generation_sha256: expected_generation_sha256.to_string(),
            recovery_table: recovery.join(" "),
            recovery_table_sha256: sha256_bytes(recovery.join(" ").as_bytes()),
            isolation_table: isolation.join(" "),
            isolation_table_sha256: sha256_bytes(isolation.join(" ").as_bytes()),
        })
    }

    pub fn validate(&self) -> Result<()> {
        let rebuilt = Self::new(
            &self.mapping_name,
            &self.expected_generation_sha256,
            &self.recovery_table,
            &self.isolation_table,
        )?;
        ensure!(
            *self == rebuilt,
            "stale device-mapper plan digests are not canonical"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestoreOutcome {
    Restored,
    AlreadyRepaired,
    VerifiedSuperseded,
    Quarantined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRecoveryOperationReceipt {
    pub operation_id: String,
    pub operation: StorageRecoveryHostOperation,
    pub context_sha256: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub journal_persisted_at_ms: u64,
    pub journal_fsync_succeeded: bool,
}

impl StorageRecoveryOperationReceipt {
    pub fn validate_for(
        &self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<()> {
        ensure!(
            uuid::Uuid::parse_str(&self.operation_id).is_ok() && self.operation == *operation,
            "storage-recovery receipt has the wrong operation identity"
        );
        let expected_context_sha256 = context_sha256(context)?;
        validate_sha256(&self.context_sha256)?;
        validate_sha256(&self.response_sha256)?;
        ensure!(
            self.context_sha256 == expected_context_sha256
                && self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "storage-recovery receipt digest does not match its context or raw response"
        );
        ensure!(
            self.started_at_ms >= context.observed_at_ms
                && self.started_at_ms <= self.journal_persisted_at_ms
                && self.journal_persisted_at_ms <= self.completed_at_ms
                && self.journal_fsync_succeeded,
            "storage-recovery receipt is not durably persisted and ordered"
        );
        if matches!(
            operation,
            StorageRecoveryHostOperation::DetachDeviceMapper { .. }
                | StorageRecoveryHostOperation::ReattachDeviceMapper { .. }
        ) {
            serde_json::from_str::<StaleDeviceMapperTransitionResponse>(&self.response_body)
                .context("decode stale device-mapper transition response")?
                .validate_for(context, operation)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleDeviceMapperAction {
    Isolate,
    Reattach,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMapperCommandReceipt {
    pub argv: Vec<String>,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDeviceMapperTransitionResponse {
    pub action: StaleDeviceMapperAction,
    pub mapping_name: String,
    pub generation_sha256: String,
    pub before_table: String,
    pub before_table_sha256: String,
    pub after_table: String,
    pub after_table_sha256: String,
    pub commands: Vec<DeviceMapperCommandReceipt>,
}

impl StaleDeviceMapperTransitionResponse {
    pub fn validate_for(
        &self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<()> {
        let (expected_action, mapping_name, generation_sha256, recovery_table, isolation_table) =
            match operation {
                StorageRecoveryHostOperation::DetachDeviceMapper {
                    mapping_name,
                    expected_generation_sha256,
                    recovery_table,
                    isolation_table,
                } => (
                    StaleDeviceMapperAction::Isolate,
                    mapping_name,
                    expected_generation_sha256,
                    recovery_table,
                    isolation_table,
                ),
                StorageRecoveryHostOperation::ReattachDeviceMapper {
                    mapping_name,
                    expected_generation_sha256,
                    recovery_table,
                    isolation_table,
                } => (
                    StaleDeviceMapperAction::Reattach,
                    mapping_name,
                    expected_generation_sha256,
                    recovery_table,
                    isolation_table,
                ),
                _ => bail!("device-mapper response is bound to a non-DM operation"),
            };
        let plan = StaleDeviceMapperPlan::new(
            mapping_name,
            generation_sha256,
            recovery_table,
            isolation_table,
        )?;
        let expected_generation = host_generation_sha256(&context.host_generation)?;
        ensure!(
            expected_generation == *generation_sha256
                && context
                    .host_generation
                    .device_mapper_table_sha256
                    .as_deref()
                    == Some(plan.recovery_table_sha256.as_str())
                && self.action == expected_action
                && self.mapping_name == *mapping_name
                && self.generation_sha256 == *generation_sha256,
            "stale device-mapper response is not bound to the owned storage generation"
        );
        let (before, after, target) = match expected_action {
            StaleDeviceMapperAction::Isolate => (
                plan.recovery_table.as_str(),
                plan.isolation_table.as_str(),
                plan.isolation_table.as_str(),
            ),
            StaleDeviceMapperAction::Reattach => (
                plan.isolation_table.as_str(),
                plan.recovery_table.as_str(),
                plan.recovery_table.as_str(),
            ),
        };
        ensure!(
            self.before_table == before
                && self.after_table == after
                && self.before_table_sha256 == sha256_bytes(before.as_bytes())
                && self.after_table_sha256 == sha256_bytes(after.as_bytes()),
            "stale device-mapper response does not prove the exact before/after tables"
        );
        let expected_argv = [
            vec!["dmsetup", "table", "--showkeys", mapping_name],
            vec!["dmsetup", "suspend", "--noflush", mapping_name],
            vec!["dmsetup", "reload", mapping_name, "--table", target],
            vec!["dmsetup", "resume", mapping_name],
            vec!["dmsetup", "table", "--showkeys", mapping_name],
        ];
        ensure!(
            self.commands.len() == expected_argv.len(),
            "stale device-mapper transition has an incomplete command transcript"
        );
        let mut previous_completed_at_ms = 0;
        for (receipt, expected) in self.commands.iter().zip(expected_argv) {
            ensure!(
                receipt.argv == expected
                    && receipt.exit_code == 0
                    && receipt.stderr.trim().is_empty()
                    && receipt.started_at_ms > 0
                    && receipt.started_at_ms <= receipt.completed_at_ms
                    && receipt.started_at_ms >= previous_completed_at_ms,
                "stale device-mapper transition command transcript is invalid"
            );
            previous_completed_at_ms = receipt.completed_at_ms;
        }
        ensure!(
            self.commands[0].stdout.trim() == before && self.commands[4].stdout.trim() == after,
            "stale device-mapper table observations do not match the transition"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealObservationReceipt {
    pub mode: HealMode,
    pub context_sha256: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactQuorumReadReceipt {
    pub context_sha256: String,
    pub mapping_artifact_sha256: String,
    pub response_sha256: String,
    pub response_body: String,
    pub fault_active_from_ms: u64,
    pub completed_at_ms: u64,
    pub fault_active_until_ms: u64,
}

#[async_trait]
pub trait StorageRecoveryRuntimePort: Send {
    async fn acquire(&mut self, case: StorageRecoveryCase) -> Result<OwnedStorageContext>;

    async fn observe_current(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<CurrentStorageObservation>;

    async fn execute_host_operation(
        &mut self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<StorageRecoveryOperationReceipt>;

    async fn observe_heal(
        &mut self,
        context: &OwnedStorageContext,
        mode: HealMode,
    ) -> Result<HealObservationReceipt>;

    async fn force_read_exact_quorum(
        &mut self,
        context: &OwnedStorageContext,
        mapping_artifact: &str,
    ) -> Result<ExactQuorumReadReceipt>;

    async fn restore_or_quarantine(
        &mut self,
        context: &OwnedStorageContext,
    ) -> Result<RestoreOutcome>;
}

pub async fn execute_checked_host_operation(
    runtime: &mut dyn StorageRecoveryRuntimePort,
    context: &OwnedStorageContext,
    operation: &StorageRecoveryHostOperation,
) -> Result<StorageRecoveryOperationReceipt> {
    operation.validate()?;
    let current = runtime.observe_current(context).await?;
    context.require_current(&current)?;
    let receipt = runtime.execute_host_operation(context, operation).await?;
    receipt.validate_for(context, operation)?;
    Ok(receipt)
}

pub fn storage_scope_sha256(context: &OwnedStorageContext) -> String {
    let mut hasher = Sha256::new();
    for value in [
        context.cluster_context.as_str(),
        context.volume.namespace.as_str(),
        context.tenant_uid.as_str(),
        context.volume.persistent_volume_uid.as_str(),
        context.volume.node_uid.as_str(),
        context.volume.canonical_device.as_str(),
        context.volume.filesystem_uuid.as_str(),
    ] {
        hasher.update(value.as_bytes());
        hasher.update([0]);
    }
    hex::encode(hasher.finalize())
}

pub(crate) fn same_storage_volume_generation(
    left: &StorageVolumeIdentity,
    right: &StorageVolumeIdentity,
) -> bool {
    let mut left = left.clone();
    left.observed_at_ms = right.observed_at_ms;
    left == *right
}

pub fn storage_lease_name(scope_sha256: &str) -> Result<String> {
    validate_sha256(scope_sha256)?;
    Ok(format!("s3chaos-storage-{}", &scope_sha256[..20]))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MutationOwnershipDigest<'a> {
    schema_version: u8,
    attempt_id: &'a str,
    scope_sha256: &'a str,
    volume: &'a StorageVolumeIdentity,
    host_generation: &'a HostGenerationIdentity,
    lease_namespace: &'a str,
    lease_name: &'a str,
    lease_uid: &'a str,
    lease_holder_identity: &'a str,
    lease_acquired_at_ms: u64,
}

/// Digests the stable ownership and physical-target identity for a host mutation.
///
/// Lease renewal timestamps and resource versions are deliberately excluded: they
/// change while the same owner is preserving its Lease. The Lease UID, holder,
/// acquisition generation, and immutable storage identities remain bound so a
/// receipt or unresolved journal cannot cross an ownership generation.
pub fn context_sha256(context: &OwnedStorageContext) -> Result<String> {
    let lease = &context.exclusive_access.kubernetes_lease;
    let ownership = MutationOwnershipDigest {
        schema_version: 1,
        attempt_id: &context.attempt_id,
        scope_sha256: &context.scope_sha256,
        volume: &context.volume,
        host_generation: &context.host_generation,
        lease_namespace: &context.volume.namespace,
        lease_name: &lease.name,
        lease_uid: &lease.uid,
        lease_holder_identity: &lease.holder_identity,
        lease_acquired_at_ms: lease.acquired_at_ms,
    };
    Ok(sha256_bytes(
        serde_json::to_vec(&ownership)
            .context("encode storage-recovery mutation ownership for digest")?
            .as_slice(),
    ))
}

pub fn host_generation_sha256(generation: &HostGenerationIdentity) -> Result<String> {
    Ok(sha256_bytes(
        serde_json::to_vec(generation)
            .context("encode storage generation for digest")?
            .as_slice(),
    ))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StorageHelperInvocation {
    pub context: OwnedStorageContext,
    pub operation: StorageRecoveryHostOperation,
}

/// Concrete attempt-scoped transport for the privileged storage helper.
/// A persistent `kubectl exec -i` child owns the host flock until typed cleanup
/// succeeds; every operation also re-reads the Kubernetes Lease directly.
pub struct KubectlStorageRecoveryHostAdapter {
    kubectl: Kubectl,
    namespace: String,
    helper_pod: String,
    timeout: Duration,
}

impl KubectlStorageRecoveryHostAdapter {
    pub fn new(
        cluster: &ClusterTestConfig,
        namespace: impl Into<String>,
        helper_pod: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self> {
        let namespace = namespace.into();
        let helper_pod = helper_pod.into();
        ensure!(
            valid_kubernetes_name(&namespace) && valid_kubernetes_name(&helper_pod),
            "storage-recovery helper namespace or Pod name is invalid"
        );
        ensure!(
            !timeout.is_zero(),
            "storage-recovery helper timeout is zero"
        );
        Ok(Self {
            kubectl: Kubectl::new(cluster).namespaced(&namespace),
            namespace,
            helper_pod,
            timeout,
        })
    }

    fn command(&self, context: &OwnedStorageContext) -> Result<CommandSpec> {
        context.validate()?;
        ensure!(
            context.cluster_context == self.kubectl.context()
                && context.volume.namespace == self.namespace
                && context.helper_pod_name == self.helper_pod,
            "storage-recovery helper adapter is bound to another context, namespace, or Pod"
        );
        Ok(self.kubectl.command([
            "exec",
            "-i",
            self.helper_pod.as_str(),
            "--",
            STORAGE_RECOVERY_HELPER_PROGRAM,
        ]))
    }

    pub async fn begin_attempt(
        &self,
        context: &OwnedStorageContext,
    ) -> Result<KubectlStorageRecoveryAttemptGuard> {
        let client = client_for_context(&context.cluster_context)
            .await
            .context("build Kubernetes client for storage helper session")?;
        require_current_lease(client.clone(), context).await?;
        let spec = self.command(context)?;
        let mut command = tokio::process::Command::new(&spec.program);
        command
            .args(&spec.args)
            .kill_on_drop(true)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        if let Some(cwd) = &spec.cwd {
            command.current_dir(cwd);
        }
        let mut child = command
            .spawn()
            .with_context(|| format!("start storage helper session: {}", spec.display()))?;
        let stdin = child
            .stdin
            .take()
            .context("storage helper stdin is absent")?;
        let stdout = child
            .stdout
            .take()
            .context("storage helper stdout is absent")?;
        let mut guard = KubectlStorageRecoveryAttemptGuard {
            client,
            child,
            stdin,
            stdout: BufReader::new(stdout),
            timeout: self.timeout,
            finished: false,
        };
        let response = guard
            .exchange(&StorageHelperSessionRequest::Begin {
                context: Box::new(context.clone()),
            })
            .await?;
        if let StorageHelperSessionResponse::Error { message } = &response {
            bail!("storage helper rejected session startup: {message}");
        }
        ensure!(
            matches!(
                response,
                StorageHelperSessionResponse::Ready { ref scope_sha256 }
                    if scope_sha256 == &context.scope_sha256
            ),
            "storage helper returned the wrong session-ready response"
        );
        Ok(guard)
    }
}

pub struct KubectlStorageRecoveryAttemptGuard {
    client: kube::Client,
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    timeout: Duration,
    finished: bool,
}

impl KubectlStorageRecoveryAttemptGuard {
    pub async fn execute(
        &mut self,
        context: &OwnedStorageContext,
        operation: &StorageRecoveryHostOperation,
    ) -> Result<StorageRecoveryOperationReceipt> {
        operation.validate()?;
        require_current_lease(self.client.clone(), context).await?;
        let response = self
            .exchange(&StorageHelperSessionRequest::Execute {
                invocation: Box::new(StorageHelperInvocation {
                    context: context.clone(),
                    operation: operation.clone(),
                }),
            })
            .await?;
        match response {
            StorageHelperSessionResponse::Receipt { receipt } => {
                receipt.validate_for(context, operation)?;
                Ok(*receipt)
            }
            StorageHelperSessionResponse::Error { message } => {
                bail!("storage helper rejected operation: {message}")
            }
            _ => bail!("storage helper returned an unexpected operation response"),
        }
    }

    pub async fn execute_stale(
        &mut self,
        context: &OwnedStorageContext,
        request: &crate::fault::storage_recovery_helper::StaleOfflineHelperRequest,
    ) -> Result<crate::fault::storage_recovery_helper::StaleOfflineHelperResponse> {
        require_current_lease(self.client.clone(), context).await?;
        let response = self
            .exchange(&StorageHelperSessionRequest::StaleExecute {
                context: Box::new(context.clone()),
                request: Box::new(request.clone()),
            })
            .await?;
        match response {
            StorageHelperSessionResponse::StaleResponse { response } => Ok(*response),
            StorageHelperSessionResponse::Error { message } => {
                bail!("storage helper rejected stale operation: {message}")
            }
            _ => bail!("storage helper returned an unexpected stale response"),
        }
    }

    pub async fn finish(
        mut self,
        context: &OwnedStorageContext,
        cleanup: &StorageRecoveryCleanupProof,
    ) -> Result<()> {
        require_current_lease(self.client.clone(), context).await?;
        cleanup.validate_for(context)?;
        let response = self
            .exchange(&StorageHelperSessionRequest::Finish {
                context: Box::new(context.clone()),
                cleanup: Box::new(cleanup.clone()),
            })
            .await?;
        match response {
            StorageHelperSessionResponse::Finished { scope_sha256 }
                if scope_sha256 == context.scope_sha256 => {}
            StorageHelperSessionResponse::Error { message } => {
                bail!("storage helper rejected cleanup: {message}")
            }
            _ => bail!("storage helper returned an unexpected cleanup response"),
        }
        let status = tokio::time::timeout(self.timeout, self.child.wait())
            .await
            .context("storage helper did not exit after cleanup")??;
        ensure!(
            status.success(),
            "storage helper exited unsuccessfully after cleanup"
        );
        self.finished = true;
        release_owned_lease(self.client.clone(), context, cleanup).await
    }

    async fn exchange(
        &mut self,
        request: &StorageHelperSessionRequest,
    ) -> Result<StorageHelperSessionResponse> {
        let mut line = serde_json::to_vec(request).context("encode storage helper request")?;
        line.push(b'\n');
        tokio::time::timeout(self.timeout, self.stdin.write_all(&line))
            .await
            .context("storage helper request write timed out")??;
        tokio::time::timeout(self.timeout, self.stdin.flush())
            .await
            .context("storage helper request flush timed out")??;
        let mut response = String::new();
        let count = tokio::time::timeout(self.timeout, self.stdout.read_line(&mut response))
            .await
            .context("storage helper response timed out")??;
        ensure!(
            count > 0,
            "storage helper ended before returning a response"
        );
        ensure!(
            response.len() <= 4 * 1024 * 1024,
            "storage helper response is oversized"
        );
        serde_json::from_str(&response).context("decode storage helper session response")
    }
}

impl Drop for KubectlStorageRecoveryAttemptGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.child.start_kill();
        }
    }
}

fn valid_kubernetes_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.')
        })
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
}

fn validate_relative_path(label: &str, path: &str) -> Result<()> {
    ensure!(
        !path.is_empty()
            && !path.starts_with('/')
            && !path.ends_with('/')
            && !path.chars().any(char::is_whitespace)
            && path
                .split('/')
                .all(|component| !component.is_empty() && component != "." && component != ".."),
        "storage-recovery {label} must be a normalized relative path"
    );
    Ok(())
}

fn validate_explicit_version(version_id: &str) -> Result<()> {
    if version_id.trim().is_empty() || version_id == "null" {
        bail!("storage-recovery requires an explicit non-null version id")
    }
    uuid::Uuid::parse_str(version_id)
        .map(|_| ())
        .map_err(|error| anyhow::anyhow!("invalid storage-recovery version id: {error}"))
}

fn validate_sha256(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "storage-recovery digest must be a SHA-256 hex string"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn volume() -> StorageVolumeIdentity {
        StorageVolumeIdentity {
            target_proof_sha256: HASH.to_string(),
            host_storage_proof_sha256: HASH.to_string(),
            rustfs_deployment_id: "deployment-1".to_string(),
            namespace: "rustfs-system".to_string(),
            tenant: "tenant-1".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: "pod-uid-1".to_string(),
            rustfs_container_id: "containerd://container-1".to_string(),
            volume_name: "data".to_string(),
            persistent_volume_claim: "data-rustfs-0".to_string(),
            persistent_volume_claim_uid: "pvc-uid-1".to_string(),
            persistent_volume: "pv-1".to_string(),
            persistent_volume_uid: "pv-uid-1".to_string(),
            node: "node-1".to_string(),
            node_uid: "node-uid-1".to_string(),
            storage_class: "local".to_string(),
            local_volume_path: "/var/lib/rustfs-1".to_string(),
            mount_path: "/data".to_string(),
            canonical_device: "/dev/mapper/rustfs-1".to_string(),
            target_mount_namespace_id: "mnt:[1]".to_string(),
            filesystem_uuid: "fs-1".to_string(),
            rustfs_drive_uuid: "drive-1".to_string(),
            pool_index: 0,
            set_index: 0,
            observed_at_ms: 100,
        }
    }

    fn versions() -> KubernetesResourceVersions {
        KubernetesResourceVersions {
            tenant: "10".to_string(),
            pod: "11".to_string(),
            persistent_volume_claim: "12".to_string(),
            persistent_volume: "13".to_string(),
            node: "14".to_string(),
            helper_pod: "15".to_string(),
        }
    }

    fn context() -> OwnedStorageContext {
        let mut context = OwnedStorageContext {
            identity: StorageRecoveryArtifactIdentity {
                run_id: "run-1".to_string(),
                scenario: "on-disk-bitrot".to_string(),
                case_name: "automatic-scanner".to_string(),
                bucket: "bucket-1".to_string(),
            },
            case: StorageRecoveryCase::OnDiskBitrotAutomaticScanner,
            attempt_id: "attempt-1".to_string(),
            cluster_context: "kind-s3chaos".to_string(),
            tenant_uid: "tenant-uid-1".to_string(),
            scope_sha256: String::new(),
            volume: volume(),
            resource_versions: versions(),
            host_generation: HostGenerationIdentity {
                mount_id: "mount-1".to_string(),
                mount_namespace_id: "mnt:[1]".to_string(),
                device_major_minor: "259:0".to_string(),
                device_mapper_uuid: Some("dm-uuid-1".to_string()),
                device_mapper_table_sha256: Some(HASH.to_string()),
                filesystem_uuid: "fs-1".to_string(),
                rustfs_drive_uuid: "drive-1".to_string(),
            },
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: KubernetesLeaseProof {
                    name: String::new(),
                    uid: "lease-uid-1".to_string(),
                    resource_version: "20".to_string(),
                    holder_identity: "run-1/attempt-1".to_string(),
                    scope_sha256: String::new(),
                    acquired_at_ms: 100,
                    renew_at_ms: 105,
                    expires_at_ms: 1_000,
                },
                host_flock: HostFlockProof {
                    node: "node-1".to_string(),
                    node_uid: "node-uid-1".to_string(),
                    path: String::new(),
                    device_id: "8:1".to_string(),
                    inode: 42,
                    scope_sha256: String::new(),
                    acquired_at_ms: 106,
                },
            },
            helper_pod_name: "s3chaos-storage-helper".to_string(),
            helper_pod_uid: "helper-uid-1".to_string(),
            observed_at_ms: 110,
        };
        let scope = storage_scope_sha256(&context);
        context.scope_sha256 = scope.clone();
        context.exclusive_access.kubernetes_lease.name =
            format!("s3chaos-storage-{}", &scope[..20]);
        context.exclusive_access.kubernetes_lease.scope_sha256 = scope.clone();
        context.exclusive_access.host_flock.path =
            format!("{STORAGE_RECOVERY_HOST_LOCK_DIRECTORY}/storage-{scope}.lock");
        context.exclusive_access.host_flock.scope_sha256 = scope;
        context
    }

    fn renew_same_lease(context: &OwnedStorageContext) -> OwnedStorageContext {
        let mut renewed = context.clone();
        renewed.exclusive_access.kubernetes_lease.resource_version = "21".to_string();
        renewed.exclusive_access.kubernetes_lease.renew_at_ms += 100;
        renewed.exclusive_access.kubernetes_lease.expires_at_ms += 100;
        renewed
    }

    fn current(context: &OwnedStorageContext) -> CurrentStorageObservation {
        CurrentStorageObservation {
            cluster_context: context.cluster_context.clone(),
            tenant_uid: context.tenant_uid.clone(),
            scope_sha256: context.scope_sha256.clone(),
            volume: context.volume.clone(),
            resource_versions: context.resource_versions.clone(),
            host_generation: context.host_generation.clone(),
            helper_pod_name: context.helper_pod_name.clone(),
            helper_pod_uid: context.helper_pod_uid.clone(),
            kubernetes_lease_uid: context.exclusive_access.kubernetes_lease.uid.clone(),
            kubernetes_lease_resource_version: context
                .exclusive_access
                .kubernetes_lease
                .resource_version
                .clone(),
            kubernetes_lease_holder: context
                .exclusive_access
                .kubernetes_lease
                .holder_identity
                .clone(),
            host_lock_device_id: context.exclusive_access.host_flock.device_id.clone(),
            host_lock_inode: context.exclusive_access.host_flock.inode,
            observed_at_ms: 111,
        }
    }

    #[test]
    fn owned_context_rejects_generation_and_lock_drift() {
        let context = context();
        context
            .require_current(&current(&context))
            .expect("matching current identity");

        let mut drifted_generation = current(&context);
        drifted_generation.volume.persistent_volume_uid = "other-pv-uid".to_string();
        assert!(context.require_current(&drifted_generation).is_err());

        let mut restarted_helper = current(&context);
        restarted_helper.helper_pod_uid = "other-helper".to_string();
        assert!(context.require_current(&restarted_helper).is_err());

        let mut replaced_lock = current(&context);
        replaced_lock.host_lock_inode += 1;
        assert!(context.require_current(&replaced_lock).is_err());

        let mut remounted = current(&context);
        remounted.host_generation.mount_id = "mount-2".to_string();
        assert!(context.require_current(&remounted).is_err());

        let mut changed_table = current(&context);
        changed_table.host_generation.device_mapper_table_sha256 =
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string());
        assert!(context.require_current(&changed_table).is_err());
    }

    #[test]
    fn owned_context_rejects_expired_or_cross_run_lease() {
        let mut cross_run = context();
        cross_run.exclusive_access.kubernetes_lease.holder_identity =
            "other-run/attempt-1".to_string();
        assert!(cross_run.validate().is_err());

        let mut expired = context();
        expired.exclusive_access.kubernetes_lease.expires_at_ms = expired.observed_at_ms;
        assert!(expired.validate().is_err());

        let mut other_tenant = context();
        other_tenant.tenant_uid = "tenant-uid-2".to_string();
        assert!(other_tenant.validate().is_err());
    }

    #[test]
    fn host_operations_are_closed_and_reject_unsafe_paths() {
        StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket/object".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "object".to_string(),
            object_sha256: HASH.to_string(),
            version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            selected_part_number: 1,
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        }
        .validate()
        .expect("read-only inspection");

        for operation in [
            StorageRecoveryHostOperation::MutateShard {
                inspection_operation_id: "not-a-uuid".to_string(),
                part_number: 1,
                byte_offset: 0,
            },
            StorageRecoveryHostOperation::MutateShard {
                inspection_operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                part_number: 0,
                byte_offset: 0,
            },
        ] {
            assert!(operation.validate().is_err());
        }

        let path_injection = serde_json::json!({
            "kind": "mutate-shard",
            "inspection_operation_id": "01234567-89ab-cdef-0123-456789abcdef",
            "part_number": 1,
            "byte_offset": 0,
            "relative_part_path": "bucket/object/data-dir/part.2"
        });
        assert!(
            serde_json::from_value::<StorageRecoveryHostOperation>(path_injection).is_err(),
            "the controller must not be able to select a shard path"
        );
    }

    #[test]
    fn helper_protocol_rejects_unknown_fields() {
        let operation = serde_json::json!({
            "kind": "restore-shard",
            "mutation_operation_id": "01234567-89ab-cdef-0123-456789abcdef",
            "argv": ["sh", "-c", "true"]
        });
        assert!(serde_json::from_value::<StorageRecoveryHostOperation>(operation).is_err());

        let mut invocation = serde_json::to_value(StorageHelperInvocation {
            context: context(),
            operation: StorageRecoveryHostOperation::RestoreShard {
                mutation_operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            },
        })
        .expect("invocation");
        invocation
            .as_object_mut()
            .expect("invocation object")
            .insert("command".to_string(), serde_json::json!("sh"));
        assert!(serde_json::from_value::<StorageHelperInvocation>(invocation).is_err());
    }

    #[test]
    fn offline_mapping_is_derived_from_exact_inspection_receipt() {
        use crate::fault::{
            quorum::{ErasureSetMember, ErasureSetMembership, ErasureSetShape},
            storage_recovery::{
                OfflineVersionShardMappingEvidence, ShardMappingSource,
                VersionShardMappingObservation,
            },
            storage_recovery_helper::{OfflineInspectedShard, OfflineXl2InspectResponse},
            xl2_inspector::{
                OFFLINE_XL2_INSPECTOR_REVISION, Xl2FormatProfile, Xl2ObjectVersionLayout,
            },
        };

        let context = context();
        let operation = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket-1/object".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "object".to_string(),
            object_sha256: HASH.to_string(),
            version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            selected_part_number: 1,
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        };
        let response_body = serde_json::to_string(&OfflineXl2InspectResponse {
            mount_device_id: "259:0".to_string(),
            drive_uuid: "drive-1".to_string(),
            format_json_sha256: HASH.to_string(),
            xl_meta_sha256: HASH.to_string(),
            layout: Xl2ObjectVersionLayout {
                inspector_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
                profile: Xl2FormatProfile::LATEST_RUSTFS,
                version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                data_directory: "fedcba98-7654-3210-fedc-ba9876543210".to_string(),
                erasure_data_shards: 1,
                erasure_parity_shards: 1,
                erasure_index: 1,
                part_numbers: vec![1],
                part_sizes: vec![1024],
                relative_part_paths: vec![
                    "bucket-1/object/fedcba98-7654-3210-fedc-ba9876543210/part.1".to_string(),
                ],
            },
            selected_part: OfflineInspectedShard {
                part_number: 1,
                relative_part_path: "bucket-1/object/fedcba98-7654-3210-fedc-ba9876543210/part.1"
                    .to_string(),
                shard_device_id: "259:0".to_string(),
                shard_inode: 42,
                shard_size_bytes: 1024,
                original_sha256: HASH.to_string(),
            },
        })
        .expect("inspection response");
        let receipt = StorageRecoveryOperationReceipt {
            operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            operation,
            context_sha256: context_sha256(&context).expect("context digest"),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body: response_body.clone(),
            started_at_ms: 120,
            journal_persisted_at_ms: 121,
            completed_at_ms: 122,
            journal_fsync_succeeded: true,
        };
        let observation = VersionShardMappingObservation {
            schema_version: crate::fault::storage_recovery::STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: context.identity.clone(),
            observation_id: "mapping-1".to_string(),
            source: ShardMappingSource::OfflineXl2Inspector,
            api_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
            response_sha256: receipt.response_sha256.clone(),
            response_body,
            offline_evidence: Some(Box::new(OfflineVersionShardMappingEvidence {
                context: Box::new(context),
                inspection_receipt: Box::new(receipt),
            })),
            target_proof_sha256: HASH.to_string(),
            observed_at_ms: 122,
        };
        let shape = ErasureSetShape {
            pool_index: 0,
            set_index: 0,
            server_count: 2,
            volumes_per_server: 1,
            total_shards: 2,
            payload_data_shards: 1,
            payload_parity_shards: 1,
        };
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            vec![
                ErasureSetMember {
                    pod_name: "rustfs-0".to_string(),
                    server_endpoint: "http://rustfs-0:9000".to_string(),
                    shard_ids: vec!["drive-1".to_string()],
                },
                ErasureSetMember {
                    pod_name: "rustfs-1".to_string(),
                    server_endpoint: "http://rustfs-1:9000".to_string(),
                    shard_ids: vec!["drive-2".to_string()],
                },
            ],
        )
        .expect("membership");

        let mapping = observation
            .validated_mapping(&membership, &shape)
            .expect("receipt-bound offline mapping");
        assert_eq!(mapping.object_key, "object");
        assert_eq!(mapping.shard_ids, ["drive-1", "drive-2"]);
    }

    struct FakeRuntime {
        current: CurrentStorageObservation,
        observations: usize,
    }

    #[async_trait]
    impl StorageRecoveryRuntimePort for FakeRuntime {
        async fn acquire(&mut self, _case: StorageRecoveryCase) -> Result<OwnedStorageContext> {
            unreachable!()
        }

        async fn observe_current(
            &mut self,
            _context: &OwnedStorageContext,
        ) -> Result<CurrentStorageObservation> {
            self.observations += 1;
            Ok(self.current.clone())
        }

        async fn execute_host_operation(
            &mut self,
            context: &OwnedStorageContext,
            operation: &StorageRecoveryHostOperation,
        ) -> Result<StorageRecoveryOperationReceipt> {
            let response_body = "{}".to_string();
            Ok(StorageRecoveryOperationReceipt {
                operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
                operation: operation.clone(),
                context_sha256: context_sha256(context)?,
                response_sha256: sha256_bytes(response_body.as_bytes()),
                response_body,
                started_at_ms: 120,
                completed_at_ms: 121,
                journal_persisted_at_ms: 120,
                journal_fsync_succeeded: true,
            })
        }

        async fn observe_heal(
            &mut self,
            _context: &OwnedStorageContext,
            _mode: HealMode,
        ) -> Result<HealObservationReceipt> {
            unreachable!()
        }

        async fn force_read_exact_quorum(
            &mut self,
            _context: &OwnedStorageContext,
            _mapping_artifact: &str,
        ) -> Result<ExactQuorumReadReceipt> {
            unreachable!()
        }

        async fn restore_or_quarantine(
            &mut self,
            _context: &OwnedStorageContext,
        ) -> Result<RestoreOutcome> {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn destructive_operation_requires_immediate_revalidation() {
        let context = context();
        let mut runtime = FakeRuntime {
            current: current(&context),
            observations: 0,
        };
        let destructive = StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            part_number: 1,
            byte_offset: 0,
        };
        execute_checked_host_operation(&mut runtime, &context, &destructive)
            .await
            .expect("checked operation");
        assert_eq!(runtime.observations, 1);

        let inspection = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: "bucket/object".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "object".to_string(),
            object_sha256: HASH.to_string(),
            version_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            selected_part_number: 1,
            expected_mount_device_id: "259:0".to_string(),
            expected_drive_uuid: "drive-1".to_string(),
        };
        execute_checked_host_operation(&mut runtime, &context, &inspection)
            .await
            .expect("read-only inspection");
        assert_eq!(runtime.observations, 2);
    }

    #[test]
    fn receipt_must_be_durable_and_bound_to_mutation_owner() {
        let context = context();
        let operation = StorageRecoveryHostOperation::MutateShard {
            inspection_operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            part_number: 1,
            byte_offset: 0,
        };
        let response_body = "{}".to_string();
        let mut receipt = StorageRecoveryOperationReceipt {
            operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            operation: operation.clone(),
            context_sha256: context_sha256(&context).expect("context digest"),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
            started_at_ms: 120,
            completed_at_ms: 122,
            journal_persisted_at_ms: 121,
            journal_fsync_succeeded: true,
        };
        receipt
            .validate_for(&context, &operation)
            .expect("durable owner-bound receipt");

        receipt
            .validate_for(&renew_same_lease(&context), &operation)
            .expect("same Lease renewal must preserve receipt ownership");

        receipt.journal_fsync_succeeded = false;
        assert!(receipt.validate_for(&context, &operation).is_err());
        receipt.journal_fsync_succeeded = true;
        receipt.context_sha256 = HASH.to_string();
        assert!(receipt.validate_for(&context, &operation).is_err());
    }

    #[test]
    fn fresh_volume_receipt_survives_renewal_but_not_a_new_lease_generation() {
        let context = context();
        let operation = StorageRecoveryHostOperation::PrepareFreshVolume {
            replacement_persistent_volume: "replacement-pv".to_string(),
            replacement_persistent_volume_claim: "replacement-pvc".to_string(),
        };
        let response_body = "{}".to_string();
        let receipt = StorageRecoveryOperationReceipt {
            operation_id: "01234567-89ab-cdef-0123-456789abcdef".to_string(),
            operation: operation.clone(),
            context_sha256: context_sha256(&context).expect("ownership digest"),
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
            started_at_ms: 120,
            completed_at_ms: 122,
            journal_persisted_at_ms: 121,
            journal_fsync_succeeded: true,
        };

        receipt
            .validate_for(&renew_same_lease(&context), &operation)
            .expect("fresh-volume receipt remains valid after Lease renewal");

        let mut next_generation = renew_same_lease(&context);
        next_generation
            .exclusive_access
            .kubernetes_lease
            .acquired_at_ms += 1;
        assert!(receipt.validate_for(&next_generation, &operation).is_err());

        let mut foreign_holder = renew_same_lease(&context);
        foreign_holder
            .exclusive_access
            .kubernetes_lease
            .holder_identity = "run-2/attempt-2".to_string();
        assert!(receipt.validate_for(&foreign_holder, &operation).is_err());

        let mut foreign_uid = renew_same_lease(&context);
        foreign_uid.exclusive_access.kubernetes_lease.uid = "lease-uid-2".to_string();
        assert!(receipt.validate_for(&foreign_uid, &operation).is_err());
    }

    #[test]
    fn kubectl_helper_adapter_exposes_no_shell_or_arbitrary_argv() {
        let context = context();
        let cluster = crate::framework::config::E2eConfig::defaults().cluster;
        let adapter = KubectlStorageRecoveryHostAdapter::new(
            &cluster,
            "rustfs-system",
            "s3chaos-storage-helper",
            Duration::from_secs(5),
        )
        .expect("adapter");
        let command = adapter.command(&context).expect("typed session command");

        assert_eq!(
            command.args[4..],
            [
                "exec",
                "-i",
                "s3chaos-storage-helper",
                "--",
                STORAGE_RECOVERY_HELPER_PROGRAM,
            ]
        );
        assert!(
            !command
                .args
                .iter()
                .any(|arg| matches!(arg.as_str(), "sh" | "bash" | "-c"))
        );
        assert!(command.stdin.is_none());
    }

    #[test]
    fn stale_dm_plan_preserves_linear_generation_and_forces_eio() {
        let plan = StaleDeviceMapperPlan::new(
            "rustfs-data",
            HASH,
            "0 2097152 linear /dev/nvme0n1 4096",
            "0 2097152 flakey /dev/nvme0n1 4096 0 86400 2 error_reads error_writes",
        )
        .expect("stale DM plan");

        plan.validate().expect("canonical plan");
        assert_ne!(plan.recovery_table_sha256, plan.isolation_table_sha256);
    }

    #[test]
    fn stale_dm_plan_rejects_crash_and_periodic_flakey_policies() {
        for table in [
            "0 2097152 flakey /dev/nvme0n1 4096 0 86400 1 drop_writes",
            "0 2097152 flakey /dev/nvme0n1 4096 10 1 2 error_reads error_writes",
            "0 2097152 error",
            "0 2097152 flakey /dev/other 4096 0 86400 2 error_reads error_writes",
        ] {
            assert!(
                StaleDeviceMapperPlan::new(
                    "rustfs-data",
                    HASH,
                    "0 2097152 linear /dev/nvme0n1 4096",
                    table,
                )
                .is_err(),
                "unexpectedly accepted {table}"
            );
        }
    }

    #[test]
    fn stale_dm_transition_response_requires_exact_linear_to_eio_transcript() {
        let recovery = "0 2097152 linear /dev/nvme0n1 4096";
        let isolation = "0 2097152 flakey /dev/nvme0n1 4096 0 86400 2 error_reads error_writes";
        let mut context = context();
        context.case = StorageRecoveryCase::StaleDiskReturn;
        context.identity.scenario = context.case.scenario().to_string();
        context.host_generation.device_mapper_table_sha256 =
            Some(sha256_bytes(recovery.as_bytes()));
        let generation = host_generation_sha256(&context.host_generation).expect("generation");
        let operation = StorageRecoveryHostOperation::DetachDeviceMapper {
            mapping_name: "rustfs-data".to_string(),
            expected_generation_sha256: generation.clone(),
            recovery_table: recovery.to_string(),
            isolation_table: isolation.to_string(),
        };
        let command = |argv: &[&str], stdout: &str, timestamp: u64| DeviceMapperCommandReceipt {
            argv: argv.iter().map(|value| (*value).to_string()).collect(),
            exit_code: 0,
            stdout: stdout.to_string(),
            stderr: String::new(),
            started_at_ms: timestamp,
            completed_at_ms: timestamp,
        };
        let response = StaleDeviceMapperTransitionResponse {
            action: StaleDeviceMapperAction::Isolate,
            mapping_name: "rustfs-data".to_string(),
            generation_sha256: generation,
            before_table: recovery.to_string(),
            before_table_sha256: sha256_bytes(recovery.as_bytes()),
            after_table: isolation.to_string(),
            after_table_sha256: sha256_bytes(isolation.as_bytes()),
            commands: vec![
                command(
                    &["dmsetup", "table", "--showkeys", "rustfs-data"],
                    recovery,
                    300,
                ),
                command(&["dmsetup", "suspend", "--noflush", "rustfs-data"], "", 301),
                command(
                    &["dmsetup", "reload", "rustfs-data", "--table", isolation],
                    "",
                    302,
                ),
                command(&["dmsetup", "resume", "rustfs-data"], "", 303),
                command(
                    &["dmsetup", "table", "--showkeys", "rustfs-data"],
                    isolation,
                    304,
                ),
            ],
        };

        response
            .validate_for(&context, &operation)
            .expect("exact stale DM transition");
        let mut fabricated = response;
        fabricated.commands[4].stdout = recovery.to_string();
        assert!(fabricated.validate_for(&context, &operation).is_err());
    }
}
