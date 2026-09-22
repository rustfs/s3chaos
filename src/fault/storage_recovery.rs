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

//! Evidence contracts for RustFS storage-recovery scenarios.
//!
//! Mapping evidence may come from a RustFS diagnostic API or the bounded,
//! read-only XL2 inspector. Offline evidence remains receipt-bound and derives
//! membership from authenticated runtime topology rather than impersonating a
//! diagnostic API response.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fault::{
    backends::chaos_mesh::{
        IoChaosAction, IoChaosRuntimeContract, VolumeTargetEvidenceContract,
        validate_fixed_volume_snapshot,
    },
    checker::{
        CheckerDataVersionAudit, CheckerDeleteMarkerAudit, CheckerReport,
        checker_expected_current_get_keys, checker_expected_live_keys,
        checker_expected_version_listing, checker_history_records_sha256, checker_operation_audits,
    },
    history::{
        DurabilityCohort, FaultWindowRelation, OperationKind, OperationOutcome, OperationRecord,
        validate_history_phase_boundary, validate_history_scope_and_order,
        validate_successful_version_identity_uniqueness,
    },
    host_storage::{HostStorageMutationProof, dm_tables_match},
    preflight::{PreflightStatus, TARGET_PROOF_SCHEMA_VERSION, TargetProof, TargetProofStatus},
    quorum::{ErasureSetMembership, ErasureSetShape, PersistedVersionClass, QuorumRequirements},
    storage_recovery_helper::{OfflineXl2InspectResponse, StaleOwnedOrphanReceipt},
    storage_recovery_runtime::{
        OwnedStorageContext, StorageRecoveryHostOperation, StorageRecoveryOperationReceipt,
    },
    xl2_inspector::OFFLINE_XL2_INSPECTOR_REVISION,
};

pub const STORAGE_RECOVERY_PROOF_SCHEMA_VERSION: u8 = 1;
pub const DISK_GENERATION_PROOF_ARTIFACT: &str = "disk-generation-proof.json";
pub const SHARD_MUTATION_PROOF_ARTIFACT: &str = "shard-mutation-proof.json";
pub const HEAL_SUMMARY_ARTIFACT: &str = "heal-summary.json";
pub const HEAL_PROGRESS_ARTIFACT: &str = "heal-progress.jsonl";
pub const FORCE_READ_PROOF_ARTIFACT: &str = "force-read-proof.json";
pub const VERSION_SHARD_MAPPING_ARTIFACT: &str = "version-shard-mapping.json";
pub const DANGLING_CLEANUP_PROOF_ARTIFACT: &str = "dangling-cleanup-proof.json";
pub const SHARD_INVENTORY_BEFORE_ARTIFACT: &str = "shard-inventory-before.json";
pub const SHARD_INVENTORY_AFTER_ARTIFACT: &str = "shard-inventory-after.json";
const STORAGE_OBSERVATION_MAX_AGE_MS: u64 = 5_000;
const HOST_DISK_WATCH_MAX_POLL_INTERVAL_MS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageRecoveryArtifactIdentity {
    pub run_id: String,
    pub scenario: String,
    pub case_name: String,
    pub bucket: String,
}

impl StorageRecoveryArtifactIdentity {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("run id", self.run_id.as_str()),
            ("scenario", self.scenario.as_str()),
            ("case name", self.case_name.as_str()),
            ("bucket", self.bucket.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage recovery artifact {field} is empty"
            );
        }
        Ok(())
    }
}

/// Closed set of storage-recovery cases. These are variants of three catalog
/// families, not generic workflow steps or backend parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StorageRecoveryCase {
    FreshVolumeReplacementAutomaticReplacement,
    FreshVolumeReplacementAdminDeep,
    OnDiskBitrotAutomaticScanner,
    OnDiskBitrotAdminDeep,
    StaleDiskReturn,
}

impl StorageRecoveryCase {
    pub const ALL: [Self; 5] = [
        Self::FreshVolumeReplacementAutomaticReplacement,
        Self::FreshVolumeReplacementAdminDeep,
        Self::OnDiskBitrotAutomaticScanner,
        Self::OnDiskBitrotAdminDeep,
        Self::StaleDiskReturn,
    ];

    pub fn scenario(self) -> &'static str {
        match self {
            Self::FreshVolumeReplacementAutomaticReplacement
            | Self::FreshVolumeReplacementAdminDeep => "fresh-volume-replacement",
            Self::OnDiskBitrotAutomaticScanner | Self::OnDiskBitrotAdminDeep => "on-disk-bitrot",
            Self::StaleDiskReturn => "stale-disk-return-detect",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreshVolumeReplacementAutomaticReplacement => {
                "fresh-volume-replacement-automatic-replacement"
            }
            Self::FreshVolumeReplacementAdminDeep => "fresh-volume-replacement-admin-deep",
            Self::OnDiskBitrotAutomaticScanner => "on-disk-bitrot-automatic-scanner",
            Self::OnDiskBitrotAdminDeep => "on-disk-bitrot-admin-deep",
            Self::StaleDiskReturn => "stale-disk-return",
        }
    }

    pub fn parse_explicit(value: &str) -> Result<Self> {
        Self::parse(value)
    }

    pub fn heal_mode(self) -> Option<HealMode> {
        match self {
            Self::FreshVolumeReplacementAutomaticReplacement => {
                Some(HealMode::AutomaticReplacement)
            }
            Self::OnDiskBitrotAutomaticScanner => Some(HealMode::AutomaticScanner),
            Self::FreshVolumeReplacementAdminDeep | Self::OnDiskBitrotAdminDeep => {
                Some(HealMode::AdminDeep)
            }
            Self::StaleDiskReturn => None,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|case| case.as_str() == value)
            .with_context(|| format!("unknown storage-recovery case {value:?}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageVolumeIdentity {
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
    pub rustfs_deployment_id: String,
    pub namespace: String,
    pub tenant: String,
    pub pod: String,
    pub pod_uid: String,
    pub rustfs_container_id: String,
    pub volume_name: String,
    pub persistent_volume_claim: String,
    pub persistent_volume_claim_uid: String,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub node: String,
    pub node_uid: String,
    pub storage_class: String,
    pub local_volume_path: String,
    pub mount_path: String,
    pub canonical_device: String,
    pub target_mount_namespace_id: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
    pub pool_index: u32,
    pub set_index: u32,
    pub observed_at_ms: u64,
}

impl StorageVolumeIdentity {
    pub fn validate(&self) -> Result<()> {
        validate_sha256("target proof", &self.target_proof_sha256)?;
        validate_sha256("host-storage proof", &self.host_storage_proof_sha256)?;
        for (field, value) in [
            ("RustFS deployment id", self.rustfs_deployment_id.as_str()),
            ("namespace", self.namespace.as_str()),
            ("tenant", self.tenant.as_str()),
            ("Pod", self.pod.as_str()),
            ("Pod UID", self.pod_uid.as_str()),
            ("RustFS container id", self.rustfs_container_id.as_str()),
            ("volume name", self.volume_name.as_str()),
            ("PVC", self.persistent_volume_claim.as_str()),
            ("PVC UID", self.persistent_volume_claim_uid.as_str()),
            ("PV", self.persistent_volume.as_str()),
            ("PV UID", self.persistent_volume_uid.as_str()),
            ("node", self.node.as_str()),
            ("node UID", self.node_uid.as_str()),
            ("storage class", self.storage_class.as_str()),
            ("local volume path", self.local_volume_path.as_str()),
            ("canonical device", self.canonical_device.as_str()),
            (
                "target mount namespace id",
                self.target_mount_namespace_id.as_str(),
            ),
            ("filesystem UUID", self.filesystem_uuid.as_str()),
            ("RustFS drive UUID", self.rustfs_drive_uuid.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "storage identity {field} is empty"
            );
        }
        ensure!(
            is_normalized_absolute_path(&self.mount_path)
                && !self.mount_path.chars().any(char::is_whitespace)
                && self.mount_path != "/",
            "storage identity mount path must be an absolute normalized non-root path without whitespace"
        );
        ensure!(
            self.canonical_device.starts_with('/')
                && !self.canonical_device.chars().any(char::is_whitespace),
            "storage identity canonical device must be absolute and contain no whitespace"
        );
        ensure!(
            self.local_volume_path.starts_with('/'),
            "storage identity local volume path must be absolute"
        );
        ensure!(
            self.observed_at_ms > 0,
            "storage identity observation timestamp must be positive"
        );
        Ok(())
    }

    fn same_logical_slot(&self, other: &Self) -> bool {
        self.rustfs_deployment_id == other.rustfs_deployment_id
            && self.namespace == other.namespace
            && self.tenant == other.tenant
            && self.volume_name == other.volume_name
            && self.persistent_volume_claim == other.persistent_volume_claim
            && self.node == other.node
            && self.node_uid == other.node_uid
            && self.storage_class == other.storage_class
            && self.mount_path == other.mount_path
            && self.pool_index == other.pool_index
            && self.set_index == other.set_index
    }

    fn same_storage_generation(&self, other: &Self) -> bool {
        self.persistent_volume_uid == other.persistent_volume_uid
            && self.canonical_device == other.canonical_device
            && self.filesystem_uuid == other.filesystem_uuid
            && self.rustfs_drive_uuid == other.rustfs_drive_uuid
    }

    pub(crate) fn validate_replacement_generation(&self, replacement: &Self) -> Result<()> {
        ensure!(
            self.same_logical_slot(replacement),
            "replacement does not occupy the original RustFS logical volume slot"
        );
        ensure!(
            replacement.observed_at_ms > self.observed_at_ms,
            "replacement identity must be observed after the original identity"
        );
        ensure!(
            self.persistent_volume_claim_uid != replacement.persistent_volume_claim_uid,
            "fresh replacement reused the original PVC generation"
        );
        // Format healing preserves the logical slot's RustFS UUID. Physical
        // replacement must instead be proven by the storage generations.
        ensure!(
            self.persistent_volume_uid != replacement.persistent_volume_uid
                && self.canonical_device != replacement.canonical_device
                && self.filesystem_uuid != replacement.filesystem_uuid,
            "fresh replacement must have new PV, device, and filesystem generations"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostExecutionIdentity {
    pub namespace: String,
    pub node: String,
    pub node_uid: String,
    pub target_pod: String,
    pub target_pod_uid: String,
    pub target_container_id: String,
    pub helper_pod: String,
    pub helper_pod_uid: String,
    pub mount_namespace_id: String,
    pub helper_pod_sha256: String,
    pub helper_pod_body: String,
    pub target_runtime_sha256: String,
    pub target_runtime_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostTargetRuntimeResponse {
    pub target_container_id: String,
    pub cri_container_id: String,
    pub container_pid: u32,
    pub inspect_argv: Vec<String>,
    pub inspect_exit_code: i32,
    pub inspect_stdout_sha256: String,
    pub inspect_stdout_body: String,
    pub inspect_stderr: String,
    pub mount_namespace_argv: Vec<String>,
    pub mount_namespace_exit_code: i32,
    pub mount_namespace_stdout: String,
    pub mount_namespace_stderr: String,
}

impl HostExecutionIdentity {
    fn validate_for(&self, volume: &StorageVolumeIdentity) -> Result<u32> {
        ensure!(
            self.namespace == volume.namespace
                && self.node == volume.node
                && self.node_uid == volume.node_uid
                && self.target_pod == volume.pod
                && self.target_pod_uid == volume.pod_uid
                && self.target_container_id == volume.rustfs_container_id
                && self.mount_namespace_id == volume.target_mount_namespace_id
                && !self.helper_pod.trim().is_empty()
                && !self.helper_pod_uid.trim().is_empty(),
            "host helper execution identity is not bound to the target Pod, node, and mount namespace"
        );
        for (label, digest, body) in [
            (
                "host helper Pod",
                &self.helper_pod_sha256,
                &self.helper_pod_body,
            ),
            (
                "host target runtime",
                &self.target_runtime_sha256,
                &self.target_runtime_body,
            ),
        ] {
            validate_sha256(label, digest)?;
            ensure!(
                digest == &sha256_bytes(body.as_bytes()),
                "{label} digest does not match its captured response body"
            );
        }
        let helper = serde_json::from_str::<serde_json::Value>(&self.helper_pod_body)
            .context("decode captured host helper Pod")?;
        let runtime = serde_json::from_str::<HostTargetRuntimeResponse>(&self.target_runtime_body)
            .context("decode captured target runtime identity")?;
        let (container_runtime, cri_container_id) =
            split_kubernetes_container_id(&self.target_container_id)?;
        let inspect = serde_json::from_str::<serde_json::Value>(&runtime.inspect_stdout_body)
            .context("decode captured target container inspect response")?;
        fn string_at<'a>(value: &'a serde_json::Value, pointer: &str) -> Option<&'a str> {
            value.pointer(pointer).and_then(serde_json::Value::as_str)
        }
        validate_sha256(
            "target container inspect response",
            &runtime.inspect_stdout_sha256,
        )?;
        ensure!(
            runtime.inspect_stdout_sha256 == sha256_bytes(runtime.inspect_stdout_body.as_bytes())
                && string_at(&helper, "/apiVersion") == Some("v1")
                && string_at(&helper, "/kind") == Some("Pod")
                && string_at(&helper, "/metadata/namespace") == Some(self.namespace.as_str())
                && string_at(&helper, "/metadata/name") == Some(self.helper_pod.as_str())
                && string_at(&helper, "/metadata/uid") == Some(self.helper_pod_uid.as_str())
                && string_at(&helper, "/metadata/resourceVersion")
                    .is_some_and(|value| !value.trim().is_empty())
                && string_at(&helper, "/spec/nodeName") == Some(self.node.as_str())
                && string_at(&helper, "/status/phase") == Some("Running")
                && runtime.target_container_id == self.target_container_id
                && container_runtime == "containerd"
                && runtime.cri_container_id == cri_container_id
                && runtime.container_pid > 0
                && runtime.inspect_argv == ["crictl", "inspect", cri_container_id]
                && runtime.inspect_exit_code == 0
                && runtime.inspect_stderr.trim().is_empty()
                && string_at(&inspect, "/status/id") == Some(cri_container_id)
                && inspect
                    .pointer("/info/pid")
                    .and_then(serde_json::Value::as_u64)
                    == Some(u64::from(runtime.container_pid))
                && runtime.mount_namespace_argv
                    == [
                        "readlink".to_string(),
                        format!("/proc/{}/ns/mnt", runtime.container_pid),
                    ]
                && runtime.mount_namespace_exit_code == 0
                && runtime.mount_namespace_stdout.trim() == self.mount_namespace_id
                && runtime.mount_namespace_stderr.trim().is_empty(),
            "raw helper Pod, container runtime, and mount namespace responses do not prove the host execution identity"
        );
        Ok(runtime.container_pid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyVolumeObservation {
    pub observed_at_ms: u64,
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_process_can_access_volume: bool,
    pub data_entries: Vec<String>,
    pub scan_response_sha256: String,
    pub scan_response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyVolumeScanResponse {
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_process_can_access_volume: bool,
    pub scan_started_at_ms: u64,
    pub scan_completed_at_ms: u64,
    pub exhaustive: bool,
    pub data_entries: Vec<String>,
}

impl EmptyVolumeObservation {
    fn validate(&self, replacement: &StorageVolumeIdentity) -> Result<()> {
        validate_sha256("empty-volume scan response", &self.scan_response_sha256)?;
        ensure!(
            self.scan_response_sha256 == sha256_bytes(self.scan_response_body.as_bytes()),
            "empty-volume scan response digest does not match its captured body"
        );
        let response = serde_json::from_str::<EmptyVolumeScanResponse>(&self.scan_response_body)
            .context("decode captured empty-volume scan response")?;
        ensure!(
            response.scan_started_at_ms > 0
                && response.scan_started_at_ms < response.scan_completed_at_ms
                && response.scan_completed_at_ms == self.observed_at_ms
                && self.observed_at_ms < replacement.observed_at_ms,
            "empty-volume observation must precede the replacement identity observation"
        );
        ensure!(
            self.persistent_volume_uid == replacement.persistent_volume_uid
                && self.canonical_device == replacement.canonical_device
                && self.filesystem_uuid == replacement.filesystem_uuid,
            "empty-volume observation is not bound to the replacement storage generation"
        );
        ensure!(
            !self.rustfs_process_can_access_volume,
            "replacement emptiness must be observed before RustFS can access the volume"
        );
        ensure!(
            self.data_entries.is_empty(),
            "replacement volume contains data entries before RustFS adoption"
        );
        ensure!(
            response.persistent_volume_uid == self.persistent_volume_uid
                && response.canonical_device == self.canonical_device
                && response.filesystem_uuid == self.filesystem_uuid
                && response.rustfs_process_can_access_volume
                    == self.rustfs_process_can_access_volume
                && response.data_entries == self.data_entries
                && response.exhaustive,
            "empty-volume fields are not derived from one exhaustive host scan response"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshVolumeReplacementProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub original: StorageVolumeIdentity,
    pub replacement: StorageVolumeIdentity,
    pub empty_before_adoption: EmptyVolumeObservation,
}

impl FreshVolumeReplacementProof {
    pub fn prove(
        identity: StorageRecoveryArtifactIdentity,
        original: StorageVolumeIdentity,
        replacement: StorageVolumeIdentity,
        empty_before_adoption: EmptyVolumeObservation,
    ) -> Result<Self> {
        let proof = Self {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity,
            original,
            replacement,
            empty_before_adoption,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported disk-generation proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.identity.scenario == "fresh-volume-replacement",
            "fresh replacement proof is bound to the wrong scenario"
        );
        self.original.validate()?;
        self.replacement.validate()?;
        self.original
            .validate_replacement_generation(&self.replacement)?;
        self.empty_before_adoption.validate(&self.replacement)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleMutationKind {
    Overwrite,
    DeleteMarker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommittedMutationEvidence {
    pub operation_id: String,
    pub kind: StaleMutationKind,
    pub object_key: String,
    pub version_id: String,
    pub acknowledged_at_ms: u64,
    pub absence_observation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskAbsenceObservation {
    pub observation_id: String,
    pub detachment_operation_id: String,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
    pub watch_started_at_ms: u64,
    pub watch_ended_at_ms: u64,
    pub kubernetes_binding_evidence: KubernetesLocalPvBindingEvidence,
    pub host_watch_evidence: DiskAbsenceWatchEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiskPresenceState {
    Absent,
    Present,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "kebab-case")]
pub enum RawDiskStateResponse {
    HostDevice {
        execution: HostExecutionIdentity,
        argv: Vec<String>,
        exit_code: i32,
        stdout: String,
        stderr: String,
        observed_at_ms: u64,
        mount_path: String,
        canonical_device: String,
    },
    HostIoProbe {
        execution: HostExecutionIdentity,
        relative_path: String,
        openat2_resolve_flags: Vec<String>,
        requested_bytes: usize,
        bytes_read: usize,
        errno: Option<i32>,
        observed_at_ms: u64,
        mount_path: String,
        canonical_device: String,
    },
    DeviceMapperTable {
        host_storage_proof_sha256: String,
        host_storage_proof_body: String,
        observer_namespace: String,
        observer_pod: String,
        mapper_name: String,
        argv: Vec<String>,
        exit_code: i32,
        stdout: String,
        stderr: String,
        suspended: bool,
        observed_at_ms: u64,
        canonical_device: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesLocalPvBindingResponse {
    pub observed_at_ms: u64,
    pub persistent_volume_sha256: String,
    pub persistent_volume_body: String,
    pub persistent_volume_claim_sha256: String,
    pub persistent_volume_claim_body: String,
    pub pod_sha256: String,
    pub pod_body: String,
    pub node_sha256: String,
    pub node_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesLocalPvBindingEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostDiskStateSample {
    pub cursor: String,
    pub observed_at_ms: u64,
    pub state: DiskPresenceState,
    pub raw_evidence: RawDiskStateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RawDiskStateEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsDiskAbsenceWatchResponse {
    pub observation_id: String,
    pub detachment_operation_id: String,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
    pub watch_started_at_ms: u64,
    pub watch_ended_at_ms: u64,
    pub poll_interval_ms: u64,
    pub samples: Vec<HostDiskStateSample>,
    pub closed_normally: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiskAbsenceWatchEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StaleDiskLifecycleAction {
    Detach,
    Reattach,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsStaleDiskOperationReceipt {
    pub operation_id: String,
    pub action: StaleDiskLifecycleAction,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: String,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub kubernetes_binding_evidence: KubernetesLocalPvBindingEvidence,
    pub host_result_evidence: RawDiskStateEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDiskOperationEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDiskLifecycleEvidence {
    pub detach: StaleDiskOperationEvidence,
    pub reattach: StaleDiskOperationEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostReturnCheckerEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone)]
struct ValidatedDiskAbsenceWatch {
    sample_times_ms: Vec<u64>,
    first_absent_index: usize,
    poll_interval_ms: u64,
}

impl ValidatedDiskAbsenceWatch {
    fn proves_absent_at(&self, acknowledged_at_ms: u64) -> bool {
        let after_index = self
            .sample_times_ms
            .partition_point(|observed_at_ms| *observed_at_ms < acknowledged_at_ms);
        if after_index == 0 || after_index >= self.sample_times_ms.len() {
            return false;
        }
        let before_index = after_index - 1;
        before_index >= self.first_absent_index
            && self.sample_times_ms[before_index] <= acknowledged_at_ms
            && acknowledged_at_ms <= self.sample_times_ms[after_index]
            && self.sample_times_ms[after_index] - self.sample_times_ms[before_index]
                <= self.poll_interval_ms
    }
}

#[derive(Debug, Clone, Copy)]
struct RawDiskStateExpectation<'a> {
    state: DiskPresenceState,
    observed_at_ms: u64,
    cursor: &'a str,
    volume: &'a StorageVolumeIdentity,
}

impl RawDiskStateEvidence {
    fn cursor(&self) -> Result<String> {
        validate_sha256("raw disk-state response", &self.response_sha256)?;
        Ok(self.response_sha256.clone())
    }

    fn validate(&self, expectation: RawDiskStateExpectation<'_>) -> Result<()> {
        let RawDiskStateExpectation {
            state,
            observed_at_ms,
            cursor,
            volume,
        } = expectation;
        validate_sha256("raw disk-state response", &self.response_sha256)?;
        ensure!(
            self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "raw disk-state response digest does not match its captured body"
        );
        let response = serde_json::from_str::<RawDiskStateResponse>(&self.response_body)
            .context("decode raw disk-state response")?;
        match response {
            RawDiskStateResponse::HostDevice {
                execution,
                argv,
                exit_code,
                stdout,
                stderr,
                observed_at_ms: raw_observed_at_ms,
                mount_path,
                canonical_device,
            } => {
                let target_pid = execution.validate_for(volume)?;
                let expected_argv = vec![
                    "nsenter".to_string(),
                    "--target".to_string(),
                    target_pid.to_string(),
                    "--mount".to_string(),
                    "--".to_string(),
                    "findmnt".to_string(),
                    "-n".to_string(),
                    "--raw".to_string(),
                    "-o".to_string(),
                    "SOURCE,TARGET".to_string(),
                    "--mountpoint".to_string(),
                    volume.mount_path.clone(),
                ];
                let output_fields = stdout.split_whitespace().collect::<Vec<_>>();
                let command_result_matches = match state {
                    DiskPresenceState::Present => {
                        exit_code == 0
                            && output_fields.as_slice()
                                == [volume.canonical_device.as_str(), volume.mount_path.as_str()]
                            && stderr.trim().is_empty()
                    }
                    DiskPresenceState::Absent => match exit_code {
                        1 => stdout.trim().is_empty() && stderr.trim().is_empty(),
                        0 => {
                            stderr.trim().is_empty()
                                && output_fields.len() == 2
                                && output_fields[1] != volume.mount_path
                        }
                        _ => false,
                    },
                };
                ensure!(
                    cursor == self.response_sha256
                        && raw_observed_at_ms == observed_at_ms
                        && mount_path == volume.mount_path
                        && canonical_device == volume.canonical_device
                        && argv == expected_argv
                        && command_result_matches,
                    "raw target-node findmnt result does not prove the claimed disk state"
                );
            }
            RawDiskStateResponse::HostIoProbe {
                execution,
                relative_path,
                openat2_resolve_flags,
                requested_bytes,
                bytes_read,
                errno,
                observed_at_ms: raw_observed_at_ms,
                mount_path,
                canonical_device,
            } => {
                execution.validate_for(volume)?;
                let result_matches = match state {
                    DiskPresenceState::Present => bytes_read == 1 && errno.is_none(),
                    DiskPresenceState::Absent => bytes_read == 0 && errno == Some(libc::EIO),
                };
                ensure!(
                    cursor == self.response_sha256
                        && raw_observed_at_ms == observed_at_ms
                        && mount_path == volume.mount_path
                        && canonical_device == volume.canonical_device
                        && relative_path == ".rustfs.sys/format.json"
                        && openat2_resolve_flags == ["NO_XDEV", "NO_SYMLINKS", "BENEATH"]
                        && requested_bytes == 1
                        && result_matches,
                    "raw host-helper probe does not prove the claimed continuous EIO disk state"
                );
            }
            RawDiskStateResponse::DeviceMapperTable {
                host_storage_proof_sha256,
                host_storage_proof_body,
                observer_namespace,
                observer_pod,
                mapper_name,
                argv,
                exit_code,
                stdout,
                stderr,
                suspended,
                observed_at_ms: raw_observed_at_ms,
                canonical_device,
            } => {
                let proof =
                    serde_json::from_str::<HostStorageMutationProof>(&host_storage_proof_body)
                        .context("decode captured host-storage proof for DM state")?;
                proof.validate()?;
                let expected_table = match state {
                    DiskPresenceState::Present => proof.tables.recovery_table.as_str(),
                    DiskPresenceState::Absent => proof.tables.fault_table.as_str(),
                };
                ensure!(
                    cursor == self.response_sha256
                        && host_storage_proof_sha256 == volume.host_storage_proof_sha256
                        && host_storage_proof_sha256
                            == sha256_bytes(host_storage_proof_body.as_bytes())
                        && proof.target.persistent_volume == volume.persistent_volume
                        && proof.target.persistent_volume_uid == volume.persistent_volume_uid
                        && proof.target.canonical_device == volume.canonical_device
                        && proof.target.container_mount_path == volume.mount_path
                        && observer_namespace == proof.observer_namespace
                        && observer_pod == proof.observer_pod
                        && mapper_name == proof.target.mapper_name
                        && argv == ["dmsetup", "table", "--showkeys", mapper_name.as_str()]
                        && exit_code == 0
                        && stderr.trim().is_empty()
                        && !suspended
                        && raw_observed_at_ms == observed_at_ms
                        && canonical_device == volume.canonical_device
                        && dm_tables_match(&stdout, expected_table)?,
                    "raw device-mapper table observation does not prove the claimed present/EIO state"
                );
            }
        }
        Ok(())
    }
}

impl KubernetesLocalPvBindingEvidence {
    fn validate(&self, volume: &StorageVolumeIdentity, observed_at_ms: u64) -> Result<()> {
        validate_sha256(
            "Kubernetes Local PV binding response",
            &self.response_sha256,
        )?;
        ensure!(
            self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "Kubernetes Local PV binding digest does not match its captured response body"
        );
        let response =
            serde_json::from_str::<KubernetesLocalPvBindingResponse>(&self.response_body)
                .context("decode captured Kubernetes Local PV binding response")?;
        for (label, digest, body) in [
            (
                "PersistentVolume",
                &response.persistent_volume_sha256,
                &response.persistent_volume_body,
            ),
            (
                "PersistentVolumeClaim",
                &response.persistent_volume_claim_sha256,
                &response.persistent_volume_claim_body,
            ),
            ("Pod", &response.pod_sha256, &response.pod_body),
            ("Node", &response.node_sha256, &response.node_body),
        ] {
            validate_sha256(label, digest)?;
            ensure!(
                digest == &sha256_bytes(body.as_bytes()),
                "raw Kubernetes {label} digest does not match its response body"
            );
        }
        let pv = serde_json::from_str::<serde_json::Value>(&response.persistent_volume_body)
            .context("decode raw Kubernetes PersistentVolume")?;
        let pvc = serde_json::from_str::<serde_json::Value>(&response.persistent_volume_claim_body)
            .context("decode raw Kubernetes PersistentVolumeClaim")?;
        let pod = serde_json::from_str::<serde_json::Value>(&response.pod_body)
            .context("decode raw Kubernetes Pod")?;
        let node = serde_json::from_str::<serde_json::Value>(&response.node_body)
            .context("decode raw Kubernetes Node")?;
        fn string_at<'a>(value: &'a serde_json::Value, pointer: &str) -> Option<&'a str> {
            value.pointer(pointer).and_then(serde_json::Value::as_str)
        }
        let matching_volumes = pod
            .pointer("/spec/volumes")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|binding| {
                string_at(binding, "/name") == Some(volume.volume_name.as_str())
                    && string_at(binding, "/persistentVolumeClaim/claimName")
                        == Some(volume.persistent_volume_claim.as_str())
            })
            .count();
        let matching_mounts = pod
            .pointer("/spec/containers")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|container| string_at(container, "/name") == Some("rustfs"))
            .flat_map(|container| {
                container
                    .pointer("/volumeMounts")
                    .and_then(serde_json::Value::as_array)
                    .into_iter()
                    .flatten()
            })
            .filter(|mount| {
                string_at(mount, "/name") == Some(volume.volume_name.as_str())
                    && string_at(mount, "/mountPath") == Some(volume.mount_path.as_str())
            })
            .count();
        let matching_containers = pod
            .pointer("/status/containerStatuses")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|container| {
                string_at(container, "/name") == Some("rustfs")
                    && string_at(container, "/containerID")
                        == Some(volume.rustfs_container_id.as_str())
            })
            .count();
        ensure!(
            response.observed_at_ms == observed_at_ms
                && string_at(&pv, "/apiVersion") == Some("v1")
                && string_at(&pv, "/kind") == Some("PersistentVolume")
                && string_at(&pv, "/metadata/name") == Some(volume.persistent_volume.as_str())
                && string_at(&pv, "/metadata/uid")
                    == Some(volume.persistent_volume_uid.as_str())
                && string_at(&pv, "/metadata/resourceVersion")
                    .is_some_and(|value| !value.trim().is_empty())
                && string_at(&pv, "/spec/storageClassName")
                    == Some(volume.storage_class.as_str())
                && string_at(&pv, "/spec/local/path")
                    == Some(volume.local_volume_path.as_str())
                && string_at(&pv, "/spec/claimRef/namespace")
                    == Some(volume.namespace.as_str())
                && string_at(&pv, "/spec/claimRef/name")
                    == Some(volume.persistent_volume_claim.as_str())
                && string_at(&pv, "/spec/claimRef/uid")
                    == Some(volume.persistent_volume_claim_uid.as_str())
                && string_at(
                    &pv,
                    "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/key",
                ) == Some("kubernetes.io/hostname")
                && string_at(
                    &pv,
                    "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/operator",
                ) == Some("In")
                && pv
                    .pointer("/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0/values")
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|values| {
                        matches!(values.as_slice(), [value] if value.as_str() == Some(volume.node.as_str()))
                    })
                && string_at(&pv, "/status/phase") == Some("Bound")
                && string_at(&pvc, "/apiVersion") == Some("v1")
                && string_at(&pvc, "/kind") == Some("PersistentVolumeClaim")
                && string_at(&pvc, "/metadata/name")
                    == Some(volume.persistent_volume_claim.as_str())
                && string_at(&pvc, "/metadata/namespace") == Some(volume.namespace.as_str())
                && string_at(&pvc, "/metadata/uid")
                    == Some(volume.persistent_volume_claim_uid.as_str())
                && string_at(&pvc, "/metadata/resourceVersion")
                    .is_some_and(|value| !value.trim().is_empty())
                && string_at(&pvc, "/spec/volumeName")
                    == Some(volume.persistent_volume.as_str())
                && string_at(&pvc, "/spec/storageClassName")
                    == Some(volume.storage_class.as_str())
                && string_at(&pvc, "/status/phase") == Some("Bound")
                && string_at(&pod, "/apiVersion") == Some("v1")
                && string_at(&pod, "/kind") == Some("Pod")
                && string_at(&pod, "/metadata/name") == Some(volume.pod.as_str())
                && string_at(&pod, "/metadata/namespace") == Some(volume.namespace.as_str())
                && string_at(&pod, "/metadata/uid") == Some(volume.pod_uid.as_str())
                && string_at(&pod, "/metadata/resourceVersion")
                    .is_some_and(|value| !value.trim().is_empty())
                && string_at(&pod, "/spec/nodeName") == Some(volume.node.as_str())
                && matching_volumes == 1
                && matching_mounts == 1
                && matching_containers == 1
                && string_at(&node, "/apiVersion") == Some("v1")
                && string_at(&node, "/kind") == Some("Node")
                && string_at(&node, "/metadata/name") == Some(volume.node.as_str())
                && string_at(&node, "/metadata/uid") == Some(volume.node_uid.as_str())
                && string_at(&node, "/metadata/resourceVersion")
                    .is_some_and(|value| !value.trim().is_empty()),
            "raw Kubernetes objects do not prove the exact Local PV/PVC/Pod/node generation"
        );
        Ok(())
    }
}

impl DiskAbsenceObservation {
    fn validate_captured_watches(
        &self,
        generation: &StorageVolumeIdentity,
        detach_started_at_ms: u64,
        detached_at_ms: u64,
        mutation_window_ended_at_ms: u64,
        reattach_started_at_ms: u64,
    ) -> Result<ValidatedDiskAbsenceWatch> {
        self.kubernetes_binding_evidence
            .validate(generation, self.watch_started_at_ms)?;
        let evidence = &self.host_watch_evidence;
        validate_sha256("disk-absence watch response", &evidence.response_sha256)?;
        ensure!(
            evidence.response_sha256 == sha256_bytes(evidence.response_body.as_bytes()),
            "disk-absence watch digest does not match its captured response body"
        );
        let response =
            serde_json::from_str::<RustfsDiskAbsenceWatchResponse>(&evidence.response_body)
                .context("decode captured disk-absence watch response")?;
        ensure!(
            response.observation_id == self.observation_id
                && response.detachment_operation_id == self.detachment_operation_id
                && response.persistent_volume == self.persistent_volume
                && response.persistent_volume_uid == self.persistent_volume_uid
                && response.canonical_device == self.canonical_device
                && response.filesystem_uuid == self.filesystem_uuid
                && response.rustfs_drive_uuid == self.rustfs_drive_uuid
                && response.target_proof_sha256 == self.target_proof_sha256
                && response.host_storage_proof_sha256 == self.host_storage_proof_sha256
                && response.watch_started_at_ms == self.watch_started_at_ms
                && response.watch_ended_at_ms == self.watch_ended_at_ms,
            "disk-absence watch fields are not derived from the detached storage generation"
        );
        ensure!(
            response.closed_normally
                && (1..=HOST_DISK_WATCH_MAX_POLL_INTERVAL_MS).contains(&response.poll_interval_ms)
                && response.watch_started_at_ms <= detach_started_at_ms
                && response.watch_ended_at_ms >= mutation_window_ended_at_ms
                && response.watch_ended_at_ms < reattach_started_at_ms
                && response.watch_started_at_ms < response.watch_ended_at_ms
                && response.samples.len() >= 3,
            "host disk watch lacks a bounded, non-overlapping sample interval from detach through mutations"
        );
        let mut cursors = BTreeSet::new();
        for (index, sample) in response.samples.iter().enumerate() {
            ensure!(
                !sample.cursor.trim().is_empty()
                    && cursors.insert(sample.cursor.as_str())
                    && sample.cursor == sample.raw_evidence.cursor()?
                    && (index == 0
                        || sample.observed_at_ms > response.samples[index - 1].observed_at_ms),
                "host disk watch samples are duplicate or unordered"
            );
            sample.raw_evidence.validate(RawDiskStateExpectation {
                state: sample.state,
                observed_at_ms: sample.observed_at_ms,
                cursor: &sample.cursor,
                volume: generation,
            })?;
        }
        let first = &response.samples[0];
        let last = response.samples.last().expect("sample count checked above");
        let first_absent = response
            .samples
            .iter()
            .position(|sample| sample.state == DiskPresenceState::Absent)
            .context("host disk watch never observed the detach")?;
        ensure!(
            response.samples[first_absent..]
                .windows(2)
                .all(|window| window[1].observed_at_ms - window[0].observed_at_ms
                    <= response.poll_interval_ms),
            "continuous EIO samples exceed the bounded poll interval after detachment"
        );
        ensure!(
            first.state == DiskPresenceState::Present
                && first.observed_at_ms == response.watch_started_at_ms
                && response.samples[first_absent].observed_at_ms >= detach_started_at_ms
                && response.samples[first_absent].observed_at_ms <= detached_at_ms
                && response.samples[first_absent..]
                    .iter()
                    .all(|sample| sample.state == DiskPresenceState::Absent)
                && last.observed_at_ms == response.watch_ended_at_ms
                && last.state == DiskPresenceState::Absent,
            "host disk watch does not prove one bounded present-to-absent interval without reconnect"
        );
        Ok(ValidatedDiskAbsenceWatch {
            sample_times_ms: response
                .samples
                .iter()
                .map(|sample| sample.observed_at_ms)
                .collect(),
            first_absent_index: first_absent,
            poll_interval_ms: response.poll_interval_ms,
        })
    }
}

impl StaleDiskOperationEvidence {
    fn receipt(&self) -> Result<RustfsStaleDiskOperationReceipt> {
        validate_sha256("stale-disk operation response", &self.response_sha256)?;
        ensure!(
            self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "stale-disk operation digest does not match its captured response body"
        );
        serde_json::from_str(&self.response_body)
            .context("decode captured stale-disk operation receipt")
    }
}

impl PostReturnCheckerEvidence {
    fn validate(
        &self,
        identity: &StorageRecoveryArtifactIdentity,
        returned_generation_observed_at_ms: u64,
        committed_mutations: &[CommittedMutationEvidence],
        history: &[OperationRecord],
    ) -> Result<()> {
        validate_sha256("post-return checker response", &self.response_sha256)?;
        ensure!(
            self.response_sha256 == sha256_bytes(self.response_body.as_bytes()),
            "post-return checker digest does not match its captured response body"
        );
        let report = serde_json::from_str::<CheckerReport>(&self.response_body)
            .context("decode captured post-return checker report")?;
        let audit = report
            .audit
            .as_ref()
            .context("post-return CheckerReport lacks its producer-native audit")?;
        validate_history_scope_and_order(
            history,
            &identity.scenario,
            &identity.run_id,
            &identity.bucket,
        )
        .context("post-return checker history violates the run history contract")?;
        validate_sha256("post-return history prefix", &audit.history_prefix_sha256)?;
        validate_sha256("post-return checker suffix", &audit.history_suffix_sha256)?;
        ensure!(
            audit.bucket == identity.bucket
                && audit.started_at_ms > returned_generation_observed_at_ms
                && audit.started_at_ms <= audit.completed_at_ms
                && audit.history_prefix_record_count > 0
                && audit.history_prefix_record_count < history.len(),
            "post-return checker audit is not bound to this bucket and post-return interval"
        );
        let history_prefix = &history[..audit.history_prefix_record_count];
        let history_suffix = &history[audit.history_prefix_record_count..];
        validate_history_phase_boundary(
            history_prefix,
            history_suffix,
            "post-return prefix/checker",
        )?;
        validate_settled_current_mutations(history_prefix, identity)?;
        ensure!(
            history_prefix.iter().all(|record| {
                record_matches_identity(record, identity)
                    && valid_operation_interval(record)
                    && record.ended_at_ms <= audit.started_at_ms
            }) && audit.history_prefix_sha256 == checker_history_records_sha256(history_prefix)?
                && audit.history_suffix_record_count == history_suffix.len()
                && audit.history_suffix_sha256 == checker_history_records_sha256(history_suffix)?
                && audit.suffix_operations == checker_operation_audits(history_suffix)
                && history_suffix.iter().all(|record| {
                    record_matches_identity(record, identity)
                        && matches!(
                            record.kind,
                            OperationKind::Get | OperationKind::List | OperationKind::ListVersions
                        )
                        && valid_operation_interval(record)
                        && record.started_at_ms >= audit.started_at_ms
                        && record.ended_at_ms <= audit.completed_at_ms
                })
                && history_suffix
                    .iter()
                    .any(|record| record.kind == OperationKind::List)
                && history_suffix
                    .iter()
                    .any(|record| record.kind == OperationKind::ListVersions),
            "post-return checker audit does not bind a complete read-only checker suffix over quiesced history"
        );
        let prefix_operation_ids = history_prefix
            .iter()
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            committed_mutations
                .iter()
                .all(|mutation| { prefix_operation_ids.contains(mutation.operation_id.as_str()) }),
            "post-return checker history prefix omits a stale-window mutation"
        );
        let mut committed_current_state = BTreeMap::<String, Option<String>>::new();
        let mut pending_ambiguous_deletes = BTreeSet::new();
        for record in history_prefix.iter().filter(|record| {
            record_matches_identity(record, identity) && valid_operation_interval(record)
        }) {
            let Some(key) = record.key.as_ref() else {
                continue;
            };
            match record.kind {
                OperationKind::Put | OperationKind::CompleteMultipartUpload
                    if record.outcome == OperationOutcome::Ok
                        && record
                            .http_status
                            .is_some_and(|status| (200..300).contains(&status)) =>
                {
                    let expected_sha256 = record
                        .value_sha256
                        .clone()
                        .context("committed current-object write lacks its content hash")?;
                    committed_current_state.insert(key.clone(), Some(expected_sha256));
                    pending_ambiguous_deletes.remove(key);
                }
                OperationKind::Delete
                    if record.outcome == OperationOutcome::Ok
                        && record
                            .http_status
                            .is_some_and(|status| (200..300).contains(&status)) =>
                {
                    committed_current_state.insert(key.clone(), None);
                    pending_ambiguous_deletes.remove(key);
                }
                OperationKind::Delete
                    if matches!(
                        record.outcome,
                        OperationOutcome::Timeout | OperationOutcome::Unknown
                    ) =>
                {
                    pending_ambiguous_deletes.insert(key.clone());
                }
                _ => {}
            }
        }
        let mut expected_data_checks = Vec::new();
        let mut expected_delete_checks = Vec::new();
        for record in history_prefix.iter().filter(|record| {
            record_matches_identity(record, identity)
                && record.outcome == OperationOutcome::Ok
                && record
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
        }) {
            let Some(key) = record.key.as_ref() else {
                continue;
            };
            let Some(version_id) = record
                .version_id
                .as_deref()
                .filter(|version_id| !version_id.is_empty() && *version_id != "null")
            else {
                continue;
            };
            match record.kind {
                OperationKind::Put | OperationKind::CompleteMultipartUpload => {
                    let expected_sha256 = record
                        .value_sha256
                        .clone()
                        .context("committed data version lacks its expected content hash")?;
                    expected_data_checks.push(CheckerDataVersionAudit {
                        key: key.clone(),
                        version_id: version_id.to_string(),
                        expected_sha256: expected_sha256.clone(),
                        observed_sha256: Some(expected_sha256),
                        outcome: OperationOutcome::Ok,
                        http_status: Some(200),
                    });
                }
                OperationKind::Delete => {
                    expected_delete_checks.push(CheckerDeleteMarkerAudit {
                        key: key.clone(),
                        version_id: version_id.to_string(),
                        visible_in_list_object_versions: true,
                    });
                }
                _ => {}
            }
        }
        expected_data_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        expected_delete_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        let mut recorded_version_gets = BTreeMap::new();
        for record in history_suffix
            .iter()
            .filter(|record| record.kind == OperationKind::Get && record.version_id.is_some())
        {
            *recorded_version_gets
                .entry((
                    record.key.clone(),
                    record.version_id.clone(),
                    record.value_sha256.clone(),
                    operation_outcome_rank(record.outcome),
                    record.http_status,
                ))
                .or_insert(0usize) += 1;
        }
        for check in &audit.data_version_checks {
            let recorded = recorded_version_gets.get_mut(&(
                Some(check.key.clone()),
                Some(check.version_id.clone()),
                check.observed_sha256.clone(),
                operation_outcome_rank(check.outcome),
                check.http_status,
            ));
            ensure!(
                recorded.as_deref().is_some_and(|count| *count > 0),
                "post-return checker data-version audit lacks one exact recorded GET"
            );
            *recorded.expect("count checked above") -= 1;
        }
        ensure!(
            recorded_version_gets.values().all(|count| *count == 0),
            "post-return checker suffix contains an unreported version GET"
        );
        let checker_prefix = format!("fault-test/{}/", identity.run_id);
        let matching_version_lists = history_suffix
            .iter()
            .filter(|record| record.kind == OperationKind::ListVersions)
            .collect::<Vec<_>>();
        let [version_list] = matching_version_lists.as_slice() else {
            anyhow::bail!("post-return checker requires one ListObjectVersions request");
        };
        ensure!(
            version_list.key.as_deref() == Some(checker_prefix.as_str())
                && version_list.outcome == OperationOutcome::Ok
                && version_list
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
                && version_list.error.is_none(),
            "post-return checker requires one successful bounded ListObjectVersions request"
        );
        let listed_versions = version_list
            .listed_versions
            .as_ref()
            .context("successful post-return ListObjectVersions lacks recorded entries")?;
        let listed_version_set = listed_versions.iter().cloned().collect::<BTreeSet<_>>();
        let expected_version_listing = checker_expected_version_listing(history_prefix);
        ensure!(
            version_list.size_bytes == Some(listed_versions.len())
                && listed_versions.len() == listed_version_set.len()
                && listed_version_set == expected_version_listing,
            "post-return ListObjectVersions contents do not exactly match committed version lineage"
        );

        let matching_lists = history_suffix
            .iter()
            .filter(|record| record.kind == OperationKind::List)
            .collect::<Vec<_>>();
        let [list] = matching_lists.as_slice() else {
            anyhow::bail!("post-return checker requires one LIST request");
        };
        ensure!(
            list.key.as_deref() == Some(checker_prefix.as_str())
                && list.outcome == OperationOutcome::Ok
                && list
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
                && list.error.is_none(),
            "post-return checker requires one successful bounded LIST request"
        );
        let listed_keys = list
            .listed_keys
            .as_ref()
            .context("successful post-return LIST lacks recorded keys")?;
        let listed_key_set = listed_keys.iter().cloned().collect::<BTreeSet<_>>();
        let expected_live_keys = checker_expected_live_keys(history_prefix);
        ensure!(
            list.size_bytes == Some(listed_keys.len())
                && listed_keys.len() == listed_key_set.len()
                && listed_key_set == expected_live_keys,
            "post-return LIST contents do not exactly match committed live keys"
        );
        let mut tolerated_ambiguous_deletes = BTreeSet::new();
        let mut current_get_counts = BTreeMap::new();
        for record in history_suffix
            .iter()
            .filter(|record| record.kind == OperationKind::Get && record.version_id.is_none())
        {
            let key = record
                .key
                .as_ref()
                .context("post-return checker current-object GET lacks a key")?;
            *current_get_counts.entry(key.clone()).or_insert(0usize) += 1;
            let clean = match committed_current_state.get(key) {
                Some(Some(expected_sha256)) => {
                    if pending_ambiguous_deletes.contains(key)
                        && record.outcome == OperationOutcome::NotFound
                        && record.http_status == Some(404)
                        && record.value_sha256.is_none()
                    {
                        tolerated_ambiguous_deletes.insert(key.clone());
                        true
                    } else {
                        record.outcome == OperationOutcome::Ok
                            && record.http_status == Some(200)
                            && record.value_sha256.as_ref() == Some(expected_sha256)
                    }
                }
                Some(None) | None => {
                    record.outcome == OperationOutcome::NotFound
                        && record.http_status == Some(404)
                        && record.value_sha256.is_none()
                }
            };
            ensure!(
                clean && (record.outcome != OperationOutcome::Ok || record.error.is_none()),
                "post-return checker current-object GET contradicts the committed object model"
            );
        }
        ensure!(
            current_get_counts.keys().cloned().collect::<BTreeSet<_>>()
                == checker_expected_current_get_keys(history_prefix)
                && current_get_counts.values().all(|count| *count == 1),
            "post-return checker suffix does not probe every required current-object key exactly once"
        );
        report.require_success()?;
        ensure!(
            report.scenario == identity.scenario
                && report.run_id == identity.run_id
                && audit.list_object_versions_completed == Some(true)
                && audit.data_version_checks == expected_data_checks
                && audit.delete_marker_checks == expected_delete_checks
                && report.tenant_recovered
                && report.versioning_expected
                && report.expected_live_objects
                    == committed_current_state
                        .values()
                        .filter(|value| value.is_some())
                        .count()
                && report.expected_live_objects == report.verified_live_objects
                && report.final_listed_objects == Some(expected_live_keys.len())
                && report
                    .tolerated_ambiguous_deletes
                    .iter()
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    == tolerated_ambiguous_deletes
                && report.final_list_warning_count == 0
                && report.list_warnings.is_empty()
                && report.expected_committed_versions == expected_data_checks.len()
                && report.verified_committed_versions == report.expected_committed_versions
                && report.committed_writes_missing_version_id_count == 0
                && report.missing_committed_objects.is_empty()
                && report.unavailable_committed_objects.is_empty()
                && report.unknown_committed_read_failures.is_empty()
                && report.hash_mismatches.is_empty()
                && report.successful_corrupted_reads.is_empty()
                && report.unexpected_visible_deleted_objects.is_empty()
                && report.unknown_writes_materialized.is_empty()
                && report.unknown_write_value_conflicts.is_empty()
                && report.missing_committed_versions.is_empty()
                && report.unavailable_committed_versions.is_empty()
                && report.version_hash_mismatches.is_empty()
                && report.missing_committed_delete_markers.is_empty()
                && report.resurrected_deleted_objects.is_empty()
                && report.delete_marker_lineage_incomplete.is_empty()
                && report.multipart_upload_lineage_incomplete.is_empty(),
            "producer-native post-return checker audit does not prove current objects, immutable versions, and delete markers"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDiskReturnEvidence {
    pub detached_at_ms: u64,
    pub mutation_window_ended_at_ms: u64,
    pub returned_at_ms: u64,
    pub detachment_operation_id: String,
    pub reattachment_operation_id: String,
    pub lifecycle_evidence: StaleDiskLifecycleEvidence,
    pub absence_observations: Vec<DiskAbsenceObservation>,
    pub committed_mutations: Vec<CommittedMutationEvidence>,
    pub post_return_checker: PostReturnCheckerEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StaleDiskReturnProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub detached_generation: StorageVolumeIdentity,
    pub returned_generation: StorageVolumeIdentity,
    pub detached_at_ms: u64,
    pub mutation_window_ended_at_ms: u64,
    pub returned_at_ms: u64,
    pub detachment_operation_id: String,
    pub reattachment_operation_id: String,
    pub lifecycle_evidence: StaleDiskLifecycleEvidence,
    pub absence_observations: Vec<DiskAbsenceObservation>,
    pub committed_mutations: Vec<CommittedMutationEvidence>,
    pub post_return_checker: PostReturnCheckerEvidence,
}

impl StaleDiskReturnProof {
    pub fn prove(
        identity: StorageRecoveryArtifactIdentity,
        detached_generation: StorageVolumeIdentity,
        returned_generation: StorageVolumeIdentity,
        evidence: StaleDiskReturnEvidence,
        history: &[OperationRecord],
    ) -> Result<Self> {
        let proof = Self {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity,
            detached_generation,
            returned_generation,
            detached_at_ms: evidence.detached_at_ms,
            mutation_window_ended_at_ms: evidence.mutation_window_ended_at_ms,
            returned_at_ms: evidence.returned_at_ms,
            detachment_operation_id: evidence.detachment_operation_id,
            reattachment_operation_id: evidence.reattachment_operation_id,
            lifecycle_evidence: evidence.lifecycle_evidence,
            absence_observations: evidence.absence_observations,
            committed_mutations: evidence.committed_mutations,
            post_return_checker: evidence.post_return_checker,
        };
        proof.validate_against_history(history)?;
        Ok(proof)
    }

    pub fn validate_against_history(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported disk-generation proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        validate_immutable_version_history(history, &self.identity)?;
        ensure!(
            self.identity.scenario == "stale-disk-return-detect",
            "stale-disk proof is bound to the wrong scenario"
        );
        self.detached_generation.validate()?;
        self.returned_generation.validate()?;
        ensure!(
            self.detached_generation
                .same_logical_slot(&self.returned_generation),
            "returned stale disk does not occupy its original logical volume slot"
        );
        ensure!(
            self.detached_generation
                .same_storage_generation(&self.returned_generation),
            "returned disk is not the detached storage generation"
        );
        ensure!(
            self.detached_at_ms >= self.detached_generation.observed_at_ms
                && self.detached_at_ms < self.mutation_window_ended_at_ms
                && self.mutation_window_ended_at_ms < self.returned_at_ms
                && self.returned_at_ms <= self.returned_generation.observed_at_ms,
            "stale-disk detach, mutation, return, and observation timestamps are not ordered"
        );
        ensure!(
            !self.detachment_operation_id.trim().is_empty()
                && !self.reattachment_operation_id.trim().is_empty()
                && self.detachment_operation_id != self.reattachment_operation_id,
            "stale-disk proof requires distinct detach and reattach operation identities"
        );
        let (detach_receipt, reattach_receipt) = self.validate_lifecycle_evidence()?;
        ensure!(
            !self.absence_observations.is_empty(),
            "stale-disk proof has no runtime absence observations"
        );
        let mut absence_by_id = BTreeMap::new();
        for observation in &self.absence_observations {
            ensure!(
                !observation.observation_id.trim().is_empty()
                    && !absence_by_id.contains_key(observation.observation_id.as_str()),
                "stale-disk proof has an empty or duplicate absence observation id"
            );
            ensure!(
                observation.detachment_operation_id == self.detachment_operation_id
                    && observation.persistent_volume == self.detached_generation.persistent_volume
                    && observation.persistent_volume_uid
                        == self.detached_generation.persistent_volume_uid
                    && observation.canonical_device == self.detached_generation.canonical_device
                    && observation.filesystem_uuid == self.detached_generation.filesystem_uuid
                    && observation.rustfs_drive_uuid == self.detached_generation.rustfs_drive_uuid,
                "stale-disk absence observation is not bound to the detached generation and operation"
            );
            ensure!(
                observation.target_proof_sha256 == self.detached_generation.target_proof_sha256
                    && observation.host_storage_proof_sha256
                        == self.detached_generation.host_storage_proof_sha256,
                "stale-disk absence observation is not bound to the target and host-storage proofs"
            );
            ensure!(
                observation.watch_started_at_ms <= self.detached_at_ms
                    && observation.watch_ended_at_ms >= self.mutation_window_ended_at_ms
                    && observation.watch_ended_at_ms > observation.watch_started_at_ms,
                "stale-disk absence watch does not cover the bounded host observation window"
            );
            let validated_watch = observation.validate_captured_watches(
                &self.detached_generation,
                detach_receipt.started_at_ms,
                self.detached_at_ms,
                self.mutation_window_ended_at_ms,
                reattach_receipt.started_at_ms,
            )?;
            absence_by_id.insert(
                observation.observation_id.as_str(),
                (observation, validated_watch),
            );
        }
        ensure!(
            !self.committed_mutations.is_empty(),
            "stale-disk proof has no committed mutations while the disk was absent"
        );
        let mut history_by_id = HashMap::with_capacity(history.len());
        for record in history {
            ensure!(
                history_by_id.insert(record.id.as_str(), record).is_none(),
                "workload history contains a duplicate operation id"
            );
        }
        let mut operation_ids = BTreeSet::new();
        let mut saw_overwrite = false;
        let mut saw_delete_marker = false;
        for mutation in &self.committed_mutations {
            ensure!(
                !mutation.operation_id.trim().is_empty()
                    && operation_ids.insert(mutation.operation_id.as_str())
                    && !mutation.object_key.trim().is_empty()
                    && !mutation.version_id.trim().is_empty()
                    && mutation.version_id != "null"
                    && !mutation.absence_observation_id.trim().is_empty(),
                "stale-disk committed mutation lacks a unique operation/object/version identity"
            );
            ensure!(
                mutation.acknowledged_at_ms > self.detached_at_ms
                    && mutation.acknowledged_at_ms <= self.mutation_window_ended_at_ms,
                "stale-disk mutation ACK falls outside the disk-absence window"
            );
            let (absence, validated_watch) = absence_by_id
                .get(mutation.absence_observation_id.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("stale-disk mutation references an unknown absence observation")
                })?;
            ensure!(
                absence.watch_started_at_ms <= mutation.acknowledged_at_ms
                    && absence.watch_ended_at_ms >= mutation.acknowledged_at_ms
                    && validated_watch.proves_absent_at(mutation.acknowledged_at_ms),
                "stale-disk mutation ACK is not bracketed by bounded target-node absence samples"
            );
            let record = history_by_id
                .get(mutation.operation_id.as_str())
                .copied()
                .context("stale-disk mutation lacks its workload history record")?;
            let kind_matches = match mutation.kind {
                StaleMutationKind::Overwrite => matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                ),
                StaleMutationKind::DeleteMarker => record.kind == OperationKind::Delete,
            };
            ensure!(
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && kind_matches
                    && record.outcome == OperationOutcome::Ok
                    && record
                        .http_status
                        .is_some_and(|status| (200..300).contains(&status))
                    && record.key.as_deref() == Some(mutation.object_key.as_str())
                    && record.version_id.as_deref() == Some(mutation.version_id.as_str())
                    && valid_operation_interval(record)
                    && record.started_at_ms > self.detached_at_ms
                    && record.started_at_ms >= absence.watch_started_at_ms
                    && record.ended_at_ms <= absence.watch_ended_at_ms
                    && record.ended_at_ms == mutation.acknowledged_at_ms,
                "stale-disk mutation does not match a successful versioned request wholly executed during the proven absence window"
            );
            match mutation.kind {
                StaleMutationKind::Overwrite => saw_overwrite = true,
                StaleMutationKind::DeleteMarker => saw_delete_marker = true,
            }
        }
        ensure!(
            saw_overwrite && saw_delete_marker,
            "stale-disk proof requires both a committed overwrite and delete marker"
        );
        let history_mutation_ids = history
            .iter()
            .filter(|record| {
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && matches!(
                        record.kind,
                        OperationKind::Put
                            | OperationKind::CompleteMultipartUpload
                            | OperationKind::Delete
                    )
                    && record.outcome == OperationOutcome::Ok
                    && valid_operation_interval(record)
                    && record.started_at_ms > self.detached_at_ms
                    && record.ended_at_ms > self.detached_at_ms
                    && record.ended_at_ms <= self.mutation_window_ended_at_ms
            })
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            history_mutation_ids == operation_ids,
            "stale-disk proof does not cover the exact successful mutation history from the disk-absence window"
        );
        self.post_return_checker.validate(
            &self.identity,
            self.returned_generation.observed_at_ms,
            &self.committed_mutations,
            history,
        )?;
        Ok(())
    }

    fn validate_lifecycle_evidence(
        &self,
    ) -> Result<(
        RustfsStaleDiskOperationReceipt,
        RustfsStaleDiskOperationReceipt,
    )> {
        let detach = self.lifecycle_evidence.detach.receipt()?;
        let reattach = self.lifecycle_evidence.reattach.receipt()?;
        for (receipt, generation, state) in [
            (
                &detach,
                &self.detached_generation,
                DiskPresenceState::Absent,
            ),
            (
                &reattach,
                &self.returned_generation,
                DiskPresenceState::Present,
            ),
        ] {
            ensure!(
                receipt.persistent_volume == generation.persistent_volume
                    && receipt.persistent_volume_uid == generation.persistent_volume_uid
                    && receipt.canonical_device == generation.canonical_device
                    && receipt.filesystem_uuid == generation.filesystem_uuid
                    && receipt.rustfs_drive_uuid == generation.rustfs_drive_uuid
                    && receipt.target_proof_sha256 == generation.target_proof_sha256
                    && receipt.host_storage_proof_sha256 == generation.host_storage_proof_sha256
                    && receipt.started_at_ms > 0
                    && receipt.started_at_ms < receipt.completed_at_ms,
                "stale-disk lifecycle receipt is not bound to its action-specific storage generation"
            );
            receipt
                .kubernetes_binding_evidence
                .validate(generation, receipt.completed_at_ms)?;
            let host_cursor = receipt.host_result_evidence.cursor()?;
            receipt
                .host_result_evidence
                .validate(RawDiskStateExpectation {
                    state,
                    observed_at_ms: receipt.completed_at_ms,
                    cursor: &host_cursor,
                    volume: generation,
                })?;
        }
        ensure!(
            detach.operation_id == self.detachment_operation_id
                && detach.action == StaleDiskLifecycleAction::Detach
                && detach.started_at_ms >= self.detached_generation.observed_at_ms
                && detach.completed_at_ms == self.detached_at_ms
                && reattach.operation_id == self.reattachment_operation_id
                && reattach.action == StaleDiskLifecycleAction::Reattach
                && reattach.started_at_ms > self.mutation_window_ended_at_ms
                && reattach.completed_at_ms == self.returned_at_ms,
            "captured detach and reattach receipts do not bound the mutation window"
        );
        Ok((detach, reattach))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShardMappingSource {
    RustfsDiagnosticApi,
    OfflineXl2Inspector,
}

impl ShardMappingSource {
    fn validate_revision(self, revision: &str) -> Result<()> {
        match self {
            Self::RustfsDiagnosticApi => ensure!(
                !revision.trim().is_empty(),
                "RustFS diagnostic mapping API revision is empty"
            ),
            Self::OfflineXl2Inspector => ensure!(
                revision == OFFLINE_XL2_INSPECTOR_REVISION,
                "offline XL2 mapping has an unsupported inspector revision"
            ),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsShardMutationMappingResponse {
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub object_sha256: String,
    pub drive_uuid: String,
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardRollbackObservation {
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub observed_sha256: String,
    pub observed_at_ms: u64,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShardPathResolutionMethod {
    Openat2BeneathNoSymlinksNoXdev,
    CanonicalizeOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Openat2PathResolutionReceipt {
    pub execution: HostExecutionIdentity,
    pub method: ShardPathResolutionMethod,
    pub requested_path: String,
    pub canonical_mount_path: String,
    pub mount_canonical_device: String,
    pub mount_filesystem_uuid: String,
    pub resolved_path: String,
    pub mount_device_id: String,
    pub returned_fd_device_id: String,
    pub returned_fd_inode: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardPathContainmentProof {
    pub observed_at_ms: u64,
    pub resolver_evidence_sha256: String,
    pub resolver_response_body: String,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardMutationProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub mapping_source: ShardMappingSource,
    pub mapping_api_revision: String,
    pub mapping_response_sha256: String,
    pub mapping_response_body: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_object_sha256: String,
    pub volume: StorageVolumeIdentity,
    pub mutation_target_proof_body: String,
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub path_containment: ShardPathContainmentProof,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub original_sha256: String,
    pub mutated_sha256: String,
    pub host_mutation_evidence: Option<ShardMutationHostEvidence>,
    pub rollback: ShardRollbackObservation,
    pub mapped_at_ms: u64,
    pub mutated_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardMutationHostReceipt {
    pub execution: HostExecutionIdentity,
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub shard_size_bytes: u64,
    pub byte_offset: u64,
    pub byte_length: u64,
    pub original_sha256: String,
    pub mutated_sha256: String,
    pub rollback_sha256: String,
    pub original_observed_at_ms: u64,
    pub pwrite_completed_at_ms: u64,
    pub mutation_fsync_completed_at_ms: u64,
    pub mutation_fstat_observed_at_ms: u64,
    pub mutated_readback_at_ms: u64,
    pub rollback_pwrite_started_at_ms: u64,
    pub rollback_pwrite_completed_at_ms: u64,
    pub rollback_fsync_completed_at_ms: u64,
    pub rollback_fstat_observed_at_ms: u64,
    pub rollback_readback_at_ms: u64,
    pub pwrite_bytes: u64,
    pub rollback_pwrite_bytes: u64,
    pub mutation_fsync_succeeded: bool,
    pub rollback_fsync_succeeded: bool,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardMutationHostEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

impl ShardMutationProof {
    pub fn validate_against_history(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported shard-mutation proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        validate_immutable_version_history(history, &self.identity)?;
        ensure!(
            self.identity.scenario == "on-disk-bitrot",
            "shard mutation proof is bound to the wrong scenario"
        );
        self.volume.validate()?;
        let mutation_target_proof = self.mutation_target_proof()?;
        self.mapping_source
            .validate_revision(&self.mapping_api_revision)?;
        for (field, value) in [
            ("mapping API revision", self.mapping_api_revision.as_str()),
            ("object key", self.object_key.as_str()),
            ("version id", self.version_id.as_str()),
            ("shard device id", self.shard_device_id.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "shard mutation {field} is empty");
        }
        ensure!(
            self.version_id != "null",
            "shard mutation requires an explicit non-null object version"
        );
        for (field, value) in [
            ("expected object", self.expected_object_sha256.as_str()),
            ("original shard", self.original_sha256.as_str()),
            ("mutated shard", self.mutated_sha256.as_str()),
        ] {
            validate_sha256(field, value)?;
        }
        validate_sha256("shard mapping response", &self.mapping_response_sha256)?;
        ensure!(
            self.mapping_response_sha256 == sha256_bytes(self.mapping_response_body.as_bytes()),
            "shard mapping response digest does not match the captured RustFS response body"
        );
        let mapping_response =
            serde_json::from_str::<RustfsShardMutationMappingResponse>(&self.mapping_response_body)
                .context("decode captured RustFS shard mutation mapping response")?;
        ensure!(
            mapping_response.bucket == self.identity.bucket
                && mapping_response.object_key == self.object_key
                && mapping_response.version_id == self.version_id
                && mapping_response.object_sha256 == self.expected_object_sha256
                && mapping_response.drive_uuid == self.volume.rustfs_drive_uuid
                && mapping_response.shard_path == self.shard_path
                && mapping_response.shard_device_id == self.shard_device_id
                && mapping_response.shard_inode == self.shard_inode
                && mapping_response.shard_size_bytes == self.shard_size_bytes,
            "shard mutation fields do not match the captured RustFS mapping response"
        );
        validate_sha256("rollback shard", &self.rollback.observed_sha256)?;
        validate_sha256(
            "shard path resolver evidence",
            &self.path_containment.resolver_evidence_sha256,
        )?;
        ensure!(
            self.path_containment.resolver_evidence_sha256
                == sha256_bytes(self.path_containment.resolver_response_body.as_bytes()),
            "shard path resolver digest does not match the captured openat2 receipt"
        );
        let path_receipt = serde_json::from_str::<Openat2PathResolutionReceipt>(
            &self.path_containment.resolver_response_body,
        )
        .context("decode captured openat2 shard path receipt")?;
        let _ = path_receipt.execution.validate_for(&self.volume)?;
        ensure!(
            self.shard_path
                .starts_with(&format!("{}/", self.volume.mount_path))
                && !self.shard_path.split('/').any(|part| part == ".."),
            "mapped shard path must be a normalized descendant of the proven volume mount"
        );
        ensure!(
            path_receipt.method == ShardPathResolutionMethod::Openat2BeneathNoSymlinksNoXdev
                && path_receipt.requested_path == self.shard_path
                && path_receipt.canonical_mount_path == self.volume.mount_path
                && path_receipt.mount_canonical_device == self.volume.canonical_device
                && path_receipt.mount_filesystem_uuid == self.volume.filesystem_uuid
                && path_receipt.resolved_path == self.shard_path
                && path_receipt.mount_device_id == self.shard_device_id
                && path_receipt.returned_fd_device_id == self.shard_device_id
                && path_receipt.returned_fd_inode == self.shard_inode
                && self.path_containment.observed_at_ms >= self.mapped_at_ms
                && self.path_containment.observed_at_ms <= self.mutated_at_ms
                && self.path_containment.target_proof_sha256 == self.volume.target_proof_sha256
                && self.path_containment.host_storage_proof_sha256
                    == self.volume.host_storage_proof_sha256,
            "shard path was not opened beneath the proven mount with no symlinks or device crossing"
        );
        ensure!(
            self.byte_length > 0,
            "shard mutation byte length must be positive"
        );
        let byte_end = self
            .byte_offset
            .checked_add(self.byte_length)
            .ok_or_else(|| anyhow::anyhow!("shard mutation byte range overflows"))?;
        ensure!(
            self.shard_inode > 0 && self.shard_size_bytes > 0 && byte_end <= self.shard_size_bytes,
            "shard mutation range must fall inside the proven non-empty shard inode"
        );
        let host_receipt = self.host_receipt()?;
        let _ = host_receipt.execution.validate_for(&self.volume)?;
        for (field, value) in [
            (
                "receipt original shard",
                host_receipt.original_sha256.as_str(),
            ),
            (
                "receipt mutated shard",
                host_receipt.mutated_sha256.as_str(),
            ),
            (
                "receipt rollback shard",
                host_receipt.rollback_sha256.as_str(),
            ),
        ] {
            validate_sha256(field, value)?;
        }
        ensure!(
            host_receipt.shard_path == self.shard_path
                && host_receipt.execution == path_receipt.execution
                && host_receipt.shard_device_id == self.shard_device_id
                && host_receipt.shard_inode == self.shard_inode
                && host_receipt.shard_size_bytes == self.shard_size_bytes
                && host_receipt.byte_offset == self.byte_offset
                && host_receipt.byte_length == self.byte_length
                && host_receipt.pwrite_bytes == self.byte_length
                && host_receipt.rollback_pwrite_bytes == self.byte_length
                && host_receipt.original_sha256 == self.original_sha256
                && host_receipt.mutated_sha256 == self.mutated_sha256
                && host_receipt.rollback_sha256 == self.rollback.observed_sha256
                && host_receipt.target_proof_sha256 == self.volume.target_proof_sha256
                && host_receipt.host_storage_proof_sha256 == self.volume.host_storage_proof_sha256
                && host_receipt.mutation_fsync_succeeded
                && host_receipt.rollback_fsync_succeeded,
            "shard mutation fields are not derived from a successful host-helper receipt for the proven inode"
        );
        ensure!(
            host_receipt.original_observed_at_ms >= self.path_containment.observed_at_ms
                && host_receipt.original_observed_at_ms < host_receipt.pwrite_completed_at_ms
                && host_receipt.pwrite_completed_at_ms
                    <= host_receipt.mutation_fsync_completed_at_ms
                && host_receipt.mutation_fsync_completed_at_ms
                    <= host_receipt.mutation_fstat_observed_at_ms
                && host_receipt.mutation_fstat_observed_at_ms
                    <= host_receipt.mutated_readback_at_ms
                && host_receipt.mutated_readback_at_ms == self.mutated_at_ms
                && host_receipt.mutated_readback_at_ms < host_receipt.rollback_pwrite_started_at_ms
                && host_receipt.rollback_pwrite_started_at_ms
                    <= host_receipt.rollback_pwrite_completed_at_ms
                && host_receipt.rollback_pwrite_completed_at_ms
                    <= host_receipt.rollback_fsync_completed_at_ms
                && host_receipt.rollback_fsync_completed_at_ms
                    <= host_receipt.rollback_fstat_observed_at_ms
                && host_receipt.rollback_fstat_observed_at_ms
                    <= host_receipt.rollback_readback_at_ms
                && host_receipt.rollback_readback_at_ms == self.rollback.observed_at_ms,
            "host-helper pwrite, fsync, fstat, readback, and rollback receipt is not strictly ordered"
        );
        ensure!(
            self.original_sha256 != self.mutated_sha256,
            "shard mutation did not change the shard hash"
        );
        ensure!(
            self.rollback.observed_sha256 == self.original_sha256
                && self.rollback.shard_path == self.shard_path
                && self.rollback.shard_device_id == self.shard_device_id
                && self.rollback.shard_inode == self.shard_inode
                && self.rollback.shard_size_bytes == self.shard_size_bytes
                && self.rollback.observed_at_ms > self.mutated_at_ms
                && self.rollback.target_proof_sha256 == self.volume.target_proof_sha256
                && self.rollback.host_storage_proof_sha256 == self.volume.host_storage_proof_sha256,
            "post-rollback observation does not prove restoration of the mutated shard and target"
        );
        ensure!(
            self.mapped_at_ms >= self.volume.observed_at_ms
                && mutation_target_proof.generated_at_ms == self.volume.observed_at_ms
                && self.mutated_at_ms >= self.mapped_at_ms
                && self.mutated_at_ms - self.mapped_at_ms <= STORAGE_OBSERVATION_MAX_AGE_MS,
            "shard mapping must be fresh and precede mutation"
        );
        let matching_history = history
            .iter()
            .filter(|record| {
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && matches!(
                        record.kind,
                        OperationKind::Put | OperationKind::CompleteMultipartUpload
                    )
                    && record.outcome == OperationOutcome::Ok
                    && record
                        .http_status
                        .is_some_and(|status| (200..300).contains(&status))
                    && record.key.as_deref() == Some(self.object_key.as_str())
                    && record.version_id.as_deref() == Some(self.version_id.as_str())
                    && valid_operation_interval(record)
                    && record.ended_at_ms <= self.mapped_at_ms
            })
            .collect::<Vec<_>>();
        let [committed_write] = matching_history.as_slice() else {
            anyhow::bail!(
                "shard mapping must match exactly one committed object version identity in workload history"
            )
        };
        ensure!(
            committed_write.value_sha256.as_deref() == Some(self.expected_object_sha256.as_str()),
            "committed object version identity has a conflicting content hash"
        );
        Ok(())
    }

    fn mutation_target_proof(&self) -> Result<TargetProof> {
        ensure!(
            self.volume.target_proof_sha256
                == sha256_bytes(self.mutation_target_proof_body.as_bytes()),
            "mutation target proof digest does not match captured target-proof.json"
        );
        let proof = serde_json::from_str::<TargetProof>(&self.mutation_target_proof_body)
            .context("decode captured mutation target-proof.json")?;
        ensure!(
            proof.schema_version == TARGET_PROOF_SCHEMA_VERSION
                && proof.status == TargetProofStatus::Satisfied
                && proof.run_id == self.identity.run_id
                && proof.scenario == self.identity.scenario
                && proof.case_name == self.identity.case_name
                && proof.namespace == self.volume.namespace
                && proof.tenant == self.volume.tenant
                && proof.generated_at_ms > 0
                && proof.generated_at_ms <= self.mapped_at_ms
                && self.mapped_at_ms - proof.generated_at_ms <= STORAGE_OBSERVATION_MAX_AGE_MS
                && !proof.requirements.is_empty()
                && proof
                    .requirements
                    .iter()
                    .all(|requirement| requirement.status == PreflightStatus::Passed),
            "mutation target proof has the wrong identity, status, or pre-mutation interval"
        );
        let matching_pods = proof
            .resolved_pods
            .iter()
            .filter(|pod| pod.name == self.volume.pod)
            .collect::<Vec<_>>();
        let [pod] = matching_pods.as_slice() else {
            anyhow::bail!("mutation target proof must contain exactly one target Pod")
        };
        let matching_mounts = pod
            .volume_mounts
            .iter()
            .filter(|mount| {
                mount.container_name == "rustfs"
                    && mount.volume_name == self.volume.volume_name
                    && mount.mount_path == self.volume.mount_path
                    && mount.persistent_volume_claim.as_deref()
                        == Some(self.volume.persistent_volume_claim.as_str())
            })
            .collect::<Vec<_>>();
        ensure!(
            matching_mounts.len() == 1,
            "mutation target proof does not bind one exact RustFS volume mount"
        );
        let matching_claims = pod
            .persistent_volume_claims
            .iter()
            .filter(|claim| claim.name == self.volume.persistent_volume_claim)
            .collect::<Vec<_>>();
        let [claim] = matching_claims.as_slice() else {
            anyhow::bail!("mutation target proof must contain exactly one target PVC")
        };
        let persistent_volume = claim
            .persistent_volume
            .as_ref()
            .context("mutation target PVC is not bound to a PV")?;
        ensure!(
            pod.ready
                && pod.uid == self.volume.pod_uid
                && pod.rustfs_container_id.as_deref()
                    == Some(self.volume.rustfs_container_id.as_str())
                && pod.node.as_deref() == Some(self.volume.node.as_str())
                && claim.uid == self.volume.persistent_volume_claim_uid
                && claim.storage_class.as_deref() == Some(self.volume.storage_class.as_str())
                && claim.volume_name.as_deref() == Some(self.volume.persistent_volume.as_str())
                && persistent_volume.name == self.volume.persistent_volume
                && persistent_volume.uid == self.volume.persistent_volume_uid
                && persistent_volume.source.as_deref() == Some("local")
                && persistent_volume.node.as_deref() == Some(self.volume.node.as_str())
                && persistent_volume.device_or_path.as_deref()
                    == Some(self.volume.local_volume_path.as_str()),
            "mutation target Pod/PVC/PV generation differs from the captured storage identity"
        );
        let matching_topologies = proof
            .faults
            .iter()
            .filter(|fault| {
                fault.kind == "rustfs-on-disk-bitrot"
                    && fault.backend == "host"
                    && fault.target_kind == "rustfs-shard"
                    && fault.selection_kind == "fixed-targets"
                    && fault.selection_value == 1
            })
            .filter_map(|fault| fault.erasure_set.as_ref())
            .filter(|topology| {
                topology.required
                    && topology.resolved
                    && topology.source.as_deref() == Some("rustfs-admin-server-info")
                    && topology.deployment_id.as_deref()
                        == Some(self.volume.rustfs_deployment_id.as_str())
                    && topology.observed_at_ms > 0
                    && topology.observed_at_ms <= proof.generated_at_ms
                    && topology.shape.as_ref().is_some_and(|shape| {
                        shape.pool_index == self.volume.pool_index
                            && shape.set_index == self.volume.set_index
                    })
            })
            .collect::<Vec<_>>();
        let [topology] = matching_topologies.as_slice() else {
            anyhow::bail!(
                "mutation target proof does not contain one matching RustFS erasure-set topology"
            )
        };
        let shape = topology
            .shape
            .as_ref()
            .context("mutation target proof lacks erasure-set shape")?;
        let membership = topology
            .membership
            .as_ref()
            .context("mutation target proof lacks erasure-set membership")?;
        shape.validate()?;
        membership.validate(shape)?;
        topology
            .health
            .context("mutation target proof lacks erasure-set health")?
            .require_all_online(shape.total_shards)?;
        let matching_members = membership
            .members
            .iter()
            .filter(|member| member.pod_name == self.volume.pod)
            .collect::<Vec<_>>();
        let [member] = matching_members.as_slice() else {
            anyhow::bail!("mutation target proof must map one erasure-set member to the target Pod")
        };
        ensure!(
            member.shard_ids == [self.volume.rustfs_drive_uuid.clone()],
            "mutation target proof does not derive the selected RustFS drive from membership"
        );
        Ok(proof)
    }

    fn host_receipt(&self) -> Result<ShardMutationHostReceipt> {
        let host_evidence = self
            .host_mutation_evidence
            .as_ref()
            .context("shard mutation lacks a captured host-helper receipt")?;
        validate_sha256("host mutation receipt", &host_evidence.response_sha256)?;
        ensure!(
            host_evidence.response_sha256 == sha256_bytes(host_evidence.response_body.as_bytes()),
            "host mutation receipt digest does not match its captured body"
        );
        serde_json::from_str::<ShardMutationHostReceipt>(&host_evidence.response_body)
            .context("decode captured shard-mutation host-helper receipt")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealMode {
    AutomaticReplacement,
    AutomaticScanner,
    AdminDeep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum HealObserverIdentity {
    ReplacementTask {
        task_id: String,
        generation: Option<String>,
    },
    ScannerStatus {
        status_cursor: String,
    },
    AdminOperation {
        operation_id: String,
    },
}

impl HealObserverIdentity {
    fn validate_for_mode(&self, mode: HealMode) -> Result<()> {
        match (mode, self) {
            (
                HealMode::AutomaticReplacement,
                Self::ReplacementTask {
                    task_id,
                    generation,
                },
            ) => ensure!(
                !task_id.trim().is_empty()
                    && generation
                        .as_deref()
                        .is_some_and(|generation| !generation.trim().is_empty()),
                "automatic replacement requires a task id and captured generation"
            ),
            (HealMode::AutomaticScanner, Self::ScannerStatus { status_cursor }) => ensure!(
                !status_cursor.trim().is_empty(),
                "automatic scanner requires a status cursor"
            ),
            (HealMode::AdminDeep, Self::AdminOperation { operation_id }) => ensure!(
                !operation_id.trim().is_empty(),
                "admin heal requires an operation id"
            ),
            _ => anyhow::bail!("heal observer kind does not match the selected heal mode"),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HealProgressState {
    Queued,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealProgressSample {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub observer: HealObserverIdentity,
    pub observed_at_ms: u64,
    pub state: HealProgressState,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub status_evidence: Option<HealStatusEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealStatusEvidence {
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsHealStatusResponse {
    pub observer: HealObserverIdentity,
    pub observed_at_ms: u64,
    pub state: HealProgressState,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub cluster_definitive: bool,
    pub target_drive_uuid: Option<String>,
    pub pool_index: u32,
    pub set_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealSummary {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub case: StorageRecoveryCase,
    pub observer: HealObserverIdentity,
    pub mode: HealMode,
    pub target_drive_uuid: Option<String>,
    pub pool_index: u32,
    pub set_index: u32,
    pub cluster_definitive: bool,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub state: HealProgressState,
}

impl HealSummary {
    pub fn validate_progress(
        &self,
        samples: &[HealProgressSample],
        expected_target: Option<(&str, u32, u32)>,
    ) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported heal-summary schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        ensure!(
            self.case.scenario() == self.identity.scenario
                && self.case.heal_mode() == Some(self.mode),
            "heal case, scenario identity, and mode do not identify the same qualified variant"
        );
        self.observer.validate_for_mode(self.mode)?;
        ensure!(
            self.cluster_definitive,
            "heal status must be reported by a cluster-definitive observer"
        );
        match (
            self.mode,
            expected_target,
            self.target_drive_uuid.as_deref(),
        ) {
            (
                HealMode::AutomaticReplacement | HealMode::AdminDeep,
                Some((expected_drive, expected_pool, expected_set)),
                Some(actual_drive),
            ) => ensure!(
                !expected_drive.trim().is_empty()
                    && actual_drive == expected_drive
                    && self.pool_index == expected_pool
                    && self.set_index == expected_set,
                "heal target does not match the replacement or mutation evidence"
            ),
            (HealMode::AutomaticScanner, None, None) => {}
            _ => anyhow::bail!(
                "heal mode has an incompatible target contract; replacement/admin heals are target-specific while scanner status is aggregate"
            ),
        }
        ensure!(
            self.started_at_ms > 0 && self.completed_at_ms >= self.started_at_ms,
            "heal summary timestamps are not ordered"
        );
        ensure!(
            self.state == HealProgressState::Completed && self.failed == 0,
            "heal did not reach a successful terminal state"
        );
        if self.mode != HealMode::AutomaticReplacement {
            ensure!(
                self.scanned > 0 && self.repaired > 0,
                "scanner/admin heal requires positive scanned and repaired counters"
            );
        }
        ensure!(!samples.is_empty(), "heal progress has no samples");

        let mut previous: Option<&HealProgressSample> = None;
        for sample in samples {
            ensure!(
                sample.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION
                    && sample.identity == self.identity,
                "heal progress identity or schema does not match the summary"
            );
            ensure!(
                sample.observer == self.observer,
                "heal progress observer identity does not match the summary"
            );
            let status_evidence = sample
                .status_evidence
                .as_ref()
                .context("heal progress sample lacks a captured RustFS status response")?;
            ensure!(
                !status_evidence.api_revision.trim().is_empty(),
                "heal progress status response lacks an API revision"
            );
            validate_sha256("heal status response", &status_evidence.response_sha256)?;
            ensure!(
                status_evidence.response_sha256
                    == sha256_bytes(status_evidence.response_body.as_bytes()),
                "heal status response digest does not match its captured body"
            );
            let response =
                serde_json::from_str::<RustfsHealStatusResponse>(&status_evidence.response_body)
                    .context("decode captured RustFS heal status response")?;
            ensure!(
                response.observer == sample.observer
                    && response.observed_at_ms == sample.observed_at_ms
                    && response.state == sample.state
                    && response.scanned == sample.scanned
                    && response.repaired == sample.repaired
                    && response.failed == sample.failed
                    && response.cluster_definitive == self.cluster_definitive
                    && response.target_drive_uuid == self.target_drive_uuid
                    && response.pool_index == self.pool_index
                    && response.set_index == self.set_index,
                "heal progress fields are not derived from the captured RustFS status response"
            );
            ensure!(
                sample.observed_at_ms >= self.started_at_ms
                    && sample.observed_at_ms <= self.completed_at_ms,
                "heal progress timestamp falls outside the operation window"
            );
            if let Some(previous) = previous {
                ensure!(
                    sample.observed_at_ms >= previous.observed_at_ms
                        && sample.scanned >= previous.scanned
                        && sample.repaired >= previous.repaired
                        && sample.failed >= previous.failed,
                    "heal progress timestamps and counters must be monotonic"
                );
                ensure!(
                    previous.state != HealProgressState::Completed
                        && previous.state != HealProgressState::Failed,
                    "heal progress contains samples after a terminal state"
                );
                ensure!(
                    heal_state_rank(sample.state) >= heal_state_rank(previous.state),
                    "heal progress state regressed"
                );
            }
            previous = Some(sample);
        }

        let last = samples.last().expect("non-empty checked above");
        ensure!(
            last.state == self.state
                && last.observed_at_ms == self.completed_at_ms
                && last.scanned == self.scanned
                && last.repaired == self.repaired
                && last.failed == self.failed,
            "heal summary does not match the terminal progress sample"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForcedReadProbe {
    pub operation_id: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_sha256: String,
    pub observed_sha256: String,
    pub http_status: u16,
    pub observed_at_ms: u64,
    pub mapping_observation_id: String,
    pub active_fault_snapshot_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OfflineVersionShardMappingEvidence {
    pub context: Box<OwnedStorageContext>,
    pub inspection_receipt: Box<StorageRecoveryOperationReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionShardMappingObservation {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub observation_id: String,
    pub source: ShardMappingSource,
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_evidence: Option<Box<OfflineVersionShardMappingEvidence>>,
    pub target_proof_sha256: String,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsVersionShardMappingResponse {
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub object_sha256: String,
    pub pool_index: u32,
    pub set_index: u32,
    pub shard_ids: Vec<String>,
}

impl VersionShardMappingObservation {
    pub fn validated_mapping(
        &self,
        membership: &ErasureSetMembership,
        shape: &ErasureSetShape,
    ) -> Result<RustfsVersionShardMappingResponse> {
        self.source.validate_revision(&self.api_revision)?;
        validate_sha256("version-shard mapping response", &self.response_sha256)?;
        validate_sha256(
            "version-shard mapping target proof",
            &self.target_proof_sha256,
        )?;
        ensure!(
            self.response_sha256 == sha256_bytes(self.response_body.as_bytes())
                && self.observed_at_ms > 0,
            "version-shard mapping source body or observation timestamp is invalid"
        );
        match self.source {
            ShardMappingSource::RustfsDiagnosticApi => {
                ensure!(
                    self.offline_evidence.is_none(),
                    "RustFS diagnostic mapping must not carry offline inspector evidence"
                );
                serde_json::from_str(&self.response_body)
                    .context("decode captured RustFS version-shard mapping response")
            }
            ShardMappingSource::OfflineXl2Inspector => {
                let evidence = self.offline_evidence.as_deref().context(
                    "offline version-shard mapping lacks its helper receipt and context",
                )?;
                let context = evidence.context.as_ref();
                let receipt = evidence.inspection_receipt.as_ref();
                context.validate()?;
                receipt.validate_for(context, &receipt.operation)?;
                let StorageRecoveryHostOperation::InspectXlMeta {
                    bucket,
                    object_key,
                    object_sha256,
                    version_id,
                    selected_part_number,
                    expected_mount_device_id,
                    expected_drive_uuid,
                    ..
                } = &receipt.operation
                else {
                    anyhow::bail!("offline version-shard mapping receipt is not an XL2 inspection")
                };
                ensure!(
                    context.identity == self.identity
                        && context.identity.scenario == context.case.scenario()
                        && context.volume.target_proof_sha256 == self.target_proof_sha256
                        && receipt.completed_at_ms == self.observed_at_ms
                        && receipt.response_sha256 == self.response_sha256
                        && receipt.response_body == self.response_body,
                    "offline version-shard mapping is not bound to its exact context and helper receipt"
                );
                let response =
                    serde_json::from_str::<OfflineXl2InspectResponse>(&receipt.response_body)
                        .context("decode receipt-bound offline XL2 inspection response")?;
                validate_sha256("offline format.json", &response.format_json_sha256)?;
                validate_sha256("offline xl.meta", &response.xl_meta_sha256)?;
                ensure!(
                    bucket == &self.identity.bucket
                        && version_id == &response.layout.version_id
                        && response.layout.inspector_revision == self.api_revision
                        && expected_mount_device_id == &response.mount_device_id
                        && expected_mount_device_id == &context.host_generation.device_major_minor
                        && expected_drive_uuid == &response.drive_uuid
                        && expected_drive_uuid == &context.volume.rustfs_drive_uuid
                        && response.selected_part.part_number == *selected_part_number
                        && response.selected_part.shard_device_id
                            == context.host_generation.device_major_minor
                        && response.selected_part.shard_inode > 0
                        && response.selected_part.shard_size_bytes > 0
                        && context.volume.pool_index == shape.pool_index
                        && context.volume.set_index == shape.set_index,
                    "offline XL2 receipt does not identify the mapped object, drive, or erasure set"
                );
                validate_sha256(
                    "offline selected shard preimage",
                    &response.selected_part.original_sha256,
                )?;
                let selected_path = response
                    .layout
                    .part_numbers
                    .iter()
                    .position(|part| part == selected_part_number)
                    .and_then(|index| response.layout.relative_part_paths.get(index));
                ensure!(
                    selected_path == Some(&response.selected_part.relative_part_path),
                    "offline XL2 receipt selected shard is not present in the inspected layout"
                );
                let shard_ids = membership
                    .members
                    .iter()
                    .flat_map(|member| member.shard_ids.iter().cloned())
                    .collect::<Vec<_>>();
                let total = response
                    .layout
                    .erasure_data_shards
                    .checked_add(response.layout.erasure_parity_shards)
                    .context("offline XL2 erasure width overflow")?;
                ensure!(
                    usize::try_from(total)? == shard_ids.len()
                        && response.layout.erasure_index > 0
                        && response.layout.erasure_index <= total
                        && shard_ids
                            .iter()
                            .filter(|id| *id == &response.drive_uuid)
                            .count()
                            == 1,
                    "offline XL2 layout does not match authenticated runtime membership"
                );
                Ok(RustfsVersionShardMappingResponse {
                    bucket: bucket.clone(),
                    object_key: object_key.clone(),
                    version_id: version_id.clone(),
                    object_sha256: object_sha256.clone(),
                    pool_index: context.volume.pool_index,
                    set_index: context.volume.set_index,
                    shard_ids,
                })
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnavailableShardObservation {
    pub pod_name: String,
    pub drive_uuid: String,
    pub pool_index: u32,
    pub set_index: u32,
    pub fault_resource_id: String,
    pub active_snapshot_id: String,
    pub target_proof_sha256: String,
    pub fault_evidence_sha256: String,
    pub active_from_ms: u64,
    pub active_until_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForceReadThroughProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub shape: ErasureSetShape,
    pub persisted_version_class: PersistedVersionClass,
    pub all_shard_ids: Vec<String>,
    pub repaired_shard_id: String,
    pub target_proof_sha256: String,
    pub fault_evidence_sha256: String,
    pub fault_evidence_body: Option<String>,
    pub unavailable_shards: Vec<UnavailableShardObservation>,
    pub fault_active_from_ms: u64,
    pub fault_active_until_ms: u64,
    pub probes: Vec<ForcedReadProbe>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForceReadTargetIdentity {
    pod_uid: String,
    rustfs_container_id: String,
    drive_uuid: String,
}

/// Exact IOChaos behavior required while proving reads through a repaired drive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForceReadRuntimeParameters {
    pub chaos_namespace: String,
    pub action: IoChaosAction,
    pub methods: Vec<String>,
    pub io_sampling_percent: u8,
    pub duration_seconds: u64,
}

/// Opaque validated view of target-proof.json plus the active fault artifact.
#[derive(Debug, Clone)]
pub struct ForceReadRuntimeEvidenceContract {
    target_proof_sha256: String,
    target_proof: TargetProof,
    verified_fault_evidence_sha256: String,
    parameters: ForceReadRuntimeParameters,
}

impl ForceReadRuntimeEvidenceContract {
    /// Parses the captured target proof so callers cannot supply volume identities separately.
    pub fn from_artifacts(
        target_proof_body: &str,
        verified_fault_evidence_sha256: &str,
        parameters: ForceReadRuntimeParameters,
    ) -> Result<Self> {
        validate_sha256(
            "verified force-read fault evidence",
            verified_fault_evidence_sha256,
        )?;
        let target_proof = serde_json::from_str::<TargetProof>(target_proof_body)
            .context("decode captured force-read target-proof.json")?;
        ensure!(
            target_proof.schema_version == TARGET_PROOF_SCHEMA_VERSION
                && target_proof.status == TargetProofStatus::Satisfied
                && target_proof.generated_at_ms > 0
                && !target_proof.requirements.is_empty()
                && target_proof
                    .requirements
                    .iter()
                    .all(|requirement| requirement.status == PreflightStatus::Passed),
            "force-read target proof is not a satisfied current target-proof contract"
        );
        ensure!(
            matches!(parameters.action, IoChaosAction::Fault { errno } if errno != 0)
                && parameters.io_sampling_percent == 100
                && parameters.duration_seconds > 0
                && parameters.methods == ["READ"],
            "force-read runtime must inject a nonzero I/O fault into every READ for a positive duration"
        );
        ensure!(
            !parameters.chaos_namespace.trim().is_empty(),
            "force-read Chaos Mesh namespace is empty"
        );
        Ok(Self {
            target_proof_sha256: sha256_bytes(target_proof_body.as_bytes()),
            target_proof,
            verified_fault_evidence_sha256: verified_fault_evidence_sha256.to_string(),
            parameters,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StorageFaultPodIdentity {
    name: String,
    uid: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StorageFaultStatusSnapshot {
    stage: String,
    resource_kind: Option<String>,
    resource_name: Option<String>,
    chaos_status: Option<serde_json::Value>,
    dm_status: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct StorageFaultEvidenceResponse {
    scenario: String,
    run_id: String,
    injected: bool,
    active_during_workload: bool,
    pods_at_fault_activation: Vec<StorageFaultPodIdentity>,
    pods_at_workload_snapshot: Vec<StorageFaultPodIdentity>,
    fixed_volume_targets_at_fault_activation: Vec<String>,
    fixed_volume_targets_at_workload_snapshot: Vec<String>,
    fixed_volume_containers_at_fault_activation: BTreeMap<String, String>,
    fixed_volume_containers_at_workload_snapshot: BTreeMap<String, String>,
    active_snapshots: Vec<StorageFaultStatusSnapshot>,
    workload_snapshots: Vec<StorageFaultStatusSnapshot>,
    fault_active_at_ms: Option<u64>,
    workload_started_at_ms: Option<u64>,
    workload_ended_at_ms: Option<u64>,
    fault_delete_started_at_ms: Option<u64>,
}

struct ValidatedForceReadFaultEvidence {
    targets: BTreeMap<String, ForceReadTargetIdentity>,
    snapshot_id: String,
    resource_id: String,
}

#[derive(Debug)]
struct ValidatedForceReadTargetProof {
    namespace: String,
    tenant: String,
    volume_path: String,
    expected_targets: u32,
    candidates: BTreeMap<String, ForceReadTargetIdentity>,
}

impl ForceReadThroughProof {
    pub fn validate_against_runtime(
        &self,
        membership: &ErasureSetMembership,
        runtime: &ForceReadRuntimeEvidenceContract,
        expected_repaired_shard_id: &str,
        history: &[OperationRecord],
        mapping_observations: &[VersionShardMappingObservation],
    ) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported force-read proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        validate_immutable_version_history(history, &self.identity)?;
        ensure!(
            matches!(
                self.identity.scenario.as_str(),
                "fresh-volume-replacement" | "on-disk-bitrot"
            ),
            "force-read proof is bound to a scenario without a repaired drive"
        );
        self.shape.validate()?;
        membership.validate(&self.shape)?;
        validate_sha256("target proof", &self.target_proof_sha256)?;
        validate_sha256("fault evidence", &self.fault_evidence_sha256)?;
        let fault_evidence = self.validate_fault_evidence(membership, runtime)?;
        let evidence_pods = fault_evidence
            .targets
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            self.persisted_version_class == PersistedVersionClass::DataObject,
            "force-read heal proof requires a data-bearing object version"
        );
        validate_unique_nonempty("erasure shard id", &self.all_shard_ids, true)?;
        ensure!(
            self.all_shard_ids.len() == usize::try_from(self.shape.total_shards)?,
            "force-read proof shard inventory does not match the erasure-set width"
        );
        let membership_shards = membership
            .members
            .iter()
            .flat_map(|member| member.shard_ids.iter())
            .collect::<BTreeSet<_>>();
        ensure!(
            self.all_shard_ids.iter().collect::<BTreeSet<_>>() == membership_shards,
            "force-read shard inventory does not match runtime erasure-set membership"
        );
        ensure!(
            !expected_repaired_shard_id.trim().is_empty()
                && self.repaired_shard_id == expected_repaired_shard_id
                && self.all_shard_ids.contains(&self.repaired_shard_id),
            "repaired shard does not match the replacement/mutation evidence or is outside the proven erasure set"
        );
        let unavailable_ids = self
            .unavailable_shards
            .iter()
            .map(|observation| observation.drive_uuid.clone())
            .collect::<Vec<_>>();
        validate_unique_nonempty("unavailable shard id", &unavailable_ids, true)?;
        let all = self.all_shard_ids.iter().collect::<BTreeSet<_>>();
        let unavailable = unavailable_ids.iter().collect::<BTreeSet<_>>();
        ensure!(
            unavailable.is_subset(&all) && !unavailable.contains(&self.repaired_shard_id),
            "force-read unavailable set is invalid or contains the repaired shard"
        );
        let quorum = QuorumRequirements::for_persisted_version(
            self.shape.total_shards,
            self.shape.payload_parity_shards,
            self.persisted_version_class,
        )?;
        ensure!(
            self.unavailable_shards.len() == usize::try_from(quorum.read_tolerance)?,
            "force-read proof must leave exactly read quorum online"
        );
        ensure!(
            self.fault_active_from_ms > 0 && self.fault_active_until_ms > self.fault_active_from_ms,
            "force-read fault-active window is invalid"
        );
        ensure!(
            !self.probes.is_empty(),
            "force-read proof contains no S3 reads"
        );
        let mut mappings_by_id = BTreeMap::new();
        let mut mapping_ids = BTreeSet::new();
        for mapping in mapping_observations {
            ensure!(
                mapping.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION
                    && mapping.identity == self.identity
                    && !mapping.observation_id.trim().is_empty()
                    && mapping_ids.insert(mapping.observation_id.as_str()),
                "version-shard mapping has a mismatched schema/identity or duplicate observation id"
            );
            ensure!(
                mapping.target_proof_sha256 == self.target_proof_sha256
                    && mapping.observed_at_ms > 0
                    && mapping.observed_at_ms >= runtime.target_proof.generated_at_ms
                    && mapping.observed_at_ms < self.fault_active_from_ms
                    && self.fault_active_from_ms - mapping.observed_at_ms
                        <= STORAGE_OBSERVATION_MAX_AGE_MS,
                "version-shard mapping is not a fresh pre-fault observation"
            );
            mapping.source.validate_revision(&mapping.api_revision)?;
            validate_sha256("version-shard mapping response", &mapping.response_sha256)?;
            ensure!(
                mapping.response_sha256 == sha256_bytes(mapping.response_body.as_bytes()),
                "version-shard mapping response digest does not match the captured source body"
            );
            validate_sha256(
                "version-shard mapping target proof",
                &mapping.target_proof_sha256,
            )?;
            let response = mapping.validated_mapping(membership, &self.shape)?;
            ensure!(
                !response.object_key.trim().is_empty()
                    && !response.version_id.trim().is_empty()
                    && response.version_id != "null",
                "captured RustFS version-shard mapping response lacks object/version identity"
            );
            validate_sha256("version-shard mapping object", &response.object_sha256)?;
            validate_unique_nonempty("version-shard mapping shard id", &response.shard_ids, true)?;
            mappings_by_id.insert(mapping.observation_id.as_str(), (mapping, response));
        }
        let mut snapshot_ids = BTreeSet::new();
        let target_pods = evidence_pods;
        let selected_membership_shards = membership
            .members
            .iter()
            .filter(|member| target_pods.contains(member.pod_name.as_str()))
            .flat_map(|member| member.shard_ids.iter())
            .collect::<BTreeSet<_>>();
        let unavailable_pods = self
            .unavailable_shards
            .iter()
            .map(|observation| observation.pod_name.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            unavailable_pods == target_pods && selected_membership_shards == unavailable,
            "unavailable drives are not the shards owned by the Pods selected in target proof and active fault evidence"
        );
        for observation in &self.unavailable_shards {
            snapshot_ids.insert(observation.active_snapshot_id.as_str());
            let matching_members = membership
                .members
                .iter()
                .filter(|member| member.pod_name == observation.pod_name)
                .collect::<Vec<_>>();
            let [member] = matching_members.as_slice() else {
                anyhow::bail!(
                    "unavailable shard observation must match exactly one erasure-set member Pod"
                )
            };
            let runtime_target = fault_evidence
                .targets
                .get(&observation.pod_name)
                .context("unavailable shard lacks a validated runtime target identity")?;
            ensure!(
                !observation.pod_name.trim().is_empty()
                    && member.shard_ids.contains(&observation.drive_uuid)
                    && runtime_target.drive_uuid == observation.drive_uuid
                    && observation.pool_index == self.shape.pool_index
                    && observation.set_index == self.shape.set_index
                    && observation.fault_resource_id == fault_evidence.resource_id
                    && observation.active_snapshot_id == fault_evidence.snapshot_id
                    && observation.active_from_ms <= self.fault_active_from_ms
                    && observation.active_until_ms >= self.fault_active_until_ms
                    && observation.target_proof_sha256 == self.target_proof_sha256
                    && observation.fault_evidence_sha256 == self.fault_evidence_sha256,
                "unavailable shard is not bound to its owning Pod and a unique active fault spanning the force-read window in the repaired set"
            );
        }
        ensure!(
            snapshot_ids.len() == 1,
            "force-read unavailable shards were not proven active in one atomic snapshot"
        );
        let mut history_by_operation_id = HashMap::new();
        let mut committed_writes_by_version = HashMap::new();
        for record in history {
            history_by_operation_id
                .entry(record.id.as_str())
                .or_insert_with(Vec::new)
                .push(record);
            if record_matches_identity(record, &self.identity)
                && is_object_commit(record.kind)
                && record.outcome == OperationOutcome::Ok
                && record
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
                && record.durability_cohort == Some(DurabilityCohort::PreFault)
                && matches!(
                    record.fault_window_relation,
                    None | Some(FaultWindowRelation::BeforeFault)
                )
                && valid_operation_interval(record)
                && record.ended_at_ms < self.fault_active_from_ms
                && let (Some(key), Some(version_id)) =
                    (record.key.as_deref(), record.version_id.as_deref())
            {
                committed_writes_by_version
                    .entry((key, version_id))
                    .or_insert_with(Vec::new)
                    .push(record);
            }
        }
        let mut probe_operation_ids = BTreeSet::new();
        let mut used_mapping_ids = BTreeSet::new();
        for probe in &self.probes {
            ensure!(
                !probe.operation_id.trim().is_empty()
                    && probe_operation_ids.insert(probe.operation_id.as_str())
                    && !probe.object_key.trim().is_empty()
                    && !probe.version_id.trim().is_empty(),
                "force-read probe lacks object/version identity"
            );
            validate_sha256("force-read expected object", &probe.expected_sha256)?;
            validate_sha256("force-read observed object", &probe.observed_sha256)?;
            ensure!(
                (200..300).contains(&probe.http_status)
                    && probe.expected_sha256 == probe.observed_sha256,
                "force-read probe did not return the expected object bytes"
            );
            ensure!(
                probe.version_id != "null"
                    && !probe.mapping_observation_id.trim().is_empty()
                    && snapshot_ids.contains(probe.active_fault_snapshot_id.as_str()),
                "force-read probe lacks an authoritative mapping or active fault snapshot"
            );
            let (mapping, response) = mappings_by_id
                .get(probe.mapping_observation_id.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "force-read probe references an unknown version-shard mapping observation"
                    )
                })?;
            ensure!(
                used_mapping_ids.insert(mapping.observation_id.as_str())
                    && response.bucket == self.identity.bucket
                    && response.object_key == probe.object_key
                    && response.version_id == probe.version_id
                    && response.object_sha256 == probe.expected_sha256
                    && response.pool_index == self.shape.pool_index
                    && response.set_index == self.shape.set_index
                    && response.shard_ids.iter().collect::<BTreeSet<_>>() == all
                    && response.shard_ids.len() == self.all_shard_ids.len(),
                "force-read probe is not uniquely mapped by RustFS diagnostics to the repaired erasure set"
            );
            ensure!(
                probe.observed_at_ms > self.fault_active_from_ms
                    && probe.observed_at_ms < self.fault_active_until_ms,
                "force-read probe falls outside the exact-quorum fault-active window"
            );
            let Some(committed_writes) = committed_writes_by_version
                .get(&(probe.object_key.as_str(), probe.version_id.as_str()))
            else {
                anyhow::bail!(
                    "force-read probe must match exactly one successful pre-fault object version identity"
                )
            };
            let [committed_write] = committed_writes.as_slice() else {
                anyhow::bail!(
                    "force-read probe must match exactly one successful pre-fault object version identity"
                )
            };
            ensure!(
                committed_write.value_sha256.as_deref() == Some(probe.expected_sha256.as_str()),
                "force-read object version identity has a conflicting committed content hash"
            );
            ensure!(
                mapping.observed_at_ms >= committed_write.ended_at_ms,
                "version-shard mapping was observed before the committed object version existed"
            );
            let Some(matching_history) = history_by_operation_id.get(probe.operation_id.as_str())
            else {
                anyhow::bail!("force-read probe must match exactly one workload history record")
            };
            let [record] = matching_history.as_slice() else {
                anyhow::bail!("force-read probe must match exactly one workload history record")
            };
            ensure!(
                record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.scenario == self.identity.scenario
                    && record.bucket == self.identity.bucket
                    && record.kind == OperationKind::Get
                    && record.outcome == OperationOutcome::Ok
                    && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                    && record.fault_window_relation == Some(FaultWindowRelation::DuringFault)
                    && record.http_status == Some(probe.http_status)
                    && record.key.as_deref() == Some(probe.object_key.as_str())
                    && record.version_id.as_deref() == Some(probe.version_id.as_str())
                    && record.value_sha256.as_deref() == Some(probe.observed_sha256.as_str())
                    && valid_operation_interval(record)
                    && record.started_at_ms < record.ended_at_ms
                    && record.started_at_ms > self.fault_active_from_ms
                    && record.ended_at_ms < self.fault_active_until_ms
                    && record.ended_at_ms == probe.observed_at_ms,
                "force-read probe does not match its successful versioned GET in workload history"
            );
        }
        ensure!(
            used_mapping_ids == mappings_by_id.keys().copied().collect::<BTreeSet<_>>(),
            "force-read proof does not consume the exact version-shard mapping evidence set"
        );
        Ok(())
    }

    fn validate_fault_evidence(
        &self,
        membership: &ErasureSetMembership,
        runtime: &ForceReadRuntimeEvidenceContract,
    ) -> Result<ValidatedForceReadFaultEvidence> {
        let target_proof = self.validate_target_proof(membership, runtime)?;
        ensure!(
            runtime.target_proof_sha256 == self.target_proof_sha256,
            "force-read proof is not bound to its captured target-proof.json"
        );
        ensure!(
            runtime.verified_fault_evidence_sha256 == self.fault_evidence_sha256,
            "force-read proof is not bound to the fault evidence validated by the outer artifact contract"
        );
        let body = self
            .fault_evidence_body
            .as_deref()
            .context("force-read proof lacks captured fault-evidence.json")?;
        ensure!(
            self.fault_evidence_sha256 == sha256_bytes(body.as_bytes()),
            "force-read fault-evidence digest does not match its captured body"
        );
        let evidence = serde_json::from_str::<StorageFaultEvidenceResponse>(body)
            .context("decode captured force-read fault evidence")?;
        ensure!(
            evidence.run_id == self.identity.run_id
                && evidence.scenario == self.identity.scenario
                && evidence.injected
                && evidence.active_during_workload,
            "force-read fault evidence is not the active fault from this scenario run"
        );
        let active_at = evidence
            .fault_active_at_ms
            .context("force-read fault evidence lacks activation time")?;
        let workload_started = evidence
            .workload_started_at_ms
            .context("force-read fault evidence lacks workload start time")?;
        let workload_ended = evidence
            .workload_ended_at_ms
            .context("force-read fault evidence lacks workload end time")?;
        let delete_started = evidence
            .fault_delete_started_at_ms
            .context("force-read fault evidence lacks fault-delete start time")?;
        ensure!(
            active_at == self.fault_active_from_ms
                && delete_started == self.fault_active_until_ms
                && active_at <= workload_started
                && workload_started < workload_ended
                && workload_ended <= delete_started,
            "force-read window is not derived from the captured fault lifecycle"
        );
        let active_pods =
            unique_storage_fault_pods("activation", &evidence.pods_at_fault_activation)?;
        let workload_pods =
            unique_storage_fault_pods("workload", &evidence.pods_at_workload_snapshot)?;
        let expected_pods = active_pods
            .keys()
            .map(|pod_name| {
                let target = target_proof
                    .candidates
                    .get(pod_name)
                    .context("force-read IOChaos selected a Pod absent from target-proof.json")?;
                Ok((pod_name.clone(), target.pod_uid.as_str()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(
            active_pods.len() == usize::try_from(target_proof.expected_targets)?
                && active_pods == workload_pods
                && active_pods == expected_pods,
            "force-read selected Pod identities changed or differ from the validated target proof"
        );
        let selected_targets = active_pods
            .keys()
            .map(|pod_name| {
                let target = target_proof
                    .candidates
                    .get(pod_name)
                    .expect("selected target was resolved above")
                    .clone();
                (pod_name.clone(), target)
            })
            .collect::<BTreeMap<_, _>>();
        let expected_containers = selected_targets
            .iter()
            .map(|(pod_name, target)| (pod_name.clone(), target.rustfs_container_id.clone()))
            .collect::<BTreeMap<_, _>>();
        ensure!(
            evidence.fixed_volume_containers_at_fault_activation == expected_containers
                && evidence.fixed_volume_containers_at_workload_snapshot == expected_containers,
            "force-read RustFS container identities changed or differ from the validated target proof"
        );
        let [active_snapshot] = evidence.active_snapshots.as_slice() else {
            anyhow::bail!("force-read fault evidence must contain one active snapshot")
        };
        let [workload_snapshot] = evidence.workload_snapshots.as_slice() else {
            anyhow::bail!("force-read fault evidence must contain one workload snapshot")
        };
        ensure!(
            active_snapshot.stage == "active"
                && workload_snapshot.stage == "after-workload"
                && active_snapshot.resource_kind == workload_snapshot.resource_kind
                && active_snapshot.resource_name == workload_snapshot.resource_name
                && active_snapshot.dm_status.is_none()
                && workload_snapshot.dm_status.is_none(),
            "force-read fault snapshots do not identify one resource across the active window"
        );
        let resource_kind = active_snapshot
            .resource_kind
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("force-read active snapshot lacks a resource kind")?;
        ensure!(
            resource_kind == "iochaos",
            "force-read exact-quorum proof requires a RustFS volume IOChaos resource"
        );
        let name = active_snapshot
            .resource_name
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("force-read IOChaos snapshot lacks a resource name")?;
        let active_resource = active_snapshot
            .chaos_status
            .as_ref()
            .context("force-read active snapshot lacks its IOChaos resource")?;
        let workload_resource = workload_snapshot
            .chaos_status
            .as_ref()
            .context("force-read workload snapshot lacks its IOChaos resource")?;
        let active_uid = active_resource
            .pointer("/metadata/uid")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .context("force-read active IOChaos resource lacks a UID")?;
        ensure!(
            active_resource
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                == Some(name)
                && workload_resource
                    .pointer("/metadata/name")
                    .and_then(serde_json::Value::as_str)
                    == Some(name)
                && workload_resource
                    .pointer("/metadata/uid")
                    .and_then(serde_json::Value::as_str)
                    == Some(active_uid),
            "force-read snapshots do not capture the same IOChaos resource name and UID"
        );
        let candidate_pod_ids = target_proof
            .candidates
            .keys()
            .map(|pod_name| format!("{}/{pod_name}", target_proof.namespace))
            .collect::<BTreeSet<_>>();
        let iochaos_runtime = IoChaosRuntimeContract {
            action: runtime.parameters.action.clone(),
            methods: runtime.parameters.methods.clone(),
            io_sampling_percent: runtime.parameters.io_sampling_percent,
            duration_seconds: runtime.parameters.duration_seconds,
        };
        let contract = VolumeTargetEvidenceContract {
            chaos_namespace: &runtime.parameters.chaos_namespace,
            target_namespace: &target_proof.namespace,
            tenant: &target_proof.tenant,
            run_id: &self.identity.run_id,
            scenario: &self.identity.scenario,
            volume_path: &target_proof.volume_path,
            path: None,
            exact_pod_names: None,
            expected_targets: target_proof.expected_targets,
            candidate_pod_ids: &candidate_pod_ids,
            runtime: &iochaos_runtime,
        };
        let active_targets = validate_fixed_volume_snapshot(active_resource, &contract)?;
        let workload_targets = validate_fixed_volume_snapshot(workload_resource, &contract)?;
        let persisted_active_targets = evidence
            .fixed_volume_targets_at_fault_activation
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        let persisted_workload_targets = evidence
            .fixed_volume_targets_at_workload_snapshot
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>();
        ensure!(
            persisted_active_targets.len()
                == evidence.fixed_volume_targets_at_fault_activation.len()
                && persisted_workload_targets.len()
                    == evidence.fixed_volume_targets_at_workload_snapshot.len()
                && active_targets == persisted_active_targets
                && workload_targets == persisted_workload_targets
                && active_targets == workload_targets,
            "force-read persisted IOChaos targets differ from the controller injection records"
        );
        let expected_selected_records = selected_targets
            .keys()
            .map(|pod_name| format!("{}/{pod_name}/rustfs", target_proof.namespace))
            .collect::<BTreeSet<_>>();
        ensure!(
            active_targets == expected_selected_records,
            "force-read IOChaos controller records do not match the selected target-proof volumes"
        );
        let resource_id = format!("{resource_kind}/{name}/{active_uid}");
        let snapshot_id = sha256_bytes(&serde_json::to_vec(active_snapshot)?);
        Ok(ValidatedForceReadFaultEvidence {
            targets: selected_targets,
            snapshot_id,
            resource_id,
        })
    }

    fn validate_target_proof(
        &self,
        membership: &ErasureSetMembership,
        runtime: &ForceReadRuntimeEvidenceContract,
    ) -> Result<ValidatedForceReadTargetProof> {
        let proof = &runtime.target_proof;
        ensure!(
            proof.schema_version == TARGET_PROOF_SCHEMA_VERSION
                && proof.status == TargetProofStatus::Satisfied
                && proof.run_id == self.identity.run_id
                && proof.scenario == self.identity.scenario
                && proof.case_name == self.identity.case_name
                && !proof.namespace.trim().is_empty()
                && !proof.tenant.trim().is_empty()
                && proof.generated_at_ms > 0
                && proof.generated_at_ms < self.fault_active_from_ms
                && self.fault_active_from_ms - proof.generated_at_ms
                    <= STORAGE_OBSERVATION_MAX_AGE_MS,
            "force-read target proof has the wrong identity, status, or observation interval"
        );
        ensure!(
            self.shape.volumes_per_server == 1,
            "storage-recovery forced reads currently require exactly one RustFS volume per server"
        );
        let [fault] = proof.faults.as_slice() else {
            anyhow::bail!("force-read target proof must describe exactly one volume-read fault")
        };
        let volume_path = fault
            .volume_path
            .as_deref()
            .filter(|path| path.starts_with('/') && *path != "/")
            .context("force-read target proof lacks an absolute non-root volume path")?;
        let selector = fault
            .pod_selector
            .as_ref()
            .context("force-read target proof lacks its RustFS Pod selector")?;
        ensure!(
            fault.kind == "rustfs-volume-io-error"
                && fault.backend == "chaos-mesh"
                && fault.target_kind == "rustfs-volume"
                && fault.selection_kind == "fixed-targets"
                && fault.selection_value > 0
                && selector.namespace == proof.namespace
                && selector.tenant == proof.tenant
                && selector.exact_pods_resolved,
            "force-read target proof does not describe one resolved fixed-target RustFS read fault"
        );
        let topology = fault
            .erasure_set
            .as_ref()
            .context("force-read target proof lacks RustFS erasure-set evidence")?;
        ensure!(
            topology.required
                && topology.resolved
                && topology.source.as_deref() == Some("rustfs-admin-server-info")
                && topology.shape.as_ref() == Some(&self.shape)
                && topology.membership.as_ref() == Some(membership)
                && topology
                    .deployment_id
                    .as_deref()
                    .is_some_and(|deployment_id| !deployment_id.trim().is_empty())
                && topology.observed_at_ms > 0
                && topology.observed_at_ms <= proof.generated_at_ms
                && topology.observed_at_ms < self.fault_active_from_ms
                && self.fault_active_from_ms - topology.observed_at_ms
                    <= STORAGE_OBSERVATION_MAX_AGE_MS,
            "force-read target proof does not bind the supplied RustFS erasure-set membership"
        );
        topology
            .health
            .context("force-read target proof lacks erasure-set health")?
            .require_all_online(self.shape.total_shards)?;
        membership.validate(&self.shape)?;
        ensure!(
            proof.resolved_pods.len() == membership.members.len(),
            "force-read target proof does not cover every erasure-set Pod"
        );
        let mut candidates = BTreeMap::new();
        let mut pod_uids = BTreeSet::new();
        let mut pvc_uids = BTreeSet::new();
        let mut pv_uids = BTreeSet::new();
        for pod in &proof.resolved_pods {
            let member = membership
                .members
                .iter()
                .find(|member| member.pod_name == pod.name)
                .context("target-proof Pod is absent from erasure-set membership")?;
            let [drive_uuid] = member.shard_ids.as_slice() else {
                anyhow::bail!("force-read target Pod must own exactly one RustFS drive")
            };
            let container_id = pod
                .rustfs_container_id
                .as_deref()
                .filter(|value| !value.trim().is_empty())
                .context("force-read target Pod lacks its running RustFS container ID")?;
            let matching_mounts = pod
                .volume_mounts
                .iter()
                .filter(|mount| mount.container_name == "rustfs" && mount.mount_path == volume_path)
                .collect::<Vec<_>>();
            let [mount] = matching_mounts.as_slice() else {
                anyhow::bail!("force-read target Pod must have one exact RustFS volume mount")
            };
            let claim_name = mount
                .persistent_volume_claim
                .as_deref()
                .context("force-read target mount is not backed by a PVC")?;
            let matching_claims = pod
                .persistent_volume_claims
                .iter()
                .filter(|claim| claim.name == claim_name)
                .collect::<Vec<_>>();
            let [claim] = matching_claims.as_slice() else {
                anyhow::bail!("force-read target mount must resolve to one PVC")
            };
            let persistent_volume = claim
                .persistent_volume
                .as_ref()
                .context("force-read target PVC is not bound to a PV")?;
            ensure!(
                pod.ready
                    && !pod.uid.trim().is_empty()
                    && pod_uids.insert(pod.uid.as_str())
                    && pod
                        .node
                        .as_deref()
                        .is_some_and(|node| !node.trim().is_empty())
                    && !pod.node_labels.is_empty()
                    && !claim.uid.trim().is_empty()
                    && pvc_uids.insert(claim.uid.as_str())
                    && !persistent_volume.uid.trim().is_empty()
                    && pv_uids.insert(persistent_volume.uid.as_str())
                    && claim.volume_name.as_deref() == Some(persistent_volume.name.as_str())
                    && !mount.volume_name.trim().is_empty()
                    && persistent_volume
                        .device_or_path
                        .as_deref()
                        .is_some_and(|path| !path.trim().is_empty())
                    && !drive_uuid.trim().is_empty(),
                "force-read target proof contains an unready, duplicate, or incomplete Pod/PVC/PV/drive identity"
            );
            let target = ForceReadTargetIdentity {
                pod_uid: pod.uid.clone(),
                rustfs_container_id: container_id.to_string(),
                drive_uuid: drive_uuid.clone(),
            };
            ensure!(
                candidates.insert(pod.name.clone(), target).is_none(),
                "force-read target proof contains duplicate Pod names"
            );
        }
        ensure!(
            candidates.len() == membership.members.len(),
            "force-read target proof does not cover the exact erasure-set membership"
        );
        Ok(ValidatedForceReadTargetProof {
            namespace: proof.namespace.clone(),
            tenant: proof.tenant.clone(),
            volume_path: volume_path.to_string(),
            expected_targets: fault.selection_value,
            candidates,
        })
    }
}

/// Complete evidence chain required to prove one on-disk bitrot recovery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorruptionWindowProbe {
    pub operation_id: String,
    pub object_key: String,
    pub version_id: String,
    pub expected_sha256: String,
    pub detection_evidence: BitrotDetectionEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum BitrotDetectionCode {
    ShardChecksumMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsBitrotDetectionResponse {
    pub operation_id: String,
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub drive_uuid: String,
    pub shard_path: String,
    pub shard_device_id: String,
    pub shard_inode: u64,
    pub expected_shard_sha256: String,
    pub observed_shard_sha256: String,
    pub code: BitrotDetectionCode,
    pub detected_at_ms: u64,
    pub target_proof_sha256: String,
    pub host_storage_proof_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitrotDetectionEvidence {
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, Copy)]
pub struct BitrotRecoveryCaseEvidence<'a> {
    pub mutation: &'a ShardMutationProof,
    pub corruption_probe: &'a CorruptionWindowProbe,
    pub heal: &'a HealSummary,
    pub heal_samples: &'a [HealProgressSample],
    pub force_read: &'a ForceReadThroughProof,
    pub membership: &'a ErasureSetMembership,
    pub runtime: &'a ForceReadRuntimeEvidenceContract,
    pub history: &'a [OperationRecord],
    pub mappings: &'a [VersionShardMappingObservation],
}

/// Validates the full mutation, heal, forced-read, and rollback chain as one unit.
pub fn validate_bitrot_recovery_case(evidence: &BitrotRecoveryCaseEvidence<'_>) -> Result<()> {
    let BitrotRecoveryCaseEvidence {
        mutation,
        corruption_probe,
        heal,
        heal_samples,
        force_read,
        membership,
        runtime,
        history,
        mappings,
    } = evidence;
    mutation.validate_against_history(history)?;
    let mutation_target_proof = mutation.mutation_target_proof()?;
    let host_receipt = mutation.host_receipt()?;
    ensure!(
        mutation.identity.scenario == "on-disk-bitrot"
            && heal.identity == mutation.identity
            && force_read.identity == mutation.identity
            && runtime.target_proof_sha256 == force_read.target_proof_sha256,
        "bitrot mutation, heal, and forced-read evidence do not share one attempt identity"
    );
    let force_fault = runtime
        .target_proof
        .faults
        .first()
        .context("bitrot force-read target proof lacks its fault")?;
    let force_topology = force_fault
        .erasure_set
        .as_ref()
        .context("bitrot force-read target proof lacks its erasure-set topology")?;
    let target_member = membership
        .members
        .iter()
        .filter(|member| {
            member
                .shard_ids
                .contains(&mutation.volume.rustfs_drive_uuid)
        })
        .collect::<Vec<_>>();
    let [target_member] = target_member.as_slice() else {
        anyhow::bail!("bitrot mutation drive is not owned by one force-read erasure-set member")
    };
    let force_pods = runtime
        .target_proof
        .resolved_pods
        .iter()
        .filter(|pod| pod.name == mutation.volume.pod)
        .collect::<Vec<_>>();
    let [force_pod] = force_pods.as_slice() else {
        anyhow::bail!("bitrot mutation Pod is not uniquely resolved by the force-read proof")
    };
    let force_claims = force_pod
        .persistent_volume_claims
        .iter()
        .filter(|claim| claim.name == mutation.volume.persistent_volume_claim)
        .collect::<Vec<_>>();
    let [force_claim] = force_claims.as_slice() else {
        anyhow::bail!("bitrot mutation PVC is not uniquely resolved by the force-read proof")
    };
    let force_volume = force_claim
        .persistent_volume
        .as_ref()
        .context("bitrot force-read PVC is not bound to a PV")?;
    ensure!(
        force_topology.deployment_id.as_deref()
            == Some(mutation.volume.rustfs_deployment_id.as_str())
            && force_read.shape.pool_index == mutation.volume.pool_index
            && force_read.shape.set_index == mutation.volume.set_index
            && target_member.pod_name == mutation.volume.pod
            && force_pod.uid == mutation.volume.pod_uid
            && force_pod.rustfs_container_id.as_deref()
                == Some(mutation.volume.rustfs_container_id.as_str())
            && force_claim.uid == mutation.volume.persistent_volume_claim_uid
            && force_claim.storage_class.as_deref() == Some(mutation.volume.storage_class.as_str())
            && force_claim.volume_name.as_deref()
                == Some(mutation.volume.persistent_volume.as_str())
            && force_volume.name == mutation.volume.persistent_volume
            && force_volume.uid == mutation.volume.persistent_volume_uid
            && force_volume.source.as_deref() == Some("local")
            && force_volume.node.as_deref() == Some(mutation.volume.node.as_str())
            && force_volume.device_or_path.as_deref()
                == Some(mutation.volume.local_volume_path.as_str()),
        "bitrot mutation and post-heal force-read do not target the same RustFS deployment and Pod/PVC/PV generation"
    );
    let expected_heal_target = match heal.mode {
        HealMode::AutomaticScanner => None,
        HealMode::AdminDeep => Some((
            mutation.volume.rustfs_drive_uuid.as_str(),
            mutation.volume.pool_index,
            mutation.volume.set_index,
        )),
        HealMode::AutomaticReplacement => {
            anyhow::bail!("bitrot recovery cannot use automatic replacement heal mode")
        }
    };
    heal.validate_progress(heal_samples, expected_heal_target)?;
    validate_bitrot_object_evidence(
        mutation,
        corruption_probe,
        heal.started_at_ms,
        force_read,
        history,
    )?;
    validate_bitrot_target_proof_phases(
        &mutation.volume.target_proof_sha256,
        mutation_target_proof.generated_at_ms,
        mutation.mapped_at_ms,
        &force_read.target_proof_sha256,
        runtime.target_proof.generated_at_ms,
        heal.completed_at_ms,
    )?;
    force_read.validate_against_runtime(
        membership,
        runtime,
        &mutation.volume.rustfs_drive_uuid,
        history,
        mappings,
    )?;
    validate_bitrot_recovery_order(
        mutation.mutated_at_ms,
        heal.started_at_ms,
        heal.completed_at_ms,
        force_read.fault_active_from_ms,
        force_read.fault_active_until_ms,
        host_receipt.rollback_pwrite_started_at_ms,
        mutation.rollback.observed_at_ms,
    )?;
    Ok(())
}

fn validate_bitrot_object_evidence(
    mutation: &ShardMutationProof,
    corruption_probe: &CorruptionWindowProbe,
    heal_started_at_ms: u64,
    force_read: &ForceReadThroughProof,
    history: &[OperationRecord],
) -> Result<()> {
    validate_sha256(
        "corruption-window expected object",
        &corruption_probe.expected_sha256,
    )?;
    ensure!(
        !corruption_probe.operation_id.trim().is_empty()
            && corruption_probe.object_key == mutation.object_key
            && corruption_probe.version_id == mutation.version_id
            && corruption_probe.expected_sha256 == mutation.expected_object_sha256,
        "corruption-window probe does not target the mutated object version"
    );
    ensure!(
        !corruption_probe
            .detection_evidence
            .api_revision
            .trim()
            .is_empty(),
        "corruption-window probe lacks a RustFS bitrot-detection API revision"
    );
    validate_sha256(
        "RustFS bitrot detection response",
        &corruption_probe.detection_evidence.response_sha256,
    )?;
    ensure!(
        corruption_probe.detection_evidence.response_sha256
            == sha256_bytes(corruption_probe.detection_evidence.response_body.as_bytes()),
        "RustFS bitrot detection digest does not match its captured response body"
    );
    let detection = serde_json::from_str::<RustfsBitrotDetectionResponse>(
        &corruption_probe.detection_evidence.response_body,
    )
    .context("decode captured RustFS bitrot detection response")?;
    ensure!(
        detection.operation_id == corruption_probe.operation_id
            && detection.bucket == mutation.identity.bucket
            && detection.object_key == mutation.object_key
            && detection.version_id == mutation.version_id
            && detection.drive_uuid == mutation.volume.rustfs_drive_uuid
            && detection.shard_path == mutation.shard_path
            && detection.shard_device_id == mutation.shard_device_id
            && detection.shard_inode == mutation.shard_inode
            && detection.expected_shard_sha256 == mutation.original_sha256
            && detection.observed_shard_sha256 == mutation.mutated_sha256
            && detection.code == BitrotDetectionCode::ShardChecksumMismatch
            && detection.target_proof_sha256 == mutation.volume.target_proof_sha256
            && detection.host_storage_proof_sha256 == mutation.volume.host_storage_proof_sha256,
        "RustFS bitrot detection did not observe the exact mutated shard and object version"
    );
    let matching_records = history
        .iter()
        .filter(|record| record.id == corruption_probe.operation_id)
        .collect::<Vec<_>>();
    let [record] = matching_records.as_slice() else {
        anyhow::bail!("corruption-window probe must match one workload history record")
    };
    let clean_read = record.outcome == OperationOutcome::Ok
        && record
            .http_status
            .is_some_and(|status| (200..300).contains(&status))
        && record.value_sha256.as_deref() == Some(corruption_probe.expected_sha256.as_str())
        && record.error.is_none();
    let clean_rejection = record.outcome == OperationOutcome::Failed
        && record
            .http_status
            .is_some_and(|status| (500..600).contains(&status))
        && record.value_sha256.is_none()
        && record
            .error
            .as_deref()
            .is_some_and(|error| !error.trim().is_empty());
    ensure!(
        record_matches_identity(record, &mutation.identity)
            && record.kind == OperationKind::Get
            && record.key.as_deref() == Some(mutation.object_key.as_str())
            && record.version_id.as_deref() == Some(mutation.version_id.as_str())
            && valid_operation_interval(record)
            && record.started_at_ms > mutation.mutated_at_ms
            && record.ended_at_ms < heal_started_at_ms
            && detection.detected_at_ms >= record.started_at_ms
            && detection.detected_at_ms <= record.ended_at_ms
            && (clean_read || clean_rejection),
        "corruption-window GET did not consume the detected shard corruption and return clean bytes or a clean rejection"
    );
    ensure!(
        force_read.probes.iter().any(|probe| {
            probe.object_key == mutation.object_key
                && probe.version_id == mutation.version_id
                && probe.expected_sha256 == mutation.expected_object_sha256
                && probe.observed_sha256 == mutation.expected_object_sha256
        }),
        "post-heal exact-quorum reads do not include the mutated object version"
    );
    Ok(())
}

fn validate_bitrot_target_proof_phases(
    mutation_target_proof_sha256: &str,
    mutation_target_observed_at_ms: u64,
    mapped_at_ms: u64,
    force_read_target_proof_sha256: &str,
    force_read_target_observed_at_ms: u64,
    heal_completed_at_ms: u64,
) -> Result<()> {
    ensure!(
        mutation_target_proof_sha256 != force_read_target_proof_sha256
            && mutation_target_observed_at_ms < mapped_at_ms
            && force_read_target_observed_at_ms > heal_completed_at_ms,
        "bitrot mutation target proof must precede mutation and a distinct force-read target proof must follow heal"
    );
    Ok(())
}

fn validate_bitrot_recovery_order(
    mutated_at_ms: u64,
    heal_started_at_ms: u64,
    heal_completed_at_ms: u64,
    force_read_started_at_ms: u64,
    force_read_completed_at_ms: u64,
    rollback_started_at_ms: u64,
    rollback_observed_at_ms: u64,
) -> Result<()> {
    ensure!(
        mutated_at_ms < heal_started_at_ms
            && heal_started_at_ms < heal_completed_at_ms
            && heal_completed_at_ms < force_read_started_at_ms
            && force_read_started_at_ms < force_read_completed_at_ms
            && force_read_completed_at_ms < rollback_started_at_ms
            && rollback_started_at_ms <= rollback_observed_at_ms,
        "bitrot success requires mutation readback, RustFS heal, exact-quorum reads, then host rollback in strict order"
    );
    Ok(())
}

fn unique_storage_fault_pods<'a>(
    stage: &str,
    pods: &'a [StorageFaultPodIdentity],
) -> Result<BTreeMap<String, &'a str>> {
    let mut identities = BTreeMap::new();
    for pod in pods {
        ensure!(
            !pod.name.trim().is_empty()
                && !pod.uid.trim().is_empty()
                && identities
                    .insert(pod.name.clone(), pod.uid.as_str())
                    .is_none(),
            "force-read {stage} fault evidence contains an empty or duplicate Pod identity"
        );
    }
    Ok(identities)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardInventoryEntry {
    pub fragment_id: String,
    pub bucket: String,
    pub object_key: String,
    pub version_id: String,
    pub drive_uuid: String,
    pub object_sha256: String,
    pub sha256: String,
    pub reference_state: FragmentReferenceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentReferenceState {
    ReferencedVersion,
    OrphanedUncommitted,
    /// A fragment discovered by the closed offline traversal that cannot be
    /// reconciled to the captured S3/history model.
    Unclassified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShardInventorySource {
    RustfsDiagnosticApi,
    OfflineXl2Inspector,
}

impl ShardInventorySource {
    fn validate_revision(self, revision: &str) -> Result<()> {
        match self {
            Self::RustfsDiagnosticApi => ensure!(
                !revision.trim().is_empty(),
                "RustFS diagnostic inventory API revision is empty"
            ),
            Self::OfflineXl2Inspector => ensure!(
                revision == OFFLINE_XL2_INSPECTOR_REVISION,
                "offline XL2 inventory has an unsupported inspector revision"
            ),
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardInventoryScanReceipt {
    pub snapshot_id: String,
    pub source: ShardInventorySource,
    pub api_revision: String,
    pub response_sha256: String,
    pub response_body: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsShardInventoryResponse {
    pub bucket: String,
    pub drive_uuid: String,
    pub filesystem_uuid: String,
    pub snapshot_id: String,
    pub scan_started_at_ms: u64,
    pub scan_completed_at_ms: u64,
    pub start_cursor: Option<String>,
    pub end_cursor: String,
    pub exhausted: bool,
    pub total_count: usize,
    pub entries: Vec<ShardInventoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShardInventorySnapshot {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub receipt: ShardInventoryScanReceipt,
    pub volume: StorageVolumeIdentity,
    pub entry_count: usize,
    pub entries_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FragmentRecoverability {
    Committed,
    RecoverableUnknown,
    UncommittedDangling,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ClassifiedVersionFragments {
    pub evidence_id: String,
    pub operation_id: Option<String>,
    pub object_key: String,
    pub version_id: String,
    pub recoverability: FragmentRecoverability,
    pub fragment_ids: Vec<String>,
}

impl ShardInventoryEntry {
    fn validate(&self) -> Result<()> {
        for (field, value) in [
            ("fragment id", self.fragment_id.as_str()),
            ("bucket", self.bucket.as_str()),
            ("object key", self.object_key.as_str()),
            ("version id", self.version_id.as_str()),
            ("drive UUID", self.drive_uuid.as_str()),
        ] {
            ensure!(!value.trim().is_empty(), "shard inventory {field} is empty");
        }
        validate_sha256("shard inventory object", &self.object_sha256)?;
        validate_sha256("shard inventory fragment", &self.sha256)
    }
}

impl ShardInventorySnapshot {
    pub fn from_complete_scan(
        identity: StorageRecoveryArtifactIdentity,
        volume: StorageVolumeIdentity,
        receipt: ShardInventoryScanReceipt,
    ) -> Result<Self> {
        let response = serde_json::from_str::<RustfsShardInventoryResponse>(&receipt.response_body)
            .context("decode captured RustFS shard-inventory response")?;
        let proof = Self {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity,
            receipt,
            volume,
            entry_count: response.entries.len(),
            entries_sha256: inventory_entries_sha256(&response.entries)?,
        };
        proof.validate()?;
        Ok(proof)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported shard-inventory schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        self.volume.validate()?;
        self.receipt
            .source
            .validate_revision(&self.receipt.api_revision)?;
        ensure!(
            !self.receipt.snapshot_id.trim().is_empty()
                && self.receipt.started_at_ms > 0
                && self.receipt.started_at_ms < self.receipt.completed_at_ms
                && self.receipt.completed_at_ms == self.receipt.observed_at_ms
                && self.receipt.observed_at_ms >= self.volume.observed_at_ms,
            "shard inventory lacks a complete, ordered scan receipt"
        );
        validate_sha256(
            "shard inventory diagnostic response",
            &self.receipt.response_sha256,
        )?;
        ensure!(
            self.receipt.response_sha256 == sha256_bytes(self.receipt.response_body.as_bytes()),
            "shard inventory response digest does not match the captured RustFS response body"
        );
        let response = self.response()?;
        ensure!(
            response.bucket == self.identity.bucket
                && response.drive_uuid == self.volume.rustfs_drive_uuid
                && response.filesystem_uuid == self.volume.filesystem_uuid
                && response.snapshot_id == self.receipt.snapshot_id
                && response.scan_started_at_ms == self.receipt.started_at_ms
                && response.scan_completed_at_ms == self.receipt.completed_at_ms
                && response.start_cursor.is_none()
                && !response.end_cursor.trim().is_empty()
                && response.exhausted
                && response.total_count == response.entries.len(),
            "shard inventory response is not a complete server-scoped scan of the returned generation"
        );
        for entry in &response.entries {
            entry.validate()?;
            ensure!(
                entry.drive_uuid == self.volume.rustfs_drive_uuid
                    && entry.bucket == self.identity.bucket,
                "shard inventory entry is not located in the run bucket on the scanned drive"
            );
        }
        unique_fragments("shard-inventory", &response.entries)?;
        validate_sha256("shard inventory entries", &self.entries_sha256)?;
        ensure!(
            self.entry_count == response.entries.len()
                && self.entries_sha256 == inventory_entries_sha256(&response.entries)?,
            "shard inventory count or canonical entries digest does not match the complete scan"
        );
        Ok(())
    }

    fn response(&self) -> Result<RustfsShardInventoryResponse> {
        serde_json::from_str(&self.receipt.response_body)
            .context("decode captured RustFS shard-inventory response")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DanglingCleanupProof {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub returned_generation: StorageVolumeIdentity,
    pub before_inventory_snapshot_id: String,
    pub before_inventory_sha256: String,
    pub after_inventory_snapshot_id: String,
    pub after_inventory_sha256: String,
    pub cleanup_operation_id: String,
    pub orphan_injection: StaleOwnedOrphanReceipt,
    pub cleanup_evidence: Option<DanglingCleanupEvidence>,
    pub writes_quiesced_at_ms: u64,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub ack_loss_puts: Vec<AckLossPutEvidence>,
    pub classified_versions: Vec<ClassifiedVersionFragments>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckLossPutEvidence {
    pub operation_id: String,
    pub proxy_endpoint: String,
    pub request_count: usize,
    pub retries_disabled: bool,
    pub request_sha256: String,
    pub value_sha256: String,
    pub size_bytes: usize,
    pub upstream_http_status: u16,
    pub upstream_request_id: String,
    pub upstream_version_id: String,
    pub accepted_at_ms: u64,
    pub upstream_completed_at_ms: u64,
    pub client_response_bytes: usize,
    pub connection_closed_at_ms: u64,
}

impl AckLossPutEvidence {
    fn validate_for(
        &self,
        identity: &StorageRecoveryArtifactIdentity,
        record: &OperationRecord,
    ) -> Result<()> {
        let endpoint = self
            .proxy_endpoint
            .parse::<std::net::SocketAddr>()
            .context("ACK-loss proxy endpoint is not a socket address")?;
        validate_sha256("ACK-loss request", &self.request_sha256)?;
        validate_sha256("ACK-loss value", &self.value_sha256)?;
        ensure!(
            endpoint.ip().is_loopback()
                && endpoint.port() > 0
                && self.request_count == 1
                && self.retries_disabled
                && (200..300).contains(&self.upstream_http_status)
                && !self.upstream_request_id.trim().is_empty()
                && !self.upstream_version_id.trim().is_empty()
                && self.upstream_version_id != "null"
                && self.client_response_bytes == 0,
            "recoverable-unknown evidence is not a one-shot localhost ACK-loss PUT"
        );
        ensure!(
            self.operation_id == record.id
                && record_matches_identity(record, identity)
                && record.kind == OperationKind::Put
                && matches!(
                    record.outcome,
                    OperationOutcome::Timeout
                        | OperationOutcome::Unknown
                        | OperationOutcome::Failed
                )
                && record.http_status.is_none()
                && record.key.is_some()
                && record.value_sha256.as_deref() == Some(self.value_sha256.as_str())
                && record.size_bytes == Some(self.size_bytes)
                && record.version_id.as_deref().is_none_or(|version_id| {
                    version_id == "null" || version_id == self.upstream_version_id
                }),
            "ACK-loss receipt does not bind the ambiguous workload PUT"
        );
        ensure!(
            record.started_at_ms <= self.accepted_at_ms
                && self.accepted_at_ms <= self.upstream_completed_at_ms
                && self.upstream_completed_at_ms <= self.connection_closed_at_ms
                && self.connection_closed_at_ms <= record.ended_at_ms,
            "ACK-loss proxy and workload operation intervals are not ordered"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DanglingCleanupEvidence {
    pub response_sha256: String,
    pub response_body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RustfsDanglingCleanupResponse {
    pub operation_id: String,
    pub bucket: String,
    pub drive_uuid: String,
    pub filesystem_uuid: String,
    pub before_inventory_snapshot_id: String,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub deletion_authority: String,
    pub dry_run_evidence: DanglingCleanupEvidence,
    pub live_evidence: DanglingCleanupEvidence,
    /// Raw admin heal output is diagnostic only. Exact deletion authority is
    /// the stable offline inventory delta bound to `orphan_injection`.
    #[serde(default)]
    pub removed_fragment_ids: Vec<String>,
}

impl DanglingCleanupProof {
    pub fn validate_against_stale_return(
        &self,
        stale_return: &StaleDiskReturnProof,
        before_inventory: &ShardInventorySnapshot,
        after_inventory: &ShardInventorySnapshot,
        history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            self.schema_version == STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            "unsupported dangling-cleanup proof schema version {}",
            self.schema_version
        );
        self.identity.validate()?;
        validate_immutable_version_history(history, &self.identity)?;
        ensure!(
            self.identity.scenario == "stale-disk-return-detect",
            "dangling-cleanup proof is bound to the wrong scenario"
        );
        stale_return.validate_against_history(history)?;
        self.returned_generation.validate()?;
        ensure!(
            stale_return.identity == self.identity
                && stale_return.returned_generation == self.returned_generation,
            "dangling-cleanup proof is not bound to the validated stale-return generation"
        );
        ensure!(
            !self.cleanup_operation_id.trim().is_empty(),
            "dangling-cleanup operation id is empty"
        );
        let cleanup_evidence = self
            .cleanup_evidence
            .as_ref()
            .context("dangling-cleanup proof lacks a captured RustFS cleanup response")?;
        validate_sha256(
            "dangling-cleanup response",
            &cleanup_evidence.response_sha256,
        )?;
        ensure!(
            cleanup_evidence.response_sha256
                == sha256_bytes(cleanup_evidence.response_body.as_bytes()),
            "dangling-cleanup response digest does not match its captured body"
        );
        let cleanup_response =
            serde_json::from_str::<RustfsDanglingCleanupResponse>(&cleanup_evidence.response_body)
                .context("decode captured RustFS dangling-cleanup response")?;
        ensure!(
            cleanup_response.removed_fragment_ids.is_empty()
                && cleanup_response.deletion_authority
                    == "offline-inventory-delta-and-injection-receipt",
            "raw admin heal output must remain diagnostic-only cleanup evidence"
        );
        for (label, evidence) in [
            ("dry-run heal", &cleanup_response.dry_run_evidence),
            ("live heal", &cleanup_response.live_evidence),
        ] {
            validate_sha256(label, &evidence.response_sha256)?;
            ensure!(
                evidence.response_sha256 == sha256_bytes(evidence.response_body.as_bytes()),
                "{label} evidence digest does not match its captured body"
            );
        }
        before_inventory.validate()?;
        after_inventory.validate()?;
        let before_response = before_inventory.response()?;
        let after_response = after_inventory.response()?;
        ensure!(
            before_inventory.identity == self.identity
                && after_inventory.identity == self.identity
                && before_inventory.volume == self.returned_generation
                && after_inventory.volume == self.returned_generation
                && before_inventory.receipt.api_revision == after_inventory.receipt.api_revision,
            "dangling-cleanup inventories do not describe the validated returned stale generation"
        );
        ensure!(
            self.before_inventory_snapshot_id == before_inventory.receipt.snapshot_id
                && self.before_inventory_sha256 == before_inventory.entries_sha256
                && self.after_inventory_snapshot_id == after_inventory.receipt.snapshot_id
                && self.after_inventory_sha256 == after_inventory.entries_sha256
                && before_inventory.receipt.snapshot_id != after_inventory.receipt.snapshot_id
                && before_response.end_cursor != after_response.end_cursor,
            "dangling-cleanup proof does not reference two distinct complete inventory receipts"
        );
        ensure!(
            cleanup_response.operation_id == self.cleanup_operation_id
                && cleanup_response.bucket == self.identity.bucket
                && cleanup_response.drive_uuid == self.returned_generation.rustfs_drive_uuid
                && cleanup_response.filesystem_uuid == self.returned_generation.filesystem_uuid
                && cleanup_response.before_inventory_snapshot_id
                    == self.before_inventory_snapshot_id
                && cleanup_response.started_at_ms == self.started_at_ms
                && cleanup_response.completed_at_ms == self.completed_at_ms,
            "dangling-cleanup identity and interval are not derived from its captured RustFS response"
        );
        validate_sha256(
            "pre-cleanup inventory reference",
            &self.before_inventory_sha256,
        )?;
        validate_sha256(
            "post-cleanup inventory reference",
            &self.after_inventory_sha256,
        )?;
        ensure!(
            self.writes_quiesced_at_ms > self.returned_generation.observed_at_ms
                && before_inventory.receipt.started_at_ms > self.writes_quiesced_at_ms
                && self.started_at_ms > before_inventory.receipt.completed_at_ms
                && self.started_at_ms - before_inventory.receipt.completed_at_ms
                    <= STORAGE_OBSERVATION_MAX_AGE_MS
                && self.completed_at_ms > self.started_at_ms
                && after_inventory.receipt.started_at_ms > self.completed_at_ms
                && after_inventory.receipt.completed_at_ms > after_inventory.receipt.started_at_ms
                && after_inventory.receipt.completed_at_ms - self.completed_at_ms
                    <= STORAGE_OBSERVATION_MAX_AGE_MS,
            "dangling-cleanup and complete inventory observations are not ordered after the stale return"
        );
        ensure!(
            history
                .iter()
                .filter(|record| {
                    record_matches_identity(record, &self.identity)
                        && is_object_mutation(record.kind)
                })
                .all(|record| {
                    valid_operation_interval(record)
                        && (record.ended_at_ms <= self.writes_quiesced_at_ms
                            || record.started_at_ms > after_inventory.receipt.completed_at_ms)
                }),
            "object mutation overlapped the quiesced inventory and dangling-cleanup window"
        );
        ensure!(
            !before_response.entries.is_empty(),
            "pre-cleanup shard inventory is empty"
        );
        let before = unique_fragments("pre-cleanup", &before_response.entries)?;
        let after = unique_fragments("post-cleanup", &after_response.entries)?;
        ensure!(
            !self.classified_versions.is_empty(),
            "dangling-cleanup validation requires fragment classifications"
        );
        let mut history_by_id = HashMap::with_capacity(history.len());
        for record in history {
            ensure!(
                history_by_id.insert(record.id.as_str(), record).is_none(),
                "workload history contains a duplicate operation id"
            );
        }
        let mut inventory_versions_by_object =
            HashMap::<(&str, &str), BTreeSet<&str>>::with_capacity(before_response.entries.len());
        for entry in &before_response.entries {
            inventory_versions_by_object
                .entry((entry.object_key.as_str(), entry.object_sha256.as_str()))
                .or_default()
                .insert(entry.version_id.as_str());
        }
        let mut classified_fragment_ids = BTreeSet::new();
        let mut classified_versions = BTreeSet::new();
        let mut classification_evidence_ids = BTreeSet::new();
        let mut protected_operation_ids = BTreeSet::new();
        let ack_loss_by_operation = self
            .ack_loss_puts
            .iter()
            .map(|evidence| (evidence.operation_id.as_str(), evidence))
            .collect::<HashMap<_, _>>();
        ensure!(
            ack_loss_by_operation.len() == self.ack_loss_puts.len(),
            "dangling-cleanup proof contains duplicate ACK-loss operation receipts"
        );
        for version in &self.classified_versions {
            ensure!(
                !version.evidence_id.trim().is_empty()
                    && !version.object_key.trim().is_empty()
                    && !version.version_id.trim().is_empty()
                    && version.version_id != "null",
                "fragment classification has incomplete version identity"
            );
            ensure!(
                classification_evidence_ids.insert(version.evidence_id.as_str()),
                "fragment classification contains a duplicate evidence id"
            );
            ensure!(
                classified_versions
                    .insert((version.object_key.as_str(), version.version_id.as_str(),)),
                "fragment classification contains a duplicate object version"
            );
            validate_unique_nonempty("classified fragment id", &version.fragment_ids, true)?;
            let mut object_hashes = BTreeSet::new();
            let mut reference_states = BTreeSet::new();
            for fragment_id in &version.fragment_ids {
                ensure!(
                    classified_fragment_ids.insert(fragment_id.as_str()),
                    "version classifications reuse a fragment identity"
                );
                let Some(entry) = before.get(fragment_id) else {
                    anyhow::bail!(
                        "classified fragment {fragment_id:?} is absent from the pre-cleanup inventory"
                    )
                };
                ensure!(
                    entry.object_key == version.object_key
                        && entry.version_id == version.version_id,
                    "classified fragment does not match its inventory object/version identity"
                );
                object_hashes.insert(entry.object_sha256.as_str());
                reference_states.insert(entry.reference_state);
            }
            ensure!(
                object_hashes.len() == 1 && reference_states.len() == 1,
                "all fragments classified for one object version must carry one object hash and reference state"
            );
            let object_sha256 = object_hashes
                .first()
                .copied()
                .expect("non-empty fragment classification has one object hash");

            let operation = match version.operation_id.as_deref() {
                Some(operation_id) => {
                    ensure!(
                        !operation_id.trim().is_empty(),
                        "classified operation id is empty"
                    );
                    let record = history_by_id
                        .get(operation_id)
                        .copied()
                        .context("classified version lacks its workload history operation")?;
                    ensure!(
                        record_matches_identity(record, &self.identity)
                            && is_object_commit(record.kind)
                            && valid_operation_interval(record)
                            && record.key.as_deref() == Some(version.object_key.as_str())
                            && record.value_sha256.as_deref() == Some(object_sha256)
                            && record.ended_at_ms <= self.writes_quiesced_at_ms,
                        "classified version is not bound to the matching pre-cleanup PUT or multipart completion"
                    );
                    Some(record)
                }
                None => None,
            };

            match version.recoverability {
                FragmentRecoverability::Committed => {
                    let Some(record) = operation else {
                        anyhow::bail!("committed fragments require a workload operation")
                    };
                    ensure!(
                        reference_states.contains(&FragmentReferenceState::ReferencedVersion)
                            && record.outcome == OperationOutcome::Ok
                            && record
                                .http_status
                                .is_some_and(|status| (200..300).contains(&status))
                            && record.version_id.as_deref() == Some(version.version_id.as_str()),
                        "committed fragments are not backed by a successful versioned write"
                    );
                    ensure!(
                        protected_operation_ids.insert(record.id.as_str()),
                        "one committed/ambiguous operation backs multiple classifications"
                    );
                }
                FragmentRecoverability::RecoverableUnknown => {
                    let Some(record) = operation else {
                        anyhow::bail!("recoverable-unknown fragments require an ACK-loss operation")
                    };
                    let status_is_ambiguous = match record.outcome {
                        OperationOutcome::Timeout => record.http_status.is_none(),
                        OperationOutcome::Unknown => {
                            record.http_status.is_none_or(ambiguous_http_status)
                        }
                        OperationOutcome::Failed => {
                            record.http_status.is_none_or(ambiguous_http_status)
                        }
                        _ => false,
                    };
                    ensure!(
                        reference_states.contains(&FragmentReferenceState::ReferencedVersion)
                            && status_is_ambiguous
                            && record.version_id.as_deref().is_none_or(|version_id| {
                                version_id == "null" || version_id == version.version_id
                            }),
                        "recoverable-unknown fragments are not backed by an ambiguous write outcome"
                    );
                    ack_loss_by_operation
                        .get(record.id.as_str())
                        .context(
                            "recoverable-unknown fragments lack a one-shot ACK-loss proxy receipt",
                        )?
                        .validate_for(&self.identity, record)?;
                    ensure!(
                        ack_loss_by_operation[record.id.as_str()].upstream_version_id
                            == version.version_id,
                        "ACK-loss upstream version does not match the classified inventory version"
                    );
                    if record
                        .version_id
                        .as_deref()
                        .is_none_or(|version_id| version_id == "null")
                    {
                        let possible_versions = inventory_versions_by_object
                            .get(&(version.object_key.as_str(), object_sha256))
                            .cloned()
                            .unwrap_or_default();
                        ensure!(
                            possible_versions.len() == 1
                                && possible_versions.contains(version.version_id.as_str()),
                            "an ACK-loss write without a version id must map to exactly one inventory version"
                        );
                    }
                    ensure!(
                        protected_operation_ids.insert(record.id.as_str()),
                        "one committed/ambiguous operation backs multiple classifications"
                    );
                }
                FragmentRecoverability::UncommittedDangling => {
                    ensure!(
                        reference_states.contains(&FragmentReferenceState::OrphanedUncommitted),
                        "uncommitted-dangling fragments lack authoritative orphan classification"
                    );
                    if let Some(record) = operation {
                        ensure!(
                            record.outcome == OperationOutcome::Failed
                                && record.http_status.is_some_and(|status| {
                                    (400..500).contains(&status) && status != 408
                                })
                                && record.version_id.as_deref().is_none_or(|version_id| {
                                    version_id == "null" || version_id == version.version_id
                                }),
                            "uncommitted-dangling fragments are not backed by a failed write"
                        );
                    }
                }
            }
        }
        ensure!(
            self.classified_versions
                .iter()
                .any(|version| { version.recoverability == FragmentRecoverability::Committed })
                && self.classified_versions.iter().any(|version| {
                    version.recoverability == FragmentRecoverability::RecoverableUnknown
                })
                && self.classified_versions.iter().any(|version| {
                    version.recoverability == FragmentRecoverability::UncommittedDangling
                }),
            "ACK-loss cleanup must exercise committed, recoverable-unknown, and uncommitted-dangling versions"
        );
        ensure!(
            classified_fragment_ids
                == before
                    .keys()
                    .map(|fragment_id| fragment_id.as_str())
                    .collect::<BTreeSet<_>>(),
            "fragment classifications do not cover the complete pre-cleanup inventory"
        );
        let inventory_versions = before_response
            .entries
            .iter()
            .map(|entry| {
                (
                    entry.object_key.as_str(),
                    entry.version_id.as_str(),
                    entry.object_sha256.as_str(),
                )
            })
            .collect::<BTreeSet<_>>();
        let inventory_objects = before_response
            .entries
            .iter()
            .map(|entry| (entry.object_key.as_str(), entry.object_sha256.as_str()))
            .collect::<BTreeSet<_>>();
        let mut relevant_protected_operations = BTreeSet::new();
        for record in history.iter().filter(|record| {
            record_matches_identity(record, &self.identity)
                && is_object_commit(record.kind)
                && write_may_have_committed(record)
                && valid_operation_interval(record)
                && record.ended_at_ms <= self.writes_quiesced_at_ms
        }) {
            let key = record
                .key
                .as_deref()
                .context("a possibly committed write lacks an object key")?;
            let object_sha256 = record
                .value_sha256
                .as_deref()
                .context("a possibly committed write lacks a content hash")?;
            let matches_inventory = match record.version_id.as_deref() {
                Some(version_id) if version_id != "null" => {
                    inventory_versions.contains(&(key, version_id, object_sha256))
                }
                _ => inventory_objects.contains(&(key, object_sha256)),
            };
            if matches_inventory {
                ensure!(
                    relevant_protected_operations.insert(record.id.as_str()),
                    "workload history contains a duplicate relevant operation id"
                );
            }
        }
        ensure!(
            protected_operation_ids == relevant_protected_operations,
            "fragment classifications do not exactly cover successful and ambiguous writes represented in the inventory"
        );
        ensure!(
            self.ack_loss_puts.iter().all(|evidence| {
                protected_operation_ids.contains(evidence.operation_id.as_str())
            }),
            "ACK-loss receipts contain an operation not protected by the inventory classification"
        );
        ensure!(
            after_response
                .entries
                .iter()
                .all(|entry| before.get(&entry.fragment_id) == Some(&entry)),
            "dangling cleanup changed or introduced a fragment instead of only removing one"
        );
        let removed_fragment_ids = before
            .keys()
            .filter(|fragment_id| !after.contains_key(*fragment_id))
            .map(|fragment_id| (*fragment_id).clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            self.orphan_injection.run_id == self.identity.run_id
                && self.orphan_injection.bucket == self.identity.bucket
                && self.orphan_injection.drive_uuid == self.returned_generation.rustfs_drive_uuid
                && self.orphan_injection.created_at_ms > self.writes_quiesced_at_ms
                && self.orphan_injection.created_at_ms < before_inventory.receipt.started_at_ms,
            "orphan injection receipt is not bound and ordered within the returned generation"
        );
        let injected = before
            .get(&self.orphan_injection.fragment_id)
            .context("run-owned injected orphan is absent from the pre-cleanup inventory")?;
        ensure!(
            injected.bucket == self.orphan_injection.bucket
                && injected.object_key == self.orphan_injection.object_key
                && injected.version_id == self.orphan_injection.version_id
                && injected.drive_uuid == self.orphan_injection.drive_uuid
                && injected.object_sha256 == self.orphan_injection.object_sha256
                && injected.sha256 == self.orphan_injection.fragment_sha256
                && injected.reference_state == FragmentReferenceState::OrphanedUncommitted,
            "pre-cleanup inventory does not bind the injected orphan receipt"
        );
        let mut removed_dangling = false;
        for version in &self.classified_versions {
            let protected = version.recoverability != FragmentRecoverability::UncommittedDangling;
            for fragment_id in &version.fragment_ids {
                let retained = after.get(fragment_id) == before.get(fragment_id);
                if protected {
                    ensure!(
                        retained,
                        "dangling cleanup removed a committed or recoverable-unknown fragment {fragment_id:?}"
                    );
                } else if !retained {
                    removed_dangling = true;
                }
            }
        }
        ensure!(
            removed_fragment_ids == BTreeSet::from([self.orphan_injection.fragment_id.clone()]),
            "post-cleanup inventory delta is not exactly the run-owned injected orphan"
        );
        ensure!(
            removed_dangling,
            "dangling-cleanup case has no proven uncommitted-dangling fragment removal signal"
        );
        Ok(())
    }
}

fn is_object_commit(kind: OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::Put | OperationKind::CompleteMultipartUpload
    )
}

fn is_object_mutation(kind: OperationKind) -> bool {
    matches!(
        kind,
        OperationKind::Put
            | OperationKind::Delete
            | OperationKind::CreateMultipartUpload
            | OperationKind::UploadPart
            | OperationKind::CompleteMultipartUpload
            | OperationKind::AbortMultipartUpload
    )
}

fn valid_operation_interval(record: &OperationRecord) -> bool {
    record.started_at_ms > 0 && record.started_at_ms <= record.ended_at_ms
}

fn ambiguous_http_status(status: u16) -> bool {
    status == 408 || (500..600).contains(&status)
}

fn write_may_have_committed(record: &OperationRecord) -> bool {
    match record.outcome {
        OperationOutcome::Ok | OperationOutcome::Timeout | OperationOutcome::Unknown => true,
        OperationOutcome::Failed => record.http_status.is_none_or(ambiguous_http_status),
        OperationOutcome::NotFound => false,
    }
}

fn validate_settled_current_mutations(
    history: &[OperationRecord],
    identity: &StorageRecoveryArtifactIdentity,
) -> Result<()> {
    let mut committed_by_key = BTreeMap::<String, Vec<&OperationRecord>>::new();
    for record in history.iter().filter(|record| {
        record_matches_identity(record, identity)
            && matches!(
                record.kind,
                OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
            )
    }) {
        if record.kind == OperationKind::Delete && write_may_have_committed(record) {
            ensure!(
                record.outcome == OperationOutcome::Ok
                    && record
                        .http_status
                        .is_some_and(|status| (200..300).contains(&status)),
                "stale-return history contains an ambiguous delete that could have committed: {}",
                record.id
            );
        }
        if record.outcome != OperationOutcome::Ok
            || !record
                .http_status
                .is_some_and(|status| (200..300).contains(&status))
        {
            continue;
        }
        let key = record
            .key
            .as_ref()
            .context("committed stale-return mutation lacks an object key")?;
        ensure!(
            record
                .version_id
                .as_deref()
                .is_some_and(|version_id| !version_id.is_empty() && version_id != "null"),
            "committed stale-return mutation {} lacks a usable version id",
            record.id
        );
        if is_object_commit(record.kind) {
            ensure!(
                record.value_sha256.is_some() && record.size_bytes.is_some(),
                "committed stale-return write {} lacks content identity",
                record.id
            );
        }
        let (Some(started_sequence), Some(ended_sequence)) =
            (record.started_sequence, record.ended_sequence)
        else {
            anyhow::bail!(
                "committed stale-return mutation {} lacks recorder event ordering",
                record.id
            );
        };
        ensure!(
            started_sequence < ended_sequence,
            "committed stale-return mutation {} has an invalid recorder event interval",
            record.id
        );
        committed_by_key
            .entry(key.clone())
            .or_default()
            .push(record);
    }
    for (key, records) in &mut committed_by_key {
        records.sort_by_key(|record| record.started_sequence);
        for pair in records.windows(2) {
            let previous_end = pair[0]
                .ended_sequence
                .expect("committed mutation sequence validated above");
            let next_start = pair[1]
                .started_sequence
                .expect("committed mutation sequence validated above");
            ensure!(
                previous_end < next_start,
                "stale-return mutations for key {key:?} overlap; response order cannot prove latest S3 state"
            );
        }
    }
    Ok(())
}

fn validate_immutable_version_history(
    history: &[OperationRecord],
    identity: &StorageRecoveryArtifactIdentity,
) -> Result<()> {
    validate_successful_version_identity_uniqueness(
        history
            .iter()
            .filter(|record| record_matches_identity(record, identity)),
    )?;
    for record in history.iter().filter(|record| {
        record_matches_identity(record, identity)
            && (is_object_commit(record.kind) || record.kind == OperationKind::Delete)
            && record.outcome == OperationOutcome::Ok
            && record
                .http_status
                .is_some_and(|status| (200..300).contains(&status))
    }) {
        let Some(_version_id) = record
            .version_id
            .as_deref()
            .filter(|version_id| *version_id != "null")
        else {
            continue;
        };
        ensure!(
            valid_operation_interval(record),
            "successful versioned write has an invalid operation interval"
        );
        let _key = record
            .key
            .as_deref()
            .filter(|key| !key.is_empty())
            .context("successful versioned write lacks an object key")?;
        if is_object_commit(record.kind) {
            let hash = record
                .value_sha256
                .as_deref()
                .context("successful versioned write lacks a content hash")?;
            validate_sha256("successful versioned write", hash)?;
        }
    }
    Ok(())
}

fn record_matches_identity(
    record: &OperationRecord,
    identity: &StorageRecoveryArtifactIdentity,
) -> bool {
    record.run_id.as_deref() == Some(identity.run_id.as_str())
        && record.scenario == identity.scenario
        && record.bucket == identity.bucket
}

fn unique_fragments<'a>(
    label: &str,
    entries: &'a [ShardInventoryEntry],
) -> Result<BTreeMap<&'a String, &'a ShardInventoryEntry>> {
    let mut fragments = BTreeMap::new();
    for entry in entries {
        ensure!(
            fragments.insert(&entry.fragment_id, entry).is_none(),
            "{label} shard inventory contains duplicate fragment id {:?}",
            entry.fragment_id
        );
    }
    Ok(fragments)
}

fn inventory_entries_sha256(entries: &[ShardInventoryEntry]) -> Result<String> {
    let mut canonical = entries.to_vec();
    canonical.sort();
    let encoded = serde_json::to_vec(&canonical)?;
    Ok(sha256_bytes(&encoded))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn heal_state_rank(state: HealProgressState) -> u8 {
    match state {
        HealProgressState::Queued => 0,
        HealProgressState::Running => 1,
        HealProgressState::Completed | HealProgressState::Failed => 2,
    }
}

fn operation_outcome_rank(outcome: OperationOutcome) -> u8 {
    match outcome {
        OperationOutcome::Ok => 0,
        OperationOutcome::NotFound => 1,
        OperationOutcome::Failed => 2,
        OperationOutcome::Timeout => 3,
        OperationOutcome::Unknown => 4,
    }
}

fn validate_unique_nonempty(label: &str, values: &[String], require_nonempty: bool) -> Result<()> {
    if require_nonempty {
        ensure!(!values.is_empty(), "{label} list is empty");
    }
    let mut unique = BTreeSet::new();
    for value in values {
        ensure!(
            !value.trim().is_empty() && unique.insert(value),
            "{label} list contains an empty or duplicate value"
        );
    }
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} SHA-256 must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn is_normalized_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && path
            .split('/')
            .skip(1)
            .all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

fn split_kubernetes_container_id(value: &str) -> Result<(&str, &str)> {
    let (runtime, container_id) = value
        .split_once("://")
        .context("Kubernetes container ID lacks its runtime scheme")?;
    ensure!(
        !runtime.is_empty()
            && container_id.len() == 64
            && container_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Kubernetes container ID must contain a runtime and a 64-hex CRI ID"
    );
    Ok((runtime, container_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::quorum::ErasureSetMember;

    const HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn volume(generation: &str, observed_at_ms: u64) -> StorageVolumeIdentity {
        StorageVolumeIdentity {
            target_proof_sha256: HASH_A.to_string(),
            host_storage_proof_sha256: HASH_B.to_string(),
            rustfs_deployment_id: "deployment-1".to_string(),
            namespace: "fault-run".to_string(),
            tenant: "rustfs".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: format!("pod-{generation}"),
            rustfs_container_id: format!("containerd://{}", sha256_bytes(generation.as_bytes())),
            volume_name: "data-0".to_string(),
            persistent_volume_claim: "data-0-rustfs-0".to_string(),
            persistent_volume_claim_uid: format!("pvc-{generation}"),
            persistent_volume: format!("pv-{generation}"),
            persistent_volume_uid: format!("pv-uid-{generation}"),
            node: "worker-0".to_string(),
            node_uid: "node-0".to_string(),
            storage_class: "rustfs-local".to_string(),
            local_volume_path: "/var/lib/rustfs/data0".to_string(),
            mount_path: "/data0".to_string(),
            canonical_device: format!("/dev/mapper/data-{generation}"),
            target_mount_namespace_id: "mnt:[4026533000]".to_string(),
            filesystem_uuid: format!("fs-{generation}"),
            rustfs_drive_uuid: format!("drive-{generation}"),
            pool_index: 0,
            set_index: 0,
            observed_at_ms,
        }
    }

    fn identity(scenario: &str) -> StorageRecoveryArtifactIdentity {
        StorageRecoveryArtifactIdentity {
            run_id: "run-1".to_string(),
            scenario: scenario.to_string(),
            case_name: format!("case-{scenario}"),
            bucket: "bucket-1".to_string(),
        }
    }

    fn returned_runtime(
        mut volume: StorageVolumeIdentity,
        observed_at_ms: u64,
    ) -> StorageVolumeIdentity {
        volume.pod_uid = "pod-returned".to_string();
        volume.rustfs_container_id = format!("containerd://{HASH_C}");
        volume.target_mount_namespace_id = "mnt:[4026533999]".to_string();
        volume.target_proof_sha256 = HASH_C.to_string();
        volume.host_storage_proof_sha256 = HASH_A.to_string();
        volume.observed_at_ms = observed_at_ms;
        volume
    }

    fn host_execution(volume: &StorageVolumeIdentity) -> HostExecutionIdentity {
        let (_, cri_container_id) =
            split_kubernetes_container_id(&volume.rustfs_container_id).expect("container ID");
        let helper_pod = format!("s3chaos-host-helper-{}", volume.node);
        let helper_pod_uid = format!("helper-uid-{}", volume.node_uid);
        let helper_pod_body = serde_json::to_string(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "namespace": volume.namespace,
                "name": helper_pod,
                "uid": helper_pod_uid,
                "resourceVersion": "helper-rv-1"
            },
            "spec": {"nodeName": volume.node},
            "status": {"phase": "Running"}
        }))
        .expect("host helper Pod");
        let inspect_stdout_body = serde_json::to_string(&serde_json::json!({
            "status": {"id": cri_container_id},
            "info": {"pid": 4242}
        }))
        .expect("container inspect response");
        let runtime_body = serde_json::to_string(&HostTargetRuntimeResponse {
            target_container_id: volume.rustfs_container_id.clone(),
            cri_container_id: cri_container_id.to_string(),
            container_pid: 4242,
            inspect_argv: vec![
                "crictl".to_string(),
                "inspect".to_string(),
                cri_container_id.to_string(),
            ],
            inspect_exit_code: 0,
            inspect_stdout_sha256: sha256_bytes(inspect_stdout_body.as_bytes()),
            inspect_stdout_body,
            inspect_stderr: String::new(),
            mount_namespace_argv: vec!["readlink".to_string(), "/proc/4242/ns/mnt".to_string()],
            mount_namespace_exit_code: 0,
            mount_namespace_stdout: volume.target_mount_namespace_id.clone(),
            mount_namespace_stderr: String::new(),
        })
        .expect("target runtime identity");
        HostExecutionIdentity {
            namespace: volume.namespace.clone(),
            node: volume.node.clone(),
            node_uid: volume.node_uid.clone(),
            target_pod: volume.pod.clone(),
            target_pod_uid: volume.pod_uid.clone(),
            target_container_id: volume.rustfs_container_id.clone(),
            helper_pod,
            helper_pod_uid,
            mount_namespace_id: volume.target_mount_namespace_id.clone(),
            helper_pod_sha256: sha256_bytes(helper_pod_body.as_bytes()),
            helper_pod_body,
            target_runtime_sha256: sha256_bytes(runtime_body.as_bytes()),
            target_runtime_body: runtime_body,
        }
    }

    fn mutation_target_proof_body(volume: &StorageVolumeIdentity) -> String {
        let target_index = volume
            .pod
            .strip_prefix("rustfs-")
            .and_then(|index| index.parse::<usize>().ok())
            .expect("indexed RustFS Pod name");
        let shape = ErasureSetShape {
            pool_index: volume.pool_index,
            set_index: volume.set_index,
            server_count: 8,
            volumes_per_server: 1,
            total_shards: 8,
            payload_data_shards: 4,
            payload_parity_shards: 4,
        };
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..8)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![if index == target_index {
                        volume.rustfs_drive_uuid.clone()
                    } else {
                        format!("drive-{index}")
                    }],
                })
                .collect(),
        )
        .expect("mutation target membership");
        serde_json::to_string(&serde_json::json!({
            "schemaVersion": TARGET_PROOF_SCHEMA_VERSION,
            "status": "satisfied",
            "proofLevel": "selector_intent",
            "generatedAtMs": volume.observed_at_ms,
            "scenario": "on-disk-bitrot",
            "caseName": "case-on-disk-bitrot",
            "runId": "run-1",
            "namespace": volume.namespace,
            "tenant": volume.tenant,
            "resolvedPods": [{
                "name": volume.pod,
                "uid": volume.pod_uid,
                "rustfsContainerId": volume.rustfs_container_id,
                "ready": true,
                "node": volume.node,
                "nodeLabels": {"kubernetes.io/hostname": volume.node},
                "persistentVolumeClaims": [{
                    "name": volume.persistent_volume_claim,
                    "uid": volume.persistent_volume_claim_uid,
                    "volumeName": volume.persistent_volume,
                    "storageClass": volume.storage_class,
                    "persistentVolume": {
                        "name": volume.persistent_volume,
                        "uid": volume.persistent_volume_uid,
                        "source": "local",
                        "node": volume.node,
                        "deviceOrPath": volume.local_volume_path
                    }
                }],
                "volumeMounts": [{
                    "containerName": "rustfs",
                    "mountPath": volume.mount_path,
                    "volumeName": volume.volume_name,
                    "persistentVolumeClaim": volume.persistent_volume_claim
                }]
            }],
            "faults": [{
                "name": "bitrot-mutation",
                "kind": "rustfs-on-disk-bitrot",
                "backend": "host",
                "targetKind": "rustfs-shard",
                "targetSummary": "one mapped RustFS shard",
                "selection": "fixed-targets(1)",
                "selectionKind": "fixed-targets",
                "selectionValue": 1,
                "conflictDomain": "dedicated host volume",
                "erasureSet": {
                    "required": true,
                    "resolved": true,
                    "source": "rustfs-admin-server-info",
                    "deploymentId": volume.rustfs_deployment_id,
                    "shape": shape,
                    "health": {
                        "onlineShards": 8,
                        "offlineShards": 0,
                        "unknownShards": 0
                    },
                    "membership": membership,
                    "observedAtMs": volume.observed_at_ms,
                    "note": "captured before shard mapping"
                }
            }],
            "requirements": [{
                "name": "target_volume_bindings_resolved",
                "status": "passed",
                "message": "resolved"
            }]
        }))
        .expect("mutation target proof")
    }

    fn rebind_mutation_target_proof(proof: &mut ShardMutationProof, body: String) {
        let sha256 = sha256_bytes(body.as_bytes());
        proof.mutation_target_proof_body = body;
        proof.volume.target_proof_sha256 = sha256.clone();
        proof.path_containment.target_proof_sha256 = sha256.clone();
        proof.rollback.target_proof_sha256 = sha256.clone();
        let evidence = proof
            .host_mutation_evidence
            .as_mut()
            .expect("host mutation evidence");
        let mut receipt = serde_json::from_str::<ShardMutationHostReceipt>(&evidence.response_body)
            .expect("host mutation receipt");
        receipt.target_proof_sha256 = sha256;
        evidence.response_body = serde_json::to_string(&receipt).expect("host mutation receipt");
        evidence.response_sha256 = sha256_bytes(evidence.response_body.as_bytes());
    }

    fn bitrot_mutation_proof(
        mut volume: StorageVolumeIdentity,
        object_key: &str,
        version_id: &str,
        mapped_at_ms: u64,
        mutated_at_ms: u64,
        rollback_pwrite_started_at_ms: u64,
        rollback_observed_at_ms: u64,
    ) -> ShardMutationProof {
        let target_proof_body = mutation_target_proof_body(&volume);
        let target_proof_sha256 = sha256_bytes(target_proof_body.as_bytes());
        volume.target_proof_sha256 = target_proof_sha256.clone();
        let shard_path = format!("{}/.rustfs/shard", volume.mount_path);
        let mapping_response = serde_json::to_string(&RustfsShardMutationMappingResponse {
            bucket: "bucket-1".to_string(),
            object_key: object_key.to_string(),
            version_id: version_id.to_string(),
            object_sha256: HASH_A.to_string(),
            drive_uuid: volume.rustfs_drive_uuid.clone(),
            shard_path: shard_path.clone(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
        })
        .expect("shard mapping response");
        let path_response = serde_json::to_string(&Openat2PathResolutionReceipt {
            execution: host_execution(&volume),
            method: ShardPathResolutionMethod::Openat2BeneathNoSymlinksNoXdev,
            requested_path: shard_path.clone(),
            canonical_mount_path: volume.mount_path.clone(),
            mount_canonical_device: volume.canonical_device.clone(),
            mount_filesystem_uuid: volume.filesystem_uuid.clone(),
            resolved_path: shard_path.clone(),
            mount_device_id: "259:0".to_string(),
            returned_fd_device_id: "259:0".to_string(),
            returned_fd_inode: 42,
        })
        .expect("openat2 path receipt");
        let host_mutation_response = serde_json::to_string(&ShardMutationHostReceipt {
            execution: host_execution(&volume),
            shard_path: shard_path.clone(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
            byte_offset: 4096,
            byte_length: 1,
            original_sha256: HASH_A.to_string(),
            mutated_sha256: HASH_B.to_string(),
            rollback_sha256: HASH_A.to_string(),
            original_observed_at_ms: mapped_at_ms,
            pwrite_completed_at_ms: mutated_at_ms,
            mutation_fsync_completed_at_ms: mutated_at_ms,
            mutation_fstat_observed_at_ms: mutated_at_ms,
            mutated_readback_at_ms: mutated_at_ms,
            rollback_pwrite_started_at_ms,
            rollback_pwrite_completed_at_ms: rollback_pwrite_started_at_ms,
            rollback_fsync_completed_at_ms: rollback_pwrite_started_at_ms,
            rollback_fstat_observed_at_ms: rollback_observed_at_ms,
            rollback_readback_at_ms: rollback_observed_at_ms,
            pwrite_bytes: 1,
            rollback_pwrite_bytes: 1,
            mutation_fsync_succeeded: true,
            rollback_fsync_succeeded: true,
            target_proof_sha256: target_proof_sha256.clone(),
            host_storage_proof_sha256: volume.host_storage_proof_sha256.clone(),
        })
        .expect("host mutation receipt");
        ShardMutationProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("on-disk-bitrot"),
            mapping_source: ShardMappingSource::RustfsDiagnosticApi,
            mapping_api_revision: "v1".to_string(),
            mapping_response_sha256: sha256_bytes(mapping_response.as_bytes()),
            mapping_response_body: mapping_response,
            object_key: object_key.to_string(),
            version_id: version_id.to_string(),
            expected_object_sha256: HASH_A.to_string(),
            volume: volume.clone(),
            mutation_target_proof_body: target_proof_body,
            shard_path: shard_path.clone(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
            path_containment: ShardPathContainmentProof {
                observed_at_ms: mapped_at_ms,
                resolver_evidence_sha256: sha256_bytes(path_response.as_bytes()),
                resolver_response_body: path_response,
                target_proof_sha256: target_proof_sha256.clone(),
                host_storage_proof_sha256: volume.host_storage_proof_sha256.clone(),
            },
            byte_offset: 4096,
            byte_length: 1,
            original_sha256: HASH_A.to_string(),
            mutated_sha256: HASH_B.to_string(),
            host_mutation_evidence: Some(ShardMutationHostEvidence {
                response_sha256: sha256_bytes(host_mutation_response.as_bytes()),
                response_body: host_mutation_response,
            }),
            rollback: ShardRollbackObservation {
                shard_path,
                shard_device_id: "259:0".to_string(),
                shard_inode: 42,
                shard_size_bytes: 8192,
                observed_sha256: HASH_A.to_string(),
                observed_at_ms: rollback_observed_at_ms,
                target_proof_sha256,
                host_storage_proof_sha256: volume.host_storage_proof_sha256,
            },
            mapped_at_ms,
            mutated_at_ms,
        }
    }

    fn corruption_probe(
        mutation: &ShardMutationProof,
        operation_id: &str,
        detected_at_ms: u64,
    ) -> CorruptionWindowProbe {
        let response_body = serde_json::to_string(&RustfsBitrotDetectionResponse {
            operation_id: operation_id.to_string(),
            bucket: mutation.identity.bucket.clone(),
            object_key: mutation.object_key.clone(),
            version_id: mutation.version_id.clone(),
            drive_uuid: mutation.volume.rustfs_drive_uuid.clone(),
            shard_path: mutation.shard_path.clone(),
            shard_device_id: mutation.shard_device_id.clone(),
            shard_inode: mutation.shard_inode,
            expected_shard_sha256: mutation.original_sha256.clone(),
            observed_shard_sha256: mutation.mutated_sha256.clone(),
            code: BitrotDetectionCode::ShardChecksumMismatch,
            detected_at_ms,
            target_proof_sha256: mutation.volume.target_proof_sha256.clone(),
            host_storage_proof_sha256: mutation.volume.host_storage_proof_sha256.clone(),
        })
        .expect("RustFS bitrot detection response");
        CorruptionWindowProbe {
            operation_id: operation_id.to_string(),
            object_key: mutation.object_key.clone(),
            version_id: mutation.version_id.clone(),
            expected_sha256: mutation.expected_object_sha256.clone(),
            detection_evidence: BitrotDetectionEvidence {
                api_revision: "v1".to_string(),
                response_sha256: sha256_bytes(response_body.as_bytes()),
                response_body,
            },
        }
    }

    fn empty_observation(
        replacement: &StorageVolumeIdentity,
        observed_at_ms: u64,
    ) -> EmptyVolumeObservation {
        let response = serde_json::to_string(&EmptyVolumeScanResponse {
            persistent_volume_uid: replacement.persistent_volume_uid.clone(),
            canonical_device: replacement.canonical_device.clone(),
            filesystem_uuid: replacement.filesystem_uuid.clone(),
            rustfs_process_can_access_volume: false,
            scan_started_at_ms: observed_at_ms - 1,
            scan_completed_at_ms: observed_at_ms,
            exhaustive: true,
            data_entries: vec![],
        })
        .expect("empty-volume scan response");
        EmptyVolumeObservation {
            observed_at_ms,
            persistent_volume_uid: replacement.persistent_volume_uid.clone(),
            canonical_device: replacement.canonical_device.clone(),
            filesystem_uuid: replacement.filesystem_uuid.clone(),
            rustfs_process_can_access_volume: false,
            data_entries: vec![],
            scan_response_sha256: sha256_bytes(response.as_bytes()),
            scan_response_body: response,
        }
    }

    fn raw_disk_state_evidence(
        generation: &StorageVolumeIdentity,
        state: DiskPresenceState,
        observed_at_ms: u64,
    ) -> RawDiskStateEvidence {
        let execution = host_execution(generation);
        let response = RawDiskStateResponse::HostDevice {
            execution,
            argv: vec![
                "nsenter".to_string(),
                "--target".to_string(),
                "4242".to_string(),
                "--mount".to_string(),
                "--".to_string(),
                "findmnt".to_string(),
                "-n".to_string(),
                "--raw".to_string(),
                "-o".to_string(),
                "SOURCE,TARGET".to_string(),
                "--mountpoint".to_string(),
                generation.mount_path.clone(),
            ],
            exit_code: match state {
                DiskPresenceState::Present => 0,
                DiskPresenceState::Absent => 0,
            },
            stdout: match state {
                DiskPresenceState::Present => {
                    format!("{} {}", generation.canonical_device, generation.mount_path)
                }
                DiskPresenceState::Absent => "/dev/root /".to_string(),
            },
            stderr: String::new(),
            observed_at_ms,
            mount_path: generation.mount_path.clone(),
            canonical_device: generation.canonical_device.clone(),
        };
        let response_body = serde_json::to_string(&response).expect("raw disk-state response");
        RawDiskStateEvidence {
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
        }
    }

    fn kubernetes_binding_evidence(
        generation: &StorageVolumeIdentity,
        observed_at_ms: u64,
    ) -> KubernetesLocalPvBindingEvidence {
        let persistent_volume_body = serde_json::to_string(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolume",
            "metadata": {
                "name": generation.persistent_volume,
                "uid": generation.persistent_volume_uid,
                "resourceVersion": format!("rv-{observed_at_ms}-pv")
            },
            "spec": {
                "storageClassName": generation.storage_class,
                "local": {"path": generation.local_volume_path},
                "claimRef": {
                    "namespace": generation.namespace,
                    "name": generation.persistent_volume_claim,
                    "uid": generation.persistent_volume_claim_uid
                },
                "nodeAffinity": {"required": {"nodeSelectorTerms": [{
                    "matchExpressions": [{
                        "key": "kubernetes.io/hostname",
                        "operator": "In",
                        "values": [generation.node]
                    }]
                }]}}
            },
            "status": {"phase": "Bound"}
        }))
        .expect("raw Kubernetes PersistentVolume");
        let persistent_volume_claim_body = serde_json::to_string(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {
                "name": generation.persistent_volume_claim,
                "namespace": generation.namespace,
                "uid": generation.persistent_volume_claim_uid,
                "resourceVersion": format!("rv-{observed_at_ms}-pvc")
            },
            "spec": {
                "storageClassName": generation.storage_class,
                "volumeName": generation.persistent_volume
            },
            "status": {"phase": "Bound"}
        }))
        .expect("raw Kubernetes PersistentVolumeClaim");
        let pod_body = serde_json::to_string(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": generation.pod,
                "namespace": generation.namespace,
                "uid": generation.pod_uid,
                "resourceVersion": format!("rv-{observed_at_ms}-pod")
            },
            "spec": {
                "nodeName": generation.node,
                "volumes": [{
                    "name": generation.volume_name,
                    "persistentVolumeClaim": {"claimName": generation.persistent_volume_claim}
                }],
                "containers": [{
                    "name": "rustfs",
                    "volumeMounts": [{
                        "name": generation.volume_name,
                        "mountPath": generation.mount_path
                    }]
                }]
            },
            "status": {"containerStatuses": [{
                "name": "rustfs",
                "containerID": generation.rustfs_container_id
            }]}
        }))
        .expect("raw Kubernetes Pod");
        let node_body = serde_json::to_string(&serde_json::json!({
            "apiVersion": "v1",
            "kind": "Node",
            "metadata": {
                "name": generation.node,
                "uid": generation.node_uid,
                "resourceVersion": format!("rv-{observed_at_ms}-node")
            }
        }))
        .expect("raw Kubernetes Node");
        let response = KubernetesLocalPvBindingResponse {
            observed_at_ms,
            persistent_volume_sha256: sha256_bytes(persistent_volume_body.as_bytes()),
            persistent_volume_body,
            persistent_volume_claim_sha256: sha256_bytes(persistent_volume_claim_body.as_bytes()),
            persistent_volume_claim_body,
            pod_sha256: sha256_bytes(pod_body.as_bytes()),
            pod_body,
            node_sha256: sha256_bytes(node_body.as_bytes()),
            node_body,
        };
        let response_body =
            serde_json::to_string(&response).expect("Kubernetes Local PV binding response");
        KubernetesLocalPvBindingEvidence {
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
        }
    }

    fn absence_observation(
        generation: &StorageVolumeIdentity,
        observation_id: &str,
        watch_started_at_ms: u64,
    ) -> DiskAbsenceObservation {
        let sample = |observed_at_ms, state| {
            let raw_evidence = raw_disk_state_evidence(generation, state, observed_at_ms);
            HostDiskStateSample {
                cursor: raw_evidence.response_sha256.clone(),
                observed_at_ms,
                state,
                raw_evidence,
            }
        };
        let watch_response = serde_json::to_string(&RustfsDiskAbsenceWatchResponse {
            observation_id: observation_id.to_string(),
            detachment_operation_id: "detach-1".to_string(),
            persistent_volume: generation.persistent_volume.clone(),
            persistent_volume_uid: generation.persistent_volume_uid.clone(),
            canonical_device: generation.canonical_device.clone(),
            filesystem_uuid: generation.filesystem_uuid.clone(),
            rustfs_drive_uuid: generation.rustfs_drive_uuid.clone(),
            target_proof_sha256: generation.target_proof_sha256.clone(),
            host_storage_proof_sha256: generation.host_storage_proof_sha256.clone(),
            watch_started_at_ms,
            watch_ended_at_ms: 400,
            poll_interval_ms: 50,
            samples: vec![
                sample(watch_started_at_ms, DiskPresenceState::Present),
                sample(200, DiskPresenceState::Absent),
                sample(240, DiskPresenceState::Absent),
                sample(280, DiskPresenceState::Absent),
                sample(320, DiskPresenceState::Absent),
                sample(340, DiskPresenceState::Absent),
                sample(380, DiskPresenceState::Absent),
                sample(400, DiskPresenceState::Absent),
            ],
            closed_normally: true,
        })
        .expect("disk-absence watch response");
        DiskAbsenceObservation {
            observation_id: observation_id.to_string(),
            detachment_operation_id: "detach-1".to_string(),
            persistent_volume: generation.persistent_volume.clone(),
            persistent_volume_uid: generation.persistent_volume_uid.clone(),
            canonical_device: generation.canonical_device.clone(),
            filesystem_uuid: generation.filesystem_uuid.clone(),
            rustfs_drive_uuid: generation.rustfs_drive_uuid.clone(),
            target_proof_sha256: generation.target_proof_sha256.clone(),
            host_storage_proof_sha256: generation.host_storage_proof_sha256.clone(),
            watch_started_at_ms,
            watch_ended_at_ms: 400,
            kubernetes_binding_evidence: kubernetes_binding_evidence(
                generation,
                watch_started_at_ms,
            ),
            host_watch_evidence: DiskAbsenceWatchEvidence {
                response_sha256: sha256_bytes(watch_response.as_bytes()),
                response_body: watch_response,
            },
        }
    }

    fn set_absence_watch_end(
        observation: &mut DiskAbsenceObservation,
        generation: &StorageVolumeIdentity,
        watch_ended_at_ms: u64,
    ) {
        observation.watch_ended_at_ms = watch_ended_at_ms;
        let evidence = &mut observation.host_watch_evidence;
        let mut response =
            serde_json::from_str::<RustfsDiskAbsenceWatchResponse>(&evidence.response_body)
                .expect("disk-absence watch response");
        response.watch_ended_at_ms = watch_ended_at_ms;
        response
            .samples
            .retain(|sample| sample.observed_at_ms < watch_ended_at_ms);
        let raw_evidence =
            raw_disk_state_evidence(generation, DiskPresenceState::Absent, watch_ended_at_ms);
        response.samples.push(HostDiskStateSample {
            cursor: raw_evidence.response_sha256.clone(),
            observed_at_ms: watch_ended_at_ms,
            state: DiskPresenceState::Absent,
            raw_evidence,
        });
        evidence.response_body =
            serde_json::to_string(&response).expect("disk-absence watch response");
        evidence.response_sha256 = sha256_bytes(evidence.response_body.as_bytes());
    }

    fn mutate_host_watch(
        observation: &mut DiskAbsenceObservation,
        mutate: impl FnOnce(&mut RustfsDiskAbsenceWatchResponse),
    ) {
        let evidence = &mut observation.host_watch_evidence;
        let mut response =
            serde_json::from_str::<RustfsDiskAbsenceWatchResponse>(&evidence.response_body)
                .expect("host watch response");
        mutate(&mut response);
        evidence.response_body = serde_json::to_string(&response).expect("host watch response");
        evidence.response_sha256 = sha256_bytes(evidence.response_body.as_bytes());
    }

    fn stale_disk_lifecycle_evidence(
        detached_generation: &StorageVolumeIdentity,
        returned_generation: &StorageVolumeIdentity,
    ) -> StaleDiskLifecycleEvidence {
        let operation = |generation: &StorageVolumeIdentity,
                         operation_id: &str,
                         action: StaleDiskLifecycleAction,
                         started_at_ms: u64,
                         completed_at_ms: u64| {
            let state = match action {
                StaleDiskLifecycleAction::Detach => DiskPresenceState::Absent,
                StaleDiskLifecycleAction::Reattach => DiskPresenceState::Present,
            };
            let response = serde_json::to_string(&RustfsStaleDiskOperationReceipt {
                operation_id: operation_id.to_string(),
                action,
                persistent_volume: generation.persistent_volume.clone(),
                persistent_volume_uid: generation.persistent_volume_uid.clone(),
                canonical_device: generation.canonical_device.clone(),
                filesystem_uuid: generation.filesystem_uuid.clone(),
                rustfs_drive_uuid: generation.rustfs_drive_uuid.clone(),
                target_proof_sha256: generation.target_proof_sha256.clone(),
                host_storage_proof_sha256: generation.host_storage_proof_sha256.clone(),
                started_at_ms,
                completed_at_ms,
                kubernetes_binding_evidence: kubernetes_binding_evidence(
                    generation,
                    completed_at_ms,
                ),
                host_result_evidence: raw_disk_state_evidence(generation, state, completed_at_ms),
            })
            .expect("stale-disk operation receipt");
            StaleDiskOperationEvidence {
                response_sha256: sha256_bytes(response.as_bytes()),
                response_body: response,
            }
        };
        StaleDiskLifecycleEvidence {
            detach: operation(
                detached_generation,
                "detach-1",
                StaleDiskLifecycleAction::Detach,
                190,
                200,
            ),
            reattach: operation(
                returned_generation,
                "reattach-1",
                StaleDiskLifecycleAction::Reattach,
                425,
                450,
            ),
        }
    }

    fn post_return_checker(history: &[OperationRecord]) -> PostReturnCheckerEvidence {
        let prefix_record_count = history
            .iter()
            .position(|record| record.id.starts_with("checker-"))
            .unwrap_or(history.len());
        let history_prefix = &history[..prefix_record_count];
        let history_suffix = &history[prefix_record_count..];
        let mut data_version_checks = history_prefix
            .iter()
            .filter(|record| {
                matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                ) && record.outcome == OperationOutcome::Ok
            })
            .map(|record| {
                let expected_sha256 = record.value_sha256.clone().expect("data version hash");
                CheckerDataVersionAudit {
                    key: record.key.clone().expect("versioned object key"),
                    version_id: record.version_id.clone().expect("version id"),
                    expected_sha256: expected_sha256.clone(),
                    observed_sha256: Some(expected_sha256),
                    outcome: OperationOutcome::Ok,
                    http_status: Some(200),
                }
            })
            .collect::<Vec<_>>();
        data_version_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        let mut delete_marker_checks = history_prefix
            .iter()
            .filter(|record| {
                record.kind == OperationKind::Delete && record.outcome == OperationOutcome::Ok
            })
            .map(|record| CheckerDeleteMarkerAudit {
                key: record.key.clone().expect("delete-marker object key"),
                version_id: record.version_id.clone().expect("delete-marker version id"),
                visible_in_list_object_versions: true,
            })
            .collect::<Vec<_>>();
        delete_marker_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        let current_state = committed_current_state_for_test(history_prefix);
        let expected_live_objects = current_state
            .values()
            .filter(|value| value.is_some())
            .count();
        let expected_versions = data_version_checks.len();
        let report = CheckerReport {
            scenario: "stale-disk-return-detect".to_string(),
            run_id: "run-1".to_string(),
            committed_puts: expected_versions,
            expected_live_objects,
            verified_live_objects: expected_live_objects,
            missing_committed_objects: Vec::new(),
            unavailable_committed_objects: Vec::new(),
            unknown_committed_read_failures: Vec::new(),
            hash_mismatches: Vec::new(),
            successful_corrupted_reads: Vec::new(),
            unexpected_visible_deleted_objects: Vec::new(),
            unknown_writes_materialized: Vec::new(),
            unknown_writes_preserved_committed: Vec::new(),
            unknown_write_value_conflicts: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: Some(expected_live_objects),
            versioning_expected: true,
            expected_committed_versions: expected_versions,
            verified_committed_versions: expected_versions,
            committed_writes_missing_version_id_count: 0,
            committed_writes_missing_version_id: Vec::new(),
            missing_committed_versions: Vec::new(),
            unavailable_committed_versions: Vec::new(),
            version_hash_mismatches: Vec::new(),
            missing_committed_delete_markers: Vec::new(),
            resurrected_deleted_objects: Vec::new(),
            listed_keys_unreadable: Vec::new(),
            unexpected_listed_objects: Vec::new(),
            failed_writes_materialized: Vec::new(),
            delete_marker_lineage_incomplete: Vec::new(),
            multipart_upload_lineage_incomplete: Vec::new(),
            tolerated_ambiguous_deletes: Vec::new(),
            operation_cohorts: BTreeMap::new(),
            fault_window_relations: BTreeMap::new(),
            audit: Some(crate::fault::checker::CheckerAudit {
                bucket: "bucket-1".to_string(),
                started_at_ms: 560,
                completed_at_ms: 580,
                history_prefix_record_count: prefix_record_count,
                history_prefix_sha256: checker_history_records_sha256(history_prefix)
                    .expect("history snapshot"),
                history_suffix_record_count: history_suffix.len(),
                history_suffix_sha256: checker_history_records_sha256(history_suffix)
                    .expect("checker suffix"),
                suffix_operations: checker_operation_audits(history_suffix),
                data_version_checks,
                delete_marker_checks,
                list_object_versions_completed: Some(true),
            }),
            tenant_recovered: true,
            passed: true,
        };
        let response_body = serde_json::to_string(&report).expect("post-return checker report");
        PostReturnCheckerEvidence {
            response_sha256: sha256_bytes(response_body.as_bytes()),
            response_body,
        }
    }

    fn append_post_return_checker_suffix(history: &mut Vec<OperationRecord>) {
        let current_state = committed_current_state_for_test(history);
        let current_get_keys = checker_expected_current_get_keys(history);
        let listed_keys = checker_expected_live_keys(history)
            .into_iter()
            .collect::<Vec<_>>();
        let listed_versions = checker_expected_version_listing(history)
            .into_iter()
            .collect::<Vec<_>>();
        let data_versions = history
            .iter()
            .filter(|record| {
                matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                ) && record.outcome == OperationOutcome::Ok
            })
            .cloned()
            .collect::<Vec<_>>();
        for (index, version) in data_versions.into_iter().enumerate() {
            let mut get = history_record(
                &format!("checker-version-get-{index}"),
                "stale-disk-return-detect",
                OperationKind::Get,
                version.key.as_deref().expect("data-version key"),
                version.version_id.as_deref().expect("data-version id"),
                version.value_sha256.as_deref(),
                570,
            );
            get.durability_cohort = Some(DurabilityCohort::PostRecovery);
            get.fault_window_relation = Some(FaultWindowRelation::AfterFault);
            history.push(get);
        }
        for (index, key) in current_get_keys.into_iter().enumerate() {
            let expected_sha256 = current_state.get(&key).cloned().flatten();
            let mut get = history_record(
                &format!("checker-current-get-{index}"),
                "stale-disk-return-detect",
                OperationKind::Get,
                &key,
                "",
                expected_sha256.as_deref(),
                572,
            );
            get.version_id = None;
            if expected_sha256.is_none() {
                get.outcome = OperationOutcome::NotFound;
                get.http_status = Some(404);
                get.error = Some("get object failed: NoSuchKey".to_string());
            }
            get.durability_cohort = Some(DurabilityCohort::PostRecovery);
            get.fault_window_relation = Some(FaultWindowRelation::AfterFault);
            history.push(get);
        }
        for (id, kind, ended_at_ms) in [
            ("checker-list-versions", OperationKind::ListVersions, 575),
            ("checker-list", OperationKind::List, 578),
        ] {
            let mut record = history_record(
                id,
                "stale-disk-return-detect",
                kind,
                "fault-test/run-1/",
                "",
                None,
                ended_at_ms,
            );
            record.durability_cohort = Some(DurabilityCohort::PostRecovery);
            record.fault_window_relation = Some(FaultWindowRelation::AfterFault);
            record.version_id = None;
            match kind {
                OperationKind::ListVersions => {
                    record.size_bytes = Some(listed_versions.len());
                    record.listed_versions = Some(listed_versions.clone());
                }
                OperationKind::List => {
                    record.size_bytes = Some(listed_keys.len());
                    record.listed_keys = Some(listed_keys.clone());
                }
                _ => unreachable!("checker suffix only appends list operations"),
            }
            history.push(record);
        }
        for (index, record) in history.iter_mut().enumerate() {
            record.started_sequence = Some((index as u64) * 2 + 1);
            record.ended_sequence = Some((index as u64) * 2 + 2);
        }
    }

    fn committed_current_state_for_test(
        history: &[OperationRecord],
    ) -> BTreeMap<String, Option<String>> {
        let mut state = BTreeMap::new();
        for record in history.iter().filter(|record| {
            record.outcome == OperationOutcome::Ok
                && record
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
        }) {
            let Some(key) = record.key.clone() else {
                continue;
            };
            match record.kind {
                OperationKind::Put | OperationKind::CompleteMultipartUpload => {
                    state.insert(key, record.value_sha256.clone());
                }
                OperationKind::Delete => {
                    state.insert(key, None);
                }
                _ => {}
            }
        }
        state
    }

    fn checker_prefix_record_count(evidence: &PostReturnCheckerEvidence) -> usize {
        serde_json::from_str::<CheckerReport>(&evidence.response_body)
            .expect("checker report")
            .audit
            .expect("checker audit")
            .history_prefix_record_count
    }

    fn rebind_checker_suffix(
        evidence: &mut PostReturnCheckerEvidence,
        history: &[OperationRecord],
    ) {
        let mut report =
            serde_json::from_str::<CheckerReport>(&evidence.response_body).expect("checker report");
        let audit = report.audit.as_mut().expect("checker audit");
        let suffix = &history[audit.history_prefix_record_count..];
        audit.history_suffix_record_count = suffix.len();
        audit.history_suffix_sha256 =
            checker_history_records_sha256(suffix).expect("checker suffix");
        audit.suffix_operations = checker_operation_audits(suffix);
        evidence.response_body = serde_json::to_string(&report).expect("checker report");
        evidence.response_sha256 = sha256_bytes(evidence.response_body.as_bytes());
    }

    fn history_record(
        id: &str,
        scenario: &str,
        kind: OperationKind,
        key: &str,
        version_id: &str,
        value_sha256: Option<&str>,
        ended_at_ms: u64,
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: scenario.to_string(),
            run_id: Some("run-1".to_string()),
            kind,
            bucket: "bucket-1".to_string(),
            key: Some(key.to_string()),
            value_sha256: value_sha256.map(str::to_string),
            size_bytes: value_sha256.map(|_| 1),
            version_id: Some(version_id.to_string()),
            request_version_id: None,
            is_delete_marker: None,
            request_id: None,
            extended_request_id: None,
            mutation_max_attempts: None,
            mutation_attempts: None,
            read_purpose: None,
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: Some(ended_at_ms.saturating_mul(2).saturating_sub(1)),
            ended_sequence: Some(ended_at_ms.saturating_mul(2)),
            started_at_ms: ended_at_ms.saturating_sub(1),
            ended_at_ms,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: Some(DurabilityCohort::FaultActive),
            fault_window_relation: Some(FaultWindowRelation::DuringFault),
        }
    }

    fn stale_return_fixture() -> (StaleDiskReturnProof, Vec<OperationRecord>) {
        let original = volume("old", 100);
        let returned = returned_runtime(original.clone(), 500);
        let mut history = vec![
            history_record(
                "stale-put",
                "stale-disk-return-detect",
                OperationKind::Put,
                "stale/key-a",
                "stale-version-a",
                Some(HASH_A),
                300,
            ),
            history_record(
                "stale-delete",
                "stale-disk-return-detect",
                OperationKind::Delete,
                "stale/key-b",
                "stale-version-b",
                None,
                350,
            ),
        ];
        append_post_return_checker_suffix(&mut history);
        let proof = StaleDiskReturnProof::prove(
            identity("stale-disk-return-detect"),
            original.clone(),
            returned.clone(),
            StaleDiskReturnEvidence {
                detached_at_ms: 200,
                mutation_window_ended_at_ms: 400,
                returned_at_ms: 450,
                detachment_operation_id: "detach-1".to_string(),
                reattachment_operation_id: "reattach-1".to_string(),
                lifecycle_evidence: stale_disk_lifecycle_evidence(&original, &returned),
                absence_observations: vec![absence_observation(&original, "absence-watch", 190)],
                committed_mutations: vec![
                    CommittedMutationEvidence {
                        operation_id: "stale-put".to_string(),
                        kind: StaleMutationKind::Overwrite,
                        object_key: "stale/key-a".to_string(),
                        version_id: "stale-version-a".to_string(),
                        acknowledged_at_ms: 300,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                    CommittedMutationEvidence {
                        operation_id: "stale-delete".to_string(),
                        kind: StaleMutationKind::DeleteMarker,
                        object_key: "stale/key-b".to_string(),
                        version_id: "stale-version-b".to_string(),
                        acknowledged_at_ms: 350,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                ],
                post_return_checker: post_return_checker(&history),
            },
            &history,
        )
        .expect("valid stale return fixture");
        (proof, history)
    }

    fn duplicate_stale_mutation(
        proof: &mut StaleDiskReturnProof,
        history: &mut Vec<OperationRecord>,
        source_index: usize,
        duplicate_id: &str,
    ) {
        history.truncate(checker_prefix_record_count(&proof.post_return_checker));
        let mut duplicate_record = history[source_index].clone();
        duplicate_record.id = duplicate_id.to_string();
        history.push(duplicate_record);

        let mut duplicate_evidence = proof.committed_mutations[source_index].clone();
        duplicate_evidence.operation_id = duplicate_id.to_string();
        proof.committed_mutations.push(duplicate_evidence);

        append_post_return_checker_suffix(history);
        proof.post_return_checker = post_return_checker(history);
    }

    #[test]
    fn post_return_checker_rejects_duplicate_put_version_identity() {
        let (mut proof, mut history) = stale_return_fixture();
        duplicate_stale_mutation(&mut proof, &mut history, 0, "stale-put-duplicate");

        let error = proof
            .post_return_checker
            .validate(
                &proof.identity,
                proof.returned_generation.observed_at_ms,
                &proof.committed_mutations,
                &history,
            )
            .expect_err("duplicate successful PUT version identity must be rejected");

        assert!(
            format!("{error:#}").contains("reuses successful immutable S3 version identity"),
            "{error:#}"
        );
    }

    #[test]
    fn post_return_checker_rejects_duplicate_delete_marker_version_identity() {
        let (mut proof, mut history) = stale_return_fixture();
        duplicate_stale_mutation(&mut proof, &mut history, 1, "stale-delete-duplicate");

        let error = proof
            .post_return_checker
            .validate(
                &proof.identity,
                proof.returned_generation.observed_at_ms,
                &proof.committed_mutations,
                &history,
            )
            .expect_err("duplicate successful delete-marker version identity must be rejected");

        assert!(
            format!("{error:#}").contains("reuses successful immutable S3 version identity"),
            "{error:#}"
        );
    }

    #[test]
    fn post_return_checker_rejects_duplicate_recorder_sequence() {
        let (mut proof, mut history) = stale_return_fixture();
        let prefix_count = checker_prefix_record_count(&proof.post_return_checker);
        history[prefix_count].started_sequence = history[0].started_sequence;
        proof.post_return_checker = post_return_checker(&history);

        let error = proof
            .validate_against_history(&history)
            .expect_err("duplicate recorder sequence must invalidate post-return evidence");

        assert!(
            format!("{error:#}").contains("duplicate recorder event sequence"),
            "{error:#}"
        );
    }

    #[test]
    fn post_return_checker_rejects_suffix_sequence_inside_prefix() {
        let (mut proof, mut history) = stale_return_fixture();
        let prefix_count = checker_prefix_record_count(&proof.post_return_checker);
        let prefix_end = history[prefix_count - 1]
            .ended_sequence
            .expect("prefix end sequence");
        let suffix_start = history[prefix_count]
            .started_sequence
            .expect("suffix start sequence");
        history[prefix_count - 1].ended_sequence = Some(suffix_start);
        history[prefix_count].started_sequence = Some(prefix_end);
        proof.post_return_checker = post_return_checker(&history);

        let error = proof
            .validate_against_history(&history)
            .expect_err("checker suffix cannot start before its prefix completes");

        assert!(error.to_string().contains("post-return prefix/checker"));
    }

    #[test]
    fn fresh_replacement_preserves_slot_uuid_but_rejects_reused_physical_storage() {
        let original = volume("old", 100);
        let mut replacement = volume("new", 300);
        replacement.rustfs_drive_uuid = original.rustfs_drive_uuid.clone();
        FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            original.clone(),
            replacement.clone(),
            empty_observation(&replacement, 200),
        )
        .expect("format heal may preserve the logical slot UUID");

        for reused in ["pv", "pvc", "device", "filesystem"] {
            let mut candidate = replacement.clone();
            match reused {
                "pv" => candidate.persistent_volume_uid = original.persistent_volume_uid.clone(),
                "pvc" => {
                    candidate.persistent_volume_claim_uid =
                        original.persistent_volume_claim_uid.clone()
                }
                "device" => candidate.canonical_device = original.canonical_device.clone(),
                "filesystem" => candidate.filesystem_uuid = original.filesystem_uuid.clone(),
                _ => unreachable!(),
            }
            assert!(
                FreshVolumeReplacementProof::prove(
                    identity("fresh-volume-replacement"),
                    original.clone(),
                    candidate.clone(),
                    empty_observation(&candidate, 200),
                )
                .is_err(),
                "reusing {reused} cannot prove a physical replacement"
            );
        }
    }

    #[test]
    fn fresh_replacement_requires_new_empty_storage_in_the_same_slot() {
        let replacement = volume("new", 300);
        let proof = FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            volume("old", 100),
            replacement.clone(),
            empty_observation(&replacement, 200),
        )
        .expect("valid replacement");

        assert_eq!(proof.replacement.rustfs_drive_uuid, "drive-new");

        assert!(
            FreshVolumeReplacementProof::prove(
                identity("fresh-volume-replacement"),
                volume("old", 100),
                replacement.clone(),
                empty_observation(&replacement, replacement.observed_at_ms),
            )
            .is_err(),
            "an equal scan-completion and replacement timestamp cannot prove causal order"
        );

        let mut mismatched_scan_receipt = empty_observation(&replacement, 200);
        let mut mismatched_scan_response = serde_json::from_str::<EmptyVolumeScanResponse>(
            &mismatched_scan_receipt.scan_response_body,
        )
        .expect("empty-volume scan response");
        mismatched_scan_response.scan_completed_at_ms = 199;
        mismatched_scan_receipt.scan_response_body =
            serde_json::to_string(&mismatched_scan_response).expect("empty-volume scan response");
        mismatched_scan_receipt.scan_response_sha256 =
            sha256_bytes(mismatched_scan_receipt.scan_response_body.as_bytes());
        assert!(
            FreshVolumeReplacementProof::prove(
                identity("fresh-volume-replacement"),
                volume("old", 100),
                replacement.clone(),
                mismatched_scan_receipt,
            )
            .is_err(),
            "the raw empty-volume scan interval must match its persisted receipt"
        );

        let mut reused = volume("old", 300);
        reused.pod_uid = "pod-new".to_string();
        let reused_empty = empty_observation(&reused, 200);
        let error = FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            volume("old", 100),
            reused,
            reused_empty,
        )
        .expect_err("same storage generation");
        assert!(error.to_string().contains("PVC generation"));

        let replacement = volume("new", 300);
        let mut unrelated_empty = empty_observation(&replacement, 200);
        unrelated_empty.filesystem_uuid = "fs-unrelated".to_string();
        assert!(
            FreshVolumeReplacementProof::prove(
                identity("fresh-volume-replacement"),
                volume("old", 100),
                replacement.clone(),
                unrelated_empty,
            )
            .is_err()
        );

        let mut fabricated_empty = empty_observation(&replacement, 200);
        let mut raw =
            serde_json::from_str::<EmptyVolumeScanResponse>(&fabricated_empty.scan_response_body)
                .expect("empty-volume scan response");
        raw.exhaustive = false;
        fabricated_empty.scan_response_body =
            serde_json::to_string(&raw).expect("empty-volume scan response");
        fabricated_empty.scan_response_sha256 =
            sha256_bytes(fabricated_empty.scan_response_body.as_bytes());
        assert!(
            FreshVolumeReplacementProof::prove(
                identity("fresh-volume-replacement"),
                volume("old", 100),
                replacement,
                fabricated_empty,
            )
            .is_err(),
            "a self-reported empty Vec cannot replace one exhaustive host scan"
        );
    }

    #[test]
    fn storage_recovery_case_matrix_has_five_distinct_qualified_variants() {
        assert_eq!(StorageRecoveryCase::ALL.len(), 5);
        assert_eq!(
            StorageRecoveryCase::ALL
                .iter()
                .filter(|case| case.scenario() == "fresh-volume-replacement")
                .count(),
            2
        );
        assert_eq!(
            StorageRecoveryCase::ALL
                .iter()
                .filter(|case| case.scenario() == "on-disk-bitrot")
                .count(),
            2
        );
        assert_eq!(StorageRecoveryCase::StaleDiskReturn.heal_mode(), None);
        assert_eq!(
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement.heal_mode(),
            Some(HealMode::AutomaticReplacement)
        );
    }

    #[test]
    fn fresh_replacement_rejects_emptiness_observed_after_adoption() {
        let replacement = volume("new", 300);
        let mut empty = empty_observation(&replacement, 200);
        empty.rustfs_process_can_access_volume = true;
        let error = FreshVolumeReplacementProof::prove(
            identity("fresh-volume-replacement"),
            volume("old", 100),
            replacement,
            empty,
        )
        .expect_err("RustFS already mounted replacement");
        assert!(error.to_string().contains("before RustFS can access"));
    }

    #[test]
    fn stale_return_requires_the_original_generation_and_commits_while_absent() {
        let original = volume("old", 100);
        let returned = returned_runtime(original.clone(), 500);
        let absence = vec![absence_observation(&original, "absence-watch", 190)];
        let mut history = vec![
            history_record(
                "put-1",
                "stale-disk-return-detect",
                OperationKind::Put,
                "key-a",
                "version-a",
                Some(HASH_A),
                300,
            ),
            history_record(
                "mpu-2",
                "stale-disk-return-detect",
                OperationKind::CompleteMultipartUpload,
                "key-mpu",
                "version-mpu",
                Some(HASH_B),
                325,
            ),
            history_record(
                "delete-2",
                "stale-disk-return-detect",
                OperationKind::Delete,
                "key-b",
                "version-b",
                None,
                350,
            ),
        ];
        append_post_return_checker_suffix(&mut history);

        let proof = StaleDiskReturnProof::prove(
            identity("stale-disk-return-detect"),
            original.clone(),
            returned.clone(),
            StaleDiskReturnEvidence {
                detached_at_ms: 200,
                mutation_window_ended_at_ms: 400,
                returned_at_ms: 450,
                detachment_operation_id: "detach-1".to_string(),
                reattachment_operation_id: "reattach-1".to_string(),
                lifecycle_evidence: stale_disk_lifecycle_evidence(&original, &returned),
                absence_observations: absence,
                committed_mutations: vec![
                    CommittedMutationEvidence {
                        operation_id: "put-1".to_string(),
                        kind: StaleMutationKind::Overwrite,
                        object_key: "key-a".to_string(),
                        version_id: "version-a".to_string(),
                        acknowledged_at_ms: 300,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                    CommittedMutationEvidence {
                        operation_id: "mpu-2".to_string(),
                        kind: StaleMutationKind::Overwrite,
                        object_key: "key-mpu".to_string(),
                        version_id: "version-mpu".to_string(),
                        acknowledged_at_ms: 325,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                    CommittedMutationEvidence {
                        operation_id: "delete-2".to_string(),
                        kind: StaleMutationKind::DeleteMarker,
                        object_key: "key-b".to_string(),
                        version_id: "version-b".to_string(),
                        acknowledged_at_ms: 350,
                        absence_observation_id: "absence-watch".to_string(),
                    },
                ],
                post_return_checker: post_return_checker(&history),
            },
            &history,
        )
        .expect("valid stale return");

        let mut swapped_return_runtime = proof.clone();
        swapped_return_runtime.returned_generation.pod_uid = "unrelated-pod".to_string();
        swapped_return_runtime
            .returned_generation
            .rustfs_container_id = format!("containerd://{HASH_B}");
        assert!(
            swapped_return_runtime
                .validate_against_history(&history)
                .is_err(),
            "reattach evidence must prove the claimed returned Pod and container generation"
        );

        let mut omitted_multipart = proof.clone();
        omitted_multipart
            .committed_mutations
            .retain(|mutation| mutation.operation_id != "mpu-2");
        assert!(
            omitted_multipart
                .validate_against_history(&history)
                .is_err(),
            "a successful multipart completion during absence must be covered exactly"
        );

        let mut started_while_attached = history.clone();
        started_while_attached[0].started_at_ms = 150;
        assert!(
            proof
                .validate_against_history(&started_while_attached)
                .is_err(),
            "a request started before detachment must not prove an absent-disk mutation"
        );

        let mut inverted_absence_mutation = history.clone();
        inverted_absence_mutation[0].started_at_ms = 301;
        assert!(
            proof
                .validate_against_history(&inverted_absence_mutation)
                .is_err(),
            "an inverted request interval cannot prove a mutation during disk absence"
        );

        let mut cross_window_conflict = history.clone();
        cross_window_conflict.push(history_record(
            "put-conflict-after-return",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key-a",
            "version-a",
            Some(HASH_B),
            520,
        ));
        assert!(
            proof
                .validate_against_history(&cross_window_conflict)
                .is_err(),
            "immutable-version conflicts after disk return must still fail closed"
        );

        let mut data_marker_conflict = history.clone();
        data_marker_conflict.push(history_record(
            "delete-conflict-after-return",
            "stale-disk-return-detect",
            OperationKind::Delete,
            "key-a",
            "version-a",
            None,
            520,
        ));
        assert!(
            proof
                .validate_against_history(&data_marker_conflict)
                .is_err(),
            "one version ID cannot identify both data and a delete marker"
        );

        let mut rolled_back_after_return = proof.clone();
        let mut checker = serde_json::from_str::<CheckerReport>(
            &rolled_back_after_return.post_return_checker.response_body,
        )
        .expect("post-return checker report");
        checker
            .resurrected_deleted_objects
            .push("key-b".to_string());
        rolled_back_after_return.post_return_checker.response_body =
            serde_json::to_string(&checker).expect("post-return checker report");
        rolled_back_after_return.post_return_checker.response_sha256 = sha256_bytes(
            rolled_back_after_return
                .post_return_checker
                .response_body
                .as_bytes(),
        );
        assert!(
            rolled_back_after_return
                .validate_against_history(&history)
                .is_err(),
            "a self-consistent report cannot hide delete-marker resurrection after stale return"
        );

        let mut replayed_checker = proof.clone();
        let mut earlier_history = vec![history[0].clone()];
        append_post_return_checker_suffix(&mut earlier_history);
        replayed_checker.post_return_checker = post_return_checker(&earlier_history);
        assert!(
            replayed_checker.validate_against_history(&history).is_err(),
            "a clean checker receipt for an earlier history universe cannot be replayed after return"
        );

        let mut failed_version_list_history = history.clone();
        let failed_version_list = failed_version_list_history
            .iter_mut()
            .find(|record| record.id == "checker-list-versions")
            .expect("checker ListObjectVersions");
        failed_version_list.outcome = OperationOutcome::Timeout;
        failed_version_list.http_status = None;
        failed_version_list.error = Some("list object versions timed out".to_string());
        let mut forged_clean_version_list = proof.clone();
        rebind_checker_suffix(
            &mut forged_clean_version_list.post_return_checker,
            &failed_version_list_history,
        );
        assert!(
            forged_clean_version_list
                .validate_against_history(&failed_version_list_history)
                .is_err(),
            "a failed ListObjectVersions record cannot be rewrapped as a clean checker report"
        );

        let mut resurrected_get_history = history.clone();
        let resurrected_get = resurrected_get_history
            .iter_mut()
            .find(|record| {
                record.id.starts_with("checker-current-get-")
                    && record.key.as_deref() == Some("key-b")
            })
            .expect("checker deleted-key GET");
        resurrected_get.outcome = OperationOutcome::Ok;
        resurrected_get.http_status = Some(200);
        resurrected_get.value_sha256 = Some(HASH_C.to_string());
        resurrected_get.error = None;
        let mut forged_clean_resurrection = proof.clone();
        rebind_checker_suffix(
            &mut forged_clean_resurrection.post_return_checker,
            &resurrected_get_history,
        );
        assert!(
            forged_clean_resurrection
                .validate_against_history(&resurrected_get_history)
                .is_err(),
            "a deleted-key GET returning bytes cannot be rewrapped as a clean checker report"
        );

        let mut omitted_list_key_history = history.clone();
        let list = omitted_list_key_history
            .iter_mut()
            .find(|record| record.id == "checker-list")
            .expect("checker LIST");
        list.listed_keys = Some(Vec::new());
        list.size_bytes = Some(0);
        let mut forged_clean_list = proof.clone();
        rebind_checker_suffix(
            &mut forged_clean_list.post_return_checker,
            &omitted_list_key_history,
        );
        assert!(
            forged_clean_list
                .validate_against_history(&omitted_list_key_history)
                .is_err(),
            "a 200 LIST that omits live keys cannot be rewrapped as a clean checker report"
        );

        let mut omitted_version_history = history.clone();
        let version_list = omitted_version_history
            .iter_mut()
            .find(|record| record.id == "checker-list-versions")
            .expect("checker ListObjectVersions");
        version_list
            .listed_versions
            .as_mut()
            .expect("recorded version entries")
            .pop();
        version_list.size_bytes = version_list.listed_versions.as_ref().map(Vec::len);
        let mut forged_clean_version_contents = proof.clone();
        rebind_checker_suffix(
            &mut forged_clean_version_contents.post_return_checker,
            &omitted_version_history,
        );
        assert!(
            forged_clean_version_contents
                .validate_against_history(&omitted_version_history)
                .is_err(),
            "a 200 ListObjectVersions that omits lineage cannot be rewrapped as clean"
        );

        let mut unreported_version_get_history = history.clone();
        let mut failed_version_get = history_record(
            "checker-unreported-version-get",
            "stale-disk-return-detect",
            OperationKind::Get,
            "key-a",
            "version-a",
            None,
            579,
        );
        failed_version_get.outcome = OperationOutcome::NotFound;
        failed_version_get.http_status = Some(404);
        failed_version_get.error = Some("get object version failed: NoSuchVersion".to_string());
        failed_version_get.durability_cohort = Some(DurabilityCohort::PostRecovery);
        failed_version_get.fault_window_relation = Some(FaultWindowRelation::AfterFault);
        unreported_version_get_history.push(failed_version_get);
        let mut forged_unreported_version_get = proof.clone();
        rebind_checker_suffix(
            &mut forged_unreported_version_get.post_return_checker,
            &unreported_version_get_history,
        );
        assert!(
            forged_unreported_version_get
                .validate_against_history(&unreported_version_get_history)
                .is_err(),
            "any version GET omitted from the producer audit must fail closed"
        );

        let checker_prefix_count = checker_prefix_record_count(&proof.post_return_checker);
        let mut ambiguous_history = history[..checker_prefix_count].to_vec();
        let mut ambiguous_delete = history_record(
            "ambiguous-delete",
            "stale-disk-return-detect",
            OperationKind::Delete,
            "key-a",
            "",
            None,
            375,
        );
        ambiguous_delete.version_id = None;
        ambiguous_delete.outcome = OperationOutcome::Timeout;
        ambiguous_delete.http_status = None;
        ambiguous_delete.error = Some("delete timed out after request dispatch".to_string());
        ambiguous_history.push(ambiguous_delete);
        append_post_return_checker_suffix(&mut ambiguous_history);
        let mut ambiguous_mutation_proof = proof.clone();
        ambiguous_mutation_proof.post_return_checker = post_return_checker(&ambiguous_history);
        let error = ambiguous_mutation_proof
            .validate_against_history(&ambiguous_history)
            .expect_err("an ambiguous delete cannot prove exact stale-return state");
        assert!(
            error.to_string().contains("ambiguous delete"),
            "a potentially committed delete timeout must fail closed: {error:#}"
        );

        let mut malformed_history = history.clone();
        let malformed_put = malformed_history
            .iter_mut()
            .find(|record| record.id == "put-1")
            .expect("committed PUT");
        malformed_put.value_sha256 = None;
        malformed_put.size_bytes = None;
        let error = proof
            .validate_against_history(&malformed_history)
            .expect_err("malformed committed writes must return an error");
        assert!(
            error.to_string().contains("content"),
            "malformed history must fail closed without panicking: {error:#}"
        );

        let mut overlapping_history = history[..checker_prefix_count].to_vec();
        overlapping_history[1].key = Some("key-a".to_string());
        append_post_return_checker_suffix(&mut overlapping_history);
        let first_end = overlapping_history[0]
            .ended_sequence
            .expect("first mutation end sequence");
        let second_start = overlapping_history[1]
            .started_sequence
            .expect("second mutation start sequence");
        overlapping_history[0].ended_sequence = Some(second_start);
        overlapping_history[1].started_sequence = Some(first_end);
        let mut overlapping_mutations = proof.clone();
        overlapping_mutations.committed_mutations[1].object_key = "key-a".to_string();
        overlapping_mutations.post_return_checker = post_return_checker(&overlapping_history);
        let error = overlapping_mutations
            .validate_against_history(&overlapping_history)
            .expect_err("same-key overlapping mutations have no unique latest state");
        assert!(
            format!("{error:#}").contains("overlap"),
            "same-key mutation overlap must fail before latest-state inference: {error:#}"
        );

        for (index, kind, value_sha256) in [
            (0, OperationKind::Put, Some(HASH_C)),
            (1, OperationKind::Delete, None),
            (2, OperationKind::CompleteMultipartUpload, Some(HASH_C)),
        ] {
            let mut history_with_suffix = history.clone();
            history_with_suffix.push(history_record(
                &format!("post-checker-mutation-{index}"),
                "stale-disk-return-detect",
                kind,
                &format!("post-checker-key-{index}"),
                &format!("post-checker-version-{index}"),
                value_sha256,
                600 + index,
            ));
            let mut forged_checker = proof.clone();
            let mut report = serde_json::from_str::<CheckerReport>(
                &forged_checker.post_return_checker.response_body,
            )
            .expect("checker report");
            let audit = report.audit.as_mut().expect("checker audit");
            audit.completed_at_ms = 610;
            let suffix = &history_with_suffix[audit.history_prefix_record_count..];
            audit.history_suffix_record_count = suffix.len();
            audit.history_suffix_sha256 =
                checker_history_records_sha256(suffix).expect("checker suffix");
            audit.suffix_operations = checker_operation_audits(suffix);
            forged_checker.post_return_checker.response_body =
                serde_json::to_string(&report).expect("checker report");
            forged_checker.post_return_checker.response_sha256 =
                sha256_bytes(forged_checker.post_return_checker.response_body.as_bytes());
            assert!(
                forged_checker
                    .validate_against_history(&history_with_suffix)
                    .is_err(),
                "post-return checker must reject any PUT, DELETE, or MPU suffix outside its quiesced history"
            );
        }

        let mut forged_detach = proof.clone();
        let mut detach_receipt = serde_json::from_str::<RustfsStaleDiskOperationReceipt>(
            &forged_detach.lifecycle_evidence.detach.response_body,
        )
        .expect("detach receipt");
        detach_receipt.completed_at_ms = 250;
        forged_detach.lifecycle_evidence.detach.response_body =
            serde_json::to_string(&detach_receipt).expect("detach receipt");
        forged_detach.lifecycle_evidence.detach.response_sha256 = sha256_bytes(
            forged_detach
                .lifecycle_evidence
                .detach
                .response_body
                .as_bytes(),
        );
        assert!(
            forged_detach.validate_against_history(&history).is_err(),
            "serialized timestamps cannot replace the captured detach receipt"
        );

        let mut overlapping_watch = proof.clone();
        set_absence_watch_end(
            &mut overlapping_watch.absence_observations[0],
            &proof.detached_generation,
            425,
        );
        assert!(
            overlapping_watch
                .validate_against_history(&history)
                .is_err(),
            "absence watch cannot overlap or equal reattach start"
        );

        let mut initially_absent = proof.clone();
        let host_watch = &mut initially_absent.absence_observations[0].host_watch_evidence;
        let mut host_response =
            serde_json::from_str::<RustfsDiskAbsenceWatchResponse>(&host_watch.response_body)
                .expect("host watch response");
        host_response.samples[0].state = DiskPresenceState::Absent;
        host_response.samples[0].raw_evidence = raw_disk_state_evidence(
            &proof.detached_generation,
            DiskPresenceState::Absent,
            host_response.watch_started_at_ms,
        );
        host_response.samples[0].cursor = host_response.samples[0]
            .raw_evidence
            .response_sha256
            .clone();
        host_watch.response_body =
            serde_json::to_string(&host_response).expect("host watch response");
        host_watch.response_sha256 = sha256_bytes(host_watch.response_body.as_bytes());
        assert!(
            initially_absent.validate_against_history(&history).is_err(),
            "a watch that starts absent cannot prove the detach transition"
        );

        let mut missing_ack_sample = proof.clone();
        mutate_host_watch(
            &mut missing_ack_sample.absence_observations[0],
            |response| {
                response
                    .samples
                    .retain(|sample| sample.observed_at_ms != 320);
            },
        );
        assert!(
            missing_ack_sample
                .validate_against_history(&history)
                .is_err(),
            "bounded absence polling cannot leave a gap around a mutation ACK"
        );

        let mut wrong_host_node = proof.clone();
        mutate_host_watch(&mut wrong_host_node.absence_observations[0], |response| {
            let sample = response
                .samples
                .iter_mut()
                .find(|sample| sample.observed_at_ms == 320)
                .expect("host sample bounding an ACK");
            let mut raw =
                serde_json::from_str::<RawDiskStateResponse>(&sample.raw_evidence.response_body)
                    .expect("raw host response");
            let RawDiskStateResponse::HostDevice { execution, .. } = &mut raw else {
                unreachable!("fixture uses host-device evidence")
            };
            execution.node = "wrong-node".to_string();
            sample.raw_evidence.response_body =
                serde_json::to_string(&raw).expect("raw host response");
            sample.raw_evidence.response_sha256 =
                sha256_bytes(sample.raw_evidence.response_body.as_bytes());
            sample.cursor = sample.raw_evidence.response_sha256.clone();
        });
        assert!(
            wrong_host_node.validate_against_history(&history).is_err(),
            "host absence from another node cannot stand in for the target mount namespace"
        );

        let mut wrong_helper_binding = proof.clone();
        mutate_host_watch(
            &mut wrong_helper_binding.absence_observations[0],
            |response| {
                let sample = response
                    .samples
                    .iter_mut()
                    .find(|sample| sample.observed_at_ms == 320)
                    .expect("host sample bounding an ACK");
                let mut raw = serde_json::from_str::<RawDiskStateResponse>(
                    &sample.raw_evidence.response_body,
                )
                .expect("raw host response");
                let RawDiskStateResponse::HostDevice { execution, .. } = &mut raw else {
                    unreachable!("fixture uses host-device evidence")
                };
                let mut helper =
                    serde_json::from_str::<serde_json::Value>(&execution.helper_pod_body)
                        .expect("raw helper Pod");
                helper["spec"]["nodeName"] = serde_json::json!("wrong-node");
                execution.helper_pod_body = serde_json::to_string(&helper).expect("raw helper Pod");
                execution.helper_pod_sha256 = sha256_bytes(execution.helper_pod_body.as_bytes());
                sample.raw_evidence.response_body =
                    serde_json::to_string(&raw).expect("raw host response");
                sample.raw_evidence.response_sha256 =
                    sha256_bytes(sample.raw_evidence.response_body.as_bytes());
                sample.cursor = sample.raw_evidence.response_sha256.clone();
            },
        );
        assert!(
            wrong_helper_binding
                .validate_against_history(&history)
                .is_err(),
            "raw helper Pod evidence must bind host execution to the target node"
        );

        let mut wrong_local_pv = proof.clone();
        let binding = &mut wrong_local_pv.absence_observations[0].kubernetes_binding_evidence;
        let mut binding_response =
            serde_json::from_str::<KubernetesLocalPvBindingResponse>(&binding.response_body)
                .expect("Kubernetes Local PV binding response");
        let mut raw_pv =
            serde_json::from_str::<serde_json::Value>(&binding_response.persistent_volume_body)
                .expect("raw PersistentVolume");
        raw_pv["spec"]["local"]["path"] = serde_json::json!("/var/lib/rustfs/other");
        binding_response.persistent_volume_body =
            serde_json::to_string(&raw_pv).expect("raw PersistentVolume");
        binding_response.persistent_volume_sha256 =
            sha256_bytes(binding_response.persistent_volume_body.as_bytes());
        binding.response_body =
            serde_json::to_string(&binding_response).expect("Kubernetes Local PV binding response");
        binding.response_sha256 = sha256_bytes(binding.response_body.as_bytes());
        assert!(
            wrong_local_pv.validate_against_history(&history).is_err(),
            "Local PV evidence must bind the raw PV path, claim, Pod, and node generation"
        );

        let mut scaled_proof = proof.clone();
        let mut scaled_history = history.clone();
        let prefix_record_count = checker_prefix_record_count(&proof.post_return_checker);
        scaled_history.truncate(prefix_record_count);
        for index in 0..10_000 {
            let operation_id = format!("scaled-mutation-{index}");
            let object_key = format!("scaled-key-{index}");
            let version_id = format!("scaled-version-{index}");
            let (kind, operation_kind, value_sha256) = if index % 2 == 0 {
                (
                    StaleMutationKind::Overwrite,
                    OperationKind::Put,
                    Some(HASH_C),
                )
            } else {
                (StaleMutationKind::DeleteMarker, OperationKind::Delete, None)
            };
            scaled_history.push(history_record(
                &operation_id,
                "stale-disk-return-detect",
                operation_kind,
                &object_key,
                &version_id,
                value_sha256,
                360,
            ));
            scaled_proof
                .committed_mutations
                .push(CommittedMutationEvidence {
                    operation_id,
                    kind,
                    object_key,
                    version_id,
                    acknowledged_at_ms: 360,
                    absence_observation_id: "absence-watch".to_string(),
                });
        }
        append_post_return_checker_suffix(&mut scaled_history);
        scaled_proof.post_return_checker = post_return_checker(&scaled_history);
        scaled_proof
            .validate_against_history(&scaled_history)
            .expect("large stale-return histories are indexed once");

        let error = StaleDiskReturnProof::prove(
            identity("stale-disk-return-detect"),
            original,
            volume("new", 500),
            StaleDiskReturnEvidence {
                detached_at_ms: 200,
                mutation_window_ended_at_ms: 400,
                returned_at_ms: 450,
                detachment_operation_id: "detach-1".to_string(),
                reattachment_operation_id: "reattach-1".to_string(),
                lifecycle_evidence: stale_disk_lifecycle_evidence(
                    &volume("old", 100),
                    &volume("new", 500),
                ),
                absence_observations: vec![absence_observation(
                    &volume("old", 100),
                    "absence-watch",
                    190,
                )],
                committed_mutations: vec![CommittedMutationEvidence {
                    operation_id: "put-1".to_string(),
                    kind: StaleMutationKind::Overwrite,
                    object_key: "key-a".to_string(),
                    version_id: "version-a".to_string(),
                    acknowledged_at_ms: 300,
                    absence_observation_id: "absence-watch".to_string(),
                }],
                post_return_checker: post_return_checker(&history[..1]),
            },
            &history[..1],
        )
        .expect_err("new disk is not the stale generation");
        assert!(error.to_string().contains("detached storage generation"));

        let mut reconnected = absence_observation(&volume("old", 100), "absence-watch", 190);
        let mut reconnected_response = serde_json::from_str::<RustfsDiskAbsenceWatchResponse>(
            &reconnected.host_watch_evidence.response_body,
        )
        .expect("host watch response");
        let reconnect_sample = reconnected_response
            .samples
            .iter_mut()
            .find(|sample| sample.observed_at_ms == 320)
            .expect("host sample bounding an ACK");
        reconnect_sample.state = DiskPresenceState::Present;
        reconnect_sample.raw_evidence =
            raw_disk_state_evidence(&volume("old", 100), DiskPresenceState::Present, 320);
        reconnect_sample.cursor = reconnect_sample.raw_evidence.response_sha256.clone();
        reconnected.host_watch_evidence.response_body =
            serde_json::to_string(&reconnected_response).expect("host watch response");
        reconnected.host_watch_evidence.response_sha256 =
            sha256_bytes(reconnected.host_watch_evidence.response_body.as_bytes());
        let mut history = vec![
            history_record(
                "put-1",
                "stale-disk-return-detect",
                OperationKind::Put,
                "key-a",
                "version-a",
                Some(HASH_A),
                300,
            ),
            history_record(
                "delete-2",
                "stale-disk-return-detect",
                OperationKind::Delete,
                "key-b",
                "version-b",
                None,
                350,
            ),
        ];
        append_post_return_checker_suffix(&mut history);
        let original = volume("old", 100);
        let mut returned = original.clone();
        returned.observed_at_ms = 500;
        assert!(
            StaleDiskReturnProof::prove(
                identity("stale-disk-return-detect"),
                original.clone(),
                returned.clone(),
                StaleDiskReturnEvidence {
                    detached_at_ms: 200,
                    mutation_window_ended_at_ms: 400,
                    returned_at_ms: 450,
                    detachment_operation_id: "detach-1".to_string(),
                    reattachment_operation_id: "reattach-1".to_string(),
                    lifecycle_evidence: stale_disk_lifecycle_evidence(&original, &returned),
                    absence_observations: vec![reconnected],
                    committed_mutations: vec![
                        CommittedMutationEvidence {
                            operation_id: "put-1".to_string(),
                            kind: StaleMutationKind::Overwrite,
                            object_key: "key-a".to_string(),
                            version_id: "version-a".to_string(),
                            acknowledged_at_ms: 300,
                            absence_observation_id: "absence-watch".to_string(),
                        },
                        CommittedMutationEvidence {
                            operation_id: "delete-2".to_string(),
                            kind: StaleMutationKind::DeleteMarker,
                            object_key: "key-b".to_string(),
                            version_id: "version-b".to_string(),
                            acknowledged_at_ms: 350,
                            absence_observation_id: "absence-watch".to_string(),
                        },
                    ],
                    post_return_checker: post_return_checker(&history),
                },
                &history,
            )
            .is_err()
        );
    }

    #[test]
    fn absence_watch_ack_lookup_scales_with_long_fault_windows() {
        const SAMPLE_COUNT: usize = 72_001;
        const MUTATION_COUNT: usize = 40_000;
        let watch = ValidatedDiskAbsenceWatch {
            sample_times_ms: (0..SAMPLE_COUNT)
                .map(|index| u64::try_from(index).expect("sample index") * 100)
                .collect(),
            first_absent_index: 1,
            poll_interval_ms: 100,
        };
        for index in 1..=MUTATION_COUNT {
            let acknowledged_at_ms = u64::try_from(index).expect("mutation index") * 100 + 50;
            assert!(watch.proves_absent_at(acknowledged_at_ms));
        }
        assert!(!watch.proves_absent_at(50));
        assert!(!watch.proves_absent_at(u64::try_from(SAMPLE_COUNT).expect("sample count") * 100));
    }

    #[test]
    fn host_runtime_identity_requires_normalized_paths_and_bare_cri_ids() {
        for path in ["/data0/", "/data0/.", "/data0//shard", "/data0/../other"] {
            assert!(!is_normalized_absolute_path(path));
        }
        assert!(is_normalized_absolute_path("/data0/shard"));

        let kubernetes_id = format!("containerd://{HASH_A}");
        assert_eq!(
            split_kubernetes_container_id(&kubernetes_id).expect("containerd ID"),
            ("containerd", HASH_A)
        );
        assert!(split_kubernetes_container_id("containerd://not-a-cri-id").is_err());
        assert!(split_kubernetes_container_id(HASH_A).is_err());
    }

    #[test]
    fn bitrot_proof_requires_stable_mapping_and_reversible_mutation() {
        let mut mutation_volume = volume("old", 100);
        let mutation_target_proof_body = mutation_target_proof_body(&mutation_volume);
        let mutation_target_proof_sha256 = sha256_bytes(mutation_target_proof_body.as_bytes());
        mutation_volume.target_proof_sha256 = mutation_target_proof_sha256.clone();
        let history = vec![history_record(
            "put-bitrot",
            "on-disk-bitrot",
            OperationKind::Put,
            "bitrot/key",
            "version-1",
            Some(HASH_A),
            90,
        )];
        let mapping_response = serde_json::to_string(&RustfsShardMutationMappingResponse {
            bucket: "bucket-1".to_string(),
            object_key: "bitrot/key".to_string(),
            version_id: "version-1".to_string(),
            object_sha256: HASH_A.to_string(),
            drive_uuid: "drive-old".to_string(),
            shard_path: "/data0/.rustfs/shard".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
        })
        .expect("shard mapping response");
        let path_response = serde_json::to_string(&Openat2PathResolutionReceipt {
            execution: host_execution(&mutation_volume),
            method: ShardPathResolutionMethod::Openat2BeneathNoSymlinksNoXdev,
            requested_path: "/data0/.rustfs/shard".to_string(),
            canonical_mount_path: "/data0".to_string(),
            mount_canonical_device: "/dev/mapper/data-old".to_string(),
            mount_filesystem_uuid: "fs-old".to_string(),
            resolved_path: "/data0/.rustfs/shard".to_string(),
            mount_device_id: "259:0".to_string(),
            returned_fd_device_id: "259:0".to_string(),
            returned_fd_inode: 42,
        })
        .expect("openat2 path receipt");
        let host_mutation_response = serde_json::to_string(&ShardMutationHostReceipt {
            execution: host_execution(&mutation_volume),
            shard_path: "/data0/.rustfs/shard".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
            byte_offset: 4096,
            byte_length: 1,
            original_sha256: HASH_A.to_string(),
            mutated_sha256: HASH_B.to_string(),
            rollback_sha256: HASH_A.to_string(),
            original_observed_at_ms: 200,
            pwrite_completed_at_ms: 201,
            mutation_fsync_completed_at_ms: 201,
            mutation_fstat_observed_at_ms: 201,
            mutated_readback_at_ms: 201,
            rollback_pwrite_started_at_ms: 202,
            rollback_pwrite_completed_at_ms: 202,
            rollback_fsync_completed_at_ms: 202,
            rollback_fstat_observed_at_ms: 202,
            rollback_readback_at_ms: 202,
            pwrite_bytes: 1,
            rollback_pwrite_bytes: 1,
            mutation_fsync_succeeded: true,
            rollback_fsync_succeeded: true,
            target_proof_sha256: mutation_target_proof_sha256.clone(),
            host_storage_proof_sha256: HASH_B.to_string(),
        })
        .expect("host mutation receipt");
        let proof = ShardMutationProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("on-disk-bitrot"),
            mapping_source: ShardMappingSource::RustfsDiagnosticApi,
            mapping_api_revision: "v1".to_string(),
            mapping_response_sha256: sha256_bytes(mapping_response.as_bytes()),
            mapping_response_body: mapping_response,
            object_key: "bitrot/key".to_string(),
            version_id: "version-1".to_string(),
            expected_object_sha256: HASH_A.to_string(),
            volume: mutation_volume,
            mutation_target_proof_body,
            shard_path: "/data0/.rustfs/shard".to_string(),
            shard_device_id: "259:0".to_string(),
            shard_inode: 42,
            shard_size_bytes: 8192,
            path_containment: ShardPathContainmentProof {
                observed_at_ms: 200,
                resolver_evidence_sha256: sha256_bytes(path_response.as_bytes()),
                resolver_response_body: path_response,
                target_proof_sha256: mutation_target_proof_sha256.clone(),
                host_storage_proof_sha256: HASH_B.to_string(),
            },
            byte_offset: 4096,
            byte_length: 1,
            original_sha256: HASH_A.to_string(),
            mutated_sha256: HASH_B.to_string(),
            host_mutation_evidence: Some(ShardMutationHostEvidence {
                response_sha256: sha256_bytes(host_mutation_response.as_bytes()),
                response_body: host_mutation_response,
            }),
            rollback: ShardRollbackObservation {
                shard_path: "/data0/.rustfs/shard".to_string(),
                shard_device_id: "259:0".to_string(),
                shard_inode: 42,
                shard_size_bytes: 8192,
                observed_sha256: HASH_A.to_string(),
                observed_at_ms: 202,
                target_proof_sha256: mutation_target_proof_sha256,
                host_storage_proof_sha256: HASH_B.to_string(),
            },
            mapped_at_ms: 200,
            mutated_at_ms: 201,
        };
        proof
            .validate_against_history(&history)
            .expect("valid bitrot proof");

        let mut offline_mapping = proof.clone();
        offline_mapping.mapping_source = ShardMappingSource::OfflineXl2Inspector;
        offline_mapping.mapping_api_revision = OFFLINE_XL2_INSPECTOR_REVISION.to_string();
        offline_mapping
            .validate_against_history(&history)
            .expect("offline XL2 mapping source");
        offline_mapping.mapping_api_revision = "unknown-xl2-profile".to_string();
        assert!(
            offline_mapping.validate_against_history(&history).is_err(),
            "offline mapping evidence must name the supported capability profile"
        );

        let mut wrong_host_node = proof.clone();
        let host_evidence = wrong_host_node
            .host_mutation_evidence
            .as_mut()
            .expect("host mutation evidence");
        let mut wrong_host_receipt =
            serde_json::from_str::<ShardMutationHostReceipt>(&host_evidence.response_body)
                .expect("host mutation receipt");
        wrong_host_receipt.execution.node_uid = "wrong-node-uid".to_string();
        host_evidence.response_body =
            serde_json::to_string(&wrong_host_receipt).expect("host mutation receipt");
        host_evidence.response_sha256 = sha256_bytes(host_evidence.response_body.as_bytes());
        assert!(
            wrong_host_node.validate_against_history(&history).is_err(),
            "a mutation helper on another node cannot prove the target shard write"
        );

        let mut unauthorized_target = proof.clone();
        let mut unauthorized_body = serde_json::from_str::<serde_json::Value>(
            &unauthorized_target.mutation_target_proof_body,
        )
        .expect("mutation target proof");
        unauthorized_body["faults"][0]["selectionValue"] = serde_json::json!(0);
        rebind_mutation_target_proof(
            &mut unauthorized_target,
            serde_json::to_string(&unauthorized_body).expect("mutation target proof"),
        );
        assert!(
            unauthorized_target
                .validate_against_history(&history)
                .is_err(),
            "an unrelated or zero-target fault topology cannot authorize host shard mutation"
        );

        let corruption_probe = corruption_probe(&proof, "bitrot-corruption-read", 205);
        let mut corruption_history = history.clone();
        corruption_history.push(history_record(
            &corruption_probe.operation_id,
            "on-disk-bitrot",
            OperationKind::Get,
            &proof.object_key,
            &proof.version_id,
            Some(HASH_A),
            205,
        ));
        let force_read = ForceReadThroughProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("on-disk-bitrot"),
            shape: ErasureSetShape {
                pool_index: 0,
                set_index: 0,
                server_count: 8,
                volumes_per_server: 1,
                total_shards: 8,
                payload_data_shards: 4,
                payload_parity_shards: 4,
            },
            persisted_version_class: PersistedVersionClass::DataObject,
            all_shard_ids: Vec::new(),
            repaired_shard_id: proof.volume.rustfs_drive_uuid.clone(),
            target_proof_sha256: HASH_C.to_string(),
            fault_evidence_sha256: HASH_C.to_string(),
            fault_evidence_body: None,
            unavailable_shards: Vec::new(),
            fault_active_from_ms: 230,
            fault_active_until_ms: 240,
            probes: vec![ForcedReadProbe {
                operation_id: "post-heal-read".to_string(),
                object_key: proof.object_key.clone(),
                version_id: proof.version_id.clone(),
                expected_sha256: HASH_A.to_string(),
                observed_sha256: HASH_A.to_string(),
                http_status: 200,
                observed_at_ms: 235,
                mapping_observation_id: "post-heal-mapping".to_string(),
                active_fault_snapshot_id: HASH_C.to_string(),
            }],
        };
        validate_bitrot_object_evidence(
            &proof,
            &corruption_probe,
            210,
            &force_read,
            &corruption_history,
        )
        .expect("same mutated version is checked before and after heal");
        let mut unrelated_detection = corruption_probe.clone();
        let mut detection = serde_json::from_str::<RustfsBitrotDetectionResponse>(
            &unrelated_detection.detection_evidence.response_body,
        )
        .expect("RustFS bitrot detection response");
        detection.drive_uuid = "drive-unrelated".to_string();
        unrelated_detection.detection_evidence.response_body =
            serde_json::to_string(&detection).expect("RustFS bitrot detection response");
        unrelated_detection.detection_evidence.response_sha256 = sha256_bytes(
            unrelated_detection
                .detection_evidence
                .response_body
                .as_bytes(),
        );
        assert!(
            validate_bitrot_object_evidence(
                &proof,
                &unrelated_detection,
                210,
                &force_read,
                &corruption_history,
            )
            .is_err(),
            "an unrelated shard detection cannot prove that the mutated shard participated"
        );
        let mut corrupted_read_history = corruption_history.clone();
        corrupted_read_history[1].value_sha256 = Some(HASH_B.to_string());
        assert!(
            validate_bitrot_object_evidence(
                &proof,
                &corruption_probe,
                210,
                &force_read,
                &corrupted_read_history,
            )
            .is_err(),
            "successful corrupt bytes during the mutation window must fail the case"
        );
        let mut unrelated_force_read = force_read.clone();
        unrelated_force_read.probes[0].object_key = "another-object".to_string();
        assert!(
            validate_bitrot_object_evidence(
                &proof,
                &corruption_probe,
                210,
                &unrelated_force_read,
                &corruption_history,
            )
            .is_err(),
            "post-heal force-read must cover the mutated object version"
        );

        let early_rollback_receipt = proof.host_receipt().expect("host mutation receipt");
        assert!(
            validate_bitrot_recovery_order(
                201,
                210,
                220,
                230,
                240,
                early_rollback_receipt.rollback_pwrite_started_at_ms,
                early_rollback_receipt.rollback_readback_at_ms,
            )
            .is_err(),
            "the raw rollback pwrite timestamp must follow the forced-read window"
        );
        validate_bitrot_recovery_order(201, 210, 220, 230, 240, 245, 250)
            .expect("valid end-to-end bitrot recovery order");
        assert!(
            validate_bitrot_recovery_order(201, 210, 220, 230, 240, 239, 250).is_err(),
            "a rollback that starts before GET completion cannot be hidden by a later pwrite completion"
        );
        assert!(
            validate_bitrot_recovery_order(201, 210, 220, 230, 240, 240, 250).is_err(),
            "host rollback cannot overlap the forced-read proof"
        );
        assert!(
            validate_bitrot_recovery_order(201, 210, 210, 230, 240, 245, 250).is_err(),
            "heal completion must be observed strictly after heal start"
        );
        validate_bitrot_target_proof_phases(
            &proof.volume.target_proof_sha256,
            100,
            200,
            HASH_C,
            230,
            220,
        )
        .expect("separate pre-mutation and post-heal target proofs");
        assert!(
            validate_bitrot_target_proof_phases(
                &proof.volume.target_proof_sha256,
                100,
                200,
                &proof.volume.target_proof_sha256,
                230,
                220,
            )
            .is_err(),
            "one target proof cannot represent mutation-time and post-heal topology"
        );
        assert!(
            validate_bitrot_target_proof_phases(HASH_A, 201, 200, HASH_C, 230, 220).is_err(),
            "mutation targeting captured after mapping is post-hoc evidence"
        );
        assert!(
            validate_bitrot_target_proof_phases(HASH_A, 100, 200, HASH_C, 220, 220).is_err(),
            "force-read targeting must be captured after heal completion"
        );

        let mut inverted_commit = history.clone();
        inverted_commit[0].started_at_ms = 91;
        assert!(
            proof.validate_against_history(&inverted_commit).is_err(),
            "an inverted write interval cannot prove that the mapped shard version existed"
        );

        let mut null_version = proof.clone();
        null_version.version_id = "null".to_string();
        assert!(null_version.validate_against_history(&history).is_err());

        let mut out_of_bounds = proof.clone();
        out_of_bounds.byte_length = 8193;
        assert!(out_of_bounds.validate_against_history(&history).is_err());

        let mut false_rollback = proof.clone();
        false_rollback.rollback.observed_sha256 = HASH_B.to_string();
        assert!(false_rollback.validate_against_history(&history).is_err());

        let mut unsafe_resolution = proof.clone();
        let mut unsafe_receipt = serde_json::from_str::<Openat2PathResolutionReceipt>(
            &unsafe_resolution.path_containment.resolver_response_body,
        )
        .expect("openat2 path receipt");
        unsafe_receipt.method = ShardPathResolutionMethod::CanonicalizeOnly;
        unsafe_resolution.path_containment.resolver_response_body =
            serde_json::to_string(&unsafe_receipt).expect("openat2 path receipt");
        unsafe_resolution.path_containment.resolver_evidence_sha256 = sha256_bytes(
            unsafe_resolution
                .path_containment
                .resolver_response_body
                .as_bytes(),
        );
        assert!(
            unsafe_resolution
                .validate_against_history(&history)
                .is_err(),
            "a shard reached through a symlink or mount crossing must be rejected"
        );

        let mut no_host_receipt = proof.clone();
        no_host_receipt.host_mutation_evidence = None;
        assert!(
            no_host_receipt.validate_against_history(&history).is_err(),
            "serialized A/B/A hashes cannot substitute for a host-helper mutation receipt"
        );

        let mut no_persisted_mutation = proof.clone();
        let host_evidence = no_persisted_mutation
            .host_mutation_evidence
            .as_mut()
            .expect("host mutation evidence");
        let mut receipt =
            serde_json::from_str::<ShardMutationHostReceipt>(&host_evidence.response_body)
                .expect("host mutation receipt");
        receipt.mutation_fsync_succeeded = false;
        host_evidence.response_body =
            serde_json::to_string(&receipt).expect("host mutation receipt");
        host_evidence.response_sha256 = sha256_bytes(host_evidence.response_body.as_bytes());
        assert!(
            no_persisted_mutation
                .validate_against_history(&history)
                .is_err(),
            "a failed fsync cannot prove an on-disk bitrot mutation"
        );

        let mut conflicting_history = history.clone();
        conflicting_history.push(history_record(
            "put-bitrot-conflict",
            "on-disk-bitrot",
            OperationKind::Put,
            "bitrot/key",
            "version-1",
            Some(HASH_B),
            250,
        ));
        assert!(
            proof
                .validate_against_history(&conflicting_history)
                .is_err(),
            "one immutable version identity cannot have two committed content hashes"
        );

        let mut foreign_bucket = proof.clone();
        let mut mapping = serde_json::from_str::<RustfsShardMutationMappingResponse>(
            &foreign_bucket.mapping_response_body,
        )
        .expect("shard mapping response");
        mapping.bucket = "bucket-foreign".to_string();
        foreign_bucket.mapping_response_body =
            serde_json::to_string(&mapping).expect("shard mapping response");
        foreign_bucket.mapping_response_sha256 =
            sha256_bytes(foreign_bucket.mapping_response_body.as_bytes());
        assert!(
            foreign_bucket.validate_against_history(&history).is_err(),
            "a same-key mapping from another bucket cannot identify the mutated shard"
        );

        let mut inferred_path = proof;
        inferred_path.shard_path = "/tmp/guessed-shard".to_string();
        assert!(inferred_path.validate_against_history(&history).is_err());
    }

    #[test]
    fn heal_progress_must_be_monotonic_and_terminal() {
        let observer = HealObserverIdentity::AdminOperation {
            operation_id: "heal-1".to_string(),
        };
        let mut samples = vec![
            HealProgressSample {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("fresh-volume-replacement"),
                observer: observer.clone(),
                observed_at_ms: 110,
                state: HealProgressState::Running,
                scanned: 10,
                repaired: 1,
                failed: 0,
                status_evidence: None,
            },
            HealProgressSample {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("fresh-volume-replacement"),
                observer: observer.clone(),
                observed_at_ms: 200,
                state: HealProgressState::Completed,
                scanned: 20,
                repaired: 2,
                failed: 0,
                status_evidence: None,
            },
        ];
        for sample in &mut samples {
            let response = serde_json::to_string(&RustfsHealStatusResponse {
                observer: sample.observer.clone(),
                observed_at_ms: sample.observed_at_ms,
                state: sample.state,
                scanned: sample.scanned,
                repaired: sample.repaired,
                failed: sample.failed,
                cluster_definitive: true,
                target_drive_uuid: Some("drive-new".to_string()),
                pool_index: 0,
                set_index: 0,
            })
            .expect("heal status response");
            sample.status_evidence = Some(HealStatusEvidence {
                api_revision: "v1".to_string(),
                response_sha256: sha256_bytes(response.as_bytes()),
                response_body: response,
            });
        }
        let summary = HealSummary {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("fresh-volume-replacement"),
            case: StorageRecoveryCase::FreshVolumeReplacementAdminDeep,
            observer,
            mode: HealMode::AdminDeep,
            target_drive_uuid: Some("drive-new".to_string()),
            pool_index: 0,
            set_index: 0,
            cluster_definitive: true,
            started_at_ms: 100,
            completed_at_ms: 200,
            scanned: 20,
            repaired: 2,
            failed: 0,
            state: HealProgressState::Completed,
        };
        summary
            .validate_progress(&samples, Some(("drive-new", 0, 0)))
            .expect("valid heal progress");

        let mut regressed = samples.clone();
        regressed[1].repaired = 0;
        assert!(
            summary
                .validate_progress(&regressed, Some(("drive-new", 0, 0)))
                .is_err()
        );

        assert!(
            summary
                .validate_progress(&samples, Some(("drive-unrelated", 0, 0)))
                .is_err()
        );
        let mut wrong_qualified_variant = summary.clone();
        wrong_qualified_variant.case =
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement;
        assert!(
            wrong_qualified_variant
                .validate_progress(&samples, Some(("drive-new", 0, 0)))
                .is_err()
        );
        let mut missing_status = samples.clone();
        missing_status[0].status_evidence = None;
        assert!(
            summary
                .validate_progress(&missing_status, Some(("drive-new", 0, 0)))
                .is_err(),
            "self-reported heal counters require a captured RustFS status response"
        );
        let mut forged_status = samples.clone();
        let evidence = forged_status[1]
            .status_evidence
            .as_mut()
            .expect("heal status evidence");
        let mut response =
            serde_json::from_str::<RustfsHealStatusResponse>(&evidence.response_body)
                .expect("heal status response");
        response.repaired = 99;
        evidence.response_body = serde_json::to_string(&response).expect("heal status response");
        evidence.response_sha256 = sha256_bytes(evidence.response_body.as_bytes());
        assert!(
            summary
                .validate_progress(&forged_status, Some(("drive-new", 0, 0)))
                .is_err(),
            "heal progress must be derived from the captured RustFS status body"
        );
        let mut no_op = summary.clone();
        no_op.scanned = 0;
        no_op.repaired = 0;
        let mut no_op_samples = samples;
        no_op_samples[0].scanned = 0;
        no_op_samples[0].repaired = 0;
        no_op_samples[1].scanned = 0;
        no_op_samples[1].repaired = 0;
        assert!(
            no_op
                .validate_progress(&no_op_samples, Some(("drive-new", 0, 0)))
                .is_err()
        );
    }

    #[test]
    fn force_read_leaves_exact_quorum_and_requires_repaired_shard() {
        let shape = ErasureSetShape {
            pool_index: 0,
            set_index: 0,
            server_count: 8,
            volumes_per_server: 1,
            total_shards: 8,
            payload_data_shards: 4,
            payload_parity_shards: 4,
        };
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..8)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![format!("drive-{index}")],
                })
                .collect(),
        )
        .expect("membership");
        let selected_pods = (0..4)
            .map(|index| format!("rustfs-{index}"))
            .collect::<Vec<_>>();
        let resolved_pods = (0..8)
            .map(|index| {
                serde_json::json!({
                    "name": format!("rustfs-{index}"),
                    "uid": format!("uid-rustfs-{index}"),
                    "rustfsContainerId": format!(
                        "containerd://{}",
                        sha256_bytes(format!("rustfs-{index}").as_bytes())
                    ),
                    "ready": true,
                    "node": format!("node-{index}"),
                    "nodeLabels": {"kubernetes.io/hostname": format!("node-{index}")},
                    "persistentVolumeClaims": [{
                        "name": format!("data-rustfs-{index}"),
                        "uid": format!("pvc-uid-{index}"),
                        "volumeName": format!("pv-{index}"),
                        "storageClass": "rustfs-local",
                        "persistentVolume": {
                            "name": format!("pv-{index}"),
                            "uid": format!("pv-uid-{index}"),
                            "source": "local",
                            "node": format!("node-{index}"),
                            "deviceOrPath": format!("/var/lib/rustfs/data-{index}")
                        }
                    }],
                    "volumeMounts": [{
                        "containerName": "rustfs",
                        "mountPath": "/data0",
                        "volumeName": "data",
                        "persistentVolumeClaim": format!("data-rustfs-{index}")
                    }]
                })
            })
            .collect::<Vec<_>>();
        let target_proof_body = serde_json::to_string(&serde_json::json!({
            "schemaVersion": TARGET_PROOF_SCHEMA_VERSION,
            "status": "satisfied",
            "proofLevel": "selector_intent",
            "generatedAtMs": 290,
            "scenario": "fresh-volume-replacement",
            "caseName": "case-fresh-volume-replacement",
            "runId": "run-1",
            "namespace": "fault-run",
            "tenant": "rustfs",
            "resolvedPods": resolved_pods,
            "faults": [{
                "name": "force-read-fault",
                "kind": "rustfs-volume-io-error",
                "backend": "chaos-mesh",
                "targetKind": "rustfs-volume",
                "targetSummary": "fixed RustFS volume targets",
                "selection": "fixed-targets(4)",
                "selectionKind": "fixed-targets",
                "selectionValue": 4,
                "conflictDomain": "fresh test tenant",
                "podSelector": {
                    "namespace": "fault-run",
                    "tenant": "rustfs",
                    "selector": "rustfs.tenant=rustfs",
                    "exactPodsResolved": true,
                    "note": "captured before force-read"
                },
                "volumePath": "/data0",
                "erasureSet": {
                    "required": true,
                    "resolved": true,
                    "source": "rustfs-admin-server-info",
                    "deploymentId": "deployment-1",
                    "shape": shape.clone(),
                    "health": {
                        "onlineShards": 8,
                        "offlineShards": 0,
                        "unknownShards": 0
                    },
                    "membership": membership.clone(),
                    "observedAtMs": 280,
                    "note": "fresh runtime topology"
                }
            }],
            "requirements": [{
                "name": "target_volume_bindings_resolved",
                "status": "passed",
                "message": "resolved"
            }]
        }))
        .expect("target proof");
        let target_proof_sha256 = sha256_bytes(target_proof_body.as_bytes());
        let mut committed = history_record(
            "put-1",
            "fresh-volume-replacement",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_A),
            250,
        );
        committed.durability_cohort = Some(DurabilityCohort::PreFault);
        // Recorder cannot label BeforeFault until the future fault boundary is
        // known; the PreFault cohort plus the proof timestamp supplies it.
        committed.fault_window_relation = None;
        let history = vec![
            committed,
            history_record(
                "get-1",
                "fresh-volume-replacement",
                OperationKind::Get,
                "key",
                "version-1",
                Some(HASH_A),
                350,
            ),
        ];
        let mapping_response = serde_json::to_string(&RustfsVersionShardMappingResponse {
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "version-1".to_string(),
            object_sha256: HASH_A.to_string(),
            pool_index: 0,
            set_index: 0,
            shard_ids: (0..8).map(|index| format!("drive-{index}")).collect(),
        })
        .expect("mapping response");
        let mapping_observations = vec![VersionShardMappingObservation {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("fresh-volume-replacement"),
            observation_id: "mapping-1".to_string(),
            source: ShardMappingSource::RustfsDiagnosticApi,
            api_revision: "v1".to_string(),
            response_sha256: sha256_bytes(mapping_response.as_bytes()),
            response_body: mapping_response,
            offline_evidence: None,
            target_proof_sha256: target_proof_sha256.clone(),
            observed_at_ms: 299,
        }];
        let controller_targets = selected_pods
            .iter()
            .map(|name| format!("fault-run/{name}/rustfs"))
            .collect::<Vec<_>>();
        let controller_records = controller_targets
            .iter()
            .map(|id| {
                serde_json::json!({
                    "id": id,
                    "selectorKey": ".",
                    "phase": "Injected",
                    "injectedCount": 1
                })
            })
            .collect::<Vec<_>>();
        let iochaos_resource = serde_json::json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": "IOChaos",
            "metadata": {
                "name": "force-read-fault",
                "namespace": "chaos-mesh",
                "uid": "iochaos-uid",
                "labels": {
                    "rustfs-fault-test/run-id": "run-1",
                    "rustfs-fault-test/scenario": "fresh-volume-replacement",
                    "app.kubernetes.io/managed-by": "s3chaos"
                }
            },
            "spec": {
                "mode": "fixed",
                "value": "4",
                "selector": {
                    "namespaces": ["fault-run"],
                    "labelSelectors": {"rustfs.tenant": "rustfs"}
                },
                "volumePath": "/data0",
                "path": "/data0/**/*",
                "containerNames": ["rustfs"],
                "percent": 100,
                "duration": "60s",
                "methods": ["READ"],
                "action": "fault",
                "errno": 5
            },
            "status": {
                "conditions": [
                    {"type": "Selected", "status": "True"},
                    {"type": "AllInjected", "status": "True"},
                    {"type": "AllRecovered", "status": "False"}
                ],
                "experiment": {
                    "desiredPhase": "Run",
                    "containerRecords": controller_records
                }
            }
        });
        let active_snapshot = StorageFaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: Some("iochaos".to_string()),
            resource_name: Some("force-read-fault".to_string()),
            chaos_status: Some(iochaos_resource),
            dm_status: None,
        };
        let workload_snapshot = StorageFaultStatusSnapshot {
            stage: "after-workload".to_string(),
            ..active_snapshot.clone()
        };
        let fault_snapshot_id =
            sha256_bytes(&serde_json::to_vec(&active_snapshot).expect("active fault snapshot"));
        let fault_evidence_body = serde_json::to_string(&StorageFaultEvidenceResponse {
            scenario: "fresh-volume-replacement".to_string(),
            run_id: "run-1".to_string(),
            injected: true,
            active_during_workload: true,
            pods_at_fault_activation: selected_pods
                .iter()
                .map(|name| StorageFaultPodIdentity {
                    name: name.clone(),
                    uid: format!("uid-{name}"),
                })
                .collect(),
            pods_at_workload_snapshot: selected_pods
                .iter()
                .map(|name| StorageFaultPodIdentity {
                    name: name.clone(),
                    uid: format!("uid-{name}"),
                })
                .collect(),
            fixed_volume_targets_at_fault_activation: controller_targets.clone(),
            fixed_volume_targets_at_workload_snapshot: controller_targets,
            fixed_volume_containers_at_fault_activation: selected_pods
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        format!("containerd://{}", sha256_bytes(name.as_bytes())),
                    )
                })
                .collect(),
            fixed_volume_containers_at_workload_snapshot: selected_pods
                .iter()
                .map(|name| {
                    (
                        name.clone(),
                        format!("containerd://{}", sha256_bytes(name.as_bytes())),
                    )
                })
                .collect(),
            active_snapshots: vec![active_snapshot],
            workload_snapshots: vec![workload_snapshot],
            fault_active_at_ms: Some(300),
            workload_started_at_ms: Some(300),
            workload_ended_at_ms: Some(400),
            fault_delete_started_at_ms: Some(400),
        })
        .expect("fault evidence");
        let fault_evidence_sha256 = sha256_bytes(fault_evidence_body.as_bytes());
        let runtime_contract = ForceReadRuntimeEvidenceContract::from_artifacts(
            &target_proof_body,
            &fault_evidence_sha256,
            ForceReadRuntimeParameters {
                chaos_namespace: "chaos-mesh".to_string(),
                action: IoChaosAction::Fault { errno: 5 },
                methods: vec!["READ".to_string()],
                io_sampling_percent: 100,
                duration_seconds: 60,
            },
        )
        .expect("validated runtime evidence contract");
        let proof = ForceReadThroughProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("fresh-volume-replacement"),
            shape,
            persisted_version_class: PersistedVersionClass::DataObject,
            all_shard_ids: (0..8).map(|index| format!("drive-{index}")).collect(),
            repaired_shard_id: "drive-7".to_string(),
            target_proof_sha256: target_proof_sha256.clone(),
            fault_evidence_sha256: fault_evidence_sha256.clone(),
            fault_evidence_body: Some(fault_evidence_body),
            unavailable_shards: (0..4)
                .map(|index| UnavailableShardObservation {
                    pod_name: format!("rustfs-{index}"),
                    drive_uuid: format!("drive-{index}"),
                    pool_index: 0,
                    set_index: 0,
                    fault_resource_id: "iochaos/force-read-fault/iochaos-uid".to_string(),
                    active_snapshot_id: fault_snapshot_id.clone(),
                    target_proof_sha256: target_proof_sha256.clone(),
                    fault_evidence_sha256: fault_evidence_sha256.clone(),
                    active_from_ms: 290,
                    active_until_ms: 410,
                })
                .collect(),
            fault_active_from_ms: 300,
            fault_active_until_ms: 400,
            probes: vec![ForcedReadProbe {
                operation_id: "get-1".to_string(),
                object_key: "key".to_string(),
                version_id: "version-1".to_string(),
                expected_sha256: HASH_A.to_string(),
                observed_sha256: HASH_A.to_string(),
                http_status: 200,
                observed_at_ms: 350,
                mapping_observation_id: "mapping-1".to_string(),
                active_fault_snapshot_id: fault_snapshot_id,
            }],
        };
        proof
            .validate_against_runtime(
                &membership,
                &runtime_contract,
                "drive-7",
                &history,
                &mapping_observations,
            )
            .expect("valid forced read");

        let mut synthesized_offline_mapping = mapping_observations.clone();
        synthesized_offline_mapping[0].source = ShardMappingSource::OfflineXl2Inspector;
        synthesized_offline_mapping[0].api_revision = OFFLINE_XL2_INSPECTOR_REVISION.to_string();
        let error = proof
            .validate_against_runtime(
                &membership,
                &runtime_contract,
                "drive-7",
                &history,
                &synthesized_offline_mapping,
            )
            .expect_err("offline mapping without helper receipt must fail");
        assert!(
            error.to_string().contains("lacks its helper receipt"),
            "{error:#}"
        );

        {
            let mut bitrot_target = serde_json::from_str::<serde_json::Value>(&target_proof_body)
                .expect("force-read target proof");
            bitrot_target["scenario"] = serde_json::json!("on-disk-bitrot");
            bitrot_target["caseName"] = serde_json::json!("case-on-disk-bitrot");
            let bitrot_target_body =
                serde_json::to_string(&bitrot_target).expect("bitrot force-read target proof");
            let bitrot_target_sha256 = sha256_bytes(bitrot_target_body.as_bytes());

            let mut bitrot_force_read = proof.clone();
            bitrot_force_read.identity = identity("on-disk-bitrot");
            bitrot_force_read.target_proof_sha256 = bitrot_target_sha256.clone();
            let mut bitrot_fault = serde_json::from_str::<StorageFaultEvidenceResponse>(
                bitrot_force_read
                    .fault_evidence_body
                    .as_deref()
                    .expect("force-read fault evidence"),
            )
            .expect("force-read fault evidence");
            bitrot_fault.scenario = "on-disk-bitrot".to_string();
            for snapshot in bitrot_fault
                .active_snapshots
                .iter_mut()
                .chain(bitrot_fault.workload_snapshots.iter_mut())
            {
                *snapshot
                    .chaos_status
                    .as_mut()
                    .expect("IOChaos resource")
                    .pointer_mut("/metadata/labels/rustfs-fault-test~1scenario")
                    .expect("scenario label") = serde_json::json!("on-disk-bitrot");
            }
            let bitrot_snapshot_id = sha256_bytes(
                &serde_json::to_vec(&bitrot_fault.active_snapshots[0])
                    .expect("bitrot active snapshot"),
            );
            let bitrot_fault_body =
                serde_json::to_string(&bitrot_fault).expect("bitrot fault evidence");
            let bitrot_fault_sha256 = sha256_bytes(bitrot_fault_body.as_bytes());
            bitrot_force_read.fault_evidence_sha256 = bitrot_fault_sha256.clone();
            bitrot_force_read.fault_evidence_body = Some(bitrot_fault_body);
            for shard in &mut bitrot_force_read.unavailable_shards {
                shard.target_proof_sha256 = bitrot_target_sha256.clone();
                shard.fault_evidence_sha256 = bitrot_fault_sha256.clone();
                shard.active_snapshot_id = bitrot_snapshot_id.clone();
            }
            for probe in &mut bitrot_force_read.probes {
                probe.active_fault_snapshot_id = bitrot_snapshot_id.clone();
            }
            let bitrot_runtime = ForceReadRuntimeEvidenceContract::from_artifacts(
                &bitrot_target_body,
                &bitrot_fault_sha256,
                ForceReadRuntimeParameters {
                    chaos_namespace: "chaos-mesh".to_string(),
                    action: IoChaosAction::Fault { errno: 5 },
                    methods: vec!["READ".to_string()],
                    io_sampling_percent: 100,
                    duration_seconds: 60,
                },
            )
            .expect("bitrot force-read runtime evidence");

            let mut bitrot_history = history.clone();
            for record in &mut bitrot_history {
                record.scenario = "on-disk-bitrot".to_string();
            }
            bitrot_history.push(history_record(
                "bitrot-corruption-read",
                "on-disk-bitrot",
                OperationKind::Get,
                "key",
                "version-1",
                Some(HASH_A),
                278,
            ));
            let mut bitrot_mappings = mapping_observations.clone();
            for mapping in &mut bitrot_mappings {
                mapping.identity = identity("on-disk-bitrot");
                mapping.target_proof_sha256 = bitrot_target_sha256.clone();
            }

            let mut mutation_volume = volume("bitrot", 260);
            mutation_volume.pod = "rustfs-7".to_string();
            mutation_volume.pod_uid = "uid-rustfs-7".to_string();
            mutation_volume.rustfs_container_id =
                format!("containerd://{}", sha256_bytes(b"rustfs-7"));
            mutation_volume.volume_name = "data".to_string();
            mutation_volume.persistent_volume_claim = "data-rustfs-7".to_string();
            mutation_volume.persistent_volume_claim_uid = "pvc-uid-7".to_string();
            mutation_volume.persistent_volume = "pv-7".to_string();
            mutation_volume.persistent_volume_uid = "pv-uid-7".to_string();
            mutation_volume.node = "node-7".to_string();
            mutation_volume.node_uid = "node-uid-7".to_string();
            mutation_volume.local_volume_path = "/var/lib/rustfs/data-7".to_string();
            mutation_volume.canonical_device = "/dev/mapper/data-7".to_string();
            mutation_volume.filesystem_uuid = "fs-7".to_string();
            mutation_volume.rustfs_drive_uuid = "drive-7".to_string();
            let mutation =
                bitrot_mutation_proof(mutation_volume, "key", "version-1", 270, 275, 410, 420);
            let corruption_probe = corruption_probe(&mutation, "bitrot-corruption-read", 278);
            let observer = HealObserverIdentity::AdminOperation {
                operation_id: "bitrot-heal-1".to_string(),
            };
            let status_body = serde_json::to_string(&RustfsHealStatusResponse {
                observer: observer.clone(),
                observed_at_ms: 285,
                state: HealProgressState::Completed,
                scanned: 1,
                repaired: 1,
                failed: 0,
                cluster_definitive: true,
                target_drive_uuid: Some("drive-7".to_string()),
                pool_index: 0,
                set_index: 0,
            })
            .expect("bitrot heal status response");
            let heal_samples = vec![HealProgressSample {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("on-disk-bitrot"),
                observer: observer.clone(),
                observed_at_ms: 285,
                state: HealProgressState::Completed,
                scanned: 1,
                repaired: 1,
                failed: 0,
                status_evidence: Some(HealStatusEvidence {
                    api_revision: "v1".to_string(),
                    response_sha256: sha256_bytes(status_body.as_bytes()),
                    response_body: status_body,
                }),
            }];
            let heal = HealSummary {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("on-disk-bitrot"),
                case: StorageRecoveryCase::OnDiskBitrotAdminDeep,
                observer,
                mode: HealMode::AdminDeep,
                target_drive_uuid: Some("drive-7".to_string()),
                pool_index: 0,
                set_index: 0,
                cluster_definitive: true,
                started_at_ms: 280,
                completed_at_ms: 285,
                scanned: 1,
                repaired: 1,
                failed: 0,
                state: HealProgressState::Completed,
            };
            let evidence = BitrotRecoveryCaseEvidence {
                mutation: &mutation,
                corruption_probe: &corruption_probe,
                heal: &heal,
                heal_samples: &heal_samples,
                force_read: &bitrot_force_read,
                membership: &membership,
                runtime: &bitrot_runtime,
                history: &bitrot_history,
                mappings: &bitrot_mappings,
            };
            validate_bitrot_recovery_case(&evidence)
                .expect("complete bitrot recovery evidence chain");

            let mut corrupted_history = bitrot_history.clone();
            corrupted_history[2].value_sha256 = Some(HASH_B.to_string());
            let corrupted_evidence = BitrotRecoveryCaseEvidence {
                history: &corrupted_history,
                ..evidence
            };
            assert!(
                validate_bitrot_recovery_case(&corrupted_evidence).is_err(),
                "the aggregate case must reject a successful corrupted read"
            );
        }

        let mut boundary_mapping = mapping_observations.clone();
        boundary_mapping[0].observed_at_ms = proof.fault_active_from_ms;
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &boundary_mapping,
                )
                .is_err(),
            "a mapping captured at fault activation is not proven pre-fault evidence"
        );

        let mut pre_target_mapping = mapping_observations.clone();
        pre_target_mapping[0].observed_at_ms = 289;
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &pre_target_mapping,
                )
                .is_err(),
            "version mapping cannot precede the post-heal target proof it references"
        );

        let mut incomplete_target_proof =
            serde_json::from_str::<serde_json::Value>(&target_proof_body).expect("target proof");
        *incomplete_target_proof
            .pointer_mut("/resolvedPods/0/persistentVolumeClaims/0/uid")
            .expect("PVC UID") = serde_json::json!("");
        let incomplete_target_proof =
            serde_json::to_string(&incomplete_target_proof).expect("target proof");
        let incomplete_target_contract = ForceReadRuntimeEvidenceContract::from_artifacts(
            &incomplete_target_proof,
            &fault_evidence_sha256,
            ForceReadRuntimeParameters {
                chaos_namespace: "chaos-mesh".to_string(),
                action: IoChaosAction::Fault { errno: 5 },
                methods: vec!["READ".to_string()],
                io_sampling_percent: 100,
                duration_seconds: 60,
            },
        )
        .expect("decodable target proof");
        assert!(
            proof
                .validate_target_proof(&membership, &incomplete_target_contract)
                .is_err(),
            "the force-read PVC UID must be derived from captured target-proof.json"
        );

        for weak_parameters in [
            ForceReadRuntimeParameters {
                chaos_namespace: "chaos-mesh".to_string(),
                action: IoChaosAction::Latency {
                    delay: "1ms".to_string(),
                },
                methods: vec!["READ".to_string()],
                io_sampling_percent: 100,
                duration_seconds: 60,
            },
            ForceReadRuntimeParameters {
                chaos_namespace: "chaos-mesh".to_string(),
                action: IoChaosAction::Fault { errno: 5 },
                methods: vec!["WRITE".to_string()],
                io_sampling_percent: 100,
                duration_seconds: 60,
            },
            ForceReadRuntimeParameters {
                chaos_namespace: "chaos-mesh".to_string(),
                action: IoChaosAction::Fault { errno: 5 },
                methods: vec!["READ".to_string()],
                io_sampling_percent: 1,
                duration_seconds: 60,
            },
        ] {
            assert!(
                ForceReadRuntimeEvidenceContract::from_artifacts(
                    &target_proof_body,
                    &fault_evidence_sha256,
                    weak_parameters,
                )
                .is_err(),
                "weaker IOChaos semantics cannot prove an exact-quorum read"
            );
        }

        let mut zero_fault_window = proof.clone();
        zero_fault_window.fault_active_until_ms = zero_fault_window.fault_active_from_ms;
        assert!(
            zero_fault_window
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "a zero-length fault window cannot prove forced reading"
        );

        let multi_volume_shape = ErasureSetShape {
            server_count: 4,
            volumes_per_server: 2,
            ..proof.shape.clone()
        };
        let multi_volume_membership = ErasureSetMembership::from_runtime(
            &multi_volume_shape,
            (0..4)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![
                        format!("drive-{}", index * 2),
                        format!("drive-{}", index * 2 + 1),
                    ],
                })
                .collect(),
        )
        .expect("consistent 4x2 membership");
        let mut multi_target =
            serde_json::from_str::<serde_json::Value>(&target_proof_body).expect("target proof");
        *multi_target
            .pointer_mut("/faults/0/erasureSet/shape")
            .expect("target shape") =
            serde_json::to_value(&multi_volume_shape).expect("target shape");
        *multi_target
            .pointer_mut("/faults/0/erasureSet/membership")
            .expect("target membership") =
            serde_json::to_value(&multi_volume_membership).expect("target membership");
        multi_target["resolvedPods"] = serde_json::Value::Array(
            (0..4)
                .map(|index| {
                    serde_json::json!({
                        "name": format!("rustfs-{index}"),
                        "uid": format!("uid-rustfs-{index}"),
                        "rustfsContainerId": format!(
                            "containerd://{}",
                            sha256_bytes(format!("rustfs-{index}").as_bytes())
                        ),
                        "ready": true,
                        "node": format!("node-{index}"),
                        "nodeLabels": {"kubernetes.io/hostname": format!("node-{index}")},
                        "persistentVolumeClaims": (0..2).map(|volume| serde_json::json!({
                            "name": format!("data{volume}-rustfs-{index}"),
                            "uid": format!("pvc-uid-{index}-{volume}"),
                            "volumeName": format!("pv-{index}-{volume}"),
                            "storageClass": "fast-csi",
                            "persistentVolume": {
                                "name": format!("pv-{index}-{volume}"),
                                "uid": format!("pv-uid-{index}-{volume}"),
                                "source": "csi",
                                "deviceOrPath": format!("volume-handle-{index}-{volume}")
                            }
                        })).collect::<Vec<_>>(),
                        "volumeMounts": (0..2).map(|volume| serde_json::json!({
                            "containerName": "rustfs",
                            "mountPath": format!("/data{volume}"),
                            "volumeName": format!("data{volume}"),
                            "persistentVolumeClaim": format!("data{volume}-rustfs-{index}")
                        })).collect::<Vec<_>>()
                    })
                })
                .collect(),
        );
        let multi_target_body = serde_json::to_string(&multi_target).expect("target proof");
        let multi_runtime = ForceReadRuntimeEvidenceContract::from_artifacts(
            &multi_target_body,
            &fault_evidence_sha256,
            ForceReadRuntimeParameters {
                chaos_namespace: "chaos-mesh".to_string(),
                action: IoChaosAction::Fault { errno: 5 },
                methods: vec!["READ".to_string()],
                io_sampling_percent: 100,
                duration_seconds: 60,
            },
        )
        .expect("consistent 4x2 target proof");
        let mut multi_volume_proof = proof.clone();
        multi_volume_proof.shape = multi_volume_shape;
        multi_volume_proof.target_proof_sha256 = sha256_bytes(multi_target_body.as_bytes());
        let error = multi_volume_proof
            .validate_target_proof(&multi_volume_membership, &multi_runtime)
            .expect_err("multi-volume servers are not yet supported");
        assert!(
            error
                .to_string()
                .contains("exactly one RustFS volume per server"),
            "a coherent 4x2 topology must fail at the explicit adapter boundary"
        );

        let mut missing_fault_receipt = proof.clone();
        missing_fault_receipt.fault_evidence_body = None;
        assert!(
            missing_fault_receipt
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "Pod names and active timestamps cannot replace captured fault evidence"
        );

        let mut inactive_fault = proof.clone();
        let mut raw = serde_json::from_str::<StorageFaultEvidenceResponse>(
            inactive_fault
                .fault_evidence_body
                .as_deref()
                .expect("fault evidence"),
        )
        .expect("fault evidence");
        *raw.active_snapshots[0]
            .chaos_status
            .as_mut()
            .expect("IOChaos resource")
            .pointer_mut("/status/conditions/1/status")
            .expect("AllInjected condition") = serde_json::json!("False");
        let inactive_snapshot_id =
            sha256_bytes(&serde_json::to_vec(&raw.active_snapshots[0]).expect("active snapshot"));
        let body = serde_json::to_string(&raw).expect("fault evidence");
        inactive_fault.fault_evidence_sha256 = sha256_bytes(body.as_bytes());
        inactive_fault.fault_evidence_body = Some(body);
        let mut inactive_runtime = runtime_contract.clone();
        inactive_runtime.verified_fault_evidence_sha256 =
            inactive_fault.fault_evidence_sha256.clone();
        for shard in &mut inactive_fault.unavailable_shards {
            shard.fault_evidence_sha256 = inactive_fault.fault_evidence_sha256.clone();
            shard.active_snapshot_id = inactive_snapshot_id.clone();
        }
        inactive_fault.probes[0].active_fault_snapshot_id = inactive_snapshot_id;
        assert!(
            inactive_fault
                .validate_against_runtime(
                    &membership,
                    &inactive_runtime,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "a self-consistent but inactive IOChaos snapshot cannot prove forced reading"
        );

        let mut wrong_mapping = mapping_observations.clone();
        let mut wrong_response = serde_json::from_str::<RustfsVersionShardMappingResponse>(
            &wrong_mapping[0].response_body,
        )
        .expect("mapping response");
        wrong_response.set_index = 1;
        wrong_mapping[0].response_body =
            serde_json::to_string(&wrong_response).expect("mapping response");
        wrong_mapping[0].response_sha256 = sha256_bytes(wrong_mapping[0].response_body.as_bytes());
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &wrong_mapping,
                )
                .is_err(),
            "the probe cannot self-assert membership in the repaired erasure set"
        );

        let mut wrong_bucket_mapping = mapping_observations.clone();
        let mut response = serde_json::from_str::<RustfsVersionShardMappingResponse>(
            &wrong_bucket_mapping[0].response_body,
        )
        .expect("mapping response");
        response.bucket = "bucket-foreign".to_string();
        wrong_bucket_mapping[0].response_body =
            serde_json::to_string(&response).expect("mapping response");
        wrong_bucket_mapping[0].response_sha256 =
            sha256_bytes(wrong_bucket_mapping[0].response_body.as_bytes());
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &wrong_bucket_mapping,
                )
                .is_err(),
            "a same-key mapping from another bucket cannot select force-read shards"
        );

        let mut conflicting_commits = history.clone();
        let mut conflicting = history_record(
            "put-2",
            "fresh-volume-replacement",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_B),
            450,
        );
        conflicting.durability_cohort = Some(DurabilityCohort::PreFault);
        conflicting.fault_window_relation = None;
        conflicting_commits.push(conflicting);
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &conflicting_commits,
                    &mapping_observations,
                )
                .is_err(),
            "conflicting successful writes for one immutable version identity must fail closed"
        );

        let mut contradictory_commit_window = history.clone();
        contradictory_commit_window[0].durability_cohort = Some(DurabilityCohort::FaultActive);
        contradictory_commit_window[0].fault_window_relation =
            Some(FaultWindowRelation::DuringFault);
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &contradictory_commit_window,
                    &mapping_observations,
                )
                .is_err(),
            "a timestamp alone must not override contradictory recorder fault-window evidence"
        );

        let mut inverted_commit_interval = history.clone();
        inverted_commit_interval[0].started_at_ms = 301;
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &inverted_commit_interval,
                    &mapping_observations,
                )
                .is_err(),
            "an inverted PUT interval cannot be made pre-fault by forging only its end time"
        );

        let mut inverted_probe_interval = history.clone();
        inverted_probe_interval[1].started_at_ms = 351;
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &inverted_probe_interval,
                    &mapping_observations,
                )
                .is_err(),
            "an inverted GET interval cannot prove a read during the active fault window"
        );

        let mut contradictory_probe_window = history.clone();
        contradictory_probe_window[1].durability_cohort = Some(DurabilityCohort::PreFault);
        contradictory_probe_window[1].fault_window_relation =
            Some(FaultWindowRelation::BeforeFault);
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &contradictory_probe_window,
                    &mapping_observations,
                )
                .is_err(),
            "timestamps cannot make a recorder-labeled pre-fault GET prove exact-quorum reading"
        );

        let mut swapped_pod_drives = proof.clone();
        let first_drive = swapped_pod_drives.unavailable_shards[0].drive_uuid.clone();
        swapped_pod_drives.unavailable_shards[0].drive_uuid =
            swapped_pod_drives.unavailable_shards[1].drive_uuid.clone();
        swapped_pod_drives.unavailable_shards[1].drive_uuid = first_drive;
        assert!(
            swapped_pod_drives
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "unavailable drive identities must remain paired with their owning Pods"
        );

        let mut too_many_online = proof.clone();
        too_many_online.unavailable_shards.pop();
        assert!(
            too_many_online
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err()
        );

        let mut repaired_offline = proof.clone();
        repaired_offline.unavailable_shards[0].drive_uuid = "drive-7".to_string();
        assert!(
            repaired_offline
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err()
        );

        let mut wrong_runtime_targets = runtime_contract.clone();
        wrong_runtime_targets.target_proof.resolved_pods[0].uid = "uid-replaced".to_string();
        assert!(
            proof
                .validate_against_runtime(
                    &membership,
                    &wrong_runtime_targets,
                    "drive-7",
                    &history,
                    &mapping_observations,
                )
                .is_err(),
            "captured fault Pod UIDs must match the target-proof Pod generations"
        );

        let mut self_consistent_wrong_value = proof.clone();
        self_consistent_wrong_value.probes[0].expected_sha256 = HASH_B.to_string();
        self_consistent_wrong_value.probes[0].observed_sha256 = HASH_B.to_string();
        let mut wrong_history = history.clone();
        wrong_history[1].value_sha256 = Some(HASH_B.to_string());
        assert!(
            self_consistent_wrong_value
                .validate_against_runtime(
                    &membership,
                    &runtime_contract,
                    "drive-7",
                    &wrong_history,
                    &mapping_observations,
                )
                .is_err()
        );

        const DEFAULT_PREFILL_COHORT: usize = 20_000;
        let mut scaled_proof = proof.clone();
        scaled_proof.probes = Vec::with_capacity(DEFAULT_PREFILL_COHORT);
        let mut scaled_history = Vec::with_capacity(DEFAULT_PREFILL_COHORT * 2);
        let mut scaled_mappings = Vec::with_capacity(DEFAULT_PREFILL_COHORT);
        for index in 0..DEFAULT_PREFILL_COHORT {
            let key = format!("scale-key-{index}");
            let version_id = format!("scale-version-{index}");
            let put_id = format!("scale-put-{index}");
            let get_id = format!("scale-get-{index}");
            let mapping_id = format!("scale-mapping-{index}");
            let mut committed = history_record(
                &put_id,
                "fresh-volume-replacement",
                OperationKind::Put,
                &key,
                &version_id,
                Some(HASH_A),
                250,
            );
            committed.durability_cohort = Some(DurabilityCohort::PreFault);
            committed.fault_window_relation = None;
            scaled_history.push(committed);
            scaled_history.push(history_record(
                &get_id,
                "fresh-volume-replacement",
                OperationKind::Get,
                &key,
                &version_id,
                Some(HASH_A),
                350,
            ));
            let response = serde_json::to_string(&RustfsVersionShardMappingResponse {
                bucket: "bucket-1".to_string(),
                object_key: key.clone(),
                version_id: version_id.clone(),
                object_sha256: HASH_A.to_string(),
                pool_index: 0,
                set_index: 0,
                shard_ids: (0..8).map(|shard| format!("drive-{shard}")).collect(),
            })
            .expect("scaled mapping response");
            scaled_mappings.push(VersionShardMappingObservation {
                schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity("fresh-volume-replacement"),
                observation_id: mapping_id.clone(),
                source: ShardMappingSource::RustfsDiagnosticApi,
                api_revision: "v1".to_string(),
                response_sha256: sha256_bytes(response.as_bytes()),
                response_body: response,
                offline_evidence: None,
                target_proof_sha256: target_proof_sha256.clone(),
                observed_at_ms: 299,
            });
            scaled_proof.probes.push(ForcedReadProbe {
                operation_id: get_id,
                object_key: key,
                version_id,
                expected_sha256: HASH_A.to_string(),
                observed_sha256: HASH_A.to_string(),
                http_status: 200,
                observed_at_ms: 350,
                mapping_observation_id: mapping_id,
                active_fault_snapshot_id: scaled_proof.unavailable_shards[0]
                    .active_snapshot_id
                    .clone(),
            });
        }
        scaled_proof
            .validate_against_runtime(
                &membership,
                &runtime_contract,
                "drive-7",
                &scaled_history,
                &scaled_mappings,
            )
            .expect("default 20k force-read cohort uses indexed history lookups");
    }

    #[test]
    fn dangling_cleanup_cannot_remove_committed_fragments() {
        let (mut stale_return, mut history) = stale_return_fixture();
        history.truncate(checker_prefix_record_count(
            &stale_return.post_return_checker,
        ));
        let committed = ShardInventoryEntry {
            fragment_id: "fragment-committed".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "version-1".to_string(),
            drive_uuid: "drive-old".to_string(),
            object_sha256: HASH_A.to_string(),
            sha256: HASH_B.to_string(),
            reference_state: FragmentReferenceState::ReferencedVersion,
        };
        let dangling = ShardInventoryEntry {
            fragment_id: "fragment-dangling".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "unknown-write".to_string(),
            drive_uuid: "drive-old".to_string(),
            object_sha256: HASH_C.to_string(),
            sha256: HASH_B.to_string(),
            reference_state: FragmentReferenceState::OrphanedUncommitted,
        };
        let unknown = ShardInventoryEntry {
            fragment_id: "fragment-unknown".to_string(),
            bucket: "bucket-1".to_string(),
            object_key: "key".to_string(),
            version_id: "ack-lost-version".to_string(),
            drive_uuid: "drive-old".to_string(),
            object_sha256: HASH_B.to_string(),
            sha256: HASH_A.to_string(),
            reference_state: FragmentReferenceState::ReferencedVersion,
        };
        let mut ack_lost = history_record(
            "ack-loss-1",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key",
            "null",
            Some(HASH_B),
            530,
        );
        ack_lost.version_id = None;
        ack_lost.outcome = OperationOutcome::Timeout;
        ack_lost.http_status = None;
        history.push(history_record(
            "put-1",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_A),
            520,
        ));
        history.push(ack_lost);
        append_post_return_checker_suffix(&mut history);
        stale_return.post_return_checker = post_return_checker(&history);
        let inventory = |snapshot_id: &str,
                         cursor: &str,
                         observed_at_ms: u64,
                         entries: Vec<ShardInventoryEntry>| {
            let response = serde_json::to_string(&RustfsShardInventoryResponse {
                bucket: "bucket-1".to_string(),
                drive_uuid: stale_return.returned_generation.rustfs_drive_uuid.clone(),
                filesystem_uuid: stale_return.returned_generation.filesystem_uuid.clone(),
                snapshot_id: snapshot_id.to_string(),
                scan_started_at_ms: observed_at_ms - 5,
                scan_completed_at_ms: observed_at_ms,
                start_cursor: None,
                end_cursor: cursor.to_string(),
                exhausted: true,
                total_count: entries.len(),
                entries,
            })
            .expect("inventory response");
            ShardInventorySnapshot::from_complete_scan(
                identity("stale-disk-return-detect"),
                stale_return.returned_generation.clone(),
                ShardInventoryScanReceipt {
                    snapshot_id: snapshot_id.to_string(),
                    source: ShardInventorySource::RustfsDiagnosticApi,
                    api_revision: "v1".to_string(),
                    response_sha256: sha256_bytes(response.as_bytes()),
                    response_body: response,
                    started_at_ms: observed_at_ms - 5,
                    completed_at_ms: observed_at_ms,
                    observed_at_ms,
                },
            )
            .expect("complete shard inventory")
        };
        let before_inventory = inventory(
            "inventory-before",
            "cursor-before",
            550,
            vec![committed.clone(), unknown.clone(), dangling.clone()],
        );
        let mut offline_inventory = before_inventory.clone();
        offline_inventory.receipt.source = ShardInventorySource::OfflineXl2Inspector;
        offline_inventory.receipt.api_revision = OFFLINE_XL2_INSPECTOR_REVISION.to_string();
        offline_inventory
            .validate()
            .expect("offline XL2 inventory source");
        offline_inventory.receipt.api_revision = "unknown-xl2-profile".to_string();
        assert!(
            offline_inventory.validate().is_err(),
            "offline inventory evidence must name the supported capability profile"
        );
        let after_inventory = inventory(
            "inventory-after",
            "cursor-after",
            710,
            vec![committed.clone(), unknown.clone()],
        );
        let cleanup_response = serde_json::to_string(&RustfsDanglingCleanupResponse {
            operation_id: "cleanup-1".to_string(),
            bucket: "bucket-1".to_string(),
            drive_uuid: stale_return.returned_generation.rustfs_drive_uuid.clone(),
            filesystem_uuid: stale_return.returned_generation.filesystem_uuid.clone(),
            before_inventory_snapshot_id: before_inventory.receipt.snapshot_id.clone(),
            started_at_ms: 600,
            completed_at_ms: 700,
            deletion_authority: "offline-inventory-delta-and-injection-receipt".to_string(),
            dry_run_evidence: DanglingCleanupEvidence {
                response_sha256: sha256_bytes(b"{}"),
                response_body: "{}".to_string(),
            },
            live_evidence: DanglingCleanupEvidence {
                response_sha256: sha256_bytes(b"{}"),
                response_body: "{}".to_string(),
            },
            removed_fragment_ids: Vec::new(),
        })
        .expect("cleanup response");
        let proof = DanglingCleanupProof {
            schema_version: STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity("stale-disk-return-detect"),
            returned_generation: stale_return.returned_generation.clone(),
            before_inventory_snapshot_id: before_inventory.receipt.snapshot_id.clone(),
            before_inventory_sha256: before_inventory.entries_sha256.clone(),
            after_inventory_snapshot_id: after_inventory.receipt.snapshot_id.clone(),
            after_inventory_sha256: after_inventory.entries_sha256.clone(),
            cleanup_operation_id: "cleanup-1".to_string(),
            orphan_injection: StaleOwnedOrphanReceipt {
                run_id: "run-1".to_string(),
                bucket: dangling.bucket.clone(),
                object_key: dangling.object_key.clone(),
                version_id: dangling.version_id.clone(),
                relative_part_path: "bucket-1/key/unknown-write/part.1".to_string(),
                drive_uuid: dangling.drive_uuid.clone(),
                fragment_id: dangling.fragment_id.clone(),
                object_sha256: dangling.object_sha256.clone(),
                fragment_sha256: dangling.sha256.clone(),
                part_device_id: "8:1".to_string(),
                part_inode: 42,
                part_size_bytes: 1,
                created_at_ms: 542,
            },
            cleanup_evidence: Some(DanglingCleanupEvidence {
                response_sha256: sha256_bytes(cleanup_response.as_bytes()),
                response_body: cleanup_response,
            }),
            writes_quiesced_at_ms: 540,
            started_at_ms: 600,
            completed_at_ms: 700,
            ack_loss_puts: vec![AckLossPutEvidence {
                operation_id: "ack-loss-1".to_string(),
                proxy_endpoint: "127.0.0.1:39001".to_string(),
                request_count: 1,
                retries_disabled: true,
                request_sha256: HASH_C.to_string(),
                value_sha256: HASH_B.to_string(),
                size_bytes: 1,
                upstream_http_status: 200,
                upstream_request_id: "request-ack-loss-1".to_string(),
                upstream_version_id: "ack-lost-version".to_string(),
                accepted_at_ms: 529,
                upstream_completed_at_ms: 529,
                client_response_bytes: 0,
                connection_closed_at_ms: 530,
            }],
            classified_versions: vec![
                ClassifiedVersionFragments {
                    evidence_id: "put-1".to_string(),
                    operation_id: Some("put-1".to_string()),
                    object_key: committed.object_key.clone(),
                    version_id: committed.version_id.clone(),
                    recoverability: FragmentRecoverability::Committed,
                    fragment_ids: vec![committed.fragment_id.clone()],
                },
                ClassifiedVersionFragments {
                    evidence_id: "ack-loss-1".to_string(),
                    operation_id: Some("ack-loss-1".to_string()),
                    object_key: unknown.object_key.clone(),
                    version_id: unknown.version_id.clone(),
                    recoverability: FragmentRecoverability::RecoverableUnknown,
                    fragment_ids: vec![unknown.fragment_id.clone()],
                },
                ClassifiedVersionFragments {
                    evidence_id: "inventory-1".to_string(),
                    operation_id: None,
                    object_key: dangling.object_key.clone(),
                    version_id: dangling.version_id.clone(),
                    recoverability: FragmentRecoverability::UncommittedDangling,
                    fragment_ids: vec![dangling.fragment_id.clone()],
                },
            ],
        };
        proof
            .validate_against_stale_return(
                &stale_return,
                &before_inventory,
                &after_inventory,
                &history,
            )
            .expect("committed and recoverable-unknown fragments retained");

        let mut ordinary_unknown = proof.clone();
        ordinary_unknown.ack_loss_puts.clear();
        assert!(
            ordinary_unknown
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "an ordinary ambiguous SDK outcome must not count as recoverable-unknown"
        );

        let mut no_cleanup_response = proof.clone();
        no_cleanup_response.cleanup_evidence = None;
        assert!(
            no_cleanup_response
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "local cleanup fields cannot substitute for the captured RustFS response"
        );

        let mut wrong_cleanup_operation = proof.clone();
        let cleanup_evidence = wrong_cleanup_operation
            .cleanup_evidence
            .as_mut()
            .expect("cleanup evidence");
        let mut cleanup_response =
            serde_json::from_str::<RustfsDanglingCleanupResponse>(&cleanup_evidence.response_body)
                .expect("cleanup response");
        cleanup_response.operation_id = "cleanup-foreign".to_string();
        cleanup_evidence.response_body =
            serde_json::to_string(&cleanup_response).expect("cleanup response");
        cleanup_evidence.response_sha256 = sha256_bytes(cleanup_evidence.response_body.as_bytes());
        assert!(
            wrong_cleanup_operation
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "the cleanup operation ID must come from the captured RustFS response"
        );

        let mut mismatched_scan_time = before_inventory.clone();
        let mut scan_response = mismatched_scan_time.response().expect("inventory response");
        scan_response.scan_completed_at_ms -= 1;
        mismatched_scan_time.receipt.response_body =
            serde_json::to_string(&scan_response).expect("inventory response");
        mismatched_scan_time.receipt.response_sha256 =
            sha256_bytes(mismatched_scan_time.receipt.response_body.as_bytes());
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &mismatched_scan_time,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "the raw inventory scan interval must match its persisted receipt"
        );

        let mut cross_boundary_conflict = history.clone();
        cross_boundary_conflict.push(history_record(
            "put-conflict-after-cleanup",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key",
            "version-1",
            Some(HASH_B),
            720,
        ));
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &cross_boundary_conflict,
                )
                .is_err(),
            "immutable-version conflicts outside the cleanup window must still fail closed"
        );

        let rejects_order = |candidate: &DanglingCleanupProof,
                             before: &ShardInventorySnapshot,
                             after: &ShardInventorySnapshot| {
            candidate
                .validate_against_stale_return(&stale_return, before, after, &history)
                .is_err()
        };
        let mut quiesce_at_return = proof.clone();
        quiesce_at_return.writes_quiesced_at_ms = stale_return.returned_generation.observed_at_ms;
        assert!(rejects_order(
            &quiesce_at_return,
            &before_inventory,
            &after_inventory
        ));
        let mut before_at_quiesce = before_inventory.clone();
        before_at_quiesce.receipt.started_at_ms = proof.writes_quiesced_at_ms;
        assert!(rejects_order(&proof, &before_at_quiesce, &after_inventory));
        let mut cleanup_at_before = proof.clone();
        cleanup_at_before.started_at_ms = before_inventory.receipt.completed_at_ms;
        assert!(rejects_order(
            &cleanup_at_before,
            &before_inventory,
            &after_inventory
        ));
        let mut completed_at_start = proof.clone();
        completed_at_start.completed_at_ms = completed_at_start.started_at_ms;
        assert!(rejects_order(
            &completed_at_start,
            &before_inventory,
            &after_inventory
        ));
        let mut after_at_complete = after_inventory.clone();
        after_at_complete.receipt.started_at_ms = proof.completed_at_ms;
        assert!(rejects_order(&proof, &before_inventory, &after_at_complete));

        let mut inverted_cleanup_history = history.clone();
        inverted_cleanup_history
            .iter_mut()
            .find(|record| record.id == "put-1")
            .expect("committed cleanup history")
            .started_at_ms = 601;
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &inverted_cleanup_history,
                )
                .is_err(),
            "an inverted history interval cannot prove a fragment existed before cleanup"
        );

        let mut overlapping_write = history.clone();
        overlapping_write.push(history_record(
            "overlapping-put",
            "stale-disk-return-detect",
            OperationKind::Put,
            "key-overlap",
            "version-overlap",
            Some(HASH_C),
            650,
        ));
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &overlapping_write,
                )
                .is_err(),
            "writes must be quiesced until the post-cleanup inventory is complete"
        );
        for kind in [
            OperationKind::Delete,
            OperationKind::UploadPart,
            OperationKind::AbortMultipartUpload,
        ] {
            let mut overlapping_mutation = history.clone();
            overlapping_mutation.push(history_record(
                "overlapping-mutation",
                "stale-disk-return-detect",
                kind,
                "key-overlap",
                "version-overlap",
                Some(HASH_C),
                650,
            ));
            assert!(
                proof
                    .validate_against_stale_return(
                        &stale_return,
                        &before_inventory,
                        &after_inventory,
                        &overlapping_mutation,
                    )
                    .is_err(),
                "{kind:?} must not overlap the quiesced cleanup window"
            );
        }

        let mut incomplete_scan = before_inventory.clone();
        let mut partial_response = incomplete_scan.response().expect("inventory response");
        partial_response.exhausted = false;
        incomplete_scan.receipt.response_body =
            serde_json::to_string(&partial_response).expect("inventory response");
        incomplete_scan.receipt.response_sha256 =
            sha256_bytes(incomplete_scan.receipt.response_body.as_bytes());
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &incomplete_scan,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "a partial inventory response must not define the cleanup universe"
        );

        let mut truncated_scan = before_inventory.clone();
        let mut truncated_response = truncated_scan.response().expect("inventory response");
        truncated_response.entries.remove(0);
        truncated_scan.entry_count = truncated_response.entries.len();
        truncated_scan.entries_sha256 =
            inventory_entries_sha256(&truncated_response.entries).expect("inventory digest");
        truncated_scan.receipt.response_body =
            serde_json::to_string(&truncated_response).expect("inventory response");
        truncated_scan.receipt.response_sha256 =
            sha256_bytes(truncated_scan.receipt.response_body.as_bytes());
        let mut truncated_proof = proof.clone();
        truncated_proof.before_inventory_sha256 = truncated_scan.entries_sha256.clone();
        assert!(
            truncated_proof
                .validate_against_stale_return(
                    &stale_return,
                    &truncated_scan,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "recomputing local inventory fields cannot hide an entry omitted from the server total"
        );

        let missing_after = inventory(
            "inventory-missing-after",
            "cursor-missing-after",
            710,
            vec![committed],
        );
        let mut missing = proof.clone();
        missing.after_inventory_snapshot_id = missing_after.receipt.snapshot_id.clone();
        missing.after_inventory_sha256 = missing_after.entries_sha256.clone();
        let error = missing
            .validate_against_stale_return(
                &stale_return,
                &before_inventory,
                &missing_after,
                &history,
            )
            .expect_err("recoverable-unknown fragment was removed");
        assert!(error.to_string().contains("recoverable-unknown"));

        let mut incomplete = proof.clone();
        incomplete.classified_versions.pop();
        assert!(
            incomplete
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err()
        );

        let mut relabeled_unknown = proof.clone();
        relabeled_unknown.classified_versions[1].recoverability =
            FragmentRecoverability::UncommittedDangling;
        assert!(
            relabeled_unknown
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err()
        );

        let mut foreign_before = before_inventory.clone();
        let mut foreign_response = foreign_before.response().expect("inventory response");
        foreign_response.entries[0].drive_uuid = "drive-foreign".to_string();
        foreign_before.entries_sha256 =
            inventory_entries_sha256(&foreign_response.entries).expect("inventory digest");
        foreign_before.receipt.response_body =
            serde_json::to_string(&foreign_response).expect("inventory response");
        foreign_before.receipt.response_sha256 =
            sha256_bytes(foreign_before.receipt.response_body.as_bytes());
        let mut foreign_drive = proof.clone();
        foreign_drive.before_inventory_sha256 = foreign_before.entries_sha256.clone();
        assert!(
            foreign_drive
                .validate_against_stale_return(
                    &stale_return,
                    &foreign_before,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "inventory from a foreign drive must not prove stale-drive cleanup"
        );

        let mut foreign_bucket_inventory = before_inventory.clone();
        let mut foreign_bucket_response = foreign_bucket_inventory
            .response()
            .expect("inventory response");
        foreign_bucket_response.bucket = "bucket-foreign".to_string();
        for entry in &mut foreign_bucket_response.entries {
            entry.bucket = "bucket-foreign".to_string();
        }
        foreign_bucket_inventory.entries_sha256 =
            inventory_entries_sha256(&foreign_bucket_response.entries).expect("inventory digest");
        foreign_bucket_inventory.receipt.response_body =
            serde_json::to_string(&foreign_bucket_response).expect("inventory response");
        foreign_bucket_inventory.receipt.response_sha256 =
            sha256_bytes(foreign_bucket_inventory.receipt.response_body.as_bytes());
        let mut foreign_bucket_proof = proof.clone();
        foreign_bucket_proof.before_inventory_sha256 =
            foreign_bucket_inventory.entries_sha256.clone();
        assert!(
            foreign_bucket_proof
                .validate_against_stale_return(
                    &stale_return,
                    &foreign_bucket_inventory,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "same-key fragments from another bucket cannot enter this cleanup universe"
        );

        let mut definite_http_failure = history.clone();
        let ambiguous = definite_http_failure
            .iter_mut()
            .find(|record| record.id == "ack-loss-1")
            .expect("ACK-loss history record");
        ambiguous.outcome = OperationOutcome::Unknown;
        ambiguous.http_status = Some(400);
        assert!(
            proof
                .validate_against_stale_return(
                    &stale_return,
                    &before_inventory,
                    &after_inventory,
                    &definite_http_failure,
                )
                .is_err(),
            "a definite HTTP 4xx response must not be treated as ACK loss"
        );

        let mut server_error = history.clone();
        let ambiguous = server_error
            .iter_mut()
            .find(|record| record.id == "ack-loss-1")
            .expect("ACK-loss history record");
        ambiguous.outcome = OperationOutcome::Failed;
        ambiguous.http_status = Some(500);
        let mut server_error_stale_return = stale_return.clone();
        server_error_stale_return.post_return_checker = post_return_checker(&server_error);
        assert!(
            proof
                .validate_against_stale_return(
                    &server_error_stale_return,
                    &before_inventory,
                    &after_inventory,
                    &server_error,
                )
                .is_err(),
            "a client-observed 5xx is not a byte-dropped successful upstream ACK"
        );

        let extra_unclassified = ShardInventoryEntry {
            fragment_id: "fragment-unlisted-version".to_string(),
            version_id: "unlisted-version".to_string(),
            reference_state: FragmentReferenceState::Unclassified,
            ..unknown.clone()
        };
        let mut unclassified_entries = before_inventory
            .response()
            .expect("inventory response")
            .entries;
        unclassified_entries.push(extra_unclassified);
        let unclassified_before = inventory(
            "inventory-unclassified",
            "cursor-unclassified",
            550,
            unclassified_entries,
        );
        let mut unclassified_proof = proof.clone();
        unclassified_proof.before_inventory_snapshot_id =
            unclassified_before.receipt.snapshot_id.clone();
        unclassified_proof.before_inventory_sha256 = unclassified_before.entries_sha256.clone();
        assert!(
            unclassified_proof
                .validate_against_stale_return(
                    &stale_return,
                    &unclassified_before,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "an exhaustively discovered unlisted version must deny cleanup authority"
        );

        let second_unknown = ShardInventoryEntry {
            fragment_id: "fragment-unknown-2".to_string(),
            version_id: "ack-lost-version-2".to_string(),
            reference_state: FragmentReferenceState::OrphanedUncommitted,
            ..unknown
        };
        let mut ambiguous_materialization = proof;
        let original_entries = before_inventory
            .response()
            .expect("inventory response")
            .entries;
        let ambiguous_before = inventory(
            "inventory-ambiguous",
            "cursor-ambiguous",
            550,
            vec![
                original_entries[0].clone(),
                original_entries[1].clone(),
                original_entries[2].clone(),
                second_unknown.clone(),
            ],
        );
        ambiguous_materialization.before_inventory_snapshot_id =
            ambiguous_before.receipt.snapshot_id.clone();
        ambiguous_materialization.before_inventory_sha256 = ambiguous_before.entries_sha256.clone();
        ambiguous_materialization
            .classified_versions
            .push(ClassifiedVersionFragments {
                evidence_id: "inventory-ambiguous-2".to_string(),
                operation_id: None,
                object_key: second_unknown.object_key.clone(),
                version_id: second_unknown.version_id.clone(),
                recoverability: FragmentRecoverability::UncommittedDangling,
                fragment_ids: vec![second_unknown.fragment_id],
            });
        assert!(
            ambiguous_materialization
                .validate_against_stale_return(
                    &stale_return,
                    &ambiguous_before,
                    &after_inventory,
                    &history,
                )
                .is_err(),
            "an unversioned ACK-loss operation must not select one of multiple inventory versions"
        );
    }
}
