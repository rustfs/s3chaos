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

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const HOST_STORAGE_PROOF_SCHEMA_VERSION: u8 = 3;
pub const HOST_STORAGE_PROOF_ARTIFACT: &str = "host-storage-proof.json";
pub const HOST_STORAGE_CLEANUP_ARTIFACT: &str = "host-storage-post-cleanup.json";
pub const DM_FILESYSTEM_CHECK_ARTIFACT: &str = "dm-filesystem-check.json";
pub(crate) const DM_FILESYSTEM_CHECK_SCHEMA_VERSION: u8 = 1;
pub const HOST_STORAGE_PROOF_MAX_AGE_MS: u64 = 60_000;

const DM_FLAKEY_KIND: &str = "rustfs_block_device_flakey";
const DM_DROP_WRITES_KIND: &str = "rustfs_block_device_drop_writes_crash";
pub const DM_QUORUM_EIO_KIND: &str = "rustfs_block_device_quorum_eio";
pub const DM_STALE_RETURN_KIND: &str = "rustfs_block_device_stale_return";
const DM_CRASH_TAINT_KEY: &str = "s3chaos.rustfs.com/dm-crash";
const READ_ONLY_PREFLIGHT_SCOPE: &str = "read-only Kubernetes and host metadata observation plus proof artifact write; no disk, PV, PVC, object, or power mutation";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HostStorageProofStatus {
    Satisfied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageAllowlist {
    pub nodes: Vec<String>,
    pub devices: Vec<String>,
    pub persistent_volumes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStorageMutationIntent {
    pub scenario: String,
    pub fault_name: String,
    pub fault_kind: String,
    pub run_id: String,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub observer_namespace: String,
    pub observer_pod: String,
    pub backend_specific_destructive_opt_in: bool,
    pub allowlist: HostStorageAllowlist,
    pub fault_table: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStoragePersistentVolumeClaimRef {
    pub namespace: String,
    pub name: String,
    pub uid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageNodeSelector {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DmFilesystemCheck {
    pub(crate) schema_version: u8,
    pub(crate) scenario: String,
    pub(crate) fault_name: String,
    pub(crate) run_id: String,
    pub(crate) node: String,
    pub(crate) persistent_volume: String,
    pub(crate) mapper_name: String,
    pub(crate) logical_device: String,
    pub(crate) canonical_device: String,
    pub(crate) mount_path: String,
    pub(crate) filesystem: String,
    pub(crate) checker: String,
    pub(crate) arguments: Vec<String>,
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) clean: bool,
    pub(crate) mounted_for_recovery: bool,
    pub(crate) unmounted_for_check: bool,
    pub(crate) remounted_after_check: bool,
    pub(crate) remounted_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostStorageTargetObservation {
    pub node: String,
    pub node_uid: String,
    pub node_labels: BTreeMap<String, String>,
    pub pod: String,
    pub pod_uid: String,
    pub volume_name: String,
    pub persistent_volume_claim: String,
    pub persistent_volume_claim_uid: String,
    pub persistent_volume_claim_phase: String,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub persistent_volume_phase: String,
    pub persistent_volume_claim_ref: HostStoragePersistentVolumeClaimRef,
    pub node_selector: HostStorageNodeSelector,
    pub container_mount_path: String,
    pub persistent_volume_path: String,
    pub mapper_name: String,
    pub logical_device: String,
    pub canonical_device: String,
    pub mount_source: String,
    pub mount_canonical_source: String,
    pub filesystem: String,
    pub recovery_table: String,
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageProvenTarget {
    pub node: String,
    pub node_uid: String,
    pub node_labels: BTreeMap<String, String>,
    pub pod: String,
    pub pod_uid: String,
    pub volume_name: String,
    pub persistent_volume_claim: String,
    pub persistent_volume_claim_uid: String,
    pub persistent_volume_claim_phase: String,
    pub persistent_volume: String,
    pub persistent_volume_uid: String,
    pub persistent_volume_phase: String,
    pub persistent_volume_claim_ref: HostStoragePersistentVolumeClaimRef,
    pub node_selector: HostStorageNodeSelector,
    pub container_mount_path: String,
    pub persistent_volume_path: String,
    pub mapper_name: String,
    pub logical_device: String,
    pub canonical_device: String,
    pub mount_source: String,
    pub mount_canonical_source: String,
    pub filesystem: String,
    pub recovery_table_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMapperRollbackContract {
    pub mapper_name: String,
    pub suspend_mode: String,
    pub recovery_table: String,
    pub recovery_table_sha256: String,
    pub resume_without_udev_sync: bool,
    pub commands: DeviceMapperRollbackCommands,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMapperRollbackCommands {
    pub suspend: Vec<String>,
    pub load: Vec<String>,
    pub resume: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceMapperTableContract {
    pub start_sector: u64,
    pub length_sectors: u64,
    pub backing_device: String,
    pub backing_offset_sector: u64,
    pub recovery_table: String,
    pub recovery_table_sha256: String,
    pub fault_table: String,
    pub fault_table_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageQuarantineContract {
    pub node: String,
    pub taint_key: String,
    pub effect: String,
    pub required_on_rollback_failure: bool,
    pub suspend_mapper: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStoragePostCleanupContract {
    pub require_recovery_table_match: bool,
    pub require_mount_device_match: bool,
    pub require_filesystem_mounted: bool,
    pub require_quarantine_absent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageRecoveryContract {
    pub rollback: DeviceMapperRollbackContract,
    pub quarantine: HostStorageQuarantineContract,
    pub post_cleanup: HostStoragePostCleanupContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStorageMutationProof {
    pub schema_version: u8,
    pub status: HostStorageProofStatus,
    pub generated_at_ms: u64,
    pub scenario: String,
    pub fault_name: String,
    pub fault_kind: String,
    pub run_id: String,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub observer_namespace: String,
    pub observer_pod: String,
    pub backend: String,
    pub backend_specific_destructive_opt_in: bool,
    pub preflight_side_effects: String,
    pub allowlist: HostStorageAllowlist,
    pub target: HostStorageProvenTarget,
    pub tables: DeviceMapperTableContract,
    pub recovery: HostStorageRecoveryContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStoragePostCleanupObservation {
    pub schema_version: u8,
    pub scenario: String,
    pub fault_name: String,
    pub run_id: String,
    pub observed_at_ms: u64,
    pub node: String,
    pub persistent_volume: String,
    pub mapper_name: String,
    pub logical_device: String,
    pub canonical_device: String,
    pub mount_canonical_source: String,
    pub filesystem_mounted: bool,
    pub node_quarantined: bool,
    pub recovery_table_sha256: String,
}

impl HostStorageMutationProof {
    pub fn prove_device_mapper(
        intent: HostStorageMutationIntent,
        observation: HostStorageTargetObservation,
    ) -> Result<Self> {
        ensure!(
            intent.backend_specific_destructive_opt_in,
            "device-mapper mutation requires RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1"
        );
        ensure_supported_dm_kind(&intent.fault_kind)?;
        validate_observation(&observation)?;
        require_exact_singleton("host node", &intent.allowlist.nodes, &observation.node)?;
        require_exact_singleton(
            "host device",
            &intent.allowlist.devices,
            &observation.logical_device,
        )?;
        require_exact_singleton(
            "PersistentVolume",
            &intent.allowlist.persistent_volumes,
            &observation.persistent_volume,
        )?;
        ensure!(
            observation.persistent_volume_claim_ref.namespace == intent.namespace
                && observation.persistent_volume_claim_ref.name
                    == observation.persistent_volume_claim
                && observation.persistent_volume_claim_ref.uid
                    == observation.persistent_volume_claim_uid,
            "PersistentVolume claimRef does not bind the observed PVC identity and namespace"
        );

        let tables = canonical_table_contract(
            &intent.fault_kind,
            &observation.recovery_table,
            intent.fault_table.as_deref(),
        )?;
        let recovery_table_sha256 = tables.recovery_table_sha256.clone();
        let target = HostStorageProvenTarget {
            node: observation.node,
            node_uid: observation.node_uid,
            node_labels: observation.node_labels,
            pod: observation.pod,
            pod_uid: observation.pod_uid,
            volume_name: observation.volume_name,
            persistent_volume_claim: observation.persistent_volume_claim,
            persistent_volume_claim_uid: observation.persistent_volume_claim_uid,
            persistent_volume_claim_phase: observation.persistent_volume_claim_phase,
            persistent_volume: observation.persistent_volume,
            persistent_volume_uid: observation.persistent_volume_uid,
            persistent_volume_phase: observation.persistent_volume_phase,
            persistent_volume_claim_ref: observation.persistent_volume_claim_ref,
            node_selector: observation.node_selector,
            container_mount_path: observation.container_mount_path,
            persistent_volume_path: observation.persistent_volume_path,
            mapper_name: observation.mapper_name,
            logical_device: observation.logical_device,
            canonical_device: observation.canonical_device,
            mount_source: observation.mount_source,
            mount_canonical_source: observation.mount_canonical_source,
            filesystem: observation.filesystem,
            recovery_table_sha256: recovery_table_sha256.clone(),
        };
        let recovery = canonical_recovery_contract(&intent.fault_kind, &target, &tables)?;
        let proof = Self {
            schema_version: HOST_STORAGE_PROOF_SCHEMA_VERSION,
            status: HostStorageProofStatus::Satisfied,
            generated_at_ms: observation.observed_at_ms,
            scenario: intent.scenario,
            fault_name: intent.fault_name,
            fault_kind: intent.fault_kind,
            run_id: intent.run_id,
            context: intent.context,
            namespace: intent.namespace,
            tenant: intent.tenant,
            observer_namespace: intent.observer_namespace,
            observer_pod: intent.observer_pod,
            backend: "device-mapper".to_string(),
            backend_specific_destructive_opt_in: true,
            preflight_side_effects: READ_ONLY_PREFLIGHT_SCOPE.to_string(),
            allowlist: intent.allowlist,
            target,
            tables,
            recovery,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == HOST_STORAGE_PROOF_SCHEMA_VERSION,
            "unsupported host-storage proof schema version {}",
            self.schema_version
        );
        ensure!(self.status == HostStorageProofStatus::Satisfied);
        ensure!(
            self.backend == "device-mapper" && self.backend_specific_destructive_opt_in,
            "host-storage proof lacks the device-mapper destructive opt-in"
        );
        ensure!(
            self.preflight_side_effects == READ_ONLY_PREFLIGHT_SCOPE,
            "host-storage proof does not declare the side-effect-free preflight scope"
        );
        for (label, value) in [
            ("scenario", self.scenario.as_str()),
            ("fault name", self.fault_name.as_str()),
            ("run id", self.run_id.as_str()),
            ("context", self.context.as_str()),
            ("namespace", self.namespace.as_str()),
            ("tenant", self.tenant.as_str()),
            ("observer namespace", self.observer_namespace.as_str()),
            ("observer Pod", self.observer_pod.as_str()),
        ] {
            ensure!(
                !value.trim().is_empty(),
                "host-storage proof {label} is empty"
            );
        }
        ensure!(
            self.observer_namespace != self.namespace,
            "host observer must be outside the disposable fault Tenant namespace"
        );
        ensure_supported_dm_kind(&self.fault_kind)?;
        validate_proven_target(&self.target)?;
        ensure!(
            self.target.persistent_volume_claim_ref.namespace == self.namespace,
            "proven PersistentVolume claimRef namespace does not match the run namespace"
        );
        require_exact_singleton("host node", &self.allowlist.nodes, &self.target.node)?;
        require_exact_singleton(
            "host device",
            &self.allowlist.devices,
            &self.target.logical_device,
        )?;
        require_exact_singleton(
            "PersistentVolume",
            &self.allowlist.persistent_volumes,
            &self.target.persistent_volume,
        )?;
        let canonical_tables = canonical_table_contract(
            &self.fault_kind,
            &self.tables.recovery_table,
            Some(&self.tables.fault_table),
        )?;
        ensure!(
            self.tables == canonical_tables
                && self.target.recovery_table_sha256 == self.tables.recovery_table_sha256,
            "host-storage device-mapper table contract is not canonical"
        );
        ensure!(
            self.recovery
                == canonical_recovery_contract(&self.fault_kind, &self.target, &self.tables)?,
            "host-storage recovery/quarantine/cleanup contract is not canonical"
        );
        Ok(())
    }

    pub fn require_fresh_at(&self, fault_apply_started_at_ms: u64) -> Result<()> {
        ensure!(
            self.generated_at_ms > 0 && self.generated_at_ms <= fault_apply_started_at_ms,
            "host-storage proof timestamp is after fault apply or is missing"
        );
        ensure!(
            fault_apply_started_at_ms - self.generated_at_ms <= HOST_STORAGE_PROOF_MAX_AGE_MS,
            "host-storage proof is older than {}ms at fault apply",
            HOST_STORAGE_PROOF_MAX_AGE_MS
        );
        Ok(())
    }

    pub fn require_generated_during_apply(
        &self,
        fault_apply_started_at_ms: u64,
        fault_active_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.generated_at_ms >= fault_apply_started_at_ms,
            "final host-storage proof predates the apply-time re-observation"
        );
        self.require_fresh_at(fault_active_at_ms)
    }

    pub fn require_apply_observation(
        &self,
        observation: &HostStorageTargetObservation,
    ) -> Result<()> {
        validate_observation(observation)?;
        ensure!(
            self.target.node == observation.node
                && self.target.node_uid == observation.node_uid
                && self.target.node_labels == observation.node_labels
                && self.target.pod == observation.pod
                && self.target.pod_uid == observation.pod_uid
                && self.target.volume_name == observation.volume_name
                && self.target.persistent_volume_claim == observation.persistent_volume_claim
                && self.target.persistent_volume_claim_uid
                    == observation.persistent_volume_claim_uid
                && self.target.persistent_volume_claim_phase
                    == observation.persistent_volume_claim_phase
                && self.target.persistent_volume == observation.persistent_volume
                && self.target.persistent_volume_uid == observation.persistent_volume_uid
                && self.target.persistent_volume_phase == observation.persistent_volume_phase
                && self.target.persistent_volume_claim_ref
                    == observation.persistent_volume_claim_ref
                && self.target.node_selector == observation.node_selector
                && self.target.container_mount_path == observation.container_mount_path
                && self.target.persistent_volume_path == observation.persistent_volume_path
                && self.target.mapper_name == observation.mapper_name
                && self.target.logical_device == observation.logical_device
                && self.target.canonical_device == observation.canonical_device
                && self.target.mount_source == observation.mount_source
                && self.target.mount_canonical_source == observation.mount_canonical_source
                && self.target.filesystem == observation.filesystem
                && self.target.recovery_table_sha256
                    == normalized_dm_table_sha256(&observation.recovery_table)?,
            "device-mapper target changed between host-storage preflight and fault apply"
        );
        Ok(())
    }

    pub fn refresh_for_apply(&self, observation: HostStorageTargetObservation) -> Result<Self> {
        self.validate()?;
        self.require_apply_observation(&observation)?;
        let refreshed = Self::prove_device_mapper(
            HostStorageMutationIntent {
                scenario: self.scenario.clone(),
                fault_name: self.fault_name.clone(),
                fault_kind: self.fault_kind.clone(),
                run_id: self.run_id.clone(),
                context: self.context.clone(),
                namespace: self.namespace.clone(),
                tenant: self.tenant.clone(),
                observer_namespace: self.observer_namespace.clone(),
                observer_pod: self.observer_pod.clone(),
                backend_specific_destructive_opt_in: self.backend_specific_destructive_opt_in,
                allowlist: self.allowlist.clone(),
                fault_table: (self.fault_kind == DM_FLAKEY_KIND)
                    .then(|| self.tables.fault_table.clone()),
            },
            observation,
        )?;
        ensure!(
            refreshed.target == self.target
                && refreshed.tables == self.tables
                && refreshed.recovery == self.recovery,
            "host-storage authorization changed while refreshing the apply observation"
        );
        Ok(refreshed)
    }

    pub fn validate_post_cleanup(
        &self,
        observation: &HostStoragePostCleanupObservation,
    ) -> Result<()> {
        ensure!(observation.schema_version == 1);
        ensure!(
            observation.scenario == self.scenario
                && observation.fault_name == self.fault_name
                && observation.run_id == self.run_id
                && observation.node == self.target.node
                && observation.persistent_volume == self.target.persistent_volume
                && observation.mapper_name == self.target.mapper_name
                && observation.logical_device == self.target.logical_device
                && observation.canonical_device == self.target.canonical_device
                && observation.mount_canonical_source == self.target.mount_canonical_source,
            "post-cleanup host-storage observation does not match its preflight proof"
        );
        ensure!(
            observation.observed_at_ms >= self.generated_at_ms,
            "post-cleanup host-storage observation predates preflight"
        );
        ensure!(
            observation.recovery_table_sha256 == self.target.recovery_table_sha256,
            "post-cleanup device-mapper table does not match the preflight recovery table"
        );
        ensure!(
            observation.filesystem_mounted && !observation.node_quarantined,
            "post-cleanup observation must prove the filesystem is mounted and node quarantine is absent"
        );
        Ok(())
    }
}

pub fn normalized_dm_table_sha256(table: &str) -> Result<String> {
    let recovery = parse_linear_table(table)?;
    Ok(table_sha256(&recovery.canonical))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDmTable {
    start_sector: u64,
    length_sectors: u64,
    backing_device: String,
    backing_offset_sector: u64,
    canonical: String,
}

fn canonical_table_contract(
    fault_kind: &str,
    recovery_table: &str,
    configured_fault_table: Option<&str>,
) -> Result<DeviceMapperTableContract> {
    let recovery = parse_linear_table(recovery_table)?;
    let fault_table = match fault_kind {
        DM_FLAKEY_KIND => parse_error_flakey_table(
            configured_fault_table
                .ok_or_else(|| anyhow::anyhow!("dm-flakey requires an explicit fault table"))?,
            &recovery,
        )?,
        DM_DROP_WRITES_KIND => {
            let expected = drop_writes_table(&recovery);
            if let Some(configured) = configured_fault_table {
                ensure!(
                    normalize_table(configured) == expected,
                    "drop_writes fault table is not the canonical table derived from recovery state"
                );
            }
            expected
        }
        DM_STALE_RETURN_KIND | DM_QUORUM_EIO_KIND => {
            let expected = format!(
                "{} {} flakey {} {} 0 86400 2 error_reads error_writes",
                recovery.start_sector,
                recovery.length_sectors,
                recovery.backing_device,
                recovery.backing_offset_sector
            );
            if let Some(configured) = configured_fault_table {
                ensure!(
                    normalize_table(configured) == expected,
                    "stale-return fault table is not the continuous EIO table derived from recovery state"
                );
            }
            expected
        }
        other => bail!("fault kind {other:?} is not a supported device-mapper mutation"),
    };
    Ok(DeviceMapperTableContract {
        start_sector: recovery.start_sector,
        length_sectors: recovery.length_sectors,
        backing_device: recovery.backing_device,
        backing_offset_sector: recovery.backing_offset_sector,
        recovery_table_sha256: table_sha256(&recovery.canonical),
        recovery_table: recovery.canonical,
        fault_table_sha256: table_sha256(&fault_table),
        fault_table,
    })
}

fn parse_linear_table(table: &str) -> Result<ParsedDmTable> {
    let fields = table.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 5 && fields[2] == "linear",
        "device-mapper recovery table must be one linear segment in '<start> <length> linear <backing> <offset>' form"
    );
    let start_sector = parse_sector(fields[0], "start")?;
    let length_sectors = parse_sector(fields[1], "length")?;
    ensure!(
        length_sectors > 0,
        "device-mapper table length must be positive"
    );
    let backing_device = parse_backing_device(fields[3])?;
    let backing_offset_sector = parse_sector(fields[4], "backing offset")?;
    let canonical =
        format!("{start_sector} {length_sectors} linear {backing_device} {backing_offset_sector}");
    Ok(ParsedDmTable {
        start_sector,
        length_sectors,
        backing_device,
        backing_offset_sector,
        canonical,
    })
}

fn parse_error_flakey_table(table: &str, recovery: &ParsedDmTable) -> Result<String> {
    let fields = table.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 7 && fields[2] == "flakey" && fields[5] == "1" && fields[6] == "15",
        "dm-flakey table must use exactly '<start> <length> flakey <backing> <offset> 1 15'"
    );
    require_matching_geometry(fields.as_slice(), recovery)?;
    Ok(format!(
        "{} {} flakey {} {} 1 15",
        recovery.start_sector,
        recovery.length_sectors,
        recovery.backing_device,
        recovery.backing_offset_sector
    ))
}

fn require_matching_geometry(fields: &[&str], recovery: &ParsedDmTable) -> Result<()> {
    let start_sector = parse_sector(fields[0], "fault start")?;
    let length_sectors = parse_sector(fields[1], "fault length")?;
    let backing_device = parse_backing_device(fields[3])?;
    let backing_offset_sector = parse_sector(fields[4], "fault backing offset")?;
    ensure!(
        start_sector == recovery.start_sector
            && length_sectors == recovery.length_sectors
            && backing_device == recovery.backing_device
            && backing_offset_sector == recovery.backing_offset_sector,
        "fault table geometry/backing device must exactly match the active recovery table"
    );
    Ok(())
}

fn parse_sector(value: &str, label: &str) -> Result<u64> {
    value
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("device-mapper {label} sector is not an unsigned integer"))
}

fn parse_backing_device(value: &str) -> Result<String> {
    let device_number = value.split_once(':').is_some_and(|(major, minor)| {
        !major.is_empty()
            && !minor.is_empty()
            && major.chars().all(|ch| ch.is_ascii_digit())
            && minor.chars().all(|ch| ch.is_ascii_digit())
    });
    ensure!(
        (value.starts_with("/dev/") && value.len() > "/dev/".len()) || device_number,
        "device-mapper backing device must be an absolute /dev path or major:minor number"
    );
    Ok(value.to_string())
}

fn normalize_table(table: &str) -> String {
    table.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn table_sha256(table: &str) -> String {
    format!("{:x}", Sha256::digest(table.as_bytes()))
}

fn drop_writes_table(recovery: &ParsedDmTable) -> String {
    format!(
        "{} {} flakey {} {} 0 86400 1 drop_writes",
        recovery.start_sector,
        recovery.length_sectors,
        recovery.backing_device,
        recovery.backing_offset_sector
    )
}

fn validate_observation(observation: &HostStorageTargetObservation) -> Result<()> {
    for (label, value) in [
        ("node", observation.node.as_str()),
        ("node UID", observation.node_uid.as_str()),
        ("pod", observation.pod.as_str()),
        ("pod UID", observation.pod_uid.as_str()),
        ("volume name", observation.volume_name.as_str()),
        ("PVC", observation.persistent_volume_claim.as_str()),
        ("PVC UID", observation.persistent_volume_claim_uid.as_str()),
        (
            "PVC phase",
            observation.persistent_volume_claim_phase.as_str(),
        ),
        ("PV", observation.persistent_volume.as_str()),
        ("PV UID", observation.persistent_volume_uid.as_str()),
        ("PV phase", observation.persistent_volume_phase.as_str()),
        (
            "PV claimRef namespace",
            observation.persistent_volume_claim_ref.namespace.as_str(),
        ),
        (
            "PV claimRef name",
            observation.persistent_volume_claim_ref.name.as_str(),
        ),
        (
            "PV claimRef UID",
            observation.persistent_volume_claim_ref.uid.as_str(),
        ),
        (
            "container mount path",
            observation.container_mount_path.as_str(),
        ),
        ("PV path", observation.persistent_volume_path.as_str()),
        ("mapper name", observation.mapper_name.as_str()),
        ("logical device", observation.logical_device.as_str()),
        ("canonical device", observation.canonical_device.as_str()),
        ("mount source", observation.mount_source.as_str()),
        (
            "canonical mount source",
            observation.mount_canonical_source.as_str(),
        ),
        ("filesystem", observation.filesystem.as_str()),
        ("recovery table", observation.recovery_table.as_str()),
    ] {
        ensure!(
            !value.trim().is_empty(),
            "observed host-storage {label} is empty"
        );
    }
    ensure!(
        observation.logical_device == format!("/dev/mapper/{}", observation.mapper_name),
        "logical device does not match the device-mapper target name"
    );
    ensure!(
        observation.canonical_device == observation.mount_canonical_source,
        "mounted device does not resolve to the selected device-mapper target"
    );
    ensure!(
        observation.persistent_volume_claim_phase == "Bound"
            && observation.persistent_volume_phase == "Bound",
        "host-storage observation requires Bound PVC and PV phases"
    );
    validate_node_selector(&observation.node_selector, &observation.node_labels)?;
    ensure!(
        observation.observed_at_ms > 0,
        "host-storage observation timestamp is missing"
    );
    Ok(())
}

fn validate_proven_target(target: &HostStorageProvenTarget) -> Result<()> {
    ensure!(
        target.logical_device == format!("/dev/mapper/{}", target.mapper_name)
            && target.canonical_device == target.mount_canonical_source,
        "host-storage proven device identity is inconsistent"
    );
    for (label, value) in [
        ("node", target.node.as_str()),
        ("node UID", target.node_uid.as_str()),
        ("pod", target.pod.as_str()),
        ("pod UID", target.pod_uid.as_str()),
        ("volume name", target.volume_name.as_str()),
        ("PVC", target.persistent_volume_claim.as_str()),
        ("PVC UID", target.persistent_volume_claim_uid.as_str()),
        ("PVC phase", target.persistent_volume_claim_phase.as_str()),
        ("PV", target.persistent_volume.as_str()),
        ("PV UID", target.persistent_volume_uid.as_str()),
        ("PV phase", target.persistent_volume_phase.as_str()),
        (
            "PV claimRef namespace",
            target.persistent_volume_claim_ref.namespace.as_str(),
        ),
        (
            "PV claimRef name",
            target.persistent_volume_claim_ref.name.as_str(),
        ),
        (
            "PV claimRef UID",
            target.persistent_volume_claim_ref.uid.as_str(),
        ),
        ("container mount path", target.container_mount_path.as_str()),
        ("PV path", target.persistent_volume_path.as_str()),
        ("mapper name", target.mapper_name.as_str()),
        ("logical device", target.logical_device.as_str()),
        ("canonical device", target.canonical_device.as_str()),
        ("mount source", target.mount_source.as_str()),
        ("filesystem", target.filesystem.as_str()),
        ("recovery table hash", target.recovery_table_sha256.as_str()),
    ] {
        ensure!(
            !value.trim().is_empty(),
            "proven host-storage {label} is empty"
        );
    }
    ensure_sha256("proven recovery table", &target.recovery_table_sha256)?;
    ensure!(
        target.persistent_volume_claim_ref.name == target.persistent_volume_claim
            && target.persistent_volume_claim_ref.uid == target.persistent_volume_claim_uid,
        "proven PersistentVolume claimRef does not match the PVC identity"
    );
    ensure!(
        target.persistent_volume_claim_phase == "Bound"
            && target.persistent_volume_phase == "Bound",
        "host-storage proven target requires Bound PVC and PV phases"
    );
    validate_node_selector(&target.node_selector, &target.node_labels)?;
    Ok(())
}

fn validate_node_selector(
    selector: &HostStorageNodeSelector,
    node_labels: &BTreeMap<String, String>,
) -> Result<()> {
    let hostname = node_labels
        .get("kubernetes.io/hostname")
        .context("host-storage Node labels lack kubernetes.io/hostname")?;
    ensure!(
        !hostname.trim().is_empty(),
        "host-storage Node hostname label is empty"
    );
    ensure!(
        selector.key == "kubernetes.io/hostname"
            && selector.operator == "In"
            && selector.values.len() == 1
            && selector.values.first() == Some(hostname),
        "host-storage PV node selector must exactly match the proven Node kubernetes.io/hostname label {hostname:?}"
    );
    Ok(())
}

fn canonical_recovery_contract(
    fault_kind: &str,
    target: &HostStorageProvenTarget,
    tables: &DeviceMapperTableContract,
) -> Result<HostStorageRecoveryContract> {
    let suspend_mode = match fault_kind {
        DM_FLAKEY_KIND | DM_STALE_RETURN_KIND | DM_QUORUM_EIO_KIND => "noflush",
        DM_DROP_WRITES_KIND => "nolockfs",
        other => bail!("fault kind {other:?} is not a host-storage mutation"),
    };
    Ok(HostStorageRecoveryContract {
        rollback: DeviceMapperRollbackContract {
            mapper_name: target.mapper_name.clone(),
            suspend_mode: suspend_mode.to_string(),
            recovery_table: tables.recovery_table.clone(),
            recovery_table_sha256: tables.recovery_table_sha256.clone(),
            resume_without_udev_sync: true,
            commands: DeviceMapperRollbackCommands {
                suspend: vec![
                    "/usr/sbin/dmsetup".to_string(),
                    "suspend".to_string(),
                    format!("--{suspend_mode}"),
                    target.mapper_name.clone(),
                ],
                load: vec![
                    "/usr/sbin/dmsetup".to_string(),
                    "load".to_string(),
                    target.mapper_name.clone(),
                    "--table".to_string(),
                    tables.recovery_table.clone(),
                ],
                resume: vec![
                    "/usr/sbin/dmsetup".to_string(),
                    "resume".to_string(),
                    "--noudevsync".to_string(),
                    target.mapper_name.clone(),
                ],
            },
        },
        quarantine: HostStorageQuarantineContract {
            node: target.node.clone(),
            taint_key: DM_CRASH_TAINT_KEY.to_string(),
            effect: "NoSchedule".to_string(),
            required_on_rollback_failure: true,
            suspend_mapper: vec![
                "/usr/sbin/dmsetup".to_string(),
                "suspend".to_string(),
                "--noflush".to_string(),
                "--nolockfs".to_string(),
                target.mapper_name.clone(),
            ],
        },
        post_cleanup: HostStoragePostCleanupContract {
            require_recovery_table_match: true,
            require_mount_device_match: true,
            require_filesystem_mounted: true,
            require_quarantine_absent: true,
        },
    })
}

fn ensure_sha256(label: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} SHA-256 must be 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn ensure_supported_dm_kind(fault_kind: &str) -> Result<()> {
    match fault_kind {
        DM_FLAKEY_KIND | DM_DROP_WRITES_KIND | DM_STALE_RETURN_KIND | DM_QUORUM_EIO_KIND => Ok(()),
        other => bail!("fault kind {other:?} is not a supported device-mapper mutation"),
    }
}

fn require_exact_singleton(label: &str, allowlist: &[String], observed: &str) -> Result<()> {
    let values = allowlist
        .iter()
        .map(|value| value.trim())
        .collect::<BTreeSet<_>>();
    ensure!(
        allowlist.len() == 1 && values.len() == 1 && values.contains(observed),
        "{label} allowlist must contain exactly the observed target {observed:?}; configured={allowlist:?}"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmVolumeMapping {
    pub node: String,
    pub node_uid: String,
    pub node_labels: BTreeMap<String, String>,
    pub pod: String,
    pub pod_uid: String,
    pub volume_name: String,
    pub pvc: String,
    pub pvc_uid: String,
    pub pvc_phase: String,
    pub pv: String,
    pub pv_uid: String,
    pub pv_phase: String,
    pub pv_claim_ref: HostStoragePersistentVolumeClaimRef,
    pub node_selector: HostStorageNodeSelector,
    pub container_mount_path: String,
    pub mount_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmStatusSnapshot {
    pub stage: String,
    pub mapper_name: String,
    pub canonical_device: String,
    pub suspended: bool,
    pub observed_at_ms: u64,
    pub helper_pod: String,
    pub mapping: DmVolumeMapping,
    pub table: String,
    pub status: String,
}

impl DmStatusSnapshot {
    pub(crate) fn validate_proof(
        &self,
        proof: &HostStorageMutationProof,
        stage: &str,
        expected_table: &str,
    ) -> Result<()> {
        let target = &proof.target;
        let mapping = &self.mapping;
        ensure!(
            self.stage == stage
                && self.helper_pod == helper_pod_name(&proof.run_id)
                && self.mapper_name == target.mapper_name
                && self.canonical_device == target.canonical_device
                && !self.suspended
                && self.observed_at_ms >= proof.generated_at_ms
                && dm_tables_match(&self.table, expected_table)?,
            "device-mapper {stage} snapshot does not match the proven device, table, or active state"
        );
        ensure!(
            mapping.node == target.node
                && mapping.node_uid == target.node_uid
                && mapping.node_labels == target.node_labels
                && mapping.pod == target.pod
                && mapping.pod_uid == target.pod_uid
                && mapping.volume_name == target.volume_name
                && mapping.pvc == target.persistent_volume_claim
                && mapping.pvc_uid == target.persistent_volume_claim_uid
                && mapping.pvc_phase == target.persistent_volume_claim_phase
                && mapping.pv == target.persistent_volume
                && mapping.pv_uid == target.persistent_volume_uid
                && mapping.pv_phase == target.persistent_volume_phase
                && mapping.pv_claim_ref == target.persistent_volume_claim_ref
                && mapping.node_selector == target.node_selector
                && mapping.container_mount_path == target.container_mount_path
                && mapping.mount_path == target.persistent_volume_path,
            "device-mapper {stage} snapshot does not match the proven Pod/PVC/PV/node mapping"
        );
        Ok(())
    }
}

pub(crate) fn helper_pod_name(run_id: &str) -> String {
    let suffix = run_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(12)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("rustfs-fault-dm-helper-{suffix}")
}

pub(crate) fn dm_tables_match(left: &str, right: &str) -> Result<bool> {
    Ok(canonical_dm_table(left)? == canonical_dm_table(right)?)
}

fn canonical_dm_table(table: &str) -> Result<String> {
    let fields = table.split_whitespace().collect::<Vec<_>>();
    let target = fields
        .get(2)
        .copied()
        .context("device-mapper table is missing its target type")?;
    match target {
        "linear" => Ok(parse_linear_table(table)?.canonical),
        "flakey" => canonical_flakey_table(&fields),
        other => bail!("unsupported device-mapper target type {other:?}"),
    }
}

fn canonical_flakey_table(fields: &[&str]) -> Result<String> {
    ensure!(
        fields.len() >= 7,
        "device-mapper flakey table is shorter than its required geometry and intervals"
    );
    let start_sector = parse_sector(fields[0], "start")?;
    let length_sectors = parse_sector(fields[1], "length")?;
    ensure!(
        length_sectors > 0,
        "device-mapper table length must be positive"
    );
    let backing_device = parse_backing_device(fields[3])?;
    let backing_offset_sector = parse_sector(fields[4], "backing offset")?;
    let up_interval = parse_sector(fields[5], "flakey up interval")?;
    let down_interval = parse_sector(fields[6], "flakey down interval")?;

    // The kernel expands a flakey table without optional features into the
    // equivalent explicit error_reads/error_writes pair when `dmsetup table`
    // reports it. Canonicalizing that representation keeps identity and
    // behavior checks strict without comparing kernel formatting.
    let mut features = if fields.len() == 7 {
        vec!["error_reads", "error_writes"]
    } else {
        let count = fields[7]
            .parse::<usize>()
            .map_err(|_| anyhow::anyhow!("device-mapper flakey feature count is invalid"))?;
        ensure!(
            fields.len() == 8 + count,
            "device-mapper flakey feature count does not match its table"
        );
        let features = fields[8..].to_vec();
        ensure!(
            features
                .iter()
                .all(|feature| matches!(*feature, "drop_writes" | "error_reads" | "error_writes")),
            "device-mapper flakey table contains unsupported feature arguments"
        );
        if features.is_empty() {
            vec!["error_reads", "error_writes"]
        } else {
            features
        }
    };
    features.sort_unstable();
    ensure!(
        features.windows(2).all(|pair| pair[0] != pair[1]),
        "device-mapper flakey table contains duplicate feature arguments"
    );
    ensure!(
        !features.contains(&"drop_writes")
            || (!features.contains(&"error_writes") && !features.contains(&"error_reads")),
        "drop_writes cannot be combined with error_reads or error_writes in this fault contract"
    );

    Ok(format!(
        "{start_sector} {length_sectors} flakey {backing_device} {backing_offset_sector} {up_interval} {down_interval} {} {}",
        features.len(),
        features.join(" ")
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::{
        DM_STALE_RETURN_KIND, HostStorageAllowlist, HostStorageMutationIntent,
        HostStorageMutationProof, HostStorageNodeSelector, HostStoragePersistentVolumeClaimRef,
        HostStoragePostCleanupObservation, HostStorageTargetObservation, dm_tables_match,
    };
    use std::collections::BTreeMap;

    fn observation() -> HostStorageTargetObservation {
        HostStorageTargetObservation {
            node: "worker-a".to_string(),
            node_uid: "node-uid-a".to_string(),
            node_labels: BTreeMap::from([
                ("disk.example.com/class".to_string(), "nvme".to_string()),
                ("kubernetes.io/hostname".to_string(), "worker-a".to_string()),
            ]),
            pod: "rustfs-0".to_string(),
            pod_uid: "uid-0".to_string(),
            volume_name: "data".to_string(),
            persistent_volume_claim: "data-rustfs-0".to_string(),
            persistent_volume_claim_uid: "pvc-uid-0".to_string(),
            persistent_volume_claim_phase: "Bound".to_string(),
            persistent_volume: "pv-a".to_string(),
            persistent_volume_uid: "pv-uid-a".to_string(),
            persistent_volume_phase: "Bound".to_string(),
            persistent_volume_claim_ref: HostStoragePersistentVolumeClaimRef {
                namespace: "rustfs-fault-test".to_string(),
                name: "data-rustfs-0".to_string(),
                uid: "pvc-uid-0".to_string(),
            },
            node_selector: HostStorageNodeSelector {
                key: "kubernetes.io/hostname".to_string(),
                operator: "In".to_string(),
                values: vec!["worker-a".to_string()],
            },
            container_mount_path: "/data/rustfs0".to_string(),
            persistent_volume_path: "/data/rustfs-fault/dm-volume".to_string(),
            mapper_name: "rustfs-fault-dm".to_string(),
            logical_device: "/dev/mapper/rustfs-fault-dm".to_string(),
            canonical_device: "/dev/dm-0".to_string(),
            mount_source: "/dev/mapper/rustfs-fault-dm".to_string(),
            mount_canonical_source: "/dev/dm-0".to_string(),
            filesystem: "ext4".to_string(),
            recovery_table: "0 1024 linear /dev/loop0 0".to_string(),
            observed_at_ms: 1,
        }
    }

    fn intent() -> HostStorageMutationIntent {
        HostStorageMutationIntent {
            scenario: "dm-flakey".to_string(),
            fault_name: "dm-flakey-00-rustfs_block_device_flakey".to_string(),
            fault_kind: "rustfs_block_device_flakey".to_string(),
            run_id: "run-1".to_string(),
            context: "lab".to_string(),
            namespace: "rustfs-fault-test".to_string(),
            tenant: "fault-test-tenant".to_string(),
            observer_namespace: "rustfs-fault-observers".to_string(),
            observer_pod: "observer-worker-a".to_string(),
            backend_specific_destructive_opt_in: true,
            allowlist: HostStorageAllowlist {
                nodes: vec!["worker-a".to_string()],
                devices: vec!["/dev/mapper/rustfs-fault-dm".to_string()],
                persistent_volumes: vec!["pv-a".to_string()],
            },
            fault_table: Some("0 1024 flakey /dev/loop0 0 1 15".to_string()),
        }
    }

    pub(crate) fn quorum_eio_fixture(index: usize, run_id: &str) -> HostStorageMutationProof {
        let mut observed = observation();
        observed.node = format!("worker-{index}");
        observed.node_uid = format!("node-uid-{index}");
        observed
            .node_labels
            .insert("kubernetes.io/hostname".into(), observed.node.clone());
        observed.node_selector.values = vec![observed.node.clone()];
        observed.pod = format!("rustfs-{index}");
        observed.pod_uid = format!("uid-{index}");
        observed.persistent_volume = format!("pv-{index}");
        observed.persistent_volume_uid = format!("pv-uid-{index}");
        observed.persistent_volume_claim = format!("data-rustfs-{index}");
        observed.persistent_volume_claim_uid = format!("pvc-uid-{index}");
        observed.persistent_volume_claim_ref.name = observed.persistent_volume_claim.clone();
        observed.persistent_volume_claim_ref.uid = observed.persistent_volume_claim_uid.clone();
        observed.mapper_name = format!("mapper-{index}");
        observed.logical_device = format!("/dev/mapper/mapper-{index}");
        observed.canonical_device = format!("/dev/dm-{index}");
        observed.mount_source = observed.logical_device.clone();
        observed.mount_canonical_source = observed.canonical_device.clone();
        observed.observed_at_ms = 100;
        let mut request = intent();
        request.scenario = "quorum-p-dm-eio".into();
        request.fault_name = "quorum-dm-eio".into();
        request.fault_kind = super::DM_QUORUM_EIO_KIND.into();
        request.run_id = run_id.into();
        request.allowlist.nodes = vec![observed.node.clone()];
        request.allowlist.devices = vec![observed.logical_device.clone()];
        request.allowlist.persistent_volumes = vec![observed.persistent_volume.clone()];
        request.fault_table = None;
        HostStorageMutationProof::prove_device_mapper(request, observed).unwrap()
    }

    #[test]
    fn exact_allowlists_and_cleanup_contract_produce_a_valid_proof() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");
        proof.validate().expect("valid proof");
        proof.require_fresh_at(60_001).expect("bounded age");

        proof
            .validate_post_cleanup(&HostStoragePostCleanupObservation {
                schema_version: 1,
                scenario: proof.scenario.clone(),
                fault_name: proof.fault_name.clone(),
                run_id: proof.run_id.clone(),
                observed_at_ms: 2,
                node: proof.target.node.clone(),
                persistent_volume: proof.target.persistent_volume.clone(),
                mapper_name: proof.target.mapper_name.clone(),
                logical_device: proof.target.logical_device.clone(),
                canonical_device: proof.target.canonical_device.clone(),
                mount_canonical_source: proof.target.mount_canonical_source.clone(),
                filesystem_mounted: true,
                node_quarantined: false,
                recovery_table_sha256: proof.target.recovery_table_sha256.clone(),
            })
            .expect("cleanup proof");
    }

    #[test]
    fn proof_fails_closed_without_backend_opt_in_or_exact_allowlists() {
        let mut disabled = intent();
        disabled.backend_specific_destructive_opt_in = false;
        assert!(HostStorageMutationProof::prove_device_mapper(disabled, observation()).is_err());

        let mut broad = intent();
        broad.allowlist.nodes.push("worker-b".to_string());
        assert!(HostStorageMutationProof::prove_device_mapper(broad, observation()).is_err());

        let mut wrong_device = intent();
        wrong_device.allowlist.devices = vec!["/dev/mapper/other".to_string()];
        assert!(
            HostStorageMutationProof::prove_device_mapper(wrong_device, observation()).is_err()
        );

        let mut redirected = intent();
        redirected.fault_table = Some("0 1024 flakey /dev/sda 0 1 15".to_string());
        assert!(
            HostStorageMutationProof::prove_device_mapper(redirected, observation()).is_err(),
            "fault table must not redirect the authorized mapper to another backing device"
        );
    }

    #[test]
    fn proof_and_cleanup_tampering_is_rejected() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");
        let mut tampered = proof.clone();
        tampered.recovery.rollback.mapper_name = "other".to_string();
        assert!(tampered.validate().is_err());

        let mut invalid_hash = proof.clone();
        invalid_hash.target.recovery_table_sha256 = "g".repeat(64);
        assert!(
            invalid_hash
                .validate()
                .expect_err("non-hex recovery hash must fail")
                .to_string()
                .contains("64 lowercase hexadecimal")
        );

        let mut changed = observation();
        changed.persistent_volume = "pv-b".to_string();
        assert!(proof.require_apply_observation(&changed).is_err());

        let cleanup = HostStoragePostCleanupObservation {
            schema_version: 1,
            scenario: proof.scenario.clone(),
            fault_name: proof.fault_name.clone(),
            run_id: proof.run_id.clone(),
            observed_at_ms: 2,
            node: proof.target.node.clone(),
            persistent_volume: proof.target.persistent_volume.clone(),
            mapper_name: proof.target.mapper_name.clone(),
            logical_device: proof.target.logical_device.clone(),
            canonical_device: proof.target.canonical_device.clone(),
            mount_canonical_source: proof.target.mount_canonical_source.clone(),
            filesystem_mounted: true,
            node_quarantined: true,
            recovery_table_sha256: proof.target.recovery_table_sha256.clone(),
        };
        assert!(proof.validate_post_cleanup(&cleanup).is_err());
    }

    #[test]
    fn proof_persists_canonical_fault_and_executable_rollback_state() {
        let mut observed = observation();
        observed.recovery_table = " 0  1024 linear  /dev/loop0  0\n".to_string();
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observed)
            .expect("host-storage proof");

        assert_eq!(proof.tables.recovery_table, "0 1024 linear /dev/loop0 0");
        assert_eq!(proof.tables.fault_table, "0 1024 flakey /dev/loop0 0 1 15");
        assert_eq!(
            proof.recovery.rollback.commands.load,
            [
                "/usr/sbin/dmsetup",
                "load",
                "rustfs-fault-dm",
                "--table",
                "0 1024 linear /dev/loop0 0",
            ]
        );
        assert_eq!(
            proof.recovery.rollback.recovery_table,
            "0 1024 linear /dev/loop0 0"
        );
        assert_eq!(proof.recovery.rollback.recovery_table_sha256.len(), 64);
    }

    #[test]
    fn quorum_eio_table_has_no_healthy_interval_and_rejects_foreign_geometry() {
        let mut request = intent();
        request.fault_kind = super::DM_QUORUM_EIO_KIND.into();
        request.fault_table = None;
        let proof =
            HostStorageMutationProof::prove_device_mapper(request.clone(), observation()).unwrap();
        assert_eq!(
            proof.tables.fault_table,
            "0 1024 flakey /dev/loop0 0 0 86400 2 error_reads error_writes"
        );
        assert_eq!(proof.recovery.rollback.suspend_mode, "noflush");
        proof.validate().unwrap();
        let mut redirected = proof.clone();
        redirected.target.persistent_volume = "foreign-pv".into();
        assert!(redirected.validate().is_err());
        request.fault_table =
            Some("0 1024 flakey /dev/loop1 0 0 86400 2 error_reads error_writes".into());
        assert!(HostStorageMutationProof::prove_device_mapper(request, observation()).is_err());
    }

    #[test]
    fn drop_writes_table_is_derived_from_the_live_linear_geometry() {
        let mut drop_intent = intent();
        drop_intent.fault_kind = "rustfs_block_device_drop_writes_crash".to_string();
        drop_intent.fault_table = None;
        let proof = HostStorageMutationProof::prove_device_mapper(drop_intent, observation())
            .expect("drop-writes proof");

        assert_eq!(
            proof.tables.fault_table,
            "0 1024 flakey /dev/loop0 0 0 86400 1 drop_writes"
        );
        assert_eq!(proof.recovery.rollback.suspend_mode, "nolockfs");
    }

    #[test]
    fn stale_return_table_is_continuous_eio_and_not_user_selected() {
        let mut stale_intent = intent();
        stale_intent.scenario = "stale-disk-return-detect".to_string();
        stale_intent.fault_kind = DM_STALE_RETURN_KIND.to_string();
        stale_intent.fault_table = None;
        let proof = HostStorageMutationProof::prove_device_mapper(stale_intent, observation())
            .expect("stale-return proof");

        assert_eq!(
            proof.tables.fault_table,
            "0 1024 flakey /dev/loop0 0 0 86400 2 error_reads error_writes"
        );
        assert_eq!(proof.recovery.rollback.suspend_mode, "noflush");
    }

    #[test]
    fn kernel_expanded_flakey_defaults_match_the_requested_table() {
        assert!(
            dm_tables_match(
                "0 1024 flakey 7:0 0 1 15",
                "0 1024 flakey 7:0 0 1 15 2 error_reads error_writes",
            )
            .expect("compare flakey defaults")
        );
        assert!(
            dm_tables_match(
                "0 1024 flakey 7:0 0 1 15 2 error_writes error_reads",
                "0 1024 flakey 7:0 0 1 15",
            )
            .expect("compare reordered flakey defaults")
        );
        assert!(
            dm_tables_match("0 1024 flakey 7:0 0 1 15 0", "0 1024 flakey 7:0 0 1 15",)
                .expect("compare explicit empty flakey defaults")
        );
    }

    #[test]
    fn flakey_table_comparison_rejects_behavior_or_geometry_drift() {
        for actual in [
            "0 1024 flakey 7:0 0 1 15 1 drop_writes",
            "0 2048 flakey 7:0 0 1 15",
            "0 1024 flakey 7:1 0 1 15",
        ] {
            assert!(
                !dm_tables_match("0 1024 flakey 7:0 0 1 15", actual).expect("compare flakey table")
            );
        }
        assert!(
            dm_tables_match(
                "0 1024 flakey 7:0 0 1 15",
                "0 1024 flakey 7:0 0 1 15 2 error_reads error_reads",
            )
            .is_err()
        );
    }

    #[test]
    fn apply_refresh_rejects_a_replaced_pod_identity() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");
        let mut replaced = observation();
        replaced.pod_uid = "uid-replacement".to_string();
        replaced.observed_at_ms = 2;

        assert!(proof.refresh_for_apply(replaced).is_err());
    }

    #[test]
    fn apply_refresh_rejects_same_name_pvc_or_pv_recreation() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");
        let mut replaced_pvc = observation();
        replaced_pvc.persistent_volume_claim_uid = "pvc-uid-new".to_string();
        replaced_pvc.persistent_volume_claim_ref.uid = "pvc-uid-new".to_string();
        replaced_pvc.observed_at_ms = 2;
        assert!(proof.refresh_for_apply(replaced_pvc).is_err());

        let mut replaced_pv = observation();
        replaced_pv.persistent_volume_uid = "pv-uid-new".to_string();
        replaced_pv.observed_at_ms = 2;
        assert!(proof.refresh_for_apply(replaced_pv).is_err());
    }

    #[test]
    fn apply_refresh_rejects_node_identity_label_or_volume_phase_drift() {
        let proof = HostStorageMutationProof::prove_device_mapper(intent(), observation())
            .expect("host-storage proof");

        let mut replaced_node = observation();
        replaced_node.node_uid = "node-uid-new".to_string();
        replaced_node.observed_at_ms = 2;
        assert!(proof.refresh_for_apply(replaced_node).is_err());

        let mut relabeled_node = observation();
        relabeled_node.node_labels.insert(
            "kubernetes.io/hostname".to_string(),
            "storage-host-new".to_string(),
        );
        relabeled_node.observed_at_ms = 2;
        assert!(proof.refresh_for_apply(relabeled_node).is_err());

        let mut lost_pvc = observation();
        lost_pvc.persistent_volume_claim_phase = "Lost".to_string();
        lost_pvc.observed_at_ms = 2;
        assert!(proof.refresh_for_apply(lost_pvc).is_err());

        let mut released_pv = observation();
        released_pv.persistent_volume_phase = "Released".to_string();
        released_pv.observed_at_ms = 2;
        assert!(proof.refresh_for_apply(released_pv).is_err());
    }
}
