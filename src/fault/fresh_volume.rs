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

//! Test-owned static Local-PV replacement and RustFS heal transports.
//!
//! Kubernetes lifecycle policy lives here; the raw-wire adapter below only
//! signs requests, retains receipts, and tracks an operation identity owned by
//! this attempt. Verdict policy remains in the storage-recovery runner.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::future::Future;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use http::Method;
use k8s_openapi::api::core::v1::{PersistentVolume, PersistentVolumeClaim, Pod};
use kube::{
    Api,
    api::{DeleteParams, Preconditions},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::fault::{
    backends::{chaos_mesh, lifecycle},
    checker,
    config::FaultTestConfig,
    events::{RunEventRecorder, RunEventStatus},
    fixture,
    history::{OperationKind, OperationOutcome, Recorder},
    plan::{FaultKind, StorageRecoveryExecutionPlan},
    pods::{RustfsTargetInventory, rustfs_target_inventory},
    preflight::{
        PreflightCheck, PreflightPhase, PreflightSummary, TargetErasureSetProof, TargetProof,
    },
    quorum::{
        ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape, QuorumCaseClass,
        QuorumVolumeBinding, QuorumVolumeBoundary, QuorumVolumeTargetProof,
    },
    reporting::{FaultStatusSnapshot, ResponsibilityDomain, RunMetadata},
    runner::access::{
        ensure_s3_access, s3_access, wait_for_ready_tenant, wait_for_stable_rustfs_pods,
    },
    scenarios::{FaultBackend, FaultScenario},
    shutdown::RunDeadline,
    spec::FaultRunSpec,
    storage_recovery::{
        DISK_GENERATION_PROOF_ARTIFACT, EmptyVolumeObservation, EmptyVolumeScanResponse,
        FreshVolumeReplacementProof, HEAL_PROGRESS_ARTIFACT, HEAL_SUMMARY_ARTIFACT,
        HealObserverIdentity, HealProgressSample, HealProgressState, HealStatusEvidence,
        HealSummary, OfflineVersionShardMappingEvidence, RustfsHealStatusResponse,
        ShardMappingSource, StorageRecoveryArtifactIdentity, StorageRecoveryCase,
        StorageVolumeIdentity, VERSION_SHARD_MAPPING_ARTIFACT, VersionShardMappingObservation,
    },
    storage_recovery_helper::{
        FreshVolumeShardInspectionRequest, FreshVolumeShardInspectionResponse,
        STORAGE_HELPER_JOURNAL_ROOT, STORAGE_HELPER_VOLUME_ROOT,
    },
    storage_recovery_lease::{
        KubernetesStorageLeaseAdapter, StorageRecoveryCleanupProof, release_owned_lease,
    },
    storage_recovery_runner::{
        OwnedHealCancel, STORAGE_RECOVERY_WORKFLOW_ARTIFACT, StorageRecoveryCaseDriver,
        StorageRecoveryWorkflowEvidence,
    },
    storage_recovery_runtime::{
        HostFlockProof, HostGenerationIdentity, KubectlStorageRecoveryAttemptGuard,
        KubectlStorageRecoveryHostAdapter, KubernetesResourceVersions, OwnedStorageContext,
        StorageRecoveryExclusiveAccess, StorageRecoveryHostOperation,
        StorageRecoveryOperationReceipt,
    },
    workload::execution::{
        MixedWorkloadRequest, PostRecoveryWriteRequest, WorkloadPlanArtifact,
        post_recovery_object_count, prefill_objects, recommit_unconfirmed_objects,
        run_mixed_workload, run_post_recovery_write_probe,
    },
    workload::{ObjectSpec, S3WorkloadClient, WorkloadPlan},
};
use crate::framework::{
    artifacts::ArtifactCollector,
    kubectl::Kubectl,
    port_forward::{PortForwardGuard, PortForwardSpec, replace_port_forward},
    resources,
};
use crate::rustfs::{RustfsAdminTransport, RustfsErasureLayout, read_erasure_layout};

pub const FRESH_VOLUME_FIXTURE_ARTIFACT: &str = "fresh-volume-fixture.json";
pub const FRESH_VOLUME_HEAL_TRANSCRIPT_ARTIFACT: &str = "fresh-volume-heal-transcript.json";

const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const RUN_LABEL: &str = "s3chaos.rustfs.com/run";
const MANAGER: &str = "s3chaos-fresh-volume";
const REPLACEMENT_STATUS_PATH: &str = "/rustfs/admin/v4/heal/replacement-recovery";
const ADMIN_HEAL_PATH: &str = "/rustfs/admin/v3/heal/";
pub(crate) const FRESH_VOLUME_READ_PROOF_ARTIFACT: &str = "force-read-proof.json";
pub(crate) const FRESH_VOLUME_READ_HISTORY_ARTIFACT: &str = "force-read-history.jsonl";
pub(crate) const FRESH_VOLUME_CLEANUP_ARTIFACT: &str = "fresh-volume-cleanup.json";
pub(crate) const FRESH_VOLUME_ABORT_PROOF_ARTIFACT: &str =
    "fresh-volume-aborted-before-mutation.json";
pub(crate) const FRESH_VOLUME_HEAL_START_ARTIFACT: &str = "fresh-volume-heal-start.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ControllerSnapshotEvidence {
    phase: String,
    observed_at_ms: u64,
    sha256: String,
    body: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct VersionReadEvidence {
    phase: String,
    operation_id: String,
    started_at_ms: u64,
    ended_at_ms: u64,
    outcome: OperationOutcome,
    http_status: Option<u16>,
    observed_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementShardInspectionEvidence {
    captured_at_ms: u64,
    helper_pod: String,
    target_pod: String,
    target_pod_uid: String,
    target_container_id: String,
    mount_path: String,
    request: crate::fault::storage_recovery_helper::FreshVolumeShardInspectionRequest,
    response_sha256: String,
    response: crate::fault::storage_recovery_helper::FreshVolumeShardInspectionResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SiblingReadFaultEvidence {
    target_proof_sha256: String,
    target_proof_body: String,
    selected_targets: Vec<String>,
    unavailable_drive_uuids: Vec<String>,
    active_at_ms: u64,
    delete_started_at_ms: u64,
    deleted_at_ms: u64,
    snapshots: Vec<ControllerSnapshotEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementPathFaultEvidence {
    exact_container_path: String,
    manifest_sha256: String,
    manifest_body: String,
    selected_target: String,
    active_at_ms: u64,
    delete_started_at_ms: u64,
    deleted_at_ms: u64,
    snapshots: Vec<ControllerSnapshotEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FreshVolumeReadMatrixEvidence {
    schema_version: u8,
    identity: StorageRecoveryArtifactIdentity,
    chaos_namespace: String,
    shape: ErasureSetShape,
    membership: ErasureSetMembership,
    repaired_drive_uuid: String,
    object_key: String,
    version_id: String,
    expected_sha256: String,
    ordinary_get_operation_id: String,
    shard_before_fault: ReplacementShardInspectionEvidence,
    shard_after_fault: ReplacementShardInspectionEvidence,
    sibling_fault: SiblingReadFaultEvidence,
    replacement_path_fault: ReplacementPathFaultEvidence,
    replacement_available: VersionReadEvidence,
    replacement_blocked: VersionReadEvidence,
    replacement_restored: VersionReadEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReplacementTargetFingerprint<'a> {
    helper_pod: &'a str,
    target_pod: &'a str,
    target_pod_uid: &'a str,
    target_container_id: &'a str,
    mount_path: &'a str,
    relative_part_path: &'a str,
    shard_device_id: &'a str,
    shard_inode: u64,
    shard_size_bytes: u64,
    shard_sha256: &'a str,
}

impl<'a> From<&'a ReplacementShardInspectionEvidence> for ReplacementTargetFingerprint<'a> {
    fn from(evidence: &'a ReplacementShardInspectionEvidence) -> Self {
        let shard = &evidence.response.inspection.selected_part;
        Self {
            helper_pod: &evidence.helper_pod,
            target_pod: &evidence.target_pod,
            target_pod_uid: &evidence.target_pod_uid,
            target_container_id: &evidence.target_container_id,
            mount_path: &evidence.mount_path,
            relative_part_path: &shard.relative_part_path,
            shard_device_id: &shard.shard_device_id,
            shard_inode: shard.shard_inode,
            shard_size_bytes: shard.shard_size_bytes,
            shard_sha256: &shard.original_sha256,
        }
    }
}

fn validate_replacement_part_path(
    bucket: &str,
    object_key: &str,
    part_number: u32,
    path: &str,
) -> Result<()> {
    ensure!(
        part_number > 0
            && path.starts_with(&format!("{bucket}/{object_key}/"))
            && path.ends_with(&format!("/part.{part_number}"))
            && !path.contains(".metadata.bin")
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "replacement shard path is not the selected exact part file"
    );
    Ok(())
}

fn validate_version_binding(expected: &str, requested: &str, inspected: &str) -> Result<()> {
    ensure!(
        !expected.trim().is_empty() && requested == expected && inspected == expected,
        "replacement shard inspection version differs from the sealed version"
    );
    Ok(())
}

fn validate_target_continuity(
    before: ReplacementTargetFingerprint<'_>,
    after: ReplacementTargetFingerprint<'_>,
) -> Result<()> {
    ensure!(
        before == after,
        "replacement shard target changed during the causal read proof"
    );
    Ok(())
}

fn validate_replacement_membership(
    original: &ErasureSetMembership,
    current: &ErasureSetMembership,
    old_volume: &StorageVolumeIdentity,
    new_volume: &StorageVolumeIdentity,
) -> Result<()> {
    let mut expected = original.clone();
    let target = expected
        .members
        .iter_mut()
        .find(|member| member.pod_name == old_volume.pod)
        .context("original volume is outside pre-replacement membership")?;
    ensure!(
        target.shard_ids.as_slice() == [old_volume.rustfs_drive_uuid.as_str()],
        "original volume does not own the mapped shard"
    );
    target.pod_name = new_volume.pod.clone();
    target.shard_ids = vec![new_volume.rustfs_drive_uuid.clone()];
    ensure!(
        expected == *current,
        "runtime membership changed outside the replacement slot"
    );
    Ok(())
}

fn validate_rebuilt_shard(
    original: &crate::fault::storage_recovery_helper::OfflineXl2InspectResponse,
    rebuilt: &crate::fault::storage_recovery_helper::OfflineXl2InspectResponse,
) -> Result<()> {
    ensure!(
        original.layout == rebuilt.layout
            && original.selected_part.part_number == rebuilt.selected_part.part_number
            && original.selected_part.relative_part_path
                == rebuilt.selected_part.relative_part_path
            && original.selected_part.shard_size_bytes == rebuilt.selected_part.shard_size_bytes
            && original.selected_part.original_sha256 == rebuilt.selected_part.original_sha256,
        "replacement shard differs from the sealed pre-replacement shard"
    );
    Ok(())
}

fn validate_read_result(
    outcome: OperationOutcome,
    http_status: Option<u16>,
    observed_sha256: Option<&str>,
    expected_sha256: &str,
    succeeds: bool,
) -> Result<()> {
    if succeeds {
        ensure!(
            outcome == OperationOutcome::Ok && observed_sha256 == Some(expected_sha256),
            "replacement-dependent GET did not return the sealed bytes"
        );
    } else {
        ensure!(
            outcome == OperationOutcome::Failed
                && http_status.is_some_and(|status| status >= 500)
                && observed_sha256.is_none(),
            "replacement part READ EIO did not make the exact version unavailable"
        );
    }
    Ok(())
}

fn validate_causal_timeline(points: [u64; 11]) -> Result<()> {
    ensure!(
        points.windows(2).all(|window| window[0] <= window[1]),
        "fresh-volume causal read phases are out of order"
    );
    Ok(())
}

impl FreshVolumeReadMatrixEvidence {
    pub(crate) fn validate(
        &self,
        records: &[crate::fault::history::OperationRecord],
    ) -> Result<()> {
        ensure!(
            self.schema_version == 3,
            "unsupported fresh-volume read proof schema"
        );
        self.shape.validate()?;
        self.membership.validate(&self.shape)?;
        ensure!(
            self.identity.scenario == "fresh-volume-replacement"
                && !self.identity.run_id.trim().is_empty()
                && !self.chaos_namespace.trim().is_empty()
                && !self.object_key.trim().is_empty()
                && !self.version_id.trim().is_empty()
                && self.version_id != "null"
                && self.expected_sha256.len() == 64
                && !self.repaired_drive_uuid.trim().is_empty(),
            "fresh-volume read proof identity is incomplete"
        );
        let all_drives = self
            .membership
            .members
            .iter()
            .flat_map(|member| member.shard_ids.iter())
            .collect::<BTreeSet<_>>();
        ensure!(
            all_drives.contains(&self.repaired_drive_uuid),
            "repaired drive is outside runtime membership"
        );
        self.validate_replacement_shard()?;
        self.validate_faults(&all_drives)?;
        self.validate_reads(records)?;
        let ordinary = records
            .iter()
            .filter(|record| record.id == self.ordinary_get_operation_id)
            .collect::<Vec<_>>();
        let [ordinary] = ordinary.as_slice() else {
            bail!("fresh-volume ordinary post-replacement GET is missing or duplicate")
        };
        ensure!(
            ordinary.kind == OperationKind::Get
                && ordinary.key.as_deref() == Some(self.object_key.as_str())
                && ordinary.version_id.as_deref() == Some(self.version_id.as_str())
                && ordinary.outcome == OperationOutcome::Ok
                && ordinary.value_sha256.as_deref() == Some(self.expected_sha256.as_str())
                && ordinary.ended_at_ms <= self.shard_before_fault.captured_at_ms,
            "ordinary replacement GET does not precede the causal read proof"
        );
        Ok(())
    }

    fn validate_replacement_shard(&self) -> Result<()> {
        let expected_phases = [&self.shard_before_fault, &self.shard_after_fault];
        for evidence in expected_phases {
            let encoded = serde_json::to_string(&evidence.response)?;
            let inspection = &evidence.response.inspection;
            ensure!(
                evidence.captured_at_ms > 0
                    && evidence.response.observed_at_ms > 0
                    && evidence.response_sha256 == sha256_text(&encoded)
                    && evidence.request.bucket == self.identity.bucket
                    && evidence.request.object_key == self.object_key
                    && evidence.request.object_sha256 == self.expected_sha256
                    && evidence.request.drive_uuid == self.repaired_drive_uuid
                    && evidence.request.selected_part_number == 1
                    && evidence.target_pod
                        == self
                            .membership
                            .members
                            .iter()
                            .find(|member| {
                                member.shard_ids.as_slice() == [self.repaired_drive_uuid.as_str()]
                            })
                            .context("replacement drive has no unique runtime member")?
                            .pod_name
                    && !evidence.target_pod_uid.trim().is_empty()
                    && !evidence.target_container_id.trim().is_empty()
                    && evidence.mount_path.starts_with('/')
                    && inspection.drive_uuid == evidence.request.drive_uuid
                    && inspection.mount_device_id == evidence.request.mount_device_id
                    && inspection.layout.erasure_data_shards == self.shape.payload_data_shards
                    && inspection.layout.erasure_parity_shards == self.shape.payload_parity_shards
                    && inspection.layout.erasure_index > 0
                    && inspection.layout.erasure_index <= self.shape.total_shards
                    && inspection.selected_part.part_number == 1
                    && inspection.selected_part.shard_device_id == evidence.request.mount_device_id
                    && inspection.selected_part.shard_inode > 0
                    && inspection.selected_part.shard_size_bytes > 0,
                "replacement shard inspection is not bound to the sealed version and runtime generation"
            );
            validate_version_binding(
                &self.version_id,
                &evidence.request.version_id,
                &inspection.layout.version_id,
            )?;
            validate_replacement_part_path(
                &self.identity.bucket,
                &self.object_key,
                evidence.request.selected_part_number,
                &inspection.selected_part.relative_part_path,
            )?;
        }
        ensure!(
            self.shard_before_fault.request == self.shard_after_fault.request
                && self.shard_before_fault.response.inspection.layout
                    == self.shard_after_fault.response.inspection.layout,
            "replacement shard inspection request changed during the causal read proof"
        );
        validate_target_continuity(
            ReplacementTargetFingerprint::from(&self.shard_before_fault),
            ReplacementTargetFingerprint::from(&self.shard_after_fault),
        )?;
        Ok(())
    }

    fn validate_faults(&self, all_drives: &BTreeSet<&String>) -> Result<()> {
        let tolerance = usize::try_from(self.shape.payload_quorum()?.read_tolerance)?;
        let target_proof: TargetProof = serde_json::from_str(&self.sibling_fault.target_proof_body)
            .context("decode fresh-volume sibling target proof")?;
        ensure!(
            self.sibling_fault.target_proof_sha256
                == sha256_text(&self.sibling_fault.target_proof_body)
                && target_proof.status == crate::fault::preflight::TargetProofStatus::Satisfied
                && target_proof.scenario == self.identity.scenario
                && target_proof.run_id == self.identity.run_id
                && !target_proof.namespace.trim().is_empty()
                && !target_proof.tenant.trim().is_empty()
                && self.sibling_fault.selected_targets.len() == tolerance
                && self.sibling_fault.unavailable_drive_uuids.len() == tolerance
                && self
                    .sibling_fault
                    .unavailable_drive_uuids
                    .iter()
                    .collect::<BTreeSet<_>>()
                    .len()
                    == tolerance
                && self
                    .sibling_fault
                    .unavailable_drive_uuids
                    .iter()
                    .all(|drive| all_drives.contains(drive))
                && !self
                    .sibling_fault
                    .unavailable_drive_uuids
                    .contains(&self.repaired_drive_uuid),
            "sibling fault is not bound to the exact runtime read tolerance"
        );
        let erasure = target_proof
            .faults
            .first()
            .and_then(|fault| fault.erasure_set.as_ref())
            .context("fresh-volume target proof lacks erasure membership")?;
        ensure!(
            target_proof.faults.len() == 1
                && erasure.shape.as_ref() == Some(&self.shape)
                && erasure.membership.as_ref() == Some(&self.membership)
                && erasure.volume_quorum.is_some(),
            "fresh-volume target proof geometry differs from the read proof"
        );
        let candidate_pod_ids = self
            .membership
            .members
            .iter()
            .map(|member| format!("{}/{}", target_proof.namespace, member.pod_name))
            .collect::<BTreeSet<_>>();
        let sibling_pod_names = self
            .sibling_fault
            .selected_targets
            .iter()
            .map(|record| {
                chaos_mesh::iochaos_record_pod_id(record).and_then(|pod_id| {
                    pod_id
                        .strip_prefix(&format!("{}/", target_proof.namespace))
                        .map(str::to_string)
                        .context("sibling IOChaos selected another namespace")
                })
            })
            .collect::<Result<BTreeSet<_>>>()?;
        let selected_drives = sibling_pod_names
            .iter()
            .map(|pod| {
                let member = self
                    .membership
                    .members
                    .iter()
                    .find(|member| member.pod_name == *pod)
                    .context("sibling IOChaos selected outside runtime membership")?;
                let [drive] = member.shard_ids.as_slice() else {
                    bail!("sibling IOChaos selected a Pod without one runtime shard")
                };
                Ok(drive.clone())
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            selected_drives
                == self
                    .sibling_fault
                    .unavailable_drive_uuids
                    .iter()
                    .cloned()
                    .collect(),
            "sibling IOChaos targets do not match unavailable drive identities"
        );
        let sibling_runtime = chaos_mesh::IoChaosRuntimeContract {
            action: chaos_mesh::IoChaosAction::Fault { errno: 5 },
            methods: vec!["READ".to_string()],
            io_sampling_percent: 100,
            duration_seconds: self.snapshot_duration(&self.sibling_fault.snapshots)?,
        };
        let sibling_contract = chaos_mesh::VolumeTargetEvidenceContract {
            chaos_namespace: &self.chaos_namespace,
            target_namespace: &target_proof.namespace,
            tenant: &target_proof.tenant,
            run_id: &self.identity.run_id,
            scenario: &self.identity.scenario,
            volume_path: &self.shard_before_fault.mount_path,
            path: None,
            exact_pod_names: Some(&sibling_pod_names),
            expected_targets: u32::try_from(tolerance)?,
            candidate_pod_ids: &candidate_pod_ids,
            runtime: &sibling_runtime,
        };
        ensure!(
            self.sibling_fault
                .snapshots
                .iter()
                .map(|snapshot| snapshot.phase.as_str())
                .eq([
                    "siblings-active",
                    "after-replacement-available",
                    "replacement-path-active",
                    "after-replacement-path-removed",
                    "after-replacement-restored",
                ]),
            "sibling controller snapshots have an invalid phase sequence"
        );
        for snapshot in &self.sibling_fault.snapshots {
            ensure!(
                snapshot.observed_at_ms > 0,
                "sibling IOChaos snapshot lacks a timestamp"
            );
            let selected = self.validate_snapshot(snapshot, &sibling_contract)?;
            ensure!(
                selected
                    == self
                        .sibling_fault
                        .selected_targets
                        .iter()
                        .cloned()
                        .collect(),
                "sibling controller target set changed during the causal read proof"
            );
        }
        let exact_path = format!(
            "{}/{}",
            self.shard_before_fault.mount_path.trim_end_matches('/'),
            self.shard_before_fault
                .response
                .inspection
                .selected_part
                .relative_part_path
        );
        ensure!(
            self.replacement_path_fault.exact_container_path == exact_path
                && self.replacement_path_fault.manifest_sha256
                    == sha256_text(&self.replacement_path_fault.manifest_body)
                && self
                    .replacement_path_fault
                    .snapshots
                    .iter()
                    .map(|snapshot| snapshot.phase.as_str())
                    .eq(["replacement-path-active", "after-replacement-blocked",]),
            "replacement path fault does not target the inspected part file"
        );
        let exact_runtime = chaos_mesh::IoChaosRuntimeContract {
            action: chaos_mesh::IoChaosAction::Fault { errno: 5 },
            methods: vec!["READ".to_string()],
            io_sampling_percent: 100,
            duration_seconds: self.snapshot_duration(&self.replacement_path_fault.snapshots)?,
        };
        let replacement_candidate = [format!(
            "{}/{}",
            target_proof.namespace, self.shard_before_fault.target_pod
        )]
        .into_iter()
        .collect();
        let replacement_pod_names = [self.shard_before_fault.target_pod.clone()]
            .into_iter()
            .collect();
        let exact_contract = chaos_mesh::VolumeTargetEvidenceContract {
            chaos_namespace: &self.chaos_namespace,
            target_namespace: &target_proof.namespace,
            tenant: &target_proof.tenant,
            run_id: &self.identity.run_id,
            scenario: &self.identity.scenario,
            volume_path: &self.shard_before_fault.mount_path,
            path: Some(&exact_path),
            exact_pod_names: Some(&replacement_pod_names),
            expected_targets: 1,
            candidate_pod_ids: &replacement_candidate,
            runtime: &exact_runtime,
        };
        for snapshot in &self.replacement_path_fault.snapshots {
            ensure!(
                snapshot.observed_at_ms > 0,
                "replacement path IOChaos snapshot lacks a timestamp"
            );
            let selected = self.validate_snapshot(snapshot, &exact_contract)?;
            ensure!(
                selected.len() == 1
                    && selected.contains(&self.replacement_path_fault.selected_target),
                "replacement path fault selected another runtime target"
            );
        }
        Ok(())
    }

    fn snapshot_duration(&self, snapshots: &[ControllerSnapshotEvidence]) -> Result<u64> {
        let first = snapshots
            .first()
            .context("IOChaos snapshot list is empty")?;
        let snapshot: Value = serde_json::from_str(&first.body)?;
        snapshot
            .get("chaos_status")
            .and_then(|resource| resource.pointer("/spec/duration"))
            .and_then(Value::as_str)
            .and_then(|duration| duration.strip_suffix('s'))
            .and_then(|seconds| seconds.parse().ok())
            .context("IOChaos duration is not an exact second value")
    }

    fn validate_snapshot(
        &self,
        snapshot: &ControllerSnapshotEvidence,
        contract: &chaos_mesh::VolumeTargetEvidenceContract<'_>,
    ) -> Result<BTreeSet<String>> {
        ensure!(
            snapshot.sha256 == sha256_text(&snapshot.body),
            "IOChaos snapshot digest changed"
        );
        let snapshot: Value = serde_json::from_str(&snapshot.body)?;
        ensure!(
            snapshot.get("resource_kind").and_then(Value::as_str) == Some("iochaos"),
            "fresh-volume snapshot is not IOChaos"
        );
        let resource = snapshot
            .get("chaos_status")
            .context("fresh-volume snapshot lacks controller status")?;
        chaos_mesh::validate_fixed_volume_snapshot(resource, contract)
    }

    fn validate_reads(&self, records: &[crate::fault::history::OperationRecord]) -> Result<()> {
        for (trial, phase, succeeds) in [
            (&self.replacement_available, "replacement-available", true),
            (&self.replacement_blocked, "replacement-blocked", false),
            (&self.replacement_restored, "replacement-restored", true),
        ] {
            let matching = records
                .iter()
                .filter(|record| record.id == trial.operation_id)
                .collect::<Vec<_>>();
            let [record] = matching.as_slice() else {
                bail!("fresh-volume causal read operation id is missing or duplicate")
            };
            ensure!(
                trial.phase == phase
                    && record.kind == OperationKind::Get
                    && record.key.as_deref() == Some(self.object_key.as_str())
                    && record.version_id.as_deref() == Some(self.version_id.as_str())
                    && record.started_at_ms == trial.started_at_ms
                    && record.ended_at_ms == trial.ended_at_ms
                    && record.outcome == trial.outcome
                    && record.http_status == trial.http_status
                    && record.value_sha256 == trial.observed_sha256,
                "fresh-volume causal read does not match its versionId GET history record"
            );
            validate_read_result(
                trial.outcome,
                trial.http_status,
                trial.observed_sha256.as_deref(),
                &self.expected_sha256,
                succeeds,
            )?;
        }
        validate_causal_timeline([
            self.shard_before_fault.captured_at_ms,
            self.sibling_fault.active_at_ms,
            self.replacement_available.started_at_ms,
            self.replacement_available.ended_at_ms,
            self.replacement_path_fault.active_at_ms,
            self.replacement_blocked.started_at_ms,
            self.replacement_blocked.ended_at_ms,
            self.replacement_path_fault.delete_started_at_ms,
            self.replacement_path_fault.deleted_at_ms,
            self.replacement_restored.started_at_ms,
            self.replacement_restored.ended_at_ms,
        ])?;
        let siblings = &self.sibling_fault.snapshots;
        let exact = &self.replacement_path_fault.snapshots;
        ensure!(
            self.sibling_fault.active_at_ms <= siblings[0].observed_at_ms
                && siblings[0].observed_at_ms <= self.replacement_available.started_at_ms
                && self.replacement_available.ended_at_ms <= siblings[1].observed_at_ms
                && siblings[1].observed_at_ms <= self.replacement_path_fault.active_at_ms
                && self.replacement_path_fault.active_at_ms <= siblings[2].observed_at_ms
                && siblings[2].observed_at_ms <= exact[0].observed_at_ms
                && exact[0].observed_at_ms <= self.replacement_blocked.started_at_ms
                && self.replacement_blocked.ended_at_ms <= exact[1].observed_at_ms
                && exact[1].observed_at_ms <= self.replacement_path_fault.delete_started_at_ms
                && self.replacement_path_fault.deleted_at_ms <= siblings[3].observed_at_ms
                && siblings[3].observed_at_ms <= self.replacement_restored.started_at_ms
                && self.replacement_restored.ended_at_ms <= siblings[4].observed_at_ms,
            "controller snapshots do not bracket the causal reads"
        );
        ensure!(
            self.replacement_restored.ended_at_ms <= self.sibling_fault.delete_started_at_ms
                && self.sibling_fault.delete_started_at_ms <= self.sibling_fault.deleted_at_ms
                && self.sibling_fault.deleted_at_ms <= self.shard_after_fault.captured_at_ms,
            "fresh-volume cleanup and final shard inspection are out of order"
        );
        Ok(())
    }

    pub(crate) fn validate_chain(
        &self,
        mappings: &[VersionShardMappingObservation],
        replacement: &FreshVolumeReplacementProof,
        summary: &HealSummary,
        progress: &[HealProgressSample],
        records: &[crate::fault::history::OperationRecord],
        original_target_proof_body: &str,
    ) -> Result<()> {
        self.validate(records)?;
        replacement.validate()?;
        let target_proof: TargetProof =
            serde_json::from_str(&self.sibling_fault.target_proof_body)?;
        ensure!(
            self.identity == replacement.identity
                && self.identity == summary.identity
                && self.repaired_drive_uuid == replacement.replacement.rustfs_drive_uuid
                && target_proof.namespace == replacement.replacement.namespace
                && target_proof.tenant == replacement.replacement.tenant
                && mappings.len() == 1
                && self.shard_before_fault.request.deployment_id
                    == replacement.replacement.rustfs_deployment_id
                && self.shard_before_fault.request.drive_uuid
                    == replacement.replacement.rustfs_drive_uuid,
            "fresh-volume evidence identities or mapping cardinality do not match"
        );
        let original_proof: TargetProof = serde_json::from_str(original_target_proof_body)?;
        let original_erasure = original_proof
            .faults
            .first()
            .and_then(|fault| fault.erasure_set.as_ref())
            .context("original target proof lacks erasure membership")?;
        let original_membership = original_erasure
            .membership
            .as_ref()
            .context("original target proof lacks runtime members")?;
        original_membership.validate(&self.shape)?;
        ensure!(
            original_proof.status == crate::fault::preflight::TargetProofStatus::Satisfied
                && original_proof.scenario == self.identity.scenario
                && original_proof.run_id == self.identity.run_id
                && original_proof.namespace == replacement.original.namespace
                && original_proof.tenant == replacement.original.tenant
                && original_erasure.shape.as_ref() == Some(&self.shape)
                && sha256_text(original_target_proof_body) == mappings[0].target_proof_sha256
                && mappings[0].identity == self.identity
                && mappings[0].source == ShardMappingSource::OfflineXl2Inspector,
            "original shard mapping is not bound to its pre-replacement target proof"
        );
        let original = mappings[0]
            .offline_evidence
            .as_ref()
            .context("original shard mapping lacks its offline inspection")?;
        ensure!(
            original.context.volume == replacement.original,
            "original shard inspection belongs to another storage generation"
        );
        validate_replacement_membership(
            original_membership,
            &self.membership,
            &replacement.original,
            &replacement.replacement,
        )?;
        let mapping = mappings[0].validated_mapping(original_membership, &self.shape)?;
        let original_shard: crate::fault::storage_recovery_helper::OfflineXl2InspectResponse =
            serde_json::from_str(&mappings[0].response_body)?;
        validate_rebuilt_shard(
            &original_shard,
            &self.shard_before_fault.response.inspection,
        )?;
        ensure!(
            self.shard_before_fault.target_pod == replacement.replacement.pod
                && self.shard_before_fault.target_pod_uid == replacement.replacement.pod_uid
                && self.shard_before_fault.target_container_id
                    == replacement.replacement.rustfs_container_id
                && self.shard_before_fault.mount_path == replacement.replacement.mount_path
                && replacement.replacement.observed_at_ms <= self.shard_before_fault.captured_at_ms
                && summary.completed_at_ms <= self.shard_before_fault.captured_at_ms,
            "replacement shard inspection is not bound to the adopted and healed storage generation"
        );
        ensure!(
            mapping.bucket == self.identity.bucket
                && mapping.object_key == self.object_key
                && mapping.version_id == self.version_id
                && mapping.object_sha256 == self.expected_sha256
                && mapping
                    .shard_ids
                    .contains(&replacement.original.rustfs_drive_uuid),
            "offline mapping is not bound to the sealed version and original shard"
        );
        summary.validate_progress(
            progress,
            Some((
                &replacement.replacement.rustfs_drive_uuid,
                replacement.replacement.pool_index,
                replacement.replacement.set_index,
            )),
        )
    }

    pub(crate) fn chaos_namespace(&self) -> &str {
        &self.chaos_namespace
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FreshVolumeHostProbeRequest {
    pub target_container_id: String,
    pub target_mount_path: String,
    pub volume_root: PathBuf,
    pub host_proc_root: PathBuf,
    pub host_dev_root: PathBuf,
    pub lock_path: PathBuf,
    pub require_format: bool,
    #[serde(default)]
    pub skip_format_read: bool,
    pub scan_empty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FreshVolumeHostProbeResponse {
    pub observed_at_ms: u64,
    pub scan_started_at_ms: u64,
    pub scan_completed_at_ms: u64,
    pub container_pid: u32,
    pub mount_id: String,
    pub mount_namespace_id: String,
    pub device_major_minor: String,
    pub canonical_device: String,
    pub filesystem_uuid: String,
    pub rustfs_drive_uuid: Option<String>,
    pub lock_device_id: String,
    pub lock_inode: u64,
    pub exhaustive: bool,
    pub data_entries: Vec<String>,
}

fn read_rustfs_drive_uuid(
    format_path: &Path,
    require_format: bool,
    skip_format_read: bool,
) -> Result<Option<String>> {
    ensure!(
        !(require_format && skip_format_read),
        "required format.json cannot be skipped"
    );
    if skip_format_read {
        return Ok(None);
    }
    match fs::read(format_path) {
        Ok(bytes) => {
            let value: Value = serde_json::from_slice(&bytes).context("decode format.json")?;
            Ok(Some(
                value
                    .pointer("/xl/this")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .context("format.json lacks xl.this")?
                    .to_string(),
            ))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !require_format => Ok(None),
        Err(error) => Err(error).context("read target format.json"),
    }
}

/// Closed host probe used by the dedicated helper image. It performs no
/// mutation beyond creating the fixed run lock inode and never executes a
/// caller-supplied command.
pub fn run_fresh_volume_host_probe(
    request: &FreshVolumeHostProbeRequest,
) -> Result<FreshVolumeHostProbeResponse> {
    let scan_started_at_ms = now_ms();
    ensure!(
        request.target_mount_path.starts_with('/')
            && request.target_mount_path != "/"
            && request.volume_root.is_absolute()
            && request.host_proc_root.is_absolute()
            && request.host_dev_root.is_absolute()
            && request.lock_path.is_absolute()
            && !(request.require_format && request.skip_format_read),
        "fresh-volume host probe paths must be absolute and non-root"
    );
    let mut pids = Vec::new();
    if request.target_container_id.is_empty() {
        pids.push(std::process::id());
    } else {
        let container_id = request
            .target_container_id
            .strip_prefix("containerd://")
            .context("fresh-volume host probe supports only containerd identities")?;
        ensure!(
            container_id.len() >= 32 && container_id.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "fresh-volume target container id is malformed"
        );
        for entry in fs::read_dir(&request.host_proc_root).context("read host proc")? {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            let Ok(pid) = name.parse::<u32>() else {
                continue;
            };
            let cgroup = fs::read_to_string(entry.path().join("cgroup")).unwrap_or_default();
            if cgroup.contains(container_id) {
                pids.push(pid);
            }
        }
    }
    ensure!(
        pids.len() == 1,
        "fresh-volume host probe resolved {} target container PIDs",
        pids.len()
    );
    let pid = pids[0];
    let process = request.host_proc_root.join(pid.to_string());
    let mount_namespace_id = fs::read_link(process.join("ns/mnt"))
        .context("read target mount namespace")?
        .to_string_lossy()
        .to_string();
    let mountinfo =
        fs::read_to_string(process.join("mountinfo")).context("read target mountinfo")?;
    let mut matches = mountinfo.lines().filter_map(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        let separator = fields.iter().position(|field| *field == "-")?;
        (fields.get(4).copied() == Some(request.target_mount_path.as_str())).then(|| {
            (
                fields[0].to_string(),
                fields[2].to_string(),
                fields
                    .get(separator + 2)
                    .copied()
                    .unwrap_or_default()
                    .to_string(),
            )
        })
    });
    let (mount_id, device_major_minor, mount_source) = matches
        .next()
        .context("target mount path is absent from target mount namespace")?;
    ensure!(
        matches.next().is_none() && !mount_source.is_empty(),
        "target mount path is duplicate or lacks a mount source"
    );
    let volume_metadata = fs::metadata(&request.volume_root).context("stat helper volume root")?;
    ensure!(
        device_id(&volume_metadata) == device_major_minor,
        "helper volume root is not the target mount device"
    );
    ensure!(
        mount_source.starts_with("/dev/"),
        "fresh-volume Local PV is not backed by a device mount"
    );
    let host_source = request
        .host_dev_root
        .join(mount_source.trim_start_matches("/dev/"));
    let canonical_host_source = fs::canonicalize(&host_source)
        .with_context(|| format!("resolve target mount source {mount_source}"))?;
    let canonical_device = format!(
        "/dev/{}",
        canonical_host_source
            .strip_prefix(&request.host_dev_root)
            .context("canonical target device escaped host /dev")?
            .display()
    );
    let source_rdev = fs::metadata(&canonical_host_source)
        .context("stat canonical target device")?
        .rdev();
    let by_uuid = request.host_dev_root.join("disk/by-uuid");
    let mut filesystem_uuids = fs::read_dir(&by_uuid)
        .with_context(|| format!("read {}", by_uuid.display()))?
        .filter_map(|entry| entry.ok())
        .filter_map(|entry| {
            let resolved = fs::canonicalize(entry.path()).ok()?;
            (fs::metadata(resolved).ok()?.rdev() == source_rdev)
                .then(|| entry.file_name().to_string_lossy().to_string())
        })
        .collect::<Vec<_>>();
    filesystem_uuids.sort();
    filesystem_uuids.dedup();
    let [filesystem_uuid] = filesystem_uuids.as_slice() else {
        bail!("fresh-volume target device does not have exactly one filesystem UUID")
    };
    let rustfs_drive_uuid = read_rustfs_drive_uuid(
        &request.volume_root.join(".rustfs.sys/format.json"),
        request.require_format,
        request.skip_format_read,
    )?;
    let data_entries = if request.scan_empty {
        exhaustive_entries(&request.volume_root)?
    } else {
        Vec::new()
    };
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&request.lock_path)
        .context("open fresh-volume host lock")?;
    let lock_metadata = lock.metadata().context("stat fresh-volume host lock")?;
    let scan_completed_at_ms = now_ms().max(scan_started_at_ms.saturating_add(1));
    Ok(FreshVolumeHostProbeResponse {
        observed_at_ms: scan_completed_at_ms,
        scan_started_at_ms,
        scan_completed_at_ms,
        container_pid: pid,
        mount_id,
        mount_namespace_id,
        device_major_minor,
        canonical_device,
        filesystem_uuid: filesystem_uuid.clone(),
        rustfs_drive_uuid,
        lock_device_id: device_id(&lock_metadata),
        lock_inode: lock_metadata.ino(),
        exhaustive: request.scan_empty,
        data_entries,
    })
}

fn exhaustive_entries(root: &Path) -> Result<Vec<String>> {
    fn visit(root: &Path, directory: &Path, entries: &mut Vec<String>) -> Result<()> {
        for entry in fs::read_dir(directory)
            .with_context(|| format!("scan fresh volume {}", directory.display()))?
        {
            let entry = entry?;
            let file_type = entry.file_type()?;
            ensure!(!file_type.is_symlink(), "fresh volume contains a symlink");
            let relative = entry
                .path()
                .strip_prefix(root)?
                .to_string_lossy()
                .to_string();
            if relative == "lost+found" {
                ensure!(
                    file_type.is_dir(),
                    "fresh volume lost+found entry is not a directory"
                );
                visit(root, &entry.path(), entries)?;
                continue;
            }
            entries.push(relative);
            if file_type.is_dir() {
                visit(root, &entry.path(), entries)?;
            }
        }
        Ok(())
    }
    let mut entries = Vec::new();
    visit(root, root, &mut entries)?;
    entries.sort();
    Ok(entries)
}

fn device_id(metadata: &fs::Metadata) -> String {
    let device = metadata.dev();
    format!("{}:{}", libc::major(device), libc::minor(device))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StaticLocalPvSpec {
    pub name: String,
    pub node: String,
    pub local_path: String,
    pub capacity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticLocalPvFixturePlan {
    initial: Vec<StaticLocalPvSpec>,
    replacement: StaticLocalPvSpec,
}

impl StaticLocalPvFixturePlan {
    pub fn parse(config: &FaultTestConfig) -> Result<Self> {
        let raw = config.storage_local_pvs_json.as_deref().context(
            "RUSTFS_FAULT_TEST_STATIC_LOCAL_PVS_JSON is required for fresh-volume qualification",
        )?;
        let mut volumes = serde_json::from_str::<Vec<StaticLocalPvSpec>>(raw)
            .context("parse RUSTFS_FAULT_TEST_STATIC_LOCAL_PVS_JSON")?;
        ensure!(
            volumes.len() == config.expected_rustfs_pod_count + 1,
            "fresh-volume fixture needs exactly one Local PV per server plus one held-back replacement"
        );
        let replacement = volumes.pop().expect("length checked");
        let plan = Self {
            initial: volumes,
            replacement,
        };
        plan.validate(config)?;
        Ok(plan)
    }

    fn validate(&self, config: &FaultTestConfig) -> Result<()> {
        ensure!(
            config.cluster.tenant_spread_across_hosts,
            "fresh-volume fixture requires one server per host"
        );
        let mut names = BTreeSet::new();
        let mut locations = BTreeSet::new();
        for volume in self.initial.iter().chain([&self.replacement]) {
            validate_dns_name(&volume.name, "Local PV")?;
            validate_dns_name(&volume.node, "Local PV node")?;
            ensure!(
                volume.local_path.starts_with('/')
                    && volume.local_path != "/"
                    && !volume.local_path.contains(['\n', '\r'])
                    && !volume.capacity.trim().is_empty(),
                "Local PV {} has an unsafe path or empty capacity",
                volume.name
            );
            ensure!(
                names.insert(volume.name.as_str())
                    && locations.insert((volume.node.as_str(), volume.local_path.as_str())),
                "fresh-volume fixture reuses a PV name or node/path"
            );
            ensure!(
                config
                    .host_mutation_allowed_nodes
                    .iter()
                    .any(|node| node == &volume.node)
                    && config
                        .host_mutation_allowed_persistent_volumes
                        .iter()
                        .any(|pv| pv == &volume.name),
                "Local PV {} is outside the exact host/PV allowlists",
                volume.name
            );
        }
        ensure!(
            self.initial
                .iter()
                .map(|volume| volume.node.as_str())
                .collect::<BTreeSet<_>>()
                .len()
                == self.initial.len(),
            "fresh-volume fixture requires exactly one initial volume per server/node"
        );
        ensure!(
            self.initial
                .iter()
                .any(|volume| volume.node == self.replacement.node),
            "held-back replacement must target an existing server node"
        );
        Ok(())
    }

    pub fn initial(&self) -> &[StaticLocalPvSpec] {
        &self.initial
    }

    pub fn replacement(&self) -> &StaticLocalPvSpec {
        &self.replacement
    }
}

pub fn static_local_pv_manifest(
    config: &FaultTestConfig,
    run_id: &str,
    volume: &StaticLocalPvSpec,
) -> Result<String> {
    validate_run_label(run_id)?;
    validate_dns_name(&config.cluster.storage_class, "StorageClass")?;
    let manifest = json!({
        "apiVersion": "v1",
        "kind": "PersistentVolume",
        "metadata": {
            "name": volume.name,
            "labels": {
                MANAGED_BY_LABEL: MANAGER,
                RUN_LABEL: run_id,
            },
        },
        "spec": {
            "capacity": {"storage": volume.capacity},
            "volumeMode": "Filesystem",
            "accessModes": ["ReadWriteOnce"],
            "persistentVolumeReclaimPolicy": "Retain",
            "storageClassName": config.cluster.storage_class,
            "local": {"path": volume.local_path},
            "nodeAffinity": {
                "required": {
                    "nodeSelectorTerms": [{
                        "matchExpressions": [{
                            "key": "kubernetes.io/hostname",
                            "operator": "In",
                            "values": [volume.node],
                        }],
                    }],
                },
            },
        },
    });
    serde_yaml_ng::to_string(&manifest).context("encode static Local PV")
}

fn validate_dns_name(value: &str, label: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 253
            && value.split('.').all(|part| {
                !part.is_empty()
                    && !part.starts_with('-')
                    && !part.ends_with('-')
                    && part.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    })
            }),
        "{label} {value:?} is not a DNS-1123 name"
    );
    Ok(())
}

fn validate_run_label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.') }),
        "run id is not safe as a Kubernetes label value"
    );
    Ok(())
}

fn storage_helper_pod_manifest(
    config: &FaultTestConfig,
    run_id: &str,
    name: &str,
    node: &str,
    local_path: &str,
) -> Result<String> {
    validate_run_label(run_id)?;
    validate_dns_name(name, "storage helper Pod")?;
    validate_dns_name(node, "storage helper node")?;
    ensure!(
        local_path.starts_with('/') && local_path != "/",
        "storage helper host path is unsafe"
    );
    let image = config
        .storage_recovery_helper_image
        .as_deref()
        .context("RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE is required for storage qualification")?;
    ensure!(!image.trim().is_empty(), "storage helper image is empty");
    serde_yaml_ng::to_string(&json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": config.cluster.test_namespace,
            "labels": {MANAGED_BY_LABEL: MANAGER, RUN_LABEL: run_id},
        },
        "spec": {
            "restartPolicy": "Never",
            "nodeName": node,
            "hostPID": true,
            "containers": [{
                "name": "storage-helper",
                "image": image,
                "command": ["/usr/local/bin/s3chaos-storage-helper", "hold"],
                "securityContext": {
                    "privileged": true,
                    "allowPrivilegeEscalation": true,
                    "readOnlyRootFilesystem": true,
                },
                "volumeMounts": [
                    {"name": "volume", "mountPath": STORAGE_HELPER_VOLUME_ROOT, "readOnly": true},
                    {"name": "host-proc", "mountPath": "/host/proc", "readOnly": true},
                    {"name": "host-dev", "mountPath": "/host/dev", "readOnly": true},
                    {"name": "host-sys", "mountPath": "/host/sys", "readOnly": true},
                    {"name": "locks", "mountPath": "/var/lock/s3chaos"},
                    {"name": "journal", "mountPath": STORAGE_HELPER_JOURNAL_ROOT},
                ],
            }],
            "volumes": [
                {"name": "volume", "hostPath": {"path": local_path, "type": "Directory"}},
                {"name": "host-proc", "hostPath": {"path": "/proc", "type": "Directory"}},
                {"name": "host-dev", "hostPath": {"path": "/dev", "type": "Directory"}},
                {"name": "host-sys", "hostPath": {"path": "/sys", "type": "Directory"}},
                {"name": "locks", "hostPath": {"path": "/var/lock/s3chaos", "type": "DirectoryOrCreate"}},
                {"name": "journal", "emptyDir": {}},
            ],
        },
    }))
    .context("encode storage helper Pod")
}

fn probe_helper(
    config: &FaultTestConfig,
    helper_pod: &str,
    request: &FreshVolumeHostProbeRequest,
) -> Result<(FreshVolumeHostProbeResponse, String)> {
    let body = serde_json::to_string(request)?;
    let output = Kubectl::new(&config.cluster)
        .namespaced(&config.cluster.test_namespace)
        .command([
            "exec",
            "-i",
            helper_pod,
            "--",
            "/usr/local/bin/s3chaos-storage-helper",
            "probe-fresh-volume",
        ])
        .stdin(body)
        .run_checked()
        .context("run typed fresh-volume host probe")?;
    let response = serde_json::from_str(&output.stdout)
        .context("decode typed fresh-volume host probe response")?;
    Ok((response, output.stdout))
}

fn inspect_replacement_shard_helper(
    config: &FaultTestConfig,
    helper_pod: &str,
    request: &FreshVolumeShardInspectionRequest,
) -> Result<FreshVolumeShardInspectionResponse> {
    let body = serde_json::to_string(request)?;
    let output = Kubectl::new(&config.cluster)
        .namespaced(&config.cluster.test_namespace)
        .command([
            "exec",
            "-i",
            helper_pod,
            "--",
            "/usr/local/bin/s3chaos-storage-helper",
            "inspect-fresh-volume-shard",
        ])
        .stdin(body)
        .run_checked()
        .context("run typed replacement shard inspection")?;
    serde_json::from_str(&output.stdout).context("decode replacement shard inspection response")
}

fn get_raw_json(kubectl: &Kubectl, kind: &str, name: &str) -> Result<String> {
    let output = kubectl
        .command(["get", kind, name, "-o", "json"])
        .run_checked()
        .with_context(|| format!("get {kind} {name}"))?;
    serde_json::from_str::<Value>(&output.stdout)
        .with_context(|| format!("decode {kind} {name}"))?;
    Ok(output.stdout)
}

fn required_json_string(value: &Value, pointer: &str, label: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .with_context(|| format!("{label} is missing at {pointer}"))
}

fn sha256_text(value: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn helper_pod_is_run_owned(value: &Value, run_id: &str) -> bool {
    value
        .pointer("/metadata/labels/app.kubernetes.io~1managed-by")
        .and_then(Value::as_str)
        == Some(MANAGER)
        && value
            .pointer("/metadata/labels/s3chaos.rustfs.com~1run")
            .and_then(Value::as_str)
            == Some(run_id)
}

async fn delete_owned_pvc(
    client: kube::Client,
    namespace: &str,
    name: &str,
    uid: &str,
    timeout: Duration,
) -> Result<()> {
    let api: Api<PersistentVolumeClaim> = Api::namespaced(client, namespace);
    api.delete(
        name,
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid.to_string()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        },
    )
    .await
    .with_context(|| format!("delete owned PVC {namespace}/{name}"))?;
    wait_kube_object_absent(&api, name, timeout).await
}

async fn delete_owned_pv(
    client: kube::Client,
    name: &str,
    uid: &str,
    run_id: &str,
    timeout: Duration,
) -> Result<()> {
    let api: Api<PersistentVolume> = Api::all(client);
    let volume = api
        .get(name)
        .await
        .with_context(|| format!("read owned PV {name}"))?;
    ensure!(
        volume.metadata.uid.as_deref() == Some(uid)
            && volume
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(MANAGED_BY_LABEL))
                .is_some_and(|value| value == MANAGER)
            && volume
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(RUN_LABEL))
                .is_some_and(|value| value == run_id),
        "PV {name} is no longer the run-owned generation"
    );
    api.delete(
        name,
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid.to_string()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        },
    )
    .await
    .with_context(|| format!("delete owned PV {name}"))?;
    wait_cluster_object_absent(&api, name, timeout).await
}

async fn delete_owned_helper_pod(
    client: kube::Client,
    namespace: &str,
    identity: &OwnedHelperPodCleanup,
    run_id: &str,
    timeout: Duration,
) -> Result<()> {
    let api: Api<Pod> = Api::namespaced(client, namespace);
    let Some(pod) = api
        .get_opt(&identity.name)
        .await
        .with_context(|| format!("read helper Pod {namespace}/{}", identity.name))?
    else {
        return Ok(());
    };
    let uid = pod
        .metadata
        .uid
        .as_deref()
        .context("run-owned helper Pod lacks a UID")?;
    ensure!(
        identity
            .uid
            .as_deref()
            .is_none_or(|expected| expected == uid)
            && pod
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(MANAGED_BY_LABEL))
                .is_some_and(|value| value == MANAGER)
            && pod
                .metadata
                .labels
                .as_ref()
                .and_then(|labels| labels.get(RUN_LABEL))
                .is_some_and(|value| value == run_id),
        "helper Pod {namespace}/{} is no longer the exact run-owned generation",
        identity.name
    );
    api.delete(
        &identity.name,
        &DeleteParams {
            preconditions: Some(Preconditions {
                uid: Some(uid.to_string()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        },
    )
    .await
    .with_context(|| format!("delete owned helper Pod {namespace}/{}", identity.name))?;
    wait_kube_object_absent(&api, &identity.name, timeout).await
}

async fn wait_kube_object_absent<K>(api: &Api<K>, name: &str, timeout: Duration) -> Result<()>
where
    K: Clone
        + serde::de::DeserializeOwned
        + kube::Resource<Scope = kube::core::NamespaceResourceScope>
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let deadline = Instant::now() + timeout;
    loop {
        if api.get_opt(name).await?.is_none() {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for {name} deletion"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_cluster_object_absent<K>(api: &Api<K>, name: &str, timeout: Duration) -> Result<()>
where
    K: Clone
        + serde::de::DeserializeOwned
        + kube::Resource<Scope = kube::core::ClusterResourceScope>
        + std::fmt::Debug,
    <K as kube::Resource>::DynamicType: Default,
{
    let deadline = Instant::now() + timeout;
    loop {
        if api.get_opt(name).await?.is_none() {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for {name} deletion"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_rustfs_pods_absent(config: &FaultTestConfig) -> Result<()> {
    let kubectl = Kubectl::new(&config.cluster).namespaced(&config.cluster.test_namespace);
    let selector = format!("rustfs.tenant={}", config.cluster.tenant_name);
    let deadline = Instant::now() + config.cluster.timeout;
    loop {
        let output = kubectl
            .command(["get", "pod", "-l", &selector, "-o", "json"])
            .run_checked()?;
        let value: Value = serde_json::from_str(&output.stdout)?;
        let count = value
            .pointer("/items")
            .and_then(Value::as_array)
            .map_or(usize::MAX, Vec::len);
        if count == 0 {
            return Ok(());
        }
        ensure!(
            Instant::now() < deadline,
            "timed out waiting for every RustFS Pod to terminate"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HealWireReceipt {
    observed_at_ms: u64,
    method: String,
    path: String,
    status: u16,
    request_id: Option<String>,
    response_body: String,
}

pub(crate) fn validate_heal_transcript(
    receipts: &[HealWireReceipt],
    case: StorageRecoveryCase,
) -> Result<()> {
    ensure!(
        receipts.len() >= 2
            && receipts
                .windows(2)
                .all(|pair| { pair[0].observed_at_ms <= pair[1].observed_at_ms })
            && receipts.iter().all(|receipt| {
                receipt.observed_at_ms > 0
                    && (200..300).contains(&receipt.status)
                    && serde_json::from_str::<Value>(&receipt.response_body).is_ok()
            }),
        "fresh-volume transcript lacks ordered successful JSON receipts"
    );
    match case {
        StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement => ensure!(
            receipts
                .iter()
                .all(|receipt| receipt.method == "GET" && receipt.path == REPLACEMENT_STATUS_PATH),
            "automatic replacement transcript contains another admin operation"
        ),
        StorageRecoveryCase::FreshVolumeReplacementAdminDeep => ensure!(
            receipts.iter().all(|receipt| {
                receipt.method == "POST"
                    && receipt
                        .path
                        .strip_prefix(ADMIN_HEAL_PATH)
                        .is_some_and(|bucket| !bucket.is_empty() && !bucket.contains('/'))
            }),
            "admin deep transcript contains another admin operation"
        ),
        _ => bail!("fresh-volume transcript received another storage case"),
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedHealObservation {
    pub observed_at_ms: u64,
    pub observer: HealObserverIdentity,
    pub state: HealProgressState,
    pub scanned: u64,
    pub repaired: u64,
    pub failed: u64,
    pub cluster_definitive: bool,
    pub target_drive_uuid: Option<String>,
    pub pool_index: u32,
    pub set_index: u32,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementStatusEnvelope {
    #[serde(default)]
    cluster: Option<ReplacementClusterStatus>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementClusterStatus {
    definitive: bool,
    #[serde(default)]
    records: Vec<ReplacementTaskRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ReplacementTaskRecord {
    task_id: String,
    state: String,
    generation: Option<String>,
    set_disk_id: Option<String>,
    #[serde(default)]
    target_slots: Vec<String>,
    #[serde(default)]
    scanned: u64,
    #[serde(default)]
    repaired: u64,
    #[serde(default)]
    failed: u64,
    pool_index: Option<u32>,
    set_index: Option<u32>,
}

pub(crate) struct RustfsFreshHealAdapter {
    transport: RustfsAdminTransport,
    case: StorageRecoveryCase,
    pool_index: u32,
    set_index: u32,
    baseline_replacement_tasks: Mutex<BTreeSet<String>>,
    baseline_captured: Mutex<bool>,
    expected_target_drive: Mutex<Option<String>>,
    owned_observer: Mutex<Option<HealObserverIdentity>>,
    admin_heal_path: String,
    admin_start: Mutex<AdminHealStartState>,
    transcript: Mutex<Vec<HealWireReceipt>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
enum AdminHealStartState {
    NotStarted,
    Ambiguous {
        bucket: String,
        prefix: String,
        request_path: String,
        requested_at_ms: u64,
    },
    Owned {
        bucket: String,
        prefix: String,
        request_path: String,
        requested_at_ms: u64,
        acknowledged_at_ms: u64,
        operation_id: String,
        start_time: String,
        reconciled_after_response_loss: bool,
    },
}

impl AdminHealStartState {
    fn ambiguous(bucket: &str, prefix: &str, request_path: &str, requested_at_ms: u64) -> Self {
        Self::Ambiguous {
            bucket: bucket.to_string(),
            prefix: prefix.to_string(),
            request_path: request_path.to_string(),
            requested_at_ms,
        }
    }

    fn own(
        &mut self,
        receipt: &HealWireReceipt,
        status: &HealWireReceipt,
        reconciled_after_response_loss: bool,
    ) -> Result<HealObserverIdentity> {
        let Self::Ambiguous {
            bucket,
            prefix,
            request_path,
            requested_at_ms,
        } = self
        else {
            bail!("admin heal start was not durably registered as ambiguous")
        };
        ensure!(
            receipt.path == *request_path && status.path == *request_path,
            "admin heal reconciliation escaped its exact bucket/prefix path"
        );
        ensure_success(receipt, "start admin deep heal")?;
        ensure_success(status, "reconcile admin deep heal")?;
        let start: Value = serde_json::from_str(&receipt.response_body)
            .context("decode admin heal start response")?;
        let operation_id = start
            .pointer("/clientToken")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .context("admin heal start response lacks clientToken")?
            .to_string();
        let start_time = start
            .pointer("/startTime")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .context("admin heal start response lacks startTime")?
            .to_string();
        let status_body: Value = serde_json::from_str(&status.response_body)
            .context("decode admin heal reconciliation status")?;
        let status_time = status_body
            .pointer("/startTime")
            .and_then(Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .context("admin heal status response lacks startTime")?;
        let parsed_start = time::OffsetDateTime::parse(
            &start_time,
            &time::format_description::well_known::Rfc3339,
        )
        .context("parse admin heal startTime")?;
        let parsed_status = time::OffsetDateTime::parse(
            status_time,
            &time::format_description::well_known::Rfc3339,
        )
        .context("parse admin heal status startTime")?;
        let start_ms = u64::try_from(parsed_start.unix_timestamp_nanos() / 1_000_000)
            .context("admin heal startTime precedes the Unix epoch")?;
        let status_ms = u64::try_from(parsed_status.unix_timestamp_nanos() / 1_000_000)
            .context("admin heal status startTime precedes the Unix epoch")?;
        ensure!(
            start_ms.saturating_add(2_000) >= *requested_at_ms
                && start_ms <= receipt.observed_at_ms.saturating_add(2_000)
                && status_ms.saturating_add(2_000) >= receipt.observed_at_ms
                && status_ms <= status.observed_at_ms.saturating_add(2_000),
            "admin heal response times are outside the registered request/status intervals"
        );
        let observer = HealObserverIdentity::AdminOperation {
            operation_id: operation_id.clone(),
        };
        *self = Self::Owned {
            bucket: bucket.clone(),
            prefix: prefix.clone(),
            request_path: request_path.clone(),
            requested_at_ms: *requested_at_ms,
            acknowledged_at_ms: status.observed_at_ms,
            operation_id,
            start_time,
            reconciled_after_response_loss,
        };
        Ok(observer)
    }
}

impl RustfsFreshHealAdapter {
    pub(crate) fn new(
        endpoint: &str,
        access_key: &str,
        secret_key: &str,
        case: StorageRecoveryCase,
        pool_index: u32,
        set_index: u32,
        bucket: &str,
    ) -> Result<Self> {
        ensure!(
            matches!(
                case,
                StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement
                    | StorageRecoveryCase::FreshVolumeReplacementAdminDeep
            ),
            "fresh-volume heal adapter received another storage case"
        );
        ensure!(
            !bucket.trim().is_empty()
                && bucket.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'.')
                }),
            "fresh-volume heal bucket is invalid"
        );
        Ok(Self {
            transport: RustfsAdminTransport::new(
                endpoint,
                "us-east-1",
                access_key,
                secret_key,
                None,
                "s3chaos-fresh-volume-heal",
            )?,
            case,
            pool_index,
            set_index,
            baseline_replacement_tasks: Mutex::new(BTreeSet::new()),
            baseline_captured: Mutex::new(false),
            expected_target_drive: Mutex::new(None),
            owned_observer: Mutex::new(None),
            admin_heal_path: format!("{ADMIN_HEAL_PATH}{bucket}"),
            admin_start: Mutex::new(AdminHealStartState::NotStarted),
            transcript: Mutex::new(Vec::new()),
        })
    }

    pub(crate) async fn capture_automatic_baseline(&self) -> Result<()> {
        if self.case != StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement {
            return Ok(());
        }
        let receipt = self
            .request(Method::GET, REPLACEMENT_STATUS_PATH, &[], Vec::new(), None)
            .await?;
        let envelope = parse_replacement_status(&receipt)?;
        let cluster = envelope
            .cluster
            .context("replacement baseline status lacks cluster view")?;
        ensure!(
            cluster.definitive,
            "replacement baseline is not cluster-definitive"
        );
        *self.baseline_replacement_tasks.lock().await = cluster
            .records
            .into_iter()
            .map(|record| record.task_id)
            .collect();
        *self.baseline_captured.lock().await = true;
        Ok(())
    }

    pub(crate) async fn set_expected_target_drive(&self, drive_uuid: String) -> Result<()> {
        ensure!(
            !drive_uuid.trim().is_empty(),
            "expected heal drive UUID is empty"
        );
        let mut expected = self.expected_target_drive.lock().await;
        ensure!(
            expected
                .as_ref()
                .is_none_or(|existing| existing == &drive_uuid),
            "expected heal target drive changed"
        );
        *expected = Some(drive_uuid);
        Ok(())
    }

    pub(crate) async fn register_start_intent(&self) -> Result<String> {
        if self.case == StorageRecoveryCase::FreshVolumeReplacementAdminDeep {
            let bucket = self
                .admin_heal_path
                .strip_prefix(ADMIN_HEAL_PATH)
                .context("admin heal path escaped the expected route")?;
            let mut state = self.admin_start.lock().await;
            ensure!(
                matches!(*state, AdminHealStartState::NotStarted),
                "admin heal start intent was already registered"
            );
            *state = AdminHealStartState::ambiguous(bucket, "", &self.admin_heal_path, now_ms());
        }
        self.start_state_json().await
    }

    pub(crate) async fn start_registered(&self) -> Result<()> {
        match self.case {
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement => {
                ensure!(
                    *self.baseline_captured.lock().await,
                    "automatic replacement baseline was not captured before volume replacement"
                );
                ensure!(
                    self.expected_target_drive.lock().await.is_some(),
                    "automatic replacement target drive was not bound after adoption"
                );
                Ok(())
            }
            StorageRecoveryCase::FreshVolumeReplacementAdminDeep => {
                ensure!(
                    matches!(
                        *self.admin_start.lock().await,
                        AdminHealStartState::Ambiguous { .. }
                    ),
                    "admin heal request was not registered before transmission"
                );
                let body = serde_json::to_vec(&json!({
                    "recursive": true,
                    "scanMode": 2,
                    "pool": self.pool_index,
                    "set": self.set_index,
                }))?;
                let first = self
                    .request(
                        Method::POST,
                        &self.admin_heal_path,
                        &[],
                        body.clone(),
                        Some("application/json"),
                    )
                    .await;
                let (receipt, reconciled_after_response_loss) = match first {
                    Ok(receipt) => (receipt, false),
                    Err(response_loss) => (
                        self.request(
                            Method::POST,
                            &self.admin_heal_path,
                            &[],
                            body,
                            Some("application/json"),
                        )
                        .await
                        .with_context(|| {
                            format!(
                                "admin heal start remained ambiguous after exact-scope reconciliation: {response_loss:#}"
                            )
                        })?,
                        true,
                    ),
                };
                ensure_success(&receipt, "start admin deep heal")?;
                let start_body: Value = serde_json::from_str(&receipt.response_body)
                    .context("decode admin heal start response")?;
                let token = start_body
                    .pointer("/clientToken")
                    .and_then(Value::as_str)
                    .filter(|value| !value.trim().is_empty())
                    .context("admin heal start response lacks clientToken")?
                    .to_string();
                let status = self
                    .request(
                        Method::POST,
                        &self.admin_heal_path,
                        &[("clientToken", token.as_str())],
                        Vec::new(),
                        None,
                    )
                    .await
                    .context("reconcile admin heal start with exact-scope status")?;
                let observer = self.admin_start.lock().await.own(
                    &receipt,
                    &status,
                    reconciled_after_response_loss,
                )?;
                *self.owned_observer.lock().await = Some(observer);
                Ok(())
            }
            _ => unreachable!("constructor validates fresh-volume case"),
        }
    }

    pub(crate) async fn observe(&self) -> Result<Option<NormalizedHealObservation>> {
        match self.case {
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement => {
                let receipt = self
                    .request(Method::GET, REPLACEMENT_STATUS_PATH, &[], Vec::new(), None)
                    .await?;
                let envelope = parse_replacement_status(&receipt)?;
                let cluster = envelope
                    .cluster
                    .context("replacement status lacks cluster view")?;
                ensure!(
                    cluster.definitive,
                    "replacement status is not cluster-definitive"
                );
                let baseline = self.baseline_replacement_tasks.lock().await.clone();
                let expected_set = format!("pool_{}_set_{}", self.pool_index, self.set_index);
                let mut matching = cluster.records.into_iter().filter(|record| {
                    !baseline.contains(&record.task_id)
                        && record.set_disk_id.as_deref() == Some(expected_set.as_str())
                        && !record.target_slots.is_empty()
                });
                let Some(record) = matching.next() else {
                    return Ok(None);
                };
                ensure!(
                    matching.next().is_none(),
                    "multiple new replacement tasks target the run-owned slot"
                );
                ensure!(
                    record.generation.as_deref() == Some(record.task_id.as_str()),
                    "automatic replacement task lacks its actual generation identity"
                );
                let expected_drive = self
                    .expected_target_drive
                    .lock()
                    .await
                    .clone()
                    .context("automatic replacement target drive is not bound")?;
                ensure!(
                    record.set_disk_id.as_deref() == Some(expected_set.as_str()),
                    "automatic replacement task targets another erasure set"
                );
                let observer = HealObserverIdentity::ReplacementTask {
                    task_id: record.task_id,
                    generation: record.generation,
                };
                let mut owned = self.owned_observer.lock().await;
                ensure!(
                    owned.as_ref().is_none_or(|existing| existing == &observer),
                    "automatic replacement observer identity changed"
                );
                *owned = Some(observer.clone());
                Ok(Some(NormalizedHealObservation {
                    observed_at_ms: receipt.observed_at_ms,
                    observer,
                    state: normalize_replacement_state(&record.state)?,
                    scanned: record.scanned,
                    repaired: record.repaired,
                    failed: record.failed,
                    cluster_definitive: true,
                    // The v4 record identifies the exact erasure set and
                    // durable generation, while live membership binds the new
                    // drive UUID to that set.
                    target_drive_uuid: Some(expected_drive),
                    pool_index: record.pool_index.unwrap_or(self.pool_index),
                    set_index: record.set_index.unwrap_or(self.set_index),
                }))
            }
            StorageRecoveryCase::FreshVolumeReplacementAdminDeep => {
                let observer = self
                    .owned_observer
                    .lock()
                    .await
                    .clone()
                    .context("admin heal was not started by this attempt")?;
                let HealObserverIdentity::AdminOperation { operation_id } = &observer else {
                    bail!("owned heal identity is not an admin operation")
                };
                let receipt = self
                    .request(
                        Method::POST,
                        &self.admin_heal_path,
                        &[("clientToken", operation_id.as_str())],
                        Vec::new(),
                        None,
                    )
                    .await?;
                ensure_success(&receipt, "poll admin deep heal")?;
                let expected_drive = self
                    .expected_target_drive
                    .lock()
                    .await
                    .clone()
                    .context("admin replacement target drive is not bound")?;
                normalize_admin_status(
                    observer,
                    receipt.observed_at_ms,
                    &receipt.response_body,
                    &expected_drive,
                    self.pool_index,
                    self.set_index,
                )
                .map(Some)
            }
            _ => unreachable!("constructor validates fresh-volume case"),
        }
    }

    pub(crate) async fn cancel_owned(&self) -> Result<OwnedHealCancel> {
        if self.case == StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement {
            return Ok(OwnedHealCancel::NoOwnedHeal);
        }
        let state = self.admin_start.lock().await.clone();
        let AdminHealStartState::Owned { operation_id, .. } = state else {
            return Ok(OwnedHealCancel::NoOwnedHeal);
        };
        ensure!(
            self.owned_observer.lock().await.as_ref()
                == Some(&HealObserverIdentity::AdminOperation {
                    operation_id: operation_id.clone(),
                }),
            "admin heal ownership state and observer identity diverged"
        );
        let receipt = self
            .request(
                Method::POST,
                &self.admin_heal_path,
                &[
                    ("forceStop", "true"),
                    ("clientToken", operation_id.as_str()),
                ],
                Vec::new(),
                None,
            )
            .await?;
        ensure_success(&receipt, "cancel owned admin deep heal")?;
        Ok(OwnedHealCancel::Canceled)
    }

    pub(crate) async fn transcript_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&*self.transcript.lock().await)
            .context("encode fresh-volume heal transcript")
    }

    pub(crate) async fn start_state_json(&self) -> Result<String> {
        serde_json::to_string_pretty(&*self.admin_start.lock().await)
            .context("encode fresh-volume heal start ownership")
    }

    pub(crate) async fn has_ambiguous_start(&self) -> bool {
        matches!(
            *self.admin_start.lock().await,
            AdminHealStartState::Ambiguous { .. }
        )
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<HealWireReceipt> {
        let response = self
            .transport
            .request(method.clone(), path, query, body, content_type)
            .await?;
        let receipt = HealWireReceipt {
            observed_at_ms: now_ms(),
            method: method.as_str().to_string(),
            path: path.to_string(),
            status: response.status,
            request_id: response.request_id,
            response_body: String::from_utf8(response.body)
                .context("RustFS heal response is not UTF-8 JSON")?,
        };
        self.transcript.lock().await.push(receipt.clone());
        Ok(receipt)
    }
}

fn ensure_success(receipt: &HealWireReceipt, operation: &str) -> Result<()> {
    ensure!(
        (200..300).contains(&receipt.status),
        "{operation} failed with status {} request_id={}",
        receipt.status,
        receipt.request_id.as_deref().unwrap_or("unknown")
    );
    Ok(())
}

fn parse_replacement_status(receipt: &HealWireReceipt) -> Result<ReplacementStatusEnvelope> {
    ensure_success(receipt, "read automatic replacement status")?;
    serde_json::from_str(&receipt.response_body)
        .context("decode automatic replacement status response")
}

fn normalize_replacement_state(state: &str) -> Result<HealProgressState> {
    match state {
        "waiting_for_replacement" | "queued" => Ok(HealProgressState::Queued),
        "running" | "cleanup_pending" | "incomplete" => Ok(HealProgressState::Running),
        "completed" => Ok(HealProgressState::Completed),
        "unrecoverable" | "failed" | "unknown" => Ok(HealProgressState::Failed),
        other => bail!("unknown automatic replacement state {other:?}"),
    }
}

fn normalize_admin_status(
    observer: HealObserverIdentity,
    observed_at_ms: u64,
    raw: &str,
    expected_drive: &str,
    pool_index: u32,
    set_index: u32,
) -> Result<NormalizedHealObservation> {
    let value: Value = serde_json::from_str(raw).context("decode admin heal status response")?;
    let state = value
        .pointer("/summary")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/state").and_then(Value::as_str))
        .unwrap_or("running");
    let state = match state.to_ascii_lowercase().as_str() {
        "finished" | "completed" | "success" => HealProgressState::Completed,
        "failed" | "stopped" | "canceled" => HealProgressState::Failed,
        "queued" => HealProgressState::Queued,
        _ => HealProgressState::Running,
    };
    let items = value
        .pointer("/items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let scanned = value
        .pointer("/progress/objectsScanned")
        .and_then(Value::as_u64)
        .unwrap_or(items.len() as u64);
    let failed = value
        .pointer("/progress/objectsFailed")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| {
            items
                .iter()
                .filter(|item| {
                    item.pointer("/detail")
                        .and_then(Value::as_str)
                        .is_some_and(|detail| detail.to_ascii_lowercase().contains("fail"))
                })
                .count() as u64
        });
    let repaired = value
        .pointer("/progress/objectsHealed")
        .and_then(Value::as_u64)
        .unwrap_or_else(|| scanned.saturating_sub(failed));
    Ok(NormalizedHealObservation {
        observed_at_ms,
        observer,
        state,
        scanned,
        repaired,
        failed,
        cluster_definitive: true,
        // The client token came from the exact bucket-scoped start request,
        // whose body selected this pool/set. RustFS status uses default HealOpts
        // and therefore does not echo that scope or individual drive UUIDs.
        target_drive_uuid: Some(expected_drive.to_string()),
        pool_index,
        set_index,
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
        .max(1)
}

/// Concrete driver state is deliberately constructed only after all static
/// fixture gates pass. Later phase methods remain fail-closed until their
/// receipt-producing adapters have populated the required state.
pub(crate) struct FreshVolumeDriver<'a> {
    config: &'a FaultTestConfig,
    collector: &'a ArtifactCollector,
    scenario: &'a FaultScenario,
    plan: &'a StorageRecoveryExecutionPlan,
    run_id: &'a str,
    deadline: RunDeadline,
    fixture: StaticLocalPvFixturePlan,
    state: SyncMutex<FreshVolumeDriverState>,
    helper_guard: Mutex<Option<KubectlStorageRecoveryAttemptGuard>>,
    operator_pause: SyncMutex<Option<crate::fault::backends::lifecycle::OperatorPause>>,
}

struct FreshVolumeDriverState {
    session: Option<FreshVolumeWorkloadSession>,
    owned_context: Option<OwnedStorageContext>,
    membership: Option<ErasureSetMembership>,
    shape: Option<ErasureSetShape>,
    target_pod: Option<String>,
    helper_pod: Option<OwnedHelperPodCleanup>,
    replacement_helper_pod: Option<OwnedHelperPodCleanup>,
    ownership_checkpoint: Option<FreshVolumeOwnershipCheckpoint>,
    abort_before_mutation: Option<StorageRecoveryCleanupProof>,
    replacement_volume: Option<StorageVolumeIdentity>,
    replacement_mount_device_id: Option<String>,
    prepare_receipt: Option<StorageRecoveryOperationReceipt>,
    old_device_absence_sha256: Option<String>,
    heal_adapter: Option<Arc<RustfsFreshHealAdapter>>,
    heal_started_at_ms: Option<u64>,
    heal_progress: Vec<HealProgressSample>,
    heal_summary: Option<HealSummary>,
    causal_read_proof: Option<FreshVolumeReadMatrixEvidence>,
    ordinary_after_replacement_operation_id: Option<String>,
    replacement_proof: Option<FreshVolumeReplacementProof>,
    cleanup_evidence: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnedHelperPodCleanup {
    name: String,
    uid: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HelperPodRole {
    Original,
    Replacement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FreshVolumeOwnershipCheckpoint {
    LeaseAcquired,
    PostAcquireProbePassed,
    HelperSessionBegun,
    InspectionStarted,
    InspectionCompleted,
    VolumeMutationStarted,
}

impl FreshVolumeOwnershipCheckpoint {
    fn permits_abort_before_mutation(self) -> bool {
        self != Self::VolumeMutationStarted
    }

    fn begin_volume_mutation(checkpoint: &mut Option<Self>) -> Result<()> {
        ensure!(
            *checkpoint == Some(Self::InspectionCompleted),
            "fresh-volume mutation must begin from the completed inspection checkpoint"
        );
        *checkpoint = Some(Self::VolumeMutationStarted);
        Ok(())
    }
}

fn prepare_volume_mutation_request<
    Pause,
    Command,
    PauseFn,
    RecordPauseFn,
    CommandFn,
    BeginMutationFn,
>(
    pause_operator: PauseFn,
    record_pause: RecordPauseFn,
    prepare_command: CommandFn,
    begin_mutation: BeginMutationFn,
) -> Result<Command>
where
    PauseFn: FnOnce() -> Result<Pause>,
    RecordPauseFn: FnOnce(Pause) -> Result<()>,
    CommandFn: FnOnce() -> Result<Command>,
    BeginMutationFn: FnOnce() -> Result<()>,
{
    let pause = pause_operator()?;
    record_pause(pause)?;
    let command = prepare_command()?;
    begin_mutation()?;
    Ok(command)
}

impl OwnedHelperPodCleanup {
    fn registered(name: String) -> Self {
        Self { name, uid: None }
    }

    fn record_uid(&mut self, name: &str, uid: String) -> Result<()> {
        ensure!(self.name == name, "helper Pod cleanup identity changed");
        ensure!(!uid.trim().is_empty(), "helper Pod cleanup UID is empty");
        ensure!(
            self.uid.as_ref().is_none_or(|current| current == &uid),
            "helper Pod cleanup UID changed"
        );
        self.uid = Some(uid);
        Ok(())
    }
}

struct FreshVolumeWorkloadSession {
    s3: S3WorkloadClient,
    history: Recorder,
    proof_history: Recorder,
    workload_plan: WorkloadPlan,
    prefilled: Vec<ObjectSpec>,
    sealed: SealedVersion,
    endpoint: String,
    port_forward: Option<PortForwardGuard>,
    events: RunEventRecorder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealedVersion {
    key: String,
    version_id: String,
    sha256: String,
    ordinary_get_operation_id: String,
}

fn single_set_runtime_topology(
    inventory: &RustfsTargetInventory,
    layout: &RustfsErasureLayout,
) -> Result<(ErasureSetShape, ErasureSetMembership)> {
    ensure!(
        inventory.pod_proofs.iter().all(|pod| {
            pod.ready
                && pod.persistent_volume_claims.len() == 1
                && pod.rustfs_container_id.is_some()
        }),
        "storage-recovery topology requires one Ready one-volume server per Pod"
    );
    let shape = ErasureSetShape::from_runtime_single_set(
        inventory.pod_proofs.len(),
        1,
        &layout.total_sets,
        &layout.drives_per_set,
        layout.standard_parity,
    )?;
    let mut members = Vec::new();
    for server in &layout.servers {
        let candidate_pods = inventory
            .pod_proofs
            .iter()
            .map(|pod| pod.name.as_str())
            .collect();
        let pod_name =
            super::runner::targets::runtime_server_pod_name(&server.endpoint, &candidate_pods)?;
        let drives = server
            .drives
            .iter()
            .filter(|drive| drive.pool_index == 0 && drive.set_index == 0)
            .map(|drive| drive.uuid.clone())
            .collect::<Vec<_>>();
        ensure!(
            drives.len() == 1,
            "runtime server does not own one target-set shard"
        );
        members.push(ErasureSetMember {
            pod_name,
            server_endpoint: server.endpoint.clone(),
            shard_ids: drives,
        });
    }
    let membership = ErasureSetMembership::from_runtime(&shape, members)?;
    Ok((shape, membership))
}

fn quorum_bindings(
    inventory: &RustfsTargetInventory,
    membership: &ErasureSetMembership,
    mount_path: &str,
) -> Result<Vec<QuorumVolumeBinding>> {
    inventory
        .pod_proofs
        .iter()
        .map(|pod| {
            let claim = pod
                .persistent_volume_claims
                .as_slice()
                .first()
                .context("runtime Pod has no sole PVC")?;
            let volume = claim
                .persistent_volume
                .as_ref()
                .context("runtime PVC has no bound PV")?;
            let member = membership
                .members
                .iter()
                .find(|member| member.pod_name == pod.name)
                .context("runtime Pod is outside erasure membership")?;
            let [drive_uuid] = member.shard_ids.as_slice() else {
                bail!("runtime Pod does not own exactly one target-set drive")
            };
            Ok(QuorumVolumeBinding {
                pod_name: pod.name.clone(),
                pod_uid: pod.uid.clone(),
                container_id: pod
                    .rustfs_container_id
                    .clone()
                    .context("runtime Pod has no RustFS container identity")?,
                mount_path: mount_path.to_string(),
                persistent_volume_claim: claim.name.clone(),
                persistent_volume: volume.name.clone(),
                drive_uuid: drive_uuid.clone(),
                pool_index: 0,
                set_index: 0,
            })
        })
        .collect()
}

impl<'a> FreshVolumeDriver<'a> {
    pub(crate) fn new(
        config: &'a FaultTestConfig,
        collector: &'a ArtifactCollector,
        scenario: &'a FaultScenario,
        plan: &'a StorageRecoveryExecutionPlan,
        run_id: &'a str,
        deadline: RunDeadline,
    ) -> Result<Self> {
        let fixture = StaticLocalPvFixturePlan::parse(config)?;
        Ok(Self {
            config,
            collector,
            scenario,
            plan,
            run_id,
            deadline,
            fixture,
            state: SyncMutex::new(FreshVolumeDriverState {
                session: None,
                owned_context: None,
                membership: None,
                shape: None,
                target_pod: None,
                helper_pod: None,
                replacement_helper_pod: None,
                ownership_checkpoint: None,
                abort_before_mutation: None,
                replacement_volume: None,
                replacement_mount_device_id: None,
                prepare_receipt: None,
                old_device_absence_sha256: None,
                heal_adapter: None,
                heal_started_at_ms: None,
                heal_progress: Vec::new(),
                heal_summary: None,
                causal_read_proof: None,
                ordinary_after_replacement_operation_id: None,
                replacement_proof: None,
                cleanup_evidence: None,
            }),
            helper_guard: Mutex::new(None),
            operator_pause: SyncMutex::new(None),
        })
    }

    fn register_helper_pod_cleanup(&self, role: HelperPodRole, name: &str) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
        let slot = match role {
            HelperPodRole::Original => &mut state.helper_pod,
            HelperPodRole::Replacement => &mut state.replacement_helper_pod,
        };
        ensure!(
            slot.is_none(),
            "helper Pod cleanup identity was already registered"
        );
        *slot = Some(OwnedHelperPodCleanup::registered(name.to_string()));
        Ok(())
    }

    fn record_helper_pod_uid(&self, role: HelperPodRole, name: &str, uid: String) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
        let slot = match role {
            HelperPodRole::Original => &mut state.helper_pod,
            HelperPodRole::Replacement => &mut state.replacement_helper_pod,
        };
        slot.as_mut()
            .context("helper Pod cleanup identity was not registered before creation")?
            .record_uid(name, uid)
    }

    fn create_owned_helper_pod(
        &self,
        role: HelperPodRole,
        namespaced: &Kubectl,
        name: &str,
        manifest: String,
    ) -> Result<String> {
        self.register_helper_pod_cleanup(role, name)?;
        let result = namespaced
            .command(["create", "-f", "-", "-o", "json"])
            .stdin(manifest)
            .run_checked();
        let raw = match result {
            Ok(output) => output.stdout,
            Err(primary) => {
                if let Ok(body) = get_raw_json(namespaced, "pod", name)
                    && let Ok(value) = serde_json::from_str::<Value>(&body)
                    && helper_pod_is_run_owned(&value, self.run_id)
                    && let Ok(uid) = required_json_string(&value, "/metadata/uid", "helper Pod UID")
                {
                    self.record_helper_pod_uid(role, name, uid)?;
                }
                return Err(primary).context("create run-owned storage helper Pod");
            }
        };
        let value: Value = serde_json::from_str(&raw).context("decode created helper Pod")?;
        ensure!(
            helper_pod_is_run_owned(&value, self.run_id),
            "created helper Pod lacks exact run ownership labels"
        );
        let uid = required_json_string(&value, "/metadata/uid", "created helper Pod UID")?;
        self.record_helper_pod_uid(role, name, uid.clone())?;
        Ok(uid)
    }

    fn prepare_run_artifacts(
        &self,
    ) -> Result<(WorkloadPlan, Recorder, Recorder, RunEventRecorder, String)> {
        let seed = self.config.workload_seed.unwrap_or_else(|| {
            let id = uuid::Uuid::new_v4();
            u64::from_le_bytes(id.as_bytes()[..8].try_into().expect("UUID prefix"))
        });
        let workload_plan = WorkloadPlan::seeded_with_profile(
            seed,
            self.scenario.object_count,
            self.config.workload.concurrency,
            self.config.workload_operation_mix,
            self.config.workload_payload_distribution.clone(),
            self.config.workload_hotspot,
        )?;
        let suffix = self
            .run_id
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(16)
            .collect::<String>()
            .to_ascii_lowercase();
        let bucket = format!("rustfs-fault-{suffix}");
        let case_dir = self.collector.case_dir(self.scenario.case_name);
        let events = RunEventRecorder::create(
            case_dir.join("run-events.jsonl"),
            &self.scenario.name,
            self.run_id,
        )?;
        let history = Recorder::create(
            case_dir.join("history.jsonl"),
            &self.scenario.name,
            self.run_id,
        )?;
        let proof_history = Recorder::create(
            case_dir.join(FRESH_VOLUME_READ_HISTORY_ARTIFACT),
            &self.scenario.name,
            self.run_id,
        )?;
        let execution_plan = crate::fault::plan::ExecutionPlan::StorageRecovery(self.plan.clone());
        let spec = crate::fault::scenarios::scenario_spec(&self.scenario.name)?;
        let run_spec = FaultRunSpec::resolved_execution(
            self.config,
            self.scenario,
            spec,
            &execution_plan,
            &workload_plan,
            self.run_id,
            &bucket,
        );
        self.collector.write_text(
            self.scenario.case_name,
            "run-spec.yaml",
            &run_spec.to_yaml()?,
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            "run-spec.json",
            &run_spec.to_json()?,
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            "run-metadata.json",
            &serde_json::to_string_pretty(&RunMetadata::from_case(
                self.config,
                self.scenario,
                spec,
                &execution_plan,
                &workload_plan,
                self.run_id,
                &bucket,
            ))?,
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-plan.json",
            &serde_json::to_string_pretty(&WorkloadPlanArtifact {
                scenario: &self.scenario.name,
                run_id: self.run_id,
                plan: &workload_plan,
            })?,
        )?;
        events.record(
            "run",
            RunEventStatus::Started,
            "storage-recovery run initialized",
            Some(json!({"bucket": bucket, "case": self.plan.case.as_str()})),
        )?;
        Ok((workload_plan, history, proof_history, events, bucket))
    }

    fn ensure_fixture_pvs_absent(&self) -> Result<()> {
        let kubectl = Kubectl::new(&self.config.cluster);
        for volume in self
            .fixture
            .initial()
            .iter()
            .chain([self.fixture.replacement()])
        {
            let output = kubectl
                .command([
                    "get",
                    "persistentvolume",
                    &volume.name,
                    "--ignore-not-found",
                    "-o",
                    "name",
                ])
                .run_checked()?;
            ensure!(
                output.stdout.trim().is_empty(),
                "run-owned Local PV {} already exists; refuse to reuse or delete a possibly foreign generation",
                volume.name
            );
        }
        Ok(())
    }

    async fn renew_owned_context(&self) -> Result<OwnedStorageContext> {
        let mut context = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .owned_context
            .clone()
            .context("fresh-volume storage ownership was not acquired")?;
        let client =
            crate::framework::kube_client::client_for_context(&self.config.cluster.context).await?;
        let adapter = KubernetesStorageLeaseAdapter::new(
            client,
            &self.config.cluster.test_namespace,
            &context.scope_sha256,
            self.run_id,
            &context.attempt_id,
            Duration::from_secs(self.config.cluster.timeout.as_secs().clamp(5, 300)),
        )?;
        context.exclusive_access.kubernetes_lease = adapter
            .renew(&context.exclusive_access.kubernetes_lease)
            .await?;
        context.validate()?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .owned_context = Some(context.clone());
        Ok(context)
    }

    async fn with_lease_heartbeat<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        tokio::pin!(future);
        let mut renewal = tokio::time::interval(Duration::from_secs(60));
        renewal.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        renewal.tick().await;
        loop {
            tokio::select! {
                result = &mut future => return result,
                _ = renewal.tick() => {
                    self.renew_owned_context().await?;
                }
            }
        }
    }

    async fn current_runtime_topology(
        &self,
    ) -> Result<(
        RustfsTargetInventory,
        RustfsErasureLayout,
        ErasureSetShape,
        ErasureSetMembership,
    )> {
        let endpoint = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .session
            .as_ref()
            .context("fresh-volume workload session was not prepared")?
            .endpoint
            .clone();
        let inventory = rustfs_target_inventory(&self.config.cluster, true, false)?;
        let (access_key, secret_key) = resources::test_credentials();
        let layout = read_erasure_layout(&endpoint, "us-east-1", access_key, secret_key).await?;
        let (shape, membership) = single_set_runtime_topology(&inventory, &layout)?;
        Ok((inventory, layout, shape, membership))
    }

    async fn wait_for_runtime_topology(
        &self,
        phase: &str,
    ) -> Result<(
        RustfsTargetInventory,
        RustfsErasureLayout,
        ErasureSetShape,
        ErasureSetMembership,
    )> {
        let deadline = Instant::now()
            + Duration::from_secs(self.config.cluster.timeout.as_secs().clamp(10, 120));
        loop {
            match self.current_runtime_topology().await {
                Ok(topology) => return Ok(topology),
                Err(error) => {
                    if Instant::now() >= deadline {
                        bail!("{phase} runtime topology did not converge: {error:#}");
                    }
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    fn trial_target_proof(
        &self,
        inventory: &RustfsTargetInventory,
        layout: &RustfsErasureLayout,
        shape: &ErasureSetShape,
        membership: &ErasureSetMembership,
    ) -> Result<TargetProof> {
        let boundary = QuorumVolumeBoundary {
            class: QuorumCaseClass::Payload,
            beyond_read_tolerance: false,
        };
        let target_count = shape.payload_quorum()?.read_tolerance;
        let volume_quorum = QuorumVolumeTargetProof::from_runtime(
            shape,
            membership,
            boundary,
            quorum_bindings(inventory, membership, &self.config.rustfs_volume_path)?,
        )?;
        let mut proof = TargetProof::for_storage_recovery(
            self.config,
            self.scenario,
            self.run_id,
            inventory.pod_proofs.clone(),
            TargetErasureSetProof {
                required: true,
                resolved: true,
                source: Some("rustfs-admin-info".to_string()),
                deployment_id: Some(layout.deployment_id.clone()),
                shape: Some(shape.clone()),
                health: Some(ErasureSetHealth {
                    online_shards: u32::try_from(layout.online_drives)?,
                    offline_shards: u32::try_from(layout.offline_drives)?,
                    unknown_shards: u32::try_from(layout.unknown_drives)?,
                }),
                membership: Some(membership.clone()),
                volume_quorum: Some(volume_quorum),
                observed_at_ms: now_ms(),
                note: "exact-quorum siblings bound to live one-volume RustFS servers".to_string(),
            },
        );
        let fault = proof
            .faults
            .first_mut()
            .context("fresh-volume target proof lacks its quorum fault")?;
        fault.name = format!("{}-exact-quorum-eio", self.scenario.name);
        fault.kind = FaultKind::RustfsVolumeIoError.as_str().to_string();
        fault.backend = FaultBackend::ChaosMeshIoChaos.as_str().to_string();
        fault.selection = format!("exactly {target_count} runtime targets");
        fault.selection_kind = "fixed".to_string();
        fault.selection_value = target_count;
        fault.conflict_domain =
            "one runtime erasure set excluding the replacement drive".to_string();
        Ok(proof)
    }

    fn controller_snapshot(
        guard: &chaos_mesh::ChaosGuard,
        phase: &str,
    ) -> Result<ControllerSnapshotEvidence> {
        let body = serde_json::to_string_pretty(&FaultStatusSnapshot {
            stage: phase.to_string(),
            resource_kind: Some(guard.kind().to_string()),
            resource_name: Some(guard.name().to_string()),
            chaos_status: Some(serde_json::from_str(&guard.json()?)?),
            dm_status: None,
            quorum_dm_status: None,
            lifecycle_status: None,
        })?;
        Ok(ControllerSnapshotEvidence {
            phase: phase.to_string(),
            observed_at_ms: now_ms(),
            sha256: sha256_text(&body),
            body,
        })
    }

    fn write_causal_checkpoint<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        self.collector
            .write_text(
                self.scenario.case_name,
                name,
                &serde_json::to_string_pretty(value)?,
            )
            .map(|_| ())
    }

    async fn inspect_replacement_shard(&self) -> Result<ReplacementShardInspectionEvidence> {
        let (sealed, replacement, helper_pod, target_pod, mount_device_id) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            (
                state
                    .session
                    .as_ref()
                    .context("fresh-volume workload session was not prepared")?
                    .sealed
                    .clone(),
                state
                    .replacement_volume
                    .clone()
                    .context("fresh-volume replacement identity was not observed")?,
                state
                    .replacement_helper_pod
                    .as_ref()
                    .context("replacement helper Pod is absent")?
                    .name
                    .clone(),
                state
                    .target_pod
                    .clone()
                    .context("fresh-volume target Pod is absent")?,
                state
                    .replacement_mount_device_id
                    .clone()
                    .context("replacement mount device identity is absent")?,
            )
        };
        let (inventory, layout, shape, membership) = self.current_runtime_topology().await?;
        let target = inventory
            .pod_proofs
            .iter()
            .find(|pod| pod.name == target_pod)
            .context("replacement target Pod is absent from runtime inventory")?;
        let target_container_id = target
            .rustfs_container_id
            .clone()
            .context("replacement target Pod lacks a RustFS container id")?;
        ensure!(
            layout.deployment_id == replacement.rustfs_deployment_id
                && shape
                    == self
                        .state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                        .shape
                        .clone()
                        .context("fresh-volume runtime shape is absent")?
                && membership
                    == self
                        .state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                        .membership
                        .clone()
                        .context("fresh-volume runtime membership is absent")?
                && target.uid == replacement.pod_uid
                && target_container_id == replacement.rustfs_container_id,
            "replacement runtime target changed before shard inspection"
        );
        let request = FreshVolumeShardInspectionRequest {
            volume_root: PathBuf::from(STORAGE_HELPER_VOLUME_ROOT),
            deployment_id: replacement.rustfs_deployment_id,
            drive_uuid: replacement.rustfs_drive_uuid,
            mount_device_id,
            object_directory: format!("{}/{}", self.scenario_bucket()?, sealed.key),
            bucket: self.scenario_bucket()?,
            object_key: sealed.key,
            object_sha256: sealed.sha256,
            version_id: sealed.version_id,
            selected_part_number: 1,
        };
        let response = inspect_replacement_shard_helper(self.config, &helper_pod, &request)?;
        let captured_at_ms = now_ms();
        let response_sha256 = sha256_text(&serde_json::to_string(&response)?);
        Ok(ReplacementShardInspectionEvidence {
            captured_at_ms,
            helper_pod,
            target_pod,
            target_pod_uid: target.uid.clone(),
            target_container_id,
            mount_path: self.config.rustfs_volume_path.clone(),
            request,
            response_sha256,
            response,
        })
    }

    fn scenario_bucket(&self) -> Result<String> {
        let state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
        Ok(state
            .session
            .as_ref()
            .context("fresh-volume workload session was not prepared")?
            .s3
            .bucket()
            .to_string())
    }

    async fn version_read(&self, phase: &str, expect_success: bool) -> Result<VersionReadEvidence> {
        let (s3, history, sealed) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state
                .session
                .as_ref()
                .context("fresh-volume workload session was not prepared")?;
            (
                session.s3.clone(),
                session.proof_history.clone(),
                session.sealed.clone(),
            )
        };
        let before = history.records().len();
        let result = s3
            .get_object_version_result(&sealed.key, &sealed.version_id, &history)
            .await?;
        let records = history.records();
        let matching = records[before..]
            .iter()
            .filter(|record| {
                record.kind == OperationKind::Get
                    && record.key.as_deref() == Some(sealed.key.as_str())
                    && record.version_id.as_deref() == Some(sealed.version_id.as_str())
            })
            .collect::<Vec<_>>();
        let [record] = matching.as_slice() else {
            bail!("causal versionId GET was not recorded exactly once")
        };
        let observed_sha256 = result
            .body
            .as_deref()
            .map(crate::fault::workload::sha256_hex);
        validate_read_result(
            result.outcome,
            result.http_status,
            observed_sha256.as_deref(),
            &sealed.sha256,
            expect_success,
        )?;
        Ok(VersionReadEvidence {
            phase: phase.to_string(),
            operation_id: record.id.clone(),
            started_at_ms: record.started_at_ms,
            ended_at_ms: record.ended_at_ms,
            outcome: record.outcome,
            http_status: record.http_status,
            observed_sha256,
        })
    }

    async fn run_causal_read_proof(&self) -> Result<FreshVolumeReadMatrixEvidence> {
        let before = self.inspect_replacement_shard().await?;
        self.write_causal_checkpoint("fresh-volume-replacement-shard-before.json", &before)?;
        let (inventory, layout, shape, membership) = self.current_runtime_topology().await?;
        let target_count = usize::try_from(shape.payload_quorum()?.read_tolerance)?;
        let sibling_pods = membership
            .members
            .iter()
            .filter(|member| member.pod_name != before.target_pod)
            .take(target_count)
            .map(|member| member.pod_name.clone())
            .collect::<Vec<_>>();
        ensure!(
            sibling_pods.len() == target_count,
            "runtime membership lacks enough sibling volumes for exact read tolerance"
        );
        let target_proof = self.trial_target_proof(&inventory, &layout, &shape, &membership)?;
        let target_proof_body = serde_json::to_string_pretty(&target_proof)?;
        let causal_fault_duration = self
            .config
            .duration
            .max(self.config.cluster.timeout.saturating_mul(3));
        let sibling_spec = chaos_mesh::IoChaosSpec::eio_on_rustfs_volume(
            &self.config.cluster,
            &self.config.chaos_namespace,
            self.run_id,
            &self.scenario.name,
            &self.config.rustfs_volume_path,
            100,
            causal_fault_duration,
        )?
        .with_read_only()
        .with_exact_pods(sibling_pods.clone())?
        .with_name_suffix("-fresh-siblings");
        self.collector.write_text(
            self.scenario.case_name,
            "fresh-volume-sibling-read-eio.yaml",
            &sibling_spec.manifest(),
        )?;
        let mut sibling_guard = chaos_mesh::apply_iochaos(&self.config.cluster, &sibling_spec)?;
        let attempt = async {
            sibling_guard.wait_active(self.config.cluster.timeout)?;
            let active_at_ms = {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
                state
                    .session
                    .as_ref()
                    .context("fresh-volume workload session was not prepared")?
                    .proof_history
                    .mark_fault_active_now()
            };
            let sibling_active = Self::controller_snapshot(&sibling_guard, "siblings-active")?;
            self.write_causal_checkpoint("fresh-volume-siblings-active.json", &sibling_active)?;
            let active_resource: Value = serde_json::from_str(&sibling_active.body)?;
            let selected = chaos_mesh::validate_fixed_volume_snapshot(
                active_resource
                    .get("chaos_status")
                    .context("sibling IOChaos snapshot lacks controller status")?,
                &chaos_mesh::VolumeTargetEvidenceContract {
                    chaos_namespace: &self.config.chaos_namespace,
                    target_namespace: &self.config.cluster.test_namespace,
                    tenant: &self.config.cluster.tenant_name,
                    run_id: self.run_id,
                    scenario: &self.scenario.name,
                    volume_path: &self.config.rustfs_volume_path,
                    path: None,
                    exact_pod_names: Some(&sibling_pods.iter().cloned().collect()),
                    expected_targets: u32::try_from(target_count)?,
                    candidate_pod_ids: &inventory
                        .pod_proofs
                        .iter()
                        .map(|pod| format!("{}/{}", self.config.cluster.test_namespace, pod.name))
                        .collect(),
                    runtime: &chaos_mesh::IoChaosRuntimeContract {
                        action: chaos_mesh::IoChaosAction::Fault { errno: 5 },
                        methods: vec!["READ".to_string()],
                        io_sampling_percent: 100,
                        duration_seconds: causal_fault_duration.as_secs(),
                    },
                },
            )?;
            let unavailable_drive_uuids = sibling_pods
                .iter()
                .map(|pod| {
                    let member = membership
                        .members
                        .iter()
                        .find(|member| member.pod_name == *pod)
                        .context("sibling Pod is outside runtime membership")?;
                    let [drive] = member.shard_ids.as_slice() else {
                        bail!("sibling Pod does not own exactly one target-set drive")
                    };
                    Ok(drive.clone())
                })
                .collect::<Result<Vec<_>>>()?;
            let replacement_available = self.version_read("replacement-available", true).await?;
            let sibling_after_available =
                Self::controller_snapshot(&sibling_guard, "after-replacement-available")?;
            self.write_causal_checkpoint(
                "fresh-volume-replacement-available.json",
                &json!({
                    "read": replacement_available,
                    "siblingFault": sibling_after_available,
                }),
            )?;
            let exact_path = format!(
                "{}/{}",
                before.mount_path.trim_end_matches('/'),
                before.response.inspection.selected_part.relative_part_path
            );
            ensure!(
                !exact_path.contains(".metadata.bin") && exact_path.ends_with("/part.1"),
                "replacement path fault is not restricted to one part file"
            );
            let exact_spec = chaos_mesh::IoChaosSpec::eio_on_rustfs_volume(
                &self.config.cluster,
                &self.config.chaos_namespace,
                self.run_id,
                &self.scenario.name,
                &self.config.rustfs_volume_path,
                100,
                causal_fault_duration,
            )?
            .with_read_only()
            .with_exact_path(&exact_path)?
            .with_exact_pods(vec![before.target_pod.clone()])?
            .with_name_suffix("-fresh-replacement-part");
            let manifest_body = exact_spec.manifest();
            self.collector.write_text(
                self.scenario.case_name,
                "fresh-volume-replacement-part-read-eio.yaml",
                &manifest_body,
            )?;
            let mut exact_guard = chaos_mesh::apply_iochaos(&self.config.cluster, &exact_spec)?;
            let exact_attempt = async {
                exact_guard.wait_active(self.config.cluster.timeout)?;
                let exact_active_at_ms = now_ms();
                let sibling_during_exact =
                    Self::controller_snapshot(&sibling_guard, "replacement-path-active")?;
                let exact_active =
                    Self::controller_snapshot(&exact_guard, "replacement-path-active")?;
                let exact_resource: Value = serde_json::from_str(&exact_active.body)?;
                let exact_pod_names = [before.target_pod.clone()].into_iter().collect();
                let exact_candidates = [format!(
                    "{}/{}",
                    self.config.cluster.test_namespace, before.target_pod
                )]
                .into_iter()
                .collect();
                let exact_selected = chaos_mesh::validate_fixed_volume_snapshot(
                    exact_resource
                        .get("chaos_status")
                        .context("replacement part IOChaos snapshot lacks controller status")?,
                    &chaos_mesh::VolumeTargetEvidenceContract {
                        chaos_namespace: &self.config.chaos_namespace,
                        target_namespace: &self.config.cluster.test_namespace,
                        tenant: &self.config.cluster.tenant_name,
                        run_id: self.run_id,
                        scenario: &self.scenario.name,
                        volume_path: &self.config.rustfs_volume_path,
                        path: Some(&exact_path),
                        exact_pod_names: Some(&exact_pod_names),
                        expected_targets: 1,
                        candidate_pod_ids: &exact_candidates,
                        runtime: &chaos_mesh::IoChaosRuntimeContract {
                            action: chaos_mesh::IoChaosAction::Fault { errno: 5 },
                            methods: vec!["READ".to_string()],
                            io_sampling_percent: 100,
                            duration_seconds: causal_fault_duration.as_secs(),
                        },
                    },
                )?;
                let exact_selected = exact_selected.into_iter().collect::<Vec<_>>();
                let [exact_selected_target] = exact_selected.as_slice() else {
                    bail!("replacement part IOChaos did not select one controller target")
                };
                self.write_causal_checkpoint(
                    "fresh-volume-replacement-path-active.json",
                    &json!({
                        "siblingFault": sibling_during_exact,
                        "replacementPathFault": exact_active,
                    }),
                )?;
                let replacement_blocked = self.version_read("replacement-blocked", false).await?;
                let exact_after_blocked =
                    Self::controller_snapshot(&exact_guard, "after-replacement-blocked")?;
                self.write_causal_checkpoint(
                    "fresh-volume-replacement-blocked.json",
                    &json!({
                        "read": replacement_blocked,
                        "replacementPathFault": exact_after_blocked,
                    }),
                )?;
                Ok((
                    exact_active_at_ms,
                    exact_selected_target.clone(),
                    sibling_during_exact,
                    exact_active,
                    replacement_blocked,
                    exact_after_blocked,
                ))
            }
            .await;
            let exact_delete_started_at_ms = now_ms();
            let exact_delete_result = exact_guard
                .delete(self.config.cluster.timeout)
                .context("remove replacement part IOChaos");
            let exact_deleted_at_ms = now_ms();
            let exact_cleanup_checkpoint = self.write_causal_checkpoint(
                "fresh-volume-replacement-path-cleanup.json",
                &json!({
                    "deleteStartedAtMs": exact_delete_started_at_ms,
                    "deletedAtMs": exact_deleted_at_ms,
                    "succeeded": exact_delete_result.is_ok(),
                    "error": exact_delete_result.as_ref().err().map(|error| format!("{error:#}")),
                }),
            );
            let exact_delete = match (exact_delete_result, exact_cleanup_checkpoint) {
                (Ok(()), Ok(())) => Ok(()),
                (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
                (Err(delete), Err(checkpoint)) => Err(delete.context(format!(
                    "replacement part cleanup evidence also failed: {checkpoint:#}"
                ))),
            };
            let (
                exact_active_at_ms,
                exact_selected_target,
                sibling_during_exact,
                exact_active,
                replacement_blocked,
                exact_after_blocked,
            ) = match (exact_attempt, exact_delete) {
                (Ok(evidence), Ok(())) => evidence,
                (Err(primary), Ok(())) => return Err(primary),
                (Err(primary), Err(cleanup)) => {
                    return Err(primary.context(format!(
                        "replacement part IOChaos cleanup also failed: {cleanup:#}"
                    )));
                }
                (Ok(_), Err(cleanup)) => return Err(cleanup),
            };
            sibling_guard.ensure_active("after replacement part IOChaos removal")?;
            let sibling_after_exact =
                Self::controller_snapshot(&sibling_guard, "after-replacement-path-removed")?;
            let replacement_restored = self.version_read("replacement-restored", true).await?;
            let sibling_after_restored =
                Self::controller_snapshot(&sibling_guard, "after-replacement-restored")?;
            self.write_causal_checkpoint(
                "fresh-volume-replacement-restored.json",
                &json!({
                    "read": replacement_restored,
                    "siblingFault": sibling_after_restored,
                }),
            )?;
            Ok((
                active_at_ms,
                selected,
                unavailable_drive_uuids,
                vec![
                    sibling_active,
                    sibling_after_available,
                    sibling_during_exact,
                    sibling_after_exact,
                    sibling_after_restored,
                ],
                replacement_available,
                ReplacementPathFaultEvidence {
                    exact_container_path: exact_path,
                    manifest_sha256: sha256_text(&manifest_body),
                    manifest_body,
                    selected_target: exact_selected_target,
                    active_at_ms: exact_active_at_ms,
                    delete_started_at_ms: exact_delete_started_at_ms,
                    deleted_at_ms: exact_deleted_at_ms,
                    snapshots: vec![exact_active, exact_after_blocked],
                },
                replacement_blocked,
                replacement_restored,
            ))
        }
        .await;
        let sibling_delete_started_at_ms = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            state
                .session
                .as_ref()
                .context("fresh-volume workload session was not prepared")?
                .proof_history
                .mark_fault_ended_now()
        };
        let sibling_delete_result = sibling_guard
            .delete(self.config.cluster.timeout)
            .context("remove sibling read IOChaos");
        let sibling_deleted_at_ms = now_ms();
        let sibling_cleanup_checkpoint = self.write_causal_checkpoint(
            "fresh-volume-sibling-fault-cleanup.json",
            &json!({
                "deleteStartedAtMs": sibling_delete_started_at_ms,
                "deletedAtMs": sibling_deleted_at_ms,
                "succeeded": sibling_delete_result.is_ok(),
                "error": sibling_delete_result.as_ref().err().map(|error| format!("{error:#}")),
            }),
        );
        let sibling_delete = match (sibling_delete_result, sibling_cleanup_checkpoint) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
            (Err(delete), Err(checkpoint)) => Err(delete.context(format!(
                "sibling cleanup evidence also failed: {checkpoint:#}"
            ))),
        };
        let (
            active_at_ms,
            selected,
            unavailable_drive_uuids,
            sibling_snapshots,
            replacement_available,
            replacement_path_fault,
            replacement_blocked,
            replacement_restored,
        ) = match (attempt, sibling_delete) {
            (Ok(evidence), Ok(())) => evidence,
            (Err(primary), Ok(())) => return Err(primary),
            (Err(primary), Err(cleanup)) => {
                return Err(
                    primary.context(format!("sibling IOChaos cleanup also failed: {cleanup:#}"))
                );
            }
            (Ok(_), Err(cleanup)) => return Err(cleanup),
        };
        let after = self.inspect_replacement_shard().await?;
        self.write_causal_checkpoint("fresh-volume-replacement-shard-after.json", &after)?;
        let (identity, sealed, ordinary_get_operation_id, records, repaired_drive_uuid) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state
                .session
                .as_ref()
                .context("fresh-volume workload session was not prepared")?;
            (
                state
                    .owned_context
                    .as_ref()
                    .context("fresh-volume ownership is absent")?
                    .identity
                    .clone(),
                session.sealed.clone(),
                state
                    .ordinary_after_replacement_operation_id
                    .clone()
                    .context("ordinary replacement GET identity is absent")?,
                session.proof_history.records(),
                state
                    .replacement_volume
                    .as_ref()
                    .context("fresh-volume replacement identity is absent")?
                    .rustfs_drive_uuid
                    .clone(),
            )
        };
        let proof = FreshVolumeReadMatrixEvidence {
            schema_version: 3,
            identity,
            chaos_namespace: self.config.chaos_namespace.clone(),
            shape,
            membership,
            repaired_drive_uuid,
            object_key: sealed.key,
            version_id: sealed.version_id,
            expected_sha256: sealed.sha256,
            ordinary_get_operation_id,
            shard_before_fault: before,
            shard_after_fault: after,
            sibling_fault: SiblingReadFaultEvidence {
                target_proof_sha256: sha256_text(&target_proof_body),
                target_proof_body,
                selected_targets: selected.into_iter().collect(),
                unavailable_drive_uuids,
                active_at_ms,
                delete_started_at_ms: sibling_delete_started_at_ms,
                deleted_at_ms: sibling_deleted_at_ms,
                snapshots: sibling_snapshots,
            },
            replacement_path_fault,
            replacement_available,
            replacement_blocked,
            replacement_restored,
        };
        proof.validate(&records)?;
        Ok(proof)
    }
}

#[async_trait(?Send)]
impl StorageRecoveryCaseDriver for FreshVolumeDriver<'_> {
    async fn prepare_and_seal_dataset(&self) -> Result<()> {
        ensure!(
            self.config.workload_versioning,
            "fresh-volume qualification requires a versioned workload"
        );
        self.ensure_fixture_pvs_absent()?;
        fixture::reset_tenant_resources(&self.config.cluster)?;
        fixture::apply_tenant_resources(&self.config.cluster)?;
        let kubectl = Kubectl::new(&self.config.cluster);
        for volume in self.fixture.initial() {
            kubectl
                .create_yaml_command(static_local_pv_manifest(self.config, self.run_id, volume)?)
                .run_checked()
                .with_context(|| format!("create run-owned static Local PV {}", volume.name))?;
        }
        wait_for_ready_tenant(&self.config.cluster).await?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;

        let (workload_plan, history, proof_history, events, bucket) =
            self.prepare_run_artifacts()?;
        let (endpoint, mut port_forward) = s3_access(self.config)?;
        ensure_s3_access(&mut port_forward, &self.config.cluster, &endpoint).await?;
        let (access_key, secret_key) = resources::test_credentials();
        let s3 = S3WorkloadClient::new(
            &endpoint,
            &bucket,
            access_key,
            secret_key,
            self.config.request_timeout,
        )
        .await?;
        ensure!(
            s3.create_bucket(&history).await? == OperationOutcome::Ok,
            "fresh-volume workload bucket creation failed"
        );
        ensure!(
            s3.enable_bucket_versioning(&history).await? == OperationOutcome::Ok,
            "fresh-volume workload versioning enablement failed"
        );
        let prefilled = prefill_objects(
            &s3,
            &history,
            self.run_id,
            &workload_plan,
            self.scenario.prefill_count(),
            self.config.prefill_concurrency,
            self.config.workload_directory_marker_percent,
        )
        .await?;
        let object = prefilled
            .iter()
            .find(|object| object.size_bytes > 0)
            .cloned()
            .context("fresh-volume sealed dataset has no payload object")?;
        let write = history
            .records()
            .into_iter()
            .find(|record| {
                record.kind == OperationKind::Put
                    && record.outcome == OperationOutcome::Ok
                    && record.key.as_deref() == Some(object.key.as_str())
                    && record
                        .version_id
                        .as_deref()
                        .is_some_and(|version| version != "null")
                    && record.value_sha256.as_deref() == Some(object.sha256.as_str())
            })
            .context("fresh-volume payload lacks an acknowledged immutable version")?;
        let version_id = write.version_id.context("version identity checked above")?;
        let ordinary = s3
            .get_object_version_result(&object.key, &version_id, &history)
            .await?;
        ensure!(
            ordinary.outcome == OperationOutcome::Ok
                && ordinary.body.as_deref().is_some_and(|body| {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(body)) == object.sha256
                }),
            "ordinary versionId GET did not verify the sealed object before replacement"
        );
        let ordinary_get_operation_id = history
            .records()
            .last()
            .filter(|record| {
                record.kind == OperationKind::Get
                    && record.key.as_deref() == Some(object.key.as_str())
                    && record.version_id.as_deref() == Some(version_id.as_str())
            })
            .map(|record| record.id.clone())
            .context("ordinary sealed version GET was not recorded")?;
        events.record(
            "sealed-version",
            RunEventStatus::Succeeded,
            "version-aware pre-replacement dataset sealed",
            Some(json!({"key": object.key, "versionId": version_id})),
        )?;
        let session = FreshVolumeWorkloadSession {
            s3,
            history,
            proof_history,
            workload_plan,
            prefilled,
            sealed: SealedVersion {
                key: object.key.clone(),
                version_id,
                sha256: object.sha256.clone(),
                ordinary_get_operation_id,
            },
            endpoint,
            port_forward,
            events,
        };
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .session = Some(session);
        Ok(())
    }

    async fn capture_offline_mapping(&self) -> Result<()> {
        let (endpoint, sealed) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state
                .session
                .as_ref()
                .context("fresh-volume workload session was not prepared")?;
            (session.endpoint.clone(), session.sealed.clone())
        };
        let inventory = rustfs_target_inventory(&self.config.cluster, true, false)?;
        ensure!(
            inventory.pod_proofs.len() == self.config.expected_rustfs_pod_count
                && inventory.pod_proofs.iter().all(|pod| {
                    pod.ready
                        && pod.persistent_volume_claims.len() == 1
                        && pod
                            .volume_mounts
                            .iter()
                            .filter(|mount| {
                                mount.container_name == "rustfs"
                                    && mount.mount_path == self.config.rustfs_volume_path
                            })
                            .count()
                            == 1
                }),
            "fresh-volume fixture did not resolve exactly one Local-PV volume per Ready server"
        );
        let replacement = self.fixture.replacement();
        let target_pod = inventory
            .pod_proofs
            .iter()
            .find(|pod| pod.node.as_deref() == Some(replacement.node.as_str()))
            .context("replacement node does not host exactly one RustFS server")?;
        ensure!(
            inventory
                .pod_proofs
                .iter()
                .filter(|pod| pod.node.as_deref() == Some(replacement.node.as_str()))
                .count()
                == 1,
            "replacement node hosts multiple RustFS servers"
        );
        let claim = &target_pod.persistent_volume_claims[0];
        let volume = claim
            .persistent_volume
            .as_ref()
            .context("target PVC is not bound to a Local PV")?;
        let original_spec = self
            .fixture
            .initial()
            .iter()
            .find(|candidate| candidate.node == replacement.node)
            .context("replacement node has no run-owned original PV")?;
        ensure!(
            volume.name == original_spec.name
                && volume.source.as_deref() == Some("local")
                && volume.node.as_deref() == Some(original_spec.node.as_str())
                && volume.device_or_path.as_deref() == Some(original_spec.local_path.as_str())
                && claim.storage_class.as_deref()
                    == Some(self.config.cluster.storage_class.as_str()),
            "target Pod/PVC/PV binding does not match the run-owned original Local PV"
        );
        let target_container_id = target_pod
            .rustfs_container_id
            .as_deref()
            .context("target RustFS container id is absent")?;
        let target_mount = target_pod
            .volume_mounts
            .iter()
            .find(|mount| {
                mount.container_name == "rustfs"
                    && mount.mount_path == self.config.rustfs_volume_path
                    && mount.persistent_volume_claim.as_deref() == Some(claim.name.as_str())
            })
            .context("target RustFS mount is not bound to its sole PVC")?;

        let helper_name = format!(
            "s3chaos-storage-{}",
            self.run_id
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .take(20)
                .collect::<String>()
                .to_ascii_lowercase()
        );
        let namespaced =
            Kubectl::new(&self.config.cluster).namespaced(&self.config.cluster.test_namespace);
        let helper_uid = self.create_owned_helper_pod(
            HelperPodRole::Original,
            &namespaced,
            &helper_name,
            storage_helper_pod_manifest(
                self.config,
                self.run_id,
                &helper_name,
                &replacement.node,
                &original_spec.local_path,
            )?,
        )?;
        namespaced
            .command([
                "wait",
                "--for=condition=Ready",
                &format!("pod/{helper_name}"),
                &format!("--timeout={}s", self.config.cluster.timeout.as_secs()),
            ])
            .run_checked()
            .context("wait for storage helper Pod")?;

        let probe_request = |lock_path: PathBuf| FreshVolumeHostProbeRequest {
            target_container_id: target_container_id.to_string(),
            target_mount_path: self.config.rustfs_volume_path.clone(),
            volume_root: PathBuf::from(STORAGE_HELPER_VOLUME_ROOT),
            host_proc_root: PathBuf::from("/host/proc"),
            host_dev_root: PathBuf::from("/host/dev"),
            lock_path,
            require_format: true,
            skip_format_read: false,
            scan_empty: false,
        };
        let (initial_probe, _) = probe_helper(
            self.config,
            &helper_name,
            &probe_request(PathBuf::from("/var/lock/s3chaos/probe.lock")),
        )?;
        let drive_uuid = initial_probe
            .rustfs_drive_uuid
            .as_deref()
            .context("original Local PV lacks RustFS drive identity")?;
        ensure!(
            self.config
                .host_mutation_allowed_devices
                .iter()
                .any(|device| device == &initial_probe.canonical_device),
            "original Local PV canonical device is outside the exact device allowlist"
        );

        let (access_key, secret_key) = resources::test_credentials();
        let layout = read_erasure_layout(&endpoint, "us-east-1", access_key, secret_key).await?;
        let shape = ErasureSetShape::from_runtime_single_set(
            inventory.pod_proofs.len(),
            1,
            &layout.total_sets,
            &layout.drives_per_set,
            layout.standard_parity,
        )?;
        let mut members = Vec::new();
        for server in &layout.servers {
            let candidate_pods = inventory
                .pod_proofs
                .iter()
                .map(|pod| pod.name.as_str())
                .collect();
            let pod_name =
                super::runner::targets::runtime_server_pod_name(&server.endpoint, &candidate_pods)?;
            let drives = server
                .drives
                .iter()
                .filter(|drive| drive.pool_index == 0 && drive.set_index == 0)
                .map(|drive| drive.uuid.clone())
                .collect::<Vec<_>>();
            ensure!(
                drives.len() == 1,
                "runtime server does not own one shard in the target set"
            );
            members.push(ErasureSetMember {
                pod_name,
                server_endpoint: server.endpoint.clone(),
                shard_ids: drives,
            });
        }
        let membership = ErasureSetMembership::from_runtime(&shape, members)?;
        ensure!(
            membership.members.iter().any(|member| {
                member.pod_name == target_pod.name && member.shard_ids.as_slice() == [drive_uuid]
            }),
            "original host drive identity is not the target Pod's runtime shard"
        );
        let erasure = TargetErasureSetProof {
            required: true,
            resolved: true,
            source: Some("rustfs-admin-info".to_string()),
            deployment_id: Some(layout.deployment_id.clone()),
            shape: Some(shape.clone()),
            health: Some(ErasureSetHealth {
                online_shards: u32::try_from(layout.online_drives)?,
                offline_shards: u32::try_from(layout.offline_drives)?,
                unknown_shards: u32::try_from(layout.unknown_drives)?,
            }),
            membership: Some(membership.clone()),
            volume_quorum: None,
            observed_at_ms: now_ms(),
            note: "single-set runtime membership bound to the run-owned Local PV fixture"
                .to_string(),
        };
        let target_proof = TargetProof::for_storage_recovery(
            self.config,
            self.scenario,
            self.run_id,
            inventory.pod_proofs.clone(),
            erasure,
        );
        let target_proof_body = serde_json::to_string_pretty(&target_proof)?;
        let target_proof_sha256 = sha256_text(&target_proof_body);
        self.collector.write_text(
            self.scenario.case_name,
            "target-proof.json",
            &target_proof_body,
        )?;
        let preflight = PreflightSummary::single_run(
            self.config,
            &self.scenario.name,
            self.run_id,
            vec![PreflightPhase::new(
                "target-proof",
                vec![
                    target_proof.preflight_check(),
                    PreflightCheck::passed(
                        "static_local_pv_fixture",
                        "all initial and replacement Local PVs are run-owned and exact-allowlisted",
                        ResponsibilityDomain::Harness,
                    ),
                ],
            )],
        );
        self.collector.write_text(
            self.scenario.case_name,
            "preflight-summary.json",
            &serde_json::to_string_pretty(&preflight)?,
        )?;

        let tenant_raw = get_raw_json(&namespaced, "tenant", &self.config.cluster.tenant_name)?;
        let pod_raw = get_raw_json(&namespaced, "pod", &target_pod.name)?;
        let pvc_raw = get_raw_json(&namespaced, "pvc", &claim.name)?;
        let cluster = Kubectl::new(&self.config.cluster);
        let pv_raw = get_raw_json(&cluster, "pv", &volume.name)?;
        let node_raw = get_raw_json(&cluster, "node", &replacement.node)?;
        let helper_raw = get_raw_json(&namespaced, "pod", &helper_name)?;
        let tenant_json: Value = serde_json::from_str(&tenant_raw)?;
        let pod_json: Value = serde_json::from_str(&pod_raw)?;
        let pvc_json: Value = serde_json::from_str(&pvc_raw)?;
        let pv_json: Value = serde_json::from_str(&pv_raw)?;
        let node_json: Value = serde_json::from_str(&node_raw)?;
        let helper_json: Value = serde_json::from_str(&helper_raw)?;
        let resource_versions = KubernetesResourceVersions {
            tenant: required_json_string(
                &tenant_json,
                "/metadata/resourceVersion",
                "Tenant resourceVersion",
            )?,
            pod: required_json_string(
                &pod_json,
                "/metadata/resourceVersion",
                "Pod resourceVersion",
            )?,
            persistent_volume_claim: required_json_string(
                &pvc_json,
                "/metadata/resourceVersion",
                "PVC resourceVersion",
            )?,
            persistent_volume: required_json_string(
                &pv_json,
                "/metadata/resourceVersion",
                "PV resourceVersion",
            )?,
            node: required_json_string(
                &node_json,
                "/metadata/resourceVersion",
                "node resourceVersion",
            )?,
            helper_pod: required_json_string(
                &helper_json,
                "/metadata/resourceVersion",
                "helper Pod resourceVersion",
            )?,
        };
        ensure!(
            required_json_string(&helper_json, "/metadata/uid", "helper Pod UID")? == helper_uid,
            "helper Pod UID changed after creation"
        );
        let tenant_uid = required_json_string(&tenant_json, "/metadata/uid", "Tenant UID")?;
        let node_uid = required_json_string(&node_json, "/metadata/uid", "node UID")?;
        let observed_at_ms = now_ms();
        let mut original = StorageVolumeIdentity {
            target_proof_sha256,
            host_storage_proof_sha256: sha256_text(&serde_json::to_string(&initial_probe)?),
            rustfs_deployment_id: layout.deployment_id,
            namespace: self.config.cluster.test_namespace.clone(),
            tenant: self.config.cluster.tenant_name.clone(),
            pod: target_pod.name.clone(),
            pod_uid: target_pod.uid.clone(),
            rustfs_container_id: target_container_id.to_string(),
            volume_name: target_mount.volume_name.clone(),
            persistent_volume_claim: claim.name.clone(),
            persistent_volume_claim_uid: claim.uid.clone(),
            persistent_volume: volume.name.clone(),
            persistent_volume_uid: volume.uid.clone(),
            node: replacement.node.clone(),
            node_uid,
            storage_class: self.config.cluster.storage_class.clone(),
            local_volume_path: original_spec.local_path.clone(),
            mount_path: self.config.rustfs_volume_path.clone(),
            canonical_device: initial_probe.canonical_device.clone(),
            target_mount_namespace_id: initial_probe.mount_namespace_id.clone(),
            filesystem_uuid: initial_probe.filesystem_uuid.clone(),
            rustfs_drive_uuid: drive_uuid.to_string(),
            pool_index: 0,
            set_index: 0,
            observed_at_ms,
        };
        original.validate()?;
        let scope_sha256 = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            for value in [
                self.config.cluster.context.as_str(),
                original.namespace.as_str(),
                tenant_uid.as_str(),
                original.persistent_volume_uid.as_str(),
                original.node_uid.as_str(),
                original.canonical_device.as_str(),
                original.filesystem_uuid.as_str(),
            ] {
                hasher.update(value.as_bytes());
                hasher.update([0]);
            }
            hex::encode(hasher.finalize())
        };
        let lock_path = PathBuf::from(format!("/var/lock/s3chaos/storage-{scope_sha256}.lock"));
        let (ownership_probe, ownership_probe_body) =
            probe_helper(self.config, &helper_name, &probe_request(lock_path.clone()))?;
        ensure!(
            ownership_probe.device_major_minor == initial_probe.device_major_minor
                && ownership_probe.canonical_device == initial_probe.canonical_device
                && ownership_probe.filesystem_uuid == initial_probe.filesystem_uuid
                && ownership_probe.rustfs_drive_uuid == initial_probe.rustfs_drive_uuid
                && ownership_probe.mount_namespace_id == initial_probe.mount_namespace_id,
            "original host generation drifted before storage ownership acquisition"
        );
        original.observed_at_ms = ownership_probe.observed_at_ms;
        original.host_storage_proof_sha256 = sha256_text(&ownership_probe_body);
        let identity = StorageRecoveryArtifactIdentity {
            run_id: self.run_id.to_string(),
            scenario: self.scenario.name.clone(),
            case_name: self.scenario.case_name.to_string(),
            bucket: {
                let state = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
                state
                    .session
                    .as_ref()
                    .expect("session checked above")
                    .s3
                    .bucket()
                    .to_string()
            },
        };
        let owned_drive_uuid = ownership_probe
            .rustfs_drive_uuid
            .clone()
            .context("original drive disappeared")?;
        let host_node_uid = original.node_uid.clone();
        let client =
            crate::framework::kube_client::client_for_context(&self.config.cluster.context).await?;
        let lease_adapter = KubernetesStorageLeaseAdapter::new(
            client,
            &self.config.cluster.test_namespace,
            &scope_sha256,
            self.run_id,
            "fresh-volume",
            std::time::Duration::from_secs(self.config.cluster.timeout.as_secs().clamp(5, 300)),
        )?;
        let lease = lease_adapter.acquire().await?;
        let context = OwnedStorageContext {
            identity,
            case: self.plan.case,
            attempt_id: "fresh-volume".to_string(),
            cluster_context: self.config.cluster.context.clone(),
            tenant_uid,
            scope_sha256: scope_sha256.clone(),
            volume: original,
            resource_versions,
            host_generation: HostGenerationIdentity {
                mount_id: ownership_probe.mount_id.clone(),
                mount_namespace_id: ownership_probe.mount_namespace_id.clone(),
                device_major_minor: ownership_probe.device_major_minor.clone(),
                device_mapper_uuid: None,
                device_mapper_table_sha256: None,
                filesystem_uuid: ownership_probe.filesystem_uuid.clone(),
                rustfs_drive_uuid: owned_drive_uuid,
            },
            exclusive_access: StorageRecoveryExclusiveAccess {
                kubernetes_lease: lease,
                host_flock: HostFlockProof {
                    node: replacement.node.clone(),
                    node_uid: host_node_uid,
                    path: lock_path.to_string_lossy().to_string(),
                    device_id: ownership_probe.lock_device_id.clone(),
                    inode: ownership_probe.lock_inode,
                    scope_sha256: scope_sha256.clone(),
                    acquired_at_ms: now_ms(),
                },
            },
            helper_pod_name: helper_name.clone(),
            helper_pod_uid: helper_uid,
            observed_at_ms: now_ms(),
        };
        // The acquired Lease and exact helper UID become cleanup obligations
        // before any post-acquisition probe or helper session can fail.
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            state.owned_context = Some(context.clone());
            state.membership = Some(membership.clone());
            state.shape = Some(shape.clone());
            state.target_pod = Some(target_pod.name.clone());
            state.ownership_checkpoint = Some(FreshVolumeOwnershipCheckpoint::LeaseAcquired);
        }
        context.validate()?;
        self.collector.write_text(
            self.scenario.case_name,
            "fresh-volume-owned-context.json",
            &serde_json::to_string_pretty(&context)?,
        )?;
        let (post_acquire_probe, _) =
            probe_helper(self.config, &helper_name, &probe_request(lock_path))?;
        ensure!(
            post_acquire_probe.mount_id == ownership_probe.mount_id
                && post_acquire_probe.mount_namespace_id == ownership_probe.mount_namespace_id
                && post_acquire_probe.device_major_minor == ownership_probe.device_major_minor
                && post_acquire_probe.canonical_device == ownership_probe.canonical_device
                && post_acquire_probe.filesystem_uuid == ownership_probe.filesystem_uuid
                && post_acquire_probe.rustfs_drive_uuid == ownership_probe.rustfs_drive_uuid
                && post_acquire_probe.lock_device_id == ownership_probe.lock_device_id
                && post_acquire_probe.lock_inode == ownership_probe.lock_inode,
            "original host generation drifted after storage ownership acquisition"
        );
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .ownership_checkpoint = Some(FreshVolumeOwnershipCheckpoint::PostAcquireProbePassed);
        let helper = KubectlStorageRecoveryHostAdapter::new(
            &self.config.cluster,
            &self.config.cluster.test_namespace,
            &helper_name,
            self.config.cluster.timeout,
        )?;
        let guard = helper.begin_attempt(&context).await?;
        *self.helper_guard.lock().await = Some(guard);
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .ownership_checkpoint = Some(FreshVolumeOwnershipCheckpoint::HelperSessionBegun);
        let operation = StorageRecoveryHostOperation::InspectXlMeta {
            object_directory: format!("{}/{}", context.identity.bucket, sealed.key),
            bucket: context.identity.bucket.clone(),
            object_key: sealed.key.clone(),
            object_sha256: sealed.sha256.clone(),
            version_id: sealed.version_id.clone(),
            selected_part_number: 1,
            expected_mount_device_id: context.host_generation.device_major_minor.clone(),
            expected_drive_uuid: context.volume.rustfs_drive_uuid.clone(),
        };
        let mut guard = self
            .helper_guard
            .lock()
            .await
            .take()
            .context("original-volume helper session disappeared before inspection")?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .ownership_checkpoint = Some(FreshVolumeOwnershipCheckpoint::InspectionStarted);
        let inspection = guard.execute(&context, &operation).await;
        *self.helper_guard.lock().await = Some(guard);
        let receipt = inspection?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .ownership_checkpoint = Some(FreshVolumeOwnershipCheckpoint::InspectionCompleted);
        let completed_at_ms = receipt.completed_at_ms;
        let observation = VersionShardMappingObservation {
            schema_version: crate::fault::storage_recovery::STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: context.identity.clone(),
            observation_id: uuid::Uuid::new_v4().to_string(),
            source: ShardMappingSource::OfflineXl2Inspector,
            api_revision: crate::fault::xl2_inspector::OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
            response_sha256: receipt.response_sha256.clone(),
            response_body: receipt.response_body.clone(),
            offline_evidence: Some(Box::new(OfflineVersionShardMappingEvidence {
                context: Box::new(context.clone()),
                inspection_receipt: Box::new(receipt),
            })),
            target_proof_sha256: context.volume.target_proof_sha256.clone(),
            observed_at_ms: completed_at_ms,
        };
        observation.validated_mapping(&membership, &shape)?;
        self.collector.write_text(
            self.scenario.case_name,
            VERSION_SHARD_MAPPING_ARTIFACT,
            &serde_json::to_string_pretty(&vec![observation])?,
        )?;
        let heal_adapter = Arc::new(RustfsFreshHealAdapter::new(
            &endpoint,
            access_key,
            secret_key,
            self.plan.case,
            0,
            0,
            &context.identity.bucket,
        )?);
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            state.heal_adapter = Some(heal_adapter.clone());
        }
        // Store every cleanup handle before the first admin request. If the
        // endpoint is absent or malformed, the workflow can still persist the
        // raw transcript and tear down only this attempt's resources.
        heal_adapter.capture_automatic_baseline().await?;
        Ok(())
    }
    async fn replace_volume(&self) -> Result<()> {
        let original = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .owned_context
            .as_ref()
            .context("fresh-volume original volume ownership is absent")?
            .volume
            .clone();
        let replacement_spec = self.fixture.replacement().clone();
        let statefulset = lifecycle::observe_statefulset_topology(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
        )?
        .statefulset
        .identity;
        statefulset.require_cold_restart_eligible()?;
        let deployment = self.config.operator_deployment.as_deref().context(
            "RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT is required for fresh-volume qualification",
        )?;
        let scale_down =
            prepare_volume_mutation_request(
                || {
                    lifecycle::OperatorPause::pause(
                        &self.config.cluster,
                        deployment,
                        &self.config.operator_image_match,
                        self.run_id,
                        self.config.cluster.timeout,
                    )
                },
                |pause| {
                    *self.operator_pause.lock().map_err(|_| {
                        anyhow::anyhow!("fresh-volume operator pause lock poisoned")
                    })? = Some(pause);
                    Ok(())
                },
                || {
                    lifecycle::kube::scale_statefulset_command(
                        &self.config.cluster,
                        &statefulset.name,
                        0,
                    )
                },
                || {
                    let mut state = self
                        .state
                        .lock()
                        .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
                    FreshVolumeOwnershipCheckpoint::begin_volume_mutation(
                        &mut state.ownership_checkpoint,
                    )
                },
            )?;
        scale_down
            .run_checked()
            .context("scale owned RustFS StatefulSet to zero")?;
        wait_rustfs_pods_absent(self.config).await?;

        let client =
            crate::framework::kube_client::client_for_context(&self.config.cluster.context).await?;
        delete_owned_pvc(
            client.clone(),
            &original.namespace,
            &original.persistent_volume_claim,
            &original.persistent_volume_claim_uid,
            self.config.cluster.timeout,
        )
        .await?;
        delete_owned_pv(
            client,
            &original.persistent_volume,
            &original.persistent_volume_uid,
            self.run_id,
            self.config.cluster.timeout,
        )
        .await?;

        let cluster_kubectl = Kubectl::new(&self.config.cluster);
        cluster_kubectl
            .create_yaml_command(static_local_pv_manifest(
                self.config,
                self.run_id,
                &replacement_spec,
            )?)
            .run_checked()
            .context("create run-owned replacement Local PV")?;
        let replacement_pv_raw = get_raw_json(&cluster_kubectl, "pv", &replacement_spec.name)?;
        let replacement_pv_json: Value = serde_json::from_str(&replacement_pv_raw)?;
        let replacement_pv_uid =
            required_json_string(&replacement_pv_json, "/metadata/uid", "replacement PV UID")?;

        let helper_name = format!(
            "s3chaos-storage-new-{}",
            self.run_id
                .chars()
                .filter(|character| character.is_ascii_alphanumeric())
                .take(16)
                .collect::<String>()
                .to_ascii_lowercase()
        );
        let namespaced =
            Kubectl::new(&self.config.cluster).namespaced(&self.config.cluster.test_namespace);
        self.create_owned_helper_pod(
            HelperPodRole::Replacement,
            &namespaced,
            &helper_name,
            storage_helper_pod_manifest(
                self.config,
                self.run_id,
                &helper_name,
                &replacement_spec.node,
                &replacement_spec.local_path,
            )?,
        )?;
        namespaced
            .command([
                "wait",
                "--for=condition=Ready",
                &format!("pod/{helper_name}"),
                &format!("--timeout={}s", self.config.cluster.timeout.as_secs()),
            ])
            .run_checked()
            .context("wait for replacement-volume helper Pod")?;
        let empty_lock = PathBuf::from(format!(
            "/var/lock/s3chaos/fresh-empty-{}.lock",
            self.run_id
        ));
        let empty_request = FreshVolumeHostProbeRequest {
            target_container_id: String::new(),
            target_mount_path: STORAGE_HELPER_VOLUME_ROOT.to_string(),
            volume_root: PathBuf::from(STORAGE_HELPER_VOLUME_ROOT),
            host_proc_root: PathBuf::from("/host/proc"),
            host_dev_root: PathBuf::from("/host/dev"),
            lock_path: empty_lock,
            require_format: false,
            skip_format_read: false,
            scan_empty: true,
        };
        let (empty_probe, _empty_probe_body) =
            probe_helper(self.config, &helper_name, &empty_request)?;
        ensure!(
            empty_probe.exhaustive
                && empty_probe.data_entries.is_empty()
                && empty_probe.rustfs_drive_uuid.is_none(),
            "replacement Local PV was not exhaustively empty before RustFS adoption"
        );
        ensure!(
            self.config
                .host_mutation_allowed_devices
                .iter()
                .any(|device| device == &empty_probe.canonical_device)
                && empty_probe.canonical_device != original.canonical_device
                && empty_probe.filesystem_uuid != original.filesystem_uuid,
            "replacement Local PV device is not a distinct allowlisted storage generation"
        );
        let empty_response = EmptyVolumeScanResponse {
            persistent_volume_uid: replacement_pv_uid.clone(),
            canonical_device: empty_probe.canonical_device.clone(),
            filesystem_uuid: empty_probe.filesystem_uuid.clone(),
            rustfs_process_can_access_volume: false,
            scan_started_at_ms: empty_probe.scan_started_at_ms,
            scan_completed_at_ms: empty_probe.scan_completed_at_ms,
            exhaustive: empty_probe.exhaustive,
            data_entries: empty_probe.data_entries.clone(),
        };
        let empty_response_body = serde_json::to_string(&empty_response)?;

        lifecycle::kube::scale_statefulset_command(
            &self.config.cluster,
            &statefulset.name,
            u32::try_from(self.config.expected_rustfs_pod_count)?,
        )?
        .run_checked()
        .context("scale owned RustFS StatefulSet back to its fixture size")?;
        wait_for_ready_tenant(&self.config.cluster).await?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;

        // Scaling every Pod down invalidates the Service port-forward's
        // selected Pod. Keep the same endpoint for the workload and heal clients.
        let (endpoint, mut port_forward) = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state
                .session
                .as_mut()
                .context("fresh-volume workload session was not prepared")?;
            (session.endpoint.clone(), session.port_forward.take())
        };
        let access = async {
            if port_forward.is_some() {
                let local_port = endpoint
                    .rsplit_once(':')
                    .and_then(|(_, port)| port.parse::<u16>().ok())
                    .context("parse local S3 port-forward endpoint")?;
                let spec = PortForwardSpec::tenant_io_with_local_port(
                    &self.config.cluster.test_namespace,
                    &self.config.cluster.tenant_name,
                    local_port,
                );
                replace_port_forward(&mut port_forward, || {
                    spec.start_with_temp_log(&Kubectl::new(&self.config.cluster))
                })?;
            }
            ensure_s3_access(&mut port_forward, &self.config.cluster, &endpoint).await
        }
        .await;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .session
            .as_mut()
            .context("fresh-volume workload session disappeared during access recovery")?
            .port_forward = port_forward;
        access.context("restore S3 access after fresh-volume Pod replacement")?;

        let (inventory, layout, shape, membership) = self
            .wait_for_runtime_topology("replacement adoption")
            .await?;
        ensure!(
            layout.deployment_id == original.rustfs_deployment_id,
            "RustFS deployment identity changed during fresh-volume adoption"
        );
        let matches = inventory
            .pod_proofs
            .iter()
            .filter(|pod| pod.node.as_deref() == Some(replacement_spec.node.as_str()))
            .collect::<Vec<_>>();
        let [target_pod] = matches.as_slice() else {
            bail!("replacement node does not host exactly one adopted RustFS server")
        };
        let [claim] = target_pod.persistent_volume_claims.as_slice() else {
            bail!("replacement RustFS server does not own exactly one PVC")
        };
        let volume = claim
            .persistent_volume
            .as_ref()
            .context("replacement PVC is not bound to a Local PV")?;
        ensure!(
            volume.name == replacement_spec.name
                && volume.uid == replacement_pv_uid
                && volume.source.as_deref() == Some("local")
                && volume.node.as_deref() == Some(replacement_spec.node.as_str())
                && volume.device_or_path.as_deref() == Some(replacement_spec.local_path.as_str()),
            "adopted Pod/PVC/PV does not match the run-owned replacement Local PV"
        );
        let target_mount = target_pod
            .volume_mounts
            .iter()
            .find(|mount| {
                mount.container_name == "rustfs"
                    && mount.mount_path == self.config.rustfs_volume_path
                    && mount.persistent_volume_claim.as_deref() == Some(claim.name.as_str())
            })
            .context("replacement RustFS volume mount is not uniquely bound")?;
        let adopted_request = FreshVolumeHostProbeRequest {
            target_container_id: target_pod
                .rustfs_container_id
                .clone()
                .context("replacement RustFS container identity is absent")?,
            target_mount_path: self.config.rustfs_volume_path.clone(),
            volume_root: PathBuf::from(STORAGE_HELPER_VOLUME_ROOT),
            host_proc_root: PathBuf::from("/host/proc"),
            host_dev_root: PathBuf::from("/host/dev"),
            lock_path: PathBuf::from(format!(
                "/var/lock/s3chaos/fresh-adopted-{}.lock",
                self.run_id
            )),
            require_format: true,
            skip_format_read: false,
            scan_empty: false,
        };
        let (adopted_probe, adopted_probe_body) =
            probe_helper(self.config, &helper_name, &adopted_request)?;
        let replacement_drive = adopted_probe
            .rustfs_drive_uuid
            .clone()
            .context("adopted replacement lacks a RustFS drive UUID")?;
        let replacement_mount_device_id = adopted_probe.device_major_minor.clone();
        ensure!(
            adopted_probe.canonical_device == empty_probe.canonical_device
                && adopted_probe.filesystem_uuid == empty_probe.filesystem_uuid,
            "replacement physical generation changed during adoption"
        );
        ensure!(
            membership.members.iter().any(|member| {
                member.pod_name == target_pod.name
                    && member.shard_ids.as_slice() == [replacement_drive.as_str()]
            }),
            "adopted replacement drive is not the target Pod's runtime shard"
        );
        let node_raw = get_raw_json(&cluster_kubectl, "node", &replacement_spec.node)?;
        let node_json: Value = serde_json::from_str(&node_raw)?;
        let replacement_volume = StorageVolumeIdentity {
            target_proof_sha256: original.target_proof_sha256.clone(),
            host_storage_proof_sha256: sha256_text(&adopted_probe_body),
            rustfs_deployment_id: layout.deployment_id,
            namespace: original.namespace.clone(),
            tenant: original.tenant.clone(),
            pod: target_pod.name.clone(),
            pod_uid: target_pod.uid.clone(),
            rustfs_container_id: adopted_request.target_container_id,
            volume_name: target_mount.volume_name.clone(),
            persistent_volume_claim: claim.name.clone(),
            persistent_volume_claim_uid: claim.uid.clone(),
            persistent_volume: volume.name.clone(),
            persistent_volume_uid: volume.uid.clone(),
            node: replacement_spec.node.clone(),
            node_uid: required_json_string(&node_json, "/metadata/uid", "replacement node UID")?,
            storage_class: self.config.cluster.storage_class.clone(),
            local_volume_path: replacement_spec.local_path.clone(),
            mount_path: self.config.rustfs_volume_path.clone(),
            canonical_device: adopted_probe.canonical_device,
            target_mount_namespace_id: adopted_probe.mount_namespace_id,
            filesystem_uuid: adopted_probe.filesystem_uuid,
            rustfs_drive_uuid: replacement_drive.clone(),
            pool_index: 0,
            set_index: 0,
            observed_at_ms: adopted_probe
                .observed_at_ms
                .max(empty_probe.observed_at_ms + 1),
        };
        replacement_volume.validate()?;
        let empty_observation = EmptyVolumeObservation {
            observed_at_ms: empty_probe.observed_at_ms,
            persistent_volume_uid: replacement_pv_uid,
            canonical_device: empty_probe.canonical_device,
            filesystem_uuid: empty_probe.filesystem_uuid,
            rustfs_process_can_access_volume: false,
            data_entries: empty_probe.data_entries,
            scan_response_sha256: sha256_text(&empty_response_body),
            scan_response_body: empty_response_body,
        };
        let identity = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .owned_context
            .as_ref()
            .context("fresh-volume original ownership disappeared")?
            .identity
            .clone();
        let proof = FreshVolumeReplacementProof::prove(
            identity,
            original.clone(),
            replacement_volume.clone(),
            empty_observation,
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            DISK_GENERATION_PROOF_ARTIFACT,
            &serde_json::to_string_pretty(&proof)?,
        )?;

        let renewed_context = self.renew_owned_context().await?;
        let mut guard = self
            .helper_guard
            .lock()
            .await
            .take()
            .context("original-volume helper session is absent")?;
        let prepare_result = guard
            .execute(
                &renewed_context,
                &StorageRecoveryHostOperation::PrepareFreshVolume {
                    replacement_persistent_volume: replacement_volume.persistent_volume.clone(),
                    replacement_persistent_volume_claim: replacement_volume
                        .persistent_volume_claim
                        .clone(),
                },
            )
            .await;
        *self.helper_guard.lock().await = Some(guard);
        let prepare_receipt = prepare_result?;
        ensure!(
            inventory.pod_proofs.iter().all(|pod| {
                pod.persistent_volume_claims.iter().all(|claim| {
                    claim.persistent_volume.as_ref().is_none_or(|volume| {
                        volume.name != original.persistent_volume
                            && volume.uid != original.persistent_volume_uid
                    })
                })
            }),
            "original PV generation is still referenced by the recovered Tenant"
        );
        let absence_body = serde_json::to_string_pretty(&json!({
            "originalPersistentVolume": original.persistent_volume,
            "originalPersistentVolumeUid": original.persistent_volume_uid,
            "originalCanonicalDevice": original.canonical_device,
            "originalFilesystemUuid": original.filesystem_uuid,
            "originalDriveUuid": original.rustfs_drive_uuid,
            "replacementPersistentVolume": replacement_volume.persistent_volume,
            "replacementPersistentVolumeUid": replacement_volume.persistent_volume_uid,
            "replacementCanonicalDevice": replacement_volume.canonical_device,
            "replacementFilesystemUuid": replacement_volume.filesystem_uuid,
            "replacementDriveUuid": replacement_volume.rustfs_drive_uuid,
            "runtimePods": inventory.pod_proofs,
            "observedAtMs": now_ms(),
        }))?;
        let old_device_absence_sha256 = sha256_text(&absence_body);
        self.collector.write_text(
            self.scenario.case_name,
            "old-device-absence.json",
            &absence_body,
        )?;
        let heal_adapter = {
            let mut state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            state.membership = Some(membership);
            state.shape = Some(shape);
            state.target_pod = Some(target_pod.name.clone());
            state.replacement_volume = Some(replacement_volume.clone());
            state.replacement_mount_device_id = Some(replacement_mount_device_id);
            state.prepare_receipt = Some(prepare_receipt);
            state.old_device_absence_sha256 = Some(old_device_absence_sha256);
            state.replacement_proof = Some(proof);
            state
                .heal_adapter
                .clone()
                .context("fresh-volume heal adapter was not initialized")?
        };
        heal_adapter
            .set_expected_target_drive(replacement_drive)
            .await?;
        if let Some(pause) = self
            .operator_pause
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume operator pause lock poisoned"))?
            .as_mut()
        {
            pause.resume(self.config.cluster.timeout)?;
        }
        Ok(())
    }
    async fn start_heal(&self) -> Result<()> {
        let adapter = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .heal_adapter
            .clone()
            .context("fresh-volume heal adapter was not initialized")?;
        let started_at_ms = now_ms();
        let intent = adapter.register_start_intent().await?;
        self.collector.write_text(
            self.scenario.case_name,
            FRESH_VOLUME_HEAL_START_ARTIFACT,
            &intent,
        )?;
        adapter.start_registered().await?;
        let owned_start = adapter.start_state_json().await;
        let record_owned_start = owned_start.and_then(|owned_start| {
            self.collector.write_text(
                self.scenario.case_name,
                FRESH_VOLUME_HEAL_START_ARTIFACT,
                &owned_start,
            )?;
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                .heal_started_at_ms = Some(started_at_ms);
            Ok(())
        });
        if let Err(primary) = record_owned_start {
            return match adapter.cancel_owned().await {
                Ok(_) => Err(primary),
                Err(cancel) => Err(primary.context(format!(
                    "owned heal cancellation after state persistence failure also failed: {cancel:#}"
                ))),
            };
        }
        Ok(())
    }

    async fn verify_replacement_baseline(&self) -> Result<()> {
        let (s3, history, sealed) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state
                .session
                .as_ref()
                .context("fresh-volume workload session was not prepared")?;
            (
                session.s3.clone(),
                session.proof_history.clone(),
                session.sealed.clone(),
            )
        };
        let before = history.records().len();
        let ordinary = s3
            .get_object_version_result(&sealed.key, &sealed.version_id, &history)
            .await?;
        let ordinary_sha256 = ordinary
            .body
            .as_deref()
            .map(crate::fault::workload::sha256_hex);
        ensure!(
            ordinary.outcome == OperationOutcome::Ok
                && ordinary_sha256.as_deref() == Some(sealed.sha256.as_str()),
            "ordinary versionId GET could not read the sealed object after replacement"
        );
        let records = history.records();
        let matching = records[before..]
            .iter()
            .filter(|record| {
                record.kind == OperationKind::Get
                    && record.key.as_deref() == Some(sealed.key.as_str())
                    && record.version_id.as_deref() == Some(sealed.version_id.as_str())
            })
            .collect::<Vec<_>>();
        let [ordinary_record] = matching.as_slice() else {
            bail!("post-replacement ordinary versionId GET was not recorded exactly once")
        };
        let ordinary_operation_id = ordinary_record.id.clone();
        let mut state = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
        state.ordinary_after_replacement_operation_id = Some(ordinary_operation_id);
        Ok(())
    }

    async fn wait_for_owned_heal(&self) -> Result<()> {
        let (adapter, started_at_ms, identity, replacement) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            (
                state
                    .heal_adapter
                    .clone()
                    .context("fresh-volume heal adapter was not initialized")?,
                state
                    .heal_started_at_ms
                    .context("fresh-volume heal was not started")?,
                state
                    .owned_context
                    .as_ref()
                    .context("fresh-volume ownership is absent")?
                    .identity
                    .clone(),
                state
                    .replacement_volume
                    .clone()
                    .context("fresh-volume replacement identity is absent")?,
            )
        };
        let mut next_lease_renewal = Instant::now();
        loop {
            if Instant::now() >= next_lease_renewal {
                self.renew_owned_context().await?;
                next_lease_renewal = Instant::now() + Duration::from_secs(60);
            }
            let Some(observation) = adapter.observe().await? else {
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };
            let normalized = RustfsHealStatusResponse {
                observer: observation.observer.clone(),
                observed_at_ms: observation.observed_at_ms,
                state: observation.state,
                scanned: observation.scanned,
                repaired: observation.repaired,
                failed: observation.failed,
                cluster_definitive: observation.cluster_definitive,
                target_drive_uuid: observation.target_drive_uuid.clone(),
                pool_index: observation.pool_index,
                set_index: observation.set_index,
            };
            let response_body = serde_json::to_string(&normalized)?;
            let sample = HealProgressSample {
                schema_version:
                    crate::fault::storage_recovery::STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                identity: identity.clone(),
                observer: observation.observer.clone(),
                observed_at_ms: observation.observed_at_ms,
                state: observation.state,
                scanned: observation.scanned,
                repaired: observation.repaired,
                failed: observation.failed,
                status_evidence: Some(HealStatusEvidence {
                    api_revision: match self.plan.case {
                        StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement => {
                            "rustfs-admin-v4-replacement-recovery".to_string()
                        }
                        StorageRecoveryCase::FreshVolumeReplacementAdminDeep => {
                            "rustfs-admin-v3-heal".to_string()
                        }
                        _ => unreachable!("fresh-volume plan validated by constructor"),
                    },
                    response_sha256: sha256_text(&response_body),
                    response_body,
                }),
            };
            if observation.target_drive_uuid.is_some() {
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                    .heal_progress
                    .push(sample.clone());
            }
            if observation.state == HealProgressState::Failed {
                bail!("RustFS heal reported a failed terminal state")
            }
            if observation.state == HealProgressState::Completed {
                ensure!(
                    observation.target_drive_uuid.as_deref()
                        == Some(replacement.rustfs_drive_uuid.as_str()),
                    "completed RustFS heal is not bound to the replacement drive"
                );
                let progress = self
                    .state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                    .heal_progress
                    .clone();
                let summary = HealSummary {
                    schema_version:
                        crate::fault::storage_recovery::STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
                    identity,
                    case: self.plan.case,
                    observer: observation.observer,
                    mode: self.plan.case.heal_mode().expect("fresh-volume cases heal"),
                    target_drive_uuid: observation.target_drive_uuid,
                    pool_index: observation.pool_index,
                    set_index: observation.set_index,
                    cluster_definitive: observation.cluster_definitive,
                    started_at_ms,
                    completed_at_ms: observation.observed_at_ms,
                    scanned: observation.scanned,
                    repaired: observation.repaired,
                    failed: observation.failed,
                    state: observation.state,
                };
                summary.validate_progress(
                    &progress,
                    Some((
                        &replacement.rustfs_drive_uuid,
                        replacement.pool_index,
                        replacement.set_index,
                    )),
                )?;
                self.state
                    .lock()
                    .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                    .heal_summary = Some(summary);
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    async fn verify_recovery_and_post_write(&self) -> Result<()> {
        self.renew_owned_context().await?;
        let causal_read_proof = self
            .with_lease_heartbeat(self.run_causal_read_proof())
            .await?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .causal_read_proof = Some(causal_read_proof);
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let (s3, history, workload_plan, prefilled, sealed, events) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state
                .session
                .as_ref()
                .context("fresh-volume workload session was not prepared")?;
            (
                session.s3.clone(),
                session.history.clone(),
                session.workload_plan.clone(),
                session.prefilled.clone(),
                session.sealed.clone(),
                session.events.clone(),
            )
        };
        let recovered = s3
            .get_object_version_result(&sealed.key, &sealed.version_id, &history)
            .await?;
        ensure!(
            recovered.outcome == OperationOutcome::Ok
                && recovered.body.as_deref().is_some_and(|body| {
                    use sha2::{Digest, Sha256};
                    hex::encode(Sha256::digest(body)) == sealed.sha256
                }),
            "repaired exact version did not return its sealed bytes"
        );
        let mut workload = self
            .with_lease_heartbeat(run_mixed_workload(&MixedWorkloadRequest {
                s3: &s3,
                history: &history,
                scenario: &self.scenario.name,
                run_id: self.run_id,
                plan: &workload_plan,
                prefilled: &prefilled,
                start_index: 0,
                count: self.scenario.object_count,
                ranged_get_percent: self.config.workload_ranged_get_percent,
                staged_multipart_uploads: None,
                progress_events: None,
                deadline: self.deadline,
            }))
            .await?;
        self.renew_owned_context().await?;
        workload.seal_recommit_candidates(&s3, &history)?;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let prechecker = self
            .with_lease_heartbeat(checker::check_s3_history(
                &s3,
                &history,
                true,
                workload_plan.concurrency,
                true,
            ))
            .await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-pre-recommit-report.json",
            &serde_json::to_string_pretty(&prechecker)?,
        )?;
        prechecker.require_success()?;
        let recommit = self
            .with_lease_heartbeat(async {
                Ok(recommit_unconfirmed_objects(
                    &s3,
                    &history,
                    &workload.unconfirmed_puts,
                    workload_plan.concurrency,
                    self.deadline,
                )
                .await)
            })
            .await?;
        self.renew_owned_context().await?;
        ensure!(
            !recommit.has_failures(),
            "fresh-volume recommit failed: {}",
            recommit.failure_message()
        );
        workload.summary.recommitted_after_recovery = recommit.committed;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            "recommit-report.json",
            &serde_json::to_string_pretty(&recommit)?,
        )?;
        let checker = self
            .with_lease_heartbeat(checker::check_s3_history(
                &s3,
                &history,
                true,
                workload_plan.concurrency,
                true,
            ))
            .await?;
        self.renew_owned_context().await?;
        checker.require_success()?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&checker)?,
        )?;
        let post_write_history = Recorder::create(
            self.collector
                .case_dir(self.scenario.case_name)
                .join("post-recovery-write-history.jsonl"),
            &self.scenario.name,
            self.run_id,
        )?;
        let post_write = self
            .with_lease_heartbeat(run_post_recovery_write_probe(&PostRecoveryWriteRequest {
                s3: &s3,
                history: &post_write_history,
                run_id: self.run_id,
                scope: crate::fault::workload::WriteProbeScope::PostRecovery,
                seed: workload_plan.seed,
                object_count: post_recovery_object_count(workload_plan.object_count),
                concurrency: workload_plan.concurrency,
                deadline: self.deadline,
            }))
            .await?;
        post_write.require_success()?;
        self.collector.write_text(
            self.scenario.case_name,
            "post-recovery-write-report.json",
            &serde_json::to_string_pretty(&post_write)?,
        )?;
        events.record(
            "checker-final",
            RunEventStatus::Succeeded,
            "fresh-volume history, version lineage, and post-write checks passed",
            None,
        )?;
        events.record(
            "run",
            RunEventStatus::Succeeded,
            "fresh-volume recovery qualification completed",
            None,
        )?;
        Ok(())
    }
    async fn persist_raw_evidence(&self) -> Result<()> {
        let (
            adapter,
            progress,
            summary,
            context,
            replacement,
            prepare_receipt,
            old_device_absence_sha256,
            replacement_proof,
            causal_read_proof,
            proof_history,
            helper_pod,
            replacement_helper_pod,
            ownership_checkpoint,
        ) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            let session = state.session.as_ref();
            (
                state.heal_adapter.clone(),
                state.heal_progress.clone(),
                state.heal_summary.clone(),
                state.owned_context.clone(),
                state.replacement_volume.clone(),
                state.prepare_receipt.clone(),
                state.old_device_absence_sha256.clone(),
                state.replacement_proof.clone(),
                state.causal_read_proof.clone(),
                session.map(|session| session.proof_history.clone()),
                state.helper_pod.clone(),
                state.replacement_helper_pod.clone(),
                state.ownership_checkpoint,
            )
        };
        if let Some(context) = context.as_ref()
            && ownership_checkpoint
                .is_some_and(FreshVolumeOwnershipCheckpoint::permits_abort_before_mutation)
        {
            let proof = StorageRecoveryCleanupProof::AbortedBeforeMutation {
                observed_at_ms: now_ms()
                    .max(context.exclusive_access.kubernetes_lease.acquired_at_ms),
            };
            proof.validate_for(context)?;
            self.collector.write_text(
                self.scenario.case_name,
                FRESH_VOLUME_ABORT_PROOF_ARTIFACT,
                &serde_json::to_string_pretty(&proof)?,
            )?;
            self.state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
                .abort_before_mutation = Some(proof);
        }
        let transcript = match adapter {
            Some(adapter) => {
                self.collector.write_text(
                    self.scenario.case_name,
                    FRESH_VOLUME_HEAL_START_ARTIFACT,
                    &adapter.start_state_json().await?,
                )?;
                adapter.transcript_json().await?
            }
            None => "[]".to_string(),
        };
        self.collector.write_text(
            self.scenario.case_name,
            FRESH_VOLUME_HEAL_TRANSCRIPT_ARTIFACT,
            &transcript,
        )?;
        if !progress.is_empty() {
            let mut body = String::new();
            for sample in &progress {
                body.push_str(&serde_json::to_string(sample)?);
                body.push('\n');
            }
            self.collector
                .write_text(self.scenario.case_name, HEAL_PROGRESS_ARTIFACT, &body)?;
        }
        if let Some(summary) = &summary {
            self.collector.write_text(
                self.scenario.case_name,
                HEAL_SUMMARY_ARTIFACT,
                &serde_json::to_string_pretty(summary)?,
            )?;
        }
        if let Some(causal_read_proof) = &causal_read_proof {
            self.collector.write_text(
                self.scenario.case_name,
                FRESH_VOLUME_READ_PROOF_ARTIFACT,
                &serde_json::to_string_pretty(causal_read_proof)?,
            )?;
        }
        self.collector.write_text(
            self.scenario.case_name,
            FRESH_VOLUME_FIXTURE_ARTIFACT,
            &serde_json::to_string_pretty(&json!({
                "schemaVersion": 1,
                "runId": self.run_id,
                "scenario": self.scenario.name,
                "case": self.plan.case,
                "initialVolumes": self.fixture.initial(),
                "replacementVolume": self.fixture.replacement(),
                "originalHelperPod": helper_pod,
                "replacementHelperPod": replacement_helper_pod,
                "ownedContext": context,
                "replacementIdentity": replacement,
                "prepareReceipt": prepare_receipt,
                "oldDeviceAbsenceSha256": old_device_absence_sha256,
                "replacementProof": replacement_proof,
                "cleanupPolicy": "retain-host-volumes-delete-run-owned-kubernetes-objects",
            }))?,
        )?;
        if context.is_some() {
            let (_, layout, shape, membership) = self
                .current_runtime_topology()
                .await
                .context("capture post-recovery RustFS topology")?;
            self.collector.write_text(
                self.scenario.case_name,
                "recovery-health.json",
                &serde_json::to_string_pretty(&json!({
                    "deploymentId": layout.deployment_id,
                    "onlineDrives": layout.online_drives,
                    "offlineDrives": layout.offline_drives,
                    "unknownDrives": layout.unknown_drives,
                    "shape": shape,
                    "membership": membership,
                    "observedAtMs": now_ms(),
                }))?,
            )?;
        }
        if let (Some(replacement_proof), Some(causal_read_proof), Some(proof_history)) = (
            replacement_proof.as_ref(),
            causal_read_proof.as_ref(),
            proof_history.as_ref(),
        ) {
            let case_dir = self.collector.case_dir(self.scenario.case_name);
            let mappings = serde_json::from_str::<Vec<VersionShardMappingObservation>>(
                &fs::read_to_string(case_dir.join(VERSION_SHARD_MAPPING_ARTIFACT))?,
            )?;
            let original_target_proof = fs::read_to_string(case_dir.join("target-proof.json"))?;
            causal_read_proof.validate_chain(
                &mappings,
                replacement_proof,
                summary
                    .as_ref()
                    .context("causal read proof lacks completed heal evidence")?,
                &progress,
                &proof_history.records(),
                &original_target_proof,
            )?;
        }
        Ok(())
    }

    async fn persist_workflow_snapshot(
        &self,
        evidence: &StorageRecoveryWorkflowEvidence,
    ) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            STORAGE_RECOVERY_WORKFLOW_ARTIFACT,
            &serde_json::to_string_pretty(evidence)?,
        )?;
        Ok(())
    }

    async fn cancel_owned_heal(&self) -> Result<OwnedHealCancel> {
        let adapter = self
            .state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .heal_adapter
            .clone();
        match adapter {
            Some(adapter) => adapter.cancel_owned().await,
            None => Ok(OwnedHealCancel::NoOwnedHeal),
        }
    }

    async fn cleanup_or_quarantine(&self) -> Result<()> {
        let (
            context,
            replacement,
            prepare_receipt,
            old_device_absence_sha256,
            abort_before_mutation,
            ownership_checkpoint,
            heal_adapter,
            helper_pods,
        ) = {
            let state = self
                .state
                .lock()
                .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?;
            (
                state.owned_context.clone(),
                state.replacement_volume.clone(),
                state.prepare_receipt.clone(),
                state.old_device_absence_sha256.clone(),
                state.abort_before_mutation.clone(),
                state.ownership_checkpoint,
                state.heal_adapter.clone(),
                [
                    state.helper_pod.clone(),
                    state.replacement_helper_pod.clone(),
                ],
            )
        };
        let mut primary: Option<anyhow::Error> = None;
        if let Some(adapter) = heal_adapter
            && adapter.has_ambiguous_start().await
        {
            primary = Some(anyhow::anyhow!(
                "admin heal start ownership remains ambiguous; no foreign-safe cancellation is possible"
            ));
        }
        let terminal_proof = match (
            replacement.as_ref(),
            prepare_receipt.as_ref(),
            old_device_absence_sha256.as_ref(),
        ) {
            (Some(replacement), Some(prepare_receipt), Some(old_device_absence_sha256)) => {
                Some(StorageRecoveryCleanupProof::FreshVolumeCommitted {
                    prepare_receipt: Box::new(prepare_receipt.clone()),
                    replacement_volume: Box::new(replacement.clone()),
                    old_device_absence_sha256: old_device_absence_sha256.clone(),
                    observed_at_ms: now_ms().max(prepare_receipt.completed_at_ms),
                })
            }
            _ if context.is_some()
                && ownership_checkpoint
                    .is_some_and(FreshVolumeOwnershipCheckpoint::permits_abort_before_mutation) =>
            {
                abort_before_mutation
            }
            _ => None,
        };
        if let (Some(_), Some(proof)) = (context.as_ref(), terminal_proof.as_ref()) {
            let finish_result = async {
                let context = self.renew_owned_context().await?;
                if let Some(guard) = self.helper_guard.lock().await.take() {
                    guard.finish(&context, proof).await
                } else {
                    let client = crate::framework::kube_client::client_for_context(
                        &self.config.cluster.context,
                    )
                    .await?;
                    release_owned_lease(client, &context, proof).await
                }
            }
            .await;
            if let Err(error) = finish_result {
                primary = Some(match primary {
                    Some(original) => original.context(format!(
                        "receipt-bound original-volume ownership cleanup also failed: {error:#}"
                    )),
                    None => error.context("finish receipt-bound original-volume ownership"),
                });
            }
        } else if context.is_some() {
            let error =
                anyhow::anyhow!("owned storage Lease lacks a durable terminal cleanup proof");
            primary = Some(match primary {
                Some(original) => original.context(format!("Lease cleanup also failed: {error:#}")),
                None => error,
            });
        }
        if let Err(error) = fixture::reset_tenant_resources(&self.config.cluster) {
            primary = Some(match primary {
                Some(original) => {
                    original.context(format!("Tenant cleanup also failed: {error:#}"))
                }
                None => error,
            });
        }
        for helper in helper_pods.into_iter().flatten() {
            let cleanup = async {
                let client =
                    crate::framework::kube_client::client_for_context(&self.config.cluster.context)
                        .await?;
                delete_owned_helper_pod(
                    client,
                    &self.config.cluster.test_namespace,
                    &helper,
                    self.run_id,
                    self.config.cluster.timeout,
                )
                .await
            }
            .await;
            if let Err(error) = cleanup {
                primary = Some(match primary {
                    Some(original) => original.context(format!(
                        "helper Pod cleanup for {} also failed: {error:#}",
                        helper.name
                    )),
                    None => error,
                });
            }
        }
        match crate::framework::kube_client::client_for_context(&self.config.cluster.context).await
        {
            Ok(client) => {
                let api: Api<PersistentVolume> = Api::all(client.clone());
                for volume in self
                    .fixture
                    .initial()
                    .iter()
                    .chain([self.fixture.replacement()])
                {
                    match api.get_opt(&volume.name).await {
                        Ok(Some(object)) => {
                            let Some(uid) = object.metadata.uid else {
                                primary = Some(anyhow::anyhow!(
                                    "run-owned PV {} lacks a UID during cleanup",
                                    volume.name
                                ));
                                continue;
                            };
                            if let Err(error) = delete_owned_pv(
                                client.clone(),
                                &volume.name,
                                &uid,
                                self.run_id,
                                self.config.cluster.timeout,
                            )
                            .await
                            {
                                primary = Some(match primary {
                                    Some(original) => original.context(format!(
                                        "PV cleanup for {} also failed: {error:#}",
                                        volume.name
                                    )),
                                    None => error,
                                });
                            }
                        }
                        Ok(None) => {}
                        Err(error) => {
                            primary = Some(match primary {
                                Some(original) => original.context(format!(
                                    "read PV {} during cleanup also failed: {error:#}",
                                    volume.name
                                )),
                                None => error.into(),
                            });
                        }
                    }
                }
            }
            Err(error) => {
                primary = Some(match primary {
                    Some(original) => original
                        .context(format!("Kubernetes client creation also failed: {error:#}")),
                    None => error.context("create Kubernetes client during PV cleanup"),
                });
            }
        }
        if let Some(pause) = self
            .operator_pause
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume operator pause lock poisoned"))?
            .as_mut()
            && let Err(error) = pause.resume(self.config.cluster.timeout)
        {
            primary = Some(match primary {
                Some(original) => {
                    original.context(format!("operator resume also failed: {error:#}"))
                }
                None => error,
            });
        }
        let cleanup = json!({
            "schemaVersion": 1,
            "runId": self.run_id,
            "tenantResourcesRemoved": primary.is_none(),
            "hostVolumesRetainedAndQuarantined": self.fixture.initial().iter()
                .chain([self.fixture.replacement()])
                .map(|volume| volume.local_path.clone())
                .collect::<Vec<_>>(),
            "completedAtMs": now_ms(),
            "error": primary.as_ref().map(|error| format!("{error:#}")),
        });
        self.collector.write_text(
            self.scenario.case_name,
            FRESH_VOLUME_CLEANUP_ARTIFACT,
            &serde_json::to_string_pretty(&cleanup)?,
        )?;
        self.state
            .lock()
            .map_err(|_| anyhow::anyhow!("fresh-volume driver state lock poisoned"))?
            .cleanup_evidence = Some(cleanup);
        match primary {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn volume(generation: &str, observed_at_ms: u64) -> StorageVolumeIdentity {
        StorageVolumeIdentity {
            target_proof_sha256: "a".repeat(64),
            host_storage_proof_sha256: "b".repeat(64),
            rustfs_deployment_id: "deployment-1".to_string(),
            namespace: "fault-run".to_string(),
            tenant: "rustfs".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: format!("pod-{generation}"),
            rustfs_container_id: format!("containerd://{}", sha256_text(generation)),
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

    #[test]
    fn replacement_membership_binds_both_storage_generations() {
        let mut old = volume("old", 100);
        old.pod = "rustfs-0".to_string();
        let mut new = volume("new", 300);
        new.pod = old.pod.clone();
        let original = ErasureSetMembership {
            members: vec![
                ErasureSetMember {
                    pod_name: old.pod.clone(),
                    server_endpoint: "server-0".to_string(),
                    shard_ids: vec![old.rustfs_drive_uuid.clone()],
                },
                ErasureSetMember {
                    pod_name: "rustfs-1".to_string(),
                    server_endpoint: "server-1".to_string(),
                    shard_ids: vec!["sibling".to_string()],
                },
            ],
        };
        let mut current = original.clone();
        current.members[0].shard_ids = vec![new.rustfs_drive_uuid.clone()];
        validate_replacement_membership(&original, &current, &old, &new)
            .expect("replacement UUID may change");
        let mut same_uuid = new.clone();
        same_uuid.rustfs_drive_uuid = old.rustfs_drive_uuid.clone();
        validate_replacement_membership(&original, &original, &old, &same_uuid)
            .expect("format healing may preserve the slot UUID");
        assert!(validate_replacement_membership(&current, &current, &old, &new).is_err());
        current.members[1].shard_ids = vec!["foreign-sibling".to_string()];
        assert!(validate_replacement_membership(&original, &current, &old, &new).is_err());
    }

    #[test]
    fn rebuilt_shard_must_restore_the_sealed_shard_on_a_new_device() {
        use crate::fault::storage_recovery_helper::{
            OfflineInspectedShard, OfflineXl2InspectResponse,
        };
        use crate::fault::xl2_inspector::{
            OFFLINE_XL2_INSPECTOR_REVISION, Xl2FormatProfile, Xl2ObjectVersionLayout,
        };
        let original = OfflineXl2InspectResponse {
            mount_device_id: "8:1".to_string(),
            drive_uuid: "old".to_string(),
            format_json_sha256: "a".repeat(64),
            xl_meta_sha256: "b".repeat(64),
            layout: Xl2ObjectVersionLayout {
                inspector_revision: OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
                profile: Xl2FormatProfile::LATEST_RUSTFS,
                version_id: "version-1".to_string(),
                data_directory: "data".to_string(),
                erasure_data_shards: 2,
                erasure_parity_shards: 2,
                erasure_index: 1,
                part_numbers: vec![1],
                part_sizes: vec![1024],
                relative_part_paths: vec!["bucket/key/data/part.1".to_string()],
            },
            selected_part: OfflineInspectedShard {
                part_number: 1,
                relative_part_path: "bucket/key/data/part.1".to_string(),
                shard_device_id: "8:1".to_string(),
                shard_inode: 42,
                shard_size_bytes: 1024,
                original_sha256: "c".repeat(64),
            },
        };
        let mut rebuilt = original.clone();
        rebuilt.mount_device_id = "8:2".to_string();
        rebuilt.drive_uuid = "new".to_string();
        rebuilt.format_json_sha256 = "d".repeat(64);
        rebuilt.xl_meta_sha256 = "e".repeat(64);
        rebuilt.selected_part.shard_device_id = "8:2".to_string();
        rebuilt.selected_part.shard_inode = 99;
        validate_rebuilt_shard(&original, &rebuilt)
            .expect("physical and metadata generations may differ");
        for corruption in ["bytes", "index", "version", "path", "size"] {
            let mut altered = rebuilt.clone();
            match corruption {
                "bytes" => altered.selected_part.original_sha256 = "f".repeat(64),
                "index" => altered.layout.erasure_index = 2,
                "version" => altered.layout.version_id = "another-version".to_string(),
                "path" => {
                    altered.selected_part.relative_part_path = "bucket/key/other/part.1".to_string()
                }
                "size" => altered.selected_part.shard_size_bytes += 1,
                _ => unreachable!(),
            }
            assert!(
                validate_rebuilt_shard(&original, &altered).is_err(),
                "must reject changed {corruption}"
            );
        }
    }

    fn target_fingerprint(
        pod_uid: &'static str,
        relative_part_path: &'static str,
        shard_sha256: &'static str,
    ) -> ReplacementTargetFingerprint<'static> {
        ReplacementTargetFingerprint {
            helper_pod: "helper-1",
            target_pod: "rustfs-0",
            target_pod_uid: pod_uid,
            target_container_id: "containerd://container-1",
            mount_path: "/data",
            relative_part_path,
            shard_device_id: "8:1",
            shard_inode: 42,
            shard_size_bytes: 4096,
            shard_sha256,
        }
    }

    #[test]
    fn causal_proof_rejects_the_wrong_shard_path() {
        assert!(
            validate_replacement_part_path("bucket", "key", 1, "bucket/key/data/part.2").is_err()
        );
    }

    #[test]
    fn causal_proof_rejects_the_wrong_version() {
        assert!(validate_version_binding("version-1", "version-2", "version-1").is_err());
        assert!(validate_version_binding("version-1", "version-1", "version-2").is_err());
    }

    #[test]
    fn causal_proof_rejects_fault_removal_before_the_blocked_read() {
        assert!(validate_causal_timeline([1, 2, 3, 4, 5, 6, 8, 7, 9, 10, 11]).is_err());
    }

    #[test]
    fn causal_proof_rejects_metadata_paths() {
        assert!(
            validate_replacement_part_path("bucket", "key", 1, "bucket/key/data/.metadata.bin")
                .is_err()
        );
    }

    #[test]
    fn causal_proof_rejects_runtime_target_drift() {
        assert!(
            validate_target_continuity(
                target_fingerprint("pod-uid-1", "bucket/key/data/part.1", "abc"),
                target_fingerprint("pod-uid-2", "bucket/key/data/part.1", "abc"),
            )
            .is_err()
        );
    }

    #[test]
    fn causal_proof_rejects_an_invalid_response_sequence() {
        assert!(validate_causal_timeline([1, 2, 3, 4, 5, 6, 7, 8, 10, 9, 11]).is_err());
    }

    #[test]
    fn causal_proof_rejects_a_restored_hash_mismatch() {
        assert!(
            validate_read_result(
                OperationOutcome::Ok,
                Some(200),
                Some("different"),
                "expected",
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn skipped_format_read_tolerates_an_eio_backed_volume() {
        let unreadable = Path::new("/proc/self/mem");
        assert_eq!(
            read_rustfs_drive_uuid(unreadable, false, true).expect("skip format read"),
            None
        );
        let error = read_rustfs_drive_uuid(unreadable, true, false)
            .expect_err("required format read must surface EIO");
        assert!(error.to_string().contains("read target format.json"));
        assert!(read_rustfs_drive_uuid(unreadable, true, true).is_err());
    }

    #[test]
    fn fresh_helper_mounts_match_session_roots() {
        let mut config = FaultTestConfig::for_test("real-cluster", "local-static");
        config.storage_recovery_helper_image = Some("rustfs/s3chaos:test".to_string());
        let raw = storage_helper_pod_manifest(
            &config,
            "run-1",
            "fresh-helper",
            "storage-a",
            "/mnt/rustfs-a",
        )
        .expect("helper manifest");
        let pod: Pod = serde_yaml_ng::from_str(&raw).expect("helper Pod");
        let spec = pod.spec.expect("spec");
        let mounts = spec.containers[0].volume_mounts.as_ref().expect("mounts");
        let roots = crate::fault::storage_recovery_helper::StorageHelperRoots::default();
        for (name, path) in [
            ("volume", roots.volume),
            ("journal", roots.journal),
            ("locks", roots.lock),
        ] {
            let mount = mounts
                .iter()
                .find(|mount| mount.name == name)
                .expect("required mount");
            assert_eq!(Path::new(&mount.mount_path), path.as_path());
        }
        assert_eq!(
            mounts
                .iter()
                .find(|mount| mount.name == "volume")
                .unwrap()
                .read_only,
            Some(true)
        );
    }

    #[test]
    fn lost_found_is_allowed_only_when_recursively_empty() {
        let volume = tempfile::tempdir().expect("volume");
        fs::create_dir(volume.path().join("lost+found")).expect("lost+found");
        assert!(
            exhaustive_entries(volume.path())
                .expect("empty scan")
                .is_empty()
        );

        fs::create_dir(volume.path().join("lost+found/orphan-dir")).expect("orphan directory");
        fs::write(
            volume.path().join("lost+found/orphan-dir/fragment"),
            b"orphan",
        )
        .expect("orphan fragment");
        let entries = exhaustive_entries(volume.path()).expect("nonempty scan");
        assert_eq!(
            entries,
            [
                "lost+found/orphan-dir".to_string(),
                "lost+found/orphan-dir/fragment".to_string(),
            ]
        );
    }

    #[test]
    fn helper_cleanup_identity_is_registered_before_uid_and_never_rebound() {
        let mut identity = OwnedHelperPodCleanup::registered("helper-1".to_string());
        assert_eq!(identity.uid, None);
        identity
            .record_uid("helper-1", "uid-1".to_string())
            .expect("record exact UID");
        assert!(
            identity
                .record_uid("helper-1", "uid-2".to_string())
                .is_err()
        );
        assert!(
            identity
                .record_uid("helper-2", "uid-1".to_string())
                .is_err()
        );
    }

    #[test]
    fn every_post_lease_pre_mutation_failure_requires_abort_proof() {
        for checkpoint in [
            FreshVolumeOwnershipCheckpoint::LeaseAcquired,
            FreshVolumeOwnershipCheckpoint::PostAcquireProbePassed,
            FreshVolumeOwnershipCheckpoint::HelperSessionBegun,
            FreshVolumeOwnershipCheckpoint::InspectionStarted,
            FreshVolumeOwnershipCheckpoint::InspectionCompleted,
        ] {
            assert!(
                checkpoint.permits_abort_before_mutation(),
                "{checkpoint:?} must retain the AbortedBeforeMutation cleanup path"
            );
        }
        assert!(
            !FreshVolumeOwnershipCheckpoint::VolumeMutationStarted.permits_abort_before_mutation()
        );
    }

    #[test]
    fn volume_mutation_request_preserves_cleanup_boundary_on_prepare_failures() {
        use std::{cell::RefCell, rc::Rc};

        let checkpoint = Rc::new(RefCell::new(Some(
            FreshVolumeOwnershipCheckpoint::InspectionCompleted,
        )));
        let calls = Rc::new(RefCell::new(Vec::new()));
        let pause_calls = calls.clone();
        let result = prepare_volume_mutation_request(
            move || {
                pause_calls.borrow_mut().push("pause");
                Err::<(), _>(anyhow::anyhow!("pause failed"))
            },
            |_| Ok(()),
            || Ok("request"),
            || Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(calls.borrow().as_slice(), ["pause"]);
        assert!(
            checkpoint
                .borrow()
                .is_some_and(FreshVolumeOwnershipCheckpoint::permits_abort_before_mutation)
        );

        calls.borrow_mut().clear();
        let pause_calls = calls.clone();
        let record_calls = calls.clone();
        let setup_calls = calls.clone();
        let result = prepare_volume_mutation_request(
            move || {
                pause_calls.borrow_mut().push("pause");
                Ok(())
            },
            move |_| {
                record_calls.borrow_mut().push("record-pause");
                Ok(())
            },
            move || {
                setup_calls.borrow_mut().push("prepare-request");
                Err::<&str, _>(anyhow::anyhow!("request setup failed"))
            },
            || Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(
            calls.borrow().as_slice(),
            ["pause", "record-pause", "prepare-request"]
        );
        assert!(
            checkpoint
                .borrow()
                .is_some_and(FreshVolumeOwnershipCheckpoint::permits_abort_before_mutation)
        );

        calls.borrow_mut().clear();
        let pause_calls = calls.clone();
        let record_calls = calls.clone();
        let setup_calls = calls.clone();
        let mutation_calls = calls.clone();
        let mutation_checkpoint = checkpoint.clone();
        let command = prepare_volume_mutation_request(
            move || {
                pause_calls.borrow_mut().push("pause");
                Ok(())
            },
            move |_| {
                record_calls.borrow_mut().push("record-pause");
                Ok(())
            },
            move || {
                setup_calls.borrow_mut().push("prepare-request");
                Ok("request")
            },
            move || {
                mutation_calls.borrow_mut().push("begin-mutation");
                FreshVolumeOwnershipCheckpoint::begin_volume_mutation(
                    &mut mutation_checkpoint.borrow_mut(),
                )
            },
        )
        .expect("prepare request");
        calls.borrow_mut().push(command);
        assert_eq!(
            calls.borrow().as_slice(),
            [
                "pause",
                "record-pause",
                "prepare-request",
                "begin-mutation",
                "request"
            ]
        );
        assert_eq!(
            *checkpoint.borrow(),
            Some(FreshVolumeOwnershipCheckpoint::VolumeMutationStarted)
        );
    }

    #[test]
    fn response_loss_reconciliation_owns_only_matching_scope_and_time() {
        let requested_at_ms = 1_000;
        let mut state = AdminHealStartState::ambiguous(
            "rustfs-fault-run",
            "",
            "/rustfs/admin/v3/heal/rustfs-fault-run",
            requested_at_ms,
        );
        let start = HealWireReceipt {
            observed_at_ms: 1_200,
            method: "POST".to_string(),
            path: "/rustfs/admin/v3/heal/rustfs-fault-run".to_string(),
            status: 200,
            request_id: Some("request-1".to_string()),
            response_body: r#"{"clientToken":"owned-token","startTime":"1970-01-01T00:00:01Z"}"#
                .to_string(),
        };
        let status = HealWireReceipt {
            observed_at_ms: 1_500,
            method: "POST".to_string(),
            path: start.path.clone(),
            status: 200,
            request_id: Some("request-2".to_string()),
            response_body: r#"{"summary":"running","startTime":"1970-01-01T00:00:01.4Z","settings":{"recursive":false,"scanMode":0}}"#
                .to_string(),
        };
        assert_eq!(
            state
                .own(&start, &status, true)
                .expect("reconciled ownership"),
            HealObserverIdentity::AdminOperation {
                operation_id: "owned-token".to_string(),
            }
        );
        assert!(matches!(
            state,
            AdminHealStartState::Owned {
                reconciled_after_response_loss: true,
                ..
            }
        ));

        let mut foreign_scope = AdminHealStartState::ambiguous(
            "rustfs-fault-run",
            "",
            "/rustfs/admin/v3/heal/rustfs-fault-run",
            requested_at_ms,
        );
        let mut wrong_status = status;
        wrong_status.path = "/rustfs/admin/v3/heal/foreign".to_string();
        assert!(foreign_scope.own(&start, &wrong_status, true).is_err());
        assert!(matches!(
            foreign_scope,
            AdminHealStartState::Ambiguous { .. }
        ));
    }

    #[test]
    fn manifest_is_retain_local_and_run_owned() {
        let mut config = FaultTestConfig::for_test("real-cluster", "local-static");
        config.expected_rustfs_pod_count = 1;
        let volume = StaticLocalPvSpec {
            name: "fresh-pv-a".to_string(),
            node: "storage-a".to_string(),
            local_path: "/mnt/rustfs-a".to_string(),
            capacity: "100Gi".to_string(),
        };
        let raw = static_local_pv_manifest(&config, "run-1", &volume).expect("manifest");
        let value: Value = serde_yaml_ng::from_str(&raw).expect("yaml");
        assert_eq!(
            value
                .pointer("/spec/persistentVolumeReclaimPolicy")
                .and_then(Value::as_str),
            Some("Retain")
        );
        assert_eq!(
            value.pointer("/spec/local/path").and_then(Value::as_str),
            Some("/mnt/rustfs-a")
        );
        assert_eq!(
            value
                .pointer("/metadata/labels/s3chaos.rustfs.com~1run")
                .and_then(Value::as_str),
            Some("run-1")
        );
    }

    #[test]
    fn fixture_requires_one_server_per_node_and_exact_allowlists() {
        let mut config = FaultTestConfig::for_test("real-cluster", "local-static");
        config.expected_rustfs_pod_count = 2;
        config.host_mutation_allowed_nodes = vec!["node-a".to_string(), "node-b".to_string()];
        config.host_mutation_allowed_persistent_volumes =
            vec!["pv-a".to_string(), "pv-b".to_string(), "pv-new".to_string()];
        config.storage_local_pvs_json = Some(
            r#"[
              {"name":"pv-a","node":"node-a","localPath":"/mnt/a","capacity":"100Gi"},
              {"name":"pv-b","node":"node-b","localPath":"/mnt/b","capacity":"100Gi"},
              {"name":"pv-new","node":"node-a","localPath":"/mnt/new","capacity":"100Gi"}
            ]"#
            .to_string(),
        );
        let plan = StaticLocalPvFixturePlan::parse(&config).expect("closed fixture");
        assert_eq!(plan.initial().len(), 2);
        assert_eq!(plan.replacement().node, "node-a");

        config.host_mutation_allowed_persistent_volumes.pop();
        assert!(StaticLocalPvFixturePlan::parse(&config).is_err());
    }

    #[test]
    fn automatic_status_requires_actual_generation_and_exact_slot() {
        let receipt = HealWireReceipt {
            observed_at_ms: 1,
            method: "GET".to_string(),
            path: REPLACEMENT_STATUS_PATH.to_string(),
            status: 200,
            request_id: None,
            response_body: r#"{"cluster":{"definitive":true,"records":[{"taskId":"task-1","state":"completed","generation":null,"setDiskId":"pool_0_set_0","targetSlots":["http://rustfs-0/data"]}]}}"#.to_string(),
        };
        let parsed = parse_replacement_status(&receipt).expect("wire response");
        assert_eq!(parsed.cluster.expect("cluster").records[0].generation, None);
        assert_eq!(
            normalize_replacement_state("unknown").expect("fail closed state"),
            HealProgressState::Failed
        );
    }

    #[test]
    fn admin_status_normalization_rejects_non_json() {
        assert!(
            normalize_admin_status(
                HealObserverIdentity::AdminOperation {
                    operation_id: "owned".to_string()
                },
                1,
                "not-json",
                "drive-new",
                0,
                0,
            )
            .is_err()
        );
    }

    #[test]
    fn admin_status_uses_rustfs_progress_without_assuming_echoed_start_settings() {
        let observation = normalize_admin_status(
            HealObserverIdentity::AdminOperation {
                operation_id: "owned".to_string(),
            },
            10,
            r#"{"summary":"finished","settings":{"recursive":false,"scanMode":0},"items":[],"progress":{"objectsScanned":7,"objectsHealed":3,"objectsFailed":0}}"#,
            "drive-new",
            0,
            0,
        )
        .expect("RustFS v3 heal status");
        assert_eq!(observation.state, HealProgressState::Completed);
        assert_eq!((observation.scanned, observation.repaired), (7, 3));
        assert_eq!(observation.target_drive_uuid.as_deref(), Some("drive-new"));
    }

    #[test]
    fn heal_transcript_is_bound_to_the_selected_wire_operation() {
        let automatic = [1, 2].map(|observed_at_ms| HealWireReceipt {
            observed_at_ms,
            method: "GET".to_string(),
            path: REPLACEMENT_STATUS_PATH.to_string(),
            status: 200,
            request_id: None,
            response_body: r#"{"cluster":{"definitive":true,"records":[]}}"#.to_string(),
        });
        validate_heal_transcript(
            &automatic,
            StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement,
        )
        .expect("automatic transcript");
        assert!(
            validate_heal_transcript(
                &automatic,
                StorageRecoveryCase::FreshVolumeReplacementAdminDeep,
            )
            .is_err()
        );
    }
}
