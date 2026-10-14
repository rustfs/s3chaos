// Copyright 2025 RustFS Team
// SPDX-License-Identifier: Apache-2.0

//! Evidence for a partition applied while an owned replacement heal is moving.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::fault::{
    backends::chaos_mesh::{
        ScopedNetworkPartitionEvidenceContract, validate_scoped_network_partition_snapshot,
    },
    fresh_volume::{ControllerSnapshotEvidence, FreshVolumeReadMatrixEvidence, HealWireReceipt},
    history::{OperationKind, OperationOutcome, OperationRecord},
    pod_network::{PodConnectivityObservation, PodNetworkIdentity, validate_connectivity},
    storage_recovery::{
        FreshVolumeReplacementProof, HealObserverIdentity, HealProgressSample, HealProgressState,
        HealSummary, RustfsHealStatusResponse, StorageRecoveryArtifactIdentity,
        StorageRecoveryCase, StorageVolumeIdentity,
    },
};

pub(crate) const HEAL_PARTITION_PROOF_ARTIFACT: &str = "heal-partition-proof.json";
pub(crate) const HEAL_PARTITION_TTL_SECONDS: u64 = 60;
pub(crate) const HEAL_PARTITION_HOLD_MILLIS: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HealPartitionEvidence {
    pub schema_version: u8,
    pub identity: StorageRecoveryArtifactIdentity,
    pub replacement: StorageVolumeIdentity,
    pub chaos_namespace: String,
    pub pods: Vec<PodNetworkIdentity>,
    pub source_pod_names: BTreeSet<String>,
    pub peer_pod_names: BTreeSet<String>,
    pub object_key: String,
    pub version_id: String,
    pub expected_sha256: String,
    pub manifest: String,
    pub baseline_connectivity: Vec<PodConnectivityObservation>,
    pub apply_started_at_ms: Option<u64>,
    pub snapshots: Vec<ControllerSnapshotEvidence>,
    pub active_connectivity: Vec<PodConnectivityObservation>,
    pub read_operation_ids: Vec<String>,
    pub delete_started_at_ms: Option<u64>,
    pub deleted_at_ms: Option<u64>,
    pub restored_connectivity: Vec<PodConnectivityObservation>,
}

/// Requires two real nonterminal observations. A task accepted by the server,
/// an unchanged counter, or a task that completed before injection cannot
/// qualify the partition trigger.
pub(crate) fn require_moving_heal(
    previous: &HealProgressSample,
    current: &HealProgressSample,
) -> Result<()> {
    ensure!(
        previous.identity == current.identity
            && previous.observer == current.observer
            && matches!(&current.observer, HealObserverIdentity::AdminOperation { operation_id } if !operation_id.trim().is_empty())
            && previous.observed_at_ms > 0
            && previous.observed_at_ms < current.observed_at_ms
            && previous.state == HealProgressState::Running
            && current.state == HealProgressState::Running
            && previous.failed == 0
            && current.failed == 0
            && current.scanned >= previous.scanned
            && current.repaired >= previous.repaired
            && (current.scanned > previous.scanned || current.repaired > previous.repaired),
        "partition-during-heal requires progressing owned nonterminal heal samples"
    );
    Ok(())
}

impl HealPartitionEvidence {
    pub(crate) fn validate_chain(
        &self,
        replacement: &FreshVolumeReplacementProof,
        summary: &HealSummary,
        progress: &[HealProgressSample],
        history: &[OperationRecord],
        transcript: &[HealWireReceipt],
        read_proof: &FreshVolumeReadMatrixEvidence,
    ) -> Result<()> {
        replacement.validate()?;
        ensure!(
            self.schema_version == 1
                && self.identity.scenario == "network-partition-during-heal"
                && self.identity == replacement.identity
                && self.identity == summary.identity
                && summary.case == StorageRecoveryCase::FreshVolumeReplacementPartitionDuringHeal
                && self.replacement == replacement.replacement
                && self.pods.len() == 4
                && !self.chaos_namespace.trim().is_empty()
                && self.source_pod_names == BTreeSet::from([self.replacement.pod.clone()])
                && !self.object_key.trim().is_empty()
                && !self.version_id.trim().is_empty()
                && self.version_id != "null"
                && self.expected_sha256.len() == 64
                && self
                    .expected_sha256
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit()),
            "heal partition proof does not identify the run-owned replacement and owned heal"
        );
        ensure!(
            read_proof.sealed_version()
                == (
                    self.object_key.as_str(),
                    self.version_id.as_str(),
                    self.expected_sha256.as_str()
                )
                && read_proof.chaos_namespace() == self.chaos_namespace,
            "partition probes and repaired-drive verification address different sealed versions"
        );
        let target = self
            .pods
            .iter()
            .find(|pod| pod.name == self.replacement.pod)
            .context("replacement Pod is absent from the network identity set")?;
        ensure!(
            target.namespace == self.replacement.namespace
                && target.uid == self.replacement.pod_uid
                && target.container_id == self.replacement.rustfs_container_id
                && target.node == self.replacement.node
                && self
                    .pods
                    .iter()
                    .all(|pod| pod.namespace == self.replacement.namespace),
            "heal partition selected a different replacement Pod generation"
        );
        let apply_started = self
            .apply_started_at_ms
            .context("partition was never applied")?;
        let delete_started = self
            .delete_started_at_ms
            .context("partition deletion was not attempted")?;
        let deleted = self
            .deleted_at_ms
            .context("partition removal was not confirmed")?;
        ensure!(
            apply_started > 0 && apply_started < delete_started && delete_started <= deleted,
            "partition lifecycle timestamps are missing or unordered"
        );
        ensure!(
            self.snapshots.len() >= 2,
            "partition requires controller samples before and after its probes"
        );
        let first = self
            .snapshots
            .first()
            .expect("count checked")
            .observed_at_ms;
        let last = self.snapshots.last().expect("count checked").observed_at_ms;
        ensure!(
            apply_started <= first
                && first < last
                && last <= delete_started
                && delete_started - first >= HEAL_PARTITION_HOLD_MILLIS
                && deleted < summary.completed_at_ms,
            "partition did not span its bounded probes or precede heal completion"
        );
        let contract = ScopedNetworkPartitionEvidenceContract {
            chaos_namespace: &self.chaos_namespace,
            target_namespace: &self.replacement.namespace,
            tenant: &self.replacement.tenant,
            run_id: &self.identity.run_id,
            scenario: &self.identity.scenario,
            source_pod_names: &self.source_pod_names,
            peer_pod_names: &self.peer_pod_names,
            duration_seconds: HEAL_PARTITION_TTL_SECONDS,
        };
        let submitted: Value =
            serde_yaml_ng::from_str(&self.manifest).context("decode heal partition manifest")?;
        let mut previous_snapshot_at = 0;
        let mut resource_uid = None;
        for snapshot in &self.snapshots {
            ensure!(
                snapshot.sha256 == crate::fault::workload::sha256_hex(snapshot.body.as_bytes())
                    && snapshot.observed_at_ms >= previous_snapshot_at
                    && snapshot.observed_at_ms >= first
                    && snapshot.observed_at_ms <= last,
                "partition controller samples are unordered or have another kind"
            );
            let wrapper: Value = serde_json::from_str(&snapshot.body)?;
            ensure!(
                wrapper.get("resource_kind").and_then(Value::as_str) == Some("networkchaos"),
                "heal partition snapshot contains another controller kind"
            );
            let captured = wrapper
                .get("chaos_status")
                .context("network controller status is absent")?;
            validate_scoped_network_partition_snapshot(captured, &contract)?;
            for pointer in [
                "/metadata/name",
                "/spec/action",
                "/spec/direction",
                "/spec/duration",
                "/spec/mode",
                "/spec/selector/namespaces",
                "/spec/selector/labelSelectors",
                "/spec/selector/pods",
                "/spec/target/mode",
                "/spec/target/selector/namespaces",
                "/spec/target/selector/labelSelectors",
                "/spec/target/selector/pods",
            ] {
                ensure!(
                    captured.pointer(pointer).is_some()
                        && captured.pointer(pointer) == submitted.pointer(pointer),
                    "partition controller {pointer} differs from the submitted exact selector manifest"
                );
            }
            let uid = captured
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .filter(|uid| !uid.trim().is_empty())
                .context("partition controller snapshot lacks a resource UID")?
                .to_owned();
            ensure!(
                resource_uid
                    .as_ref()
                    .is_none_or(|expected| expected == &uid),
                "partition controller resource was replaced during the active window"
            );
            resource_uid = Some(uid);
            previous_snapshot_at = snapshot.observed_at_ms;
        }
        for (observations, active, start, end) in [
            (&self.baseline_connectivity, false, 1, apply_started),
            (&self.active_connectivity, true, first, last),
            (
                &self.restored_connectivity,
                false,
                deleted,
                summary.completed_at_ms,
            ),
        ] {
            validate_connectivity(
                observations,
                &self.pods,
                &self.source_pod_names,
                &self.peer_pod_names,
                active,
            )?;
            ensure!(
                observations
                    .iter()
                    .all(|probe| probe.started_at_ms >= start && probe.completed_at_ms <= end),
                "Pod-network connectivity observations escaped their partition lifecycle phase"
            );
        }
        summary.validate_progress(
            progress,
            Some((
                &self.replacement.rustfs_drive_uuid,
                self.replacement.pool_index,
                self.replacement.set_index,
            )),
        )?;
        let before = progress
            .iter()
            .filter(|sample| sample.observed_at_ms <= apply_started)
            .collect::<Vec<_>>();
        let [.., previous, current] = before.as_slice() else {
            anyhow::bail!("partition has no pair of pre-injection heal observations")
        };
        require_moving_heal(previous, current)?;
        let active = progress
            .iter()
            .filter(|sample| sample.observed_at_ms >= first && sample.observed_at_ms <= last)
            .collect::<Vec<_>>();
        ensure!(
            active.len() >= 2
                && active
                    .iter()
                    .all(|sample| sample.state == HealProgressState::Running && sample.failed == 0),
            "owned heal was not observed nonterminal on both sides of the partition probes"
        );
        for sample in before.into_iter().chain(active.iter().copied()) {
            validate_raw_heal_sample(sample, transcript, &self.identity.bucket, &self.replacement)?;
        }
        validate_raw_heal_response(
            progress
                .last()
                .context("owned heal has no terminal sample")?,
            transcript,
            &self.identity.bucket,
            &self.replacement,
            HealProgressState::Completed,
        )?;
        let HealObserverIdentity::AdminOperation { operation_id } = &summary.observer else {
            anyhow::bail!("heal partition has another observer kind")
        };
        let owned_starts = transcript
            .iter()
            .filter(|receipt| {
                receipt.method == "POST"
                    && receipt.path == format!("/rustfs/admin/v3/heal/{}", self.identity.bucket)
                    && receipt.query.is_empty()
                    && (200..300).contains(&receipt.status)
                    && serde_json::from_str::<Value>(&receipt.response_body).is_ok_and(|body| {
                        body.get("clientToken").and_then(Value::as_str)
                            == Some(operation_id.as_str())
                    })
            })
            .collect::<Vec<_>>();
        let [start] = owned_starts.as_slice() else {
            anyhow::bail!("heal partition lacks a unique accepted start for its owned token")
        };
        let start_body: Value = serde_json::from_str(
            start
                .request_body
                .as_deref()
                .context("owned heal start has no raw request body")?,
        )?;
        ensure!(
            start.observed_at_ms <= apply_started
                && start_body.get("recursive").and_then(Value::as_bool) == Some(true)
                && start_body.get("scanMode").and_then(Value::as_u64) == Some(2)
                && start_body.get("pool").and_then(Value::as_u64)
                    == Some(u64::from(self.replacement.pool_index))
                && start_body.get("set").and_then(Value::as_u64)
                    == Some(u64::from(self.replacement.set_index)),
            "partition progress does not originate from the scoped recursive AdminDeep request"
        );
        let active_first = active.first().expect("count checked").observed_at_ms;
        let active_last = active.last().expect("count checked").observed_at_ms;
        ensure!(
            !self.read_operation_ids.is_empty(),
            "partition has no exact-version S3 probe history"
        );
        let mut ids = BTreeSet::new();
        for id in &self.read_operation_ids {
            ensure!(ids.insert(id), "partition S3 probe operation is duplicated");
            let matches = history
                .iter()
                .filter(|record| &record.id == id)
                .collect::<Vec<_>>();
            let [record] = matches.as_slice() else {
                anyhow::bail!("partition S3 probe is absent or duplicated in history")
            };
            ensure!(
                record.scenario == self.identity.scenario
                    && record.run_id.as_deref() == Some(self.identity.run_id.as_str())
                    && record.bucket == self.identity.bucket
                    && record.kind == OperationKind::Get
                    && record.key.as_deref() == Some(self.object_key.as_str())
                    && record.version_id.as_deref() == Some(self.version_id.as_str())
                    && record.range.is_none()
                    && record.started_at_ms >= active_first
                    && record.ended_at_ms <= active_last
                    && record.started_at_ms <= record.ended_at_ms,
                "partition S3 probe is not an exact sealed-version GET bracketed by active heal samples"
            );
            match record.outcome {
                OperationOutcome::Ok => ensure!(
                    record.http_status == Some(200)
                        && record.value_sha256.as_deref() == Some(self.expected_sha256.as_str())
                        && record.size_bytes.is_some_and(|size| size > 0),
                    "successful partition GET did not return the complete committed version"
                ),
                OperationOutcome::Failed
                | OperationOutcome::Timeout
                | OperationOutcome::Unknown => {}
                OperationOutcome::NotFound => {
                    anyhow::bail!("committed version disappeared during heal partition")
                }
            }
        }
        Ok(())
    }
}

pub(crate) fn validate_raw_heal_sample(
    sample: &HealProgressSample,
    transcript: &[HealWireReceipt],
    bucket: &str,
    replacement: &StorageVolumeIdentity,
) -> Result<()> {
    validate_raw_heal_response(
        sample,
        transcript,
        bucket,
        replacement,
        HealProgressState::Running,
    )
}

fn validate_raw_heal_response(
    sample: &HealProgressSample,
    transcript: &[HealWireReceipt],
    bucket: &str,
    replacement: &StorageVolumeIdentity,
    expected_state: HealProgressState,
) -> Result<()> {
    let HealObserverIdentity::AdminOperation { operation_id } = &sample.observer else {
        anyhow::bail!("partition requires an owned AdminDeep heal operation")
    };
    let matching = transcript
        .iter()
        .filter(|receipt| {
            receipt.observed_at_ms == sample.observed_at_ms
                && receipt.query.get("clientToken") == Some(operation_id)
        })
        .collect::<Vec<_>>();
    let [receipt] = matching.as_slice() else {
        anyhow::bail!("heal sample has no unique raw owned-token status response")
    };
    ensure!(
        receipt.method == "POST"
            && receipt.path == format!("/rustfs/admin/v3/heal/{bucket}")
            && receipt.query == BTreeMap::from([("clientToken".to_string(), operation_id.clone())])
            && receipt.request_body.is_none()
            && (200..300).contains(&receipt.status),
        "heal sample did not come from the exact owned-token status request"
    );
    let raw: Value = serde_json::from_str(&receipt.response_body)?;
    let expected_summary = match expected_state {
        HealProgressState::Running => "running",
        HealProgressState::Completed => "finished",
        _ => anyhow::bail!("partition status requires running or completed evidence"),
    };
    ensure!(
        raw.get("summary").and_then(Value::as_str) == Some(expected_summary)
            && raw
                .pointer("/progress/objectsScanned")
                .and_then(Value::as_u64)
                == Some(sample.scanned)
            && raw
                .pointer("/progress/objectsHealed")
                .and_then(Value::as_u64)
                == Some(sample.repaired)
            && raw
                .pointer("/progress/objectsFailed")
                .and_then(Value::as_u64)
                == Some(0)
            && sample.failed == 0
            && sample.state == expected_state,
        "partition status is not derived from the explicit owned RustFS state and progress counters"
    );
    let normalized: RustfsHealStatusResponse = serde_json::from_str(
        &sample
            .status_evidence
            .as_ref()
            .context("heal sample has no normalized status receipt")?
            .response_body,
    )?;
    ensure!(
        normalized.target_drive_uuid.as_deref() == Some(replacement.rustfs_drive_uuid.as_str())
            && normalized.pool_index == replacement.pool_index
            && normalized.set_index == replacement.set_index,
        "heal sample belongs to another replacement drive or erasure set"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::storage_recovery::{
        EmptyVolumeObservation, EmptyVolumeScanResponse, HealMode, HealStatusEvidence,
    };

    fn sample(at: u64, scanned: u64, state: HealProgressState) -> HealProgressSample {
        HealProgressSample {
            schema_version: 1,
            identity: StorageRecoveryArtifactIdentity {
                run_id: "run".to_string(),
                scenario: "network-partition-during-heal".to_string(),
                case_name: "case".to_string(),
                bucket: "bucket".to_string(),
            },
            observer: HealObserverIdentity::AdminOperation {
                operation_id: "owned-token".to_string(),
            },
            observed_at_ms: at,
            state,
            scanned,
            repaired: scanned,
            failed: 0,
            status_evidence: None,
        }
    }

    #[test]
    fn partition_trigger_rejects_accepted_idle_completed_and_foreign_heal() {
        let previous = sample(100, 1, HealProgressState::Running);
        let moving = sample(200, 2, HealProgressState::Running);
        require_moving_heal(&previous, &moving).expect("actual progress");
        assert!(
            require_moving_heal(&previous, &sample(200, 1, HealProgressState::Running)).is_err()
        );
        assert!(
            require_moving_heal(&previous, &sample(200, 2, HealProgressState::Queued)).is_err()
        );
        assert!(
            require_moving_heal(&previous, &sample(200, 2, HealProgressState::Completed)).is_err()
        );
        let mut foreign = moving.clone();
        foreign.observer = HealObserverIdentity::AdminOperation {
            operation_id: "foreign".to_string(),
        };
        assert!(require_moving_heal(&previous, &foreign).is_err());
        let mut failed = moving;
        failed.failed = 1;
        assert!(require_moving_heal(&previous, &failed).is_err());
    }

    fn wire_fixture() -> (
        HealProgressSample,
        Vec<HealWireReceipt>,
        StorageVolumeIdentity,
    ) {
        let replacement = StorageVolumeIdentity {
            target_proof_sha256: "a".repeat(64),
            host_storage_proof_sha256: "b".repeat(64),
            rustfs_deployment_id: "deployment".to_string(),
            namespace: "namespace".to_string(),
            tenant: "tenant".to_string(),
            pod: "rustfs-0".to_string(),
            pod_uid: "pod-uid".to_string(),
            rustfs_container_id: "container".to_string(),
            volume_name: "data".to_string(),
            persistent_volume_claim: "claim".to_string(),
            persistent_volume_claim_uid: "claim-uid".to_string(),
            persistent_volume: "pv".to_string(),
            persistent_volume_uid: "pv-uid".to_string(),
            node: "node".to_string(),
            node_uid: "node-uid".to_string(),
            storage_class: "local".to_string(),
            local_volume_path: "/lab/volume".to_string(),
            mount_path: "/data".to_string(),
            canonical_device: "/dev/mapper/lab".to_string(),
            target_mount_namespace_id: "mnt:1".to_string(),
            filesystem_uuid: "filesystem".to_string(),
            rustfs_drive_uuid: "drive-new".to_string(),
            pool_index: 0,
            set_index: 0,
            observed_at_ms: 1,
        };
        let mut sample = sample(200, 2, HealProgressState::Running);
        let normalized = RustfsHealStatusResponse {
            observer: sample.observer.clone(),
            observed_at_ms: sample.observed_at_ms,
            state: sample.state,
            scanned: sample.scanned,
            repaired: sample.repaired,
            failed: 0,
            cluster_definitive: true,
            target_drive_uuid: Some(replacement.rustfs_drive_uuid.clone()),
            pool_index: 0,
            set_index: 0,
        };
        let body = serde_json::to_string(&normalized).expect("normalized status");
        sample.status_evidence = Some(HealStatusEvidence {
            api_revision: "rustfs-admin-v3-heal".to_string(),
            response_sha256: crate::fault::workload::sha256_hex(body.as_bytes()),
            response_body: body,
        });
        let receipt = HealWireReceipt {
            observed_at_ms: 200, method: "POST".to_string(), path: "/rustfs/admin/v3/heal/bucket".to_string(),
            query: BTreeMap::from([("clientToken".to_string(), "owned-token".to_string())]), request_body: None,
            status: 200, request_id: Some("request".to_string()),
            response_body: r#"{"summary":"running","progress":{"objectsScanned":2,"objectsHealed":2,"objectsFailed":0}}"#.to_string(),
        };
        (sample, vec![receipt], replacement)
    }

    #[test]
    fn heal_partition_requires_real_owned_wire_progress() {
        let (sample, transcript, replacement) = wire_fixture();
        validate_raw_heal_sample(&sample, &transcript, "bucket", &replacement)
            .expect("owned running progress");
        for body in [
            r#"{"summary":"running"}"#,
            r#"{"summary":"finished","progress":{"objectsScanned":2,"objectsHealed":2,"objectsFailed":0}}"#,
            r#"{"summary":"running","progress":{"objectsScanned":1,"objectsHealed":2,"objectsFailed":0}}"#,
            r#"{"summary":"running","progress":{"objectsScanned":2,"objectsHealed":2,"objectsFailed":1}}"#,
        ] {
            let mut altered = transcript.clone();
            altered[0].response_body = body.to_string();
            assert!(validate_raw_heal_sample(&sample, &altered, "bucket", &replacement).is_err());
        }
        let mut foreign = transcript.clone();
        foreign[0]
            .query
            .insert("clientToken".to_string(), "foreign-token".to_string());
        assert!(validate_raw_heal_sample(&sample, &foreign, "bucket", &replacement).is_err());
        let mut cancellation = transcript.clone();
        cancellation[0]
            .query
            .insert("forceStop".to_string(), "true".to_string());
        assert!(validate_raw_heal_sample(&sample, &cancellation, "bucket", &replacement).is_err());
        let mut duplicate = transcript.clone();
        duplicate.push(transcript[0].clone());
        assert!(validate_raw_heal_sample(&sample, &duplicate, "bucket", &replacement).is_err());
        let mut other_drive = replacement;
        other_drive.rustfs_drive_uuid = "drive-other".to_string();
        assert!(validate_raw_heal_sample(&sample, &transcript, "bucket", &other_drive).is_err());
    }

    struct ChainFixture {
        evidence: HealPartitionEvidence,
        replacement: FreshVolumeReplacementProof,
        summary: HealSummary,
        progress: Vec<HealProgressSample>,
        history: Vec<OperationRecord>,
        transcript: Vec<HealWireReceipt>,
        read_proof: FreshVolumeReadMatrixEvidence,
    }

    impl ChainFixture {
        fn validate(&self) -> Result<()> {
            self.evidence.validate_chain(
                &self.replacement,
                &self.summary,
                &self.progress,
                &self.history,
                &self.transcript,
                &self.read_proof,
            )
        }
    }

    fn chain_fixture() -> ChainFixture {
        let (_, _, mut volume) = wire_fixture();
        volume.observed_at_ms = 50;
        let mut original = volume.clone();
        original.observed_at_ms = 1;
        original.persistent_volume_claim_uid = "original-claim".to_string();
        original.persistent_volume_uid = "original-pv".to_string();
        original.canonical_device = "/dev/original".to_string();
        original.filesystem_uuid = "original-filesystem".to_string();
        let identity = sample(100, 1, HealProgressState::Running).identity;
        let scan = EmptyVolumeScanResponse {
            persistent_volume_uid: volume.persistent_volume_uid.clone(),
            canonical_device: volume.canonical_device.clone(),
            filesystem_uuid: volume.filesystem_uuid.clone(),
            rustfs_process_can_access_volume: false,
            scan_started_at_ms: 10,
            scan_completed_at_ms: 20,
            exhaustive: true,
            data_entries: Vec::new(),
        };
        let body = serde_json::to_string(&scan).unwrap();
        let replacement = FreshVolumeReplacementProof::prove(
            identity.clone(),
            original,
            volume.clone(),
            EmptyVolumeObservation {
                observed_at_ms: 20,
                persistent_volume_uid: scan.persistent_volume_uid,
                canonical_device: scan.canonical_device,
                filesystem_uuid: scan.filesystem_uuid,
                rustfs_process_can_access_volume: false,
                data_entries: Vec::new(),
                scan_response_sha256: crate::fault::workload::sha256_hex(body.as_bytes()),
                scan_response_body: body,
            },
        )
        .expect("replacement generation");
        let pods = (0..4)
            .map(|index| PodNetworkIdentity {
                namespace: volume.namespace.clone(),
                name: format!("rustfs-{index}"),
                uid: if index == 0 {
                    volume.pod_uid.clone()
                } else {
                    format!("uid-{index}")
                },
                container_id: if index == 0 {
                    volume.rustfs_container_id.clone()
                } else {
                    format!("container-{index}")
                },
                node: if index == 0 {
                    volume.node.clone()
                } else {
                    format!("node-{index}")
                },
                pod_ip: format!("10.42.0.{}", index + 1),
                listener_port: 9000,
            })
            .collect::<Vec<_>>();
        let source = BTreeSet::from([volume.pod.clone()]);
        let peer = pods
            .iter()
            .filter(|pod| pod.name != volume.pod)
            .map(|pod| pod.name.clone())
            .collect::<BTreeSet<_>>();
        let matrix = |at, active| {
            pods.iter()
                .flat_map(|left| {
                    let sources = &source;
                    pods.iter()
                        .filter(move |right| left.name != right.name)
                        .map(move |right| {
                            let blocked = active
                                && sources.contains(&left.name) != sources.contains(&right.name);
                            PodConnectivityObservation {
                                source: left.clone(),
                                target: right.clone(),
                                started_at_ms: at,
                                completed_at_ms: at + 1,
                                exit_code: Some(if blocked { 28 } else { 0 }),
                                http_status: Some(if blocked { 0 } else { 200 }),
                                connect_seconds: Some(if blocked { 0.0 } else { 0.001 }),
                                remote_ip: if blocked {
                                    None
                                } else {
                                    Some(right.pod_ip.clone())
                                },
                                stdout: if blocked {
                                    "000\t0.000000\t".to_string()
                                } else {
                                    format!("200\t0.001000\t{}", right.pod_ip)
                                },
                                stderr: String::new(),
                            }
                        })
                })
                .collect::<Vec<_>>()
        };
        let config =
            crate::fault::config::FaultTestConfig::for_test("real-cluster", "local-static");
        let mut cluster = config.cluster.clone();
        cluster.test_namespace = volume.namespace.clone();
        cluster.tenant_name = volume.tenant.clone();
        let manifest =
            crate::fault::backends::chaos_mesh::NetworkChaosSpec::partition_between_rustfs_pods(
                &cluster,
                "chaos-mesh",
                "run",
                "network-partition-during-heal",
                std::time::Duration::from_secs(60),
                &source,
                &peer,
            )
            .expect("scoped network manifest")
            .manifest();
        let mut controller: Value = serde_yaml_ng::from_str(&manifest).unwrap();
        controller["metadata"]["uid"] = serde_json::json!("network-uid");
        controller["status"] = serde_json::json!({"conditions":[{"type":"Selected","status":"True"},
            {"type":"AllInjected","status":"True"},{"type":"AllRecovered","status":"False"}],
            "experiment":{"desiredPhase":"Run","containerRecords":pods.iter().map(|pod| serde_json::json!({
                "id":format!("{}/{}", pod.namespace, pod.name), "selectorKey":if source.contains(&pod.name){"."}else{".Target"},
                "phase":"Injected","injectedCount":1})).collect::<Vec<_>>()}});
        controller["spec"]["selector"]["expressionSelectors"] = serde_json::json!([]);
        let snapshots = [1000, 12000]
            .map(|at| {
                let body = serde_json::to_string(
                    &serde_json::json!({"resource_kind":"networkchaos", "chaos_status":controller}),
                )
                .unwrap();
                ControllerSnapshotEvidence {
                    phase: "active".to_string(),
                    observed_at_ms: at,
                    sha256: crate::fault::workload::sha256_hex(body.as_bytes()),
                    body,
                }
            })
            .to_vec();
        let progress = [
            (100, 1, HealProgressState::Running),
            (200, 2, HealProgressState::Running),
            (1100, 3, HealProgressState::Running),
            (11900, 4, HealProgressState::Running),
            (15000, 5, HealProgressState::Completed),
        ]
        .map(|(at, scanned, state)| {
            let mut sample = sample(at, scanned, state);
            let response = RustfsHealStatusResponse {
                observer: sample.observer.clone(),
                observed_at_ms: at,
                state,
                scanned,
                repaired: scanned,
                failed: 0,
                cluster_definitive: true,
                target_drive_uuid: Some(volume.rustfs_drive_uuid.clone()),
                pool_index: 0,
                set_index: 0,
            };
            let body = serde_json::to_string(&response).unwrap();
            sample.status_evidence = Some(HealStatusEvidence {
                api_revision: "rustfs-admin-v3-heal".to_string(),
                response_sha256: crate::fault::workload::sha256_hex(body.as_bytes()),
                response_body: body,
            });
            sample
        })
        .to_vec();
        let summary = HealSummary {
            schema_version: 1,
            identity: identity.clone(),
            case: StorageRecoveryCase::FreshVolumeReplacementPartitionDuringHeal,
            observer: progress[0].observer.clone(),
            mode: HealMode::AdminDeep,
            target_drive_uuid: Some(volume.rustfs_drive_uuid.clone()),
            pool_index: 0,
            set_index: 0,
            cluster_definitive: true,
            started_at_ms: 90,
            completed_at_ms: 15000,
            scanned: 5,
            repaired: 5,
            failed: 0,
            state: HealProgressState::Completed,
        };
        let mut transcript = progress.iter().map(|sample| HealWireReceipt { observed_at_ms:sample.observed_at_ms,
            method:"POST".to_string(), path:"/rustfs/admin/v3/heal/bucket".to_string(),
            query:BTreeMap::from([("clientToken".to_string(), "owned-token".to_string())]), request_body:None,
            status:200, request_id:None, response_body:serde_json::json!({"summary":if sample.state==HealProgressState::Running{"running"}else{"finished"},
                "progress":{"objectsScanned":sample.scanned,"objectsHealed":sample.repaired,"objectsFailed":0}}).to_string() }).collect::<Vec<_>>();
        transcript.push(HealWireReceipt {
            observed_at_ms: 90,
            method: "POST".to_string(),
            path: "/rustfs/admin/v3/heal/bucket".to_string(),
            query: BTreeMap::new(),
            request_body: Some(r#"{"recursive":true,"scanMode":2,"pool":0,"set":0}"#.to_string()),
            status: 200,
            request_id: None,
            response_body: r#"{"clientToken":"owned-token"}"#.to_string(),
        });
        let history = vec![serde_json::from_value(serde_json::json!({"id":"get", "scenario":identity.scenario,
            "run_id":"run","kind":"get","bucket":"bucket","key":"key","value_sha256":"c".repeat(64),
            "size_bytes":1024,"version_id":"version","started_at_ms":2000,"ended_at_ms":2100,"outcome":"ok","http_status":200})).unwrap()];
        let inspection = serde_json::json!({"capturedAtMs":0,"helperPod":"helper","targetPod":"rustfs-0","targetPodUid":"pod-uid",
            "targetContainerId":"container","mountPath":"/data","request":{"volumeRoot":"/volume","deploymentId":"deployment",
                "driveUuid":"drive-new","mountDeviceId":"1:1","objectDirectory":"bucket/key","bucket":"bucket","objectKey":"key",
                "objectSha256":"c".repeat(64),"versionId":"version","selectedPartNumber":1},"responseSha256":"a".repeat(64),
            "response":{"observedAtMs":0,"inspection":{"mountDeviceId":"1:1","driveUuid":"drive-new","formatJsonSha256":"a".repeat(64),
                "xlMetaSha256":"b".repeat(64),"layout":{"inspectorRevision":"xl2-1.3-header3-meta3","profile":{"fileMajor":1,"fileMinor":3,
                    "headerVersion":3,"metadataVersion":3},"versionId":"version","dataDirectory":"directory","erasureDataShards":2,
                    "erasureParityShards":2,"erasureIndex":1,"partNumbers":[1],"partSizes":[1024],"relativePartPaths":["bucket/key/directory/part.1"]},
                "selectedPart":{"partNumber":1,"relativePartPath":"bucket/key/directory/part.1","shardDeviceId":"1:1","shardInode":1,
                    "shardSizeBytes":1024,"originalSha256":"c".repeat(64)}}}});
        let read = serde_json::json!({"phase":"read","operationId":"get","startedAtMs":2000,"endedAtMs":2100,
            "outcome":"ok","httpStatus":200,"observedSha256":"c".repeat(64)});
        let read_proof = serde_json::from_value(serde_json::json!({"schemaVersion":1,"identity":identity,"chaosNamespace":"chaos-mesh",
            "shape":{"poolIndex":0,"setIndex":0,"totalShards":4,"payloadDataShards":2,"payloadParityShards":2,"serverCount":4,"volumesPerServer":1},
            "membership":{"members":[]},"repairedDriveUuid":"drive-new","objectKey":"key","versionId":"version","expectedSha256":"c".repeat(64),
            "ordinaryGetOperationId":"get","shardBeforeFault":inspection,"shardAfterFault":inspection,
            "siblingFault":{"targetProofSha256":"a".repeat(64),"targetProofBody":"{}","selectedTargets":[],"unavailableDriveUuids":[],
                "activeAtMs":0,"deleteStartedAtMs":0,"deletedAtMs":0,"snapshots":[]},
            "replacementPathFault":{"exactContainerPath":"/data/bucket/key/part.1","manifestSha256":"a".repeat(64),"manifestBody":"{}",
                "selectedTarget":"rustfs-0","activeAtMs":0,"deleteStartedAtMs":0,"deletedAtMs":0,"snapshots":[]},
            "replacementAvailable":read,"replacementBlocked":read,"replacementRestored":read})).unwrap();
        let evidence = HealPartitionEvidence {
            schema_version: 1,
            identity,
            replacement: volume,
            chaos_namespace: "chaos-mesh".to_string(),
            pods: pods.clone(),
            source_pod_names: source.clone(),
            peer_pod_names: peer,
            object_key: "key".to_string(),
            version_id: "version".to_string(),
            expected_sha256: "c".repeat(64),
            manifest,
            baseline_connectivity: matrix(300, false),
            apply_started_at_ms: Some(900),
            snapshots,
            active_connectivity: matrix(2000, true),
            read_operation_ids: vec!["get".to_string()],
            delete_started_at_ms: Some(13000),
            deleted_at_ms: Some(13100),
            restored_connectivity: matrix(14000, false),
        };
        ChainFixture {
            evidence,
            replacement,
            summary,
            progress,
            history,
            transcript,
            read_proof,
        }
    }

    #[test]
    fn heal_partition_chain_binds_real_network_progress_and_read_windows() {
        let fixture = chain_fixture();
        fixture
            .validate()
            .expect("complete partition chain, including API default fields");
        let mut changed = chain_fixture();
        changed.evidence.active_connectivity[0].exit_code = Some(0);
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed.evidence.delete_started_at_ms = Some(2000);
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed.history[0].ended_at_ms = 12000;
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed.history[0].outcome = OperationOutcome::NotFound;
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed.history[0].value_sha256 = Some("d".repeat(64));
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed.transcript.last_mut().unwrap().request_body =
            Some(r#"{"recursive":true,"scanMode":0,"pool":0,"set":0}"#.to_string());
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        let snapshot = changed.evidence.snapshots.last_mut().unwrap();
        let mut body: Value = serde_json::from_str(&snapshot.body).unwrap();
        body["chaos_status"]["metadata"]["uid"] = serde_json::json!("replacement-controller");
        snapshot.body = body.to_string();
        snapshot.sha256 = crate::fault::workload::sha256_hex(snapshot.body.as_bytes());
        assert!(changed.validate().is_err());
    }

    #[test]
    fn heal_partition_completion_requires_the_owned_terminal_wire_receipt() {
        let mut changed = chain_fixture();
        changed.transcript.iter_mut().find(|receipt| receipt.observed_at_ms == 15000).unwrap().response_body =
            r#"{"summary":"running","progress":{"objectsScanned":5,"objectsHealed":5,"objectsFailed":0}}"#.to_string();
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed
            .transcript
            .retain(|receipt| receipt.observed_at_ms != 15000);
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed
            .transcript
            .iter_mut()
            .find(|receipt| receipt.observed_at_ms == 15000)
            .unwrap()
            .query
            .insert("clientToken".to_string(), "foreign-token".to_string());
        assert!(changed.validate().is_err());
        let mut changed = chain_fixture();
        changed.transcript.iter_mut().find(|receipt| receipt.observed_at_ms == 15000).unwrap().response_body =
            r#"{"summary":"finished","progress":{"objectsScanned":5,"objectsHealed":4,"objectsFailed":0}}"#.to_string();
        assert!(changed.validate().is_err());
    }
}
