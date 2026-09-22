// Copyright 2025 RustFS Team
// SPDX-License-Identifier: Apache-2.0

//! Two-volume device-mapper reference for the payload P boundary. Filesystem
//! metadata can be cached, so activation is proved below the filesystem with
//! a direct block read and a table that rejects both reads and writes.

use super::{host, host_command};
use crate::fault::{
    config::FaultTestConfig,
    fault_lifecycle::{AppliedFault, FaultLifecyclePort},
    host_storage::{DM_QUORUM_EIO_KIND, DmStatusSnapshot, HostStorageMutationProof},
    preflight::TargetProof,
    quorum::{QuorumCaseClass, QuorumVolumeTargetProof},
    reporting::FaultStatusSnapshot,
    scenarios::FaultScenario,
};
use crate::framework::{artifacts::ArtifactCollector, config::ClusterTestConfig};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetFile {
    targets: Vec<TargetConfig>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TargetConfig {
    node: String,
    mapper_name: String,
    mount_path: String,
    persistent_volume: String,
    observer_namespace: String,
    observer_pod: String,
    state_file: PathBuf,
    state_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DirectReadReceipt {
    pub(crate) device: String,
    pub(crate) run_id: String,
    pub(crate) context: String,
    pub(crate) namespace: String,
    pub(crate) pod: String,
    pub(crate) node: String,
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) transport_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct DirectReadSample {
    pub(crate) before: DmStatusSnapshot,
    pub(crate) read: DirectReadReceipt,
    pub(crate) after: DmStatusSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QuorumDmTargetEvidence {
    pub(crate) proof: HostStorageMutationProof,
    pub(crate) baseline: DirectReadReceipt,
    pub(crate) activation_started_at_ms: u64,
    pub(crate) activated_at_ms: u64,
    pub(crate) status: DmStatusSnapshot,
    pub(crate) probes: Vec<DirectReadSample>,
    pub(crate) post_cleanup: Option<crate::fault::host_storage::HostStoragePostCleanupObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct QuorumDmStatusSnapshot {
    pub(crate) schema_version: u8,
    pub(crate) run_id: String,
    pub(crate) stage: String,
    pub(crate) targets: Vec<QuorumDmTargetEvidence>,
}

fn child_run_id(run_id: &str, index: usize) -> String {
    format!("qdm{index}-{:x}", Sha256::digest(run_id.as_bytes()))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn direct_read(
    config: &ClusterTestConfig,
    namespace: &str,
    pod: &str,
    device: &str,
    run_id: &str,
    node: &str,
) -> Result<DirectReadReceipt> {
    ensure!(
        device.starts_with("/dev/dm-")
            && device[8..].bytes().all(|c| c.is_ascii_digit())
            && device.len() > 8,
        "direct probe requires a proven canonical mapper device"
    );
    let started_at_ms = now_ms();
    // Arguments are passed separately through the existing remote-exit framing.
    // O_DIRECT avoids the page cache; no writes are issued to a live filesystem.
    let output = host_command::run(
        config,
        namespace,
        pod,
        [
            "/usr/bin/timeout".to_string(),
            "10".into(),
            "/usr/bin/env".into(),
            "LC_ALL=C".into(),
            "/usr/bin/dd".into(),
            format!("if={device}"),
            "of=/dev/null".into(),
            "bs=4096".into(),
            "count=1".into(),
            "iflag=direct,fullblock".into(),
        ],
    );
    let (exit_code, stdout, stderr, transport_error) = match output {
        Ok(output) => (output.code, output.stdout, output.stderr, None),
        Err(error) => (
            None,
            String::new(),
            String::new(),
            Some(format!("{error:#}")),
        ),
    };
    Ok(DirectReadReceipt {
        device: device.into(),
        run_id: run_id.into(),
        context: config.context.clone(),
        namespace: namespace.into(),
        pod: pod.into(),
        node: node.into(),
        started_at_ms,
        completed_at_ms: now_ms(),
        exit_code,
        stdout,
        stderr,
        transport_error,
    })
}

fn validate_receipt(receipt: &DirectReadReceipt, proof: &HostStorageMutationProof) -> Result<()> {
    ensure!(
        receipt.device == proof.target.canonical_device
            && receipt.run_id == proof.run_id
            && receipt.context == proof.context
            && receipt.node == proof.target.node
            && receipt.started_at_ms > 0
            && receipt.completed_at_ms >= receipt.started_at_ms
            && receipt.completed_at_ms - receipt.started_at_ms <= 30_000,
        "direct-read receipt device or time window is invalid"
    );
    Ok(())
}

fn baseline_passed(receipt: &DirectReadReceipt) -> bool {
    receipt.transport_error.is_none()
        && receipt.exit_code == Some(0)
        && receipt.stdout.is_empty()
        && receipt.stderr.contains("4096 bytes")
}

fn read_failed_eio(receipt: &DirectReadReceipt) -> bool {
    receipt.transport_error.is_none()
        && receipt.exit_code == Some(1)
        && receipt.stdout.is_empty()
        && receipt
            .stderr
            .contains(&format!("error reading '{}'", receipt.device))
        && receipt.stderr.contains("Input/output error")
        && receipt.stderr.contains("0 bytes")
}

fn quorum_proof(proof: &TargetProof) -> Result<&QuorumVolumeTargetProof> {
    ensure!(
        proof.scenario == "quorum-p-dm-eio" && proof.faults.len() == 1,
        "wrong dm reference scenario"
    );
    let erasure = proof.faults[0]
        .erasure_set
        .as_ref()
        .context("missing erasure proof")?;
    let shape = erasure.shape.as_ref().context("missing erasure shape")?;
    let volumes = erasure
        .volume_quorum
        .as_ref()
        .context("missing volume quorum proof")?;
    volumes.validate(
        shape,
        erasure
            .membership
            .as_ref()
            .context("missing erasure membership")?,
    )?;
    ensure!(
        erasure.resolved
            && shape.server_count == 4
            && shape.volumes_per_server == 1
            && shape.total_shards == 4
            && shape.payload_data_shards == 2
            && shape.payload_parity_shards == 2
            && volumes.boundary.class == QuorumCaseClass::Payload
            && !volumes.boundary.beyond_read_tolerance
            && volumes.target_count == 2
            && volumes.candidates.len() == 4,
        "dm reference requires the four-node single-volume EC 2+2 payload P boundary"
    );
    ensure!(
        volumes.requirements == volumes.boundary.class.requirements(shape)?,
        "invalid quorum requirements"
    );
    Ok(volumes)
}

fn validate_target_binding(
    proof: &HostStorageMutationProof,
    parent: &TargetProof,
    index: usize,
) -> Result<()> {
    proof.validate()?;
    ensure!(
        proof.run_id == child_run_id(&parent.run_id, index)
            && proof.scenario == parent.scenario
            && proof.namespace == parent.namespace
            && proof.tenant == parent.tenant
            && proof.fault_kind == DM_QUORUM_EIO_KIND,
        "foreign dm target proof"
    );
    let target = &proof.target;
    ensure!(
        parent.resolved_pods.iter().any(|pod| pod.name == target.pod
            && pod.uid == target.pod_uid
            && pod.node.as_deref() == Some(target.node.as_str())
            && pod.ready),
        "dm node binding differs from the ready runtime Pod"
    );
    let matches = quorum_proof(parent)?
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.pod_name == target.pod
                && candidate.pod_uid == target.pod_uid
                && candidate.persistent_volume == target.persistent_volume
                && candidate.persistent_volume_claim == target.persistent_volume_claim
                && candidate.mount_path == target.container_mount_path
        })
        .count();
    ensure!(
        matches == 1,
        "dm target is not exactly one runtime quorum candidate"
    );
    Ok(())
}

fn require_distinct<T: Ord>(items: impl Iterator<Item = T>, label: &str) -> Result<()> {
    ensure!(
        items.collect::<BTreeSet<_>>().len() == 2,
        "dm reference requires two independent {label}"
    );
    Ok(())
}

fn validate_target_file(file: &TargetFile, config: &FaultTestConfig) -> Result<()> {
    ensure!(
        file.targets.len() == 2 && config.device_mapper_destructive_enabled,
        "dm reference requires exactly two targets and destructive opt-in"
    );
    require_distinct(file.targets.iter().map(|t| &t.node), "nodes")?;
    require_distinct(file.targets.iter().map(|t| &t.persistent_volume), "PVs")?;
    require_distinct(file.targets.iter().map(|t| &t.state_file), "state files")?;
    require_distinct(file.targets.iter().map(|t| &t.state_token), "state tokens")?;
    for (configured, selected) in [
        (
            &config.host_mutation_allowed_nodes,
            file.targets
                .iter()
                .map(|t| t.node.clone())
                .collect::<Vec<_>>(),
        ),
        (
            &config.host_mutation_allowed_devices,
            file.targets
                .iter()
                .map(|t| format!("/dev/mapper/{}", t.mapper_name))
                .collect(),
        ),
        (
            &config.host_mutation_allowed_persistent_volumes,
            file.targets
                .iter()
                .map(|t| t.persistent_volume.clone())
                .collect(),
        ),
    ] {
        ensure!(
            configured.len() == 2
                && configured.iter().collect::<BTreeSet<_>>() == selected.iter().collect(),
            "dm target file must exactly match the explicit parent allowlists"
        );
    }
    Ok(())
}

pub(crate) fn validate_config(config: &FaultTestConfig) -> Result<()> {
    let path = config
        .quorum_dm_targets
        .as_ref()
        .context("RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS is required")?;
    let file: TargetFile = serde_json::from_slice(&std::fs::read(path)?)?;
    validate_target_file(&file, config)?;
    for target in &file.targets {
        host::validate_quorum_dm_config(&member_config(config, target))?;
    }
    Ok(())
}

pub(crate) fn selected_bindings(
    snapshot: &QuorumDmStatusSnapshot,
    proof: &TargetProof,
) -> Result<Vec<crate::fault::quorum::QuorumVolumeBinding>> {
    validate_evidence(snapshot, proof, &proof.run_id)?;
    let candidates = &quorum_proof(proof)?.candidates;
    snapshot
        .targets
        .iter()
        .map(|target| {
            candidates
                .iter()
                .find(|candidate| candidate.pod_uid == target.proof.target.pod_uid)
                .cloned()
                .context("missing selected quorum binding")
        })
        .collect()
}

fn member_config(config: &FaultTestConfig, target: &TargetConfig) -> FaultTestConfig {
    let mut child = config.clone();
    child.dm_name = Some(target.mapper_name.clone());
    child.dm_node = Some(target.node.clone());
    child.dm_mount_path = Some(target.mount_path.clone());
    child.dm_observer_namespace = Some(target.observer_namespace.clone());
    child.dm_observer_pod = Some(target.observer_pod.clone());
    child.dm_fault_table = None;
    child.dm_recovery_table = None;
    child.host_mutation_allowed_nodes = vec![target.node.clone()];
    child.host_mutation_allowed_devices = vec![format!("/dev/mapper/{}", target.mapper_name)];
    child.host_mutation_allowed_persistent_volumes = vec![target.persistent_volume.clone()];
    child.host_mutation_state_file = Some(target.state_file.clone());
    child.host_mutation_state_token = Some(target.state_token.clone());
    child
}

trait GroupMember {
    fn activate_member(&mut self) -> Result<()>;
    fn restore_member(&mut self, timeout: Duration) -> Result<()>;
}

struct Member {
    config: ClusterTestConfig,
    guard: host::DmFlakeyGuard,
    baseline: DirectReadReceipt,
    restored: bool,
    cleanup_path: PathBuf,
    topology_observed_at_ms: u64,
    activation_started_at_ms: u64,
    activated_at_ms: u64,
}

impl GroupMember for Member {
    fn activate_member(&mut self) -> Result<()> {
        self.activation_started_at_ms = now_ms();
        crate::fault::quorum::require_fresh_runtime_observation(
            self.topology_observed_at_ms,
            self.activation_started_at_ms,
        )?;
        self.activated_at_ms = self.guard.activate()?;
        crate::fault::quorum::require_fresh_runtime_observation(
            self.topology_observed_at_ms,
            self.activated_at_ms,
        )
    }
    fn restore_member(&mut self, timeout: Duration) -> Result<()> {
        if !self.restored {
            self.guard.restore_with_timeout(timeout)?;
            self.restored = true;
        }
        Ok(())
    }
}

fn restore_all<T: GroupMember>(members: &mut [T], timeout: Duration) -> Result<()> {
    let mut failures = Vec::new();
    for (index, member) in members.iter_mut().enumerate().rev() {
        if let Err(error) = member.restore_member(timeout) {
            failures.push(format!("target {index}: {error:#}"));
        }
    }
    ensure!(
        failures.is_empty(),
        "dm group rollback failed: {}",
        failures.join("; ")
    );
    Ok(())
}

fn activate_all<T: GroupMember>(members: &mut [T], timeout: Duration) -> Result<()> {
    for index in 0..members.len() {
        if let Err(primary) = members[index].activate_member() {
            // The failed activation may have committed remotely. Include it,
            // continue after cleanup errors, and unwind in reverse order.
            let rollback = restore_all(&mut members[..=index], timeout);
            bail!("dm target {index} activation failed: {primary:#}; rollback: {rollback:?}");
        }
    }
    Ok(())
}

struct Group {
    run_id: String,
    members: Vec<Member>,
    collector: ArtifactCollector,
    case_name: String,
    timeout: Duration,
}

impl Group {
    fn persist<T: Serialize>(&self, name: &str, value: &T) -> Result<()> {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')),
            "invalid dm evidence filename"
        );
        let directory = self.collector.case_dir(&self.case_name);
        std::fs::create_dir_all(&directory)?;
        let temporary = directory.join(format!(".{name}.{}", uuid::Uuid::new_v4()));
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        serde_json::to_writer_pretty(&file, value)?;
        file.sync_all()?;
        std::fs::rename(&temporary, directory.join(name))?;
        std::fs::File::open(directory)?.sync_all()?;
        Ok(())
    }

    fn evidence(&self, stage: &str) -> Result<QuorumDmStatusSnapshot> {
        let mut targets = Vec::new();
        for (target_index, member) in self.members.iter().enumerate() {
            let proof = member.guard.stale_host_proof().clone();
            let (status, probes) = if member.restored {
                (
                    member
                        .guard
                        .recovery_snapshot()
                        .context("missing restored dm snapshot")?
                        .clone(),
                    Vec::new(),
                )
            } else {
                let status = member.guard.ensure_active(stage)?;
                let mut probes = Vec::new();
                for sample in 0..3 {
                    if sample > 0 {
                        std::thread::sleep(Duration::from_secs(1));
                    }
                    let before = member.guard.ensure_active(stage)?;
                    let read = direct_read(
                        &member.config,
                        &member.config.test_namespace,
                        member.guard.stale_helper_pod_name(),
                        &proof.target.canonical_device,
                        &proof.run_id,
                        &proof.target.node,
                    )?;
                    let after = member.guard.ensure_active(stage)?;
                    let observation = DirectReadSample {
                        before,
                        read,
                        after,
                    };
                    self.persist(
                        &format!("quorum-dm-{stage}-target-{target_index}-sample-{sample}.json"),
                        &observation,
                    )?;
                    probes.push(observation);
                }
                (status, probes)
            };
            targets.push(QuorumDmTargetEvidence {
                proof,
                baseline: member.baseline.clone(),
                activation_started_at_ms: member.activation_started_at_ms,
                activated_at_ms: member.activated_at_ms,
                status,
                probes,
                post_cleanup: if member.restored {
                    Some(serde_json::from_slice(&std::fs::read(
                        &member.cleanup_path,
                    )?)?)
                } else {
                    None
                },
            });
        }
        let evidence = QuorumDmStatusSnapshot {
            schema_version: 1,
            run_id: self.run_id.clone(),
            stage: stage.into(),
            targets,
        };
        self.persist(&format!("quorum-dm-{stage}.json"), &evidence)?;
        Ok(evidence)
    }
}

impl FaultLifecyclePort for Group {
    fn wait_active(&self, _timeout: Duration) -> Result<()> {
        self.ensure_active("active")
    }
    fn ensure_active(&self, stage: &str) -> Result<()> {
        for member in &self.members {
            member.guard.ensure_active(stage)?;
        }
        Ok(())
    }
    fn delete(&mut self, timeout: Duration) -> Result<()> {
        let result = restore_all(&mut self.members, timeout);
        if result.is_ok() {
            self.evidence("recovered")?;
        }
        result
    }
    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        Ok(FaultStatusSnapshot {
            stage: stage.into(),
            resource_kind: Some("DeviceMapperGroup".into()),
            resource_name: Some("quorum-p-dm-eio".into()),
            chaos_status: None,
            dm_status: None,
            lifecycle_status: None,
            quorum_dm_status: Some(self.evidence(stage)?),
        })
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if let Err(error) = restore_all(&mut self.members, self.timeout) {
            eprintln!(
                "warning: quorum dm group cleanup incomplete; retain per-target mutation states: {error:#}"
            );
        }
    }
}

pub(crate) fn prepare(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    run_id: &str,
    target_proof: &TargetProof,
) -> Result<PreparedGroup> {
    ensure!(
        run_id == target_proof.run_id && scenario.name == target_proof.scenario,
        "foreign dm reference run"
    );
    quorum_proof(target_proof)?;
    let path = config
        .quorum_dm_targets
        .as_ref()
        .context("RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS is required")?;
    let file: TargetFile = serde_json::from_slice(&std::fs::read(path)?)?;
    validate_target_file(&file, config)?;
    // Resolve both complete ownership chains before creating either helper.
    let mut prepared = Vec::new();
    for (index, target) in file.targets.iter().enumerate() {
        let child = member_config(config, target);
        let child_id = child_run_id(run_id, index);
        let proof = host::preflight_quorum_dm_mutation(&child, scenario, &child_id)?;
        validate_target_binding(&proof, target_proof, index)?;
        let baseline = direct_read(
            &child.cluster,
            &target.observer_namespace,
            &target.observer_pod,
            &proof.target.canonical_device,
            &proof.run_id,
            &proof.target.node,
        )?;
        ensure!(
            baseline_passed(&baseline),
            "target {index} baseline direct read must transfer a full block before mutation"
        );
        prepared.push((child, child_id, proof, baseline));
    }
    require_distinct(
        prepared.iter().map(|(_, _, p, _)| &p.target.pod_uid),
        "Pods",
    )?;
    let mut group = Group {
        run_id: run_id.into(),
        members: Vec::new(),
        collector: collector.clone(),
        case_name: scenario.case_name.into(),
        timeout: config.cluster.timeout,
    };
    for (index, (child, child_id, proof, baseline)) in prepared.into_iter().enumerate() {
        let child_collector = ArtifactCollector::new(
            collector
                .case_dir(scenario.case_name)
                .join(format!("quorum-dm-target-{index}")),
        );
        let guard = host::prepare_quorum_dm(&child, &child_collector, scenario, &child_id, &proof)?;
        let proof_path = child_collector
            .case_dir(scenario.case_name)
            .join(crate::fault::host_storage::HOST_STORAGE_PROOF_ARTIFACT);
        std::fs::File::open(&proof_path)?.sync_all()?;
        std::fs::File::open(proof_path.parent().context("missing proof directory")?)?.sync_all()?;
        group.members.push(Member {
            config: child.cluster,
            guard,
            baseline,
            restored: false,
            cleanup_path: child_collector
                .case_dir(scenario.case_name)
                .join("host-storage-post-cleanup.json"),
            topology_observed_at_ms: 0,
            activation_started_at_ms: 0,
            activated_at_ms: 0,
        });
    }
    Ok(PreparedGroup { group })
}

pub(crate) struct PreparedGroup {
    group: Group,
}

impl PreparedGroup {
    pub(crate) fn activate(mut self, target_proof: &TargetProof) -> Result<AppliedFault> {
        ensure!(
            self.group.run_id == target_proof.run_id,
            "foreign activation proof"
        );
        quorum_proof(target_proof)?;
        let observed_at_ms = target_proof.faults[0]
            .erasure_set
            .as_ref()
            .context("missing erasure proof")?
            .observed_at_ms;
        for (index, member) in self.group.members.iter_mut().enumerate() {
            validate_target_binding(member.guard.stale_host_proof(), target_proof, index)?;
            member.topology_observed_at_ms = observed_at_ms;
        }
        activate_all(&mut self.group.members, self.group.timeout)?;
        Ok(Box::new(self.group))
    }
}

pub(crate) fn validate_evidence(
    snapshot: &QuorumDmStatusSnapshot,
    target: &TargetProof,
    run_id: &str,
) -> Result<()> {
    ensure!(
        snapshot.schema_version == 1
            && snapshot.run_id == run_id
            && target.run_id == run_id
            && snapshot.targets.len() == 2,
        "invalid quorum dm group identity"
    );
    quorum_proof(target)?;
    ensure!(
        snapshot.targets[0].proof.context == snapshot.targets[1].proof.context,
        "dm target proofs refer to different cluster contexts"
    );
    require_distinct(
        snapshot.targets.iter().map(|t| &t.proof.target.node),
        "nodes",
    )?;
    require_distinct(
        snapshot
            .targets
            .iter()
            .map(|t| &t.proof.target.persistent_volume),
        "PVs",
    )?;
    require_distinct(
        snapshot.targets.iter().map(|t| &t.proof.target.pod_uid),
        "Pods",
    )?;
    for (index, evidence) in snapshot.targets.iter().enumerate() {
        let proof = &evidence.proof;
        validate_target_binding(proof, target, index)?;
        let observed_at_ms = target.faults[0]
            .erasure_set
            .as_ref()
            .context("missing erasure proof")?
            .observed_at_ms;
        crate::fault::quorum::require_fresh_runtime_observation(
            observed_at_ms,
            evidence.activation_started_at_ms,
        )?;
        crate::fault::quorum::require_fresh_runtime_observation(
            observed_at_ms,
            evidence.activated_at_ms,
        )?;
        proof.require_fresh_at(evidence.activated_at_ms)?;
        ensure!(
            evidence.activation_started_at_ms <= evidence.activated_at_ms
                && evidence.activated_at_ms <= evidence.status.observed_at_ms,
            "dm activation is not before its table evidence"
        );
        validate_receipt(&evidence.baseline, proof)?;
        ensure!(
            evidence.baseline.namespace == proof.observer_namespace
                && evidence.baseline.pod == proof.observer_pod
                && baseline_passed(&evidence.baseline)
                && evidence.baseline.completed_at_ms <= proof.generated_at_ms,
            "dm baseline does not establish a healthy uncached read before preparation"
        );
        if snapshot.stage == "recovered" {
            ensure!(evidence.probes.is_empty(), "unexpected recovery probe");
            evidence
                .status
                .validate_proof(proof, "recovered", &proof.tables.recovery_table)?;
            let cleanup = evidence
                .post_cleanup
                .as_ref()
                .context("missing post-cleanup proof")?;
            proof.validate_post_cleanup(cleanup)?;
            ensure!(
                cleanup.observed_at_ms >= evidence.status.observed_at_ms,
                "post-cleanup proof predates recovery"
            );
        } else {
            ensure!(
                evidence.post_cleanup.is_none(),
                "active dm snapshot has premature cleanup evidence"
            );
            evidence
                .status
                .validate_proof(proof, &snapshot.stage, &proof.tables.fault_table)?;
            ensure!(
                evidence.probes.len() == 3,
                "dm reference requires three sustained direct samples"
            );
            let mut preceding = evidence.status.observed_at_ms;
            for (sample_index, sample) in evidence.probes.iter().enumerate() {
                let direct = &sample.read;
                validate_receipt(direct, proof)?;
                ensure!(
                    direct.namespace == proof.namespace
                        && direct.pod == crate::fault::host_storage::helper_pod_name(&proof.run_id),
                    "direct probe did not run in the owned target helper"
                );
                sample
                    .before
                    .validate_proof(proof, &snapshot.stage, &proof.tables.fault_table)?;
                sample
                    .after
                    .validate_proof(proof, &snapshot.stage, &proof.tables.fault_table)?;
                ensure!(
                    sample.before.observed_at_ms >= preceding
                        && sample.before.observed_at_ms - preceding <= 30_000
                        && sample.after.observed_at_ms >= sample.before.observed_at_ms
                        && sample.after.observed_at_ms - sample.before.observed_at_ms <= 30_000
                        && (sample_index == 0 || sample.before.observed_at_ms - preceding >= 1_000)
                        && direct.started_at_ms >= sample.before.observed_at_ms
                        && direct.completed_at_ms <= sample.after.observed_at_ms,
                    "direct samples lack sustained, enclosing active-table observations"
                );
                preceding = sample.after.observed_at_ms;
            }
        }
    }
    Ok(())
}

pub(crate) fn require_qualified(snapshot: &QuorumDmStatusSnapshot) -> Result<()> {
    ensure!(
        snapshot.targets.len() == 2
            && snapshot.stage != "recovered"
            && snapshot
                .targets
                .iter()
                .all(|target| target.probes.len() == 3
                    && target
                        .probes
                        .iter()
                        .all(|sample| read_failed_eio(&sample.read))),
        "both dm volumes must independently reject uncached reads with EIO"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    struct Fake {
        index: usize,
        fail: bool,
        fail_restore: bool,
        events: Arc<Mutex<Vec<String>>>,
    }
    impl GroupMember for Fake {
        fn activate_member(&mut self) -> Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("apply{}", self.index));
            ensure!(!self.fail, "activation response lost");
            Ok(())
        }
        fn restore_member(&mut self, _: Duration) -> Result<()> {
            self.events
                .lock()
                .unwrap()
                .push(format!("restore{}", self.index));
            ensure!(!self.fail_restore, "restore failure");
            Ok(())
        }
    }
    fn evidence_fixture() -> (TargetProof, QuorumDmStatusSnapshot) {
        use crate::fault::host_storage::{DmVolumeMapping, helper_pod_name};
        use crate::fault::quorum::{
            ErasureSetMember, ErasureSetMembership, ErasureSetShape, QuorumVolumeBinding,
            QuorumVolumeBoundary,
        };
        use serde_json::json;
        let host: Vec<_> = (0..4)
            .map(|index| {
                crate::fault::host_storage::tests::quorum_eio_fixture(
                    index,
                    &child_run_id("parent", index),
                )
            })
            .collect();
        let shape = ErasureSetShape {
            pool_index: 0,
            set_index: 0,
            server_count: 4,
            volumes_per_server: 1,
            total_shards: 4,
            payload_data_shards: 2,
            payload_parity_shards: 2,
        };
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            host.iter()
                .enumerate()
                .map(|(i, p)| ErasureSetMember {
                    pod_name: p.target.pod.clone(),
                    server_endpoint: format!("http://rustfs-{i}:9000"),
                    shard_ids: vec![format!("drive-{i}")],
                })
                .collect(),
        )
        .unwrap();
        let candidates = host
            .iter()
            .enumerate()
            .map(|(i, p)| QuorumVolumeBinding {
                pod_name: p.target.pod.clone(),
                pod_uid: p.target.pod_uid.clone(),
                container_id: format!("container-{i}"),
                mount_path: p.target.container_mount_path.clone(),
                persistent_volume_claim: p.target.persistent_volume_claim.clone(),
                persistent_volume: p.target.persistent_volume.clone(),
                drive_uuid: format!("drive-{i}"),
                pool_index: 0,
                set_index: 0,
            })
            .collect();
        let volumes = QuorumVolumeTargetProof::from_runtime(
            &shape,
            &membership,
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Payload,
                beyond_read_tolerance: false,
            },
            candidates,
        )
        .unwrap();
        let target: TargetProof = serde_json::from_value(json!({
            "schemaVersion":2,"status":"satisfied","proofLevel":"configured_host_target","generatedAtMs":200,
            "scenario":"quorum-p-dm-eio","caseName":"case","runId":"parent","namespace":"rustfs-fault-test","tenant":"fault-test-tenant","requirements":[],
            "resolvedPods":host.iter().map(|p| json!({"name":p.target.pod,"uid":p.target.pod_uid,"ready":true,"node":p.target.node})).collect::<Vec<_>>(),
            "faults":[{"name":"quorum-dm-eio","kind":"rustfs_volume_io_error","backend":"device-mapper","targetKind":"volume","targetSummary":"two","selection":"two","conflictDomain":"volume",
                "erasureSet":{"required":true,"resolved":true,"shape":shape,"membership":membership,"volumeQuorum":volumes,"observedAtMs":200,"note":"runtime"}}]
        })).unwrap();
        let targets = host
            .into_iter()
            .take(2)
            .map(|proof| {
                let p = &proof.target;
                let status = DmStatusSnapshot {
                    stage: "active".into(),
                    mapper_name: p.mapper_name.clone(),
                    canonical_device: p.canonical_device.clone(),
                    suspended: false,
                    observed_at_ms: 400,
                    helper_pod: helper_pod_name(&proof.run_id),
                    table: proof.tables.fault_table.clone(),
                    status: "0 1024 flakey".into(),
                    mapping: DmVolumeMapping {
                        node: p.node.clone(),
                        node_uid: p.node_uid.clone(),
                        node_labels: p.node_labels.clone(),
                        pod: p.pod.clone(),
                        pod_uid: p.pod_uid.clone(),
                        volume_name: p.volume_name.clone(),
                        pvc: p.persistent_volume_claim.clone(),
                        pvc_uid: p.persistent_volume_claim_uid.clone(),
                        pvc_phase: p.persistent_volume_claim_phase.clone(),
                        pv: p.persistent_volume.clone(),
                        pv_uid: p.persistent_volume_uid.clone(),
                        pv_phase: p.persistent_volume_phase.clone(),
                        pv_claim_ref: p.persistent_volume_claim_ref.clone(),
                        node_selector: p.node_selector.clone(),
                        container_mount_path: p.container_mount_path.clone(),
                        mount_path: p.persistent_volume_path.clone(),
                    },
                };
                let baseline = DirectReadReceipt {
                    device: p.canonical_device.clone(),
                    run_id: proof.run_id.clone(),
                    context: proof.context.clone(),
                    namespace: proof.observer_namespace.clone(),
                    pod: proof.observer_pod.clone(),
                    node: p.node.clone(),
                    started_at_ms: 50,
                    completed_at_ms: 60,
                    exit_code: Some(0),
                    stdout: String::new(),
                    stderr: "4096 bytes copied".into(),
                    transport_error: None,
                };
                let probes = (0..3)
                    .map(|i| {
                        let mut before = status.clone();
                        before.observed_at_ms = 500 + i * 1100;
                        let mut after = before.clone();
                        after.observed_at_ms += 20;
                        let mut read = baseline.clone();
                        read.namespace = proof.namespace.clone();
                        read.pod = status.helper_pod.clone();
                        read.started_at_ms = before.observed_at_ms + 1;
                        read.completed_at_ms = before.observed_at_ms + 10;
                        read.exit_code = Some(1);
                        read.stderr = format!(
                            "dd: error reading '{}': Input/output error\n0 bytes copied",
                            p.canonical_device
                        );
                        DirectReadSample {
                            before,
                            read,
                            after,
                        }
                    })
                    .collect();
                QuorumDmTargetEvidence {
                    proof,
                    baseline,
                    activation_started_at_ms: 300,
                    activated_at_ms: 350,
                    status,
                    probes,
                    post_cleanup: None,
                }
            })
            .collect();
        (
            target,
            QuorumDmStatusSnapshot {
                schema_version: 1,
                run_id: "parent".into(),
                stage: "active".into(),
                targets,
            },
        )
    }

    #[test]
    fn native_dm_evidence_chain_accepts_active_and_recovered_and_rejects_splices() {
        use crate::fault::host_storage::HostStoragePostCleanupObservation;
        let (target, active) = evidence_fixture();
        validate_evidence(&active, &target, "parent").unwrap();
        require_qualified(&active).unwrap();
        let mut short = active.clone();
        short.targets[1].probes.pop();
        assert!(validate_evidence(&short, &target, "parent").is_err());
        let mut spliced = active.clone();
        spliced.targets[1].probes[0].read = active.targets[0].probes[0].read.clone();
        assert!(validate_evidence(&spliced, &target, "parent").is_err());
        let mut recovered = active.clone();
        recovered.stage = "recovered".into();
        for evidence in &mut recovered.targets {
            let proof = &evidence.proof;
            let p = &proof.target;
            evidence.probes.clear();
            evidence.status.stage = "recovered".into();
            evidence.status.observed_at_ms = 5000;
            evidence.status.table = proof.tables.recovery_table.clone();
            evidence.post_cleanup = Some(HostStoragePostCleanupObservation {
                schema_version: 1,
                scenario: proof.scenario.clone(),
                fault_name: proof.fault_name.clone(),
                run_id: proof.run_id.clone(),
                observed_at_ms: 5100,
                node: p.node.clone(),
                persistent_volume: p.persistent_volume.clone(),
                mapper_name: p.mapper_name.clone(),
                logical_device: p.logical_device.clone(),
                canonical_device: p.canonical_device.clone(),
                mount_canonical_source: p.mount_canonical_source.clone(),
                filesystem_mounted: true,
                node_quarantined: false,
                recovery_table_sha256: p.recovery_table_sha256.clone(),
            });
        }
        validate_evidence(&recovered, &target, "parent").unwrap();
        recovered.targets[1]
            .post_cleanup
            .as_mut()
            .unwrap()
            .persistent_volume = "foreign".into();
        assert!(validate_evidence(&recovered, &target, "parent").is_err());
    }

    #[test]
    fn failed_second_activation_rolls_back_both_in_reverse_even_if_restore_fails() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut members = [
            Fake {
                index: 0,
                fail: false,
                fail_restore: false,
                events: events.clone(),
            },
            Fake {
                index: 1,
                fail: true,
                fail_restore: true,
                events: events.clone(),
            },
        ];
        let error = activate_all(&mut members, Duration::from_secs(1)).unwrap_err();
        assert!(error.to_string().contains("activation response lost"));
        assert_eq!(
            *events.lock().unwrap(),
            ["apply0", "apply1", "restore1", "restore0"]
        );
    }
    #[test]
    fn helper_ids_do_not_collide_after_truncation() {
        use crate::fault::host_storage::helper_pod_name;
        assert_ne!(
            helper_pod_name(&child_run_id("same-parent-run", 0)),
            helper_pod_name(&child_run_id("same-parent-run", 1))
        );
    }
    #[test]
    fn direct_probe_does_not_accept_transport_or_permission_failure_as_eio() {
        let mut receipt = DirectReadReceipt {
            device: "/dev/dm-2".into(),
            run_id: "run".into(),
            context: "lab".into(),
            namespace: "ns".into(),
            pod: "helper".into(),
            node: "node".into(),
            started_at_ms: 1,
            completed_at_ms: 2,
            exit_code: Some(1),
            stdout: String::new(),
            stderr: "dd: error reading '/dev/dm-2': Input/output error\n0 bytes copied".into(),
            transport_error: None,
        };
        assert!(read_failed_eio(&receipt));
        receipt.exit_code = Some(124);
        assert!(!read_failed_eio(&receipt));
        receipt.exit_code = Some(1);
        receipt.stderr = "kubectl connection Input/output error".into();
        assert!(!read_failed_eio(&receipt));
    }
    #[test]
    fn target_file_rejects_duplicate_nodes_and_broad_allowlists() {
        let mut config = FaultTestConfig::for_test("lab", "local");
        config.device_mapper_destructive_enabled = true;
        config.host_mutation_allowed_nodes = vec!["node-a".into(), "node-b".into()];
        config.host_mutation_allowed_devices = vec!["/dev/mapper/a".into(), "/dev/mapper/b".into()];
        config.host_mutation_allowed_persistent_volumes = vec!["pv-a".into(), "pv-b".into()];
        let mut file = TargetFile {
            targets: ["a", "b"]
                .into_iter()
                .map(|id| TargetConfig {
                    node: format!("node-{id}"),
                    mapper_name: id.into(),
                    mount_path: format!("/data/{id}"),
                    persistent_volume: format!("pv-{id}"),
                    observer_namespace: "observer".into(),
                    observer_pod: format!("observer-{id}"),
                    state_file: PathBuf::from(format!("/tmp/artifacts/.host-mutation-{id}.json")),
                    state_token: id.into(),
                })
                .collect(),
        };
        validate_target_file(&file, &config).unwrap();
        config.host_mutation_allowed_nodes.push("node-c".into());
        assert!(validate_target_file(&file, &config).is_err());
        config.host_mutation_allowed_nodes.pop();
        file.targets[1].node = file.targets[0].node.clone();
        assert!(validate_target_file(&file, &config).is_err());
    }

    #[test]
    fn direct_probe_rejects_unproven_or_argument_injection_device_before_execution() {
        let config = FaultTestConfig::for_test("lab", "local");
        for device in [
            "/dev/sda",
            "/dev/dm-",
            "/dev/dm-1; touch /tmp/unsafe",
            "/dev/dm-1/../sda",
        ] {
            assert!(
                direct_read(&config.cluster, "observer", "helper", device, "run", "node").is_err()
            );
        }
    }

    #[test]
    fn closed_target_schema_rejects_arbitrary_commands() {
        assert!(
            serde_json::from_str::<TargetFile>(r#"{"targets":[],"command":"rm -rf /"}"#).is_err()
        );
    }
}
