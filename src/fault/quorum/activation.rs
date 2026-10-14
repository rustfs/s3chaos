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

use crate::fault::workload::sha256_hex;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub(crate) const ACTIVATION_SCHEMA_VERSION: u8 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuorumCanaryOutcome {
    NotRun,
    IoErrorObserved,
    WriteSucceeded,
    UnexpectedFailure,
    TransportFailure,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum QuorumCanaryCleanupOutcome {
    Removed,
    Failed,
    TimedOut,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuorumActivationDisposition {
    RunTypedOracle,
    SkipTypedOracleAndRecover,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuorumCanaryCleanupEvidence {
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) outcome: QuorumCanaryCleanupOutcome,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stderr: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuorumFaultActivationTargetEvidence {
    pub(crate) pod_name: String,
    pub(crate) pod_uid: String,
    pub(crate) container_id: String,
    pub(crate) persistent_volume_claim: String,
    pub(crate) persistent_volume: String,
    pub(crate) mount_path: String,
    pub(crate) drive_uuid: String,
    pub(crate) controller_record_id: String,
    pub(crate) canary_path: String,
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) outcome: QuorumCanaryOutcome,
    pub(crate) exit_code: Option<i32>,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cleanup: Option<QuorumCanaryCleanupEvidence>,
    #[serde(default)]
    pub(crate) probe: Option<super::probe::ProbeReceipt>,
    #[serde(default)]
    pub(crate) probe_cleanup: Option<QuorumCanaryCleanupEvidence>,
    #[serde(default)]
    pub(crate) continuity: Option<super::probe::ProbeReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QuorumFaultActivationEvidence {
    pub(crate) schema_version: u8,
    pub(crate) scenario: String,
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) iochaos_resource_name: String,
    pub(crate) iochaos_snapshot_sha256: String,
    pub(crate) volume_path: String,
    pub(crate) expected_targets: u32,
    pub(crate) controller_records: usize,
    pub(crate) started_at_ms: u64,
    pub(crate) completed_at_ms: u64,
    pub(crate) qualified: bool,
    pub(crate) failure_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) cleanup_failure_reason: Option<String>,
    pub(crate) targets: Vec<QuorumFaultActivationTargetEvidence>,
}

impl QuorumFaultActivationEvidence {
    pub(crate) fn disposition(&self) -> QuorumActivationDisposition {
        if self.qualified {
            QuorumActivationDisposition::RunTypedOracle
        } else {
            QuorumActivationDisposition::SkipTypedOracleAndRecover
        }
    }

    pub(crate) fn validate(&self) -> Result<()> {
        let same_pod =
            self.scenario == crate::fault::scenarios::IO_EIO_SAME_POD_TWO_VOLUMES_SCENARIO;
        ensure!(
            self.schema_version == ACTIVATION_SCHEMA_VERSION,
            "quorum activation evidence uses an unsupported schema version"
        );
        ensure!(
            !self.scenario.trim().is_empty()
                && !self.run_id.trim().is_empty()
                && self.backend == "chaos-mesh-iochaos"
                && self.volume_path.starts_with('/')
                && self.expected_targets > 0
                && self.started_at_ms > 0
                && self.started_at_ms <= self.completed_at_ms,
            "quorum activation evidence identity or timing is invalid"
        );
        if self.qualified {
            ensure!(
                !self.iochaos_resource_name.trim().is_empty()
                    && self.iochaos_snapshot_sha256.len() == 64,
                "qualified quorum activation evidence lacks its IOChaos identity"
            );
        }
        ensure!(
            self.targets.iter().all(|target| {
                !target.pod_name.trim().is_empty()
                    && !target.pod_uid.trim().is_empty()
                    && !target.container_id.trim().is_empty()
                    && !target.persistent_volume_claim.trim().is_empty()
                    && !target.persistent_volume.trim().is_empty()
                    && (target.mount_path == self.volume_path
                        || (same_pod && target.mount_path.starts_with('/')))
                    && !target.drive_uuid.trim().is_empty()
                    && !target.controller_record_id.trim().is_empty()
                    && target.started_at_ms >= self.started_at_ms
                    && target.started_at_ms <= target.completed_at_ms
                    && target.completed_at_ms <= self.completed_at_ms
            }),
            "quorum activation target identity, path, or timing is invalid"
        );
        let mut unique_identities = vec![
            self.targets
                .iter()
                .map(|target| target.persistent_volume_claim.as_str())
                .collect::<Vec<_>>(),
            self.targets
                .iter()
                .map(|target| target.persistent_volume.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.drive_uuid.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.controller_record_id.as_str())
                .collect(),
            self.targets
                .iter()
                .map(|target| target.canary_path.as_str())
                .collect(),
        ];
        if same_pod {
            ensure!(
                self.expected_targets == 2,
                "same-Pod activation must expect two volumes"
            );
            if let [first, second] = self.targets.as_slice() {
                ensure!(
                    first.pod_name == second.pod_name
                        && first.pod_uid == second.pod_uid
                        && first.container_id == second.container_id
                        && first.mount_path != second.mount_path,
                    "same-Pod activation must exercise two distinct mounts on one container generation"
                );
            }
        } else {
            unique_identities.extend([
                self.targets
                    .iter()
                    .map(|target| target.pod_name.as_str())
                    .collect::<Vec<_>>(),
                self.targets
                    .iter()
                    .map(|target| target.pod_uid.as_str())
                    .collect(),
                self.targets
                    .iter()
                    .map(|target| target.container_id.as_str())
                    .collect(),
            ]);
        }
        for values in unique_identities {
            ensure!(
                values
                    .iter()
                    .copied()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    == values.len(),
                "quorum activation evidence contains duplicate target identities"
            );
        }
        ensure!(
            self.qualified == self.qualification(),
            "quorum activation qualification is inconsistent with its controller and canary evidence"
        );
        ensure!(
            self.cleanup_failure_reason
                .as_deref()
                .is_none_or(|reason| !reason.trim().is_empty()),
            "quorum activation cleanup failure reason is empty"
        );
        for target in &self.targets {
            if let Some(probe) = &target.probe {
                probe.fixture.validate()?;
                ensure!(
                    probe.fixture.path == format!("{}.operations", target.canary_path)
                        && probe.fixture.nonce
                            == probe_nonce(&self.run_id, &target.pod_uid, &target.container_id)
                        && probe
                            .samples
                            .iter()
                            .all(|sample| sample.started_at_ms >= target.started_at_ms
                                && sample.completed_at_ms <= target.completed_at_ms),
                    "quorum probe receipt belongs to another target or time window"
                );
            }
            if let Some(continuity) = &target.continuity {
                ensure!(
                    target
                        .probe
                        .as_ref()
                        .is_some_and(|probe| probe.fixture == continuity.fixture
                            && probe.active_device == continuity.active_device)
                        && continuity
                            .samples
                            .iter()
                            .all(|sample| sample.started_at_ms >= self.completed_at_ms),
                    "quorum continuity probe differs from activation fixture or precedes the workload gate"
                );
            }
            match target.outcome {
                QuorumCanaryOutcome::NotRun | QuorumCanaryOutcome::TimedOut => ensure!(
                    target.exit_code.is_none() && target.stdout.is_empty(),
                    "unfinished quorum canary contains a process receipt"
                ),
                _ => ensure!(
                    target.outcome
                        == classify_canary_result(
                            target.exit_code,
                            &target.stdout,
                            &target.stderr,
                            &target.canary_path
                        ),
                    "quorum activation canary verdict does not match its remote write receipt"
                ),
            }
            ensure!(
                target.canary_path
                    == quorum_canary_path(&target.mount_path, &target.pod_name, &self.run_id),
                "quorum activation canary path does not belong to this run and target"
            );
        }
        Ok(())
    }

    pub(crate) fn qualification(&self) -> bool {
        self.failure_reasons.is_empty()
            && usize::try_from(self.expected_targets).ok() == Some(self.targets.len())
            && usize::try_from(self.expected_targets).ok() == Some(self.controller_records)
            && self.targets.iter().all(|target| {
                target.outcome == QuorumCanaryOutcome::IoErrorObserved
                    && target
                        .probe
                        .as_ref()
                        .is_some_and(super::probe::ProbeReceipt::qualifies)
            })
    }

    pub(crate) fn failure_reason(&self) -> Option<String> {
        (!self.qualified).then(|| {
            if self.failure_reasons.is_empty() {
                "fault activation was not independently proven".to_string()
            } else {
                self.failure_reasons.join("; ")
            }
        })
    }

    pub(crate) fn selected_record_ids(&self) -> std::collections::BTreeSet<String> {
        self.targets
            .iter()
            .map(|target| target.controller_record_id.clone())
            .collect()
    }

    pub(crate) fn selected_containers(&self) -> BTreeMap<String, String> {
        self.targets
            .iter()
            .map(|target| (target.pod_name.clone(), target.container_id.clone()))
            .collect()
    }
}

/// Require the remote shell's write receipt; kubectl transport stderr is not
/// evidence that the mutation reached the selected disk.
pub(crate) fn classify_canary_result(
    code: Option<i32>,
    stdout: &str,
    stderr: &str,
    path: &str,
) -> QuorumCanaryOutcome {
    let Some(code) = code.filter(|code| (0..=255).contains(code)) else {
        return QuorumCanaryOutcome::TransportFailure;
    };
    if stdout != format!("s3chaos-canary-write-v1:{path}:{code}\n") {
        return QuorumCanaryOutcome::TransportFailure;
    }
    if code == 0 {
        return QuorumCanaryOutcome::WriteSucceeded;
    }
    let error = stderr.to_ascii_lowercase();
    if ["input/output error", "i/o error", "os error 5", "errno 5"]
        .iter()
        .any(|pattern| error.contains(pattern))
    {
        QuorumCanaryOutcome::IoErrorObserved
    } else {
        QuorumCanaryOutcome::UnexpectedFailure
    }
}

pub(crate) fn quorum_canary_path(mount_path: &str, pod_name: &str, run_id: &str) -> String {
    format!(
        "{}/.s3chaos-quorum-{}-{}",
        mount_path.trim_end_matches('/'),
        sha256_hex(run_id.as_bytes()),
        pod_name
    )
}

pub(crate) fn probe_nonce(run_id: &str, pod_uid: &str, container_id: &str) -> String {
    sha256_hex(format!("{run_id}\0{pod_uid}\0{container_id}").as_bytes())
}

pub(crate) fn validate_runtime_provenance(
    value: &serde_json::Value,
    run_id: &str,
    context: &str,
    candidates: &[super::QuorumVolumeBinding],
) -> Result<()> {
    use anyhow::Context;
    ensure!(
        value["schemaVersion"] == 1 && value["runId"] == run_id && value["context"] == context,
        "quorum runtime provenance belongs to another run"
    );
    let observations = &value["observations"];
    let versions = observations["crd"]["spec"]["versions"]
        .as_array()
        .context("IOChaos CRD versions missing")?;
    let methods = versions
        .iter()
        .find(|v| v["name"] == "v1alpha1" && v["served"] == true)
        .and_then(|v| v.pointer("/schema/openAPIV3Schema/properties/spec/properties/methods"))
        .context("IOChaos served methods schema missing")?;
    ensure!(
        methods["type"] == "array" && methods["items"]["type"] == "string",
        "unsupported IOChaos methods schema"
    );
    // Upstream 2.8 uses an unrestricted string array, not an enum. Actual
    // syscall EIO receipts remain the deployed implementation compatibility gate.
    if let Some(allowed) = methods["items"].get("enum") {
        let allowed = allowed.as_array().context("invalid IOChaos method enum")?;
        ensure!(
            ["READ", "WRITE", "FSYNC", "RENAME", "UNLINK"]
                .iter()
                .all(|method| allowed.iter().any(|value| value
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case(method)))),
            "installed IOChaos schema does not support all quorum probe methods"
        );
    }
    let backend = observations["backend"]["items"]
        .as_array()
        .context("Chaos Mesh Pod identities missing")?;
    for component in ["chaos-controller-manager", "chaos-daemon"] {
        ensure!(
            backend.iter().any(|pod| pod["metadata"]["name"]
                .as_str()
                .is_some_and(|name| name.contains(component))
                && pod["status"]["containerStatuses"]
                    .as_array()
                    .is_some_and(|statuses| !statuses.is_empty()
                        && statuses.iter().all(|status| status["ready"] == true
                            && status["imageID"]
                                .as_str()
                                .is_some_and(|id| id.contains("sha256:"))))),
            "ready {component} resolved image digest missing"
        );
    }
    let pods = observations["rustfs"]["items"]
        .as_array()
        .context("RustFS Pod identities missing")?;
    for target in candidates {
        ensure!(
            pods.iter()
                .any(|pod| pod["metadata"]["name"] == target.pod_name
                    && pod["metadata"]["uid"] == target.pod_uid
                    && pod["status"]["containerStatuses"]
                        .as_array()
                        .is_some_and(|statuses| statuses.iter().any(|status| status["name"]
                            == "rustfs"
                            && status["containerID"] == target.container_id
                            && status["imageID"]
                                .as_str()
                                .is_some_and(|id| id.contains("sha256:"))))),
            "quorum derived RustFS image digest or container generation missing"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_pod_activation_requires_independent_eio_on_both_mounts() {
        let (_, _, proof) = crate::fault::quorum::same_pod_volume_proof_fixture();
        let run_id = "same-pod-run";
        let targets = proof
            .bindings
            .iter()
            .enumerate()
            .map(|(index, binding)| {
                let path = quorum_canary_path(&binding.mount_path, &binding.pod_name, run_id);
                QuorumFaultActivationTargetEvidence {
                    pod_name: binding.pod_name.clone(),
                    pod_uid: binding.pod_uid.clone(),
                    container_id: binding.container_id.clone(),
                    persistent_volume_claim: binding.persistent_volume_claim.clone(),
                    persistent_volume: binding.persistent_volume.clone(),
                    mount_path: binding.mount_path.clone(),
                    drive_uuid: binding.drive_uuid.clone(),
                    controller_record_id: format!(
                        "same-pod-{index}/resource-{index}:faults/{}/rustfs",
                        binding.pod_name
                    ),
                    canary_path: path.clone(),
                    started_at_ms: 110,
                    completed_at_ms: 2200,
                    outcome: QuorumCanaryOutcome::IoErrorObserved,
                    exit_code: Some(1),
                    stdout: format!("s3chaos-canary-write-v1:{path}:1\n"),
                    stderr: "write error: Input/output error".to_string(),
                    probe: Some(crate::fault::quorum::probe::test_receipt(
                        format!("{path}.operations"),
                        probe_nonce(run_id, &binding.pod_uid, &binding.container_id),
                        120,
                    )),
                    cleanup: None,
                    probe_cleanup: None,
                    continuity: None,
                }
            })
            .collect();
        let activation = QuorumFaultActivationEvidence {
            schema_version: ACTIVATION_SCHEMA_VERSION,
            scenario: crate::fault::scenarios::IO_EIO_SAME_POD_TWO_VOLUMES_SCENARIO.to_string(),
            run_id: run_id.to_string(),
            backend: "chaos-mesh-iochaos".to_string(),
            iochaos_resource_name: "same-pod-0,same-pod-1".to_string(),
            iochaos_snapshot_sha256: "a".repeat(64),
            volume_path: "/data/rustfs0".to_string(),
            expected_targets: 2,
            controller_records: 2,
            started_at_ms: 100,
            completed_at_ms: 3000,
            qualified: true,
            failure_reasons: vec![],
            cleanup_failure_reason: None,
            targets,
        };
        activation
            .validate()
            .expect("two proven mounts on one container");
        assert_eq!(
            activation.disposition(),
            QuorumActivationDisposition::RunTypedOracle
        );
        assert_eq!(activation.selected_record_ids().len(), 2);
        assert_eq!(activation.selected_containers().len(), 1);
        for field in [
            "pod",
            "container",
            "mount",
            "pvc",
            "record",
            "probe",
            "canary",
        ] {
            let mut changed = activation.clone();
            match field {
                "pod" => changed.targets[1].pod_name = "rustfs-2".to_string(),
                "container" => {
                    changed.targets[1].container_id = "containerd://replacement".to_string()
                }
                "mount" => changed.targets[1].mount_path = changed.targets[0].mount_path.clone(),
                "pvc" => {
                    changed.targets[1].persistent_volume_claim =
                        changed.targets[0].persistent_volume_claim.clone()
                }
                "record" => {
                    changed.targets[1].controller_record_id =
                        changed.targets[0].controller_record_id.clone()
                }
                "probe" => changed.targets[1].probe = None,
                "canary" => {
                    changed.targets[1].outcome = QuorumCanaryOutcome::WriteSucceeded;
                    changed.targets[1].exit_code = Some(0);
                }
                _ => unreachable!(),
            }
            assert!(
                changed.validate().is_err(),
                "changed {field} cannot qualify"
            );
        }
        let mut incomplete = activation.clone();
        incomplete.targets.pop();
        incomplete.qualified = incomplete.qualification();
        incomplete
            .validate()
            .expect("unqualified partial evidence remains inspectable");
        assert_eq!(
            incomplete.disposition(),
            QuorumActivationDisposition::SkipTypedOracleAndRecover
        );
    }

    #[test]
    fn transport_eio_is_not_disk_activation_evidence() {
        let path = quorum_canary_path("/data/rustfs0", "rustfs-0", "run-1");
        let receipt = format!("s3chaos-canary-write-v1:{path}:1\n");
        for (code, stdout, stderr, expected) in [
            (
                Some(1),
                "",
                "error: unable to upgrade connection: backend i/o error",
                QuorumCanaryOutcome::TransportFailure,
            ),
            (
                None,
                receipt.as_str(),
                "write error: Input/output error",
                QuorumCanaryOutcome::TransportFailure,
            ),
            (
                Some(1),
                "s3chaos-canary-write-v1:/another-path:1\n",
                "write error: Input/output error",
                QuorumCanaryOutcome::TransportFailure,
            ),
            (
                Some(1),
                receipt.as_str(),
                "Permission denied",
                QuorumCanaryOutcome::UnexpectedFailure,
            ),
            (
                Some(1),
                receipt.as_str(),
                "write error: Input/output error",
                QuorumCanaryOutcome::IoErrorObserved,
            ),
        ] {
            assert_eq!(
                classify_canary_result(code, stdout, stderr, &path),
                expected
            );
        }
    }

    #[test]
    fn canary_paths_bind_the_entire_run_identity() {
        assert_ne!(
            quorum_canary_path("/data", "pod", "run-01234567890123456789-a"),
            quorum_canary_path("/data", "pod", "run-01234567890123456789-b")
        );
    }
}
