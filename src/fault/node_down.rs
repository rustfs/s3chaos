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

//! Node-down hold contract for the node-level soft-power-loss proxy.
//!
//! The device-mapper crash boundary force-deletes the target Pod while its
//! writes are dropped and unmounts the filesystem with the node tainted
//! `NoSchedule`. The data volume is node-local, so the replacement Pod stays
//! unscheduled until the device is restored: the server is down exactly as
//! long as the harness keeps the fault. The hold keeps it down for a bounded
//! time and proves the surviving servers keep serving. The samples in the
//! artifact are what makes "down the whole time" checkable offline.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

use crate::fault::{
    history::{DurabilityCohort, OperationKind, OperationRecord},
    pods::pod_is_ready,
    workload::execution::ReadProbeSummary,
};
use std::collections::{BTreeMap, BTreeSet};

pub(in crate::fault) const NODE_DOWN_HOLD_ARTIFACT: &str = "node-down-hold.json";

/// Pre-calibration minimum for how long the node stays down. It must outlast
/// RustFS's own drive-offline detection so the survivors serve from a cluster
/// that has noticed the loss, not one still waiting on the dead peer.
pub(in crate::fault) const NODE_DOWN_MIN_HOLD: Duration = Duration::from_secs(60);
pub(in crate::fault) const NODE_DOWN_SAMPLE_INTERVAL: Duration = Duration::from_secs(5);
/// Largest gap tolerated between two samples, covering a slow API server on
/// top of the sampling interval; a longer gap would leave a window in which
/// the Pod could have come back unobserved.
pub(in crate::fault) const NODE_DOWN_MAX_SAMPLE_GAP: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::fault) struct NodeDownTarget {
    pub(in crate::fault) pod: String,
    /// UID of the Pod the crash boundary force-deleted.
    pub(in crate::fault) crashed_pod_uid: String,
    pub(in crate::fault) node: String,
}

/// One observation of the target Pod name while the node is held down.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::fault) struct NodeDownPodSample {
    pub(in crate::fault) at_ms: u64,
    /// False when no Pod with the target name exists.
    pub(in crate::fault) present: bool,
    pub(in crate::fault) uid: Option<String>,
    pub(in crate::fault) node_name: Option<String>,
    pub(in crate::fault) phase: Option<String>,
    pub(in crate::fault) ready: bool,
}

impl NodeDownPodSample {
    pub(in crate::fault) fn from_pod(at_ms: u64, pod: Option<&Value>) -> Self {
        let text = |pointer: &str| {
            pod.and_then(|pod| pod.pointer(pointer))
                .and_then(Value::as_str)
                .map(str::to_string)
        };
        Self {
            at_ms,
            present: pod.is_some(),
            uid: text("/metadata/uid"),
            node_name: text("/spec/nodeName"),
            phase: text("/status/phase"),
            ready: pod.is_some_and(pod_is_ready),
        }
    }

    /// The server counts as down when its name has no Pod, or only a
    /// replacement that is neither ready nor placed on the quarantined node.
    /// The crashed Pod itself must never be observed again.
    pub(in crate::fault) fn require_down(&self, target: &NodeDownTarget) -> Result<()> {
        if !self.present {
            return Ok(());
        }
        ensure!(
            self.uid.as_deref() != Some(target.crashed_pod_uid.as_str()),
            "the crashed Pod {} ({}) is still present at {}",
            target.pod,
            target.crashed_pod_uid,
            self.at_ms
        );
        ensure!(
            !self.ready,
            "replacement Pod {} ({:?}) became Ready at {} while its node was held down",
            target.pod,
            self.uid,
            self.at_ms
        );
        ensure!(
            self.node_name.as_deref() != Some(target.node.as_str()),
            "replacement Pod {} ({:?}) was scheduled on quarantined node {} at {}",
            target.pod,
            self.uid,
            target.node,
            self.at_ms
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(in crate::fault) struct NodeDownHoldEvidence {
    pub(in crate::fault) scenario: String,
    pub(in crate::fault) run_id: String,
    pub(in crate::fault) target: NodeDownTarget,
    /// Surviving Pod the workload forward was pinned to; absent for a
    /// ClusterIP endpoint.
    pub(in crate::fault) served_by_pod: Option<String>,
    pub(in crate::fault) min_hold_ms: u64,
    pub(in crate::fault) max_sample_gap_ms: u64,
    pub(in crate::fault) started_at_ms: u64,
    pub(in crate::fault) ended_at_ms: u64,
    pub(in crate::fault) samples: Vec<NodeDownPodSample>,
    /// Read verification of every prefilled object the workload never
    /// mutated, through the survivors.
    pub(in crate::fault) read_probe: ReadProbeSummary,
}

impl NodeDownHoldEvidence {
    /// Re-derive the whole contract from the recorded content, so a hand-made
    /// artifact cannot claim a hold its samples or probe do not show.
    pub(in crate::fault) fn validate(&self, stable_objects: usize) -> Result<()> {
        let min_hold_ms = u64::try_from(NODE_DOWN_MIN_HOLD.as_millis())?;
        let max_gap_ms = u64::try_from(NODE_DOWN_MAX_SAMPLE_GAP.as_millis())?;
        ensure!(
            self.min_hold_ms >= min_hold_ms && self.max_sample_gap_ms <= max_gap_ms,
            "{NODE_DOWN_HOLD_ARTIFACT} weakens the catalog hold bounds (min {} ms, max gap {} ms)",
            self.min_hold_ms,
            self.max_sample_gap_ms
        );
        ensure!(
            !self.target.pod.is_empty()
                && !self.target.crashed_pod_uid.is_empty()
                && !self.target.node.is_empty(),
            "{NODE_DOWN_HOLD_ARTIFACT} target identity is incomplete"
        );
        ensure!(
            self.served_by_pod.as_deref() != Some(self.target.pod.as_str()),
            "{NODE_DOWN_HOLD_ARTIFACT} was served by the Pod it held down"
        );
        let first = self
            .samples
            .first()
            .with_context(|| format!("{NODE_DOWN_HOLD_ARTIFACT} has no Pod samples"))?;
        let last = self.samples.last().context("non-empty samples")?;
        ensure!(
            first.at_ms == self.started_at_ms && last.at_ms == self.ended_at_ms,
            "{NODE_DOWN_HOLD_ARTIFACT} hold window is not bounded by its first and last samples"
        );
        ensure!(
            self.ended_at_ms.saturating_sub(self.started_at_ms) >= self.min_hold_ms,
            "{NODE_DOWN_HOLD_ARTIFACT} held the node down for {} ms, below the {} ms minimum",
            self.ended_at_ms.saturating_sub(self.started_at_ms),
            self.min_hold_ms
        );
        for pair in self.samples.windows(2) {
            ensure!(
                pair[0].at_ms <= pair[1].at_ms,
                "{NODE_DOWN_HOLD_ARTIFACT} samples are out of order"
            );
            ensure!(
                pair[1].at_ms - pair[0].at_ms <= self.max_sample_gap_ms,
                "{NODE_DOWN_HOLD_ARTIFACT} has a {} ms sampling gap after {}, longer than {} ms",
                pair[1].at_ms - pair[0].at_ms,
                pair[0].at_ms,
                self.max_sample_gap_ms
            );
        }
        for sample in &self.samples {
            sample.require_down(&self.target)?;
        }
        self.read_probe
            .require_complete_survival()
            .with_context(|| format!("{NODE_DOWN_HOLD_ARTIFACT} read probe did not pass"))?;
        ensure!(
            self.read_probe.objects == stable_objects,
            "{NODE_DOWN_HOLD_ARTIFACT} read probe covers {} objects, but the untouched prefilled cohort has {stable_objects}",
            self.read_probe.objects
        );
        Ok(())
    }

    /// Whether `[started, ended]` lies inside the hold window.
    pub(in crate::fault) fn contains(&self, started_at_ms: u64, ended_at_ms: u64) -> bool {
        self.started_at_ms <= started_at_ms
            && started_at_ms <= ended_at_ms
            && ended_at_ms <= self.ended_at_ms
    }
}

/// Prefilled keys whose only mutation in the run is their single pre-fault
/// PUT, mapped to that PUT's payload hash. The hold runs after the mixed
/// workload, so only these still hold exactly the prefill bytes; a key with
/// any later write, delete, or multipart attempt, even a failed one, is left
/// out rather than guessed at.
pub(in crate::fault) fn untouched_prefill_keys<'a>(
    prefill_keys: impl IntoIterator<Item = &'a str>,
    records: &[OperationRecord],
    scenario: &str,
    run_id: &str,
) -> BTreeMap<String, String> {
    let prefill_keys = prefill_keys.into_iter().collect::<BTreeSet<_>>();
    let mut mutations = BTreeMap::<&str, Vec<&OperationRecord>>::new();
    for record in records {
        if record.scenario != scenario || record.run_id.as_deref() != Some(run_id) {
            continue;
        }
        let Some(key) = record.key.as_deref() else {
            continue;
        };
        if prefill_keys.contains(key)
            && matches!(
                record.kind,
                OperationKind::Put
                    | OperationKind::Delete
                    | OperationKind::CreateMultipartUpload
                    | OperationKind::UploadPart
                    | OperationKind::CompleteMultipartUpload
                    | OperationKind::AbortMultipartUpload
            )
        {
            mutations.entry(key).or_default().push(record);
        }
    }
    mutations
        .into_iter()
        .filter_map(|(key, records)| match records.as_slice() {
            [put]
                if put.kind == OperationKind::Put
                    && put.outcome == crate::fault::history::OperationOutcome::Ok
                    && put.durability_cohort == Some(DurabilityCohort::PreFault) =>
            {
                put.value_sha256
                    .clone()
                    .map(|sha256| (key.to_string(), sha256))
            }
            _ => None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn target() -> NodeDownTarget {
        NodeDownTarget {
            pod: "rustfs-2".to_string(),
            crashed_pod_uid: "uid-old".to_string(),
            node: "worker-dm".to_string(),
        }
    }

    fn pending(at_ms: u64) -> NodeDownPodSample {
        NodeDownPodSample::from_pod(
            at_ms,
            Some(&json!({
                "metadata": {"name": "rustfs-2", "uid": "uid-new"},
                "status": {"phase": "Pending"}
            })),
        )
    }

    fn evidence() -> NodeDownHoldEvidence {
        let started = 1_000;
        let samples = (0..=12)
            .map(|step| pending(started + step * 5_000))
            .collect::<Vec<_>>();
        NodeDownHoldEvidence {
            scenario: "node-crash-proxy".to_string(),
            run_id: "run-1".to_string(),
            target: target(),
            served_by_pod: Some("rustfs-0".to_string()),
            min_hold_ms: 60_000,
            max_sample_gap_ms: 30_000,
            started_at_ms: started,
            ended_at_ms: samples.last().expect("samples").at_ms,
            samples,
            read_probe: ReadProbeSummary {
                objects: 6,
                verified: 6,
                failures: Vec::new(),
            },
        }
    }

    #[test]
    fn samples_classify_absent_and_unscheduled_replacements_as_down() {
        NodeDownPodSample::from_pod(1, None)
            .require_down(&target())
            .expect("no Pod is down");
        pending(1)
            .require_down(&target())
            .expect("pending replacement");

        let crashed = NodeDownPodSample::from_pod(
            1,
            Some(&json!({"metadata": {"uid": "uid-old"}, "status": {"phase": "Running"}})),
        );
        assert!(crashed.require_down(&target()).is_err());

        let ready = NodeDownPodSample::from_pod(
            1,
            Some(&json!({
                "metadata": {"uid": "uid-new"},
                "spec": {"nodeName": "worker-other"},
                "status": {"phase": "Running", "conditions": [{"type": "Ready", "status": "True"}]}
            })),
        );
        assert!(ready.ready);
        assert!(ready.require_down(&target()).is_err());

        let on_quarantined_node = NodeDownPodSample::from_pod(
            1,
            Some(&json!({
                "metadata": {"uid": "uid-new"},
                "spec": {"nodeName": "worker-dm"},
                "status": {"phase": "Pending"}
            })),
        );
        assert!(on_quarantined_node.require_down(&target()).is_err());
    }

    #[test]
    fn untouched_prefill_keys_exclude_any_later_mutation_attempt() {
        let record = |key: &str, kind: OperationKind, cohort, outcome| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": format!("{key}-{kind:?}"),
                "scenario": "node-crash-proxy",
                "run_id": "run-1",
                "bucket": "bucket-1",
                "key": key,
                "kind": kind,
                "outcome": outcome,
                "durability_cohort": cohort,
                "value_sha256": format!("sha-{key}"),
                "started_at_ms": 1,
                "ended_at_ms": 2
            }))
            .expect("record")
        };
        let prefill = |key| record(key, OperationKind::Put, "pre_fault", "ok");
        let records = vec![
            prefill("a"),
            prefill("b"),
            record("b", OperationKind::Put, "fault_active", "ok"),
            prefill("c"),
            record("c", OperationKind::Delete, "fault_active", "failed"),
            prefill("d"),
            record("d", OperationKind::Get, "fault_active", "ok"),
            record("e", OperationKind::Put, "pre_fault", "failed"),
            record(
                "f",
                OperationKind::CreateMultipartUpload,
                "fault_active",
                "ok",
            ),
            prefill("g"),
            prefill("g"),
        ];
        let untouched = untouched_prefill_keys(
            ["a", "b", "c", "d", "e", "f", "g"],
            &records,
            "node-crash-proxy",
            "run-1",
        );
        assert_eq!(
            untouched,
            BTreeMap::from([
                ("a".to_string(), "sha-a".to_string()),
                ("d".to_string(), "sha-d".to_string()),
            ]),
            "reads never disqualify a key; overwrites, failed deletes, failed prefills, multipart attempts, and retried prefills do"
        );
        assert!(
            untouched_prefill_keys(["a"], &records, "node-crash-proxy", "other-run").is_empty()
        );
    }

    #[test]
    fn hold_evidence_requires_bounds_continuity_and_full_reads() {
        evidence().validate(6).expect("valid hold");

        assert!(evidence().validate(12).is_err(), "partial cohort");

        let mut short = evidence();
        short.samples.truncate(6);
        short.ended_at_ms = short.samples.last().expect("samples").at_ms;
        assert!(short.validate(6).is_err(), "hold below the minimum");

        let mut gap = evidence();
        gap.samples.remove(3);
        gap.samples.remove(3);
        gap.samples.remove(3);
        gap.samples.remove(3);
        gap.samples.remove(3);
        gap.samples.remove(3);
        assert!(gap.validate(6).is_err(), "35 s sampling gap");

        let mut weakened = evidence();
        weakened.min_hold_ms = 1;
        assert!(weakened.validate(6).is_err());

        let mut unbounded = evidence();
        unbounded.started_at_ms = 0;
        assert!(unbounded.validate(6).is_err());

        let mut came_back = evidence();
        came_back.samples[4].ready = true;
        assert!(came_back.validate(6).is_err());

        let mut self_served = evidence();
        self_served.served_by_pod = Some("rustfs-2".to_string());
        assert!(self_served.validate(6).is_err());

        let mut failed_read = evidence();
        failed_read.read_probe.verified = 5;
        failed_read.read_probe.failures = vec!["k: 503".to_string()];
        assert!(failed_read.validate(6).is_err());

        let hold = evidence();
        assert!(hold.contains(hold.started_at_ms, hold.ended_at_ms));
        assert!(!hold.contains(hold.started_at_ms - 1, hold.ended_at_ms));
        assert!(!hold.contains(hold.started_at_ms, hold.ended_at_ms + 1));
    }
}
