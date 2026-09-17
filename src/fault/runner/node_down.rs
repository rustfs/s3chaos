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

use anyhow::{Context, Result, ensure};
use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use super::{
    FaultRun, PreparedWorkload, ProvenTarget, now_ms, post_recovery::probe_error_classification,
};
use crate::{
    fault::{
        events::RunEventStatus,
        fault_lifecycle::AppliedFault,
        history::{DurabilityCohort, Recorder},
        node_down::{
            NODE_DOWN_HOLD_ARTIFACT, NODE_DOWN_MAX_SAMPLE_GAP, NODE_DOWN_MIN_HOLD,
            NODE_DOWN_SAMPLE_INTERVAL, NodeDownHoldEvidence, NodeDownPodSample, NodeDownTarget,
            untouched_prefill_keys,
        },
        scenarios::holds_node_down_after_crash,
        workload::{
            WriteProbeScope,
            execution::{
                NODE_DOWN_READ_HISTORY_ARTIFACT, NODE_DOWN_WRITE_HISTORY_ARTIFACT,
                NODE_DOWN_WRITE_REPORT_ARTIFACT, PostRecoveryWriteRequest,
                post_recovery_object_count, probe_read_cohort, run_post_recovery_write_probe,
            },
        },
    },
    framework::{config::ClusterTestConfig, kubectl::Kubectl},
};

/// Distinct from the post-recovery salt so the two probes never write the
/// same bodies.
const NODE_DOWN_SEED_SALT: u64 = 0x4E4F_4445_444F_574E;

impl FaultRun<'_> {
    /// Keep the crashed node down after the drop_writes crash boundary and
    /// prove the surviving servers keep serving committed reads and fresh
    /// writes. Runs only for scenarios that declare the hold; the fault stays
    /// applied throughout so the quarantine taint keeps the replacement Pod
    /// unscheduled.
    pub(super) async fn hold_node_down(
        &self,
        prepared: &mut PreparedWorkload,
        target: &ProvenTarget,
        fault: &AppliedFault,
    ) -> Result<()> {
        if !holds_node_down_after_crash(&self.plan.scenario) {
            return Ok(());
        }
        let events = &self.context.events;
        let node_target = match target.host_storage_proof.as_ref() {
            Some(proof) => NodeDownTarget {
                pod: proof.target.pod.clone(),
                crashed_pod_uid: proof.target.pod_uid.clone(),
                node: proof.target.node.clone(),
            },
            None => {
                let error = anyhow::anyhow!(
                    "node-down hold requires the host-storage proof that names the crashed Pod"
                );
                self.record_failure(
                    "node-down-hold",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((fault, "node-down-hold-failed")),
                )?;
                return Err(error);
            }
        };
        events.record(
            "node-down-hold",
            RunEventStatus::Started,
            "keeping the crashed node down while the surviving servers serve",
            Some(serde_json::json!({
                "target_pod": node_target.pod,
                "target_node": node_target.node,
                "min_hold_ms": NODE_DOWN_MIN_HOLD.as_millis(),
            })),
        )?;

        let sampler = PodSampler::start(self.config.cluster.clone(), node_target.pod.clone());
        let held = self
            .run_node_down_hold(prepared, target, fault, &node_target, &sampler)
            .await;
        let samples = sampler.stop().await;
        let (served_by_pod, read_probe, stable_objects) = match held {
            Ok(held) => held,
            Err((classification, error)) => {
                let details = Some(serde_json::json!({
                    "samples": samples.as_ref().ok(),
                    "sampling_error": samples.as_ref().err().map(|error| format!("{error:#}")),
                }));
                // A quarantine that did not hold explains the failure better
                // than whatever a probe saw through the returning node, and it
                // replaces any verdict the probe already wrote.
                let broken = samples.as_ref().ok().and_then(|samples| {
                    samples
                        .iter()
                        .find_map(|sample| sample.require_down(&node_target).err())
                });
                if let Some(broken) = broken {
                    let error = broken.context(format!(
                        "the node-down quarantine did not hold while the hold failed: {error:#}"
                    ));
                    self.record_failure(
                        "node-down-hold",
                        "environment_or_fault_backend",
                        &error,
                        details,
                        Some((fault, "node-down-hold-failed")),
                    )?;
                    return Err(error);
                }
                // `None` means the failing step already wrote its own verdict.
                if let Some(classification) = classification {
                    self.record_failure(
                        "node-down-hold",
                        classification,
                        &error,
                        details,
                        Some((fault, "node-down-hold-failed")),
                    )?;
                }
                return Err(error);
            }
        };
        let samples = match samples {
            Ok(samples) => samples,
            Err(error) => {
                self.record_failure(
                    "node-down-hold",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((fault, "node-down-hold-failed")),
                )?;
                return Err(error);
            }
        };
        let evidence = NodeDownHoldEvidence {
            scenario: self.scenario.name.clone(),
            run_id: self.context.run_id.clone(),
            target: node_target,
            served_by_pod,
            min_hold_ms: u64::try_from(NODE_DOWN_MIN_HOLD.as_millis())?,
            max_sample_gap_ms: u64::try_from(NODE_DOWN_MAX_SAMPLE_GAP.as_millis())?,
            started_at_ms: samples.first().map_or(0, |sample| sample.at_ms),
            ended_at_ms: samples.last().map_or(0, |sample| sample.at_ms),
            samples,
            read_probe,
        };
        self.collector.write_text(
            self.scenario.case_name,
            NODE_DOWN_HOLD_ARTIFACT,
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        // The artifact is written first so a quarantine that did not hold is
        // still investigable. The probes already passed, so what is left to
        // fail here (sampling continuity, hold bounds, the Pod coming back) is
        // the harness or the quarantine, never the survivors.
        if let Err(error) = evidence.validate(stable_objects) {
            self.record_failure(
                "node-down-hold",
                "environment_or_fault_backend",
                &error,
                None,
                Some((fault, "node-down-hold-failed")),
            )?;
            return Err(error);
        }
        events.record(
            "node-down-hold",
            RunEventStatus::Succeeded,
            "the node stayed down for the whole hold while the survivors served every committed read and fresh write",
            Some(serde_json::json!({
                "held_ms": evidence.ended_at_ms - evidence.started_at_ms,
                "samples": evidence.samples.len(),
                "served_by_pod": evidence.served_by_pod,
            })),
        )?;
        Ok(())
    }

    async fn run_node_down_hold(
        &self,
        prepared: &mut PreparedWorkload,
        target: &ProvenTarget,
        fault: &AppliedFault,
        node_target: &NodeDownTarget,
        sampler: &PodSampler,
    ) -> std::result::Result<
        (
            Option<String>,
            crate::fault::workload::execution::ReadProbeSummary,
            usize,
        ),
        (Option<&'static str>, anyhow::Error),
    > {
        let backend = |error: anyhow::Error| (Some("environment_or_fault_backend"), error);
        let probe_error = |error: anyhow::Error| (Some(probe_error_classification(&error)), error);
        let hold_started_at_ms = sampler
            .wait_first_sample(NODE_DOWN_MAX_SAMPLE_GAP)
            .await
            .map_err(backend)?;
        sampler.require_down(node_target).map_err(backend)?;
        fault.ensure_active("node-down-hold").map_err(backend)?;

        // A failed re-pin records its own availability-endpoint verdict.
        let served_by_pod = self
            .repin_endpoint_to_survivor(
                fault,
                &target.pods_before,
                BTreeSet::from([node_target.pod.clone()]),
                &prepared.endpoint,
                &mut prepared.port_forward,
            )
            .await
            .map_err(|error| (None, error))?;

        // Only prefilled objects the workload never touched still hold their
        // prefill bytes; offline validation re-derives the same set.
        let untouched = untouched_prefill_keys(
            prepared.prefilled.iter().map(|object| object.key.as_str()),
            &self.context.history.records(),
            &self.scenario.name,
            &self.context.run_id,
        );
        let stable = prepared
            .prefilled
            .iter()
            .filter(|object| untouched.get(&object.key) == Some(&object.sha256))
            .cloned()
            .collect::<Vec<_>>();
        if stable.is_empty() {
            return Err(backend(anyhow::anyhow!(
                "every prefilled object was mutated by the workload; the node-down read probe would be vacuous"
            )));
        }
        // Probe only once the node has been down for the minimum hold, so the
        // survivors are measured after RustFS can have noticed the loss, not
        // while it may still be waiting on the dead peer.
        let min_hold_ms =
            u64::try_from(NODE_DOWN_MIN_HOLD.as_millis()).map_err(|error| backend(error.into()))?;
        let remaining =
            Duration::from_millis((hold_started_at_ms + min_hold_ms).saturating_sub(now_ms()));
        if !remaining.is_zero() {
            self.deadline
                .run(async {
                    tokio::time::sleep(remaining).await;
                    Ok(())
                })
                .await
                .map_err(probe_error)?;
        }
        sampler.require_down(node_target).map_err(backend)?;
        fault.ensure_active("node-down-detected").map_err(backend)?;

        let case_dir = self.collector.case_dir(self.scenario.case_name);
        let read_history = Recorder::create(
            case_dir.join(NODE_DOWN_READ_HISTORY_ARTIFACT),
            &self.scenario.name,
            &self.context.run_id,
        )
        .context("create node-down read probe history")
        .map_err(backend)?;
        read_history.set_durability_cohort(DurabilityCohort::FaultActive);
        let read_probe = self
            .deadline
            .run(probe_read_cohort(
                &prepared.s3,
                &read_history,
                &stable,
                self.context.workload_plan.concurrency,
            ))
            .await
            .map_err(probe_error)?;
        read_probe.require_complete_survival().map_err(|error| {
            (
                Some("availability_regression"),
                error.context("committed objects were unreadable with one node down"),
            )
        })?;

        // The write probe records its own node-down-write verdict.
        self.probe_node_down_writes(&prepared.s3, fault)
            .await
            .map_err(|error| (None, error))?;

        // The node stays down until both probes finished; the closing sample
        // taken on stop ends the recorded window.
        sampler.require_down(node_target).map_err(backend)?;
        fault.ensure_active("node-down-hold-end").map_err(backend)?;
        Ok((served_by_pod, read_probe, stable.len()))
    }

    async fn probe_node_down_writes(
        &self,
        s3: &crate::fault::workload::S3WorkloadClient,
        fault: &AppliedFault,
    ) -> Result<()> {
        let events = &self.context.events;
        let workload_plan = &self.context.workload_plan;
        let object_count = post_recovery_object_count(workload_plan.object_count);
        let s3 = match self.deadline.instant()? {
            Some(deadline) => s3.with_mutation_deadline(deadline),
            None => s3.clone(),
        };
        events.record(
            "node-down-write",
            RunEventStatus::Started,
            "writing, listing, and deleting fresh objects while the node is down",
            Some(serde_json::json!({ "objects": object_count })),
        )?;
        let report = async {
            let history = Recorder::create(
                self.collector
                    .case_dir(self.scenario.case_name)
                    .join(NODE_DOWN_WRITE_HISTORY_ARTIFACT),
                &self.scenario.name,
                &self.context.run_id,
            )
            .context("create node-down write probe history")?;
            history.set_durability_cohort(DurabilityCohort::FaultActive);
            run_post_recovery_write_probe(&PostRecoveryWriteRequest {
                s3: &s3,
                history: &history,
                run_id: &self.context.run_id,
                scope: WriteProbeScope::NodeDown,
                seed: workload_plan.seed ^ NODE_DOWN_SEED_SALT,
                object_count,
                concurrency: workload_plan.concurrency,
                deadline: self.deadline,
            })
            .await
        }
        .await;
        let report = match report {
            Ok(report) => report,
            Err(error) => {
                self.record_failure(
                    "node-down-write",
                    probe_error_classification(&error),
                    &error,
                    None,
                    Some((fault, "node-down-write-failed")),
                )?;
                return Err(error);
            }
        };
        self.collector.write_text(
            self.scenario.case_name,
            NODE_DOWN_WRITE_REPORT_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        if let Err(error) = report.require_success() {
            let error = error.context("fresh writes failed with one node down");
            self.record_failure(
                "node-down-write",
                "availability_regression",
                &error,
                Some(serde_json::json!({
                    "objects": report.objects,
                    "puts_verified": report.puts_verified,
                    "deletes_verified_absent": report.deletes_verified_absent,
                    "failures": report.failures,
                })),
                Some((fault, "node-down-write-failed")),
            )?;
            return Err(error);
        }
        events.record(
            "node-down-write",
            RunEventStatus::Succeeded,
            "fresh writes, reads, listings, and deletes all succeeded with the node down",
            Some(serde_json::json!({
                "objects": report.objects,
                "multipart_completes_verified": report.multipart_completes_verified,
            })),
        )?;
        Ok(())
    }
}

/// Bound on one Pod sample, well inside the evidence's gap bound, so a hung
/// API call can neither hide the Pod nor keep cleanup from unwinding the
/// active fault.
const NODE_DOWN_SAMPLE_TIMEOUT: Duration = Duration::from_secs(10);

/// Samples the target Pod name on a fixed interval from a background task so
/// the hold's evidence covers the probes as well as the idle wait.
struct PodSampler {
    stop: Arc<AtomicBool>,
    samples: Arc<Mutex<Vec<NodeDownPodSample>>>,
    task: tokio::task::JoinHandle<()>,
    cluster: ClusterTestConfig,
    pod: String,
}

impl PodSampler {
    fn start(cluster: ClusterTestConfig, pod: String) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let samples = Arc::new(Mutex::new(Vec::new()));
        let task = {
            let stop = stop.clone();
            let samples = samples.clone();
            let cluster = cluster.clone();
            let pod = pod.clone();
            tokio::spawn(async move {
                while !stop.load(Ordering::SeqCst) {
                    // A failed observation is skipped rather than fatal: the
                    // evidence bounds the gap between recorded samples, so an
                    // API outage long enough to hide the Pod still fails.
                    match sample_pod(&cluster, &pod).await {
                        Ok(sample) => match samples.lock() {
                            Ok(mut samples) => samples.push(sample),
                            Err(_) => return,
                        },
                        Err(error) => eprintln!("warning: {error:#}"),
                    }
                    let next = Instant::now() + NODE_DOWN_SAMPLE_INTERVAL;
                    while Instant::now() < next && !stop.load(Ordering::SeqCst) {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            })
        };
        Self {
            stop,
            samples,
            task,
            cluster,
            pod,
        }
    }

    fn snapshot(&self) -> Result<Vec<NodeDownPodSample>> {
        Ok(self
            .samples
            .lock()
            .map_err(|_| anyhow::anyhow!("node-down sample lock poisoned"))?
            .clone())
    }

    /// Wait for the first observation and return its time.
    async fn wait_first_sample(&self, timeout: Duration) -> Result<u64> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(first) = self.snapshot()?.first() {
                return Ok(first.at_ms);
            }
            ensure!(
                Instant::now() < deadline,
                "node-down Pod sampler produced no sample within {timeout:?}"
            );
            ensure!(
                !self.task.is_finished(),
                "node-down Pod sampler stopped before its first sample"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Fail fast when the node already came back, rather than waiting for
    /// the artifact validation at the end of the hold.
    fn require_down(&self, target: &NodeDownTarget) -> Result<()> {
        for sample in self.snapshot()? {
            sample.require_down(target)?;
        }
        Ok(())
    }

    /// Stop sampling, take one closing sample so the hold window ends on an
    /// observation, and return every sample in order.
    async fn stop(mut self) -> Result<Vec<NodeDownPodSample>> {
        self.stop.store(true, Ordering::SeqCst);
        // Each sample is bounded, so the task ends within one bound plus a
        // poll interval.
        (&mut self.task)
            .await
            .map_err(|error| anyhow::anyhow!("node-down Pod sampler failed: {error}"))?;
        let mut closing = None;
        for attempt in 0..3 {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            if let Ok(sample) = sample_pod(&self.cluster, &self.pod).await {
                closing = Some(sample);
                break;
            }
        }
        let closing = closing.context("the closing node-down Pod sample failed three times")?;
        let mut samples = self.snapshot()?;
        samples.push(closing);
        Ok(samples)
    }
}

impl Drop for PodSampler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.task.abort();
    }
}

async fn sample_pod(cluster: &ClusterTestConfig, pod: &str) -> Result<NodeDownPodSample> {
    let output = Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command(["get", "pod", pod, "-o", "json", "--ignore-not-found"])
        .run_bounded(NODE_DOWN_SAMPLE_TIMEOUT)
        .await
        .with_context(|| format!("sample RustFS Pod {pod} while its node is held down"))?;
    ensure!(
        output.code == Some(0),
        "sample RustFS Pod {pod} while its node is held down: exit={:?} {}",
        output.code,
        output.stderr.trim()
    );
    let at_ms = now_ms();
    let stdout = output.stdout.trim();
    if stdout.is_empty() {
        return Ok(NodeDownPodSample::from_pod(at_ms, None));
    }
    let value = serde_json::from_str::<serde_json::Value>(stdout)
        .with_context(|| format!("parse RustFS Pod {pod} while its node is held down"))?;
    Ok(NodeDownPodSample::from_pod(at_ms, Some(&value)))
}
