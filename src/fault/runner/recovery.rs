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

use crate::fault::{
    events::RunEventStatus,
    fault_lifecycle::AppliedFault,
    history::DurabilityCohort,
    pods::rustfs_pod_identities,
    recovery_health::{
        PodReadinessProbe, RECOVERY_HEALTH_ARTIFACT, RecoveryHealthBaseline,
        RecoveryHealthObservation, RecoveryHealthReport, readiness_proxy_path,
    },
    reporting::FaultEvidence,
};
use crate::fault::{reporting::PodIdentity, workload::StagedMultipartUpload};
use crate::framework::{kubectl::Kubectl, resources};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use tokio::time::sleep as async_sleep;

const RECOVERY_HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(2);
const READINESS_DETAIL_LIMIT: usize = 300;
/// Hard bound on one `kubectl get --raw` readiness probe, matching the admin
/// HTTP client's per-request timeout; an API server that accepts the
/// connection but never answers the Pod proxy must not stall the poll loop.
const READINESS_PROBE_TIMEOUT: Duration = Duration::from_secs(15);

use super::access::{ensure_s3_access, wait_for_ready_tenant, wait_for_stable_rustfs_pods};
use super::{
    ActiveFault, FaultRemoval, FaultRun, FaultWorkload, PreparedWorkload, ProvenTarget, now_ms,
};
use crate::fault::workload::execution::{cleanup_staged_multipart_uploads, crash_window_evidence};

impl FaultRun<'_> {
    pub(super) fn prepare_crash_boundary(
        &self,
        fault: &mut AppliedFault,
        fault_active_at_ms: u64,
    ) -> Result<()> {
        let collector = self.collector;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        if fault.requires_recovery_boundary() {
            events.record(
                "crash-recovery-boundary",
                RunEventStatus::Started,
                "proving an acknowledged mutation and forcing the backend-owned crash boundary",
                None,
            )?;
            let crash_boundary_started_at_ms = now_ms();
            let crash_window_evidence = match crash_window_evidence(
                &history.records(),
                &scenario.name,
                run_id,
                fault_active_at_ms,
                crash_boundary_started_at_ms,
            ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    self.record_failure(
                        "crash-recovery-boundary",
                        "no_signal",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
            collector.write_text(
                scenario.case_name,
                "crash-window-evidence.json",
                &serde_json::to_string_pretty(&crash_window_evidence)?,
            )?;
            if let Err(error) =
                fault.prepare_recovery_boundary(cluster.timeout, crash_boundary_started_at_ms)
            {
                self.record_failure(
                    "crash-recovery-boundary",
                    "environment_or_fault_backend",
                    &error,
                    Some(serde_json::json!({
                        "trigger_operation_id": crash_window_evidence.trigger_operation_id,
                    })),
                    Some((fault, "crash-boundary-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "crash-recovery-boundary",
                RunEventStatus::Succeeded,
                "target Pod was force-deleted and the filesystem was unmounted while drop_writes remained active",
                Some(serde_json::json!({
                    "trigger_operation_id": crash_window_evidence.trigger_operation_id,
                    "ack_to_crash_boundary_ms": crash_window_evidence.ack_to_crash_boundary_ms,
                })),
            )?;
        }
        Ok(())
    }
    pub(super) fn remove_fault(&self, fault: &mut AppliedFault) -> Result<FaultRemoval> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        events.record(
            "fault-delete",
            RunEventStatus::Started,
            "removing applied faults",
            None,
        )?;
        let fault_delete_started_at_ms = history.mark_fault_ended_now();
        // Host-storage cleanup observations are emitted by delete.
        let recovery_started_at_ms = now_ms();
        let fault_delete_started_at = Instant::now();
        if let Err(error) = fault.delete(cluster.timeout) {
            let finalizer_recovery = match fault.recover_delete_timeout(
                &crate::fault::fault_lifecycle::FaultDeleteTimeoutRecoveryRequest {
                    config,
                    collector,
                    case_name: scenario.case_name,
                    run_id,
                    original_error: &error,
                    delete_started_at: fault_delete_started_at,
                },
            ) {
                Ok(recovery) => recovery,
                Err(recovery_error) => {
                    let _ = collector.write_text(
                        scenario.case_name,
                        "iochaos-finalizer-recovery-error.txt",
                        &format!(
                            "failed to evaluate or apply IOChaos finalizer recovery:\n{recovery_error}"
                        ),
                    );
                    None
                }
            };
            if let Some(recovery) = finalizer_recovery {
                events.record(
                    "fault-delete",
                    RunEventStatus::Succeeded,
                    "patched stuck IOChaos finalizer after recovery evidence",
                    Some(serde_json::json!({
                        "warning_artifact": recovery.warning_artifact,
                        "iochaos": recovery.resource_name,
                        "target_nodes": recovery.target_nodes,
                    })),
                )?;
            } else {
                self.record_failure(
                    "fault-delete",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((fault, "delete-failed")),
                )?;
                return Err(error);
            }
        } else {
            events.record(
                "fault-delete",
                RunEventStatus::Succeeded,
                "applied faults were removed",
                None,
            )?;
        }
        Ok(FaultRemoval {
            fault_delete_started_at_ms,
            recovery_started_at_ms,
        })
    }
    pub(super) async fn recover_access(
        &self,
        prepared: &mut PreparedWorkload,
        target: &ProvenTarget,
        staged_multipart_uploads: &mut BTreeMap<usize, StagedMultipartUpload>,
    ) -> Result<(Vec<PodIdentity>, u64)> {
        let config = self.config;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        let cleanup_concurrency = self.context.workload_plan.concurrency;
        let PreparedWorkload {
            s3,
            endpoint,
            port_forward,
            prefilled: _,
        } = prepared;
        events.record(
            "tenant-recovery",
            RunEventStatus::Started,
            "waiting for Tenant readiness after fault removal",
            None,
        )?;
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        if let Err(error) = self.deadline.run(wait_for_ready_tenant(cluster)).await {
            self.record_failure(
                "tenant-recovery",
                "product_or_environment",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        events.record(
            "tenant-recovery",
            RunEventStatus::Succeeded,
            "Tenant is Ready after fault removal",
            None,
        )?;
        events.record(
            "pod-stability-after-recovery",
            RunEventStatus::Started,
            "waiting for RustFS pods to remain stable after recovery",
            Some(serde_json::json!({
                "expected_pod_count": config.expected_rustfs_pod_count,
                "stable_window_seconds": config.rustfs_pod_stable_window.as_secs(),
            })),
        )?;
        if let Err(error) = self
            .deadline
            .run(wait_for_stable_rustfs_pods(
                cluster,
                config.expected_rustfs_pod_count,
                config.rustfs_pod_stable_window,
            ))
            .await
        {
            self.record_failure(
                "pod-stability-after-recovery",
                "product_or_environment",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        events.record(
            "pod-stability-after-recovery",
            RunEventStatus::Succeeded,
            "RustFS pods were stable after recovery",
            None,
        )?;
        let pods_after = rustfs_pod_identities(cluster)?;
        events.record(
            "s3-access-after-recovery",
            RunEventStatus::Started,
            "checking S3 access after recovery",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
        if let Err(error) = self
            .deadline
            .run(ensure_s3_access(port_forward, cluster, endpoint))
            .await
        {
            self.record_failure(
                "s3-access-after-recovery",
                "product_or_environment",
                &error,
                Some(serde_json::json!({ "endpoint": endpoint })),
                None,
            )?;
            return Err(error);
        }
        events.record(
            "s3-access-after-recovery",
            RunEventStatus::Succeeded,
            "S3 endpoint is reachable after recovery",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
        self.require_recovery_health(endpoint, &target.health_baseline, &pods_after)
            .await?;
        cleanup_staged_multipart_uploads(
            s3,
            history,
            std::mem::take(staged_multipart_uploads),
            cleanup_concurrency,
        )
        .await
        .context("cleaning staged uploads before recovery verification")?;
        let recovery_ended_at_ms = now_ms();
        Ok((pods_after, recovery_ended_at_ms))
    }
    pub(super) fn write_recovery_evidence(
        &self,
        target: &ProvenTarget,
        active: &ActiveFault,
        workload: &FaultWorkload,
        removal: &FaultRemoval,
        recovered: &(Vec<PodIdentity>, u64),
    ) -> Result<FaultEvidence> {
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let ProvenTarget {
            pods_before,
            target_proof: _,
            topology_observed_at_ms: _,
            host_storage_proof: _,
            execution_injection: _,
            health_baseline: _,
        } = target;
        let ActiveFault {
            fault,
            fault_apply_started_at_ms,
            fault_active_at_ms,
            active_snapshots,
            pods_at_fault_activation,
            active_partition_targets: _,
            active_fixed_volume_targets,
            active_fixed_volume_containers,
        } = active;
        let FaultWorkload {
            workload,
            workload_started_at_ms,
            workload_ended_at_ms,
            require_client_disruption,
            workload_snapshots,
            pods_at_workload_snapshot,
            workload_fixed_volume_targets,
            workload_fixed_volume_containers,
            quorum_health_before_workload,
            quorum_health_after_workload,
        } = workload;
        let FaultRemoval {
            fault_delete_started_at_ms,
            recovery_started_at_ms,
        } = removal;
        let (pods_after, recovery_ended_at_ms) = recovered;
        let evidence = FaultEvidence {
            scenario: scenario.name.clone(),
            run_id: run_id.clone(),
            backend: plan.backend_summary(),
            target: plan.target_summary(),
            injected: true,
            active_during_workload: true,
            recovered: true,
            require_client_disruption: *require_client_disruption,
            client_disruptions: workload.summary.disrupted(),
            workload_plan: workload_plan.clone(),
            pods_before: pods_before.clone(),
            pods_at_fault_activation: pods_at_fault_activation.clone(),
            pods_at_workload_snapshot: pods_at_workload_snapshot.clone(),
            fixed_volume_targets_at_fault_activation: active_fixed_volume_targets
                .iter()
                .cloned()
                .collect(),
            fixed_volume_targets_at_workload_snapshot: workload_fixed_volume_targets
                .iter()
                .cloned()
                .collect(),
            fixed_volume_containers_at_fault_activation: active_fixed_volume_containers.clone(),
            fixed_volume_containers_at_workload_snapshot: workload_fixed_volume_containers.clone(),
            pods_after: pods_after.clone(),
            active_snapshots: active_snapshots.clone(),
            workload_snapshots: workload_snapshots.clone(),
            dm_recovery_snapshot: fault.recovery_dm_snapshot(),
            fault_apply_started_at_ms: Some(*fault_apply_started_at_ms),
            fault_active_at_ms: Some(*fault_active_at_ms),
            workload_started_at_ms: Some(*workload_started_at_ms),
            workload_ended_at_ms: Some(*workload_ended_at_ms),
            fault_delete_started_at_ms: Some(*fault_delete_started_at_ms),
            recovery_started_at_ms: Some(*recovery_started_at_ms),
            recovery_ended_at_ms: Some(*recovery_ended_at_ms),
            quorum_health_before_workload: quorum_health_before_workload.clone(),
            quorum_health_after_workload: quorum_health_after_workload.clone(),
        };
        collector.write_text(
            scenario.case_name,
            "fault-evidence.json",
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        // Artifact validation requires this event to precede the
        // post-recovery write probe's start, proving the lifecycle evidence
        // was on disk before the write gate could fail the run.
        self.context.events.record(
            "recovery-evidence",
            RunEventStatus::Succeeded,
            "fault-evidence.json persisted with the completed fault lifecycle",
            Some(serde_json::json!({
                "recovery_ended_at_ms": recovery_ended_at_ms,
            })),
        )?;
        Ok(evidence)
    }
}

impl FaultRun<'_> {
    /// Poll RustFS until it reports the pre-fault drive set fully `ok` and
    /// every Pod answers readiness, or the recovery timeout expires. The
    /// report is written on every outcome so a degraded cluster leaves the
    /// exact drive states behind as evidence.
    async fn require_recovery_health(
        &self,
        endpoint: &str,
        baseline: &RecoveryHealthBaseline,
        pods: &[PodIdentity],
    ) -> Result<()> {
        let collector = self.collector;
        let scenario = self.scenario;
        let events = &self.context.events;
        let cluster = &self.config.cluster;
        events.record(
            "recovery-health",
            RunEventStatus::Started,
            "waiting for RustFS to report every baseline drive ok and every Pod ready",
            Some(serde_json::json!({
                "expected_drives": baseline.drive_uuids.len(),
                "pods": pods.len(),
                "timeout_seconds": cluster.timeout.as_secs(),
            })),
        )?;
        let report = match self
            .deadline
            .run(observe_recovery_health(
                cluster,
                endpoint,
                baseline,
                pods,
                &self.scenario.name,
                &self.context.run_id,
                &|report| {
                    collector
                        .write_text(
                            scenario.case_name,
                            RECOVERY_HEALTH_ARTIFACT,
                            &serde_json::to_string_pretty(report)?,
                        )
                        .map(|_| ())
                },
            ))
            .await
        {
            Ok(report) => report,
            Err(error) => {
                // The harness could not observe RustFS at all (for example the
                // kube context lacks `pods/proxy`); that is not product evidence.
                self.record_failure("recovery-health", "test_or_environment", &error, None, None)?;
                return Err(error);
            }
        };
        collector.write_text(
            scenario.case_name,
            RECOVERY_HEALTH_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        if let Err(error) = report.require_success() {
            self.record_failure(
                "recovery-health",
                "recovery_health_degraded",
                &error,
                Some(serde_json::json!({
                    "attempts": report.attempts,
                    "violations": report.violations,
                    "unready_pods": report
                        .readiness
                        .iter()
                        .filter(|probe| !probe.ready)
                        .map(|probe| probe.pod_name.clone())
                        .collect::<Vec<_>>(),
                })),
                None,
            )?;
            return Err(error);
        }
        events.record(
            "recovery-health",
            RunEventStatus::Succeeded,
            "RustFS reports the full baseline drive set ok and every Pod ready",
            Some(serde_json::json!({
                "attempts": report.attempts,
                "first_healthy_at_ms": report.first_healthy_at_ms,
            })),
        )?;
        Ok(())
    }
}

async fn observe_recovery_health(
    cluster: &crate::framework::config::ClusterTestConfig,
    endpoint: &str,
    baseline: &RecoveryHealthBaseline,
    pods: &[PodIdentity],
    scenario: &str,
    run_id: &str,
    persist: &dyn Fn(&RecoveryHealthReport) -> Result<()>,
) -> Result<RecoveryHealthReport> {
    let (access_key, secret_key) = resources::test_credentials();
    let started_at_ms = now_ms();
    let deadline = Instant::now() + cluster.timeout;
    let mut report = RecoveryHealthReport {
        scenario: scenario.to_string(),
        run_id: run_id.to_string(),
        baseline: baseline.clone(),
        started_at_ms,
        completed_at_ms: started_at_ms,
        timeout_seconds: cluster.timeout.as_secs(),
        attempts: 0,
        first_healthy_at_ms: None,
        observation: None,
        readiness: Vec::new(),
        violations: Vec::new(),
        passed: false,
    };
    loop {
        report.attempts += 1;
        let attempt_started_at_ms = now_ms();
        let mut violations =
            match crate::rustfs::read_erasure_layout(endpoint, "us-east-1", access_key, secret_key)
                .await
            {
                Ok(layout) => {
                    let observation = RecoveryHealthObservation::from_layout(
                        &layout,
                        attempt_started_at_ms,
                        now_ms(),
                    );
                    let violations = observation.violations(baseline);
                    report.observation = Some(observation);
                    violations
                }
                Err(error) => {
                    report.observation = None;
                    vec![format!("RustFS admin info unavailable: {error:#}")]
                }
            };
        let mut readiness = Vec::with_capacity(pods.len());
        for pod in pods {
            // Each probe is also capped by the remaining recovery budget so N
            // Pods cannot push one attempt past the loop's own deadline.
            let bound =
                READINESS_PROBE_TIMEOUT.min(deadline.saturating_duration_since(Instant::now()));
            readiness.push(probe_pod_readiness(cluster, &pod.name, bound).await);
        }
        report.readiness = readiness;
        if let Some(denied) = report
            .readiness
            .iter()
            .find(|probe| probe.detail.as_deref().is_some_and(readiness_probe_denied))
        {
            bail!(
                "readiness probe for Pod {} was refused by the API server rather than answered by RustFS; grant `get` on `pods/proxy` to the fault-test context: {}",
                denied.pod_name,
                denied.detail.as_deref().unwrap_or_default()
            );
        }
        violations.extend(
            report
                .readiness
                .iter()
                .filter(|probe| !probe.ready)
                .map(|probe| {
                    format!(
                        "Pod {} readiness {} failed: {}",
                        probe.pod_name,
                        probe.proxy_path,
                        probe.detail.as_deref().unwrap_or("no detail")
                    )
                }),
        );
        if pods.is_empty() {
            violations.push("no RustFS Pods to probe for readiness".to_string());
        }
        violations.sort();
        report.violations = violations;
        report.completed_at_ms = now_ms();
        // Persist every attempt so a run cut off by the outer deadline still
        // leaves the last observed drive states behind as evidence.
        persist(&report)?;
        if report.violations.is_empty() {
            report.first_healthy_at_ms = Some(report.completed_at_ms);
            report.passed = true;
            return Ok(report);
        }
        if Instant::now() >= deadline {
            return Ok(report);
        }
        async_sleep(RECOVERY_HEALTH_POLL_INTERVAL).await;
    }
}

/// `kubectl get --raw` through the API server Pod proxy returns success only
/// for a 2xx readiness reply, so the exit status is the probe verdict. The
/// subprocess is bounded and killed on expiry so the enclosing recovery and
/// suite deadlines stay able to cancel the poll.
async fn probe_pod_readiness(
    cluster: &crate::framework::config::ClusterTestConfig,
    pod_name: &str,
    bound: Duration,
) -> PodReadinessProbe {
    let proxy_path = readiness_proxy_path(&cluster.test_namespace, pod_name);
    let observed_at_ms = now_ms();
    let (ready, detail) = match Kubectl::new(cluster)
        .command(["get", "--raw", proxy_path.as_str()])
        .run_bounded(bound)
        .await
    {
        Ok(output) if output.code == Some(0) => (true, None),
        Ok(output) => (
            false,
            Some(truncate_detail(&format!(
                "exit={:?} {}",
                output.code,
                output.stderr.trim()
            ))),
        ),
        Err(error) => (false, Some(truncate_detail(&error.to_string()))),
    };
    PodReadinessProbe {
        pod_name: pod_name.to_string(),
        proxy_path,
        ready,
        observed_at_ms,
        detail,
    }
}

/// An authorization refusal comes from the API server, not from RustFS, so it
/// must not be recorded as a degraded product.
fn readiness_probe_denied(detail: &str) -> bool {
    let lowered = detail.to_ascii_lowercase();
    lowered.contains("forbidden")
        || lowered.contains("unauthorized")
        || lowered.contains("unable to connect to the server")
        || lowered.contains("context was not found")
        || lowered.contains("failed to start command")
}

fn truncate_detail(detail: &str) -> String {
    let detail = detail.trim();
    if detail.chars().count() <= READINESS_DETAIL_LIMIT {
        return detail.to_string();
    }
    let truncated = detail
        .chars()
        .take(READINESS_DETAIL_LIMIT)
        .collect::<String>();
    format!("{truncated}...")
}

#[cfg(test)]
mod tests {
    use super::{readiness_probe_denied, truncate_detail};

    #[test]
    fn api_server_refusals_are_environment_not_product() {
        assert!(readiness_probe_denied(
            "exit=Some(1) Error from server (Forbidden): pods \"rustfs-0\" is forbidden"
        ));
        assert!(readiness_probe_denied(
            "error: You must be logged in to the server (Unauthorized)"
        ));
        assert!(!readiness_probe_denied(
            "exit=Some(1) Error from server (ServiceUnavailable): the server is currently unable to handle the request"
        ));
        assert!(readiness_probe_denied(
            "exit=Some(1) Unable to connect to the server: dial tcp 10.0.0.1:6443: i/o timeout"
        ));
        assert!(!readiness_probe_denied(
            "exit=Some(1) error: connection refused"
        ));
        // A probe cut off by its own bound is a Pod that did not answer, not
        // an API server refusal: it stays a readiness violation to re-poll.
        assert!(!readiness_probe_denied(
            "command timed out after 15s: kubectl --context c get --raw /api/v1/namespaces/ns/pods/p:9000/proxy/health/ready"
        ));
    }

    #[test]
    fn readiness_detail_is_bounded() {
        let long = "x".repeat(1000);
        let detail = truncate_detail(&long);
        assert!(detail.ends_with("..."));
        assert!(detail.chars().count() <= 303);
        assert_eq!(truncate_detail("  short  "), "short");
    }
}
