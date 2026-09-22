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

use crate::fault::shutdown::RunDeadline;
use crate::fault::{
    host_storage::HostStorageMutationProof,
    quorum::QuorumHealthObservation,
    recovery_health::RecoveryHealthBaseline,
    reporting::{FaultStatusSnapshot, PodIdentity},
    workload::ObjectSpec,
};
use crate::framework::port_forward::PortForwardGuard;
use crate::{
    fault::{
        config::FaultTestConfig,
        diagnostics::diagnose_rustfs_snapshot,
        events::{RunEventRecorder, RunEventStatus},
        fault_lifecycle::AppliedFault,
        history::Recorder,
        plan::{ExecutionPlan, FaultPlan, FaultPlanOptions},
        preflight::{PreflightPhase, PreflightSummary, TargetProof},
        reporting::{FailureSummary, RunMetadata, write_failure_summary_if_absent},
        scenarios::{self, FaultScenario, FaultScenarioSpec},
        spec::FaultRunSpec,
        suite_plan::fault_run_id,
        workload::{S3WorkloadClient, WorkloadPlan},
    },
    framework::artifacts::ArtifactCollector,
};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub(in crate::fault) mod access;
mod ack;
mod injection;
mod node_down;
mod post_recovery;
mod quorum_activation;
mod recovery;
mod setup;
pub(crate) mod targets;
mod verification;
use crate::fault::backends::runtime::collect_fault_artifacts;
use crate::fault::workload::execution::{
    MixedWorkloadResult, WorkloadPlanArtifact, cleanup_staged_multipart_uploads,
};
pub(crate) use access::{
    ensure_s3_access, s3_access, tenant_port_forward, wait_for_ready_tenant,
    wait_for_stable_rustfs_pods, wait_for_tenant_s3,
};
pub(crate) use post_recovery::POST_RECOVERY_SEED_SALT;
pub(crate) use recovery::observe_recovery_health;

#[derive(Clone)]
pub(crate) struct FaultRunContext {
    pub(crate) spec: &'static FaultScenarioSpec,
    pub(crate) run_id: String,
    pub(crate) workload_plan: WorkloadPlan,
    pub(crate) bucket: String,
    pub(crate) events: RunEventRecorder,
    pub(crate) history: Recorder,
}

pub async fn run_selected_scenario_from_env() -> Result<()> {
    let config = FaultTestConfig::from_env()?;
    run_scenario_with_config(config).await
}

pub async fn run_scenario_with_config(mut config: FaultTestConfig) -> Result<()> {
    scenarios::apply_catalog_defaults(&mut config)?;
    let reference_root = config.cluster.artifacts_dir.clone();
    run_prepared_scenario_with_config_and_reference_root(
        config,
        reference_root,
        fault_run_id(),
        RunDeadline::default(),
    )
    .await
}

pub(crate) async fn run_prepared_scenario_with_config_and_reference_root(
    config: FaultTestConfig,
    reference_root: impl Into<PathBuf>,
    run_id: String,
    deadline: RunDeadline,
) -> Result<()> {
    let scenario = FaultScenario::from_config_for_execution(&config)?;
    let spec = scenarios::scenario_spec(&scenario.name)?;
    let plan = ExecutionPlan::from_scenario_with_options(
        &scenario,
        spec,
        FaultPlanOptions::from_config(&config),
    )?;

    config.require_destructive_enabled()?;
    config.validate_cluster(plan.requires_static_storage())?;
    eprintln!(
        "running destructive RustFS fault scenario {} against real Kubernetes context: {}",
        scenario.name, config.cluster.context
    );

    let collector =
        ArtifactCollector::with_reference_root(&config.cluster.artifacts_dir, reference_root)?;
    let result = match &plan {
        ExecutionPlan::Injection(fault_plan) => {
            run_fault_case(
                &config, &collector, &scenario, &plan, fault_plan, &run_id, deadline,
            )
            .await
        }
        ExecutionPlan::Admin(admin_plan) => {
            crate::fault::admin_runner::run_admin_case(
                &config, &collector, &scenario, &plan, admin_plan, &run_id, deadline,
            )
            .await
        }
        ExecutionPlan::StorageRecovery(storage_plan) => {
            crate::fault::storage_recovery_runner::run_storage_recovery_case(
                &config,
                &collector,
                &scenario,
                &plan,
                storage_plan,
                &run_id,
                deadline,
            )
            .await
        }
    };

    if let Err(error) = &result {
        write_failure_summary_if_absent(
            &collector,
            scenario.case_name,
            FailureSummary::new(&scenario.name, "scenario", "unknown", error.to_string())?
                .with_run_id(run_id),
        )
        .ok();
        match collector.collect_kubernetes_snapshot_with_diagnosis(
            scenario.case_name,
            &config.cluster,
            diagnose_rustfs_snapshot,
        ) {
            Ok(report) => {
                eprintln!(
                    "collected fault-test artifacts under {}",
                    report.dir.display()
                );
                eprintln!("{}", report.diagnosis);
            }
            Err(artifact_error) => {
                eprintln!("failed to collect fault-test artifacts after {error}: {artifact_error}");
            }
        }
    }

    result
}

async fn run_fault_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &FaultPlan,
    planned_run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    let context =
        initialize_fault_run(config, collector, scenario, execution_plan, planned_run_id)?;
    let run = FaultRun {
        config,
        collector,
        scenario,
        plan,
        context: &context,
        deadline,
    };
    let mut run_completion = context
        .events
        .completion_guard("run", "fault run failed before successful completion");
    let result = async {
        let mut preflight_phases = Vec::new();
        let mut prepared = deadline
            .run(async {
                run.preflight_backends(&mut preflight_phases)?;
                run.prepare_fixture().await?;
                run.connect_workload().await
            })
            .await?;
        let mut staged_multipart_uploads = BTreeMap::new();
        // Keep the S3 client and access guard alive through cleanup on every exit.
        let result = if scenarios::acknowledged_mutation_kind(&scenario.name).is_some() {
            run.run_ack_triggered_case(
                &mut prepared,
                &mut preflight_phases,
                &mut staged_multipart_uploads,
            )
            .await
        } else {
            async {
                run.stage_uploads(&prepared.s3, &mut staged_multipart_uploads)
                    .await?;
                let mut target = deadline
                    .run(run.prove_target(&prepared.endpoint, &mut preflight_phases))
                    .await?;
                let dm_prepared = if plan.scenario == scenarios::QUORUM_P_DM_EIO_SCENARIO {
                    context.events.record("quorum-dm-preflight", RunEventStatus::Started, "proving both devices before mutation", None)?;
                    let group = crate::fault::backends::quorum_dm::prepare(config, collector, scenario, &context.run_id, &target.target_proof)?;
                    context.events.record("quorum-dm-preflight", RunEventStatus::Succeeded, "both device ownership and baseline read proofs persisted", None)?;
                    target = deadline.run(run.prove_target(&prepared.endpoint, &mut preflight_phases)).await?;
                    Some(group)
                } else { None };
                let mut probe_fixtures = if injection::requires_independent_quorum_probe(&plan.scenario) {
                    let fixtures = quorum_activation::QuorumProbeFixtures::stage(&config.cluster, &config.chaos_namespace, &context.run_id, &target.target_proof, collector, scenario.case_name).await?;
                    let refreshed = deadline.run(run.prove_target(&prepared.endpoint, &mut preflight_phases)).await?;
                    anyhow::ensure!(target.pods_before == refreshed.pods_before, "RustFS Pod generations changed while staging quorum probes");
                    fixtures.require_matches(&context.run_id, &refreshed.target_proof)?;
                    target = refreshed;
                    target.quorum_probe_fixtures = fixtures.fixtures.clone();
                    Some(fixtures)
                } else { None };
                deadline.check()?;
                let mut active = run.activate_fault(&target, dm_prepared).await?;
                let skip_typed_oracle = (plan.scenario == scenarios::QUORUM_P_DM_EIO_SCENARIO && active.deferred_failure.is_some()) || active.quorum_activation.as_ref().is_some_and(|evidence| {
                    evidence.evidence().disposition()
                        == crate::fault::quorum::activation::QuorumActivationDisposition::SkipTypedOracleAndRecover
                });
                let mut workload = if skip_typed_oracle {
                    run.skip_unqualified_quorum_workload(&active)?
                } else {
                    run.exercise_fault(&mut prepared, &target, &active, &staged_multipart_uploads)
                        .await?
                };
                if !skip_typed_oracle {
                    deadline.check()?;
                    if plan.scenario == scenarios::QUORUM_P_DM_EIO_SCENARIO {
                        let calibrated = workload.workload_snapshots.first().and_then(|snapshot| snapshot.quorum_dm_status.as_ref()).context("missing post-workload dm calibration").and_then(crate::fault::backends::quorum_dm::require_qualified);
                        if let Err(error) = calibrated {
                            run.record_failure("fault-evidence", "fault_not_active", &error, None, None)?;
                            active.deferred_failure.get_or_insert_with(|| format!("fault_activation_unproven: {error:#}"));
                        }
                    }
                }
                if !skip_typed_oracle
                    && let Some(activation) = active.quorum_activation.as_mut()
                    && let Err(error) = quorum_activation::verify_quorum_continuity(&config.cluster, activation).await {
                    run.record_failure("fault-evidence", "fault_not_active", &error, None, None)?;
                    active.deferred_failure.get_or_insert_with(|| format!("{error:#}"));
                }
                run.prepare_crash_boundary(&mut active.fault, active.fault_active_at_ms)?;
                run.hold_node_down(&mut prepared, &target, &active.fault)
                    .await?;
                let removal = run.remove_fault(&mut active.fault)?;
                run.cleanup_quorum_activation_canaries(&mut active).await;
                if let Some(fixtures) = probe_fixtures.as_mut() {
                    if let Some(activation) = &active.quorum_activation {
                        for target in &activation.evidence().targets {
                            if target.probe_cleanup.as_ref().is_some_and(|cleanup| cleanup.outcome == crate::fault::quorum::activation::QuorumCanaryCleanupOutcome::Removed) {
                                fixtures.fixtures.remove(&target.pod_name);
                            }
                        }
                    }
                    if let Err(error) = fixtures.cleanup().await {
                        collector.write_text(scenario.case_name, "quorum-probe-cleanup-error.txt", &format!("{error:#}"))?;
                        active.deferred_failure.get_or_insert_with(|| format!("quorum probe cleanup failed: {error:#}"));
                    }
                }
                let recovered = run
                    .recover_access(&mut prepared, &target, &mut staged_multipart_uploads)
                    .await?;
                // A fault whose evidence can still change after removal (a
                // lifecycle replacement that crashes after Ready) is re-read once
                // the recovery gate has passed.
                run.recheck_fault_after_recovery(&mut active.fault)?;
                // The lifecycle evidence is complete once recovery finished, so it
                // is persisted before the write gate: a product failure found by
                // the probe must still leave fault-evidence.json behind for the
                // suite's failed-attempt accounting.
                let mut evidence =
                    run.write_recovery_evidence(&target, &active, &workload, &removal, &recovered)?;
                run.probe_post_recovery_writes(&prepared.s3).await?;
                deadline
                    .run(run.verify_recovered(&prepared.s3, &mut workload.workload))
                    .await?;
                run.recommit(&prepared.s3, &mut workload.workload).await?;
                deadline
                    .run(run.verify_final(&prepared.s3, &workload.workload, &mut evidence))
                    .await?;
                if let Some(reason) = active.deferred_failure.as_deref() {
                    let error = anyhow::anyhow!(reason.to_string());
                    return Err(error);
                }
                Ok(())
            }
            .await
        };
        let cleanup = cleanup_staged_multipart_uploads(
            &prepared.s3,
            &context.history,
            staged_multipart_uploads,
            context.workload_plan.concurrency,
        )
        .await;
        finish_upload_cleanup(&run, result, cleanup)?;
        deadline.check()?;
        context.events.record(
            "run",
            RunEventStatus::Succeeded,
            "fault run completed successfully",
            None,
        )?;
        Ok(())
    }
    .await;

    match result {
        Ok(()) => {
            run_completion.complete();
            Ok(())
        }
        Err(error) => {
            ensure_unclassified_runner_failure(
                collector,
                &context.events,
                &scenario.name,
                scenario.case_name,
                planned_run_id,
                &error,
            )
            .ok();
            Err(error)
        }
    }
}

fn record_unclassified_runner_failure(
    collector: &ArtifactCollector,
    events: &RunEventRecorder,
    scenario_name: &str,
    case_name: &str,
    run_id: &str,
    error: &anyhow::Error,
) -> Result<()> {
    events
        .record("runner", RunEventStatus::Failed, error.to_string(), None)
        .ok();
    write_failure_summary_if_absent(
        collector,
        case_name,
        FailureSummary::new(
            scenario_name,
            "runner",
            "test_or_environment",
            error.to_string(),
        )?
        .with_run_id(run_id)
        .with_case_name(case_name),
    )
}

fn ensure_unclassified_runner_failure(
    collector: &ArtifactCollector,
    events: &RunEventRecorder,
    scenario_name: &str,
    case_name: &str,
    run_id: &str,
    error: &anyhow::Error,
) -> Result<()> {
    let summary_path = collector.case_dir(case_name).join("failure-summary.json");
    if summary_path.is_file() {
        return Ok(());
    }
    record_unclassified_runner_failure(collector, events, scenario_name, case_name, run_id, error)
}

fn finish_upload_cleanup(
    run: &FaultRun<'_>,
    result: Result<()>,
    cleanup: Result<()>,
) -> Result<()> {
    let events = &run.context.events;
    let collector = run.collector;
    let scenario = run.scenario;
    let run_id = &run.context.run_id;
    if let Err(error) = &result {
        ensure_unclassified_runner_failure(
            collector,
            events,
            &scenario.name,
            scenario.case_name,
            run_id,
            error,
        )
        .ok();
    }
    if let Err(error) = cleanup {
        events
            .record(
                "multipart-cleanup",
                RunEventStatus::Failed,
                format!("{error:#}"),
                None,
            )
            .ok();
        if result.is_ok() {
            write_failure_summary_if_absent(
                collector,
                scenario.case_name,
                FailureSummary::new(
                    &scenario.name,
                    "multipart-cleanup",
                    "test_or_environment",
                    format!("{error:#}"),
                )?
                .with_run_id(run_id),
            )
            .ok();
        }
        return match result {
            Ok(()) => Err(error),
            Err(original) => {
                Err(original.context(format!("multipart cleanup also failed: {error:#}")))
            }
        };
    }
    result
}

struct FaultRun<'a> {
    config: &'a FaultTestConfig,
    collector: &'a ArtifactCollector,
    scenario: &'a FaultScenario,
    plan: &'a FaultPlan,
    context: &'a FaultRunContext,
    deadline: RunDeadline,
}

struct PreparedWorkload {
    s3: S3WorkloadClient,
    endpoint: String,
    port_forward: Option<PortForwardGuard>,
    prefilled: Vec<ObjectSpec>,
}

struct ProvenTarget {
    quorum_probe_fixtures: BTreeMap<String, crate::fault::quorum::probe::ProbeFixture>,
    pods_before: Vec<PodIdentity>,
    target_proof: TargetProof,
    topology_observed_at_ms: Option<u64>,
    host_storage_proof: Option<HostStorageMutationProof>,
    execution_injection: crate::fault::plan::FaultInjection,
    /// Healthy RustFS layout captured before the fault; recovery must return
    /// the cluster to exactly this state.
    health_baseline: RecoveryHealthBaseline,
}

struct ActiveFault {
    // Field order is a cleanup invariant: the backend fault must be dropped
    // before the canary guard performs its cancellation fallback.
    fault: AppliedFault,
    fault_prepare_started_at_ms: Option<u64>,
    fault_apply_started_at_ms: u64,
    fault_active_at_ms: u64,
    active_snapshots: Vec<FaultStatusSnapshot>,
    pods_at_fault_activation: Vec<PodIdentity>,
    active_partition_targets: BTreeSet<String>,
    active_fixed_volume_targets: BTreeSet<String>,
    active_fixed_volume_containers: BTreeMap<String, String>,
    quorum_activation: Option<quorum_activation::QuorumCanaryCleanupGuard>,
    deferred_failure: Option<String>,
}

struct FaultWorkload {
    workload: MixedWorkloadResult,
    workload_started_at_ms: u64,
    workload_ended_at_ms: u64,
    require_client_disruption: bool,
    workload_snapshots: Vec<FaultStatusSnapshot>,
    pods_at_workload_snapshot: Vec<PodIdentity>,
    workload_fixed_volume_targets: BTreeSet<String>,
    workload_fixed_volume_containers: BTreeMap<String, String>,
    quorum_health_before_workload: Option<QuorumHealthObservation>,
    quorum_health_after_workload: Option<QuorumHealthObservation>,
    ran_under_fault: bool,
}

struct WorkloadTargetEvidence {
    pods_at_workload_snapshot: Vec<PodIdentity>,
    workload_fixed_volume_targets: BTreeSet<String>,
    workload_fixed_volume_containers: BTreeMap<String, String>,
}

struct FaultRemoval {
    fault_delete_started_at_ms: u64,
    recovery_started_at_ms: u64,
}

impl FaultRun<'_> {
    fn write_failure_summary(&self, summary: FailureSummary) -> Result<()> {
        write_failure_summary_if_absent(
            self.collector,
            self.scenario.case_name,
            summary.with_run_id(&self.context.run_id),
        )
    }

    fn record_failure(
        &self,
        stage: &str,
        classification: &str,
        error: &anyhow::Error,
        details: Option<serde_json::Value>,
        fault: Option<(&AppliedFault, &str)>,
    ) -> Result<()> {
        self.context
            .events
            .record(stage, RunEventStatus::Failed, error.to_string(), details)
            .ok();
        self.write_failure_summary(FailureSummary::new(
            &self.scenario.name,
            stage,
            classification,
            error.to_string(),
        )?)?;
        if let Some((fault, suffix)) = fault {
            collect_fault_artifacts(self.collector, self.scenario.case_name, fault, suffix)?;
        }
        Ok(())
    }
}

pub(crate) fn initialize_fault_run(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    run_id: &str,
) -> Result<FaultRunContext> {
    let spec = scenarios::scenario_spec(&scenario.name)?;
    if spec.impact_policy.requires_availability() {
        crate::fault::workload::execution::require_availability_family_totals(
            &scenario.name,
            scenario.object_count,
            config.workload_operation_mix,
        )?;
    }
    let run_id = run_id.to_string();
    let workload_seed = config.workload_seed.unwrap_or_else(generated_seed);
    let workload_plan = WorkloadPlan::seeded_with_profile(
        workload_seed,
        scenario.object_count,
        config.workload.concurrency,
        config.workload_operation_mix,
        config.workload_payload_distribution.clone(),
        config.workload_hotspot,
    )
    .context("build workload plan")?;
    let bucket = bucket_name(&run_id);
    let events_path = collector
        .case_dir(scenario.case_name)
        .join("run-events.jsonl");
    let events = RunEventRecorder::create(events_path, &scenario.name, &run_id)?;
    let run_spec = FaultRunSpec::resolved_execution(
        config,
        scenario,
        spec,
        execution_plan,
        &workload_plan,
        &run_id,
        &bucket,
    );
    collector.write_text(scenario.case_name, "run-spec.yaml", &run_spec.to_yaml()?)?;
    collector.write_text(scenario.case_name, "run-spec.json", &run_spec.to_json()?)?;
    let history_path = collector.case_dir(scenario.case_name).join("history.jsonl");
    let history = Recorder::create(history_path, &scenario.name, &run_id)?;
    collector.write_text(
        scenario.case_name,
        "run-metadata.json",
        &serde_json::to_string_pretty(&RunMetadata::from_case(
            config,
            scenario,
            spec,
            execution_plan,
            &workload_plan,
            &run_id,
            &bucket,
        ))?,
    )?;
    collector.write_text(
        scenario.case_name,
        "workload-plan.json",
        &serde_json::to_string_pretty(&WorkloadPlanArtifact {
            scenario: &scenario.name,
            run_id: &run_id,
            plan: &workload_plan,
        })?,
    )?;
    events.record(
        "run",
        RunEventStatus::Started,
        "fault run initialized",
        Some(serde_json::json!({
            "bucket": bucket,
            "backend": execution_plan.backend_summary(),
            "target": execution_plan.target_summary(),
            "faults": execution_plan.injection().map_or(0, |plan| plan.faults().len()),
        })),
    )?;
    eprintln!(
        "fault workload seed={} objects={} concurrency={} payload_bytes={}",
        workload_plan.seed,
        workload_plan.object_count,
        workload_plan.concurrency,
        workload_plan.total_payload_bytes
    );

    Ok(FaultRunContext {
        spec,
        run_id,
        workload_plan,
        bucket,
        events,
        history,
    })
}

pub(crate) fn write_preflight_summary(
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    config: &FaultTestConfig,
    run_id: &str,
    phases: &[PreflightPhase],
) -> Result<()> {
    let summary = PreflightSummary::single_run(config, &scenario.name, run_id, phases.to_vec());
    collector.write_text(
        scenario.case_name,
        "preflight-summary.json",
        &serde_json::to_string_pretty(&summary)?,
    )?;
    Ok(())
}

fn bucket_name(run_id: &str) -> String {
    let suffix = run_id
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(16)
        .collect::<String>()
        .to_ascii_lowercase();
    format!("rustfs-fault-{suffix}")
}

fn generated_seed() -> u64 {
    let run = Uuid::new_v4();
    let mut bytes = [0; 8];
    bytes.copy_from_slice(&run.as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn warp_bucket_name(run_id: &str) -> String {
    format!("{}-warp", bucket_name(run_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_bucket_name_is_s3_compatible_and_run_scoped() {
        assert_eq!(
            bucket_name("run-12345678-abcd-efgh"),
            "rustfs-fault-run12345678abcde"
        );
        assert_eq!(
            warp_bucket_name("run-12345678-abcd-efgh"),
            "rustfs-fault-run12345678abcde-warp"
        );
    }

    #[test]
    fn suite_deadline_writes_a_runner_failure_stage_and_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let case_name = "fault_io_eio_preserves_committed_objects";
        let run_id = "run-timeout";
        let events = RunEventRecorder::create(
            collector.case_dir(case_name).join("run-events.jsonl"),
            "io-eio",
            run_id,
        )
        .expect("events");
        events
            .record("run", RunEventStatus::Started, "started", None)
            .expect("run start");
        let deadline = RunDeadline::new(Some(0)).expect("deadline");
        let error = deadline.check().expect_err("expired suite deadline");

        record_unclassified_runner_failure(
            &collector, &events, "io-eio", case_name, run_id, &error,
        )
        .expect("runner failure evidence");
        events
            .record("run", RunEventStatus::Failed, "run failed", None)
            .expect("run terminal");

        let summary: FailureSummary = serde_json::from_str(
            &std::fs::read_to_string(collector.case_dir(case_name).join("failure-summary.json"))
                .expect("summary"),
        )
        .expect("summary JSON");
        assert_eq!(summary.stage, "runner");
        assert_eq!(
            summary.phase(),
            Some(crate::fault::reporting::FailurePhase::Runner)
        );
        assert_eq!(summary.run_id.as_deref(), Some(run_id));
        let events =
            std::fs::read_to_string(collector.case_dir(case_name).join("run-events.jsonl"))
                .expect("events text");
        assert!(events.contains("\"stage\":\"runner\",\"status\":\"failed\""));
    }

    #[test]
    fn primary_runner_failure_is_persisted_before_cleanup_failure() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let case_name = "fault_io_eio_preserves_committed_objects";
        let run_id = "run-timeout-cleanup";
        let events = RunEventRecorder::create(
            collector.case_dir(case_name).join("run-events.jsonl"),
            "io-eio",
            run_id,
        )
        .expect("events");
        let primary = anyhow::anyhow!("suite deadline reached");
        ensure_unclassified_runner_failure(
            &collector, &events, "io-eio", case_name, run_id, &primary,
        )
        .expect("primary summary");
        write_failure_summary_if_absent(
            &collector,
            case_name,
            FailureSummary::new(
                "io-eio",
                "multipart-cleanup",
                "test_or_environment",
                "abort failed",
            )
            .expect("cleanup summary")
            .with_run_id(run_id),
        )
        .expect("secondary cleanup summary");

        let summary: FailureSummary = serde_json::from_str(
            &std::fs::read_to_string(collector.case_dir(case_name).join("failure-summary.json"))
                .expect("summary"),
        )
        .expect("summary JSON");
        assert_eq!(summary.stage, "runner");
        assert!(summary.message.contains("suite deadline"));
    }
}
