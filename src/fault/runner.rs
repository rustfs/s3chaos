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
        plan::{FaultPlan, FaultPlanOptions},
        preflight::{PreflightPhase, PreflightSummary, TargetProof},
        reporting::{
            FailureSummary, RunMetadata, write_failure_summary as persist_failure_summary,
            write_failure_summary_if_absent,
        },
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

mod access;
mod injection;
mod recovery;
mod setup;
mod targets;
mod verification;
use crate::fault::backends::runtime::collect_fault_artifacts;
use crate::fault::workload::execution::{
    MixedWorkloadResult, WorkloadPlanArtifact, cleanup_staged_multipart_uploads,
};

struct FaultRunContext {
    spec: &'static FaultScenarioSpec,
    run_id: String,
    workload_plan: WorkloadPlan,
    bucket: String,
    events: RunEventRecorder,
    history: Recorder,
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
    let scenario = FaultScenario::from_config(&config)?;
    let spec = scenarios::scenario_spec(&scenario.name)?;
    let plan = FaultPlan::from_scenario_with_options(
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
    let result = run_fault_case(&config, &collector, &scenario, &plan, &run_id, deadline).await;

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
    plan: &FaultPlan,
    planned_run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    let context = initialize_fault_run(config, collector, scenario, plan, planned_run_id)?;
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
    let result = async {
        run.stage_uploads(&prepared.s3, &mut staged_multipart_uploads)
            .await?;
        let target = deadline
            .run(run.prove_target(&prepared.endpoint, &mut preflight_phases))
            .await?;
        deadline.check()?;
        let mut active = run.activate_fault(&target)?;
        let mut workload = run
            .exercise_fault(&mut prepared, &target, &active, &staged_multipart_uploads)
            .await?;
        deadline.check()?;
        run.prepare_crash_boundary(&mut active.fault, active.fault_active_at_ms)?;
        let removal = run.remove_fault(&mut active.fault)?;
        let recovered = run
            .recover_access(&mut prepared, &mut staged_multipart_uploads)
            .await?;
        let mut evidence =
            run.write_recovery_evidence(&target, &active, &workload, &removal, &recovered)?;
        deadline
            .run(run.verify_recovered(&prepared.s3, &mut workload.workload))
            .await?;
        deadline
            .run(run.recommit(&prepared.s3, &mut workload.workload))
            .await?;
        deadline
            .run(run.verify_final(&prepared.s3, &workload.workload, &mut evidence))
            .await
    }
    .await;
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
    run_completion.complete();
    Ok(())
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
    if let Err(error) = cleanup {
        events
            .record(
                "multipart-cleanup",
                RunEventStatus::Failed,
                format!("{error:#}"),
                None,
            )
            .ok();
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
    pods_before: Vec<PodIdentity>,
    target_proof: TargetProof,
    topology_observed_at_ms: Option<u64>,
    host_storage_proof: Option<HostStorageMutationProof>,
    execution_injection: crate::fault::plan::FaultInjection,
}

struct ActiveFault {
    fault: AppliedFault,
    fault_apply_started_at_ms: u64,
    fault_active_at_ms: u64,
    active_snapshots: Vec<FaultStatusSnapshot>,
    pods_at_fault_activation: Vec<PodIdentity>,
    active_partition_targets: BTreeSet<String>,
    active_fixed_volume_targets: BTreeSet<String>,
    active_fixed_volume_containers: BTreeMap<String, String>,
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
        persist_failure_summary(
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
        if let Some((fault, suffix)) = fault {
            collect_fault_artifacts(self.collector, self.scenario.case_name, fault, suffix)?;
        }
        self.write_failure_summary(FailureSummary::new(
            &self.scenario.name,
            stage,
            classification,
            error.to_string(),
        )?)
    }
}

fn initialize_fault_run(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    plan: &FaultPlan,
    run_id: &str,
) -> Result<FaultRunContext> {
    let spec = scenarios::scenario_spec(&scenario.name)?;
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
    let run_spec = FaultRunSpec::resolved(
        config,
        scenario,
        spec,
        plan,
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
            plan,
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
            "backend": plan.backend_summary(),
            "target": plan.target_summary(),
            "faults": plan.faults().len(),
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

fn write_preflight_summary(
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
}
