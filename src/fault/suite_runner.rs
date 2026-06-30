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
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::fault::{
    artifact_validation::{ArtifactValidationOptions, validate_fault_artifacts},
    config::{FaultTestConfig, FaultWorkloadProfile, default_percent_for_scenario},
    plan::{FaultPlan, FaultPlanOptions, FaultSelection, FaultTarget, FaultWorkloadMode},
    runner::run_scenario_with_config,
    scenarios::{FaultScenario, FaultScenarioSpec, scenario_spec},
    spec::FaultRunArtifactSpec,
    suite::{ResolvedFaultSuite, ResolvedFaultSuiteScenario, resolve_fault_suite_yaml},
};

pub const FAULT_SUITE_PLAN_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const FAULT_SUITE_PLAN_KIND: &str = "FaultSuitePlan";
pub const FAULT_SUITE_RUN_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const FAULT_SUITE_RUN_KIND: &str = "FaultSuiteRun";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlan {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub suite: String,
    pub run_id: String,
    pub suite_seed: u64,
    pub artifact_root: String,
    pub cluster: FaultSuitePlanCluster,
    pub budgets: FaultSuitePlanBudgets,
    pub requires_chaos_mesh: bool,
    pub requires_static_storage: bool,
    pub required_crds: Vec<String>,
    pub required_tools: Vec<String>,
    pub attempts: Vec<FaultSuitePlanAttempt>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanCluster {
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub storage_class: String,
    pub rustfs_image: String,
    pub chaos_namespace: String,
    pub use_cluster_ip: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanBudgets {
    pub stop_on_first_failure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_stable_window_seconds: Option<u64>,
    pub cluster_timeout_seconds: u64,
    pub minimum_required_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanAttempt {
    pub index: usize,
    pub scenario: String,
    pub case_name: String,
    pub repetition: usize,
    pub priority: String,
    pub isolation: String,
    pub impact_policy: String,
    pub expected_backend: String,
    pub catalog_target: String,
    pub duration_seconds: u64,
    pub workload: FaultSuitePlanWorkload,
    pub faults: Vec<FaultSuitePlanFault>,
    pub requires_chaos_mesh: bool,
    pub requires_static_storage: bool,
    pub crds: Vec<String>,
    pub required_tools: Vec<String>,
    pub artifacts: FaultSuitePlanArtifacts,
    pub budget: FaultSuitePlanBudgetImpact,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanWorkload {
    pub mode: String,
    pub objects: usize,
    pub concurrency: usize,
    pub prefill_concurrency: usize,
    pub request_timeout_seconds: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanFault {
    pub name: String,
    pub kind: String,
    pub backend: String,
    pub target: FaultSuitePlanTarget,
    pub selection: FaultSuitePlanSelection,
    pub duration_seconds: u64,
    pub observability: String,
    pub conflict_domain: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanTarget {
    pub kind: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanSelection {
    pub kind: String,
    pub value: u32,
    pub summary: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanArtifacts {
    pub attempt_dir: String,
    pub case_dir: String,
    pub required: Vec<String>,
    pub event_stream: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanBudgetImpact {
    pub duration_seconds: u64,
    pub recovery_timeout_seconds: u64,
    pub minimum_required_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_before_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_after_minimum_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
struct PlannedFaultSuiteAttempt {
    plan: FaultSuitePlanAttempt,
    config: FaultTestConfig,
}

#[derive(Debug, Clone)]
struct FaultSuiteExecutionPlan {
    suite: ResolvedFaultSuite,
    plan: FaultSuitePlan,
    attempts: Vec<PlannedFaultSuiteAttempt>,
}

struct FaultSuitePlanAttemptInput<'a> {
    index: usize,
    scenario: &'a ResolvedFaultSuiteScenario,
    repetition: usize,
    config: &'a FaultTestConfig,
    spec: &'a FaultScenarioSpec,
    fault_plan: &'a FaultPlan,
    attempt_dir: &'a Path,
    budget: FaultSuitePlanBudgetImpact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuiteRunStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuiteAttemptStatus {
    Running,
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuiteRunSummary {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub suite: String,
    pub run_id: String,
    pub status: SuiteRunStatus,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elapsed_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    pub stop_on_first_failure: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    pub total_client_disruptions: usize,
    pub attempts: Vec<FaultSuiteRunAttempt>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuiteRunAttempt {
    pub index: usize,
    pub scenario: String,
    pub repetition: usize,
    pub status: SuiteAttemptStatus,
    pub started_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at_ms: Option<u64>,
    pub artifacts_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recommitted: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub committed: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn plan_fault_suite_from_yaml(path: impl AsRef<Path>) -> Result<FaultSuitePlan> {
    let suite = resolve_fault_suite_yaml(path)?;
    let base_config = FaultTestConfig::from_env()?;
    Ok(build_fault_suite_execution_plan(suite, base_config, suite_run_id())?.plan)
}

pub async fn run_fault_suite_from_yaml(path: impl AsRef<Path>) -> Result<()> {
    let suite = resolve_fault_suite_yaml(&path)?;
    let base_config = FaultTestConfig::from_env()?;
    base_config.require_destructive_enabled()?;
    let execution_plan = build_fault_suite_execution_plan(suite, base_config, suite_run_id())?;

    let suite_root = PathBuf::from(&execution_plan.plan.artifact_root);
    fs::create_dir_all(&suite_root)
        .with_context(|| format!("create suite artifact root {}", suite_root.display()))?;
    let summary_path = suite_root.join("suite-summary.json");
    let plan_path = suite_root.join("suite-plan.json");
    let started = Instant::now();
    let mut summary =
        FaultSuiteRunSummary::started(&execution_plan.suite, execution_plan.plan.run_id.clone());
    fs::write(&plan_path, execution_plan.plan.to_json()?)
        .with_context(|| format!("write suite plan {}", plan_path.display()))?;
    write_summary(&summary_path, &summary)?;

    eprintln!(
        "running destructive RustFS fault suite {} run_id={} artifacts={}",
        execution_plan.suite.metadata.name,
        execution_plan.plan.run_id,
        suite_root.display()
    );

    'suite: for planned in &execution_plan.attempts {
        if let Some(reason) = suite_duration_budget_failure(
            started.elapsed(),
            execution_plan.suite.budgets.max_duration_seconds,
            &planned.config,
            &planned.plan.scenario,
            planned.plan.repetition,
        ) {
            summary.fail(reason);
            write_summary(&summary_path, &summary)?;
            break 'suite;
        }

        let attempt_dir = Path::new(&planned.plan.artifacts.attempt_dir);
        let mut attempt = FaultSuiteRunAttempt::running(
            planned.plan.index,
            &planned.plan.scenario,
            planned.plan.repetition,
            attempt_dir,
        );
        write_attempt_started(&mut summary, &summary_path, attempt.clone())?;

        eprintln!(
            "suite attempt {} scenario={} repetition={} artifacts={}",
            planned.plan.index,
            planned.plan.scenario,
            planned.plan.repetition,
            attempt_dir.display()
        );

        let result = run_scenario_with_config(planned.config.clone()).await;
        match result {
            Ok(()) => match validate_attempt_artifacts(&planned.config) {
                Ok(report) => {
                    summary.total_client_disruptions += report.client_disruptions;
                    attempt.succeed(
                        report.seed,
                        report.client_disruptions,
                        report.recommitted,
                        report.committed,
                    );
                    replace_last_attempt(&mut summary, attempt);
                    if let Some(max_disruptions) =
                        execution_plan.suite.budgets.max_client_disruptions
                        && summary.total_client_disruptions > max_disruptions
                    {
                        summary.fail(format!(
                            "suite maxClientDisruptions budget {max_disruptions} was exceeded with {} disruptions",
                            summary.total_client_disruptions
                        ));
                        write_summary(&summary_path, &summary)?;
                        break 'suite;
                    }
                }
                Err(error) => {
                    attempt.fail(format!("artifact validation failed: {error}"));
                    replace_last_attempt(&mut summary, attempt);
                    summary.fail(format!(
                        "scenario {} repetition {} artifact validation failed: {error}",
                        planned.plan.scenario, planned.plan.repetition
                    ));
                }
            },
            Err(error) => {
                attempt.fail(error.to_string());
                replace_last_attempt(&mut summary, attempt);
                summary.fail(format!(
                    "scenario {} repetition {} failed: {error}",
                    planned.plan.scenario, planned.plan.repetition
                ));
            }
        }

        write_summary(&summary_path, &summary)?;
        if summary.status == SuiteRunStatus::Failed
            && execution_plan.suite.budgets.stop_on_first_failure
        {
            break 'suite;
        }
    }

    if summary.status == SuiteRunStatus::Running {
        summary.succeed();
    }
    summary.ended_at_ms = Some(now_ms());
    summary.elapsed_seconds = Some(started.elapsed().as_secs());
    write_summary(&summary_path, &summary)?;

    eprintln!("suite summary: {}", summary_path.display());
    if summary.status == SuiteRunStatus::Failed {
        bail!(
            "fault suite {} failed; summary: {}",
            execution_plan.suite.metadata.name,
            summary_path.display()
        );
    }

    Ok(())
}

fn build_fault_suite_execution_plan(
    suite: ResolvedFaultSuite,
    mut base_config: FaultTestConfig,
    run_id: String,
) -> Result<FaultSuiteExecutionPlan> {
    validate_suite_runtime_contract(&suite, &base_config)?;
    if base_config.workload_seed.is_none() {
        base_config.workload_seed = Some(generated_suite_seed());
    }
    let suite_seed = base_config
        .workload_seed
        .expect("suite planning sets a seed before expanding attempts");
    let suite_root = suite_run_root(&base_config, &suite, &run_id);
    let mut attempts = Vec::new();
    let mut attempt_index = 0usize;
    let mut minimum_required_seconds = 0u64;
    let mut remaining = suite.budgets.max_duration_seconds;
    let mut required_crds = BTreeSet::new();
    let mut required_tools = BTreeSet::new();
    let mut requires_chaos_mesh = false;
    let mut requires_static_storage = false;

    for scenario in &suite.scenarios {
        for repetition in 1..=scenario.repetitions {
            attempt_index += 1;
            let attempt_dir = suite_root.join(format!(
                "{attempt_index:03}-{}-r{repetition}",
                scenario.name
            ));
            let config = scenario_config(
                &base_config,
                &suite,
                scenario,
                repetition,
                attempt_index,
                &attempt_dir,
            )?;
            let fault_scenario = FaultScenario::from_config(&config)?;
            let spec = scenario_spec(&fault_scenario.name)?;
            let fault_plan = FaultPlan::from_scenario_with_options(
                &fault_scenario,
                spec,
                FaultPlanOptions::from_config(&config),
            )?;
            let required = attempt_minimum_required_seconds(&config)?;
            let remaining_before = remaining;
            let remaining_after = match remaining {
                Some(before) => {
                    if before < required {
                        bail!(
                            "suite maxDuration budget {before}s cannot cover planned scenario {} repetition {} requiring at least {required}s",
                            scenario.name,
                            repetition
                        );
                    }
                    Some(before - required)
                }
                None => None,
            };
            remaining = remaining_after;
            minimum_required_seconds = minimum_required_seconds
                .checked_add(required)
                .context("suite minimum required duration overflowed")?;
            requires_chaos_mesh |= spec.requires_chaos_mesh();
            requires_static_storage |= spec.requires_static_storage();
            required_crds.extend(spec.crds.iter().map(|crd| (*crd).to_string()));
            required_tools.extend(spec.required_tools.iter().map(|tool| (*tool).to_string()));

            let budget = FaultSuitePlanBudgetImpact {
                duration_seconds: config.duration.as_secs(),
                recovery_timeout_seconds: config.cluster.timeout.as_secs(),
                minimum_required_seconds: required,
                remaining_before_seconds: remaining_before,
                remaining_after_minimum_seconds: remaining_after,
            };
            let plan = FaultSuitePlanAttempt::from_attempt(FaultSuitePlanAttemptInput {
                index: attempt_index,
                scenario,
                repetition,
                config: &config,
                spec,
                fault_plan: &fault_plan,
                attempt_dir: &attempt_dir,
                budget,
            })?;
            attempts.push(PlannedFaultSuiteAttempt { plan, config });
        }
    }

    let plan_attempts = attempts
        .iter()
        .map(|attempt| attempt.plan.clone())
        .collect();
    let plan = FaultSuitePlan {
        api_version: FAULT_SUITE_PLAN_API_VERSION.to_string(),
        kind: FAULT_SUITE_PLAN_KIND.to_string(),
        suite: suite.metadata.name.clone(),
        run_id,
        suite_seed,
        artifact_root: suite_root.display().to_string(),
        cluster: FaultSuitePlanCluster::from_config(&base_config),
        budgets: FaultSuitePlanBudgets {
            stop_on_first_failure: suite.budgets.stop_on_first_failure,
            max_duration_seconds: suite.budgets.max_duration_seconds,
            max_client_disruptions: suite.budgets.max_client_disruptions,
            recovery_stable_window_seconds: suite.budgets.recovery_stable_window_seconds,
            cluster_timeout_seconds: base_config.cluster.timeout.as_secs(),
            minimum_required_seconds,
        },
        requires_chaos_mesh,
        requires_static_storage,
        required_crds: required_crds.into_iter().collect(),
        required_tools: required_tools.into_iter().collect(),
        attempts: plan_attempts,
    };

    Ok(FaultSuiteExecutionPlan {
        suite,
        plan,
        attempts,
    })
}

impl FaultSuitePlan {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

impl FaultSuitePlanCluster {
    fn from_config(config: &FaultTestConfig) -> Self {
        Self {
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            storage_class: config.cluster.storage_class.clone(),
            rustfs_image: config.cluster.rustfs_image.clone(),
            chaos_namespace: config.chaos_namespace.clone(),
            use_cluster_ip: config.use_cluster_ip,
        }
    }
}

impl FaultSuitePlanAttempt {
    fn from_attempt(input: FaultSuitePlanAttemptInput<'_>) -> Result<Self> {
        let seed = input
            .config
            .workload_seed
            .context("suite attempt workload seed must be resolved during planning")?;
        let case_dir = input.attempt_dir.join(input.spec.case_name);
        let faults = input
            .fault_plan
            .faults()
            .iter()
            .enumerate()
            .map(|(fault_index, fault)| {
                FaultSuitePlanFault::from_fault(fault_index, input.scenario, input.spec, fault)
            })
            .collect();

        Ok(Self {
            index: input.index,
            scenario: input.scenario.name.clone(),
            case_name: input.spec.case_name.to_string(),
            repetition: input.repetition,
            priority: input.spec.priority.as_str().to_string(),
            isolation: input.spec.isolation.as_str().to_string(),
            impact_policy: input.spec.impact_policy.as_str().to_string(),
            expected_backend: input.spec.backend.as_str().to_string(),
            catalog_target: input.spec.target.to_string(),
            duration_seconds: input.config.duration.as_secs(),
            workload: FaultSuitePlanWorkload {
                mode: workload_mode_name(input.fault_plan.workload_mode).to_string(),
                objects: input.config.workload.object_count,
                concurrency: input.config.workload.concurrency,
                prefill_concurrency: input.config.prefill_concurrency,
                request_timeout_seconds: input.config.request_timeout.as_secs(),
                seed,
            },
            faults,
            requires_chaos_mesh: input.spec.requires_chaos_mesh(),
            requires_static_storage: input.spec.requires_static_storage(),
            crds: input
                .spec
                .crds
                .iter()
                .map(|crd| (*crd).to_string())
                .collect(),
            required_tools: input
                .spec
                .required_tools
                .iter()
                .map(|tool| (*tool).to_string())
                .collect(),
            artifacts: FaultSuitePlanArtifacts {
                attempt_dir: input.attempt_dir.display().to_string(),
                case_dir: case_dir.display().to_string(),
                required: FaultRunArtifactSpec::required_names(),
                event_stream: "run-events.jsonl".to_string(),
            },
            budget: input.budget,
        })
    }
}

impl FaultSuitePlanFault {
    fn from_fault(
        index: usize,
        scenario: &ResolvedFaultSuiteScenario,
        spec: &FaultScenarioSpec,
        fault: &crate::fault::plan::FaultInjection,
    ) -> Self {
        Self {
            name: format!("{}-{:02}-{}", scenario.name, index, fault.kind().as_str()),
            kind: fault.kind().as_str().to_string(),
            backend: fault.backend().as_str().to_string(),
            target: FaultSuitePlanTarget::from_target(fault.target()),
            selection: FaultSuitePlanSelection::from_selection(fault.selection()),
            duration_seconds: fault.duration().as_secs(),
            observability: spec.observability.to_string(),
            conflict_domain: spec.conflict_domain.to_string(),
        }
    }
}

impl FaultSuitePlanTarget {
    fn from_target(target: &FaultTarget) -> Self {
        match target {
            FaultTarget::RustfsVolume { path } => Self {
                kind: "rustfs-volume".to_string(),
                summary: target.summary(),
                path: Some(path.clone()),
            },
            FaultTarget::RustfsServerPod => Self {
                kind: "rustfs-server-pod".to_string(),
                summary: target.summary(),
                path: None,
            },
            FaultTarget::RustfsServerPeerNetwork => Self {
                kind: "rustfs-server-peer-network".to_string(),
                summary: target.summary(),
                path: None,
            },
            FaultTarget::RustfsServerResource => Self {
                kind: "rustfs-server-resource".to_string(),
                summary: target.summary(),
                path: None,
            },
            FaultTarget::DedicatedBlockDevice => Self {
                kind: "dedicated-block-device".to_string(),
                summary: target.summary(),
                path: None,
            },
        }
    }
}

impl FaultSuitePlanSelection {
    fn from_selection(selection: FaultSelection) -> Self {
        match selection {
            FaultSelection::Percent(percent) => Self {
                kind: "percent".to_string(),
                value: percent.into(),
                summary: selection.summary(),
            },
            FaultSelection::FixedTargets(count) => Self {
                kind: "fixed-targets".to_string(),
                value: count,
                summary: selection.summary(),
            },
        }
    }
}

fn scenario_config(
    base: &FaultTestConfig,
    suite: &ResolvedFaultSuite,
    scenario: &ResolvedFaultSuiteScenario,
    repetition: usize,
    attempt_index: usize,
    attempt_dir: &Path,
) -> Result<FaultTestConfig> {
    let mut config = base.clone();
    config.scenario = scenario.name.clone();
    if let Some(duration_seconds) = scenario.duration_seconds {
        config.duration = Duration::from_secs(duration_seconds);
    }
    if let Some(percent) = scenario.percent {
        config.percent = percent;
        config.percent_overridden = true;
    } else if !base.percent_overridden {
        config.percent = default_percent_for_scenario(&scenario.name);
        config.percent_overridden = false;
    }
    if let Some(workload) = &scenario.workload {
        let object_count = workload.objects.unwrap_or(config.workload.object_count);
        let concurrency = workload.concurrency.unwrap_or(config.workload.concurrency);
        config.workload = FaultWorkloadProfile::new(object_count, concurrency)?;
        config.prefill_concurrency = config
            .prefill_concurrency
            .min(config.workload.concurrency)
            .min(config.workload.object_count)
            .max(1);
    }
    if let Some(stable_window_seconds) = suite.budgets.recovery_stable_window_seconds {
        config.rustfs_pod_stable_window = Duration::from_secs(stable_window_seconds);
        ensure!(
            config.rustfs_pod_stable_window < config.cluster.timeout,
            "suite budgets.recoveryStableWindowSeconds must be less than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS"
        );
    }
    config.workload_seed = attempt_seed(base.workload_seed, attempt_index, repetition);
    config.cluster.artifacts_dir = attempt_dir.to_path_buf();
    Ok(config)
}

fn validate_suite_runtime_contract(
    suite: &ResolvedFaultSuite,
    base_config: &FaultTestConfig,
) -> Result<()> {
    if let Some(stable_window_seconds) = suite.budgets.recovery_stable_window_seconds {
        ensure!(
            Duration::from_secs(stable_window_seconds) < base_config.cluster.timeout,
            "suite budgets.recoveryStableWindowSeconds must be less than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS"
        );
    }
    Ok(())
}

fn suite_duration_budget_failure(
    elapsed: Duration,
    max_duration_seconds: Option<u64>,
    config: &FaultTestConfig,
    scenario: &str,
    repetition: usize,
) -> Option<String> {
    let max_duration_seconds = max_duration_seconds?;
    let max_duration = Duration::from_secs(max_duration_seconds);
    let remaining = match max_duration.checked_sub(elapsed) {
        Some(remaining) => remaining,
        None => {
            return Some(format!(
                "suite maxDuration budget {max_duration_seconds}s was reached before starting scenario {scenario} repetition {repetition}"
            ));
        }
    };
    let required = config
        .duration
        .checked_add(config.cluster.timeout)
        .unwrap_or(Duration::MAX);
    if remaining < required {
        return Some(format!(
            "suite maxDuration budget {max_duration_seconds}s leaves {}s, but scenario {scenario} repetition {repetition} needs at least {}s (duration {}s + recovery timeout {}s)",
            remaining.as_secs(),
            required.as_secs(),
            config.duration.as_secs(),
            config.cluster.timeout.as_secs()
        ));
    }
    None
}

fn attempt_minimum_required_seconds(config: &FaultTestConfig) -> Result<u64> {
    config
        .duration
        .checked_add(config.cluster.timeout)
        .context("suite attempt duration plus recovery timeout overflowed")
        .map(|required| required.as_secs())
}

fn attempt_seed(base_seed: Option<u64>, attempt_index: usize, repetition: usize) -> Option<u64> {
    base_seed.map(|seed| seed ^ ((attempt_index as u64) << 32) ^ repetition as u64)
}

fn validate_attempt_artifacts(
    config: &FaultTestConfig,
) -> Result<crate::fault::artifact_validation::ArtifactValidationReport> {
    let options = ArtifactValidationOptions {
        scenario: config.scenario.clone(),
        artifact_root: config.cluster.artifacts_dir.clone(),
        expected_workload_objects: config.workload.object_count,
        expected_workload_concurrency: config.workload.concurrency,
        expected_rustfs_pod_count: config.expected_rustfs_pod_count,
        expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
        expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
    };
    validate_fault_artifacts(&options)
}

fn suite_run_root(config: &FaultTestConfig, suite: &ResolvedFaultSuite, run_id: &str) -> PathBuf {
    config
        .cluster
        .artifacts_dir
        .join(&suite.metadata.name)
        .join(run_id)
}

fn suite_run_id() -> String {
    format!("suite-{}", Uuid::new_v4())
}

fn generated_suite_seed() -> u64 {
    let bytes = *Uuid::new_v4().as_bytes();
    u64::from_le_bytes(
        bytes[0..8]
            .try_into()
            .expect("uuid contains at least eight bytes"),
    )
}

fn workload_mode_name(mode: FaultWorkloadMode) -> &'static str {
    match mode {
        FaultWorkloadMode::S3Mixed => "s3-mixed",
        FaultWorkloadMode::S3MixedWithWarp => "s3-mixed-with-warp",
    }
}

fn write_attempt_started(
    summary: &mut FaultSuiteRunSummary,
    path: &Path,
    attempt: FaultSuiteRunAttempt,
) -> Result<()> {
    summary.attempts.push(attempt);
    write_summary(path, summary)
}

fn replace_last_attempt(summary: &mut FaultSuiteRunSummary, attempt: FaultSuiteRunAttempt) {
    if let Some(last) = summary.attempts.last_mut() {
        *last = attempt;
    }
}

fn write_summary(path: &Path, summary: &FaultSuiteRunSummary) -> Result<()> {
    fs::write(path, serde_json::to_string_pretty(summary)?)
        .with_context(|| format!("write suite summary {}", path.display()))
}

impl FaultSuiteRunSummary {
    fn started(suite: &ResolvedFaultSuite, run_id: String) -> Self {
        Self {
            api_version: FAULT_SUITE_RUN_API_VERSION.to_string(),
            kind: FAULT_SUITE_RUN_KIND.to_string(),
            suite: suite.metadata.name.clone(),
            run_id,
            status: SuiteRunStatus::Running,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            elapsed_seconds: None,
            failure_reason: None,
            stop_on_first_failure: suite.budgets.stop_on_first_failure,
            max_duration_seconds: suite.budgets.max_duration_seconds,
            max_client_disruptions: suite.budgets.max_client_disruptions,
            total_client_disruptions: 0,
            attempts: Vec::new(),
        }
    }

    fn succeed(&mut self) {
        self.status = SuiteRunStatus::Succeeded;
    }

    fn fail(&mut self, reason: String) {
        self.status = SuiteRunStatus::Failed;
        if self.failure_reason.is_none() {
            self.failure_reason = Some(reason);
        }
    }
}

impl FaultSuiteRunAttempt {
    fn running(index: usize, scenario: &str, repetition: usize, artifacts_dir: &Path) -> Self {
        Self {
            index,
            scenario: scenario.to_string(),
            repetition,
            status: SuiteAttemptStatus::Running,
            started_at_ms: now_ms(),
            ended_at_ms: None,
            artifacts_dir: artifacts_dir.display().to_string(),
            seed: None,
            client_disruptions: None,
            recommitted: None,
            committed: None,
            error: None,
        }
    }

    fn succeed(&mut self, seed: u64, disruptions: usize, recommitted: usize, committed: usize) {
        self.status = SuiteAttemptStatus::Succeeded;
        self.ended_at_ms = Some(now_ms());
        self.seed = Some(seed);
        self.client_disruptions = Some(disruptions);
        self.recommitted = Some(recommitted);
        self.committed = Some(committed);
    }

    fn fail(&mut self, error: String) {
        self.status = SuiteAttemptStatus::Failed;
        self.ended_at_ms = Some(now_ms());
        self.error = Some(error);
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        attempt_seed, build_fault_suite_execution_plan, scenario_config,
        suite_duration_budget_failure, validate_suite_runtime_contract,
    };
    use crate::fault::{config::FaultTestConfig, suite::FaultSuite};
    use std::{path::PathBuf, time::Duration};

    #[test]
    fn suite_plan_expands_attempts_artifacts_faults_and_budget() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 30m
  maxClientDisruptions: 10
  recoveryStableWindowSeconds: 30
scenarios:
  - name: io-eio
    repetitions: 2
    duration: 10m
    percent: 35
    workload:
      objects: 64
      concurrency: 8
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = PathBuf::from("target/fault-tests/artifacts");

        let execution = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect("suite execution plan");

        assert_eq!(execution.plan.kind, "FaultSuitePlan");
        assert_eq!(execution.plan.suite, "rustfs-smoke");
        assert_eq!(execution.plan.run_id, "suite-fixed");
        assert_eq!(execution.plan.suite_seed, 100);
        assert_eq!(execution.plan.budgets.max_duration_seconds, Some(1800));
        assert_eq!(execution.plan.budgets.minimum_required_seconds, 1800);
        assert!(execution.plan.requires_chaos_mesh);
        assert_eq!(
            execution.plan.required_crds,
            vec!["iochaos.chaos-mesh.org".to_string()]
        );
        assert_eq!(execution.plan.attempts.len(), 2);

        let first = &execution.plan.attempts[0];
        assert_eq!(first.index, 1);
        assert_eq!(first.scenario, "io-eio");
        assert_eq!(first.case_name, "fault_io_eio_preserves_committed_objects");
        assert_eq!(first.duration_seconds, 600);
        assert_eq!(first.workload.objects, 64);
        assert_eq!(first.workload.concurrency, 8);
        assert_eq!(first.workload.seed, attempt_seed(Some(100), 1, 1).unwrap());
        assert!(first.artifacts.attempt_dir.ends_with("001-io-eio-r1"));
        assert!(
            first
                .artifacts
                .case_dir
                .ends_with("001-io-eio-r1/fault_io_eio_preserves_committed_objects")
        );
        assert!(
            first
                .artifacts
                .required
                .contains(&"run-spec.json".to_string())
        );
        assert_eq!(first.budget.minimum_required_seconds, 900);
        assert_eq!(first.budget.remaining_before_seconds, Some(1800));
        assert_eq!(first.budget.remaining_after_minimum_seconds, Some(900));

        let fault = &first.faults[0];
        assert_eq!(fault.kind, "rustfs_volume_io_error");
        assert_eq!(fault.backend, "chaos-mesh-io-chaos");
        assert_eq!(fault.target.kind, "rustfs-volume");
        assert_eq!(fault.target.path.as_deref(), Some("/data/rustfs0"));
        assert_eq!(fault.selection.kind, "percent");
        assert_eq!(fault.selection.value, 35);
        assert_eq!(
            execution.attempts[0].config.cluster.artifacts_dir,
            PathBuf::from("target/fault-tests/artifacts/rustfs-smoke/suite-fixed/001-io-eio-r1")
        );
    }

    #[test]
    fn suite_plan_rejects_impossible_max_duration_before_execution() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 10m
scenarios:
  - name: io-eio
    duration: 10m
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);

        let error = build_fault_suite_execution_plan(suite, base, "suite-fixed".to_string())
            .expect_err("budget should fail before execution");

        assert!(error.to_string().contains("cannot cover planned scenario"));
    }

    #[test]
    fn scenario_config_applies_suite_overrides_and_unique_artifacts() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  recoveryStableWindowSeconds: 30
scenarios:
  - name: io-eio
    duration: 10m
    percent: 35
    workload:
      objects: 64
      concurrency: 8
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let attempt_dir = std::path::PathBuf::from("target/fault-tests/suite/attempt-1");

        let config = scenario_config(&base, &suite, &suite.scenarios[0], 1, 1, &attempt_dir)
            .expect("scenario config");

        assert_eq!(config.scenario, "io-eio");
        assert_eq!(config.duration, Duration::from_secs(600));
        assert_eq!(config.percent, 35);
        assert!(config.percent_overridden);
        assert_eq!(config.workload.object_count, 64);
        assert_eq!(config.workload.concurrency, 8);
        assert_eq!(config.prefill_concurrency, 8);
        assert_eq!(config.rustfs_pod_stable_window, Duration::from_secs(30));
        assert_eq!(config.cluster.artifacts_dir, attempt_dir);
    }

    #[test]
    fn scenario_config_uses_per_scenario_default_percent_without_global_override() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: disk-full
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let base = FaultTestConfig::for_test("real-cluster", "fast-csi");

        let config = scenario_config(
            &base,
            &suite,
            &suite.scenarios[0],
            1,
            1,
            std::path::Path::new("target/fault-tests/suite/disk-full"),
        )
        .expect("scenario config");

        assert_eq!(config.percent, 100);
        assert!(!config.percent_overridden);
    }

    #[test]
    fn attempt_seed_keeps_repetitions_distinct_when_seed_is_fixed() {
        assert_ne!(attempt_seed(Some(42), 1, 1), attempt_seed(Some(42), 2, 1));
        assert_eq!(attempt_seed(None, 1, 1), None);
    }

    #[test]
    fn suite_duration_budget_requires_room_for_attempt_and_recovery() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.duration = Duration::from_secs(600);
        config.cluster.timeout = Duration::from_secs(300);

        assert!(
            suite_duration_budget_failure(
                Duration::from_secs(300),
                Some(1_200),
                &config,
                "io-eio",
                1
            )
            .is_none()
        );

        let error = suite_duration_budget_failure(
            Duration::from_secs(301),
            Some(1_200),
            &config,
            "io-eio",
            1,
        )
        .expect("budget should fail");
        assert!(error.contains("needs at least 900s"));

        assert!(
            suite_duration_budget_failure(Duration::from_secs(10_000), None, &config, "io-eio", 1)
                .is_none()
        );
    }

    #[test]
    fn suite_runtime_contract_rejects_stable_window_that_matches_timeout_before_run_starts() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  recoveryStableWindowSeconds: 300
scenarios:
  - name: io-eio
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let base = FaultTestConfig::for_test("real-cluster", "fast-csi");

        let error = validate_suite_runtime_contract(&suite, &base).expect_err("runtime contract");

        assert!(
            error
                .to_string()
                .contains("recoveryStableWindowSeconds must be less")
        );
    }
}
