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
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

use crate::fault::{
    config::{FaultTestConfig, FaultWorkloadProfile, default_percent_for_scenario},
    plan::{
        FaultInjection, FaultInjectionParameters, FaultPlan, FaultPlanOptions, FaultSelection,
        FaultTarget, FaultWorkloadMode,
    },
    reporting::FailureSeverity,
    scenarios::{
        FaultDetectorContract, FaultScenario, FaultScenarioSpec, acknowledged_mutation_kind,
        apply_catalog_defaults, scenario_spec,
    },
    spec::{FaultRunAckTriggerSpec, FaultRunArtifactSpec},
    suite::{
        FaultExpectedFailure, ResolvedFaultSuite, ResolvedFaultSuiteScenario,
        ResolvedFaultSuiteWorkloadOverride, resolve_fault_suite_yaml,
    },
    workload::{WorkloadHotspot, WorkloadOperationMix, WorkloadPlan, WorkloadSizeClass},
};

pub const FAULT_SUITE_PLAN_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const FAULT_SUITE_PLAN_KIND: &str = "FaultSuitePlan";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanBudgets {
    pub stop_on_first_failure: bool,
    pub continue_on_severities: Vec<FailureSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_stable_window_seconds: Option<u64>,
    pub cluster_timeout_seconds: u64,
    pub recovery_stability_reread_seconds: u64,
    pub minimum_required_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanAttempt {
    pub index: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub scenario: String,
    pub case_name: String,
    pub repetition: usize,
    pub priority: String,
    pub isolation: String,
    pub impact_policy: String,
    pub expected_backend: String,
    pub catalog_target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<FaultDetectorContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_trigger: Option<FaultRunAckTriggerSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_failure: Option<FaultExpectedFailure>,
    pub fault_duration_seconds: u64,
    pub workload: FaultSuitePlanWorkload,
    pub faults: Vec<FaultSuitePlanFault>,
    pub requires_chaos_mesh: bool,
    pub requires_static_storage: bool,
    pub crds: Vec<String>,
    pub required_tools: Vec<String>,
    pub artifacts: FaultSuitePlanArtifacts,
    pub budget: FaultSuitePlanBudgetImpact,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanWorkload {
    pub mode: String,
    pub objects: usize,
    pub concurrency: usize,
    pub versioning: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub catalog_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    pub operation_mix: WorkloadOperationMix,
    pub payload_distribution: Vec<FaultSuitePlanPayloadClass>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hotspot: Option<WorkloadHotspot>,
    pub prefill_concurrency: usize,
    pub request_timeout_seconds: u64,
    pub seed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanPayloadClass {
    pub size_bytes: usize,
    pub object_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanFault {
    pub name: String,
    pub kind: String,
    pub backend: String,
    pub parameters: FaultInjectionParameters,
    pub target: FaultSuitePlanTarget,
    pub target_proof: FaultSuitePlanTargetProof,
    pub selection: FaultSuitePlanSelection,
    pub target_proof_requirements: Vec<String>,
    pub fault_duration_seconds: u64,
    pub observability: String,
    pub conflict_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanTarget {
    pub kind: String,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanTargetProof {
    pub required: bool,
    pub artifact: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanSelection {
    pub kind: String,
    pub value: u32,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanArtifacts {
    pub attempt_dir: String,
    pub case_dir: String,
    pub required: Vec<String>,
    pub event_stream: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FaultSuitePlanBudgetImpact {
    pub fault_duration_seconds: u64,
    pub recovery_timeout_seconds: u64,
    pub recovery_stability_reread_seconds: u64,
    pub minimum_required_seconds: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_before_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_after_minimum_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct FaultSuitePlanExpansion {
    pub suite: ResolvedFaultSuite,
    pub plan: FaultSuitePlan,
    pub attempts: Vec<FaultSuiteExpandedAttempt>,
}

#[derive(Debug, Clone)]
pub(crate) struct FaultSuiteExpandedAttempt {
    pub plan: FaultSuitePlanAttempt,
    pub config: FaultTestConfig,
}

struct FaultSuitePlanAttemptInput<'a> {
    index: usize,
    run_id: String,
    scenario: &'a ResolvedFaultSuiteScenario,
    repetition: usize,
    config: &'a FaultTestConfig,
    spec: &'a FaultScenarioSpec,
    fault_plan: &'a FaultPlan,
    attempt_dir: &'a Path,
    budget: FaultSuitePlanBudgetImpact,
}

pub fn plan_fault_suite_from_yaml(path: impl AsRef<Path>) -> Result<FaultSuitePlan> {
    let suite = resolve_fault_suite_yaml(path)?;
    let base_config = FaultTestConfig::from_env()?;
    Ok(build_fault_suite_plan_expansion(suite, base_config, suite_run_id())?.plan)
}

pub(crate) fn build_fault_suite_plan_expansion(
    suite: ResolvedFaultSuite,
    mut base_config: FaultTestConfig,
    run_id: String,
) -> Result<FaultSuitePlanExpansion> {
    validate_suite_runtime_contract(&suite, &base_config)?;
    base_config.cluster.artifacts_dir = std::path::absolute(&base_config.cluster.artifacts_dir)
        .context("resolve suite artifact root")?;
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
                fault_duration_seconds: config.duration.as_secs(),
                recovery_timeout_seconds: config.cluster.timeout.as_secs(),
                recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
                minimum_required_seconds: required,
                remaining_before_seconds: remaining_before,
                remaining_after_minimum_seconds: remaining_after,
            };
            let plan = FaultSuitePlanAttempt::from_attempt(FaultSuitePlanAttemptInput {
                index: attempt_index,
                run_id: fault_run_id(),
                scenario,
                repetition,
                config: &config,
                spec,
                fault_plan: &fault_plan,
                attempt_dir: &attempt_dir,
                budget,
            })?;
            attempts.push(FaultSuiteExpandedAttempt { plan, config });
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
            continue_on_severities: suite.budgets.continue_on_severities.clone(),
            max_duration_seconds: suite.budgets.max_duration_seconds,
            max_client_disruptions: suite.budgets.max_client_disruptions,
            recovery_stable_window_seconds: suite.budgets.recovery_stable_window_seconds,
            cluster_timeout_seconds: base_config.cluster.timeout.as_secs(),
            recovery_stability_reread_seconds: base_config.recovery_stability_reread.as_secs(),
            minimum_required_seconds,
        },
        requires_chaos_mesh,
        requires_static_storage,
        required_crds: required_crds.into_iter().collect(),
        required_tools: required_tools.into_iter().collect(),
        attempts: plan_attempts,
    };

    Ok(FaultSuitePlanExpansion {
        suite,
        plan,
        attempts,
    })
}

impl FaultSuitePlan {
    pub fn to_json(&self) -> Result<String> {
        self.validate_current_contract()?;
        Ok(serde_json::to_string_pretty(self)?)
    }

    fn validate_current_contract(&self) -> Result<()> {
        ensure!(
            self.api_version == FAULT_SUITE_PLAN_API_VERSION && self.kind == FAULT_SUITE_PLAN_KIND,
            "fault suite plan apiVersion/kind is unsupported"
        );
        let mut run_ids = BTreeSet::new();
        for attempt in &self.attempts {
            let run_id = attempt.run_id.as_deref().with_context(|| {
                format!(
                    "current fault suite plan attempt {} ({}) is missing runId",
                    attempt.index, attempt.scenario
                )
            })?;
            ensure!(
                parse_fault_run_id(run_id).is_some(),
                "current fault suite plan attempt {} ({}) has invalid runId {:?}",
                attempt.index,
                attempt.scenario,
                run_id
            );
            ensure!(
                run_ids.insert(run_id),
                "current fault suite plan contains duplicate attempt runId {:?}",
                run_id
            );
            attempt
                .detector
                .as_ref()
                .with_context(|| {
                    format!(
                        "current fault suite plan attempt {} ({}) is missing detector contract",
                        attempt.index, attempt.scenario
                    )
                })?
                .validate()
                .with_context(|| {
                    format!(
                        "current fault suite plan attempt {} ({}) has invalid detector contract",
                        attempt.index, attempt.scenario
                    )
                })?;
            let catalog = scenario_spec(&attempt.scenario)?;
            ensure!(
                attempt.detector.as_ref() == Some(&catalog.detector.contract()),
                "current fault suite plan detector contract does not match scenario {}",
                attempt.scenario
            );
            let expected_ack = acknowledged_mutation_kind(&attempt.scenario);
            ensure!(
                attempt.ack_trigger.as_ref().map(|trigger| trigger.mutation) == expected_ack,
                "current fault suite plan ACK trigger does not match scenario {}",
                attempt.scenario
            );
            if let Some(trigger) = &attempt.ack_trigger {
                ensure!(
                    trigger.operation_timeout_ms > 0
                        && (1..=crate::fault::config::MAX_ACK_TO_FAULT_MS)
                            .contains(&trigger.max_ack_to_fault_ms),
                    "current fault suite plan ACK trigger requires a positive operation timeout and max_ack_to_fault_ms between 1 and {}",
                    crate::fault::config::MAX_ACK_TO_FAULT_MS
                );
            }
            if let Some(expected) = &attempt.expected_failure {
                expected.validate(&attempt.scenario)?;
            }
        }
        Ok(())
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

        let workload_plan = WorkloadPlan::seeded_with_profile(
            seed,
            input.config.workload.object_count,
            input.config.workload.concurrency,
            input.config.workload_operation_mix,
            input.config.workload_payload_distribution.clone(),
            input.config.workload_hotspot,
        )?;

        let payload_distribution = workload_plan
            .size_distribution
            .iter()
            .map(FaultSuitePlanPayloadClass::from)
            .collect();
        let hotspot = workload_plan.hotspot;

        Ok(Self {
            index: input.index,
            run_id: Some(input.run_id),
            scenario: input.scenario.name.clone(),
            case_name: input.spec.case_name.to_string(),
            repetition: input.repetition,
            priority: input.spec.priority.as_str().to_string(),
            isolation: input.spec.isolation.as_str().to_string(),
            impact_policy: input.spec.impact_policy.as_str().to_string(),
            expected_backend: input.spec.backend.as_str().to_string(),
            catalog_target: input.spec.target.to_string(),
            detector: Some(input.spec.detector.contract()),
            ack_trigger: acknowledged_mutation_kind(&input.scenario.name).map(|mutation| {
                FaultRunAckTriggerSpec {
                    mutation,
                    operation_timeout_ms: input.config.ack_operation_timeout.as_millis() as u64,
                    max_ack_to_fault_ms: input.config.max_ack_to_fault.as_millis() as u64,
                }
            }),
            expected_failure: input.scenario.expected_failure.clone(),
            fault_duration_seconds: input.config.duration.as_secs(),
            workload: FaultSuitePlanWorkload {
                mode: workload_mode_name(input.fault_plan.workload_mode).to_string(),
                objects: input.config.workload.object_count,
                concurrency: input.config.workload.concurrency,
                versioning: input.config.workload_versioning,
                catalog_profile: input
                    .spec
                    .workload_profile
                    .explicit_name()
                    .map(str::to_string),
                profile: input.scenario.workload_profile.clone(),
                operation_mix: input.config.workload_operation_mix,
                payload_distribution,
                hotspot,
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
                required: FaultRunArtifactSpec::required_names_for_scenario(&input.scenario.name),
                event_stream: "run-events.jsonl".to_string(),
            },
            budget: input.budget,
        })
    }
}

impl From<&WorkloadSizeClass> for FaultSuitePlanPayloadClass {
    fn from(class: &WorkloadSizeClass) -> Self {
        Self {
            size_bytes: class.size_bytes,
            object_count: class.object_count,
        }
    }
}

impl FaultSuitePlanFault {
    fn from_fault(
        index: usize,
        scenario: &ResolvedFaultSuiteScenario,
        spec: &FaultScenarioSpec,
        fault: &FaultInjection,
    ) -> Self {
        Self {
            name: format!("{}-{:02}-{}", scenario.name, index, fault.kind().as_str()),
            kind: fault.kind().as_str().to_string(),
            backend: fault.backend().as_str().to_string(),
            parameters: fault.parameters().clone(),
            target: FaultSuitePlanTarget::from_target(fault.target()),
            target_proof: FaultSuitePlanTargetProof {
                required: true,
                artifact: "target-proof.json".to_string(),
            },
            selection: FaultSuitePlanSelection::from_selection(fault.selection()),
            target_proof_requirements: spec
                .target_proof
                .iter()
                .map(|proof| (*proof).to_string())
                .collect(),
            fault_duration_seconds: fault.duration().as_secs(),
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
    config.scenario_parameters = scenario.params.clone();
    if let Some(fault_duration_seconds) = scenario.fault_duration_seconds {
        config.duration = Duration::from_secs(fault_duration_seconds);
    }
    // A suite attempt's fault percent comes only from the scenario YAML or the
    // catalog default — never from an ambient RUSTFS_FAULT_TEST_PERCENT. Letting
    // the env leak in silently rewrites per-scenario semantics across a mixed
    // suite (e.g. an ambient 20 turns disk-full's 100 into a partial fill).
    if let Some(percent) = scenario.percent {
        config.percent = percent;
        config.percent_overridden = true;
    } else {
        config.percent = default_percent_for_scenario(&scenario.name);
        config.percent_overridden = false;
    }
    if let Some(workload) = &scenario.workload {
        apply_workload_dimensions(&mut config, workload.objects, workload.concurrency)?;
    }
    apply_catalog_defaults(&mut config)?;
    if let Some(workload) = &scenario.workload {
        apply_workload_behavior_overrides(&mut config, workload);
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

fn apply_workload_dimensions(
    config: &mut FaultTestConfig,
    objects: Option<usize>,
    concurrency: Option<usize>,
) -> Result<()> {
    if objects.is_some() || concurrency.is_some() {
        let object_count = objects.unwrap_or(config.workload.object_count);
        let concurrency = concurrency.unwrap_or(config.workload.concurrency);
        config.workload = FaultWorkloadProfile::new(object_count, concurrency)?;
    }
    Ok(())
}

fn apply_workload_behavior_overrides(
    config: &mut FaultTestConfig,
    workload: &ResolvedFaultSuiteWorkloadOverride,
) {
    if let Some(operation_weights) = workload.operation_weights {
        config.workload_operation_mix = operation_weights;
    }
    if let Some(payload_distribution) = &workload.payload_distribution {
        config.workload_payload_distribution = Some(payload_distribution.clone());
    }
    if let Some(hotspot) = workload.hotspot {
        config.workload_hotspot = Some(hotspot);
    }
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

fn attempt_minimum_required_seconds(config: &FaultTestConfig) -> Result<u64> {
    attempt_minimum_required_duration(config).map(|required| required.as_secs())
}

pub(crate) fn attempt_minimum_required_duration(config: &FaultTestConfig) -> Result<Duration> {
    config
        .duration
        .checked_add(config.cluster.timeout)
        .and_then(|duration| duration.checked_add(config.recovery_stability_reread))
        .context("suite attempt duration plus recovery timeout plus recovery stability reread overflowed")
}

fn attempt_seed(base_seed: Option<u64>, attempt_index: usize, repetition: usize) -> Option<u64> {
    base_seed.map(|seed| seed ^ ((attempt_index as u64) << 32) ^ repetition as u64)
}

fn suite_run_root(config: &FaultTestConfig, suite: &ResolvedFaultSuite, run_id: &str) -> PathBuf {
    config
        .cluster
        .artifacts_dir
        .join(&suite.metadata.name)
        .join(run_id)
}

pub(crate) fn suite_run_id() -> String {
    format!("suite-{}", Uuid::new_v4())
}

pub(crate) fn fault_run_id() -> String {
    format!("run-{}", Uuid::new_v4())
}

fn parse_fault_run_id(value: &str) -> Option<Uuid> {
    Uuid::parse_str(value.strip_prefix("run-")?).ok()
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
        FaultWorkloadMode::AckTriggeredQuietMutation => "ack-triggered-quiet-mutation",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        attempt_seed, build_fault_suite_plan_expansion, scenario_config,
        validate_suite_runtime_contract,
    };
    use crate::fault::{
        acknowledged_mutation::AcknowledgedMutationKind,
        config::FaultTestConfig,
        scenarios::{
            DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO, FaultScenario, POD_CRASH_VERSIONED_HOT_SCENARIO,
        },
        suite::{FaultSuite, fault_suite_template_yaml},
        workload::{WorkloadHotspot, WorkloadOperationMix},
    };
    use serde_json::json;
    use std::{path::Path, path::PathBuf, time::Duration};

    #[test]
    fn suite_template_plan_matches_golden_output() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(&fault_suite_template_yaml())
            .expect("suite template yaml")
            .resolve()
            .expect("resolved suite template");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);
        base.cluster.artifacts_dir = PathBuf::from("/fixture/fault-tests/artifacts");

        let expansion = build_fault_suite_plan_expansion(suite, base, "suite-fixed".to_string())
            .expect("suite plan expansion");
        let mut plan = serde_json::to_value(&expansion.plan).expect("plan json");
        for attempt in plan["attempts"].as_array_mut().expect("plan attempts") {
            attempt
                .as_object_mut()
                .expect("plan attempt")
                .remove("runId");
        }
        let required_artifacts = json!([
            "run-spec.yaml",
            "run-spec.json",
            "preflight-summary.json",
            "target-proof.json",
            "run-events.jsonl",
            "run-metadata.json",
            "workload-plan.json",
            "history.jsonl",
            "workload-summary.json",
            "recommit-report.json",
            "checker-pre-recommit-report.json",
            "checker-report.json",
            "fault-evidence.json"
        ]);
        let operation_mix = json!({
            "put": 1,
            "overwrite": 1,
            "get": 1,
            "list": 1,
            "delete": 1,
            "multipart": 1
        });
        let payload_distribution = json!([
            {
                "sizeBytes": 4096,
                "objectCount": 34000
            },
            {
                "sizeBytes": 16384,
                "objectCount": 4000
            },
            {
                "sizeBytes": 8388608,
                "objectCount": 1600
            },
            {
                "sizeBytes": 16777216,
                "objectCount": 400
            }
        ]);
        let hotspot = json!({
            "objectPercent": 10,
            "operationPercent": 70
        });
        let target_proof = json!([
            "run artifacts must include the selected Kubernetes object or host device identity before the fault is activated"
        ]);
        assert_eq!(
            plan,
            json!({
                "apiVersion": "rustfs.com/s3chaos/v1alpha1",
                "kind": "FaultSuitePlan",
                "suite": "rustfs-smoke",
                "runId": "suite-fixed",
                "suiteSeed": 100,
                "artifactRoot": "/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed",
                "cluster": {
                    "context": "real-cluster",
                    "namespace": "rustfs-fault-test",
                    "tenant": "fault-test-tenant",
                    "storageClass": "fast-csi",
                    "rustfsImage": "rustfs/rustfs:test",
                    "chaosNamespace": "chaos-mesh",
                    "useClusterIp": false
                },
                "budgets": {
                    "stopOnFirstFailure": true,
                    "continueOnSeverities": ["degraded"],
                    "maxDurationSeconds": 7200,
                    "maxClientDisruptions": 20,
                    "recoveryStableWindowSeconds": 60,
                    "clusterTimeoutSeconds": 300,
                    "recoveryStabilityRereadSeconds": 60,
                    "minimumRequiredSeconds": 1800
                },
                "requiresChaosMesh": true,
                "requiresStaticStorage": false,
                "requiredCrds": [
                    "iochaos.chaos-mesh.org",
                    "networkchaos.chaos-mesh.org"
                ],
                "requiredTools": [],
                "attempts": [
                    {
                        "index": 1,
                        "scenario": "io-eio",
                        "caseName": "fault_io_eio_preserves_committed_objects",
                        "repetition": 1,
                        "priority": "p0",
                        "isolation": "fresh-tenant",
                        "impactPolicy": "client-disruption-required",
                        "expectedBackend": "chaos-mesh-io-chaos",
                        "catalogTarget": "one RustFS container data volume selected by tenant label and configured RustFS volume path",
                        "detector": {
                            "revision": 1,
                            "qualification": "gate-candidate",
                            "detects": ["data-shard-loss", "silent-data-corruption"]
                        },
                        "faultDurationSeconds": 600,
                        "workload": {
                            "mode": "s3-mixed",
                            "objects": 40000,
                            "concurrency": 80,
                            "versioning": false,
                            "profile": "smoke",
                            "operationMix": operation_mix.clone(),
                            "payloadDistribution": payload_distribution.clone(),
                            "hotspot": hotspot.clone(),
                            "prefillConcurrency": 16,
                            "requestTimeoutSeconds": 30,
                            "seed": 4294967397u64
                        },
                        "faults": [
                            {
                                "name": "io-eio-00-rustfs_volume_io_error",
                                "kind": "rustfs_volume_io_error",
                                "backend": "chaos-mesh-io-chaos",
                                "parameters": {
                                    "kind": "default"
                                },
                                "target": {
                                    "kind": "rustfs-volume",
                                    "summary": "one RustFS volume at /data/rustfs0",
                                    "path": "/data/rustfs0"
                                },
                                "targetProof": {
                                    "required": true,
                                    "artifact": "target-proof.json"
                                },
                                "selection": {
                                    "kind": "percent",
                                    "value": 20,
                                    "summary": "20%"
                                },
                                "targetProofRequirements": target_proof.clone(),
                                "faultDurationSeconds": 600,
                                "observability": "history.jsonl, workload-summary.json, checker-report.json, chaos-manifest.yaml, chaos-describe*.txt, Kubernetes snapshot artifacts",
                                "conflictDomain": "fresh Tenant/PVC/PV fixture and run-scoped IOChaos cleanup"
                            }
                        ],
                        "requiresChaosMesh": true,
                        "requiresStaticStorage": false,
                        "crds": ["iochaos.chaos-mesh.org"],
                        "requiredTools": [],
                        "artifacts": {
                            "attemptDir": "/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/001-io-eio-r1",
                            "caseDir": "/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/001-io-eio-r1/fault_io_eio_preserves_committed_objects",
                            "required": required_artifacts.clone(),
                            "eventStream": "run-events.jsonl"
                        },
                        "budget": {
                            "faultDurationSeconds": 600,
                            "recoveryTimeoutSeconds": 300,
                            "recoveryStabilityRereadSeconds": 60,
                            "minimumRequiredSeconds": 960,
                            "remainingBeforeSeconds": 7200,
                            "remainingAfterMinimumSeconds": 6240
                        }
                    },
                    {
                        "index": 2,
                        "scenario": "network-delay",
                        "caseName": "fault_network_delay_preserves_object_model",
                        "repetition": 1,
                        "priority": "p1",
                        "isolation": "reusable-tenant",
                        "impactPolicy": "client-disruption-optional",
                        "expectedBackend": "chaos-mesh-network-chaos",
                        "catalogTarget": "one RustFS Pod selected by tenant label with delayed peer traffic inside the e2e namespace",
                        "detector": {
                            "revision": 1,
                            "qualification": "gate-candidate",
                            "detects": ["silent-data-corruption", "recovery-availability-regression"]
                        },
                        "faultDurationSeconds": 480,
                        "workload": {
                            "mode": "s3-mixed",
                            "objects": 40000,
                            "concurrency": 80,
                            "versioning": false,
                            "profile": "smoke",
                            "operationMix": operation_mix,
                            "payloadDistribution": payload_distribution,
                            "hotspot": hotspot,
                            "prefillConcurrency": 16,
                            "requestTimeoutSeconds": 30,
                            "seed": 8589934693u64
                        },
                        "faults": [
                            {
                                "name": "network-delay-00-rustfs_server_network_delay",
                                "kind": "rustfs_server_network_delay",
                                "backend": "chaos-mesh-network-chaos",
                                "parameters": {
                                    "kind": "networkDelay",
                                    "latency": "200ms",
                                    "jitter": "50ms",
                                    "correlationPercent": 25
                                },
                                "target": {
                                    "kind": "rustfs-server-peer-network",
                                    "summary": "one RustFS server Pod partitioned from its peers"
                                },
                                "targetProof": {
                                    "required": true,
                                    "artifact": "target-proof.json"
                                },
                                "selection": {
                                    "kind": "fixed-targets",
                                    "value": 1,
                                    "summary": "1 target(s)"
                                },
                                "targetProofRequirements": target_proof.clone(),
                                "faultDurationSeconds": 480,
                                "observability": "history.jsonl, checker reports, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
                                "conflictDomain": "run-scoped NetworkChaos resource; must not overlap with other network faults in the same Tenant"
                            }
                        ],
                        "requiresChaosMesh": true,
                        "requiresStaticStorage": false,
                        "crds": ["networkchaos.chaos-mesh.org"],
                        "requiredTools": [],
                        "artifacts": {
                            "attemptDir": "/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/002-network-delay-r1",
                            "caseDir": "/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/002-network-delay-r1/fault_network_delay_preserves_object_model",
                            "required": required_artifacts,
                            "eventStream": "run-events.jsonl"
                        },
                        "budget": {
                            "faultDurationSeconds": 480,
                            "recoveryTimeoutSeconds": 300,
                            "recoveryStabilityRereadSeconds": 60,
                            "minimumRequiredSeconds": 840,
                            "remainingBeforeSeconds": 6240,
                            "remainingAfterMinimumSeconds": 5400
                        }
                    }
                ]
            })
        );
        assert_eq!(
            expansion.attempts[0].config.cluster.artifacts_dir,
            PathBuf::from("/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/001-io-eio-r1")
        );
        assert_eq!(
            expansion.attempts[1].config.cluster.artifacts_dir,
            PathBuf::from(
                "/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/002-network-delay-r1"
            )
        );
    }

    #[test]
    fn suite_plan_preserves_expected_failure_and_detector_contracts() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: vulnerable-mode-calibration
scenarios:
  - name: io-eio
    expectedFailure:
      classification: data_corruption
      severity: fail_correctness
      responsibilityDomain: product
      evidenceRefs:
        - checker-report.json
        - fault-evidence.json
        - run-events.jsonl
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_seed = Some(100);

        let expansion = build_fault_suite_plan_expansion(suite, base, "suite-fixed".to_string())
            .expect("suite plan expansion");
        let attempt = &expansion.plan.attempts[0];

        assert!(
            attempt
                .run_id
                .as_deref()
                .and_then(super::parse_fault_run_id)
                .is_some()
        );
        assert!(
            expansion.plan.attempts[1..]
                .iter()
                .all(|other| other.run_id != attempt.run_id)
        );
        assert_eq!(
            attempt.detector.as_ref(),
            Some(&expansion.suite.scenarios[0].detector)
        );
        assert_eq!(
            attempt.expected_failure,
            expansion.suite.scenarios[0].expected_failure
        );
        let json = serde_json::to_value(attempt).expect("attempt json");
        assert_eq!(json["runId"], attempt.run_id.as_deref().expect("run id"));
        assert_eq!(json["expectedFailure"]["classification"], "data_corruption");
        assert_eq!(
            json["expectedFailure"]["evidenceRefs"],
            json!([
                "checker-report.json",
                "fault-evidence.json",
                "run-events.jsonl"
            ])
        );
        assert_eq!(json["detector"]["detects"][0], "data-shard-loss");
        let encoded = expansion.plan.to_json().expect("plan json");
        let decoded = serde_json::from_str::<super::FaultSuitePlan>(&encoded).expect("plan decode");
        assert_eq!(decoded, expansion.plan);
        let mut changed = decoded.clone();
        changed.attempts[0]
            .detector
            .as_mut()
            .expect("detector")
            .detects
            .clear();
        changed.attempts[0]
            .detector
            .as_mut()
            .expect("detector")
            .detects
            .push(crate::fault::scenarios::DurabilityBugFamily::CommitMetadataLoss);
        assert!(
            changed
                .to_json()
                .unwrap_err()
                .to_string()
                .contains("does not match scenario")
        );

        let mut legacy = serde_json::to_value(&decoded).expect("legacy plan json");
        for attempt in legacy["attempts"]
            .as_array_mut()
            .expect("legacy plan attempts")
        {
            attempt
                .as_object_mut()
                .expect("legacy plan attempt")
                .remove("detector");
            attempt
                .as_object_mut()
                .expect("legacy plan attempt")
                .remove("runId");
        }
        let legacy = serde_json::from_value::<super::FaultSuitePlan>(legacy)
            .expect("legacy v1alpha1 plan without detector must remain readable");
        assert!(
            legacy
                .attempts
                .iter()
                .all(|attempt| attempt.detector.is_none())
        );
        assert!(
            legacy
                .attempts
                .iter()
                .all(|attempt| attempt.run_id.is_none())
        );
        assert!(
            legacy.validate_current_contract().is_err(),
            "new plan validation must still require detector contracts"
        );
        assert!(
            legacy.to_json().is_err(),
            "new plan writer must not emit a detector-less plan"
        );
    }

    #[test]
    fn suite_plan_keeps_ack_case_independently_typed_and_identifiable() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: ack-case
scenarios:
  - name: dm-drop-writes-after-ack-put
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "rustfs-fault-dm");
        base.workload_seed = Some(100);
        base.ack_operation_timeout = Duration::from_millis(2_300);
        base.max_ack_to_fault = Duration::from_millis(175);

        let expansion = build_fault_suite_plan_expansion(suite, base, "suite-fixed".to_string())
            .expect("suite plan expansion");
        let [attempt] = expansion.plan.attempts.as_slice() else {
            panic!("expected one independently planned ACK case")
        };
        assert_eq!(attempt.scenario, DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO);
        assert_eq!(attempt.workload.mode, "ack-triggered-quiet-mutation");
        assert!(attempt.workload.versioning);
        assert_eq!(
            attempt.ack_trigger.as_ref().expect("ACK trigger").mutation,
            AcknowledgedMutationKind::Put
        );
        assert_eq!(
            serde_json::to_value(attempt).expect("attempt JSON")["ackTrigger"],
            json!({
                "mutation": "put",
                "operation_timeout_ms": 2300,
                "max_ack_to_fault_ms": 175
            })
        );
        assert!(
            attempt
                .artifacts
                .required
                .contains(&"ack-to-fault-evidence.json".to_string())
        );
        let mut tampered = expansion.plan.clone();
        tampered.attempts[0]
            .ack_trigger
            .as_mut()
            .expect("ACK trigger")
            .max_ack_to_fault_ms = 0;
        assert!(tampered.to_json().is_err());
        tampered.attempts[0]
            .ack_trigger
            .as_mut()
            .expect("ACK trigger")
            .max_ack_to_fault_ms = crate::fault::config::MAX_ACK_TO_FAULT_MS + 1;
        assert!(tampered.to_json().is_err());
    }

    #[test]
    fn workload_override_inherits_base_operation_mix_when_weights_are_omitted() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      objects: 72
      concurrency: 9
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved suite");
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.workload_operation_mix = WorkloadOperationMix {
            put: 2,
            overwrite: 1,
            get: 3,
            list: 1,
            delete: 1,
            multipart: 1,
        };
        let attempt_dir =
            PathBuf::from("/fixture/fault-tests/artifacts/rustfs-smoke/suite-fixed/001-io-eio-r1");

        let config = scenario_config(&base, &suite, &suite.scenarios[0], 1, 1, &attempt_dir)
            .expect("scenario config");

        assert_eq!(config.workload.object_count, 72);
        assert_eq!(config.workload.concurrency, 9);
        assert_eq!(config.workload_operation_mix, base.workload_operation_mix);
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
    faultDuration: 10m
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
        let attempt_dir = PathBuf::from("target/fault-tests/suite/attempt-1");

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
            Path::new("target/fault-tests/suite/disk-full"),
        )
        .expect("scenario config");

        assert_eq!(config.percent, 100);
        assert!(!config.percent_overridden);
    }

    #[test]
    fn scenario_config_applies_catalog_workload_profile() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(&format!(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-reliability
scenarios:
  - name: {POD_CRASH_VERSIONED_HOT_SCENARIO}
"#
        ))
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
            Path::new("target/fault-tests/suite/pod-crash-versioned-hot"),
        )
        .expect("scenario config");

        assert!(config.workload_versioning);
        assert_eq!(
            config.workload_hotspot,
            Some(WorkloadHotspot {
                object_percent: 10,
                operation_percent: 80,
            })
        );
    }

    #[test]
    fn scenario_config_derives_catalog_profile_after_small_workload_override() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(&format!(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-reliability-small
scenarios:
  - name: {POD_CRASH_VERSIONED_HOT_SCENARIO}
    workload:
      objects: 12
      concurrency: 2
"#
        ))
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
            Path::new("target/fault-tests/suite/pod-crash-versioned-hot-small"),
        )
        .expect("scenario config");

        assert_eq!(config.workload.object_count, 12);
        assert_eq!(config.workload.concurrency, 2);
        assert_eq!(
            config.workload_operation_mix,
            WorkloadOperationMix::default()
        );
        FaultScenario::from_config(&config).expect("small catalog workload must remain valid");
    }

    #[test]
    fn scenario_config_ignores_ambient_percent_for_suite_scenarios() {
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

        // Simulate an ambient RUSTFS_FAULT_TEST_PERCENT=20 leaking in from the
        // environment. The suite scenario declares no percent, so it must still
        // use disk-full's catalog default (100), not the ambient value.
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.percent = 20;
        base.percent_overridden = true;

        let config = scenario_config(
            &base,
            &suite,
            &suite.scenarios[0],
            1,
            1,
            Path::new("target/fault-tests/suite/disk-full"),
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
    fn warp_example_rejects_duration_without_post_warp_headroom() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(include_str!(
            "../../fault/examples/warp-performance.yaml"
        ))
        .expect("Warp example")
        .resolve()
        .expect("resolved Warp example");
        for (warp_seconds, timeout_seconds, accepted) in [
            (60, 300, true),
            (599, 300, true),
            (600, 300, false),
            (900, 300, false),
            (1200, 300, false),
            (0, 300, false),
            (60, 900, false),
            (60, 901, false),
        ] {
            let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
            base.warp_duration = Duration::from_secs(warp_seconds);
            base.cluster.timeout = Duration::from_secs(timeout_seconds);
            let result = build_fault_suite_plan_expansion(
                suite.clone(),
                base,
                "warp-duration-test".to_string(),
            );
            if accepted {
                assert!(result.is_ok(), "Warp {warp_seconds}s: {result:?}");
            } else {
                let error = result.expect_err("invalid Warp duration must fail before execution");
                assert!(error.to_string().contains("WARP_DURATION_SECONDS"));
            }
        }
        let mut extended_suite = suite;
        extended_suite.scenarios[0].fault_duration_seconds = Some(1800);
        let mut base = FaultTestConfig::for_test("real-cluster", "fast-csi");
        base.warp_duration = Duration::from_secs(1200);
        assert!(
            build_fault_suite_plan_expansion(
                extended_suite,
                base,
                "extended-warp-window".to_string()
            )
            .is_ok()
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
