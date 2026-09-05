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

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::fault::{
    config::{DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS, FaultTestConfig},
    host_storage::{HOST_STORAGE_CLEANUP_ARTIFACT, HOST_STORAGE_PROOF_ARTIFACT},
    plan::{
        FaultInjection, FaultInjectionParameters, FaultPlan, FaultSelection, FaultTarget,
        FaultWorkloadMode,
    },
    scenarios::{
        FaultDetectorContract, FaultScenario, FaultScenarioSpec, acknowledged_mutation_kind,
    },
    workload::WorkloadPlan,
};

pub const FAULT_RUN_API_VERSION: &str = "rustfs.com/fault-test/v1alpha1";
pub const FAULT_RUN_KIND: &str = "FaultRun";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunSpec {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: FaultRunMetadata,
    pub cluster: FaultRunClusterSpec,
    pub scenario: FaultRunScenarioSpec,
    pub workload: FaultRunWorkloadSpec,
    pub recovery: FaultRunRecoverySpec,
    pub faults: Vec<FaultRunFaultSpec>,
    pub artifacts: FaultRunArtifactSpec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunMetadata {
    pub name: String,
    pub run_id: String,
    pub bucket: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunClusterSpec {
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub storage_class: String,
    pub rustfs_image: String,
    pub chaos_namespace: String,
    pub use_cluster_ip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunScenarioSpec {
    pub name: String,
    pub case_name: String,
    pub priority: String,
    pub isolation: String,
    pub impact_policy: String,
    pub boundary: String,
    pub validation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detector: Option<FaultDetectorContract>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack_trigger: Option<FaultRunAckTriggerSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunAckTriggerSpec {
    pub mutation: crate::fault::acknowledged_mutation::AcknowledgedMutationKind,
    pub operation_timeout_ms: u64,
    pub max_ack_to_fault_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunWorkloadSpec {
    pub mode: String,
    pub object_count: usize,
    pub concurrency: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog_profile: Option<String>,
    #[serde(default)]
    pub operation_mix: crate::fault::workload::WorkloadOperationMix,
    pub prefill_concurrency: usize,
    pub request_timeout_seconds: u64,
    pub seed: u64,
    #[serde(default)]
    pub versioning: bool,
    pub plan: WorkloadPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunRecoverySpec {
    pub timeout_seconds: u64,
    pub expected_rustfs_pod_count: usize,
    pub stable_pod_window_seconds: u64,
    #[serde(default = "default_recovery_stability_reread_seconds")]
    pub recovery_stability_reread_seconds: u64,
    pub recommit_unconfirmed_writes: bool,
}

fn default_recovery_stability_reread_seconds() -> u64 {
    DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunFaultSpec {
    pub name: String,
    pub kind: String,
    pub backend: String,
    #[serde(default)]
    pub parameters: FaultInjectionParameters,
    pub target: FaultRunTargetSpec,
    #[serde(default = "default_target_proof_spec")]
    pub target_proof: FaultRunTargetProofSpec,
    pub selection: FaultRunSelectionSpec,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub io_sampling_percent: Option<u8>,
    #[serde(default)]
    pub target_proof_requirements: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub erasure_set_proof_required: bool,
    pub fault_duration_seconds: u64,
    pub observability: String,
    pub conflict_domain: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunTargetProofSpec {
    pub required: bool,
    pub artifact: String,
}

fn default_target_proof_spec() -> FaultRunTargetProofSpec {
    FaultRunTargetProofSpec {
        required: false,
        artifact: String::new(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunTargetSpec {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunSelectionSpec {
    pub kind: String,
    pub value: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultRunArtifactSpec {
    pub required: Vec<String>,
    pub event_stream: String,
}

impl FaultRunSpec {
    pub fn resolved(
        config: &FaultTestConfig,
        scenario: &FaultScenario,
        scenario_spec: &FaultScenarioSpec,
        plan: &FaultPlan,
        workload_plan: &WorkloadPlan,
        run_id: &str,
        bucket: &str,
    ) -> Self {
        let mut artifacts = FaultRunArtifactSpec {
            required: FaultRunArtifactSpec::required_names_for_scenario(&scenario.name),
            event_stream: "run-events.jsonl".to_string(),
        };
        if plan.requires_static_storage() {
            artifacts.required.extend(
                [HOST_STORAGE_PROOF_ARTIFACT, HOST_STORAGE_CLEANUP_ARTIFACT].map(str::to_string),
            );
        }
        Self {
            api_version: FAULT_RUN_API_VERSION.to_string(),
            kind: FAULT_RUN_KIND.to_string(),
            metadata: FaultRunMetadata {
                name: scenario.case_name.to_string(),
                run_id: run_id.to_string(),
                bucket: bucket.to_string(),
            },
            cluster: FaultRunClusterSpec {
                context: config.cluster.context.clone(),
                namespace: config.cluster.test_namespace.clone(),
                tenant: config.cluster.tenant_name.clone(),
                storage_class: config.cluster.storage_class.clone(),
                rustfs_image: config.cluster.rustfs_image.clone(),
                chaos_namespace: config.chaos_namespace.clone(),
                use_cluster_ip: config.use_cluster_ip,
            },
            scenario: FaultRunScenarioSpec {
                name: scenario.name.clone(),
                case_name: scenario.case_name.to_string(),
                priority: scenario_spec.priority.as_str().to_string(),
                isolation: scenario_spec.isolation.as_str().to_string(),
                impact_policy: scenario_spec.impact_policy.as_str().to_string(),
                boundary: scenario_spec.boundary.to_string(),
                validation: scenario_spec.validation.to_string(),
                detector: Some(scenario_spec.detector.contract()),
                ack_trigger: acknowledged_mutation_kind(&scenario.name).map(|mutation| {
                    FaultRunAckTriggerSpec {
                        mutation,
                        operation_timeout_ms: config.ack_operation_timeout.as_millis() as u64,
                        max_ack_to_fault_ms: config.max_ack_to_fault.as_millis() as u64,
                    }
                }),
            },
            workload: FaultRunWorkloadSpec {
                mode: workload_mode_name(plan.workload_mode).to_string(),
                object_count: workload_plan.object_count,
                concurrency: workload_plan.concurrency,
                catalog_profile: scenario_spec
                    .workload_profile
                    .explicit_name()
                    .map(str::to_string),
                operation_mix: workload_plan.operation_mix,
                prefill_concurrency: config.prefill_concurrency,
                request_timeout_seconds: config.request_timeout.as_secs(),
                seed: workload_plan.seed,
                versioning: config.workload_versioning,
                plan: workload_plan.clone(),
            },
            recovery: FaultRunRecoverySpec {
                timeout_seconds: config.cluster.timeout.as_secs(),
                expected_rustfs_pod_count: config.expected_rustfs_pod_count,
                stable_pod_window_seconds: config.rustfs_pod_stable_window.as_secs(),
                recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
                recommit_unconfirmed_writes: acknowledged_mutation_kind(&scenario.name).is_none(),
            },
            faults: plan
                .faults()
                .iter()
                .enumerate()
                .map(|(index, fault)| {
                    FaultRunFaultSpec::from_fault(index, scenario, scenario_spec, fault)
                })
                .collect(),
            artifacts,
        }
    }

    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml_ng::to_string(self)?)
    }

    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

impl FaultRunArtifactSpec {
    pub fn required_names() -> Vec<String> {
        [
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
            "fault-evidence.json",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }

    pub fn required_names_for_scenario(scenario: &str) -> Vec<String> {
        if acknowledged_mutation_kind(scenario).is_none() {
            return Self::required_names();
        }
        [
            "run-spec.yaml",
            "run-spec.json",
            "preflight-summary.json",
            "target-proof.json",
            "run-events.jsonl",
            "run-metadata.json",
            "workload-plan.json",
            "history.jsonl",
            "ack-to-fault-evidence.json",
            "dm-crash-boundary.json",
            "dm-crash-recovered.json",
            "checker-pre-recommit-report.json",
            "checker-report.json",
            "fault-evidence.json",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    }
}

impl FaultRunFaultSpec {
    pub(crate) fn from_fault(
        index: usize,
        scenario: &FaultScenario,
        scenario_spec: &FaultScenarioSpec,
        fault: &FaultInjection,
    ) -> Self {
        Self {
            name: format!("{}-{:02}-{}", scenario.name, index, fault.kind().as_str()),
            kind: fault.kind().as_str().to_string(),
            backend: fault.backend().as_str().to_string(),
            parameters: fault.parameters().clone(),
            target: FaultRunTargetSpec::from_target(fault.target()),
            target_proof: FaultRunTargetProofSpec {
                required: true,
                artifact: "target-proof.json".to_string(),
            },
            selection: FaultRunSelectionSpec::from_selection(fault.selection()),
            io_sampling_percent: match fault.selection() {
                FaultSelection::FixedTargets(_) => fault
                    .volume_targeting()
                    .ok()
                    .map(|targeting| targeting.io_sampling_percent),
                FaultSelection::Percent(_) => None,
            },
            target_proof_requirements: scenario_spec
                .target_proof
                .iter()
                .map(|proof| (*proof).to_string())
                .collect(),
            erasure_set_proof_required: scenario_spec.requires_erasure_set_proof(),
            fault_duration_seconds: fault.duration().as_secs(),
            observability: scenario_spec.observability.to_string(),
            conflict_domain: scenario_spec.conflict_domain.to_string(),
        }
    }
}

impl FaultRunTargetSpec {
    fn from_target(target: &FaultTarget) -> Self {
        match target {
            FaultTarget::RustfsVolume { path } => Self {
                kind: "rustfs-volume".to_string(),
                path: Some(path.clone()),
            },
            FaultTarget::RustfsServerPod => Self {
                kind: "rustfs-server-pod".to_string(),
                path: None,
            },
            FaultTarget::RustfsServerPeerNetwork => Self {
                kind: "rustfs-server-peer-network".to_string(),
                path: None,
            },
            FaultTarget::RustfsServerResource => Self {
                kind: "rustfs-server-resource".to_string(),
                path: None,
            },
            FaultTarget::DedicatedBlockDevice => Self {
                kind: "dedicated-block-device".to_string(),
                path: None,
            },
        }
    }
}

impl FaultRunSelectionSpec {
    fn from_selection(selection: FaultSelection) -> Self {
        Self {
            kind: selection.kind().to_string(),
            value: selection.value(),
        }
    }
}

impl Default for FaultRunArtifactSpec {
    fn default() -> Self {
        Self {
            required: Self::required_names(),
            event_stream: "run-events.jsonl".to_string(),
        }
    }
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
    use super::{FAULT_RUN_API_VERSION, FaultRunSpec};
    use crate::fault::{
        acknowledged_mutation::AcknowledgedMutationKind,
        config::FaultTestConfig,
        plan::{FaultInjectionParameters, FaultPlan, FaultPlanOptions},
        scenarios::{
            DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO, FaultScenario,
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO, apply_catalog_defaults, scenario_spec,
        },
        workload::WorkloadPlan,
    };

    #[test]
    fn resolved_spec_exports_yaml_ready_contract() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let scenario_spec = scenario_spec(&scenario.name).expect("scenario spec");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            scenario_spec,
            FaultPlanOptions::from_config(&config),
        )
        .expect("plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);

        let spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            scenario_spec,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );

        assert_eq!(spec.api_version, FAULT_RUN_API_VERSION);
        assert_eq!(spec.faults.len(), 1);
        assert_eq!(spec.faults[0].target.path.as_deref(), Some("/data/rustfs0"));
        assert!(spec.faults[0].target_proof.required);
        assert_eq!(spec.faults[0].target_proof.artifact, "target-proof.json");
        assert_eq!(spec.scenario.priority, "p0");
        assert_eq!(spec.scenario.isolation, "fresh-tenant");
        assert_eq!(
            spec.scenario.detector,
            Some(scenario_spec.detector.contract())
        );
        assert_eq!(spec.faults[0].backend, "chaos-mesh-io-chaos");
        assert_eq!(spec.recovery.expected_rustfs_pod_count, 4);
        assert_eq!(spec.recovery.recovery_stability_reread_seconds, 60);
        assert!(
            spec.artifacts
                .required
                .contains(&"run-events.jsonl".to_string())
        );
        assert!(
            spec.artifacts
                .required
                .contains(&"run-spec.json".to_string())
        );
        assert!(spec.to_yaml().expect("yaml").contains("apiVersion:"));
        assert!(spec.to_json().expect("json").contains("\"faults\""));
        let decoded =
            serde_json::from_str::<FaultRunSpec>(&spec.to_json().expect("json")).expect("json");
        assert_eq!(decoded.api_version, spec.api_version);
        assert_eq!(decoded.scenario.priority, spec.scenario.priority);
        assert_eq!(decoded.scenario.detector, spec.scenario.detector);
        assert_eq!(decoded.workload.object_count, spec.workload.object_count);
        assert_eq!(
            decoded.workload.plan.size_distribution,
            spec.workload.plan.size_distribution
        );
        let decoded =
            serde_yaml_ng::from_str::<FaultRunSpec>(&spec.to_yaml().expect("yaml")).expect("yaml");
        assert_eq!(decoded.api_version, spec.api_version);
        assert_eq!(decoded.scenario.priority, spec.scenario.priority);
        assert_eq!(decoded.scenario.detector, spec.scenario.detector);
        assert_eq!(decoded.workload.object_count, spec.workload.object_count);
        assert_eq!(
            decoded.workload.plan.size_distribution,
            spec.workload.plan.size_distribution
        );
    }

    #[test]
    fn resolved_spec_marks_erasure_set_proof_as_a_typed_requirement() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let scenario_spec = scenario_spec(&scenario.name).expect("scenario spec");
        let plan = FaultPlan::from_scenario(&scenario, scenario_spec).expect("plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);

        let spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            scenario_spec,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );

        assert!(spec.faults[0].erasure_set_proof_required);
        assert!(
            spec.to_json()
                .expect("json")
                .contains("\"erasure_set_proof_required\": true")
        );
    }

    #[test]
    fn resolved_ack_spec_records_trigger_and_quiet_artifact_contract() {
        let mut config = FaultTestConfig::for_test("real-cluster", "rustfs-fault-dm");
        config.scenario = DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO.to_string();
        config.ack_operation_timeout = std::time::Duration::from_millis(2_300);
        config.max_ack_to_fault = std::time::Duration::from_millis(175);
        apply_catalog_defaults(&mut config).expect("catalog defaults");
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("scenario spec");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);

        let spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );

        let trigger = spec.scenario.ack_trigger.as_ref().expect("ACK trigger");
        assert_eq!(trigger.mutation, AcknowledgedMutationKind::Put);
        assert_eq!(trigger.operation_timeout_ms, 2_300);
        assert_eq!(trigger.max_ack_to_fault_ms, 175);
        assert_eq!(spec.workload.mode, "ack-triggered-quiet-mutation");
        assert!(spec.workload.versioning);
        assert!(!spec.recovery.recommit_unconfirmed_writes);
        assert_eq!(spec.faults[0].parameters, FaultInjectionParameters::Default);
        assert!(
            spec.artifacts
                .required
                .contains(&"ack-to-fault-evidence.json".to_string())
                && spec
                    .artifacts
                    .required
                    .contains(&"dm-crash-boundary.json".to_string())
                && spec
                    .artifacts
                    .required
                    .contains(&"dm-crash-recovered.json".to_string())
        );
        assert!(
            !spec
                .artifacts
                .required
                .contains(&"workload-summary.json".to_string())
                && !spec
                    .artifacts
                    .required
                    .contains(&"recommit-report.json".to_string())
        );
        assert!(
            spec.artifacts
                .required
                .contains(&"host-storage-proof.json".to_string())
                && spec
                    .artifacts
                    .required
                    .contains(&"host-storage-post-cleanup.json".to_string())
        );
    }
}
