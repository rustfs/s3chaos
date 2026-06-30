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
use serde::Serialize;

use crate::{
    fault::{
        backends::host::DmStatusSnapshot,
        config::FaultTestConfig,
        plan::{FaultPlan, FaultSelection},
        scenarios::FaultScenario,
        workload::WorkloadPlan,
    },
    framework::artifacts::ArtifactCollector,
};

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FaultStatusSnapshot {
    pub(crate) stage: String,
    pub(crate) resource_kind: Option<String>,
    pub(crate) resource_name: Option<String>,
    pub(crate) chaos_status: Option<serde_json::Value>,
    pub(crate) dm_status: Option<DmStatusSnapshot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct PodIdentity {
    pub(crate) name: String,
    pub(crate) uid: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FaultEvidence {
    pub(crate) scenario: String,
    pub(crate) backend: String,
    pub(crate) target: String,
    pub(crate) injected: bool,
    pub(crate) active_during_workload: bool,
    pub(crate) recovered: bool,
    pub(crate) client_disruptions: usize,
    pub(crate) workload_plan: WorkloadPlan,
    pub(crate) pods_before: Vec<PodIdentity>,
    pub(crate) pods_after: Vec<PodIdentity>,
    pub(crate) active_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) workload_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) dm_recovery_snapshot: Option<DmStatusSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RunMetadata {
    scenario: String,
    case_name: String,
    run_id: String,
    bucket: String,
    backend: String,
    target: String,
    context: String,
    namespace: String,
    tenant: String,
    storage_class: String,
    rustfs_image: String,
    artifacts_dir: String,
    duration_seconds: u64,
    percent: Option<u8>,
    fault_selection: Vec<String>,
    fault_parameters: Vec<crate::fault::plan::FaultInjectionParameters>,
    workload_objects: usize,
    workload_concurrency: usize,
    workload_operation_mix: crate::fault::workload::WorkloadOperationMix,
    prefill_concurrency: usize,
    request_timeout_seconds: u64,
    use_cluster_ip: bool,
    require_client_disruption: bool,
    chaos_namespace: String,
}

impl RunMetadata {
    pub(crate) fn from_case(
        config: &FaultTestConfig,
        scenario: &FaultScenario,
        plan: &FaultPlan,
        workload_plan: &WorkloadPlan,
        run_id: &str,
        bucket: &str,
    ) -> Self {
        Self {
            scenario: scenario.name.clone(),
            case_name: scenario.case_name.to_string(),
            run_id: run_id.to_string(),
            bucket: bucket.to_string(),
            backend: plan.backend_summary(),
            target: plan.target_summary(),
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            storage_class: config.cluster.storage_class.clone(),
            rustfs_image: config.cluster.rustfs_image.clone(),
            artifacts_dir: config.cluster.artifacts_dir.display().to_string(),
            duration_seconds: scenario.duration.as_secs(),
            percent: plan
                .faults()
                .iter()
                .find_map(|fault| match fault.selection() {
                    FaultSelection::Percent(percent) => Some(percent),
                    FaultSelection::FixedTargets(_) => None,
                }),
            fault_selection: plan
                .faults()
                .iter()
                .map(|fault| fault.selection().summary())
                .collect(),
            fault_parameters: plan
                .faults()
                .iter()
                .map(|fault| fault.parameters().clone())
                .collect(),
            workload_objects: workload_plan.object_count,
            workload_concurrency: workload_plan.concurrency,
            workload_operation_mix: workload_plan.operation_mix,
            prefill_concurrency: config.prefill_concurrency,
            request_timeout_seconds: config.request_timeout.as_secs(),
            use_cluster_ip: config.use_cluster_ip,
            require_client_disruption: config.require_client_disruption,
            chaos_namespace: config.chaos_namespace.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct FailureSummary {
    scenario: String,
    stage: String,
    classification: String,
    message: String,
}

impl FailureSummary {
    pub(crate) fn new(
        scenario: impl Into<String>,
        stage: impl Into<String>,
        classification: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            scenario: scenario.into(),
            stage: stage.into(),
            classification: classification.into(),
            message: message.into(),
        }
    }
}

pub(crate) fn write_failure_summary(
    collector: &ArtifactCollector,
    case_name: &str,
    summary: FailureSummary,
) -> Result<()> {
    collector.write_text(
        case_name,
        "failure-summary.json",
        &serde_json::to_string_pretty(&summary)?,
    )?;
    Ok(())
}

pub(crate) fn write_failure_summary_if_absent(
    collector: &ArtifactCollector,
    case_name: &str,
    summary: FailureSummary,
) -> Result<()> {
    let path = collector.case_dir(case_name).join("failure-summary.json");
    if path.exists() {
        return Ok(());
    }
    write_failure_summary(collector, case_name, summary)
}

pub(crate) fn write_checker_error(
    collector: &ArtifactCollector,
    case_name: &str,
    artifact: &str,
    message: &str,
) -> Result<()> {
    collector.write_text(case_name, artifact, message)?;
    Ok(())
}
