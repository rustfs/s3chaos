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
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};

use crate::{
    fault::{
        config::FaultTestConfig,
        plan::{FaultInjection, FaultKind, FaultSelection, VolumeTargetSelection},
        pods::rustfs_pod_identities,
        quorum::MAX_ERASURE_SET_SHARDS,
        reporting::PodIdentity,
        scenarios::FaultScenario,
    },
    framework::{artifacts::ArtifactCollector, config::ClusterTestConfig},
};

mod runtime;

pub use runtime::{
    ChaosGuard, POD_KILL_STORM_SCHEDULE_GRACE, apply_iochaos, apply_networkchaos, apply_podchaos,
    apply_schedule, apply_stresschaos, chaos_schedule_is_armed, cleanup_managed_chaos,
    cleanup_managed_iochaos, cleanup_managed_networkchaos, cleanup_managed_podchaos,
    cleanup_managed_stresschaos, cleanup_podiochaos, cleanup_run, cleanup_run_kind,
    names_with_finalizers, pod_kill_storm_needs_controller_loop, require_iochaos_crd,
    require_networkchaos_crd, require_podchaos_crd, require_schedule_crd, require_stresschaos_crd,
};

pub(crate) const RUN_ID_LABEL: &str = "rustfs-fault-test/run-id";
const SCENARIO_LABEL: &str = "rustfs-fault-test/scenario";
pub(crate) const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub(crate) const MANAGED_BY_VALUE: &str = "s3chaos";

pub(crate) struct NetworkPartitionEvidenceContract<'a> {
    pub chaos_namespace: &'a str,
    pub target_namespace: &'a str,
    pub tenant: &'a str,
    pub run_id: &'a str,
    pub scenario: &'a str,
    pub expected_source_targets: u32,
    pub candidate_pod_ids: &'a BTreeSet<String>,
}

pub(crate) struct PodFailureEvidenceContract<'a> {
    pub chaos_namespace: &'a str,
    pub target_namespace: &'a str,
    pub tenant: &'a str,
    pub run_id: &'a str,
    pub scenario: &'a str,
    pub expected_targets: u32,
    pub duration_seconds: u64,
    pub candidate_pod_ids: &'a BTreeSet<String>,
}

#[derive(Clone, Copy)]
pub(crate) struct VolumeTargetEvidenceContract<'a> {
    pub chaos_namespace: &'a str,
    pub target_namespace: &'a str,
    pub tenant: &'a str,
    pub run_id: &'a str,
    pub scenario: &'a str,
    pub volume_path: &'a str,
    pub path: Option<&'a str>,
    pub exact_pod_names: Option<&'a BTreeSet<String>>,
    pub expected_targets: u32,
    pub candidate_pod_ids: &'a BTreeSet<String>,
    pub runtime: &'a IoChaosRuntimeContract,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IoChaosRuntimeContract {
    pub action: IoChaosAction,
    pub methods: Vec<String>,
    pub io_sampling_percent: u8,
    pub duration_seconds: u64,
}

pub(crate) fn volume_fault_runtime_contract(
    injection: &FaultInjection,
) -> Result<IoChaosRuntimeContract> {
    let targeting = injection.volume_targeting()?;
    let (action, methods) = match injection.kind() {
        FaultKind::RustfsVolumeIoError => (
            IoChaosAction::Fault { errno: 5 },
            vec!["READ".to_string(), "WRITE".to_string()],
        ),
        FaultKind::RustfsVolumeEnospc => (
            IoChaosAction::Fault { errno: 28 },
            vec!["WRITE".to_string()],
        ),
        FaultKind::RustfsVolumeErofs => (
            IoChaosAction::Fault { errno: 30 },
            vec!["WRITE".to_string()],
        ),
        FaultKind::RustfsVolumeReadMistake => (
            IoChaosAction::Mistake {
                filling: "random".to_string(),
                max_occurrences: 1,
                max_length: 4096,
            },
            vec!["READ".to_string()],
        ),
        FaultKind::RustfsVolumeLatency => {
            let (delay, methods) = injection.parameters().io_latency()?;
            (IoChaosAction::Latency { delay }, methods)
        }
        other => bail!(
            "fault kind {} is not a RustFS volume IOChaos fault",
            other.as_str()
        ),
    };
    Ok(IoChaosRuntimeContract {
        action,
        methods,
        io_sampling_percent: targeting.io_sampling_percent,
        duration_seconds: injection.duration().as_secs(),
    })
}

/// Validates the submitted fixed-target IOChaos selector and the controller's
/// per-container records. The CRD selector count alone is only intent; these
/// records prove which unique RustFS volume-bearing Pods were injected.
pub(crate) fn validate_fixed_volume_snapshot(
    resource: &Value,
    contract: &VolumeTargetEvidenceContract<'_>,
) -> Result<BTreeSet<String>> {
    ensure!(
        resource.get("apiVersion").and_then(Value::as_str) == Some("chaos-mesh.org/v1alpha1")
            && resource.get("kind").and_then(Value::as_str) == Some("IOChaos"),
        "runtime fault snapshot is not a Chaos Mesh v1alpha1 IOChaos"
    );
    validate_run_metadata(
        resource,
        "IOChaos",
        contract.chaos_namespace,
        contract.run_id,
        contract.scenario,
    )?;
    ensure!(
        resource.pointer("/spec/mode").and_then(Value::as_str) == Some("fixed")
            && resource
                .pointer("/spec/value")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u32>().ok())
                == Some(contract.expected_targets),
        "runtime IOChaos does not match the fixed volume target count"
    );
    let spec = resource
        .pointer("/spec")
        .context("IOChaos spec is missing")?;
    if let Some(expected) = contract.exact_pod_names {
        let pods = spec
            .pointer("/selector/pods")
            .and_then(Value::as_object)
            .context("IOChaos exact Pod selector is missing")?;
        ensure!(
            pods.len() == 1,
            "IOChaos exact Pod selector contains another namespace"
        );
        let names = pods
            .get(contract.target_namespace)
            .and_then(Value::as_array)
            .context("IOChaos exact Pod namespace is missing")?;
        let selected = names
            .iter()
            .map(|pod| {
                pod.as_str()
                    .map(str::to_string)
                    .context("IOChaos exact Pod selector contains a non-string")
            })
            .collect::<Result<BTreeSet<_>>>()?;
        ensure!(
            selected == *expected
                && names.len() == expected.len()
                && expected.len() == usize::try_from(contract.expected_targets)?
                && spec.pointer("/selector/namespaces").is_none()
                && spec.pointer("/selector/labelSelectors").is_none(),
            "runtime IOChaos exact Pod selector changed"
        );
    } else {
        validate_pod_selector(spec, "IOChaos", contract.target_namespace, contract.tenant)?;
    }
    ensure!(
        resource.pointer("/spec/volumePath").and_then(Value::as_str) == Some(contract.volume_path)
            && resource.pointer("/spec/path").and_then(Value::as_str)
                == Some(
                    contract
                        .path
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("{}/**/*", contract.volume_path))
                        .as_str(),
                ),
        "runtime IOChaos volume path does not match the planned target"
    );
    ensure!(
        resource
            .pointer("/spec/containerNames")
            .and_then(Value::as_array)
            .is_some_and(|containers| {
                containers.len() == 1 && containers[0].as_str() == Some("rustfs")
            }),
        "runtime IOChaos must target only the RustFS container"
    );
    ensure!(
        resource.pointer("/spec/percent").and_then(Value::as_u64)
            == Some(u64::from(contract.runtime.io_sampling_percent)),
        "runtime IOChaos I/O sampling percent does not match the planned volume fault"
    );
    validate_iochaos_behavior(resource, contract.runtime)?;
    ensure!(
        chaos_condition_is_true(resource, "Selected")
            && chaos_condition_is_true(resource, "AllInjected")
            && !chaos_condition_is_true(resource, "AllRecovered"),
        "runtime IOChaos is not selected and fully injected"
    );
    ensure!(
        resource
            .pointer("/status/experiment/desiredPhase")
            .and_then(Value::as_str)
            == Some("Run"),
        "runtime IOChaos desired phase is not Run"
    );
    let records = resource
        .pointer("/status/experiment/containerRecords")
        .and_then(Value::as_array)
        .context("runtime IOChaos has no per-target controller records")?;
    ensure!(
        records.len() == usize::try_from(contract.expected_targets)?,
        "runtime IOChaos contains {} controller records, expected exactly {}",
        records.len(),
        contract.expected_targets
    );
    ensure!(
        records.iter().all(|record| {
            record.get("selectorKey").and_then(Value::as_str) == Some(".")
                && record.get("phase").and_then(Value::as_str) == Some("Injected")
                && record
                    .get("injectedCount")
                    .and_then(Value::as_u64)
                    .is_some_and(|count| count > 0)
        }),
        "runtime IOChaos contains an unknown selector or a controller record without successful injection"
    );
    let record_ids = records
        .iter()
        .map(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_string)
                .context("runtime IOChaos controller record has no target id")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        record_ids.len() == records.len(),
        "runtime IOChaos contains duplicate controller target records"
    );
    ensure!(
        record_ids.len() == usize::try_from(contract.expected_targets)?,
        "runtime IOChaos injected {} unique targets, expected {}",
        record_ids.len(),
        contract.expected_targets
    );
    let pod_ids = record_ids
        .iter()
        .map(|record_id| iochaos_record_pod_id(record_id))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        pod_ids.len() == record_ids.len(),
        "runtime IOChaos contains multiple target records for one Pod"
    );
    ensure!(
        pod_ids.is_subset(contract.candidate_pod_ids),
        "runtime IOChaos selected a target outside the proved Ready Pod set"
    );
    if let Some(expected) = contract.exact_pod_names {
        let expected_ids = expected
            .iter()
            .map(|pod| format!("{}/{}", contract.target_namespace, pod))
            .collect::<BTreeSet<_>>();
        ensure!(
            pod_ids == expected_ids,
            "runtime IOChaos records differ from the exact Pod selector"
        );
    }
    Ok(record_ids)
}

fn validate_iochaos_behavior(resource: &Value, expected: &IoChaosRuntimeContract) -> Result<()> {
    let spec = resource
        .pointer("/spec")
        .context("IOChaos spec is missing")?;
    let methods = spec
        .get("methods")
        .and_then(Value::as_array)
        .context("runtime IOChaos methods are missing")?
        .iter()
        .map(|method| {
            method
                .as_str()
                .map(str::to_string)
                .context("runtime IOChaos method is not a string")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        methods == expected.methods,
        "runtime IOChaos methods do not match the planned volume fault"
    );
    ensure!(
        spec.get("duration").and_then(Value::as_str)
            == Some(format!("{}s", expected.duration_seconds).as_str()),
        "runtime IOChaos duration does not match the planned volume fault"
    );
    match &expected.action {
        IoChaosAction::Fault { errno } => ensure!(
            spec.get("action").and_then(Value::as_str) == Some("fault")
                && spec.get("errno").and_then(Value::as_u64) == Some(u64::from(*errno))
                && spec.get("delay").is_none()
                && spec.get("mistake").is_none(),
            "runtime IOChaos fault action/errno does not match the planned volume fault"
        ),
        IoChaosAction::Latency { delay } => ensure!(
            spec.get("action").and_then(Value::as_str) == Some("latency")
                && spec.get("delay").and_then(Value::as_str) == Some(delay.as_str())
                && spec.get("errno").is_none()
                && spec.get("mistake").is_none(),
            "runtime IOChaos latency action/delay does not match the planned volume fault"
        ),
        IoChaosAction::Mistake {
            filling,
            max_occurrences,
            max_length,
        } => ensure!(
            spec.get("action").and_then(Value::as_str) == Some("mistake")
                && spec.pointer("/mistake/filling").and_then(Value::as_str)
                    == Some(filling.as_str())
                && spec
                    .pointer("/mistake/maxOccurrences")
                    .and_then(Value::as_u64)
                    == Some(u64::from(*max_occurrences))
                && spec.pointer("/mistake/maxLength").and_then(Value::as_u64)
                    == u64::try_from(*max_length).ok()
                && spec.get("errno").is_none()
                && spec.get("delay").is_none(),
            "runtime IOChaos mistake action does not match the planned volume fault"
        ),
    }
    Ok(())
}

pub(crate) fn iochaos_record_pod_id(record_id: &str) -> Result<String> {
    let mut parts = record_id.split('/');
    let namespace = parts.next().unwrap_or_default();
    let pod = parts.next().unwrap_or_default();
    let container = parts.next().unwrap_or_default();
    ensure!(
        !namespace.is_empty() && !pod.is_empty() && container == "rustfs" && parts.next().is_none(),
        "runtime IOChaos target id {record_id:?} is not namespace/pod/rustfs"
    );
    Ok(format!("{namespace}/{pod}"))
}

/// Validates both the submitted NetworkChaos contract and the controller's
/// per-target records. Conditions alone do not prove how many targets were
/// actually selected and injected.
pub(crate) fn validate_network_partition_snapshot(
    resource: &Value,
    contract: &NetworkPartitionEvidenceContract<'_>,
) -> Result<BTreeSet<String>> {
    ensure!(
        resource.get("apiVersion").and_then(Value::as_str) == Some("chaos-mesh.org/v1alpha1")
            && resource.get("kind").and_then(Value::as_str) == Some("NetworkChaos"),
        "runtime fault snapshot is not a Chaos Mesh v1alpha1 NetworkChaos"
    );
    ensure!(
        resource
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            == Some(contract.chaos_namespace)
            && resource
                .pointer(&format!(
                    "/metadata/labels/{}",
                    RUN_ID_LABEL.replace('/', "~1")
                ))
                .and_then(Value::as_str)
                == Some(contract.run_id)
            && resource
                .pointer(&format!(
                    "/metadata/labels/{}",
                    SCENARIO_LABEL.replace('/', "~1")
                ))
                .and_then(Value::as_str)
                == Some(contract.scenario)
            && resource
                .pointer(&format!(
                    "/metadata/labels/{}",
                    MANAGED_BY_LABEL.replace('/', "~1")
                ))
                .and_then(Value::as_str)
                == Some(MANAGED_BY_VALUE),
        "runtime NetworkChaos metadata is outside the run scope"
    );
    ensure!(
        resource.pointer("/spec/action").and_then(Value::as_str) == Some("partition")
            && resource.pointer("/spec/direction").and_then(Value::as_str) == Some("both")
            && resource.pointer("/spec/mode").and_then(Value::as_str) == Some("fixed")
            && resource
                .pointer("/spec/value")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u32>().ok())
                == Some(contract.expected_source_targets),
        "runtime NetworkChaos does not match the fixed bidirectional partition plan"
    );
    validate_pod_selector(
        resource
            .pointer("/spec")
            .context("NetworkChaos spec is missing")?,
        "NetworkChaos",
        contract.target_namespace,
        contract.tenant,
    )?;
    let target = resource
        .pointer("/spec/target")
        .context("NetworkChaos target selector is missing")?;
    ensure!(
        target.get("mode").and_then(Value::as_str) == Some("all"),
        "runtime NetworkChaos peer selector must use mode all"
    );
    validate_pod_selector(
        target,
        "NetworkChaos",
        contract.target_namespace,
        contract.tenant,
    )?;
    ensure!(
        chaos_condition_is_true(resource, "Selected")
            && chaos_condition_is_true(resource, "AllInjected")
            && !chaos_condition_is_true(resource, "AllRecovered"),
        "runtime NetworkChaos is not selected and fully injected"
    );
    ensure!(
        resource
            .pointer("/status/experiment/desiredPhase")
            .and_then(Value::as_str)
            == Some("Run"),
        "runtime NetworkChaos desired phase is not Run"
    );
    let records = resource
        .pointer("/status/experiment/containerRecords")
        .and_then(Value::as_array)
        .context("runtime NetworkChaos has no per-target controller records")?;
    ensure!(
        records.iter().all(|record| matches!(
            record.get("selectorKey").and_then(Value::as_str),
            Some("." | ".Target")
        )),
        "runtime NetworkChaos contains an unknown or missing controller selector key"
    );
    let source_ids = injected_record_ids(records, ".", "NetworkChaos")?;
    let peer_ids = injected_record_ids(records, ".Target", "NetworkChaos")?;
    ensure!(
        source_ids.len() == usize::try_from(contract.expected_source_targets)?,
        "runtime NetworkChaos injected {} source targets, expected {}",
        source_ids.len(),
        contract.expected_source_targets
    );
    ensure!(
        source_ids.is_subset(contract.candidate_pod_ids),
        "runtime NetworkChaos selected a source target outside the proved Ready Pod set"
    );
    ensure!(
        peer_ids == *contract.candidate_pod_ids,
        "runtime NetworkChaos peer records do not cover the proved Ready Pod set"
    );
    Ok(source_ids)
}

/// Prove the live PodChaos really failed the plan-declared number of tenant
/// Pods, and return their namespaced ids so the caller can bind them to the
/// runtime erasure-set membership.
pub(crate) fn validate_pod_failure_snapshot(
    resource: &Value,
    contract: &PodFailureEvidenceContract<'_>,
) -> Result<BTreeSet<String>> {
    ensure!(
        resource.get("apiVersion").and_then(Value::as_str) == Some("chaos-mesh.org/v1alpha1")
            && resource.get("kind").and_then(Value::as_str) == Some("PodChaos"),
        "runtime fault snapshot is not a Chaos Mesh v1alpha1 PodChaos"
    );
    validate_run_metadata(
        resource,
        "PodChaos",
        contract.chaos_namespace,
        contract.run_id,
        contract.scenario,
    )?;
    ensure!(
        resource.pointer("/spec/action").and_then(Value::as_str) == Some("pod-failure")
            && resource.pointer("/spec/mode").and_then(Value::as_str) == Some("fixed")
            && resource
                .pointer("/spec/value")
                .and_then(Value::as_str)
                .and_then(|value| value.parse::<u32>().ok())
                == Some(contract.expected_targets),
        "runtime PodChaos does not match the fixed multi-Pod failure plan"
    );
    ensure!(
        resource.pointer("/spec/duration").and_then(Value::as_str)
            == Some(format!("{}s", contract.duration_seconds).as_str()),
        "runtime PodChaos duration does not match the planned fault duration"
    );
    validate_pod_selector(
        resource
            .pointer("/spec")
            .context("PodChaos spec is missing")?,
        "PodChaos",
        contract.target_namespace,
        contract.tenant,
    )?;
    ensure!(
        chaos_condition_is_true(resource, "Selected")
            && chaos_condition_is_true(resource, "AllInjected")
            && !chaos_condition_is_true(resource, "AllRecovered"),
        "runtime PodChaos is not selected and fully injected"
    );
    ensure!(
        resource
            .pointer("/status/experiment/desiredPhase")
            .and_then(Value::as_str)
            == Some("Run"),
        "runtime PodChaos desired phase is not Run"
    );
    let records = resource
        .pointer("/status/experiment/containerRecords")
        .and_then(Value::as_array)
        .context("runtime PodChaos has no per-target controller records")?;
    ensure!(
        records
            .iter()
            .all(|record| matches!(record.get("selectorKey").and_then(Value::as_str), Some("."))),
        "runtime PodChaos contains an unknown or missing controller selector key"
    );
    let target_ids = injected_record_ids(records, ".", "PodChaos")?;
    ensure!(
        target_ids.len() == usize::try_from(contract.expected_targets)?,
        "runtime PodChaos injected {} targets, expected {}",
        target_ids.len(),
        contract.expected_targets
    );
    ensure!(
        target_ids.is_subset(contract.candidate_pod_ids),
        "runtime PodChaos selected a target outside the proved Ready Pod set"
    );
    ensure!(
        target_ids.len() < contract.candidate_pod_ids.len(),
        "runtime PodChaos failed every proved Ready Pod; the quorum-edge boundary needs survivors"
    );
    Ok(target_ids)
}

fn validate_pod_selector(
    selector: &Value,
    kind: &str,
    namespace: &str,
    tenant: &str,
) -> Result<()> {
    let namespaces = selector
        .pointer("/selector/namespaces")
        .and_then(Value::as_array)
        .with_context(|| format!("{kind} selector.namespaces is missing"))?;
    ensure!(
        namespaces.len() == 1 && namespaces[0].as_str() == Some(namespace),
        "runtime {kind} selector namespace does not match the target namespace"
    );
    ensure!(
        selector
            .pointer("/selector/labelSelectors/rustfs.tenant")
            .and_then(Value::as_str)
            == Some(tenant),
        "runtime {kind} selector tenant does not match the target tenant"
    );
    Ok(())
}

fn chaos_condition_is_true(resource: &Value, condition_type: &str) -> bool {
    resource
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .is_some_and(|conditions| {
            conditions.iter().any(|condition| {
                condition.get("type").and_then(Value::as_str) == Some(condition_type)
                    && condition.get("status").and_then(Value::as_str) == Some("True")
            })
        })
}

fn validate_run_metadata(
    resource: &Value,
    kind: &str,
    chaos_namespace: &str,
    run_id: &str,
    scenario: &str,
) -> Result<()> {
    ensure!(
        resource
            .pointer("/metadata/namespace")
            .and_then(Value::as_str)
            == Some(chaos_namespace)
            && resource
                .pointer(&format!(
                    "/metadata/labels/{}",
                    RUN_ID_LABEL.replace('/', "~1")
                ))
                .and_then(Value::as_str)
                == Some(run_id)
            && resource
                .pointer(&format!(
                    "/metadata/labels/{}",
                    SCENARIO_LABEL.replace('/', "~1")
                ))
                .and_then(Value::as_str)
                == Some(scenario)
            && resource
                .pointer(&format!(
                    "/metadata/labels/{}",
                    MANAGED_BY_LABEL.replace('/', "~1")
                ))
                .and_then(Value::as_str)
                == Some(MANAGED_BY_VALUE),
        "runtime {kind} metadata is outside the run scope"
    );
    Ok(())
}

fn injected_record_ids(
    records: &[Value],
    selector_key: &str,
    kind: &str,
) -> Result<BTreeSet<String>> {
    let matching = records
        .iter()
        .filter(|record| record.get("selectorKey").and_then(Value::as_str) == Some(selector_key))
        .collect::<Vec<_>>();
    ensure!(
        matching.iter().all(|record| {
            record.get("phase").and_then(Value::as_str) == Some("Injected")
                && record
                    .get("injectedCount")
                    .and_then(Value::as_u64)
                    .is_some_and(|count| count > 0)
        }),
        "runtime {kind} selector {selector_key:?} has a target without successful injection"
    );
    let ids = matching
        .iter()
        .map(|record| {
            record
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .map(str::to_string)
                .with_context(|| format!("runtime {kind} record is missing its target id"))
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        ids.len() == matching.len(),
        "runtime {kind} selector {selector_key:?} contains duplicate target records"
    );
    Ok(ids)
}

pub(crate) struct FaultApplyRequest<'a> {
    pub config: &'a FaultTestConfig,
    pub collector: &'a ArtifactCollector,
    pub scenario: &'a FaultScenario,
    pub injection: &'a FaultInjection,
    pub run_id: &'a str,
    pub manifest_name: &'a str,
    pub resource_name_suffix: &'a str,
}

pub(crate) enum AppliedFault {
    Experiment {
        guard: ChaosGuard,
        active_required: bool,
    },
    PodKill {
        guard: ChaosGuard,
        before_pods: Vec<PodIdentity>,
    },
    PodKillStorm {
        guard: ChaosGuard,
        before_pods: Vec<PodIdentity>,
        victim: PodIdentity,
    },
}

enum FaultSpec {
    Io(IoChaosSpec),
    Pod(PodChaosSpec),
    PodKill(PodChaosSpec),
    PodKillStorm(ScheduleSpec),
    Network(NetworkChaosSpec),
    Stress(StressChaosSpec),
}

impl FaultSpec {
    fn manifest(&self) -> String {
        match self {
            Self::Io(chaos) => chaos.manifest(),
            Self::Pod(chaos) | Self::PodKill(chaos) => chaos.manifest(),
            Self::PodKillStorm(chaos) => chaos.manifest(),
            Self::Network(chaos) => chaos.manifest(),
            Self::Stress(chaos) => chaos.manifest(),
        }
    }
}

struct PodKillStormPins {
    before_pods: Vec<PodIdentity>,
    victim: PodIdentity,
}

pub(crate) fn apply_fault(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    let config = request.config;
    let cluster = &config.cluster;
    let scenario = request.scenario;
    let storm = if request.injection.kind() == FaultKind::RustfsServerPodKillStorm {
        Some(resolve_pod_kill_storm_victim(cluster)?)
    } else {
        None
    };
    let spec = build_fault_spec(
        config,
        scenario,
        request.injection,
        request.run_id,
        request.resource_name_suffix,
        storm.as_ref().map(|storm| storm.victim.name.as_str()),
    )?;
    let before_pods = if matches!(spec, FaultSpec::PodKill(_)) {
        Some(rustfs_pod_identities(cluster)?)
    } else {
        None
    };
    request
        .collector
        .write_text(scenario.case_name, request.manifest_name, &spec.manifest())?;

    match spec {
        FaultSpec::Io(chaos) => Ok(AppliedFault::Experiment {
            guard: apply_iochaos(cluster, &chaos)?,
            active_required: true,
        }),
        FaultSpec::Pod(chaos) => Ok(AppliedFault::Experiment {
            guard: apply_podchaos(cluster, &chaos)?,
            active_required: true,
        }),
        FaultSpec::PodKill(chaos) => {
            let Some(before_pods) = before_pods else {
                unreachable!("PodKill captures pod identities before apply");
            };
            Ok(AppliedFault::PodKill {
                guard: apply_podchaos(cluster, &chaos)?,
                before_pods,
            })
        }
        FaultSpec::PodKillStorm(chaos) => {
            let Some(storm) = storm else {
                unreachable!("pod kill storm resolves its victim before rendering");
            };
            Ok(AppliedFault::PodKillStorm {
                guard: apply_schedule(cluster, &chaos)?,
                before_pods: storm.before_pods,
                victim: storm.victim,
            })
        }
        FaultSpec::Network(chaos) => Ok(AppliedFault::Experiment {
            guard: apply_networkchaos(cluster, &chaos)?,
            active_required: true,
        }),
        FaultSpec::Stress(chaos) => Ok(AppliedFault::Experiment {
            guard: apply_stresschaos(cluster, &chaos)?,
            active_required: true,
        }),
    }
}

fn build_fault_spec(
    config: &FaultTestConfig,
    scenario: &FaultScenario,
    injection: &FaultInjection,
    run_id: &str,
    resource_name_suffix: &str,
    pinned_pod: Option<&str>,
) -> Result<FaultSpec> {
    let cluster = &config.cluster;
    let io_targeting = || -> Result<(u8, Option<u32>)> {
        let targeting = injection.volume_targeting()?;
        let targets = match targeting.target_selection {
            VolumeTargetSelection::One => None,
            VolumeTargetSelection::FixedTargets(count) => Some(count),
        };
        Ok((targeting.io_sampling_percent, targets))
    };
    match injection.kind() {
        FaultKind::RustfsVolumeEnospc => {
            let (percent, targets) = io_targeting()?;
            Ok(FaultSpec::Io(
                IoChaosSpec::enospc_on_rustfs_volume(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    injection.rustfs_volume_path()?,
                    percent,
                    injection.duration(),
                )?
                .with_fixed_targets(targets)?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsVolumeErofs => {
            let (percent, targets) = io_targeting()?;
            Ok(FaultSpec::Io(
                IoChaosSpec::erofs_on_rustfs_volume(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    injection.rustfs_volume_path()?,
                    percent,
                    injection.duration(),
                )?
                .with_fixed_targets(targets)?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsVolumeReadMistake => {
            let (percent, targets) = io_targeting()?;
            Ok(FaultSpec::Io(
                IoChaosSpec::read_mistake_on_rustfs_volume(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    injection.rustfs_volume_path()?,
                    percent,
                    injection.duration(),
                )?
                .with_fixed_targets(targets)?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsVolumeLatency => {
            let (percent, targets) = io_targeting()?;
            let (delay, methods) = injection.parameters().io_latency()?;
            Ok(FaultSpec::Io(
                IoChaosSpec::latency_on_rustfs_volume(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    injection.rustfs_volume_path()?,
                    IoLatencyParameters {
                        methods,
                        delay,
                        percent,
                    },
                    injection.duration(),
                )?
                .with_fixed_targets(targets)?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsVolumeIoError => {
            let (percent, targets) = io_targeting()?;
            Ok(FaultSpec::Io(
                IoChaosSpec::eio_on_rustfs_volume(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    injection.rustfs_volume_path()?,
                    percent,
                    injection.duration(),
                )?
                .with_fixed_targets(targets)?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsServerPodKill => Ok(FaultSpec::PodKill(
            PodChaosSpec::kill_one_rustfs_pod(
                cluster,
                &config.chaos_namespace,
                run_id,
                &scenario.name,
            )
            .with_name_suffix(resource_name_suffix),
        )),
        FaultKind::RustfsServerPodKillStorm => {
            let pod_name = pinned_pod.context(
                "pod-restart-storm requires the highest-ordinal pod before the schedule is rendered",
            )?;
            Ok(FaultSpec::PodKillStorm(
                ScheduleSpec::pod_kill_storm(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    pod_name,
                )?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsServerPodFailure => {
            // Honor the plan-declared blast radius: the quorum-edge scenario
            // fails more than one Pod at once, everything else stays
            // single-target.
            let chaos = PodChaosSpec::fail_one_rustfs_pod(
                cluster,
                &config.chaos_namespace,
                run_id,
                &scenario.name,
                injection.duration(),
            )?;
            let chaos = match injection.selection() {
                FaultSelection::FixedTargets(count) if count > 1 => {
                    chaos.with_fixed_targets(count)?
                }
                FaultSelection::FixedTargets(_) | FaultSelection::Percent(_) => chaos,
                FaultSelection::RuntimeQuorum(_) => {
                    bail!("runtime quorum selection must be resolved before PodChaos rendering")
                }
            };
            Ok(FaultSpec::Pod(chaos.with_name_suffix(resource_name_suffix)))
        }
        FaultKind::RustfsServerNetworkAsymmetricPartition => Ok(FaultSpec::Network(
            NetworkChaosSpec::partition_one_way(
                cluster,
                &config.chaos_namespace,
                run_id,
                &scenario.name,
                injection.duration(),
            )?
            .with_name_suffix(resource_name_suffix),
        )),
        FaultKind::RustfsServerNetworkPartition => {
            // Honor the plan-declared blast radius: quorum-loss scenarios
            // partition more than one Pod, everything else stays single-target.
            let targets = match injection.selection() {
                FaultSelection::FixedTargets(count) => count,
                FaultSelection::Percent(_) => 1,
                FaultSelection::RuntimeQuorum(_) => {
                    bail!("runtime quorum selection must be resolved before IOChaos rendering")
                }
            };
            Ok(FaultSpec::Network(
                NetworkChaosSpec::partition_rustfs_pods(
                    cluster,
                    &config.chaos_namespace,
                    run_id,
                    &scenario.name,
                    injection.duration(),
                    targets,
                )?
                .with_name_suffix(resource_name_suffix),
            ))
        }
        FaultKind::RustfsServerNetworkDelay
        | FaultKind::RustfsServerNetworkLoss
        | FaultKind::RustfsServerNetworkFlaky
        | FaultKind::RustfsServerNetworkCorrupt
        | FaultKind::RustfsServerNetworkDuplicate => {
            let chaos = match injection.kind() {
                FaultKind::RustfsServerNetworkDelay => {
                    let (latency, jitter, correlation_percent) =
                        injection.parameters().network_delay()?;
                    NetworkChaosSpec::delay_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        NetworkDelayParameters {
                            latency,
                            jitter,
                            correlation_percent,
                        },
                    )?
                }
                FaultKind::RustfsServerNetworkLoss => {
                    let (loss_percent, correlation_percent) =
                        injection.parameters().network_loss()?;
                    let mut spec = NetworkChaosSpec::loss_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        loss_percent,
                        correlation_percent,
                    )?;
                    if std::env::var("RUSTFS_RELEASE_GATE_NETWORK_LOSS_SCOPE")
                        .ok()
                        .as_deref()
                        == Some("all")
                    {
                        spec = spec.with_all_sources();
                    }
                    spec
                }
                FaultKind::RustfsServerNetworkFlaky => {
                    let (loss_percent, correlation_percent) =
                        injection.parameters().network_flaky()?;
                    NetworkChaosSpec::flaky_loss_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        loss_percent,
                        correlation_percent,
                    )?
                }
                FaultKind::RustfsServerNetworkCorrupt => {
                    let (corrupt_percent, correlation_percent) =
                        injection.parameters().network_corrupt()?;
                    NetworkChaosSpec::corrupt_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        corrupt_percent,
                        correlation_percent,
                    )?
                }
                FaultKind::RustfsServerNetworkDuplicate => {
                    let (duplicate_percent, correlation_percent) =
                        injection.parameters().network_duplicate()?;
                    NetworkChaosSpec::duplicate_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        duplicate_percent,
                        correlation_percent,
                    )?
                }
                _ => unreachable!(),
            }
            .with_name_suffix(resource_name_suffix);
            Ok(FaultSpec::Network(chaos))
        }
        FaultKind::RustfsServerCpuStress | FaultKind::RustfsServerMemoryStress => {
            let chaos = match injection.kind() {
                FaultKind::RustfsServerCpuStress => {
                    let (workers, load) = injection.parameters().stress_cpu()?;
                    StressChaosSpec::cpu_on_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        workers,
                        load,
                    )?
                }
                FaultKind::RustfsServerMemoryStress => {
                    let (workers, size) = injection.parameters().stress_memory()?;
                    StressChaosSpec::memory_on_one_rustfs_pod(
                        cluster,
                        &config.chaos_namespace,
                        run_id,
                        &scenario.name,
                        injection.duration(),
                        workers,
                        size,
                    )?
                }
                _ => unreachable!(),
            }
            .with_name_suffix(resource_name_suffix);
            Ok(FaultSpec::Stress(chaos))
        }
        FaultKind::RustfsBlockDeviceFlakey | FaultKind::RustfsBlockDeviceDropWritesCrash => {
            bail!(
                "fault kind {} must be applied by the host backend",
                injection.kind().as_str()
            )
        }
        FaultKind::RustfsServerPodGracefulRestart
        | FaultKind::RustfsServerRollingRestart
        | FaultKind::RustfsServerColdRestart => {
            bail!(
                "fault kind {} must be applied by the Kubernetes lifecycle backend",
                injection.kind().as_str()
            )
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoChaosAction {
    Fault {
        errno: u8,
    },
    Latency {
        delay: String,
    },
    Mistake {
        filling: String,
        max_occurrences: u8,
        max_length: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoLatencyParameters {
    pub methods: Vec<String>,
    pub delay: String,
    pub percent: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub container_name: String,
    pub volume_path: String,
    pub path: Option<String>,
    pub methods: Vec<String>,
    pub action: IoChaosAction,
    pub percent: u8,
    pub targets: Option<u32>,
    /// Closed Pod-name selector used by exact-cohort storage recovery cases.
    /// Ordinary fault cases keep using the Tenant label selector.
    pub pod_names: Option<Vec<String>>,
    pub duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodChaosAction {
    PodKill,
    PodFailure { duration: Duration },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub action: PodChaosAction,
    /// `None` renders `mode: one`; `Some(n)` renders `mode: fixed` with
    /// `value: n`, which is how quorum-edge scenarios take more than one
    /// server offline at the same instant.
    pub targets: Option<u32>,
    /// When set, the selector is this Pod name instead of the tenant label,
    /// so a restart storm cannot kill the port-forward target.
    pub pinned_pod: Option<String>,
    /// `Some(0)` is the SIGKILL grace used by the restart-storm fallback.
    /// `None` omits `gracePeriod` and keeps the historical pod-kill manifest.
    pub grace_period_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkChaosAction {
    Partition,
    Delay {
        latency: String,
        jitter: String,
        correlation: String,
    },
    Loss {
        loss: String,
        correlation: String,
    },
    Corrupt {
        corrupt: String,
        correlation: String,
    },
    Duplicate {
        duplicate: String,
        correlation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDelayParameters {
    pub latency: String,
    pub jitter: String,
    pub correlation_percent: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkChaosDirection {
    Both,
    /// Packets from the selected source Pod toward the peer selector.
    /// The reverse path stays open, so this is a one-way blackhole.
    To,
}

impl NetworkChaosDirection {
    fn as_str(self) -> &'static str {
        match self {
            Self::Both => "both",
            Self::To => "to",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub action: NetworkChaosAction,
    pub direction: NetworkChaosDirection,
    pub duration: Duration,
    /// How many tenant Pods the source selector picks. 1 renders `mode: one`;
    /// N > 1 renders `mode: fixed` + `value: "N"` so the plan-declared blast
    /// radius is honored instead of silently narrowing to a single Pod.
    pub targets: u32,
    /// When set, the source selector is `mode: all` so every tenant Pod loses
    /// packets. The default stays `mode: one`.
    pub all_sources: bool,
}

#[derive(Debug, Clone)]
pub enum StressChaosAction {
    Cpu { workers: u32, load: u32 },
    Memory { workers: u32, size: String },
}

#[derive(Debug, Clone)]
pub struct StressChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub action: StressChaosAction,
    pub duration: Duration,
}

impl IoChaosSpec {
    pub fn eio_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-eio-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            path: None,
            methods: vec!["READ".to_string(), "WRITE".to_string()],
            action: IoChaosAction::Fault { errno: 5 },
            percent,
            targets: None,
            pod_names: None,
            duration,
        })
    }

    pub fn read_mistake_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-mistake-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            path: None,
            methods: vec!["READ".to_string()],
            action: IoChaosAction::Mistake {
                filling: "random".to_string(),
                max_occurrences: 1,
                max_length: 4096,
            },
            percent,
            targets: None,
            pod_names: None,
            duration,
        })
    }

    pub fn latency_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        parameters: IoLatencyParameters,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&parameters.percent),
            "IOChaos percent must be in 1..=100, got {}",
            parameters.percent
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );
        ensure!(
            !parameters.methods.is_empty(),
            "IOChaos methods must not be empty"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-latency-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            path: None,
            methods: parameters.methods,
            action: IoChaosAction::Latency {
                delay: parameters.delay,
            },
            percent: parameters.percent,
            targets: None,
            pod_names: None,
            duration,
        })
    }

    pub fn erofs_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-erofs-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            path: None,
            methods: vec!["WRITE".to_string()],
            action: IoChaosAction::Fault { errno: 30 },
            percent,
            targets: None,
            pod_names: None,
            duration,
        })
    }

    pub fn enospc_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-enospc-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            path: None,
            methods: vec!["WRITE".to_string()],
            action: IoChaosAction::Fault { errno: 28 },
            percent,
            targets: None,
            pod_names: None,
            duration,
        })
    }

    fn with_fixed_targets(mut self, targets: Option<u32>) -> Result<Self> {
        if let Some(targets) = targets {
            ensure!(
                (1..=MAX_ERASURE_SET_SHARDS).contains(&targets),
                "IOChaos fixed targets must be in 1..={MAX_ERASURE_SET_SHARDS}, got {targets}"
            );
        }
        self.targets = targets;
        Ok(self)
    }

    pub(crate) fn with_exact_pods(mut self, pod_names: Vec<String>) -> Result<Self> {
        ensure!(
            !pod_names.is_empty()
                && pod_names.len() <= usize::try_from(MAX_ERASURE_SET_SHARDS)?
                && pod_names.iter().all(|name| {
                    !name.is_empty()
                        && name.len() <= 253
                        && name.bytes().all(|byte| {
                            byte.is_ascii_lowercase()
                                || byte.is_ascii_digit()
                                || matches!(byte, b'-' | b'.')
                        })
                }),
            "IOChaos exact Pod selector is empty, oversized, or invalid"
        );
        let unique = pod_names.iter().collect::<BTreeSet<_>>();
        ensure!(
            unique.len() == pod_names.len(),
            "IOChaos exact Pod selector contains duplicates"
        );
        self.targets = Some(u32::try_from(pod_names.len())?);
        self.pod_names = Some(pod_names);
        Ok(self)
    }

    pub(crate) fn with_exact_path(mut self, path: impl Into<String>) -> Result<Self> {
        let path = path.into();
        ensure!(
            path.starts_with(&format!("{}/", self.volume_path))
                && !path.contains("/**")
                && path
                    .split('/')
                    .all(|component| component != "." && component != "..")
                && path.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')
                }),
            "IOChaos exact path must be a normalized child of volumePath"
        );
        self.path = Some(path);
        Ok(self)
    }

    pub(crate) fn with_read_only(mut self) -> Self {
        self.methods = vec!["READ".to_string()];
        self
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let methods = self
            .methods
            .iter()
            .map(|method| format!("    - {method}"))
            .collect::<Vec<_>>()
            .join("\n");
        let seconds = self.duration.as_secs();
        let action = self.action_manifest();
        let (mode, value) = match self.targets {
            Some(targets) => ("fixed", format!("  value: \"{targets}\"\n")),
            None => ("one", String::new()),
        };

        let selector = match &self.pod_names {
            Some(pods) => {
                let names = pods
                    .iter()
                    .map(|name| format!("        - {name}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!("    pods:\n      {}:\n{names}", self.target_namespace)
            }
            None => format!(
                "    namespaces:\n      - {}\n    labelSelectors:\n      rustfs.tenant: {}",
                self.target_namespace, self.tenant_name
            ),
        };

        let path = self
            .path
            .clone()
            .unwrap_or_else(|| format!("{}/**/*", self.volume_path));
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: IOChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
{action}
  mode: {mode}
{value}  selector:
{selector}
  containerNames:
    - {container_name}
  volumePath: {volume_path}
  path: {path}
  methods:
{methods}
  percent: {percent}
  duration: "{seconds}s"
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            selector = selector,
            container_name = self.container_name,
            volume_path = self.volume_path,
            path = path,
            methods = methods,
            percent = self.percent,
            action = action,
            mode = mode,
            value = value,
        )
    }

    fn action_manifest(&self) -> String {
        match &self.action {
            IoChaosAction::Fault { errno } => {
                format!("  action: fault\n  errno: {errno}")
            }
            IoChaosAction::Latency { delay } => {
                format!("  action: latency\n  delay: {delay}")
            }
            IoChaosAction::Mistake {
                filling,
                max_occurrences,
                max_length,
            } => format!(
                r#"  action: mistake
  mistake:
    filling: {filling}
    maxOccurrences: {max_occurrences}
    maxLength: {max_length}"#
            ),
        }
    }
}

impl PodChaosSpec {
    pub fn kill_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
    ) -> Self {
        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Self {
            name: format!("rustfs-fault-pod-kill-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action: PodChaosAction::PodKill,
            targets: None,
            pinned_pod: None,
            grace_period_seconds: None,
        }
    }

    /// Pod-kill pinned to one Pod name, with grace 0. The restart-storm
    /// controller loop uses this when the Chaos Mesh Schedule does not fire.
    pub fn kill_named_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        pod_name: impl Into<String>,
    ) -> Result<Self> {
        let pod_name = pod_name.into();
        ensure!(
            !pod_name.is_empty()
                && pod_name.len() <= 253
                && pod_name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !pod_name.starts_with('-')
                && !pod_name.ends_with('-'),
            "pinned pod-kill target {pod_name:?} is not a DNS label"
        );
        let mut spec = Self::kill_one_rustfs_pod(config, chaos_namespace, run_id, scenario);
        spec.name = format!(
            "rustfs-fault-pod-kill-named-{}",
            spec.run_id.chars().take(12).collect::<String>()
        );
        spec.pinned_pod = Some(pod_name);
        spec.grace_period_seconds = Some(0);
        Ok(spec)
    }

    pub fn fail_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            duration > Duration::ZERO,
            "PodChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-pod-failure-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action: PodChaosAction::PodFailure { duration },
            targets: None,
            pinned_pod: None,
            grace_period_seconds: None,
        })
    }

    /// Select a plan-declared number of Pods instead of a single arbitrary
    /// one. The range is only a sanity bound: that survivors remain and the
    /// selection crosses the intended quorum boundary is proved against the
    /// live snapshot and runtime geometry, not here.
    pub(crate) fn with_fixed_targets(mut self, targets: u32) -> Result<Self> {
        ensure!(
            (1..=MAX_ERASURE_SET_SHARDS).contains(&targets),
            "PodChaos fixed targets must be in 1..={MAX_ERASURE_SET_SHARDS}, got {targets}"
        );
        self.targets = Some(targets);
        Ok(self)
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let action = self.action_manifest();
        let (mode, value) = match self.targets {
            Some(targets) if self.pinned_pod.is_none() => {
                ("fixed", format!("  value: \"{targets}\"\n"))
            }
            _ => ("one", String::new()),
        };
        let selector = match &self.pinned_pod {
            Some(pod_name) => format!(
                "    pods:\n      {}:\n        - {pod_name}",
                self.target_namespace
            ),
            None => format!(
                "    namespaces:\n      - {}\n    labelSelectors:\n      rustfs.tenant: {}",
                self.target_namespace, self.tenant_name
            ),
        };
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
{action}
  mode: {mode}
{value}  selector:
{selector}
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            selector = selector,
            action = action,
            mode = mode,
            value = value,
        )
    }

    fn action_manifest(&self) -> String {
        match self.action {
            PodChaosAction::PodKill => match self.grace_period_seconds {
                Some(seconds) => format!("  action: pod-kill\n  gracePeriod: {seconds}"),
                None => "  action: pod-kill".to_string(),
            },
            PodChaosAction::PodFailure { duration } => {
                format!(
                    "  action: pod-failure\n  duration: \"{}s\"",
                    duration.as_secs()
                )
            }
        }
    }
}

impl NetworkChaosSpec {
    /// Partition `targets` tenant Pods from every peer (source and target
    /// selectors overlap, so the selected Pods are fully isolated — from the
    /// remaining peers and from each other). `targets` > 1 is how quorum-loss
    /// scenarios remove more than one server's drives at once.
    pub fn partition_rustfs_pods(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        targets: u32,
    ) -> Result<Self> {
        ensure!(
            targets > 0,
            "NetworkChaos partition must select at least one Pod"
        );
        let mut spec = Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-partition",
            NetworkChaosAction::Partition,
        )?;
        spec.targets = targets;
        Ok(spec)
    }

    /// One-way partition: traffic from the selected Pod toward every peer is
    /// dropped, and the reverse direction is left intact. `mode: one` keeps
    /// this off the bidirectional write-quorum evidence contract, which
    /// requires `direction: both` and `mode: fixed`.
    pub fn partition_one_way(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
    ) -> Result<Self> {
        let mut spec = Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-asym",
            NetworkChaosAction::Partition,
        )?;
        spec.direction = NetworkChaosDirection::To;
        Ok(spec)
    }

    pub fn delay_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        parameters: NetworkDelayParameters,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-delay",
            NetworkChaosAction::Delay {
                latency: parameters.latency,
                jitter: parameters.jitter,
                correlation: parameters.correlation_percent.to_string(),
            },
        )
    }

    pub fn loss_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        loss_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-loss",
            NetworkChaosAction::Loss {
                loss: loss_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    pub fn flaky_loss_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        loss_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-flaky",
            NetworkChaosAction::Loss {
                loss: loss_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    pub fn corrupt_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        corrupt_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-corrupt",
            NetworkChaosAction::Corrupt {
                corrupt: corrupt_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    pub fn duplicate_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        duplicate_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-duplicate",
            NetworkChaosAction::Duplicate {
                duplicate: duplicate_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    fn one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        name_action: &str,
        action: NetworkChaosAction,
    ) -> Result<Self> {
        ensure!(
            duration > Duration::ZERO,
            "NetworkChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-{name_action}-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action,
            direction: NetworkChaosDirection::Both,
            duration,
            targets: 1,
            all_sources: false,
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn with_all_sources(mut self) -> Self {
        self.all_sources = true;
        self
    }

    fn mode_manifest(&self) -> String {
        if self.all_sources {
            "  mode: all".to_string()
        } else if self.targets == 1 {
            "  mode: one".to_string()
        } else {
            format!("  mode: fixed\n  value: \"{}\"", self.targets)
        }
    }

    pub fn manifest(&self) -> String {
        let seconds = self.duration.as_secs();
        let action = self.action_manifest();
        let mode = self.mode_manifest();
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
{action}
{mode}
  selector:
    namespaces:
      - {target_namespace}
    labelSelectors:
      rustfs.tenant: {tenant_name}
  direction: {direction}
  target:
    mode: all
    selector:
      namespaces:
        - {target_namespace}
      labelSelectors:
        rustfs.tenant: {tenant_name}
  duration: "{seconds}s"
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            tenant_name = self.tenant_name,
            action = action,
            mode = mode,
            direction = self.direction.as_str(),
        )
    }

    fn action_manifest(&self) -> String {
        match &self.action {
            NetworkChaosAction::Partition => "  action: partition".to_string(),
            NetworkChaosAction::Delay {
                latency,
                jitter,
                correlation,
            } => format!(
                r#"  action: delay
  delay:
    latency: "{latency}"
    jitter: "{jitter}"
    correlation: "{correlation}""#
            ),
            NetworkChaosAction::Loss { loss, correlation } => format!(
                r#"  action: loss
  loss:
    loss: "{loss}"
    correlation: "{correlation}""#
            ),
            NetworkChaosAction::Corrupt {
                corrupt,
                correlation,
            } => format!(
                r#"  action: corrupt
  corrupt:
    corrupt: "{corrupt}"
    correlation: "{correlation}""#
            ),
            NetworkChaosAction::Duplicate {
                duplicate,
                correlation,
            } => format!(
                r#"  action: duplicate
  duplicate:
    duplicate: "{duplicate}"
    correlation: "{correlation}""#
            ),
        }
    }
}

impl StressChaosSpec {
    pub fn cpu_on_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        workers: u32,
        load: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "stress-cpu",
            StressChaosAction::Cpu {
                workers,
                load: load.into(),
            },
        )
    }

    pub fn memory_on_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        workers: u32,
        size: impl Into<String>,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "stress-memory",
            StressChaosAction::Memory {
                workers,
                size: size.into(),
            },
        )
    }

    fn one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        name_action: &str,
        action: StressChaosAction,
    ) -> Result<Self> {
        ensure!(
            duration > Duration::ZERO,
            "StressChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-{name_action}-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action,
            duration,
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let seconds = self.duration.as_secs();
        let stressors = self.stressors_manifest();
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
  mode: one
  selector:
    namespaces:
      - {target_namespace}
    labelSelectors:
      rustfs.tenant: {tenant_name}
  stressors:
{stressors}
  duration: "{seconds}s"
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            tenant_name = self.tenant_name,
            stressors = stressors,
        )
    }

    fn stressors_manifest(&self) -> String {
        match &self.action {
            StressChaosAction::Cpu { workers, load } => format!(
                r#"    cpu:
      workers: {workers}
      load: {load}"#
            ),
            StressChaosAction::Memory { workers, size } => format!(
                r#"    memory:
      workers: {workers}
      size: "{size}""#
            ),
        }
    }
}

/// Repeated pod-kill. Chaos Mesh `Schedule` is the actuator because one
/// PodChaos is a single kill. The selector is one StatefulSet pod so the
/// port-forward target (lowest ordinal) stays up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub pod_name: String,
}

impl ScheduleSpec {
    pub fn pod_kill_storm(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        pod_name: impl Into<String>,
    ) -> Result<Self> {
        let pod_name = pod_name.into();
        ensure!(
            !pod_name.is_empty()
                && pod_name.len() <= 253
                && pod_name
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !pod_name.starts_with('-')
                && !pod_name.ends_with('-'),
            "pod-restart-storm target {pod_name:?} is not a DNS label"
        );
        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-pod-kill-storm-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            pod_name,
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: Schedule
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
  schedule: "@every 15s"
  concurrencyPolicy: Forbid
  historyLimit: 1
  startingDeadlineSeconds: 10
  type: PodChaos
  podChaos:
    action: pod-kill
    gracePeriod: 0
    mode: one
    selector:
      pods:
        {target_namespace}:
          - {pod_name}
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            pod_name = self.pod_name,
        )
    }
}

pub(crate) fn highest_ordinal_pod_name<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<&'a str> {
    let mut best: Option<(&'a str, u32)> = None;
    let mut saw_any = false;
    for name in names {
        saw_any = true;
        let ordinal = name
            .rsplit_once('-')
            .and_then(|(_, suffix)| suffix.parse::<u32>().ok())
            .with_context(|| {
                format!(
                    "pod {name:?} has no numeric StatefulSet ordinal; pod-restart-storm fails closed"
                )
            })?;
        match best {
            Some((other, existing)) if existing == ordinal => {
                bail!("pod-restart-storm found tied ordinal {ordinal} on {other:?} and {name:?}");
            }
            Some((_, existing)) if existing > ordinal => {}
            _ => best = Some((name, ordinal)),
        }
    }
    ensure!(
        saw_any,
        "pod-restart-storm requires at least one RustFS pod"
    );
    best.map(|(name, _)| name)
        .context("pod-restart-storm requires a numeric ordinal")
}

fn resolve_pod_kill_storm_victim(cluster: &ClusterTestConfig) -> Result<PodKillStormPins> {
    let before_pods = rustfs_pod_identities(cluster)?;
    let victim_name = highest_ordinal_pod_name(before_pods.iter().map(|pod| pod.name.as_str()))?;
    let victim = before_pods
        .iter()
        .find(|pod| pod.name == victim_name)
        .cloned()
        .context("highest-ordinal RustFS pod disappeared before the schedule was rendered")?;
    Ok(PodKillStormPins {
        before_pods,
        victim,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        FaultSpec, IoChaosAction, IoChaosSpec, IoLatencyParameters, MAX_ERASURE_SET_SHARDS,
        NetworkChaosAction, NetworkChaosDirection, NetworkChaosSpec, NetworkDelayParameters,
        NetworkPartitionEvidenceContract, POD_KILL_STORM_SCHEDULE_GRACE, PodChaosAction,
        PodChaosSpec, PodFailureEvidenceContract, ScheduleSpec, StressChaosAction, StressChaosSpec,
        VolumeTargetEvidenceContract, build_fault_spec, chaos_schedule_is_armed,
        highest_ordinal_pod_name, names_with_finalizers, pod_kill_storm_needs_controller_loop,
        runtime::chaos_experiment_is_active, validate_fixed_volume_snapshot,
        validate_network_partition_snapshot, validate_pod_failure_snapshot,
        volume_fault_runtime_contract,
    };
    use crate::fault::config::FaultTestConfig;
    use crate::fault::plan::{
        FaultInjection, FaultInjectionParameters, FaultKind, FaultSelection, FaultTarget, IoMethod,
    };
    use crate::fault::quorum::{ErasureSetShape, QuorumCaseClass, QuorumVolumeBoundary};
    use crate::fault::scenarios::{FaultBackend, FaultScenario};
    use std::{collections::BTreeSet, time::Duration};

    fn test_scenario(name: &str) -> FaultScenario {
        FaultScenario {
            name: name.to_string(),
            case_name: "fault_case",
            duration: Duration::from_secs(60),
            percent: 20,
            object_count: 12,
        }
    }

    #[test]
    fn network_loss_all_sources_renders_mode_all() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = NetworkChaosSpec::loss_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-loss",
            Duration::from_secs(60),
            80,
            0,
        )
        .expect("loss spec")
        .with_all_sources();
        let manifest = spec.manifest();
        assert!(manifest.contains("\n  mode: all\n"), "{manifest}");
        assert!(!manifest.contains("\n  mode: one\n"), "{manifest}");
        let one = NetworkChaosSpec::loss_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-loss",
            Duration::from_secs(60),
            80,
            0,
        )
        .expect("default loss spec");
        assert!(one.manifest().contains("\n  mode: one\n"));
    }

    #[test]
    fn iochaos_manifest_targets_rustfs_workload_only() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-eio",
            "/data/rustfs0",
            20,
            Duration::from_secs(60),
        )
        .expect("valid io chaos");
        let manifest = spec.manifest();

        assert!(manifest.contains("kind: IOChaos"));
        assert!(manifest.contains("namespace: chaos-mesh"));
        assert!(manifest.contains("rustfs.tenant: fault-test-tenant"));
        assert!(manifest.contains("rustfs-fault-test/run-id"));
        assert!(manifest.contains("s3chaos"));
        assert!(manifest.contains("containerNames:\n    - rustfs"));
        assert!(manifest.contains("volumePath: /data/rustfs0"));
        assert!(manifest.contains("errno: 5"));
        assert!(manifest.contains("percent: 20"));
        assert!(manifest.contains("\n  mode: one\n"));
        assert!(!manifest.contains("\n  value:"));
    }

    #[test]
    fn exact_pod_selector_replaces_the_tenant_label_selector() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "on-disk-bitrot",
            "/data/rustfs0",
            100,
            Duration::from_secs(60),
        )
        .expect("valid io chaos")
        .with_exact_pods(vec!["rustfs-1".to_string(), "rustfs-2".to_string()])
        .expect("exact Pod selector");
        let manifest = spec.manifest();

        assert!(manifest.contains("\n  mode: fixed\n  value: \"2\"\n"));
        assert!(manifest.contains(
            "    pods:\n      rustfs-fault-test:\n        - rustfs-1\n        - rustfs-2"
        ));
        assert!(!manifest.contains("labelSelectors:"));
    }

    #[test]
    fn exact_part_read_fault_keeps_volume_and_path_scopes_distinct() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "fresh-volume-replacement",
            "/data/rustfs0",
            100,
            Duration::from_secs(60),
        )
        .expect("valid io chaos")
        .with_read_only()
        .with_exact_path("/data/rustfs0/bucket/key/data/part.1")
        .expect("exact part path")
        .with_exact_pods(vec!["rustfs-0".to_string()])
        .expect("replacement Pod selector");
        let manifest = spec.manifest();

        assert!(manifest.contains("volumePath: /data/rustfs0"));
        assert!(manifest.contains("path: /data/rustfs0/bucket/key/data/part.1"));
        assert!(manifest.contains("methods:\n    - READ"));
        assert!(!manifest.contains("    - WRITE"));
        assert!(!manifest.contains(".metadata.bin"));
    }

    #[test]
    fn fixed_volume_manifest_and_runtime_records_prove_exact_targets() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = test_scenario("io-eio");
        let injection = FaultInjection::new(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: "/data/rustfs0".to_string(),
            },
            FaultSelection::FixedTargets(2),
            Duration::from_secs(60),
        )
        .expect("fixed volume injection");
        let spec = build_fault_spec(&config, &scenario, &injection, "run-1", "", None)
            .expect("fault spec");
        let runtime_contract = volume_fault_runtime_contract(&injection).expect("runtime contract");
        let FaultSpec::Io(spec) = spec else {
            panic!("expected IOChaos spec")
        };
        let manifest = spec.manifest();
        assert!(manifest.contains("\n  mode: fixed\n  value: \"2\"\n"));
        assert!(manifest.contains("\n  percent: 100\n"));

        let candidates = ["faults/rustfs-0", "faults/rustfs-1", "faults/rustfs-2"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let contract = VolumeTargetEvidenceContract {
            chaos_namespace: "chaos-mesh",
            target_namespace: "faults",
            tenant: "tenant-1",
            run_id: "run-1",
            scenario: "io-eio",
            volume_path: "/data/rustfs0",
            path: None,
            exact_pod_names: None,
            expected_targets: 2,
            candidate_pod_ids: &candidates,
            runtime: &runtime_contract,
        };
        let resource = serde_json::json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": "IOChaos",
            "metadata": {
                "namespace": "chaos-mesh",
                "labels": {
                    "rustfs-fault-test/run-id": "run-1",
                    "rustfs-fault-test/scenario": "io-eio",
                    "app.kubernetes.io/managed-by": "s3chaos"
                }
            },
            "spec": {
                "action": "fault",
                "errno": 5,
                "mode": "fixed",
                "value": "2",
                "selector": {
                    "namespaces": ["faults"],
                    "labelSelectors": {"rustfs.tenant": "tenant-1"}
                },
                "containerNames": ["rustfs"],
                "volumePath": "/data/rustfs0",
                "path": "/data/rustfs0/**/*",
                "methods": ["READ", "WRITE"],
                "percent": 100,
                "duration": "60s"
            },
            "status": {
                "conditions": [
                    {"type": "Selected", "status": "True"},
                    {"type": "AllInjected", "status": "True"},
                    {"type": "AllRecovered", "status": "False"}
                ],
                "experiment": {
                    "desiredPhase": "Run",
                    "containerRecords": [
                        {"id": "faults/rustfs-0/rustfs", "selectorKey": ".", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-1/rustfs", "selectorKey": ".", "phase": "Injected", "injectedCount": 1}
                    ]
                }
            }
        });
        assert_eq!(
            validate_fixed_volume_snapshot(&resource, &contract).expect("runtime proof"),
            ["faults/rustfs-0/rustfs", "faults/rustfs-1/rustfs"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        let exact_pods = ["rustfs-0", "rustfs-1"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut exact_resource = resource.clone();
        exact_resource["spec"]["selector"] = serde_json::json!({
            "pods": {"faults": ["rustfs-0", "rustfs-1"]}
        });
        let exact_contract = VolumeTargetEvidenceContract {
            exact_pod_names: Some(&exact_pods),
            ..contract
        };
        validate_fixed_volume_snapshot(&exact_resource, &exact_contract)
            .expect("exact Pod runtime proof");
        for (pointer, value) in [
            ("/spec/selector/pods/other", serde_json::json!(["rustfs-0"])),
            (
                "/spec/selector/pods/faults",
                serde_json::json!(["rustfs-0", "rustfs-1", "rustfs-1"]),
            ),
            (
                "/status/experiment/containerRecords/1/id",
                serde_json::json!("faults/rustfs-2/rustfs"),
            ),
        ] {
            let mut changed = exact_resource.clone();
            if pointer == "/spec/selector/pods/other" {
                changed["spec"]["selector"]["pods"]["other"] = value;
            } else {
                *changed.pointer_mut(pointer).expect("fixture field") = value;
            }
            assert!(
                validate_fixed_volume_snapshot(&changed, &exact_contract).is_err(),
                "reject changed {pointer}"
            );
        }

        for (pointer, value) in [
            ("/metadata/namespace", serde_json::json!("other-chaos")),
            ("/spec/action", serde_json::json!("latency")),
            ("/spec/errno", serde_json::json!(28)),
            ("/spec/methods", serde_json::json!(["WRITE"])),
            ("/spec/duration", serde_json::json!("61s")),
        ] {
            let mut tampered = resource.clone();
            *tampered.pointer_mut(pointer).expect("tamper target") = value;
            assert!(
                validate_fixed_volume_snapshot(&tampered, &contract).is_err(),
                "runtime contract must reject tampered {pointer}"
            );
        }

        let latency_injection = FaultInjection::new_with_parameters(
            FaultKind::RustfsVolumeLatency,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: "/data/rustfs0".to_string(),
            },
            FaultSelection::FixedTargets(2),
            Duration::from_secs(60),
            FaultInjectionParameters::IoLatency {
                delay: "250ms".to_string(),
                methods: vec![IoMethod::Read, IoMethod::Write],
            },
        )
        .expect("latency injection");
        let latency_runtime =
            volume_fault_runtime_contract(&latency_injection).expect("latency runtime contract");
        let latency_contract = VolumeTargetEvidenceContract {
            runtime: &latency_runtime,
            ..contract
        };
        let mut latency_resource = resource.clone();
        let latency_spec = latency_resource["spec"]
            .as_object_mut()
            .expect("latency spec");
        latency_spec.insert("action".to_string(), serde_json::json!("latency"));
        latency_spec.insert("delay".to_string(), serde_json::json!("250ms"));
        latency_spec.remove("errno");
        validate_fixed_volume_snapshot(&latency_resource, &latency_contract)
            .expect("latency runtime proof");
        latency_resource["spec"]["delay"] = serde_json::json!("251ms");
        assert!(validate_fixed_volume_snapshot(&latency_resource, &latency_contract).is_err());

        let mistake_injection = FaultInjection::new(
            FaultKind::RustfsVolumeReadMistake,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: "/data/rustfs0".to_string(),
            },
            FaultSelection::FixedTargets(2),
            Duration::from_secs(60),
        )
        .expect("mistake injection");
        let mistake_runtime =
            volume_fault_runtime_contract(&mistake_injection).expect("mistake runtime contract");
        let mistake_contract = VolumeTargetEvidenceContract {
            runtime: &mistake_runtime,
            ..contract
        };
        let mut mistake_resource = resource.clone();
        let mistake_spec = mistake_resource["spec"]
            .as_object_mut()
            .expect("mistake spec");
        mistake_spec.insert("action".to_string(), serde_json::json!("mistake"));
        mistake_spec.insert("methods".to_string(), serde_json::json!(["READ"]));
        mistake_spec.insert(
            "mistake".to_string(),
            serde_json::json!({
                "filling": "random",
                "maxOccurrences": 1,
                "maxLength": 4096
            }),
        );
        mistake_spec.remove("errno");
        validate_fixed_volume_snapshot(&mistake_resource, &mistake_contract)
            .expect("mistake runtime proof");
        mistake_resource["spec"]["mistake"]["maxOccurrences"] = serde_json::json!(2);
        assert!(validate_fixed_volume_snapshot(&mistake_resource, &mistake_contract).is_err());

        let mut duplicate_pod = resource.clone();
        duplicate_pod["status"]["experiment"]["containerRecords"][1]["id"] =
            serde_json::json!("faults/rustfs-0/rustfs");
        assert!(validate_fixed_volume_snapshot(&duplicate_pod, &contract).is_err());
        for selector_key in [".Target", "unknown"] {
            let mut extra_record = resource.clone();
            extra_record["status"]["experiment"]["containerRecords"]
                .as_array_mut()
                .expect("container records")
                .push(serde_json::json!({
                    "id": "faults/rustfs-2/rustfs",
                    "selectorKey": selector_key,
                    "phase": "Injected",
                    "injectedCount": 1
                }));
            assert!(
                validate_fixed_volume_snapshot(&extra_record, &contract).is_err(),
                "extra {selector_key} record must fail closed"
            );
        }
        let mut outside_proof = resource;
        outside_proof["status"]["experiment"]["containerRecords"][1]["id"] =
            serde_json::json!("faults/rustfs-9/rustfs");
        assert!(validate_fixed_volume_snapshot(&outside_proof, &contract).is_err());
    }

    #[test]
    fn metadata_p_plus_one_renders_nine_iochaos_targets_for_sixteen_shards() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = test_scenario("quorum-p-plus-one-io-fault");
        let semantic = FaultInjection::new_with_parameters(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: "/data/rustfs0".to_string(),
            },
            FaultSelection::RuntimeQuorum(QuorumVolumeBoundary {
                class: QuorumCaseClass::Metadata,
                beyond_read_tolerance: true,
            }),
            Duration::from_secs(60),
            FaultInjectionParameters::QuorumIo {
                class: QuorumCaseClass::Metadata,
            },
        )
        .expect("semantic quorum injection");
        let shape = ErasureSetShape::from_runtime_single_set(16, 1, &[1], &[16], 4)
            .expect("16-shard runtime shape");
        let injection = semantic
            .resolve_runtime_quorum(&shape)
            .expect("metadata P+1 target count");
        assert_eq!(injection.selection(), FaultSelection::FixedTargets(9));

        let FaultSpec::Io(spec) =
            build_fault_spec(&config, &scenario, &injection, "run-1", "", None)
                .expect("IOChaos fault spec")
        else {
            panic!("expected IOChaos spec")
        };
        assert!(
            spec.manifest()
                .contains("\n  mode: fixed\n  value: \"9\"\n")
        );
    }

    #[test]
    fn enospc_manifest_targets_only_volume_writes() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::enospc_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "disk-full",
            "/data/rustfs0",
            100,
            Duration::from_secs(60),
        )
        .expect("valid enospc chaos");
        let manifest = spec.manifest();

        assert!(manifest.contains("errno: 28"));
        assert!(manifest.contains("methods:\n    - WRITE"));
        assert!(manifest.contains("percent: 100"));
        assert!(!manifest.contains("    - READ"));
    }

    #[test]
    fn io_latency_manifest_targets_volume_reads_and_writes() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::latency_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-latency",
            "/data/rustfs0",
            IoLatencyParameters {
                methods: vec!["READ".to_string()],
                delay: "400ms".to_string(),
                percent: 20,
            },
            Duration::from_secs(60),
        )
        .expect("valid latency chaos");
        let manifest = spec.manifest();

        assert!(manifest.contains("action: latency"));
        assert!(manifest.contains("delay: 400ms"));
        assert!(manifest.contains("methods:\n    - READ"));
        assert!(!manifest.contains("    - WRITE"));
    }

    #[test]
    fn pod_failure_manifest_uses_duration() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = PodChaosSpec::fail_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "pod-failure",
            Duration::from_secs(60),
        )
        .expect("valid pod failure");
        let manifest = spec.manifest();

        assert!(manifest.contains("kind: PodChaos"));
        assert!(manifest.contains("action: pod-failure"));
        assert!(manifest.contains("duration: \"60s\""));
        assert!(manifest.contains("rustfs.tenant: fault-test-tenant"));
    }

    #[test]
    fn pod_failure_manifest_renders_the_plan_declared_fixed_target_count() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = PodChaosSpec::fail_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "pod-failure-quorum-edge",
            Duration::from_secs(900),
        )
        .expect("valid pod failure")
        .with_fixed_targets(2)
        .expect("fixed targets");
        let manifest = spec.manifest();

        assert!(manifest.contains("action: pod-failure"));
        assert!(manifest.contains("mode: fixed"));
        assert!(manifest.contains("value: \"2\""));
        assert!(manifest.contains("duration: \"900s\""));
        // A single target keeps the cheaper selector Chaos Mesh resolves
        // without a count.
        assert!(
            PodChaosSpec::fail_one_rustfs_pod(
                &config.cluster,
                "chaos-mesh",
                "run-1234567890",
                "pod-failure",
                Duration::from_secs(60),
            )
            .expect("valid pod failure")
            .manifest()
            .contains("mode: one")
        );
        assert!(
            PodChaosSpec::fail_one_rustfs_pod(
                &config.cluster,
                "chaos-mesh",
                "run-1234567890",
                "pod-failure-quorum-edge",
                Duration::from_secs(60),
            )
            .expect("valid pod failure")
            .with_fixed_targets(MAX_ERASURE_SET_SHARDS + 1)
            .is_err()
        );
    }

    #[test]
    fn pod_failure_runtime_evidence_binds_injected_records() {
        let candidates = [
            "faults/rustfs-0",
            "faults/rustfs-1",
            "faults/rustfs-2",
            "faults/rustfs-3",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
        let contract = PodFailureEvidenceContract {
            chaos_namespace: "chaos-mesh",
            target_namespace: "faults",
            tenant: "tenant-1",
            run_id: "run-1",
            scenario: "pod-failure-quorum-edge",
            expected_targets: 2,
            duration_seconds: 900,
            candidate_pod_ids: &candidates,
        };
        let resource = serde_json::json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": "PodChaos",
            "metadata": {
                "namespace": "chaos-mesh",
                "labels": {
                    "rustfs-fault-test/run-id": "run-1",
                    "rustfs-fault-test/scenario": "pod-failure-quorum-edge",
                    "app.kubernetes.io/managed-by": "s3chaos"
                }
            },
            "spec": {
                "action": "pod-failure",
                "mode": "fixed",
                "value": "2",
                "duration": "900s",
                "selector": {
                    "namespaces": ["faults"],
                    "labelSelectors": {"rustfs.tenant": "tenant-1"}
                }
            },
            "status": {
                "conditions": [
                    {"type": "Selected", "status": "True"},
                    {"type": "AllInjected", "status": "True"},
                    {"type": "AllRecovered", "status": "False"}
                ],
                "experiment": {
                    "desiredPhase": "Run",
                    "containerRecords": [
                        {"id": "faults/rustfs-0", "selectorKey": ".", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-1", "selectorKey": ".", "phase": "Injected", "injectedCount": 1}
                    ]
                }
            }
        });

        assert_eq!(
            validate_pod_failure_snapshot(&resource, &contract).expect("runtime proof"),
            ["faults/rustfs-0", "faults/rustfs-1"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );

        let mut wrong_mode = resource.clone();
        wrong_mode["spec"]["mode"] = serde_json::json!("one");
        assert!(validate_pod_failure_snapshot(&wrong_mode, &contract).is_err());

        let mut wrong_duration = resource.clone();
        wrong_duration["spec"]["duration"] = serde_json::json!("60s");
        assert!(validate_pod_failure_snapshot(&wrong_duration, &contract).is_err());

        let mut foreign_target = resource.clone();
        foreign_target["status"]["experiment"]["containerRecords"][1]["id"] =
            serde_json::json!("other/rustfs-9");
        assert!(validate_pod_failure_snapshot(&foreign_target, &contract).is_err());

        let mut unknown_selector = resource.clone();
        unknown_selector["status"]["experiment"]["containerRecords"]
            .as_array_mut()
            .expect("records")
            .push(serde_json::json!({"id": "faults/rustfs-2", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}));
        assert!(validate_pod_failure_snapshot(&unknown_selector, &contract).is_err());

        let mut not_injected = resource.clone();
        not_injected["status"]["experiment"]["containerRecords"][0]["phase"] =
            serde_json::json!("Not Injected");
        assert!(validate_pod_failure_snapshot(&not_injected, &contract).is_err());

        // Failing the whole proved set leaves no survivor to serve reads, so
        // the quorum-edge boundary cannot hold.
        let whole_cluster_candidates = ["faults/rustfs-0", "faults/rustfs-1"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        let whole_cluster = PodFailureEvidenceContract {
            candidate_pod_ids: &whole_cluster_candidates,
            ..contract
        };
        assert!(validate_pod_failure_snapshot(&resource, &whole_cluster).is_err());
    }

    #[test]
    fn network_delay_and_loss_manifests_use_targeted_actions() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let delay = NetworkChaosSpec::delay_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-delay",
            Duration::from_secs(60),
            NetworkDelayParameters {
                latency: "350ms".to_string(),
                jitter: "75ms".to_string(),
                correlation_percent: 15,
            },
        )
        .expect("valid network delay")
        .manifest();
        let loss = NetworkChaosSpec::loss_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-loss",
            Duration::from_secs(60),
            40,
            10,
        )
        .expect("valid network loss")
        .manifest();

        assert!(delay.contains("action: delay"));
        assert!(delay.contains("latency: \"350ms\""));
        assert!(delay.contains("jitter: \"75ms\""));
        assert!(delay.contains("correlation: \"15\""));
        assert!(loss.contains("action: loss"));
        assert!(loss.contains("loss: \"40\""));
        assert!(loss.contains("correlation: \"10\""));
    }

    #[test]
    fn network_partition_manifest_honors_multi_target_count() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");

        // Single-target keeps the historical `mode: one` shape.
        let single = NetworkChaosSpec::partition_rustfs_pods(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-partition-one",
            Duration::from_secs(60),
            1,
        )
        .expect("valid single-target partition")
        .manifest();
        assert!(single.contains("action: partition"));
        assert!(single.contains("\n  mode: one\n"));
        assert!(!single.contains("mode: fixed"));

        // Multi-target renders `mode: fixed` with the exact count so the
        // plan-declared blast radius is honored, and the peer side stays
        // `mode: all`.
        let quorum = NetworkChaosSpec::partition_rustfs_pods(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-partition-write-quorum-loss",
            Duration::from_secs(60),
            2,
        )
        .expect("valid multi-target partition")
        .manifest();
        assert!(quorum.contains("action: partition"));
        assert!(quorum.contains("\n  mode: fixed\n  value: \"2\"\n"));
        assert!(
            quorum.contains("    mode: all"),
            "peer target selector must stay mode: all"
        );

        assert!(
            NetworkChaosSpec::partition_rustfs_pods(
                &config.cluster,
                "chaos-mesh",
                "run-1234567890",
                "network-partition-write-quorum-loss",
                Duration::from_secs(60),
                0,
            )
            .is_err(),
            "zero targets must be rejected"
        );
    }

    #[test]
    fn network_partition_runtime_evidence_binds_injected_records() {
        let candidates = [
            "faults/rustfs-0",
            "faults/rustfs-1",
            "faults/rustfs-2",
            "faults/rustfs-3",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
        let contract = NetworkPartitionEvidenceContract {
            chaos_namespace: "chaos-mesh",
            target_namespace: "faults",
            tenant: "tenant-1",
            run_id: "run-1",
            scenario: "network-partition-write-quorum-loss",
            expected_source_targets: 2,
            candidate_pod_ids: &candidates,
        };
        let resource = serde_json::json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": "NetworkChaos",
            "metadata": {
                "namespace": "chaos-mesh",
                "labels": {
                    "rustfs-fault-test/run-id": "run-1",
                    "rustfs-fault-test/scenario": "network-partition-write-quorum-loss",
                    "app.kubernetes.io/managed-by": "s3chaos"
                }
            },
            "spec": {
                "action": "partition",
                "mode": "fixed",
                "value": "2",
                "selector": {
                    "namespaces": ["faults"],
                    "labelSelectors": {"rustfs.tenant": "tenant-1"}
                },
                "direction": "both",
                "target": {
                    "mode": "all",
                    "selector": {
                        "namespaces": ["faults"],
                        "labelSelectors": {"rustfs.tenant": "tenant-1"}
                    }
                }
            },
            "status": {
                "conditions": [
                    {"type": "Selected", "status": "True"},
                    {"type": "AllInjected", "status": "True"},
                    {"type": "AllRecovered", "status": "False"}
                ],
                "experiment": {
                    "desiredPhase": "Run",
                    "containerRecords": [
                        {"id": "faults/rustfs-0", "selectorKey": ".", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-1", "selectorKey": ".", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-0", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-1", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-2", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1},
                        {"id": "faults/rustfs-3", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}
                    ]
                }
            }
        });

        assert_eq!(
            validate_network_partition_snapshot(&resource, &contract).expect("runtime proof"),
            ["faults/rustfs-0", "faults/rustfs-1"]
                .into_iter()
                .map(str::to_string)
                .collect()
        );
        let mut missing_injection = resource.clone();
        missing_injection["status"]["experiment"]["containerRecords"]
            .as_array_mut()
            .expect("records")
            .remove(1);
        assert!(validate_network_partition_snapshot(&missing_injection, &contract).is_err());
        for extra in [
            serde_json::json!({"id": "foreign/pod", "selectorKey": ".Unexpected", "phase": "Injected", "injectedCount": 1}),
            serde_json::json!({"id": "foreign/pod", "phase": "Injected", "injectedCount": 1}),
        ] {
            let mut unknown_selector = resource.clone();
            unknown_selector["status"]["experiment"]["containerRecords"]
                .as_array_mut()
                .expect("records")
                .push(extra);
            assert!(validate_network_partition_snapshot(&unknown_selector, &contract).is_err());
        }
    }

    #[test]
    fn stress_manifests_target_one_rustfs_pod() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let cpu = StressChaosSpec::cpu_on_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "stress-cpu",
            Duration::from_secs(60),
            2,
            65,
        )
        .expect("valid cpu stress")
        .manifest();
        let memory = StressChaosSpec::memory_on_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "stress-memory",
            Duration::from_secs(60),
            3,
            "768MiB",
        )
        .expect("valid memory stress")
        .manifest();

        assert!(cpu.contains("kind: StressChaos"));
        assert!(cpu.contains("cpu:"));
        assert!(cpu.contains("workers: 2"));
        assert!(cpu.contains("load: 65"));
        assert!(memory.contains("memory:"));
        assert!(memory.contains("workers: 3"));
        assert!(memory.contains("size: \"768MiB\""));
        assert!(memory.contains("rustfs.tenant: fault-test-tenant"));
    }

    #[test]
    fn backend_spec_builder_maps_io_latency_params() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = test_scenario("io-latency");
        let injection = FaultInjection::new_with_parameters(
            FaultKind::RustfsVolumeLatency,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: "/data/rustfs0".to_string(),
            },
            FaultSelection::Percent(35),
            Duration::from_secs(90),
            FaultInjectionParameters::IoLatency {
                delay: "250ms".to_string(),
                methods: vec![IoMethod::Read],
            },
        )
        .expect("valid injection");

        let spec = build_fault_spec(
            &config,
            &scenario,
            &injection,
            "run-1234567890",
            "-01",
            None,
        )
        .expect("fault spec");

        match spec {
            FaultSpec::Io(spec) => {
                assert_eq!(spec.name, "rustfs-fault-io-latency-run-12345678-01");
                assert_eq!(
                    spec.action,
                    IoChaosAction::Latency {
                        delay: "250ms".to_string()
                    }
                );
                assert_eq!(spec.methods, ["READ"]);
                assert_eq!(spec.percent, 35);
                assert_eq!(spec.duration, Duration::from_secs(90));
            }
            _ => panic!("expected IOChaos spec"),
        }
    }

    #[test]
    fn backend_spec_builder_maps_network_delay_params() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = test_scenario("network-delay");
        let injection = FaultInjection::new_with_parameters(
            FaultKind::RustfsServerNetworkDelay,
            FaultBackend::ChaosMeshNetworkChaos,
            FaultTarget::RustfsServerPeerNetwork,
            FaultSelection::FixedTargets(1),
            Duration::from_secs(75),
            FaultInjectionParameters::NetworkDelay {
                latency: "350ms".to_string(),
                jitter: "75ms".to_string(),
                correlation_percent: 15,
            },
        )
        .expect("valid injection");

        let spec = build_fault_spec(
            &config,
            &scenario,
            &injection,
            "run-1234567890",
            "-02",
            None,
        )
        .expect("fault spec");

        match spec {
            FaultSpec::Network(spec) => {
                assert_eq!(spec.name, "rustfs-fault-net-delay-run-12345678-02");
                assert_eq!(
                    spec.action,
                    NetworkChaosAction::Delay {
                        latency: "350ms".to_string(),
                        jitter: "75ms".to_string(),
                        correlation: "15".to_string(),
                    }
                );
                assert_eq!(spec.duration, Duration::from_secs(75));
            }
            _ => panic!("expected NetworkChaos spec"),
        }
    }

    #[test]
    fn backend_spec_builder_preserves_special_pod_kill_variant() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = test_scenario("pod-kill-one");
        let injection = FaultInjection::new(
            FaultKind::RustfsServerPodKill,
            FaultBackend::ChaosMeshPodChaos,
            FaultTarget::RustfsServerPod,
            FaultSelection::FixedTargets(1),
            Duration::from_secs(60),
        )
        .expect("valid injection");

        let spec = build_fault_spec(
            &config,
            &scenario,
            &injection,
            "run-1234567890",
            "-03",
            None,
        )
        .expect("fault spec");

        match spec {
            FaultSpec::PodKill(spec) => {
                assert_eq!(spec.name, "rustfs-fault-pod-kill-run-12345678-03");
                assert_eq!(spec.action, PodChaosAction::PodKill);
            }
            _ => panic!("expected PodKill spec"),
        }
    }

    #[test]
    fn backend_spec_builder_maps_memory_stress_params() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = test_scenario("stress-memory");
        let injection = FaultInjection::new_with_parameters(
            FaultKind::RustfsServerMemoryStress,
            FaultBackend::ChaosMeshStressChaos,
            FaultTarget::RustfsServerResource,
            FaultSelection::FixedTargets(1),
            Duration::from_secs(120),
            FaultInjectionParameters::StressMemory {
                workers: 2,
                size: "768MiB".to_string(),
            },
        )
        .expect("valid injection");

        let spec = build_fault_spec(
            &config,
            &scenario,
            &injection,
            "run-1234567890",
            "-04",
            None,
        )
        .expect("fault spec");

        match spec {
            FaultSpec::Stress(spec) => {
                assert_eq!(spec.name, "rustfs-fault-stress-memory-run-12345678-04");
                match spec.action {
                    StressChaosAction::Memory { workers, size } => {
                        assert_eq!(workers, 2);
                        assert_eq!(size, "768MiB");
                    }
                    _ => panic!("expected memory stress"),
                }
                assert_eq!(spec.duration, Duration::from_secs(120));
            }
            _ => panic!("expected StressChaos spec"),
        }
    }

    #[test]
    fn chaos_name_suffix_keeps_run_label_stable() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-eio",
            "/data/rustfs0",
            20,
            Duration::from_secs(60),
        )
        .expect("valid io chaos")
        .with_name_suffix("-01");
        let manifest = spec.manifest();

        assert_eq!(spec.name, "rustfs-fault-io-eio-run-12345678-01");
        assert!(manifest.contains("name: rustfs-fault-io-eio-run-12345678-01"));
        assert!(manifest.contains("rustfs-fault-test/run-id: \"run-1234567890\""));
    }

    #[test]
    fn iochaos_active_requires_selected_and_injected_not_recovered() {
        let status = r#"{
          "status": {
            "conditions": [
              {"type": "Selected", "status": "True"},
              {"type": "AllInjected", "status": "True"},
              {"type": "AllRecovered", "status": "False"}
            ]
          }
        }"#;

        assert!(chaos_experiment_is_active(status).expect("valid status"));
    }

    #[test]
    fn chaos_experiment_active_rejects_unselected_experiment() {
        let status = r#"{
          "status": {
            "conditions": [
              {"type": "Selected", "status": "False"},
              {"type": "AllInjected", "status": "True"}
            ]
          }
        }"#;

        assert!(!chaos_experiment_is_active(status).expect("valid status"));
    }

    #[test]
    fn asymmetric_partition_is_one_way_and_single_target() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = NetworkChaosSpec::partition_one_way(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-asymmetric-partition",
            Duration::from_secs(60),
        )
        .expect("one-way partition");
        let manifest = spec.manifest();
        assert!(manifest.contains("name: rustfs-fault-net-asym-run-12345678"));
        assert!(manifest.contains("action: partition"));
        assert!(manifest.contains("direction: to"));
        assert!(manifest.contains("mode: one"));
        assert!(!manifest.contains("direction: both"));
        assert_eq!(spec.direction, NetworkChaosDirection::To);
        assert_eq!(spec.targets, 1);
    }

    #[test]
    fn flaky_loss_uses_bursty_correlation_and_distinct_name() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = NetworkChaosSpec::flaky_loss_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-flaky",
            Duration::from_secs(60),
            10,
            90,
        )
        .expect("flaky loss");
        let manifest = spec.manifest();
        assert!(manifest.contains("name: rustfs-fault-net-flaky-run-12345678"));
        assert!(manifest.contains("action: loss"));
        assert!(manifest.contains("loss: \"10\""));
        assert!(manifest.contains("correlation: \"90\""));
        assert!(manifest.contains("direction: both"));
    }

    #[test]
    fn erofs_iochaos_returns_errno_30_on_writes() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::erofs_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-read-only",
            "/data/rustfs0",
            100,
            Duration::from_secs(60),
        )
        .expect("erofs");
        let manifest = spec.manifest();
        assert!(manifest.contains("errno: 30"));
        assert!(manifest.contains("- WRITE"));
        assert!(!manifest.contains("- READ"));
        assert!(manifest.contains("percent: 100"));
        assert_eq!(spec.action, IoChaosAction::Fault { errno: 30 });
    }

    #[test]
    fn pod_kill_storm_schedule_pins_one_pod() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = ScheduleSpec::pod_kill_storm(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "pod-restart-storm",
            "tenant-pool-0-3",
        )
        .expect("schedule");
        let manifest = spec.manifest();
        assert_eq!(manifest.matches("kind:").count(), 1);
        assert!(manifest.contains("kind: Schedule"));
        assert!(manifest.contains("schedule: \"@every 15s\""));
        assert!(manifest.contains("concurrencyPolicy: Forbid"));
        assert!(manifest.contains("historyLimit: 1"));
        assert!(manifest.contains("type: PodChaos"));
        assert!(manifest.contains("action: pod-kill"));
        assert!(manifest.contains("gracePeriod: 0"));
        assert!(manifest.contains("tenant-pool-0-3"));
        assert!(
            ScheduleSpec::pod_kill_storm(
                &config.cluster,
                "chaos-mesh",
                "run-1",
                "pod-restart-storm",
                "Pod_3",
            )
            .is_err()
        );
    }

    #[test]
    fn highest_ordinal_pod_fails_closed() {
        assert_eq!(
            highest_ordinal_pod_name(["pool-0", "pool-2", "pool-1"]).expect("ordinal"),
            "pool-2"
        );
        assert!(highest_ordinal_pod_name(["pool-1", "other-1"]).is_err());
        assert!(highest_ordinal_pod_name(["pool-a"]).is_err());
        assert!(highest_ordinal_pod_name(std::iter::empty()).is_err());
    }

    #[test]
    fn named_pod_kill_pins_the_storm_victim_with_sigkill_grace() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = PodChaosSpec::kill_named_pod(
            &config.cluster,
            "chaos-mesh",
            "loop0001",
            "pod-restart-storm",
            "tenant-pool-0-3",
        )
        .expect("pinned kill");
        let manifest = spec.manifest();
        assert!(manifest.contains("gracePeriod: 0"));
        assert!(manifest.contains("tenant-pool-0-3"));
        assert!(manifest.contains("pods:"));
        assert!(!manifest.contains("labelSelectors"));
        assert!(manifest.contains("\n  mode: one\n"));
        assert!(
            PodChaosSpec::kill_named_pod(
                &config.cluster,
                "chaos-mesh",
                "loop0001",
                "pod-restart-storm",
                "Not_A_Pod",
            )
            .is_err()
        );
    }

    #[test]
    fn schedule_that_never_arms_falls_back_after_the_grace_window() {
        assert!(!pod_kill_storm_needs_controller_loop(
            Duration::from_secs(29),
            false
        ));
        assert!(pod_kill_storm_needs_controller_loop(
            POD_KILL_STORM_SCHEDULE_GRACE,
            false
        ));
        assert!(!pod_kill_storm_needs_controller_loop(
            Duration::from_secs(120),
            true
        ));
    }

    #[test]
    fn stuck_iochaos_finalizers_are_the_ones_cleanup_clears() {
        let names = names_with_finalizers(
            r#"{"items":[
                {"metadata":{"name":"stuck","finalizers":["chaos-mesh/records"]}},
                {"metadata":{"name":"clean","finalizers":[]}},
                {"metadata":{"name":"live"}}
            ]}"#,
        )
        .expect("list");
        assert_eq!(names, vec!["stuck".to_string()]);
    }

    #[test]
    fn schedule_armed_requires_status_time_and_no_deletion() {
        assert!(
            chaos_schedule_is_armed(r#"{"status":{"time":"2026-09-24T00:00:00Z"}}"#).expect("json")
        );
        assert!(
            !chaos_schedule_is_armed(
                r#"{"metadata":{"deletionTimestamp":"2026-01-01T00:00:01Z"},"status":{"time":"2026-09-24T00:00:00Z"}}"#
            )
            .expect("json")
        );
        assert!(!chaos_schedule_is_armed(r#"{"status":{}}"#).expect("json"));
        assert!(!chaos_schedule_is_armed(r#"{"status":{"time":""}}"#).expect("json"));
        assert!(
            !chaos_schedule_is_armed(r#"{"status":{"lastScheduleTime":"2026-09-24T00:00:00Z"}}"#)
                .expect("json")
        );
    }
}
