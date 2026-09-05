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

use crate::{
    fault::{
        backends::{
            chaos_mesh::{self, ChaosGuard},
            host::{self, DmFlakeyGuard, DmStatusSnapshot},
        },
        config::FaultTestConfig,
        fault_artifacts::FaultFailureArtifactSource,
        fault_lifecycle::{
            AppliedFault, FaultDeleteTimeoutRecovery, FaultDeleteTimeoutRecoveryRequest,
            FaultLifecyclePort,
        },
        host_storage::HostStorageMutationProof,
        plan::{FaultInjection, FaultPlan},
        pods::{wait_for_rustfs_pod_deletion, wait_for_rustfs_pod_replacement},
        reporting::{FaultStatusSnapshot, PodIdentity},
        scenarios::{FaultBackend, FaultScenario},
    },
    framework::{
        artifacts::ArtifactCollector,
        command::{CommandOutput, CommandSpec},
        config::ClusterTestConfig,
        kubectl::Kubectl,
    },
};
use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::collections::BTreeSet;
use std::time::{Duration, Instant};

pub(in crate::fault) fn require_fault_backends(
    config: &FaultTestConfig,
    plan: &FaultPlan,
) -> Result<()> {
    require_fault_backend(config, plan.fault().backend())?;
    for fault in plan
        .faults()
        .iter()
        .filter(|fault| fault.backend() == FaultBackend::DeviceMapper)
    {
        host::validate_config(config, fault.kind())?;
    }
    // Runtime erasure geometry is read after the fixture and S3 access path are
    // ready; neither exists yet during this static backend preflight.
    Ok(())
}

pub(in crate::fault) fn preflight_host_storage_mutation(
    config: &FaultTestConfig,
    scenario: &FaultScenario,
    plan: &FaultPlan,
    run_id: &str,
) -> Result<Option<HostStorageMutationProof>> {
    let injection = plan.fault();
    if injection.backend() != FaultBackend::DeviceMapper {
        return Ok(None);
    }
    let fault_name = format!("{}-00-{}", scenario.name, injection.kind().as_str());
    host::preflight_mutation(&host::HostStoragePreflightRequest {
        config,
        scenario,
        injection,
        run_id,
        fault_name: &fault_name,
    })
    .map(Some)
}

fn require_fault_backend(config: &FaultTestConfig, backend: FaultBackend) -> Result<()> {
    let cluster = &config.cluster;
    match backend {
        FaultBackend::ChaosMeshIoChaos => chaos_mesh::require_iochaos_crd(cluster),
        FaultBackend::MinioWarpWithChaos => {
            chaos_mesh::require_iochaos_crd(cluster)?;
            require_tool("warp", ["--help"])
        }
        FaultBackend::ChaosMeshPodChaos => chaos_mesh::require_podchaos_crd(cluster),
        FaultBackend::ChaosMeshNetworkChaos => chaos_mesh::require_networkchaos_crd(cluster),
        FaultBackend::ChaosMeshStressChaos => chaos_mesh::require_stresschaos_crd(cluster),
        FaultBackend::DeviceMapper => Ok(()),
        FaultBackend::PlannedReliabilityWorkflow => {
            bail!("planned reliability workflow scenarios are catalog-only and cannot execute yet")
        }
    }
}

fn require_tool<I, S>(program: &'static str, args: I) -> Result<()>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    CommandSpec::new(program)
        .args(args)
        .run_checked()
        .with_context(|| format!("{program} is required for the selected fault scenario"))?;
    Ok(())
}

pub(in crate::fault) fn cleanup_fault_backends(
    config: &FaultTestConfig,
    plan: &FaultPlan,
) -> Result<()> {
    cleanup_fault_backend(config, plan.fault().backend())?;
    Ok(())
}

fn cleanup_fault_backend(config: &FaultTestConfig, backend: FaultBackend) -> Result<()> {
    match backend {
        FaultBackend::ChaosMeshIoChaos
        | FaultBackend::MinioWarpWithChaos
        | FaultBackend::ChaosMeshPodChaos
        | FaultBackend::ChaosMeshNetworkChaos
        | FaultBackend::ChaosMeshStressChaos => {
            // Sweep every managed chaos kind, not just this plan's backend: a
            // chaos CR leaked by a prior run or a prior suite attempt of a
            // different kind would otherwise stay active during this attempt and
            // be misattributed to (or mask) the fault under test.
            chaos_mesh::cleanup_managed_chaos(&config.cluster, &config.chaos_namespace)
        }
        FaultBackend::DeviceMapper => Ok(()),
        FaultBackend::PlannedReliabilityWorkflow => Ok(()),
    }
}

struct ChaosFaultHandle {
    guard: Box<ChaosGuard>,
    active_required: bool,
}

struct PodKillFaultHandle {
    guard: Box<ChaosGuard>,
    before_pods: Vec<PodIdentity>,
    config: Box<ClusterTestConfig>,
}

struct DmFlakeyFaultHandle {
    guard: Box<DmFlakeyGuard>,
}

pub(in crate::fault) fn apply_fault(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    run_id: &str,
    host_storage_proof: Option<&HostStorageMutationProof>,
    execution_injection: &FaultInjection,
) -> Result<AppliedFault> {
    apply_fault_backend(&FaultApplyRequest {
        config,
        collector,
        scenario,
        injection: execution_injection,
        run_id,
        manifest_name: "chaos-manifest.yaml",
        resource_name_suffix: "",
        host_storage_proof,
    })
}

fn apply_fault_backend(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    match request.injection.backend() {
        FaultBackend::DeviceMapper => apply_host_fault_backend(request),
        FaultBackend::ChaosMeshIoChaos
        | FaultBackend::ChaosMeshPodChaos
        | FaultBackend::ChaosMeshNetworkChaos
        | FaultBackend::ChaosMeshStressChaos
        | FaultBackend::MinioWarpWithChaos => apply_chaos_mesh_fault_backend(request),
        FaultBackend::PlannedReliabilityWorkflow => {
            bail!("planned reliability workflow scenarios are catalog-only and cannot execute yet")
        }
    }
}

struct FaultApplyRequest<'a> {
    config: &'a FaultTestConfig,
    collector: &'a ArtifactCollector,
    scenario: &'a FaultScenario,
    injection: &'a FaultInjection,
    run_id: &'a str,
    manifest_name: &'a str,
    resource_name_suffix: &'a str,
    host_storage_proof: Option<&'a HostStorageMutationProof>,
}

fn apply_chaos_mesh_fault_backend(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    let applied = chaos_mesh::apply_fault(&chaos_mesh::FaultApplyRequest {
        config: request.config,
        collector: request.collector,
        scenario: request.scenario,
        injection: request.injection,
        run_id: request.run_id,
        manifest_name: request.manifest_name,
        resource_name_suffix: request.resource_name_suffix,
    })?;
    match applied {
        chaos_mesh::AppliedFault::Experiment {
            guard,
            active_required,
        } => Ok(Box::new(ChaosFaultHandle {
            guard: Box::new(guard),
            active_required,
        })),
        chaos_mesh::AppliedFault::PodKill { guard, before_pods } => {
            Ok(Box::new(PodKillFaultHandle {
                guard: Box::new(guard),
                before_pods,
                config: Box::new(request.config.cluster.clone()),
            }))
        }
    }
}

fn apply_host_fault_backend(request: &FaultApplyRequest<'_>) -> Result<AppliedFault> {
    let host_storage_proof = request
        .host_storage_proof
        .context("device-mapper fault lacks a host-storage mutation proof")?;
    Ok(Box::new(DmFlakeyFaultHandle {
        guard: Box::new(host::apply_fault(&host::FaultApplyRequest {
            config: request.config,
            collector: request.collector,
            scenario: request.scenario,
            injection: request.injection,
            run_id: request.run_id,
            host_storage_proof,
        })?),
    }))
}

impl FaultFailureArtifactSource for ChaosFaultHandle {
    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        suffix: &str,
    ) -> Result<()> {
        collect_chaos_failure_artifacts(self.guard.as_ref(), collector, case_name, suffix)
    }
}

impl FaultLifecyclePort for ChaosFaultHandle {
    fn wait_active(&self, timeout: Duration) -> Result<()> {
        if self.active_required {
            self.guard.wait_active(timeout)?;
        }
        Ok(())
    }

    fn ensure_active(&self, stage: &str) -> Result<()> {
        if self.active_required {
            self.guard.ensure_active(stage)?;
        }
        Ok(())
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        self.guard.delete(timeout)
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        chaos_fault_snapshot(self.guard.as_ref(), stage)
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        Some(self)
    }

    fn recover_delete_timeout(
        &mut self,
        request: &FaultDeleteTimeoutRecoveryRequest<'_>,
    ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
        if !self.guard.is_kind("iochaos") {
            return Ok(None);
        }
        Ok(recover_stuck_iochaos_finalizer(
            request.config,
            request.collector,
            request.case_name,
            self.guard.as_mut(),
            request.run_id,
            request.original_error,
            request.delete_started_at,
        )?
        .map(FaultDeleteTimeoutRecovery::from))
    }
}

impl FaultFailureArtifactSource for PodKillFaultHandle {
    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        suffix: &str,
    ) -> Result<()> {
        collect_chaos_failure_artifacts(self.guard.as_ref(), collector, case_name, suffix)
    }
}

impl FaultLifecyclePort for PodKillFaultHandle {
    fn wait_active(&self, timeout: Duration) -> Result<()> {
        wait_for_rustfs_pod_deletion(&self.config, &self.before_pods, timeout)
    }

    fn ensure_active(&self, _stage: &str) -> Result<()> {
        Ok(())
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        self.guard.delete(timeout)?;
        wait_for_rustfs_pod_replacement(&self.config, &self.before_pods, timeout)
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        chaos_fault_snapshot(self.guard.as_ref(), stage)
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        Some(self)
    }
}

impl FaultLifecyclePort for DmFlakeyFaultHandle {
    fn wait_active(&self, _timeout: Duration) -> Result<()> {
        Ok(())
    }

    fn ensure_active(&self, stage: &str) -> Result<()> {
        self.guard.ensure_active(stage)?;
        Ok(())
    }

    fn requires_recovery_boundary(&self) -> bool {
        self.guard.requires_crash_boundary()
    }

    fn prepare_recovery_boundary(&mut self, timeout: Duration, started_at_ms: u64) -> Result<()> {
        self.guard.prepare_recovery_boundary(timeout, started_at_ms)
    }

    fn delete(&mut self, _timeout: Duration) -> Result<()> {
        self.guard.restore()
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        Ok(FaultStatusSnapshot {
            stage: stage.to_string(),
            resource_kind: Some("device-mapper".to_string()),
            resource_name: None,
            chaos_status: None,
            dm_status: Some(match stage {
                "active" | "after-workload" => self.guard.ensure_active(stage)?,
                _ => self.guard.snapshot(stage)?,
            }),
        })
    }

    fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
        self.guard.recovery_snapshot().cloned()
    }
}

fn chaos_fault_snapshot(guard: &ChaosGuard, stage: &str) -> Result<FaultStatusSnapshot> {
    Ok(FaultStatusSnapshot {
        stage: stage.to_string(),
        resource_kind: Some(guard.kind().to_string()),
        resource_name: Some(guard.name().to_string()),
        chaos_status: Some(serde_json::from_str(&guard.json()?)?),
        dm_status: None,
    })
}

const IOCHAOS_FINALIZER_RECOVERY_WARNING: &str = "iochaos-finalizer-recovery-warning.json";
const IOCHAOS_FINALIZER_RECOVERY_DIAGNOSTIC: &str = "iochaos-finalizer-recovery-diagnostic.json";
const CHAOS_DAEMON_UNMOUNT_MARKER: &str = "unmount successfully";
const MANAGED_IOCHAOS_FINALIZERS: &[&str] = &[
    "chaos-mesh/records",
    "finalizer.chaos-mesh.org",
    "chaos-mesh.org/finalizer",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IoChaosFinalizerRecoveryReport {
    iochaos_namespace: String,
    iochaos_name: String,
    source: String,
    original_error: String,
    finalizers: Vec<String>,
    managed_finalizers: Vec<String>,
    unmanaged_finalizers: Vec<String>,
    finalizers_after_patch: Vec<String>,
    deletion_timestamp: Option<String>,
    run_id_label_matches: bool,
    managed_label_matches: bool,
    podiochaos_action_cleared: bool,
    target_pod_injection_absent: bool,
    daemon_unmount_observed: bool,
    daemon_unmount_matches: Vec<DaemonUnmountLogEvidence>,
    target_pods_ready: bool,
    namespace_deleting: bool,
    safe_to_patch: bool,
    patched: bool,
    decision: String,
    target_pods: Vec<TargetPodRecoveryEvidence>,
    target_nodes: Vec<String>,
    podiochaos: PodIoChaosRecoveryEvidence,
    daemon_log_artifacts: Vec<String>,
    controller_log_artifact: String,
    daemon_log_since: String,
}

impl From<IoChaosFinalizerRecoveryReport> for FaultDeleteTimeoutRecovery {
    fn from(report: IoChaosFinalizerRecoveryReport) -> Self {
        Self {
            warning_artifact: IOCHAOS_FINALIZER_RECOVERY_WARNING,
            resource_name: report.iochaos_name,
            target_nodes: report.target_nodes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DaemonUnmountLogEvidence {
    node: String,
    artifact: String,
    line: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct TargetPodRecoveryEvidence {
    name: String,
    node: Option<String>,
    ready: bool,
    terminating: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PodIoChaosRecoveryEvidence {
    query_succeeded: bool,
    related_count: usize,
    source_actions_remaining: usize,
    empty_action_objects: usize,
}

fn recover_stuck_iochaos_finalizer(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    guard: &mut ChaosGuard,
    run_id: &str,
    original_error: &anyhow::Error,
    delete_started_at: Instant,
) -> Result<Option<IoChaosFinalizerRecoveryReport>> {
    let mut report = collect_iochaos_finalizer_recovery_evidence(
        config,
        collector,
        case_name,
        guard,
        run_id,
        original_error,
        delete_started_at,
    )?;

    if !report.safe_to_patch {
        collector.write_text(
            case_name,
            IOCHAOS_FINALIZER_RECOVERY_DIAGNOSTIC,
            &serde_json::to_string_pretty(&report)?,
        )?;
        return Ok(None);
    }

    if let Err(error) = guard
        .replace_finalizers_and_wait_deleted(&report.finalizers_after_patch, config.cluster.timeout)
    {
        report.decision = format!("finalizer patch was allowed but failed: {error}");
        collector.write_text(
            case_name,
            IOCHAOS_FINALIZER_RECOVERY_DIAGNOSTIC,
            &serde_json::to_string_pretty(&report)?,
        )?;
        return Err(error);
    }
    report.patched = true;
    report.decision = "patched managed IOChaos finalizers after recovery evidence".to_string();
    collector.write_text(
        case_name,
        IOCHAOS_FINALIZER_RECOVERY_WARNING,
        &serde_json::to_string_pretty(&report)?,
    )?;
    Ok(Some(report))
}

fn collect_iochaos_finalizer_recovery_evidence(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    guard: &ChaosGuard,
    run_id: &str,
    original_error: &anyhow::Error,
    delete_started_at: Instant,
) -> Result<IoChaosFinalizerRecoveryReport> {
    let source = format!("{}/{}", guard.namespace(), guard.name());
    let iochaos_json_output = capture_command_artifact(
        collector,
        case_name,
        "iochaos-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(guard.namespace())
            .command(["get", guard.kind(), guard.name(), "-o", "json"]),
    )?;
    capture_command_artifact(
        collector,
        case_name,
        "iochaos-delete-timeout.yaml",
        Kubectl::new(&config.cluster)
            .namespaced(guard.namespace())
            .command(["get", guard.kind(), guard.name(), "-o", "yaml"]),
    )?;

    let iochaos = parse_success_json(&iochaos_json_output);
    let finalizers = iochaos
        .as_ref()
        .map(finalizers_from_resource)
        .unwrap_or_default();
    let managed_finalizers = finalizers
        .iter()
        .filter(|finalizer| is_managed_iochaos_finalizer(finalizer))
        .cloned()
        .collect::<Vec<_>>();
    let unmanaged_finalizers = finalizers
        .iter()
        .filter(|finalizer| !is_managed_iochaos_finalizer(finalizer))
        .cloned()
        .collect::<Vec<_>>();
    let finalizers_after_patch = unmanaged_finalizers.clone();
    let deletion_timestamp = iochaos
        .as_ref()
        .and_then(|value| value.pointer("/metadata/deletionTimestamp"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let run_id_label_matches = iochaos
        .as_ref()
        .is_some_and(|value| resource_label_matches(value, chaos_mesh::RUN_ID_LABEL, run_id));
    let managed_label_matches = iochaos.as_ref().is_some_and(|value| {
        resource_label_matches(
            value,
            chaos_mesh::MANAGED_BY_LABEL,
            chaos_mesh::MANAGED_BY_VALUE,
        )
    });

    let TargetRecoveryObservation {
        target_pods,
        target_nodes,
        podiochaos,
    } = observe_recovery_targets(config, collector, case_name, &source)?;
    let RecoveryLogEvidence {
        daemon_log_artifacts,
        daemon_unmount_matches,
        daemon_log_since,
        controller_log_artifact,
    } = collect_recovery_logs(
        config,
        collector,
        case_name,
        &target_nodes,
        delete_started_at,
    )?;
    let namespace_json_output = capture_command_artifact(
        collector,
        case_name,
        "target-namespace-delete-timeout.json",
        Kubectl::new(&config.cluster).command([
            "get",
            "namespace",
            &config.cluster.test_namespace,
            "-o",
            "json",
        ]),
    )?;
    let namespace_deleting = parse_success_json(&namespace_json_output)
        .as_ref()
        .is_some_and(resource_has_deletion_timestamp);

    let podiochaos_action_cleared = podiochaos.query_succeeded
        && podiochaos.related_count > 0
        && podiochaos.empty_action_objects == podiochaos.related_count
        && podiochaos.source_actions_remaining == 0;
    let target_pod_injection_absent =
        podiochaos.query_succeeded && podiochaos.source_actions_remaining == 0;
    let target_pods_ready =
        !target_pods.is_empty() && target_pods.iter().all(|pod| pod.ready && !pod.terminating);
    let mut report = IoChaosFinalizerRecoveryReport {
        iochaos_namespace: guard.namespace().to_string(),
        iochaos_name: guard.name().to_string(),
        source,
        original_error: original_error.to_string(),
        finalizers,
        managed_finalizers,
        unmanaged_finalizers,
        finalizers_after_patch,
        deletion_timestamp,
        run_id_label_matches,
        managed_label_matches,
        podiochaos_action_cleared,
        target_pod_injection_absent,
        daemon_unmount_observed: !daemon_unmount_matches.is_empty(),
        daemon_unmount_matches,
        target_pods_ready,
        namespace_deleting,
        safe_to_patch: false,
        patched: false,
        decision: String::new(),
        target_pods,
        target_nodes,
        podiochaos,
        daemon_log_artifacts,
        controller_log_artifact,
        daemon_log_since,
    };
    report.safe_to_patch = iochaos_finalizer_patch_allowed(&report);
    report.decision = if report.safe_to_patch {
        "recovery evidence satisfied; patching finalizers is allowed".to_string()
    } else {
        "recovery evidence incomplete; leaving IOChaos failure classification unchanged".to_string()
    };
    Ok(report)
}

struct TargetRecoveryObservation {
    target_pods: Vec<TargetPodRecoveryEvidence>,
    target_nodes: Vec<String>,
    podiochaos: PodIoChaosRecoveryEvidence,
}

fn observe_recovery_targets(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    source: &str,
) -> Result<TargetRecoveryObservation> {
    let target_pods_output = capture_command_artifact(
        collector,
        case_name,
        "target-pods-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(&config.cluster.test_namespace)
            .command([
                "get",
                "pod",
                "-l",
                &format!("rustfs.tenant={}", config.cluster.tenant_name),
                "-o",
                "json",
            ]),
    )?;
    let target_pods = parse_success_json(&target_pods_output)
        .as_ref()
        .map(target_pods_from_json)
        .unwrap_or_default();
    let target_pod_names = target_pods
        .iter()
        .map(|pod| pod.name.clone())
        .collect::<BTreeSet<_>>();
    let target_nodes = target_pods
        .iter()
        .filter_map(|pod| pod.node.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    capture_command_artifact(
        collector,
        case_name,
        "podiochaos-delete-timeout.yaml",
        Kubectl::new(&config.cluster)
            .namespaced(&config.cluster.test_namespace)
            .command(["get", "podiochaos", "-o", "yaml"]),
    )?;
    let podiochaos_json_output = capture_command_artifact(
        collector,
        case_name,
        "podiochaos-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(&config.cluster.test_namespace)
            .command(["get", "podiochaos", "-o", "json"]),
    )?;
    let podiochaos = parse_success_json(&podiochaos_json_output)
        .as_ref()
        .map(|value| podiochaos_recovery_evidence(value, &target_pod_names, source))
        .unwrap_or(PodIoChaosRecoveryEvidence {
            query_succeeded: false,
            related_count: 0,
            source_actions_remaining: usize::MAX,
            empty_action_objects: 0,
        });

    Ok(TargetRecoveryObservation {
        target_pods,
        target_nodes,
        podiochaos,
    })
}

struct RecoveryLogEvidence {
    daemon_log_artifacts: Vec<String>,
    daemon_unmount_matches: Vec<DaemonUnmountLogEvidence>,
    daemon_log_since: String,
    controller_log_artifact: String,
}

fn collect_recovery_logs(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    target_nodes: &[String],
    delete_started_at: Instant,
) -> Result<RecoveryLogEvidence> {
    let daemon_pods_output = capture_command_artifact(
        collector,
        case_name,
        "chaos-daemon-pods-delete-timeout.json",
        Kubectl::new(&config.cluster)
            .namespaced(&config.chaos_namespace)
            .command(["get", "pod", "-o", "json"]),
    )?;
    let daemon_pods = parse_success_json(&daemon_pods_output)
        .as_ref()
        .map(chaos_daemon_pods_from_json)
        .unwrap_or_default();
    let mut daemon_log_artifacts = Vec::new();
    let mut daemon_unmount_matches = Vec::new();
    let daemon_log_since = format!(
        "{}s",
        delete_started_at
            .elapsed()
            .as_secs()
            .saturating_add(30)
            .max(1)
    );
    for node in target_nodes {
        let artifact = format!(
            "chaos-daemon-{}-delete-timeout.log",
            sanitize_artifact_token(node)
        );
        if let Some(daemon_pod) = daemon_pods
            .iter()
            .find(|pod| pod.node.as_deref() == Some(node.as_str()))
        {
            let output = capture_command_artifact(
                collector,
                case_name,
                &artifact,
                Kubectl::new(&config.cluster)
                    .namespaced(&config.chaos_namespace)
                    .command(vec![
                        "logs".to_string(),
                        format!("pod/{}", daemon_pod.name),
                        "--since".to_string(),
                        daemon_log_since.clone(),
                        "--tail=1000".to_string(),
                    ]),
            )?;
            daemon_unmount_matches.extend(
                unmount_success_log_lines(&output.stdout)
                    .into_iter()
                    .map(|line| DaemonUnmountLogEvidence {
                        node: node.clone(),
                        artifact: artifact.clone(),
                        line,
                    }),
            );
            daemon_log_artifacts.push(artifact);
        } else {
            collector.write_text(
                case_name,
                &artifact,
                &format!("no chaos-daemon pod was found on target node {node}\n"),
            )?;
            daemon_log_artifacts.push(artifact);
        }
    }

    let controller_log_artifact = "chaos-controller-manager-delete-timeout.log".to_string();
    capture_command_artifact(
        collector,
        case_name,
        &controller_log_artifact,
        Kubectl::new(&config.cluster)
            .namespaced(&config.chaos_namespace)
            .command(vec![
                "logs".to_string(),
                "deployment/chaos-controller-manager".to_string(),
                "--since".to_string(),
                daemon_log_since.clone(),
                "--tail=1000".to_string(),
            ]),
    )?;

    Ok(RecoveryLogEvidence {
        daemon_log_artifacts,
        daemon_unmount_matches,
        daemon_log_since,
        controller_log_artifact,
    })
}

fn iochaos_finalizer_patch_allowed(report: &IoChaosFinalizerRecoveryReport) -> bool {
    report.run_id_label_matches
        && report.managed_label_matches
        && !report.finalizers.is_empty()
        && !report.managed_finalizers.is_empty()
        && report.unmanaged_finalizers.is_empty()
        && report.deletion_timestamp.is_some()
        && (report.podiochaos_action_cleared || report.target_pod_injection_absent)
        && report.daemon_unmount_observed
        && (report.target_pods_ready || report.namespace_deleting)
}

fn is_managed_iochaos_finalizer(finalizer: &str) -> bool {
    MANAGED_IOCHAOS_FINALIZERS.contains(&finalizer)
}

fn capture_command_artifact(
    collector: &ArtifactCollector,
    case_name: &str,
    file_name: &str,
    command: CommandSpec,
) -> Result<CommandOutput> {
    let output = command.run()?;
    let content = format!(
        "$ {cmd}\nexit: {code:?}\n\nstdout:\n{stdout}\n\nstderr:\n{stderr}\n",
        cmd = command.display(),
        code = output.code,
        stdout = output.stdout,
        stderr = output.stderr
    );
    collector.write_text(case_name, file_name, &content)?;
    Ok(output)
}

fn parse_success_json(output: &CommandOutput) -> Option<serde_json::Value> {
    if output.code == Some(0) {
        serde_json::from_str(&output.stdout).ok()
    } else {
        None
    }
}

fn finalizers_from_resource(value: &serde_json::Value) -> Vec<String> {
    value
        .pointer("/metadata/finalizers")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_str)
        .map(str::to_string)
        .collect()
}

fn resource_label_matches(value: &serde_json::Value, key: &str, expected: &str) -> bool {
    value
        .pointer("/metadata/labels")
        .and_then(serde_json::Value::as_object)
        .and_then(|labels| labels.get(key))
        .and_then(serde_json::Value::as_str)
        == Some(expected)
}

fn resource_has_deletion_timestamp(value: &serde_json::Value) -> bool {
    value
        .pointer("/metadata/deletionTimestamp")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|timestamp| !timestamp.is_empty())
}

fn target_pods_from_json(value: &serde_json::Value) -> Vec<TargetPodRecoveryEvidence> {
    value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let name = item
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)?
                .to_string();
            let node = item
                .pointer("/spec/nodeName")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string);
            let ready = item
                .pointer("/status/conditions")
                .and_then(serde_json::Value::as_array)
                .into_iter()
                .flatten()
                .any(|condition| {
                    condition.get("type").and_then(serde_json::Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(serde_json::Value::as_str)
                            == Some("True")
                });
            let terminating = resource_has_deletion_timestamp(item);
            Some(TargetPodRecoveryEvidence {
                name,
                node,
                ready,
                terminating,
            })
        })
        .collect()
}

fn podiochaos_recovery_evidence(
    value: &serde_json::Value,
    target_pod_names: &BTreeSet<String>,
    source: &str,
) -> PodIoChaosRecoveryEvidence {
    let related = value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            item.pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| target_pod_names.contains(name))
        })
        .collect::<Vec<_>>();
    let mut source_actions_remaining = 0usize;
    let mut empty_action_objects = 0usize;
    for item in &related {
        let actions = item
            .pointer("/spec/actions")
            .and_then(serde_json::Value::as_array);
        match actions {
            Some(actions) if actions.is_empty() => empty_action_objects += 1,
            Some(actions) => {
                source_actions_remaining += actions
                    .iter()
                    .filter(|action| {
                        action.get("source").and_then(serde_json::Value::as_str) == Some(source)
                    })
                    .count();
            }
            None => empty_action_objects += 1,
        }
    }

    PodIoChaosRecoveryEvidence {
        query_succeeded: true,
        related_count: related.len(),
        source_actions_remaining,
        empty_action_objects,
    }
}

fn chaos_daemon_pods_from_json(value: &serde_json::Value) -> Vec<TargetPodRecoveryEvidence> {
    value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|item| {
            let name_matches = item
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|name| name.contains("chaos-daemon"));
            let label_matches = item
                .pointer("/metadata/labels")
                .and_then(serde_json::Value::as_object)
                .is_some_and(|labels| {
                    labels
                        .get("app.kubernetes.io/component")
                        .and_then(serde_json::Value::as_str)
                        == Some("chaos-daemon")
                });
            name_matches || label_matches
        })
        .filter_map(|item| {
            Some(TargetPodRecoveryEvidence {
                name: item
                    .pointer("/metadata/name")
                    .and_then(serde_json::Value::as_str)?
                    .to_string(),
                node: item
                    .pointer("/spec/nodeName")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string),
                ready: true,
                terminating: resource_has_deletion_timestamp(item),
            })
        })
        .collect()
}

fn unmount_success_log_lines(log: &str) -> Vec<String> {
    log.lines()
        .filter(|line| {
            line.to_ascii_lowercase()
                .contains(CHAOS_DAEMON_UNMOUNT_MARKER)
        })
        .take(8)
        .map(str::to_string)
        .collect()
}

fn sanitize_artifact_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

pub(in crate::fault) fn collect_fault_artifacts(
    collector: &ArtifactCollector,
    case_name: &str,
    fault: &AppliedFault,
    suffix: &str,
) -> Result<()> {
    let status = fault
        .snapshot(suffix)
        .and_then(|snapshot| serde_json::to_string_pretty(&snapshot).map_err(Into::into))
        .unwrap_or_else(|error| format!("failed to collect fault status: {error}"));
    collector.write_text(case_name, &format!("fault-status-{suffix}.json"), &status)?;
    if let Some(artifacts) = fault.failure_artifacts() {
        artifacts.collect_failure_artifacts(collector, case_name, suffix)?;
    }
    Ok(())
}

fn collect_chaos_failure_artifacts(
    guard: &ChaosGuard,
    collector: &ArtifactCollector,
    case_name: &str,
    suffix: &str,
) -> Result<()> {
    let describe = guard
        .describe()
        .unwrap_or_else(|error| format!("failed to describe chaos before cleanup: {error}"));
    let describe_name = format!("chaos-describe-{suffix}.txt");
    collector.write_text(case_name, &describe_name, &describe)?;

    let yaml = guard
        .yaml()
        .unwrap_or_else(|error| format!("failed to get chaos yaml before cleanup: {error}"));
    let yaml_name = format!("chaos-{suffix}.yaml");
    collector.write_text(case_name, &yaml_name, &yaml)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::fault::reporting::FaultStatusSnapshot;

    use crate::framework::artifacts::ArtifactCollector;

    use anyhow::Result;
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::fs;
    use std::time::Duration;
    impl FaultLifecyclePort for RecordingFaultBackend {
        fn wait_active(&self, _timeout: Duration) -> Result<()> {
            Ok(())
        }

        fn ensure_active(&self, _stage: &str) -> Result<()> {
            Ok(())
        }

        fn delete(&mut self, _timeout: Duration) -> Result<()> {
            Ok(())
        }

        fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
            Ok(FaultStatusSnapshot {
                stage: stage.to_string(),
                resource_kind: Some("recording".to_string()),
                resource_name: Some(self.name.to_string()),
                chaos_status: None,
                dm_status: None,
            })
        }

        fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
            self.artifact_body
                .map(|_| self as &dyn FaultFailureArtifactSource)
        }
    }
    impl FaultFailureArtifactSource for RecordingFaultBackend {
        fn collect_failure_artifacts(
            &self,
            collector: &ArtifactCollector,
            case_name: &str,
            suffix: &str,
        ) -> Result<()> {
            let Some(body) = self.artifact_body else {
                return Ok(());
            };
            let artifact_name = format!("recording-artifact-{suffix}.txt");
            collector.write_text(case_name, &artifact_name, body)?;
            Ok(())
        }
    }
    struct RecordingFaultBackend {
        name: &'static str,
        artifact_body: Option<&'static str>,
    }
    #[test]
    fn single_fault_collects_only_its_declared_artifacts() {
        for body in [Some("fault artifact"), None] {
            let fault: AppliedFault = Box::new(RecordingFaultBackend {
                name: "target",
                artifact_body: body,
            });
            let tempdir = tempfile::tempdir().expect("tempdir");
            let collector = ArtifactCollector::new(tempdir.path());
            collect_fault_artifacts(&collector, "case", &fault, "failed").expect("collect");
            let dir = collector.case_dir("case");
            assert!(dir.join("fault-status-failed.json").is_file());
            let path = dir.join("recording-artifact-failed.txt");
            assert_eq!(path.exists(), body.is_some());
            if let Some(body) = body {
                assert_eq!(fs::read_to_string(path).expect("artifact"), body);
            }
        }
    }

    #[test]
    fn iochaos_finalizer_scope_requires_run_and_managed_labels() {
        let iochaos = json!({
            "metadata": {
                "labels": {
                    "rustfs-fault-test/run-id": "run-123",
                    "app.kubernetes.io/managed-by": "s3chaos"
                },
                "finalizers": ["chaos-mesh/records"],
                "deletionTimestamp": "2026-06-30T01:02:03Z"
            }
        });

        assert!(resource_label_matches(
            &iochaos,
            "rustfs-fault-test/run-id",
            "run-123"
        ));
        assert!(resource_label_matches(
            &iochaos,
            "app.kubernetes.io/managed-by",
            "s3chaos"
        ));
        assert_eq!(
            finalizers_from_resource(&iochaos),
            vec!["chaos-mesh/records"]
        );
        assert!(resource_has_deletion_timestamp(&iochaos));
    }
    #[test]
    fn podiochaos_evidence_tracks_current_source_actions() {
        let mut target_pods = BTreeSet::new();
        target_pods.insert("rustfs-0".to_string());
        let podiochaos = json!({
            "items": [
                {
                    "metadata": {"name": "rustfs-0"},
                    "spec": {
                        "actions": [
                            {"source": "chaos-mesh/rustfs-fault-io-eio"}
                        ]
                    }
                }
            ]
        });

        let evidence = podiochaos_recovery_evidence(
            &podiochaos,
            &target_pods,
            "chaos-mesh/rustfs-fault-io-eio",
        );

        assert_eq!(evidence.related_count, 1);
        assert_eq!(evidence.source_actions_remaining, 1);
        assert_eq!(evidence.empty_action_objects, 0);

        let cleared = json!({
            "items": [
                {
                    "metadata": {"name": "rustfs-0"},
                    "spec": {"actions": []}
                }
            ]
        });
        let evidence =
            podiochaos_recovery_evidence(&cleared, &target_pods, "chaos-mesh/rustfs-fault-io-eio");

        assert_eq!(evidence.related_count, 1);
        assert_eq!(evidence.source_actions_remaining, 0);
        assert_eq!(evidence.empty_action_objects, 1);
    }
    #[test]
    fn finalizer_patch_requires_complete_recovery_evidence() {
        let mut report = IoChaosFinalizerRecoveryReport {
            iochaos_namespace: "chaos-mesh".to_string(),
            iochaos_name: "rustfs-fault-io-eio-run-123".to_string(),
            source: "chaos-mesh/rustfs-fault-io-eio-run-123".to_string(),
            original_error: "timeout".to_string(),
            finalizers: vec!["chaos-mesh/records".to_string()],
            managed_finalizers: vec!["chaos-mesh/records".to_string()],
            unmanaged_finalizers: Vec::new(),
            finalizers_after_patch: Vec::new(),
            deletion_timestamp: Some("2026-06-30T01:02:03Z".to_string()),
            run_id_label_matches: true,
            managed_label_matches: true,
            podiochaos_action_cleared: true,
            target_pod_injection_absent: true,
            daemon_unmount_observed: true,
            daemon_unmount_matches: vec![DaemonUnmountLogEvidence {
                node: "node-a".to_string(),
                artifact: "chaos-daemon-node-a-delete-timeout.log".to_string(),
                line: "iochaos unmount successfully".to_string(),
            }],
            target_pods_ready: true,
            namespace_deleting: false,
            safe_to_patch: false,
            patched: false,
            decision: String::new(),
            target_pods: vec![TargetPodRecoveryEvidence {
                name: "rustfs-0".to_string(),
                node: Some("node-a".to_string()),
                ready: true,
                terminating: false,
            }],
            target_nodes: vec!["node-a".to_string()],
            podiochaos: PodIoChaosRecoveryEvidence {
                query_succeeded: true,
                related_count: 1,
                source_actions_remaining: 0,
                empty_action_objects: 1,
            },
            daemon_log_artifacts: vec!["chaos-daemon-node-a-delete-timeout.log".to_string()],
            controller_log_artifact: "chaos-controller-manager-delete-timeout.log".to_string(),
            daemon_log_since: "90s".to_string(),
        };

        assert!(iochaos_finalizer_patch_allowed(&report));

        report.daemon_unmount_observed = false;
        assert!(!iochaos_finalizer_patch_allowed(&report));

        report.daemon_unmount_observed = true;
        report.finalizers.push("example.com/cleanup".to_string());
        report
            .unmanaged_finalizers
            .push("example.com/cleanup".to_string());
        report
            .finalizers_after_patch
            .push("example.com/cleanup".to_string());
        assert!(!iochaos_finalizer_patch_allowed(&report));
    }
    #[test]
    fn finalizer_recovery_parses_target_pods_and_daemon_logs() {
        let pods = json!({
            "items": [
                {
                    "metadata": {"name": "rustfs-0"},
                    "spec": {"nodeName": "node-a"},
                    "status": {
                        "conditions": [
                            {"type": "Ready", "status": "True"}
                        ]
                    }
                }
            ]
        });
        let daemon_pods = json!({
            "items": [
                {
                    "metadata": {
                        "name": "chaos-daemon-abc",
                        "labels": {"app.kubernetes.io/component": "chaos-daemon"}
                    },
                    "spec": {"nodeName": "node-a"}
                }
            ]
        });

        let target_pods = target_pods_from_json(&pods);
        assert_eq!(target_pods[0].name, "rustfs-0");
        assert_eq!(target_pods[0].node.as_deref(), Some("node-a"));
        assert!(target_pods[0].ready);

        let daemon_pods = chaos_daemon_pods_from_json(&daemon_pods);
        assert_eq!(daemon_pods[0].name, "chaos-daemon-abc");
        assert!(!unmount_success_log_lines("iochaos unmount successfully").is_empty());
        assert_eq!(
            unmount_success_log_lines("old line\niochaos unmount successfully\nother"),
            vec!["iochaos unmount successfully"]
        );
    }
}
