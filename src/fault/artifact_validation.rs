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
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

use crate::fault::{
    acknowledged_mutation::AcknowledgedMutationKind,
    admin_decommission::{
        ADMIN_DECOMMISSION_OVERLAP_ARTIFACT, ADMIN_DECOMMISSION_TRANSCRIPT_ARTIFACT,
        AdminDecommissionOverlapEvidence, AdminDecommissionTranscript,
        validate_admin_decommission_evidence,
    },
    admin_rebalance::{
        ADMIN_REBALANCE_OVERLAP_ARTIFACT, ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
        AdminRebalanceOverlapEvidence, AdminRebalanceTranscript, validate_admin_rebalance_evidence,
    },
    admin_runner::{ADMIN_WORKFLOW_ARTIFACT, AdminWorkflowEvidence, AdminWorkflowPhaseStatus},
    admin_topology::{
        ADMIN_OPERATION_ARTIFACT, ADMIN_OPERATION_PROGRESS_ARTIFACT, ADMIN_TOPOLOGY_PROOF_ARTIFACT,
        AdminAttemptIdentity, AdminAttemptWindow, AdminCall, AdminOperationEvidence,
        AdminOperationProgressSample, AdminRequestEvidence, AdminTopologyProof, RebalanceStart,
        RebalanceStatus, rebalance_progress_sample, validate_admin_operation_progress,
        validate_admin_topology_artifacts,
    },
    backends::chaos_mesh::{
        NetworkPartitionEvidenceContract, PodFailureEvidenceContract, VolumeTargetEvidenceContract,
        iochaos_record_pod_id, validate_fixed_volume_snapshot, validate_network_partition_snapshot,
        validate_pod_failure_snapshot,
    },
    backends::lifecycle::evidence::{
        LifecycleRunContext, POD_LIFECYCLE_EVIDENCE_ARTIFACT, PodLifecycleEvidence,
        SNAPSHOT_TARGET_PODS_POINTER, total_outage_violation,
    },
    checker::{self, CheckerReport, RecoveryStabilityClassification, RecoveryStabilityReport},
    config::{
        DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS, DEFAULT_RUSTFS_POD_COUNT,
        DEFAULT_RUSTFS_POD_STABLE_WINDOW_SECONDS, DEFAULT_RUSTFS_VOLUME_PATH,
        DEFAULT_WORKLOAD_CONCURRENCY, DEFAULT_WORKLOAD_OBJECTS, MAX_ACK_TO_FAULT_MS,
    },
    events::{RunEvent, RunEventStatus},
    fixture::{ADMIN_FIXTURE_ARTIFACT, AdminFixtureEvidence, AdminFixturePhase, AdminFixturePlan},
    fresh_volume::{
        FRESH_VOLUME_CLEANUP_ARTIFACT, FRESH_VOLUME_FIXTURE_ARTIFACT,
        FRESH_VOLUME_HEAL_TRANSCRIPT_ARTIFACT, FRESH_VOLUME_READ_HISTORY_ARTIFACT,
        FreshVolumeReadMatrixEvidence, HealWireReceipt, validate_heal_transcript,
    },
    history::{
        DurabilityCohort, FaultWindowRelation, OperationKind, OperationOutcome, OperationRecord,
        validate_history_phase_boundary, validate_history_scope_and_order,
    },
    host_storage::DmStatusSnapshot,
    host_storage::{
        DM_FILESYSTEM_CHECK_ARTIFACT, DM_FILESYSTEM_CHECK_SCHEMA_VERSION, DmFilesystemCheck,
        HOST_STORAGE_CLEANUP_ARTIFACT, HOST_STORAGE_PROOF_ARTIFACT, HostStorageMutationProof,
        HostStoragePostCleanupObservation, normalized_dm_table_sha256,
    },
    node_down::{
        NODE_DOWN_HOLD_ARTIFACT, NodeDownHoldEvidence, NodeDownTarget, untouched_prefill_keys,
    },
    on_disk_bitrot::{
        BITROT_CLEANUP_ARTIFACT, BITROT_CORRUPTION_WINDOW_ARTIFACT, BITROT_HEAL_ARTIFACT,
        BITROT_MUTATION_ARTIFACT, BITROT_SELECTION_ARTIFACT, BITROT_WORKFLOW_ARTIFACT,
        BitrotCleanupEvidence, BitrotCorruptionWindowProof, BitrotHealEvidence,
        BitrotMutationEvidence, BitrotSelectionEvidence, OnDiskBitrotEvidenceSet,
        OnDiskBitrotWorkflowEvidence, validate_on_disk_bitrot_evidence,
    },
    plan::{
        ExecutionKind, ExecutionPlan, FaultInjection, FaultInjectionParameters, FaultKind,
        FaultPlanOptions, FaultSelection, FaultTarget, FaultWorkloadMode,
    },
    pods::fixed_volume_container_ids,
    preflight::{
        PreflightStatus, PreflightSummary, TargetProof, TargetProofStatus,
        target_pod_has_bound_volume, target_pod_has_fixed_volume,
    },
    quorum::{
        QuorumHealthObservation, QuorumMutationClass, QuorumVolumeBoundary,
        require_fresh_runtime_observation,
    },
    recovery_health::{
        RECOVERY_HEALTH_ARTIFACT, RecoveryHealthBaseline, RecoveryHealthReport,
        readiness_proxy_path,
    },
    reporting::{FailurePhase, FailureSummary, FailureVerdict, validate_failure_summary_v2_fields},
    scenarios::{
        self, ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO,
        DM_FLAKEY_VERSIONED_HOT_SCENARIO, FaultScenario, acknowledged_mutation_kind,
    },
    spec::{
        FAULT_RUN_API_VERSION, FAULT_RUN_KIND, FaultRunAckTriggerSpec, FaultRunArtifactSpec,
        FaultRunFaultSpec, FaultRunSpec, FaultRunTargetSpec,
    },
    storage_recovery::{
        DANGLING_CLEANUP_PROOF_ARTIFACT, DISK_GENERATION_PROOF_ARTIFACT, DanglingCleanupProof,
        FORCE_READ_PROOF_ARTIFACT, FreshVolumeReplacementProof, HEAL_PROGRESS_ARTIFACT,
        HEAL_SUMMARY_ARTIFACT, HealProgressSample, HealSummary, SHARD_INVENTORY_AFTER_ARTIFACT,
        SHARD_INVENTORY_BEFORE_ARTIFACT, ShardInventorySnapshot, StaleDiskReturnProof,
        StorageRecoveryCase, VERSION_SHARD_MAPPING_ARTIFACT, VersionShardMappingObservation,
    },
    storage_recovery_runner::{
        STORAGE_RECOVERY_WORKFLOW_ARTIFACT, StorageRecoveryWorkflowEvidence,
    },
    workload::execution::{
        AVAILABILITY_REPORT_ARTIFACT, AvailabilityReport, FamilyAvailability,
        NODE_DOWN_READ_HISTORY_ARTIFACT, NODE_DOWN_WRITE_HISTORY_ARTIFACT,
        NODE_DOWN_WRITE_REPORT_ARTIFACT, POST_RECOVERY_WRITE_HISTORY_ARTIFACT,
        POST_RECOVERY_WRITE_REPORT_ARTIFACT, PostRecoveryWriteReport,
        QUORUM_EDGE_READ_SURVIVAL_ARTIFACT, QuorumEdgeReadSurvivalReport,
        post_recovery_object_count,
    },
    workload::{
        ObjectSpec, WorkloadOperation, WorkloadPlan, WriteProbeScope,
        execution::{
            TypedQuorumReadCohortSource, TypedQuorumReadExpectation,
            require_typed_quorum_read_survival,
        },
    },
};

pub fn validate_admin_topology_artifact_files(
    scenario: &str,
    expected_attempt: &AdminAttemptIdentity,
    attempt_window: AdminAttemptWindow,
    case_dir: &Path,
) -> Result<()> {
    let case_dir = fs::canonicalize(case_dir).with_context(|| {
        format!(
            "canonicalize admin topology artifact directory {}",
            case_dir.display()
        )
    })?;
    let proof = read_json::<AdminTopologyProof>(&bound_case_artifact(
        &case_dir,
        ADMIN_TOPOLOGY_PROOF_ARTIFACT,
    )?)?;
    let operation = read_json::<AdminOperationEvidence>(&bound_case_artifact(
        &case_dir,
        ADMIN_OPERATION_ARTIFACT,
    )?)?;
    let progress = read_jsonl::<AdminOperationProgressSample>(&bound_case_artifact(
        &case_dir,
        ADMIN_OPERATION_PROGRESS_ARTIFACT,
    )?)?;
    let workload = read_json::<AdminWorkloadPlanArtifact>(&bound_case_artifact(
        &case_dir,
        "workload-plan.json",
    )?)?;
    let prefilled_count = workload.plan.object_count / 2;
    let mixed_count = workload.plan.object_count - prefilled_count;
    ensure!(
        mixed_count as u64 >= workload.plan.operation_mix.total_weight(),
        "admin workload plan must execute at least one complete operation-mix cycle"
    );
    let workload_max_bytes = workload
        .plan
        .mixed_write_upper_bound(prefilled_count, mixed_count)?;

    ensure!(
        workload.scenario == scenario
            && workload.run_id == expected_attempt.run_id
            && workload_max_bytes == proof.workload_max_bytes,
        "admin workload plan identity or byte bound does not match the current topology attempt"
    );

    validate_admin_topology_artifacts(
        scenario,
        expected_attempt,
        attempt_window,
        &proof,
        &operation,
    )?;
    validate_admin_operation_progress(&operation, &progress, attempt_window)?;
    if scenario == ADMIN_REBALANCE_SCENARIO {
        let overlap = read_json::<AdminRebalanceOverlapEvidence>(&bound_case_artifact(
            &case_dir,
            ADMIN_REBALANCE_OVERLAP_ARTIFACT,
        )?)?;
        let history =
            read_jsonl::<OperationRecord>(&bound_case_artifact(&case_dir, "history.jsonl")?)?;
        let checker =
            read_json::<CheckerReport>(&bound_case_artifact(&case_dir, "checker-report.json")?)?;
        let transcript = read_json::<AdminRebalanceTranscript>(&bound_case_artifact(
            &case_dir,
            ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
        )?)?;
        transcript.validate(&operation, &progress)?;
        validate_admin_rebalance_evidence(&operation, &progress, &overlap, &history, &checker)?;
    }
    if scenario == ADMIN_DECOMMISSION_SCENARIO {
        let transcript = read_json::<AdminDecommissionTranscript>(&bound_case_artifact(
            &case_dir,
            ADMIN_DECOMMISSION_TRANSCRIPT_ARTIFACT,
        )?)?;
        ensure!(
            transcript.operation_id.as_deref() == Some(operation.operation_id.as_str())
                && transcript.requests == operation.requests
                && transcript.progress == progress,
            "admin-decommission transcript does not match operation/progress evidence"
        );
        let overlap = read_json::<AdminDecommissionOverlapEvidence>(&bound_case_artifact(
            &case_dir,
            ADMIN_DECOMMISSION_OVERLAP_ARTIFACT,
        )?)?;
        let history =
            read_jsonl::<OperationRecord>(&bound_case_artifact(&case_dir, "history.jsonl")?)?;
        let checker =
            read_json::<CheckerReport>(&bound_case_artifact(&case_dir, "checker-report.json")?)?;
        validate_admin_decommission_evidence(&operation, &progress, &overlap, &history, &checker)?;
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct AdminWorkloadPlanArtifact {
    scenario: String,
    run_id: String,
    #[serde(flatten)]
    plan: WorkloadPlan,
}

#[derive(Debug, Clone)]
pub struct ArtifactValidationOptions {
    pub scenario: String,
    pub artifact_root: PathBuf,
    pub expected_workload_objects: usize,
    pub expected_workload_concurrency: usize,
    pub expected_workload_versioning: bool,
    pub expected_rustfs_pod_count: usize,
    pub expected_stable_window_seconds: u64,
    pub expected_recovery_stability_reread_seconds: u64,
    pub expected_rustfs_volume_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ArtifactValidationReport {
    pub scenario: String,
    pub case_name: String,
    pub seed: u64,
    pub client_disruptions: usize,
    pub recommitted: usize,
    pub committed: usize,
    pub required_artifacts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactValidationStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ArtifactValidationFileReport {
    pub schema_version: u8,
    pub status: ArtifactValidationStatus,
    pub scenario: String,
    pub artifact_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub case_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation: Option<ArtifactValidationReport>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ExpectedFailureArtifactReport {
    pub failure_summary: String,
    pub summary: FailureSummary,
    pub client_disruptions: usize,
}

struct FailedAttemptDisruptionEvidence {
    client_disruptions: usize,
    run_failed: bool,
}

#[derive(Clone, Copy)]
enum ArtifactIdentityPolicy<'a> {
    LegacyCompatible,
    PlannedAttempt(&'a str),
}

impl<'a> ArtifactIdentityPolicy<'a> {
    fn planned_run_id(self) -> Option<&'a str> {
        match self {
            Self::LegacyCompatible => None,
            Self::PlannedAttempt(run_id) => Some(run_id),
        }
    }
}

pub(crate) fn validate_failed_attempt_disruptions(
    suite_root: &Path,
    case_dir: &Path,
    attempt_run_id: &str,
    scenario: &str,
    case_name: &str,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<usize> {
    Ok(validate_failed_attempt_disruption_evidence(
        suite_root,
        case_dir,
        attempt_run_id,
        scenario,
        case_name,
        attempt_started_at_ms,
        evaluated_at_ms,
    )?
    .client_disruptions)
}

fn validate_failed_attempt_disruption_evidence(
    suite_root: &Path,
    case_dir: &Path,
    attempt_run_id: &str,
    scenario: &str,
    case_name: &str,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<FailedAttemptDisruptionEvidence> {
    let ack_mutation = acknowledged_mutation_kind(scenario);
    ensure!(
        attempt_run_id
            .strip_prefix("run-")
            .and_then(|id| Uuid::parse_str(id).ok())
            .is_some(),
        "failed-attempt safety requires a valid planned attempt runId"
    );
    let suite_root = fs::canonicalize(suite_root)
        .with_context(|| format!("canonicalize suite artifact root {}", suite_root.display()))?;
    let case_dir = fs::canonicalize(case_dir).with_context(|| {
        format!(
            "canonicalize case artifact directory {}",
            case_dir.display()
        )
    })?;
    ensure!(
        case_dir.starts_with(&suite_root),
        "case artifact directory is outside suite artifact root"
    );
    ensure!(
        attempt_started_at_ms <= evaluated_at_ms,
        "failed-attempt evaluation window is invalid"
    );

    let run_spec_path = bound_case_artifact(&case_dir, "run-spec.json")?;
    let run_spec = read_json::<ExpectedFailureRunSpecIdentity>(&run_spec_path)?;
    ensure!(
        run_spec.metadata.name == case_name
            && run_spec.metadata.run_id == attempt_run_id
            && run_spec.scenario.name == scenario
            && run_spec.scenario.case_name == case_name,
        "run-spec.json identity does not match the planned attempt"
    );
    if scenario == ADMIN_REBALANCE_SCENARIO {
        let run_spec = read_json::<FaultRunSpec>(&run_spec_path)?;
        ensure!(
            run_spec.execution_kind()? == ExecutionKind::Admin,
            "failed admin scenario does not carry an admin run-spec"
        );
        return validate_failed_admin_attempt_disruption_evidence(
            &case_dir,
            attempt_run_id,
            scenario,
            case_name,
            attempt_started_at_ms,
            evaluated_at_ms,
            &run_spec,
        );
    }
    let evidence_path = bound_case_artifact(&case_dir, "fault-evidence.json")?;
    let evidence = read_json::<FaultEvidenceArtifact>(&evidence_path)?;
    ensure!(
        evidence.scenario.as_deref() == Some(scenario)
            && evidence.run_id.as_deref() == Some(attempt_run_id),
        "fault-evidence.json identity does not match the planned attempt"
    );
    if ack_mutation.is_some() {
        ensure!(
            evidence.injected
                && !evidence.active_during_workload
                && evidence.recovered
                && evidence.client_disruptions == 0
                && !evidence.active_snapshots.is_empty()
                && evidence.workload_snapshots.is_empty(),
            "fault-evidence.json does not prove a completed ACK-triggered quiet lifecycle"
        );
        validate_ack_fault_window_evidence(&evidence)?;
    } else {
        ensure!(
            evidence.injected && evidence.active_during_workload && evidence.recovered,
            "fault-evidence.json does not prove a completed fault lifecycle"
        );
        ensure!(
            !evidence.active_snapshots.is_empty() && !evidence.workload_snapshots.is_empty(),
            "fault-evidence.json does not prove fault activity during the workload"
        );
        validate_fault_window_evidence(&evidence)?;
    }
    let lifecycle_started_at_ms = evidence
        .fault_prepare_started_at_ms
        .or(evidence.fault_apply_started_at_ms);
    ensure!(
        lifecycle_started_at_ms.is_some_and(|at| at >= attempt_started_at_ms)
            && evidence
                .recovery_ended_at_ms
                .is_some_and(|at| at <= evaluated_at_ms),
        "fault-evidence.json timestamps are outside the current attempt window"
    );

    let workload_plan =
        read_json::<ArtifactIdentity>(&bound_case_artifact(&case_dir, "workload-plan.json")?)?;
    ensure!(
        workload_plan.scenario.as_deref() == Some(scenario)
            && workload_plan.run_id.as_deref() == Some(attempt_run_id),
        "workload-plan.json identity does not match the planned attempt"
    );
    let disrupted = if ack_mutation.is_some() {
        0
    } else {
        let workload_path = bound_case_artifact(&case_dir, "workload-summary.json")?;
        let workload = read_json::<WorkloadSummaryArtifact>(&workload_path)?;
        ensure!(
            workload.scenario.as_deref() == Some(scenario)
                && workload.run_id.as_deref() == Some(attempt_run_id),
            "workload-summary.json identity does not match the planned attempt"
        );
        let disrupted = workload.disrupted()?;
        ensure!(
            disrupted == evidence.client_disruptions,
            "fault-evidence.json client_disruptions does not match workload-summary.json"
        );
        disrupted
    };

    let events_path = bound_case_artifact(&case_dir, "run-events.jsonl")?;
    let events = read_jsonl::<RunEvent>(&events_path)?;
    ensure!(
        !events.is_empty()
            && events.iter().all(|event| {
                event.scenario == scenario
                    && event.run_id == attempt_run_id
                    && (attempt_started_at_ms..=evaluated_at_ms).contains(&event.at_ms)
            }),
        "run-events.jsonl identity or timestamps do not match the planned attempt"
    );
    if let Some(expected_mutation) = ack_mutation {
        let full_run_spec = read_json::<FaultRunSpec>(&run_spec_path)?;
        let history =
            read_jsonl::<OperationRecord>(&bound_case_artifact(&case_dir, "history.jsonl")?)?;
        let _ = validate_ack_triggered_dm_artifacts(
            AckArtifactValidationContext {
                root: &case_dir,
                case_name,
                events: &events,
                evidence: &evidence,
                history: &history,
                scenario,
                run_id: attempt_run_id,
                bucket: &full_run_spec.metadata.bucket,
                run_spec: &full_run_spec,
            },
            expected_mutation,
        )?;
    }
    ensure!(
        has_event(&events, "run", RunEventStatus::Started)
            && (has_event(&events, "run", RunEventStatus::Failed)
                || has_event(&events, "run", RunEventStatus::Succeeded)),
        "run-events.jsonl is missing current-attempt run start or terminal event"
    );
    Ok(FailedAttemptDisruptionEvidence {
        client_disruptions: disrupted,
        run_failed: has_event(&events, "run", RunEventStatus::Failed),
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_failed_admin_attempt_disruption_evidence(
    case_dir: &Path,
    attempt_run_id: &str,
    scenario: &str,
    case_name: &str,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
    run_spec: &FaultRunSpec,
) -> Result<FailedAttemptDisruptionEvidence> {
    ensure!(
        run_spec.api_version == FAULT_RUN_API_VERSION
            && run_spec.kind == FAULT_RUN_KIND
            && run_spec.metadata.run_id == attempt_run_id
            && run_spec.metadata.name == case_name
            && run_spec.scenario.name == scenario
            && run_spec.scenario.case_name == case_name,
        "failed admin run-spec does not match the planned attempt"
    );
    let workflow = read_json::<AdminWorkflowEvidence>(&bound_case_artifact(
        case_dir,
        ADMIN_WORKFLOW_ARTIFACT,
    )?)?;
    workflow.validate()?;
    ensure!(
        !workflow.completed
            && workflow.scenario == scenario
            && workflow.run_id == attempt_run_id
            && workflow.phases.iter().all(|phase| {
                attempt_started_at_ms <= phase.started_at_ms && phase.ended_at_ms <= evaluated_at_ms
            }),
        "failed admin workflow does not belong to the current attempt window"
    );
    let phase_names = workflow
        .phases
        .iter()
        .map(|phase| phase.phase.as_str())
        .collect::<Vec<_>>();
    ensure!(
        matches!(
            phase_names.as_slice(),
            ["start", "cancel", "cleanup"]
                | ["start", "operation-workload-overlap", "cancel", "cleanup"]
                | [
                    "start",
                    "operation-workload-overlap",
                    "verify",
                    "cancel",
                    "cleanup"
                ]
                | ["start", "operation-workload-overlap", "verify", "cleanup"]
        ),
        "failed admin workflow has an unsupported phase sequence"
    );
    ensure!(
        workflow
            .phases
            .iter()
            .find(|phase| phase.phase == "cancel")
            .is_none_or(|phase| phase.status == AdminWorkflowPhaseStatus::Succeeded),
        "failed admin workflow does not prove successful ownership-safe cancellation"
    );

    let fixture =
        read_json::<AdminFixtureEvidence>(&bound_case_artifact(case_dir, ADMIN_FIXTURE_ARTIFACT)?)?;
    validate_failed_admin_fixture(
        &fixture,
        run_spec,
        attempt_run_id,
        scenario,
        attempt_started_at_ms,
        evaluated_at_ms,
    )?;
    let transcript = match scenario {
        ADMIN_REBALANCE_SCENARIO => read_json::<AdminRebalanceTranscript>(&bound_case_artifact(
            case_dir,
            ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
        )?)?,
        other => bail!("failed-attempt safety does not support admin scenario {other:?}"),
    };
    let proof = if transcript.requests.is_empty() {
        None
    } else {
        let proof = read_json::<AdminTopologyProof>(&bound_case_artifact(
            case_dir,
            ADMIN_TOPOLOGY_PROOF_ARTIFACT,
        )?)?;
        validate_failed_admin_topology_proof(&proof, &fixture, run_spec, case_name)?;
        Some(proof)
    };
    if transcript.requests.is_empty() {
        ensure!(
            !workflow.cancel_attempted,
            "failed admin workflow attempted cancellation without an owned operation receipt"
        );
    }
    validate_failed_admin_rebalance_transcript(
        &transcript,
        proof.as_ref(),
        &fixture,
        run_spec,
        case_name,
        attempt_started_at_ms,
        evaluated_at_ms,
    )?;
    validate_failed_admin_cancellation(&workflow, &transcript)?;

    let events = read_jsonl::<RunEvent>(&bound_case_artifact(case_dir, "run-events.jsonl")?)?;
    ensure!(
        !events.is_empty()
            && events.iter().all(|event| {
                event.scenario == scenario
                    && event.run_id == attempt_run_id
                    && (attempt_started_at_ms..=evaluated_at_ms).contains(&event.at_ms)
            })
            && has_event(&events, "run", RunEventStatus::Started)
            && has_event(&events, "run", RunEventStatus::Failed),
        "failed admin run events do not prove the current failed attempt"
    );

    let workload_window = failed_admin_workload_window(
        &workflow,
        &events,
        case_dir.join("workload-summary.json").exists(),
    )?;
    let client_disruptions =
        if let Some((workload_started_at_ms, workload_ended_at_ms)) = workload_window {
            fixture.validate_complete()?;
            ensure!(
                transcript.operation_id.is_some() && !transcript.requests.is_empty(),
                "failed admin workload phase lacks a run-owned operation start receipt"
            );
            let workload =
                read_json::<WorkloadPlan>(&bound_case_artifact(case_dir, "workload-plan.json")?)?;
            ensure!(
                workload == run_spec.workload.plan
                    && workload.seed == run_spec.workload.seed
                    && workload.object_count == run_spec.workload.object_count
                    && workload.concurrency == run_spec.workload.concurrency
                    && workload.operation_mix == run_spec.workload.operation_mix,
                "failed admin workload plan does not match run-spec"
            );
            let history =
                read_jsonl::<OperationRecord>(&bound_case_artifact(case_dir, "history.jsonl")?)?;
            ensure!(
                !history.is_empty(),
                "failed admin workload history must not be empty"
            );
            validate_history_scope_and_order(
                &history,
                scenario,
                attempt_run_id,
                &run_spec.metadata.bucket,
            )?;
            let workload_history = history
                .iter()
                .filter(|record| {
                    workload_started_at_ms <= record.started_at_ms
                        && record.started_at_ms < workload_ended_at_ms
                })
                .collect::<Vec<_>>();
            ensure!(
                !workload_history.is_empty()
                    && workload_history.iter().all(|record| {
                        record.ended_at_ms <= workload_ended_at_ms
                            && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                    })
                    && history
                        .iter()
                        .filter(|record| {
                            record.durability_cohort == Some(DurabilityCohort::FaultActive)
                        })
                        .all(|record| {
                            workload_started_at_ms <= record.started_at_ms
                                && record.started_at_ms < workload_ended_at_ms
                                && record.ended_at_ms <= workload_ended_at_ms
                        }),
                "failed admin workload history is not exactly bound to its workflow phase"
            );
            let summary = read_json::<WorkloadSummaryArtifact>(&bound_case_artifact(
                case_dir,
                "workload-summary.json",
            )?)?;
            ensure!(
                summary.scenario.as_deref() == Some(scenario)
                    && summary.run_id.as_deref() == Some(attempt_run_id)
                    && summary.seed == workload.seed
                    && summary.object_count == workload.object_count
                    && summary.concurrency == workload.concurrency
                    && summary.exercised_all_operation_families(),
                "failed admin workload summary does not match the completed current-run workload"
            );
            summary.require_history_matches(
                &history,
                scenario,
                &run_spec.metadata.bucket,
                DurabilityCohort::FaultActive,
                &workload,
                attempt_run_id,
            )?;
            validate_primary_workload_history(&workload_history, &workload, attempt_run_id)?;
            summary.disrupted()?
        } else {
            0
        };

    Ok(FailedAttemptDisruptionEvidence {
        client_disruptions,
        run_failed: true,
    })
}

fn failed_admin_workload_window(
    workflow: &AdminWorkflowEvidence,
    events: &[RunEvent],
    workload_summary_exists: bool,
) -> Result<Option<(u64, u64)>> {
    let workload_phase = workflow
        .phases
        .iter()
        .find(|phase| phase.phase == "operation-workload-overlap");
    match workload_phase {
        Some(phase) => {
            ensure!(
                has_event(events, "mixed-workload", RunEventStatus::Started)
                    && has_event(events, "mixed-workload", RunEventStatus::Succeeded)
                    && !has_event(events, "mixed-workload", RunEventStatus::Failed)
                    && workload_summary_exists,
                "failed admin attempt does not prove one completed workload phase with workload-summary.json"
            );
            Ok(Some((phase.started_at_ms, phase.ended_at_ms)))
        }
        None => {
            ensure!(
                !events.iter().any(|event| event.stage == "mixed-workload")
                    && !workload_summary_exists,
                "pre-workload admin failure carries unexpected workload evidence"
            );
            Ok(None)
        }
    }
}

fn validate_failed_admin_fixture(
    fixture: &AdminFixtureEvidence,
    run_spec: &FaultRunSpec,
    attempt_run_id: &str,
    scenario: &str,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<()> {
    let expected_plan =
        AdminFixturePlan::for_scenario(scenario, run_spec.recovery.expected_rustfs_pod_count)?;
    ensure!(
        fixture.schema_version == 1
            && fixture.scenario == scenario
            && fixture.run_id == attempt_run_id
            && fixture.tenant == run_spec.cluster.tenant
            && fixture.plan == expected_plan,
        "failed admin fixture does not match the current run-spec"
    );
    let expected_phases = [
        AdminFixturePhase::PrimaryReady,
        AdminFixturePhase::PrefillComplete,
        AdminFixturePhase::ExpansionApplied,
        AdminFixturePhase::TopologyStable,
    ];
    ensure!(
        fixture.observations.len() <= expected_phases.len(),
        "failed admin fixture has too many observations"
    );
    let tenant_uid = fixture
        .observations
        .first()
        .map(|observation| observation.tenant_uid.as_str());
    let initial = vec![fixture.plan.initial_pool_name.clone()];
    let expanded = vec![
        fixture.plan.initial_pool_name.clone(),
        fixture.plan.expansion_pool_name.clone(),
    ];
    let mut previous_at_ms = 0;
    for (index, observation) in fixture.observations.iter().enumerate() {
        let expected_pools = if index < 2 { &initial } else { &expanded };
        ensure!(
            observation.phase == expected_phases[index]
                && observation.observed_at_ms > previous_at_ms
                && (attempt_started_at_ms..=evaluated_at_ms).contains(&observation.observed_at_ms)
                && tenant_uid.is_some_and(|uid| !uid.is_empty() && observation.tenant_uid == uid)
                && observation.pool_names == *expected_pools
                && if index == 1 {
                    observation.prefilled_objects.is_some_and(|count| count > 0)
                } else {
                    observation.prefilled_objects.is_none()
                },
            "failed admin fixture observation is not a valid current-run prefix"
        );
        previous_at_ms = observation.observed_at_ms;
    }
    Ok(())
}

fn validate_failed_admin_topology_proof(
    proof: &AdminTopologyProof,
    fixture: &AdminFixtureEvidence,
    run_spec: &FaultRunSpec,
    case_name: &str,
) -> Result<()> {
    let tenant_uid = fixture
        .observations
        .first()
        .map(|observation| observation.tenant_uid.as_str())
        .context("failed admin transcript lacks a complete fixture Tenant identity")?;
    ensure!(
        proof.scenario == ADMIN_REBALANCE_SCENARIO
            && proof.attempt
                == (AdminAttemptIdentity {
                    run_id: run_spec.metadata.run_id.clone(),
                    case_name: case_name.to_string(),
                    tenant_uid: tenant_uid.to_string(),
                }),
        "failed admin topology proof does not belong to the current attempt"
    );
    proof.require_cluster_scope(
        &run_spec.cluster.context,
        &run_spec.cluster.namespace,
        &run_spec.cluster.tenant,
    )?;
    proof.require_satisfied()?;
    let prefilled_count = run_spec.workload.plan.object_count / 2;
    let mixed_count = run_spec.workload.plan.object_count - prefilled_count;
    ensure!(
        proof.workload_max_bytes
            == run_spec
                .workload
                .plan
                .mixed_write_upper_bound(prefilled_count, mixed_count)?,
        "failed admin topology proof does not reserve the planned workload budget"
    );
    Ok(())
}

fn validate_failed_admin_cancellation(
    workflow: &AdminWorkflowEvidence,
    transcript: &AdminRebalanceTranscript,
) -> Result<()> {
    let cancel_phase = workflow.phases.iter().find(|phase| phase.phase == "cancel");
    let starts = transcript
        .requests
        .iter()
        .filter(|request| {
            request.method == "POST" && request.path == "/rustfs/admin/v3/rebalance/start"
        })
        .count();
    let stops = transcript
        .requests
        .iter()
        .filter(|request| {
            request.method == "POST" && request.path == "/rustfs/admin/v3/rebalance/stop"
        })
        .count();
    let terminal = transcript
        .progress
        .last()
        .is_some_and(|sample| sample.completed || sample.failed || sample.canceled_or_stopped);
    let terminal_observed_at_ms = transcript
        .progress
        .last()
        .map(|sample| sample.observed_at_ms);

    ensure!(
        stops <= 1 && (!workflow.cancel_attempted || starts == 1) && (stops == 0 || starts == 1),
        "failed admin cancellation is not bound to one attempt-owned start receipt"
    );
    ensure!(
        (!workflow.cancel_attempted && stops == 0)
            || (workflow.cancel_attempted && cancel_phase.is_some()),
        "failed admin cancelAttempted summary contradicts its stop receipt"
    );
    ensure!(
        transcript.requests.is_empty() || terminal,
        "failed admin attempt does not prove the operation reached a terminal state"
    );
    if let Some(cancel_phase) = cancel_phase {
        ensure!(
            transcript
                .requests
                .iter()
                .filter(|request| request.path == "/rustfs/admin/v3/rebalance/stop")
                .all(|request| {
                    cancel_phase.started_at_ms <= request.started_at_ms
                        && request.observed_at_ms <= cancel_phase.ended_at_ms
                })
                && terminal_observed_at_ms
                    .is_none_or(|observed| observed <= cancel_phase.ended_at_ms),
            "failed admin cancellation receipts lie outside the cancel phase"
        );
    }
    Ok(())
}

fn validate_failed_admin_rebalance_transcript(
    transcript: &AdminRebalanceTranscript,
    proof: Option<&AdminTopologyProof>,
    fixture: &AdminFixtureEvidence,
    run_spec: &FaultRunSpec,
    case_name: &str,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<()> {
    if transcript.requests.is_empty() {
        ensure!(
            transcript.operation_id.is_none() && transcript.progress.is_empty(),
            "empty failed admin transcript carries an operation identity or progress"
        );
        return Ok(());
    }
    fixture.validate_complete()?;
    let tenant_uid = fixture.observations[0].tenant_uid.as_str();
    let proof = proof.context("failed admin transcript lacks its pre-start topology proof")?;
    let allowed_request = |request: &AdminRequestEvidence| {
        matches!(
            (request.method.as_str(), request.path.as_str()),
            ("POST", "/rustfs/admin/v3/rebalance/start")
                | ("GET", "/rustfs/admin/v3/rebalance/status")
                | ("POST", "/rustfs/admin/v3/rebalance/stop")
        ) && request.query.is_empty()
    };
    for request in &transcript.requests {
        ensure!(
            allowed_request(request)
                && (200..300).contains(&request.status)
                && attempt_started_at_ms <= request.started_at_ms
                && request.started_at_ms <= request.observed_at_ms
                && request.observed_at_ms <= evaluated_at_ms
                && request
                    .request_id
                    .as_deref()
                    .is_some_and(|request_id| !request_id.trim().is_empty()),
            "failed admin transcript contains an invalid request interval or route"
        );
        request.validate()?;
        proof
            .runtime
            .target
            .require_same_runtime_identity(&request.target)?;
        if let Some(probe) = &request.runtime_probe {
            proof.runtime.require_same_runtime(probe)?;
        }
        if request.path == "/rustfs/admin/v3/rebalance/stop" {
            ensure!(
                request.response_sha256.is_none() && request.response_body.is_none(),
                "failed admin stop receipt unexpectedly carries an unvalidated response body"
            );
        } else {
            validate_failed_admin_response_receipt(
                request.response_sha256.as_deref(),
                request.response_body.as_deref(),
            )?;
        }
    }
    ensure!(
        transcript
            .requests
            .windows(2)
            .all(|pair| pair[0].observed_at_ms <= pair[1].started_at_ms),
        "failed admin transcript requests are unordered"
    );
    let start_requests = transcript
        .requests
        .iter()
        .filter(|request| {
            request.method == "POST" && request.path == "/rustfs/admin/v3/rebalance/start"
        })
        .collect::<Vec<_>>();
    ensure!(
        start_requests.len() <= 1,
        "failed admin transcript contains duplicate start requests"
    );
    if let Some(start) = start_requests.first() {
        let captured = serde_json::from_str::<RebalanceStart>(
            start
                .response_body
                .as_deref()
                .expect("receipt checked above"),
        )?;
        ensure!(
            !captured.id.trim().is_empty()
                && transcript.operation_id.as_deref() == Some(captured.id.as_str()),
            "failed admin transcript operation ID does not match its start receipt"
        );
    }
    if let Some(operation_id) = &transcript.operation_id {
        ensure!(
            !operation_id.trim().is_empty(),
            "failed admin transcript has an empty operation ID"
        );
    }
    let status_requests = transcript
        .requests
        .iter()
        .filter(|request| {
            request.method == "GET" && request.path == "/rustfs/admin/v3/rebalance/status"
        })
        .collect::<Vec<_>>();
    ensure!(
        status_requests.len() == transcript.progress.len(),
        "failed admin transcript progress does not cover the exact status receipts"
    );
    let derived_operation_id = transcript
        .operation_id
        .as_deref()
        .or_else(|| {
            transcript
                .progress
                .first()
                .map(|sample| sample.operation_id.as_str())
        })
        .context("failed admin status transcript lacks an operation identity")?;
    for (request, sample) in status_requests.iter().zip(&transcript.progress) {
        let status = serde_json::from_str::<RebalanceStatus>(
            request
                .response_body
                .as_deref()
                .expect("receipt checked above"),
        )?;
        ensure!(
            !derived_operation_id.trim().is_empty() && status.id == derived_operation_id,
            "failed admin status receipt belongs to a different operation"
        );
        let projected = rebalance_progress_sample(
            proof,
            derived_operation_id,
            &AdminCall {
                value: status,
                request: (*request).clone(),
            },
        )?;
        ensure!(
            projected == *sample
                && sample.attempt.run_id == run_spec.metadata.run_id
                && sample.attempt.case_name == case_name
                && sample.attempt.tenant_uid == tenant_uid,
            "failed admin transcript progress is not derived from its current-run status receipt"
        );
    }
    Ok(())
}

fn validate_failed_admin_response_receipt(
    response_sha256: Option<&str>,
    response_body: Option<&str>,
) -> Result<()> {
    let response_sha256 = response_sha256.context("admin response digest is missing")?;
    let response_body = response_body.context("admin response body is missing")?;
    ensure!(
        response_sha256 == hex::encode(Sha256::digest(response_body.as_bytes())),
        "admin response digest does not match its body"
    );
    Ok(())
}

fn bound_case_artifact(case_dir: &Path, name: &str) -> Result<PathBuf> {
    let path = fs::canonicalize(case_dir.join(name))
        .with_context(|| format!("canonicalize current-attempt artifact {name}"))?;
    ensure!(
        path.parent() == Some(case_dir),
        "current-attempt artifact {name} does not belong to its planned case directory"
    );
    Ok(path)
}

pub(crate) struct AttemptFailureSummaryReference<'a> {
    pub observed_attempt_artifacts_dir: &'a str,
    pub planned_attempt_artifacts_dir: &'a str,
    pub planned_case_artifacts_dir: &'a str,
    pub planned_case_name: &'a str,
    pub failure_summary_ref: &'a str,
    pub scenario: &'a str,
    pub run_id: &'a str,
}

pub(crate) fn validate_attempt_failure_summary_reference(
    suite_root: &Path,
    reference: &AttemptFailureSummaryReference<'_>,
) -> Result<()> {
    let summary_ref = Path::new(reference.failure_summary_ref);
    ensure!(
        !summary_ref.is_absolute()
            && summary_ref.components().all(|component| {
                matches!(
                    component,
                    std::path::Component::Normal(_) | std::path::Component::CurDir
                )
            }),
        "failureSummary must be a relative path without parent traversal"
    );
    let suite_root = fs::canonicalize(suite_root)
        .with_context(|| format!("canonicalize suite artifact root {}", suite_root.display()))?;
    let canonical_dir = |reference: &str, label: &str| -> Result<PathBuf> {
        let reference = Path::new(reference);
        let path = if reference.is_absolute() {
            reference.to_path_buf()
        } else {
            suite_root.join(reference)
        };
        fs::canonicalize(&path).with_context(|| format!("canonicalize {label} {}", path.display()))
    };
    let observed_attempt_path = canonical_dir(
        reference.observed_attempt_artifacts_dir,
        "observed attempt artifact directory",
    )?;
    let planned_attempt_path = canonical_dir(
        reference.planned_attempt_artifacts_dir,
        "planned attempt artifact directory",
    )?;
    let planned_case_path = canonical_dir(
        reference.planned_case_artifacts_dir,
        "planned case artifact directory",
    )?;
    ensure!(
        observed_attempt_path == planned_attempt_path
            && planned_attempt_path.starts_with(&suite_root)
            && planned_case_path.parent() == Some(planned_attempt_path.as_path())
            && planned_case_path.file_name().and_then(|name| name.to_str())
                == Some(reference.planned_case_name),
        "suite-summary attempt directories do not match the suite plan"
    );
    let summary_path = fs::canonicalize(suite_root.join(summary_ref)).with_context(|| {
        format!(
            "canonicalize expected-failure proof {}",
            summary_ref.display()
        )
    })?;
    ensure!(
        summary_path.file_name().and_then(|name| name.to_str()) == Some("failure-summary.json")
            && summary_path.parent() == Some(planned_case_path.as_path()),
        "failureSummary does not belong to the current attempt"
    );
    let summary = read_json::<FailureSummaryReferenceIdentity>(&summary_path)?;
    ensure!(
        summary.scenario.as_deref() == Some(reference.scenario)
            && summary.run_id.as_deref() == Some(reference.run_id)
            && summary.case_name.as_deref() == Some(reference.planned_case_name),
        "failureSummary identity does not match the current attempt"
    );
    Ok(())
}

impl ArtifactValidationReport {
    pub fn validation_summary_tsv_row(&self) -> String {
        format!(
            "{}\t{}\t0\t{}\t{}\t{}\t0\t0\t0\t0\ttrue",
            self.scenario, self.seed, self.client_disruptions, self.recommitted, self.committed
        )
    }
}

pub fn validate_fault_artifacts_and_write_report(
    options: &ArtifactValidationOptions,
) -> Result<ArtifactValidationReport> {
    validate_fault_artifacts_and_write_report_with_identity(
        options,
        ArtifactIdentityPolicy::LegacyCompatible,
    )
}

pub(crate) fn validate_fault_artifacts_for_planned_attempt_and_write_report(
    options: &ArtifactValidationOptions,
    planned_run_id: &str,
) -> Result<ArtifactValidationReport> {
    ensure!(
        planned_run_id
            .strip_prefix("run-")
            .and_then(|id| Uuid::parse_str(id).ok())
            .is_some(),
        "success artifact validation requires a valid planned attempt runId"
    );
    validate_fault_artifacts_and_write_report_with_identity(
        options,
        ArtifactIdentityPolicy::PlannedAttempt(planned_run_id),
    )
}

fn validate_fault_artifacts_and_write_report_with_identity(
    options: &ArtifactValidationOptions,
    identity: ArtifactIdentityPolicy<'_>,
) -> Result<ArtifactValidationReport> {
    match validate_fault_artifacts_with_identity(options, identity) {
        Ok(report) => {
            write_artifact_validation_file_report(
                options,
                Some(&report.case_name),
                &ArtifactValidationFileReport {
                    schema_version: 1,
                    status: ArtifactValidationStatus::Passed,
                    scenario: options.scenario.clone(),
                    artifact_root: options.artifact_root.display().to_string(),
                    case_name: Some(report.case_name.clone()),
                    validation: Some(report.clone()),
                    errors: Vec::new(),
                },
            )
            .context("write artifact-validation-report.json")?;
            Ok(report)
        }
        Err(error) => {
            let message = error.to_string();
            let case_name = scenarios::scenario_spec(&options.scenario)
                .ok()
                .map(|spec| spec.case_name.to_string());
            let report = ArtifactValidationFileReport {
                schema_version: 1,
                status: ArtifactValidationStatus::Failed,
                scenario: options.scenario.clone(),
                artifact_root: options.artifact_root.display().to_string(),
                case_name: case_name.clone(),
                validation: None,
                errors: vec![message],
            };
            write_artifact_validation_file_report(options, case_name.as_deref(), &report)
                .context("write artifact-validation-report.json after validation failure")?;
            Err(error)
        }
    }
}

fn write_artifact_validation_file_report(
    options: &ArtifactValidationOptions,
    case_name: Option<&str>,
    report: &ArtifactValidationFileReport,
) -> Result<()> {
    let dir = case_name
        .map(|case_name| options.artifact_root.join(case_name))
        .unwrap_or_else(|| options.artifact_root.clone());
    fs::create_dir_all(&dir)
        .with_context(|| format!("create artifact validation report dir {}", dir.display()))?;
    fs::write(
        dir.join("artifact-validation-report.json"),
        serde_json::to_string_pretty(report)?,
    )
    .with_context(|| {
        format!(
            "write artifact validation report {}",
            dir.join("artifact-validation-report.json").display()
        )
    })
}

impl ArtifactValidationOptions {
    pub fn from_env(
        scenario: impl Into<String>,
        artifact_root: impl Into<PathBuf>,
    ) -> Result<Self> {
        let scenario = scenario.into();
        let expected_workload_versioning = scenarios::expected_workload_versioning_for_scenario(
            &scenario,
            env_bool("RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING")?,
        )?;
        Ok(Self {
            scenario,
            artifact_root: artifact_root.into(),
            expected_workload_objects: env_usize(
                "RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS",
                DEFAULT_WORKLOAD_OBJECTS,
            )?,
            expected_workload_concurrency: env_usize(
                "RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY",
                DEFAULT_WORKLOAD_CONCURRENCY,
            )?,
            expected_workload_versioning,
            expected_rustfs_pod_count: env_usize(
                "RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT",
                DEFAULT_RUSTFS_POD_COUNT,
            )?,
            expected_stable_window_seconds: env_u64(
                "RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS",
                DEFAULT_RUSTFS_POD_STABLE_WINDOW_SECONDS,
            )?,
            expected_recovery_stability_reread_seconds: env_u64(
                "RUSTFS_FAULT_TEST_RECOVERY_STABILITY_REREAD_SECONDS",
                DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS,
            )?,
            expected_rustfs_volume_path: env_string(
                "RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH",
                DEFAULT_RUSTFS_VOLUME_PATH,
            ),
        })
    }
}

pub fn validate_fault_artifacts(
    options: &ArtifactValidationOptions,
) -> Result<ArtifactValidationReport> {
    validate_fault_artifacts_with_identity(options, ArtifactIdentityPolicy::LegacyCompatible)
}

fn validate_fault_artifacts_with_identity(
    options: &ArtifactValidationOptions,
    identity: ArtifactIdentityPolicy<'_>,
) -> Result<ArtifactValidationReport> {
    let scenario_spec = scenarios::scenario_spec(&options.scenario)?;
    if matches!(
        options.scenario.as_str(),
        scenarios::ADMIN_DECOMMISSION_SCENARIO | scenarios::ADMIN_REBALANCE_SCENARIO
    ) {
        return validate_admin_execution_artifacts(options, identity, scenario_spec.case_name);
    }
    if options.scenario == scenarios::FRESH_VOLUME_REPLACEMENT_SCENARIO {
        return validate_storage_recovery_execution_artifacts(
            options,
            identity,
            scenario_spec.case_name,
        );
    }
    if options.scenario == scenarios::ON_DISK_BITROT_SCENARIO {
        return validate_on_disk_bitrot_artifacts(options, identity, scenario_spec.case_name);
    }
    if options.scenario == scenarios::STALE_DISK_RETURN_DETECT_SCENARIO {
        return validate_stale_disk_execution_artifacts(options, identity, scenario_spec.case_name);
    }
    let ack_mutation = acknowledged_mutation_kind(&options.scenario);
    validate_conditional_recovery_stability_artifact(
        &options.artifact_root,
        scenario_spec.case_name,
        &options.scenario,
        identity.planned_run_id(),
    )?;
    let artifacts = locate_required_artifacts(
        &options.artifact_root,
        scenario_spec.case_name,
        &options.scenario,
    )?;

    let metadata_path = required(&artifacts, "run-metadata.json")?;
    ensure_json_field_present(
        metadata_path,
        "/recovery_stability_reread_seconds",
        "run-metadata.json recovery_stability_reread_seconds",
    )?;
    ensure_json_field_present(
        metadata_path,
        "/require_client_disruption",
        "run-metadata.json require_client_disruption",
    )?;
    let metadata = read_json::<RunMetadataArtifact>(metadata_path)?;
    ensure!(
        metadata.scenario == options.scenario,
        "run-metadata.json scenario {:?} does not match selected scenario {:?}",
        metadata.scenario,
        options.scenario
    );
    ensure_nonempty(&metadata.run_id, "run-metadata.json run_id")?;
    if let Some(planned_run_id) = identity.planned_run_id() {
        ensure!(
            metadata.run_id == planned_run_id,
            "run-metadata.json run_id does not match the planned attempt"
        );
    }
    ensure_nonempty(&metadata.rustfs_image, "run-metadata.json rustfs_image")?;
    ensure_nonempty(&metadata.storage_class, "run-metadata.json storage_class")?;
    ensure_nonempty(&metadata.context, "run-metadata.json context")?;
    ensure!(
        metadata.workload_objects == options.expected_workload_objects,
        "run-metadata.json workload_objects {} does not match expected {}",
        metadata.workload_objects,
        options.expected_workload_objects
    );
    ensure!(
        metadata.workload_concurrency == options.expected_workload_concurrency,
        "run-metadata.json workload_concurrency {} does not match expected {}",
        metadata.workload_concurrency,
        options.expected_workload_concurrency
    );
    ensure!(
        metadata.recovery_stability_reread_seconds
            == options.expected_recovery_stability_reread_seconds,
        "run-metadata.json recovery_stability_reread_seconds {} does not match expected {}",
        metadata.recovery_stability_reread_seconds,
        options.expected_recovery_stability_reread_seconds
    );

    let workload_plan_path = required(&artifacts, "workload-plan.json")?;
    let workload_plan = read_json::<WorkloadPlan>(workload_plan_path)?;
    let workload_plan_identity = read_json::<ArtifactIdentity>(workload_plan_path)?;
    validate_optional_artifact_identity(
        "workload-plan.json",
        &workload_plan_identity,
        &metadata,
        identity,
    )?;
    ensure!(
        workload_plan.object_count == options.expected_workload_objects,
        "workload-plan.json object_count {} does not match expected {}",
        workload_plan.object_count,
        options.expected_workload_objects
    );
    ensure!(
        workload_plan.concurrency == options.expected_workload_concurrency,
        "workload-plan.json concurrency {} does not match expected {}",
        workload_plan.concurrency,
        options.expected_workload_concurrency
    );

    let json_spec_path = required(&artifacts, "run-spec.json")?;
    let yaml_spec_path = required(&artifacts, "run-spec.yaml")?;
    ensure_json_field_present(
        json_spec_path,
        "/recovery/recovery_stability_reread_seconds",
        "run-spec.json recovery.recovery_stability_reread_seconds",
    )?;
    ensure_yaml_field_present(
        yaml_spec_path,
        "/recovery/recovery_stability_reread_seconds",
        "run-spec.yaml recovery.recovery_stability_reread_seconds",
    )?;
    let json_spec = read_json::<FaultRunSpec>(json_spec_path)?;
    let yaml_spec = read_yaml::<FaultRunSpec>(yaml_spec_path)?;
    ensure!(
        json_spec == yaml_spec,
        "run spec JSON and YAML artifacts do not describe the same contract"
    );
    validate_run_spec(&json_spec, options)?;
    ensure!(
        identity.planned_run_id().is_none()
            || json_spec.scenario.detector.as_ref() == Some(&scenario_spec.detector.contract()),
        "current-attempt run-spec.json detector contract does not match the scenario"
    );
    ensure!(
        json_spec.metadata.name == scenario_spec.case_name
            && json_spec.metadata.run_id == metadata.run_id,
        "run-spec metadata does not match the selected case and run-metadata.json run identity"
    );
    ensure!(
        json_spec.workload.plan == workload_plan
            && json_spec.workload.seed == workload_plan.seed
            && json_spec.workload.object_count == workload_plan.object_count
            && json_spec.workload.concurrency == workload_plan.concurrency
            && json_spec.workload.operation_mix == workload_plan.operation_mix,
        "run-spec workload fields and workload-plan.json do not identify the same deterministic workload"
    );

    let preflight_summary =
        read_json::<PreflightSummary>(required(&artifacts, "preflight-summary.json")?)?;
    validate_preflight_summary(&preflight_summary, options)?;
    validate_optional_identity_fields(
        "preflight-summary.json",
        Some(metadata.scenario.as_str()),
        preflight_summary.run_id.as_deref(),
        &metadata,
        identity,
    )?;
    let target_proof = read_json::<TargetProof>(required(&artifacts, "target-proof.json")?)?;
    validate_target_proof(&target_proof, &json_spec, options)?;

    let events = read_jsonl::<RunEvent>(required(&artifacts, "run-events.jsonl")?)?;
    ensure!(
        events
            .iter()
            .all(|event| { event.scenario == options.scenario && event.run_id == metadata.run_id }),
        "run-events.jsonl identity does not match run-metadata.json"
    );
    ensure!(
        has_event(&events, "run", RunEventStatus::Started)
            && has_event(&events, "run", RunEventStatus::Succeeded)
            && has_event(&events, "checker-final", RunEventStatus::Succeeded),
        "run-events.jsonl is missing run started, run succeeded, or checker-final succeeded events"
    );
    let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
    ensure!(
        !history.is_empty(),
        "history.jsonl must contain operation records"
    );
    for record in &history {
        validate_optional_identity_fields(
            "history.jsonl operation record",
            Some(record.scenario.as_str()),
            record.run_id.as_deref(),
            &metadata,
            identity,
        )?;
    }

    let fault_evidence_path = required(&artifacts, "fault-evidence.json")?;
    ensure_json_field_present(
        fault_evidence_path,
        "/require_client_disruption",
        "fault-evidence.json require_client_disruption",
    )?;
    let evidence = read_json::<FaultEvidenceArtifact>(fault_evidence_path)?;
    validate_optional_identity_fields(
        "fault-evidence.json",
        evidence.scenario.as_deref(),
        evidence.run_id.as_deref(),
        &metadata,
        identity,
    )?;
    if ack_mutation.is_some() {
        ensure!(
            evidence.injected && !evidence.active_during_workload && evidence.recovered,
            "ACK-triggered fault-evidence.json must record injected=true, active_during_workload=false, recovered=true"
        );
        ensure!(
            !evidence.active_snapshots.is_empty() && evidence.workload_snapshots.is_empty(),
            "ACK-triggered fault-evidence.json must include an active snapshot and no under-fault workload snapshot"
        );
        ensure!(
            evidence.client_disruptions == 0 && !evidence.require_client_disruption,
            "ACK-triggered quiet mutation cannot claim or require client disruptions"
        );
    } else {
        ensure!(
            evidence.injected && evidence.active_during_workload && evidence.recovered,
            "fault-evidence.json must record injected=true, active_during_workload=true, recovered=true"
        );
        ensure!(
            !evidence.active_snapshots.is_empty() && !evidence.workload_snapshots.is_empty(),
            "fault-evidence.json must include active and workload fault snapshots"
        );
    }
    ensure!(
        evidence.require_client_disruption == metadata.require_client_disruption,
        "fault-evidence.json require_client_disruption {} does not match run-metadata.json {}",
        evidence.require_client_disruption,
        metadata.require_client_disruption
    );
    if options.scenario == scenarios::NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
        validate_write_quorum_runtime_evidence(
            &evidence,
            &target_proof,
            &json_spec,
            QuorumEdgeRuntimeKind::NetworkPartition,
        )?;
    }
    if options.scenario == scenarios::POD_FAILURE_QUORUM_EDGE_SCENARIO {
        validate_write_quorum_runtime_evidence(
            &evidence,
            &target_proof,
            &json_spec,
            QuorumEdgeRuntimeKind::PodFailure,
        )?;
    }
    if options.scenario == scenarios::IO_EIO_SCENARIO {
        validate_volume_availability_topology_evidence(&evidence, &target_proof)?;
    }
    if json_spec
        .faults
        .iter()
        .any(|fault| fault.backend == "device-mapper")
    {
        let proof_path = locate_artifact(
            &options.artifact_root,
            scenario_spec.case_name,
            HOST_STORAGE_PROOF_ARTIFACT,
        )?;
        let cleanup_path = locate_artifact(
            &options.artifact_root,
            scenario_spec.case_name,
            HOST_STORAGE_CLEANUP_ARTIFACT,
        )?;
        let host_proof = read_json::<HostStorageMutationProof>(&proof_path)?;
        let cleanup = read_json::<HostStoragePostCleanupObservation>(&cleanup_path)?;
        validate_host_storage_artifacts(
            &host_proof,
            &cleanup,
            &target_proof,
            &json_spec,
            &evidence,
        )?;
        if json_spec
            .faults
            .iter()
            .any(|fault| fault.kind == FaultKind::RustfsBlockDeviceDropWritesCrash.as_str())
        {
            let filesystem_check = read_json::<DmFilesystemCheck>(&locate_artifact(
                &options.artifact_root,
                scenario_spec.case_name,
                DM_FILESYSTEM_CHECK_ARTIFACT,
            )?)?;
            validate_dm_filesystem_check(&filesystem_check, &host_proof, &cleanup, &evidence)?;
        }
        ensure!(
            preflight_summary.phases.iter().any(|phase| {
                phase.name == "host-storage-mutation-proof"
                    && phase.status == PreflightStatus::Passed
            }),
            "preflight-summary.json lacks a passed host-storage mutation proof phase"
        );
        ensure!(
            has_event(
                &events,
                "host-storage-mutation-preflight",
                RunEventStatus::Succeeded,
            ),
            "run-events.jsonl lacks a successful host-storage mutation preflight"
        );
    }
    if fixed_volume_fault(&json_spec).is_some() {
        validate_fixed_volume_runtime_evidence(&evidence, &target_proof, &json_spec)?;
    }
    if matches!(
        options.scenario.as_str(),
        scenarios::QUORUM_P_IO_FAULT_SCENARIO | scenarios::QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
    ) {
        validate_volume_quorum_health_evidence(&evidence, &target_proof, &history)?;
    }
    if ack_mutation.is_some() {
        validate_ack_fault_window_evidence(&evidence)?;
    } else {
        validate_fault_window_evidence(&evidence)?;
    }
    if matches!(
        options.scenario.as_str(),
        DM_FLAKEY_VERSIONED_HOT_SCENARIO | scenarios::NODE_CRASH_PROXY_SCENARIO
    ) {
        validate_dm_crash_artifacts(
            &options.artifact_root,
            scenario_spec.case_name,
            &events,
            &evidence,
            &metadata.scenario,
            &metadata.run_id,
            &json_spec.metadata.bucket,
        )?;
    }
    if scenarios::holds_node_down_after_crash(&options.scenario) {
        validate_node_down_hold_artifacts(
            &artifacts,
            &metadata,
            identity,
            &events,
            &json_spec.metadata.bucket,
            workload_plan.object_count,
        )?;
    }
    validate_recovery_health_artifact(&artifacts, &metadata, identity, &evidence, &events)?;
    validate_post_recovery_write_artifacts(
        &artifacts,
        &metadata,
        identity,
        &evidence,
        &events,
        &json_spec.metadata.bucket,
        post_recovery_object_count(workload_plan.object_count),
    )?;
    if scenario_spec.backend == scenarios::FaultBackend::KubernetesLifecycle {
        validate_pod_lifecycle_artifact(
            &artifacts,
            &metadata,
            identity,
            &evidence,
            &json_spec,
            LifecycleValidationInputs {
                history: &history,
                statefulset_proof: target_proof
                    .faults
                    .iter()
                    .find_map(|fault| fault.statefulset.as_ref()),
                requires_availability: scenario_spec.impact_policy.requires_availability(),
            },
        )?;
    }

    let ack_checker_expectation = if let Some(expected_mutation) = ack_mutation {
        Some(validate_ack_triggered_dm_artifacts(
            AckArtifactValidationContext {
                root: &options.artifact_root,
                case_name: scenario_spec.case_name,
                events: &events,
                evidence: &evidence,
                history: &history,
                scenario: &metadata.scenario,
                run_id: &metadata.run_id,
                bucket: &json_spec.metadata.bucket,
                run_spec: &json_spec,
            },
            expected_mutation,
        )?)
    } else {
        None
    };

    let prechecker =
        read_json::<CheckerReport>(required(&artifacts, "checker-pre-recommit-report.json")?)?;
    validate_checker_identity("checker-pre-recommit-report.json", &prechecker, &metadata)?;
    validate_checker_report(
        "checker-pre-recommit-report.json",
        &prechecker,
        options.expected_workload_versioning,
        &history,
    )?;
    let checker = read_json::<CheckerReport>(required(&artifacts, "checker-report.json")?)?;
    validate_checker_identity("checker-report.json", &checker, &metadata)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
        &history,
    )?;
    if let Some(expectation) = &ack_checker_expectation {
        validate_ack_prechecker_boundary(
            &prechecker,
            &history,
            &expectation.trigger_operation_id,
            evidence.recovery_ended_at_ms,
        )?;
        validate_ack_checker_report("checker-pre-recommit-report.json", &prechecker, expectation)?;
        validate_ack_checker_report("checker-report.json", &checker, expectation)?;
    }

    if ack_mutation.is_some() {
        validate_ack_checker_phase_chain(
            &prechecker,
            &checker,
            &json_spec.metadata.bucket,
            &history,
        )?;
        return Ok(ArtifactValidationReport {
            scenario: options.scenario.clone(),
            case_name: scenario_spec.case_name.to_string(),
            seed: workload_plan.seed,
            client_disruptions: 0,
            recommitted: 0,
            committed: checker.committed_puts,
            required_artifacts: json_spec.artifacts.required.clone(),
        });
    }

    let recommit =
        read_json::<RecommitReportArtifact>(required(&artifacts, "recommit-report.json")?)?;
    validate_optional_identity_fields(
        "recommit-report.json",
        recommit.scenario.as_deref(),
        recommit.run_id.as_deref(),
        &metadata,
        identity,
    )?;
    ensure!(
        recommit.attempted == recommit.committed
            && recommit.failed == 0
            && recommit.harness_errors == 0
            && recommit.attempts.len() == recommit.attempted,
        "recommit-report.json must have attempted == committed, failed == 0, harness_errors == 0, and attempts length matching attempted"
    );
    let summary =
        read_json::<WorkloadSummaryArtifact>(required(&artifacts, "workload-summary.json")?)?;
    validate_optional_identity_fields(
        "workload-summary.json",
        summary.scenario.as_deref(),
        summary.run_id.as_deref(),
        &metadata,
        identity,
    )?;
    ensure!(
        summary.seed == workload_plan.seed
            && summary.object_count == workload_plan.object_count
            && summary.concurrency == workload_plan.concurrency,
        "workload-summary.json does not match workload-plan.json seed/object_count/concurrency"
    );
    ensure!(
        summary.recommitted_after_recovery == recommit.committed,
        "workload-summary.json recommitted_after_recovery does not match recommit-report.json committed"
    );
    validate_checker_phase_chain(
        &prechecker,
        &checker,
        &recommit,
        summary
            .recommit_candidates
            .as_ref()
            .context("workload-summary.json has no sealed recommit candidate manifest")?,
        &json_spec.metadata.bucket,
        &history,
    )?;
    ensure!(
        summary.exercised_all_operation_families(),
        "workload-summary.json did not exercise every required S3 operation family"
    );
    ensure!(
        summary.disrupted()? == evidence.client_disruptions,
        "fault-evidence.json client_disruptions does not match workload-summary.json"
    );
    if let Some(catalog_floor_percent) = scenario_spec.impact_policy.availability_floor_percent() {
        validate_availability_artifact(
            &artifacts,
            &metadata,
            identity,
            &evidence,
            &summary,
            workload_plan.object_count,
            catalog_floor_percent,
        )?;
    }
    if scenarios::requires_quorum_edge_read_survival(&options.scenario) {
        validate_quorum_edge_read_survival_artifact(
            &artifacts,
            &metadata,
            identity,
            &evidence,
            &json_spec.metadata.bucket,
            workload_plan.object_count,
        )?;
    }
    if requires_write_quorum_loss_history(&options.scenario) {
        let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
        let workload_started_at_ms = evidence
            .workload_started_at_ms
            .context("fault-evidence.json workload_started_at_ms is required")?;
        let fault_active_at_ms = evidence
            .fault_active_at_ms
            .context("fault-evidence.json fault_active_at_ms is required")?;
        let workload_ended_at_ms = evidence
            .workload_ended_at_ms
            .context("fault-evidence.json workload_ended_at_ms is required")?;
        if options.scenario == scenarios::QUORUM_P_IO_FAULT_SCENARIO {
            require_typed_quorum_read_survival(
                &history,
                &TypedQuorumReadExpectation {
                    scenario: &metadata.scenario,
                    run_id: &metadata.run_id,
                    bucket: &json_spec.metadata.bucket,
                    class: json_spec
                        .faults
                        .first()
                        .context("runtime quorum run-spec has no fault")?
                        .parameters
                        .quorum_case()?,
                    workload_plan: &workload_plan,
                    cohort_source: TypedQuorumReadCohortSource::ArtifactHistory,
                    fault_active_at_ms,
                    workload_started_at_ms,
                },
            )?;
        }
        if matches!(
            options.scenario.as_str(),
            scenarios::QUORUM_P_IO_FAULT_SCENARIO | scenarios::QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        ) {
            let shape = target_proof
                .faults
                .iter()
                .find_map(|fault| fault.erasure_set.as_ref())
                .and_then(|proof| proof.shape.as_ref())
                .context("volume quorum artifacts lack proven runtime geometry")?;
            let unavailable = QuorumVolumeBoundary {
                class: json_spec
                    .faults
                    .first()
                    .context("runtime quorum run-spec has no fault")?
                    .parameters
                    .quorum_case()?,
                beyond_read_tolerance: options.scenario
                    == scenarios::QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
            }
            .unavailable_mutations(shape)?;
            summary.require_typed_write_quorum_loss_effect(
                &history,
                &metadata.scenario,
                &json_spec.metadata.bucket,
                &unavailable,
                workload_started_at_ms,
                workload_ended_at_ms,
            )?;
        } else {
            summary.require_write_quorum_loss_effect(
                &history,
                &metadata.scenario,
                &json_spec.metadata.bucket,
                workload_started_at_ms,
                workload_ended_at_ms,
            )?;
        }
    }

    Ok(ArtifactValidationReport {
        scenario: options.scenario.clone(),
        case_name: scenario_spec.case_name.to_string(),
        seed: workload_plan.seed,
        client_disruptions: evidence.client_disruptions,
        recommitted: recommit.committed,
        committed: checker.committed_puts,
        required_artifacts: json_spec.artifacts.required.clone(),
    })
}

fn validate_on_disk_bitrot_artifacts(
    options: &ArtifactValidationOptions,
    identity: ArtifactIdentityPolicy<'_>,
    case_name: &str,
) -> Result<ArtifactValidationReport> {
    let artifacts =
        locate_required_artifacts(&options.artifact_root, case_name, &options.scenario)?;
    let metadata = read_json::<RunMetadataArtifact>(required(&artifacts, "run-metadata.json")?)?;
    ensure!(
        metadata.scenario == options.scenario
            && metadata.workload_objects == options.expected_workload_objects
            && metadata.workload_concurrency == options.expected_workload_concurrency,
        "bitrot run metadata does not match the selected scenario or workload"
    );
    if let Some(run_id) = identity.planned_run_id() {
        ensure!(
            metadata.run_id == run_id,
            "bitrot run metadata does not match the planned attempt"
        );
    }
    let json_spec = read_json::<FaultRunSpec>(required(&artifacts, "run-spec.json")?)?;
    let yaml_spec = read_yaml::<FaultRunSpec>(required(&artifacts, "run-spec.yaml")?)?;
    ensure!(
        json_spec == yaml_spec,
        "bitrot run spec JSON and YAML differ"
    );
    validate_run_spec(&json_spec, options)?;
    ensure!(
        json_spec.execution_kind()? == ExecutionKind::StorageRecovery
            && json_spec.metadata.run_id == metadata.run_id
            && json_spec.metadata.name == case_name,
        "bitrot run spec execution or identity does not match the attempt"
    );
    let workload = read_json::<WorkloadPlan>(required(&artifacts, "workload-plan.json")?)?;
    ensure!(
        workload.object_count == options.expected_workload_objects
            && workload.concurrency == options.expected_workload_concurrency
            && workload.seed == json_spec.workload.seed,
        "bitrot workload plan does not match run-spec"
    );
    let preflight = read_json::<PreflightSummary>(required(&artifacts, "preflight-summary.json")?)?;
    validate_preflight_summary(&preflight, options)?;
    let events = read_jsonl::<RunEvent>(required(&artifacts, "run-events.jsonl")?)?;
    ensure!(
        events
            .iter()
            .all(|event| { event.scenario == options.scenario && event.run_id == metadata.run_id })
            && has_event(&events, "run", RunEventStatus::Started)
            && has_event(&events, "run", RunEventStatus::Succeeded)
            && has_event(&events, "checker-final", RunEventStatus::Succeeded),
        "bitrot run events do not prove successful completion and final checking"
    );
    let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
    ensure!(!history.is_empty(), "bitrot history is empty");
    validate_history_scope_and_order(
        &history,
        &options.scenario,
        &metadata.run_id,
        &json_spec.metadata.bucket,
    )?;

    let selection =
        read_json::<BitrotSelectionEvidence>(required(&artifacts, BITROT_SELECTION_ARTIFACT)?)?;
    let mutation =
        read_json::<BitrotMutationEvidence>(required(&artifacts, BITROT_MUTATION_ARTIFACT)?)?;
    let corruption_window = read_json::<BitrotCorruptionWindowProof>(required(
        &artifacts,
        BITROT_CORRUPTION_WINDOW_ARTIFACT,
    )?)?;
    let heal = read_json::<BitrotHealEvidence>(required(&artifacts, BITROT_HEAL_ARTIFACT)?)?;
    let cleanup =
        read_json::<BitrotCleanupEvidence>(required(&artifacts, BITROT_CLEANUP_ARTIFACT)?)?;
    let workflow =
        read_json::<OnDiskBitrotWorkflowEvidence>(required(&artifacts, BITROT_WORKFLOW_ARTIFACT)?)?;
    let checker_path = required(&artifacts, "checker-report.json")?;
    let checker_body =
        fs::read_to_string(checker_path).context("read bitrot final checker report")?;
    let checker = serde_json::from_str::<CheckerReport>(&checker_body)
        .context("decode bitrot final checker report")?;
    validate_checker_identity("checker-report.json", &checker, &metadata)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
        &history,
    )?;
    let post_write_path = required(&artifacts, POST_RECOVERY_WRITE_REPORT_ARTIFACT)?;
    let post_write_body =
        fs::read_to_string(post_write_path).context("read bitrot post-write report")?;
    let post_write = serde_json::from_str::<PostRecoveryWriteReport>(&post_write_body)
        .context("decode bitrot post-write report")?;
    ensure!(
        post_write.scenario == options.scenario && post_write.run_id == metadata.run_id,
        "bitrot post-write report identity mismatch"
    );
    post_write.require_success()?;
    validate_on_disk_bitrot_evidence(&OnDiskBitrotEvidenceSet {
        workflow: &workflow,
        selection: &selection,
        mutation: &mutation,
        corruption_window: &corruption_window,
        heal: &heal,
        cleanup: &cleanup,
        checker_report_body: &checker_body,
        post_write_report_body: &post_write_body,
    })?;
    ensure!(
        workflow.identity.run_id == metadata.run_id
            && workflow.identity.scenario == metadata.scenario
            && workflow.identity.case_name == case_name
            && workflow.identity.bucket == json_spec.metadata.bucket,
        "bitrot workflow identity does not match run metadata and spec"
    );
    Ok(ArtifactValidationReport {
        scenario: options.scenario.clone(),
        case_name: case_name.to_string(),
        seed: workload.seed,
        client_disruptions: 0,
        recommitted: 0,
        committed: checker.committed_puts,
        required_artifacts: json_spec.artifacts.required,
    })
}

fn validate_admin_execution_artifacts(
    options: &ArtifactValidationOptions,
    identity: ArtifactIdentityPolicy<'_>,
    case_name: &str,
) -> Result<ArtifactValidationReport> {
    let artifacts =
        locate_required_artifacts(&options.artifact_root, case_name, &options.scenario)?;
    let metadata = read_json::<RunMetadataArtifact>(required(&artifacts, "run-metadata.json")?)?;
    ensure!(
        metadata.scenario == options.scenario
            && metadata.workload_objects == options.expected_workload_objects
            && metadata.workload_concurrency == options.expected_workload_concurrency,
        "admin run metadata does not match the selected scenario or workload"
    );
    if let Some(run_id) = identity.planned_run_id() {
        ensure!(
            metadata.run_id == run_id,
            "admin run metadata does not match the planned attempt"
        );
    }

    let json_spec = read_json::<FaultRunSpec>(required(&artifacts, "run-spec.json")?)?;
    let yaml_spec = read_yaml::<FaultRunSpec>(required(&artifacts, "run-spec.yaml")?)?;
    ensure!(
        json_spec == yaml_spec,
        "admin run spec JSON and YAML differ"
    );
    validate_run_spec(&json_spec, options)?;
    ensure!(
        json_spec.execution_kind()? == ExecutionKind::Admin
            && json_spec.metadata.run_id == metadata.run_id
            && json_spec.metadata.name == case_name
            && metadata.context == json_spec.cluster.context
            && metadata.namespace == json_spec.cluster.namespace
            && metadata.tenant == json_spec.cluster.tenant,
        "admin run spec execution, identity, or cluster scope does not match run metadata"
    );

    let workload = read_json::<WorkloadPlan>(required(&artifacts, "workload-plan.json")?)?;
    ensure!(
        workload.object_count == options.expected_workload_objects
            && workload.concurrency == options.expected_workload_concurrency
            && workload.seed == json_spec.workload.seed,
        "admin workload plan does not match run-spec"
    );
    let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
    ensure!(!history.is_empty(), "admin history must not be empty");
    validate_history_scope_and_order(
        &history,
        &options.scenario,
        &metadata.run_id,
        &json_spec.metadata.bucket,
    )?;

    let fixture = read_json::<AdminFixtureEvidence>(required(&artifacts, ADMIN_FIXTURE_ARTIFACT)?)?;
    fixture.validate_complete()?;
    let workflow =
        read_json::<AdminWorkflowEvidence>(required(&artifacts, ADMIN_WORKFLOW_ARTIFACT)?)?;
    workflow.validate()?;
    ensure!(
        workflow.completed
            && workflow.scenario == options.scenario
            && workflow.run_id == metadata.run_id
            && fixture.scenario == options.scenario
            && fixture.run_id == metadata.run_id,
        "admin fixture or workflow identity and completion do not match the attempt"
    );
    let proof =
        read_json::<AdminTopologyProof>(required(&artifacts, ADMIN_TOPOLOGY_PROOF_ARTIFACT)?)?;
    let operation =
        read_json::<AdminOperationEvidence>(required(&artifacts, ADMIN_OPERATION_ARTIFACT)?)?;
    proof.require_cluster_scope(
        &json_spec.cluster.context,
        &json_spec.cluster.namespace,
        &json_spec.cluster.tenant,
    )?;
    ensure!(
        fixture.tenant == json_spec.cluster.tenant,
        "admin fixture Tenant does not match the configured cluster scope"
    );
    let tenant_uid = fixture
        .observations
        .first()
        .map(|observation| observation.tenant_uid.clone())
        .context("admin fixture lacks Tenant UID")?;
    let expected_attempt = AdminAttemptIdentity {
        run_id: metadata.run_id.clone(),
        case_name: case_name.to_string(),
        tenant_uid,
    };
    ensure!(
        proof.attempt == expected_attempt
            && proof
                .tenant_pools
                .iter()
                .map(|pool| pool.name.as_str())
                .collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    fixture.plan.initial_pool_name.as_str(),
                    fixture.plan.expansion_pool_name.as_str(),
                ]),
        "admin topology proof does not match the staged fixture"
    );
    let attempt_window = AdminAttemptWindow {
        started_at_ms: fixture.observations[0].observed_at_ms,
        evaluated_at_ms: workflow
            .phases
            .last()
            .map(|phase| phase.ended_at_ms)
            .context("admin workflow lacks cleanup receipt")?,
    };
    let case_dir = required(&artifacts, ADMIN_TOPOLOGY_PROOF_ARTIFACT)?
        .parent()
        .context("admin topology proof has no case directory")?;
    validate_admin_topology_artifact_files(
        &options.scenario,
        &expected_attempt,
        attempt_window,
        case_dir,
    )?;

    let events = read_jsonl::<RunEvent>(required(&artifacts, "run-events.jsonl")?)?;
    let (recovery, baseline_event) =
        validate_recovery_health_report(&artifacts, &metadata, identity, &events)?;
    let expected_pods = proof.expected_pod_names()?;
    let readiness_pods = recovery
        .readiness
        .iter()
        .map(|probe| probe.pod_name.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        readiness_pods == expected_pods
            && recovery.readiness.len() == expected_pods.len()
            && recovery.readiness.iter().all(|probe| {
                probe.proxy_path
                    == readiness_proxy_path(&json_spec.cluster.namespace, &probe.pod_name)
                    && probe.observed_at_ms >= recovery.started_at_ms
                    && probe.observed_at_ms <= recovery.completed_at_ms
            }),
        "admin recovery-health readiness probes do not cover the exact proven Tenant Pod set"
    );
    let start_phase = workflow
        .phases
        .iter()
        .find(|phase| phase.phase == "start")
        .context("admin workflow lacks start receipt")?;
    let verify_phase = workflow
        .phases
        .iter()
        .find(|phase| phase.phase == "verify")
        .context("admin workflow lacks verify receipt")?;
    let operation_start = operation
        .requests
        .iter()
        .find(|request| request.method == "POST")
        .context("admin operation lacks its start request")?;
    ensure!(
        recovery.baseline.observed_at_ms <= baseline_event.at_ms
            && baseline_event.at_ms <= operation_start.started_at_ms
            && start_phase.started_at_ms <= operation_start.started_at_ms
            && operation_start.observed_at_ms <= start_phase.ended_at_ms,
        "admin recovery-health baseline was not recorded before the admin operation started"
    );
    let recovery_started_event = events
        .iter()
        .find(|event| event.stage == "recovery-health" && event.status == RunEventStatus::Started)
        .context("run-events.jsonl lacks a recovery-health started event")?;
    let recovery_succeeded_event = events
        .iter()
        .find(|event| event.stage == "recovery-health" && event.status == RunEventStatus::Succeeded)
        .context("run-events.jsonl lacks a successful recovery-health event")?;
    ensure!(
        verify_phase.started_at_ms <= recovery_started_event.at_ms
            && recovery_started_event.at_ms <= recovery.started_at_ms
            && recovery.completed_at_ms <= recovery_succeeded_event.at_ms
            && recovery_succeeded_event.at_ms <= verify_phase.ended_at_ms,
        "admin recovery-health report and events are outside the successful verify phase"
    );
    validate_post_recovery_write_artifacts_after(
        &artifacts,
        &metadata,
        identity,
        &events,
        &json_spec.metadata.bucket,
        post_recovery_object_count(workload.object_count),
        recovery.completed_at_ms,
        "recovery-health",
    )?;

    let prechecker =
        read_json::<CheckerReport>(required(&artifacts, "checker-pre-recommit-report.json")?)?;
    validate_checker_identity("checker-pre-recommit-report.json", &prechecker, &metadata)?;
    validate_checker_report(
        "checker-pre-recommit-report.json",
        &prechecker,
        options.expected_workload_versioning,
        &history,
    )?;
    let checker = read_json::<CheckerReport>(required(&artifacts, "checker-report.json")?)?;
    validate_checker_identity("checker-report.json", &checker, &metadata)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
        &history,
    )?;
    let recommit =
        read_json::<RecommitReportArtifact>(required(&artifacts, "recommit-report.json")?)?;
    validate_optional_identity_fields(
        "recommit-report.json",
        recommit.scenario.as_deref(),
        recommit.run_id.as_deref(),
        &metadata,
        identity,
    )?;
    ensure!(
        recommit.failed == 0
            && recommit.harness_errors == 0
            && recommit.attempted == recommit.committed
            && recommit.attempts.len() == recommit.attempted,
        "admin recommit report contains unresolved writes"
    );
    let summary =
        read_json::<WorkloadSummaryArtifact>(required(&artifacts, "workload-summary.json")?)?;
    validate_optional_identity_fields(
        "workload-summary.json",
        summary.scenario.as_deref(),
        summary.run_id.as_deref(),
        &metadata,
        identity,
    )?;
    ensure!(
        summary.seed == workload.seed
            && summary.object_count == workload.object_count
            && summary.concurrency == workload.concurrency,
        "workload-summary.json does not match workload-plan.json seed/object_count/concurrency"
    );
    ensure!(
        summary.recommitted_after_recovery == recommit.committed,
        "workload-summary.json recommitted_after_recovery does not match recommit-report.json committed"
    );
    validate_checker_phase_chain(
        &prechecker,
        &checker,
        &recommit,
        summary
            .recommit_candidates
            .as_ref()
            .context("workload-summary.json has no sealed recommit candidate manifest")?,
        &json_spec.metadata.bucket,
        &history,
    )?;
    ensure!(
        summary.exercised_all_operation_families(),
        "workload-summary.json did not exercise every required S3 operation family"
    );
    summary.require_history_matches(
        &history,
        &options.scenario,
        &json_spec.metadata.bucket,
        DurabilityCohort::FaultActive,
        &workload,
        &metadata.run_id,
    )?;
    let client_disruptions = summary.disrupted()?;
    ensure!(
        events
            .iter()
            .all(|event| { event.scenario == options.scenario && event.run_id == metadata.run_id })
            && has_event(&events, "run", RunEventStatus::Succeeded)
            && has_event(&events, "checker-final", RunEventStatus::Succeeded),
        "admin run events do not prove successful completion and final checking"
    );

    Ok(ArtifactValidationReport {
        scenario: options.scenario.clone(),
        case_name: case_name.to_string(),
        seed: workload.seed,
        client_disruptions,
        recommitted: recommit.committed,
        committed: checker.committed_puts,
        required_artifacts: json_spec.artifacts.required,
    })
}

fn validate_storage_recovery_execution_artifacts(
    options: &ArtifactValidationOptions,
    identity: ArtifactIdentityPolicy<'_>,
    case_name: &str,
) -> Result<ArtifactValidationReport> {
    let artifacts =
        locate_required_artifacts(&options.artifact_root, case_name, &options.scenario)?;
    let metadata = read_json::<RunMetadataArtifact>(required(&artifacts, "run-metadata.json")?)?;
    ensure!(
        metadata.scenario == options.scenario
            && metadata.workload_objects == options.expected_workload_objects
            && metadata.workload_concurrency == options.expected_workload_concurrency,
        "storage-recovery run metadata does not match the selected scenario or workload"
    );
    if let Some(run_id) = identity.planned_run_id() {
        ensure!(
            metadata.run_id == run_id,
            "storage-recovery run metadata does not match the planned attempt"
        );
    }

    let json_spec = read_json::<FaultRunSpec>(required(&artifacts, "run-spec.json")?)?;
    let yaml_spec = read_yaml::<FaultRunSpec>(required(&artifacts, "run-spec.yaml")?)?;
    ensure!(
        json_spec == yaml_spec,
        "storage-recovery run spec JSON and YAML differ"
    );
    validate_run_spec(&json_spec, options)?;
    let case = match json_spec.execution.as_ref() {
        Some(crate::fault::spec::FaultRunExecutionSpec::StorageRecovery { case, .. }) => *case,
        _ => bail!("fresh-volume artifacts require typed storage-recovery execution"),
    };
    ensure!(
        json_spec.metadata.run_id == metadata.run_id && json_spec.metadata.name == case_name,
        "storage-recovery run spec identity does not match the attempt"
    );

    let workload = read_json::<WorkloadPlan>(required(&artifacts, "workload-plan.json")?)?;
    ensure!(
        workload.object_count == options.expected_workload_objects
            && workload.concurrency == options.expected_workload_concurrency
            && workload.seed == json_spec.workload.seed,
        "storage-recovery workload plan does not match run-spec"
    );
    let preflight = read_json::<PreflightSummary>(required(&artifacts, "preflight-summary.json")?)?;
    validate_preflight_summary(&preflight, options)?;
    ensure!(
        preflight
            .run_id
            .as_deref()
            .is_none_or(|run_id| run_id == metadata.run_id),
        "storage-recovery preflight belongs to another attempt"
    );

    let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
    ensure!(
        !history.is_empty(),
        "storage-recovery history must not be empty"
    );
    validate_history_scope_and_order(
        &history,
        &metadata.scenario,
        &metadata.run_id,
        &json_spec.metadata.bucket,
    )?;

    let workflow = read_json::<StorageRecoveryWorkflowEvidence>(required(
        &artifacts,
        STORAGE_RECOVERY_WORKFLOW_ARTIFACT,
    )?)?;
    workflow.validate_completed_attempt(&metadata.scenario, &metadata.run_id, case)?;
    let replacement = read_json::<FreshVolumeReplacementProof>(required(
        &artifacts,
        DISK_GENERATION_PROOF_ARTIFACT,
    )?)?;
    let mappings = read_json::<Vec<VersionShardMappingObservation>>(required(
        &artifacts,
        VERSION_SHARD_MAPPING_ARTIFACT,
    )?)?;
    let progress = read_jsonl::<HealProgressSample>(required(&artifacts, HEAL_PROGRESS_ARTIFACT)?)?;
    let summary = read_json::<HealSummary>(required(&artifacts, HEAL_SUMMARY_ARTIFACT)?)?;
    let proof_history =
        read_jsonl::<OperationRecord>(required(&artifacts, FRESH_VOLUME_READ_HISTORY_ARTIFACT)?)?;
    validate_history_scope_and_order(
        &proof_history,
        &metadata.scenario,
        &metadata.run_id,
        &json_spec.metadata.bucket,
    )?;
    let read_proof = read_json::<FreshVolumeReadMatrixEvidence>(required(
        &artifacts,
        FORCE_READ_PROOF_ARTIFACT,
    )?)?;
    read_proof.validate_chain(&mappings, &replacement, &summary, &progress, &proof_history)?;
    ensure!(
        replacement.identity.run_id == metadata.run_id
            && replacement.identity.case_name == case_name
            && replacement.identity.bucket == json_spec.metadata.bucket,
        "storage-recovery proof identity does not match metadata"
    );

    let fixture = read_json::<Value>(required(&artifacts, FRESH_VOLUME_FIXTURE_ARTIFACT)?)?;
    ensure!(
        fixture.pointer("/schemaVersion").and_then(Value::as_u64) == Some(1)
            && fixture.pointer("/runId").and_then(Value::as_str) == Some(metadata.run_id.as_str())
            && fixture.pointer("/scenario").and_then(Value::as_str)
                == Some(metadata.scenario.as_str())
            && fixture
                .pointer("/replacementProof")
                .is_some_and(|value| !value.is_null())
            && fixture
                .pointer("/prepareReceipt")
                .is_some_and(|value| !value.is_null()),
        "fresh-volume fixture artifact is incomplete or belongs to another attempt"
    );
    let transcript = read_json::<Vec<HealWireReceipt>>(required(
        &artifacts,
        FRESH_VOLUME_HEAL_TRANSCRIPT_ARTIFACT,
    )?)?;
    validate_heal_transcript(&transcript, case)?;
    let cleanup = read_json::<Value>(required(&artifacts, FRESH_VOLUME_CLEANUP_ARTIFACT)?)?;
    ensure!(
        cleanup.pointer("/runId").and_then(Value::as_str) == Some(metadata.run_id.as_str())
            && cleanup
                .pointer("/tenantResourcesRemoved")
                .and_then(Value::as_bool)
                == Some(true)
            && cleanup.pointer("/error").is_none_or(Value::is_null),
        "fresh-volume cleanup does not prove successful run-owned teardown"
    );
    let recovery_health = read_json::<Value>(required(&artifacts, RECOVERY_HEALTH_ARTIFACT)?)?;
    ensure!(
        recovery_health
            .pointer("/deploymentId")
            .and_then(Value::as_str)
            .is_some_and(|deployment| !deployment.trim().is_empty())
            && recovery_health
                .pointer("/offlineDrives")
                .and_then(Value::as_u64)
                == Some(0)
            && recovery_health
                .pointer("/unknownDrives")
                .and_then(Value::as_u64)
                == Some(0)
            && recovery_health.pointer("/shape").is_some()
            && recovery_health.pointer("/membership").is_some(),
        "fresh-volume recovery health is not a fully online runtime observation"
    );

    let prechecker =
        read_json::<CheckerReport>(required(&artifacts, "checker-pre-recommit-report.json")?)?;
    validate_checker_identity("checker-pre-recommit-report.json", &prechecker, &metadata)?;
    validate_checker_report(
        "checker-pre-recommit-report.json",
        &prechecker,
        options.expected_workload_versioning,
        &history,
    )?;
    let checker = read_json::<CheckerReport>(required(&artifacts, "checker-report.json")?)?;
    validate_checker_identity("checker-report.json", &checker, &metadata)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
        &history,
    )?;
    let recommit =
        read_json::<RecommitReportArtifact>(required(&artifacts, "recommit-report.json")?)?;
    ensure!(
        recommit.failed == 0
            && recommit.harness_errors == 0
            && recommit.attempted == recommit.committed,
        "storage-recovery recommit report contains unresolved writes"
    );
    let events = read_jsonl::<RunEvent>(required(&artifacts, "run-events.jsonl")?)?;
    ensure!(
        events
            .iter()
            .all(|event| { event.scenario == options.scenario && event.run_id == metadata.run_id })
            && has_event(&events, "run", RunEventStatus::Succeeded)
            && has_event(&events, "checker-final", RunEventStatus::Succeeded),
        "storage-recovery events do not prove successful checking"
    );
    let post_write = read_json::<PostRecoveryWriteReport>(required(
        &artifacts,
        POST_RECOVERY_WRITE_REPORT_ARTIFACT,
    )?)?;
    post_write.require_success()?;
    ensure!(
        post_write.scenario == metadata.scenario
            && post_write.run_id == metadata.run_id
            && post_write.objects == post_recovery_object_count(workload.object_count),
        "storage-recovery post-write report does not match the attempt"
    );
    let expected_post_write_prefix = ObjectSpec::post_recovery_key_prefix(&metadata.run_id);
    ensure!(
        post_write.key_prefix == expected_post_write_prefix,
        "storage-recovery post-write report is outside the run-scoped prefix"
    );
    let post_write_history =
        read_jsonl::<OperationRecord>(required(&artifacts, POST_RECOVERY_WRITE_HISTORY_ARTIFACT)?)?;
    validate_history_scope_and_order(
        &post_write_history,
        &metadata.scenario,
        &metadata.run_id,
        &json_spec.metadata.bucket,
    )?;
    ensure!(
        post_write_history.iter().all(|record| {
            record
                .key
                .as_deref()
                .is_some_and(|key| key.starts_with(&expected_post_write_prefix))
                && record.started_at_ms >= post_write.started_at_ms
                && record.ended_at_ms <= post_write.completed_at_ms
        }),
        "storage-recovery post-write history escaped its run prefix or report window"
    );
    validate_write_probe_history(
        POST_RECOVERY_WRITE_PROBE,
        &post_write_history,
        &post_write,
        &metadata.run_id,
    )?;

    Ok(ArtifactValidationReport {
        scenario: options.scenario.clone(),
        case_name: case_name.to_string(),
        seed: workload.seed,
        client_disruptions: 0,
        recommitted: recommit.committed,
        committed: checker.committed_puts,
        required_artifacts: json_spec.artifacts.required,
    })
}

fn validate_stale_disk_execution_artifacts(
    options: &ArtifactValidationOptions,
    identity: ArtifactIdentityPolicy<'_>,
    case_name: &str,
) -> Result<ArtifactValidationReport> {
    let artifacts =
        locate_required_artifacts(&options.artifact_root, case_name, &options.scenario)?;
    let metadata = read_json::<RunMetadataArtifact>(required(&artifacts, "run-metadata.json")?)?;
    ensure!(
        metadata.scenario == options.scenario
            && metadata.workload_objects == options.expected_workload_objects
            && metadata.workload_concurrency == options.expected_workload_concurrency,
        "stale-disk run metadata does not match the selected scenario or workload"
    );
    if let Some(run_id) = identity.planned_run_id() {
        ensure!(
            metadata.run_id == run_id,
            "stale-disk run metadata does not match the planned attempt"
        );
    }
    let json_spec = read_json::<FaultRunSpec>(required(&artifacts, "run-spec.json")?)?;
    let yaml_spec = read_yaml::<FaultRunSpec>(required(&artifacts, "run-spec.yaml")?)?;
    ensure!(
        json_spec == yaml_spec,
        "stale-disk run spec JSON and YAML differ"
    );
    validate_run_spec(&json_spec, options)?;
    ensure!(
        matches!(
            &json_spec.execution,
            Some(crate::fault::spec::FaultRunExecutionSpec::StorageRecovery {
                case: StorageRecoveryCase::StaleDiskReturn,
                operation_timeout_seconds,
            }) if *operation_timeout_seconds > 0
        ) && json_spec.metadata.run_id == metadata.run_id
            && json_spec.metadata.name == case_name,
        "stale-disk run spec execution or identity does not match the attempt"
    );
    let workload = read_json::<WorkloadPlan>(required(&artifacts, "workload-plan.json")?)?;
    ensure!(
        workload.object_count == options.expected_workload_objects
            && workload.concurrency == options.expected_workload_concurrency
            && workload.seed == json_spec.workload.seed,
        "stale-disk workload plan does not match run-spec"
    );
    let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
    validate_history_scope_and_order(
        &history,
        &options.scenario,
        &metadata.run_id,
        &json_spec.metadata.bucket,
    )?;
    let stale =
        read_json::<StaleDiskReturnProof>(required(&artifacts, DISK_GENERATION_PROOF_ARTIFACT)?)?;
    stale.validate_against_history(&history)?;
    ensure!(
        stale.identity.run_id == metadata.run_id
            && stale.identity.case_name == case_name
            && stale.identity.bucket == json_spec.metadata.bucket,
        "disk-generation proof does not match the run identity"
    );
    let before = read_json::<ShardInventorySnapshot>(required(
        &artifacts,
        SHARD_INVENTORY_BEFORE_ARTIFACT,
    )?)?;
    let after =
        read_json::<ShardInventorySnapshot>(required(&artifacts, SHARD_INVENTORY_AFTER_ARTIFACT)?)?;
    let cleanup =
        read_json::<DanglingCleanupProof>(required(&artifacts, DANGLING_CLEANUP_PROOF_ARTIFACT)?)?;
    cleanup.validate_against_stale_return(&stale, &before, &after, &history)?;
    let host =
        read_json::<HostStorageMutationProof>(required(&artifacts, HOST_STORAGE_PROOF_ARTIFACT)?)?;
    host.validate()?;
    ensure!(
        host.scenario == options.scenario && host.run_id == metadata.run_id,
        "host-storage proof does not match the stale-disk run"
    );
    let checker = read_json::<CheckerReport>(required(&artifacts, "checker-report.json")?)?;
    validate_checker_identity("checker-report.json", &checker, &metadata)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
        &history,
    )?;
    let events = read_jsonl::<RunEvent>(required(&artifacts, "run-events.jsonl")?)?;
    ensure!(
        events
            .iter()
            .all(|event| { event.scenario == options.scenario && event.run_id == metadata.run_id })
            && has_event(&events, "run", RunEventStatus::Succeeded)
            && has_event(&events, "checker-final", RunEventStatus::Succeeded),
        "stale-disk events do not prove successful completion and final checking"
    );
    Ok(ArtifactValidationReport {
        scenario: options.scenario.clone(),
        case_name: case_name.to_string(),
        seed: workload.seed,
        client_disruptions: 0,
        recommitted: 0,
        committed: checker.committed_puts,
        required_artifacts: json_spec.artifacts.required,
    })
}

fn validate_run_spec(spec: &FaultRunSpec, options: &ArtifactValidationOptions) -> Result<()> {
    ensure!(
        spec.api_version == FAULT_RUN_API_VERSION,
        "run-spec apiVersion {:?} does not match {FAULT_RUN_API_VERSION}",
        spec.api_version
    );
    ensure!(
        spec.kind == FAULT_RUN_KIND,
        "run-spec kind {:?} does not match {FAULT_RUN_KIND}",
        spec.kind
    );
    ensure!(
        spec.scenario.name == options.scenario,
        "run-spec scenario {:?} does not match selected scenario {:?}",
        spec.scenario.name,
        options.scenario
    );
    if let Some(detector) = &spec.scenario.detector {
        detector
            .validate()
            .context("run-spec scenario detector contract is invalid")?;
    }
    let execution_kind = spec.execution_kind()?;
    let catalog = scenarios::scenario_spec(&options.scenario)?;
    if catalog.status == crate::fault::scenarios::FaultScenarioStatus::Planned {
        match execution_kind {
            ExecutionKind::Admin => ensure!(
                spec.scenario.planned_qualification && !spec.scenario.planned_storage_qualification,
                "planned admin run-spec must record only the explicit admin qualification opt-in"
            ),
            ExecutionKind::StorageRecovery => ensure!(
                spec.scenario.planned_storage_qualification && !spec.scenario.planned_qualification,
                "planned storage run-spec must record only the explicit storage qualification opt-in"
            ),
            ExecutionKind::Injection => {
                bail!("planned run-spec cannot use the injection execution route")
            }
        }
    }
    validate_run_spec_catalog_contract(spec, options)?;
    ensure!(
        spec.workload.object_count == options.expected_workload_objects,
        "run-spec workload.object_count {} does not match expected {}",
        spec.workload.object_count,
        options.expected_workload_objects
    );
    ensure!(
        spec.workload.concurrency == options.expected_workload_concurrency,
        "run-spec workload.concurrency {} does not match expected {}",
        spec.workload.concurrency,
        options.expected_workload_concurrency
    );
    ensure!(
        spec.workload.versioning == options.expected_workload_versioning,
        "run-spec workload.versioning {} does not match expected {}",
        spec.workload.versioning,
        options.expected_workload_versioning
    );
    ensure!(
        spec.recovery.expected_rustfs_pod_count == options.expected_rustfs_pod_count,
        "run-spec recovery.expected_rustfs_pod_count {} does not match expected {}",
        spec.recovery.expected_rustfs_pod_count,
        options.expected_rustfs_pod_count
    );
    ensure!(
        spec.recovery.stable_pod_window_seconds == options.expected_stable_window_seconds,
        "run-spec recovery.stable_pod_window_seconds {} does not match expected {}",
        spec.recovery.stable_pod_window_seconds,
        options.expected_stable_window_seconds
    );
    ensure!(
        spec.recovery.recovery_stability_reread_seconds
            == options.expected_recovery_stability_reread_seconds,
        "run-spec recovery.recovery_stability_reread_seconds {} does not match expected {}",
        spec.recovery.recovery_stability_reread_seconds,
        options.expected_recovery_stability_reread_seconds
    );
    ensure!(
        spec.artifacts.event_stream == "run-events.jsonl",
        "run-spec artifacts.event_stream must be run-events.jsonl"
    );
    for required in FaultRunArtifactSpec::required_names_for_scenario(&spec.scenario.name) {
        ensure!(
            spec.artifacts.required.contains(&required),
            "run-spec artifacts.required is missing {required}"
        );
    }
    let requires_host_storage_proof = spec
        .faults
        .iter()
        .any(|fault| fault.backend == "device-mapper");
    for conditional in [HOST_STORAGE_PROOF_ARTIFACT, HOST_STORAGE_CLEANUP_ARTIFACT] {
        ensure!(
            spec.artifacts
                .required
                .iter()
                .any(|name| name == conditional)
                == requires_host_storage_proof,
            "run-spec artifacts.required host-storage contract does not match its fault backends"
        );
    }
    let requires_filesystem_check = spec
        .faults
        .iter()
        .any(|fault| fault.kind == FaultKind::RustfsBlockDeviceDropWritesCrash.as_str());
    ensure!(
        spec.artifacts
            .required
            .iter()
            .any(|name| name == DM_FILESYSTEM_CHECK_ARTIFACT)
            == requires_filesystem_check,
        "run-spec artifacts.required filesystem-check contract does not match its fault kind"
    );
    if execution_kind != ExecutionKind::Injection {
        ensure!(
            spec.artifacts
                .required
                .iter()
                .all(|name| name != "target-proof.json" && name != "fault-evidence.json"),
            "non-injection run-spec must not require fabricated injection evidence"
        );
        return Ok(());
    }
    for fault in &spec.faults {
        ensure!(
            fault.fault_duration_seconds > 0,
            "run-spec fault {} has zero fault_duration_seconds",
            fault.name
        );
        ensure!(
            !fault.conflict_domain.is_empty(),
            "run-spec fault {} has empty conflict_domain",
            fault.name
        );
        ensure!(
            !fault.target_proof_requirements.is_empty(),
            "run-spec fault {} has empty target_proof_requirements",
            fault.name
        );
        ensure!(
            fault.selection.value > 0 || fault.selection.kind == "runtime-quorum",
            "run-spec fault {} has zero selection value outside a semantic runtime quorum selection",
            fault.name
        );
        ensure!(
            fault.target_proof.required && fault.target_proof.artifact == "target-proof.json",
            "run-spec fault {} must require target-proof.json",
            fault.name
        );
        validate_run_spec_target(&fault.name, &fault.target, options)?;
    }
    Ok(())
}

fn validate_run_spec_catalog_contract(
    spec: &FaultRunSpec,
    options: &ArtifactValidationOptions,
) -> Result<()> {
    let catalog = scenarios::scenario_spec(&options.scenario)?;
    ensure!(
        spec.scenario.case_name == catalog.case_name
            && spec.scenario.priority == catalog.priority.as_str()
            && spec.scenario.isolation == catalog.isolation.as_str()
            && spec.scenario.impact_policy == catalog.impact_policy.as_str()
            && spec.scenario.boundary == catalog.boundary
            && spec.scenario.validation == catalog.validation,
        "run-spec scenario contract does not match catalog scenario {:?}",
        options.scenario
    );
    let expected_ack = acknowledged_mutation_kind(&options.scenario);
    ensure!(
        spec.scenario
            .ack_trigger
            .as_ref()
            .map(|trigger| trigger.mutation)
            == expected_ack,
        "run-spec ACK trigger does not match the catalog scenario"
    );
    if let Some(trigger) = &spec.scenario.ack_trigger {
        ensure!(
            trigger.operation_timeout_ms > 0
                && (1..=MAX_ACK_TO_FAULT_MS).contains(&trigger.max_ack_to_fault_ms),
            "run-spec ACK trigger requires a positive operation timeout and max_ack_to_fault_ms between 1 and {MAX_ACK_TO_FAULT_MS}"
        );
        ensure!(
            !spec.recovery.recommit_unconfirmed_writes
                && !spec.artifacts.required.iter().any(|name| matches!(
                    name.as_str(),
                    "workload-summary.json" | "recommit-report.json"
                )),
            "ACK-triggered run-spec must disable recommit and omit mixed-workload artifacts"
        );
    }
    let execution_kind = spec.execution_kind()?;
    let (duration, percent, parameters, storage_recovery_case) = match execution_kind {
        ExecutionKind::Injection => {
            let artifact_fault = spec
                .faults
                .first()
                .context("run-spec must contain a fault before catalog validation")?;
            let percent = if artifact_fault.selection.kind == "percent" {
                u8::try_from(artifact_fault.selection.value)
                    .context("run-spec percent selection exceeds u8")?
            } else {
                1
            };
            (
                artifact_fault.fault_duration_seconds,
                percent,
                artifact_fault.parameters.clone(),
                None,
            )
        }
        ExecutionKind::Admin => {
            let operation_timeout_seconds = match &spec.execution {
                Some(crate::fault::spec::FaultRunExecutionSpec::Admin {
                    operation_timeout_seconds,
                    ..
                }) => *operation_timeout_seconds,
                _ => unreachable!("execution_kind validated the admin shape"),
            };
            (
                operation_timeout_seconds,
                1,
                FaultInjectionParameters::Default,
                None,
            )
        }
        ExecutionKind::StorageRecovery => {
            let (case, operation_timeout_seconds) = match &spec.execution {
                Some(crate::fault::spec::FaultRunExecutionSpec::StorageRecovery {
                    case,
                    operation_timeout_seconds,
                }) => (*case, *operation_timeout_seconds),
                _ => unreachable!("execution_kind validated the storage-recovery shape"),
            };
            (
                operation_timeout_seconds,
                1,
                FaultInjectionParameters::Default,
                Some(case),
            )
        }
    };
    let scenario = FaultScenario {
        name: options.scenario.clone(),
        case_name: catalog.case_name,
        duration: Duration::from_secs(duration),
        percent,
        object_count: spec.workload.object_count,
    };
    let plan = ExecutionPlan::from_scenario_with_options(
        &scenario,
        catalog,
        FaultPlanOptions {
            rustfs_volume_path: options.expected_rustfs_volume_path.clone(),
            scenario_parameters: parameters,
            storage_recovery_case,
        },
    )
    .context("rebuild canonical execution plan for artifact validation")?;
    ensure!(
        plan.kind() == execution_kind,
        "run-spec execution type does not match the catalog's canonical plan"
    );
    if let Some(crate::fault::spec::FaultRunExecutionSpec::Admin { topology, .. }) = &spec.execution
    {
        ensure!(
            plan.admin().is_some_and(|plan| &plan.topology == topology),
            "run-spec admin topology does not match the catalog's canonical plan"
        );
    }
    if let Some(crate::fault::spec::FaultRunExecutionSpec::StorageRecovery { case, .. }) =
        &spec.execution
    {
        ensure!(
            plan.storage_recovery()
                .is_some_and(|plan| plan.case == *case),
            "run-spec storage-recovery case does not match the catalog's canonical plan"
        );
    }
    let expected_mode = match plan.workload_mode() {
        FaultWorkloadMode::S3Mixed => "s3-mixed",
        FaultWorkloadMode::S3MixedWithWarp => "s3-mixed-with-warp",
        FaultWorkloadMode::AckTriggeredQuietMutation => "ack-triggered-quiet-mutation",
    };
    ensure!(
        spec.workload.mode == expected_mode,
        "run-spec workload mode {:?} does not match canonical plan {expected_mode:?}",
        spec.workload.mode
    );
    let expected_faults = plan.injection().map_or_else(Vec::new, |plan| {
        plan.faults()
            .iter()
            .enumerate()
            .map(|(index, fault)| FaultRunFaultSpec::from_fault(index, &scenario, catalog, fault))
            .collect::<Vec<_>>()
    });
    ensure!(
        spec.faults == expected_faults,
        "run-spec faults do not match the catalog's canonical fault plan: actual={:?} expected={expected_faults:?}",
        spec.faults
    );
    Ok(())
}

fn validate_preflight_summary(
    summary: &PreflightSummary,
    options: &ArtifactValidationOptions,
) -> Result<()> {
    ensure!(
        summary.schema_version == 1,
        "preflight-summary.json schema_version {} is unsupported",
        summary.schema_version
    );
    ensure!(
        summary.status == PreflightStatus::Passed,
        "preflight-summary.json status must be passed for successful artifact validation"
    );
    ensure!(
        summary
            .scenario_set
            .iter()
            .any(|scenario| scenario == &options.scenario),
        "preflight-summary.json scenario_set does not include selected scenario {:?}",
        options.scenario
    );
    ensure_nonempty(&summary.context, "preflight-summary.json context")?;
    ensure_nonempty(&summary.namespace, "preflight-summary.json namespace")?;
    ensure_nonempty(&summary.tenant, "preflight-summary.json tenant")?;
    ensure_nonempty(
        &summary.storage_class,
        "preflight-summary.json storage_class",
    )?;
    ensure!(
        summary
            .phases
            .iter()
            .any(|phase| phase.name == "target-proof" && phase.status == PreflightStatus::Passed),
        "preflight-summary.json must include passed target-proof phase"
    );
    Ok(())
}

fn validate_target_proof(
    proof: &TargetProof,
    spec: &FaultRunSpec,
    options: &ArtifactValidationOptions,
) -> Result<()> {
    ensure!(
        (1..=2).contains(&proof.schema_version),
        "target-proof.json schema_version {} is unsupported",
        proof.schema_version
    );
    ensure!(
        proof.status == TargetProofStatus::Satisfied,
        "target-proof.json status must be satisfied for successful artifact validation"
    );
    ensure!(
        proof.scenario == options.scenario,
        "target-proof.json scenario {:?} does not match selected scenario {:?}",
        proof.scenario,
        options.scenario
    );
    ensure!(
        proof.case_name == spec.scenario.case_name,
        "target-proof.json case_name {:?} does not match run-spec case {:?}",
        proof.case_name,
        spec.scenario.case_name
    );
    ensure!(
        proof.run_id == spec.metadata.run_id,
        "target-proof.json run_id {:?} does not match run-spec run_id {:?}",
        proof.run_id,
        spec.metadata.run_id
    );
    ensure!(
        proof.namespace == spec.cluster.namespace && proof.tenant == spec.cluster.tenant,
        "target-proof.json namespace/tenant does not match run-spec cluster scope"
    );
    ensure!(
        proof.faults.len() == spec.faults.len(),
        "target-proof.json faults length {} does not match run-spec faults length {}",
        proof.faults.len(),
        spec.faults.len()
    );
    ensure!(
        !proof.requirements.is_empty(),
        "target-proof.json must record target requirements"
    );
    ensure!(
        proof
            .requirements
            .iter()
            .all(|requirement| requirement.status == PreflightStatus::Passed),
        "target-proof.json includes failed target requirements"
    );
    if spec
        .faults
        .iter()
        .any(|fault| fault.erasure_set_proof_required)
    {
        ensure!(
            proof.schema_version >= 2,
            "target-proof.json schema v2 is required for erasure-set evidence"
        );
    }
    if proof.schema_version >= 2 {
        for (proof_fault, spec_fault) in proof.faults.iter().zip(&spec.faults) {
            ensure!(
                proof_fault.name == spec_fault.name
                    && proof_fault.kind == spec_fault.kind
                    && proof_fault.backend == spec_fault.backend,
                "target-proof.json fault identity does not match run-spec fault {}",
                spec_fault.name
            );
            ensure!(
                proof_fault.target_kind == spec_fault.target.kind
                    && proof_fault.volume_path == spec_fault.target.path
                    && proof_fault.conflict_domain == spec_fault.conflict_domain,
                "target-proof.json fault {} target does not match run-spec",
                spec_fault.name
            );
            ensure!(
                proof_fault.selection_kind == spec_fault.selection.kind
                    && proof_fault.selection_value == spec_fault.selection.value,
                "target-proof.json fault {} selection does not match run-spec",
                spec_fault.name
            );
            ensure!(
                proof_fault.erasure_set.is_some() == spec_fault.erasure_set_proof_required,
                "target-proof.json fault {} erasure-set evidence does not match run-spec requirements",
                spec_fault.name
            );
            let requires_pod_selector = spec_fault.target.kind != "dedicated-block-device";
            ensure!(
                proof_fault.pod_selector.is_some() == requires_pod_selector,
                "target-proof.json fault {} selector evidence does not match run-spec target",
                spec_fault.name
            );
            if let Some(selector) = &proof_fault.pod_selector {
                ensure!(
                    selector.namespace == spec.cluster.namespace
                        && selector.tenant == spec.cluster.tenant
                        && selector.selector == format!("rustfs.tenant={}", spec.cluster.tenant),
                    "target-proof.json fault {} selector scope does not match run-spec",
                    spec_fault.name
                );
            }
        }
    }
    for (proof_fault, spec_fault) in proof.faults.iter().zip(&spec.faults) {
        let lifecycle = spec_fault.backend == scenarios::FaultBackend::KubernetesLifecycle.as_str();
        ensure!(
            proof_fault.statefulset.is_some() == lifecycle,
            "target-proof.json fault {} StatefulSet evidence does not match its backend",
            spec_fault.name
        );
        let Some(statefulset) = &proof_fault.statefulset else {
            continue;
        };
        ensure!(
            !statefulset.uid.trim().is_empty()
                && !statefulset.name.trim().is_empty()
                && statefulset.namespace == spec.cluster.namespace,
            "target-proof.json fault {} StatefulSet identity is incomplete",
            spec_fault.name
        );
        ensure!(
            usize::try_from(statefulset.replicas).ok() == Some(options.expected_rustfs_pod_count)
                && statefulset.owned_pods.len() == options.expected_rustfs_pod_count,
            "target-proof.json fault {} StatefulSet replicas {} / owned Pods {} do not match the expected {} RustFS Pods",
            spec_fault.name,
            statefulset.replicas,
            statefulset.owned_pods.len(),
            options.expected_rustfs_pod_count
        );
        let owned = statefulset
            .owned_pods
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str()))
            .collect::<BTreeSet<_>>();
        let resolved = proof
            .resolved_pods
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str()))
            .collect::<BTreeSet<_>>();
        ensure!(
            owned == resolved && owned.len() == statefulset.owned_pods.len(),
            "target-proof.json fault {} StatefulSet-owned Pods do not match resolved_pods",
            spec_fault.name
        );
        ensure!(
            proof.requirements.iter().any(|requirement| {
                requirement.name == crate::fault::preflight::STATEFULSET_OWNERSHIP_REQUIREMENT
                    && requirement.status == PreflightStatus::Passed
            }),
            "target-proof.json fault {} lacks the passed StatefulSet ownership requirement",
            spec_fault.name
        );
    }
    if proof
        .faults
        .iter()
        .any(|fault| fault.pod_selector.is_some() || fault.host_target.is_some())
    {
        ensure!(
            !proof.resolved_pods.is_empty()
                && proof.faults.iter().all(|fault| {
                    fault
                        .pod_selector
                        .as_ref()
                        .is_none_or(|selector| selector.exact_pods_resolved)
                }),
            "target-proof.json runtime targets must include resolved current pods"
        );
        ensure!(
            proof
                .resolved_pods
                .iter()
                .all(|pod| pod.node.as_deref().is_some_and(|node| !node.is_empty())),
            "target-proof.json runtime targets must include target pod nodes"
        );
    }
    if proof
        .faults
        .iter()
        .any(|fault| fault.volume_path.is_some() || fault.host_target.is_some())
    {
        ensure!(
            proof.resolved_pods.iter().all(target_pod_has_bound_volume),
            "target-proof.json volume targets must include pod PVC/PV/node/device-or-path bindings"
        );
    }
    if let Some(fault) = fixed_volume_fault(spec) {
        let volume_path = fault
            .target
            .path
            .as_deref()
            .context("fixed volume path is missing")?;
        let expected_targets = if fault.selection.kind == "runtime-quorum" {
            proof
                .faults
                .iter()
                .find_map(|fault| fault.erasure_set.as_ref())
                .and_then(|proof| proof.volume_quorum.as_ref())
                .map(|proof| proof.target_count)
                .context("runtime quorum target proof is missing its resolved volume count")?
        } else {
            fault.selection.value
        };
        ensure!(
            expected_targets > 0
                && proof.resolved_pods.len() >= usize::try_from(expected_targets)?
                && proof
                    .resolved_pods
                    .iter()
                    .all(|pod| pod.ready && target_pod_has_fixed_volume(pod, volume_path)),
            "target-proof.json must prove every fixed volume selector Pod before injection"
        );
    }
    for (fault, spec_fault) in proof.faults.iter().zip(&spec.faults) {
        let Some(erasure_set) = &fault.erasure_set else {
            continue;
        };
        ensure!(
            erasure_set.required && erasure_set.resolved,
            "target-proof.json fault {} requires unresolved erasure-set evidence",
            fault.name
        );
        if proof.schema_version == 1 {
            continue;
        }
        ensure!(
            erasure_set.source.as_deref() == Some("rustfs-admin-server-info")
                && erasure_set
                    .deployment_id
                    .as_deref()
                    .is_some_and(|deployment_id| !deployment_id.trim().is_empty()),
            "target-proof.json fault {} is missing its RustFS runtime source",
            fault.name
        );
        let shape = erasure_set.shape.as_ref().with_context(|| {
            format!(
                "target-proof.json fault {} resolved erasure-set evidence without a shape",
                fault.name
            )
        })?;
        shape.validate().with_context(|| {
            format!(
                "target-proof.json fault {} has an invalid erasure-set shape",
                fault.name
            )
        })?;
        let health = erasure_set.health.with_context(|| {
            format!(
                "target-proof.json fault {} resolved erasure-set evidence without drive health",
                fault.name
            )
        })?;
        health
            .require_all_online(shape.total_shards)
            .with_context(|| {
                format!(
                    "target-proof.json fault {} runtime erasure set was not fully online",
                    fault.name
                )
            })?;
        let resolved_identities = unique_pod_identities(
            "target-proof.json resolved_pods",
            proof
                .resolved_pods
                .iter()
                .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
        )?;
        ensure!(
            erasure_set.observed_at_ms > 0 && erasure_set.observed_at_ms <= proof.generated_at_ms,
            "target-proof.json fault {} has an invalid topology observation timestamp",
            fault.name
        );
        ensure!(
            resolved_identities.len() == usize::try_from(shape.server_count)?
                && proof.resolved_pods.iter().all(|pod| pod.ready),
            "target-proof.json fault {} runtime shape requires exactly {} Ready resolved pods",
            fault.name,
            shape.server_count
        );
        let membership = erasure_set.membership.as_ref().with_context(|| {
            format!(
                "target-proof.json fault {} resolved erasure-set evidence without server/drive membership",
                fault.name
            )
        })?;
        membership.validate(shape).with_context(|| {
            format!(
                "target-proof.json fault {} has invalid server/drive membership",
                fault.name
            )
        })?;
        let resolved_pod_names = resolved_identities
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>();
        let membership_pod_names = membership
            .members
            .iter()
            .map(|member| member.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            membership_pod_names == resolved_pod_names,
            "target-proof.json fault {} server/drive membership does not match resolved_pods",
            fault.name
        );
        if spec_fault.target.kind == "rustfs-server-peer-network" {
            ensure!(
                spec_fault.selection.kind == "fixed-targets",
                "target-proof.json fault {} quorum partition requires fixed targets",
                fault.name
            );
            shape
                .require_server_partition_boundary(spec_fault.selection.value)
                .with_context(|| {
                    format!(
                        "target-proof.json fault {} does not establish the declared read/write quorum boundary",
                        fault.name
                    )
                })?;
        } else if options.scenario == scenarios::IO_EIO_SCENARIO {
            let unavailable_volumes = match spec_fault.selection.kind.as_str() {
                // For legacy volume selections, `percent` is the I/O sampling
                // rate on one selected volume, not a percentage of Pods.
                "percent" => 1,
                "fixed-targets" => spec_fault.selection.value,
                other => bail!(
                    "target-proof.json fault {} has unsupported availability selection {other:?}",
                    fault.name
                ),
            };
            shape
                .require_volume_availability_boundary(unavailable_volumes)
                .with_context(|| {
                    format!(
                        "target-proof.json fault {} does not establish a read/write availability boundary",
                        fault.name
                    )
                })?;
        } else if spec_fault.selection.kind == "runtime-quorum" {
            let volume_quorum = erasure_set.volume_quorum.as_ref().with_context(|| {
                format!(
                    "target-proof.json fault {} lacks runtime volume quorum bindings",
                    fault.name
                )
            })?;
            volume_quorum.validate(shape, membership).with_context(|| {
                format!(
                    "target-proof.json fault {} has invalid volume quorum bindings",
                    fault.name
                )
            })?;
            proof
                .validate_volume_quorum_bindings(volume_quorum)
                .with_context(|| {
                    format!(
                        "target-proof.json fault {} volume quorum candidates do not match resolvedPods",
                        fault.name
                    )
                })?;
            let class = spec_fault.parameters.quorum_case()?;
            ensure!(
                volume_quorum.boundary.class == class
                    && volume_quorum.boundary.beyond_read_tolerance
                        == (spec_fault.selection.value == 1)
                    && spec_fault.selection.value <= 1,
                "target-proof.json fault {} typed quorum boundary does not match run-spec",
                fault.name
            );
        }
    }
    Ok(())
}

fn unique_pod_identities<'a>(
    label: &str,
    identities: impl IntoIterator<Item = (&'a str, &'a str)>,
) -> Result<BTreeSet<(String, String)>> {
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut pairs = BTreeSet::new();
    let mut count = 0_usize;
    for (name, uid) in identities {
        count += 1;
        ensure!(
            !name.trim().is_empty() && !uid.trim().is_empty(),
            "{label} contains an empty Pod name or UID"
        );
        names.insert(name.to_string());
        uids.insert(uid.to_string());
        pairs.insert((name.to_string(), uid.to_string()));
    }
    ensure!(
        names.len() == count && uids.len() == count && pairs.len() == count,
        "{label} requires unique Pod names, UIDs, and identity pairs"
    );
    Ok(pairs)
}

/// Which Chaos Mesh resource removed the servers that crossed the
/// write-quorum boundary. Both kinds prove the same geometry; only the
/// resource and its runtime contract differ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuorumEdgeRuntimeKind {
    NetworkPartition,
    PodFailure,
}

impl QuorumEdgeRuntimeKind {
    fn resource_kind(self) -> &'static str {
        match self {
            Self::NetworkPartition => "networkchaos",
            Self::PodFailure => "podchaos",
        }
    }

    fn kind(self) -> &'static str {
        match self {
            Self::NetworkPartition => "NetworkChaos",
            Self::PodFailure => "PodChaos",
        }
    }
}

fn validate_write_quorum_runtime_evidence(
    evidence: &FaultEvidenceArtifact,
    proof: &TargetProof,
    spec: &FaultRunSpec,
    runtime_kind: QuorumEdgeRuntimeKind,
) -> Result<()> {
    let spec_fault = spec
        .faults
        .first()
        .context("write-quorum-loss run-spec has no fault")?;
    let erasure_set = proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .context("target-proof.json has no runtime erasure-set evidence")?;
    let shape = erasure_set
        .shape
        .as_ref()
        .context("target-proof.json runtime erasure-set evidence has no shape")?;
    let membership = erasure_set
        .membership
        .as_ref()
        .context("target-proof.json runtime erasure-set evidence has no server/drive membership")?;
    let apply_started_at_ms = evidence
        .fault_apply_started_at_ms
        .context("fault-evidence.json fault_apply_started_at_ms is required")?;
    require_fresh_runtime_observation(erasure_set.observed_at_ms, apply_started_at_ms)
        .context("target-proof.json runtime erasure-set observation was stale at fault apply")?;

    let proved_identities = unique_pod_identities(
        "target-proof.json resolved_pods",
        proof
            .resolved_pods
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    let active_identities = unique_pod_identities(
        "fault-evidence.json pods_at_fault_activation",
        evidence
            .pods_at_fault_activation
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    let workload_identities = unique_pod_identities(
        "fault-evidence.json pods_at_workload_snapshot",
        evidence
            .pods_at_workload_snapshot
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    ensure!(
        !active_identities.is_empty() && active_identities == proved_identities,
        "fault-evidence.json Pod identities at activation do not match target-proof.json"
    );
    ensure!(
        workload_identities == proved_identities,
        "fault-evidence.json Pod identities after workload do not match target-proof.json"
    );
    let candidate_pod_ids = active_identities
        .iter()
        .map(|(name, _)| format!("{}/{name}", spec.cluster.namespace))
        .collect::<BTreeSet<_>>();
    let partition_contract = NetworkPartitionEvidenceContract {
        chaos_namespace: &spec.cluster.chaos_namespace,
        target_namespace: &spec.cluster.namespace,
        tenant: &spec.cluster.tenant,
        run_id: &spec.metadata.run_id,
        scenario: &spec.scenario.name,
        expected_source_targets: spec_fault.selection.value,
        candidate_pod_ids: &candidate_pod_ids,
    };
    let pod_failure_contract = PodFailureEvidenceContract {
        chaos_namespace: &spec.cluster.chaos_namespace,
        target_namespace: &spec.cluster.namespace,
        tenant: &spec.cluster.tenant,
        run_id: &spec.metadata.run_id,
        scenario: &spec.scenario.name,
        expected_targets: spec_fault.selection.value,
        duration_seconds: spec_fault.fault_duration_seconds,
        candidate_pod_ids: &candidate_pod_ids,
    };
    let kind = runtime_kind.kind();
    let mut selected_targets = None;
    for (stage, snapshots) in [
        ("active", &evidence.active_snapshots),
        ("after-workload", &evidence.workload_snapshots),
    ] {
        ensure!(
            snapshots.len() == 1,
            "fault-evidence.json {stage} stage must contain exactly one {kind} snapshot"
        );
        let snapshot = &snapshots[0];
        ensure!(
            snapshot.get("stage").and_then(Value::as_str) == Some(stage)
                && snapshot.get("resource_kind").and_then(Value::as_str)
                    == Some(runtime_kind.resource_kind()),
            "fault-evidence.json {stage} snapshot metadata is invalid"
        );
        let resource = snapshot.get("chaos_status").with_context(|| {
            format!("fault-evidence.json {kind} snapshot has no resource object")
        })?;
        ensure!(
            snapshot.get("resource_name").and_then(Value::as_str)
                == resource.pointer("/metadata/name").and_then(Value::as_str),
            "fault-evidence.json {kind} snapshot resource name is inconsistent"
        );
        let current_targets = match runtime_kind {
            QuorumEdgeRuntimeKind::NetworkPartition => {
                validate_network_partition_snapshot(resource, &partition_contract)
            }
            QuorumEdgeRuntimeKind::PodFailure => {
                validate_pod_failure_snapshot(resource, &pod_failure_contract)
            }
        }
        .with_context(|| format!("validate {stage} {kind} runtime evidence"))?;
        if let Some(expected_targets) = &selected_targets {
            ensure!(
                expected_targets == &current_targets,
                "{kind} selected targets changed across workload snapshots"
            );
        } else {
            selected_targets = Some(current_targets);
        }
    }
    let selected_targets =
        selected_targets.with_context(|| format!("no {kind} targets observed"))?;
    let namespace_prefix = format!("{}/", spec.cluster.namespace);
    let selected_pods = selected_targets
        .iter()
        .map(|target| {
            target.strip_prefix(&namespace_prefix).with_context(|| {
                format!("{kind} selected target {target:?} is outside the run namespace")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    membership
        .require_selected_boundary(shape, selected_pods)
        .with_context(|| format!("actual {kind} targets do not cross the write-quorum boundary"))?;
    Ok(())
}

fn validate_volume_availability_topology_evidence(
    evidence: &FaultEvidenceArtifact,
    proof: &TargetProof,
) -> Result<()> {
    let erasure_set = proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .context("target-proof.json has no volume-availability erasure-set evidence")?;
    let apply_started_at_ms = evidence
        .fault_apply_started_at_ms
        .context("fault-evidence.json fault_apply_started_at_ms is required")?;
    require_fresh_runtime_observation(erasure_set.observed_at_ms, apply_started_at_ms)
        .context("volume-availability topology was stale at fault apply")?;

    let proved = unique_pod_identities(
        "target-proof.json resolved_pods",
        proof
            .resolved_pods
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    let before = unique_pod_identities(
        "fault-evidence.json pods_before",
        evidence
            .pods_before
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    ensure!(
        proved == before,
        "volume-availability topology Pods do not match fault-evidence.json pods_before"
    );
    Ok(())
}

fn validate_host_storage_artifacts(
    proof: &HostStorageMutationProof,
    cleanup: &HostStoragePostCleanupObservation,
    target_proof: &TargetProof,
    spec: &FaultRunSpec,
    evidence: &FaultEvidenceArtifact,
) -> Result<()> {
    proof
        .validate()
        .context("validate host-storage-proof.json")?;
    let host_faults = spec
        .faults
        .iter()
        .filter(|fault| fault.backend == "device-mapper")
        .collect::<Vec<_>>();
    ensure!(
        host_faults.len() == 1,
        "host-storage proof requires exactly one device-mapper fault"
    );
    let fault = host_faults[0];
    ensure!(
        proof.scenario == spec.scenario.name
            && proof.fault_name == fault.name
            && proof.fault_kind == fault.kind
            && proof.run_id == spec.metadata.run_id
            && proof.context == spec.cluster.context
            && proof.namespace == spec.cluster.namespace
            && proof.tenant == spec.cluster.tenant,
        "host-storage-proof.json identity or cluster scope does not match run-spec.json"
    );
    let target_fault = target_proof
        .faults
        .iter()
        .find(|candidate| candidate.name == fault.name)
        .context("target-proof.json lacks the device-mapper fault")?;
    let host_target = target_fault
        .host_target
        .as_ref()
        .context("target-proof.json device-mapper fault lacks a host target")?;
    ensure!(
        host_target.node == proof.target.node
            && host_target.mapper_name == proof.target.mapper_name
            && host_target.mount_path == proof.target.persistent_volume_path,
        "host-storage-proof.json target does not match target-proof.json host target"
    );
    let pod = target_proof
        .resolved_pods
        .iter()
        .find(|pod| pod.name == proof.target.pod && pod.uid == proof.target.pod_uid)
        .context("target-proof.json lacks the host-storage target Pod identity")?;
    ensure!(
        pod.node.as_deref() == Some(proof.target.node.as_str()),
        "host-storage target Pod node does not match target-proof.json"
    );
    let proven_hostname = proof
        .target
        .node_labels
        .get("kubernetes.io/hostname")
        .context("host-storage proof lacks the proven Node hostname label")?;
    ensure!(
        pod.persistent_volume_claims.iter().any(|claim| {
            claim.name == proof.target.persistent_volume_claim
                && claim.volume_name.as_deref() == Some(proof.target.persistent_volume.as_str())
                && claim.persistent_volume.as_ref().is_some_and(|pv| {
                    pv.name == proof.target.persistent_volume
                        && pv.node.as_deref() == Some(proven_hostname.as_str())
                        && pv.device_or_path.as_deref()
                            == Some(proof.target.persistent_volume_path.as_str())
                })
        }),
        "host-storage target PVC/PV/path does not match target-proof.json"
    );
    let fault_apply_started_at_ms = evidence
        .fault_apply_started_at_ms
        .context("fault-evidence.json lacks fault_apply_started_at_ms")?;
    let fault_active_at_ms = evidence
        .fault_active_at_ms
        .context("fault-evidence.json lacks fault_active_at_ms")?;
    if spec.scenario.ack_trigger.is_some() {
        let fault_prepare_started_at_ms = evidence
            .fault_prepare_started_at_ms
            .context("ACK-triggered fault-evidence.json lacks fault_prepare_started_at_ms")?;
        ensure!(
            fault_prepare_started_at_ms <= proof.generated_at_ms
                && proof.generated_at_ms <= fault_apply_started_at_ms,
            "host-storage proof was not regenerated during pre-ACK fault preparation"
        );
        proof
            .require_fresh_at(fault_apply_started_at_ms)
            .context("prepared host-storage proof was stale at ACK-triggered fault apply")?;
    } else {
        proof
            .require_generated_during_apply(fault_apply_started_at_ms, fault_active_at_ms)
            .context("host-storage proof was not freshly regenerated during fault apply")?;
    }
    proof
        .validate_post_cleanup(cleanup)
        .context("validate host-storage-post-cleanup.json")?;
    let recovery_snapshot = evidence
        .dm_recovery_snapshot
        .as_ref()
        .context("fault-evidence.json lacks dm_recovery_snapshot")?;
    let recovery_table = recovery_snapshot
        .get("table")
        .and_then(Value::as_str)
        .context("fault-evidence.json dm_recovery_snapshot lacks table")?;
    let recovery_table_sha256 = normalized_dm_table_sha256(recovery_table)
        .context("validate fault-evidence.json dm_recovery_snapshot table")?;
    ensure!(
        recovery_table_sha256 == proof.tables.recovery_table_sha256
            && recovery_table_sha256 == proof.recovery.rollback.recovery_table_sha256
            && recovery_table_sha256 == cleanup.recovery_table_sha256
            && proof.tables.recovery_table == proof.recovery.rollback.recovery_table,
        "device-mapper recovery table/hash is not cross-bound across proof, rollback, cleanup, and fault evidence"
    );
    let recovery_snapshot: DmStatusSnapshot = serde_json::from_value(recovery_snapshot.clone())
        .context("parse device-mapper recovery snapshot")?;
    recovery_snapshot.validate_proof(proof, "recovered", &proof.tables.recovery_table)?;
    let recovery_started_at_ms = evidence
        .recovery_started_at_ms
        .context("fault-evidence.json lacks recovery_started_at_ms")?;
    let recovery_ended_at_ms = evidence
        .recovery_ended_at_ms
        .context("fault-evidence.json lacks recovery_ended_at_ms")?;
    ensure!(
        cleanup.observed_at_ms >= recovery_started_at_ms
            && cleanup.observed_at_ms <= recovery_ended_at_ms
            && recovery_snapshot.observed_at_ms >= recovery_started_at_ms
            && recovery_snapshot.observed_at_ms <= recovery_ended_at_ms,
        "host-storage post-cleanup observation is outside the recorded recovery window"
    );
    let fault_delete_started = evidence
        .fault_delete_started_at_ms
        .context("missing fault delete start")?;
    if spec.scenario.ack_trigger.is_some() {
        let [snapshot] = evidence.active_snapshots.as_slice() else {
            bail!("device-mapper active evidence requires exactly one fault snapshot");
        };
        ensure!(
            evidence.workload_snapshots.is_empty(),
            "ACK-triggered device-mapper evidence cannot contain an under-fault workload snapshot"
        );
        validate_dm_fault_snapshot(
            snapshot,
            "active",
            proof,
            fault_active_at_ms,
            fault_delete_started,
        )?;
        return Ok(());
    }

    let workload_started = evidence
        .workload_started_at_ms
        .context("missing workload start")?;
    let workload_ended = evidence
        .workload_ended_at_ms
        .context("missing workload end")?;
    for (stage, snapshots, start, end) in [
        (
            "active",
            &evidence.active_snapshots,
            fault_active_at_ms,
            workload_started,
        ),
        (
            "after-workload",
            &evidence.workload_snapshots,
            workload_ended,
            fault_delete_started,
        ),
    ] {
        let [snapshot] = snapshots.as_slice() else {
            bail!("device-mapper {stage} evidence requires exactly one fault snapshot");
        };
        validate_dm_fault_snapshot(snapshot, stage, proof, start, end)?;
    }
    Ok(())
}

fn validate_dm_filesystem_check(
    check: &DmFilesystemCheck,
    proof: &HostStorageMutationProof,
    cleanup: &HostStoragePostCleanupObservation,
    evidence: &FaultEvidenceArtifact,
) -> Result<()> {
    ensure!(
        check.schema_version == DM_FILESYSTEM_CHECK_SCHEMA_VERSION,
        "unsupported {DM_FILESYSTEM_CHECK_ARTIFACT} schema version {}",
        check.schema_version
    );
    ensure!(
        check.scenario == proof.scenario
            && check.fault_name == proof.fault_name
            && check.run_id == proof.run_id
            && check.node == proof.target.node
            && check.persistent_volume == proof.target.persistent_volume
            && check.mapper_name == proof.target.mapper_name
            && check.logical_device == proof.target.logical_device
            && check.canonical_device == proof.target.canonical_device
            && check.mount_path == proof.target.persistent_volume_path
            && check.filesystem == proof.target.filesystem,
        "{DM_FILESYSTEM_CHECK_ARTIFACT} identity or storage target does not match host-storage-proof.json"
    );
    let expected_arguments = match check.filesystem.as_str() {
        "ext2" | "ext3" | "ext4" => vec![
            "-f".to_string(),
            "-n".to_string(),
            check.logical_device.clone(),
        ],
        "xfs" => vec!["-n".to_string(), check.logical_device.clone()],
        filesystem => {
            bail!("{DM_FILESYSTEM_CHECK_ARTIFACT} names unsupported filesystem {filesystem:?}")
        }
    };
    let expected_checker = if check.filesystem == "xfs" {
        "/usr/sbin/xfs_repair"
    } else {
        "/usr/sbin/e2fsck"
    };
    ensure!(
        check.checker == expected_checker && check.arguments == expected_arguments,
        "{DM_FILESYSTEM_CHECK_ARTIFACT} does not record the required read-only checker command"
    );
    let recovery_started_at_ms = evidence
        .recovery_started_at_ms
        .context("fault-evidence.json lacks recovery_started_at_ms")?;
    let recovery_ended_at_ms = evidence
        .recovery_ended_at_ms
        .context("fault-evidence.json lacks recovery_ended_at_ms")?;
    let remounted_at_ms = check.remounted_at_ms.context(format!(
        "{DM_FILESYSTEM_CHECK_ARTIFACT} lacks remountedAtMs"
    ))?;
    ensure!(
        recovery_started_at_ms <= check.started_at_ms
            && check.started_at_ms <= check.completed_at_ms
            && check.completed_at_ms <= remounted_at_ms
            && remounted_at_ms <= cleanup.observed_at_ms
            && remounted_at_ms <= recovery_ended_at_ms,
        "{DM_FILESYSTEM_CHECK_ARTIFACT} timestamps are outside the recorded recovery window"
    );
    ensure!(
        check.exit_code == Some(0)
            && check.clean
            && check.mounted_for_recovery
            && check.unmounted_for_check
            && check.remounted_after_check,
        "{DM_FILESYSTEM_CHECK_ARTIFACT} does not prove a clean offline check followed by remount"
    );
    Ok(())
}

fn validate_dm_fault_snapshot(
    snapshot: &Value,
    stage: &str,
    proof: &HostStorageMutationProof,
    start: u64,
    end: u64,
) -> Result<()> {
    ensure!(
        snapshot.get("stage").and_then(Value::as_str) == Some(stage)
            && snapshot.get("resource_kind").and_then(Value::as_str) == Some("device-mapper"),
        "device-mapper {stage} snapshot metadata is inconsistent"
    );
    let dm_snapshot: DmStatusSnapshot = serde_json::from_value(
        snapshot
            .get("dm_status")
            .context("device-mapper snapshot lacks dm_status")?
            .clone(),
    )
    .with_context(|| format!("parse {stage} device-mapper snapshot"))?;
    dm_snapshot.validate_proof(proof, stage, &proof.tables.fault_table)?;
    ensure!(
        dm_snapshot.observed_at_ms >= start && dm_snapshot.observed_at_ms <= end,
        "device-mapper {stage} observation is outside its recorded fault window"
    );
    Ok(())
}

fn fixed_volume_fault(spec: &FaultRunSpec) -> Option<&FaultRunFaultSpec> {
    let [fault] = spec.faults.as_slice() else {
        return None;
    };
    (fault.target.kind == "rustfs-volume"
        && matches!(
            fault.selection.kind.as_str(),
            "fixed-targets" | "runtime-quorum"
        )
        && matches!(
            fault.kind.as_str(),
            "rustfs_volume_io_error"
                | "rustfs_volume_latency"
                | "rustfs_volume_read_mistake"
                | "rustfs_volume_enospc"
        ))
    .then_some(fault)
}

fn validate_fixed_volume_runtime_evidence(
    evidence: &FaultEvidenceArtifact,
    proof: &TargetProof,
    spec: &FaultRunSpec,
) -> Result<()> {
    let fault = fixed_volume_fault(spec)
        .context("fixed volume runtime proof requires one fixed-target volume fault")?;
    let volume_quorum = if fault.selection.kind == "runtime-quorum" {
        let erasure_set = proof
            .faults
            .iter()
            .find_map(|fault| fault.erasure_set.as_ref())
            .context("runtime quorum target proof has no erasure-set evidence")?;
        let shape = erasure_set
            .shape
            .as_ref()
            .context("runtime quorum target proof has no erasure-set shape")?;
        let membership = erasure_set
            .membership
            .as_ref()
            .context("runtime quorum target proof has no erasure-set membership")?;
        let quorum = erasure_set
            .volume_quorum
            .as_ref()
            .context("runtime quorum target proof has no volume bindings")?;
        quorum.validate(shape, membership)?;
        proof.validate_volume_quorum_bindings(quorum)?;
        let fault_apply_started_at_ms = evidence
            .fault_apply_started_at_ms
            .context("fault-evidence.json fault_apply_started_at_ms is required")?;
        require_fresh_runtime_observation(erasure_set.observed_at_ms, fault_apply_started_at_ms)
            .context("runtime volume quorum topology was stale at fault apply")?;
        Some(quorum)
    } else {
        None
    };
    let expected_target_count = volume_quorum
        .map(|proof| proof.target_count)
        .unwrap_or(fault.selection.value);
    let injection = fixed_volume_injection_from_run_spec(fault, expected_target_count)?;
    let runtime_contract =
        crate::fault::backends::chaos_mesh::volume_fault_runtime_contract(&injection)?;
    ensure!(
        fault.io_sampling_percent == Some(runtime_contract.io_sampling_percent),
        "fixed volume run-spec io_sampling_percent does not match its canonical fault kind"
    );
    let volume_path = fault
        .target
        .path
        .as_deref()
        .context("fixed volume run-spec target has no path")?;
    let expected_count = usize::try_from(expected_target_count)?;
    let before_identities = unique_pod_identities(
        "fault-evidence.json pods_before",
        evidence
            .pods_before
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    let proof_identities = unique_pod_identities(
        "target-proof.json resolved_pods",
        proof
            .resolved_pods
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    ensure!(
        !before_identities.is_empty() && before_identities == proof_identities,
        "fault-evidence.json pods_before must exactly match target-proof.json Pod identities"
    );
    let active_identities = unique_pod_identities(
        "fault-evidence.json pods_at_fault_activation",
        evidence
            .pods_at_fault_activation
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    let workload_identities = unique_pod_identities(
        "fault-evidence.json pods_at_workload_snapshot",
        evidence
            .pods_at_workload_snapshot
            .iter()
            .map(|pod| (pod.name.as_str(), pod.uid.as_str())),
    )?;
    ensure!(
        active_identities.len() == expected_count
            && workload_identities == active_identities
            && active_identities.is_subset(&proof_identities),
        "fixed volume selected Pod identities must be exactly N unchanged identities from pods_before and target-proof.json"
    );
    let active_targets = evidence
        .fixed_volume_targets_at_fault_activation
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let workload_targets = evidence
        .fixed_volume_targets_at_workload_snapshot
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        active_targets.len() == expected_count
            && active_targets.len() == evidence.fixed_volume_targets_at_fault_activation.len(),
        "fault-evidence.json must persist exactly {} unique active fixed volume targets",
        expected_target_count
    );
    ensure!(
        workload_targets == active_targets
            && workload_targets.len() == evidence.fixed_volume_targets_at_workload_snapshot.len(),
        "fault-evidence.json fixed volume target set changed across workload snapshots"
    );

    let proved_pods = proof
        .resolved_pods
        .iter()
        .map(|pod| (format!("{}/{}", proof.namespace, pod.name), pod))
        .collect::<BTreeMap<_, _>>();
    let selected_pods = active_targets
        .iter()
        .map(|target| iochaos_record_pod_id(target))
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        selected_pods.len() == active_targets.len(),
        "fault-evidence.json contains multiple fixed volume target records for one Pod"
    );
    let active_identity_pods = active_identities
        .iter()
        .map(|(name, _)| format!("{}/{name}", spec.cluster.namespace))
        .collect::<BTreeSet<_>>();
    ensure!(
        active_identity_pods == selected_pods,
        "fault-evidence.json selected Pod identities do not match controller target names"
    );
    if let Some(quorum) = volume_quorum {
        let selected_names = active_identities
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<BTreeSet<_>>();
        let selected_drives = quorum
            .candidates
            .iter()
            .filter(|binding| selected_names.contains(binding.pod_name.as_str()))
            .map(|binding| binding.drive_uuid.as_str())
            .collect::<BTreeSet<_>>();
        let non_target_drives = quorum
            .candidates
            .iter()
            .filter(|binding| !selected_names.contains(binding.pod_name.as_str()))
            .map(|binding| binding.drive_uuid.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            selected_drives.len() == expected_count
                && selected_drives.is_disjoint(&non_target_drives)
                && selected_drives.len() + non_target_drives.len() == quorum.candidates.len(),
            "runtime quorum evidence does not prove the complete selected/non-target drive partition"
        );
    }
    let selected_pod_names = active_identities
        .iter()
        .map(|(name, _)| name.clone())
        .collect();
    let expected_containers =
        fixed_volume_container_ids(&proof.resolved_pods, &selected_pod_names)?;
    ensure!(
        evidence.fixed_volume_containers_at_fault_activation == expected_containers
            && evidence.fixed_volume_containers_at_workload_snapshot == expected_containers,
        "fixed volume RustFS container identities must remain unchanged from target proof through workload completion"
    );
    for pod_id in &selected_pods {
        let pod = proved_pods.get(pod_id).with_context(|| {
            format!("fixed volume target {pod_id:?} is absent from target-proof.json")
        })?;
        ensure!(
            pod.ready && target_pod_has_fixed_volume(pod, volume_path),
            "fixed volume target {pod_id:?} lacks Ready Pod/PVC/PV/device proof"
        );
    }

    let candidate_pod_ids = proved_pods
        .iter()
        .filter(|(_, pod)| pod.ready && target_pod_has_fixed_volume(pod, volume_path))
        .map(|(pod_id, _)| pod_id.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        candidate_pod_ids.len() == proof.resolved_pods.len(),
        "fixed volume target proof must cover every selector Pod"
    );
    for (stage, snapshots, persisted_targets) in [
        ("active", &evidence.active_snapshots, &active_targets),
        (
            "after-workload",
            &evidence.workload_snapshots,
            &workload_targets,
        ),
    ] {
        ensure!(
            snapshots.len() == 1,
            "fault-evidence.json {stage} stage must contain exactly one IOChaos snapshot"
        );
        let snapshot = &snapshots[0];
        ensure!(
            snapshot.get("stage").and_then(Value::as_str) == Some(stage)
                && snapshot.get("resource_kind").and_then(Value::as_str) == Some("iochaos"),
            "fault-evidence.json {stage} fixed volume snapshot metadata is invalid"
        );
        let resource = snapshot
            .get("chaos_status")
            .context("fault-evidence.json fixed volume snapshot has no IOChaos object")?;
        ensure!(
            snapshot.get("resource_name").and_then(Value::as_str)
                == resource.pointer("/metadata/name").and_then(Value::as_str),
            "fault-evidence.json fixed volume snapshot resource name is inconsistent"
        );
        let snapshot_targets = validate_fixed_volume_snapshot(
            resource,
            &VolumeTargetEvidenceContract {
                chaos_namespace: &spec.cluster.chaos_namespace,
                target_namespace: &spec.cluster.namespace,
                tenant: &spec.cluster.tenant,
                run_id: &spec.metadata.run_id,
                scenario: &spec.scenario.name,
                volume_path,
                expected_targets: expected_target_count,
                candidate_pod_ids: &candidate_pod_ids,
                runtime: &runtime_contract,
            },
        )
        .with_context(|| format!("validate {stage} IOChaos runtime evidence"))?;
        ensure!(
            &snapshot_targets == persisted_targets,
            "fault-evidence.json persisted fixed volume targets do not match the {stage} IOChaos snapshot"
        );
    }
    Ok(())
}

fn validate_volume_quorum_health_evidence(
    evidence: &FaultEvidenceArtifact,
    proof: &TargetProof,
    history: &[OperationRecord],
) -> Result<()> {
    let erasure_set = proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .context("runtime quorum target proof has no erasure-set evidence")?;
    let deployment_id = erasure_set
        .deployment_id
        .as_deref()
        .context("runtime quorum target proof has no deployment identity")?;
    let shape = erasure_set
        .shape
        .as_ref()
        .context("runtime quorum target proof has no erasure-set shape")?;
    let membership = erasure_set
        .membership
        .as_ref()
        .context("runtime quorum target proof has no erasure-set membership")?;
    let target = erasure_set
        .volume_quorum
        .as_ref()
        .context("runtime quorum target proof has no volume bindings")?;
    let selected_at_activation = evidence
        .pods_at_fault_activation
        .iter()
        .map(|pod| pod.name.clone())
        .collect::<BTreeSet<_>>();
    let selected_after_workload = evidence
        .pods_at_workload_snapshot
        .iter()
        .map(|pod| pod.name.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        selected_at_activation.len() == evidence.pods_at_fault_activation.len()
            && selected_after_workload.len() == evidence.pods_at_workload_snapshot.len()
            && selected_at_activation == selected_after_workload,
        "volume quorum selected Pod names changed across health guard boundaries"
    );

    let before = evidence
        .quorum_health_before_workload
        .as_ref()
        .context("fault-evidence.json lacks the pre-workload quorum health observation")?;
    let after = evidence
        .quorum_health_after_workload
        .as_ref()
        .context("fault-evidence.json lacks the post-workload quorum health observation")?;
    before.validate(
        deployment_id,
        shape,
        membership,
        target,
        &selected_at_activation,
    )?;
    after.validate(
        deployment_id,
        shape,
        membership,
        target,
        &selected_after_workload,
    )?;

    let fault_active_at_ms = evidence
        .fault_active_at_ms
        .context("fault-evidence.json fault_active_at_ms is required")?;
    let workload_started_at_ms = evidence
        .workload_started_at_ms
        .context("fault-evidence.json workload_started_at_ms is required")?;
    let workload_ended_at_ms = evidence
        .workload_ended_at_ms
        .context("fault-evidence.json workload_ended_at_ms is required")?;
    let fault_delete_started_at_ms = evidence
        .fault_delete_started_at_ms
        .context("fault-evidence.json fault_delete_started_at_ms is required")?;
    let first_fault_active_operation_at_ms = history
        .iter()
        .filter(|record| {
            record.durability_cohort == Some(DurabilityCohort::FaultActive)
                && record.started_at_ms >= fault_active_at_ms
        })
        .map(|record| record.started_at_ms)
        .min()
        .unwrap_or(workload_started_at_ms);
    before.require_within(
        fault_active_at_ms,
        workload_started_at_ms.min(first_fault_active_operation_at_ms),
    )?;
    after.require_within(workload_ended_at_ms, fault_delete_started_at_ms)?;
    ensure!(
        before.completed_at_ms <= after.started_at_ms,
        "volume quorum health observations are not in pre/post workload order"
    );
    Ok(())
}

fn fixed_volume_injection_from_run_spec(
    fault: &FaultRunFaultSpec,
    expected_target_count: u32,
) -> Result<FaultInjection> {
    let kind = match fault.kind.as_str() {
        "rustfs_volume_io_error" => FaultKind::RustfsVolumeIoError,
        "rustfs_volume_latency" => FaultKind::RustfsVolumeLatency,
        "rustfs_volume_read_mistake" => FaultKind::RustfsVolumeReadMistake,
        "rustfs_volume_enospc" => FaultKind::RustfsVolumeEnospc,
        other => bail!("unsupported fixed volume fault kind {other:?}"),
    };
    let volume_path = fault
        .target
        .path
        .clone()
        .context("fixed volume run-spec target has no path")?;
    FaultInjection::new_with_parameters(
        kind,
        crate::fault::scenarios::FaultBackend::ChaosMeshIoChaos,
        FaultTarget::RustfsVolume { path: volume_path },
        FaultSelection::FixedTargets(expected_target_count),
        Duration::from_secs(fault.fault_duration_seconds),
        fault.parameters.clone(),
    )
}

fn validate_run_spec_target(
    fault_name: &str,
    target: &FaultRunTargetSpec,
    options: &ArtifactValidationOptions,
) -> Result<()> {
    if target.kind == "rustfs-volume" {
        ensure!(
            target.path.as_deref() == Some(options.expected_rustfs_volume_path.as_str()),
            "run-spec fault {fault_name} rustfs-volume path {:?} does not match expected {:?}",
            target.path,
            options.expected_rustfs_volume_path
        );
    } else {
        ensure!(
            target.path.is_none(),
            "run-spec fault {fault_name} non-volume target must not set path"
        );
    }
    Ok(())
}

fn validate_checker_report(
    name: &str,
    report: &CheckerReport,
    expected_versioning: bool,
    history: &[OperationRecord],
) -> Result<()> {
    report
        .require_success()
        .with_context(|| format!("{name} did not pass"))?;
    ensure!(
        report.versioning_expected == expected_versioning,
        "{name} versioning_expected {} does not match expected {}",
        report.versioning_expected,
        expected_versioning
    );
    ensure!(
        !report.operation_cohorts.is_empty(),
        "{name} must include operation_cohorts derived from history.jsonl"
    );
    checker::validate_checker_audit_against_history(report, history)
        .with_context(|| format!("{name} audit does not match history.jsonl"))?;
    if name == "checker-report.json" {
        let audit = report
            .audit
            .as_ref()
            .context("checker-report.json has no history-bound audit")?;
        ensure!(
            audit.history_prefix_record_count + audit.history_suffix_record_count == history.len(),
            "checker-report.json audit does not cover the terminal history.jsonl record"
        );
    }
    Ok(())
}

type RecommitIdentity = (String, usize, String);

fn derive_recommit_candidates(
    history_prefix: &[OperationRecord],
) -> Result<HashMap<RecommitIdentity, String>> {
    let mut latest_mutations = HashMap::<&str, (u64, &OperationRecord)>::new();
    for record in history_prefix.iter().filter(|record| {
        matches!(
            record.kind,
            OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
        )
    }) {
        let key = record
            .key
            .as_deref()
            .context("authenticated mutation history contains an operation without a key")?;
        let sequence = record
            .started_sequence
            .context("authenticated mutation history contains an operation without a sequence")?;
        latest_mutations
            .entry(key)
            .and_modify(|latest| {
                if sequence > latest.0 {
                    *latest = (sequence, record);
                }
            })
            .or_insert((sequence, record));
    }

    let mut candidates = HashMap::with_capacity(latest_mutations.len());
    for (_, source) in latest_mutations.into_values() {
        if !matches!(
            source.kind,
            OperationKind::Put | OperationKind::CompleteMultipartUpload
        ) || source.outcome == OperationOutcome::Ok
        {
            continue;
        }
        let identity = (
            source.key.clone().context("recommit source has no key")?,
            source.size_bytes.context("recommit source has no size")?,
            source
                .value_sha256
                .clone()
                .context("recommit source has no body digest")?,
        );
        ensure!(
            candidates.insert(identity, source.id.clone()).is_none(),
            "authenticated history produced duplicate recommit candidate identities"
        );
    }
    Ok(candidates)
}

fn validate_checker_phase_chain(
    prechecker: &CheckerReport,
    checker: &CheckerReport,
    recommit: &RecommitReportArtifact,
    manifest: &RecommitCandidateManifestArtifact,
    expected_bucket: &str,
    history: &[OperationRecord],
) -> Result<()> {
    let pre_audit = prechecker
        .audit
        .as_ref()
        .context("checker-pre-recommit-report.json has no history-bound audit")?;
    let final_audit = checker
        .audit
        .as_ref()
        .context("checker-report.json has no history-bound audit")?;
    let pre_end = pre_audit
        .history_prefix_record_count
        .checked_add(pre_audit.history_suffix_record_count)
        .context("pre-recommit checker audit history bounds overflow")?;
    validate_history_scope_and_order(
        history,
        &prechecker.scenario,
        &prechecker.run_id,
        expected_bucket,
    )?;
    ensure!(
        pre_audit.history_suffix_record_count > 0 && final_audit.history_suffix_record_count > 0,
        "checker phase audits must each contain independently captured operations"
    );
    ensure!(
        pre_audit.bucket == expected_bucket
            && final_audit.bucket == expected_bucket
            && manifest.bucket == expected_bucket
            && manifest.scenario == prechecker.scenario
            && manifest.run_id == prechecker.run_id
            && checker.scenario == prechecker.scenario
            && checker.run_id == prechecker.run_id,
        "checker phases and recommit candidate manifest do not match the run target identity"
    );
    ensure!(
        manifest.history_record_count == pre_audit.history_prefix_record_count
            && manifest.history_sha256 == pre_audit.history_prefix_sha256,
        "recommit candidate manifest is not bound to the authenticated pre-recommit history"
    );
    ensure!(
        pre_end <= final_audit.history_prefix_record_count
            && pre_audit.completed_at_ms <= final_audit.started_at_ms,
        "checker phase audits overlap or are out of order"
    );

    let recommit_record_count = recommit
        .attempted
        .checked_mul(2)
        .context("recommit history record count overflow")?;
    let recommit_end = pre_end
        .checked_add(recommit_record_count)
        .context("recommit history bounds overflow")?;
    ensure!(
        recommit_end == final_audit.history_prefix_record_count,
        "history between checker phases must contain exactly one PUT and verification GET per recommit attempt"
    );
    let recommit_history = history
        .get(pre_end..recommit_end)
        .context("checker phase history bounds exceed history.jsonl")?;
    let pre_prefix = history
        .get(..pre_audit.history_prefix_record_count)
        .context("pre-recommit checker prefix exceeds history.jsonl")?;
    let pre_suffix = history
        .get(pre_audit.history_prefix_record_count..pre_end)
        .context("pre-recommit checker suffix exceeds history.jsonl")?;
    let final_suffix_end = final_audit
        .history_prefix_record_count
        .checked_add(final_audit.history_suffix_record_count)
        .context("final checker audit history bounds overflow")?;
    let final_prefix = history
        .get(..final_audit.history_prefix_record_count)
        .context("final checker prefix exceeds history.jsonl")?;
    let final_suffix = history
        .get(final_audit.history_prefix_record_count..final_suffix_end)
        .context("final checker suffix exceeds history.jsonl")?;
    ensure!(
        final_suffix_end == history.len(),
        "final checker audit does not cover terminal history.jsonl"
    );
    validate_history_phase_boundary(pre_prefix, pre_suffix, "workload/prechecker")?;
    validate_history_phase_boundary(&history[..pre_end], recommit_history, "prechecker/recommit")?;
    validate_history_phase_boundary(final_prefix, final_suffix, "recommit/final-checker")?;

    let mut records_by_id = HashMap::with_capacity(manifest.history_record_count);
    for record in &history[..manifest.history_record_count] {
        records_by_id.insert(record.id.as_str(), record);
    }
    let derived_candidates = derive_recommit_candidates(&history[..manifest.history_record_count])?;

    let mut expected = HashMap::<RecommitIdentity, String>::new();
    for candidate in &manifest.candidates {
        ensure!(
            expected
                .insert(
                    (
                        candidate.key.clone(),
                        candidate.size_bytes,
                        candidate.sha256.clone(),
                    ),
                    candidate.source_operation_id.clone(),
                )
                .is_none(),
            "recommit candidate manifest contains a duplicate object identity"
        );
        let source = records_by_id
            .get(candidate.source_operation_id.as_str())
            .copied()
            .with_context(|| {
                format!(
                    "recommit candidate {} source operation is absent from its authenticated history",
                    candidate.key
                )
            })?;
        ensure!(
            matches!(
                source.kind,
                OperationKind::Put | OperationKind::CompleteMultipartUpload
            ) && source.outcome != OperationOutcome::Ok
                && source.bucket == expected_bucket
                && source.key.as_deref() == Some(candidate.key.as_str())
                && source.value_sha256.as_deref() == Some(candidate.sha256.as_str())
                && source.size_bytes == Some(candidate.size_bytes),
            "recommit candidate {} does not match its authenticated source operation",
            candidate.key
        );
    }
    ensure!(
        expected == derived_candidates,
        "recommit candidate manifest does not match the final unconfirmed mutations in authenticated history"
    );
    ensure!(
        manifest.candidates.len() == recommit.attempted,
        "recommit candidate manifest count does not match recommit-report.json"
    );
    let mut attempts = HashMap::<RecommitIdentity, &RecommitAttemptArtifact>::new();
    for attempt in &recommit.attempts {
        ensure!(
            attempt.outcome == Some(OperationOutcome::Ok)
                && attempt.verify_get_outcome == Some(OperationOutcome::Ok)
                && attempt.http_status == Some(200)
                && attempt.error.is_none()
                && attempt.harness_error.is_none(),
            "recommit-report.json contains an unsuccessful attempt"
        );
        let identity = (
            attempt.key.clone(),
            attempt.size_bytes,
            attempt.sha256.clone(),
        );
        ensure!(
            expected.get(&identity) == Some(&attempt.source_operation_id)
                && attempts.insert(identity, attempt).is_none(),
            "recommit-report.json attempt does not match its sealed candidate manifest"
        );
    }

    let mut put_by_key = BTreeMap::<String, (&OperationRecord, RecommitIdentity)>::new();
    let mut get_by_key = BTreeMap::<String, (&OperationRecord, RecommitIdentity)>::new();
    for record in recommit_history {
        ensure!(
            record.started_at_ms <= record.ended_at_ms
                && record.started_at_ms >= pre_audit.completed_at_ms
                && record.ended_at_ms <= final_audit.started_at_ms,
            "recommit history is outside the authenticated checker phase interval"
        );
        let started_sequence = record
            .started_sequence
            .context("recommit history operation has no started sequence")?;
        let ended_sequence = record
            .ended_sequence
            .context("recommit history operation has no ended sequence")?;
        ensure!(
            started_sequence < ended_sequence
                && record.bucket == expected_bucket
                && record.outcome == OperationOutcome::Ok
                && record.http_status == Some(200)
                && record.error.is_none(),
            "recommit history contains an unsuccessful operation"
        );
        let identity = (
            record
                .key
                .clone()
                .context("recommit history operation has no key")?,
            record
                .size_bytes
                .context("recommit history operation has no size")?,
            record
                .value_sha256
                .clone()
                .context("recommit history operation has no body digest")?,
        );
        let key = identity.0.clone();
        match record.kind {
            OperationKind::Put => ensure!(
                put_by_key.insert(key, (record, identity)).is_none(),
                "recommit history contains duplicate PUTs for one candidate key"
            ),
            OperationKind::Get if record.version_id.is_none() && record.range.is_none() => {
                ensure!(
                    get_by_key.insert(key, (record, identity)).is_none(),
                    "recommit history contains duplicate verification GETs for one candidate key"
                );
            }
            _ => bail!(
                "history between checker phases contains a non-recommit operation {}",
                record.id
            ),
        }
    }
    ensure!(
        put_by_key.len() == expected.len() && get_by_key.len() == expected.len(),
        "recommit history operation count does not match the sealed candidate manifest"
    );
    for identity in expected.keys() {
        let (put, put_identity) = put_by_key
            .get(&identity.0)
            .context("recommit history is missing a candidate PUT")?;
        let (get, get_identity) = get_by_key
            .get(&identity.0)
            .context("recommit history is missing a candidate verification GET")?;
        ensure!(
            put_identity == identity
                && get_identity == identity
                && put
                    .ended_sequence
                    .zip(get.started_sequence)
                    .is_some_and(|(put_ended, get_started)| put_ended < get_started),
            "recommit PUT/GET identity or happens-before order does not match the sealed candidate manifest"
        );
    }
    ensure!(
        attempts.len() == expected.len(),
        "recommit-report.json attempts do not match the authenticated PUT/GET history between checker phases"
    );
    Ok(())
}

fn validate_checker_identity(
    name: &str,
    report: &CheckerReport,
    metadata: &RunMetadataArtifact,
) -> Result<()> {
    ensure!(
        report.scenario == metadata.scenario && report.run_id == metadata.run_id,
        "{name} identity does not match run-metadata.json"
    );
    Ok(())
}

fn validate_optional_artifact_identity(
    name: &str,
    artifact: &ArtifactIdentity,
    metadata: &RunMetadataArtifact,
    policy: ArtifactIdentityPolicy<'_>,
) -> Result<()> {
    validate_optional_identity_fields(
        name,
        artifact.scenario.as_deref(),
        artifact.run_id.as_deref(),
        metadata,
        policy,
    )
}

fn validate_optional_identity_fields(
    name: &str,
    scenario: Option<&str>,
    run_id: Option<&str>,
    metadata: &RunMetadataArtifact,
    policy: ArtifactIdentityPolicy<'_>,
) -> Result<()> {
    if matches!(policy, ArtifactIdentityPolicy::PlannedAttempt(_)) {
        ensure!(
            scenario == Some(metadata.scenario.as_str())
                && run_id == Some(metadata.run_id.as_str()),
            "{name} identity is missing or does not match the planned attempt"
        );
    } else {
        if let Some(scenario) = scenario {
            ensure!(
                scenario == metadata.scenario,
                "{name} scenario does not match run-metadata.json"
            );
        }
        if let Some(run_id) = run_id {
            ensure!(
                run_id == metadata.run_id,
                "{name} run_id does not match run-metadata.json"
            );
        }
    }
    Ok(())
}

fn validate_recovery_health_artifact(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    evidence: &FaultEvidenceArtifact,
    events: &[RunEvent],
) -> Result<()> {
    let (report, baseline_event) =
        validate_recovery_health_report(artifacts, metadata, identity, events)?;
    ensure!(
        report.baseline.observed_at_ms <= baseline_event.at_ms
            && evidence
                .fault_apply_started_at_ms
                .is_some_and(|apply_started| baseline_event.at_ms <= apply_started),
        "recovery-health-baseline event was not recorded between the baseline observation and fault activation"
    );
    let recovery_started = evidence
        .recovery_started_at_ms
        .context("fault-evidence.json recovery_started_at_ms is required")?;
    let recovery_ended = evidence
        .recovery_ended_at_ms
        .context("fault-evidence.json recovery_ended_at_ms is required")?;
    report.require_within_recovery_window(recovery_started, recovery_ended)?;
    ensure!(
        report.readiness.len() == evidence.pods_after.len()
            && evidence.pods_after.iter().all(|pod| {
                report
                    .readiness
                    .iter()
                    .any(|probe| probe.pod_name == pod.name && probe.ready)
            }),
        "{RECOVERY_HEALTH_ARTIFACT} readiness probes do not cover every Pod in fault-evidence.json pods_after"
    );
    Ok(())
}

fn validate_recovery_health_report<'a>(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    events: &'a [RunEvent],
) -> Result<(RecoveryHealthReport, &'a RunEvent)> {
    let report = read_json::<RecoveryHealthReport>(required(artifacts, RECOVERY_HEALTH_ARTIFACT)?)?;
    validate_optional_identity_fields(
        RECOVERY_HEALTH_ARTIFACT,
        Some(report.scenario.as_str()),
        Some(report.run_id.as_str()),
        metadata,
        identity,
    )?;
    // `require_success` re-validates the embedded baseline's geometry and
    // identity invariants; binding it to the pre-fault event proves the
    // report compares against the layout the runner actually captured.
    report
        .require_success()
        .with_context(|| format!("{RECOVERY_HEALTH_ARTIFACT} did not pass"))?;
    let baseline_event = events
        .iter()
        .find(|event| {
            event.stage == "recovery-health-baseline" && event.status == RunEventStatus::Succeeded
        })
        .context("run-events.jsonl lacks a successful recovery-health-baseline event")?;
    let recorded_baseline = baseline_event
        .details
        .clone()
        .map(serde_json::from_value::<RecoveryHealthBaseline>)
        .transpose()
        .context("recovery-health-baseline event details are not a baseline")?
        .context("recovery-health-baseline event carries no baseline")?;
    ensure!(
        recorded_baseline == report.baseline,
        "{RECOVERY_HEALTH_ARTIFACT} baseline does not match the recovery-health-baseline run event"
    );
    Ok((report, baseline_event))
}

fn validate_post_recovery_write_artifacts(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    evidence: &FaultEvidenceArtifact,
    events: &[RunEvent],
    expected_bucket: &str,
    expected_objects: usize,
) -> Result<()> {
    let recovery_ended = evidence
        .recovery_ended_at_ms
        .context("fault-evidence.json recovery_ended_at_ms is required")?;
    validate_post_recovery_write_artifacts_after(
        artifacts,
        metadata,
        identity,
        events,
        expected_bucket,
        expected_objects,
        recovery_ended,
        "recovery-evidence",
    )
}

/// The artifacts and run-event stage one fresh-write probe owns. The same
/// strict history reconstruction applies wherever the probe runs.
#[derive(Debug, Clone, Copy)]
struct WriteProbeEvidence {
    scope: WriteProbeScope,
    report_artifact: &'static str,
    history_artifact: &'static str,
    event_stage: &'static str,
    /// Operator-facing probe name and the boundary it must follow.
    label: &'static str,
    starts_after: &'static str,
    boundary_name: &'static str,
    prefix_name: &'static str,
}

const POST_RECOVERY_WRITE_PROBE: WriteProbeEvidence = WriteProbeEvidence {
    scope: WriteProbeScope::PostRecovery,
    report_artifact: POST_RECOVERY_WRITE_REPORT_ARTIFACT,
    history_artifact: POST_RECOVERY_WRITE_HISTORY_ARTIFACT,
    event_stage: "post-recovery-write",
    label: "post-recovery write",
    starts_after: "recovery ended",
    boundary_name: "recovery boundary",
    prefix_name: "post-recovery",
};

const NODE_DOWN_WRITE_PROBE: WriteProbeEvidence = WriteProbeEvidence {
    scope: WriteProbeScope::NodeDown,
    report_artifact: NODE_DOWN_WRITE_REPORT_ARTIFACT,
    history_artifact: NODE_DOWN_WRITE_HISTORY_ARTIFACT,
    event_stage: "node-down-write",
    label: "node-down write",
    starts_after: "the node-down hold began",
    boundary_name: "crash boundary",
    prefix_name: "node-down",
};

#[allow(clippy::too_many_arguments)]
fn validate_post_recovery_write_artifacts_after(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    events: &[RunEvent],
    expected_bucket: &str,
    expected_objects: usize,
    recovery_completed_at_ms: u64,
    recovery_boundary_stage: &str,
) -> Result<()> {
    validate_write_probe_artifacts_after(
        POST_RECOVERY_WRITE_PROBE,
        artifacts,
        metadata,
        identity,
        events,
        expected_bucket,
        expected_objects,
        recovery_completed_at_ms,
        recovery_boundary_stage,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_write_probe_artifacts_after(
    probe: WriteProbeEvidence,
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    events: &[RunEvent],
    expected_bucket: &str,
    expected_objects: usize,
    boundary_at_ms: u64,
    boundary_stage: &str,
) -> Result<()> {
    let WriteProbeEvidence {
        report_artifact,
        history_artifact,
        event_stage,
        label,
        starts_after,
        boundary_name,
        prefix_name,
        ..
    } = probe;
    let report = read_json::<PostRecoveryWriteReport>(required(artifacts, report_artifact)?)?;
    validate_optional_identity_fields(
        report_artifact,
        Some(report.scenario.as_str()),
        Some(report.run_id.as_str()),
        metadata,
        identity,
    )?;
    ensure!(
        report.objects == expected_objects,
        "{report_artifact} probed {} objects but the workload plan sizes the probe at {expected_objects}",
        report.objects
    );
    report
        .require_success()
        .with_context(|| format!("{report_artifact} did not pass"))?;
    ensure!(
        report.started_at_ms >= boundary_at_ms,
        "{report_artifact} started before {starts_after}"
    );
    // The lifecycle evidence must have been persisted before the write gate
    // could fail the run; the runner records both as ordered events.
    let boundary = events
        .iter()
        .position(|event| {
            event.stage == boundary_stage && event.status == RunEventStatus::Succeeded
        })
        .with_context(|| format!("run-events.jsonl lacks a successful {boundary_stage} event"))?;
    let probe_started = events
        .iter()
        .position(|event| event.stage == event_stage && event.status == RunEventStatus::Started)
        .with_context(|| format!("run-events.jsonl lacks a {event_stage} started event"))?;
    let probe_succeeded = events
        .iter()
        .enumerate()
        .skip(probe_started + 1)
        .find_map(|(index, event)| {
            (event.stage == event_stage && event.status == RunEventStatus::Succeeded)
                .then_some(index)
        })
        .with_context(|| format!("run-events.jsonl lacks a successful {event_stage} event"))?;
    ensure!(
        boundary < probe_started,
        "{}",
        if boundary_stage == "recovery-evidence" {
            "run-events.jsonl shows the post-recovery write probe started before fault-evidence.json was persisted".to_string()
        } else {
            format!("run-events.jsonl shows the {label} probe started before the {boundary_name}")
        }
    );
    ensure!(
        events[probe_started].at_ms <= report.started_at_ms
            && report.completed_at_ms <= events[probe_succeeded].at_ms
            && events.iter().all(|event| {
                event.stage != event_stage || event.status != RunEventStatus::Failed
            }),
        "run-events.jsonl does not prove one successful {label} probe around its report interval"
    );
    let expected_prefix = probe.scope.key_prefix(&metadata.run_id);
    ensure!(
        report.key_prefix == expected_prefix,
        "{report_artifact} key_prefix {:?} is not the run-scoped {prefix_name} prefix",
        report.key_prefix
    );
    let history = read_jsonl::<OperationRecord>(required(artifacts, history_artifact)?)?;
    ensure!(
        !history.is_empty(),
        "{history_artifact} must contain operation records"
    );
    validate_history_scope_and_order(
        &history,
        &metadata.scenario,
        &metadata.run_id,
        expected_bucket,
    )?;
    for record in &history {
        ensure!(
            record
                .key
                .as_deref()
                .is_some_and(|key| key.starts_with(&expected_prefix)),
            "{history_artifact} record {} touched a key outside the {prefix_name} prefix",
            record.id
        );
        ensure!(
            record.started_at_ms >= report.started_at_ms
                && record.ended_at_ms <= report.completed_at_ms,
            "{history_artifact} record {} lies outside the probe window",
            record.id
        );
    }
    validate_write_probe_history(probe, &history, &report, &metadata.run_id)
}

/// Every counter the probe report claims must be evidenced by its dedicated
/// history, in the order the probe issues its requests: each plain object a
/// PUT ok, a hash- and size-matching GET, a DELETE ok, then a GET 404; the
/// multipart key its completion, matching GET, DELETE, and 404; the abort
/// key its abort; and exactly two prefix LISTs, the first returning every
/// live probe key after the writes and before any DELETE, the second empty
/// after the last DELETE. Records outside that shape are not tolerated.
fn validate_write_probe_history(
    probe: WriteProbeEvidence,
    history: &[OperationRecord],
    report: &PostRecoveryWriteReport,
    run_id: &str,
) -> Result<()> {
    let artifact = probe.history_artifact;
    let scope = probe.scope;
    let prefix = scope.key_prefix(run_id);
    let plain_keys = (0..report.objects)
        .map(|index| scope.key(run_id, index))
        .collect::<Vec<_>>();
    let multipart_key = scope.key(run_id, report.objects);
    let abort_key = scope.key(run_id, report.objects + 1);

    for record in history {
        let key = record.key.as_deref().unwrap_or_default();
        let allowed = if key == prefix {
            matches!(record.kind, OperationKind::List)
        } else if key == multipart_key {
            matches!(
                record.kind,
                OperationKind::CreateMultipartUpload
                    | OperationKind::UploadPart
                    | OperationKind::CompleteMultipartUpload
                    | OperationKind::Get
                    | OperationKind::Delete
            )
        } else if key == abort_key {
            matches!(
                record.kind,
                OperationKind::CreateMultipartUpload | OperationKind::AbortMultipartUpload
            )
        } else if plain_keys.iter().any(|plain| plain == key) {
            matches!(
                record.kind,
                OperationKind::Put | OperationKind::Get | OperationKind::Delete
            )
        } else {
            false
        };
        ensure!(
            allowed,
            "{artifact} record {} is a {:?} on {key:?}, which the probe never issues",
            record.id,
            record.kind
        );
        ensure!(
            record.outcome == OperationOutcome::Ok
                || (record.kind == OperationKind::Get
                    && record.outcome == OperationOutcome::NotFound),
            "{artifact} record {} ({:?} {key:?}) ended {:?}; a passed probe has no failed requests",
            record.id,
            record.kind,
            record.outcome
        );
    }

    let sequences = |record: &OperationRecord| -> Result<(u64, u64)> {
        Ok((
            record.started_sequence.with_context(|| {
                format!("{artifact} record {} has no start sequence", record.id)
            })?,
            record
                .ended_sequence
                .with_context(|| format!("{artifact} record {} has no end sequence", record.id))?,
        ))
    };
    let records_for = |key: &str, kind: OperationKind| {
        let mut records = history
            .iter()
            .filter(|record| record.kind == kind && record.key.as_deref() == Some(key))
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.started_sequence);
        records
    };
    let exactly_one = |key: &str, kind: OperationKind| -> Result<&OperationRecord> {
        let records = records_for(key, kind);
        ensure!(
            records.len() == 1,
            "{artifact} must hold exactly one acknowledged {kind:?} for {key:?}, found {}",
            records.len()
        );
        Ok(records[0])
    };
    // Returns the verify-GET end and the DELETE start/end sequences so the
    // LISTs can be placed relative to the writes and deletes.
    let object_lifecycle = |key: &str, write_kind: OperationKind| -> Result<(u64, u64, u64)> {
        let write = exactly_one(key, write_kind)?;
        let (_, write_ended) = sequences(write)?;
        let written_sha256 = write.value_sha256.as_deref().with_context(|| {
            format!("{artifact} {write_kind:?} for {key:?} records no payload hash")
        })?;
        let delete = exactly_one(key, OperationKind::Delete)?;
        let (delete_started, delete_ended) = sequences(delete)?;
        let gets = records_for(key, OperationKind::Get);
        ensure!(
            gets.len() == 2,
            "{artifact} must hold exactly two GETs for {key:?} (verify, then absence), found {}",
            gets.len()
        );
        let (verify, absent) = (gets[0], gets[1]);
        let (verify_started, verify_ended) = sequences(verify)?;
        ensure!(
            verify.outcome == OperationOutcome::Ok
                && verify.http_status == Some(200)
                && verify.value_sha256.as_deref() == Some(written_sha256)
                && verify.size_bytes == write.size_bytes
                && verify_started > write_ended,
            "{artifact} GET {} does not read back the acknowledged {write_kind:?} of {key:?} with its hash and size",
            verify.id
        );
        ensure!(
            delete_started > verify_ended,
            "{artifact} DELETE {} of {key:?} did not follow its verified read",
            delete.id
        );
        let (absent_started, _) = sequences(absent)?;
        ensure!(
            absent.outcome == OperationOutcome::NotFound
                && absent.http_status == Some(404)
                && absent_started > delete_ended,
            "{artifact} GET {} does not prove {key:?} absent after its acknowledged DELETE",
            absent.id
        );
        Ok((verify_ended, delete_started, delete_ended))
    };

    let mut last_verify_ended = 0;
    let mut first_delete_started = u64::MAX;
    let mut last_delete_ended = 0;
    for key in plain_keys.iter().chain(std::iter::once(&multipart_key)) {
        let write_kind = if key == &multipart_key {
            OperationKind::CompleteMultipartUpload
        } else {
            OperationKind::Put
        };
        let (verify_ended, delete_started, delete_ended) = object_lifecycle(key, write_kind)?;
        last_verify_ended = last_verify_ended.max(verify_ended);
        first_delete_started = first_delete_started.min(delete_started);
        last_delete_ended = last_delete_ended.max(delete_ended);
    }
    exactly_one(&multipart_key, OperationKind::CreateMultipartUpload)?;
    exactly_one(&abort_key, OperationKind::CreateMultipartUpload)?;
    exactly_one(&abort_key, OperationKind::AbortMultipartUpload)?;

    let lists = records_for(&prefix, OperationKind::List);
    ensure!(
        lists.len() == 2,
        "{artifact} must hold exactly two prefix LISTs, found {}",
        lists.len()
    );
    let (live_list, empty_list) = (lists[0], lists[1]);
    let mut expected_live = plain_keys.clone();
    expected_live.push(multipart_key.clone());
    expected_live.sort();
    let mut listed = live_list
        .listed_keys
        .clone()
        .with_context(|| format!("{artifact} LIST {} captured no keys", live_list.id))?;
    listed.sort();
    let (live_started, live_ended) = sequences(live_list)?;
    ensure!(
        live_list.http_status == Some(200)
            && listed == expected_live
            && live_started > last_verify_ended
            && live_ended < first_delete_started,
        "{artifact} LIST {} does not show exactly the live probe objects between the verified writes and the first DELETE",
        live_list.id
    );
    let (empty_started, _) = sequences(empty_list)?;
    ensure!(
        empty_list.http_status == Some(200)
            && empty_list
                .listed_keys
                .as_ref()
                .is_some_and(|keys| keys.is_empty())
            && empty_started > last_delete_ended,
        "{artifact} LIST {} does not prove the prefix empty after the last DELETE",
        empty_list.id
    );
    Ok(())
}

/// Scenarios whose outage must reject every mutation; the offline validator
/// re-derives that from history instead of trusting the live verdict.
fn requires_write_quorum_loss_history(scenario: &str) -> bool {
    matches!(
        scenario,
        scenarios::NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO
            | scenarios::POD_FAILURE_QUORUM_EDGE_SCENARIO
            | scenarios::QUORUM_P_IO_FAULT_SCENARIO
            | scenarios::QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
    )
}

/// The report must belong to this run, cover the whole prefilled cohort, and
/// be re-derivable from `history.jsonl`: every prefilled key has exactly one
/// fault-active GET before the mixed workload, returning its prefill bytes.
fn validate_quorum_edge_read_survival_artifact(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    evidence: &FaultEvidenceArtifact,
    bucket: &str,
    workload_object_count: usize,
) -> Result<()> {
    let report = read_json::<QuorumEdgeReadSurvivalReport>(required(
        artifacts,
        QUORUM_EDGE_READ_SURVIVAL_ARTIFACT,
    )?)?;
    validate_optional_identity_fields(
        QUORUM_EDGE_READ_SURVIVAL_ARTIFACT,
        Some(report.scenario.as_str()),
        Some(report.run_id.as_str()),
        metadata,
        identity,
    )?;
    let survival = &report.probe;
    survival
        .require_complete_survival()
        .with_context(|| format!("{QUORUM_EDGE_READ_SURVIVAL_ARTIFACT} did not pass"))?;
    let prefilled = workload_object_count / 2;
    ensure!(
        survival.objects == prefilled,
        "{QUORUM_EDGE_READ_SURVIVAL_ARTIFACT} covers {} objects, but the prefilled cohort has {prefilled}",
        survival.objects
    );

    let fault_active_at_ms = evidence
        .fault_active_at_ms
        .context("fault-evidence.json fault_active_at_ms is required")?;
    let workload_started_at_ms = evidence
        .workload_started_at_ms
        .context("fault-evidence.json workload_started_at_ms is required")?;
    let history = read_jsonl::<OperationRecord>(required(artifacts, "history.jsonl")?)?;
    let in_run = |record: &&OperationRecord| {
        record.scenario == metadata.scenario
            && record.run_id.as_deref() == Some(metadata.run_id.as_str())
            && record.bucket == bucket
    };
    let workload_prefix = crate::fault::workload::ObjectSpec::key_prefix(&metadata.run_id);
    let mut prefill = BTreeMap::<&str, &str>::new();
    for record in history.iter().filter(in_run).filter(|record| {
        record.kind == OperationKind::Put
            && record.outcome == OperationOutcome::Ok
            && record.durability_cohort == Some(DurabilityCohort::PreFault)
    }) {
        let Some(key) = record
            .key
            .as_deref()
            .filter(|key| key.starts_with(&workload_prefix))
        else {
            continue;
        };
        let sha256 = record.value_sha256.as_deref().with_context(|| {
            format!(
                "history.jsonl prefill PUT {} records no payload hash",
                record.id
            )
        })?;
        ensure!(
            prefill.insert(key, sha256).is_none(),
            "history.jsonl records more than one prefill PUT for {key:?}"
        );
    }
    ensure!(
        prefill.len() == prefilled,
        "history.jsonl records {} prefilled keys, but the workload plan prefills {prefilled}",
        prefill.len()
    );
    let mut probed = BTreeMap::<&str, bool>::new();
    for record in history.iter().filter(in_run).filter(|record| {
        record.kind == OperationKind::Get
            && record.durability_cohort == Some(DurabilityCohort::FaultActive)
            && record.fault_window_relation == Some(FaultWindowRelation::DuringFault)
            && record.started_at_ms >= fault_active_at_ms
            && record.ended_at_ms <= workload_started_at_ms
    }) {
        let Some((key, sha256)) = record
            .key
            .as_deref()
            .and_then(|key| prefill.get_key_value(key))
        else {
            continue;
        };
        let verified = record.outcome == OperationOutcome::Ok
            && record.range.is_none()
            && record.value_sha256.as_deref() == Some(*sha256);
        ensure!(
            probed.insert(key, verified).is_none(),
            "history.jsonl holds more than one fault-active probe read of {key:?}"
        );
    }
    let verified = probed.values().filter(|verified| **verified).count();
    ensure!(
        probed.len() == prefilled && verified == survival.verified,
        "history.jsonl proves {verified} verified probe reads over {} of {prefilled} prefilled keys, but {QUORUM_EDGE_READ_SURVIVAL_ARTIFACT} claims {} verified",
        probed.len(),
        survival.verified
    );
    Ok(())
}

fn validate_availability_artifact(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    evidence: &FaultEvidenceArtifact,
    summary: &WorkloadSummaryArtifact,
    workload_object_count: usize,
    catalog_floor_percent: u8,
) -> Result<()> {
    let report =
        read_json::<AvailabilityReport>(required(artifacts, AVAILABILITY_REPORT_ARTIFACT)?)?;
    validate_optional_identity_fields(
        AVAILABILITY_REPORT_ARTIFACT,
        Some(report.scenario.as_str()),
        Some(report.run_id.as_str()),
        metadata,
        identity,
    )?;
    // The floor the run was configured with is persisted in run-metadata.json
    // and may only tighten the catalog floor; a report claiming a laxer floor
    // than either is not evidence.
    let configured_floor = metadata.min_availability_percent.context(
        "run-metadata.json min_availability_percent is required for availability scenarios",
    )?;
    ensure!(
        report.min_success_percent == configured_floor,
        "{AVAILABILITY_REPORT_ARTIFACT} min_success_percent {} does not match run-metadata.json min_availability_percent {configured_floor}",
        report.min_success_percent
    );
    ensure!(
        report.min_success_percent >= catalog_floor_percent,
        "{AVAILABILITY_REPORT_ARTIFACT} min_success_percent {} is below the catalog availability floor {catalog_floor_percent}",
        report.min_success_percent
    );
    let acknowledged_commits = summary
        .puts
        .ok
        .checked_add(summary.multipart_completes.ok)
        .context("workload-summary.json acknowledged commit count overflowed")?;
    ensure!(
        report.commit_probe.objects == acknowledged_commits
            && report.commit_probe.verified == report.commit_probe.objects
            && report.commit_probe.failures.is_empty(),
        "{AVAILABILITY_REPORT_ARTIFACT} commit probe verified {} of {} reported commits with {} failure(s), but workload-summary.json records {acknowledged_commits} acknowledged PUTs, overwrites, and multipart completions",
        report.commit_probe.verified,
        report.commit_probe.objects,
        report.commit_probe.failures.len()
    );
    report
        .require_success()
        .with_context(|| format!("{AVAILABILITY_REPORT_ARTIFACT} did not pass"))?;
    ensure!(
        report.read_probe.objects == workload_object_count / 2
            && report.read_probe.verified == report.read_probe.objects
            && report.read_probe.failures.is_empty(),
        "{AVAILABILITY_REPORT_ARTIFACT} read probe did not verify the complete prefilled cohort"
    );
    // Every family is recomputed from workload-summary.json and must equal
    // the report's, so disruptions cannot be shifted from a small family
    // that would violate the floor into a large one that tolerates them, and
    // the floor verdict is re-derived rather than trusted.
    let expected_families = summary.family_availability()?;
    ensure!(
        report.workload.len() == expected_families.len(),
        "{AVAILABILITY_REPORT_ARTIFACT} lists {} workload families but workload-summary.json defines {}",
        report.workload.len(),
        expected_families.len()
    );
    for (family, expected) in report.workload.iter().zip(&expected_families) {
        ensure!(
            family == expected,
            "{AVAILABILITY_REPORT_ARTIFACT} family {:?} ({} of {} disrupted, {}%) does not match workload-summary.json {} ({} of {} disrupted, {}%)",
            family.family,
            family.disrupted,
            family.total,
            family.success_percent,
            expected.family,
            expected.disrupted,
            expected.total,
            expected.success_percent
        );
        ensure!(
            expected.meets_floor(report.min_success_percent),
            "{AVAILABILITY_REPORT_ARTIFACT} family {} ({} of {} disrupted) does not meet the {}% floor recomputed from workload-summary.json",
            expected.family,
            expected.disrupted,
            expected.total,
            report.min_success_percent
        );
    }
    let disrupted = expected_families
        .iter()
        .map(|family| family.disrupted)
        .sum::<usize>();
    ensure!(
        disrupted == evidence.client_disruptions,
        "{AVAILABILITY_REPORT_ARTIFACT} workload disruptions {disrupted} do not match fault-evidence.json client_disruptions {}",
        evidence.client_disruptions
    );
    Ok(())
}

/// Lifecycle scenarios must prove which Pods were restarted, that every
/// RustFS container left cleanly, and that the restart identities match the
/// run's Pod evidence and fault window. The active snapshot must name the
/// same under-workload targets so the availability endpoint pinning was
/// computed from the Pods that actually restarted.
/// Run artifacts the lifecycle report is bound to besides fault evidence.
struct LifecycleValidationInputs<'a> {
    history: &'a [OperationRecord],
    statefulset_proof: Option<&'a crate::fault::preflight::TargetStatefulSetProof>,
    requires_availability: bool,
}

fn validate_pod_lifecycle_artifact(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    evidence: &FaultEvidenceArtifact,
    spec: &FaultRunSpec,
    inputs: LifecycleValidationInputs<'_>,
) -> Result<()> {
    let LifecycleValidationInputs {
        history,
        statefulset_proof,
        requires_availability,
    } = inputs;
    let proof = statefulset_proof
        .context("target-proof.json carries no StatefulSet proof for the lifecycle fault")?;
    ensure!(
        proof.update_revision.is_some() && proof.current_revision == proof.update_revision,
        "target-proof.json StatefulSet {} was not proven converged on one revision (current {:?}, update {:?})",
        proof.name,
        proof.current_revision,
        proof.update_revision
    );
    let report =
        read_json::<PodLifecycleEvidence>(required(artifacts, POD_LIFECYCLE_EVIDENCE_ARTIFACT)?)?;
    validate_optional_identity_fields(
        POD_LIFECYCLE_EVIDENCE_ARTIFACT,
        Some(report.scenario.as_str()),
        Some(report.run_id.as_str()),
        metadata,
        identity,
    )?;
    let kind_name = &spec
        .faults
        .first()
        .context("lifecycle run-spec has no fault")?
        .kind;
    let kind = [
        FaultKind::RustfsServerPodGracefulRestart,
        FaultKind::RustfsServerRollingRestart,
        FaultKind::RustfsServerColdRestart,
    ]
    .into_iter()
    .find(|kind| kind.as_str() == kind_name)
    .with_context(|| format!("run-spec fault kind {kind_name:?} is not a lifecycle operation"))?;
    let served_by_pod = if requires_availability {
        read_json::<AvailabilityReport>(required(artifacts, AVAILABILITY_REPORT_ARTIFACT)?)?
            .served_by_pod
    } else {
        None
    };
    let fault_active_at_ms = evidence
        .fault_active_at_ms
        .context("fault-evidence.json fault_active_at_ms is required")?;
    let pods_before = evidence
        .pods_before
        .iter()
        .map(|pod| (pod.name.clone(), pod.uid.clone()))
        .collect::<Vec<_>>();
    let pods_after = evidence
        .pods_after
        .iter()
        .map(|pod| (pod.name.clone(), pod.uid.clone()))
        .collect::<Vec<_>>();
    report.validate_against_run(&LifecycleRunContext {
        kind,
        pods_before: &pods_before,
        pods_after: &pods_after,
        fault_apply_started_at_ms: evidence
            .fault_apply_started_at_ms
            .context("fault-evidence.json fault_apply_started_at_ms is required")?,
        fault_active_at_ms,
        workload_started_at_ms: evidence
            .workload_started_at_ms
            .context("fault-evidence.json workload_started_at_ms is required")?,
        workload_ended_at_ms: evidence
            .workload_ended_at_ms
            .context("fault-evidence.json workload_ended_at_ms is required")?,
        recovery_ended_at_ms: evidence
            .recovery_ended_at_ms
            .context("fault-evidence.json recovery_ended_at_ms is required")?,
        served_by_pod: served_by_pod.as_deref(),
        first_fault_request_at_ms: history
            .iter()
            .map(|record| record.started_at_ms)
            .filter(|started| *started >= fault_active_at_ms)
            .min(),
        proven_statefulset_uid: &proof.uid,
        proven_revision: proof.update_revision.as_deref(),
    })?;
    let active_targets = evidence
        .active_snapshots
        .iter()
        .filter_map(|snapshot| snapshot.pointer(SNAPSHOT_TARGET_PODS_POINTER))
        .filter_map(Value::as_array)
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    let under_workload = report
        .targets
        .iter()
        .filter(|target| !target.restarted_after_workload)
        .map(|target| target.pod_name.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        active_targets == under_workload,
        "fault-evidence.json active snapshot lifecycle targets {active_targets:?} do not match {POD_LIFECYCLE_EVIDENCE_ARTIFACT} under-workload targets {under_workload:?}"
    );
    if kind == FaultKind::RustfsServerColdRestart {
        let summary =
            read_json::<WorkloadSummaryArtifact>(required(artifacts, "workload-summary.json")?)?;
        for (family, counts) in [
            ("puts", &summary.puts),
            ("gets", &summary.gets),
            ("deletes", &summary.deletes),
            ("lists", &summary.lists),
            ("multipart_completes", &summary.multipart_completes),
            ("multipart_aborts", &summary.multipart_aborts),
        ] {
            if let Some(violation) =
                total_outage_violation(family, counts.ok, counts.not_found, counts.total())
            {
                bail!("workload-summary.json: {violation}");
            }
        }
    }
    Ok(())
}

fn validate_fault_window_evidence(evidence: &FaultEvidenceArtifact) -> Result<()> {
    let apply_started = evidence
        .fault_apply_started_at_ms
        .context("fault-evidence.json fault_apply_started_at_ms is required")?;
    let active = evidence
        .fault_active_at_ms
        .context("fault-evidence.json fault_active_at_ms is required")?;
    let workload_started = evidence
        .workload_started_at_ms
        .context("fault-evidence.json workload_started_at_ms is required")?;
    let workload_ended = evidence
        .workload_ended_at_ms
        .context("fault-evidence.json workload_ended_at_ms is required")?;
    let delete_started = evidence
        .fault_delete_started_at_ms
        .context("fault-evidence.json fault_delete_started_at_ms is required")?;
    let recovery_started = evidence
        .recovery_started_at_ms
        .context("fault-evidence.json recovery_started_at_ms is required")?;
    let recovery_ended = evidence
        .recovery_ended_at_ms
        .context("fault-evidence.json recovery_ended_at_ms is required")?;

    ensure!(
        apply_started <= active
            && active <= workload_started
            && workload_started <= workload_ended
            && workload_ended <= delete_started
            && delete_started <= recovery_started
            && recovery_started <= recovery_ended,
        "fault-evidence.json fault window timestamps are not monotonic"
    );
    Ok(())
}

fn validate_ack_fault_window_evidence(evidence: &FaultEvidenceArtifact) -> Result<()> {
    let prepare_started = evidence
        .fault_prepare_started_at_ms
        .context("ACK-triggered fault-evidence.json fault_prepare_started_at_ms is required")?;
    let apply_started = evidence
        .fault_apply_started_at_ms
        .context("ACK-triggered fault-evidence.json fault_apply_started_at_ms is required")?;
    let active = evidence
        .fault_active_at_ms
        .context("ACK-triggered fault-evidence.json fault_active_at_ms is required")?;
    let delete_started = evidence
        .fault_delete_started_at_ms
        .context("ACK-triggered fault-evidence.json fault_delete_started_at_ms is required")?;
    let recovery_started = evidence
        .recovery_started_at_ms
        .context("ACK-triggered fault-evidence.json recovery_started_at_ms is required")?;
    let recovery_ended = evidence
        .recovery_ended_at_ms
        .context("ACK-triggered fault-evidence.json recovery_ended_at_ms is required")?;
    ensure!(
        evidence.workload_started_at_ms.is_none() && evidence.workload_ended_at_ms.is_none(),
        "ACK-triggered quiet mutation must not claim an under-fault workload window"
    );
    ensure!(
        prepare_started <= apply_started
            && apply_started <= active
            && active <= delete_started
            && delete_started <= recovery_started
            && recovery_started <= recovery_ended,
        "ACK-triggered fault-evidence.json lifecycle timestamps are not monotonic"
    );
    Ok(())
}

struct AckArtifactValidationContext<'a> {
    root: &'a Path,
    case_name: &'a str,
    events: &'a [RunEvent],
    evidence: &'a FaultEvidenceArtifact,
    history: &'a [OperationRecord],
    scenario: &'a str,
    run_id: &'a str,
    bucket: &'a str,
    run_spec: &'a FaultRunSpec,
}

#[derive(Debug, PartialEq, Eq)]
struct AckCheckerExpectation {
    trigger_operation_id: String,
    trigger_reference: String,
    trigger_is_delete_marker: bool,
    committed_version_refs: BTreeSet<String>,
    committed_delete_marker_refs: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
struct AckFaultTimeline {
    prepare_started_at_ms: Option<u64>,
    apply_started_at_ms: Option<u64>,
}

fn validate_ack_triggered_dm_artifacts(
    context: AckArtifactValidationContext<'_>,
    expected_mutation: AcknowledgedMutationKind,
) -> Result<AckCheckerExpectation> {
    let AckArtifactValidationContext {
        root,
        case_name,
        events,
        evidence,
        history,
        scenario,
        run_id,
        bucket,
        run_spec,
    } = context;
    validate_history_scope_and_order(history, scenario, run_id, bucket)?;
    let preparation_event = events
        .iter()
        .find(|event| {
            event.stage == "fault-prepare"
                && event.status == RunEventStatus::Succeeded
                && event.scenario == scenario
                && event.run_id == run_id
        })
        .context("run-events.jsonl lacks successful fault preparation")?;
    ensure!(
        events.iter().any(|event| {
            event.stage == "ack-trigger"
                && event.status == RunEventStatus::Succeeded
                && event.scenario == scenario
                && event.run_id == run_id
        }) && events.iter().any(|event| {
            event.stage == "crash-recovery-boundary"
                && event.status == RunEventStatus::Succeeded
                && event.scenario == scenario
                && event.run_id == run_id
        }),
        "run-events.jsonl lacks a successful ACK trigger or crash-recovery boundary"
    );
    let ack = read_json::<AckTriggeredCrashEvidenceArtifact>(&locate_artifact(
        root,
        case_name,
        "ack-to-fault-evidence.json",
    )?)?;
    let planned = run_spec
        .scenario
        .ack_trigger
        .as_ref()
        .context("run-spec lacks the ACK trigger contract")?;
    let trigger = history
        .iter()
        .find(|record| record.id == ack.trigger_operation_id)
        .context("history.jsonl lacks the declared ACK trigger operation")?;
    validate_ack_trigger_contract(
        &ack,
        planned,
        expected_mutation,
        scenario,
        run_id,
        AckFaultTimeline {
            prepare_started_at_ms: evidence.fault_prepare_started_at_ms,
            apply_started_at_ms: evidence.fault_apply_started_at_ms,
        },
        trigger,
    )?;
    ensure!(
        evidence.fault_active_at_ms == Some(ack.fault_activated_at_ms),
        "ACK activation timestamp does not match fault-evidence.json"
    );

    ensure!(
        trigger.scenario == scenario
            && trigger.run_id.as_deref() == Some(run_id)
            && trigger.bucket == bucket
            && trigger.kind == ack_operation_kind(expected_mutation)
            && trigger.key.as_deref() == Some(ack.trigger_key.as_str())
            && trigger.version_id.as_deref() == Some(ack.trigger_version_id.as_str())
            && trigger.outcome == OperationOutcome::Ok
            && trigger.durability_cohort == Some(DurabilityCohort::PreFault)
            && trigger.fault_window_relation.is_none()
            && trigger
                .http_status
                .is_some_and(|status| (200..300).contains(&status))
            && trigger.ended_at_ms == ack.trigger_acknowledged_at_ms,
        "ack-to-fault-evidence.json trigger identity does not match an eligible committed history record"
    );
    if expected_mutation == AcknowledgedMutationKind::ZeroBytePut {
        ensure!(
            trigger.size_bytes == Some(0),
            "zero-byte ACK trigger history record is not empty"
        );
    }
    validate_ack_quiet_gap(
        history,
        trigger,
        ack.crash_boundary_started_at_ms,
        ack.crash_boundary_next_sequence,
    )?;
    validate_ack_mutation_shape(history, trigger, expected_mutation)?;
    let checker_expectation = ack_checker_expectation(history, trigger, expected_mutation)?;

    let boundary = read_json::<DmCrashBoundaryArtifact>(&locate_artifact(
        root,
        case_name,
        "dm-crash-boundary.json",
    )?)?;
    ensure!(
        boundary.scenario == scenario
            && boundary.run_id == run_id
            && boundary.started_at_ms == ack.crash_boundary_started_at_ms
            && boundary.completed_at_ms >= boundary.started_at_ms
            && boundary.filesystem_unmounted
            && boundary.mapper_mounts_absent
            && !boundary.mount_before.canonical_source.is_empty()
            && !boundary.mount_before.filesystem.is_empty()
            && !boundary.mount_before.options.is_empty()
            && boundary
                .fault
                .table
                .split_whitespace()
                .any(|field| field == "drop_writes")
            && evidence
                .fault_delete_started_at_ms
                .is_some_and(|started| started >= boundary.completed_at_ms),
        "dm-crash-boundary.json does not match the ACK-triggered drop_writes boundary"
    );
    if let Some(replacement_uid) = &boundary.replacement_pod_uid {
        ensure!(
            replacement_uid != &boundary.old_pod_uid,
            "dm-crash-boundary.json replacement Pod UID must differ from the deleted Pod UID"
        );
    }
    let recovered = read_json::<DmCrashRecoveryArtifact>(&locate_artifact(
        root,
        case_name,
        "dm-crash-recovered.json",
    )?)?;
    ensure!(
        recovered.scenario == scenario
            && recovered.run_id == run_id
            && recovered.recovered_at_ms >= boundary.completed_at_ms
            && recovered.taint_removed
            && !recovered.mount.source.is_empty()
            && !recovered.mount.canonical_source.is_empty()
            && !recovered.mount.filesystem.is_empty()
            && recovered.mount.canonical_source == boundary.mount_before.canonical_source
            && recovered.mount.filesystem == boundary.mount_before.filesystem
            && recovered.mount.options == boundary.mount_before.options
            && normalize_dm_table(&recovered.fault.table)
                == normalize_dm_table(&recovered.expected_table)
            && drop_writes_table_matches_recovery(&boundary.fault.table, &recovered.expected_table)
            && !recovered
                .fault
                .table
                .split_whitespace()
                .any(|field| field == "drop_writes"),
        "dm-crash-recovered.json does not prove recovery of the ACK-triggered fault"
    );
    let host_proof = read_json::<HostStorageMutationProof>(&locate_artifact(
        root,
        case_name,
        HOST_STORAGE_PROOF_ARTIFACT,
    )?)?;
    ensure!(
        host_proof.generated_at_ms <= preparation_event.at_ms
            && preparation_event.at_ms <= ack.trigger_acknowledged_at_ms,
        "host-storage proof and successful fault preparation must precede the trigger ACK"
    );
    validate_ack_crash_target_identity(&boundary, &host_proof, evidence)?;
    Ok(checker_expectation)
}

fn validate_ack_trigger_contract(
    ack: &AckTriggeredCrashEvidenceArtifact,
    planned: &FaultRunAckTriggerSpec,
    expected_mutation: AcknowledgedMutationKind,
    scenario: &str,
    run_id: &str,
    timeline: AckFaultTimeline,
    trigger: &OperationRecord,
) -> Result<()> {
    ensure!(
        ack.scenario == scenario
            && ack.run_id == run_id
            && ack.trigger_kind == expected_mutation
            && planned.mutation == expected_mutation
            && planned.operation_timeout_ms > 0
            && trigger.ended_at_ms == ack.trigger_acknowledged_at_ms
            && trigger
                .ended_at_ms
                .checked_sub(trigger.started_at_ms)
                .is_some_and(|duration| duration <= planned.operation_timeout_ms)
            && (1..=MAX_ACK_TO_FAULT_MS).contains(&planned.max_ack_to_fault_ms)
            && ack.max_ack_to_fault_ms == planned.max_ack_to_fault_ms
            && !ack.trigger_operation_id.is_empty()
            && !ack.trigger_key.is_empty()
            && !ack.trigger_version_id.is_empty()
            && ack.trigger_version_id != "null"
            && timeline.prepare_started_at_ms.is_some_and(|prepared| {
                timeline.apply_started_at_ms.is_some_and(|started| {
                    prepared <= ack.trigger_acknowledged_at_ms
                        && ack.trigger_acknowledged_at_ms <= started
                        && started <= ack.fault_activated_at_ms
                })
            })
            && ack.fault_activated_at_ms <= ack.crash_boundary_started_at_ms
            && ack.ack_to_fault_ms
                == ack
                    .fault_activated_at_ms
                    .saturating_sub(ack.trigger_acknowledged_at_ms)
            && ack.ack_to_fault_ms <= ack.max_ack_to_fault_ms
            && ack.ack_to_crash_boundary_ms
                == ack
                    .crash_boundary_started_at_ms
                    .saturating_sub(ack.trigger_acknowledged_at_ms),
        "ack-to-fault-evidence.json does not prove the planned mutation ACK preceded bounded fault application and activation"
    );
    Ok(())
}

fn ack_checker_expectation(
    history: &[OperationRecord],
    trigger: &OperationRecord,
    mutation: AcknowledgedMutationKind,
) -> Result<AckCheckerExpectation> {
    let committed_version_refs = history
        .iter()
        .filter(|record| {
            matches!(
                record.kind,
                OperationKind::Put | OperationKind::CompleteMultipartUpload
            ) && record.outcome == OperationOutcome::Ok
                && record.value_sha256.is_some()
                && record.size_bytes.is_some()
        })
        .filter_map(operation_version_reference)
        .collect::<BTreeSet<_>>();
    let committed_delete_marker_refs = history
        .iter()
        .filter(|record| {
            record.kind == OperationKind::Delete && record.outcome == OperationOutcome::Ok
        })
        .filter_map(operation_version_reference)
        .collect::<BTreeSet<_>>();
    let trigger_reference = operation_version_reference(trigger)
        .context("eligible ACK trigger lacks an exact key@version reference")?;
    let trigger_is_delete_marker = mutation == AcknowledgedMutationKind::DeleteMarker;
    let expected_set = if trigger_is_delete_marker {
        &committed_delete_marker_refs
    } else {
        &committed_version_refs
    };
    ensure!(
        expected_set.contains(&trigger_reference),
        "eligible ACK trigger is absent from the history-derived checker expectation"
    );
    Ok(AckCheckerExpectation {
        trigger_operation_id: trigger.id.clone(),
        trigger_reference,
        trigger_is_delete_marker,
        committed_version_refs,
        committed_delete_marker_refs,
    })
}

fn operation_version_reference(record: &OperationRecord) -> Option<String> {
    let key = record.key.as_deref()?;
    let version_id = record.version_id.as_deref()?;
    (!key.is_empty() && !version_id.is_empty() && version_id != "null")
        .then(|| format!("{key}@{version_id}"))
}

fn validate_ack_checker_report(
    name: &str,
    report: &CheckerReport,
    expectation: &AckCheckerExpectation,
) -> Result<()> {
    let audit = report
        .audit
        .as_ref()
        .context("ACK checker has no history-bound audit")?;
    let verified_versions = audit
        .data_version_checks
        .iter()
        .filter(|check| {
            check.outcome == OperationOutcome::Ok
                && check.http_status == Some(200)
                && check.observed_sha256.as_deref() == Some(check.expected_sha256.as_str())
        })
        .map(|check| format!("{}@{}", check.key, check.version_id))
        .collect::<BTreeSet<_>>();
    let verified_delete_markers = audit
        .delete_marker_checks
        .iter()
        .filter(|check| check.visible_in_list_object_versions)
        .map(|check| format!("{}@{}", check.key, check.version_id))
        .collect::<BTreeSet<_>>();
    ensure!(
        report.versioning_expected
            && report.expected_committed_versions == expectation.committed_version_refs.len()
            && report.verified_committed_versions == expectation.committed_version_refs.len()
            && audit.data_version_checks.len() == verified_versions.len()
            && verified_versions == expectation.committed_version_refs
            && audit.list_object_versions_completed == Some(true)
            && audit.delete_marker_checks.len() == verified_delete_markers.len()
            && verified_delete_markers == expectation.committed_delete_marker_refs,
        "{name} exact committed version/delete-marker proof does not match history.jsonl"
    );
    let trigger_verified = if expectation.trigger_is_delete_marker {
        verified_delete_markers.contains(&expectation.trigger_reference)
    } else {
        verified_versions.contains(&expectation.trigger_reference)
    };
    ensure!(
        trigger_verified,
        "{name} does not prove the exact ACK trigger {}",
        expectation.trigger_reference
    );
    Ok(())
}

fn validate_ack_prechecker_boundary(
    report: &CheckerReport,
    history: &[OperationRecord],
    trigger_operation_id: &str,
    recovery_ended_at_ms: Option<u64>,
) -> Result<()> {
    let recovery_ended_at_ms =
        recovery_ended_at_ms.context("ACK recovery has no completion timestamp")?;
    let trigger_index = history
        .iter()
        .position(|record| record.id == trigger_operation_id)
        .context("ACK checker history lacks the trigger operation")?;
    ensure!(
        report
            .audit
            .as_ref()
            .is_some_and(
                |audit| audit.history_prefix_record_count == trigger_index + 1
                    && audit.started_at_ms >= recovery_ended_at_ms
            ),
        "ACK prechecker must start after recovery and its prefix must end exactly at the trigger without intervening S3 traffic"
    );
    Ok(())
}

fn validate_ack_checker_phase_chain(
    prechecker: &CheckerReport,
    checker: &CheckerReport,
    bucket: &str,
    history: &[OperationRecord],
) -> Result<()> {
    let pre = prechecker
        .audit
        .as_ref()
        .context("ACK prechecker has no audit")?;
    let final_audit = checker
        .audit
        .as_ref()
        .context("ACK final checker has no audit")?;
    let pre_end = pre
        .history_prefix_record_count
        .checked_add(pre.history_suffix_record_count)
        .context("ACK prechecker history bounds overflow")?;
    let final_end = final_audit
        .history_prefix_record_count
        .checked_add(final_audit.history_suffix_record_count)
        .context("ACK final checker history bounds overflow")?;
    validate_history_scope_and_order(history, &prechecker.scenario, &prechecker.run_id, bucket)?;
    ensure!(
        pre.bucket == bucket
            && final_audit.bucket == bucket
            && prechecker.scenario == checker.scenario
            && prechecker.run_id == checker.run_id,
        "ACK checker phases do not match the run target identity"
    );
    ensure!(
        pre.history_suffix_record_count > 0
            && final_audit.history_suffix_record_count > 0
            && pre.completed_at_ms <= final_audit.started_at_ms
            && pre_end == final_audit.history_prefix_record_count
            && final_end == history.len(),
        "ACK checker phases must be independent, contiguous, ordered, and terminal without recommit"
    );
    let prefix = history
        .get(..pre_end)
        .context("ACK prechecker exceeds history bounds")?;
    let suffix = history
        .get(pre_end..final_end)
        .context("ACK final checker exceeds history bounds")?;
    validate_history_phase_boundary(prefix, suffix, "ACK prechecker/final-checker")
}

fn validate_ack_crash_target_identity(
    boundary: &DmCrashBoundaryArtifact,
    proof: &HostStorageMutationProof,
    evidence: &FaultEvidenceArtifact,
) -> Result<()> {
    ensure!(
        boundary.old_pod_uid == proof.target.pod_uid
            && boundary.mount_before.canonical_source == proof.target.mount_canonical_source
            && boundary.mount_before.filesystem == proof.target.filesystem,
        "dm-crash-boundary.json is not bound to the host-storage proof target"
    );
    ensure!(
        evidence
            .pods_before
            .iter()
            .any(|pod| pod.name == proof.target.pod && pod.uid == proof.target.pod_uid),
        "fault-evidence.json lacks the exact host-storage proof target Pod name/UID"
    );
    ensure!(
        evidence.pods_after.iter().any(|pod| {
            pod.name == proof.target.pod
                && pod.uid != proof.target.pod_uid
                && boundary
                    .replacement_pod_uid
                    .as_ref()
                    .is_none_or(|replacement| replacement == &pod.uid)
        }),
        "fault-evidence.json does not prove replacement of the host-storage proof target Pod"
    );
    Ok(())
}

fn validate_ack_quiet_gap(
    history: &[OperationRecord],
    trigger: &OperationRecord,
    crash_boundary_started_at_ms: u64,
    crash_boundary_next_sequence: u64,
) -> Result<()> {
    let trigger_start = trigger
        .started_sequence
        .context("ACK trigger lacks start sequence")?;
    let trigger_end = trigger
        .ended_sequence
        .context("ACK trigger lacks end sequence")?;
    ensure!(
        trigger.ended_at_ms <= crash_boundary_started_at_ms
            && trigger_end.checked_add(1) == Some(crash_boundary_next_sequence)
            && history.iter().all(|record| {
                record.id == trigger.id
                    || (record.ended_sequence.is_some_and(|end| end < trigger_start)
                        && record.ended_at_ms <= trigger.started_at_ms)
                    || (matches!(
                        record.kind,
                        OperationKind::Get | OperationKind::List | OperationKind::ListVersions
                    ) && record.durability_cohort == Some(DurabilityCohort::PostRecovery)
                        && record.fault_window_relation == Some(FaultWindowRelation::AfterFault)
                        && record
                            .started_sequence
                            .is_some_and(|start| start >= crash_boundary_next_sequence)
                        && record.started_at_ms >= crash_boundary_started_at_ms)
            }),
        "S3 traffic overlapped the quiet trigger or occurred before its crash boundary"
    );
    Ok(())
}

fn ack_operation_kind(kind: AcknowledgedMutationKind) -> OperationKind {
    match kind {
        AcknowledgedMutationKind::Put
        | AcknowledgedMutationKind::Overwrite
        | AcknowledgedMutationKind::ZeroBytePut => OperationKind::Put,
        AcknowledgedMutationKind::DeleteMarker => OperationKind::Delete,
        AcknowledgedMutationKind::MultipartComplete => OperationKind::CompleteMultipartUpload,
    }
}

fn validate_ack_mutation_shape(
    history: &[OperationRecord],
    trigger: &OperationRecord,
    kind: AcknowledgedMutationKind,
) -> Result<()> {
    let trigger_start = trigger
        .started_sequence
        .context("ACK trigger lacks start sequence")?;
    let prior_mutations = history
        .iter()
        .filter(|record| {
            record.id != trigger.id
                && record.key == trigger.key
                && matches!(
                    record.kind,
                    OperationKind::Put
                        | OperationKind::Delete
                        | OperationKind::CompleteMultipartUpload
                )
                && record.outcome == OperationOutcome::Ok
                && record.ended_sequence.is_some_and(|end| end < trigger_start)
                && record.ended_at_ms <= trigger.started_at_ms
        })
        .collect::<Vec<_>>();
    match kind {
        AcknowledgedMutationKind::Put | AcknowledgedMutationKind::ZeroBytePut => ensure!(
            prior_mutations.is_empty(),
            "create-style ACK trigger unexpectedly has a prior object version"
        ),
        AcknowledgedMutationKind::Overwrite | AcknowledgedMutationKind::DeleteMarker => {
            ensure!(
                prior_mutations.len() == 1 && prior_mutations[0].kind == OperationKind::Put,
                "overwrite/delete-marker ACK trigger must have exactly one baseline PUT"
            );
            let baseline = prior_mutations[0];
            ensure!(
                baseline
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status))
                    && operation_version_reference(baseline).is_some()
                    && baseline
                        .value_sha256
                        .as_deref()
                        .is_some_and(|hash| !hash.is_empty())
                    && baseline.size_bytes.is_some(),
                "ACK baseline PUT lacks a definite versioned commit with complete payload evidence"
            );
        }
        AcknowledgedMutationKind::MultipartComplete => {
            ensure!(
                prior_mutations.is_empty(),
                "multipart ACK trigger unexpectedly has a prior object version"
            );
            ensure!(
                history.iter().any(|record| {
                    record.key == trigger.key
                        && record.kind == OperationKind::CreateMultipartUpload
                        && record.outcome == OperationOutcome::Ok
                        && record.ended_sequence.is_some_and(|end| end < trigger_start)
                        && record.ended_at_ms <= trigger.started_at_ms
                }) && history.iter().any(|record| {
                    record.key == trigger.key
                        && record.kind == OperationKind::UploadPart
                        && record.outcome == OperationOutcome::Ok
                        && record.ended_sequence.is_some_and(|end| end < trigger_start)
                        && record.ended_at_ms <= trigger.started_at_ms
                }),
                "multipart ACK trigger lacks successfully staged upload evidence"
            );
        }
    }
    Ok(())
}

/// The node-down hold must be bound to the crashed host-storage target, must
/// have read back exactly the prefilled objects the workload never touched,
/// and must sit between the crash boundary and fault removal together with
/// its fresh-write probe.
fn validate_node_down_hold_artifacts(
    artifacts: &BTreeMap<String, PathBuf>,
    metadata: &RunMetadataArtifact,
    identity: ArtifactIdentityPolicy<'_>,
    events: &[RunEvent],
    bucket: &str,
    workload_object_count: usize,
) -> Result<()> {
    let hold = read_json::<NodeDownHoldEvidence>(required(artifacts, NODE_DOWN_HOLD_ARTIFACT)?)?;
    validate_optional_identity_fields(
        NODE_DOWN_HOLD_ARTIFACT,
        Some(hold.scenario.as_str()),
        Some(hold.run_id.as_str()),
        metadata,
        identity,
    )?;
    let host =
        read_json::<HostStorageMutationProof>(required(artifacts, HOST_STORAGE_PROOF_ARTIFACT)?)?;
    ensure!(
        hold.target
            == NodeDownTarget {
                pod: host.target.pod.clone(),
                crashed_pod_uid: host.target.pod_uid.clone(),
                node: host.target.node.clone(),
            },
        "{NODE_DOWN_HOLD_ARTIFACT} target is not the host-storage-proof.json target"
    );

    let history = read_jsonl::<OperationRecord>(required(artifacts, "history.jsonl")?)?;
    let workload_prefix = crate::fault::workload::ObjectSpec::key_prefix(&metadata.run_id);
    let prefill_keys = history
        .iter()
        .filter(|record| {
            record.scenario == metadata.scenario
                && record.run_id.as_deref() == Some(metadata.run_id.as_str())
                && record.kind == OperationKind::Put
                && record.outcome == OperationOutcome::Ok
                && record.durability_cohort == Some(DurabilityCohort::PreFault)
        })
        .filter_map(|record| record.key.as_deref())
        .filter(|key| key.starts_with(&workload_prefix))
        .collect::<BTreeSet<_>>();
    ensure!(
        prefill_keys.len() == workload_object_count / 2,
        "history.jsonl records {} prefilled keys, but the workload plan prefills {}",
        prefill_keys.len(),
        workload_object_count / 2
    );
    let untouched = untouched_prefill_keys(
        prefill_keys.iter().copied(),
        &history,
        &metadata.scenario,
        &metadata.run_id,
    );
    ensure!(
        !untouched.is_empty(),
        "history.jsonl leaves no untouched prefilled object for the node-down read probe"
    );
    hold.validate(untouched.len())?;

    // Survivors are only measured after the node has been down for the
    // minimum hold, so detection of the loss cannot postdate the probes.
    let probes_allowed_from_ms = hold.started_at_ms.saturating_add(hold.min_hold_ms);
    let reads =
        read_jsonl::<OperationRecord>(required(artifacts, NODE_DOWN_READ_HISTORY_ARTIFACT)?)?;
    validate_history_scope_and_order(&reads, &metadata.scenario, &metadata.run_id, bucket)?;
    ensure!(
        reads.len() == untouched.len(),
        "{NODE_DOWN_READ_HISTORY_ARTIFACT} holds {} records for {} untouched prefilled objects",
        reads.len(),
        untouched.len()
    );
    let mut read_keys = BTreeSet::new();
    for record in &reads {
        let key = record.key.as_deref().unwrap_or_default();
        ensure!(
            record.kind == OperationKind::Get
                && record.outcome == OperationOutcome::Ok
                && untouched.get(key) == record.value_sha256.as_ref()
                && hold.contains(record.started_at_ms, record.ended_at_ms)
                && record.started_at_ms >= probes_allowed_from_ms
                && read_keys.insert(key),
            "{NODE_DOWN_READ_HISTORY_ARTIFACT} record {} is not one successful post-detection read of an untouched prefilled object with its prefill hash",
            record.id
        );
    }

    let position = |stage: &str, status: RunEventStatus| {
        events
            .iter()
            .position(|event| event.stage == stage && event.status == status)
            .with_context(|| format!("run-events.jsonl lacks a {stage} {status:?} event"))
    };
    let crash = position("crash-recovery-boundary", RunEventStatus::Succeeded)?;
    let hold_started = position("node-down-hold", RunEventStatus::Started)?;
    let write_started = position("node-down-write", RunEventStatus::Started)?;
    let write_succeeded = position("node-down-write", RunEventStatus::Succeeded)?;
    let hold_succeeded = position("node-down-hold", RunEventStatus::Succeeded)?;
    let removal = position("fault-delete", RunEventStatus::Started)?;
    ensure!(
        crash < hold_started
            && hold_started < write_started
            && write_started < write_succeeded
            && write_succeeded < hold_succeeded
            && hold_succeeded < removal
            && events[hold_started].at_ms <= hold.started_at_ms
            && hold.ended_at_ms <= events[hold_succeeded].at_ms,
        "run-events.jsonl does not place the node-down hold and its write probe between the crash boundary and fault removal"
    );
    ensure!(
        events.iter().all(|event| {
            !matches!(event.stage.as_str(), "node-down-hold" | "node-down-write")
                || event.status != RunEventStatus::Failed
        }),
        "run-events.jsonl records a failed node-down step"
    );

    validate_write_probe_artifacts_after(
        NODE_DOWN_WRITE_PROBE,
        artifacts,
        metadata,
        identity,
        events,
        bucket,
        post_recovery_object_count(workload_object_count),
        hold.started_at_ms,
        "crash-recovery-boundary",
    )?;
    let report = read_json::<PostRecoveryWriteReport>(required(
        artifacts,
        NODE_DOWN_WRITE_REPORT_ARTIFACT,
    )?)?;
    ensure!(
        hold.contains(report.started_at_ms, report.completed_at_ms)
            && report.started_at_ms >= probes_allowed_from_ms,
        "{NODE_DOWN_WRITE_REPORT_ARTIFACT} ran outside the post-detection part of the node-down hold"
    );
    Ok(())
}

fn validate_dm_crash_artifacts(
    root: &Path,
    case_name: &str,
    events: &[RunEvent],
    evidence: &FaultEvidenceArtifact,
    scenario: &str,
    run_id: &str,
    bucket: &str,
) -> Result<()> {
    ensure!(
        events.iter().any(|event| {
            event.stage == "crash-recovery-boundary"
                && event.status == RunEventStatus::Succeeded
                && event.scenario == scenario
                && event.run_id == run_id
        }),
        "run-events.jsonl is missing a successful crash-recovery-boundary event for scenario {scenario:?} run {run_id:?}"
    );
    let crash_window = read_json::<CrashWindowEvidenceArtifact>(&locate_artifact(
        root,
        case_name,
        "crash-window-evidence.json",
    )?)?;
    ensure!(
        crash_window.scenario == scenario
            && crash_window.run_id == run_id
            && crash_window.committed_versioned_mutations > 0
            && !crash_window.trigger_operation_id.is_empty()
            && !crash_window.trigger_version_id.is_empty()
            && !crash_window.trigger_key.is_empty()
            && crash_window.trigger_acknowledged_at_ms >= crash_window.fault_active_at_ms
            && crash_window.trigger_acknowledged_at_ms <= crash_window.crash_boundary_started_at_ms
            && crash_window.ack_to_crash_boundary_ms
                == crash_window
                    .crash_boundary_started_at_ms
                    .saturating_sub(crash_window.trigger_acknowledged_at_ms),
        "crash-window-evidence.json does not prove a versioned mutation ACK before the crash boundary"
    );
    ensure!(
        evidence.fault_active_at_ms == Some(crash_window.fault_active_at_ms),
        "crash-window-evidence.json fault_active_at_ms does not match fault-evidence.json"
    );

    let history =
        read_jsonl::<OperationRecord>(&locate_artifact(root, case_name, "history.jsonl")?)?;
    let committed = history
        .iter()
        .filter(|record| {
            is_committed_crash_window_mutation(
                record,
                scenario,
                bucket,
                crash_window.fault_active_at_ms,
                crash_window.crash_boundary_started_at_ms,
            )
        })
        .collect::<Vec<_>>();
    ensure!(
        committed.len() == crash_window.committed_versioned_mutations,
        "crash-window-evidence.json committed mutation count {} does not match history.jsonl count {}",
        crash_window.committed_versioned_mutations,
        committed.len()
    );
    let trigger = committed
        .iter()
        .find(|record| record.id == crash_window.trigger_operation_id)
        .context("history.jsonl does not contain the declared crash trigger operation")?;
    ensure!(
        trigger.kind == crash_window.trigger_kind
            && trigger.key.as_deref() == Some(crash_window.trigger_key.as_str())
            && trigger.version_id.as_deref() == Some(crash_window.trigger_version_id.as_str())
            && trigger.ended_at_ms == crash_window.trigger_acknowledged_at_ms,
        "crash-window-evidence.json trigger fields do not match history.jsonl"
    );
    let latest = committed
        .iter()
        .max_by_key(|record| record.ended_at_ms)
        .context("history.jsonl does not contain a committed crash-window mutation")?;
    ensure!(
        latest.id == crash_window.trigger_operation_id,
        "crash-window-evidence.json trigger operation is not the last acknowledged mutation before the crash boundary"
    );

    let boundary = read_json::<DmCrashBoundaryArtifact>(&locate_artifact(
        root,
        case_name,
        "dm-crash-boundary.json",
    )?)?;
    ensure!(
        boundary.scenario == scenario
            && boundary.run_id == run_id
            && boundary.started_at_ms == crash_window.crash_boundary_started_at_ms
            && boundary.filesystem_unmounted
            && boundary.mapper_mounts_absent
            && !boundary.mount_before.canonical_source.is_empty()
            && !boundary.mount_before.filesystem.is_empty()
            && !boundary.mount_before.options.is_empty()
            && boundary.completed_at_ms >= boundary.started_at_ms
            && boundary
                .fault
                .table
                .split_whitespace()
                .any(|field| field == "drop_writes"),
        "dm-crash-boundary.json must prove the filesystem was unmounted while drop_writes was active"
    );
    ensure!(
        evidence
            .workload_ended_at_ms
            .is_some_and(|ended| ended <= boundary.started_at_ms)
            && evidence
                .fault_delete_started_at_ms
                .is_some_and(|started| started >= boundary.completed_at_ms),
        "dm-crash-boundary.json timestamps do not fit between workload completion and fault deletion"
    );
    if let Some(replacement_uid) = &boundary.replacement_pod_uid {
        ensure!(
            replacement_uid != &boundary.old_pod_uid,
            "dm-crash-boundary.json replacement Pod UID must differ from the deleted Pod UID"
        );
    }

    let recovered = read_json::<DmCrashRecoveryArtifact>(&locate_artifact(
        root,
        case_name,
        "dm-crash-recovered.json",
    )?)?;
    ensure!(
        recovered.scenario == scenario
            && recovered.run_id == run_id
            && recovered.recovered_at_ms >= boundary.completed_at_ms
            && recovered.taint_removed
            && !recovered.mount.source.is_empty()
            && !recovered.mount.canonical_source.is_empty()
            && !recovered.mount.filesystem.is_empty()
            && recovered.mount.canonical_source == boundary.mount_before.canonical_source
            && recovered.mount.filesystem == boundary.mount_before.filesystem
            && recovered.mount.options == boundary.mount_before.options
            && normalize_dm_table(&recovered.fault.table)
                == normalize_dm_table(&recovered.expected_table)
            && drop_writes_table_matches_recovery(&boundary.fault.table, &recovered.expected_table,)
            && !recovered
                .fault
                .table
                .split_whitespace()
                .any(|field| field == "drop_writes"),
        "dm-crash-recovered.json must prove taint removal, remount, and healthy-table recovery"
    );

    let before = evidence
        .pods_before
        .iter()
        .find(|pod| pod.uid == boundary.old_pod_uid)
        .context("fault-evidence.json does not contain the DM target Pod UID before crash")?;
    ensure!(
        evidence
            .pods_after
            .iter()
            .any(|pod| pod.name == before.name && pod.uid != before.uid),
        "fault-evidence.json does not prove replacement of the DM target Pod after crash recovery"
    );
    Ok(())
}

fn is_committed_crash_window_mutation(
    record: &OperationRecord,
    scenario: &str,
    bucket: &str,
    fault_active_at_ms: u64,
    crash_boundary_started_at_ms: u64,
) -> bool {
    record.scenario == scenario
        && record.bucket == bucket
        && record.outcome == OperationOutcome::Ok
        && record.durability_cohort == Some(DurabilityCohort::FaultActive)
        && matches!(
            record.kind,
            OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
        )
        && record.version_id.is_some()
        && record.ended_at_ms >= fault_active_at_ms
        && record.ended_at_ms <= crash_boundary_started_at_ms
}

fn drop_writes_table_matches_recovery(fault_table: &str, recovery_table: &str) -> bool {
    let fault = fault_table.split_whitespace().collect::<Vec<_>>();
    let recovery = recovery_table.split_whitespace().collect::<Vec<_>>();
    recovery.len() == 5
        && recovery[2] == "linear"
        && fault.len() == 9
        && fault[0] == recovery[0]
        && fault[1] == recovery[1]
        && fault[2] == "flakey"
        && fault[3] == recovery[3]
        && fault[4] == recovery[4]
        && fault[5] == "0"
        && fault[6] == "86400"
        && fault[7] == "1"
        && fault[8] == "drop_writes"
}

fn normalize_dm_table(table: &str) -> String {
    table.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn locate_required_artifacts(
    root: &Path,
    case_name: &str,
    scenario: &str,
) -> Result<BTreeMap<String, PathBuf>> {
    let mut artifacts = BTreeMap::new();
    for name in FaultRunArtifactSpec::required_names_for_scenario(scenario) {
        let path = locate_artifact(root, case_name, &name)
            .with_context(|| format!("locate required artifact {name} under {}", root.display()))?;
        artifacts.insert(name, path);
    }
    Ok(artifacts)
}

fn validate_conditional_recovery_stability_artifact(
    root: &Path,
    case_name: &str,
    scenario: &str,
    planned_run_id: Option<&str>,
) -> Result<()> {
    let Some(events_path) = optional_artifact(root, case_name, "run-events.jsonl")? else {
        return Ok(());
    };
    let events = read_jsonl::<RunEvent>(&events_path)?;
    let should_validate = events.iter().any(|event| {
        (event.stage == "checker-pre-recommit" && event.status == RunEventStatus::Failed)
            || event.stage == "recovery-stability-reread"
    });
    if !should_validate {
        return Ok(());
    }

    let recovery_path = locate_artifact(root, case_name, "recovery-stability-report.json")
        .with_context(|| "locate conditional artifact recovery-stability-report.json")?;
    let failure_summary_path = locate_artifact(root, case_name, "failure-summary.json")
        .with_context(|| "locate conditional artifact failure-summary.json")?;
    let recovery = read_json::<RecoveryStabilityReport>(&recovery_path)?;
    validate_recovery_stability_report(&recovery)?;
    if let Some(run_id) = planned_run_id {
        ensure!(
            recovery.scenario.as_deref() == Some(scenario)
                && recovery.run_id.as_deref() == Some(run_id)
                && events
                    .iter()
                    .all(|event| event.scenario == scenario && event.run_id == run_id),
            "conditional recovery artifacts do not match the planned attempt"
        );
    }
    let failure_summary = read_json::<FailureSummary>(&failure_summary_path)?;
    if let Some(run_id) = planned_run_id {
        ensure!(
            failure_summary.scenario == scenario
                && failure_summary.run_id.as_deref() == Some(run_id),
            "conditional failure-summary.json identity does not match the planned attempt"
        );
    }
    ensure!(
        failure_summary.classification == recovery.classification.as_str(),
        "failure-summary.json classification {:?} does not match recovery-stability-report.json classification {:?}",
        failure_summary.classification,
        recovery.classification.as_str()
    );
    ensure!(
        failure_summary.stage == "checker-pre-recommit"
            || failure_summary.stage == "checker-pre-recommit-verdict",
        "failure-summary.json stage {:?} is not a pre-recommit recovery-stability stage",
        failure_summary.stage
    );
    ensure!(
        !failure_summary.scenario.trim().is_empty() && !failure_summary.message.trim().is_empty(),
        "failure-summary.json must include non-empty scenario and message"
    );
    validate_failure_summary_v2_fields(
        &failure_summary,
        Some(failure_summary_reference_root(root)),
        Some(&failure_summary_path),
    )?;
    validate_recovery_failure_summary_fields(&failure_summary, &recovery)?;
    Ok(())
}

pub(crate) fn validate_expected_failure_artifacts(
    suite_root: &Path,
    case_dir: &Path,
    attempt_run_id: &str,
    scenario: &str,
    case_name: &str,
    attempt_started_at_ms: u64,
    evaluated_at_ms: u64,
) -> Result<ExpectedFailureArtifactReport> {
    ensure!(
        attempt_run_id
            .strip_prefix("run-")
            .and_then(|id| Uuid::parse_str(id).ok())
            .is_some(),
        "expected failure requires a valid planned attempt runId"
    );
    let suite_root = fs::canonicalize(suite_root)
        .with_context(|| format!("canonicalize suite artifact root {}", suite_root.display()))?;
    let case_dir = fs::canonicalize(case_dir).with_context(|| {
        format!(
            "canonicalize case artifact directory {}",
            case_dir.display()
        )
    })?;
    ensure!(
        case_dir.starts_with(&suite_root),
        "case artifact directory {} is outside suite artifact root {}",
        case_dir.display(),
        suite_root.display()
    );
    ensure!(
        attempt_started_at_ms <= evaluated_at_ms,
        "expected-failure evaluation window is invalid"
    );

    let summary_path = bound_case_artifact(&case_dir, "failure-summary.json")?;
    let summary_raw = fs::read_to_string(&summary_path)
        .with_context(|| format!("reading JSON artifact {}", summary_path.display()))?;
    let summary = serde_json::from_str::<FailureSummary>(&summary_raw)
        .with_context(|| format!("parsing JSON artifact {}", summary_path.display()))?;
    summary.validate_classification_projection()?;
    let run_spec = read_json::<ExpectedFailureRunSpecIdentity>(&bound_case_artifact(
        &case_dir,
        "run-spec.json",
    )?)?;
    ensure!(
        run_spec.scenario.detector.as_ref()
            == Some(&scenarios::scenario_spec(scenario)?.detector.contract()),
        "expected failure run-spec.json detector contract does not match the scenario"
    );
    ensure!(
        summary.schema_version == 2,
        "expected failure requires failure-summary.json schema_version 2, got {}",
        summary.schema_version
    );
    validate_failure_summary_v2_fields(&summary, Some(&suite_root), Some(&summary_path))?;
    ensure!(
        summary.scenario == scenario,
        "failure-summary.json scenario {:?} does not match current attempt {:?}",
        summary.scenario,
        scenario
    );
    ensure!(
        summary.run_id.as_deref() == Some(attempt_run_id),
        "failure-summary.json run_id {:?} does not match planned attempt {:?}",
        summary.run_id,
        attempt_run_id
    );
    ensure!(
        summary.case_name.as_deref() == Some(case_name),
        "failure-summary.json case_name {:?} does not match current attempt {:?}",
        summary.case_name,
        case_name
    );
    let observed_at_ms = summary
        .observed_at_ms
        .context("expected failure requires failure-summary.json observed_at_ms")?;
    ensure!(
        (attempt_started_at_ms..=evaluated_at_ms).contains(&observed_at_ms),
        "failure-summary.json observed_at_ms {observed_at_ms} is outside current attempt window {attempt_started_at_ms}..={evaluated_at_ms}"
    );
    ensure!(
        summary.phase.is_some(),
        "expected failure requires failure-summary.json phase"
    );
    ensure!(
        summary.responsibility_domain.is_some(),
        "expected failure requires failure-summary.json responsibility_domain"
    );
    ensure!(
        summary.s3_model_classification.as_deref() == Some(summary.classification.as_str())
            && summary.run_failure_reason.is_none(),
        "expected failure requires a complete product S3-model classification projection"
    );
    ensure!(
        summary.verdict == FailureVerdict::Failed,
        "expected failure requires failure-summary.json verdict failed"
    );
    ensure!(
        !summary.primary_evidence_refs.is_empty(),
        "expected failure requires primary evidence refs"
    );

    let mut referenced = BTreeMap::new();
    for evidence_ref in &summary.primary_evidence_refs {
        let relative = Path::new(evidence_ref);
        ensure!(
            relative.components().count() > 1,
            "expected failure requires suite-root-relative evidence refs"
        );
        let evidence_path = fs::canonicalize(suite_root.join(relative)).with_context(|| {
            format!(
                "canonicalize expected-failure evidence ref {:?}",
                evidence_ref
            )
        })?;
        ensure!(
            evidence_path.parent() == Some(case_dir.as_path()),
            "expected-failure evidence ref {:?} does not belong to current case directory {}",
            evidence_ref,
            case_dir.display()
        );
        let file_name = evidence_path
            .file_name()
            .and_then(|name| name.to_str())
            .context("expected-failure evidence ref has no UTF-8 file name")?;
        referenced.insert(file_name.to_string(), evidence_path);
    }

    referenced
        .get("fault-evidence.json")
        .context("expected failure requires fault-evidence.json as primary evidence")?;
    referenced
        .get("run-events.jsonl")
        .context("expected failure requires run-events.jsonl as primary evidence")?;

    let disruption_evidence = validate_failed_attempt_disruption_evidence(
        &suite_root,
        &case_dir,
        attempt_run_id,
        scenario,
        case_name,
        attempt_started_at_ms,
        evaluated_at_ms,
    )?;
    ensure!(
        disruption_evidence.run_failed,
        "run-events.jsonl does not prove the current attempt failed"
    );
    let events =
        read_jsonl::<RunEvent>(referenced.get("run-events.jsonl").expect("required events"))?;
    ensure!(
        !has_event(&events, "run", RunEventStatus::Succeeded)
            && events.iter().all(|event| {
                event.status != RunEventStatus::Failed
                    || matches!(
                        event.stage.as_str(),
                        "run" | "checker-pre-recommit" | "checker-final"
                    )
            }),
        "expected failure contains a conflicting run result or non-checker failure"
    );

    validate_expected_failure_signal(&summary, &referenced, scenario, attempt_run_id)?;

    Ok(ExpectedFailureArtifactReport {
        failure_summary: summary_path
            .strip_prefix(&suite_root)
            .context("failure-summary.json is outside suite artifact root")?
            .display()
            .to_string(),
        summary,
        client_disruptions: disruption_evidence.client_disruptions,
    })
}

fn validate_expected_failure_signal(
    summary: &FailureSummary,
    referenced: &BTreeMap<String, PathBuf>,
    scenario: &str,
    run_id: &str,
) -> Result<()> {
    ensure!(
        summary.phase == Some(FailurePhase::Checker),
        "expected product failure must be emitted by the checker phase"
    );
    match summary.stage.as_str() {
        "checker-verdict" => {
            let report =
                read_expected_failure_checker(referenced, "checker-report.json", scenario, run_id)?;
            ensure!(
                !report.passed,
                "checker-report.json passed and cannot support an expected failure"
            );
            let observed = report.failure_classification();
            ensure!(
                observed.as_str() == summary.classification,
                "checker-report.json supports classification {:?}, not {:?}",
                observed.as_str(),
                summary.classification
            );
            ensure!(
                summary.evidence_classifications == [observed.as_str()]
                    && summary.final_list_warning_count == report.final_list_warning_count
                    && summary.list_warnings == report.list_warnings
                    && summary.recovered_within_seconds.is_none(),
                "failure-summary.json evidence fields do not match checker-report.json"
            );
        }
        "checker-pre-recommit-verdict" => {
            let checker = read_expected_failure_checker(
                referenced,
                "checker-pre-recommit-report.json",
                scenario,
                run_id,
            )?;
            ensure!(
                !checker.passed,
                "checker-pre-recommit-report.json passed and cannot support an expected failure"
            );
            let recovery_path = referenced
                .get("recovery-stability-report.json")
                .context("pre-recommit expected failure requires recovery-stability-report.json")?;
            let recovery = read_json::<RecoveryStabilityReport>(recovery_path)?;
            validate_recovery_stability_report(&recovery)?;
            ensure!(
                recovery.scenario.as_deref() == Some(scenario)
                    && recovery.run_id.as_deref() == Some(run_id),
                "recovery-stability-report.json identity does not match the planned attempt"
            );
            ensure!(
                recovery.immediate_passed == checker.passed,
                "recovery-stability-report.json immediate_passed does not match checker-pre-recommit-report.json"
            );
            ensure!(
                recovery.final_list_warning_count == checker.final_list_warning_count
                    && recovery.list_warnings == checker.list_warnings,
                "recovery-stability-report.json LIST evidence does not match checker-pre-recommit-report.json"
            );
            checker::validate_recovery_key_sets(&recovery, &checker).context(
                "recovery-stability-report.json key evidence is not bound to checker evidence",
            )?;
            let observed = checker::classify_recovery_stability(&recovery, &checker);
            ensure!(
                recovery.classification == observed,
                "recovery-stability-report.json claims classification {:?}, but its checker/recovery evidence classifies as {:?}",
                recovery.classification.as_str(),
                observed.as_str()
            );
            ensure!(
                recovery.classification.as_str() == summary.classification,
                "recovery-stability-report.json supports classification {:?}, not {:?}",
                recovery.classification.as_str(),
                summary.classification
            );
            validate_recovery_failure_summary_fields(summary, &recovery)?;
        }
        stage => bail!(
            "expected product failure stage {stage:?} has no supported checker evidence contract"
        ),
    }
    Ok(())
}

fn read_expected_failure_checker(
    referenced: &BTreeMap<String, PathBuf>,
    name: &str,
    scenario: &str,
    run_id: &str,
) -> Result<CheckerReport> {
    let path = referenced
        .get(name)
        .with_context(|| format!("expected failure requires {name}"))?;
    let report = read_json::<CheckerReport>(path)?;
    ensure!(
        report.scenario == scenario && report.run_id == run_id,
        "{name} identity does not match the current attempt"
    );
    if acknowledged_mutation_kind(scenario).is_some() {
        let case_dir = path.parent().context("ACK checker has no case directory")?;
        let history =
            read_jsonl::<OperationRecord>(&bound_case_artifact(case_dir, "history.jsonl")?)?;
        let ack = read_json::<AckTriggeredCrashEvidenceArtifact>(&bound_case_artifact(
            case_dir,
            "ack-to-fault-evidence.json",
        )?)?;
        let spec = read_json::<FaultRunSpec>(&bound_case_artifact(case_dir, "run-spec.json")?)?;
        let evidence = read_json::<FaultEvidenceArtifact>(&bound_case_artifact(
            case_dir,
            "fault-evidence.json",
        )?)?;
        validate_ack_expected_failure_report(&report, &history, &ack, &spec.metadata.bucket)?;
        if name == "checker-report.json" {
            let prechecker = read_json::<CheckerReport>(&bound_case_artifact(
                case_dir,
                "checker-pre-recommit-report.json",
            )?)?;
            validate_checker_report(
                "checker-pre-recommit-report.json",
                &prechecker,
                true,
                &history,
            )?;
            validate_ack_prechecker_boundary(
                &prechecker,
                &history,
                &ack.trigger_operation_id,
                evidence.recovery_ended_at_ms,
            )?;
            validate_ack_checker_phase_chain(
                &prechecker,
                &report,
                &spec.metadata.bucket,
                &history,
            )?;
        } else {
            validate_ack_prechecker_boundary(
                &report,
                &history,
                &ack.trigger_operation_id,
                evidence.recovery_ended_at_ms,
            )?;
        }
    }
    Ok(report)
}

fn validate_ack_expected_failure_report(
    report: &CheckerReport,
    history: &[OperationRecord],
    ack: &AckTriggeredCrashEvidenceArtifact,
    bucket: &str,
) -> Result<()> {
    validate_history_scope_and_order(history, &ack.scenario, &ack.run_id, bucket)?;
    let (prefix, suffix) = checker::validate_checker_audit_receipt(report, history)?;
    let audit = report
        .audit
        .as_ref()
        .context("ACK failure checker has no audit")?;
    ensure!(
        report.scenario == ack.scenario
            && report.run_id == ack.run_id
            && audit.bucket == bucket
            && report.versioning_expected
            && !report.passed,
        "ACK failure checker does not match the versioned run identity or verdict"
    );
    let trigger = prefix
        .iter()
        .find(|record| record.id == ack.trigger_operation_id)
        .context("ACK failure checker prefix lacks the committed trigger")?;
    ensure!(
        trigger.kind == ack_operation_kind(ack.trigger_kind)
            && trigger.key.as_deref() == Some(ack.trigger_key.as_str())
            && trigger.version_id.as_deref() == Some(ack.trigger_version_id.as_str())
            && trigger.outcome == OperationOutcome::Ok,
        "ACK failure checker trigger does not match its authenticated history"
    );
    validate_ack_quiet_gap(
        history,
        trigger,
        ack.crash_boundary_started_at_ms,
        ack.crash_boundary_next_sequence,
    )?;
    let protected_history = &prefix[..prefix
        .iter()
        .position(|record| record.id == trigger.id)
        .context("ACK trigger disappeared from its authenticated prefix")?
        + 1];
    let data_signal = ack_data_version_failure_signal(report, protected_history, suffix, trigger)?;
    let current_signal = ack_current_get_failure_signal(report, suffix, trigger)?;
    let listing_signal =
        ack_version_listing_failure_signal(report, protected_history, suffix, trigger)?;
    ensure!(
        data_signal || current_signal || listing_signal,
        "ACK failure classification is not supported by the authenticated protected-key observations"
    );
    Ok(())
}

fn ack_data_version_failure_signal(
    report: &CheckerReport,
    prefix: &[OperationRecord],
    suffix: &[OperationRecord],
    trigger: &OperationRecord,
) -> Result<bool> {
    let audit = report
        .audit
        .as_ref()
        .context("ACK failure checker has no audit")?;
    let mut proven = false;
    for version in prefix.iter().filter(|record| {
        record.key == trigger.key
            && record.outcome == OperationOutcome::Ok
            && matches!(
                record.kind,
                OperationKind::Put | OperationKind::CompleteMultipartUpload
            )
    }) {
        ensure!(
            version
                .value_sha256
                .as_ref()
                .is_some_and(|hash| !hash.is_empty())
                && version.size_bytes.is_some()
                && version
                    .http_status
                    .is_some_and(|status| (200..300).contains(&status)),
            "protected ACK data version lacks a complete committed payload receipt"
        );
        let reference = operation_version_reference(version)
            .context("protected ACK data version has no identity")?;
        let gets = suffix
            .iter()
            .filter(|record| {
                record.kind == OperationKind::Get
                    && record.key == version.key
                    && record.version_id == version.version_id
            })
            .collect::<Vec<_>>();
        ensure!(
            gets.len() == 1 && gets[0].range.is_none(),
            "ACK failure needs exactly one full GET per protected data version"
        );
        let get = gets[0];
        let checks = audit
            .data_version_checks
            .iter()
            .filter(|check| {
                Some(check.key.as_str()) == version.key.as_deref()
                    && Some(check.version_id.as_str()) == version.version_id.as_deref()
            })
            .collect::<Vec<_>>();
        ensure!(
            checks.len() == 1
                && Some(checks[0].expected_sha256.as_str()) == version.value_sha256.as_deref()
                && checks[0].observed_sha256 == get.value_sha256
                && checks[0].outcome == get.outcome
                && checks[0].http_status == get.http_status,
            "ACK data-version audit does not match the protected version GET"
        );
        proven |= match report.failure_classification() {
            RecoveryStabilityClassification::CommittedVersionMissing => {
                get.outcome == OperationOutcome::NotFound
                    && get.http_status == Some(404)
                    && report.missing_committed_versions.contains(&reference)
            }
            RecoveryStabilityClassification::VersionHashMismatch => {
                get.outcome == OperationOutcome::Ok
                    && get.http_status == Some(200)
                    && get.value_sha256.is_some()
                    && (get.value_sha256 != version.value_sha256
                        || get.size_bytes != version.size_bytes)
                    && report
                        .version_hash_mismatches
                        .iter()
                        .any(|item| item.starts_with(&format!("{reference}:")))
            }
            RecoveryStabilityClassification::CommittedVersionUnavailable => {
                matches!(
                    get.outcome,
                    OperationOutcome::Failed
                        | OperationOutcome::Timeout
                        | OperationOutcome::Unknown
                ) && get.value_sha256.is_none()
                    && get.size_bytes.is_none()
                    && get.error.as_ref().is_some_and(|error| !error.is_empty())
                    && report
                        .unavailable_committed_versions
                        .iter()
                        .any(|item| item.starts_with(&format!("{reference}:")))
            }
            _ => false,
        };
    }
    Ok(proven)
}

fn ack_current_get_failure_signal(
    report: &CheckerReport,
    suffix: &[OperationRecord],
    trigger: &OperationRecord,
) -> Result<bool> {
    let key = trigger.key.as_deref().context("ACK trigger has no key")?;
    let gets = suffix
        .iter()
        .filter(|record| {
            record.kind == OperationKind::Get
                && record.key == trigger.key
                && record.version_id.is_none()
        })
        .collect::<Vec<_>>();
    ensure!(
        gets.len() == 1 && gets[0].range.is_none(),
        "ACK checker must capture exactly one full current GET for its trigger key"
    );
    let get = gets[0];
    let is_delete = trigger.kind == OperationKind::Delete;
    let successful_body = get.outcome == OperationOutcome::Ok
        && get.http_status == Some(200)
        && get.value_sha256.is_some()
        && get.size_bytes.is_some();
    Ok(match report.failure_classification() {
        RecoveryStabilityClassification::DeletedObjectResurrected =>
            is_delete && successful_body
                && report.resurrected_deleted_objects.iter().any(|item| item.starts_with(&format!("{key}:"))),
        RecoveryStabilityClassification::DataCorruption =>
            !is_delete && successful_body
                && (get.value_sha256 != trigger.value_sha256 || get.size_bytes != trigger.size_bytes)
                && report.hash_mismatches.iter().any(|item| item.starts_with(&format!("{key}:"))),
        RecoveryStabilityClassification::CommittedObjectUnavailable => !is_delete && (
            (get.outcome == OperationOutcome::NotFound && get.http_status == Some(404)
                && report.missing_committed_objects.iter().any(|item| item == key))
            || report.unavailable_committed_objects.iter().chain(&report.unknown_committed_read_failures).any(|failure| {
                matches!(failure, checker::CommittedReadFailure::Observed {
                    key: observed_key, outcome, http_status, error, unexpected_body_bytes: None,
                } if observed_key == key && *outcome == get.outcome && *http_status == get.http_status
                    && *error == get.error && matches!(get.outcome, OperationOutcome::Failed | OperationOutcome::Timeout | OperationOutcome::Unknown))
            })),
        _ => false,
    })
}

fn ack_version_listing_failure_signal(
    report: &CheckerReport,
    prefix: &[OperationRecord],
    suffix: &[OperationRecord],
    trigger: &OperationRecord,
) -> Result<bool> {
    let audit = report
        .audit
        .as_ref()
        .context("ACK failure checker has no audit")?;
    let prefix_key = crate::fault::workload::ObjectSpec::key_prefix(&report.run_id);
    let lists = suffix
        .iter()
        .filter(|record| {
            record.kind == OperationKind::ListVersions
                && record.key.as_deref() == Some(prefix_key.as_str())
        })
        .collect::<Vec<_>>();
    ensure!(
        lists.len() == 1,
        "ACK checker must capture exactly one ListObjectVersions receipt"
    );
    let list = lists[0];
    let completed = list.outcome == OperationOutcome::Ok && list.http_status == Some(200);
    ensure!(
        audit.list_object_versions_completed == Some(completed),
        "ACK version-list completion audit does not match its receipt"
    );
    let entries = if completed {
        list.listed_versions
            .as_deref()
            .context("ACK version listing lacks captured entries")?
    } else {
        &[]
    };
    let mut proven = false;
    for version in prefix.iter().filter(|record| {
        record.key == trigger.key
            && record.outcome == OperationOutcome::Ok
            && matches!(
                record.kind,
                OperationKind::Put | OperationKind::CompleteMultipartUpload | OperationKind::Delete
            )
    }) {
        let reference = operation_version_reference(version)
            .context("protected ACK version has no identity")?;
        let is_marker = version.kind == OperationKind::Delete;
        let visible = entries.iter().any(|entry| {
            Some(entry.key.as_str()) == version.key.as_deref()
                && entry.version_id == version.version_id
                && entry.is_delete_marker == is_marker
        });
        if is_marker {
            let checks = audit
                .delete_marker_checks
                .iter()
                .filter(|check| {
                    Some(check.key.as_str()) == version.key.as_deref()
                        && Some(check.version_id.as_str()) == version.version_id.as_deref()
                })
                .collect::<Vec<_>>();
            ensure!(
                checks.len() == 1 && checks[0].visible_in_list_object_versions == visible,
                "ACK marker audit does not match the protected version listing"
            );
        }
        proven |=
            completed
                && !visible
                && match report.failure_classification() {
                    RecoveryStabilityClassification::DeleteMarkerMissing => is_marker
                        && report.missing_committed_delete_markers.contains(&format!(
                            "{reference}: committed delete marker missing from ListObjectVersions"
                        )),
                    RecoveryStabilityClassification::CommittedVersionMissing => {
                        !is_marker
                            && report.missing_committed_versions.contains(&format!(
                                "{reference}: committed version missing from ListObjectVersions"
                            ))
                    }
                    _ => false,
                };
    }
    if completed
        && report.failure_classification()
            == RecoveryStabilityClassification::DeleteMarkerLineageIncomplete
    {
        let latest = entries
            .iter()
            .filter(|entry| Some(entry.key.as_str()) == trigger.key.as_deref() && entry.is_latest)
            .collect::<Vec<_>>();
        let key = trigger.key.as_deref().context("ACK trigger has no key")?;
        proven |= (latest.len() != 1
            || latest[0].version_id != trigger.version_id
            || latest[0].is_delete_marker != (trigger.kind == OperationKind::Delete))
            && report
                .delete_marker_lineage_incomplete
                .iter()
                .any(|item| item.starts_with(&format!("{key}:")));
    }
    Ok(proven)
}

fn failure_summary_reference_root(validation_root: &Path) -> &Path {
    validation_root
        .parent()
        .filter(|parent| {
            parent.join("suite-plan.json").is_file() && parent.join("suite-summary.json").is_file()
        })
        .unwrap_or(validation_root)
}

fn validate_recovery_failure_summary_fields(
    summary: &FailureSummary,
    recovery: &RecoveryStabilityReport,
) -> Result<()> {
    ensure!(
        summary.verdict == FailureVerdict::Failed,
        "failure-summary.json verdict must be failed for recovery-stability failures"
    );
    ensure!(
        summary.evidence_classifications == recovery.evidence_classifications(),
        "failure-summary.json evidence_classifications {:?} do not match recovery-stability-report.json evidence classifications {:?}",
        summary.evidence_classifications,
        recovery.evidence_classifications()
    );
    ensure!(
        summary.final_list_warning_count == recovery.final_list_warning_count
            && summary.list_warnings == recovery.list_warnings,
        "failure-summary.json LIST warning fields do not match recovery-stability-report.json"
    );
    ensure!(
        summary.classification == recovery.classification.as_str(),
        "failure-summary.json classification must match recovery-stability-report.json"
    );
    summary.validate_classification_projection()?;
    match recovery.classification {
        RecoveryStabilityClassification::RecoveryTailReadLatency => ensure!(
            summary.recovered_within_seconds == recovery.recovered_within_seconds
                && summary.recovered_within_seconds.is_some(),
            "recovery_tail_read_latency failure-summary.json recovered_within_seconds must match recovery-stability-report.json"
        ),
        RecoveryStabilityClassification::AmbiguousWriteMaterialized => ensure!(
            summary.recovered_within_seconds.is_none(),
            "ambiguous_write_materialized failure-summary.json must not claim recovery"
        ),
        _ => {}
    }

    Ok(())
}

fn validate_recovery_stability_report(report: &RecoveryStabilityReport) -> Result<()> {
    ensure_sorted_unique(
        &report.reread_attempted_keys,
        "recovery-stability-report.json reread_attempted_keys",
    )?;
    ensure_sorted_unique(
        &report.reread_recovered_keys,
        "recovery-stability-report.json reread_recovered_keys",
    )?;
    ensure_sorted_unique(
        &report.still_unavailable_keys,
        "recovery-stability-report.json still_unavailable_keys",
    )?;
    ensure_sorted_unique(
        &report.data_corruption_evidence,
        "recovery-stability-report.json data_corruption_evidence",
    )?;
    ensure_sorted_unique(
        &report.classification_evidence,
        "recovery-stability-report.json classification_evidence",
    )?;
    ensure_sorted_unique(
        &report.ambiguous_write_evidence,
        "recovery-stability-report.json ambiguous_write_evidence",
    )?;
    ensure_sorted_unique(
        &report.list_warnings,
        "recovery-stability-report.json list_warnings",
    )?;
    ensure!(
        report.final_list_warning_count >= report.list_warnings.len(),
        "recovery-stability-report.json final_list_warning_count must cover sampled list_warnings"
    );
    ensure!(
        checker::recovery_key_sets_are_consistent(report),
        "recovery-stability-report.json reread key sets are inconsistent"
    );
    match report.classification {
        RecoveryStabilityClassification::RecoveryTailReadLatency => {
            ensure!(
                !report.reread_attempted_keys.is_empty()
                    && report.reread_attempted_keys == report.reread_recovered_keys
                    && report.still_unavailable_keys.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.ambiguous_write_evidence.is_empty()
                    && report.harness_errors.is_empty(),
                "recovery_tail_read_latency requires all attempted keys to be recovered without hard failures"
            );
        }
        RecoveryStabilityClassification::CommittedObjectUnavailable => {
            ensure!(
                !report.still_unavailable_keys.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.harness_errors.is_empty(),
                "committed_object_unavailable requires still_unavailable_keys without higher-priority recovery failures"
            );
        }
        classification @ (RecoveryStabilityClassification::CommittedVersionMissing
        | RecoveryStabilityClassification::VersionHashMismatch
        | RecoveryStabilityClassification::DeleteMarkerMissing
        | RecoveryStabilityClassification::DeletedObjectResurrected
        | RecoveryStabilityClassification::ListedKeyUnreadable
        | RecoveryStabilityClassification::UnexpectedListedObject) => {
            ensure!(
                report
                    .classification_evidence
                    .iter()
                    .any(|item| classification.matches_classification_evidence(item)),
                "precise checker correctness classification {:?} requires matching classification_evidence",
                classification
            );
        }
        RecoveryStabilityClassification::CommittedVersionUnavailable => {
            ensure!(
                report
                    .classification_evidence
                    .iter()
                    .any(|item| report.classification.matches_classification_evidence(item))
                    && !report.still_unavailable_keys.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty(),
                "committed_version_unavailable requires exact-version availability evidence without proven data loss"
            );
        }
        classification @ (RecoveryStabilityClassification::DeleteMarkerLineageIncomplete
        | RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite
        | RecoveryStabilityClassification::MultipartUploadLineageIncomplete) => {
            ensure!(
                report
                    .classification_evidence
                    .iter()
                    .any(|item| classification.matches_classification_evidence(item))
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.still_unavailable_keys.is_empty(),
                "incomplete version-lineage classification requires classification_evidence without loss, corruption, or availability evidence"
            );
        }
        RecoveryStabilityClassification::ListUnavailableOrUnknown => {
            ensure!(
                report.final_list_warning_count > 0
                    && report.still_unavailable_keys.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.ambiguous_write_evidence.is_empty()
                    && report.harness_errors.is_empty(),
                "list_unavailable_or_unknown requires LIST-only availability evidence without harder recovery failures"
            );
        }
        RecoveryStabilityClassification::DataCorruption => {
            ensure!(
                !report.hash_mismatches.is_empty() || !report.data_corruption_evidence.is_empty(),
                "data_corruption requires hash_mismatches or data_corruption_evidence"
            );
        }
        RecoveryStabilityClassification::AmbiguousWriteMaterialized => {
            ensure!(
                !report.ambiguous_write_evidence.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty()
                    && report.still_unavailable_keys.is_empty()
                    && report.harness_errors.is_empty(),
                "ambiguous_write_materialized requires only ambiguous_write_evidence without harder recovery failures"
            );
        }
        RecoveryStabilityClassification::HarnessError => {
            ensure!(
                !report.harness_errors.is_empty()
                    && report.hash_mismatches.is_empty()
                    && report.data_corruption_evidence.is_empty(),
                "harness_error requires harness_errors without data-corruption evidence"
            );
        }
    }
    Ok(())
}

fn ensure_sorted_unique(values: &[String], field: &str) -> Result<()> {
    for pair in values.windows(2) {
        ensure!(
            pair[0] < pair[1],
            "{field} must be sorted and contain no duplicates"
        );
    }
    Ok(())
}

fn locate_artifact(root: &Path, case_name: &str, name: &str) -> Result<PathBuf> {
    for candidate in [root.join(case_name).join(name), root.join(name)] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    recursive_find(root, name)?.with_context(|| format!("required artifact {name} is missing"))
}

fn optional_artifact(root: &Path, case_name: &str, name: &str) -> Result<Option<PathBuf>> {
    for candidate in [root.join(case_name).join(name), root.join(name)] {
        if candidate.is_file() {
            return Ok(Some(candidate));
        }
    }
    recursive_find(root, name)
}

fn recursive_find(root: &Path, name: &str) -> Result<Option<PathBuf>> {
    if !root.exists() {
        return Ok(None);
    }
    for entry in fs::read_dir(root).with_context(|| format!("read dir {}", root.display()))? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && path.file_name().and_then(|file| file.to_str()) == Some(name) {
            return Ok(Some(path));
        }
        if path.is_dir()
            && let Some(found) = recursive_find(&path, name)?
        {
            return Ok(Some(found));
        }
    }
    Ok(None)
}

fn required<'a>(artifacts: &'a BTreeMap<String, PathBuf>, name: &str) -> Result<&'a Path> {
    artifacts
        .get(name)
        .map(PathBuf::as_path)
        .with_context(|| format!("{name} was not located"))
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parse json {}", path.display()))
}

fn read_yaml<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_yaml_ng::from_str(&raw).with_context(|| format!("parse yaml {}", path.display()))
}

fn ensure_json_field_present(path: &Path, pointer: &str, field: &str) -> Result<()> {
    let value = read_json::<Value>(path)?;
    ensure!(
        value.pointer(pointer).is_some(),
        "{field} must be explicitly present"
    );
    Ok(())
}

fn ensure_yaml_field_present(path: &Path, pointer: &str, field: &str) -> Result<()> {
    let value = read_yaml::<Value>(path)?;
    ensure!(
        value.pointer(pointer).is_some(),
        "{field} must be explicitly present"
    );
    Ok(())
}

fn read_jsonl<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut items = Vec::new();
    for (index, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read {} line {}", path.display(), index + 1))?;
        if line.trim().is_empty() {
            continue;
        }
        items.push(
            serde_json::from_str(&line)
                .with_context(|| format!("parse jsonl {} line {}", path.display(), index + 1))?,
        );
    }
    Ok(items)
}

fn has_event(events: &[RunEvent], stage: &str, status: RunEventStatus) -> bool {
    events
        .iter()
        .any(|event| event.stage == stage && event.status == status)
}

fn ensure_nonempty(value: &str, field: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{field} must not be empty");
    Ok(())
}

fn env_string(name: &str, default: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string())
}

fn env_usize(name: &str, default: usize) -> Result<usize> {
    let value = env_string(name, &default.to_string());
    value
        .parse::<usize>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    let value = env_string(name, &default.to_string());
    value
        .parse::<u64>()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn env_bool(name: &str) -> Result<bool> {
    let Ok(value) = std::env::var(name) else {
        return Ok(false);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(false);
    }
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => bail!("{name} must be a boolean: 1/0, true/false, or yes/no"),
    }
}

#[derive(Debug, Deserialize)]
struct RunMetadataArtifact {
    scenario: String,
    run_id: String,
    context: String,
    #[serde(default)]
    namespace: String,
    #[serde(default)]
    tenant: String,
    storage_class: String,
    rustfs_image: String,
    workload_objects: usize,
    workload_concurrency: usize,
    require_client_disruption: bool,
    #[serde(default = "default_recovery_stability_reread_seconds")]
    recovery_stability_reread_seconds: u64,
    /// Configured availability floor; required for availability scenarios,
    /// absent in artifacts written before the contract existed.
    #[serde(default)]
    min_availability_percent: Option<u8>,
}

#[derive(Debug, Deserialize)]
struct ArtifactIdentity {
    #[serde(default)]
    scenario: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FailureSummaryReferenceIdentity {
    #[serde(default)]
    scenario: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    #[serde(default)]
    case_name: Option<String>,
}

fn default_recovery_stability_reread_seconds() -> u64 {
    DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS
}

#[derive(Debug, Clone, Deserialize)]
struct FaultEvidenceArtifact {
    #[serde(default)]
    scenario: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    injected: bool,
    active_during_workload: bool,
    recovered: bool,
    require_client_disruption: bool,
    client_disruptions: usize,
    pods_before: Vec<PodIdentityArtifact>,
    #[serde(default)]
    pods_at_fault_activation: Vec<PodIdentityArtifact>,
    #[serde(default)]
    pods_at_workload_snapshot: Vec<PodIdentityArtifact>,
    #[serde(default)]
    fixed_volume_targets_at_fault_activation: Vec<String>,
    #[serde(default)]
    fixed_volume_targets_at_workload_snapshot: Vec<String>,
    #[serde(default)]
    fixed_volume_containers_at_fault_activation: BTreeMap<String, String>,
    #[serde(default)]
    fixed_volume_containers_at_workload_snapshot: BTreeMap<String, String>,
    pods_after: Vec<PodIdentityArtifact>,
    active_snapshots: Vec<Value>,
    workload_snapshots: Vec<Value>,
    #[serde(default)]
    dm_recovery_snapshot: Option<Value>,
    #[serde(default)]
    fault_prepare_started_at_ms: Option<u64>,
    #[serde(default)]
    fault_apply_started_at_ms: Option<u64>,
    #[serde(default)]
    fault_active_at_ms: Option<u64>,
    #[serde(default)]
    workload_started_at_ms: Option<u64>,
    #[serde(default)]
    workload_ended_at_ms: Option<u64>,
    #[serde(default)]
    fault_delete_started_at_ms: Option<u64>,
    #[serde(default)]
    recovery_started_at_ms: Option<u64>,
    #[serde(default)]
    recovery_ended_at_ms: Option<u64>,
    #[serde(default)]
    quorum_health_before_workload: Option<QuorumHealthObservation>,
    #[serde(default)]
    quorum_health_after_workload: Option<QuorumHealthObservation>,
}

#[derive(Debug, Deserialize)]
struct ExpectedFailureRunSpecIdentity {
    metadata: ExpectedFailureRunMetadataIdentity,
    scenario: ExpectedFailureScenarioIdentity,
}

#[derive(Debug, Deserialize)]
struct ExpectedFailureRunMetadataIdentity {
    name: String,
    run_id: String,
}

#[derive(Debug, Deserialize)]
struct ExpectedFailureScenarioIdentity {
    name: String,
    case_name: String,
    #[serde(default)]
    detector: Option<scenarios::FaultDetectorContract>,
}

#[derive(Debug, Clone, Deserialize)]
struct PodIdentityArtifact {
    name: String,
    uid: String,
}

#[derive(Debug, Deserialize)]
struct CrashWindowEvidenceArtifact {
    scenario: String,
    run_id: String,
    fault_active_at_ms: u64,
    crash_boundary_started_at_ms: u64,
    committed_versioned_mutations: usize,
    trigger_operation_id: String,
    trigger_kind: OperationKind,
    trigger_key: String,
    trigger_version_id: String,
    trigger_acknowledged_at_ms: u64,
    ack_to_crash_boundary_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct AckTriggeredCrashEvidenceArtifact {
    scenario: String,
    run_id: String,
    trigger_operation_id: String,
    trigger_kind: AcknowledgedMutationKind,
    trigger_key: String,
    trigger_version_id: String,
    trigger_acknowledged_at_ms: u64,
    fault_activated_at_ms: u64,
    ack_to_fault_ms: u64,
    max_ack_to_fault_ms: u64,
    crash_boundary_started_at_ms: u64,
    crash_boundary_next_sequence: u64,
    ack_to_crash_boundary_ms: u64,
}

#[derive(Debug, Deserialize)]
struct DmFaultTableArtifact {
    table: String,
}

#[derive(Debug, Deserialize)]
struct DmMountArtifact {
    source: String,
    canonical_source: String,
    filesystem: String,
    options: String,
}

#[derive(Debug, Deserialize)]
struct DmCrashBoundaryArtifact {
    scenario: String,
    run_id: String,
    started_at_ms: u64,
    completed_at_ms: u64,
    old_pod_uid: String,
    replacement_pod_uid: Option<String>,
    filesystem_unmounted: bool,
    mapper_mounts_absent: bool,
    mount_before: DmMountArtifact,
    fault: DmFaultTableArtifact,
}

#[derive(Debug, Deserialize)]
struct DmCrashRecoveryArtifact {
    scenario: String,
    run_id: String,
    recovered_at_ms: u64,
    taint_removed: bool,
    mount: DmMountArtifact,
    expected_table: String,
    fault: DmFaultTableArtifact,
}

#[derive(Debug, Deserialize)]
struct RecommitReportArtifact {
    #[serde(default)]
    scenario: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    attempted: usize,
    committed: usize,
    failed: usize,
    harness_errors: usize,
    attempts: Vec<RecommitAttemptArtifact>,
}

#[derive(Debug, Deserialize)]
struct RecommitAttemptArtifact {
    source_operation_id: String,
    key: String,
    size_bytes: usize,
    sha256: String,
    outcome: Option<OperationOutcome>,
    verify_get_outcome: Option<OperationOutcome>,
    http_status: Option<u16>,
    error: Option<String>,
    harness_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct WorkloadSummaryArtifact {
    #[serde(default)]
    scenario: Option<String>,
    #[serde(default)]
    run_id: Option<String>,
    seed: u64,
    object_count: usize,
    concurrency: usize,
    #[serde(default)]
    recommit_candidates: Option<RecommitCandidateManifestArtifact>,
    recommitted_after_recovery: usize,
    puts: OutcomeCountsArtifact,
    gets: OutcomeCountsArtifact,
    deletes: OutcomeCountsArtifact,
    lists: OutcomeCountsArtifact,
    multipart_completes: OutcomeCountsArtifact,
    multipart_aborts: OutcomeCountsArtifact,
}

#[derive(Debug, Deserialize)]
struct RecommitCandidateManifestArtifact {
    scenario: String,
    run_id: String,
    bucket: String,
    history_record_count: usize,
    history_sha256: String,
    candidates: Vec<RecommitCandidateArtifact>,
}

#[derive(Debug, Deserialize)]
struct RecommitCandidateArtifact {
    source_operation_id: String,
    key: String,
    size_bytes: usize,
    sha256: String,
}

impl WorkloadSummaryArtifact {
    fn require_history_matches(
        &self,
        history: &[OperationRecord],
        scenario: &str,
        bucket: &str,
        cohort: DurabilityCohort,
        plan: &WorkloadPlan,
        run_id: &str,
    ) -> Result<()> {
        let mut projected = [
            OutcomeCountsArtifact::default(),
            OutcomeCountsArtifact::default(),
            OutcomeCountsArtifact::default(),
            OutcomeCountsArtifact::default(),
        ];
        let workload_history = history
            .iter()
            .filter(|record| record.durability_cohort == Some(cohort))
            .collect::<Vec<_>>();
        for record in &workload_history {
            ensure!(
                record.scenario == scenario && record.bucket == bucket,
                "history.jsonl workload record does not match the selected scenario and bucket"
            );
            let index = match record.kind {
                OperationKind::Put => Some(0),
                OperationKind::Get => Some(1),
                OperationKind::Delete => Some(2),
                OperationKind::List => Some(3),
                _ => None,
            };
            if let Some(index) = index {
                projected[index].record(record.outcome);
            }
        }
        let expected = [&self.puts, &self.gets, &self.deletes, &self.lists];
        ensure!(
            projected
                .iter()
                .zip(expected)
                .all(|(actual, expected)| actual == expected),
            "workload-summary.json outcomes do not match workload history.jsonl records"
        );

        validate_multipart_summary_history(self, &workload_history, plan, run_id)?;
        Ok(())
    }

    fn exercised_all_operation_families(&self) -> bool {
        self.puts.total() > 0
            && self.gets.total() > 0
            && self.deletes.total() > 0
            && self.lists.total() > 0
            && self.multipart_completes.total() > 0
            && self.multipart_aborts.total() > 0
    }

    fn disrupted(&self) -> Result<usize> {
        [
            &self.puts,
            &self.gets,
            &self.deletes,
            &self.lists,
            &self.multipart_completes,
            &self.multipart_aborts,
        ]
        .into_iter()
        .try_fold(0usize, |total, counts| {
            total
                .checked_add(counts.disrupted()?)
                .context("workload-summary.json disrupted count overflowed")
        })
    }

    /// The per-family availability the runtime report must contain, rebuilt
    /// through the same constructor and in the same order it emits them.
    fn family_availability(&self) -> Result<Vec<FamilyAvailability>> {
        [
            ("put", &self.puts),
            ("get", &self.gets),
            ("delete", &self.deletes),
            ("list", &self.lists),
            ("multipart_complete", &self.multipart_completes),
            ("multipart_abort", &self.multipart_aborts),
        ]
        .into_iter()
        .map(|(family, counts)| {
            Ok(FamilyAvailability::new(
                family,
                counts.total(),
                counts.disrupted()?,
            ))
        })
        .collect()
    }

    fn require_write_quorum_loss_effect(
        &self,
        history: &[OperationRecord],
        scenario: &str,
        bucket: &str,
        workload_started_at_ms: u64,
        workload_ended_at_ms: u64,
    ) -> Result<()> {
        self.require_rejected_write_mutations(&[
            ("PUT", &self.puts),
            ("DELETE", &self.deletes),
            ("CompleteMultipartUpload", &self.multipart_completes),
        ])?;
        self.require_write_mutation_history_matches(
            history,
            scenario,
            bucket,
            workload_started_at_ms,
            workload_ended_at_ms,
        )
    }

    fn require_typed_write_quorum_loss_effect(
        &self,
        history: &[OperationRecord],
        scenario: &str,
        bucket: &str,
        unavailable_mutations: &[QuorumMutationClass],
        workload_started_at_ms: u64,
        workload_ended_at_ms: u64,
    ) -> Result<()> {
        let mutations = unavailable_mutations
            .iter()
            .map(|mutation| match mutation {
                QuorumMutationClass::PutObject => ("PUT", &self.puts),
                QuorumMutationClass::DeleteMarker => ("DELETE", &self.deletes),
                QuorumMutationClass::MultipartComplete => {
                    ("CompleteMultipartUpload", &self.multipart_completes)
                }
            })
            .collect::<Vec<_>>();
        self.require_rejected_write_mutations(&mutations)?;
        self.require_write_mutation_history_matches(
            history,
            scenario,
            bucket,
            workload_started_at_ms,
            workload_ended_at_ms,
        )
    }

    fn require_rejected_write_mutations(
        &self,
        mutations: &[(&str, &OutcomeCountsArtifact)],
    ) -> Result<()> {
        ensure!(
            mutations.iter().all(|(_, counts)| counts.total() > 0),
            "workload-summary.json did not exercise every mutation selected by the quorum case"
        );
        for (kind, counts) in mutations {
            ensure!(
                counts.ok == 0 && counts.not_found == 0 && counts.disrupted()? > 0,
                "write-quorum-loss {kind} outcomes must all be failed, timed out, or unknown: {counts:?}"
            );
        }
        Ok(())
    }

    fn require_write_mutation_history_matches(
        &self,
        history: &[OperationRecord],
        scenario: &str,
        bucket: &str,
        workload_started_at_ms: u64,
        workload_ended_at_ms: u64,
    ) -> Result<()> {
        for (kind, summary_counts) in [
            (OperationKind::Put, &self.puts),
            (OperationKind::Delete, &self.deletes),
            (
                OperationKind::CompleteMultipartUpload,
                &self.multipart_completes,
            ),
        ] {
            let mut history_counts = OutcomeCountsArtifact::default();
            for record in history.iter().filter(|record| {
                record.scenario == scenario
                    && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                    && record.kind == kind
            }) {
                ensure!(
                    record.bucket == bucket,
                    "fault_active history.jsonl {kind:?} record belongs to unexpected bucket {:?}",
                    record.bucket
                );
                ensure!(
                    record.started_at_ms >= workload_started_at_ms
                        && record.ended_at_ms <= workload_ended_at_ms
                        && record.started_at_ms <= record.ended_at_ms,
                    "fault_active history.jsonl {kind:?} record falls outside the workload window"
                );
                history_counts.record(record.outcome);
            }
            ensure!(
                &history_counts == summary_counts,
                "workload-summary.json {kind:?} outcomes do not match fault_active history.jsonl records"
            );
        }
        Ok(())
    }
}

fn record_key_counts<'a>(
    records: impl Iterator<Item = &'a OperationRecord>,
) -> Result<BTreeMap<String, usize>> {
    let mut counts = BTreeMap::new();
    for record in records {
        let key = record
            .key
            .as_ref()
            .context("planned workload history record lacks an object key")?;
        *counts.entry(key.clone()).or_insert(0) += 1;
    }
    Ok(counts)
}

fn validate_primary_workload_history(
    history: &[&OperationRecord],
    plan: &WorkloadPlan,
    run_id: &str,
) -> Result<()> {
    ensure!(
        history.iter().all(|record| {
            matches!(
                record.kind,
                OperationKind::Put
                    | OperationKind::Get
                    | OperationKind::List
                    | OperationKind::Delete
                    | OperationKind::CreateMultipartUpload
                    | OperationKind::UploadPart
                    | OperationKind::CompleteMultipartUpload
                    | OperationKind::AbortMultipartUpload
            )
        }),
        "history.jsonl contains an operation outside the planned mixed workload"
    );
    let prefilled_count = plan.object_count / 2;
    let mixed_count = plan.object_count - prefilled_count;
    let mut expected_puts = BTreeMap::<String, usize>::new();
    let mut expected_deletes = BTreeMap::<String, usize>::new();
    let mut expected_gets = BTreeMap::<String, usize>::new();
    let mut expected_lists = 0usize;
    for offset in 0..mixed_count {
        let index = prefilled_count + offset;
        let existing_index = plan.existing_object_offset(offset, prefilled_count);
        let existing_key = ObjectSpec::directory_marker_key(run_id, existing_index);
        match plan.operation_mix.operation_at(offset) {
            WorkloadOperation::Put => {
                *expected_puts
                    .entry(ObjectSpec::seeded_key(run_id, index))
                    .or_insert(0) += 1;
            }
            WorkloadOperation::Overwrite => {
                *expected_puts.entry(existing_key).or_insert(0) += 1;
            }
            WorkloadOperation::Get => {
                *expected_gets.entry(existing_key).or_insert(0) += 1;
            }
            WorkloadOperation::List => expected_lists += 1,
            WorkloadOperation::Delete => {
                *expected_deletes.entry(existing_key).or_insert(0) += 1;
            }
            WorkloadOperation::Multipart => {}
        }
    }

    let actual_puts = record_key_counts(
        history
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::Put),
    )?;
    let actual_deletes = record_key_counts(
        history
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::Delete),
    )?;
    ensure!(
        actual_puts == expected_puts && actual_deletes == expected_deletes,
        "history.jsonl does not contain the exact planned PUT/overwrite/DELETE operations"
    );
    let expected_list_prefix = ObjectSpec::key_prefix(run_id);
    ensure!(
        history
            .iter()
            .filter(|record| record.kind == OperationKind::List)
            .count()
            == expected_lists
            && history
                .iter()
                .filter(|record| record.kind == OperationKind::List)
                .all(|record| record.key.as_deref() == Some(expected_list_prefix.as_str())),
        "history.jsonl does not contain the exact planned LIST operations"
    );

    for record in history.iter().copied().filter(|record| {
        record.outcome == OperationOutcome::Ok
            && matches!(record.kind, OperationKind::Put | OperationKind::Delete)
    }) {
        let key = record
            .key
            .as_ref()
            .context("successful workload mutation lacks an object key")?;
        *expected_gets.entry(key.clone()).or_insert(0) += 1;
    }
    for record in history.iter().copied().filter(|record| {
        record.kind == OperationKind::CompleteMultipartUpload
            && record.outcome == OperationOutcome::Ok
    }) {
        let key = record
            .key
            .as_ref()
            .context("successful multipart completion lacks an object key")?;
        *expected_gets.entry(key.clone()).or_insert(0) += 1;
    }
    let actual_gets = record_key_counts(
        history
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::Get),
    )?;
    ensure!(
        actual_gets == expected_gets,
        "history.jsonl does not contain every planned or success-verification GET"
    );
    Ok(())
}

fn validate_multipart_summary_history(
    summary: &WorkloadSummaryArtifact,
    history: &[&OperationRecord],
    plan: &WorkloadPlan,
    run_id: &str,
) -> Result<()> {
    let prefilled_count = plan.object_count / 2;
    let multipart_indices = (0..plan.object_count - prefilled_count)
        .filter(|offset| plan.operation_mix.operation_at(*offset) == WorkloadOperation::Multipart)
        .map(|offset| prefilled_count + offset)
        .collect::<Vec<_>>();
    ensure!(
        summary.multipart_completes.total() == multipart_indices.len()
            && summary.multipart_aborts.total() == multipart_indices.len(),
        "workload-summary.json multipart totals do not match workload-plan.json"
    );
    let complete_keys = multipart_indices
        .iter()
        .map(|index| (ObjectSpec::seeded_key(run_id, *index), *index))
        .collect::<BTreeMap<_, _>>();
    let abort_keys = multipart_indices
        .iter()
        .map(|index| ObjectSpec::seeded_key(run_id, plan.object_count + *index))
        .collect::<BTreeSet<_>>();
    let records_for_key = |key: &str| {
        history
            .iter()
            .copied()
            .filter(|record| record.key.as_deref() == Some(key))
            .collect::<Vec<_>>()
    };
    let ordered_before = |before: &OperationRecord, after: &OperationRecord| {
        before
            .ended_sequence
            .zip(after.started_sequence)
            .is_some_and(|(ended, started)| ended < started)
    };

    let mut projected_completes = OutcomeCountsArtifact::default();
    for (key, index) in &complete_keys {
        let records = records_for_key(key);
        let creates = records
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::CreateMultipartUpload)
            .collect::<Vec<_>>();
        let uploads = records
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::UploadPart)
            .collect::<Vec<_>>();
        let completes = records
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::CompleteMultipartUpload)
            .collect::<Vec<_>>();
        let cleanup_aborts = records
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::AbortMultipartUpload)
            .collect::<Vec<_>>();
        ensure!(
            creates.len() == 1 && completes.len() <= 1 && cleanup_aborts.len() <= 1,
            "history.jsonl does not contain one unambiguous multipart completion sequence for {key:?}"
        );
        let create = creates[0];
        if create.outcome != OperationOutcome::Ok {
            ensure!(
                uploads.is_empty() && completes.is_empty() && cleanup_aborts.is_empty(),
                "history.jsonl continued multipart completion after failed create for {key:?}"
            );
            projected_completes.record(OperationOutcome::Unknown);
            continue;
        }

        let expected_parts = plan.multipart_part_count_at(*index);
        ensure!(
            !uploads.is_empty()
                && uploads.len() <= expected_parts
                && ordered_before(create, uploads[0])
                && uploads
                    .windows(2)
                    .all(|pair| ordered_before(pair[0], pair[1])),
            "history.jsonl multipart upload-part sequence is invalid for {key:?}"
        );
        let failed_part = uploads
            .iter()
            .position(|record| record.outcome != OperationOutcome::Ok);
        if let Some(failed_part) = failed_part {
            ensure!(
                failed_part + 1 == uploads.len()
                    && completes.is_empty()
                    && cleanup_aborts.len() == 1
                    && ordered_before(uploads[failed_part], cleanup_aborts[0])
                    && matches!(
                        cleanup_aborts[0].outcome,
                        OperationOutcome::Ok | OperationOutcome::NotFound
                    ),
                "history.jsonl continued or failed cleanup after multipart upload-part failure for {key:?}"
            );
            projected_completes.record(OperationOutcome::Unknown);
            continue;
        }

        ensure!(
            uploads.len() == expected_parts
                && completes.len() == 1
                && ordered_before(uploads[uploads.len() - 1], completes[0]),
            "history.jsonl lacks the planned upload parts or completion for {key:?}"
        );
        let complete = completes[0];
        if complete.outcome == OperationOutcome::Ok {
            ensure!(
                cleanup_aborts.is_empty(),
                "history.jsonl aborted an acknowledged multipart completion for {key:?}"
            );
        } else if let Some(cleanup) = cleanup_aborts.first() {
            ensure!(
                ordered_before(complete, cleanup)
                    && matches!(
                        cleanup.outcome,
                        OperationOutcome::Ok | OperationOutcome::NotFound
                    ),
                "history.jsonl multipart completion cleanup is invalid for {key:?}"
            );
        }
        projected_completes.record(complete.outcome);
    }

    let mut projected_aborts = OutcomeCountsArtifact::default();
    for key in &abort_keys {
        let records = records_for_key(key);
        let creates = records
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::CreateMultipartUpload)
            .collect::<Vec<_>>();
        let aborts = records
            .iter()
            .copied()
            .filter(|record| record.kind == OperationKind::AbortMultipartUpload)
            .collect::<Vec<_>>();
        ensure!(
            creates.len() == 1
                && aborts.len() <= 1
                && records.iter().all(|record| {
                    matches!(
                        record.kind,
                        OperationKind::CreateMultipartUpload | OperationKind::AbortMultipartUpload
                    )
                }),
            "history.jsonl explicit multipart abort sequence is invalid for {key:?}"
        );
        let create = creates[0];
        if create.outcome == OperationOutcome::Ok {
            ensure!(
                aborts.len() == 1 && ordered_before(create, aborts[0]),
                "history.jsonl lacks an abort after successful multipart create for {key:?}"
            );
            projected_aborts.record(aborts[0].outcome);
        } else {
            ensure!(
                aborts.is_empty(),
                "history.jsonl continued explicit multipart abort after failed create for {key:?}"
            );
            projected_aborts.record(OperationOutcome::Unknown);
        }
    }
    ensure!(
        projected_completes == summary.multipart_completes
            && projected_aborts == summary.multipart_aborts,
        "workload-summary.json multipart outcomes do not match workload history.jsonl records"
    );
    ensure!(
        history.iter().all(|record| match record.kind {
            OperationKind::CreateMultipartUpload => record
                .key
                .as_ref()
                .is_some_and(|key| complete_keys.contains_key(key) || abort_keys.contains(key)),
            OperationKind::UploadPart => record
                .key
                .as_ref()
                .is_some_and(|key| complete_keys.contains_key(key)),
            OperationKind::CompleteMultipartUpload => record
                .key
                .as_ref()
                .is_some_and(|key| complete_keys.contains_key(key)),
            OperationKind::AbortMultipartUpload => record
                .key
                .as_ref()
                .is_some_and(|key| complete_keys.contains_key(key) || abort_keys.contains(key)),
            _ => true,
        }),
        "history.jsonl contains a multipart record outside the planned workload keys"
    );
    Ok(())
}

#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
struct OutcomeCountsArtifact {
    ok: usize,
    not_found: usize,
    failed: usize,
    timeout: usize,
    unknown: usize,
}

impl OutcomeCountsArtifact {
    fn record(&mut self, outcome: OperationOutcome) {
        match outcome {
            OperationOutcome::Ok => self.ok += 1,
            OperationOutcome::NotFound => self.not_found += 1,
            OperationOutcome::Failed => self.failed += 1,
            OperationOutcome::Timeout => self.timeout += 1,
            OperationOutcome::Unknown => self.unknown += 1,
        }
    }

    fn total(&self) -> usize {
        self.ok + self.not_found + self.failed + self.timeout + self.unknown
    }

    fn disrupted(&self) -> Result<usize> {
        self.failed
            .checked_add(self.timeout)
            .and_then(|value| value.checked_add(self.unknown))
            .context("workload-summary.json outcome disrupted count overflowed")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ArtifactIdentityPolicy, POD_LIFECYCLE_EVIDENCE_ARTIFACT, RunMetadataArtifact,
        requires_write_quorum_loss_history, validate_availability_artifact,
        validate_node_down_hold_artifacts, validate_pod_lifecycle_artifact,
        validate_quorum_edge_read_survival_artifact,
    };
    use super::{
        ArtifactValidationOptions, FailureSummary, FaultEvidenceArtifact, OutcomeCountsArtifact,
        QuorumEdgeRuntimeKind, RecommitCandidateManifestArtifact, RecommitReportArtifact,
        WorkloadSummaryArtifact, derive_recommit_candidates, read_json, read_jsonl, recursive_find,
        validate_admin_topology_artifact_files, validate_checker_phase_chain,
        validate_failed_attempt_disruptions, validate_fault_artifacts,
        validate_fault_artifacts_and_write_report,
        validate_fault_artifacts_for_planned_attempt_and_write_report,
        validate_fixed_volume_runtime_evidence, validate_host_storage_artifacts, validate_run_spec,
        validate_target_proof, validate_volume_quorum_health_evidence,
        validate_write_quorum_runtime_evidence,
    };
    use crate::fault::events::RunEvent;
    use crate::fault::fixture::AdminFixturePlan;
    use crate::fault::host_storage::HOST_STORAGE_PROOF_ARTIFACT;
    use crate::fault::node_down::NODE_DOWN_HOLD_ARTIFACT;
    use crate::fault::recovery_health::RECOVERY_HEALTH_ARTIFACT;
    use crate::fault::workload::execution::{
        AVAILABILITY_REPORT_ARTIFACT, NODE_DOWN_READ_HISTORY_ARTIFACT,
        NODE_DOWN_WRITE_HISTORY_ARTIFACT, NODE_DOWN_WRITE_REPORT_ARTIFACT,
        POST_RECOVERY_WRITE_HISTORY_ARTIFACT, POST_RECOVERY_WRITE_REPORT_ARTIFACT,
        QUORUM_EDGE_READ_SURVIVAL_ARTIFACT,
    };
    use crate::fault::{
        acknowledged_mutation::AcknowledgedMutationKind,
        admin_decommission::{
            ADMIN_DECOMMISSION_OVERLAP_ARTIFACT, ADMIN_DECOMMISSION_TRANSCRIPT_ARTIFACT,
        },
        admin_rebalance::ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
        admin_topology::{ADMIN_TOPOLOGY_PROOF_ARTIFACT, AdminAttemptIdentity, AdminAttemptWindow},
        checker::{self, CheckerReport, RecoveryStabilityClassification, RecoveryStabilityReport},
        config::FaultTestConfig,
        history::{
            ByteRange, DurabilityCohort, FaultWindowRelation, ListedVersionEntry, OperationKind,
            OperationOutcome, OperationRecord,
        },
        host_storage::{
            DM_FILESYSTEM_CHECK_SCHEMA_VERSION, DmFilesystemCheck, HostStorageAllowlist,
            HostStorageMutationIntent, HostStorageMutationProof, HostStorageNodeSelector,
            HostStoragePersistentVolumeClaimRef, HostStoragePostCleanupObservation,
            HostStorageTargetObservation,
        },
        plan::{
            ExecutionPlan, FaultInjection, FaultInjectionParameters, FaultKind, FaultPlan,
            FaultPlanOptions, FaultSelection, FaultTarget,
        },
        preflight::{
            TargetNodeAffinityProof, TargetNodeSelectorRequirementProof,
            TargetNodeSelectorTermProof, TargetPersistentVolumeClaimProof,
            TargetPersistentVolumeProof, TargetProof, TargetResolvedPodProof,
            TargetVolumeMountProof,
        },
        quorum::{
            ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape,
            QuorumCaseClass, QuorumDriveHealth, QuorumHealthObservation, QuorumVolumeBinding,
            QuorumVolumeBoundary, QuorumVolumeTargetProof,
        },
        reporting::{
            AvailabilityStatus, DataCorrectnessStatus, FailurePhase, FailureSeverity,
            FailureVerdict, ResponsibilityDomain,
        },
        scenarios::ADMIN_DECOMMISSION_SCENARIO,
        scenarios::{
            ADMIN_REBALANCE_SCENARIO, DM_FLAKEY_SCENARIO, FaultScenario, IO_EIO_SCENARIO,
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO, NODE_CRASH_PROXY_SCENARIO,
            POD_FAILURE_QUORUM_EDGE_SCENARIO, POD_FAILURE_SCENARIO, POD_KILL_ONE_SCENARIO,
            QUORUM_P_IO_FAULT_SCENARIO, QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
            apply_catalog_defaults, scenario_spec,
        },
        spec::{FAULT_RUN_API_VERSION, FAULT_RUN_KIND, FaultRunArtifactSpec, FaultRunSpec},
        workload::{ObjectSpec, WorkloadPlan},
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, fs, time::Duration};

    const FAILED_ADMIN_RUN_ID: &str = "run-00000000-0000-4000-8000-000000000076";
    const FAILED_ADMIN_CASE: &str = "fault_admin_rebalance_preserves_object_model";
    const FAILED_ADMIN_BUCKET: &str = "admin-failed-bucket";

    struct FailedAdminTestCase {
        _tempdir: tempfile::TempDir,
        suite_root: std::path::PathBuf,
        case_dir: std::path::PathBuf,
    }

    fn failed_admin_test_case(
        workload_started: bool,
        include_summary: bool,
    ) -> FailedAdminTestCase {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let suite_root = tempdir.path().join("suite");
        let case_dir = suite_root.join("attempt").join(FAILED_ADMIN_CASE);
        fs::create_dir_all(&case_dir).expect("case dir");

        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.qualify_planned_admin = true;
        let catalog = scenario_spec(ADMIN_REBALANCE_SCENARIO).expect("admin catalog");
        let scenario = FaultScenario {
            name: ADMIN_REBALANCE_SCENARIO.to_string(),
            case_name: catalog.case_name,
            duration: Duration::from_secs(600),
            percent: 1,
            object_count: 12,
        };
        let execution = ExecutionPlan::from_scenario_with_options(
            &scenario,
            catalog,
            FaultPlanOptions::from_config(&config),
        )
        .expect("admin execution plan");
        let workload = WorkloadPlan::seeded(42, 12, 4);
        let run_spec = FaultRunSpec::resolved_execution(
            &config,
            &scenario,
            catalog,
            &execution,
            &workload,
            FAILED_ADMIN_RUN_ID,
            FAILED_ADMIN_BUCKET,
        );
        write_json(
            &case_dir,
            "run-spec.json",
            &serde_json::to_value(&run_spec).expect("run spec"),
        );

        let fixture_plan = AdminFixturePlan::for_scenario(
            ADMIN_REBALANCE_SCENARIO,
            run_spec.recovery.expected_rustfs_pod_count,
        )
        .expect("fixture plan");
        let initial_pool = fixture_plan.initial_pool_name.clone();
        let expansion_pool = fixture_plan.expansion_pool_name.clone();
        let observations = if workload_started {
            json!([
                {"phase": "primary-ready", "observedAtMs": 11, "tenantUid": "tenant-uid", "poolNames": [initial_pool]},
                {"phase": "prefill-complete", "observedAtMs": 12, "tenantUid": "tenant-uid", "poolNames": [initial_pool], "prefilledObjects": 6},
                {"phase": "expansion-applied", "observedAtMs": 13, "tenantUid": "tenant-uid", "poolNames": [initial_pool, expansion_pool]},
                {"phase": "topology-stable", "observedAtMs": 14, "tenantUid": "tenant-uid", "poolNames": [initial_pool, expansion_pool]}
            ])
        } else {
            json!([])
        };
        write_json(
            &case_dir,
            "admin-fixture.json",
            &json!({
                "schemaVersion": 1,
                "scenario": ADMIN_REBALANCE_SCENARIO,
                "runId": FAILED_ADMIN_RUN_ID,
                "tenant": run_spec.cluster.tenant,
                "plan": fixture_plan,
                "observations": observations
            }),
        );

        let phases = if workload_started {
            json!([
                {"phase": "start", "status": "succeeded", "startedAtMs": 10, "endedAtMs": 20},
                {"phase": "operation-workload-overlap", "status": "failed", "startedAtMs": 20, "endedAtMs": 80, "error": "operation failed"},
                {"phase": "cancel", "status": "succeeded", "startedAtMs": 80, "endedAtMs": 95},
                {"phase": "cleanup", "status": "succeeded", "startedAtMs": 95, "endedAtMs": 98}
            ])
        } else {
            json!([
                {"phase": "start", "status": "failed", "startedAtMs": 10, "endedAtMs": 20, "error": "prepare failed"},
                {"phase": "cancel", "status": "succeeded", "startedAtMs": 20, "endedAtMs": 25},
                {"phase": "cleanup", "status": "succeeded", "startedAtMs": 25, "endedAtMs": 30}
            ])
        };
        write_json(
            &case_dir,
            "admin-workflow.json",
            &json!({
                "schemaVersion": 1,
                "scenario": ADMIN_REBALANCE_SCENARIO,
                "runId": FAILED_ADMIN_RUN_ID,
                "phases": phases,
                "completed": false,
                "cancelAttempted": workload_started,
                "cleanupSucceeded": true
            }),
        );

        let transcript = if workload_started {
            let (proof, transcript) = failed_admin_evidence(&run_spec, &workload);
            write_json(&case_dir, ADMIN_TOPOLOGY_PROOF_ARTIFACT, &proof);
            transcript
        } else {
            json!({"operationId": null, "requests": [], "progress": []})
        };
        write_json(&case_dir, "admin-rebalance-transcript.json", &transcript);

        let events = if workload_started {
            vec![
                run_event(10, "run", "started"),
                run_event(21, "mixed-workload", "started"),
                run_event(70, "mixed-workload", "succeeded"),
                run_event(98, "run", "failed"),
            ]
        } else {
            vec![
                run_event(10, "run", "started"),
                run_event(30, "run", "failed"),
            ]
        };
        write_values_jsonl(&case_dir.join("run-events.jsonl"), &events);

        if workload_started {
            write_json(
                &case_dir,
                "workload-plan.json",
                &serde_json::to_value(&workload).expect("workload plan"),
            );
            let history = failed_admin_history(&workload);
            write_records_jsonl(&case_dir.join("history.jsonl"), &history);
            if include_summary {
                write_json(&case_dir, "workload-summary.json", &failed_admin_summary());
            }
        }

        FailedAdminTestCase {
            _tempdir: tempdir,
            suite_root,
            case_dir,
        }
    }

    fn failed_admin_evidence(run_spec: &FaultRunSpec, workload: &WorkloadPlan) -> (Value, Value) {
        let start_body = r#"{"id":"rebalance-1"}"#;
        let runtime_body = r#"{"info":{"deploymentID":"deployment-1"}}"#;
        let tenant = run_spec.cluster.tenant.as_str();
        let namespace = run_spec.cluster.namespace.as_str();
        let context = run_spec.cluster.context.as_str();
        let service_name = format!("{tenant}-io");
        let servers = run_spec.recovery.expected_rustfs_pod_count;
        let last_server = servers - 1;
        let primary = format!(
            "http://{tenant}-primary-{{0...{last_server}}}.{tenant}-hl.{namespace}.svc.cluster.local:9000/data/rustfs{{0...0}}"
        );
        let expansion = format!(
            "http://{tenant}-expansion-{{0...{last_server}}}.{tenant}-hl.{namespace}.svc.cluster.local:9000/data/rustfs{{0...0}}"
        );
        let cluster_body = serde_json::to_string(&json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "kube-system", "uid": "cluster-uid"}
        }))
        .expect("cluster body");
        let service_body = serde_json::to_string(&json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "namespace": namespace,
                "name": service_name,
                "uid": "service-uid",
                "resourceVersion": "service-rv-1"
            },
            "spec": {
                "ports": [{"port": 9000}],
                "selector": {"rustfs.tenant": tenant}
            }
        }))
        .expect("service body");
        let tenant_body = serde_json::to_string(&json!({
            "metadata": {
                "namespace": namespace,
                "name": tenant,
                "uid": "tenant-uid",
                "resourceVersion": "tenant-rv-1"
            },
            "spec": {"pools": [
                {"name": "primary", "servers": servers, "persistence": {"volumesPerServer": 1}},
                {"name": "expansion", "servers": servers, "persistence": {"volumesPerServer": 1}}
            ]}
        }))
        .expect("tenant body");
        let endpoint = |base: u64| {
            json!({
                "kubernetesContext": context,
                "clusterUid": "cluster-uid",
                "portForwardCommand": format!("kubectl --context {context} -n {namespace} port-forward svc/{service_name} 19000:9000"),
                "portForwardStartedAtMs": 10,
                "clusterStartedAtMs": base,
                "clusterObservedAtMs": base + 1,
                "clusterResponseSha256": hex::encode(Sha256::digest(cluster_body.as_bytes())),
                "clusterResponseBody": cluster_body,
                "namespace": namespace,
                "serviceName": service_name,
                "serviceUid": "service-uid",
                "serviceResourceVersion": "service-rv-1",
                "serviceStartedAtMs": base + 2,
                "serviceObservedAtMs": base + 3,
                "serviceResponseSha256": hex::encode(Sha256::digest(service_body.as_bytes())),
                "serviceResponseBody": service_body,
                "tenantName": tenant,
                "tenantUid": "tenant-uid",
                "tenantResourceVersion": "tenant-rv-1",
                "tenantStartedAtMs": base + 4,
                "tenantObservedAtMs": base + 5,
                "tenantResponseSha256": hex::encode(Sha256::digest(tenant_body.as_bytes())),
                "tenantResponseBody": tenant_body,
                "localEndpoint": "http://127.0.0.1:19000",
                "remotePort": 9000
            })
        };
        let target = |base| json!({"endpoint": endpoint(base), "deploymentId": "deployment-1"});
        let runtime = |base| {
            json!({
                "target": target(base),
                "status": 200,
                "startedAtMs": base + 6,
                "observedAtMs": base + 7,
                "requestId": format!("runtime-{base}"),
                "responseSha256": hex::encode(Sha256::digest(runtime_body.as_bytes())),
                "responseBody": runtime_body
            })
        };
        let runtime_pools = json!([
            {"id": 0, "cmdline": primary, "status": "active", "decommissionStatus": "none", "rebalanceStatus": "none", "totalSize": 1000000000000000_u64, "currentSize": 900000000000000_u64, "usedSize": 100000000000000_u64, "used": 0.1},
            {"id": 1, "cmdline": expansion, "status": "active", "decommissionStatus": "none", "rebalanceStatus": "none", "totalSize": 1000000000000000_u64, "currentSize": 900000000000000_u64, "usedSize": 100000000000000_u64, "used": 0.1}
        ]);
        let workload_max_bytes = workload
            .mixed_write_upper_bound(workload.object_count / 2, workload.object_count / 2)
            .expect("workload capacity");
        let proof = json!({
            "runId": FAILED_ADMIN_RUN_ID,
            "caseName": FAILED_ADMIN_CASE,
            "tenantUid": "tenant-uid",
            "scenario": ADMIN_REBALANCE_SCENARIO,
            "tenant": tenant,
            "namespace": namespace,
            "runtime": runtime(10),
            "tenantPools": [
                {"name": "primary", "tenantUid": "tenant-uid", "statefulSetName": format!("{tenant}-primary"), "expectedEndpointSet": primary, "internodeScheme": "http", "clusterDomain": "cluster.local", "dataPath": "/data", "runtimePoolId": 0, "servers": servers, "volumesPerServer": 1},
                {"name": "expansion", "tenantUid": "tenant-uid", "statefulSetName": format!("{tenant}-expansion"), "expectedEndpointSet": expansion, "internodeScheme": "http", "clusterDomain": "cluster.local", "dataPath": "/data", "runtimePoolId": 1, "servers": servers, "volumesPerServer": 1}
            ],
            "runtimePools": runtime_pools,
            "remainingFreeBytes": 1800000000000000_u64,
            "targetUsedBytes": 0,
            "workloadMaxBytes": workload_max_bytes,
            "capacityGuardPercent": 130,
            "requiredRemainingFreeBytes": workload_max_bytes,
            "mutuallyExclusive": true,
            "satisfied": true
        });
        let running_body = serde_json::to_string(&json!({
            "id": "rebalance-1",
            "pools": [
                {"id": 0, "status": "started", "progress": {"objects": 0, "versions": 0, "bytes": 0, "remainingBuckets": 1}},
                {"id": 1, "status": "started", "progress": {"objects": 0, "versions": 0, "bytes": 0, "remainingBuckets": 1}}
            ]
        })).expect("running status");
        let stopped_body = serde_json::to_string(&json!({
            "id": "rebalance-1",
            "pools": [
                {"id": 0, "status": "stopped", "progress": {"objects": 1, "versions": 1, "bytes": 10, "remainingBuckets": 1}},
                {"id": 1, "status": "stopped", "progress": {"objects": 1, "versions": 1, "bytes": 10, "remainingBuckets": 1}}
            ],
            "stoppedAt": "2026-09-13T00:00:00Z"
        })).expect("stopped status");
        let transcript = json!({
            "operationId": "rebalance-1",
            "requests": [
            {
                "target": target(20),
                "runtimeProbe": {
                    "target": target(20),
                    "status": 200,
                    "startedAtMs": 26,
                    "observedAtMs": 27,
                    "requestId": "probe-request",
                    "responseSha256": hex::encode(Sha256::digest(runtime_body.as_bytes())),
                    "responseBody": runtime_body
                },
                "method": "POST",
                "path": "/rustfs/admin/v3/rebalance/start",
                "status": 200,
                "startedAtMs": 28,
                "observedAtMs": 29,
                "requestId": "start-request",
                "responseSha256": hex::encode(Sha256::digest(start_body.as_bytes())),
                "responseBody": start_body
            },
            {"target": target(50), "method": "GET", "path": "/rustfs/admin/v3/rebalance/status", "query": {}, "status": 200, "startedAtMs": 56, "observedAtMs": 57, "requestId": "status-running", "responseSha256": hex::encode(Sha256::digest(running_body.as_bytes())), "responseBody": running_body},
            {"target": target(75), "runtimeProbe": runtime(75), "method": "POST", "path": "/rustfs/admin/v3/rebalance/stop", "query": {}, "status": 200, "startedAtMs": 83, "observedAtMs": 84, "requestId": "stop-request"},
            {"target": target(85), "method": "GET", "path": "/rustfs/admin/v3/rebalance/status", "query": {}, "status": 200, "startedAtMs": 91, "observedAtMs": 92, "requestId": "status-stopped", "responseSha256": hex::encode(Sha256::digest(stopped_body.as_bytes())), "responseBody": stopped_body}
            ],
            "progress": [
                {"runId": FAILED_ADMIN_RUN_ID, "caseName": FAILED_ADMIN_CASE, "tenantUid": "tenant-uid", "operationId": "rebalance-1", "statusRequestId": "status-running", "observedAtMs": 57, "state": "started", "completed": false, "failed": false, "canceledOrStopped": false, "objectsMoved": 0, "versionsMoved": 0, "bytesMoved": 0},
                {"runId": FAILED_ADMIN_RUN_ID, "caseName": FAILED_ADMIN_CASE, "tenantUid": "tenant-uid", "operationId": "rebalance-1", "statusRequestId": "status-stopped", "observedAtMs": 92, "state": "stopped", "completed": false, "failed": false, "canceledOrStopped": true, "objectsMoved": 2, "versionsMoved": 2, "bytesMoved": 20}
            ]
        });
        (proof, transcript)
    }

    fn run_event(at_ms: u64, stage: &str, status: &str) -> Value {
        json!({
            "at_ms": at_ms,
            "scenario": ADMIN_REBALANCE_SCENARIO,
            "run_id": FAILED_ADMIN_RUN_ID,
            "stage": stage,
            "status": status,
            "message": "test receipt"
        })
    }

    fn failed_admin_history(plan: &WorkloadPlan) -> Vec<OperationRecord> {
        let mut records = Vec::new();
        let prefilled_count = plan.object_count / 2;
        let put_key = ObjectSpec::seeded_key(FAILED_ADMIN_RUN_ID, prefilled_count);
        push_failed_admin_record(
            &mut records,
            OperationKind::Put,
            &put_key,
            OperationOutcome::Ok,
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Get,
            &put_key,
            OperationOutcome::Ok,
        );
        let overwrite_key = ObjectSpec::directory_marker_key(
            FAILED_ADMIN_RUN_ID,
            plan.existing_object_offset(1, prefilled_count),
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Put,
            &overwrite_key,
            OperationOutcome::Ok,
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Get,
            &overwrite_key,
            OperationOutcome::Ok,
        );
        let direct_get_key = ObjectSpec::directory_marker_key(
            FAILED_ADMIN_RUN_ID,
            plan.existing_object_offset(2, prefilled_count),
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Get,
            &direct_get_key,
            OperationOutcome::Failed,
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::List,
            &ObjectSpec::key_prefix(FAILED_ADMIN_RUN_ID),
            OperationOutcome::Ok,
        );
        let delete_key = ObjectSpec::directory_marker_key(
            FAILED_ADMIN_RUN_ID,
            plan.existing_object_offset(4, prefilled_count),
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Delete,
            &delete_key,
            OperationOutcome::Ok,
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Get,
            &delete_key,
            OperationOutcome::Ok,
        );

        let completion_index = prefilled_count + 5;
        let completion_key = ObjectSpec::seeded_key(FAILED_ADMIN_RUN_ID, completion_index);
        push_failed_admin_record(
            &mut records,
            OperationKind::CreateMultipartUpload,
            &completion_key,
            OperationOutcome::Ok,
        );
        for _ in 0..plan.multipart_part_count_at(completion_index) {
            push_failed_admin_record(
                &mut records,
                OperationKind::UploadPart,
                &completion_key,
                OperationOutcome::Ok,
            );
        }
        push_failed_admin_record(
            &mut records,
            OperationKind::CompleteMultipartUpload,
            &completion_key,
            OperationOutcome::Ok,
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::Get,
            &completion_key,
            OperationOutcome::Ok,
        );

        let abort_key = ObjectSpec::seeded_key(FAILED_ADMIN_RUN_ID, plan.object_count + 11);
        push_failed_admin_record(
            &mut records,
            OperationKind::CreateMultipartUpload,
            &abort_key,
            OperationOutcome::Ok,
        );
        push_failed_admin_record(
            &mut records,
            OperationKind::AbortMultipartUpload,
            &abort_key,
            OperationOutcome::Ok,
        );
        records
    }

    fn push_failed_admin_record(
        records: &mut Vec<OperationRecord>,
        kind: OperationKind,
        key: &str,
        outcome: OperationOutcome,
    ) {
        let index = records.len();
        let started_sequence = (index * 2 + 1) as u64;
        let ended_sequence = started_sequence + 1;
        records.push(OperationRecord {
            id: format!("operation-{index}"),
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            run_id: Some(FAILED_ADMIN_RUN_ID.to_string()),
            kind,
            bucket: FAILED_ADMIN_BUCKET.to_string(),
            key: Some(key.to_string()),
            value_sha256: None,
            size_bytes: None,
            version_id: None,
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: Some(started_sequence),
            ended_sequence: Some(ended_sequence),
            started_at_ms: 30 + index as u64,
            ended_at_ms: 30 + index as u64,
            outcome,
            http_status: Some(if outcome == OperationOutcome::Failed {
                500
            } else {
                200
            }),
            error: (outcome == OperationOutcome::Failed).then(|| "disrupted".to_string()),
            durability_cohort: Some(DurabilityCohort::FaultActive),
            fault_window_relation: None,
        });
    }

    fn failed_admin_summary() -> Value {
        let counts = |ok, failed| json!({"ok": ok, "not_found": 0, "failed": failed, "timeout": 0, "unknown": 0});
        json!({
            "scenario": ADMIN_REBALANCE_SCENARIO,
            "run_id": FAILED_ADMIN_RUN_ID,
            "seed": 42,
            "object_count": 12,
            "concurrency": 4,
            "recommitted_after_recovery": 0,
            "puts": counts(2, 0),
            "gets": counts(4, 1),
            "deletes": counts(1, 0),
            "lists": counts(1, 0),
            "multipart_completes": counts(1, 0),
            "multipart_aborts": counts(1, 0)
        })
    }

    fn write_values_jsonl(path: &std::path::Path, values: &[Value]) {
        let body = values
            .iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(path, format!("{body}\n")).expect("write jsonl");
    }

    fn write_records_jsonl(path: &std::path::Path, records: &[OperationRecord]) {
        let values = records
            .iter()
            .map(|record| serde_json::to_value(record).expect("history record"))
            .collect::<Vec<_>>();
        write_values_jsonl(path, &values);
    }

    #[test]
    fn failed_admin_attempt_before_workload_reports_zero_disruptions() {
        let case = failed_admin_test_case(false, false);
        let disruptions = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect("pre-workload failure is run-owned");
        assert_eq!(disruptions, 0);
    }

    #[test]
    fn failed_admin_attempt_with_completed_workload_reports_summary_disruptions() {
        let case = failed_admin_test_case(true, true);
        let disruptions = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect("completed current-run workload is valid");
        assert_eq!(disruptions, 1);
    }

    #[test]
    fn failed_admin_attempt_rejects_start_only_cancellation_evidence() {
        let case = failed_admin_test_case(true, true);
        let transcript_path = case.case_dir.join(ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT);
        let mut transcript = serde_json::from_slice::<Value>(
            &fs::read(&transcript_path).expect("transcript artifact"),
        )
        .expect("transcript JSON");
        transcript["requests"] = json!([transcript["requests"][0].clone()]);
        transcript["progress"] = json!([]);
        write_json(
            &case.case_dir,
            ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
            &transcript,
        );

        let error = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect_err("start-only cancellation evidence must fail closed");
        assert!(error.to_string().contains("terminal state"), "{error:#}");
    }

    #[test]
    fn failed_admin_attempt_rejects_forged_topology_receipt() {
        let case = failed_admin_test_case(true, true);
        let proof_path = case.case_dir.join(ADMIN_TOPOLOGY_PROOF_ARTIFACT);
        let mut proof =
            serde_json::from_slice::<Value>(&fs::read(&proof_path).expect("proof artifact"))
                .expect("proof JSON");
        let forged_body = "{}";
        proof["runtime"]["target"]["endpoint"]["clusterResponseBody"] = json!(forged_body);
        proof["runtime"]["target"]["endpoint"]["clusterResponseSha256"] =
            json!(hex::encode(Sha256::digest(forged_body.as_bytes())));
        write_json(&case.case_dir, ADMIN_TOPOLOGY_PROOF_ARTIFACT, &proof);

        let error = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect_err("forged Kubernetes topology receipt must fail closed");
        assert!(error.to_string().contains("/apiVersion"), "{error:#}");
    }

    #[test]
    fn failed_admin_attempt_rejects_progress_not_derived_from_status() {
        let case = failed_admin_test_case(true, true);
        let transcript_path = case.case_dir.join(ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT);
        let mut transcript = serde_json::from_slice::<Value>(
            &fs::read(&transcript_path).expect("transcript artifact"),
        )
        .expect("transcript JSON");
        transcript["progress"][1]["objectsMoved"] = json!(999);
        write_json(
            &case.case_dir,
            ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
            &transcript,
        );

        let error = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect_err("forged progress projection must fail closed");
        assert!(error.to_string().contains("not derived"), "{error:#}");
    }

    #[test]
    fn failed_admin_attempt_rejects_self_consistent_incomplete_workload() {
        let case = failed_admin_test_case(true, true);
        let history_path = case.case_dir.join("history.jsonl");
        let mut history = fs::read_to_string(&history_path)
            .expect("history artifact")
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).expect("history record"))
            .collect::<Vec<_>>();
        let failed_get = history
            .iter()
            .position(|record| record["kind"] == "get" && record["outcome"] == "failed")
            .expect("failed direct GET");
        history.remove(failed_get);
        for (index, record) in history.iter_mut().enumerate() {
            record["started_sequence"] = json!(index * 2 + 1);
            record["ended_sequence"] = json!(index * 2 + 2);
        }
        write_values_jsonl(&history_path, &history);
        let mut summary = failed_admin_summary();
        summary["gets"]["failed"] = json!(0);
        write_json(&case.case_dir, "workload-summary.json", &summary);

        let error = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect_err("self-consistent incomplete workload must fail closed");
        assert!(error.to_string().contains("planned"), "{error:#}");
    }

    #[test]
    fn failed_admin_attempt_rejects_unplanned_fault_active_operation() {
        for cohort in [
            json!("fault_active"),
            json!("pre_fault"),
            json!("post_recovery"),
            Value::Null,
        ] {
            let case = failed_admin_test_case(true, true);
            let history_path = case.case_dir.join("history.jsonl");
            let mut history = fs::read_to_string(&history_path)
                .expect("history artifact")
                .lines()
                .map(|line| serde_json::from_str::<Value>(line).expect("history record"))
                .collect::<Vec<_>>();
            let mut forged = history[0].clone();
            forged["id"] = json!("unplanned-head");
            forged["kind"] = json!("head");
            forged["outcome"] = json!("failed");
            forged["durability_cohort"] = cohort;
            forged["started_sequence"] = json!(history.len() * 2 + 1);
            forged["ended_sequence"] = json!(history.len() * 2 + 2);
            forged["started_at_ms"] = json!(79);
            forged["ended_at_ms"] = json!(79);
            history.push(forged);
            write_values_jsonl(&history_path, &history);

            let error = validate_failed_attempt_disruptions(
                &case.suite_root,
                &case.case_dir,
                FAILED_ADMIN_RUN_ID,
                ADMIN_REBALANCE_SCENARIO,
                FAILED_ADMIN_CASE,
                10,
                100,
            )
            .expect_err("unplanned workload-window S3 operation must fail closed");
            assert!(
                error.to_string().contains("workflow phase")
                    || error.to_string().contains("outside the planned"),
                "{error:#}"
            );
        }
    }

    #[test]
    fn failed_admin_attempt_rejects_started_workload_without_current_summary() {
        let case = failed_admin_test_case(true, false);
        let error = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect_err("started workload without summary must fail closed");
        assert!(
            error.to_string().contains("workload-summary.json"),
            "{error:#}"
        );

        let mut foreign = failed_admin_summary();
        foreign["run_id"] = json!("run-00000000-0000-4000-8000-000000000099");
        write_json(&case.case_dir, "workload-summary.json", &foreign);
        let error = validate_failed_attempt_disruptions(
            &case.suite_root,
            &case.case_dir,
            FAILED_ADMIN_RUN_ID,
            ADMIN_REBALANCE_SCENARIO,
            FAILED_ADMIN_CASE,
            10,
            100,
        )
        .expect_err("foreign summary must fail closed");
        assert!(error.to_string().contains("workload summary"), "{error:#}");
    }

    #[test]
    fn admin_topology_files_require_successful_terminal_progress() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_admin_decommission_preserves_object_model";
        let workload_max_bytes = 69_234_192_u64;
        let primary = "http://fault-tenant-primary-{0...3}.fault-tenant-hl.fault-ns.svc.cluster.local:9000/data/rustfs{0...0}";
        let target = "http://fault-tenant-decommission-target-{0...3}.fault-tenant-hl.fault-ns.svc.cluster.local:9000/data/rustfs{0...0}";
        let attempt = AdminAttemptIdentity {
            run_id: "run-admin-1".to_string(),
            case_name: case_name.to_string(),
            tenant_uid: "tenant-uid".to_string(),
        };
        let attempt_window = AdminAttemptWindow {
            started_at_ms: 50,
            evaluated_at_ms: 300,
        };
        let pools = json!([
            {
                "id": 0,
                "cmdline": primary,
                "status": "active",
                "decommissionStatus": "none",
                "rebalanceStatus": "none",
                "totalSize": 100000000,
                "currentSize": 90000000,
                "usedSize": 10000000,
                "used": 0.1
            },
            {
                "id": 1,
                "cmdline": target,
                "status": "active",
                "decommissionStatus": "none",
                "rebalanceStatus": "none",
                "totalSize": 1000,
                "currentSize": 800,
                "usedSize": 200,
                "used": 0.2
            }
        ]);
        let pools_after = json!([
            {
                "id": 0,
                "cmdline": primary,
                "status": "active",
                "decommissionStatus": "none",
                "rebalanceStatus": "none",
                "totalSize": 100000000,
                "currentSize": 89999800,
                "usedSize": 10000200,
                "used": 0.100002
            }
        ]);
        let pools_body = serde_json::to_string(&pools).expect("pools/list response body");
        let pools_sha256 = hex::encode(Sha256::digest(pools_body.as_bytes()));
        let pools_after_body =
            serde_json::to_string(&pools_after).expect("post-operation pools/list response body");
        let pools_after_sha256 = hex::encode(Sha256::digest(pools_after_body.as_bytes()));
        let terminal_status_body = serde_json::to_string(&json!({
            "id": 1,
            "cmdline": target,
            "status": "complete",
            "poolStatus": "decommissioned",
            "decommissionInfo": {
                "startTime": "2026-09-05T00:00:00Z",
                "complete": true,
                "objectsDecommissioned": 2,
                "bytesDecommissioned": 200
            }
        }))
        .expect("terminal status body");
        let terminal_status_sha256 = hex::encode(Sha256::digest(terminal_status_body.as_bytes()));
        let cluster_body = serde_json::to_string(&json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "kube-system", "uid": "cluster-uid"}
        }))
        .expect("cluster identity GET body");
        let cluster_sha256 = hex::encode(Sha256::digest(cluster_body.as_bytes()));
        let service_body = serde_json::to_string(&json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant-io",
                "uid": "service-uid",
                "resourceVersion": "service-rv-1"
            },
            "spec": {
                "ports": [{"port": 9000}],
                "selector": {"rustfs.tenant": "fault-tenant"}
            }
        }))
        .expect("Service GET body");
        let service_sha256 = hex::encode(Sha256::digest(service_body.as_bytes()));
        let endpoint_tenant_body = serde_json::to_string(&json!({
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant",
                "uid": "tenant-uid",
                "resourceVersion": "tenant-rv-1"
            },
            "spec": {
                "pools": [
                    {"name": "primary", "servers": 4, "persistence": {"volumesPerServer": 1}},
                    {"name": "decommission-target", "servers": 4, "persistence": {"volumesPerServer": 1}}
                ]
            }
        }))
        .expect("endpoint Tenant GET body");
        let endpoint_tenant_sha256 = hex::encode(Sha256::digest(endpoint_tenant_body.as_bytes()));
        let endpoint_identity = json!({
            "kubernetesContext": "kind-admin-test",
            "clusterUid": "cluster-uid",
            "portForwardCommand": "kubectl --context kind-admin-test -n fault-ns port-forward svc/fault-tenant-io 19000:9000",
            "portForwardStartedAtMs": 10,
            "clusterStartedAtMs": 20,
            "clusterObservedAtMs": 21,
            "clusterResponseSha256": cluster_sha256,
            "clusterResponseBody": cluster_body,
            "namespace": "fault-ns",
            "serviceName": "fault-tenant-io",
            "serviceUid": "service-uid",
            "serviceResourceVersion": "service-rv-1",
            "serviceStartedAtMs": 22,
            "serviceObservedAtMs": 23,
            "serviceResponseSha256": service_sha256,
            "serviceResponseBody": service_body,
            "tenantName": "fault-tenant",
            "tenantUid": "tenant-uid",
            "tenantResourceVersion": "tenant-rv-1",
            "tenantStartedAtMs": 24,
            "tenantObservedAtMs": 25,
            "tenantResponseSha256": endpoint_tenant_sha256,
            "tenantResponseBody": endpoint_tenant_body,
            "localEndpoint": "http://127.0.0.1:19000",
            "remotePort": 9000
        });
        let request_target = json!({
            "endpoint": endpoint_identity,
            "deploymentId": "deployment-1"
        });
        let info_body = r#"{"info":{"deploymentID":"deployment-1"}}"#;
        let info_sha256 = hex::encode(Sha256::digest(info_body.as_bytes()));
        let runtime_before = json!({
            "target": request_target,
            "status": 200,
            "startedAtMs": 70,
            "observedAtMs": 75,
            "requestId": "admin-info-before",
            "responseSha256": info_sha256,
            "responseBody": info_body
        });
        let runtime_probe = |request_started_at_ms: u64| {
            let mut probe = runtime_before.clone();
            probe["target"]["endpoint"]["clusterStartedAtMs"] = json!(request_started_at_ms - 3);
            probe["target"]["endpoint"]["clusterObservedAtMs"] = json!(request_started_at_ms - 3);
            probe["target"]["endpoint"]["serviceStartedAtMs"] = json!(request_started_at_ms - 2);
            probe["target"]["endpoint"]["serviceObservedAtMs"] = json!(request_started_at_ms - 2);
            probe["target"]["endpoint"]["tenantStartedAtMs"] = json!(request_started_at_ms - 1);
            probe["target"]["endpoint"]["tenantObservedAtMs"] = json!(request_started_at_ms - 1);
            probe["startedAtMs"] = json!(request_started_at_ms - 1);
            probe["observedAtMs"] = json!(request_started_at_ms - 1);
            probe["requestId"] = json!(format!("admin-info-before-{request_started_at_ms}"));
            probe
        };
        let request_target_at =
            |request_started_at_ms| runtime_probe(request_started_at_ms)["target"].clone();
        let runtime_mutation = runtime_probe(95);
        let mut runtime_after = runtime_before.clone();
        runtime_after["target"]["endpoint"]["clusterStartedAtMs"] = json!(201);
        runtime_after["target"]["endpoint"]["clusterObservedAtMs"] = json!(201);
        runtime_after["target"]["endpoint"]["serviceStartedAtMs"] = json!(201);
        runtime_after["target"]["endpoint"]["serviceObservedAtMs"] = json!(201);
        runtime_after["target"]["endpoint"]["tenantStartedAtMs"] = json!(201);
        runtime_after["target"]["endpoint"]["tenantObservedAtMs"] = json!(201);
        runtime_after["startedAtMs"] = json!(201);
        runtime_after["observedAtMs"] = json!(204);
        runtime_after["requestId"] = json!("admin-info-after");
        let tenant_before_body = serde_json::to_string(&json!({
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant",
                "uid": "tenant-uid",
                "resourceVersion": "tenant-rv-1"
            },
            "spec": {
                "pools": [
                    {"name": "primary", "servers": 4, "persistence": {"volumesPerServer": 1}},
                    {"name": "decommission-target", "servers": 4, "persistence": {"volumesPerServer": 1}}
                ]
            }
        }))
        .expect("Tenant GET body");
        let tenant_before_sha256 = hex::encode(Sha256::digest(tenant_before_body.as_bytes()));
        let tenant_after_body = serde_json::to_string(&json!({
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant",
                "uid": "tenant-uid",
                "resourceVersion": "tenant-rv-2"
            },
            "spec": {
                "pools": [
                    {"name": "primary", "servers": 4, "persistence": {"volumesPerServer": 1}},
                    {"name": "decommission-target", "servers": 4, "persistence": {"volumesPerServer": 1}}
                ]
            }
        }))
        .expect("Tenant GET body");
        let tenant_after_sha256 = hex::encode(Sha256::digest(tenant_after_body.as_bytes()));
        write_json(
            dir.path(),
            "admin-topology-proof.json",
            &json!({
                "scenario": "admin-decommission",
                "tenant": "fault-tenant",
                "runId": "run-admin-1",
                "caseName": case_name,
                "tenantUid": "tenant-uid",
                "namespace": "fault-ns",
                "runtime": runtime_before,
                "tenantPools": [
                    {"name": "primary", "tenantUid": "tenant-uid", "statefulSetName": "fault-tenant-primary", "expectedEndpointSet": primary, "internodeScheme": "http", "clusterDomain": "cluster.local", "dataPath": "/data", "runtimePoolId": 0, "servers": 4, "volumesPerServer": 1},
                    {"name": "decommission-target", "tenantUid": "tenant-uid", "statefulSetName": "fault-tenant-decommission-target", "expectedEndpointSet": target, "internodeScheme": "http", "clusterDomain": "cluster.local", "dataPath": "/data", "runtimePoolId": 1, "servers": 4, "volumesPerServer": 1}
                ],
                "runtimePools": pools,
                "targetPoolId": 1,
                "targetPoolExpression": target,
                "remainingFreeBytes": 90000000,
                "targetUsedBytes": 200,
                "workloadMaxBytes": workload_max_bytes,
                "capacityGuardPercent": 130,
                "requiredRemainingFreeBytes": workload_max_bytes + 260,
                "mutuallyExclusive": true,
                "satisfied": true
            }),
        );
        write_json(
            dir.path(),
            "admin-operation.json",
            &json!({
                "scenario": "admin-decommission",
                "runId": "run-admin-1",
                "caseName": case_name,
                "tenantUid": "tenant-uid",
                "operationId": "decommission:1:2026-09-05T00:00:00Z",
                "targetPoolId": 1,
                "targetPoolExpression": target,
                "terminalState": "complete",
                "completed": true,
                "failed": false,
                "canceledOrStopped": false,
                "participatingPoolIds": [1],
                "objectsMoved": 2,
                "bytesMoved": 200,
                "requests": [
                    {
                        "target": request_target_at(95),
                        "runtimeProbe": runtime_mutation,
                        "method": "POST",
                        "path": "/rustfs/admin/v3/pools/decommission",
                        "query": {"pool": "1", "by-id": "true"},
                        "status": 200,
                        "startedAtMs": 95,
                        "observedAtMs": 100,
                        "requestId": "decommission-start-request"
                    },
                    {
                        "target": request_target_at(195),
                        "method": "GET",
                        "path": "/rustfs/admin/v3/decommission/status",
                        "query": {"pool": "1", "by-id": "true"},
                        "status": 200,
                        "startedAtMs": 195,
                        "observedAtMs": 200,
                        "requestId": "decommission-status-request",
                        "responseSha256": terminal_status_sha256,
                        "responseBody": terminal_status_body
                    }
                ],
                "poolsBefore": {
                    "runId": "run-admin-1",
                    "caseName": case_name,
                    "tenantUid": "tenant-uid",
                    "tenantGet": {
                        "kubernetesContext": "kind-admin-test",
                        "clusterUid": "cluster-uid",
                        "namespace": "fault-ns",
                        "name": "fault-tenant",
                        "uid": "tenant-uid",
                        "resourceVersion": "tenant-rv-1",
                        "startedAtMs": 80,
                        "observedAtMs": 85,
                        "responseSha256": tenant_before_sha256,
                        "responseBody": tenant_before_body
                    },
                    "runtime": runtime_before,
                    "observedAtMs": 90,
                    "request": {
                        "target": request_target_at(90),
                        "runtimeProbe": runtime_probe(90),
                        "method": "GET",
                        "path": "/rustfs/admin/v3/pools/list",
                        "query": {},
                        "status": 200,
                        "startedAtMs": 90,
                        "observedAtMs": 90,
                        "responseSha256": pools_sha256,
                        "responseBody": pools_body
                    },
                    "pools": pools
                },
                "poolsAfter": {
                    "runId": "run-admin-1",
                    "caseName": case_name,
                    "tenantUid": "tenant-uid",
                    "tenantGet": {
                        "kubernetesContext": "kind-admin-test",
                        "clusterUid": "cluster-uid",
                        "namespace": "fault-ns",
                        "name": "fault-tenant",
                        "uid": "tenant-uid",
                        "resourceVersion": "tenant-rv-2",
                        "startedAtMs": 205,
                        "observedAtMs": 206,
                        "responseSha256": tenant_after_sha256,
                        "responseBody": tenant_after_body
                    },
                    "runtime": runtime_after,
                    "observedAtMs": 210,
                    "request": {
                        "target": request_target_at(210),
                        "runtimeProbe": runtime_probe(210),
                        "method": "GET",
                        "path": "/rustfs/admin/v3/pools/list",
                        "query": {},
                        "status": 200,
                        "startedAtMs": 210,
                        "observedAtMs": 210,
                        "responseSha256": pools_after_sha256,
                        "responseBody": pools_after_body
                    },
                    "pools": pools_after
                }
            }),
        );
        let valid_workload_plan = json!({
            "scenario": "admin-decommission",
            "run_id": "run-admin-1",
            "seed": 1,
            "generator": "splitmix64-v1",
            "object_count": 12,
            "concurrency": 1,
            "operation_mix": {"put": 1, "overwrite": 1, "get": 1, "list": 1, "delete": 1, "multipart": 1},
            "total_payload_bytes": 1200,
            "size_distribution": [{"size_bytes": 100, "object_count": 12}]
        });
        write_json(dir.path(), "workload-plan.json", &valid_workload_plan);
        let progress_path = dir.path().join("admin-operation-progress.jsonl");
        fs::write(
            &progress_path,
            concat!(
                "{\"runId\":\"run-admin-1\",\"caseName\":\"fault_admin_decommission_preserves_object_model\",\"tenantUid\":\"tenant-uid\",",
                "\"operationId\":\"decommission:1:2026-09-05T00:00:00Z\",",
                "\"statusRequestId\":\"decommission-status-request\",",
                "\"observedAtMs\":200,\"state\":\"complete\",\"completed\":true,",
                "\"failed\":false,\"canceledOrStopped\":false,",
                "\"objectsMoved\":2,\"bytesMoved\":200}\n"
            ),
        )
        .expect("progress");
        let run_id = "run-admin-1";
        let bucket = "bucket";
        let prefix_key = crate::fault::workload::ObjectSpec::key_prefix(run_id);
        let make_record =
            |id: &str,
             kind: OperationKind,
             key: Option<String>,
             sha: Option<&str>,
             size: Option<usize>,
             version_id: Option<&str>,
             listed_keys: Option<Vec<String>>,
             listed_versions: Option<Vec<crate::fault::history::ListedVersionEntry>>,
             started_sequence: u64,
             started_at_ms: u64| {
                OperationRecord {
                    id: id.to_string(),
                    scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
                    run_id: Some(run_id.to_string()),
                    kind,
                    bucket: bucket.to_string(),
                    key,
                    value_sha256: sha.map(str::to_string),
                    size_bytes: size,
                    version_id: version_id.map(str::to_string),
                    listed_keys,
                    listed_versions,
                    payload_ref: None,
                    range: None,
                    started_sequence: Some(started_sequence),
                    ended_sequence: Some(started_sequence + 1),
                    started_at_ms,
                    ended_at_ms: started_at_ms + 1,
                    outcome: OperationOutcome::Ok,
                    http_status: Some(200),
                    error: None,
                    durability_cohort: None,
                    fault_window_relation: None,
                }
            };
        let hot = format!("{prefix_key}hot");
        let zero = format!("{prefix_key}zero/");
        let new = format!("{prefix_key}new");
        let large = format!("{prefix_key}large");
        let mut history_prefix = vec![
            make_record(
                "versioning",
                OperationKind::PutBucketVersioning,
                None,
                None,
                None,
                None,
                None,
                None,
                1,
                101,
            ),
            make_record(
                "seed",
                OperationKind::Put,
                Some(hot.clone()),
                Some("h1"),
                Some(4),
                Some("v1"),
                None,
                None,
                3,
                103,
            ),
            make_record(
                "zero",
                OperationKind::Put,
                Some(zero.clone()),
                Some("hz"),
                Some(0),
                Some("v2"),
                None,
                None,
                5,
                105,
            ),
            make_record(
                "put",
                OperationKind::Put,
                Some(new.clone()),
                Some("h3"),
                Some(4),
                Some("v3"),
                None,
                None,
                7,
                107,
            ),
            make_record(
                "overwrite",
                OperationKind::Put,
                Some(hot.clone()),
                Some("h4"),
                Some(4),
                Some("v4"),
                None,
                None,
                9,
                109,
            ),
            make_record(
                "delete",
                OperationKind::Delete,
                Some(hot.clone()),
                None,
                None,
                Some("v5"),
                None,
                None,
                11,
                111,
            ),
            make_record(
                "multipart",
                OperationKind::CompleteMultipartUpload,
                Some(large.clone()),
                Some("h6"),
                Some(8),
                Some("v6"),
                None,
                None,
                13,
                113,
            ),
            make_record(
                "abort",
                OperationKind::AbortMultipartUpload,
                Some(format!("{prefix_key}aborted")),
                None,
                None,
                None,
                None,
                None,
                15,
                115,
            ),
        ];
        for record in &mut history_prefix {
            record.durability_cohort = Some(DurabilityCohort::FaultActive);
            record.fault_window_relation = Some(FaultWindowRelation::DuringFault);
        }
        let version_listing = checker::checker_expected_version_listing(&history_prefix)
            .into_iter()
            .collect();
        let live_keys = vec![large.clone(), new.clone(), zero.clone()];
        let mut checker_suffix = vec![
            make_record(
                "checker-get-new",
                OperationKind::Get,
                Some(new.clone()),
                Some("h3"),
                Some(4),
                None,
                None,
                None,
                17,
                210,
            ),
            make_record(
                "checker-get-zero",
                OperationKind::Get,
                Some(zero.clone()),
                Some("hz"),
                Some(0),
                None,
                None,
                None,
                19,
                212,
            ),
            make_record(
                "checker-get-large",
                OperationKind::Get,
                Some(large.clone()),
                Some("h6"),
                Some(8),
                None,
                None,
                None,
                21,
                214,
            ),
            make_record(
                "checker-list",
                OperationKind::List,
                Some(prefix_key.clone()),
                None,
                None,
                None,
                Some(live_keys),
                None,
                23,
                216,
            ),
            make_record(
                "checker-list-versions",
                OperationKind::ListVersions,
                Some(prefix_key.clone()),
                None,
                None,
                None,
                None,
                Some(version_listing),
                25,
                218,
            ),
        ];
        let version_checks = [
            (&hot, "v1", "h1", 4_usize),
            (&zero, "v2", "hz", 0),
            (&new, "v3", "h3", 4),
            (&hot, "v4", "h4", 4),
            (&large, "v6", "h6", 8),
        ];
        for (index, (key, version_id, sha, size)) in version_checks.iter().enumerate() {
            checker_suffix.push(make_record(
                &format!("checker-version-{index}"),
                OperationKind::Get,
                Some((*key).clone()),
                Some(sha),
                Some(*size),
                Some(version_id),
                None,
                None,
                27 + index as u64 * 2,
                220 + index as u64 * 2,
            ));
        }
        let mut deleted_get = make_record(
            "checker-get-deleted",
            OperationKind::Get,
            Some(hot.clone()),
            None,
            None,
            None,
            None,
            None,
            37,
            232,
        );
        deleted_get.outcome = OperationOutcome::NotFound;
        deleted_get.http_status = Some(404);
        checker_suffix.push(deleted_get);
        let mut data_version_checks = version_checks
            .iter()
            .map(
                |(key, version_id, sha, _)| checker::CheckerDataVersionAudit {
                    key: (*key).clone(),
                    version_id: (*version_id).to_string(),
                    expected_sha256: (*sha).to_string(),
                    observed_sha256: Some((*sha).to_string()),
                    outcome: OperationOutcome::Ok,
                    http_status: Some(200),
                },
            )
            .collect::<Vec<_>>();
        data_version_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        let checker = json!({
            "scenario": ADMIN_DECOMMISSION_SCENARIO,
            "run_id": run_id,
            "committed_puts": 5,
            "expected_live_objects": 3,
            "verified_live_objects": 3,
            "missing_committed_objects": [],
            "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [],
            "hash_mismatches": [],
            "successful_corrupted_reads": [],
            "unexpected_visible_deleted_objects": [],
            "list_history_warning_count": 0,
            "final_list_warning_count": 0,
            "list_history_warnings": [],
            "list_warnings": [],
            "final_listed_objects": 3,
            "versioning_expected": true,
            "expected_committed_versions": 5,
            "verified_committed_versions": 5,
            "operation_cohorts": {"fault_active": 8},
            "fault_window_relations": {"during_fault": 8},
            "audit": {
                "bucket": bucket,
                "started_at_ms": 210,
                "completed_at_ms": 240,
                "history_prefix_record_count": history_prefix.len(),
                "history_prefix_sha256": checker::checker_history_records_sha256(&history_prefix).expect("prefix digest"),
                "history_suffix_record_count": checker_suffix.len(),
                "history_suffix_sha256": checker::checker_history_records_sha256(&checker_suffix).expect("suffix digest"),
                "suffix_operations": checker::checker_operation_audits(&checker_suffix),
                "data_version_checks": data_version_checks,
                "delete_marker_checks": [{"key": hot, "version_id": "v5", "visible_in_list_object_versions": true}],
                "list_object_versions_completed": true
            },
            "tenant_recovered": true,
            "passed": true
        });
        history_prefix.extend(checker_suffix);
        fs::write(
            dir.path().join("history.jsonl"),
            format!(
                "{}\n",
                history_prefix
                    .iter()
                    .map(|record| serde_json::to_string(record).expect("history record"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .expect("history");
        write_json(dir.path(), "checker-report.json", &checker);
        write_json(
            dir.path(),
            ADMIN_DECOMMISSION_OVERLAP_ARTIFACT,
            &json!({
                "runId": run_id,
                "caseName": case_name,
                "tenantUid": "tenant-uid",
                "operationId": "decommission:1:2026-09-05T00:00:00Z",
                "targetPoolId": 1,
                "targetPoolExpression": target,
                "decommissionStartedAtMs": 100,
                "decommissionCompletedAtMs": 200,
                "workloadStartedAtMs": 107,
                "workloadEndedAtMs": 200,
                "workloadFirstEventSequence": 7,
                "workloadLastEventSequence": 16,
                "workloadOperationIds": ["put", "overwrite", "delete", "multipart", "abort"],
                "overlappingOperationIds": ["put", "overwrite", "delete", "multipart", "abort"],
                "overlappingStatusRequestIds": ["decommission-status-request"]
            }),
        );
        let operation = read_json::<Value>(&dir.path().join("admin-operation.json"))
            .expect("operation artifact");
        let progress = read_jsonl::<Value>(&dir.path().join("admin-operation-progress.jsonl"))
            .expect("progress artifact");
        write_json(
            dir.path(),
            ADMIN_DECOMMISSION_TRANSCRIPT_ARTIFACT,
            &json!({
                "operationId": operation["operationId"],
                "requests": operation["requests"],
                "progress": progress,
            }),
        );

        validate_admin_topology_artifact_files(
            "admin-decommission",
            &attempt,
            attempt_window,
            dir.path(),
        )
        .expect("valid admin evidence");
        let proof_path = dir.path().join("admin-topology-proof.json");
        let valid_proof = serde_json::from_slice::<Value>(
            &fs::read(&proof_path).expect("topology proof artifact"),
        )
        .expect("topology proof JSON");
        let mut same_uid_spec_drift = valid_proof.clone();
        let mut drifted_receipt = serde_json::from_str::<Value>(
            same_uid_spec_drift["runtime"]["target"]["endpoint"]["tenantResponseBody"]
                .as_str()
                .expect("Tenant receipt body"),
        )
        .expect("Tenant receipt JSON");
        drifted_receipt["spec"]["pools"][0]["persistence"]["path"] = json!("/forged");
        let drifted_body = serde_json::to_string(&drifted_receipt).expect("drifted Tenant receipt");
        same_uid_spec_drift["runtime"]["target"]["endpoint"]["tenantResponseSha256"] =
            json!(hex::encode(Sha256::digest(drifted_body.as_bytes())));
        same_uid_spec_drift["runtime"]["target"]["endpoint"]["tenantResponseBody"] =
            json!(drifted_body);
        write_json(
            dir.path(),
            "admin-topology-proof.json",
            &same_uid_spec_drift,
        );
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "same-UID Tenant spec drift must not override the authenticated topology receipt"
        );
        write_json(dir.path(), "admin-topology-proof.json", &valid_proof);
        let mut incomplete_operation_cycle = valid_workload_plan.clone();
        incomplete_operation_cycle["object_count"] = json!(2);
        incomplete_operation_cycle["total_payload_bytes"] = json!(200);
        incomplete_operation_cycle["size_distribution"] =
            json!([{"size_bytes": 100, "object_count": 2}]);
        write_json(
            dir.path(),
            "workload-plan.json",
            &incomplete_operation_cycle,
        );
        let incomplete_error = validate_admin_topology_artifact_files(
            "admin-decommission",
            &attempt,
            attempt_window,
            dir.path(),
        )
        .expect_err("incomplete operation cycle must fail closed");
        assert!(
            incomplete_error
                .to_string()
                .contains("complete operation-mix cycle")
        );
        write_json(dir.path(), "workload-plan.json", &valid_workload_plan);
        let valid_operation = serde_json::from_slice::<Value>(
            &fs::read(dir.path().join("admin-operation.json")).expect("operation artifact"),
        )
        .expect("operation artifact JSON");
        let mut cross_deployment = valid_operation.clone();
        cross_deployment["requests"][0]["target"]["deploymentId"] =
            json!("deployment-from-another-cluster");
        write_json(dir.path(), "admin-operation.json", &cross_deployment);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "a destructive request captured through another RustFS deployment must fail closed"
        );
        let mut cross_cluster = valid_operation.clone();
        cross_cluster["poolsAfter"]["runtime"]["target"]["endpoint"]["clusterUid"] =
            json!("replacement-cluster-uid");
        write_json(dir.path(), "admin-operation.json", &cross_cluster);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "post-operation evidence from another Kubernetes cluster must fail closed"
        );
        let mut missing_tenant_raw = valid_operation.clone();
        missing_tenant_raw["poolsBefore"]["tenantGet"]
            .as_object_mut()
            .expect("pre-operation Tenant GET")
            .remove("responseBody");
        write_json(dir.path(), "admin-operation.json", &missing_tenant_raw);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "Tenant identity without its raw Kubernetes GET response must fail closed"
        );
        let mut missing_pool_raw = valid_operation.clone();
        missing_pool_raw["poolsBefore"]["request"]
            .as_object_mut()
            .expect("pre-operation pool request")
            .remove("responseBody");
        write_json(dir.path(), "admin-operation.json", &missing_pool_raw);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "pool snapshot without its raw RustFS response must fail closed"
        );
        let mut bad_pool_digest = valid_operation.clone();
        bad_pool_digest["poolsAfter"]["request"]["responseSha256"] = Value::String("c".repeat(64));
        write_json(dir.path(), "admin-operation.json", &bad_pool_digest);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "pool snapshot with a mismatched response digest must fail closed"
        );
        let mut forged_pool_raw = valid_operation.clone();
        let forged_pool_body = "[]";
        forged_pool_raw["poolsBefore"]["request"]["responseSha256"] =
            Value::String(hex::encode(Sha256::digest(forged_pool_body.as_bytes())));
        forged_pool_raw["poolsBefore"]["request"]["responseBody"] =
            Value::String(forged_pool_body.to_string());
        write_json(dir.path(), "admin-operation.json", &forged_pool_raw);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "self-consistent pools/list wire tampering must not change snapshot fields"
        );
        let mut missing_raw = valid_operation.clone();
        missing_raw["requests"][1]
            .as_object_mut()
            .expect("status request")
            .remove("responseBody");
        write_json(dir.path(), "admin-operation.json", &missing_raw);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "status evidence without the raw RustFS body must fail closed"
        );
        let mut forged_raw = valid_operation.clone();
        let forged_body = serde_json::to_string(&json!({
            "id": 1,
            "cmdline": target,
            "status": "complete",
            "poolStatus": "decommissioned",
            "decommissionInfo": {
                "startTime": "2026-09-05T00:00:00Z",
                "complete": true,
                "objectsDecommissioned": 999,
                "bytesDecommissioned": 200
            }
        }))
        .expect("forged terminal status");
        forged_raw["requests"][1]["responseSha256"] =
            Value::String(hex::encode(Sha256::digest(forged_body.as_bytes())));
        forged_raw["requests"][1]["responseBody"] = Value::String(forged_body);
        write_json(dir.path(), "admin-operation.json", &forged_raw);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err(),
            "self-consistent raw status tampering must not change derived operation counters"
        );
        write_json(dir.path(), "admin-operation.json", &valid_operation);
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                AdminAttemptWindow {
                    started_at_ms: 101,
                    evaluated_at_ms: 300,
                },
                dir.path(),
            )
            .is_err()
        );
        let mut stale_attempt = attempt.clone();
        stale_attempt.run_id = "run-admin-old".to_string();
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &stale_attempt,
                attempt_window,
                dir.path(),
            )
            .is_err()
        );
        write_json(
            dir.path(),
            "workload-plan.json",
            &json!({
                "scenario": "admin-decommission",
                "run_id": "run-admin-1",
                "total_payload_bytes": 101
            }),
        );
        assert!(
            validate_admin_topology_artifact_files(
                "admin-decommission",
                &attempt,
                attempt_window,
                dir.path(),
            )
            .is_err()
        );
        write_json(dir.path(), "workload-plan.json", &valid_workload_plan);

        fs::write(
            progress_path,
            concat!(
                "{\"runId\":\"run-admin-1\",\"caseName\":\"fault_admin_decommission_preserves_object_model\",\"tenantUid\":\"tenant-uid\",",
                "\"operationId\":\"decommission:1:2026-09-05T00:00:00Z\",",
                "\"statusRequestId\":\"decommission-status-request\",",
                "\"observedAtMs\":200,\"state\":\"canceled\",\"completed\":true,",
                "\"failed\":false,\"canceledOrStopped\":true,",
                "\"objectsMoved\":2,\"bytesMoved\":200}\n"
            ),
        )
        .expect("canceled progress");
        let error = validate_admin_topology_artifact_files(
            "admin-decommission",
            &attempt,
            attempt_window,
            dir.path(),
        )
        .expect_err("canceled evidence");
        assert!(error.to_string().contains("cannot pass"));
    }

    #[test]
    fn validates_successful_fault_artifacts() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let report = validate_fault_artifacts(&options).expect("valid artifacts");

        assert_eq!(report.scenario, "io-eio");
        assert_eq!(
            report.validation_summary_tsv_row(),
            "io-eio\t42\t0\t2\t1\t2\t0\t0\t0\t0\ttrue"
        );
    }

    #[test]
    fn io_eio_success_requires_redundant_topology_bound_to_the_fault_cohort() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let proof_path = case_dir.join("target-proof.json");
        let mut proof: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&proof_path).expect("target proof"))
                .expect("target proof JSON");
        proof["faults"][0]["erasureSet"]["shape"]["payloadDataShards"] = json!(4);
        proof["faults"][0]["erasureSet"]["shape"]["payloadParityShards"] = json!(0);
        write_json(&case_dir, "target-proof.json", &proof);

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("zero-parity topology cannot support an availability claim");
        assert!(
            error
                .to_string()
                .contains("does not establish a read/write availability boundary"),
            "{error:#}"
        );

        write_success_artifacts(dir.path(), "io-eio");
        let evidence_path = case_dir.join("fault-evidence.json");
        let mut evidence: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&evidence_path).expect("fault evidence"))
                .expect("fault evidence JSON");
        evidence["pods_before"][3]["uid"] = json!("replacement-uid");
        write_json(&case_dir, "fault-evidence.json", &evidence);

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("topology proof cannot describe a different Pod cohort");
        assert!(
            error
                .to_string()
                .contains("topology Pods do not match fault-evidence.json pods_before"),
            "{error:#}"
        );
    }

    #[test]
    fn successful_artifact_validation_requires_history_bound_checker_audits() {
        for name in ["checker-pre-recommit-report.json", "checker-report.json"] {
            let dir = tempfile::tempdir().expect("tempdir");
            write_success_artifacts(dir.path(), "io-eio");
            let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
            let path = case_dir.join(name);
            let mut report: serde_json::Value =
                serde_json::from_str(&fs::read_to_string(&path).expect("checker report"))
                    .expect("checker JSON");
            report
                .as_object_mut()
                .expect("checker object")
                .remove("audit");
            write_json(&case_dir, name, &report);

            let error = validate_fault_artifacts(&success_options(dir.path()))
                .expect_err("a successful current report cannot omit its audit");
            assert!(format!("{error:#}").contains("history-bound audit"));
        }
    }

    #[test]
    fn final_checker_audit_must_cover_terminal_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join("history.jsonl");
        let current = fs::read_to_string(&path).expect("history");
        let appended = json!({
            "id": "op-000004",
            "scenario": "io-eio",
            "run_id": "run-00000000-0000-4000-8000-000000000001",
            "kind": "put",
            "bucket": "bucket",
            "key": "late-key",
            "value_sha256": "late-sha",
            "size_bytes": 1,
            "started_at_ms": 16,
            "ended_at_ms": 17,
            "outcome": "ok",
            "http_status": 200,
            "error": null
        });
        fs::write(&path, format!("{current}{appended}\n")).expect("append history mutation");

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("final checker cannot ignore a later history mutation");
        assert!(format!("{error:#}").contains("terminal history.jsonl record"));
    }

    #[test]
    fn checker_phase_audits_must_be_ordered_and_independent() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let final_report =
            fs::read_to_string(case_dir.join("checker-report.json")).expect("final checker report");
        fs::write(
            case_dir.join("checker-pre-recommit-report.json"),
            final_report,
        )
        .expect("copy final checker report over pre-recommit report");

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("a final audit cannot stand in for the pre-recommit phase");
        assert!(
            format!("{error:#}").contains("authenticated pre-recommit history"),
            "{error:#}"
        );
    }

    #[test]
    fn recommit_report_must_match_history_between_checker_phases() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join("recommit-report.json");
        let mut recommit: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("recommit report"))
                .expect("recommit JSON");
        recommit["attempts"][0]["sha256"] = json!("forged-sha");
        write_json(&case_dir, "recommit-report.json", &recommit);

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("recommit report must be bound to its history operations");
        assert!(
            format!("{error:#}").contains("sealed candidate manifest"),
            "{error:#}"
        );
    }

    #[test]
    fn recommit_candidates_cannot_be_omitted_from_the_sealed_manifest() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join("workload-summary.json");
        let mut summary: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("workload summary"))
                .expect("summary JSON");
        summary["recommit_candidates"]["candidates"] = json!([]);
        write_json(&case_dir, "workload-summary.json", &summary);

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("an authenticated final ambiguous mutation cannot be omitted");
        assert!(
            format!("{error:#}").contains("final unconfirmed mutations"),
            "{error:#}"
        );
    }

    #[test]
    fn recommit_history_must_use_the_run_bucket() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_history_and_refresh_final_audit(&case_dir, |records| {
            for record in &mut records[4..6] {
                record.bucket = "other-bucket".to_string();
            }
        });

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("recommit evidence from another bucket must be rejected");
        assert!(
            format!("{error:#}").contains("outside the checker run"),
            "{error:#}"
        );
    }

    #[test]
    fn recommit_put_must_happen_before_its_verification_get() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_history_and_refresh_final_audit(&case_dir, |records| {
            let put_ended = records[4].ended_sequence;
            records[4].ended_sequence = records[5].started_sequence;
            records[5].started_sequence = put_ended;
        });

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("verification GET must begin after its candidate PUT ended");
        assert!(
            format!("{error:#}").contains("happens-before order"),
            "{error:#}"
        );
    }

    #[test]
    fn checker_phase_chain_rejects_cross_phase_sequence_overlap() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let original = read_jsonl::<OperationRecord>(&case_dir.join("history.jsonl"))
            .expect("fixture history");
        let prechecker =
            read_json::<CheckerReport>(&case_dir.join("checker-pre-recommit-report.json"))
                .expect("prechecker");
        let checker =
            read_json::<CheckerReport>(&case_dir.join("checker-report.json")).expect("checker");
        let recommit = read_json::<RecommitReportArtifact>(&case_dir.join("recommit-report.json"))
            .expect("recommit");
        let summary = read_json::<WorkloadSummaryArtifact>(&case_dir.join("workload-summary.json"))
            .expect("summary");
        let manifest = summary.recommit_candidates.as_ref().expect("manifest");
        let pre_audit = prechecker.audit.as_ref().expect("pre audit");
        let pre_end = pre_audit.history_prefix_record_count + pre_audit.history_suffix_record_count;
        let final_prefix_count = checker
            .audit
            .as_ref()
            .expect("final audit")
            .history_prefix_record_count;

        for (left, right, boundary) in [
            (pre_end - 1, pre_end, "prechecker/recommit"),
            (
                final_prefix_count - 1,
                final_prefix_count,
                "recommit/final-checker",
            ),
        ] {
            let mut history = original.clone();
            let left_end = history[left].ended_sequence.expect("left end");
            let right_start = history[right].started_sequence.expect("right start");
            history[left].ended_sequence = Some(right_start);
            history[right].started_sequence = Some(left_end);

            let error = validate_checker_phase_chain(
                &prechecker,
                &checker,
                &recommit,
                manifest,
                "bucket",
                &history,
            )
            .expect_err("cross-phase operations must not overlap");
            assert!(error.to_string().contains(boundary), "{error:#}");
        }
    }

    #[test]
    fn offline_candidate_derivation_scales_to_twenty_thousand_keys() {
        const CANDIDATES: usize = 20_000;
        let records = (0..CANDIDATES)
            .map(|index| OperationRecord {
                id: format!("op-{index:06}"),
                scenario: "storage".to_string(),
                run_id: Some("run-1".to_string()),
                kind: OperationKind::Put,
                bucket: "bucket".to_string(),
                key: Some(format!("key-{index:06}")),
                value_sha256: Some(format!("hash-{index:06}")),
                size_bytes: Some(1),
                version_id: None,
                listed_keys: None,
                listed_versions: None,
                payload_ref: None,
                range: None,
                started_sequence: Some((index as u64) * 2 + 1),
                ended_sequence: Some((index as u64) * 2 + 2),
                started_at_ms: (index as u64) * 2 + 1,
                ended_at_ms: (index as u64) * 2 + 2,
                outcome: OperationOutcome::Timeout,
                http_status: None,
                error: Some("timeout".to_string()),
                durability_cohort: None,
                fault_window_relation: None,
            })
            .collect::<Vec<_>>();

        let candidates = derive_recommit_candidates(&records).expect("linear derivation");
        assert_eq!(candidates.len(), CANDIDATES);
    }

    #[test]
    fn checker_phase_chain_accepts_zero_recommit_candidates() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let mut history = read_jsonl::<OperationRecord>(&case_dir.join("history.jsonl"))
            .expect("read fixture history");
        history[1].outcome = OperationOutcome::Ok;
        history[1].http_status = Some(200);
        history[1].error = None;
        history.drain(4..6);
        for (index, record) in history.iter_mut().enumerate() {
            record.started_sequence = Some((index as u64) * 2 + 1);
            record.ended_sequence = Some((index as u64) * 2 + 2);
        }
        let pre_prefix = &history[..2];
        let final_prefix = &history[..4];

        let mut prechecker =
            read_json::<CheckerReport>(&case_dir.join("checker-pre-recommit-report.json"))
                .expect("prechecker");
        let mut checker =
            read_json::<CheckerReport>(&case_dir.join("checker-report.json")).expect("checker");
        let pre_audit = prechecker.audit.as_mut().expect("pre audit");
        pre_audit.history_prefix_sha256 =
            checker::checker_history_records_sha256(pre_prefix).expect("pre digest");
        let final_audit = checker.audit.as_mut().expect("final audit");
        final_audit.history_prefix_record_count = final_prefix.len();
        final_audit.history_prefix_sha256 =
            checker::checker_history_records_sha256(final_prefix).expect("final digest");
        let manifest = RecommitCandidateManifestArtifact {
            scenario: "io-eio".to_string(),
            run_id: "run-00000000-0000-4000-8000-000000000001".to_string(),
            bucket: "bucket".to_string(),
            history_record_count: pre_prefix.len(),
            history_sha256: checker::checker_history_records_sha256(pre_prefix)
                .expect("manifest digest"),
            candidates: Vec::new(),
        };
        let recommit = RecommitReportArtifact {
            scenario: Some("io-eio".to_string()),
            run_id: Some("run-00000000-0000-4000-8000-000000000001".to_string()),
            attempted: 0,
            committed: 0,
            failed: 0,
            harness_errors: 0,
            attempts: Vec::new(),
        };

        validate_checker_phase_chain(
            &prechecker,
            &checker,
            &recommit,
            &manifest,
            "bucket",
            &history,
        )
        .expect("zero-candidate phase chain");
    }

    #[test]
    fn strict_success_validation_rejects_a_copied_attempt_bundle() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let options = success_options(dir.path());

        validate_fault_artifacts_for_planned_attempt_and_write_report(
            &options,
            "run-00000000-0000-4000-8000-000000000001",
        )
        .expect("current bundle");
        let error = validate_fault_artifacts_for_planned_attempt_and_write_report(
            &options,
            "run-00000000-0000-4000-8000-000000000002",
        )
        .expect_err("copied prior-attempt bundle");
        assert!(error.to_string().contains("planned attempt"));
    }

    #[test]
    fn strict_success_validation_rejects_missing_fault_evidence_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join("fault-evidence.json");
        let mut evidence: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("evidence")).expect("json");
        evidence.as_object_mut().expect("object").remove("run_id");
        write_json(&case_dir, "fault-evidence.json", &evidence);
        let options = success_options(dir.path());

        validate_fault_artifacts(&options).expect("explicit legacy-compatible validation");
        let error = validate_fault_artifacts_for_planned_attempt_and_write_report(
            &options,
            "run-00000000-0000-4000-8000-000000000001",
        )
        .expect_err("missing current identity");
        assert!(error.to_string().contains("fault-evidence.json identity"));
    }

    #[test]
    fn every_validation_mode_rejects_a_checker_from_another_attempt() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join("checker-report.json");
        let mut checker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("checker")).expect("json");
        checker["run_id"] = json!("legacy-run");
        write_json(&case_dir, "checker-report.json", &checker);
        let options = success_options(dir.path());

        let legacy_error =
            validate_fault_artifacts(&options).expect_err("legacy mode must reject a conflict");
        assert!(
            legacy_error
                .to_string()
                .contains("checker-report.json identity")
        );
        let error = validate_fault_artifacts_for_planned_attempt_and_write_report(
            &options,
            "run-00000000-0000-4000-8000-000000000001",
        )
        .expect_err("checker from another attempt");
        assert!(error.to_string().contains("checker-report.json identity"));
    }

    #[test]
    fn verdict_artifact_identity_conflicts_are_rejected_in_every_mode() {
        for name in [
            "preflight-summary.json",
            "history.jsonl",
            "recommit-report.json",
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            write_success_artifacts(dir.path(), "io-eio");
            let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
            let path = case_dir.join(name);
            if name == "history.jsonl" {
                rewrite_first_history_record(&path, |record| {
                    record["run_id"] = json!("run-old");
                });
            } else {
                let mut artifact: serde_json::Value =
                    serde_json::from_str(&fs::read_to_string(&path).expect("artifact"))
                        .expect("json");
                let key = if name == "preflight-summary.json" {
                    "runId"
                } else {
                    "run_id"
                };
                artifact[key] = json!("run-old");
                write_json(&case_dir, name, &artifact);
            }
            let options = success_options(dir.path());
            let legacy = validate_fault_artifacts(&options)
                .expect_err("legacy-compatible validation must reject an identity conflict");
            assert!(format!("{legacy:#}").contains(name), "{legacy:#}");
            let strict = validate_fault_artifacts_for_planned_attempt_and_write_report(
                &options,
                "run-00000000-0000-4000-8000-000000000001",
            )
            .expect_err("strict validation must reject an identity conflict");
            assert!(format!("{strict:#}").contains(name), "{strict:#}");
        }
    }

    #[test]
    fn strict_verdict_artifacts_require_additive_identity_fields() {
        for name in [
            "preflight-summary.json",
            "history.jsonl",
            "recommit-report.json",
        ] {
            let dir = tempfile::tempdir().expect("tempdir");
            write_success_artifacts(dir.path(), "io-eio");
            let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
            let path = case_dir.join(name);
            if name == "history.jsonl" {
                rewrite_first_history_record(&path, |record| {
                    record.as_object_mut().expect("object").remove("run_id");
                });
            } else {
                let mut artifact: serde_json::Value =
                    serde_json::from_str(&fs::read_to_string(&path).expect("artifact"))
                        .expect("json");
                let key = if name == "preflight-summary.json" {
                    "runId"
                } else {
                    "run_id"
                };
                artifact.as_object_mut().expect("object").remove(key);
                write_json(&case_dir, name, &artifact);
            }
            let options = success_options(dir.path());
            if name == "history.jsonl" {
                let legacy = validate_fault_artifacts(&options)
                    .expect_err("history identity removal invalidates the checker audit");
                assert!(format!("{legacy:#}").contains("audit"));
            } else {
                validate_fault_artifacts(&options).expect("legacy additive field may be absent");
            }
            let strict = validate_fault_artifacts_for_planned_attempt_and_write_report(
                &options,
                "run-00000000-0000-4000-8000-000000000001",
            )
            .expect_err("strict validation requires current identity");
            assert!(format!("{strict:#}").contains(name), "{strict:#}");
        }
    }

    #[test]
    fn strict_success_validation_rejects_invalid_history_jsonl() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        fs::write(case_dir.join("history.jsonl"), "{}\n").expect("invalid history");
        let error = validate_fault_artifacts_for_planned_attempt_and_write_report(
            &success_options(dir.path()),
            "run-00000000-0000-4000-8000-000000000001",
        )
        .expect_err("invalid operation record must fail closed");
        assert!(format!("{error:#}").contains("history.jsonl"));
    }

    #[test]
    fn strict_success_validation_rejects_mixed_attempt_history() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join("history.jsonl");
        let current = fs::read_to_string(&path).expect("history");
        let mut other: serde_json::Value =
            serde_json::from_str(current.lines().next().expect("history record"))
                .expect("operation record");
        other["id"] = json!("op-000002");
        other["run_id"] = json!("run-old");
        fs::write(&path, format!("{current}{other}\n")).expect("mixed history");

        let error = validate_fault_artifacts_for_planned_attempt_and_write_report(
            &success_options(dir.path()),
            "run-00000000-0000-4000-8000-000000000001",
        )
        .expect_err("every operation record must match the planned attempt");
        assert!(format!("{error:#}").contains("history.jsonl"));
    }

    #[test]
    fn accepts_self_contained_detector_contract_after_catalog_evolution() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_run_spec_detector(
            &case_dir,
            json!({
                "revision": 1,
                "qualification": "gate-candidate",
                "detects": ["commit-metadata-loss"]
            }),
        );
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        validate_fault_artifacts(&options).expect("self-contained historical detector contract");
        let error = validate_fault_artifacts_for_planned_attempt_and_write_report(
            &options,
            "run-00000000-0000-4000-8000-000000000001",
        )
        .expect_err("current attempts must match their detector contract");
        assert!(error.to_string().contains("detector contract"));
    }

    #[test]
    fn accepts_legacy_run_spec_without_detector_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_run_spec_without_detector(&case_dir);
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        validate_fault_artifacts(&options).expect("legacy run spec");
        assert!(
            validate_fault_artifacts_for_planned_attempt_and_write_report(
                &options,
                "run-00000000-0000-4000-8000-000000000001",
            )
            .unwrap_err()
            .to_string()
            .contains("detector contract")
        );
    }

    #[test]
    fn rejects_unknown_detector_contract_revision() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_run_spec_detector(
            &case_dir,
            json!({
                "revision": 2,
                "qualification": "gate-candidate",
                "detects": ["data-shard-loss"]
            }),
        );
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("unknown detector revision");
        assert!(error.to_string().contains("detector contract"));
    }

    #[test]
    fn percent_volume_artifacts_accept_csi_pv_without_hostname_affinity() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = "io-latency".to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("percent plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let run_spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs([TargetResolvedPodProof::new("rustfs-0", "uid-0")
                .with_node("node-a")
                .with_ready(true)
                .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-0".to_string(),
                    volume_name: Some("pv-csi".to_string()),
                    storage_class: Some("fast-csi".to_string()),
                    persistent_volume: Some(TargetPersistentVolumeProof {
                        name: "pv-csi".to_string(),
                        uid: "pv-uid-0".to_string(),
                        source: Some("csi".to_string()),
                        required_node_affinity: None,
                        node: None,
                        device_or_path: Some("csi-volume-handle".to_string()),
                    }),
                }])]);
        let options = ArtifactValidationOptions {
            scenario: scenario.name.clone(),
            artifact_root: std::path::PathBuf::from("unused"),
            expected_workload_objects: scenario.object_count,
            expected_workload_concurrency: config.workload.concurrency,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: config.expected_rustfs_pod_count,
            expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
            expected_recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
            expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
        };

        validate_run_spec(&run_spec, &options).expect("canonical percent run spec");
        validate_target_proof(&proof, &run_spec, &options)
            .expect("CSI PV without hostname affinity remains valid for percent mode");
    }

    #[test]
    fn fixed_volume_runtime_evidence_binds_plan_proof_status_and_drift() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = "io-latency".to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::new(
            scenario.name.clone(),
            scenario.case_name,
            crate::fault::plan::FaultWorkloadMode::S3Mixed,
            vec![
                FaultInjection::new(
                    FaultKind::RustfsVolumeIoError,
                    crate::fault::scenarios::FaultBackend::ChaosMeshIoChaos,
                    FaultTarget::RustfsVolume {
                        path: "/data/rustfs0".to_string(),
                    },
                    FaultSelection::FixedTargets(2),
                    Duration::from_secs(60),
                )
                .expect("fixed volume injection"),
            ],
        )
        .expect("fixed volume plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let run_spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );
        let volume_pod = |index| {
            let mut pod =
                TargetResolvedPodProof::new(format!("rustfs-{index}"), format!("uid-{index}"))
                    .with_node(format!("node-{index}"))
                    .with_node_labels(BTreeMap::from([(
                        "kubernetes.io/hostname".to_string(),
                        format!("node-{index}"),
                    )]))
                    .with_ready(true)
                    .with_volume_mounts(vec![TargetVolumeMountProof {
                        container_name: "rustfs".to_string(),
                        mount_path: "/data/rustfs0".to_string(),
                        volume_name: format!("data-{index}"),
                        persistent_volume_claim: Some(format!("data-{index}")),
                    }])
                    .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                        name: format!("data-{index}"),
                        uid: format!("pvc-uid-{index}"),
                        volume_name: Some(format!("pv-{index}")),
                        storage_class: Some("fast-csi".to_string()),
                        persistent_volume: Some(TargetPersistentVolumeProof {
                            name: format!("pv-{index}"),
                            uid: format!("pv-uid-{index}"),
                            source: Some("local".to_string()),
                            required_node_affinity: Some(TargetNodeAffinityProof {
                                well_formed: true,
                                terms: vec![TargetNodeSelectorTermProof {
                                    match_expressions: vec![TargetNodeSelectorRequirementProof {
                                        key: "kubernetes.io/hostname".to_string(),
                                        operator: "In".to_string(),
                                        values: vec![format!("node-{index}")],
                                    }],
                                    match_fields: Vec::new(),
                                }],
                            }),
                            node: Some(format!("node-{index}")),
                            device_or_path: Some(format!("/dev/disk-{index}")),
                        }),
                    }]);
            pod.rustfs_container_id = Some(format!("containerd://rustfs-{index}"));
            pod
        };
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs((0..3).map(volume_pod));
        let insufficient = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs((0..1).map(volume_pod));
        assert!(insufficient.require_satisfied().is_err());
        let options = ArtifactValidationOptions {
            scenario: scenario.name.clone(),
            artifact_root: std::path::PathBuf::from("unused"),
            expected_workload_objects: scenario.object_count,
            expected_workload_concurrency: config.workload.concurrency,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: config.expected_rustfs_pod_count,
            expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
            expected_recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
            expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
        };
        assert!(
            validate_run_spec(&run_spec, &options).is_err(),
            "current catalog has no executable fixed-volume selection source"
        );
        validate_target_proof(&proof, &run_spec, &options).expect("fixed volume target proof");

        let mut unproved_candidate = volume_pod(2);
        unproved_candidate.volume_mounts[0].mount_path = "/unrelated-logs".to_string();
        let mixed_candidates = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs([volume_pod(0), volume_pod(1), unproved_candidate.clone()]);
        assert!(
            mixed_candidates.require_satisfied().is_err(),
            "two eligible Pods must not permit injection when the selector can also choose an unproved third Pod"
        );
        let mut stale_proof = proof.clone();
        stale_proof.resolved_pods[2] = unproved_candidate;
        assert!(
            validate_target_proof(&stale_proof, &run_spec, &options).is_err(),
            "artifact validation must recheck all candidates even when saved preflight flags passed"
        );

        let namespace = &run_spec.cluster.namespace;
        let target = |index| format!("{namespace}/rustfs-{index}/rustfs");
        let records = vec![
            json!({"id": target(0), "selectorKey": ".", "phase": "Injected", "injectedCount": 1}),
            json!({"id": target(1), "selectorKey": ".", "phase": "Injected", "injectedCount": 1}),
        ];
        let resource = json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": "IOChaos",
            "metadata": {
                "name": "fixed-volume",
                "namespace": run_spec.cluster.chaos_namespace,
                "labels": {
                    "rustfs-fault-test/run-id": run_spec.metadata.run_id,
                    "rustfs-fault-test/scenario": run_spec.scenario.name,
                    "app.kubernetes.io/managed-by": "s3chaos"
                }
            },
            "spec": {
                "action": "fault",
                "errno": 5,
                "mode": "fixed",
                "value": "2",
                "selector": {
                    "namespaces": [namespace],
                    "labelSelectors": {"rustfs.tenant": run_spec.cluster.tenant}
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
                "experiment": {"desiredPhase": "Run", "containerRecords": records}
            }
        });
        let snapshot = |stage: &str, resource: serde_json::Value| {
            json!({
                "stage": stage,
                "resource_kind": "iochaos",
                "resource_name": "fixed-volume",
                "chaos_status": resource
            })
        };
        let mut evidence: FaultEvidenceArtifact = serde_json::from_value(json!({
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": false,
            "client_disruptions": 0,
            "pods_before": (0..3).map(|index| json!({
                "name": format!("rustfs-{index}"),
                "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_at_fault_activation": (0..2).map(|index| json!({
                "name": format!("rustfs-{index}"),
                "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_at_workload_snapshot": (0..2).map(|index| json!({
                "name": format!("rustfs-{index}"),
                "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_after": [],
            "fixed_volume_targets_at_fault_activation": [target(0), target(1)],
            "fixed_volume_targets_at_workload_snapshot": [target(0), target(1)],
            "fixed_volume_containers_at_fault_activation": {
                "rustfs-0": "containerd://rustfs-0", "rustfs-1": "containerd://rustfs-1"
            },
            "fixed_volume_containers_at_workload_snapshot": {
                "rustfs-0": "containerd://rustfs-0", "rustfs-1": "containerd://rustfs-1"
            },
            "active_snapshots": [snapshot("active", resource.clone())],
            "workload_snapshots": [snapshot("after-workload", resource.clone())]
        }))
        .expect("fault evidence");
        validate_fixed_volume_runtime_evidence(&evidence, &proof, &run_spec)
            .expect("fixed volume runtime evidence");
        assert!(
            validate_fixed_volume_runtime_evidence(&evidence, &stale_proof, &run_spec).is_err(),
            "selecting only proved Pods does not repair an unproved preflight candidate"
        );

        for stage in ["activation", "workload", "both"] {
            let mut restarted = evidence.clone();
            if stage != "workload" {
                restarted
                    .fixed_volume_containers_at_fault_activation
                    .insert(
                        "rustfs-0".to_string(),
                        "containerd://replacement".to_string(),
                    );
            }
            if stage != "activation" {
                restarted
                    .fixed_volume_containers_at_workload_snapshot
                    .insert(
                        "rustfs-0".to_string(),
                        "containerd://replacement".to_string(),
                    );
            }
            assert!(
                validate_fixed_volume_runtime_evidence(&restarted, &proof, &run_spec).is_err(),
                "same-UID Pod with a replaced container at {stage} must invalidate IOChaos evidence"
            );
        }
        for stage in ["activation", "workload"] {
            let mut missing = evidence.clone();
            let containers = if stage == "activation" {
                &mut missing.fixed_volume_containers_at_fault_activation
            } else {
                &mut missing.fixed_volume_containers_at_workload_snapshot
            };
            containers.remove("rustfs-0");
            assert!(validate_fixed_volume_runtime_evidence(&missing, &proof, &run_spec).is_err());
        }
        let mut missing_container = proof.clone();
        missing_container.resolved_pods[0].rustfs_container_id = None;
        assert!(
            validate_fixed_volume_runtime_evidence(&evidence, &missing_container, &run_spec)
                .is_err()
        );

        let mut missing_uid = evidence.clone();
        missing_uid.pods_at_fault_activation[0].uid.clear();
        assert!(
            validate_fixed_volume_runtime_evidence(&missing_uid, &proof, &run_spec).is_err(),
            "selected Pod identities require a non-empty UID"
        );
        let mut missing_identities = evidence.clone();
        missing_identities.pods_at_fault_activation.clear();
        assert!(
            validate_fixed_volume_runtime_evidence(&missing_identities, &proof, &run_spec).is_err(),
            "selected Pod identity evidence must not be empty"
        );
        let mut duplicate_name = evidence.clone();
        duplicate_name.pods_at_fault_activation[1].name = "rustfs-0".to_string();
        assert!(
            validate_fixed_volume_runtime_evidence(&duplicate_name, &proof, &run_spec).is_err(),
            "selected Pod identity names must be unique"
        );
        let mut tampered_uid = evidence.clone();
        tampered_uid.pods_at_fault_activation[0].uid = "uid-tampered".to_string();
        assert!(
            validate_fixed_volume_runtime_evidence(&tampered_uid, &proof, &run_spec).is_err(),
            "selected Pod UID must match target-proof and pods_before"
        );
        let mut replacement = evidence.clone();
        replacement.pods_at_workload_snapshot[0].uid = "uid-replacement".to_string();
        assert!(
            validate_fixed_volume_runtime_evidence(&replacement, &proof, &run_spec).is_err(),
            "same-name Pod replacement across snapshots must fail closed"
        );

        let mut wrong_topology = proof.clone();
        wrong_topology.resolved_pods[0].node_labels.insert(
            "kubernetes.io/hostname".to_string(),
            "other-node".to_string(),
        );
        assert!(
            validate_fixed_volume_runtime_evidence(&evidence, &wrong_topology, &run_spec).is_err(),
            "local PV topology must match the selected Pod node"
        );

        let mut wrong_mount = proof.clone();
        wrong_mount.resolved_pods[0].volume_mounts[0].persistent_volume_claim =
            Some("unrelated-logs".to_string());
        assert!(
            validate_fixed_volume_runtime_evidence(&evidence, &wrong_mount, &run_spec).is_err(),
            "the configured mount path must link to its own PVC/PV"
        );

        for (pointer, value) in [
            ("/spec/action", json!("latency")),
            ("/spec/errno", json!(28)),
            ("/spec/methods", json!(["WRITE"])),
            ("/spec/duration", json!("61s")),
        ] {
            let mut tampered = evidence.clone();
            for snapshots in [
                &mut tampered.active_snapshots,
                &mut tampered.workload_snapshots,
            ] {
                *snapshots[0]["chaos_status"]
                    .pointer_mut(pointer)
                    .expect("tamper target") = value.clone();
            }
            assert!(
                validate_fixed_volume_runtime_evidence(&tampered, &proof, &run_spec).is_err(),
                "artifact validation must reject tampered {pointer}"
            );
        }

        evidence.fixed_volume_targets_at_workload_snapshot[1] = target(2);
        assert!(validate_fixed_volume_runtime_evidence(&evidence, &proof, &run_spec).is_err());
        evidence.fixed_volume_targets_at_workload_snapshot[1] = target(1);
        evidence.workload_snapshots[0]["chaos_status"]["status"]["experiment"]["containerRecords"]
            .as_array_mut()
            .expect("records")
            .pop();
        assert!(validate_fixed_volume_runtime_evidence(&evidence, &proof, &run_spec).is_err());

        let mut missing_device = proof;
        missing_device.resolved_pods[0].persistent_volume_claims[0]
            .persistent_volume
            .as_mut()
            .expect("pv")
            .device_or_path = None;
        assert!(validate_target_proof(&missing_device, &run_spec, &options).is_err());
    }

    #[test]
    fn runtime_quorum_artifacts_bind_typed_boundary_to_every_volume() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO.to_string();
        config.scenario_parameters = FaultInjectionParameters::QuorumIo {
            class: QuorumCaseClass::Metadata,
        };
        apply_catalog_defaults(&mut config).expect("quorum defaults");
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            catalog,
            FaultPlanOptions::from_config(&config),
        )
        .expect("semantic plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let run_spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );
        let shape =
            ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 2).expect("runtime shape");
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..4)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![format!("drive-{index}")],
                })
                .collect(),
        )
        .expect("runtime membership");
        let pods = (0..4)
            .map(|index| {
                TargetResolvedPodProof::new(format!("rustfs-{index}"), format!("uid-{index}"))
                    .with_node(format!("node-{index}"))
                    .with_node_labels(BTreeMap::from([(
                        "kubernetes.io/hostname".to_string(),
                        format!("node-{index}"),
                    )]))
                    .with_ready(true)
                    .with_rustfs_container_id(format!("containerd://rustfs-{index}"))
                    .with_volume_mounts(vec![TargetVolumeMountProof {
                        container_name: "rustfs".to_string(),
                        mount_path: "/data/rustfs0".to_string(),
                        volume_name: format!("data-{index}"),
                        persistent_volume_claim: Some(format!("data-{index}")),
                    }])
                    .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                        name: format!("data-{index}"),
                        volume_name: Some(format!("pv-{index}")),
                        uid: format!("pvc-uid-{index}"),
                        storage_class: Some("fast-csi".to_string()),
                        persistent_volume: Some(TargetPersistentVolumeProof {
                            name: format!("pv-{index}"),
                            source: Some("csi".to_string()),
                            uid: format!("pv-uid-{index}"),
                            required_node_affinity: None,
                            node: None,
                            device_or_path: Some(format!("csi://volume-{index}")),
                        }),
                    }])
            })
            .collect::<Vec<_>>();
        let boundary = QuorumVolumeBoundary {
            class: QuorumCaseClass::Metadata,
            beyond_read_tolerance: true,
        };
        let volume_quorum = QuorumVolumeTargetProof::from_runtime(
            &shape,
            &membership,
            boundary,
            (0..4)
                .map(|index| QuorumVolumeBinding {
                    pod_name: format!("rustfs-{index}"),
                    pod_uid: format!("uid-{index}"),
                    container_id: format!("containerd://rustfs-{index}"),
                    mount_path: "/data/rustfs0".to_string(),
                    persistent_volume_claim: format!("data-{index}"),
                    persistent_volume: format!("pv-{index}"),
                    drive_uuid: format!("drive-{index}"),
                    pool_index: 0,
                    set_index: 0,
                })
                .collect(),
        )
        .expect("volume quorum proof");
        assert_eq!(volume_quorum.target_count, 3);
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs(pods)
            .with_erasure_set_topology_proven(
                shape.clone(),
                ErasureSetHealth::from_runtime(4, 4, 0, 0).expect("runtime health"),
                membership.clone(),
                "deployment-1",
                100,
            )
            .expect("topology proof")
            .with_volume_quorum_proven(volume_quorum.clone())
            .expect("drive binding proof");
        let options = ArtifactValidationOptions {
            scenario: scenario.name.clone(),
            artifact_root: std::path::PathBuf::from("unused"),
            expected_workload_objects: scenario.object_count,
            expected_workload_concurrency: config.workload.concurrency,
            expected_workload_versioning: true,
            expected_rustfs_pod_count: config.expected_rustfs_pod_count,
            expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
            expected_recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
            expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
        };

        validate_run_spec(&run_spec, &options).expect("semantic run spec");
        validate_target_proof(&proof, &run_spec, &options).expect("runtime quorum target proof");

        for field in ["pod_uid", "container_id", "mount_path", "pvc", "pv"] {
            let mut tampered = proof.clone();
            let candidate = tampered.faults[0]
                .erasure_set
                .as_mut()
                .and_then(|erasure| erasure.volume_quorum.as_mut())
                .and_then(|quorum| quorum.candidates.first_mut())
                .expect("first volume quorum candidate");
            match field {
                "pod_uid" => candidate.pod_uid = "replacement-uid".to_string(),
                "container_id" => candidate.container_id = "containerd://replacement".to_string(),
                "mount_path" => candidate.mount_path = "/data/replacement".to_string(),
                "pvc" => candidate.persistent_volume_claim = "replacement-pvc".to_string(),
                "pv" => candidate.persistent_volume = "replacement-pv".to_string(),
                _ => unreachable!(),
            }
            assert!(
                validate_target_proof(&tampered, &run_spec, &options).is_err(),
                "runtime quorum candidate {field} must match resolvedPods exactly"
            );
        }

        let health = |started_at_ms, completed_at_ms| QuorumHealthObservation {
            started_at_ms,
            completed_at_ms,
            deployment_id: "deployment-1".to_string(),
            shape: shape.clone(),
            drives: (0..4)
                .map(|index| QuorumDriveHealth {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    drive_uuid: format!("drive-{index}"),
                    state: if index < 3 { "offline" } else { "ok" }.to_string(),
                    pool_index: 0,
                    set_index: 0,
                })
                .collect(),
        };
        let mut health_evidence = serde_json::from_value::<FaultEvidenceArtifact>(json!({
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": false,
            "client_disruptions": 0,
            "pods_before": (0..4).map(|index| json!({
                "name": format!("rustfs-{index}"), "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_at_fault_activation": (0..3).map(|index| json!({
                "name": format!("rustfs-{index}"), "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_at_workload_snapshot": (0..3).map(|index| json!({
                "name": format!("rustfs-{index}"), "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_after": [],
            "active_snapshots": [],
            "workload_snapshots": [],
            "fault_active_at_ms": 200,
            "workload_started_at_ms": 250,
            "workload_ended_at_ms": 300,
            "fault_delete_started_at_ms": 350,
            "quorum_health_before_workload": health(210, 220),
            "quorum_health_after_workload": health(310, 320)
        }))
        .expect("quorum health evidence");
        validate_volume_quorum_health_evidence(&health_evidence, &proof, &[])
            .expect("both bounded quorum health observations");

        let saved_before = health_evidence.quorum_health_before_workload.take();
        assert!(
            validate_volume_quorum_health_evidence(&health_evidence, &proof, &[]).is_err(),
            "runtime quorum artifacts require the pre-workload health observation"
        );
        health_evidence.quorum_health_before_workload = saved_before;
        let saved_after = health_evidence.quorum_health_after_workload.take();
        assert!(
            validate_volume_quorum_health_evidence(&health_evidence, &proof, &[]).is_err(),
            "runtime quorum artifacts require the post-workload health observation"
        );
        health_evidence.quorum_health_after_workload = saved_after;
        health_evidence
            .quorum_health_after_workload
            .as_mut()
            .expect("post-workload health")
            .completed_at_ms = 351;
        assert!(
            validate_volume_quorum_health_evidence(&health_evidence, &proof, &[]).is_err(),
            "post-workload health observation must complete before fault removal"
        );

        let evidence_at = |fault_apply_started_at_ms| {
            serde_json::from_value::<FaultEvidenceArtifact>(json!({
                "injected": true,
                "active_during_workload": true,
                "recovered": true,
                "require_client_disruption": false,
                "client_disruptions": 0,
                "pods_before": [],
                "pods_after": [],
                "active_snapshots": [],
                "workload_snapshots": [],
                "fault_apply_started_at_ms": fault_apply_started_at_ms
            }))
            .expect("fault evidence")
        };
        let stale = validate_fixed_volume_runtime_evidence(&evidence_at(5_101), &proof, &run_spec)
            .expect_err("topology older than five seconds must be rejected");
        assert!(format!("{stale:#}").contains("maximum is 5000ms"));
        let future = validate_fixed_volume_runtime_evidence(&evidence_at(99), &proof, &run_spec)
            .expect_err("future topology observation must be rejected");
        assert!(format!("{future:#}").contains("must precede fault application"));

        let mut wrong_boundary = run_spec;
        wrong_boundary.faults[0].selection.value = 0;
        assert!(validate_target_proof(&proof, &wrong_boundary, &options).is_err());
    }

    #[test]
    fn target_proof_v2_binds_runtime_shape_to_typed_run_spec_requirement() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let run_spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs((0..4).map(|index| {
                TargetResolvedPodProof::new(format!("rustfs-{index}"), format!("uid-{index}"))
                    .with_node(format!("node-{index}"))
                    .with_ready(true)
            }))
            .with_erasure_set_topology_proven(
                ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4)
                    .expect("runtime shape"),
                ErasureSetHealth::from_runtime(8, 8, 0, 0).expect("runtime health"),
                ErasureSetMembership::from_runtime(
                    &ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4)
                        .expect("runtime shape"),
                    (0..4)
                        .map(|index| ErasureSetMember {
                            pod_name: format!("rustfs-{index}"),
                            server_endpoint: format!("http://rustfs-{index}.rustfs:9000"),
                            shard_ids: vec![format!("drive-{index}-a"), format!("drive-{index}-b")],
                        })
                        .collect(),
                )
                .expect("runtime membership"),
                "deployment-1",
                1,
            )
            .expect("valid runtime proof");
        let options = ArtifactValidationOptions {
            scenario: NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO.to_string(),
            artifact_root: std::path::PathBuf::from("unused"),
            expected_workload_objects: scenario.object_count,
            expected_workload_concurrency: config.workload.concurrency,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: config.expected_rustfs_pod_count,
            expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
            expected_recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
            expected_rustfs_volume_path: config.rustfs_volume_path.clone(),
        };

        validate_run_spec(&run_spec, &options).expect("canonical run spec");
        validate_target_proof(&proof, &run_spec, &options).expect("valid v2 proof");

        let mut jointly_downgraded_spec = run_spec.clone();
        jointly_downgraded_spec.faults[0].erasure_set_proof_required = false;
        assert!(validate_run_spec(&jointly_downgraded_spec, &options).is_err());

        let mut jointly_drifted_spec = run_spec.clone();
        jointly_drifted_spec.faults[0].target.kind = "rustfs-server-pod".to_string();
        jointly_drifted_spec.faults[0].selection.value = 1;
        assert!(validate_run_spec(&jointly_drifted_spec, &options).is_err());

        let mut downgraded = proof.clone();
        downgraded.schema_version = 1;
        assert!(validate_target_proof(&downgraded, &run_spec, &options).is_err());

        let mut wrong_selection = proof.clone();
        wrong_selection.faults[0].selection_value = 1;
        assert!(validate_target_proof(&wrong_selection, &run_spec, &options).is_err());

        let mut wrong_scope = proof.clone();
        wrong_scope.faults[0]
            .pod_selector
            .as_mut()
            .expect("selector")
            .tenant = "other-tenant".to_string();
        assert!(validate_target_proof(&wrong_scope, &run_spec, &options).is_err());

        let mut missing = proof.clone();
        missing.faults[0].erasure_set = None;
        assert!(validate_target_proof(&missing, &run_spec, &options).is_err());

        let mut duplicate_pod = proof.clone();
        duplicate_pod.resolved_pods[2].name = duplicate_pod.resolved_pods[0].name.clone();
        duplicate_pod.resolved_pods[2].uid = duplicate_pod.resolved_pods[0].uid.clone();
        assert!(validate_target_proof(&duplicate_pod, &run_spec, &options).is_err());

        let namespace = &run_spec.cluster.namespace;
        let tenant = &run_spec.cluster.tenant;
        let chaos_namespace = &run_spec.cluster.chaos_namespace;
        let pod_id = |index| format!("{namespace}/rustfs-{index}");
        let records = vec![
            json!({"id": pod_id(0), "selectorKey": ".", "phase": "Injected", "injectedCount": 1}),
            json!({"id": pod_id(1), "selectorKey": ".", "phase": "Injected", "injectedCount": 1}),
            json!({"id": pod_id(0), "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}),
            json!({"id": pod_id(1), "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}),
            json!({"id": pod_id(2), "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}),
            json!({"id": pod_id(3), "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}),
        ];
        let resource = json!({
            "apiVersion": "chaos-mesh.org/v1alpha1",
            "kind": "NetworkChaos",
            "metadata": {
                "name": "quorum-partition",
                "namespace": chaos_namespace,
                "labels": {
                    "rustfs-fault-test/run-id": run_spec.metadata.run_id,
                    "rustfs-fault-test/scenario": run_spec.scenario.name,
                    "app.kubernetes.io/managed-by": "s3chaos"
                }
            },
            "spec": {
                "action": "partition",
                "mode": "fixed",
                "value": "2",
                "selector": {
                    "namespaces": [namespace],
                    "labelSelectors": {"rustfs.tenant": tenant}
                },
                "direction": "both",
                "target": {
                    "mode": "all",
                    "selector": {
                        "namespaces": [namespace],
                        "labelSelectors": {"rustfs.tenant": tenant}
                    }
                }
            },
            "status": {
                "conditions": [
                    {"type": "Selected", "status": "True"},
                    {"type": "AllInjected", "status": "True"},
                    {"type": "AllRecovered", "status": "False"}
                ],
                "experiment": {"desiredPhase": "Run", "containerRecords": records}
            }
        });
        let snapshot = |stage| {
            json!({
                "stage": stage,
                "resource_kind": "networkchaos",
                "resource_name": "quorum-partition",
                "chaos_status": resource
            })
        };
        let mut evidence: FaultEvidenceArtifact = serde_json::from_value(json!({
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": true,
            "client_disruptions": 1,
            "pods_before": [],
            "pods_at_fault_activation": (0..4).map(|index| json!({
                "name": format!("rustfs-{index}"),
                "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_at_workload_snapshot": (0..4).map(|index| json!({
                "name": format!("rustfs-{index}"),
                "uid": format!("uid-{index}")
            })).collect::<Vec<_>>(),
            "pods_after": [],
            "active_snapshots": [snapshot("active")],
            "workload_snapshots": [snapshot("after-workload")],
            "fault_apply_started_at_ms": 2
        }))
        .expect("fault evidence");
        validate_write_quorum_runtime_evidence(
            &evidence,
            &proof,
            &run_spec,
            QuorumEdgeRuntimeKind::NetworkPartition,
        )
        .expect("runtime selection proof");
        evidence.pods_at_fault_activation[0].uid = "replacement-uid".to_string();
        assert!(
            validate_write_quorum_runtime_evidence(
                &evidence,
                &proof,
                &run_spec,
                QuorumEdgeRuntimeKind::NetworkPartition,
            )
            .is_err()
        );
        evidence.pods_at_fault_activation[0].uid = "uid-0".to_string();
        evidence.pods_at_workload_snapshot[0].uid = "replacement-uid".to_string();
        assert!(
            validate_write_quorum_runtime_evidence(
                &evidence,
                &proof,
                &run_spec,
                QuorumEdgeRuntimeKind::NetworkPartition,
            )
            .is_err()
        );
        evidence.pods_at_workload_snapshot[0].uid = "uid-0".to_string();
        evidence.fault_apply_started_at_ms = Some(6_002);
        assert!(
            validate_write_quorum_runtime_evidence(
                &evidence,
                &proof,
                &run_spec,
                QuorumEdgeRuntimeKind::NetworkPartition,
            )
            .is_err()
        );

        let mut tampered = proof;
        let shape = tampered.faults[0]
            .erasure_set
            .as_mut()
            .and_then(|erasure| erasure.shape.as_mut())
            .expect("shape");
        shape.payload_data_shards = 7;
        shape.payload_parity_shards = 1;
        assert!(validate_target_proof(&tampered, &run_spec, &options).is_err());
    }

    #[test]
    fn pod_failure_quorum_edge_runtime_evidence_binds_podchaos_to_the_boundary() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = POD_FAILURE_QUORUM_EDGE_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let run_spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );
        let shape =
            ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4).expect("runtime shape");
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs((0..4).map(|index| {
                TargetResolvedPodProof::new(format!("rustfs-{index}"), format!("uid-{index}"))
                    .with_node(format!("node-{index}"))
                    .with_ready(true)
            }))
            .with_erasure_set_topology_proven(
                shape.clone(),
                ErasureSetHealth::from_runtime(8, 8, 0, 0).expect("runtime health"),
                ErasureSetMembership::from_runtime(
                    &shape,
                    (0..4)
                        .map(|index| ErasureSetMember {
                            pod_name: format!("rustfs-{index}"),
                            server_endpoint: format!("http://rustfs-{index}.rustfs:9000"),
                            shard_ids: vec![format!("drive-{index}-a"), format!("drive-{index}-b")],
                        })
                        .collect(),
                )
                .expect("runtime membership"),
                "deployment-1",
                1,
            )
            .expect("valid runtime proof");
        let namespace = &run_spec.cluster.namespace;
        let tenant = &run_spec.cluster.tenant;
        let resource_for = |targets: &[usize]| {
            json!({
                "apiVersion": "chaos-mesh.org/v1alpha1",
                "kind": "PodChaos",
                "metadata": {
                    "name": "quorum-edge",
                    "namespace": run_spec.cluster.chaos_namespace,
                    "labels": {
                        "rustfs-fault-test/run-id": run_spec.metadata.run_id,
                        "rustfs-fault-test/scenario": run_spec.scenario.name,
                        "app.kubernetes.io/managed-by": "s3chaos"
                    }
                },
                "spec": {
                    "action": "pod-failure",
                    "mode": "fixed",
                    "value": targets.len().to_string(),
                    "duration": format!("{}s", run_spec.faults[0].fault_duration_seconds),
                    "selector": {
                        "namespaces": [namespace],
                        "labelSelectors": {"rustfs.tenant": tenant}
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
                        "containerRecords": targets.iter().map(|index| json!({
                            "id": format!("{namespace}/rustfs-{index}"),
                            "selectorKey": ".",
                            "phase": "Injected",
                            "injectedCount": 1
                        })).collect::<Vec<_>>()
                    }
                }
            })
        };
        let evidence_for = |active: serde_json::Value, workload: serde_json::Value| {
            let snapshot = |stage: &str, resource: serde_json::Value| {
                json!({
                    "stage": stage,
                    "resource_kind": "podchaos",
                    "resource_name": "quorum-edge",
                    "chaos_status": resource
                })
            };
            let pods = (0..4)
                .map(|index| json!({"name": format!("rustfs-{index}"), "uid": format!("uid-{index}")}))
                .collect::<Vec<_>>();
            serde_json::from_value::<FaultEvidenceArtifact>(json!({
                "injected": true,
                "active_during_workload": true,
                "recovered": true,
                "require_client_disruption": true,
                "client_disruptions": 1,
                "pods_before": [],
                "pods_at_fault_activation": pods,
                "pods_at_workload_snapshot": pods,
                "pods_after": [],
                "active_snapshots": [snapshot("active", active)],
                "workload_snapshots": [snapshot("after-workload", workload)],
                "fault_apply_started_at_ms": 2
            }))
            .expect("fault evidence")
        };
        let validate = |evidence: &FaultEvidenceArtifact, kind| {
            validate_write_quorum_runtime_evidence(evidence, &proof, &run_spec, kind)
        };

        let evidence = evidence_for(resource_for(&[0, 1]), resource_for(&[0, 1]));
        validate(&evidence, QuorumEdgeRuntimeKind::PodFailure).expect("two-Pod quorum edge");
        // The same snapshot is not NetworkChaos evidence.
        assert!(validate(&evidence, QuorumEdgeRuntimeKind::NetworkPartition).is_err());
        // Targets that drift between activation and the workload snapshot.
        assert!(
            validate(
                &evidence_for(resource_for(&[0, 1]), resource_for(&[2, 3])),
                QuorumEdgeRuntimeKind::PodFailure,
            )
            .is_err()
        );
        // One failed Pod stays inside write quorum, so it is not the boundary.
        let mut single = run_spec.clone();
        single.faults[0].selection.value = 1;
        assert!(
            validate_write_quorum_runtime_evidence(
                &evidence_for(resource_for(&[0]), resource_for(&[0])),
                &proof,
                &single,
                QuorumEdgeRuntimeKind::PodFailure,
            )
            .is_err()
        );
        // A controller duration that differs from the planned fault window.
        let mut short = resource_for(&[0, 1]);
        short["spec"]["duration"] = json!("1s");
        assert!(
            validate(
                &evidence_for(short.clone(), short),
                QuorumEdgeRuntimeKind::PodFailure,
            )
            .is_err()
        );
    }

    #[test]
    fn host_storage_artifacts_bind_allowlisted_target_and_cleanup_observation() {
        let mut config = FaultTestConfig::for_test("real-cluster", "rustfs-fault-dm");
        config.scenario = DM_FLAKEY_SCENARIO.to_string();
        config.dm_name = Some("rustfs-fault-dm".to_string());
        config.dm_node = Some("worker-a".to_string());
        config.dm_mount_path = Some("/data/rustfs-fault/dm-volume".to_string());
        config.dm_fault_table = Some("0 1024 flakey /dev/loop0 0 1 15".to_string());
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("plan");
        let workload_plan =
            WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let run_spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload_plan,
            "run-1",
            "bucket-1",
        );
        assert!(
            run_spec
                .artifacts
                .required
                .contains(&"host-storage-proof.json".to_string())
                && run_spec
                    .artifacts
                    .required
                    .contains(&"host-storage-post-cleanup.json".to_string())
        );
        let target_proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-1")
            .with_resolved_pod_proofs([TargetResolvedPodProof::new("rustfs-0", "uid-0")
                .with_node("worker-a")
                .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-0".to_string(),
                    volume_name: Some("pv-a".to_string()),
                    storage_class: Some("rustfs-fault-dm".to_string()),
                    persistent_volume: Some(TargetPersistentVolumeProof {
                        name: "pv-a".to_string(),
                        uid: "pv-uid-0".to_string(),
                        source: Some("local".to_string()),
                        required_node_affinity: None,
                        node: Some("storage-host-a".to_string()),
                        device_or_path: Some("/data/rustfs-fault/dm-volume".to_string()),
                    }),
                }])]);
        let host_proof = HostStorageMutationProof::prove_device_mapper(
            HostStorageMutationIntent {
                scenario: scenario.name.clone(),
                fault_name: run_spec.faults[0].name.clone(),
                fault_kind: run_spec.faults[0].kind.clone(),
                run_id: "run-1".to_string(),
                context: config.cluster.context.clone(),
                namespace: config.cluster.test_namespace.clone(),
                tenant: config.cluster.tenant_name.clone(),
                observer_namespace: "rustfs-fault-observers".to_string(),
                observer_pod: "observer-worker-a".to_string(),
                backend_specific_destructive_opt_in: true,
                allowlist: HostStorageAllowlist {
                    nodes: vec!["worker-a".to_string()],
                    devices: vec!["/dev/mapper/rustfs-fault-dm".to_string()],
                    persistent_volumes: vec!["pv-a".to_string()],
                },
                fault_table: Some("0 1024 flakey /dev/loop0 0 1 15".to_string()),
            },
            HostStorageTargetObservation {
                node: "worker-a".to_string(),
                node_uid: "node-uid-a".to_string(),
                node_labels: BTreeMap::from([(
                    "kubernetes.io/hostname".to_string(),
                    "storage-host-a".to_string(),
                )]),
                pod: "rustfs-0".to_string(),
                pod_uid: "uid-0".to_string(),
                volume_name: "data".to_string(),
                persistent_volume_claim: "data-rustfs-0".to_string(),
                persistent_volume_claim_uid: "pvc-uid-0".to_string(),
                persistent_volume_claim_phase: "Bound".to_string(),
                persistent_volume: "pv-a".to_string(),
                persistent_volume_uid: "pv-uid-a".to_string(),
                persistent_volume_phase: "Bound".to_string(),
                persistent_volume_claim_ref: HostStoragePersistentVolumeClaimRef {
                    namespace: "rustfs-fault-test".to_string(),
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-0".to_string(),
                },
                node_selector: HostStorageNodeSelector {
                    key: "kubernetes.io/hostname".to_string(),
                    operator: "In".to_string(),
                    values: vec!["storage-host-a".to_string()],
                },
                container_mount_path: "/data/rustfs0".to_string(),
                persistent_volume_path: "/data/rustfs-fault/dm-volume".to_string(),
                mapper_name: "rustfs-fault-dm".to_string(),
                logical_device: "/dev/mapper/rustfs-fault-dm".to_string(),
                canonical_device: "/dev/dm-0".to_string(),
                mount_source: "/dev/mapper/rustfs-fault-dm".to_string(),
                mount_canonical_source: "/dev/dm-0".to_string(),
                filesystem: "ext4".to_string(),
                recovery_table: "0 1024 linear /dev/loop0 0".to_string(),
                observed_at_ms: 151,
            },
        )
        .expect("host proof");
        let cleanup = HostStoragePostCleanupObservation {
            schema_version: 1,
            scenario: scenario.name.clone(),
            fault_name: run_spec.faults[0].name.clone(),
            run_id: "run-1".to_string(),
            observed_at_ms: 300,
            node: "worker-a".to_string(),
            persistent_volume: "pv-a".to_string(),
            mapper_name: "rustfs-fault-dm".to_string(),
            logical_device: "/dev/mapper/rustfs-fault-dm".to_string(),
            canonical_device: "/dev/dm-0".to_string(),
            mount_canonical_source: "/dev/dm-0".to_string(),
            filesystem_mounted: true,
            node_quarantined: false,
            recovery_table_sha256: host_proof.target.recovery_table_sha256.clone(),
        };
        let recovery_snapshot = json!({
            "stage": "recovered",
            "mapper_name": "rustfs-fault-dm",
            "canonical_device": "/dev/dm-0",
            "suspended": false,
            "observed_at_ms": 299,
            "helper_pod": "rustfs-fault-dm-helper-run1",
            "mapping": {
                "node": "worker-a",
                "node_uid": "node-uid-a",
                "node_labels": {"kubernetes.io/hostname": "storage-host-a"},
                "pod": "rustfs-0",
                "pod_uid": "uid-0",
                "volume_name": "data",
                "pvc": "data-rustfs-0",
                "pvc_uid": "pvc-uid-0",
                "pvc_phase": "Bound",
                "pv": "pv-a",
                "pv_uid": "pv-uid-a",
                "pv_phase": "Bound",
                "pv_claim_ref": {
                    "namespace": "rustfs-fault-test",
                    "name": "data-rustfs-0",
                    "uid": "pvc-uid-0"
                },
                "node_selector": {
                    "key": "kubernetes.io/hostname",
                    "operator": "In",
                    "values": ["storage-host-a"]
                },
                "container_mount_path": "/data/rustfs0",
                "mount_path": "/data/rustfs-fault/dm-volume"
            },
            "table": "0 1024 linear /dev/loop0 0",
            "status": "0 1024 linear"
        });
        let mut evidence: FaultEvidenceArtifact = serde_json::from_value(json!({
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": true,
            "client_disruptions": 1,
            "pods_before": [],
            "pods_after": [],
            "active_snapshots": [{}],
            "workload_snapshots": [{}],
            "fault_apply_started_at_ms": 150,
            "fault_active_at_ms": 160,
            "workload_started_at_ms": 170,
            "workload_ended_at_ms": 190,
            "fault_delete_started_at_ms": 200,
            "recovery_started_at_ms": 201,
            "dm_recovery_snapshot": recovery_snapshot,
            "recovery_ended_at_ms": 400
        }))
        .expect("evidence");

        let active_snapshot = |stage, timestamp| {
            let mut dm = evidence
                .dm_recovery_snapshot
                .clone()
                .expect("recovery snapshot");
            dm["stage"] = json!(stage);
            dm["table"] = json!(host_proof.tables.fault_table);
            dm["observed_at_ms"] = json!(timestamp);
            json!({"stage": stage, "resource_kind": "device-mapper", "dm_status": dm})
        };
        evidence.active_snapshots = vec![active_snapshot("active", 161)];
        evidence.workload_snapshots = vec![active_snapshot("after-workload", 195)];
        validate_host_storage_artifacts(&host_proof, &cleanup, &target_proof, &run_spec, &evidence)
            .expect("valid host-storage artifacts");

        let filesystem_check = DmFilesystemCheck {
            schema_version: DM_FILESYSTEM_CHECK_SCHEMA_VERSION,
            scenario: host_proof.scenario.clone(),
            fault_name: host_proof.fault_name.clone(),
            run_id: host_proof.run_id.clone(),
            node: host_proof.target.node.clone(),
            persistent_volume: host_proof.target.persistent_volume.clone(),
            mapper_name: host_proof.target.mapper_name.clone(),
            logical_device: host_proof.target.logical_device.clone(),
            canonical_device: host_proof.target.canonical_device.clone(),
            mount_path: host_proof.target.persistent_volume_path.clone(),
            filesystem: "ext4".to_string(),
            checker: "/usr/sbin/e2fsck".to_string(),
            arguments: vec![
                "-f".to_string(),
                "-n".to_string(),
                host_proof.target.logical_device.clone(),
            ],
            started_at_ms: 210,
            completed_at_ms: 220,
            exit_code: Some(0),
            stdout: "clean".to_string(),
            stderr: String::new(),
            clean: true,
            mounted_for_recovery: true,
            unmounted_for_check: true,
            remounted_after_check: true,
            remounted_at_ms: Some(230),
        };
        super::validate_dm_filesystem_check(&filesystem_check, &host_proof, &cleanup, &evidence)
            .expect("valid offline filesystem check");
        for broken in [
            DmFilesystemCheck {
                exit_code: Some(4),
                clean: false,
                ..filesystem_check.clone()
            },
            DmFilesystemCheck {
                checker: "/usr/sbin/e2fsck".to_string(),
                arguments: vec!["-y".to_string(), filesystem_check.logical_device.clone()],
                ..filesystem_check.clone()
            },
            DmFilesystemCheck {
                remounted_at_ms: Some(401),
                ..filesystem_check.clone()
            },
        ] {
            assert!(
                super::validate_dm_filesystem_check(&broken, &host_proof, &cleanup, &evidence)
                    .is_err(),
                "filesystem evidence must reject a failed, mutating, or out-of-window check"
            );
        }

        let mut ack_spec = run_spec.clone();
        ack_spec.scenario.ack_trigger = Some(crate::fault::spec::FaultRunAckTriggerSpec {
            mutation: crate::fault::acknowledged_mutation::AcknowledgedMutationKind::Put,
            operation_timeout_ms: 30_000,
            max_ack_to_fault_ms: 1_000,
        });
        let mut ack_evidence = evidence.clone();
        ack_evidence.active_during_workload = false;
        ack_evidence.fault_prepare_started_at_ms = Some(140);
        ack_evidence.fault_apply_started_at_ms = Some(155);
        ack_evidence.workload_started_at_ms = None;
        ack_evidence.workload_ended_at_ms = None;
        ack_evidence.workload_snapshots.clear();
        validate_host_storage_artifacts(
            &host_proof,
            &cleanup,
            &target_proof,
            &ack_spec,
            &ack_evidence,
        )
        .expect("valid ACK-triggered host-storage artifacts");

        ack_evidence.pods_before = vec![
            super::PodIdentityArtifact {
                name: "rustfs-0".to_string(),
                uid: "uid-0".to_string(),
            },
            super::PodIdentityArtifact {
                name: "rustfs-1".to_string(),
                uid: "uid-1".to_string(),
            },
        ];
        ack_evidence.pods_after = vec![
            super::PodIdentityArtifact {
                name: "rustfs-0".to_string(),
                uid: "uid-0-replacement".to_string(),
            },
            super::PodIdentityArtifact {
                name: "rustfs-1".to_string(),
                uid: "uid-1-replacement".to_string(),
            },
        ];
        let boundary: super::DmCrashBoundaryArtifact = serde_json::from_value(json!({
            "scenario": scenario.name,
            "run_id": "run-1",
            "started_at_ms": 170,
            "completed_at_ms": 180,
            "old_pod_uid": "uid-0",
            "replacement_pod_uid": "uid-0-replacement",
            "filesystem_unmounted": true,
            "mapper_mounts_absent": true,
            "mount_before": {
                "source": "/dev/mapper/rustfs-fault-dm",
                "canonical_source": "/dev/dm-0",
                "filesystem": "ext4",
                "options": "rw"
            },
            "fault": {"table": "0 1024 drop_writes /dev/loop0 0"}
        }))
        .expect("boundary");
        super::validate_ack_crash_target_identity(&boundary, &host_proof, &ack_evidence)
            .expect("boundary is bound to the proven target Pod");

        let masquerading_boundary: super::DmCrashBoundaryArtifact = serde_json::from_value(json!({
            "scenario": scenario.name,
            "run_id": "run-1",
            "started_at_ms": 170,
            "completed_at_ms": 180,
            "old_pod_uid": "uid-1",
            "replacement_pod_uid": "uid-1-replacement",
            "filesystem_unmounted": true,
            "mapper_mounts_absent": true,
            "mount_before": {
                "source": "/dev/mapper/rustfs-fault-dm",
                "canonical_source": "/dev/dm-0",
                "filesystem": "ext4",
                "options": "rw"
            },
            "fault": {"table": "0 1024 drop_writes /dev/loop0 0"}
        }))
        .expect("masquerading boundary");
        assert!(
            super::validate_ack_crash_target_identity(
                &masquerading_boundary,
                &host_proof,
                &ack_evidence,
            )
            .is_err(),
            "a same-tenant Pod restart must not masquerade as the target disk Pod crash"
        );

        for workload in [false, true] {
            for replacement in [vec![], vec![json!({})], vec![json!({}), json!({})]] {
                let mut broken = evidence.clone();
                if workload {
                    broken.workload_snapshots = replacement;
                } else {
                    broken.active_snapshots = replacement;
                }
                assert!(
                    validate_host_storage_artifacts(
                        &host_proof,
                        &cleanup,
                        &target_proof,
                        &run_spec,
                        &broken
                    )
                    .is_err()
                );
            }
            for (pointer, value) in [
                ("/stage", json!("recovered")),
                ("/resource_kind", json!("iochaos")),
                ("/dm_status/stage", json!("recovered")),
                ("/dm_status/helper_pod", json!("other-run-helper")),
                ("/dm_status/mapper_name", json!("other-mapper")),
                ("/dm_status/canonical_device", json!("/dev/dm-9")),
                ("/dm_status/suspended", json!(true)),
                ("/dm_status/table", json!(host_proof.tables.recovery_table)),
                ("/dm_status/mapping/node_uid", json!("replaced-node")),
                ("/dm_status/mapping/pv_uid", json!("replaced-pv")),
                ("/dm_status/mapping/pvc_uid", json!("replaced-pvc")),
                ("/dm_status/mapping/pod_uid", json!("replaced-pod")),
                ("/dm_status/observed_at_ms", json!(159)),
                ("/dm_status/observed_at_ms", json!(201)),
            ] {
                let mut broken = evidence.clone();
                let snapshots = if workload {
                    &mut broken.workload_snapshots
                } else {
                    &mut broken.active_snapshots
                };
                *snapshots[0].pointer_mut(pointer).expect("tampered field") = value;
                assert!(
                    validate_host_storage_artifacts(
                        &host_proof,
                        &cleanup,
                        &target_proof,
                        &run_spec,
                        &broken
                    )
                    .is_err(),
                    "must reject {pointer} drift at workload={workload}"
                );
            }
        }

        let mut tampered_topology = target_proof.clone();
        tampered_topology.resolved_pods[0].persistent_volume_claims[0]
            .persistent_volume
            .as_mut()
            .expect("target PV")
            .node = Some("worker-a".to_string());
        assert!(
            validate_host_storage_artifacts(
                &host_proof,
                &cleanup,
                &tampered_topology,
                &run_spec,
                &evidence,
            )
            .is_err(),
            "target-proof PV topology must match the proven hostname label, not Node metadata.name"
        );

        let mut tampered_proof = host_proof.clone();
        tampered_proof.allowlist.persistent_volumes = vec!["pv-b".to_string()];
        assert!(
            validate_host_storage_artifacts(
                &tampered_proof,
                &cleanup,
                &target_proof,
                &run_spec,
                &evidence,
            )
            .is_err()
        );

        let mut recreated_pvc_proof = host_proof.clone();
        recreated_pvc_proof.target.persistent_volume_claim_uid = "pvc-uid-new".to_string();
        recreated_pvc_proof.target.persistent_volume_claim_ref.uid = "pvc-uid-new".to_string();
        assert!(
            validate_host_storage_artifacts(
                &recreated_pvc_proof,
                &cleanup,
                &target_proof,
                &run_spec,
                &evidence,
            )
            .is_err(),
            "recovery evidence must reject a coordinated same-name PVC recreation"
        );

        let mut tampered_cleanup = cleanup.clone();
        tampered_cleanup.recovery_table_sha256 = "0".repeat(64);
        assert!(
            validate_host_storage_artifacts(
                &host_proof,
                &tampered_cleanup,
                &target_proof,
                &run_spec,
                &evidence,
            )
            .is_err()
        );

        let redirected_proof = HostStorageMutationProof::prove_device_mapper(
            HostStorageMutationIntent {
                scenario: scenario.name.clone(),
                fault_name: run_spec.faults[0].name.clone(),
                fault_kind: run_spec.faults[0].kind.clone(),
                run_id: "run-1".to_string(),
                context: config.cluster.context.clone(),
                namespace: config.cluster.test_namespace.clone(),
                tenant: config.cluster.tenant_name.clone(),
                observer_namespace: "rustfs-fault-observers".to_string(),
                observer_pod: "observer-worker-a".to_string(),
                backend_specific_destructive_opt_in: true,
                allowlist: HostStorageAllowlist {
                    nodes: vec!["worker-a".to_string()],
                    devices: vec!["/dev/mapper/rustfs-fault-dm".to_string()],
                    persistent_volumes: vec!["pv-a".to_string()],
                },
                fault_table: Some("0 1024 flakey /dev/sda 0 1 15".to_string()),
            },
            HostStorageTargetObservation {
                node: "worker-a".to_string(),
                node_uid: "node-uid-a".to_string(),
                node_labels: BTreeMap::from([(
                    "kubernetes.io/hostname".to_string(),
                    "storage-host-a".to_string(),
                )]),
                pod: "rustfs-0".to_string(),
                pod_uid: "uid-0".to_string(),
                volume_name: "data".to_string(),
                persistent_volume_claim: "data-rustfs-0".to_string(),
                persistent_volume_claim_uid: "pvc-uid-0".to_string(),
                persistent_volume_claim_phase: "Bound".to_string(),
                persistent_volume: "pv-a".to_string(),
                persistent_volume_uid: "pv-uid-a".to_string(),
                persistent_volume_phase: "Bound".to_string(),
                persistent_volume_claim_ref: HostStoragePersistentVolumeClaimRef {
                    namespace: "rustfs-fault-test".to_string(),
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-0".to_string(),
                },
                node_selector: HostStorageNodeSelector {
                    key: "kubernetes.io/hostname".to_string(),
                    operator: "In".to_string(),
                    values: vec!["storage-host-a".to_string()],
                },
                container_mount_path: "/data/rustfs0".to_string(),
                persistent_volume_path: "/data/rustfs-fault/dm-volume".to_string(),
                mapper_name: "rustfs-fault-dm".to_string(),
                logical_device: "/dev/mapper/rustfs-fault-dm".to_string(),
                canonical_device: "/dev/dm-0".to_string(),
                mount_source: "/dev/mapper/rustfs-fault-dm".to_string(),
                mount_canonical_source: "/dev/dm-0".to_string(),
                filesystem: "ext4".to_string(),
                recovery_table: "0 1024 linear /dev/sda 0".to_string(),
                observed_at_ms: 151,
            },
        )
        .expect("internally consistent redirected proof");
        let mut coordinated_cleanup = cleanup;
        coordinated_cleanup.recovery_table_sha256 =
            redirected_proof.target.recovery_table_sha256.clone();
        assert!(
            validate_host_storage_artifacts(
                &redirected_proof,
                &coordinated_cleanup,
                &target_proof,
                &run_spec,
                &evidence,
            )
            .is_err(),
            "independent recovery snapshot must reject coordinated proof/cleanup tampering"
        );
    }

    #[test]
    fn workload_summary_must_match_each_fault_active_history_family() {
        let plan = WorkloadPlan::seeded(42, 12, 1);
        let summary: WorkloadSummaryArtifact = serde_json::from_value(json!({
            "seed": 42,
            "object_count": 12,
            "concurrency": 1,
            "recommitted_after_recovery": 0,
            "puts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "gets": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "deletes": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "lists": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "multipart_completes": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "multipart_aborts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0}
        }))
        .expect("summary");
        let record = |id: &str, kind: &str, key: &str, outcome: &str, sequence: u64| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": "admin-rebalance",
                "kind": kind,
                "bucket": "bucket",
                "key": key,
                "started_at_ms": 10,
                "ended_at_ms": 11,
                "started_sequence": sequence * 2 - 1,
                "ended_sequence": sequence * 2,
                "outcome": outcome,
                "durability_cohort": "fault_active"
            }))
            .expect("history record")
        };
        let complete_key = "fault-test/run-1/object-000011";
        let abort_key = "fault-test/run-1/object-000023";
        let mut history = vec![
            record("put", "put", "key", "ok", 1),
            record("get", "get", "key", "ok", 2),
            record("delete", "delete", "key", "ok", 3),
            record("list", "list", "fault-test/run-1/", "ok", 4),
            record(
                "complete-create",
                "create_multipart_upload",
                complete_key,
                "ok",
                5,
            ),
        ];
        for part in 0..plan.multipart_part_count_at(11) {
            history.push(record(
                &format!("complete-part-{part}"),
                "upload_part",
                complete_key,
                "ok",
                6 + part as u64,
            ));
        }
        let complete_sequence = 6 + plan.multipart_part_count_at(11) as u64;
        history.push(record(
            "complete",
            "complete_multipart_upload",
            complete_key,
            "ok",
            complete_sequence,
        ));
        history.push(record(
            "abort-create",
            "create_multipart_upload",
            abort_key,
            "ok",
            complete_sequence + 1,
        ));
        history.push(record(
            "abort",
            "abort_multipart_upload",
            abort_key,
            "ok",
            complete_sequence + 2,
        ));

        summary
            .require_history_matches(
                &history,
                "admin-rebalance",
                "bucket",
                DurabilityCohort::FaultActive,
                &plan,
                "run-1",
            )
            .expect("matching summary");
        let mut missing_list = history.clone();
        missing_list.remove(3);
        assert!(
            summary
                .require_history_matches(
                    &missing_list,
                    "admin-rebalance",
                    "bucket",
                    DurabilityCohort::FaultActive,
                    &plan,
                    "run-1",
                )
                .is_err(),
            "a fabricated family counter must not pass"
        );

        let mut unplanned_setup = history.clone();
        unplanned_setup.push(record(
            "foreign-create",
            "create_multipart_upload",
            "fault-test/run-1/object-999999",
            "failed",
            200,
        ));
        assert!(
            summary
                .require_history_matches(
                    &unplanned_setup,
                    "admin-rebalance",
                    "bucket",
                    DurabilityCohort::FaultActive,
                    &plan,
                    "run-1",
                )
                .is_err(),
            "unplanned multipart setup must not disappear from summary counters"
        );

        let mut setup_failure_summary = summary;
        setup_failure_summary.multipart_completes = OutcomeCountsArtifact::default();
        setup_failure_summary
            .multipart_completes
            .record(OperationOutcome::Unknown);
        let mut setup_failure_history = history
            .iter()
            .filter(|record| record.key.as_deref() != Some(complete_key))
            .cloned()
            .collect::<Vec<_>>();
        setup_failure_history.push(record(
            "complete-create-failed",
            "create_multipart_upload",
            complete_key,
            "failed",
            100,
        ));
        setup_failure_summary
            .require_history_matches(
                &setup_failure_history,
                "admin-rebalance",
                "bucket",
                DurabilityCohort::FaultActive,
                &plan,
                "run-1",
            )
            .expect("failed multipart setup projects to an unknown completion");

        setup_failure_summary.multipart_completes = OutcomeCountsArtifact::default();
        setup_failure_summary
            .multipart_completes
            .record(OperationOutcome::Ok);
        setup_failure_summary.multipart_aborts = OutcomeCountsArtifact::default();
        setup_failure_summary
            .multipart_aborts
            .record(OperationOutcome::Unknown);
        setup_failure_history = history
            .iter()
            .filter(|record| record.key.as_deref() != Some(abort_key))
            .cloned()
            .collect();
        setup_failure_history.push(record(
            "abort-create-timeout",
            "create_multipart_upload",
            abort_key,
            "timeout",
            100,
        ));
        setup_failure_summary
            .require_history_matches(
                &setup_failure_history,
                "admin-rebalance",
                "bucket",
                DurabilityCohort::FaultActive,
                &plan,
                "run-1",
            )
            .expect("failed abort setup projects to an unknown abort");

        let mut forged_abort = setup_failure_history;
        forged_abort.last_mut().expect("forged abort setup").kind = OperationKind::UploadPart;
        assert!(
            setup_failure_summary
                .require_history_matches(
                    &forged_abort,
                    "admin-rebalance",
                    "bucket",
                    DurabilityCohort::FaultActive,
                    &plan,
                    "run-1",
                )
                .is_err(),
            "an upload-part failure cannot stand in for explicit abort create evidence"
        );
    }

    #[test]
    fn workload_summary_rejects_acknowledged_mutation_during_write_quorum_loss() {
        let summary: WorkloadSummaryArtifact = serde_json::from_value(json!({
            "seed": 42,
            "object_count": 3,
            "concurrency": 1,
            "recommitted_after_recovery": 0,
            "puts": {"ok": 0, "not_found": 0, "failed": 1, "timeout": 0, "unknown": 0},
            "gets": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "deletes": {"ok": 0, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0},
            "lists": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "multipart_completes": {"ok": 0, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 1},
            "multipart_aborts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0}
        }))
        .expect("summary");
        let record = |id: &str, kind: &str, outcome: &str| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                "kind": kind,
                "bucket": "bucket",
                "key": "key",
                "value_sha256": null,
                "size_bytes": null,
                "started_at_ms": 10,
                "ended_at_ms": 11,
                "outcome": outcome,
                "http_status": null,
                "error": null,
                "durability_cohort": "fault_active"
            }))
            .expect("history record")
        };
        let mut history = vec![
            record("put-1", "put", "failed"),
            record("delete-1", "delete", "timeout"),
            record("mpu-1", "complete_multipart_upload", "unknown"),
        ];
        summary
            .require_write_quorum_loss_effect(
                &history,
                NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                "bucket",
                10,
                11,
            )
            .expect("rejected mutations prove write-quorum loss");
        for family in 0..3 {
            for replace in [true, false] {
                let mut invalid_history = history.clone();
                let mut counts = [
                    OutcomeCountsArtifact::default(),
                    OutcomeCountsArtifact::default(),
                    OutcomeCountsArtifact::default(),
                ];
                if replace {
                    invalid_history[family].outcome = OperationOutcome::NotFound;
                } else {
                    let mut extra = invalid_history[family].clone();
                    extra.id = "extra-404".to_string();
                    extra.outcome = OperationOutcome::NotFound;
                    invalid_history.push(extra);
                }
                for record in &invalid_history {
                    let index = match record.kind {
                        crate::fault::history::OperationKind::Put => 0,
                        crate::fault::history::OperationKind::Delete => 1,
                        _ => 2,
                    };
                    counts[index].record(record.outcome);
                }
                let [puts, deletes, multipart_completes] = counts;
                let invalid = WorkloadSummaryArtifact {
                    scenario: None,
                    run_id: None,
                    puts,
                    deletes,
                    multipart_completes,
                    gets: OutcomeCountsArtifact::default(),
                    lists: OutcomeCountsArtifact::default(),
                    multipart_aborts: OutcomeCountsArtifact::default(),
                    seed: 42,
                    object_count: 3,
                    concurrency: 1,
                    recommit_candidates: None,
                    recommitted_after_recovery: 0,
                };
                let error = invalid
                    .require_write_quorum_loss_effect(
                        &invalid_history,
                        NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                        "bucket",
                        10,
                        11,
                    )
                    .expect_err("404 is not quorum-loss evidence even when history matches");
                assert!(error.to_string().contains("outcomes must all"), "{error}");
            }
        }
        history[0].bucket = "foreign-bucket".to_string();
        assert!(
            summary
                .require_write_quorum_loss_effect(
                    &history,
                    NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                    "bucket",
                    10,
                    11,
                )
                .is_err()
        );
        history[0].bucket = "bucket".to_string();
        history[0].outcome = OperationOutcome::Ok;
        assert!(
            summary
                .require_write_quorum_loss_effect(
                    &history,
                    NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                    "bucket",
                    10,
                    11,
                )
                .is_err()
        );

        let read_only_disruption: WorkloadSummaryArtifact = serde_json::from_value(json!({
            "seed": 42,
            "object_count": 3,
            "concurrency": 1,
            "recommitted_after_recovery": 0,
            "puts": {"ok": 0, "not_found": 1, "failed": 0, "timeout": 0, "unknown": 0},
            "gets": {"ok": 0, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0},
            "deletes": {"ok": 0, "not_found": 1, "failed": 0, "timeout": 0, "unknown": 0},
            "lists": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
            "multipart_completes": {"ok": 0, "not_found": 1, "failed": 0, "timeout": 0, "unknown": 0},
            "multipart_aborts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0}
        }))
        .expect("read-only disruption summary");
        let history = vec![
            record("put-2", "put", "not_found"),
            record("delete-2", "delete", "not_found"),
            record("mpu-2", "complete_multipart_upload", "not_found"),
        ];
        assert!(
            read_only_disruption
                .require_write_quorum_loss_effect(
                    &history,
                    NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                    "bucket",
                    10,
                    11,
                )
                .is_err()
        );
    }

    #[test]
    fn typed_write_quorum_loss_artifacts_follow_runtime_geometry() {
        let unavailable = |shards, parity, class, beyond_read_tolerance| {
            let shape =
                ErasureSetShape::from_runtime_single_set(shards, 1, &[1], &[shards], parity)
                    .expect("runtime shape");
            QuorumVolumeBoundary {
                class,
                beyond_read_tolerance,
            }
            .unavailable_mutations(&shape)
            .expect("mutation quorum")
        };
        let payload_unavailable = unavailable(8, 2, QuorumCaseClass::Payload, true);
        let metadata_unavailable = unavailable(8, 2, QuorumCaseClass::Metadata, true);
        let summary = |puts: Value, deletes: Value, multipart_completes: Value| {
            serde_json::from_value::<WorkloadSummaryArtifact>(json!({
                "seed": 42,
                "object_count": 3,
                "concurrency": 1,
                "recommitted_after_recovery": 0,
                "puts": puts,
                "gets": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "deletes": deletes,
                "lists": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_completes": multipart_completes,
                "multipart_aborts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0}
            }))
            .expect("summary")
        };
        let record = |id: &str, kind: &str, outcome: &str| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                "kind": kind,
                "bucket": "bucket",
                "key": "key",
                "value_sha256": null,
                "size_bytes": null,
                "started_at_ms": 10,
                "ended_at_ms": 11,
                "outcome": outcome,
                "http_status": null,
                "error": null,
                "durability_cohort": "fault_active"
            }))
            .expect("history record")
        };

        let payload = summary(
            json!({"ok": 0, "not_found": 0, "failed": 1, "timeout": 0, "unknown": 0}),
            json!({"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0}),
            json!({"ok": 0, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0}),
        );
        let payload_history = vec![
            record("put-1", "put", "failed"),
            record("delete-1", "delete", "ok"),
            record("mpu-1", "complete_multipart_upload", "timeout"),
        ];
        payload
            .require_typed_write_quorum_loss_effect(
                &payload_history,
                QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                "bucket",
                &payload_unavailable,
                10,
                11,
            )
            .expect("payload quorum loss may retain metadata write quorum");
        assert!(
            payload
                .require_typed_write_quorum_loss_effect(
                    &payload_history,
                    QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                    "bucket",
                    &metadata_unavailable,
                    10,
                    11,
                )
                .is_err()
        );

        for (shards, parity, class, beyond, delete_allowed) in [
            (4, 2, QuorumCaseClass::Payload, false, false),
            (4, 2, QuorumCaseClass::Payload, true, false),
            (8, 4, QuorumCaseClass::Payload, true, false),
            (8, 2, QuorumCaseClass::Payload, false, true),
            (12, 4, QuorumCaseClass::Payload, true, true),
            (8, 2, QuorumCaseClass::Metadata, false, false),
        ] {
            assert_eq!(
                payload
                    .require_typed_write_quorum_loss_effect(
                        &payload_history,
                        QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                        "bucket",
                        &unavailable(shards, parity, class, beyond),
                        10,
                        11,
                    )
                    .is_ok(),
                delete_allowed,
                "DELETE at {shards}/{parity} {class:?} beyond={beyond}"
            );
        }

        let metadata = summary(
            json!({"ok": 0, "not_found": 0, "failed": 1, "timeout": 0, "unknown": 0}),
            json!({"ok": 0, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 1}),
            json!({"ok": 0, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0}),
        );
        let metadata_history = vec![
            record("put-2", "put", "failed"),
            record("delete-2", "delete", "unknown"),
            record("mpu-2", "complete_multipart_upload", "timeout"),
        ];
        metadata
            .require_typed_write_quorum_loss_effect(
                &metadata_history,
                QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                "bucket",
                &metadata_unavailable,
                10,
                11,
            )
            .expect("metadata quorum loss also crosses payload write quorum");

        let metadata_with_payload_ack = summary(
            json!({"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0}),
            json!({"ok": 0, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 1}),
            json!({"ok": 0, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0}),
        );
        let mut metadata_history_with_payload_ack = metadata_history.clone();
        metadata_history_with_payload_ack[0].outcome = OperationOutcome::Ok;
        assert!(
            metadata_with_payload_ack
                .require_typed_write_quorum_loss_effect(
                    &metadata_history_with_payload_ack,
                    QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                    "bucket",
                    &metadata_unavailable,
                    10,
                    11,
                )
                .is_err(),
            "metadata P+1 also loses payload write quorum"
        );
        metadata_with_payload_ack
            .require_typed_write_quorum_loss_effect(
                &metadata_history_with_payload_ack,
                QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                "bucket",
                &unavailable(8, 2, QuorumCaseClass::Payload, false),
                10,
                11,
            )
            .expect("payload P may retain every write quorum");

        let mut tampered_history = payload_history;
        tampered_history[1].outcome = OperationOutcome::Failed;
        assert!(
            payload
                .require_typed_write_quorum_loss_effect(
                    &tampered_history,
                    QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                    "bucket",
                    &payload_unavailable,
                    10,
                    11,
                )
                .is_err(),
            "unselected mutation history must still match the signed summary"
        );
    }

    #[test]
    fn validation_wrapper_writes_report_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        validate_fault_artifacts_and_write_report(&options).expect("valid artifacts");

        let report_path = dir
            .path()
            .join("fault_io_eio_preserves_committed_objects")
            .join("artifact-validation-report.json");
        let report = fs::read_to_string(report_path).expect("report");
        assert!(report.contains("\"status\": \"passed\""));
        assert!(report.contains("\"schema_version\": 1"));
    }

    #[test]
    fn validates_all_ack_triggered_mutation_shapes() {
        use crate::fault::acknowledged_mutation::AcknowledgedMutationKind;
        use crate::fault::history::OperationKind;

        let record = |id: &str,
                      kind: OperationKind,
                      key: &str,
                      size_bytes: Option<usize>,
                      started_at_ms: u64,
                      ended_at_ms: u64| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": "ack-case",
                "run_id": "run-1",
                "kind": kind,
                "bucket": "bucket",
                "key": key,
                "value_sha256": if matches!(kind, OperationKind::Put | OperationKind::CompleteMultipartUpload) { Some("sha256") } else { None },
                "size_bytes": size_bytes,
                "version_id": if matches!(kind, OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload) { Some("version-1") } else { None },
                "started_sequence": started_at_ms,
                "ended_sequence": ended_at_ms,
                "started_at_ms": started_at_ms,
                "ended_at_ms": ended_at_ms,
                "outcome": "ok",
                "http_status": 200,
                "error": null
            }))
            .expect("operation record")
        };
        let put = record("op-1", OperationKind::Put, "create", Some(4), 10, 11);
        super::validate_ack_mutation_shape(
            std::slice::from_ref(&put),
            &put,
            AcknowledgedMutationKind::Put,
        )
        .expect("create PUT shape");

        let zero = record("op-1", OperationKind::Put, "empty", Some(0), 10, 11);
        super::validate_ack_mutation_shape(
            std::slice::from_ref(&zero),
            &zero,
            AcknowledgedMutationKind::ZeroBytePut,
        )
        .expect("zero-byte PUT shape");

        let baseline = record("op-1", OperationKind::Put, "existing", Some(4), 1, 2);
        let overwrite = record("op-2", OperationKind::Put, "existing", Some(4), 10, 11);
        let overwrite_history = vec![baseline.clone(), overwrite.clone()];
        super::validate_ack_mutation_shape(
            &overwrite_history,
            &overwrite,
            AcknowledgedMutationKind::Overwrite,
        )
        .expect("overwrite shape");

        let delete = record("op-2", OperationKind::Delete, "existing", None, 10, 11);
        let delete_history = vec![baseline.clone(), delete.clone()];
        super::validate_ack_mutation_shape(
            &delete_history,
            &delete,
            AcknowledgedMutationKind::DeleteMarker,
        )
        .expect("delete-marker shape");

        let create_mpu = record(
            "op-1",
            OperationKind::CreateMultipartUpload,
            "multipart",
            None,
            1,
            2,
        );
        let upload_part = record(
            "op-2",
            OperationKind::UploadPart,
            "multipart",
            Some(8 * 1024 * 1024),
            3,
            4,
        );
        let complete = record(
            "op-3",
            OperationKind::CompleteMultipartUpload,
            "multipart",
            Some(8 * 1024 * 1024),
            10,
            11,
        );
        let multipart_history = vec![create_mpu, upload_part, complete.clone()];
        super::validate_ack_mutation_shape(
            &multipart_history,
            &complete,
            AcknowledgedMutationKind::MultipartComplete,
        )
        .expect("multipart completion shape");

        assert!(
            super::validate_ack_mutation_shape(
                &overwrite_history,
                &overwrite,
                AcknowledgedMutationKind::Put,
            )
            .is_err(),
            "create PUT must reject an existing baseline"
        );
        let incomplete_multipart_history = vec![multipart_history[0].clone(), complete.clone()];
        assert!(
            super::validate_ack_mutation_shape(
                &incomplete_multipart_history,
                &complete,
                AcknowledgedMutationKind::MultipartComplete,
            )
            .is_err(),
            "multipart completion must require both staging operations"
        );

        for trigger in [&put, &zero] {
            let prior_complete = record(
                "prior-complete",
                OperationKind::CompleteMultipartUpload,
                trigger.key.as_deref().expect("trigger key"),
                Some(4),
                1,
                2,
            );
            assert!(
                super::validate_ack_mutation_shape(
                    &[prior_complete, trigger.clone()],
                    trigger,
                    if trigger.size_bytes == Some(0) {
                        AcknowledgedMutationKind::ZeroBytePut
                    } else {
                        AcknowledgedMutationKind::Put
                    },
                )
                .is_err(),
                "create PUT variants must reject a prior multipart completion"
            );
        }

        let prior_complete = record(
            "prior-complete",
            OperationKind::CompleteMultipartUpload,
            "multipart",
            Some(4),
            1,
            2,
        );
        let staged_create = record(
            "create-mpu",
            OperationKind::CreateMultipartUpload,
            "multipart",
            None,
            3,
            4,
        );
        let staged_part = record(
            "upload-part",
            OperationKind::UploadPart,
            "multipart",
            Some(8 * 1024 * 1024),
            5,
            6,
        );
        assert!(
            super::validate_ack_mutation_shape(
                &[prior_complete, staged_create, staged_part, complete.clone()],
                &complete,
                AcknowledgedMutationKind::MultipartComplete,
            )
            .is_err(),
            "multipart create must reject a previously committed object"
        );

        for intervening_kind in [
            OperationKind::Delete,
            OperationKind::CompleteMultipartUpload,
        ] {
            let intervening = record("intervening", intervening_kind, "existing", Some(4), 3, 4);
            for (trigger, mutation) in [
                (&overwrite, AcknowledgedMutationKind::Overwrite),
                (&delete, AcknowledgedMutationKind::DeleteMarker),
            ] {
                assert!(
                    super::validate_ack_mutation_shape(
                        &[baseline.clone(), intervening.clone(), trigger.clone()],
                        trigger,
                        mutation,
                    )
                    .is_err(),
                    "overwrite/delete must reject an intervening {intervening_kind:?}"
                );
            }
        }
    }

    #[test]
    fn ack_success_path_rejects_incomplete_baseline_receipts() {
        for mutation in [
            AcknowledgedMutationKind::Overwrite,
            AcknowledgedMutationKind::DeleteMarker,
        ] {
            let scenario = match mutation {
                AcknowledgedMutationKind::Overwrite => "dm-drop-writes-after-ack-overwrite",
                AcknowledgedMutationKind::DeleteMarker => "dm-drop-writes-after-ack-delete-marker",
                _ => unreachable!("only baseline-backed mutations are tested"),
            };
            let key = "fault-test/run-1/key-1";
            let mut baseline =
                ack_failure_record(0, scenario, "baseline", OperationKind::Put, key, true);
            baseline.version_id = Some("baseline-version".to_string());
            baseline.value_sha256 = Some("baseline-hash".to_string());
            baseline.size_bytes = Some(4);
            baseline.http_status = Some(200);

            let mut trigger = ack_failure_record(
                1,
                scenario,
                "trigger",
                super::ack_operation_kind(mutation),
                key,
                true,
            );
            trigger.version_id = Some("trigger-version".to_string());
            trigger.http_status = Some(if mutation == AcknowledgedMutationKind::DeleteMarker {
                204
            } else {
                200
            });
            if mutation == AcknowledgedMutationKind::Overwrite {
                trigger.value_sha256 = Some("trigger-hash".to_string());
                trigger.size_bytes = Some(8);
            }

            let valid = vec![baseline.clone(), trigger.clone()];
            super::validate_ack_mutation_shape(&valid, &trigger, mutation)
                .expect("complete baseline receipt reaches the success checker");
            super::ack_checker_expectation(&valid, &trigger, mutation)
                .expect("complete baseline builds the success expectation");

            let invalid_baselines = [
                {
                    let mut record = baseline.clone();
                    record.size_bytes = None;
                    record
                },
                {
                    let mut record = baseline.clone();
                    record.value_sha256 = None;
                    record
                },
                {
                    let mut record = baseline.clone();
                    record.value_sha256 = Some(String::new());
                    record
                },
                {
                    let mut record = baseline.clone();
                    record.version_id = None;
                    record
                },
                {
                    let mut record = baseline.clone();
                    record.version_id = Some("null".to_string());
                    record
                },
                {
                    let mut record = baseline.clone();
                    record.http_status = Some(500);
                    record
                },
            ];
            for invalid_baseline in invalid_baselines {
                assert!(
                    super::validate_ack_mutation_shape(
                        &[invalid_baseline, trigger.clone()],
                        &trigger,
                        mutation,
                    )
                    .is_err(),
                    "{mutation:?} success artifacts must reject an incomplete baseline receipt"
                );
            }
        }
    }

    #[test]
    fn ack_trigger_contract_rejects_pre_ack_or_late_fault_activation() {
        use crate::fault::{
            acknowledged_mutation::AcknowledgedMutationKind, spec::FaultRunAckTriggerSpec,
        };

        let planned = FaultRunAckTriggerSpec {
            mutation: AcknowledgedMutationKind::Put,
            operation_timeout_ms: 30_000,
            max_ack_to_fault_ms: 5,
        };
        let valid = super::AckTriggeredCrashEvidenceArtifact {
            scenario: "dm-drop-writes-after-ack-put".to_string(),
            run_id: "run-1".to_string(),
            trigger_operation_id: "op-1".to_string(),
            trigger_kind: AcknowledgedMutationKind::Put,
            trigger_key: "key".to_string(),
            trigger_version_id: "version-1".to_string(),
            trigger_acknowledged_at_ms: 100,
            fault_activated_at_ms: 105,
            ack_to_fault_ms: 5,
            max_ack_to_fault_ms: 5,
            crash_boundary_started_at_ms: 110,
            crash_boundary_next_sequence: 3,
            ack_to_crash_boundary_ms: 10,
        };
        let trigger = serde_json::from_value::<OperationRecord>(json!({
            "id": "op-1",
            "scenario": "dm-drop-writes-after-ack-put",
            "run_id": "run-1",
            "kind": "put",
            "bucket": "bucket",
            "key": "key",
            "value_sha256": "trigger-hash",
            "size_bytes": 4,
            "version_id": "version-1",
            "started_sequence": 1,
            "ended_sequence": 2,
            "started_at_ms": 90,
            "ended_at_ms": 100,
            "outcome": "ok",
            "http_status": 200,
            "durability_cohort": "pre_fault"
        }))
        .expect("valid trigger operation");
        super::validate_ack_trigger_contract(
            &valid,
            &planned,
            AcknowledgedMutationKind::Put,
            "dm-drop-writes-after-ack-put",
            "run-1",
            super::AckFaultTimeline {
                prepare_started_at_ms: Some(80),
                apply_started_at_ms: Some(101),
            },
            &trigger,
        )
        .expect("valid trigger contract");

        for invalid_prepare in [None, Some(101)] {
            assert!(
                super::validate_ack_trigger_contract(
                    &valid,
                    &planned,
                    AcknowledgedMutationKind::Put,
                    "dm-drop-writes-after-ack-put",
                    "run-1",
                    super::AckFaultTimeline {
                        prepare_started_at_ms: invalid_prepare,
                        apply_started_at_ms: Some(101),
                    },
                    &trigger,
                )
                .is_err(),
                "fault preparation must be recorded before the trigger ACK"
            );
        }

        let boundary_plan = FaultRunAckTriggerSpec {
            operation_timeout_ms: 10,
            ..planned.clone()
        };
        super::validate_ack_trigger_contract(
            &valid,
            &boundary_plan,
            AcknowledgedMutationKind::Put,
            "dm-drop-writes-after-ack-put",
            "run-1",
            super::AckFaultTimeline {
                prepare_started_at_ms: Some(80),
                apply_started_at_ms: Some(101),
            },
            &trigger,
        )
        .expect("trigger duration equal to the planned timeout is valid");

        let mut inverted_trigger = trigger.clone();
        inverted_trigger.started_at_ms = 101;
        assert!(
            super::validate_ack_trigger_contract(
                &valid,
                &planned,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(101),
                },
                &inverted_trigger,
            )
            .is_err(),
            "an inverted trigger request interval must be rejected"
        );

        let over_timeout_plan = FaultRunAckTriggerSpec {
            operation_timeout_ms: 9,
            ..planned.clone()
        };
        assert!(
            super::validate_ack_trigger_contract(
                &valid,
                &over_timeout_plan,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(101),
                },
                &trigger,
            )
            .is_err(),
            "a trigger request longer than its planned timeout must be rejected"
        );

        let mut pre_ack = valid.clone();
        pre_ack.fault_activated_at_ms = 99;
        pre_ack.ack_to_fault_ms = 0;
        assert!(
            super::validate_ack_trigger_contract(
                &pre_ack,
                &planned,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(101),
                },
                &trigger,
            )
            .is_err()
        );

        let mut late = valid.clone();
        late.fault_activated_at_ms = 106;
        late.ack_to_fault_ms = 6;
        assert!(
            super::validate_ack_trigger_contract(
                &late,
                &planned,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(101),
                },
                &trigger,
            )
            .is_err()
        );

        let mut false_interval = valid.clone();
        false_interval.ack_to_fault_ms = 4;
        assert!(
            super::validate_ack_trigger_contract(
                &false_interval,
                &planned,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(101),
                },
                &trigger,
            )
            .is_err()
        );

        assert!(
            super::validate_ack_trigger_contract(
                &valid,
                &planned,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(99),
                },
                &trigger,
            )
            .is_err(),
            "starting fault application before the ACK must be rejected"
        );

        let over_wide_plan = FaultRunAckTriggerSpec {
            max_ack_to_fault_ms: crate::fault::config::MAX_ACK_TO_FAULT_MS + 1,
            ..planned
        };
        let mut over_wide_evidence = valid;
        over_wide_evidence.max_ack_to_fault_ms = over_wide_plan.max_ack_to_fault_ms;
        assert!(
            super::validate_ack_trigger_contract(
                &over_wide_evidence,
                &over_wide_plan,
                AcknowledgedMutationKind::Put,
                "dm-drop-writes-after-ack-put",
                "run-1",
                super::AckFaultTimeline {
                    prepare_started_at_ms: Some(80),
                    apply_started_at_ms: Some(101),
                },
                &trigger,
            )
            .is_err(),
            "artifact validation must reject an ACK window too wide for durability evidence"
        );
    }

    #[test]
    fn ack_mutation_preparation_requires_sequence_happens_before() {
        use crate::fault::acknowledged_mutation::AcknowledgedMutationKind;
        for (kind, preparation) in [
            (AcknowledgedMutationKind::Overwrite, OperationKind::Put),
            (AcknowledgedMutationKind::DeleteMarker, OperationKind::Put),
            (
                AcknowledgedMutationKind::MultipartComplete,
                OperationKind::UploadPart,
            ),
        ] {
            let record = |id: &str, operation: OperationKind, start: u64, end: u64| {
                serde_json::from_value::<OperationRecord>(json!({
                    "id": id, "scenario": "ack", "run_id": "run-1", "bucket": "bucket",
                    "key": "key", "kind": operation, "started_sequence": start, "ended_sequence": end,
                    "value_sha256": matches!(operation, OperationKind::Put | OperationKind::CompleteMultipartUpload).then_some("hash"),
                    "size_bytes": matches!(operation, OperationKind::Put | OperationKind::UploadPart | OperationKind::CompleteMultipartUpload).then_some(4),
                    "version_id": matches!(operation, OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload).then_some("version"),
                    "started_at_ms": 10, "ended_at_ms": 10, "outcome": "ok", "http_status": 200
                })).expect("record")
            };
            let trigger = record("trigger", super::ack_operation_kind(kind), 5, 6);
            let create = record("create", OperationKind::CreateMultipartUpload, 1, 2);
            let prepared = record("prepare", preparation, 3, 4);
            super::validate_ack_mutation_shape(
                &[create.clone(), prepared.clone(), trigger.clone()],
                &trigger,
                kind,
            )
            .expect("same-millisecond preparation with causal ordering");
            let mut overlapping = prepared;
            overlapping.ended_sequence = Some(6);
            assert!(
                super::validate_ack_mutation_shape(
                    &[create, overlapping, trigger.clone()],
                    &trigger,
                    kind,
                )
                .is_err(),
                "overlapping preparation cannot establish a prior committed state"
            );
        }
    }

    #[test]
    fn ack_checker_phases_require_contiguous_independent_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let mut history =
            read_jsonl::<OperationRecord>(&case_dir.join("history.jsonl")).expect("history");
        let pre = read_json::<CheckerReport>(&case_dir.join("checker-pre-recommit-report.json"))
            .expect("prechecker");
        let mut final_report = read_json::<CheckerReport>(&case_dir.join("checker-report.json"))
            .expect("final checker");
        history.drain(4..6);
        for (index, record) in history.iter_mut().enumerate() {
            record.started_sequence = Some(index as u64 * 2 + 1);
            record.ended_sequence = Some(index as u64 * 2 + 2);
        }
        final_report
            .audit
            .as_mut()
            .expect("audit")
            .history_prefix_record_count = 4;
        super::validate_ack_checker_phase_chain(&pre, &final_report, "bucket", &history)
            .expect("no recommit phase chain");
        assert!(
            super::validate_ack_checker_phase_chain(
                &final_report,
                &final_report,
                "bucket",
                &history
            )
            .is_err(),
            "one checker receipt cannot serve as both phases"
        );
        assert!(
            super::validate_ack_checker_phase_chain(&final_report, &pre, "bucket", &history)
                .is_err(),
            "checker phases cannot be swapped"
        );
        let mut overlap = history.clone();
        overlap[3].ended_sequence = Some(9);
        overlap[4].started_sequence = Some(8);
        let error =
            super::validate_ack_checker_phase_chain(&pre, &final_report, "bucket", &overlap)
                .expect_err("cross-phase sequence overlap");
        assert!(
            error.to_string().contains("ACK prechecker/final-checker"),
            "{error:#}"
        );

        let mut intervening = history[4].clone();
        intervening.id = "intervening-get".to_string();
        history.insert(4, intervening);
        for (index, record) in history.iter_mut().enumerate() {
            record.started_sequence = Some(index as u64 * 2 + 1);
            record.ended_sequence = Some(index as u64 * 2 + 2);
        }
        final_report
            .audit
            .as_mut()
            .expect("audit")
            .history_prefix_record_count = 5;
        assert!(
            super::validate_ack_checker_phase_chain(&pre, &final_report, "bucket", &history)
                .is_err(),
            "unattributed GET between checker phases must invalidate the chain"
        );
    }

    #[derive(Clone)]
    struct AckFailureFixture {
        history: Vec<OperationRecord>,
        report: CheckerReport,
        ack: super::AckTriggeredCrashEvidenceArtifact,
        prefix_len: usize,
    }

    fn ack_failure_record(
        ordinal: usize,
        scenario: &str,
        id: &str,
        kind: OperationKind,
        key: &str,
        before_fault: bool,
    ) -> OperationRecord {
        let started_sequence = ordinal as u64 * 2 + 1;
        let started_at_ms = if before_fault {
            10 + ordinal as u64 * 2
        } else {
            100 + ordinal as u64 * 2
        };
        OperationRecord {
            id: id.to_string(),
            scenario: scenario.to_string(),
            run_id: Some("run-1".to_string()),
            kind,
            bucket: "bucket".to_string(),
            key: Some(key.to_string()),
            value_sha256: None,
            size_bytes: None,
            version_id: None,
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: Some(started_sequence),
            ended_sequence: Some(started_sequence + 1),
            started_at_ms,
            ended_at_ms: started_at_ms + 1,
            outcome: OperationOutcome::Ok,
            http_status: None,
            error: None,
            durability_cohort: Some(if before_fault {
                DurabilityCohort::PreFault
            } else {
                DurabilityCohort::PostRecovery
            }),
            fault_window_relation: (!before_fault).then_some(FaultWindowRelation::AfterFault),
        }
    }

    impl AckFailureFixture {
        fn new(kind: AcknowledgedMutationKind) -> Self {
            let scenario = match kind {
                AcknowledgedMutationKind::Put => "dm-drop-writes-after-ack-put",
                AcknowledgedMutationKind::Overwrite => "dm-drop-writes-after-ack-overwrite",
                AcknowledgedMutationKind::DeleteMarker => "dm-drop-writes-after-ack-delete-marker",
                AcknowledgedMutationKind::ZeroBytePut => "dm-drop-writes-after-ack-zero-byte-put",
                AcknowledgedMutationKind::MultipartComplete => {
                    "dm-drop-writes-after-ack-multipart-complete"
                }
            };
            let key = "fault-test/run-1/key-1";
            let mut history = Vec::new();
            if matches!(
                kind,
                AcknowledgedMutationKind::Overwrite | AcknowledgedMutationKind::DeleteMarker
            ) {
                let mut baseline = ack_failure_record(
                    history.len(),
                    scenario,
                    "baseline",
                    OperationKind::Put,
                    key,
                    true,
                );
                baseline.version_id = Some("baseline-version".to_string());
                baseline.value_sha256 = Some("baseline-hash".to_string());
                baseline.size_bytes = Some(4);
                baseline.http_status = Some(200);
                history.push(baseline);
            }
            if kind == AcknowledgedMutationKind::MultipartComplete {
                let mut create = ack_failure_record(
                    history.len(),
                    scenario,
                    "create-mpu",
                    OperationKind::CreateMultipartUpload,
                    key,
                    true,
                );
                create.http_status = Some(200);
                history.push(create);
                let mut upload_part = ack_failure_record(
                    history.len(),
                    scenario,
                    "upload-part",
                    OperationKind::UploadPart,
                    key,
                    true,
                );
                upload_part.value_sha256 = Some("part-hash".to_string());
                upload_part.size_bytes = Some(4);
                upload_part.http_status = Some(200);
                history.push(upload_part);
            }
            let (trigger_hash, trigger_size) = match kind {
                AcknowledgedMutationKind::DeleteMarker => (None, None),
                AcknowledgedMutationKind::ZeroBytePut => (Some("empty-hash"), Some(0)),
                _ => (Some("trigger-hash"), Some(8)),
            };
            let mut trigger = ack_failure_record(
                history.len(),
                scenario,
                "trigger",
                super::ack_operation_kind(kind),
                key,
                true,
            );
            trigger.version_id = Some("trigger-version".to_string());
            trigger.value_sha256 = trigger_hash.map(str::to_string);
            trigger.size_bytes = trigger_size;
            trigger.http_status = Some(if kind == AcknowledgedMutationKind::DeleteMarker {
                204
            } else {
                200
            });
            history.push(trigger);
            let prefix_len = history.len();
            let trigger = history.last().expect("trigger").clone();
            let is_delete = kind == AcknowledgedMutationKind::DeleteMarker;
            let mut current_get = ack_failure_record(
                history.len(),
                scenario,
                "current-get",
                OperationKind::Get,
                key,
                false,
            );
            set_ack_get(
                &mut current_get,
                if is_delete {
                    OperationOutcome::NotFound
                } else {
                    OperationOutcome::Ok
                },
                Some(if is_delete { 404 } else { 200 }),
                if is_delete {
                    None
                } else {
                    trigger.value_sha256.as_deref()
                },
                if is_delete { None } else { trigger.size_bytes },
                is_delete.then_some("not found"),
            );
            history.push(current_get);
            let committed_data = history[..prefix_len]
                .iter()
                .filter(|record| {
                    record.outcome == OperationOutcome::Ok
                        && matches!(
                            record.kind,
                            OperationKind::Put | OperationKind::CompleteMultipartUpload
                        )
                })
                .cloned()
                .collect::<Vec<_>>();
            for version in &committed_data {
                let mut version_get = ack_failure_record(
                    history.len(),
                    scenario,
                    &format!("version-get-{}", version.id),
                    OperationKind::Get,
                    key,
                    false,
                );
                version_get.version_id = version.version_id.clone();
                set_ack_get(
                    &mut version_get,
                    OperationOutcome::Ok,
                    Some(200),
                    version.value_sha256.as_deref(),
                    version.size_bytes,
                    None,
                );
                history.push(version_get);
            }
            let prefix_key = crate::fault::workload::ObjectSpec::key_prefix("run-1");
            let mut version_list = ack_failure_record(
                history.len(),
                scenario,
                "list-versions",
                OperationKind::ListVersions,
                &prefix_key,
                false,
            );
            version_list.http_status = Some(200);
            version_list.listed_versions = Some(
                checker::checker_expected_version_listing(&history[..prefix_len])
                    .into_iter()
                    .collect(),
            );
            history.push(version_list);
            let mut final_list = ack_failure_record(
                history.len(),
                scenario,
                "list",
                OperationKind::List,
                &prefix_key,
                false,
            );
            final_list.http_status = Some(200);
            final_list.listed_keys = Some(if is_delete {
                Vec::new()
            } else {
                vec![key.to_string()]
            });
            history.push(final_list);

            let live_objects = usize::from(!is_delete);
            let report = CheckerReport {
                scenario: scenario.to_string(),
                run_id: "run-1".to_string(),
                committed_puts: committed_data.len(),
                expected_live_objects: live_objects,
                verified_live_objects: live_objects,
                missing_committed_objects: Vec::new(),
                unavailable_committed_objects: Vec::new(),
                unknown_committed_read_failures: Vec::new(),
                hash_mismatches: Vec::new(),
                successful_corrupted_reads: Vec::new(),
                unexpected_visible_deleted_objects: Vec::new(),
                unknown_writes_materialized: Vec::new(),
                unknown_writes_preserved_committed: Vec::new(),
                unknown_write_value_conflicts: Vec::new(),
                list_history_warning_count: 0,
                final_list_warning_count: 0,
                list_history_warnings: Vec::new(),
                list_warnings: Vec::new(),
                final_listed_objects: Some(live_objects),
                versioning_expected: true,
                expected_committed_versions: committed_data.len(),
                verified_committed_versions: committed_data.len(),
                committed_writes_missing_version_id_count: 0,
                committed_writes_missing_version_id: Vec::new(),
                missing_committed_versions: Vec::new(),
                unavailable_committed_versions: Vec::new(),
                version_hash_mismatches: Vec::new(),
                missing_committed_delete_markers: Vec::new(),
                resurrected_deleted_objects: Vec::new(),
                listed_keys_unreadable: Vec::new(),
                unexpected_listed_objects: Vec::new(),
                failed_writes_materialized: Vec::new(),
                delete_marker_lineage_incomplete: Vec::new(),
                multipart_upload_lineage_incomplete: Vec::new(),
                tolerated_ambiguous_deletes: Vec::new(),
                operation_cohorts: BTreeMap::from([("pre_fault".to_string(), prefix_len)]),
                fault_window_relations: BTreeMap::new(),
                audit: Some(checker::CheckerAudit {
                    bucket: "bucket".to_string(),
                    started_at_ms: 0,
                    completed_at_ms: 0,
                    history_prefix_record_count: prefix_len,
                    history_prefix_sha256: String::new(),
                    history_suffix_record_count: 0,
                    history_suffix_sha256: String::new(),
                    suffix_operations: Vec::new(),
                    data_version_checks: Vec::new(),
                    delete_marker_checks: Vec::new(),
                    list_object_versions_completed: Some(true),
                }),
                tenant_recovered: true,
                passed: false,
            };
            let trigger_acknowledged_at_ms = trigger.ended_at_ms;
            let ack = super::AckTriggeredCrashEvidenceArtifact {
                scenario: scenario.to_string(),
                run_id: "run-1".to_string(),
                trigger_operation_id: trigger.id.clone(),
                trigger_kind: kind,
                trigger_key: key.to_string(),
                trigger_version_id: "trigger-version".to_string(),
                trigger_acknowledged_at_ms,
                fault_activated_at_ms: trigger_acknowledged_at_ms + 1,
                ack_to_fault_ms: 1,
                max_ack_to_fault_ms: 5,
                crash_boundary_started_at_ms: trigger_acknowledged_at_ms + 2,
                crash_boundary_next_sequence: trigger.ended_sequence.expect("trigger end sequence")
                    + 1,
                ack_to_crash_boundary_ms: 2,
            };
            let mut fixture = Self {
                history,
                report,
                ack,
                prefix_len,
            };
            fixture.refresh_audit();
            if is_delete {
                fixture.fail_delete_marker_listing();
            } else {
                fixture.fail_data_version("trigger-version", true);
            }
            fixture
        }

        fn validate(&self) -> anyhow::Result<()> {
            super::validate_ack_expected_failure_report(
                &self.report,
                &self.history,
                &self.ack,
                "bucket",
            )
        }

        fn trigger(&self) -> &OperationRecord {
            &self.history[self.prefix_len - 1]
        }

        fn data_versions(&self) -> Vec<OperationRecord> {
            self.history[..self.prefix_len]
                .iter()
                .filter(|record| {
                    record.outcome == OperationOutcome::Ok
                        && matches!(
                            record.kind,
                            OperationKind::Put | OperationKind::CompleteMultipartUpload
                        )
                })
                .cloned()
                .collect()
        }

        fn current_get_mut(&mut self) -> &mut OperationRecord {
            self.history[self.prefix_len..]
                .iter_mut()
                .find(|record| record.kind == OperationKind::Get && record.version_id.is_none())
                .expect("current GET")
        }

        fn version_get_mut(&mut self, version_id: &str) -> &mut OperationRecord {
            self.history[self.prefix_len..]
                .iter_mut()
                .find(|record| {
                    record.kind == OperationKind::Get
                        && record.version_id.as_deref() == Some(version_id)
                })
                .expect("version GET")
        }

        fn version_list_mut(&mut self) -> &mut OperationRecord {
            self.history[self.prefix_len..]
                .iter_mut()
                .find(|record| record.kind == OperationKind::ListVersions)
                .expect("ListObjectVersions")
        }

        fn final_list_mut(&mut self) -> &mut OperationRecord {
            self.history[self.prefix_len..]
                .iter_mut()
                .find(|record| record.kind == OperationKind::List)
                .expect("final LIST")
        }

        fn clear_failures(&mut self) {
            self.report.missing_committed_objects.clear();
            self.report.unavailable_committed_objects.clear();
            self.report.unknown_committed_read_failures.clear();
            self.report.hash_mismatches.clear();
            self.report.successful_corrupted_reads.clear();
            self.report.unexpected_visible_deleted_objects.clear();
            self.report.missing_committed_versions.clear();
            self.report.unavailable_committed_versions.clear();
            self.report.version_hash_mismatches.clear();
            self.report.missing_committed_delete_markers.clear();
            self.report.resurrected_deleted_objects.clear();
            self.report.delete_marker_lineage_incomplete.clear();
            self.report.multipart_upload_lineage_incomplete.clear();
            self.report.final_list_warning_count = 0;
            self.report.list_warnings.clear();
            self.report.passed = false;
        }

        fn restore_healthy_observations(&mut self) {
            self.clear_failures();
            let data_versions = self.data_versions();
            for version in &data_versions {
                let get = self
                    .version_get_mut(version.version_id.as_deref().expect("committed version id"));
                set_ack_get(
                    get,
                    OperationOutcome::Ok,
                    Some(200),
                    version.value_sha256.as_deref(),
                    version.size_bytes,
                    None,
                );
            }
            self.report.verified_committed_versions = data_versions.len();
            let expected_listing =
                checker::checker_expected_version_listing(&self.history[..self.prefix_len])
                    .into_iter()
                    .collect::<Vec<_>>();
            self.version_list_mut().listed_versions = Some(expected_listing);
            let trigger = self.trigger().clone();
            if trigger.kind == OperationKind::Delete {
                set_ack_get(
                    self.current_get_mut(),
                    OperationOutcome::NotFound,
                    Some(404),
                    None,
                    None,
                    Some("not found"),
                );
                self.final_list_mut().listed_keys = Some(Vec::new());
                self.report.verified_live_objects = 0;
                self.report.final_listed_objects = Some(0);
            } else {
                set_ack_get(
                    self.current_get_mut(),
                    OperationOutcome::Ok,
                    Some(200),
                    trigger.value_sha256.as_deref(),
                    trigger.size_bytes,
                    None,
                );
                let trigger_key = self.ack.trigger_key.clone();
                self.final_list_mut().listed_keys = Some(vec![trigger_key]);
                self.report.verified_live_objects = 1;
                self.report.final_listed_objects = Some(1);
            }
            self.refresh_audit();
        }

        fn fail_data_version(&mut self, version_id: &str, current_missing: bool) {
            self.restore_healthy_observations();
            let version = self
                .data_versions()
                .into_iter()
                .find(|record| record.version_id.as_deref() == Some(version_id))
                .expect("protected data version");
            set_ack_get(
                self.version_get_mut(version_id),
                OperationOutcome::NotFound,
                Some(404),
                None,
                None,
                Some("not found"),
            );
            let protected_history = self.history[..self.prefix_len].to_vec();
            let entries = self
                .version_list_mut()
                .listed_versions
                .as_mut()
                .expect("listed versions");
            entries.retain(|entry| entry.version_id.as_deref() != Some(version_id));
            normalize_ack_latest(entries, &protected_history);
            let reference = format!("{}@{version_id}", self.ack.trigger_key);
            self.report.missing_committed_versions = vec![
                reference.clone(),
                format!("{reference}: committed version missing from ListObjectVersions"),
            ];
            self.report.verified_committed_versions = self.data_versions().len() - 1;
            if version.kind == OperationKind::CompleteMultipartUpload {
                self.report.multipart_upload_lineage_incomplete = vec![
                    format!("{reference}: committed multipart completion version is missing"),
                    format!(
                        "{reference}: committed multipart completion missing from ListObjectVersions"
                    ),
                ];
            }
            if current_missing {
                set_ack_get(
                    self.current_get_mut(),
                    OperationOutcome::NotFound,
                    Some(404),
                    None,
                    None,
                    Some("not found"),
                );
                self.final_list_mut().listed_keys = Some(Vec::new());
                self.report.missing_committed_objects = vec![self.ack.trigger_key.clone()];
                self.report.verified_live_objects = 0;
                self.report.final_listed_objects = Some(0);
                self.report.delete_marker_lineage_incomplete = vec![format!(
                    "{}: latest version does not match the committed trigger",
                    self.ack.trigger_key
                )];
            }
            self.refresh_audit();
        }

        fn fail_delete_marker_listing(&mut self) {
            self.restore_healthy_observations();
            let marker_version = self.ack.trigger_version_id.clone();
            let protected_history = self.history[..self.prefix_len].to_vec();
            let entries = self
                .version_list_mut()
                .listed_versions
                .as_mut()
                .expect("listed versions");
            entries.retain(|entry| entry.version_id.as_deref() != Some(marker_version.as_str()));
            normalize_ack_latest(entries, &protected_history);
            let reference = format!("{}@{marker_version}", self.ack.trigger_key);
            self.report.missing_committed_delete_markers = vec![format!(
                "{reference}: committed delete marker missing from ListObjectVersions"
            )];
            self.report.delete_marker_lineage_incomplete = vec![format!(
                "{}: latest version does not match the committed delete marker",
                self.ack.trigger_key
            )];
            self.refresh_audit();
        }

        fn refresh_audit(&mut self) {
            let prefix = &self.history[..self.prefix_len];
            let suffix = &self.history[self.prefix_len..];
            let listed_versions = suffix
                .iter()
                .find(|record| record.kind == OperationKind::ListVersions)
                .and_then(|record| record.listed_versions.clone())
                .unwrap_or_default();
            let mut data_version_checks = prefix
                .iter()
                .filter(|record| {
                    record.outcome == OperationOutcome::Ok
                        && matches!(
                            record.kind,
                            OperationKind::Put | OperationKind::CompleteMultipartUpload
                        )
                })
                .filter_map(|version| {
                    let version_id = version.version_id.as_deref()?;
                    let get = suffix.iter().find(|record| {
                        record.kind == OperationKind::Get
                            && record.key == version.key
                            && record.version_id.as_deref() == Some(version_id)
                    })?;
                    Some(checker::CheckerDataVersionAudit {
                        key: version.key.clone()?,
                        version_id: version_id.to_string(),
                        expected_sha256: version.value_sha256.clone()?,
                        observed_sha256: get.value_sha256.clone(),
                        outcome: get.outcome,
                        http_status: get.http_status,
                    })
                })
                .collect::<Vec<_>>();
            data_version_checks.sort_by(|left, right| {
                (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
            });
            let mut delete_marker_checks = prefix
                .iter()
                .filter(|record| {
                    record.kind == OperationKind::Delete && record.outcome == OperationOutcome::Ok
                })
                .filter_map(|marker| {
                    let key = marker.key.clone()?;
                    let version_id = marker.version_id.clone()?;
                    Some(checker::CheckerDeleteMarkerAudit {
                        visible_in_list_object_versions: listed_versions.iter().any(|entry| {
                            entry.key == key
                                && entry.version_id.as_deref() == Some(version_id.as_str())
                                && entry.is_delete_marker
                        }),
                        key,
                        version_id,
                    })
                })
                .collect::<Vec<_>>();
            delete_marker_checks.sort_by(|left, right| {
                (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
            });
            let list_completed = suffix
                .iter()
                .find(|record| record.kind == OperationKind::ListVersions)
                .is_some_and(|record| {
                    record.outcome == OperationOutcome::Ok && record.http_status == Some(200)
                });
            let audit = self.report.audit.as_mut().expect("checker audit");
            audit.started_at_ms = suffix
                .iter()
                .map(|record| record.started_at_ms)
                .min()
                .expect("checker suffix");
            audit.completed_at_ms = suffix
                .iter()
                .map(|record| record.ended_at_ms)
                .max()
                .expect("checker suffix");
            audit.history_prefix_record_count = self.prefix_len;
            audit.history_prefix_sha256 =
                checker::checker_history_records_sha256(prefix).expect("prefix digest");
            audit.history_suffix_record_count = suffix.len();
            audit.history_suffix_sha256 =
                checker::checker_history_records_sha256(suffix).expect("suffix digest");
            audit.suffix_operations = checker::checker_operation_audits(suffix);
            audit.data_version_checks = data_version_checks;
            audit.delete_marker_checks = delete_marker_checks;
            audit.list_object_versions_completed = Some(list_completed);
        }
    }

    fn set_ack_get(
        record: &mut OperationRecord,
        outcome: OperationOutcome,
        http_status: Option<u16>,
        value_sha256: Option<&str>,
        size_bytes: Option<usize>,
        error: Option<&str>,
    ) {
        record.outcome = outcome;
        record.http_status = http_status;
        record.value_sha256 = value_sha256.map(str::to_string);
        record.size_bytes = size_bytes;
        record.error = error.map(str::to_string);
    }

    fn normalize_ack_latest(entries: &mut [ListedVersionEntry], prefix: &[OperationRecord]) {
        entries.iter_mut().for_each(|entry| entry.is_latest = false);
        if let Some(latest) = prefix.iter().rev().find(|record| {
            entries.iter().any(|entry| {
                entry.key == record.key.as_deref().unwrap_or_default()
                    && entry.version_id == record.version_id
                    && entry.is_delete_marker == (record.kind == OperationKind::Delete)
            })
        }) && let Some(entry) = entries.iter_mut().find(|entry| {
            Some(entry.key.as_str()) == latest.key.as_deref()
                && entry.version_id == latest.version_id
                && entry.is_delete_marker == (latest.kind == OperationKind::Delete)
        }) {
            entry.is_latest = true;
        }
    }

    #[test]
    fn ack_expected_failure_accepts_direct_loss_for_all_trigger_types() {
        for kind in [
            AcknowledgedMutationKind::Put,
            AcknowledgedMutationKind::Overwrite,
            AcknowledgedMutationKind::DeleteMarker,
            AcknowledgedMutationKind::ZeroBytePut,
            AcknowledgedMutationKind::MultipartComplete,
        ] {
            let fixture = AckFailureFixture::new(kind);
            fixture
                .validate()
                .unwrap_or_else(|error| panic!("{kind:?}: {error:#}"));
            super::validate_ack_prechecker_boundary(
                &fixture.report,
                &fixture.history,
                &fixture.ack.trigger_operation_id,
                Some(90),
            )
            .expect("checker starts after recovery and exactly after trigger");
        }
    }

    #[test]
    fn ack_expected_failure_accepts_baseline_loss_for_overwrite_and_delete() {
        for kind in [
            AcknowledgedMutationKind::Overwrite,
            AcknowledgedMutationKind::DeleteMarker,
        ] {
            let mut fixture = AckFailureFixture::new(kind);
            fixture.fail_data_version("baseline-version", false);
            fixture
                .validate()
                .unwrap_or_else(|error| panic!("{kind:?}: {error:#}"));
        }
    }

    #[test]
    fn ack_expected_failure_accepts_current_rollback_or_absence_with_exact_versions() {
        let mut rollback = AckFailureFixture::new(AcknowledgedMutationKind::Overwrite);
        rollback.restore_healthy_observations();
        set_ack_get(
            rollback.current_get_mut(),
            OperationOutcome::Ok,
            Some(200),
            Some("baseline-hash"),
            Some(4),
            None,
        );
        rollback.report.verified_live_objects = 0;
        rollback.report.hash_mismatches = vec![format!(
            "{}: current GET returned the baseline value",
            rollback.ack.trigger_key
        )];
        rollback.refresh_audit();
        rollback.validate().expect("authenticated current rollback");

        let mut absent = AckFailureFixture::new(AcknowledgedMutationKind::Overwrite);
        absent.restore_healthy_observations();
        set_ack_get(
            absent.current_get_mut(),
            OperationOutcome::NotFound,
            Some(404),
            None,
            None,
            Some("not found"),
        );
        absent.final_list_mut().listed_keys = Some(Vec::new());
        absent.report.verified_live_objects = 0;
        absent.report.final_listed_objects = Some(0);
        absent.report.missing_committed_objects = vec![absent.ack.trigger_key.clone()];
        absent.refresh_audit();
        absent
            .validate()
            .expect("authenticated current GET 404 with exact versions readable");
    }

    #[test]
    fn ack_expected_failure_accepts_marker_latest_conflict_and_resurrection() {
        for duplicate_latest in [false, true] {
            let mut fixture = AckFailureFixture::new(AcknowledgedMutationKind::DeleteMarker);
            fixture.restore_healthy_observations();
            let entries = fixture
                .version_list_mut()
                .listed_versions
                .as_mut()
                .expect("listed versions");
            for entry in entries {
                if entry.version_id.as_deref() == Some("baseline-version") {
                    entry.is_latest = true;
                } else if !duplicate_latest {
                    entry.is_latest = false;
                }
            }
            fixture.report.delete_marker_lineage_incomplete = vec![format!(
                "{}: ListObjectVersions latest identity is invalid",
                fixture.ack.trigger_key
            )];
            fixture.refresh_audit();
            fixture
                .validate()
                .expect("authenticated marker latest conflict");
        }

        let mut resurrected = AckFailureFixture::new(AcknowledgedMutationKind::DeleteMarker);
        resurrected.restore_healthy_observations();
        set_ack_get(
            resurrected.current_get_mut(),
            OperationOutcome::Ok,
            Some(200),
            Some("baseline-hash"),
            Some(4),
            None,
        );
        resurrected.report.resurrected_deleted_objects = vec![format!(
            "{}: committed delete resurrected on GET",
            resurrected.ack.trigger_key
        )];
        resurrected.refresh_audit();
        resurrected
            .validate()
            .expect("authenticated deleted-object resurrection");
    }

    #[test]
    fn ack_expected_failure_accepts_version_timeout_hash_mismatch_and_list_only_omission() {
        let mut timeout = AckFailureFixture::new(AcknowledgedMutationKind::Put);
        timeout.restore_healthy_observations();
        set_ack_get(
            timeout.version_get_mut("trigger-version"),
            OperationOutcome::Timeout,
            Some(200),
            None,
            None,
            Some("body timed out"),
        );
        timeout.report.verified_committed_versions = 0;
        timeout.report.unavailable_committed_versions = vec![format!(
            "{}@trigger-version: Timeout HTTP 200: body timed out",
            timeout.ack.trigger_key
        )];
        timeout.refresh_audit();
        timeout
            .validate()
            .expect("authenticated version body timeout");

        let mut mismatch = AckFailureFixture::new(AcknowledgedMutationKind::Put);
        mismatch.restore_healthy_observations();
        set_ack_get(
            mismatch.version_get_mut("trigger-version"),
            OperationOutcome::Ok,
            Some(200),
            Some("wrong-hash"),
            Some(8),
            None,
        );
        mismatch.report.verified_committed_versions = 0;
        mismatch.report.version_hash_mismatches = vec![format!(
            "{}@trigger-version: expected trigger-hash, got wrong-hash",
            mismatch.ack.trigger_key
        )];
        mismatch.refresh_audit();
        mismatch
            .validate()
            .expect("authenticated version hash mismatch");

        let mut listing = AckFailureFixture::new(AcknowledgedMutationKind::Put);
        listing.restore_healthy_observations();
        listing
            .version_list_mut()
            .listed_versions
            .as_mut()
            .expect("listed versions")
            .clear();
        listing.report.missing_committed_versions = vec![format!(
            "{}@trigger-version: committed version missing from ListObjectVersions",
            listing.ack.trigger_key
        )];
        listing.report.delete_marker_lineage_incomplete = vec![format!(
            "{}: ListObjectVersions has no unique latest entry",
            listing.ack.trigger_key
        )];
        listing.refresh_audit();
        listing
            .validate()
            .expect("authenticated listing-only omission");
    }

    #[test]
    fn ack_expected_failure_rejects_unrelated_or_forged_evidence() {
        let fixture = AckFailureFixture::new(AcknowledgedMutationKind::Put);

        let mut unrelated = fixture.clone();
        unrelated.report.missing_committed_versions = vec![
            "fault-test/run-1/other@other-version".to_string(),
            "fault-test/run-1/other@other-version: committed version missing from ListObjectVersions"
                .to_string(),
        ];
        assert!(
            unrelated.validate().is_err(),
            "another key/version is not proof"
        );

        let mut forged_receipt = fixture.clone();
        forged_receipt
            .report
            .audit
            .as_mut()
            .expect("audit")
            .suffix_operations
            .clear();
        assert!(
            forged_receipt.validate().is_err(),
            "a self-reported audit cannot replace raw operation receipts"
        );

        let mut forged_classification = fixture.clone();
        forged_classification
            .report
            .missing_committed_versions
            .clear();
        forged_classification.report.hash_mismatches = vec![format!(
            "{}: claimed corruption",
            forged_classification.ack.trigger_key
        )];
        assert!(
            forged_classification.validate().is_err(),
            "classification without a matching negative receipt must fail closed"
        );

        let mut wrong_audit_identity = fixture.clone();
        wrong_audit_identity
            .report
            .audit
            .as_mut()
            .expect("audit")
            .data_version_checks[0]
            .version_id = "other-version".to_string();
        assert!(wrong_audit_identity.validate().is_err());

        let mut ranged = fixture.clone();
        ranged.version_get_mut("trigger-version").range = Some(ByteRange {
            offset: 0,
            length: 1,
        });
        ranged.refresh_audit();
        assert!(
            ranged.validate().is_err(),
            "a ranged GET is not full-version proof"
        );

        let mut missing_size = AckFailureFixture::new(AcknowledgedMutationKind::Overwrite);
        missing_size.history[0].size_bytes = None;
        missing_size.refresh_audit();
        assert!(
            missing_size.validate().is_err(),
            "protected baseline data without size cannot prove hash correctness"
        );

        let mut duplicate_sequence = fixture.clone();
        duplicate_sequence.history[duplicate_sequence.prefix_len].started_sequence =
            duplicate_sequence.history[0].started_sequence;
        duplicate_sequence.refresh_audit();
        assert!(
            duplicate_sequence.validate().is_err(),
            "duplicate global history sequence must be rejected"
        );

        let mut cross_bucket = fixture.clone();
        cross_bucket.history[cross_bucket.prefix_len - 1].bucket = "other-bucket".to_string();
        cross_bucket.refresh_audit();
        assert!(
            cross_bucket.validate().is_err(),
            "ACK trigger from another bucket must be rejected"
        );
    }

    #[test]
    fn ack_expected_failure_rejects_mutating_or_pre_recovery_checker_traffic() {
        for kind in [OperationKind::Put, OperationKind::Delete] {
            let mut fixture = AckFailureFixture::new(AcknowledgedMutationKind::Put);
            let trigger_key = fixture.ack.trigger_key.clone();
            let record = fixture.final_list_mut();
            record.kind = kind;
            record.key = Some(trigger_key);
            record.version_id = Some(format!("post-{kind:?}"));
            record.value_sha256 = (kind == OperationKind::Put).then(|| "post-hash".to_string());
            record.size_bytes = (kind == OperationKind::Put).then_some(4);
            fixture.refresh_audit();
            assert!(
                fixture.validate().is_err(),
                "post-boundary {kind:?} must invalidate checker evidence"
            );
        }

        let mut fault_active = AckFailureFixture::new(AcknowledgedMutationKind::Put);
        let read = fault_active.current_get_mut();
        read.durability_cohort = Some(DurabilityCohort::FaultActive);
        read.fault_window_relation = Some(FaultWindowRelation::DuringFault);
        fault_active.refresh_audit();
        assert!(
            fault_active.validate().is_err(),
            "fault-active reads cannot serve as post-recovery checker evidence"
        );

        let mut extra_before_checker = AckFailureFixture::new(AcknowledgedMutationKind::Put);
        extra_before_checker.prefix_len += 1;
        extra_before_checker.refresh_audit();
        assert!(
            super::validate_ack_prechecker_boundary(
                &extra_before_checker.report,
                &extra_before_checker.history,
                &extra_before_checker.ack.trigger_operation_id,
                Some(90),
            )
            .is_err(),
            "the first checker prefix must end exactly at the trigger"
        );

        let fixture = AckFailureFixture::new(AcknowledgedMutationKind::Put);
        let checker_started_at_ms = fixture.report.audit.as_ref().expect("audit").started_at_ms;
        assert!(
            super::validate_ack_prechecker_boundary(
                &fixture.report,
                &fixture.history,
                &fixture.ack.trigger_operation_id,
                Some(checker_started_at_ms + 1),
            )
            .is_err(),
            "checker observations cannot start before recovery completes"
        );
    }

    #[test]
    fn ack_checker_must_prove_the_exact_history_derived_version() {
        use crate::fault::{
            acknowledged_mutation::AcknowledgedMutationKind, checker::CheckerReport,
            history::OperationRecord,
        };

        let trigger: OperationRecord = serde_json::from_value(json!({
            "id": "put-1",
            "scenario": "dm-drop-writes-after-ack-put",
            "run_id": "run-1",
            "kind": "put",
            "bucket": "bucket",
            "key": "key-1",
            "value_sha256": "hash-1",
            "size_bytes": 4,
            "version_id": "version-1",
            "started_at_ms": 10,
            "ended_at_ms": 11,
            "outcome": "ok",
            "http_status": 200,
            "error": null
        }))
        .expect("trigger");
        let expectation = super::ack_checker_expectation(
            std::slice::from_ref(&trigger),
            &trigger,
            AcknowledgedMutationKind::Put,
        )
        .expect("expectation");
        let report = |verified_refs: Vec<&str>| {
            serde_json::from_value::<CheckerReport>(json!({
                "scenario": "dm-drop-writes-after-ack-put",
                "run_id": "run-1",
                "committed_puts": 1,
                "expected_live_objects": 1,
                "verified_live_objects": 1,
                "missing_committed_objects": [],
                "unavailable_committed_objects": [],
                "unknown_committed_read_failures": [],
                "hash_mismatches": [],
                "successful_corrupted_reads": [],
                "unexpected_visible_deleted_objects": [],
                "list_history_warning_count": 0,
                "final_list_warning_count": 0,
                "list_history_warnings": [],
                "list_warnings": [],
                "final_listed_objects": 1,
                "versioning_expected": true,
                "expected_committed_versions": 1,
                "verified_committed_versions": verified_refs.len(),
                "audit": {
                    "bucket": "bucket",
                    "started_at_ms": 20,
                    "completed_at_ms": 30,
                    "history_prefix_record_count": 1,
                    "history_prefix_sha256": "prefix",
                    "history_suffix_record_count": 1,
                    "history_suffix_sha256": "suffix",
                    "suffix_operations": [],
                    "data_version_checks": verified_refs.iter().map(|reference| {
                        let (key, version) = reference.split_once('@').expect("version reference");
                        json!({"key": key, "version_id": version, "expected_sha256": "hash-1",
                            "observed_sha256": "hash-1", "outcome": "ok", "http_status": 200})
                    }).collect::<Vec<_>>(),
                    "delete_marker_checks": [],
                    "list_object_versions_completed": true
                },
                "operation_cohorts": {"pre_fault": 1},
                "fault_window_relations": {},
                "tenant_recovered": true,
                "passed": true
            }))
            .expect("checker report")
        };

        super::validate_ack_checker_report(
            "checker-report.json",
            &report(vec!["key-1@version-1"]),
            &expectation,
        )
        .expect("exact version proof");
        assert!(
            super::validate_ack_checker_report(
                "checker-report.json",
                &report(Vec::new()),
                &expectation,
            )
            .is_err(),
            "an empty passed checker must not prove ACK durability"
        );
        assert!(
            super::validate_ack_checker_report(
                "checker-report.json",
                &report(vec!["key-1@other-version"]),
                &expectation,
            )
            .is_err(),
            "a different version from the same run must not prove the trigger"
        );
    }

    #[test]
    fn ack_checker_must_prove_the_exact_delete_marker() {
        use crate::fault::{
            acknowledged_mutation::AcknowledgedMutationKind, checker::CheckerReport,
            history::OperationRecord,
        };

        let record = |id: &str, kind: &str, version_id: &str, hash: Option<&str>| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": "dm-drop-writes-after-ack-delete-marker",
                "run_id": "run-1",
                "kind": kind,
                "bucket": "bucket",
                "key": "key-1",
                "value_sha256": hash,
                "size_bytes": hash.map(|_| 4),
                "version_id": version_id,
                "started_at_ms": if kind == "put" { 1 } else { 10 },
                "ended_at_ms": if kind == "put" { 2 } else { 11 },
                "outcome": "ok",
                "http_status": 200,
                "error": null
            }))
            .expect("record")
        };
        let baseline = record("put-1", "put", "version-1", Some("hash-1"));
        let trigger = record("delete-1", "delete", "marker-1", None);
        let expectation = super::ack_checker_expectation(
            &[baseline, trigger.clone()],
            &trigger,
            AcknowledgedMutationKind::DeleteMarker,
        )
        .expect("expectation");
        let report = |markers: Vec<&str>| {
            serde_json::from_value::<CheckerReport>(json!({
                "scenario": "dm-drop-writes-after-ack-delete-marker",
                "run_id": "run-1",
                "committed_puts": 1,
                "expected_live_objects": 0,
                "verified_live_objects": 0,
                "missing_committed_objects": [],
                "unavailable_committed_objects": [],
                "unknown_committed_read_failures": [],
                "hash_mismatches": [],
                "successful_corrupted_reads": [],
                "unexpected_visible_deleted_objects": [],
                "list_history_warning_count": 0,
                "final_list_warning_count": 0,
                "list_history_warnings": [],
                "list_warnings": [],
                "final_listed_objects": 0,
                "versioning_expected": true,
                "expected_committed_versions": 1,
                "verified_committed_versions": 1,
                "audit": {
                    "bucket": "bucket",
                    "started_at_ms": 20,
                    "completed_at_ms": 30,
                    "history_prefix_record_count": 2,
                    "history_prefix_sha256": "prefix",
                    "history_suffix_record_count": 1,
                    "history_suffix_sha256": "suffix",
                    "suffix_operations": [],
                    "data_version_checks": [{"key": "key-1", "version_id": "version-1",
                        "expected_sha256": "hash-1", "observed_sha256": "hash-1",
                        "outcome": "ok", "http_status": 200}],
                    "delete_marker_checks": markers.iter().map(|reference| {
                        let (key, version) = reference.split_once('@').expect("marker reference");
                        json!({"key": key, "version_id": version, "visible_in_list_object_versions": true})
                    }).collect::<Vec<_>>(),
                    "list_object_versions_completed": true
                },
                "operation_cohorts": {"pre_fault": 2},
                "fault_window_relations": {},
                "tenant_recovered": true,
                "passed": true
            }))
            .expect("checker report")
        };

        super::validate_ack_checker_report(
            "checker-report.json",
            &report(vec!["key-1@marker-1"]),
            &expectation,
        )
        .expect("exact delete marker proof");
        assert!(
            super::validate_ack_checker_report(
                "checker-report.json",
                &report(Vec::new()),
                &expectation,
            )
            .is_err(),
            "a passed checker without the trigger delete marker must fail closed"
        );
    }

    #[test]
    fn ack_trigger_contract_rejects_s3_traffic_before_crash_boundary() {
        let record = |id: &str, kind: OperationKind, started_at_ms: u64, recovered: bool| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": "ack-case",
                "run_id": "run-1",
                "kind": kind,
                "bucket": "bucket",
                "key": id,
                "value_sha256": "abc",
                "size_bytes": 4,
                "version_id": if kind == OperationKind::Put { Some(id) } else { None },
                "started_sequence": if id == "op-1" { 1 } else { 3 },
                "ended_sequence": if id == "op-1" { 2 } else { 4 },
                "started_at_ms": started_at_ms,
                "ended_at_ms": started_at_ms + 1,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": if recovered { "post_recovery" } else { "pre_fault" },
                "fault_window_relation": if recovered { "after_fault" } else { "before_fault" }
            }))
            .expect("operation record")
        };
        let trigger = record("op-1", OperationKind::Put, 90, false);
        let recovery_read = record("op-2", OperationKind::Get, 121, true);
        super::validate_ack_quiet_gap(&[trigger.clone(), recovery_read], &trigger, 120, 3)
            .expect("quiet gap");

        let extra = record("op-2", OperationKind::Get, 115, true);
        assert!(
            super::validate_ack_quiet_gap(&[trigger.clone(), extra], &trigger, 120, 5).is_err(),
            "traffic after the ACK must invalidate the quiet crash window"
        );

        let mut trigger = trigger;
        trigger.ended_at_ms = trigger.started_at_ms;
        let mut same_ms = record("op-2", OperationKind::Get, trigger.started_at_ms, true);
        same_ms.ended_at_ms = trigger.started_at_ms;
        for boundary_sequence in [4, 5] {
            assert!(
                super::validate_ack_quiet_gap(
                    &[trigger.clone(), same_ms.clone()],
                    &trigger,
                    trigger.started_at_ms,
                    boundary_sequence,
                )
                .is_err(),
                "pending or completed same-millisecond traffic before the boundary invalidates the quiet gap"
            );
        }
        super::validate_ack_quiet_gap(
            &[trigger.clone(), same_ms],
            &trigger,
            trigger.started_at_ms,
            3,
        )
        .expect("recovery traffic after the captured sequence boundary may share its millisecond");
    }

    #[test]
    fn validates_dm_crash_boundary_evidence_package() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir.path().join("case");
        fs::create_dir_all(&case_dir).expect("case dir");
        write_json(
            &case_dir,
            "crash-window-evidence.json",
            &json!({
                "scenario": "dm-flakey-versioned-hot",
                "run_id": "run-1",
                "fault_active_at_ms": 20,
                "crash_boundary_started_at_ms": 50,
                "committed_versioned_mutations": 1,
                "trigger_operation_id": "put-3",
                "trigger_kind": "put",
                "trigger_key": "key-3",
                "trigger_version_id": "version-3",
                "trigger_acknowledged_at_ms": 45,
                "ack_to_crash_boundary_ms": 5
            }),
        );
        write_json(
            &case_dir,
            "dm-crash-boundary.json",
            &json!({
                "scenario": "dm-flakey-versioned-hot",
                "run_id": "run-1",
                "started_at_ms": 50,
                "completed_at_ms": 60,
                "old_pod_uid": "uid-before",
                "replacement_pod_uid": null,
                "filesystem_unmounted": true,
                "mapper_mounts_absent": true,
                "mount_before": {
                    "source": "/dev/mapper/rustfs0",
                    "canonical_source": "/dev/dm-0",
                    "filesystem": "ext4",
                    "options": "rw,relatime"
                },
                "fault": {
                    "table": "0 100 flakey /dev/sda 0 0 86400 1 drop_writes"
                }
            }),
        );
        write_json(
            &case_dir,
            "dm-crash-recovered.json",
            &json!({
                "scenario": "dm-flakey-versioned-hot",
                "run_id": "run-1",
                "recovered_at_ms": 70,
                "taint_removed": true,
                "mount": {
                    "source": "/dev/mapper/rustfs0",
                    "canonical_source": "/dev/dm-0",
                    "filesystem": "ext4",
                    "options": "rw,relatime"
                },
                "expected_table": "0 100 linear /dev/sda 0",
                "fault": {"table": "0 100 linear /dev/sda 0"}
            }),
        );
        let history_record = json!({
            "id": "put-3",
            "scenario": "dm-flakey-versioned-hot",
            "kind": "put",
            "bucket": "bucket",
            "key": "key-3",
            "value_sha256": "abc",
            "size_bytes": 4096,
            "version_id": "version-3",
            "started_at_ms": 40,
            "ended_at_ms": 45,
            "outcome": "ok",
            "http_status": 200,
            "error": null,
            "durability_cohort": "fault_active",
            "fault_window_relation": "during_fault"
        });
        fs::write(
            case_dir.join("history.jsonl"),
            format!("{}\n", history_record),
        )
        .expect("history");
        let events = vec![
            serde_json::from_value(json!({
                "at_ms": 60,
                "scenario": "dm-flakey-versioned-hot",
                "run_id": "run-1",
                "stage": "crash-recovery-boundary",
                "status": "succeeded",
                "message": "boundary complete"
            }))
            .expect("event"),
        ];
        let evidence = serde_json::from_value(json!({
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": false,
            "client_disruptions": 0,
            "pods_before": [{"name": "rustfs-0", "uid": "uid-before"}],
            "pods_after": [{"name": "rustfs-0", "uid": "uid-after"}],
            "active_snapshots": [{}],
            "workload_snapshots": [{}],
            "fault_active_at_ms": 20,
            "workload_ended_at_ms": 49,
            "fault_delete_started_at_ms": 61
        }))
        .expect("fault evidence");

        super::validate_dm_crash_artifacts(
            dir.path(),
            "case",
            &events,
            &evidence,
            "dm-flakey-versioned-hot",
            "run-1",
            "bucket",
        )
        .expect("valid DM crash evidence package");

        let mut mismatched = history_record.clone();
        mismatched["version_id"] = json!("different-version");
        fs::write(case_dir.join("history.jsonl"), format!("{}\n", mismatched))
            .expect("mismatched history");
        assert!(
            super::validate_dm_crash_artifacts(
                dir.path(),
                "case",
                &events,
                &evidence,
                "dm-flakey-versioned-hot",
                "run-1",
                "bucket",
            )
            .is_err()
        );

        write_json(
            &case_dir,
            "crash-window-evidence.json",
            &json!({
                "scenario": "dm-flakey-versioned-hot",
                "run_id": "run-1",
                "fault_active_at_ms": 20,
                "crash_boundary_started_at_ms": 50,
                "committed_versioned_mutations": 2,
                "trigger_operation_id": "put-3",
                "trigger_kind": "put",
                "trigger_key": "key-3",
                "trigger_version_id": "version-3",
                "trigger_acknowledged_at_ms": 45,
                "ack_to_crash_boundary_ms": 5
            }),
        );
        let mut later_record = history_record.clone();
        later_record["id"] = json!("put-4");
        later_record["key"] = json!("key-4");
        later_record["version_id"] = json!("version-4");
        later_record["started_at_ms"] = json!(46);
        later_record["ended_at_ms"] = json!(48);
        fs::write(
            case_dir.join("history.jsonl"),
            format!("{}\n{}\n", history_record, later_record),
        )
        .expect("history with a later mutation");
        assert!(
            super::validate_dm_crash_artifacts(
                dir.path(),
                "case",
                &events,
                &evidence,
                "dm-flakey-versioned-hot",
                "run-1",
                "bucket",
            )
            .is_err()
        );
    }

    #[test]
    fn validates_failure_summary_v2_checker_projection() {
        let summary = failure_summary_v2_for_test();

        super::validate_failure_summary_v2_fields(&summary, None, None).expect("valid v2 summary");
    }

    #[test]
    fn accepts_legacy_v2_case_relative_evidence_refs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let summary_path = dir.path().join("failure-summary.json");
        fs::write(&summary_path, "{}").expect("summary");
        fs::write(dir.path().join("checker-report.json"), "{}").expect("checker");
        fs::write(dir.path().join("run-events.jsonl"), "").expect("events");
        let summary = failure_summary_v2_for_test();

        super::validate_failure_summary_v2_fields(&summary, Some(dir.path()), Some(&summary_path))
            .expect("existing evidence refs");
    }

    #[test]
    fn validates_suite_root_relative_evidence_refs_from_attempt_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("suite-plan.json"), "{}").expect("suite plan");
        fs::write(dir.path().join("suite-summary.json"), "{}").expect("suite summary");
        let attempt_root = dir.path().join("001-io-eio-r1");
        let case_dir = attempt_root.join("case");
        fs::create_dir_all(&case_dir).expect("case dir");
        let summary_path = case_dir.join("failure-summary.json");
        fs::write(&summary_path, "{}").expect("summary");
        fs::write(case_dir.join("checker-report.json"), "{}").expect("checker");
        fs::write(case_dir.join("run-events.jsonl"), "").expect("events");
        let mut summary = failure_summary_v2_for_test();
        summary.primary_evidence_refs = vec![
            "001-io-eio-r1/case/checker-report.json".to_string(),
            "001-io-eio-r1/case/run-events.jsonl".to_string(),
        ];

        let reference_root = super::failure_summary_reference_root(&attempt_root);
        assert_eq!(reference_root, dir.path());
        super::validate_failure_summary_v2_fields(
            &summary,
            Some(reference_root),
            Some(&summary_path),
        )
        .expect("suite-root-relative evidence refs");
    }

    #[test]
    fn rejects_failure_summary_v2_suite_root_relative_self_reference() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir.path().join("001-io-eio-r1").join("case");
        fs::create_dir_all(&case_dir).expect("case dir");
        let summary_path = case_dir.join("failure-summary.json");
        fs::write(&summary_path, "{}").expect("summary");
        let mut summary = failure_summary_v2_for_test();
        summary.primary_evidence_refs = vec!["001-io-eio-r1/case/failure-summary.json".to_string()];

        let error = super::validate_failure_summary_v2_fields(
            &summary,
            Some(dir.path()),
            Some(&summary_path),
        )
        .expect_err("self reference");

        assert!(error.to_string().contains("must not reference"));
    }

    #[test]
    fn rejects_failure_summary_v2_missing_evidence_ref_next_to_summary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let summary_path = dir.path().join("failure-summary.json");
        fs::write(&summary_path, "{}").expect("summary");
        let summary = failure_summary_v2_for_test();

        let error = super::validate_failure_summary_v2_fields(
            &summary,
            Some(dir.path()),
            Some(&summary_path),
        )
        .expect_err("missing evidence ref");

        assert!(error.to_string().contains("does not exist"));
    }

    #[test]
    fn allows_legacy_failure_summary_without_v2_fields() {
        let mut summary = failure_summary_v2_for_test();
        summary.schema_version = 0;
        summary.phase = None;
        summary.s3_model_classification = None;
        summary.responsibility_domain = None;
        summary.primary_evidence_refs.clear();

        super::validate_failure_summary_v2_fields(&summary, None, None).expect("legacy summary");
    }

    #[test]
    fn allows_existing_v2_summary_without_additive_fields() {
        let mut summary = failure_summary_v2_for_test();
        summary.schema_version = 2;
        summary.case_name = None;
        summary.observed_at_ms = None;
        summary.phase = None;
        summary.s3_model_classification = None;
        summary.run_failure_reason = None;
        summary.responsibility_domain = None;
        summary.primary_evidence_refs.clear();

        super::validate_failure_summary_v2_fields(&summary, None, None)
            .expect("existing v2 additive fields remain optional");
    }

    #[test]
    fn rejects_failure_summary_v2_unknown_classification() {
        let mut summary = failure_summary_v2_for_test();
        summary.classification = "data_corrupton".to_string();

        let error = super::validate_failure_summary_v2_fields(&summary, None, None)
            .expect_err("unknown classification");

        assert!(error.to_string().contains("writer allowlist"));
    }

    #[test]
    fn rejects_failure_summary_v2_zero_observed_timestamp() {
        let mut summary = failure_summary_v2_for_test();
        summary.observed_at_ms = Some(0);

        let error = super::validate_failure_summary_v2_fields(&summary, None, None)
            .expect_err("zero timestamp");

        assert!(error.to_string().contains("observed_at_ms"));
    }

    #[test]
    fn validates_precise_checker_recovery_summary_contracts() {
        let cases = [
            (
                RecoveryStabilityClassification::CommittedVersionMissing,
                FailureSeverity::FailCorrectness,
                DataCorrectnessStatus::Failed,
                AvailabilityStatus::Unknown,
                Some(true),
                Some(false),
                Some(false),
                false,
                "missing_committed_version: k@v1",
            ),
            (
                RecoveryStabilityClassification::CommittedVersionUnavailable,
                FailureSeverity::FailAvailability,
                DataCorrectnessStatus::Unknown,
                AvailabilityStatus::CommittedVersionUnavailable,
                None,
                Some(false),
                Some(false),
                true,
                "unavailable_committed_version: k@v1 timeout",
            ),
            (
                RecoveryStabilityClassification::VersionHashMismatch,
                FailureSeverity::FailCorrectness,
                DataCorrectnessStatus::Failed,
                AvailabilityStatus::Unknown,
                Some(false),
                Some(true),
                None,
                false,
                "version_hash_mismatch: k@v1",
            ),
            (
                RecoveryStabilityClassification::DeleteMarkerMissing,
                FailureSeverity::FailCorrectness,
                DataCorrectnessStatus::Failed,
                AvailabilityStatus::Unknown,
                Some(false),
                Some(true),
                None,
                false,
                "missing_committed_delete_marker: k@marker-1",
            ),
            (
                RecoveryStabilityClassification::DeletedObjectResurrected,
                FailureSeverity::FailCorrectness,
                DataCorrectnessStatus::Failed,
                AvailabilityStatus::Unknown,
                Some(false),
                Some(true),
                None,
                false,
                "resurrected_deleted_object: k",
            ),
            (
                RecoveryStabilityClassification::DeleteMarkerLineageIncomplete,
                FailureSeverity::NeedsInvestigation,
                DataCorrectnessStatus::Unknown,
                AvailabilityStatus::Unknown,
                None,
                Some(false),
                None,
                false,
                "delete_marker_lineage_incomplete: delete-op",
            ),
            (
                RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite,
                FailureSeverity::NeedsInvestigation,
                DataCorrectnessStatus::Unknown,
                AvailabilityStatus::Unknown,
                None,
                Some(false),
                None,
                false,
                "committed_write_missing_version_id: put-op",
            ),
            (
                RecoveryStabilityClassification::MultipartUploadLineageIncomplete,
                FailureSeverity::NeedsInvestigation,
                DataCorrectnessStatus::Unknown,
                AvailabilityStatus::Unknown,
                None,
                Some(false),
                None,
                false,
                "multipart_upload_lineage_incomplete: complete-op",
            ),
        ];

        for (
            classification,
            severity,
            data_correctness,
            availability,
            data_loss,
            corruption,
            recovered_within_window,
            version_unavailable,
            evidence,
        ) in cases
        {
            let recovery = RecoveryStabilityReport {
                scenario: None,
                run_id: None,
                immediate_passed: false,
                reread_attempted_keys: Vec::new(),
                reread_recovered_keys: Vec::new(),
                still_unavailable_keys: if version_unavailable {
                    vec!["version:k@v1".to_string()]
                } else {
                    Vec::new()
                },
                hash_mismatches: Vec::new(),
                data_corruption_evidence: Vec::new(),
                classification_evidence: vec![evidence.to_string()],
                ambiguous_write_evidence: Vec::new(),
                final_list_warning_count: 0,
                list_warnings: Vec::new(),
                harness_errors: Vec::new(),
                max_recovery_seconds: 60,
                recovered_within_seconds: None,
                classification,
            };
            super::validate_recovery_stability_report(&recovery)
                .expect("valid precise recovery classification");

            let mut summary = failure_summary_v2_for_test();
            summary.classification = classification.as_str().to_string();
            summary.s3_model_classification = Some(classification.as_str().to_string());
            summary.severity = severity;
            summary.data_correctness = data_correctness;
            summary.availability = availability;
            summary.data_loss = data_loss;
            summary.corruption = corruption;
            summary.recovered_within_window = recovered_within_window;
            summary.evidence_classifications = recovery.evidence_classifications();

            crate::fault::reporting::validate_failure_summary_v2_classification(&summary)
                .expect("valid precise summary projection");
            super::validate_recovery_failure_summary_fields(&summary, &recovery)
                .expect("valid precise recovery summary fields");
        }
    }

    #[test]
    fn rejects_version_timeout_summary_that_claims_data_loss() {
        let recovery = RecoveryStabilityReport {
            scenario: None,
            run_id: None,
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: vec!["version:k@v1".to_string()],
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            classification_evidence: vec!["unavailable_committed_version: k@v1".to_string()],
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::CommittedVersionUnavailable,
        };
        let mut summary = failure_summary_v2_for_test();
        summary.classification = "committed_version_unavailable".to_string();
        summary.s3_model_classification = Some("committed_version_unavailable".to_string());
        summary.severity = FailureSeverity::FailAvailability;
        summary.data_correctness = DataCorrectnessStatus::Unknown;
        summary.availability = AvailabilityStatus::CommittedVersionUnavailable;
        summary.data_loss = Some(true);
        summary.corruption = Some(false);
        summary.recovered_within_window = Some(false);
        summary.evidence_classifications = recovery.evidence_classifications();

        let error = super::validate_recovery_failure_summary_fields(&summary, &recovery)
            .expect_err("timeout must not claim data loss");

        assert!(
            error
                .to_string()
                .contains("outcome fields contradict classification committed_version_unavailable")
        );
    }

    #[test]
    fn rejects_timeout_list_and_harness_summaries_that_claim_data_loss() {
        let reports = [
            (
                RecoveryStabilityReport {
                    scenario: None,
                    run_id: None,
                    immediate_passed: false,
                    reread_attempted_keys: vec!["object-key".to_string()],
                    reread_recovered_keys: Vec::new(),
                    still_unavailable_keys: vec!["object-key".to_string()],
                    hash_mismatches: Vec::new(),
                    data_corruption_evidence: Vec::new(),
                    classification_evidence: Vec::new(),
                    ambiguous_write_evidence: Vec::new(),
                    final_list_warning_count: 0,
                    list_warnings: Vec::new(),
                    harness_errors: Vec::new(),
                    max_recovery_seconds: 60,
                    recovered_within_seconds: None,
                    classification: RecoveryStabilityClassification::CommittedObjectUnavailable,
                },
                FailureSeverity::FailAvailability,
                AvailabilityStatus::CommittedObjectUnavailable,
                Some(false),
                Some(false),
            ),
            (
                RecoveryStabilityReport {
                    scenario: None,
                    run_id: None,
                    immediate_passed: false,
                    reread_attempted_keys: Vec::new(),
                    reread_recovered_keys: Vec::new(),
                    still_unavailable_keys: Vec::new(),
                    hash_mismatches: Vec::new(),
                    data_corruption_evidence: Vec::new(),
                    classification_evidence: Vec::new(),
                    ambiguous_write_evidence: Vec::new(),
                    final_list_warning_count: 1,
                    list_warnings: vec!["LIST prefix did not complete".to_string()],
                    harness_errors: Vec::new(),
                    max_recovery_seconds: 60,
                    recovered_within_seconds: None,
                    classification: RecoveryStabilityClassification::ListUnavailableOrUnknown,
                },
                FailureSeverity::FailAvailability,
                AvailabilityStatus::ListUnavailableOrUnknown,
                Some(false),
                Some(false),
            ),
            (
                RecoveryStabilityReport::harness_error(
                    "synthetic checker error",
                    std::time::Duration::from_secs(60),
                ),
                FailureSeverity::Infra,
                AvailabilityStatus::Unknown,
                None,
                None,
            ),
        ];

        for (recovery, severity, availability, corruption, recovered_within_window) in reports {
            let mut summary = failure_summary_v2_for_test();
            summary.classification = recovery.classification.as_str().to_string();
            summary.severity = severity;
            summary.data_correctness = DataCorrectnessStatus::Unknown;
            summary.availability = availability;
            summary.data_loss = Some(true);
            summary.corruption = corruption;
            summary.recovered_within_window = recovered_within_window;
            summary.evidence_classifications = recovery.evidence_classifications();
            summary.final_list_warning_count = recovery.final_list_warning_count;
            summary.list_warnings = recovery.list_warnings.clone();
            if recovery.classification == RecoveryStabilityClassification::HarnessError {
                summary.s3_model_classification = None;
                summary.run_failure_reason = Some("harness_error".to_string());
                summary.responsibility_domain = Some(ResponsibilityDomain::Harness);
            } else {
                summary.s3_model_classification =
                    Some(recovery.classification.as_str().to_string());
                summary.run_failure_reason = None;
                summary.responsibility_domain = Some(ResponsibilityDomain::Product);
            }

            crate::fault::reporting::validate_failure_summary_v2_classification(&summary)
                .expect("classification tags remain valid");
            let error = super::validate_recovery_failure_summary_fields(&summary, &recovery)
                .expect_err("non-loss evidence must reject data_loss=true");
            assert!(error.to_string().contains(&format!(
                "outcome fields contradict classification {}",
                recovery.classification.as_str()
            )));
        }
    }

    #[test]
    fn rejects_precise_classification_with_unrelated_evidence() {
        let recovery = RecoveryStabilityReport {
            scenario: None,
            run_id: None,
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            classification_evidence: vec![
                "missing_committed_delete_marker: k@marker-1".to_string(),
            ],
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::CommittedVersionMissing,
        };

        let error = super::validate_recovery_stability_report(&recovery)
            .expect_err("unrelated evidence must not substantiate committed version loss");

        assert!(
            error
                .to_string()
                .contains("matching classification_evidence")
        );
    }

    #[test]
    fn validate_written_failure_summary_reads_files_from_disk() {
        let dir = tempfile::tempdir().expect("temp dir");

        // A v2 summary that violates the contract (phase mismatched) must be
        // caught when read back from disk — this is the failure-path
        // diagnostic entry used by reporting::write_failure_summary.
        let bad = dir.path().join("failure-summary.json");
        std::fs::write(
            &bad,
            serde_json::json!({
                "schema_version": 2,
                "scenario": "io-eio",
                "stage": "checker",
                "phase": "workload",
                "verdict": "failed",
                "severity": "fail_correctness",
                "classification": "data_corruption",
                "data_correctness": "failed",
                "availability": "unknown",
                "message": "boom",
            })
            .to_string(),
        )
        .expect("write bad summary");
        let error = crate::fault::reporting::validate_written_failure_summary(dir.path(), &bad)
            .expect_err("v2 violation");
        assert!(
            error.to_string().contains("phase"),
            "unexpected error: {error:#}"
        );

        // Legacy (pre-v2) summaries stay accepted, so the diagnostic check
        // never rejects old artifacts.
        let legacy = dir.path().join("legacy-failure-summary.json");
        std::fs::write(
            &legacy,
            serde_json::json!({
                "scenario": "io-eio",
                "stage": "checker",
                "verdict": "failed",
                "severity": "fail_correctness",
                "classification": "data_corruption",
                "data_correctness": "failed",
                "availability": "unknown",
                "message": "boom",
            })
            .to_string(),
        )
        .expect("write legacy summary");
        crate::fault::reporting::validate_written_failure_summary(dir.path(), &legacy)
            .expect("legacy summary accepted");

        // Unparseable JSON is a contract violation, not a silent pass.
        let torn = dir.path().join("torn-failure-summary.json");
        std::fs::write(&torn, "{ not json").expect("write torn summary");
        assert!(
            crate::fault::reporting::validate_written_failure_summary(dir.path(), &torn).is_err()
        );
    }

    #[test]
    fn parses_legacy_failure_summary_without_evidence_classifications() {
        let summary: FailureSummary = serde_json::from_value(json!({
            "scenario": "io-eio",
            "stage": "checker-pre-recommit-verdict",
            "verdict": "failed",
            "severity": "fail_correctness",
            "classification": "data_corruption",
            "data_correctness": "failed",
            "availability": "unknown",
            "message": "hash mismatch"
        }))
        .expect("legacy failure-summary.json");

        assert_eq!(summary.schema_version, 0);
        assert!(summary.evidence_classifications.is_empty());
        super::validate_failure_summary_v2_fields(&summary, None, None).expect("legacy summary");
    }

    #[test]
    fn rejects_failure_summary_v2_mismatched_phase() {
        let mut summary = failure_summary_v2_for_test();
        summary.phase = Some(FailurePhase::Workload);

        let error =
            super::validate_failure_summary_v2_fields(&summary, None, None).expect_err("bad phase");

        assert!(error.to_string().contains("phase"));
    }

    #[test]
    fn rejects_failure_summary_v2_checker_with_run_failure_reason() {
        let mut summary = failure_summary_v2_for_test();
        summary.run_failure_reason = Some("data_corruption".to_string());

        let error = super::validate_failure_summary_v2_fields(&summary, None, None)
            .expect_err("checker summary must not set run_failure_reason");

        assert!(error.to_string().contains("S3 model classification"));
    }

    #[test]
    fn rejects_failure_summary_v2_wrong_run_failure_responsibility_domain() {
        let mut summary = failure_summary_v2_for_test();
        summary.stage = "fault-backend-preflight".to_string();
        summary.phase = Some(FailurePhase::Preflight);
        summary.classification = "environment_or_fault_backend".to_string();
        summary.s3_model_classification = None;
        summary.run_failure_reason = Some("environment_or_fault_backend".to_string());
        summary.responsibility_domain = Some(ResponsibilityDomain::Product);
        summary.primary_evidence_refs = vec![
            "failure-summary.json".to_string(),
            "run-events.jsonl".to_string(),
        ];

        let error = super::validate_failure_summary_v2_fields(&summary, None, None)
            .expect_err("wrong responsibility domain");

        assert!(error.to_string().contains("responsibility_domain"));
    }

    #[test]
    fn rejects_failure_summary_v2_unsafe_evidence_ref() {
        let mut summary = failure_summary_v2_for_test();
        summary
            .primary_evidence_refs
            .push("../outside.json".to_string());

        let error = super::validate_failure_summary_v2_fields(&summary, None, None)
            .expect_err("unsafe evidence ref");

        assert!(error.to_string().contains("artifact root"));
    }

    #[test]
    fn rejects_missing_required_artifact() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        fs::remove_file(
            dir.path()
                .join("fault_io_eio_preserves_committed_objects")
                .join("checker-report.json"),
        )
        .expect("remove checker");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("missing checker");

        assert!(error.to_string().contains("checker-report.json"));
    }

    #[test]
    fn rejects_missing_explicit_recovery_stability_reread_metadata() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let metadata_path = case_dir.join("run-metadata.json");
        let mut metadata = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&metadata_path).expect("metadata"),
        )
        .expect("metadata json");
        metadata
            .as_object_mut()
            .expect("metadata object")
            .remove("recovery_stability_reread_seconds");
        fs::write(
            &metadata_path,
            serde_json::to_string_pretty(&metadata).expect("json"),
        )
        .expect("rewrite metadata");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("missing metadata field");

        assert!(
            error
                .to_string()
                .contains("recovery_stability_reread_seconds")
        );
    }

    #[test]
    fn rejects_run_spec_when_versioning_expectation_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: true,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("versioning mismatch");

        assert!(error.to_string().contains("run-spec workload.versioning"));
    }

    #[test]
    fn rejects_checker_report_when_versioning_expectation_mismatches() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        rewrite_run_spec_versioning(&case_dir, true);
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: true,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("checker versioning mismatch");

        assert!(
            error
                .to_string()
                .contains("checker-pre-recommit-report.json versioning_expected")
        );
    }

    #[test]
    fn rejects_clean_checker_report_with_ambiguous_write_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let checker_path = case_dir.join("checker-pre-recommit-report.json");
        let mut checker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&checker_path).expect("checker report"))
                .expect("checker json");
        checker["unknown_writes_materialized"] = json!(["k: op-2 materialized"]);
        write_json(&case_dir, "checker-pre-recommit-report.json", &checker);
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("ambiguous evidence mismatch");

        assert!(error.to_string().contains("did not pass"));
    }

    #[test]
    fn rejects_mismatched_recovery_stability_failure_summary_classification() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": ["k"],
                "reread_recovered_keys": ["k"],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "recovery_tail_read_latency"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "fail_availability",
                "classification": "committed_object_unavailable",
                "evidence_classifications": ["recovery_tail_read_latency"],
                "data_correctness": "unknown",
                "availability": "committed_object_unavailable",
                "corruption": false,
                "recovered_within_window": false,
                "message": "immediate checker failed"
            }),
        );
        let options = ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: dir.path().to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        };

        let error = validate_fault_artifacts(&options).expect_err("classification mismatch");

        assert!(
            error
                .to_string()
                .contains("failure-summary.json classification")
        );
    }

    #[test]
    fn validates_recovery_tail_failure_summary_severity_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": ["k"],
                "reread_recovered_keys": ["k"],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "recovered_within_seconds": 27,
                "classification": "recovery_tail_read_latency"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "evidence_classifications": ["recovery_tail_read_latency"],
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 27,
                "message": "immediate checker failed"
            }),
        );

        super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect("valid recovery failure fields");
    }

    #[test]
    fn validates_list_unavailable_failure_summary_severity_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": [],
                "final_list_warning_count": 1,
                "list_warnings": ["LIST prefix fault-test/ did not complete"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "list_unavailable_or_unknown"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "fail_availability",
                "classification": "list_unavailable_or_unknown",
                "evidence_classifications": ["list_unavailable_or_unknown"],
                "final_list_warning_count": 1,
                "list_warnings": ["LIST prefix fault-test/ did not complete"],
                "data_correctness": "unknown",
                "availability": "list_unavailable_or_unknown",
                "corruption": false,
                "recovered_within_window": false,
                "message": "final LIST did not complete"
            }),
        );

        super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect("valid LIST availability failure fields");
    }

    #[test]
    fn validates_ambiguous_write_failure_summary_severity_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "ambiguous_write_materialized"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "needs_investigation",
                "classification": "ambiguous_write_materialized",
                "evidence_classifications": ["ambiguous_write_materialized"],
                "data_correctness": "unknown",
                "availability": "unknown",
                "corruption": false,
                "message": "immediate checker failed"
            }),
        );

        super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect("valid ambiguous write failure fields");
    }

    #[test]
    fn rejects_ambiguous_write_summary_with_proven_loss_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "ambiguous_write_materialized"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "needs_investigation",
                "classification": "ambiguous_write_materialized",
                "evidence_classifications": ["ambiguous_write_materialized"],
                "data_correctness": "unknown",
                "availability": "unknown",
                "data_loss": true,
                "corruption": false,
                "recovered_within_window": false,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect_err("ambiguous summary with loss fields");

        assert!(
            error
                .to_string()
                .contains("outcome fields contradict classification ambiguous_write_materialized")
        );
    }

    #[test]
    fn rejects_ambiguous_write_report_with_harder_recovery_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": [],
                "hash_mismatches": ["k: expected old, got other"],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "ambiguous_write_materialized"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "needs_investigation",
                "classification": "ambiguous_write_materialized",
                "evidence_classifications": ["ambiguous_write_materialized", "data_corruption"],
                "data_correctness": "unknown",
                "availability": "unknown",
                "corruption": false,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect_err("ambiguous report with hard evidence");

        assert!(
            error
                .to_string()
                .contains("without harder recovery failures")
        );
    }

    #[test]
    fn rejects_tail_latency_report_with_ambiguous_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string(),
                json!({"at_ms":2,"scenario":"io-eio","run_id":"run-1","stage":"recovery-stability-reread","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": ["k"],
                "reread_recovered_keys": ["k"],
                "still_unavailable_keys": [],
                "hash_mismatches": [],
                "data_corruption_evidence": [],
                "ambiguous_write_evidence": ["ambiguous_write_materialized: k op-2"],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "recovered_within_seconds": 27,
                "classification": "recovery_tail_read_latency"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "degraded",
                "classification": "recovery_tail_read_latency",
                "evidence_classifications": ["ambiguous_write_materialized", "recovery_tail_read_latency"],
                "data_correctness": "passed",
                "availability": "recovered_after_tail_latency",
                "data_loss": false,
                "corruption": false,
                "recovered_within_window": true,
                "recovered_within_seconds": 27,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect_err("tail latency with ambiguous evidence");

        assert!(error.to_string().contains("without hard failures"));
    }

    #[test]
    fn rejects_availability_report_with_data_corruption_evidence() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = dir.path().join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [json!({"at_ms":1,"scenario":"io-eio","run_id":"run-1","stage":"checker-pre-recommit","status":"failed","message":"failed"}).to_string()].join("\n"),
        )
        .expect("events");
        write_json(
            &case_dir,
            "recovery-stability-report.json",
            &json!({
                "immediate_passed": false,
                "reread_attempted_keys": [],
                "reread_recovered_keys": [],
                "still_unavailable_keys": ["k"],
                "hash_mismatches": [],
                "data_corruption_evidence": ["unknown_write_value_conflict: k"],
                "ambiguous_write_evidence": [],
                "harness_errors": [],
                "max_recovery_seconds": 60,
                "classification": "committed_object_unavailable"
            }),
        );
        write_json(
            &case_dir,
            "failure-summary.json",
            &json!({
                "scenario": "io-eio",
                "stage": "checker-pre-recommit-verdict",
                "verdict": "failed",
                "severity": "fail_availability",
                "classification": "committed_object_unavailable",
                "evidence_classifications": ["committed_object_unavailable", "data_corruption"],
                "data_correctness": "unknown",
                "availability": "committed_object_unavailable",
                "corruption": false,
                "recovered_within_window": false,
                "message": "immediate checker failed"
            }),
        );

        let error = super::validate_conditional_recovery_stability_artifact(
            dir.path(),
            case_name,
            "io-eio",
            None,
        )
        .expect_err("availability report with data evidence");

        assert!(
            error
                .to_string()
                .contains("without higher-priority recovery failures")
        );
    }

    fn failure_summary_v2_for_test() -> FailureSummary {
        FailureSummary {
            schema_version: 2,
            scenario: "io-eio".to_string(),
            run_id: None,
            case_name: Some("fault_io_eio_preserves_committed_objects".to_string()),
            observed_at_ms: None,
            stage: "checker-pre-recommit-verdict".to_string(),
            phase: Some(FailurePhase::Checker),
            verdict: FailureVerdict::Failed,
            severity: FailureSeverity::FailCorrectness,
            classification: "data_corruption".to_string(),
            s3_model_classification: Some("data_corruption".to_string()),
            run_failure_reason: None,
            responsibility_domain: Some(ResponsibilityDomain::Product),
            data_correctness: DataCorrectnessStatus::Failed,
            availability: AvailabilityStatus::Unknown,
            primary_evidence_refs: vec![
                "failure-summary.json".to_string(),
                "checker-report.json".to_string(),
                "run-events.jsonl".to_string(),
            ],
            evidence_classifications: vec!["data_corruption".to_string()],
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            data_loss: None,
            corruption: Some(true),
            recovered_within_window: None,
            recovered_within_seconds: None,
            message: "hash mismatch".to_string(),
        }
    }

    fn success_options(root: &std::path::Path) -> ArtifactValidationOptions {
        ArtifactValidationOptions {
            scenario: "io-eio".to_string(),
            artifact_root: root.to_path_buf(),
            expected_workload_objects: 12,
            expected_workload_concurrency: 4,
            expected_workload_versioning: false,
            expected_rustfs_pod_count: 4,
            expected_stable_window_seconds: 60,
            expected_recovery_stability_reread_seconds: 60,
            expected_rustfs_volume_path: "/data/rustfs0".to_string(),
        }
    }

    fn write_success_artifacts(root: &std::path::Path, scenario: &str) {
        let run_id = "run-00000000-0000-4000-8000-000000000001";
        let case_dir = root.join("fault_io_eio_preserves_committed_objects");
        fs::create_dir_all(&case_dir).expect("case dir");
        let plan = WorkloadPlan::seeded(42, 12, 4);
        let run_spec = json!({
            "apiVersion": FAULT_RUN_API_VERSION,
            "kind": FAULT_RUN_KIND,
            "metadata": {"name": "fault_io_eio_preserves_committed_objects", "run_id": run_id, "bucket": "bucket"},
            "cluster": {
                "context": "real-cluster",
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "storage_class": "fast-csi",
                "rustfs_image": "rustfs:test",
                "chaos_namespace": "chaos-mesh",
                "use_cluster_ip": false
            },
            "scenario": {
                "name": scenario,
                "case_name": "fault_io_eio_preserves_committed_objects",
                "priority": "p0",
                "isolation": "fresh-tenant",
                "impact_policy": "availability-required",
                "boundary": "rustfs-workload/fault-injection",
                "validation": "prefill succeeds before injection, every committed object remains readable while IOChaos is active, the mixed workload meets the availability floor, committed PUTs are GET+sha256 verified after recovery, and successful GETs cannot return corrupt bytes",
                "detector": {
                    "revision": 1,
                    "qualification": "gate-candidate",
                    "detects": ["data-shard-loss", "silent-data-corruption"]
                }
            },
            "workload": {
                "mode": "s3-mixed",
                "object_count": 12,
                "concurrency": 4,
                "prefill_concurrency": 4,
                "request_timeout_seconds": 30,
                "seed": 42,
                "plan": plan
            },
            "recovery": {
                "timeout_seconds": 300,
                "expected_rustfs_pod_count": 4,
                "stable_pod_window_seconds": 60,
                "recovery_stability_reread_seconds": 60,
                "recommit_unconfirmed_writes": true
            },
            "faults": [{
                "name": "io-eio-00-rustfs_volume_io_error",
                "kind": "rustfs_volume_io_error",
                "backend": "chaos-mesh-io-chaos",
                "target": {"kind": "rustfs-volume", "path": "/data/rustfs0"},
                "target_proof": {"required": true, "artifact": "target-proof.json"},
                "selection": {"kind": "percent", "value": 20},
                "target_proof_requirements": ["run artifacts must include the selected Kubernetes object or host device identity before the fault is activated"],
                "erasure_set_proof_required": true,
                "fault_duration_seconds": 60,
                "observability": "history.jsonl, workload-summary.json, checker-report.json, chaos-manifest.yaml, chaos-describe*.txt, Kubernetes snapshot artifacts",
                "conflict_domain": "fresh Tenant/PVC/PV fixture and run-scoped IOChaos cleanup"
            }],
            "artifacts": {
                "required": FaultRunArtifactSpec::required_names_for_scenario(scenario),
                "event_stream": "run-events.jsonl"
            }
        });
        write_json(&case_dir, "run-spec.json", &run_spec);
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&run_spec).expect("yaml"),
        )
        .expect("write yaml");
        let health_baseline = json!({
            "observedAtMs": 5,
            "deploymentId": "deployment-1",
            "standardParity": 2,
            "totalSets": [1],
            "drivesPerSet": [4],
            "serverEndpoints": ["http://p0:9000", "http://p1:9000", "http://p2:9000", "http://p3:9000"],
            "driveUuids": ["d0", "d1", "d2", "d3"]
        });
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":scenario,"run_id":run_id,"stage":"run","status":"started","message":"started"}).to_string(),
                json!({"at_ms":6,"scenario":scenario,"run_id":run_id,"stage":"recovery-health-baseline","status":"succeeded","message":"healthy RustFS baseline captured","details":health_baseline}).to_string(),
                json!({"at_ms":70,"scenario":scenario,"run_id":run_id,"stage":"recovery-evidence","status":"succeeded","message":"fault-evidence.json persisted"}).to_string(),
                json!({"at_ms":71,"scenario":scenario,"run_id":run_id,"stage":"post-recovery-write","status":"started","message":"probing fresh writes"}).to_string(),
                json!({"at_ms":200,"scenario":scenario,"run_id":run_id,"stage":"post-recovery-write","status":"succeeded","message":"fresh writes succeeded"}).to_string(),
                json!({"at_ms":2,"scenario":scenario,"run_id":run_id,"stage":"checker-final","status":"succeeded","message":"checked"}).to_string(),
                json!({"at_ms":3,"scenario":scenario,"run_id":run_id,"stage":"run","status":"succeeded","message":"done"}).to_string(),
            ].join("\n"),
        ).expect("write events");
        write_json(
            &case_dir,
            "preflight-summary.json",
            &json!({
                "schemaVersion": 1,
                "runId": run_id,
                "status": "passed",
                "scenarioSet": [scenario],
                "checkedAtMs": 1,
                "context": "real-cluster",
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "storageClass": "fast-csi",
                "phases": [{
                    "name": "target-proof",
                    "status": "passed",
                    "checks": [{
                        "name": "target_proof",
                        "status": "passed",
                        "responsibilityDomain": "harness",
                        "message": "target proof artifact describes every planned fault target"
                    }]
                }]
            }),
        );
        write_json(
            &case_dir,
            "target-proof.json",
            &json!({
                "schemaVersion": 2,
                "status": "satisfied",
                "proofLevel": "selector_intent",
                "generatedAtMs": 6,
                "scenario": scenario,
                "caseName": "fault_io_eio_preserves_committed_objects",
                "runId": run_id,
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "resolvedPods": (0..4).map(|index| json!({
                    "name": format!("p{index}"),
                    "uid": format!("u{index}"),
                    "ready": true,
                    "node": format!("node-{index}"),
                    "persistentVolumeClaims": [{
                        "name": format!("data-p{index}"),
                        "volumeName": format!("pv-{index}"),
                        "storageClass": "fast-csi",
                        "persistentVolume": {
                            "name": format!("pv-{index}"),
                            "node": format!("node-{index}"),
                            "deviceOrPath": format!("/mnt/rustfs{index}")
                        }
                    }]
                })).collect::<Vec<_>>(),
                "faults": [{
                    "name": "io-eio-00-rustfs_volume_io_error",
                    "kind": "rustfs_volume_io_error",
                    "backend": "chaos-mesh-io-chaos",
                    "targetKind": "rustfs-volume",
                    "targetSummary": "one RustFS volume at /data/rustfs0",
                    "selection": "20%",
                    "selectionKind": "percent",
                    "selectionValue": 20,
                    "conflictDomain": "fresh Tenant/PVC/PV fixture and run-scoped IOChaos cleanup",
                    "podSelector": {
                        "namespace": "rustfs-fault-test",
                        "tenant": "fault-test-tenant",
                        "selector": "rustfs.tenant=fault-test-tenant",
                        "exactPodsResolved": true,
                        "note": "preflight resolved current RustFS target pods"
                    },
                    "volumePath": "/data/rustfs0",
                    "erasureSet": {
                        "required": true,
                        "resolved": true,
                        "source": "rustfs-admin-server-info",
                        "deploymentId": "deployment-1",
                        "shape": {
                            "poolIndex": 0,
                            "setIndex": 0,
                            "serverCount": 4,
                            "volumesPerServer": 1,
                            "totalShards": 4,
                            "payloadDataShards": 2,
                            "payloadParityShards": 2
                        },
                        "health": {
                            "onlineShards": 4,
                            "offlineShards": 0,
                            "unknownShards": 0
                        },
                        "membership": {
                            "members": (0..4).map(|index| json!({
                                "podName": format!("p{index}"),
                                "serverEndpoint": format!("http://p{index}:9000"),
                                "shardIds": [format!("d{index}")]
                            })).collect::<Vec<_>>()
                        },
                        "observedAtMs": 5,
                        "note": "same-erasure-set topology proven from RustFS admin runtime geometry before fault apply"
                    }
                }],
                "requirements": [
                    {
                        "name": "catalog_target_intent",
                        "status": "passed",
                        "message": "one RustFS container data volume"
                    },
                    {
                        "name": "same_erasure_set_target_proof",
                        "status": "passed",
                        "message": "same-erasure-set topology proven from RustFS admin runtime geometry before fault apply"
                    }
                ]
            }),
        );
        write_json(
            &case_dir,
            "run-metadata.json",
            &json!({
                "scenario": scenario,
                "case_name": "fault_io_eio_preserves_committed_objects",
                "run_id": run_id,
                "bucket": "bucket",
                "backend": "chaos-mesh-io-chaos",
                "target": "rustfs-volume",
                "context": "real-cluster",
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "storage_class": "fast-csi",
                "rustfs_image": "rustfs:test",
                "artifacts_dir": root.display().to_string(),
                "fault_duration_seconds": 60,
                "percent": 20,
                "fault_selection": ["percent=20"],
                "workload_objects": 12,
                "workload_concurrency": 4,
                "prefill_concurrency": 4,
                "request_timeout_seconds": 30,
                "recovery_stability_reread_seconds": 60,
                "min_availability_percent": 99,
                "use_cluster_ip": false,
                "require_client_disruption": false,
                "chaos_namespace": "chaos-mesh"
            }),
        );
        let mut workload_plan = json!(plan);
        workload_plan["scenario"] = json!(scenario);
        workload_plan["run_id"] = json!(run_id);
        write_json(&case_dir, "workload-plan.json", &workload_plan);
        let history_prefix = vec![
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000001",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "put",
                "bucket": "bucket",
                "key": "key",
                "value_sha256": "sha",
                "size_bytes": 1,
                "started_at_ms": 1,
                "ended_at_ms": 2,
                "started_sequence": 1,
                "ended_sequence": 2,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "pre_fault",
                "fault_window_relation": "before_fault"
            }))
            .expect("history PUT"),
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000002",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "put",
                "bucket": "bucket",
                "key": "key",
                "value_sha256": "recommit-sha",
                "size_bytes": 1,
                "started_at_ms": 3,
                "ended_at_ms": 4,
                "started_sequence": 3,
                "ended_sequence": 4,
                "outcome": "timeout",
                "http_status": null,
                "error": "put object timed out",
                "durability_cohort": "fault_active",
                "fault_window_relation": "during_fault"
            }))
            .expect("ambiguous workload PUT"),
        ];
        let pre_checker_suffix = vec![
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000003",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "get",
                "bucket": "bucket",
                "key": "key",
                "value_sha256": "sha",
                "size_bytes": 1,
                "started_at_ms": 11,
                "ended_at_ms": 12,
                "started_sequence": 5,
                "ended_sequence": 6,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "post_recovery",
                "fault_window_relation": "after_fault"
            }))
            .expect("checker GET"),
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000004",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "list",
                "bucket": "bucket",
                "key": format!("fault-test/{run_id}/"),
                "value_sha256": null,
                "size_bytes": 1,
                "listed_keys": ["key"],
                "started_at_ms": 13,
                "ended_at_ms": 14,
                "started_sequence": 7,
                "ended_sequence": 8,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "post_recovery",
                "fault_window_relation": "after_fault"
            }))
            .expect("checker LIST"),
        ];
        let recommit_history = vec![
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000005",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "put",
                "bucket": "bucket",
                "key": "key",
                "value_sha256": "recommit-sha",
                "size_bytes": 1,
                "started_at_ms": 16,
                "ended_at_ms": 17,
                "started_sequence": 9,
                "ended_sequence": 10,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "post_recovery",
                "fault_window_relation": "after_fault"
            }))
            .expect("recommit PUT"),
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000006",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "get",
                "bucket": "bucket",
                "key": "key",
                "value_sha256": "recommit-sha",
                "size_bytes": 1,
                "started_at_ms": 18,
                "ended_at_ms": 19,
                "started_sequence": 11,
                "ended_sequence": 12,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "post_recovery",
                "fault_window_relation": "after_fault"
            }))
            .expect("recommit verification GET"),
        ];
        let final_checker_suffix = vec![
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000007",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "get",
                "bucket": "bucket",
                "key": "key",
                "value_sha256": "recommit-sha",
                "size_bytes": 1,
                "started_at_ms": 21,
                "ended_at_ms": 22,
                "started_sequence": 13,
                "ended_sequence": 14,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "post_recovery",
                "fault_window_relation": "after_fault"
            }))
            .expect("final checker GET"),
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-000008",
                "scenario": scenario,
                "run_id": run_id,
                "kind": "list",
                "bucket": "bucket",
                "key": format!("fault-test/{run_id}/"),
                "value_sha256": null,
                "size_bytes": 1,
                "listed_keys": ["key"],
                "started_at_ms": 23,
                "ended_at_ms": 24,
                "started_sequence": 15,
                "ended_sequence": 16,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "post_recovery",
                "fault_window_relation": "after_fault"
            }))
            .expect("final checker LIST"),
        ];
        let mut history = history_prefix.clone();
        history.extend(pre_checker_suffix.clone());
        history.extend(recommit_history.clone());
        let final_checker_prefix = history.clone();
        history.extend(final_checker_suffix.clone());
        fs::write(
            case_dir.join("history.jsonl"),
            format!(
                "{}\n",
                history
                    .iter()
                    .map(|record| serde_json::to_string(record).expect("history record"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .expect("history");
        write_json(
            &case_dir,
            "workload-summary.json",
            &json!({
                "scenario": scenario,
                "run_id": run_id,
                "seed": 42,
                "object_count": 12,
                "concurrency": 4,
                "total_payload_bytes": 12582912,
                "puts": {"ok": 20, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0},
                "gets": {"ok": 20, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0},
                "deletes": {"ok": 20, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "lists": {"ok": 20, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_completes": {"ok": 20, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_aborts": {"ok": 20, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "recommit_candidates": {
                    "scenario": scenario,
                    "run_id": run_id,
                    "bucket": "bucket",
                    "history_record_count": history_prefix.len(),
                    "history_sha256": checker::checker_history_records_sha256(&history_prefix).expect("candidate history digest"),
                    "candidates": [{
                        "source_operation_id": "op-000002",
                        "key": "key",
                        "size_bytes": 1,
                        "sha256": "recommit-sha"
                    }]
                },
                "recommitted_after_recovery": 1
            }),
        );
        write_json(
            &case_dir,
            AVAILABILITY_REPORT_ARTIFACT,
            &json!({
                "scenario": scenario,
                "run_id": run_id,
                "min_success_percent": 99,
                "served_by_pod": "p1",
                "commit_probe": {"objects": 40, "verified": 40, "failures": []},
                "read_probe": {"objects": 6, "verified": 6, "failures": []},
                "workload": [
                    {"family": "put", "total": 21, "disrupted": 1, "success_percent": 95},
                    {"family": "get", "total": 21, "disrupted": 1, "success_percent": 95},
                    {"family": "delete", "total": 20, "disrupted": 0, "success_percent": 100},
                    {"family": "list", "total": 20, "disrupted": 0, "success_percent": 100},
                    {"family": "multipart_complete", "total": 20, "disrupted": 0, "success_percent": 100},
                    {"family": "multipart_abort", "total": 20, "disrupted": 0, "success_percent": 100}
                ],
                "violations": [],
                "passed": true
            }),
        );
        write_json(
            &case_dir,
            "recommit-report.json",
            &json!({
                "scenario": scenario,
                "run_id": run_id,
                "attempted": 1,
                "committed": 1,
                "failed": 0,
                "harness_errors": 0,
                "attempts": [{"source_operation_id": "op-000002", "key": "key", "size_bytes": 1, "sha256": "recommit-sha", "outcome": "ok", "verify_get_outcome": "ok", "http_status": 200, "error": null, "harness_error": null}]
            }),
        );
        let checker_report = |prefix: &[OperationRecord],
                              suffix: &[OperationRecord],
                              started_at_ms: u64,
                              completed_at_ms: u64,
                              committed_puts: usize| {
            json!({
                "scenario": scenario,
                "run_id": run_id,
                "committed_puts": committed_puts,
                "expected_live_objects": 1,
                "verified_live_objects": 1,
                "missing_committed_objects": [],
                "unavailable_committed_objects": [],
                "unknown_committed_read_failures": [],
                "hash_mismatches": [],
                "successful_corrupted_reads": [],
                "unexpected_visible_deleted_objects": [],
                "unknown_writes_materialized": [],
                "operation_cohorts": if committed_puts == 1 {
                    json!({"pre_fault": 1, "fault_active": 1})
                } else {
                    json!({"pre_fault": 1, "fault_active": 1, "post_recovery": 4})
                },
                "fault_window_relations": if committed_puts == 1 {
                    json!({"before_fault": 1, "during_fault": 1})
                } else {
                    json!({"before_fault": 1, "during_fault": 1, "after_fault": 4})
                },
                "list_history_warning_count": 0,
                "final_list_warning_count": 0,
                "list_history_warnings": [],
                "list_warnings": [],
                "final_listed_objects": 1,
                "audit": {
                    "bucket": "bucket",
                    "started_at_ms": started_at_ms,
                    "completed_at_ms": completed_at_ms,
                    "history_prefix_record_count": prefix.len(),
                    "history_prefix_sha256": checker::checker_history_records_sha256(prefix).expect("checker prefix digest"),
                    "history_suffix_record_count": suffix.len(),
                    "history_suffix_sha256": checker::checker_history_records_sha256(suffix).expect("checker suffix digest"),
                    "suffix_operations": checker::checker_operation_audits(suffix),
                    "data_version_checks": [],
                    "delete_marker_checks": [],
                    "list_object_versions_completed": null
                },
                "tenant_recovered": true,
                "passed": true
            })
        };
        let pre_checker = checker_report(&history_prefix, &pre_checker_suffix, 10, 15, 1);
        let final_checker = checker_report(&final_checker_prefix, &final_checker_suffix, 20, 25, 2);
        write_json(&case_dir, "checker-pre-recommit-report.json", &pre_checker);
        write_json(&case_dir, "checker-report.json", &final_checker);
        write_json(
            &case_dir,
            "fault-evidence.json",
            &json!({
                "scenario": scenario,
                "run_id": run_id,
                "backend": "chaos-mesh-io-chaos",
                "target": "rustfs-volume",
                "injected": true,
                "active_during_workload": true,
                "recovered": true,
                "require_client_disruption": false,
                "client_disruptions": 2,
                "workload_plan": plan,
                "pods_before": (0..4).map(|index| json!({
                    "name": format!("p{index}"),
                    "uid": format!("u{index}")
                })).collect::<Vec<_>>(),
                "pods_after": (0..4).map(|index| json!({
                    "name": format!("p{index}"),
                    "uid": format!("u{index}")
                })).collect::<Vec<_>>(),
                "active_snapshots": [{"stage": "active"}],
                "workload_snapshots": [{"stage": "after-workload"}],
                "dm_recovery_snapshot": null,
                "fault_apply_started_at_ms": 10,
                "fault_active_at_ms": 20,
                "workload_started_at_ms": 30,
                "workload_ended_at_ms": 40,
                "fault_delete_started_at_ms": 50,
                "recovery_started_at_ms": 60,
                "recovery_ended_at_ms": 70
            }),
        );
        write_json(
            &case_dir,
            RECOVERY_HEALTH_ARTIFACT,
            &json!({
                "scenario": scenario,
                "runId": run_id,
                "baseline": health_baseline,
                "startedAtMs": 61,
                "completedAtMs": 69,
                "timeoutSeconds": 300,
                "attempts": 1,
                "firstHealthyAtMs": 68,
                "observation": {
                    "startedAtMs": 61,
                    "completedAtMs": 62,
                    "deploymentId": "deployment-1",
                    "standardParity": 2,
                    "totalSets": [1],
                    "drivesPerSet": [4],
                    "onlineDrives": 4,
                    "offlineDrives": 0,
                    "unknownDrives": 0,
                    "drives": (0..4).map(|index| json!({
                        "serverEndpoint": format!("http://p{index}:9000"),
                        "driveUuid": format!("d{index}"),
                        "state": "ok",
                        "poolIndex": 0,
                        "setIndex": 0
                    })).collect::<Vec<_>>()
                },
                "readiness": (0..4).map(|index| json!({
                    "podName": format!("p{index}"),
                    "proxyPath": format!("/api/v1/namespaces/rustfs-fault-test/pods/p{index}:9000/proxy/health/ready"),
                    "ready": true,
                    "observedAtMs": 65
                })).collect::<Vec<_>>(),
                "violations": [],
                "passed": true
            }),
        );
        write_write_probe_fixture(
            &case_dir,
            scenario,
            run_id,
            &format!("fault-test-post-recovery/{run_id}/"),
            POST_RECOVERY_WRITE_HISTORY_ARTIFACT,
            POST_RECOVERY_WRITE_REPORT_ARTIFACT,
            71,
            200,
            "post_recovery",
            "after_fault",
        );
    }

    /// Write one complete, valid fresh-write probe (8 objects, one multipart
    /// completion, one abort, two LISTs) and its report.
    #[allow(clippy::too_many_arguments)]
    fn write_write_probe_fixture(
        case_dir: &std::path::Path,
        scenario: &str,
        run_id: &str,
        probe_prefix: &str,
        history_artifact: &str,
        report_artifact: &str,
        started_at_ms: u64,
        completed_at_ms: u64,
        cohort: &str,
        relation: &str,
    ) {
        let probe_key = |index: usize| format!("{probe_prefix}object-{index:06}");
        // The complete probe lifecycle in recorder order: PUT+GET per object,
        // multipart complete+GET, multipart abort, live LIST, DELETE+GET 404
        // per object, empty LIST. Sequences form one complete monotonic range.
        let mut probe_history = Vec::<serde_json::Value>::new();
        let mut probe_record = |kind: &str,
                                key: String,
                                sha: Option<&str>,
                                outcome: &str,
                                status: u16,
                                listed: Option<Vec<String>>| {
            let ordinal = probe_history.len() as u64 + 1;
            let mut record = json!({
                "id": format!("op-{ordinal:06}"),
                "scenario": scenario,
                "run_id": run_id,
                "kind": kind,
                "bucket": "bucket",
                "key": key,
                "value_sha256": sha,
                "size_bytes": sha.map(|_| 4096),
                "started_at_ms": started_at_ms + ordinal,
                "ended_at_ms": started_at_ms + ordinal,
                "started_sequence": ordinal * 2 - 1,
                "ended_sequence": ordinal * 2,
                "outcome": outcome,
                "http_status": status,
                "error": null,
                "durability_cohort": cohort,
                "fault_window_relation": relation
            });
            if let Some(listed) = listed {
                record["listed_keys"] = json!(listed);
            }
            probe_history.push(record);
        };
        for index in 0..8 {
            let sha = format!("probe-sha-{index}");
            probe_record("put", probe_key(index), Some(&sha), "ok", 200, None);
            probe_record("get", probe_key(index), Some(&sha), "ok", 200, None);
        }
        probe_record(
            "create_multipart_upload",
            probe_key(8),
            None,
            "ok",
            200,
            None,
        );
        probe_record("upload_part", probe_key(8), None, "ok", 200, None);
        probe_record(
            "complete_multipart_upload",
            probe_key(8),
            Some("probe-multipart-sha"),
            "ok",
            200,
            None,
        );
        probe_record(
            "get",
            probe_key(8),
            Some("probe-multipart-sha"),
            "ok",
            200,
            None,
        );
        probe_record(
            "create_multipart_upload",
            probe_key(9),
            None,
            "ok",
            200,
            None,
        );
        probe_record(
            "abort_multipart_upload",
            probe_key(9),
            None,
            "ok",
            204,
            None,
        );
        probe_record(
            "list",
            probe_prefix.to_string(),
            None,
            "ok",
            200,
            Some((0..9).map(probe_key).collect()),
        );
        for index in 0..9 {
            probe_record("delete", probe_key(index), None, "ok", 204, None);
            probe_record("get", probe_key(index), None, "not_found", 404, None);
        }
        probe_record(
            "list",
            probe_prefix.to_string(),
            None,
            "ok",
            200,
            Some(Vec::new()),
        );
        fs::write(
            case_dir.join(history_artifact),
            format!(
                "{}\n",
                probe_history
                    .iter()
                    .map(serde_json::Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .expect("probe history");
        write_json(
            case_dir,
            report_artifact,
            &json!({
                "scenario": scenario,
                "run_id": run_id,
                "key_prefix": probe_prefix,
                "started_at_ms": started_at_ms,
                "completed_at_ms": completed_at_ms,
                "objects": 8,
                "puts_verified": 8,
                "deletes_verified_absent": 8,
                "multipart_completes_verified": 1,
                "multipart_aborts_ok": 1,
                "lists_verified": 2,
                "failures": [],
                "passed": true
            }),
        );
    }

    #[test]
    fn node_down_hold_artifacts_bind_the_crashed_target_untouched_reads_and_event_order() {
        let dir = tempfile::tempdir().expect("tempdir");
        let case_dir = dir.path().to_path_buf();
        let run_id = "run-00000000-0000-4000-8000-000000000001";
        let scenario = NODE_CRASH_PROXY_SCENARIO;
        let bucket = "bucket";
        let metadata = RunMetadataArtifact {
            scenario: scenario.to_string(),
            run_id: run_id.to_string(),
            context: "real-cluster".to_string(),
            namespace: "rustfs-fault-test".to_string(),
            tenant: "fault-tenant".to_string(),
            storage_class: "rustfs-fault-dm".to_string(),
            rustfs_image: "rustfs:test".to_string(),
            workload_objects: 12,
            workload_concurrency: 4,
            require_client_disruption: false,
            recovery_stability_reread_seconds: 60,
            min_availability_percent: None,
        };
        let host_proof = HostStorageMutationProof::prove_device_mapper(
            HostStorageMutationIntent {
                scenario: scenario.to_string(),
                fault_name: "fault-0".to_string(),
                fault_kind: FaultKind::RustfsBlockDeviceDropWritesCrash
                    .as_str()
                    .to_string(),
                run_id: run_id.to_string(),
                context: "real-cluster".to_string(),
                namespace: "rustfs-fault-test".to_string(),
                tenant: "fault-tenant".to_string(),
                observer_namespace: "rustfs-fault-observers".to_string(),
                observer_pod: "observer-worker-a".to_string(),
                backend_specific_destructive_opt_in: true,
                allowlist: HostStorageAllowlist {
                    nodes: vec!["worker-a".to_string()],
                    devices: vec!["/dev/mapper/rustfs-fault-dm".to_string()],
                    persistent_volumes: vec!["pv-a".to_string()],
                },
                fault_table: None,
            },
            HostStorageTargetObservation {
                node: "worker-a".to_string(),
                node_uid: "node-uid-a".to_string(),
                node_labels: BTreeMap::from([(
                    "kubernetes.io/hostname".to_string(),
                    "storage-host-a".to_string(),
                )]),
                pod: "rustfs-0".to_string(),
                pod_uid: "uid-0".to_string(),
                volume_name: "data".to_string(),
                persistent_volume_claim: "data-rustfs-0".to_string(),
                persistent_volume_claim_uid: "pvc-uid-0".to_string(),
                persistent_volume_claim_phase: "Bound".to_string(),
                persistent_volume: "pv-a".to_string(),
                persistent_volume_uid: "pv-uid-a".to_string(),
                persistent_volume_phase: "Bound".to_string(),
                persistent_volume_claim_ref: HostStoragePersistentVolumeClaimRef {
                    namespace: "rustfs-fault-test".to_string(),
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-0".to_string(),
                },
                node_selector: HostStorageNodeSelector {
                    key: "kubernetes.io/hostname".to_string(),
                    operator: "In".to_string(),
                    values: vec!["storage-host-a".to_string()],
                },
                container_mount_path: "/data/rustfs0".to_string(),
                persistent_volume_path: "/data/rustfs-fault/dm-volume".to_string(),
                mapper_name: "rustfs-fault-dm".to_string(),
                logical_device: "/dev/mapper/rustfs-fault-dm".to_string(),
                canonical_device: "/dev/dm-0".to_string(),
                mount_source: "/dev/mapper/rustfs-fault-dm".to_string(),
                mount_canonical_source: "/dev/dm-0".to_string(),
                filesystem: "ext4".to_string(),
                recovery_table: "0 1024 linear /dev/loop0 0".to_string(),
                observed_at_ms: 151,
            },
        )
        .expect("host proof");
        write_json(&case_dir, HOST_STORAGE_PROOF_ARTIFACT, &json!(host_proof));

        let jsonl = |records: &[Value]| {
            format!(
                "{}\n",
                records
                    .iter()
                    .map(Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            )
        };
        let record =
            |ordinal: u64, kind: &str, key: String, sha: &str, cohort: &str, at_ms: u64| {
                json!({
                    "id": format!("op-{ordinal:06}"),
                    "scenario": scenario,
                    "run_id": run_id,
                    "kind": kind,
                    "bucket": bucket,
                    "key": key,
                    "value_sha256": sha,
                    "size_bytes": 4096,
                    "started_at_ms": at_ms,
                    "ended_at_ms": at_ms,
                    "started_sequence": ordinal * 2 - 1,
                    "ended_sequence": ordinal * 2,
                    "outcome": "ok",
                    "http_status": 200,
                    "error": null,
                    "durability_cohort": cohort
                })
            };
        let key = |index: usize| ObjectSpec::seeded_key(run_id, index);
        // Six prefilled keys; the workload overwrites key 0, so keys 1..=5 are
        // exactly the ones the hold must read.
        let mut history = (0..6)
            .map(|index| {
                record(
                    index as u64 + 1,
                    "put",
                    key(index),
                    &format!("sha-{index}"),
                    "pre_fault",
                    10,
                )
            })
            .collect::<Vec<_>>();
        history.push(record(
            7,
            "put",
            key(0),
            "sha-overwrite",
            "fault_active",
            30,
        ));
        fs::write(case_dir.join("history.jsonl"), jsonl(&history)).expect("history");

        let write_reads_at = |indices: &[usize], sha_override: Option<&str>, first_ms: u64| {
            let reads = indices
                .iter()
                .enumerate()
                .map(|(position, &index)| {
                    record(
                        position as u64 + 1,
                        "get",
                        key(index),
                        &sha_override
                            .map(str::to_string)
                            .unwrap_or_else(|| format!("sha-{index}")),
                        "fault_active",
                        first_ms + position as u64,
                    )
                })
                .collect::<Vec<_>>();
            fs::write(
                case_dir.join(NODE_DOWN_READ_HISTORY_ARTIFACT),
                jsonl(&reads),
            )
            .expect("read history");
        };
        // Probes may only start once the node has been down for the minimum
        // hold (61_000 here).
        let write_reads = |indices: &[usize], sha_override: Option<&str>| {
            write_reads_at(indices, sha_override, 62_000)
        };
        write_reads(&[1, 2, 3, 4, 5], None);

        let samples = (0..=14)
            .map(|step| {
                json!({
                    "at_ms": 1_000 + step * 5_000,
                    "present": true,
                    "uid": "uid-replacement",
                    "node_name": null,
                    "phase": "Pending",
                    "ready": false
                })
            })
            .collect::<Vec<_>>();
        let hold = json!({
            "scenario": scenario,
            "run_id": run_id,
            "target": {"pod": "rustfs-0", "crashed_pod_uid": "uid-0", "node": "worker-a"},
            "served_by_pod": "rustfs-1",
            "min_hold_ms": 60_000,
            "max_sample_gap_ms": 30_000,
            "started_at_ms": 1_000,
            "ended_at_ms": 71_000,
            "samples": samples,
            "read_probe": {"objects": 5, "verified": 5, "failures": []}
        });
        write_json(&case_dir, NODE_DOWN_HOLD_ARTIFACT, &hold);
        let node_down_prefix = format!("fault-test-node-down/{run_id}/");
        write_write_probe_fixture(
            &case_dir,
            scenario,
            run_id,
            &node_down_prefix,
            NODE_DOWN_WRITE_HISTORY_ARTIFACT,
            NODE_DOWN_WRITE_REPORT_ARTIFACT,
            63_000,
            64_000,
            "fault_active",
            "during_fault",
        );
        let event = |at_ms: u64, stage: &str, status: &str| RunEvent {
            at_ms,
            scenario: scenario.to_string(),
            run_id: run_id.to_string(),
            stage: stage.to_string(),
            status: serde_json::from_value(json!(status)).expect("status"),
            message: String::new(),
            details: None,
        };
        let events = vec![
            event(900, "crash-recovery-boundary", "succeeded"),
            event(1_000, "node-down-hold", "started"),
            event(62_900, "node-down-write", "started"),
            event(64_500, "node-down-write", "succeeded"),
            event(71_500, "node-down-hold", "succeeded"),
            event(72_000, "fault-delete", "started"),
        ];
        let artifacts = [
            HOST_STORAGE_PROOF_ARTIFACT,
            "history.jsonl",
            NODE_DOWN_HOLD_ARTIFACT,
            NODE_DOWN_READ_HISTORY_ARTIFACT,
            NODE_DOWN_WRITE_REPORT_ARTIFACT,
            NODE_DOWN_WRITE_HISTORY_ARTIFACT,
        ]
        .into_iter()
        .map(|name| (name.to_string(), case_dir.join(name)))
        .collect::<BTreeMap<_, _>>();
        let validate = |events: &[RunEvent]| {
            validate_node_down_hold_artifacts(
                &artifacts,
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                events,
                bucket,
                12,
            )
        };
        let expect_err = |events: &[RunEvent], expected: &str| {
            let error = validate(events).expect_err(expected);
            assert!(format!("{error:#}").contains(expected), "{error:#}");
        };

        validate(&events).expect("valid node-down hold");

        // Reading the overwritten key instead of an untouched one.
        write_reads(&[0, 1, 2, 3, 4], None);
        expect_err(&events, "is not one successful post-detection read");
        // Skipping one untouched key.
        write_reads(&[1, 2, 3, 4], None);
        expect_err(&events, "holds 4 records for 5 untouched");
        // Bytes that are not the prefill payload.
        write_reads(&[1, 2, 3, 4, 5], Some("sha-other"));
        expect_err(&events, "is not one successful post-detection read");
        // Reads taken before RustFS could have noticed the loss.
        write_reads_at(&[1, 2, 3, 4, 5], None, 1_500);
        expect_err(&events, "is not one successful post-detection read");
        write_reads(&[1, 2, 3, 4, 5], None);

        // The hold names a Pod that is not the crashed host-storage target.
        let mut wrong_target = hold.clone();
        wrong_target["target"]["crashed_pod_uid"] = json!("uid-9");
        write_json(&case_dir, NODE_DOWN_HOLD_ARTIFACT, &wrong_target);
        expect_err(&events, "is not the host-storage-proof.json target");
        write_json(&case_dir, NODE_DOWN_HOLD_ARTIFACT, &hold);

        // Fault removal began before the hold finished.
        let mut early_removal = events.clone();
        early_removal.swap(4, 5);
        expect_err(
            &early_removal,
            "between the crash boundary and fault removal",
        );
        // A failed node-down step next to a later success.
        let mut failed_step = events.clone();
        failed_step.insert(2, event(1_200, "node-down-hold", "failed"));
        expect_err(&failed_step, "records a failed node-down step");

        // The write probe ran inside the hold but before detection.
        write_write_probe_fixture(
            &case_dir,
            scenario,
            run_id,
            &node_down_prefix,
            NODE_DOWN_WRITE_HISTORY_ARTIFACT,
            NODE_DOWN_WRITE_REPORT_ARTIFACT,
            2_000,
            3_000,
            "fault_active",
            "during_fault",
        );
        let mut early_write_events = events.clone();
        early_write_events[2].at_ms = 1_900;
        early_write_events[3].at_ms = 3_500;
        expect_err(
            &early_write_events,
            "ran outside the post-detection part of the node-down hold",
        );

        // The write probe ran before the hold began.
        write_write_probe_fixture(
            &case_dir,
            scenario,
            run_id,
            &node_down_prefix,
            NODE_DOWN_WRITE_HISTORY_ARTIFACT,
            NODE_DOWN_WRITE_REPORT_ARTIFACT,
            500,
            800,
            "fault_active",
            "during_fault",
        );
        expect_err(&events, "started before the node-down hold began");
    }

    #[test]
    fn success_validation_rejects_a_degraded_recovery_health_report() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join(RECOVERY_HEALTH_ARTIFACT);
        let mut report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report")).expect("json");
        // A hand-edited verdict cannot hide a drive that never came back.
        report["observation"]["drives"][2]["state"] = json!("offline");
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &report);

        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("offline drive after recovery");
        assert!(
            error
                .to_string()
                .contains("recovery-health.json did not pass"),
            "{error:#}"
        );

        let mut outside_window = report.clone();
        outside_window["observation"]["drives"][2]["state"] = json!("ok");
        outside_window["completedAtMs"] = json!(71);
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &outside_window);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("observation after recovery ended");
        assert!(error.to_string().contains("recovery window"), "{error:#}");

        let mut unready = outside_window.clone();
        unready["completedAtMs"] = json!(69);
        unready["readiness"][0]["ready"] = json!(false);
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &unready);
        assert!(validate_fault_artifacts(&success_options(dir.path())).is_err());
    }

    #[test]
    fn success_validation_rejects_a_post_recovery_write_probe_that_did_not_complete() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join(POST_RECOVERY_WRITE_REPORT_ARTIFACT);
        let mut report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report")).expect("json");
        report["deletes_verified_absent"] = json!(7);
        write_json(&case_dir, POST_RECOVERY_WRITE_REPORT_ARTIFACT, &report);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("incomplete delete verification");
        assert!(
            error
                .to_string()
                .contains("post-recovery-write-report.json did not pass"),
            "{error:#}"
        );

        report["deletes_verified_absent"] = json!(8);
        report["started_at_ms"] = json!(65);
        write_json(&case_dir, POST_RECOVERY_WRITE_REPORT_ARTIFACT, &report);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("probe before recovery ended");
        assert!(
            error.to_string().contains("started before recovery ended"),
            "{error:#}"
        );

        report["started_at_ms"] = json!(71);
        write_json(&case_dir, POST_RECOVERY_WRITE_REPORT_ARTIFACT, &report);
        let history_path = case_dir.join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT);
        let mut history = fs::read_to_string(&history_path).expect("history");
        history = history.replace(
            "fault-test-post-recovery/run-00000000-0000-4000-8000-000000000001/object-000003",
            "fault-test/run-00000000-0000-4000-8000-000000000001/object-000003",
        );
        fs::write(&history_path, history).expect("rewrite history");
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("probe touched the workload prefix");
        assert!(
            error
                .to_string()
                .contains("outside the post-recovery prefix"),
            "{error:#}"
        );
    }

    #[test]
    fn recovery_health_readiness_must_cover_every_pod_after_recovery() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join(RECOVERY_HEALTH_ARTIFACT);
        let mut report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report")).expect("json");
        report["readiness"][0]["podName"] = json!("px");
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &report);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("readiness for a different Pod");
        assert!(
            error.to_string().contains("readiness probes do not cover"),
            "{error:#}"
        );
    }

    #[test]
    fn post_recovery_probe_history_must_evidence_every_claimed_transition() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        validate_fault_artifacts(&success_options(dir.path())).expect("complete probe history");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let history_path = case_dir.join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT);
        let records = fs::read_to_string(&history_path)
            .expect("history")
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("record"))
            .collect::<Vec<_>>();
        let prefix = "fault-test-post-recovery/run-00000000-0000-4000-8000-000000000001/";
        let position = |kind: &str, key: &str, outcome: &str| {
            records
                .iter()
                .position(|record| {
                    record["kind"] == kind && record["key"] == key && record["outcome"] == outcome
                })
                .expect("fixture record")
        };
        let reject = |mutate: &dyn Fn(&mut Vec<serde_json::Value>), expected: &str| {
            let mut edited = records.clone();
            mutate(&mut edited);
            // Recorder sequences follow file position, so a reordered or
            // appended record keeps the history a complete monotonic range and
            // only the probe-level ordering check can reject it.
            for (index, record) in edited.iter_mut().enumerate() {
                let ordinal = index as u64 + 1;
                record["started_sequence"] = json!(ordinal * 2 - 1);
                record["ended_sequence"] = json!(ordinal * 2);
                record["started_at_ms"] = json!(71 + ordinal);
                record["ended_at_ms"] = json!(71 + ordinal);
            }
            fs::write(
                &history_path,
                format!(
                    "{}\n",
                    edited
                        .iter()
                        .map(serde_json::Value::to_string)
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            )
            .expect("rewrite history");
            let error = validate_fault_artifacts(&success_options(dir.path()))
                .expect_err("edited probe history must not validate");
            assert!(error.to_string().contains(expected), "{error:#}");
        };

        // The report counts a DELETE that history says failed.
        let failed_delete = position("delete", &format!("{prefix}object-000000"), "ok");
        reject(
            &|records| {
                records[failed_delete]["outcome"] = json!("failed");
                records[failed_delete]["http_status"] = json!(503);
            },
            "a passed probe has no failed requests",
        );
        // The verifying GET returned different bytes than the PUT sent.
        let verify_get = position("get", &format!("{prefix}object-000001"), "ok");
        reject(
            &|records| records[verify_get]["value_sha256"] = json!("tampered"),
            "does not read back the acknowledged Put",
        );
        // The multipart completion was never read back with its bytes.
        let multipart_get = position("get", &format!("{prefix}object-000008"), "ok");
        reject(
            &|records| records[multipart_get]["size_bytes"] = json!(1),
            "does not read back the acknowledged CompleteMultipartUpload",
        );
        // The live LIST omitted a probe object.
        let live_list = position("list", prefix, "ok");
        reject(
            &|records| {
                records[live_list]["listed_keys"]
                    .as_array_mut()
                    .expect("listed keys")
                    .pop();
            },
            "does not show exactly the live probe objects",
        );
        // The final LIST still advertised a deleted key.
        let empty_list = records.len() - 1;
        reject(
            &|records| {
                records[empty_list]["listed_keys"] = json!([format!("{prefix}object-000000")]);
            },
            "does not prove the prefix empty",
        );
        // A DELETE the report claims is missing from history entirely.
        let missing_delete = position("delete", &format!("{prefix}object-000002"), "ok");
        reject(
            &|records| records[missing_delete]["kind"] = json!("head"),
            "which the probe never issues",
        );
        // The multipart abort was not evidenced.
        let abort = position(
            "abort_multipart_upload",
            &format!("{prefix}object-000009"),
            "ok",
        );
        reject(
            &|records| {
                records[abort]["kind"] = json!("upload_part");
                records[abort]["key"] = json!(format!("{prefix}object-000008"));
            },
            "exactly one acknowledged AbortMultipartUpload",
        );
        // The post-delete GET did not observe absence.
        let absent_get = position("get", &format!("{prefix}object-000003"), "not_found");
        reject(
            &|records| {
                records[absent_get]["outcome"] = json!("ok");
                records[absent_get]["http_status"] = json!(200);
                records[absent_get]["value_sha256"] = json!("probe-sha-3");
                records[absent_get]["size_bytes"] = json!(4096);
            },
            "does not prove",
        );

        // Ordering tampers: the records stay individually valid but move.
        let move_record = |records: &mut Vec<serde_json::Value>, from: usize, to: usize| {
            let record = records.remove(from);
            records.insert(to, record);
        };
        // A DELETE issued before its verifying GET.
        let delete_zero = position("delete", &format!("{prefix}object-000000"), "ok");
        let verify_zero = position("get", &format!("{prefix}object-000000"), "ok");
        reject(
            &|records| move_record(records, delete_zero, verify_zero),
            "did not follow its verified read",
        );
        // The live LIST taken after the first DELETE.
        reject(
            &|records| move_record(records, live_list, delete_zero),
            "does not show exactly the live probe objects",
        );
        // The empty LIST taken before the last DELETE.
        let delete_last = position("delete", &format!("{prefix}object-000008"), "ok");
        reject(
            &|records| move_record(records, empty_list, delete_last),
            "does not prove the prefix empty",
        );
        // A third GET for one object.
        let mut duplicate_get = records[verify_zero].clone();
        duplicate_get["id"] = json!(format!("op-{:06}", records.len() + 1));
        reject(
            &|records| records.push(duplicate_get.clone()),
            "exactly two GETs",
        );
        // A PUT that recorded no payload hash cannot be read back.
        let put_zero = position("put", &format!("{prefix}object-000000"), "ok");
        reject(
            &|records| records[put_zero]["value_sha256"] = json!(null),
            "records no payload hash",
        );

        // The report's object count is bound to the workload plan.
        fs::write(
            &history_path,
            format!(
                "{}\n",
                records
                    .iter()
                    .map(serde_json::Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .expect("restore history");
        let report_path = case_dir.join(POST_RECOVERY_WRITE_REPORT_ARTIFACT);
        let mut report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&report_path).expect("report")).expect("json");
        report["objects"] = json!(7);
        report["puts_verified"] = json!(7);
        report["deletes_verified_absent"] = json!(7);
        write_json(&case_dir, POST_RECOVERY_WRITE_REPORT_ARTIFACT, &report);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("fewer objects than the plan sizes the probe at");
        assert!(
            error
                .to_string()
                .contains("the workload plan sizes the probe at 8"),
            "{error:#}"
        );
    }

    #[test]
    fn recovery_health_baseline_must_bind_to_the_pre_fault_event_and_its_geometry() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let path = case_dir.join(RECOVERY_HEALTH_ARTIFACT);
        let report: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("report")).expect("json");

        // Baseline and observation agree on three drives while the declared
        // geometry still implies four: the report is internally consistent
        // but describes a cluster that silently lost a drive.
        let mut dropped = report.clone();
        dropped["baseline"]["driveUuids"] = json!(["d0", "d1", "d2"]);
        dropped["baseline"]["serverEndpoints"] =
            json!(["http://p0:9000", "http://p1:9000", "http://p2:9000"]);
        dropped["observation"]["drives"]
            .as_array_mut()
            .expect("drives")
            .pop();
        dropped["observation"]["onlineDrives"] = json!(3);
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &dropped);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("a dropped drive cannot certify recovery");
        assert!(
            format!("{error:#}").contains("lists 3 drives but the erasure layout declares 4"),
            "{error:#}"
        );

        // A consistent report whose baseline is not the one the runner
        // captured before the fault.
        let mut foreign = report.clone();
        foreign["baseline"]["deploymentId"] = json!("deployment-2");
        foreign["observation"]["deploymentId"] = json!("deployment-2");
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &foreign);
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("baseline must match the pre-fault event");
        assert!(
            error
                .to_string()
                .contains("does not match the recovery-health-baseline run event"),
            "{error:#}"
        );

        // The pre-fault event itself is required.
        write_json(&case_dir, RECOVERY_HEALTH_ARTIFACT, &report);
        let events_path = case_dir.join("run-events.jsonl");
        let without_baseline = fs::read_to_string(&events_path)
            .expect("events")
            .lines()
            .filter(|line| !line.contains("recovery-health-baseline"))
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&events_path, without_baseline).expect("rewrite events");
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("missing baseline event");
        assert!(
            error
                .to_string()
                .contains("lacks a successful recovery-health-baseline event"),
            "{error:#}"
        );

        // The event must sit between the baseline observation (5) and fault
        // activation (10); an event stamped outside that window cannot be
        // the capture the runner made before the fault.
        write_success_artifacts(dir.path(), "io-eio");
        let events = fs::read_to_string(&events_path).expect("events");
        for (at_ms, reason) in [
            (4, "before the baseline observation"),
            (11, "after fault apply"),
        ] {
            let stamped = events.replace("\"at_ms\":6,", &format!("\"at_ms\":{at_ms},"));
            assert_ne!(stamped, events, "fixture event must be re-stamped");
            fs::write(&events_path, stamped).expect("rewrite events");
            let error = validate_fault_artifacts(&success_options(dir.path())).expect_err(reason);
            assert!(
                error.to_string().contains(
                    "was not recorded between the baseline observation and fault activation"
                ),
                "{reason}: {error:#}"
            );
        }
    }

    #[test]
    fn post_recovery_write_probe_must_start_after_lifecycle_evidence_is_persisted() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_success_artifacts(dir.path(), "io-eio");
        let case_dir = dir.path().join("fault_io_eio_preserves_committed_objects");
        let events_path = case_dir.join("run-events.jsonl");
        let events = fs::read_to_string(&events_path).expect("events");
        let lines = events.lines().collect::<Vec<_>>();
        let evidence = lines
            .iter()
            .position(|line| line.contains("\"stage\":\"recovery-evidence\""))
            .expect("fixture evidence event");
        let probe = lines
            .iter()
            .position(|line| line.contains("\"stage\":\"post-recovery-write\""))
            .expect("fixture probe event");
        assert!(evidence < probe);

        // The probe started before fault-evidence.json existed: the runner
        // ordering this validator enforces was violated.
        let mut swapped = lines.clone();
        swapped.swap(evidence, probe);
        fs::write(&events_path, swapped.join("\n")).expect("rewrite events");
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("probe started before evidence was persisted");
        assert!(
            error
                .to_string()
                .contains("started before fault-evidence.json was persisted"),
            "{error:#}"
        );

        let without_evidence = lines
            .iter()
            .filter(|line| !line.contains("\"stage\":\"recovery-evidence\""))
            .copied()
            .collect::<Vec<_>>();
        fs::write(&events_path, without_evidence.join("\n")).expect("rewrite events");
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("missing evidence event");
        assert!(
            error
                .to_string()
                .contains("lacks a successful recovery-evidence event"),
            "{error:#}"
        );

        write_success_artifacts(dir.path(), "io-eio");
        let mut events = fs::read_to_string(&events_path).expect("events");
        events.push_str(
            "\n{\"at_ms\":99,\"scenario\":\"io-eio\",\"run_id\":\"run-00000000-0000-4000-8000-000000000001\",\"stage\":\"post-recovery-write\",\"status\":\"failed\",\"message\":\"probe failed\"}\n",
        );
        fs::write(&events_path, events).expect("append failed event");
        let error = validate_fault_artifacts(&success_options(dir.path()))
            .expect_err("failed probe event must override stale passing artifacts");
        assert!(
            error
                .to_string()
                .contains("does not prove one successful post-recovery write probe"),
            "{error:#}"
        );
    }

    #[test]
    fn quorum_edge_read_survival_artifact_must_cover_the_whole_cohort() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_id = "run-00000000-0000-4000-8000-000000000001";
        let scenario = POD_FAILURE_QUORUM_EDGE_SCENARIO;
        let bucket = "bucket";
        let metadata = RunMetadataArtifact {
            scenario: scenario.to_string(),
            run_id: run_id.to_string(),
            context: "real-cluster".to_string(),
            namespace: "rustfs-fault-test".to_string(),
            tenant: "fault-tenant".to_string(),
            storage_class: "fast-csi".to_string(),
            rustfs_image: "rustfs:test".to_string(),
            workload_objects: 12,
            workload_concurrency: 4,
            require_client_disruption: true,
            recovery_stability_reread_seconds: 60,
            min_availability_percent: None,
        };
        let evidence: FaultEvidenceArtifact = serde_json::from_value(json!({
            "scenario": scenario,
            "run_id": run_id,
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": true,
            "client_disruptions": 3,
            "pods_before": [],
            "pods_after": [],
            "active_snapshots": [],
            "workload_snapshots": [],
            "fault_active_at_ms": 100,
            "workload_started_at_ms": 200
        }))
        .expect("evidence");
        let record =
            |id: usize, kind: &str, index: usize, sha: String, cohort: &str, at_ms: u64| {
                let mut record = json!({
                    "id": format!("op-{id:06}"),
                    "scenario": scenario,
                    "run_id": run_id,
                    "kind": kind,
                    "bucket": bucket,
                    "key": ObjectSpec::seeded_key(run_id, index),
                    "value_sha256": sha,
                    "started_at_ms": at_ms,
                    "ended_at_ms": at_ms,
                    "outcome": "ok",
                    "durability_cohort": cohort
                });
                if cohort == "fault_active" {
                    record["fault_window_relation"] = json!("during_fault");
                }
                record
            };
        let prefill = (0..6)
            .map(|index| record(index, "put", index, format!("sha-{index}"), "pre_fault", 10))
            .collect::<Vec<_>>();
        let probe =
            |index: usize, sha: String| record(100 + index, "get", index, sha, "fault_active", 150);
        let validate = |report: serde_json::Value, history: &[serde_json::Value]| {
            write_json(dir.path(), QUORUM_EDGE_READ_SURVIVAL_ARTIFACT, &report);
            fs::write(
                dir.path().join("history.jsonl"),
                history
                    .iter()
                    .map(serde_json::Value::to_string)
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .expect("history");
            validate_quorum_edge_read_survival_artifact(
                &BTreeMap::from([
                    (
                        QUORUM_EDGE_READ_SURVIVAL_ARTIFACT.to_string(),
                        dir.path().join(QUORUM_EDGE_READ_SURVIVAL_ARTIFACT),
                    ),
                    (
                        "history.jsonl".to_string(),
                        dir.path().join("history.jsonl"),
                    ),
                ]),
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &evidence,
                bucket,
                12,
            )
        };
        let report = |objects: usize, verified: usize, failures: &[&str]| {
            json!({
                "scenario": scenario,
                "run_id": run_id,
                "objects": objects,
                "verified": verified,
                "failures": failures
            })
        };
        let complete = prefill
            .iter()
            .cloned()
            .chain((0..6).map(|index| probe(index, format!("sha-{index}"))))
            .collect::<Vec<_>>();

        validate(report(6, 6, &[]), &complete).expect("complete cohort survived");
        // A probe that read only part of the cohort proves nothing about the rest.
        assert!(validate(report(1, 1, &[]), &complete).is_err());
        assert!(validate(report(6, 5, &["k: 503"]), &complete).is_err());
        assert!(validate(report(6, 6, &["k: 503"]), &complete).is_err());
        // An artifact from another run.
        let mut foreign = report(6, 6, &[]);
        foreign["run_id"] = json!("run-00000000-0000-4000-8000-000000000002");
        assert!(validate(foreign, &complete).is_err());
        // Passing counters that this run's history does not back.
        assert!(
            validate(report(6, 6, &[]), &prefill).is_err(),
            "no probe reads"
        );
        let mut wrong_bytes = complete.clone();
        wrong_bytes[8]["value_sha256"] = json!("sha-other");
        assert!(validate(report(6, 6, &[]), &wrong_bytes).is_err());
        let mut after_workload_start = complete.clone();
        after_workload_start[9]["started_at_ms"] = json!(250);
        after_workload_start[9]["ended_at_ms"] = json!(250);
        assert!(validate(report(6, 6, &[]), &after_workload_start).is_err());
        let mut duplicated = complete.clone();
        duplicated.push(probe(0, "sha-0".to_string()));
        duplicated.last_mut().expect("record")["id"] = json!("op-000999");
        assert!(validate(report(6, 6, &[]), &duplicated).is_err());
        assert!(
            validate_quorum_edge_read_survival_artifact(
                &BTreeMap::new(),
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &evidence,
                bucket,
                12,
            )
            .is_err(),
            "a missing artifact must fail closed"
        );
    }

    #[test]
    fn write_quorum_loss_history_covers_every_write_breaking_boundary() {
        for scenario in [
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
            POD_FAILURE_QUORUM_EDGE_SCENARIO,
            QUORUM_P_IO_FAULT_SCENARIO,
            QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
        ] {
            assert!(requires_write_quorum_loss_history(scenario), "{scenario}");
        }
        for scenario in [POD_FAILURE_SCENARIO, IO_EIO_SCENARIO, POD_KILL_ONE_SCENARIO] {
            assert!(!requires_write_quorum_loss_history(scenario), "{scenario}");
        }
    }

    #[test]
    fn availability_artifact_must_bind_to_the_cohort_and_workload_disruptions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let run_id = "run-00000000-0000-4000-8000-000000000001";
        let metadata = RunMetadataArtifact {
            scenario: "pod-failure".to_string(),
            run_id: run_id.to_string(),
            context: "real-cluster".to_string(),
            namespace: "fault-ns".to_string(),
            tenant: "fault-tenant".to_string(),
            storage_class: "fast-csi".to_string(),
            rustfs_image: "rustfs:test".to_string(),
            workload_objects: 12,
            workload_concurrency: 4,
            require_client_disruption: false,
            recovery_stability_reread_seconds: 60,
            min_availability_percent: Some(99),
        };
        let evidence: FaultEvidenceArtifact = serde_json::from_value(json!({
            "scenario": "pod-failure",
            "run_id": run_id,
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": false,
            "client_disruptions": 3,
            "pods_before": [],
            "pods_after": [],
            "active_snapshots": [],
            "workload_snapshots": []
        }))
        .expect("evidence");
        let counts = |ok: usize, failed: usize| json!({"ok": ok, "not_found": 0, "failed": failed, "timeout": 0, "unknown": 0});
        let summary_with = |put: (usize, usize), get: (usize, usize), delete: (usize, usize)| {
            serde_json::from_value::<WorkloadSummaryArtifact>(json!({
                "scenario": "pod-failure",
                "run_id": run_id,
                "seed": 42,
                "object_count": 12,
                "concurrency": 4,
                "recommitted_after_recovery": 0,
                "puts": counts(put.0, put.1),
                "gets": counts(get.0, get.1),
                "deletes": counts(delete.0, delete.1),
                "lists": counts(100, 0),
                "multipart_completes": counts(100, 0),
                "multipart_aborts": counts(100, 0)
            }))
            .expect("workload summary")
        };
        let summary = summary_with((199, 1), (199, 1), (99, 1));
        let family = |name: &str, total: usize, disrupted: usize| {
            json!({
                "family": name,
                "total": total,
                "disrupted": disrupted,
                "success_percent": (total - disrupted) * 100 / total
            })
        };
        let mut report = json!({
            "scenario": "pod-failure",
            "run_id": run_id,
            "min_success_percent": 99,
            "commit_probe": {"objects": 299, "verified": 299, "failures": []},
            "read_probe": {"objects": 6, "verified": 6, "failures": []},
            "workload": [
                family("put", 200, 1),
                family("get", 200, 1),
                family("delete", 100, 1),
                family("list", 100, 0),
                family("multipart_complete", 100, 0),
                family("multipart_abort", 100, 0)
            ],
            "violations": [],
            "passed": true
        });
        let write = |report: &serde_json::Value| {
            write_json(dir.path(), AVAILABILITY_REPORT_ARTIFACT, report);
            BTreeMap::from([(
                AVAILABILITY_REPORT_ARTIFACT.to_string(),
                dir.path().join(AVAILABILITY_REPORT_ARTIFACT),
            )])
        };
        let validate = |report: &serde_json::Value,
                        metadata: &RunMetadataArtifact,
                        summary: &WorkloadSummaryArtifact| {
            validate_availability_artifact(
                &write(report),
                metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &evidence,
                summary,
                12,
                99,
            )
        };

        validate(&report, &metadata, &summary).expect("consistent availability report");

        report["commit_probe"]["verified"] = json!(298);
        let error = validate(&report, &metadata, &summary)
            .expect_err("every acknowledged commit needs immediate verification");
        assert!(
            error
                .to_string()
                .contains("commit probe verified 298 of 299")
        );
        report["commit_probe"]["verified"] = json!(299);

        // A family whose counts match but whose stated percentage does not
        // is not the report the runtime would have written.
        report["workload"][0]["success_percent"] = json!(100);
        let error = validate(&report, &metadata, &summary).expect_err("wrong success percentage");
        assert!(
            error
                .to_string()
                .contains("does not match workload-summary.json put"),
            "{error:#}"
        );
        report["workload"][0]["success_percent"] = json!(99);

        // A run cannot validate against a floor below the catalog's, even
        // when its own metadata agrees with the report.
        let mut lowered_metadata = RunMetadataArtifact {
            scenario: "pod-failure".to_string(),
            run_id: run_id.to_string(),
            context: "real-cluster".to_string(),
            namespace: "fault-ns".to_string(),
            tenant: "fault-tenant".to_string(),
            storage_class: "fast-csi".to_string(),
            rustfs_image: "rustfs:test".to_string(),
            workload_objects: 12,
            workload_concurrency: 4,
            require_client_disruption: false,
            recovery_stability_reread_seconds: 60,
            min_availability_percent: Some(98),
        };
        report["min_success_percent"] = json!(98);
        let error = validate(&report, &lowered_metadata, &summary)
            .expect_err("floor below the catalog floor");
        assert!(
            error
                .to_string()
                .contains("is below the catalog availability floor 99"),
            "{error:#}"
        );
        // Tightening the floor is allowed and re-derived per family.
        lowered_metadata.min_availability_percent = Some(100);
        report["min_success_percent"] = json!(100);
        let error = validate(&report, &lowered_metadata, &summary)
            .expect_err("a 100% floor tolerates no disruption");
        assert!(error.to_string().contains("did not pass"), "{error:#}");
        report["min_success_percent"] = json!(99);

        report["read_probe"]["objects"] = json!(5);
        report["read_probe"]["verified"] = json!(5);
        let error = validate(&report, &metadata, &summary)
            .expect_err("probe smaller than the prefilled cohort");
        assert!(
            error.to_string().contains("complete prefilled cohort"),
            "{error:#}"
        );

        report["read_probe"]["objects"] = json!(6);
        report["read_probe"]["verified"] = json!(6);
        report["workload"][2] = family("delete", 100, 0);
        let error = validate(&report, &metadata, &summary)
            .expect_err("family drift from workload-summary.json");
        assert!(
            error
                .to_string()
                .contains("does not match workload-summary.json delete"),
            "{error:#}"
        );

        report["workload"][2] = family("delete", 100, 1);
        report["workload"][0] = family("put", 100, 2);
        report["workload"][1] = family("get", 200, 0);
        let error = validate(&report, &metadata, &summary)
            .expect_err("a family below the floor cannot pass");
        assert!(error.to_string().contains("did not pass"), "{error:#}");

        // Two failures moved from a 50-operation PUT family (where they break
        // the 99% floor) into a 1000-operation GET family (where they pass)
        // keep the total at 3 but no longer describe the workload that ran.
        let shifted_summary = summary_with((48, 2), (999, 1), (100, 0));
        report["commit_probe"]["objects"] = json!(148);
        report["commit_probe"]["verified"] = json!(148);
        report["workload"][0] = family("put", 50, 0);
        report["workload"][1] = family("get", 1000, 3);
        report["workload"][2] = family("delete", 100, 0);
        let error = validate(&report, &metadata, &shifted_summary)
            .expect_err("disruptions shifted between families");
        assert!(
            error
                .to_string()
                .contains("does not match workload-summary.json put"),
            "{error:#}"
        );
        report["workload"][0] = family("put", 50, 2);
        report["workload"][1] = family("get", 1000, 1);
        let error = validate(&report, &metadata, &shifted_summary)
            .expect_err("the honest per-family numbers fail the floor");
        assert!(error.to_string().contains("did not pass"), "{error:#}");

        // The floor itself is bound to run-metadata.json.
        report["workload"][0] = family("put", 200, 1);
        report["workload"][1] = family("get", 200, 1);
        report["workload"][2] = family("delete", 100, 1);
        report["commit_probe"]["objects"] = json!(299);
        report["commit_probe"]["verified"] = json!(299);
        report["min_success_percent"] = json!(90);
        let error =
            validate(&report, &metadata, &summary).expect_err("laxer floor than configured");
        assert!(
            error
                .to_string()
                .contains("does not match run-metadata.json min_availability_percent 99"),
            "{error:#}"
        );
        report["min_success_percent"] = json!(99);
        let mut legacy_metadata = metadata;
        legacy_metadata.min_availability_percent = None;
        let error = validate(&report, &legacy_metadata, &summary)
            .expect_err("availability scenarios require the persisted floor");
        assert!(
            error
                .to_string()
                .contains("min_availability_percent is required"),
            "{error:#}"
        );
    }

    #[test]
    fn required_artifacts_include_recovery_evidence_for_every_scenario_family() {
        let plain = FaultRunArtifactSpec::required_names_for_scenario("io-eio");
        let ack = FaultRunArtifactSpec::required_names_for_scenario("dm-drop-writes-after-ack-put");
        let availability = FaultRunArtifactSpec::required_names_for_scenario("pod-failure");
        for names in [&plain, &ack, &availability] {
            for artifact in [
                RECOVERY_HEALTH_ARTIFACT,
                POST_RECOVERY_WRITE_REPORT_ARTIFACT,
                POST_RECOVERY_WRITE_HISTORY_ARTIFACT,
            ] {
                assert!(names.iter().any(|name| name == artifact), "{artifact}");
            }
        }
        assert!(
            availability
                .iter()
                .any(|name| name == "availability-report.json")
        );
        assert!(plain.iter().any(|name| name == "availability-report.json"));
        assert!(!ack.iter().any(|name| name == "availability-report.json"));
    }

    fn lifecycle_run_spec(
        scenario_name: &str,
    ) -> (FaultTestConfig, crate::fault::spec::FaultRunSpec) {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = scenario_name.to_string();
        config.workload = crate::fault::config::FaultWorkloadProfile::new(12, 4).expect("workload");
        let scenario =
            crate::fault::scenarios::FaultScenario::from_config(&config).expect("scenario");
        let spec = crate::fault::scenarios::scenario_spec(scenario_name).expect("spec");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            spec,
            FaultPlanOptions::from_config(&config),
        )
        .expect("plan");
        let workload_plan = crate::fault::workload::WorkloadPlan::seeded(42, 12, 4);
        let run_spec = crate::fault::spec::FaultRunSpec::resolved(
            &config,
            &scenario,
            spec,
            &plan,
            &workload_plan,
            "run-lifecycle",
            "bucket",
        );
        (config, run_spec)
    }

    fn lifecycle_options(root: &std::path::Path, scenario: &str) -> ArtifactValidationOptions {
        ArtifactValidationOptions {
            scenario: scenario.to_string(),
            ..success_options(root)
        }
    }

    fn statefulset_proof(pods: &[(&str, &str)]) -> crate::fault::preflight::TargetStatefulSetProof {
        crate::fault::preflight::TargetStatefulSetProof {
            name: "fault-test-tenant-primary".to_string(),
            uid: "sts-uid".to_string(),
            namespace: "rustfs-fault-test".to_string(),
            replicas: u32::try_from(pods.len()).expect("replicas"),
            pod_management_policy: Some("Parallel".to_string()),
            update_strategy: Some("RollingUpdate".to_string()),
            pvc_retention_when_scaled: Some("Retain".to_string()),
            pvc_retention_when_deleted: Some("Retain".to_string()),
            termination_grace_period_seconds: 30,
            current_revision: Some("rev".to_string()),
            update_revision: Some("rev".to_string()),
            owned_pods: pods
                .iter()
                .enumerate()
                .map(
                    |(ordinal, (name, uid))| crate::fault::preflight::TargetStatefulSetPodProof {
                        name: (*name).to_string(),
                        uid: (*uid).to_string(),
                        ordinal: u32::try_from(ordinal).expect("ordinal"),
                        restart_count: 0,
                    },
                )
                .collect(),
            observed_at_ms: 5,
        }
    }

    #[test]
    fn lifecycle_target_proof_requires_the_live_statefulset_ownership_proof() {
        let (config, run_spec) = lifecycle_run_spec("pod-graceful-restart-one");
        let dir = tempfile::tempdir().expect("tempdir");
        let options = lifecycle_options(dir.path(), "pod-graceful-restart-one");
        let scenario =
            crate::fault::scenarios::FaultScenario::from_config(&config).expect("scenario");
        let spec =
            crate::fault::scenarios::scenario_spec("pod-graceful-restart-one").expect("spec");
        let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");
        let pods: Vec<(&str, &str)> = vec![
            ("fault-test-tenant-primary-0", "u0"),
            ("fault-test-tenant-primary-1", "u1"),
            ("fault-test-tenant-primary-2", "u2"),
            ("fault-test-tenant-primary-3", "u3"),
        ];
        let resolved = pods.iter().map(|(name, uid)| {
            TargetResolvedPodProof::new(*name, *uid)
                .with_node("node-a")
                .with_ready(true)
        });
        let pending = crate::fault::preflight::TargetProof::from_plan(
            &config,
            &scenario,
            spec,
            &plan,
            "run-lifecycle",
        )
        .with_resolved_pod_proofs(resolved);
        assert_eq!(
            pending.status,
            crate::fault::preflight::TargetProofStatus::Missing,
            "ownership is pending until the live observation binds it"
        );
        assert!(validate_target_proof(&pending, &run_spec, &options).is_err());

        let proven = pending
            .clone()
            .with_statefulset_proven(statefulset_proof(&pods))
            .expect("bound");
        assert_eq!(
            proven.status,
            crate::fault::preflight::TargetProofStatus::Satisfied
        );
        validate_target_proof(&proven, &run_spec, &options).expect("lifecycle target proof");

        // A StatefulSet that does not own the resolved Pods cannot bind.
        let mut foreign = pods.clone();
        foreign[3] = ("fault-test-tenant-primary-3", "other");
        assert!(
            pending
                .clone()
                .with_statefulset_proven(statefulset_proof(&foreign))
                .is_err()
        );
        assert!(
            pending
                .clone()
                .with_statefulset_proven(statefulset_proof(&pods[..3]))
                .is_err()
        );

        // Hand-edited evidence: a passed requirement without the proof, or a
        // replica count that disagrees with the expected Pod count.
        let mut forged = pending.clone();
        for requirement in &mut forged.requirements {
            requirement.status = crate::fault::preflight::PreflightStatus::Passed;
        }
        forged.status = crate::fault::preflight::TargetProofStatus::Satisfied;
        let error =
            validate_target_proof(&forged, &run_spec, &options).expect_err("no StatefulSet proof");
        assert!(
            error.to_string().contains("StatefulSet evidence"),
            "{error:#}"
        );
        let mut short = proven.clone();
        short.faults[0].statefulset.as_mut().unwrap().replicas = 3;
        let error = validate_target_proof(&short, &run_spec, &options).expect_err("short replicas");
        assert!(
            error.to_string().contains("do not match the expected 4"),
            "{error:#}"
        );
        let mut elsewhere = proven.clone();
        elsewhere.faults[0].statefulset.as_mut().unwrap().namespace = "other".to_string();
        let error = validate_target_proof(&elsewhere, &run_spec, &options).expect_err("namespace");
        assert!(
            error.to_string().contains("identity is incomplete"),
            "{error:#}"
        );
        let mut unproven = proven.clone();
        for requirement in &mut unproven.requirements {
            if requirement.name == crate::fault::preflight::STATEFULSET_OWNERSHIP_REQUIREMENT {
                requirement.status = crate::fault::preflight::PreflightStatus::Failed;
            }
        }
        let error =
            validate_target_proof(&unproven, &run_spec, &options).expect_err("failed requirement");
        assert!(
            error.to_string().contains("failed target requirements"),
            "{error:#}"
        );
        let mut pending_requirement = proven.clone();
        pending_requirement.requirements.retain(|requirement| {
            requirement.name != crate::fault::preflight::STATEFULSET_OWNERSHIP_REQUIREMENT
        });
        let error = validate_target_proof(&pending_requirement, &run_spec, &options)
            .expect_err("requirement removed");
        assert!(
            error
                .to_string()
                .contains("lacks the passed StatefulSet ownership requirement"),
            "{error:#}"
        );
    }

    fn lifecycle_evidence_json(
        run_id: &str,
        scenario: &str,
        operation: &str,
        targets: Vec<serde_json::Value>,
    ) -> serde_json::Value {
        json!({
            "scenario": scenario,
            "runId": run_id,
            "operation": operation,
            "statefulset": {
                "name": "fault-test-tenant-primary",
                "uid": "sts-uid",
                "namespace": "rustfs-fault-test",
                "replicas": 4,
                "podManagementPolicy": "Parallel",
                "pvcRetentionWhenScaled": "Retain",
                "terminationGracePeriodSeconds": 30,
                "currentRevision": "rev",
                "updateRevision": "rev"
            },
            "statefulsetUidAfter": "sts-uid",
            "targets": targets,
            "loadStartedAtMs": 23,
            "recoveryRecheckedAtMs": 50_100,
            "startedAtMs": 10,
            "completedAtMs": 60_000,
            "violations": [],
            "passed": true
        })
    }

    fn lifecycle_target_json(
        name: &str,
        ordinal: u32,
        old_uid: &str,
        new_uid: &str,
        deferred: bool,
    ) -> serde_json::Value {
        let sigterm =
            crate::fault::backends::lifecycle::evidence::parse_rfc3339_ms("2026-09-11T10:05:00Z")
                .unwrap();
        let delete_requested = if deferred { 40_500 } else { 25 };
        json!({
            "podName": name,
            "ordinal": ordinal,
            "oldUid": old_uid,
            "restartCountBefore": 0,
            "terminationGracePeriodSeconds": 30,
            "deleteRequestedAtMs": delete_requested,
            "deletionTimestamp": "2026-09-11T10:05:30Z",
            "deletionGracePeriodSeconds": 30,
            "sigtermRequestedAtMs": sigterm,
            "terminated": {"exitCode": 0, "reason": "Completed", "finishedAt": "2026-09-11T10:05:06Z"},
            "observationSource": "watch",
            "terminationDurationMs": 6_000,
            "oldUidGoneAtMs": delete_requested + 100,
            "newUid": new_uid,
            "finalUid": new_uid,
            "oldRevision": "rev",
            "replacementRevision": "rev",
            "restartCountAfter": 0,
            "replacementReadyAtMs": delete_requested + 5_000,
            "classification": "graceful_exit",
            "restartedAfterWorkload": deferred
        })
    }

    /// Fault-phase `history.jsonl` requests starting at the given times.
    fn lifecycle_history(started: &[u64]) -> Vec<OperationRecord> {
        started
            .iter()
            .enumerate()
            .map(|(index, started_at_ms)| OperationRecord {
                id: format!("get-{index}"),
                scenario: "rolling-restart-all".to_string(),
                run_id: None,
                kind: OperationKind::Get,
                bucket: "bucket".to_string(),
                key: Some(format!("key-{index}")),
                value_sha256: None,
                size_bytes: None,
                version_id: None,
                listed_keys: None,
                listed_versions: None,
                payload_ref: None,
                range: None,
                started_sequence: None,
                ended_sequence: None,
                started_at_ms: *started_at_ms,
                ended_at_ms: started_at_ms + 5,
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                durability_cohort: None,
                fault_window_relation: None,
            })
            .collect()
    }

    fn lifecycle_inputs<'a>(
        history: &'a [OperationRecord],
        proof: Option<&'a crate::fault::preflight::TargetStatefulSetProof>,
        requires_availability: bool,
    ) -> super::LifecycleValidationInputs<'a> {
        super::LifecycleValidationInputs {
            history,
            statefulset_proof: proof,
            requires_availability,
        }
    }

    fn lifecycle_fault_evidence(
        run_id: &str,
        scenario: &str,
        target_pods: &[&str],
        before: &[(&str, &str)],
        after: &[(&str, &str)],
    ) -> FaultEvidenceArtifact {
        let identities = |pods: &[(&str, &str)]| {
            pods.iter()
                .map(|(name, uid)| json!({"name": name, "uid": uid}))
                .collect::<Vec<_>>()
        };
        // Serialize the real snapshot type so the fixture cannot drift from
        // what a live run writes (camelCase payload under a snake_case field).
        let active_snapshot = serde_json::to_value(crate::fault::reporting::FaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: Some("statefulset".to_string()),
            resource_name: Some("fault-test-tenant-primary".to_string()),
            chaos_status: None,
            dm_status: None,
            lifecycle_status: Some(
                crate::fault::backends::lifecycle::evidence::LifecycleStatusSnapshot {
                    operation:
                        crate::fault::backends::lifecycle::evidence::LifecycleOperation::Rolling,
                    statefulset_name: "fault-test-tenant-primary".to_string(),
                    statefulset_uid: "sts-uid".to_string(),
                    spec_replicas: 4,
                    ready_replicas: 3,
                    target_pods: target_pods.iter().map(|pod| (*pod).to_string()).collect(),
                    pods: Vec::new(),
                    observed_at_ms: 21,
                },
            ),
        })
        .expect("snapshot json");
        assert!(
            active_snapshot
                .pointer("/lifecycle_status/targetPods")
                .is_some(),
            "live snapshots serialize target_pods as targetPods: {active_snapshot}"
        );
        serde_json::from_value(json!({
            "scenario": scenario,
            "run_id": run_id,
            "injected": true,
            "active_during_workload": true,
            "recovered": true,
            "require_client_disruption": false,
            "client_disruptions": 0,
            "pods_before": identities(before),
            "pods_after": identities(after),
            "active_snapshots": [active_snapshot],
            "workload_snapshots": [{"stage": "after-workload"}],
            "fault_apply_started_at_ms": 10,
            "fault_active_at_ms": 20,
            "workload_started_at_ms": 30,
            "workload_ended_at_ms": 40_000,
            "fault_delete_started_at_ms": 40_100,
            "recovery_started_at_ms": 40_200,
            "recovery_ended_at_ms": 50_000
        }))
        .expect("evidence")
    }

    #[test]
    fn lifecycle_artifact_validation_binds_targets_to_the_run_and_fails_closed() {
        let run_id = "run-lifecycle";
        let scenario = "rolling-restart-all";
        let (_, run_spec) = lifecycle_run_spec(scenario);
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = RunMetadataArtifact {
            scenario: scenario.to_string(),
            run_id: run_id.to_string(),
            context: "real-cluster".to_string(),
            namespace: "fault-ns".to_string(),
            tenant: "fault-tenant".to_string(),
            storage_class: "fast-csi".to_string(),
            rustfs_image: "rustfs:test".to_string(),
            workload_objects: 12,
            workload_concurrency: 4,
            require_client_disruption: false,
            recovery_stability_reread_seconds: 60,
            min_availability_percent: Some(99),
        };
        let before = [
            ("p-0", "old-0"),
            ("p-1", "old-1"),
            ("p-2", "old-2"),
            ("p-3", "old-3"),
        ];
        let after = [
            ("p-0", "new-0"),
            ("p-1", "new-1"),
            ("p-2", "new-2"),
            ("p-3", "new-3"),
        ];
        let history = lifecycle_history(&[22]);
        let proof = statefulset_proof(&before);
        let report = lifecycle_evidence_json(
            run_id,
            scenario,
            "rolling-restart",
            vec![
                lifecycle_target_json("p-3", 3, "old-3", "new-3", false),
                lifecycle_target_json("p-2", 2, "old-2", "new-2", false),
                lifecycle_target_json("p-1", 1, "old-1", "new-1", false),
                lifecycle_target_json("p-0", 0, "old-0", "new-0", true),
            ],
        );
        let availability = json!({
            "scenario": scenario,
            "run_id": run_id,
            "min_success_percent": 99,
            "served_by_pod": "p-0",
            "commit_probe": {"objects": 0, "verified": 0, "failures": []},
            "read_probe": {"objects": 6, "verified": 6, "failures": []},
            "workload": [],
            "violations": [],
            "passed": true
        });
        let write = |report: &serde_json::Value, availability: &serde_json::Value| {
            write_json(dir.path(), POD_LIFECYCLE_EVIDENCE_ARTIFACT, report);
            write_json(dir.path(), AVAILABILITY_REPORT_ARTIFACT, availability);
            BTreeMap::from([
                (
                    POD_LIFECYCLE_EVIDENCE_ARTIFACT.to_string(),
                    dir.path().join(POD_LIFECYCLE_EVIDENCE_ARTIFACT),
                ),
                (
                    AVAILABILITY_REPORT_ARTIFACT.to_string(),
                    dir.path().join(AVAILABILITY_REPORT_ARTIFACT),
                ),
            ])
        };
        let evidence =
            lifecycle_fault_evidence(run_id, scenario, &["p-3", "p-2", "p-1"], &before, &after);
        validate_pod_lifecycle_artifact(
            &write(&report, &availability),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &evidence,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), true),
        )
        .expect("consistent rolling restart evidence");

        // The active snapshot must name exactly the under-workload targets.
        let drifted = lifecycle_fault_evidence(run_id, scenario, &["p-3", "p-2"], &before, &after);
        let error = validate_pod_lifecycle_artifact(
            &write(&report, &availability),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &drifted,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), true),
        )
        .expect_err("snapshot target drift");
        assert!(
            error.to_string().contains("under-workload targets"),
            "{error:#}"
        );

        // A Pod that was SIGKILLed at grace expiry cannot pass even with passed=true.
        let mut killed = report.clone();
        killed["targets"][0]["terminated"] =
            json!({"exitCode": 137, "reason": "Error", "finishedAt": "2026-09-11T10:05:30Z"});
        let error = validate_pod_lifecycle_artifact(
            &write(&killed, &availability),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &evidence,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), true),
        )
        .expect_err("grace timeout");
        assert!(error.to_string().contains("does not follow"), "{error:#}");

        // The deferred Pod must be the one that served the availability endpoint.
        let mut other_served = availability.clone();
        other_served["served_by_pod"] = json!("p-1");
        assert!(
            validate_pod_lifecycle_artifact(
                &write(&report, &other_served),
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &evidence,
                &run_spec,
                lifecycle_inputs(&history, Some(&proof), true),
            )
            .is_err()
        );

        // Recovered Pod identities must match the recorded replacements.
        let mut stale_after = after;
        stale_after[2] = ("p-2", "old-2");
        let stale = lifecycle_fault_evidence(
            run_id,
            scenario,
            &["p-3", "p-2", "p-1"],
            &before,
            &stale_after,
        );
        assert!(
            validate_pod_lifecycle_artifact(
                &write(&report, &availability),
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &stale,
                &run_spec,
                lifecycle_inputs(&history, Some(&proof), true),
            )
            .is_err()
        );

        // The first delete must follow the first fault-phase S3 request.
        let validate_with =
            |report: &serde_json::Value,
             history: &[OperationRecord],
             proof: Option<&crate::fault::preflight::TargetStatefulSetProof>| {
                validate_pod_lifecycle_artifact(
                    &write(report, &availability),
                    &metadata,
                    ArtifactIdentityPolicy::LegacyCompatible,
                    &evidence,
                    &run_spec,
                    lifecycle_inputs(history, proof, true),
                )
            };
        for (history, why) in [
            (lifecycle_history(&[30]), "request after the delete"),
            (
                lifecycle_history(&[5]),
                "request before the fault was active",
            ),
            (Vec::new(), "no request at all"),
        ] {
            let error = validate_with(&report, &history, Some(&proof)).expect_err(why);
            assert!(
                error
                    .to_string()
                    .contains("SIGTERM did not land under load"),
                "{why}: {error:#}"
            );
        }
        let mut late_load = report.clone();
        late_load["loadStartedAtMs"] = json!(30);
        assert!(validate_with(&late_load, &history, Some(&proof)).is_err());

        // The StatefulSet and its revision must be the ones target-proof.json proved.
        let mut other_revision = proof.clone();
        other_revision.current_revision = Some("rev-2".to_string());
        other_revision.update_revision = Some("rev-2".to_string());
        let error =
            validate_with(&report, &history, Some(&other_revision)).expect_err("revision drift");
        assert!(
            error.to_string().contains("proven in target-proof.json"),
            "{error:#}"
        );
        let mut unconverged = proof.clone();
        unconverged.current_revision = Some("rev-0".to_string());
        let error =
            validate_with(&report, &history, Some(&unconverged)).expect_err("pending rollout");
        assert!(error.to_string().contains("converged"), "{error:#}");
        let mut other_uid = proof.clone();
        other_uid.uid = "other-sts".to_string();
        assert!(validate_with(&report, &history, Some(&other_uid)).is_err());
        let error = validate_with(&report, &history, None).expect_err("no StatefulSet proof");
        assert!(
            error.to_string().contains("no StatefulSet proof"),
            "{error:#}"
        );
        let mut new_revision = report.clone();
        new_revision["targets"][1]["replacementRevision"] = json!("rev-9");
        assert!(validate_with(&new_revision, &history, Some(&proof)).is_err());

        // Replacements must be re-read after recovery and still be the first replacement.
        let mut unchecked = report.clone();
        unchecked
            .as_object_mut()
            .expect("report object")
            .remove("recoveryRecheckedAtMs");
        let error =
            validate_with(&unchecked, &history, Some(&proof)).expect_err("no recovery recheck");
        assert!(error.to_string().contains("recovery gate"), "{error:#}");
        let mut replaced = report.clone();
        replaced["targets"][0]["finalUid"] = json!("newer-3");
        assert!(validate_with(&replaced, &history, Some(&proof)).is_err());
        let mut crashed = report.clone();
        crashed["targets"][0]["restartCountAfter"] = json!(1);
        assert!(validate_with(&crashed, &history, Some(&proof)).is_err());

        // Missing artifact fails closed.
        assert!(
            validate_pod_lifecycle_artifact(
                &BTreeMap::new(),
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &evidence,
                &run_spec,
                lifecycle_inputs(&history, Some(&proof), true),
            )
            .is_err()
        );
    }

    #[test]
    fn cold_restart_artifact_validation_rejects_any_served_operation() {
        let run_id = "run-lifecycle";
        let scenario = "cluster-cold-restart";
        let (_, run_spec) = lifecycle_run_spec(scenario);
        let dir = tempfile::tempdir().expect("tempdir");
        let metadata = RunMetadataArtifact {
            scenario: scenario.to_string(),
            run_id: run_id.to_string(),
            context: "real-cluster".to_string(),
            namespace: "fault-ns".to_string(),
            tenant: "fault-tenant".to_string(),
            storage_class: "fast-csi".to_string(),
            rustfs_image: "rustfs:test".to_string(),
            workload_objects: 12,
            workload_concurrency: 4,
            require_client_disruption: true,
            recovery_stability_reread_seconds: 60,
            min_availability_percent: None,
        };
        let before = [
            ("p-0", "old-0"),
            ("p-1", "old-1"),
            ("p-2", "old-2"),
            ("p-3", "old-3"),
        ];
        let after = [
            ("p-0", "new-0"),
            ("p-1", "new-1"),
            ("p-2", "new-2"),
            ("p-3", "new-3"),
        ];
        let history = lifecycle_history(&[22]);
        let proof = statefulset_proof(&before);
        let mut report = lifecycle_evidence_json(
            run_id,
            scenario,
            "cold-restart",
            (0..4)
                .map(|ordinal| {
                    let mut target = lifecycle_target_json(
                        &format!("p-{ordinal}"),
                        ordinal,
                        &format!("old-{ordinal}"),
                        &format!("new-{ordinal}"),
                        false,
                    );
                    target["replacementReadyAtMs"] = json!(45_000);
                    target["deleteRequestedAtMs"] = json!(11);
                    target["oldUidGoneAtMs"] = json!(111);
                    target
                })
                .collect(),
        );
        report["outage"] = json!({
            "scaleDownRequestedAtMs": 11,
            "allPodsTerminatedAtMs": 15,
            "replicaObservations": [
                {"observedAtMs": 12, "specReplicas": 0, "pods": 4},
                {"observedAtMs": 15, "specReplicas": 0, "pods": 0}
            ],
            "scaleUpRequestedAtMs": 40_500,
            "allPodsReadyAtMs": 45_000
        });
        report["operatorPause"] = json!({
            "namespace": "rustfs-system",
            "deployment": "rustfs-operator",
            "image": "docker.io/rustfs/operator:1.0.0",
            "identityMatchedBy": "image",
            "replicasBefore": 1,
            "pauseRequestedAtMs": 5,
            "operatorPodsGoneAtMs": 8,
            "resumeRequestedAtMs": 45_100,
            "resumedAtMs": 46_000
        });
        let counts =
            |ok: usize| json!({"ok": ok, "not_found": 0, "failed": 3, "timeout": 0, "unknown": 0});
        let summary = |ok: usize| {
            json!({
                "scenario": scenario,
                "run_id": run_id,
                "seed": 42,
                "object_count": 12,
                "concurrency": 4,
                "recommitted_after_recovery": 0,
                "puts": counts(0),
                "gets": counts(ok),
                "deletes": counts(0),
                "lists": counts(0),
                "multipart_completes": counts(0),
                "multipart_aborts": counts(0)
            })
        };
        let write = |report: &serde_json::Value, summary: &serde_json::Value| {
            write_json(dir.path(), POD_LIFECYCLE_EVIDENCE_ARTIFACT, report);
            write_json(dir.path(), "workload-summary.json", summary);
            BTreeMap::from([
                (
                    POD_LIFECYCLE_EVIDENCE_ARTIFACT.to_string(),
                    dir.path().join(POD_LIFECYCLE_EVIDENCE_ARTIFACT),
                ),
                (
                    "workload-summary.json".to_string(),
                    dir.path().join("workload-summary.json"),
                ),
            ])
        };
        let evidence = lifecycle_fault_evidence(
            run_id,
            scenario,
            &["p-0", "p-1", "p-2", "p-3"],
            &before,
            &after,
        );
        validate_pod_lifecycle_artifact(
            &write(&report, &summary(0)),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &evidence,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), false),
        )
        .expect("held outage");
        let error = validate_pod_lifecycle_artifact(
            &write(&report, &summary(1)),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &evidence,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), false),
        )
        .expect_err("a served GET during a total outage");
        assert!(error.to_string().contains("was not total"), "{error:#}");
        let mut not_found = summary(0);
        not_found["deletes"]["not_found"] = json!(1);
        let error = validate_pod_lifecycle_artifact(
            &write(&report, &not_found),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &evidence,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), false),
        )
        .expect_err("a 404 during a total outage");
        assert!(error.to_string().contains("deletes answered"), "{error:#}");
        let mut unattempted = summary(0);
        unattempted["multipart_aborts"] =
            json!({"ok": 0, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0});
        let error = validate_pod_lifecycle_artifact(
            &write(&report, &unattempted),
            &metadata,
            ArtifactIdentityPolicy::LegacyCompatible,
            &evidence,
            &run_spec,
            lifecycle_inputs(&history, Some(&proof), false),
        )
        .expect_err("family never attempted");
        assert!(error.to_string().contains("never attempted"), "{error:#}");
        let mut reverted = report.clone();
        reverted["outage"]["replicaObservations"][1]["specReplicas"] = json!(4);
        assert!(
            validate_pod_lifecycle_artifact(
                &write(&reverted, &summary(0)),
                &metadata,
                ArtifactIdentityPolicy::LegacyCompatible,
                &evidence,
                &run_spec,
                lifecycle_inputs(&history, Some(&proof), false),
            )
            .is_err()
        );
        assert!(
            crate::fault::spec::FaultRunArtifactSpec::required_names_for_scenario(scenario)
                .iter()
                .any(|name| name == POD_LIFECYCLE_EVIDENCE_ARTIFACT)
        );
        assert!(
            !crate::fault::spec::FaultRunArtifactSpec::required_names_for_scenario("io-eio")
                .iter()
                .any(|name| name == POD_LIFECYCLE_EVIDENCE_ARTIFACT)
        );
    }

    fn write_json(dir: &std::path::Path, name: &str, value: &serde_json::Value) {
        fs::write(
            dir.join(name),
            serde_json::to_string_pretty(value).expect("json"),
        )
        .expect("write json");
    }

    fn rewrite_first_history_record(
        path: &std::path::Path,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) {
        let current = fs::read_to_string(path).expect("history");
        let mut records = current.lines().map(str::to_string).collect::<Vec<_>>();
        let mut first = serde_json::from_str::<serde_json::Value>(
            records.first().expect("first history record"),
        )
        .expect("history record");
        mutate(&mut first);
        records[0] = first.to_string();
        fs::write(path, format!("{}\n", records.join("\n"))).expect("rewrite history");
    }

    fn rewrite_history_and_refresh_final_audit(
        case_dir: &std::path::Path,
        mutate: impl FnOnce(&mut Vec<OperationRecord>),
    ) {
        let history_path = case_dir.join("history.jsonl");
        let mut records = read_jsonl::<OperationRecord>(&history_path).expect("history");
        mutate(&mut records);
        fs::write(
            &history_path,
            format!(
                "{}\n",
                records
                    .iter()
                    .map(|record| serde_json::to_string(record).expect("history record"))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )
        .expect("rewrite history");

        let checker_path = case_dir.join("checker-report.json");
        let mut checker: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&checker_path).expect("checker report"))
                .expect("checker JSON");
        let prefix_count = checker["audit"]["history_prefix_record_count"]
            .as_u64()
            .expect("prefix count") as usize;
        checker["audit"]["history_prefix_sha256"] = json!(
            checker::checker_history_records_sha256(&records[..prefix_count])
                .expect("checker prefix digest")
        );
        write_json(case_dir, "checker-report.json", &checker);
    }

    fn rewrite_run_spec_versioning(case_dir: &std::path::Path, versioning: bool) {
        let json_path = case_dir.join("run-spec.json");
        let mut spec = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&json_path).expect("read run spec"),
        )
        .expect("parse run spec");
        spec["workload"]["versioning"] = json!(versioning);
        fs::write(
            &json_path,
            serde_json::to_string_pretty(&spec).expect("json"),
        )
        .expect("write run spec json");
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&spec).expect("yaml"),
        )
        .expect("write run spec yaml");
    }

    fn rewrite_run_spec_detector(case_dir: &std::path::Path, detector: serde_json::Value) {
        let json_path = case_dir.join("run-spec.json");
        let mut spec = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&json_path).expect("read run spec"),
        )
        .expect("parse run spec");
        spec["scenario"]["detector"] = detector;
        fs::write(
            &json_path,
            serde_json::to_string_pretty(&spec).expect("json"),
        )
        .expect("write run spec json");
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&spec).expect("yaml"),
        )
        .expect("write run spec yaml");
    }

    fn rewrite_run_spec_without_detector(case_dir: &std::path::Path) {
        let json_path = case_dir.join("run-spec.json");
        let mut spec = serde_json::from_str::<serde_json::Value>(
            &fs::read_to_string(&json_path).expect("read run spec"),
        )
        .expect("parse run spec");
        spec["scenario"]
            .as_object_mut()
            .expect("scenario object")
            .remove("detector");
        fs::write(
            &json_path,
            serde_json::to_string_pretty(&spec).expect("json"),
        )
        .expect("write run spec json");
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&spec).expect("yaml"),
        )
        .expect("write run spec yaml");
    }

    #[test]
    fn recursive_find_returns_none_for_missing_root() {
        let dir = tempfile::tempdir().expect("tempdir");
        let missing = dir.path().join("does-not-exist");

        assert_eq!(
            recursive_find(&missing, "checker-report.json").expect("find"),
            None
        );
    }

    #[test]
    fn recursive_find_returns_none_when_name_is_absent() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join("other.json"), "{}").expect("write");

        assert_eq!(
            recursive_find(dir.path(), "checker-report.json").expect("find"),
            None
        );
    }

    #[test]
    fn recursive_find_locates_a_nested_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nested = dir.path().join("a").join("b");
        fs::create_dir_all(&nested).expect("mkdir");
        let target = nested.join("checker-report.json");
        fs::write(&target, "{}").expect("write");

        assert_eq!(
            recursive_find(dir.path(), "checker-report.json").expect("find"),
            Some(target)
        );
    }

    #[test]
    fn recursive_find_matches_by_exact_file_name_not_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A directory sharing the searched name must not be returned; only a
        // file with that exact name counts as a hit.
        fs::create_dir_all(dir.path().join("checker-report.json")).expect("mkdir");

        assert_eq!(
            recursive_find(dir.path(), "checker-report.json").expect("find"),
            None
        );
    }
}
