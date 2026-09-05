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
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

use crate::fault::{
    acknowledged_mutation::AcknowledgedMutationKind,
    backends::chaos_mesh::{
        NetworkPartitionEvidenceContract, VolumeTargetEvidenceContract, iochaos_record_pod_id,
        validate_fixed_volume_snapshot, validate_network_partition_snapshot,
    },
    checker::{self, CheckerReport, RecoveryStabilityClassification, RecoveryStabilityReport},
    config::{
        DEFAULT_RECOVERY_STABILITY_REREAD_SECONDS, DEFAULT_RUSTFS_POD_COUNT,
        DEFAULT_RUSTFS_POD_STABLE_WINDOW_SECONDS, DEFAULT_RUSTFS_VOLUME_PATH,
        DEFAULT_WORKLOAD_CONCURRENCY, DEFAULT_WORKLOAD_OBJECTS, MAX_ACK_TO_FAULT_MS,
    },
    events::{RunEvent, RunEventStatus},
    history::{DurabilityCohort, OperationKind, OperationOutcome, OperationRecord},
    host_storage::DmStatusSnapshot,
    host_storage::{
        HOST_STORAGE_CLEANUP_ARTIFACT, HOST_STORAGE_PROOF_ARTIFACT, HostStorageMutationProof,
        HostStoragePostCleanupObservation, normalized_dm_table_sha256,
    },
    plan::{
        FaultInjection, FaultKind, FaultPlan, FaultPlanOptions, FaultSelection, FaultTarget,
        FaultWorkloadMode,
    },
    pods::fixed_volume_container_ids,
    preflight::{
        PreflightStatus, PreflightSummary, TargetProof, TargetProofStatus,
        target_pod_has_bound_volume, target_pod_has_fixed_volume,
    },
    quorum::require_fresh_runtime_observation,
    reporting::{FailurePhase, FailureSummary, FailureVerdict, validate_failure_summary_v2_fields},
    scenarios::{
        self, DM_FLAKEY_VERSIONED_HOT_SCENARIO, FaultScenario, acknowledged_mutation_kind,
    },
    spec::{
        FAULT_RUN_API_VERSION, FAULT_RUN_KIND, FaultRunAckTriggerSpec, FaultRunArtifactSpec,
        FaultRunFaultSpec, FaultRunSpec, FaultRunTargetSpec,
    },
    workload::WorkloadPlan,
};

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
    ensure!(
        evidence
            .fault_apply_started_at_ms
            .is_some_and(|at| at >= attempt_started_at_ms)
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
        validate_write_quorum_runtime_evidence(&evidence, &target_proof, &json_spec)?;
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
    if ack_mutation.is_some() {
        validate_ack_fault_window_evidence(&evidence)?;
    } else {
        validate_fault_window_evidence(&evidence)?;
    }
    if options.scenario == DM_FLAKEY_VERSIONED_HOT_SCENARIO {
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
    )?;
    let checker = read_json::<CheckerReport>(required(&artifacts, "checker-report.json")?)?;
    validate_checker_identity("checker-report.json", &checker, &metadata)?;
    validate_checker_report(
        "checker-report.json",
        &checker,
        options.expected_workload_versioning,
    )?;
    if let Some(expectation) = &ack_checker_expectation {
        validate_ack_checker_report("checker-pre-recommit-report.json", &prechecker, expectation)?;
        validate_ack_checker_report("checker-report.json", &checker, expectation)?;
    }

    if ack_mutation.is_some() {
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
    ensure!(
        summary.exercised_all_operation_families(),
        "workload-summary.json did not exercise every required S3 operation family"
    );
    ensure!(
        summary.disrupted()? == evidence.client_disruptions,
        "fault-evidence.json client_disruptions does not match workload-summary.json"
    );
    if options.scenario == scenarios::NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
        let history = read_jsonl::<OperationRecord>(required(&artifacts, "history.jsonl")?)?;
        summary.require_write_quorum_loss_effect(
            &history,
            &metadata.scenario,
            &json_spec.metadata.bucket,
            evidence
                .workload_started_at_ms
                .context("fault-evidence.json workload_started_at_ms is required")?,
            evidence
                .workload_ended_at_ms
                .context("fault-evidence.json workload_ended_at_ms is required")?,
        )?;
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
    ensure!(
        !spec.faults.is_empty(),
        "run-spec must contain at least one fault"
    );
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
            fault.selection.value > 0,
            "run-spec fault {} has zero selection value",
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
    let scenario = FaultScenario {
        name: options.scenario.clone(),
        case_name: catalog.case_name,
        duration: Duration::from_secs(artifact_fault.fault_duration_seconds),
        percent,
        object_count: spec.workload.object_count,
    };
    let plan = FaultPlan::from_scenario_with_options(
        &scenario,
        catalog,
        FaultPlanOptions {
            rustfs_volume_path: options.expected_rustfs_volume_path.clone(),
            scenario_parameters: artifact_fault.parameters.clone(),
        },
    )
    .context("rebuild canonical fault plan for artifact validation")?;
    let expected_mode = match plan.workload_mode {
        FaultWorkloadMode::S3Mixed => "s3-mixed",
        FaultWorkloadMode::S3MixedWithWarp => "s3-mixed-with-warp",
        FaultWorkloadMode::AckTriggeredQuietMutation => "ack-triggered-quiet-mutation",
    };
    ensure!(
        spec.workload.mode == expected_mode,
        "run-spec workload mode {:?} does not match canonical plan {expected_mode:?}",
        spec.workload.mode
    );
    let expected_faults = plan
        .faults()
        .iter()
        .enumerate()
        .map(|(index, fault)| FaultRunFaultSpec::from_fault(index, &scenario, catalog, fault))
        .collect::<Vec<_>>();
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
        ensure!(
            fault.selection.value > 0
                && proof.resolved_pods.len() >= usize::try_from(fault.selection.value)?
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

fn validate_write_quorum_runtime_evidence(
    evidence: &FaultEvidenceArtifact,
    proof: &TargetProof,
    spec: &FaultRunSpec,
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
    let contract = NetworkPartitionEvidenceContract {
        chaos_namespace: &spec.cluster.chaos_namespace,
        target_namespace: &spec.cluster.namespace,
        tenant: &spec.cluster.tenant,
        run_id: &spec.metadata.run_id,
        scenario: &spec.scenario.name,
        expected_source_targets: spec_fault.selection.value,
        candidate_pod_ids: &candidate_pod_ids,
    };
    let mut selected_targets = None;
    for (stage, snapshots) in [
        ("active", &evidence.active_snapshots),
        ("after-workload", &evidence.workload_snapshots),
    ] {
        ensure!(
            snapshots.len() == 1,
            "fault-evidence.json {stage} stage must contain exactly one NetworkChaos snapshot"
        );
        let snapshot = &snapshots[0];
        ensure!(
            snapshot.get("stage").and_then(Value::as_str) == Some(stage)
                && snapshot.get("resource_kind").and_then(Value::as_str) == Some("networkchaos"),
            "fault-evidence.json {stage} snapshot metadata is invalid"
        );
        let resource = snapshot
            .get("chaos_status")
            .context("fault-evidence.json NetworkChaos snapshot has no resource object")?;
        ensure!(
            snapshot.get("resource_name").and_then(Value::as_str)
                == resource.pointer("/metadata/name").and_then(Value::as_str),
            "fault-evidence.json NetworkChaos snapshot resource name is inconsistent"
        );
        let current_targets = validate_network_partition_snapshot(resource, &contract)
            .with_context(|| format!("validate {stage} NetworkChaos runtime evidence"))?;
        if let Some(expected_targets) = &selected_targets {
            ensure!(
                expected_targets == &current_targets,
                "NetworkChaos selected source targets changed across workload snapshots"
            );
        } else {
            selected_targets = Some(current_targets);
        }
    }
    let selected_targets = selected_targets.context("no NetworkChaos source targets observed")?;
    let namespace_prefix = format!("{}/", spec.cluster.namespace);
    let selected_pods = selected_targets
        .iter()
        .map(|target| {
            target.strip_prefix(&namespace_prefix).with_context(|| {
                format!("NetworkChaos selected target {target:?} is outside the run namespace")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    membership
        .require_selected_boundary(shape, selected_pods)
        .context("actual NetworkChaos source targets do not cross the write-quorum boundary")?;
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
    proof
        .require_generated_during_apply(fault_apply_started_at_ms, fault_active_at_ms)
        .context("host-storage proof was not freshly regenerated during fault apply")?;
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
        && fault.selection.kind == "fixed-targets"
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
    let injection = fixed_volume_injection_from_run_spec(fault)?;
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
    let expected_count = usize::try_from(fault.selection.value)?;
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
        fault.selection.value
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
                expected_targets: fault.selection.value,
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

fn fixed_volume_injection_from_run_spec(fault: &FaultRunFaultSpec) -> Result<FaultInjection> {
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
        FaultSelection::FixedTargets(fault.selection.value),
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
    ensure!(
        report.missing_committed_objects.is_empty()
            && report.unavailable_committed_objects.is_empty()
            && report.unknown_committed_read_failures.is_empty()
            && report.hash_mismatches.is_empty()
            && report.successful_corrupted_reads.is_empty()
            && report.unexpected_visible_deleted_objects.is_empty()
            && report.unknown_writes_materialized.is_empty()
            && report.unknown_write_value_conflicts.is_empty()
            && report.final_list_warning_count == 0
            && report.list_warnings.is_empty()
            && report.committed_writes_missing_version_id_count == 0
            && report.missing_committed_versions.is_empty()
            && report.unavailable_committed_versions.is_empty()
            && report.version_hash_mismatches.is_empty()
            && report.missing_committed_delete_markers.is_empty()
            && report.resurrected_deleted_objects.is_empty()
            && report.delete_marker_lineage_incomplete.is_empty()
            && report.multipart_upload_lineage_incomplete.is_empty()
            && report.tenant_recovered,
        "{name} contains a non-clean checker verdict"
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
        apply_started <= active
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
    trigger_reference: String,
    trigger_is_delete_marker: bool,
    committed_version_refs: BTreeSet<String>,
    committed_delete_marker_refs: BTreeSet<String>,
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
    validate_ack_trigger_contract(
        &ack,
        planned,
        expected_mutation,
        scenario,
        run_id,
        evidence.fault_apply_started_at_ms,
    )?;
    ensure!(
        evidence.fault_active_at_ms == Some(ack.fault_activated_at_ms),
        "ACK activation timestamp does not match fault-evidence.json"
    );

    let trigger = history
        .iter()
        .find(|record| record.id == ack.trigger_operation_id)
        .context("history.jsonl lacks the declared ACK trigger operation")?;
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
    validate_ack_quiet_gap(history, trigger, ack.crash_boundary_started_at_ms)?;
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
    validate_ack_crash_target_identity(&boundary, &host_proof, evidence)?;
    Ok(checker_expectation)
}

fn validate_ack_trigger_contract(
    ack: &AckTriggeredCrashEvidenceArtifact,
    planned: &FaultRunAckTriggerSpec,
    expected_mutation: AcknowledgedMutationKind,
    scenario: &str,
    run_id: &str,
    fault_apply_started_at_ms: Option<u64>,
) -> Result<()> {
    ensure!(
        ack.scenario == scenario
            && ack.run_id == run_id
            && ack.trigger_kind == expected_mutation
            && planned.mutation == expected_mutation
            && (1..=MAX_ACK_TO_FAULT_MS).contains(&planned.max_ack_to_fault_ms)
            && ack.max_ack_to_fault_ms == planned.max_ack_to_fault_ms
            && !ack.trigger_operation_id.is_empty()
            && !ack.trigger_key.is_empty()
            && !ack.trigger_version_id.is_empty()
            && ack.trigger_version_id != "null"
            && fault_apply_started_at_ms.is_some_and(|started| {
                ack.trigger_acknowledged_at_ms <= started && started <= ack.fault_activated_at_ms
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
    let verified_versions = report
        .verified_committed_version_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let verified_delete_markers = report
        .verified_committed_delete_marker_refs
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        report.versioning_expected
            && report.expected_committed_versions == expectation.committed_version_refs.len()
            && report.verified_committed_versions == expectation.committed_version_refs.len()
            && report.verified_committed_version_refs.len() == verified_versions.len()
            && verified_versions == expectation.committed_version_refs
            && report.verified_committed_delete_marker_refs.len() == verified_delete_markers.len()
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
) -> Result<()> {
    ensure!(
        trigger.ended_at_ms <= crash_boundary_started_at_ms
            && history.iter().all(|record| {
                record.id == trigger.id
                    || record.ended_at_ms <= trigger.started_at_ms
                    || record.started_at_ms >= crash_boundary_started_at_ms
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
    let prior_puts = history
        .iter()
        .filter(|record| {
            record.id != trigger.id
                && record.key == trigger.key
                && record.kind == OperationKind::Put
                && record.outcome == OperationOutcome::Ok
                && record.ended_at_ms <= trigger.started_at_ms
        })
        .count();
    match kind {
        AcknowledgedMutationKind::Put | AcknowledgedMutationKind::ZeroBytePut => ensure!(
            prior_puts == 0,
            "create-style ACK trigger unexpectedly has a prior object version"
        ),
        AcknowledgedMutationKind::Overwrite | AcknowledgedMutationKind::DeleteMarker => ensure!(
            prior_puts == 1,
            "overwrite/delete-marker ACK trigger must have exactly one baseline version"
        ),
        AcknowledgedMutationKind::MultipartComplete => {
            ensure!(
                history.iter().any(|record| {
                    record.key == trigger.key
                        && record.kind == OperationKind::CreateMultipartUpload
                        && record.outcome == OperationOutcome::Ok
                        && record.ended_at_ms <= trigger.started_at_ms
                }) && history.iter().any(|record| {
                    record.key == trigger.key
                        && record.kind == OperationKind::UploadPart
                        && record.outcome == OperationOutcome::Ok
                        && record.ended_at_ms <= trigger.started_at_ms
                }),
                "multipart ACK trigger lacks successfully staged upload evidence"
            );
        }
    }
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
    Ok(report)
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
        | RecoveryStabilityClassification::DeletedObjectResurrected) => {
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
    storage_class: String,
    rustfs_image: String,
    workload_objects: usize,
    workload_concurrency: usize,
    require_client_disruption: bool,
    #[serde(default = "default_recovery_stability_reread_seconds")]
    recovery_stability_reread_seconds: u64,
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
    attempts: Vec<Value>,
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
    recommitted_after_recovery: usize,
    puts: OutcomeCountsArtifact,
    gets: OutcomeCountsArtifact,
    deletes: OutcomeCountsArtifact,
    lists: OutcomeCountsArtifact,
    multipart_completes: OutcomeCountsArtifact,
    multipart_aborts: OutcomeCountsArtifact,
}

impl WorkloadSummaryArtifact {
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

    fn require_write_quorum_loss_effect(
        &self,
        history: &[OperationRecord],
        scenario: &str,
        bucket: &str,
        workload_started_at_ms: u64,
        workload_ended_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.puts.total() > 0
                && self.deletes.total() > 0
                && self.multipart_completes.total() > 0,
            "workload-summary.json did not exercise every committing mutation family"
        );
        for (kind, counts) in [
            ("PUT", &self.puts),
            ("DELETE", &self.deletes),
            ("CompleteMultipartUpload", &self.multipart_completes),
        ] {
            ensure!(
                counts.ok == 0 && counts.not_found == 0 && counts.disrupted()? > 0,
                "write-quorum-loss {kind} outcomes must all be failed, timed out, or unknown: {counts:?}"
            );
        }
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
        ArtifactValidationOptions, FailureSummary, FaultEvidenceArtifact, OutcomeCountsArtifact,
        WorkloadSummaryArtifact, recursive_find, validate_fault_artifacts,
        validate_fault_artifacts_and_write_report,
        validate_fault_artifacts_for_planned_attempt_and_write_report,
        validate_fixed_volume_runtime_evidence, validate_host_storage_artifacts, validate_run_spec,
        validate_target_proof, validate_write_quorum_runtime_evidence,
    };
    use crate::fault::{
        checker::{RecoveryStabilityClassification, RecoveryStabilityReport},
        config::FaultTestConfig,
        history::{OperationOutcome, OperationRecord},
        host_storage::{
            HostStorageAllowlist, HostStorageMutationIntent, HostStorageMutationProof,
            HostStorageNodeSelector, HostStoragePersistentVolumeClaimRef,
            HostStoragePostCleanupObservation, HostStorageTargetObservation,
        },
        plan::{FaultInjection, FaultKind, FaultPlan, FaultSelection, FaultTarget},
        preflight::{
            TargetNodeAffinityProof, TargetNodeSelectorRequirementProof,
            TargetNodeSelectorTermProof, TargetPersistentVolumeClaimProof,
            TargetPersistentVolumeProof, TargetProof, TargetResolvedPodProof,
            TargetVolumeMountProof,
        },
        quorum::{ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape},
        reporting::{
            AvailabilityStatus, DataCorrectnessStatus, FailurePhase, FailureSeverity,
            FailureVerdict, ResponsibilityDomain,
        },
        scenarios::{
            DM_FLAKEY_SCENARIO, FaultScenario, NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
            scenario_spec,
        },
        spec::{FAULT_RUN_API_VERSION, FAULT_RUN_KIND, FaultRunArtifactSpec, FaultRunSpec},
        workload::WorkloadPlan,
    };
    use serde_json::json;
    use std::{collections::BTreeMap, fs, time::Duration};

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
            "io-eio\t42\t0\t2\t1\t7\t0\t0\t0\t0\ttrue"
        );
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
                let mut record: serde_json::Value =
                    serde_json::from_str(fs::read_to_string(&path).expect("history").trim())
                        .expect("record");
                record["run_id"] = json!("run-old");
                fs::write(&path, format!("{record}\n")).expect("write history");
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
                let mut record: serde_json::Value =
                    serde_json::from_str(fs::read_to_string(&path).expect("history").trim())
                        .expect("record");
                record.as_object_mut().expect("object").remove("run_id");
                fs::write(&path, format!("{record}\n")).expect("write history");
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
            validate_fault_artifacts(&options).expect("legacy additive field may be absent");
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
            serde_json::from_str(current.trim()).expect("operation record");
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
        config.scenario = "io-eio".to_string();
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
                    volume_name: Some("pv-csi".to_string()),
                    storage_class: Some("fast-csi".to_string()),
                    persistent_volume: Some(TargetPersistentVolumeProof {
                        name: "pv-csi".to_string(),
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
        config.scenario = "io-eio".to_string();
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
                        volume_name: Some(format!("pv-{index}")),
                        storage_class: Some("fast-csi".to_string()),
                        persistent_volume: Some(TargetPersistentVolumeProof {
                            name: format!("pv-{index}"),
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
        validate_write_quorum_runtime_evidence(&evidence, &proof, &run_spec)
            .expect("runtime selection proof");
        evidence.pods_at_fault_activation[0].uid = "replacement-uid".to_string();
        assert!(validate_write_quorum_runtime_evidence(&evidence, &proof, &run_spec).is_err());
        evidence.pods_at_fault_activation[0].uid = "uid-0".to_string();
        evidence.pods_at_workload_snapshot[0].uid = "replacement-uid".to_string();
        assert!(validate_write_quorum_runtime_evidence(&evidence, &proof, &run_spec).is_err());
        evidence.pods_at_workload_snapshot[0].uid = "uid-0".to_string();
        evidence.fault_apply_started_at_ms = Some(6_002);
        assert!(validate_write_quorum_runtime_evidence(&evidence, &proof, &run_spec).is_err());

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
                    volume_name: Some("pv-a".to_string()),
                    storage_class: Some("rustfs-fault-dm".to_string()),
                    persistent_volume: Some(TargetPersistentVolumeProof {
                        name: "pv-a".to_string(),
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

        let mut ack_spec = run_spec.clone();
        ack_spec.scenario.ack_trigger = Some(crate::fault::spec::FaultRunAckTriggerSpec {
            mutation: crate::fault::acknowledged_mutation::AcknowledgedMutationKind::Put,
            operation_timeout_ms: 30_000,
            max_ack_to_fault_ms: 1_000,
        });
        let mut ack_evidence = evidence.clone();
        ack_evidence.active_during_workload = false;
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
        let delete_history = vec![baseline, delete.clone()];
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
            ack_to_crash_boundary_ms: 10,
        };
        super::validate_ack_trigger_contract(
            &valid,
            &planned,
            AcknowledgedMutationKind::Put,
            "dm-drop-writes-after-ack-put",
            "run-1",
            Some(101),
        )
        .expect("valid trigger contract");

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
                Some(101),
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
                Some(101),
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
                Some(101),
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
                Some(99),
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
                Some(101),
            )
            .is_err(),
            "artifact validation must reject an ACK window too wide for durability evidence"
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
                "verified_committed_version_refs": verified_refs,
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
                "verified_committed_version_refs": ["key-1@version-1"],
                "verified_committed_delete_marker_refs": markers,
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
        use crate::fault::history::OperationKind;

        let record = |id: &str, started_at_ms: u64| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": "ack-case",
                "run_id": "run-1",
                "kind": OperationKind::Put,
                "bucket": "bucket",
                "key": id,
                "value_sha256": "abc",
                "size_bytes": 4,
                "version_id": id,
                "started_at_ms": started_at_ms,
                "ended_at_ms": started_at_ms + 1,
                "outcome": "ok",
                "http_status": 200,
                "error": null
            }))
            .expect("operation record")
        };
        let trigger = record("op-1", 90);
        let recovery_read = record("op-2", 121);
        super::validate_ack_quiet_gap(&[trigger.clone(), recovery_read], &trigger, 120)
            .expect("quiet gap");

        let extra = record("op-2", 115);
        assert!(
            super::validate_ack_quiet_gap(&[trigger.clone(), extra], &trigger, 120).is_err(),
            "traffic after the ACK must invalidate the quiet crash window"
        );
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

        assert!(
            error
                .to_string()
                .contains("contains a non-clean checker verdict")
        );
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
                "impact_policy": "client-disruption-required",
                "boundary": "rustfs-workload/fault-injection",
                "validation": "prefill succeeds before injection, mixed PUT/GET workload runs while IOChaos is active, committed PUTs are GET+sha256 verified after recovery, and successful GETs cannot return corrupt bytes",
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
                "fault_duration_seconds": 60,
                "observability": "history.jsonl, workload-summary.json, checker-report.json, chaos-manifest.yaml, chaos-describe*.txt, Kubernetes snapshot artifacts",
                "conflict_domain": "fresh Tenant/PVC/PV fixture and run-scoped IOChaos cleanup"
            }],
            "artifacts": {
                "required": FaultRunArtifactSpec::required_names(),
                "event_stream": "run-events.jsonl"
            }
        });
        write_json(&case_dir, "run-spec.json", &run_spec);
        fs::write(
            case_dir.join("run-spec.yaml"),
            serde_yaml_ng::to_string(&run_spec).expect("yaml"),
        )
        .expect("write yaml");
        fs::write(
            case_dir.join("run-events.jsonl"),
            [
                json!({"at_ms":1,"scenario":scenario,"run_id":run_id,"stage":"run","status":"started","message":"started"}).to_string(),
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
                "schemaVersion": 1,
                "status": "satisfied",
                "proofLevel": "selector_intent",
                "generatedAtMs": 1,
                "scenario": scenario,
                "caseName": "fault_io_eio_preserves_committed_objects",
                "runId": run_id,
                "namespace": "rustfs-fault-test",
                "tenant": "fault-test-tenant",
                "resolvedPods": [{
                    "name": "p0",
                    "uid": "u0",
                    "node": "node-a",
                    "persistentVolumeClaims": [{
                        "name": "data-p0",
                        "volumeName": "pv-a",
                        "storageClass": "fast-csi",
                        "persistentVolume": {
                            "name": "pv-a",
                            "node": "node-a",
                            "deviceOrPath": "/mnt/rustfs0"
                        }
                    }]
                }],
                "faults": [{
                    "name": "io-eio-00-rustfs_volume_io_error",
                    "kind": "rustfs_volume_io_error",
                    "backend": "chaos-mesh-io-chaos",
                    "targetKind": "rustfs-volume",
                    "targetSummary": "one RustFS volume at /data/rustfs0",
                    "selection": "20%",
                    "conflictDomain": "run-scoped IOChaos",
                    "podSelector": {
                        "namespace": "rustfs-fault-test",
                        "tenant": "fault-test-tenant",
                        "selector": "rustfs.tenant=fault-test-tenant",
                        "exactPodsResolved": true,
                        "note": "preflight resolved current RustFS target pods"
                    },
                    "volumePath": "/data/rustfs0"
                }],
                "requirements": [{
                    "name": "catalog_target_intent",
                    "status": "passed",
                    "message": "one RustFS container data volume"
                }]
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
                "use_cluster_ip": false,
                "require_client_disruption": true,
                "chaos_namespace": "chaos-mesh"
            }),
        );
        let mut workload_plan = json!(plan);
        workload_plan["scenario"] = json!(scenario);
        workload_plan["run_id"] = json!(run_id);
        write_json(&case_dir, "workload-plan.json", &workload_plan);
        fs::write(
            case_dir.join("history.jsonl"),
            format!(
                "{}\n",
                json!({
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
                    "outcome": "ok",
                    "http_status": 200,
                    "error": null
                })
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
                "puts": {"ok": 1, "not_found": 0, "failed": 1, "timeout": 0, "unknown": 0},
                "gets": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 1, "unknown": 0},
                "deletes": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "lists": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_completes": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "multipart_aborts": {"ok": 1, "not_found": 0, "failed": 0, "timeout": 0, "unknown": 0},
                "recommitted_after_recovery": 1
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
                "attempts": [{"key": "k", "size_bytes": 1, "sha256": "s", "outcome": "ok", "verify_get_outcome": "ok", "http_status": 200, "error": null, "harness_error": null}]
            }),
        );
        let checker = json!({
            "scenario": scenario,
            "run_id": run_id,
            "committed_puts": 7,
            "expected_live_objects": 7,
            "verified_live_objects": 7,
            "missing_committed_objects": [],
            "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [],
            "hash_mismatches": [],
            "successful_corrupted_reads": [],
            "unexpected_visible_deleted_objects": [],
            "unknown_writes_materialized": [],
            "operation_cohorts": {"pre_fault": 12, "fault_active": 8, "post_recovery": 4},
            "fault_window_relations": {"during_fault": 8, "after_fault": 4},
            "list_history_warning_count": 0,
            "final_list_warning_count": 0,
            "list_history_warnings": [],
            "list_warnings": [],
            "final_listed_objects": 7,
            "tenant_recovered": true,
            "passed": true
        });
        write_json(&case_dir, "checker-pre-recommit-report.json", &checker);
        write_json(&case_dir, "checker-report.json", &checker);
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
                "require_client_disruption": true,
                "client_disruptions": 2,
                "workload_plan": plan,
                "pods_before": [{"name": "p0", "uid": "u0"}],
                "pods_after": [{"name": "p0", "uid": "u0"}],
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
    }

    fn write_json(dir: &std::path::Path, name: &str, value: &serde_json::Value) {
        fs::write(
            dir.join(name),
            serde_json::to_string_pretty(value).expect("json"),
        )
        .expect("write json");
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
