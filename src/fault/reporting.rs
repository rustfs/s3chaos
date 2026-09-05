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

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

use crate::{
    fault::{
        config::FaultTestConfig,
        host_storage::DmStatusSnapshot,
        plan::{FaultPlan, FaultSelection},
        quorum::QuorumHealthObservation,
        scenarios::{FaultScenario, FaultScenarioSpec},
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
    pub(crate) run_id: String,
    pub(crate) backend: String,
    pub(crate) target: String,
    pub(crate) injected: bool,
    pub(crate) active_during_workload: bool,
    pub(crate) recovered: bool,
    pub(crate) require_client_disruption: bool,
    pub(crate) client_disruptions: usize,
    pub(crate) workload_plan: WorkloadPlan,
    pub(crate) pods_before: Vec<PodIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pods_at_fault_activation: Vec<PodIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) pods_at_workload_snapshot: Vec<PodIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) fixed_volume_targets_at_fault_activation: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) fixed_volume_targets_at_workload_snapshot: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fixed_volume_containers_at_fault_activation: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) fixed_volume_containers_at_workload_snapshot: BTreeMap<String, String>,
    pub(crate) pods_after: Vec<PodIdentity>,
    pub(crate) active_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) workload_snapshots: Vec<FaultStatusSnapshot>,
    pub(crate) dm_recovery_snapshot: Option<DmStatusSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fault_apply_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fault_active_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workload_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) workload_ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) fault_delete_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_started_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_ended_at_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quorum_health_before_workload: Option<QuorumHealthObservation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) quorum_health_after_workload: Option<QuorumHealthObservation>,
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
    fault_duration_seconds: u64,
    percent: Option<u8>,
    fault_selection: Vec<String>,
    fault_parameters: Vec<crate::fault::plan::FaultInjectionParameters>,
    workload_objects: usize,
    workload_concurrency: usize,
    workload_operation_mix: crate::fault::workload::WorkloadOperationMix,
    prefill_concurrency: usize,
    request_timeout_seconds: u64,
    recovery_stability_reread_seconds: u64,
    use_cluster_ip: bool,
    require_client_disruption: bool,
    chaos_namespace: String,
}

impl RunMetadata {
    pub(crate) fn from_case(
        config: &FaultTestConfig,
        scenario: &FaultScenario,
        spec: &FaultScenarioSpec,
        plan: &FaultPlan,
        workload_plan: &WorkloadPlan,
        run_id: &str,
        bucket: &str,
    ) -> Self {
        let require_client_disruption =
            config.require_client_disruption || spec.impact_policy.requires_client_disruption();
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
            fault_duration_seconds: scenario.duration.as_secs(),
            percent: plan
                .faults()
                .iter()
                .find_map(|fault| match fault.selection() {
                    FaultSelection::Percent(percent) => Some(percent),
                    FaultSelection::FixedTargets(_) | FaultSelection::RuntimeQuorum(_) => None,
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
            recovery_stability_reread_seconds: config.recovery_stability_reread.as_secs(),
            use_cluster_ip: config.use_cluster_ip,
            require_client_disruption,
            chaos_namespace: config.chaos_namespace.clone(),
        }
    }
}

pub(crate) use crate::fault::verdict::FailureSummary;
pub use crate::fault::verdict::{
    AvailabilityStatus, DataCorrectnessStatus, FailureClassification, FailurePhase,
    FailureSeverity, FailureVerdict, ResponsibilityDomain,
};

pub(crate) fn write_failure_summary(
    collector: &ArtifactCollector,
    case_name: &str,
    summary: FailureSummary,
) -> Result<()> {
    let summary = summary.with_case_name(case_name);
    let summary = resolve_summary_evidence(summary, collector, case_name)?;
    collector.write_text(
        case_name,
        "failure-summary.json",
        &serde_json::to_string_pretty(&summary)?,
    )?;
    // Diagnostic contract check on the failure path: the strict validator only
    // runs on passing runs, so this is the only automated coverage a failed
    // run's summary gets. Warning-only — a contract violation must never mask
    // the run's original failure.
    let path = collector.case_dir(case_name).join("failure-summary.json");
    if let Err(violation) = validate_written_failure_summary(collector.reference_root(), &path) {
        eprintln!(
            "warning: failure-summary.json violates the artifact contract (diagnostic validation): {violation:#}"
        );
    }
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

fn resolve_summary_evidence(
    mut summary: FailureSummary,
    collector: &ArtifactCollector,
    case_name: &str,
) -> Result<FailureSummary> {
    let case_dir = collector.case_dir(case_name);
    summary.primary_evidence_refs = summary
        .primary_evidence_refs
        .into_iter()
        .map(|artifact| case_dir.join(artifact))
        .filter(|path| path.is_file())
        .map(|path| {
            collector
                .reference_path(&path)
                .map(|relative| relative.display().to_string())
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(summary)
}

/// Check persisted summary metadata without requiring a complete successful run.
pub(crate) fn validate_written_failure_summary(root: &Path, path: &Path) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading just-written failure summary {}", path.display()))?;
    let summary: FailureSummary = serde_json::from_str(&raw)
        .with_context(|| format!("parsing just-written failure summary {}", path.display()))?;
    validate_failure_summary_v2_fields(&summary, Some(root), Some(path))
}

pub(crate) fn validate_failure_summary_v2_fields(
    summary: &FailureSummary,
    artifact_root: Option<&Path>,
    artifact_path: Option<&Path>,
) -> Result<()> {
    if summary.schema_version < 2 {
        return Ok(());
    }

    if let Some(phase) = summary.phase {
        ensure!(
            phase == FailurePhase::from_stage(&summary.stage),
            "failure-summary.json phase {:?} does not match stage {:?}",
            summary.phase,
            summary.stage
        );
    }
    ensure!(
        summary
            .case_name
            .as_ref()
            .is_none_or(|value| !value.trim().is_empty()),
        "failure-summary.json case_name must be null or a non-empty string"
    );
    ensure!(
        summary.observed_at_ms.is_none_or(|value| value > 0),
        "failure-summary.json observed_at_ms must be greater than zero when present"
    );

    validate_failure_summary_v2_classification(summary)?;
    if summary.primary_evidence_refs.is_empty() {
        return Ok(());
    }
    ensure!(
        summary.primary_evidence_refs.len() <= 5,
        "failure-summary.json primary_evidence_refs must contain at most 5 entries"
    );
    ensure!(
        summary
            .primary_evidence_refs
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == summary.primary_evidence_refs.len(),
        "failure-summary.json primary_evidence_refs contains duplicates"
    );
    for evidence_ref in &summary.primary_evidence_refs {
        validate_primary_evidence_ref(evidence_ref, artifact_root, artifact_path)?;
    }
    Ok(())
}

pub(crate) fn validate_failure_summary_v2_classification(summary: &FailureSummary) -> Result<()> {
    let classification =
        FailureClassification::from_name(&summary.classification).with_context(|| {
            format!(
                "failure-summary.json classification {:?} is not in the writer allowlist",
                summary.classification
            )
        })?;
    if classification.is_s3_model() {
        ensure!(
            summary
                .s3_model_classification
                .as_deref()
                .is_none_or(|value| value == summary.classification)
                && summary.run_failure_reason.is_none(),
            "failure-summary.json S3 model classification must match s3_model_classification when present and omit run_failure_reason"
        );
    } else {
        ensure!(
            summary.s3_model_classification.is_none()
                && summary
                    .run_failure_reason
                    .as_deref()
                    .is_none_or(|value| value == summary.classification),
            "failure-summary.json non-S3-model classification must match run_failure_reason when present and omit s3_model_classification"
        );
    }
    if let Some(responsibility_domain) = summary.responsibility_domain {
        ensure!(
            responsibility_domain
                == ResponsibilityDomain::from_classification(&summary.classification),
            "failure-summary.json responsibility_domain {:?} does not match classification {:?}",
            summary.responsibility_domain,
            summary.classification
        );
    }
    Ok(())
}

fn validate_primary_evidence_ref(
    evidence_ref: &str,
    artifact_root: Option<&Path>,
    artifact_path: Option<&Path>,
) -> Result<()> {
    let path = Path::new(evidence_ref);
    ensure!(
        !evidence_ref.trim().is_empty() && path.is_relative(),
        "failure-summary.json primary_evidence_refs must be non-empty relative artifact paths"
    );
    ensure!(
        path.components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "failure-summary.json primary_evidence_refs must stay inside the suite artifact root"
    );
    if let Some(artifact_root) = artifact_root {
        // v2 was originally emitted with case-directory-relative leaf names.
        // Keep those artifacts readable while all new writers use the stable
        // suite-root-relative form, which necessarily includes the case path.
        let legacy_case_relative = path.components().count() == 1;
        let evidence_path = if legacy_case_relative {
            artifact_path
                .and_then(Path::parent)
                .unwrap_or(artifact_root)
                .join(path)
        } else {
            artifact_root.join(path)
        };
        if let Some(artifact_path) = artifact_path {
            ensure!(
                legacy_case_relative || evidence_path != artifact_path,
                "failure-summary.json primary_evidence_refs must not reference the summary itself"
            );
        }
        ensure!(
            evidence_path.is_file(),
            "failure-summary.json primary evidence ref {:?} does not exist under its compatible artifact root",
            evidence_ref
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_written_failure_summary;
    use super::{
        FailureClassification, FailurePhase, FailureSeverity, FailureSummary, ResponsibilityDomain,
        write_failure_summary,
    };
    use crate::{
        fault::checker::RecoveryStabilityClassification, framework::artifacts::ArtifactCollector,
    };
    use serde_json::json;
    use std::{collections::BTreeSet, fs};

    #[test]
    fn final_checker_summary_preserves_list_warning_count_and_samples() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        for classification in [
            RecoveryStabilityClassification::ListUnavailableOrUnknown,
            RecoveryStabilityClassification::DataCorruption,
        ] {
            let case_name = classification.as_str();
            collector
                .write_text(case_name, "checker-report.json", "{}")
                .expect("checker evidence");
            let warnings = vec!["LIST warning b".to_string(), "LIST warning a".to_string()];
            write_failure_summary(
                &collector,
                case_name,
                FailureSummary::from_checker(
                    "io-eio",
                    "checker-verdict",
                    classification,
                    "LIST failed",
                )
                .with_list_warnings(3, warnings),
            )
            .expect("write summary");
            let path = collector.case_dir(case_name).join("failure-summary.json");
            let value: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).expect("summary")).expect("json");
            assert_eq!(value["classification"], classification.as_str());
            assert_eq!(value["final_list_warning_count"], 3);
            assert_eq!(
                value["list_warnings"],
                json!(["LIST warning a", "LIST warning b"])
            );
            assert_eq!(
                value["primary_evidence_refs"],
                json!([format!("{case_name}/checker-report.json")])
            );
            validate_written_failure_summary(dir.path(), &path).expect("valid final summary");
        }
    }

    #[test]
    fn checker_classification_projects_to_s3_model_fields() {
        let summary = FailureSummary::from_checker(
            "io-eio",
            "checker-pre-recommit-verdict",
            RecoveryStabilityClassification::DataCorruption,
            "hash mismatch",
        );

        assert_eq!(summary.phase(), Some(FailurePhase::Checker));
        assert_eq!(summary.s3_model_classification(), Some("data_corruption"));
        assert_eq!(summary.run_failure_reason(), None);
        assert_eq!(
            summary.responsibility_domain(),
            Some(ResponsibilityDomain::Product)
        );

        let value = serde_json::to_value(&summary).expect("summary json");
        assert_eq!(value["schema_version"], json!(2));
        assert_eq!(value["phase"], json!("checker"));
        assert_eq!(value["classification"], json!("data_corruption"));
        assert_eq!(value["s3_model_classification"], json!("data_corruption"));
        assert!(value.get("run_failure_reason").is_none());
        assert_eq!(value["responsibility_domain"], json!("product"));
        assert_eq!(
            value["primary_evidence_refs"],
            json!([
                "recovery-stability-report.json",
                "checker-pre-recommit-report.json",
                "fault-evidence.json",
                "run-events.jsonl"
            ])
        );
    }

    #[test]
    fn typed_checker_classifications_project_to_stable_failure_fields() {
        let cases = [
            (
                RecoveryStabilityClassification::CommittedVersionMissing,
                "committed_version_missing",
                "fail_correctness",
                "failed",
                "unknown",
                Some(true),
                Some(false),
            ),
            (
                RecoveryStabilityClassification::CommittedVersionUnavailable,
                "committed_version_unavailable",
                "fail_availability",
                "unknown",
                "committed_version_unavailable",
                None,
                Some(false),
            ),
            (
                RecoveryStabilityClassification::VersionHashMismatch,
                "version_hash_mismatch",
                "fail_correctness",
                "failed",
                "unknown",
                Some(false),
                Some(true),
            ),
            (
                RecoveryStabilityClassification::DeleteMarkerMissing,
                "delete_marker_missing",
                "fail_correctness",
                "failed",
                "unknown",
                Some(false),
                Some(true),
            ),
            (
                RecoveryStabilityClassification::DeletedObjectResurrected,
                "deleted_object_resurrected",
                "fail_correctness",
                "failed",
                "unknown",
                Some(false),
                Some(true),
            ),
            (
                RecoveryStabilityClassification::DeleteMarkerLineageIncomplete,
                "delete_marker_lineage_incomplete",
                "needs_investigation",
                "unknown",
                "unknown",
                None,
                Some(false),
            ),
            (
                RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite,
                "version_id_missing_on_committed_write",
                "needs_investigation",
                "unknown",
                "unknown",
                None,
                Some(false),
            ),
            (
                RecoveryStabilityClassification::MultipartUploadLineageIncomplete,
                "multipart_upload_lineage_incomplete",
                "needs_investigation",
                "unknown",
                "unknown",
                None,
                Some(false),
            ),
        ];

        for (classification, name, severity, correctness, availability, data_loss, corruption) in
            cases
        {
            let summary = FailureSummary::from_checker(
                "io-eio",
                "checker-verdict",
                classification,
                "checker failed",
            );
            let value = serde_json::to_value(summary).expect("summary json");
            assert_eq!(value["classification"], json!(name), "{name}");
            assert_eq!(value["s3_model_classification"], json!(name), "{name}");
            assert!(value.get("run_failure_reason").is_none(), "{name}");
            assert_eq!(value["severity"], json!(severity), "{name}");
            assert_eq!(value["data_correctness"], json!(correctness), "{name}");
            assert_eq!(value["availability"], json!(availability), "{name}");
            assert_eq!(
                value.get("data_loss").and_then(serde_json::Value::as_bool),
                data_loss,
                "{name}"
            );
            assert_eq!(
                value.get("corruption").and_then(serde_json::Value::as_bool),
                corruption,
                "{name}"
            );
        }
    }

    #[test]
    fn non_checker_failure_projects_to_run_failure_reason() {
        let summary = FailureSummary::new(
            "io-eio",
            "fault-backend-preflight",
            "environment_or_fault_backend",
            "missing chaos mesh",
        )
        .expect("known classification");

        assert_eq!(summary.phase(), Some(FailurePhase::Preflight));
        assert_eq!(summary.s3_model_classification(), None);
        assert_eq!(
            summary.run_failure_reason(),
            Some("environment_or_fault_backend")
        );
        assert_eq!(
            summary.responsibility_domain(),
            Some(ResponsibilityDomain::Unknown)
        );

        let value = serde_json::to_value(&summary).expect("summary json");
        assert_eq!(value["phase"], json!("preflight"));
        assert!(value.get("s3_model_classification").is_none());
        assert_eq!(
            value["run_failure_reason"],
            json!("environment_or_fault_backend")
        );
        assert_eq!(value["responsibility_domain"], json!("unknown"));
    }

    #[test]
    fn old_failure_summary_artifacts_remain_readable() {
        let old = json!({
            "scenario": "io-eio",
            "stage": "checker-pre-recommit-verdict",
            "verdict": "failed",
            "severity": "fail_correctness",
            "classification": "data_corruption",
            "data_correctness": "failed",
            "availability": "unknown",
            "message": "hash mismatch"
        });

        let summary: FailureSummary =
            serde_json::from_value(old).expect("old failure summary should deserialize");

        assert_eq!(summary.phase(), None);
        assert_eq!(summary.s3_model_classification(), None);
        assert_eq!(summary.run_failure_reason(), None);
        assert_eq!(summary.responsibility_domain(), None);
    }

    #[test]
    fn writer_fills_case_name_without_touching_call_sites() {
        let summary = FailureSummary::new("io-eio", "checker-verdict", "data_corruption", "bad")
            .expect("known classification")
            .with_case_name("fault_io_eio_preserves_committed_objects");
        let value = serde_json::to_value(&summary).expect("summary json");

        assert_eq!(
            value["case_name"],
            json!("fault_io_eio_preserves_committed_objects")
        );
    }

    #[test]
    fn writer_classification_allowlist_is_exhaustive_and_unique() {
        let expected = BTreeSet::from([
            "recovery_tail_read_latency",
            "committed_object_unavailable",
            "committed_version_missing",
            "committed_version_unavailable",
            "version_hash_mismatch",
            "delete_marker_missing",
            "deleted_object_resurrected",
            "delete_marker_lineage_incomplete",
            "version_id_missing_on_committed_write",
            "multipart_upload_lineage_incomplete",
            "list_unavailable_or_unknown",
            "data_corruption",
            "ambiguous_write_materialized",
            "harness_error",
            "test_harness",
            "workload_execution_error",
            "artifact_validation_failed",
            "checker_execution_error",
            "preflight_failed",
            "health_guard_failed",
            "fault_backend_unavailable",
            "fault_not_active",
            "fault_not_recovered",
            "unknown",
            "checker_or_environment",
            "test_or_environment",
            "environment_or_fault_backend",
            "product_or_environment",
            "environment_or_workload",
            "workload_or_product",
            "no_signal",
        ]);
        let mut names = BTreeSet::new();
        for classification in FailureClassification::ALL {
            let name = classification.as_str();
            assert!(names.insert(name), "duplicate classification {name}");
            let summary = FailureSummary::new("io-eio", "scenario", name, "failure")
                .expect("allowlisted classification");
            assert_eq!(summary.classification(), name);
            assert_eq!(
                summary.responsibility_domain(),
                Some(classification.responsibility_domain())
            );
            assert_eq!(
                summary.s3_model_classification().is_some(),
                classification.is_s3_model()
            );
            assert_eq!(
                summary.run_failure_reason().is_some(),
                !classification.is_s3_model()
            );
        }
        assert_eq!(names, expected);

        assert!(FailureSummary::new("io-eio", "checker", "data_corrupton", "typo").is_err());
    }

    #[test]
    fn writer_preserves_product_classification_severity() {
        for (classification, severity) in [
            ("recovery_tail_read_latency", FailureSeverity::Degraded),
            (
                "committed_object_unavailable",
                FailureSeverity::FailAvailability,
            ),
            (
                "committed_version_missing",
                FailureSeverity::FailCorrectness,
            ),
            (
                "committed_version_unavailable",
                FailureSeverity::FailAvailability,
            ),
            ("version_hash_mismatch", FailureSeverity::FailCorrectness),
            ("delete_marker_missing", FailureSeverity::FailCorrectness),
            (
                "deleted_object_resurrected",
                FailureSeverity::FailCorrectness,
            ),
            (
                "delete_marker_lineage_incomplete",
                FailureSeverity::NeedsInvestigation,
            ),
            (
                "version_id_missing_on_committed_write",
                FailureSeverity::NeedsInvestigation,
            ),
            (
                "multipart_upload_lineage_incomplete",
                FailureSeverity::NeedsInvestigation,
            ),
            (
                "list_unavailable_or_unknown",
                FailureSeverity::FailAvailability,
            ),
            ("data_corruption", FailureSeverity::FailCorrectness),
            (
                "ambiguous_write_materialized",
                FailureSeverity::NeedsInvestigation,
            ),
        ] {
            let summary = FailureSummary::new("io-eio", "checker", classification, "failure")
                .expect("allowlisted product classification");
            assert_eq!(summary.severity(), severity, "{classification}");
            assert_eq!(
                summary.responsibility_domain(),
                Some(ResponsibilityDomain::Product)
            );
        }
    }

    #[test]
    fn writer_emits_suite_root_relative_primary_evidence_without_self_reference() {
        let dir = tempfile::tempdir().expect("tempdir");
        let suite_root = dir.path().join("suite");
        let attempt_root = suite_root.join("001-io-eio-r1");
        let case_name = "fault_io_eio_preserves_committed_objects";
        let case_dir = attempt_root.join(case_name);
        fs::create_dir_all(&case_dir).expect("case dir");
        for artifact in [
            "recovery-stability-report.json",
            "checker-pre-recommit-report.json",
            "fault-evidence.json",
            "run-events.jsonl",
        ] {
            fs::write(case_dir.join(artifact), "{}").expect("evidence");
        }
        let collector = ArtifactCollector::with_reference_root(&attempt_root, &suite_root)
            .expect("collector roots");

        write_failure_summary(
            &collector,
            case_name,
            FailureSummary::new(
                "io-eio",
                "checker-pre-recommit-verdict",
                "data_corruption",
                "hash mismatch",
            )
            .expect("known classification"),
        )
        .expect("write failure summary");

        let raw = fs::read_to_string(case_dir.join("failure-summary.json")).expect("summary");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("summary json");
        assert_eq!(
            value["primary_evidence_refs"],
            json!([
                format!("001-io-eio-r1/{case_name}/recovery-stability-report.json"),
                format!("001-io-eio-r1/{case_name}/checker-pre-recommit-report.json"),
                format!("001-io-eio-r1/{case_name}/fault-evidence.json"),
                format!("001-io-eio-r1/{case_name}/run-events.jsonl")
            ])
        );
        assert!(
            value["observed_at_ms"]
                .as_u64()
                .is_some_and(|value| value > 0)
        );
        assert!(
            value["primary_evidence_refs"]
                .as_array()
                .expect("refs")
                .iter()
                .all(|value| !value
                    .as_str()
                    .expect("ref")
                    .ends_with("failure-summary.json"))
        );
    }
}
