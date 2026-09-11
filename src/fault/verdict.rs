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
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const FAILURE_SUMMARY_SCHEMA_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStabilityClassification {
    DataCorruption,
    CommittedObjectUnavailable,
    CommittedVersionMissing,
    CommittedVersionUnavailable,
    VersionHashMismatch,
    DeleteMarkerMissing,
    DeletedObjectResurrected,
    DeleteMarkerLineageIncomplete,
    VersionIdMissingOnCommittedWrite,
    MultipartUploadLineageIncomplete,
    ListUnavailableOrUnknown,
    ListedKeyUnreadable,
    UnexpectedListedObject,
    RecoveryTailReadLatency,
    AmbiguousWriteMaterialized,
    HarnessError,
}

impl RecoveryStabilityClassification {
    pub(crate) fn as_str(self) -> &'static str {
        FailureClassification::from(self).as_str()
    }

    pub(crate) fn from_classification_evidence(evidence: &str) -> Option<Self> {
        if evidence.starts_with("missing_committed_version:") {
            Some(Self::CommittedVersionMissing)
        } else if evidence.starts_with("unavailable_committed_version:") {
            Some(Self::CommittedVersionUnavailable)
        } else if evidence.starts_with("version_hash_mismatch:") {
            Some(Self::VersionHashMismatch)
        } else if evidence.starts_with("missing_committed_delete_marker:") {
            Some(Self::DeleteMarkerMissing)
        } else if evidence.starts_with("resurrected_deleted_object:") {
            Some(Self::DeletedObjectResurrected)
        } else if evidence.starts_with("delete_marker_lineage_incomplete:") {
            Some(Self::DeleteMarkerLineageIncomplete)
        } else if evidence.starts_with("committed_write_missing_version_id:")
            || evidence.starts_with("committed_writes_missing_version_id_count:")
        {
            Some(Self::VersionIdMissingOnCommittedWrite)
        } else if evidence.starts_with("multipart_upload_lineage_incomplete:") {
            Some(Self::MultipartUploadLineageIncomplete)
        } else if evidence.starts_with("listed_key_unreadable:") {
            Some(Self::ListedKeyUnreadable)
        } else if evidence.starts_with("unexpected_listed_object:") {
            Some(Self::UnexpectedListedObject)
        } else {
            None
        }
    }

    pub(crate) fn matches_classification_evidence(self, evidence: &str) -> bool {
        Self::from_classification_evidence(evidence) == Some(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureVerdict {
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureSeverity {
    Degraded,
    FailAvailability,
    FailCorrectness,
    Infra,
    NeedsInvestigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum FailurePhase {
    Preflight,
    Setup,
    FaultInjection,
    Workload,
    Recovery,
    Checker,
    Cleanup,
    Runner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ResponsibilityDomain {
    Product,
    Harness,
    Environment,
    FaultBackend,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCorrectnessStatus {
    Passed,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityStatus {
    RecoveredAfterTailLatency,
    CommittedObjectUnavailable,
    CommittedVersionUnavailable,
    ListUnavailableOrUnknown,
    /// The service itself is degraded after the fault: RustFS drives or
    /// readiness did not recover, or S3 mutations and reads failed when the
    /// scenario required them to succeed.
    ServiceDegraded,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClassification {
    RecoveryTailReadLatency,
    CommittedObjectUnavailable,
    CommittedVersionMissing,
    CommittedVersionUnavailable,
    VersionHashMismatch,
    DeleteMarkerMissing,
    DeletedObjectResurrected,
    DeleteMarkerLineageIncomplete,
    VersionIdMissingOnCommittedWrite,
    MultipartUploadLineageIncomplete,
    ListUnavailableOrUnknown,
    ListedKeyUnreadable,
    UnexpectedListedObject,
    DataCorruption,
    AmbiguousWriteMaterialized,
    RecoveryHealthDegraded,
    PostRecoveryWriteFailed,
    AvailabilityRegression,
    HarnessError,
    TestHarness,
    WorkloadExecutionError,
    ArtifactValidationFailed,
    CheckerExecutionError,
    PreflightFailed,
    HealthGuardFailed,
    FaultBackendUnavailable,
    FaultNotActive,
    FaultNotRecovered,
    Unknown,
    CheckerOrEnvironment,
    TestOrEnvironment,
    EnvironmentOrFaultBackend,
    ProductOrEnvironment,
    EnvironmentOrWorkload,
    WorkloadOrProduct,
    NoSignal,
}

impl FailureClassification {
    pub(crate) const ALL: [Self; 36] = [
        Self::RecoveryTailReadLatency,
        Self::CommittedObjectUnavailable,
        Self::CommittedVersionMissing,
        Self::CommittedVersionUnavailable,
        Self::VersionHashMismatch,
        Self::DeleteMarkerMissing,
        Self::DeletedObjectResurrected,
        Self::DeleteMarkerLineageIncomplete,
        Self::VersionIdMissingOnCommittedWrite,
        Self::MultipartUploadLineageIncomplete,
        Self::ListUnavailableOrUnknown,
        Self::ListedKeyUnreadable,
        Self::UnexpectedListedObject,
        Self::DataCorruption,
        Self::AmbiguousWriteMaterialized,
        Self::RecoveryHealthDegraded,
        Self::PostRecoveryWriteFailed,
        Self::AvailabilityRegression,
        Self::HarnessError,
        Self::TestHarness,
        Self::WorkloadExecutionError,
        Self::ArtifactValidationFailed,
        Self::CheckerExecutionError,
        Self::PreflightFailed,
        Self::HealthGuardFailed,
        Self::FaultBackendUnavailable,
        Self::FaultNotActive,
        Self::FaultNotRecovered,
        Self::Unknown,
        Self::CheckerOrEnvironment,
        Self::TestOrEnvironment,
        Self::EnvironmentOrFaultBackend,
        Self::ProductOrEnvironment,
        Self::EnvironmentOrWorkload,
        Self::WorkloadOrProduct,
        Self::NoSignal,
    ];

    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|classification| classification.as_str() == name)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecoveryTailReadLatency => "recovery_tail_read_latency",
            Self::CommittedObjectUnavailable => "committed_object_unavailable",
            Self::CommittedVersionMissing => "committed_version_missing",
            Self::CommittedVersionUnavailable => "committed_version_unavailable",
            Self::VersionHashMismatch => "version_hash_mismatch",
            Self::DeleteMarkerMissing => "delete_marker_missing",
            Self::DeletedObjectResurrected => "deleted_object_resurrected",
            Self::DeleteMarkerLineageIncomplete => "delete_marker_lineage_incomplete",
            Self::VersionIdMissingOnCommittedWrite => "version_id_missing_on_committed_write",
            Self::MultipartUploadLineageIncomplete => "multipart_upload_lineage_incomplete",
            Self::ListUnavailableOrUnknown => "list_unavailable_or_unknown",
            Self::ListedKeyUnreadable => "listed_key_unreadable",
            Self::UnexpectedListedObject => "unexpected_listed_object",
            Self::DataCorruption => "data_corruption",
            Self::AmbiguousWriteMaterialized => "ambiguous_write_materialized",
            Self::RecoveryHealthDegraded => "recovery_health_degraded",
            Self::PostRecoveryWriteFailed => "post_recovery_write_failed",
            Self::AvailabilityRegression => "availability_regression",
            Self::HarnessError => "harness_error",
            Self::TestHarness => "test_harness",
            Self::WorkloadExecutionError => "workload_execution_error",
            Self::ArtifactValidationFailed => "artifact_validation_failed",
            Self::CheckerExecutionError => "checker_execution_error",
            Self::PreflightFailed => "preflight_failed",
            Self::HealthGuardFailed => "health_guard_failed",
            Self::FaultBackendUnavailable => "fault_backend_unavailable",
            Self::FaultNotActive => "fault_not_active",
            Self::FaultNotRecovered => "fault_not_recovered",
            Self::Unknown => "unknown",
            Self::CheckerOrEnvironment => "checker_or_environment",
            Self::TestOrEnvironment => "test_or_environment",
            Self::EnvironmentOrFaultBackend => "environment_or_fault_backend",
            Self::ProductOrEnvironment => "product_or_environment",
            Self::EnvironmentOrWorkload => "environment_or_workload",
            Self::WorkloadOrProduct => "workload_or_product",
            Self::NoSignal => "no_signal",
        }
    }

    pub const fn is_s3_model(self) -> bool {
        matches!(
            self,
            Self::RecoveryTailReadLatency
                | Self::CommittedObjectUnavailable
                | Self::CommittedVersionMissing
                | Self::CommittedVersionUnavailable
                | Self::VersionHashMismatch
                | Self::DeleteMarkerMissing
                | Self::DeletedObjectResurrected
                | Self::DeleteMarkerLineageIncomplete
                | Self::VersionIdMissingOnCommittedWrite
                | Self::MultipartUploadLineageIncomplete
                | Self::ListUnavailableOrUnknown
                | Self::ListedKeyUnreadable
                | Self::UnexpectedListedObject
                | Self::DataCorruption
                | Self::AmbiguousWriteMaterialized
        )
    }

    pub const fn responsibility_domain(self) -> ResponsibilityDomain {
        match self {
            Self::RecoveryTailReadLatency
            | Self::CommittedObjectUnavailable
            | Self::CommittedVersionMissing
            | Self::CommittedVersionUnavailable
            | Self::VersionHashMismatch
            | Self::DeleteMarkerMissing
            | Self::DeletedObjectResurrected
            | Self::DeleteMarkerLineageIncomplete
            | Self::VersionIdMissingOnCommittedWrite
            | Self::MultipartUploadLineageIncomplete
            | Self::ListUnavailableOrUnknown
            | Self::ListedKeyUnreadable
            | Self::UnexpectedListedObject
            | Self::DataCorruption
            | Self::AmbiguousWriteMaterialized
            | Self::RecoveryHealthDegraded
            | Self::PostRecoveryWriteFailed
            | Self::AvailabilityRegression => ResponsibilityDomain::Product,
            Self::HarnessError
            | Self::TestHarness
            | Self::WorkloadExecutionError
            | Self::ArtifactValidationFailed
            | Self::CheckerExecutionError => ResponsibilityDomain::Harness,
            Self::PreflightFailed | Self::HealthGuardFailed => ResponsibilityDomain::Environment,
            Self::FaultBackendUnavailable | Self::FaultNotActive | Self::FaultNotRecovered => {
                ResponsibilityDomain::FaultBackend
            }
            Self::Unknown
            | Self::CheckerOrEnvironment
            | Self::TestOrEnvironment
            | Self::EnvironmentOrFaultBackend
            | Self::ProductOrEnvironment
            | Self::EnvironmentOrWorkload
            | Self::WorkloadOrProduct
            | Self::NoSignal => ResponsibilityDomain::Unknown,
        }
    }

    pub const fn severity(self) -> FailureSeverity {
        match self {
            Self::RecoveryTailReadLatency => FailureSeverity::Degraded,
            Self::CommittedObjectUnavailable
            | Self::CommittedVersionUnavailable
            | Self::ListUnavailableOrUnknown
            | Self::RecoveryHealthDegraded
            | Self::PostRecoveryWriteFailed
            | Self::AvailabilityRegression => FailureSeverity::FailAvailability,
            Self::CommittedVersionMissing
            | Self::VersionHashMismatch
            | Self::DeleteMarkerMissing
            | Self::DeletedObjectResurrected
            | Self::ListedKeyUnreadable
            | Self::UnexpectedListedObject
            | Self::DataCorruption => FailureSeverity::FailCorrectness,
            Self::HarnessError
            | Self::TestHarness
            | Self::TestOrEnvironment
            | Self::EnvironmentOrFaultBackend => FailureSeverity::Infra,
            Self::AmbiguousWriteMaterialized
            | Self::DeleteMarkerLineageIncomplete
            | Self::VersionIdMissingOnCommittedWrite
            | Self::MultipartUploadLineageIncomplete
            | Self::WorkloadExecutionError
            | Self::ArtifactValidationFailed
            | Self::CheckerExecutionError
            | Self::PreflightFailed
            | Self::HealthGuardFailed
            | Self::FaultBackendUnavailable
            | Self::FaultNotActive
            | Self::FaultNotRecovered
            | Self::Unknown
            | Self::CheckerOrEnvironment
            | Self::ProductOrEnvironment
            | Self::EnvironmentOrWorkload
            | Self::WorkloadOrProduct
            | Self::NoSignal => FailureSeverity::NeedsInvestigation,
        }
    }
}

impl From<RecoveryStabilityClassification> for FailureClassification {
    fn from(classification: RecoveryStabilityClassification) -> Self {
        match classification {
            RecoveryStabilityClassification::DataCorruption => Self::DataCorruption,
            RecoveryStabilityClassification::CommittedObjectUnavailable => {
                Self::CommittedObjectUnavailable
            }
            RecoveryStabilityClassification::CommittedVersionMissing => {
                Self::CommittedVersionMissing
            }
            RecoveryStabilityClassification::CommittedVersionUnavailable => {
                Self::CommittedVersionUnavailable
            }
            RecoveryStabilityClassification::VersionHashMismatch => Self::VersionHashMismatch,
            RecoveryStabilityClassification::DeleteMarkerMissing => Self::DeleteMarkerMissing,
            RecoveryStabilityClassification::DeletedObjectResurrected => {
                Self::DeletedObjectResurrected
            }
            RecoveryStabilityClassification::DeleteMarkerLineageIncomplete => {
                Self::DeleteMarkerLineageIncomplete
            }
            RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite => {
                Self::VersionIdMissingOnCommittedWrite
            }
            RecoveryStabilityClassification::MultipartUploadLineageIncomplete => {
                Self::MultipartUploadLineageIncomplete
            }
            RecoveryStabilityClassification::ListUnavailableOrUnknown => {
                Self::ListUnavailableOrUnknown
            }
            RecoveryStabilityClassification::ListedKeyUnreadable => Self::ListedKeyUnreadable,
            RecoveryStabilityClassification::UnexpectedListedObject => Self::UnexpectedListedObject,
            RecoveryStabilityClassification::RecoveryTailReadLatency => {
                Self::RecoveryTailReadLatency
            }
            RecoveryStabilityClassification::AmbiguousWriteMaterialized => {
                Self::AmbiguousWriteMaterialized
            }
            RecoveryStabilityClassification::HarnessError => Self::HarnessError,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct FailureClassificationDetails {
    data_correctness: DataCorrectnessStatus,
    availability: AvailabilityStatus,
    data_loss: Option<bool>,
    corruption: Option<bool>,
    recovered_within_window: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct FailureSummary {
    #[serde(default)]
    pub(crate) schema_version: u8,
    pub(crate) scenario: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) case_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) observed_at_ms: Option<u64>,
    pub(crate) stage: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) phase: Option<FailurePhase>,
    pub(crate) verdict: FailureVerdict,
    pub(crate) severity: FailureSeverity,
    pub(crate) classification: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) s3_model_classification: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) run_failure_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) responsibility_domain: Option<ResponsibilityDomain>,
    pub(crate) data_correctness: DataCorrectnessStatus,
    pub(crate) availability: AvailabilityStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) primary_evidence_refs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) evidence_classifications: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub(crate) final_list_warning_count: usize,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) list_warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data_loss: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) corruption: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovered_within_window: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovered_within_seconds: Option<u64>,
    pub(crate) message: String,
}

impl FailureSummary {
    pub(crate) fn validate_classification_projection(&self) -> Result<()> {
        let classification = FailureClassification::from_name(&self.classification)
            .context("failure-summary.json has an unknown classification")?;
        let details = FailureClassificationDetails::from_classification(classification);
        ensure!(
            self.severity == classification.severity()
                && self.data_correctness == details.data_correctness
                && self.availability == details.availability
                && self.data_loss == details.data_loss
                && self.corruption == details.corruption
                && self.recovered_within_window == details.recovered_within_window,
            "failure-summary.json outcome fields contradict classification {}",
            self.classification
        );
        Ok(())
    }

    pub(crate) fn new(
        scenario: impl Into<String>,
        stage: impl Into<String>,
        classification: impl AsRef<str>,
        message: impl Into<String>,
    ) -> Result<Self> {
        let stage = stage.into();
        let classification_name = classification.as_ref();
        let classification =
            FailureClassification::from_name(classification_name).with_context(|| {
                format!(
                    "failure classification {classification_name:?} is not in the writer allowlist"
                )
            })?;
        Ok(Self::from_classification(
            scenario,
            stage,
            classification,
            message,
        ))
    }

    pub(crate) fn from_checker(
        scenario: impl Into<String>,
        stage: impl Into<String>,
        classification: RecoveryStabilityClassification,
        message: impl Into<String>,
    ) -> Self {
        let classification = FailureClassification::from(classification);
        let mut summary =
            Self::from_classification(scenario, stage.into(), classification, message);
        summary.evidence_classifications = vec![classification.as_str().to_string()];
        summary
    }

    fn from_classification(
        scenario: impl Into<String>,
        stage: String,
        classification: FailureClassification,
        message: impl Into<String>,
    ) -> Self {
        let details = FailureClassificationDetails::from_classification(classification);
        let phase = FailurePhase::from_stage(&stage);
        let projection = FailureV2Projection::from_classification(classification);
        Self {
            schema_version: FAILURE_SUMMARY_SCHEMA_VERSION,
            run_id: None,
            scenario: scenario.into(),
            case_name: None,
            observed_at_ms: Some(now_ms()),
            stage: stage.clone(),
            phase: Some(phase),
            verdict: FailureVerdict::Failed,
            severity: classification.severity(),
            classification: classification.as_str().to_string(),
            s3_model_classification: projection.s3_model_classification,
            run_failure_reason: projection.run_failure_reason,
            responsibility_domain: Some(projection.responsibility_domain),
            data_correctness: details.data_correctness,
            availability: details.availability,
            primary_evidence_refs: primary_evidence_refs_for(&stage, phase),
            evidence_classifications: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            data_loss: details.data_loss,
            corruption: details.corruption,
            recovered_within_window: details.recovered_within_window,
            recovered_within_seconds: None,
            message: message.into(),
        }
    }

    pub(crate) fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    pub(crate) fn with_case_name(mut self, case_name: &str) -> Self {
        if self.case_name.is_none() {
            self.case_name = Some(case_name.to_string());
        }
        self
    }

    pub(crate) fn with_recovered_within_seconds(mut self, seconds: Option<u64>) -> Self {
        self.recovered_within_seconds = seconds;
        self
    }

    pub(crate) fn with_evidence_classifications(
        mut self,
        classifications: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.evidence_classifications = classifications.into_iter().map(Into::into).collect();
        self.evidence_classifications.sort();
        self.evidence_classifications.dedup();
        self
    }

    pub(crate) fn with_list_warnings(
        mut self,
        final_list_warning_count: usize,
        warnings: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.final_list_warning_count = final_list_warning_count;
        self.list_warnings = warnings.into_iter().map(Into::into).collect();
        self.list_warnings.sort();
        self.list_warnings.dedup();
        self
    }

    pub(crate) fn severity(&self) -> FailureSeverity {
        self.severity
    }

    pub(crate) fn phase(&self) -> Option<FailurePhase> {
        self.phase
    }

    pub(crate) fn classification(&self) -> &str {
        &self.classification
    }

    pub(crate) fn s3_model_classification(&self) -> Option<&str> {
        self.s3_model_classification.as_deref()
    }

    pub(crate) fn run_failure_reason(&self) -> Option<&str> {
        self.run_failure_reason.as_deref()
    }

    pub(crate) fn responsibility_domain(&self) -> Option<ResponsibilityDomain> {
        self.responsibility_domain
    }

    pub(crate) fn primary_evidence_refs(&self) -> &[String] {
        &self.primary_evidence_refs
    }

    pub(crate) fn evidence_classifications(&self) -> &[String] {
        &self.evidence_classifications
    }
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

#[derive(Debug, Clone)]
struct FailureV2Projection {
    pub(crate) s3_model_classification: Option<String>,
    run_failure_reason: Option<String>,
    responsibility_domain: ResponsibilityDomain,
}

impl FailureV2Projection {
    fn from_classification(classification: FailureClassification) -> Self {
        if classification.is_s3_model() {
            return Self {
                s3_model_classification: Some(classification.as_str().to_string()),
                run_failure_reason: None,
                responsibility_domain: ResponsibilityDomain::Product,
            };
        }

        Self {
            s3_model_classification: None,
            run_failure_reason: Some(classification.as_str().to_string()),
            responsibility_domain: classification.responsibility_domain(),
        }
    }
}

impl ResponsibilityDomain {
    pub(crate) fn from_classification(classification: &str) -> Self {
        FailureClassification::from_name(classification)
            .map(FailureClassification::responsibility_domain)
            .unwrap_or(Self::Unknown)
    }
}

impl FailurePhase {
    pub(crate) fn from_stage(stage: &str) -> Self {
        match stage {
            "scenario" | "fault-backend-preflight" | "fault-backend-pre-cleanup" => Self::Preflight,
            "fixture-prepare"
            | "tenant-ready-before-fault"
            | "pod-stability-before-fault"
            | "initial-s3-access"
            | "s3-endpoint"
            | "s3-client"
            | "bucket-create"
            | "prefill"
            | "pod-identity-before-fault" => Self::Setup,
            "fault-apply" | "wait-active" | "fault-snapshot-active" | "active-snapshot-failed" => {
                Self::FaultInjection
            }
            "s3-access-under-fault"
            | "warp-workload"
            | "mixed-workload"
            | "post-warp-s3-access"
            | "post-warp-port-forward-failed"
            | "fault-evidence"
            | "workload-no-fault-evidence"
            | "fault-still-active"
            | "workload-outlived-fault"
            | "fault-snapshot-after-workload"
            | "after-workload-snapshot-failed" => Self::Workload,
            "fault-delete" => Self::Cleanup,
            "tenant-recovery"
            | "pod-stability-after-recovery"
            | "s3-access-after-recovery"
            | "recovery-health"
            | "recovery-evidence"
            | "post-recovery-write"
            | "recommit-unconfirmed" => Self::Recovery,
            "availability-endpoint" | "availability-read-probe" | "availability" => Self::Workload,
            "checker-pre-recommit"
            | "checker-pre-recommit-verdict"
            | "checker-final"
            | "checker-verdict" => Self::Checker,
            _ if stage.contains("preflight") => Self::Preflight,
            _ if stage.starts_with("checker") || stage.ends_with("-verdict") => Self::Checker,
            _ if stage.contains("cleanup") || stage.ends_with("-delete") => Self::Cleanup,
            _ => Self::Runner,
        }
    }
}

fn primary_evidence_refs_for(stage: &str, phase: FailurePhase) -> Vec<String> {
    let mut refs = Vec::new();

    match phase {
        FailurePhase::Checker => {
            if stage == "checker-pre-recommit" {
                push_unique(&mut refs, "recovery-stability-report.json");
                push_unique(&mut refs, "checker-pre-recommit-error.txt");
            } else if stage.contains("pre-recommit") {
                push_unique(&mut refs, "recovery-stability-report.json");
                push_unique(&mut refs, "checker-pre-recommit-report.json");
            } else if stage == "checker-final" {
                push_unique(&mut refs, "checker-final-error.txt");
            } else {
                push_unique(&mut refs, "checker-report.json");
            }
            push_unique(&mut refs, "fault-evidence.json");
        }
        FailurePhase::Recovery if stage == "recommit-unconfirmed" => {
            push_unique(&mut refs, "fault-evidence.json");
        }
        FailurePhase::Recovery if stage == "recovery-health" => {
            push_unique(&mut refs, "recovery-health.json");
            push_unique(&mut refs, "fault-evidence.json");
        }
        FailurePhase::Recovery if stage == "post-recovery-write" => {
            push_unique(&mut refs, "post-recovery-write-report.json");
            push_unique(&mut refs, "post-recovery-write-history.jsonl");
        }
        FailurePhase::Workload if stage == "availability-read-probe" || stage == "availability" => {
            push_unique(&mut refs, "availability-report.json");
            push_unique(&mut refs, "workload-summary.json");
        }
        FailurePhase::Preflight
        | FailurePhase::Setup
        | FailurePhase::FaultInjection
        | FailurePhase::Workload
        | FailurePhase::Recovery
        | FailurePhase::Cleanup
        | FailurePhase::Runner => {}
    }

    push_unique(&mut refs, "run-events.jsonl");
    refs.truncate(5);
    refs
}

fn push_unique(refs: &mut Vec<String>, artifact: &str) {
    if !refs.iter().any(|item| item == artifact) {
        refs.push(artifact.to_string());
    }
}

impl FailureClassificationDetails {
    fn from_classification(classification: FailureClassification) -> Self {
        match classification {
            FailureClassification::RecoveryTailReadLatency => Self {
                data_correctness: DataCorrectnessStatus::Passed,
                availability: AvailabilityStatus::RecoveredAfterTailLatency,
                data_loss: Some(false),
                corruption: Some(false),
                recovered_within_window: Some(true),
            },
            FailureClassification::CommittedObjectUnavailable => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::CommittedObjectUnavailable,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::CommittedVersionMissing => Self {
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: Some(true),
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::CommittedVersionUnavailable => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::CommittedVersionUnavailable,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::VersionHashMismatch
            | FailureClassification::DeleteMarkerMissing
            | FailureClassification::DeletedObjectResurrected
            | FailureClassification::ListedKeyUnreadable
            | FailureClassification::UnexpectedListedObject => Self {
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: Some(false),
                corruption: Some(true),
                recovered_within_window: None,
            },
            FailureClassification::RecoveryHealthDegraded
            | FailureClassification::PostRecoveryWriteFailed
            | FailureClassification::AvailabilityRegression => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::ServiceDegraded,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::DeleteMarkerLineageIncomplete
            | FailureClassification::VersionIdMissingOnCommittedWrite
            | FailureClassification::MultipartUploadLineageIncomplete => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: None,
            },
            FailureClassification::ListUnavailableOrUnknown => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::ListUnavailableOrUnknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: Some(false),
            },
            FailureClassification::DataCorruption => Self {
                data_correctness: DataCorrectnessStatus::Failed,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(true),
                recovered_within_window: None,
            },
            FailureClassification::AmbiguousWriteMaterialized => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: Some(false),
                recovered_within_window: None,
            },
            FailureClassification::HarnessError
            | FailureClassification::TestHarness
            | FailureClassification::TestOrEnvironment
            | FailureClassification::EnvironmentOrFaultBackend => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: None,
                recovered_within_window: None,
            },
            FailureClassification::WorkloadExecutionError
            | FailureClassification::ArtifactValidationFailed
            | FailureClassification::CheckerExecutionError
            | FailureClassification::PreflightFailed
            | FailureClassification::HealthGuardFailed
            | FailureClassification::FaultBackendUnavailable
            | FailureClassification::FaultNotActive
            | FailureClassification::FaultNotRecovered
            | FailureClassification::Unknown
            | FailureClassification::CheckerOrEnvironment
            | FailureClassification::ProductOrEnvironment
            | FailureClassification::EnvironmentOrWorkload
            | FailureClassification::WorkloadOrProduct
            | FailureClassification::NoSignal => Self {
                data_correctness: DataCorrectnessStatus::Unknown,
                availability: AvailabilityStatus::Unknown,
                data_loss: None,
                corruption: None,
                recovered_within_window: None,
            },
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
