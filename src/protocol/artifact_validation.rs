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
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Component, Path};

use crate::protocol::{
    fixture::registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    preflight::ProtocolPreflightSummary,
    reporting::{
        PROTOCOL_FLAKE_HISTORY_FILE, PROTOCOL_JUNIT_FILE, ProtocolArtifactValidationReport,
        ProtocolCaseOutcome, ProtocolCaseReport, ProtocolCaseStatus, ProtocolCleanupReport,
        ProtocolFailureSummary, ProtocolFlakeHistory, ProtocolSuiteSummary, protocol_flake_signals,
        protocol_flake_status, protocol_junit_xml,
    },
    runner::artifacts::ProtocolArtifactWriter,
    suite_plan::{ProtocolSuitePlan, ProtocolSuitePlanCaseContract},
};

pub const PROTOCOL_ARTIFACT_VALIDATION_REPORT: &str = "protocol-artifact-validation-report.json";
const MAX_FILES: usize = 10_000;
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const LEGACY_COMPATIBILITY_COVERAGE_FILE: &str = "compatibility-coverage.json";
const LEGACY_COMPATIBILITY_COVERAGE_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
const LEGACY_COMPATIBILITY_COVERAGE_KIND: &str = "ProtocolCompatibilityCoverageReport";

#[derive(Debug, serde::Deserialize)]
struct LegacyCompatibilityCoverageEnvelope {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
}

pub fn validate_protocol_artifacts_and_write_report(
    root: impl AsRef<Path>,
    forbidden_material: &[String],
) -> Result<ProtocolArtifactValidationReport> {
    let root = root.as_ref();
    let mut checked_files = 0;
    let validation = validate_contract(root, forbidden_material, &mut checked_files);
    let errors = validation
        .as_ref()
        .err()
        .map(|error| vec![error.to_string()])
        .unwrap_or_default();
    let report = ProtocolArtifactValidationReport {
        api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
        kind: "ProtocolArtifactValidationReport".to_string(),
        artifact_root: root.display().to_string(),
        valid: validation.is_ok(),
        checked_files,
        errors,
    };
    ProtocolArtifactWriter::file(root).write_json(PROTOCOL_ARTIFACT_VALIDATION_REPORT, &report)?;
    if let Err(error) = validation {
        bail!(
            "protocol artifact validation failed: {error}; report: {}",
            root.join(PROTOCOL_ARTIFACT_VALIDATION_REPORT).display()
        );
    }
    Ok(report)
}

fn validate_contract(
    root: &Path,
    forbidden_material: &[String],
    checked_files: &mut usize,
) -> Result<()> {
    ensure!(root.is_dir(), "protocol artifact root is not a directory");
    ensure!(
        !root
            .components()
            .any(|component| component.as_os_str() == "fault-tests"),
        "protocol artifacts must not be written under a fault-tests directory"
    );
    for name in [
        "protocol-suite.yaml",
        "protocol-suite-plan.json",
        "preflight-summary.json",
        RESOURCE_REGISTRY_FILE,
        "cleanup-report.json",
        PROTOCOL_FLAKE_HISTORY_FILE,
        PROTOCOL_JUNIT_FILE,
        "protocol-suite-summary.json",
    ] {
        ensure!(
            root.join(name).is_file(),
            "required protocol artifact {name} is missing"
        );
    }

    let plan: ProtocolSuitePlan = read_json(&root.join("protocol-suite-plan.json"))?;
    let preflight: ProtocolPreflightSummary = read_json(&root.join("preflight-summary.json"))?;
    let registry = ResourceRegistry::load(root)?;
    let cleanup: ProtocolCleanupReport = read_json(&root.join("cleanup-report.json"))?;
    let flake_history: ProtocolFlakeHistory = read_json(&root.join(PROTOCOL_FLAKE_HISTORY_FILE))?;
    let summary: ProtocolSuiteSummary = read_json(&root.join("protocol-suite-summary.json"))?;
    ensure!(
        Path::new(&plan.artifact_root) == root,
        "protocol plan artifact root does not match the validated directory"
    );
    ensure!(
        plan.target.fingerprint == preflight.target_fingerprint
            && plan.target.fingerprint == registry.target_fingerprint,
        "protocol target fingerprint differs across plan, preflight, and registry"
    );
    ensure!(
        plan.run_id == registry.run_id && plan.run_id == summary.run_id,
        "protocol run id differs across plan, registry, and summary"
    );
    ensure!(
        plan.profile == summary.profile
            && plan.target.fingerprint.sha256 == summary.target_fingerprint
            && plan.preflight.capability_matrix == preflight.capability_matrix
            && preflight.capability_matrix == summary.capability_matrix,
        "protocol profile, target fingerprint, or capability matrix differs across artifacts"
    );
    ensure!(
        summary.plan == "protocol-suite-plan.json"
            && summary.preflight == "preflight-summary.json"
            && summary.registry == RESOURCE_REGISTRY_FILE
            && summary.cleanup == "cleanup-report.json"
            && summary.flaky_history == PROTOCOL_FLAKE_HISTORY_FILE,
        "protocol suite summary contains invalid artifact references"
    );
    if let Some(path) = &summary.compatibility_coverage {
        ensure!(
            path == LEGACY_COMPATIBILITY_COVERAGE_FILE,
            "protocol suite summary contains an invalid legacy compatibility coverage reference"
        );
        validate_legacy_compatibility_coverage(&root.join(path))?;
    }

    let selected_cases = plan
        .cases
        .iter()
        .map(|case| case.id.clone())
        .collect::<Vec<_>>();
    ensure!(
        selected_cases == preflight.selected_cases,
        "protocol selected cases differ between plan and preflight"
    );
    let required_capabilities = plan
        .cases
        .iter()
        .flat_map(|case| case.requires.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let checked_capabilities = preflight
        .capability_matrix
        .iter()
        .map(|check| check.capability.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        required_capabilities == checked_capabilities
            && checked_capabilities.len() == preflight.capability_matrix.len(),
        "protocol capability matrix does not exactly cover planned requirements"
    );
    ensure!(
        summary.case_reports.len() == selected_cases.len()
            && summary.case_results.len() == selected_cases.len(),
        "protocol suite summary case report count differs from the plan"
    );
    let mut case_reports = Vec::new();
    let mut case_cleanups = Vec::new();
    for (planned_case, report_path) in plan.cases.iter().zip(&summary.case_reports) {
        let case_id = &planned_case.id;
        let report_path = safe_relative_path(report_path)?;
        let report: ProtocolCaseReport = read_json(&root.join(report_path))?;
        validate_evidence_paths(root, &report.evidence)?;
        ensure!(
            &report.case_id == case_id,
            "case report id {} does not match planned case {case_id}",
            report.case_id
        );
        let expected_variant = planned_case
            .contract
            .as_ref()
            .map(|contract| contract.variant_id.as_str())
            .unwrap_or(crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT);
        ensure!(
            report.variant_id == expected_variant,
            "case report variant {} does not match planned case {case_id} variant {expected_variant}",
            report.variant_id
        );
        ensure!(
            matches!(
                (report.status, report.outcome),
                (ProtocolCaseStatus::Passed, ProtocolCaseOutcome::Passed)
                    | (
                        ProtocolCaseStatus::Passed,
                        ProtocolCaseOutcome::CapabilitySkipped
                    )
                    | (
                        ProtocolCaseStatus::Passed,
                        ProtocolCaseOutcome::ExpectedDivergence
                    )
                    | (
                        ProtocolCaseStatus::Skipped,
                        ProtocolCaseOutcome::CapabilitySkipped
                    )
                    | (ProtocolCaseStatus::Failed, ProtocolCaseOutcome::Failed)
                    | (ProtocolCaseStatus::Failed, ProtocolCaseOutcome::NotRun)
            ),
            "case {case_id} status and outcome disagree"
        );
        let reproduction = report
            .reproduction
            .as_ref()
            .with_context(|| format!("case {case_id} omitted reproduction metadata"))?;
        ensure!(
            reproduction.suite == plan.suite
                && reproduction.case_id == *case_id
                && reproduction.variant_id == expected_variant
                && reproduction.original_run_id == plan.run_id
                && reproduction.target_fingerprint == plan.target.fingerprint.sha256
                && reproduction.capability_profile == planned_case.requires
                && reproduction.seed == "deterministic-no-randomized-order"
                && reproduction
                    .command
                    .starts_with("s3chaos protocol-suite-reproduce "),
            "case {case_id} reproduction metadata differs from the plan"
        );
        let expected_capabilities = preflight
            .capability_matrix
            .iter()
            .filter(|check| {
                planned_case
                    .requires
                    .iter()
                    .any(|required| required == check.capability.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        ensure!(
            report.capabilities == expected_capabilities,
            "case {case_id} capability states differ from preflight"
        );
        let case_dir = report_path
            .parent()
            .context("case report artifact has no parent directory")?;
        let cleanup_path = root.join(case_dir).join("cleanup-report.json");
        let case_registry_path = root.join(case_dir).join(RESOURCE_REGISTRY_FILE);
        let history_path = root.join(case_dir).join("operation-history.jsonl");
        let history =
            read_json_lines::<crate::protocol::reporting::ProtocolAssertion>(&history_path)?;
        ensure!(
            history == report.assertions,
            "case {case_id} operation history differs from its case report assertions"
        );
        let case_cleanup = read_json::<ProtocolCleanupReport>(&cleanup_path)?;
        ensure!(
            report.cleanup_succeeded == case_cleanup.succeeded,
            "case {case_id} cleanup status differs between result and cleanup report"
        );
        ensure!(
            report.cleanup_failure.is_some() != case_cleanup.succeeded,
            "case {case_id} cleanup failure diagnostics differ from its cleanup report"
        );
        if let Some(cleanup_failure) = &report.cleanup_failure {
            ensure!(
                cleanup_failure.classification == "cleanup-failure"
                    && cleanup_failure.leftovers == case_cleanup.leftovers,
                "case {case_id} cleanup failure details differ from its cleanup report"
            );
        }
        if planned_case.contract.is_some() && !case_registry_path.is_file() {
            ensure!(
                case_provably_never_started(&report, &case_cleanup),
                "case {case_id} typed plan is missing its resource registry without proof that execution never started"
            );
        }
        if case_registry_path.is_file() {
            let case_registry = ResourceRegistry::load_path(&case_registry_path)?;
            ensure!(
                case_registry.run_id == plan.run_id
                    && case_registry.target_fingerprint == plan.target.fingerprint,
                "case {case_id} registry ownership differs from the suite"
            );
            if let Some(planned_contract) = &planned_case.contract {
                validate_registry_contract(case_id, planned_contract, &case_registry)?;
            }
            if case_cleanup.succeeded {
                ensure!(
                    case_registry.pending_cleanup().next().is_none(),
                    "case {case_id} cleanup succeeded while its registry has leftovers"
                );
            }
            validate_cleanup_registry(case_id, &case_cleanup, &case_registry)?;
        }
        case_cleanups.push(case_cleanup);
        case_reports.push(report);
    }
    let junit_cases = case_reports.iter().collect::<Vec<_>>();
    let expected_junit = protocol_junit_xml(&summary.suite, &junit_cases, cleanup.succeeded);
    let actual_junit = fs::read_to_string(root.join(PROTOCOL_JUNIT_FILE))
        .with_context(|| format!("read protocol artifact {PROTOCOL_JUNIT_FILE}"))?;
    ensure!(
        actual_junit == expected_junit,
        "protocol JUnit report does not match planned case/variant results"
    );
    let expected_case_results = case_reports
        .iter()
        .zip(&summary.case_reports)
        .map(|(report, path)| {
            crate::protocol::reporting::ProtocolCaseResultSummary::from_report(report, path.clone())
                .context("case report omitted reproduction metadata")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        summary.case_results == expected_case_results,
        "protocol suite JSON summary differs from case report results"
    );
    let expected_status = if case_reports
        .iter()
        .all(|report| report.status != ProtocolCaseStatus::Failed)
        && case_cleanups.iter().all(|cleanup| cleanup.succeeded)
        && cleanup.succeeded
    {
        ProtocolCaseStatus::Passed
    } else {
        ProtocolCaseStatus::Failed
    };
    ensure!(
        summary.status == expected_status,
        "protocol suite summary status does not match case and cleanup reports"
    );
    let current_history = flake_history
        .entries
        .iter()
        .filter(|entry| entry.run_id == plan.run_id)
        .collect::<Vec<_>>();
    ensure!(
        flake_history.profile == plan.profile
            && current_history.len() == case_reports.len()
            && current_history
                .iter()
                .all(|entry| entry.implicit_retry_count == 0)
            && current_history
                .iter()
                .zip(&case_reports)
                .all(|(entry, report)| {
                    entry.case_id == report.case_id
                        && entry.variant_id == report.variant_id
                        && entry.status == protocol_flake_status(report)
                })
            && flake_history.signals == protocol_flake_signals(&flake_history.entries),
        "protocol flaky-history signal differs from current results or records an implicit retry"
    );
    if cleanup.succeeded {
        ensure!(
            registry.pending_cleanup().next().is_none(),
            "cleanup report succeeded while registry still contains pending resources"
        );
    }
    match &summary.failure_summary {
        Some(path) => {
            ensure!(
                summary.status == ProtocolCaseStatus::Failed,
                "passing protocol suite must not reference a failure summary"
            );
            let path = safe_relative_path(path)?;
            let failure: ProtocolFailureSummary = read_json(&root.join(path))?;
            validate_evidence_paths(root, &failure.evidence)?;
        }
        None => ensure!(
            summary.status == ProtocolCaseStatus::Passed,
            "failed protocol suite must reference a failure summary"
        ),
    }

    scan_files(root, checked_files, &mut |path, contents| {
        for secret in forbidden_material {
            if secret.len() >= 4 && contents.contains(secret) {
                bail!(
                    "protocol artifact {} contains forbidden credential material",
                    path.display()
                );
            }
        }
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") => {
                let value: Value = serde_json::from_str(contents)
                    .with_context(|| format!("parse protocol JSON artifact {}", path.display()))?;
                reject_sensitive_fields(path, &value)?;
            }
            Some("jsonl") => {
                for (index, line) in contents.lines().enumerate() {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let value: Value = serde_json::from_str(line).with_context(|| {
                        format!(
                            "parse protocol JSONL artifact {} line {}",
                            path.display(),
                            index + 1
                        )
                    })?;
                    reject_sensitive_fields(path, &value)?;
                }
            }
            _ => {}
        }
        Ok(())
    })
}

fn case_provably_never_started(
    report: &ProtocolCaseReport,
    cleanup: &ProtocolCleanupReport,
) -> bool {
    report.status == ProtocolCaseStatus::Failed
        && matches!(
            report.failure_phase.as_deref(),
            Some("preflight" | "not-run")
        )
        && report.failure.is_some()
        && report.actors.is_empty()
        && report.assertions.is_empty()
        && cleanup.attempts.is_empty()
        && cleanup.leftovers.is_empty()
        && cleanup.succeeded
}

fn reject_sensitive_fields(path: &Path, value: &Value) -> Result<()> {
    match value {
        Value::Object(fields) => {
            for (name, value) in fields {
                let normalized = name
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .flat_map(char::to_lowercase)
                    .collect::<String>();
                ensure!(
                    !matches!(
                        normalized.as_str(),
                        "accesskey"
                            | "adminaccesskey"
                            | "secretkey"
                            | "secretaccesskey"
                            | "sessiontoken"
                            | "rawcredentials"
                    ),
                    "protocol artifact {} contains forbidden credential field {name}",
                    path.display()
                );
                reject_sensitive_fields(path, value)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                reject_sensitive_fields(path, value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_registry_contract(
    case_id: &str,
    planned: &ProtocolSuitePlanCaseContract,
    registry: &ResourceRegistry,
) -> Result<()> {
    let recorded = registry
        .contract
        .as_ref()
        .with_context(|| format!("case {case_id} registry omitted its typed contract"))?;
    ensure!(
        recorded.case_id == case_id,
        "case {case_id} registry contract records owner {}",
        recorded.case_id
    );
    ensure!(
        recorded.variant_id == planned.variant_id,
        "case {case_id} registry variant {} differs from planned variant {}",
        recorded.variant_id,
        planned.variant_id
    );
    ensure!(
        recorded.ownership == planned.ownership,
        "case {case_id} registry ownership differs from the planned contract"
    );
    ensure!(
        recorded.cleanup_scopes == planned.cleanup_scopes,
        "case {case_id} registry cleanup scopes differ from the planned contract"
    );
    ensure!(
        recorded.lock_requirements == planned.lock_requirements,
        "case {case_id} registry lock requirements differ from the planned contract"
    );
    Ok(())
}

fn validate_cleanup_registry(
    case_id: &str,
    cleanup: &ProtocolCleanupReport,
    registry: &ResourceRegistry,
) -> Result<()> {
    let pending = registry
        .pending_cleanup()
        .map(|resource| resource.id.as_str())
        .collect::<BTreeSet<_>>();
    let leftovers = cleanup
        .leftovers
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    ensure!(
        pending == leftovers,
        "case {case_id} cleanup leftovers differ from its final registry state"
    );
    ensure!(
        cleanup.succeeded == pending.is_empty(),
        "case {case_id} cleanup success differs from its final registry state"
    );
    let registered = registry
        .resources
        .iter()
        .map(|resource| resource.id.as_str())
        .collect::<BTreeSet<_>>();
    for attempt in &cleanup.attempts {
        ensure!(
            attempt.resource_kind == "registry"
                || registered.contains(attempt.resource_id.as_str()),
            "case {case_id} cleanup attempt {} is absent from its registry",
            attempt.resource_id
        );
    }
    Ok(())
}

fn validate_evidence_paths(root: &Path, evidence: &[String]) -> Result<()> {
    for reference in evidence {
        let relative = safe_relative_path(reference)?;
        ensure!(
            root.join(relative).is_file(),
            "protocol evidence path {reference} does not identify a file"
        );
    }
    Ok(())
}

fn safe_relative_path(path: &str) -> Result<&Path> {
    let path = Path::new(path);
    ensure!(!path.is_absolute(), "artifact reference must be relative");
    ensure!(
        path.components()
            .all(|component| matches!(component, Component::Normal(_))),
        "artifact reference contains unsafe path components"
    );
    Ok(path)
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read protocol JSON artifact {}", path.display()))?;
    serde_json::from_str(&raw)
        .with_context(|| format!("parse protocol JSON artifact {}", path.display()))
}

fn validate_legacy_compatibility_coverage(path: &Path) -> Result<()> {
    let envelope: LegacyCompatibilityCoverageEnvelope = read_json(path)?;
    ensure!(
        envelope.api_version == LEGACY_COMPATIBILITY_COVERAGE_API_VERSION
            && envelope.kind == LEGACY_COMPATIBILITY_COVERAGE_KIND,
        "legacy compatibility coverage artifact has an unsupported apiVersion or kind"
    );
    Ok(())
}

fn read_json_lines<T: DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read protocol JSONL artifact {}", path.display()))?;
    raw.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line).with_context(|| {
                format!(
                    "parse protocol JSONL artifact {} line {}",
                    path.display(),
                    index + 1
                )
            })
        })
        .collect()
}

fn scan_files(
    root: &Path,
    checked_files: &mut usize,
    visitor: &mut impl FnMut(&Path, &str) -> Result<()>,
) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        ensure!(
            !file_type.is_symlink(),
            "protocol artifact tree must not contain symlinks"
        );
        if file_type.is_dir() {
            scan_files(&entry.path(), checked_files, visitor)?;
        } else if file_type.is_file() {
            *checked_files += 1;
            ensure!(
                *checked_files <= MAX_FILES,
                "protocol artifact tree exceeds {MAX_FILES} files"
            );
            ensure!(
                entry.metadata()?.len() <= MAX_FILE_BYTES,
                "protocol artifact {} exceeds {} bytes",
                entry.path().display(),
                MAX_FILE_BYTES
            );
            let contents = fs::read_to_string(entry.path())
                .with_context(|| format!("read protocol artifact {}", entry.path().display()))?;
            visitor(&entry.path(), &contents)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_compatibility_coverage_requires_expected_envelope() {
        let directory = tempfile::tempdir().expect("tempdir");
        let path = directory.path().join(LEGACY_COMPATIBILITY_COVERAGE_FILE);

        fs::write(
            &path,
            r#"{"apiVersion":"rustfs.com/s3chaos/v1alpha1","kind":"ProtocolCompatibilityCoverageReport"}"#,
        )
        .expect("legacy coverage artifact");
        validate_legacy_compatibility_coverage(&path).expect("valid legacy envelope");

        for invalid in [
            "null",
            "{}",
            r#"{"apiVersion":"rustfs.com/s3chaos/v2","kind":"ProtocolCompatibilityCoverageReport"}"#,
            r#"{"apiVersion":"rustfs.com/s3chaos/v1alpha1","kind":"UnexpectedReport"}"#,
        ] {
            fs::write(&path, invalid).expect("invalid legacy coverage artifact");
            assert!(validate_legacy_compatibility_coverage(&path).is_err());
        }
    }
}
