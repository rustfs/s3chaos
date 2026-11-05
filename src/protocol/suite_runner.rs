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
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::protocol::{
    artifact_validation::validate_protocol_artifacts_and_write_report,
    cases::{ProtocolCaseExecution, ProtocolCaseServices, run_protocol_case},
    catalog::{DEFAULT_PROTOCOL_VARIANT, ProtocolCapabilitySource, ProtocolCapabilityState},
    clients::{
        admin::RustfsAdminClient,
        keycloak::KeycloakExternalIdentityProvider,
        s3::{AwsS3ClientFactory, ProtocolS3Client},
        sts::RustfsStsClient,
    },
    credentials::{CredentialProvider, EnvCredentialProvider},
    fixture::{
        naming::ProtocolResourceNamer,
        registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
    },
    ports::{ProtocolAdminServerPort, ProtocolExternalIdentityPort, ProtocolWebIdentityStsPort},
    preflight::{
        ProtocolMutatingProbeExecution, ProtocolProbeCapabilities, capability_failures,
        cleanup_interrupted_mutating_permission_probe, run_mutating_permission_probe,
    },
    reporting::{
        PROTOCOL_FLAKE_HISTORY_FILE, PROTOCOL_JUNIT_FILE, ProtocolCaseCleanupFailure,
        ProtocolCaseOutcome, ProtocolCaseResultSummary, ProtocolCaseStatus, ProtocolCleanupReport,
        ProtocolFailureSummary, ProtocolFlakeHistory, ProtocolFlakeHistoryEntry,
        ProtocolReproduction, ProtocolSuiteSummary, protocol_flake_signals, protocol_flake_status,
        protocol_junit_xml,
    },
    runner::{
        artifacts::ProtocolArtifactWriter,
        cleanup::{ProtocolCleanupCoordinator, load_cleanup_registry, registry_failure},
        executor::{ProtocolCaseLifecycle, ProtocolShutdownSignal, ProtocolSuiteExecutor},
        preflight::run_connected_preflight,
        runtime::{
            BudgetedProtocolTimeout, ConnectedProtocolRuntime, MonotonicProtocolClock,
            ProcessShutdownSignal, ensure_dedicated_target_acknowledgement,
            ensure_dedicated_target_fingerprint, protocol_artifact_base,
        },
    },
    suite::{
        ProtocolExternalIdentityProviderKind, ProtocolSuite, ProtocolSuiteContracts,
        ProtocolSuiteExternalIdentity, ProtocolSuiteSelector,
    },
    suite_plan::{
        ProtocolMutatingProbeStatus, ProtocolMutatingProbeSummary, ProtocolSuitePlan,
        ProtocolSuitePlanCase, TargetFingerprint,
    },
};

struct LiveProtocolCaseLifecycle<'a> {
    artifact_root: &'a Path,
    artifacts: &'a ProtocolArtifactWriter,
    run_id: &'a str,
    fingerprint: &'a TargetFingerprint,
    namer: &'a ProtocolResourceNamer,
    admin: &'a RustfsAdminClient,
    s3: &'a ProtocolS3Client,
    sts: &'a RustfsStsClient,
    external_identity: Option<&'a dyn ProtocolExternalIdentityPort>,
    web_identity_sts: Option<&'a dyn ProtocolWebIdentityStsPort>,
    actor_clients: &'a AwsS3ClientFactory,
    contracts: ProtocolSuiteContracts,
    cleanup: &'a ProtocolCleanupCoordinator<'a, RustfsAdminClient, ProtocolS3Client>,
    api_version: &'a str,
}

pub async fn plan_protocol_suite_from_yaml(path: impl AsRef<Path>) -> Result<ProtocolSuitePlan> {
    let runtime = ConnectedProtocolRuntime::connect(path).await?;
    let preflight = run_connected_preflight(&runtime).await?;
    ProtocolSuitePlan::generated(
        &runtime.suite,
        preflight.target_fingerprint.clone(),
        (&preflight).into(),
        protocol_artifact_base(),
    )
}

pub async fn run_protocol_suite_from_yaml(path: impl AsRef<Path>) -> Result<()> {
    run_protocol_suite(path.as_ref(), None, None).await
}

/// Rebuilds the effective suite without writing to the original run.
pub fn protocol_reproduction_suite(
    artifact_root: impl AsRef<Path>,
    case_id: Option<&str>,
) -> Result<(ProtocolSuite, TargetFingerprint)> {
    let artifact_root = artifact_root.as_ref();
    let plan: ProtocolSuitePlan = serde_json::from_str(
        &fs::read_to_string(artifact_root.join("protocol-suite-plan.json"))
            .context("read protocol suite plan for reproduction")?,
    )
    .context("parse protocol suite plan for reproduction")?;
    ensure!(
        !plan.cases.is_empty(),
        "recorded protocol plan contains no cases to reproduce"
    );
    if let Some(case_id) = case_id {
        ensure!(
            plan.cases.iter().any(|case| case.id == case_id),
            "case {case_id} was not part of run {}",
            plan.run_id
        );
    }
    let mut suite = ProtocolSuite::from_yaml_path(artifact_root.join("protocol-suite.yaml"))?;
    ensure!(
        suite.metadata.name == plan.suite,
        "protocol source suite does not match the recorded plan"
    );
    suite.selector = ProtocolSuiteSelector {
        cases: plan
            .cases
            .iter()
            .filter(|case| case_id.is_none_or(|selected| selected == case.id))
            .map(|case| case.id.clone())
            .collect(),
        ..ProtocolSuiteSelector::default()
    };
    suite.execution.profile = plan.profile;
    suite.execution.parallelism = plan.execution.parallelism;
    suite.execution.cleanup = plan.execution.cleanup;
    suite.execution.timeouts = plan.execution.timeouts;
    suite.execution.artifact_retention = plan.execution.artifact_retention;
    suite.contracts = plan.contracts;
    suite.target.endpoint = plan.target.fingerprint.endpoint.clone();
    suite.target.region = plan.target.fingerprint.region.clone();
    suite.target.credentials.admin_profile = plan.target.admin_profile;
    suite.target.ownership.resource_prefixes.bucket = plan.target.bucket_prefix;
    suite.target.ownership.resource_prefixes.identity = plan.target.identity_prefix;
    suite.target.external_identity =
        plan.target
            .external_identity_profile
            .map(|profile| ProtocolSuiteExternalIdentity {
                provider: ProtocolExternalIdentityProviderKind::Keycloak,
                profile,
            });
    suite.resolve()?;
    Ok((suite, plan.target.fingerprint))
}

pub async fn reproduce_protocol_case_from_artifacts(
    artifact_root: impl AsRef<Path>,
    case_id: &str,
) -> Result<()> {
    let artifact_root = artifact_root.as_ref();
    let (suite, fingerprint) = protocol_reproduction_suite(artifact_root, Some(case_id))?;
    run_protocol_suite(
        &artifact_root.join("protocol-suite.yaml"),
        Some(&fingerprint),
        Some(suite),
    )
    .await
}

async fn run_protocol_suite(
    path: &Path,
    expected_fingerprint: Option<&TargetFingerprint>,
    suite_override: Option<ProtocolSuite>,
) -> Result<()> {
    ensure_dedicated_target_acknowledgement()?;
    let mut source_suite = match suite_override {
        Some(suite) => suite,
        None => ProtocolSuite::from_yaml_path(path)?,
    };
    let runtime = ConnectedProtocolRuntime::connect_suite(&source_suite).await?;
    let mut preflight = run_connected_preflight(&runtime).await?;
    ensure_dedicated_target_fingerprint(&preflight.target_fingerprint)?;
    if let Some(expected) = expected_fingerprint {
        ensure!(
            &preflight.target_fingerprint == expected,
            "refuse reproduction because target fingerprint changed: expected {}, observed {}",
            expected.sha256,
            preflight.target_fingerprint.sha256
        );
    }
    let mut plan = ProtocolSuitePlan::generated(
        &runtime.suite,
        preflight.target_fingerprint.clone(),
        (&preflight).into(),
        protocol_artifact_base(),
    )?;
    if let Some(root) = std::env::var_os("RUSTFS_PROTOCOL_TEST_RUN_ROOT") {
        claim_exact_protocol_run_root(&mut plan, Path::new(&root))?;
    }
    let artifact_root = plan.artifact_root();
    let artifacts = ProtocolArtifactWriter::file(&artifact_root);
    artifacts.initialize_run(path)?;
    source_suite.target.endpoint = runtime.endpoint.clone();
    source_suite.selector = ProtocolSuiteSelector {
        cases: plan.cases.iter().map(|case| case.id.clone()).collect(),
        ..ProtocolSuiteSelector::default()
    };
    artifacts.write_text(
        "protocol-suite.yaml",
        &serde_yaml_ng::to_string(&source_suite)?,
    )?;
    artifacts.write_json("protocol-suite-plan.json", &plan)?;
    artifacts.write_json("preflight-summary.json", &preflight)?;
    eprintln!(
        "protocol suite {}: {} cases; artifacts: {}",
        plan.suite,
        plan.cases.len(),
        artifact_root.display()
    );

    let mut registry = ResourceRegistry::create(
        &artifact_root,
        &plan.run_id,
        preflight.target_fingerprint.clone(),
    )?;
    registry.set_versioned_cleanup(
        plan.cases
            .iter()
            .any(|case| case.requires.iter().any(|item| item == "versioning")),
    )?;
    let namer = ProtocolResourceNamer::new(
        &plan.target.bucket_prefix,
        &plan.target.identity_prefix,
        &plan.run_id,
    )?;

    let capability_failure = capability_failures(&preflight)
        .first()
        .map(|failure| (failure.capability, failure.reason.clone()));
    let probe = if let Some((capability, reason)) = &capability_failure {
        ProtocolMutatingProbeExecution {
            summary: ProtocolMutatingProbeSummary {
                status: ProtocolMutatingProbeStatus::Failed,
                synthetic_case_id: "preflight-permission-probe".to_string(),
                version_count: 0,
                delete_marker_count: 0,
                cleanup_succeeded: true,
                cleanup_report: Some("preflight-cleanup-report.json".to_string()),
                error: Some(format!(
                    "required capability {} failed before mutation: {}",
                    capability, reason
                )),
            },
            cleanup: ProtocolCleanupReport::empty(&runtime.suite.api_version),
            forbidden_secrets: Vec::new(),
        }
    } else {
        let probe_capabilities = ProtocolProbeCapabilities::from_suite(&runtime.suite);
        let mut probe_future = Box::pin(run_mutating_permission_probe(
            &namer,
            &mut registry,
            &runtime.admin,
            &runtime.s3,
            Some(&runtime.sts),
            probe_capabilities,
        ));
        let probe_result = tokio::select! {
            probe = &mut probe_future => Ok(probe),
            signal = ProcessShutdownSignal.wait() => Err(signal),
        };
        drop(probe_future);
        match probe_result {
            Ok(probe) => probe,
            Err(signal) => {
                let reason = match signal {
                    Ok(()) => {
                        "protocol suite interrupted during mutating preflight probe; cleanup requested"
                            .to_string()
                    }
                    Err(error) => format!(
                        "protocol signal handler failed during mutating preflight probe: {error}"
                    ),
                };
                cleanup_interrupted_mutating_permission_probe(
                    &mut registry,
                    &runtime.admin,
                    &runtime.s3,
                    reason,
                )
                .await
            }
        }
    };
    preflight.mutating_permission_probe = probe.summary.clone();
    if capability_failure.is_none() && probe.summary.status == ProtocolMutatingProbeStatus::Failed {
        let reason = probe
            .summary
            .error
            .as_deref()
            .unwrap_or("mutating permission probe failed");
        for capability in &mut preflight.capability_matrix {
            if capability.source == ProtocolCapabilitySource::BuiltIn
                && capability.state == ProtocolCapabilityState::Pass
            {
                capability.state = ProtocolCapabilityState::Fail;
                capability.reason = format!("mutating preflight failed: {reason}");
            }
        }
    }
    plan.preflight = (&preflight).into();
    artifacts.write_json("protocol-suite-plan.json", &plan)?;
    artifacts.write_json("preflight-summary.json", &preflight)?;
    artifacts.write_json("preflight-cleanup-report.json", &probe.cleanup)?;
    let mut probe_forbidden_secrets = probe.forbidden_secrets;

    let selected_cases = plan.cases.clone();
    let actor_clients = AwsS3ClientFactory::new(
        &runtime.endpoint,
        &runtime.suite.target.region,
        runtime.credentials.clone(),
    );
    let preflight_failure_message = capability_failure
        .as_ref()
        .map(|(capability, reason)| {
            format!("required capability {} failed: {}", capability, reason)
        })
        .or_else(|| probe.summary.error.clone())
        .unwrap_or_else(|| "mutating preflight probe failed".to_string());
    let external_identity = runtime
        .external_identity
        .as_ref()
        .map(|provider| provider as &dyn ProtocolExternalIdentityPort);
    let cleanup = ProtocolCleanupCoordinator::new(
        &artifact_root,
        &runtime.admin,
        &runtime.s3,
        external_identity,
        &runtime.suite.api_version,
    );
    let case_lifecycle = LiveProtocolCaseLifecycle {
        artifact_root: &artifact_root,
        artifacts: &artifacts,
        run_id: &plan.run_id,
        fingerprint: &plan.target.fingerprint,
        namer: &namer,
        admin: &runtime.admin,
        s3: &runtime.s3,
        sts: &runtime.sts,
        external_identity,
        web_identity_sts: runtime
            .web_identity_sts
            .as_ref()
            .map(|sts| sts as &dyn ProtocolWebIdentityStsPort),
        actor_clients: &actor_clients,
        contracts: plan.contracts,
        cleanup: &cleanup,
        api_version: &runtime.suite.api_version,
    };
    let clock = MonotonicProtocolClock::default();
    let timeout = BudgetedProtocolTimeout::new(plan.execution.timeouts);
    let executor = ProtocolSuiteExecutor::new(
        &case_lifecycle,
        &cleanup,
        &ProcessShutdownSignal,
        &clock,
        &timeout,
        &runtime.suite.api_version,
    );
    let preflight_failure = (capability_failure.is_some()
        || probe.summary.status != ProtocolMutatingProbeStatus::Passed)
        .then_some(preflight_failure_message.as_str());
    let suite_execution = executor
        .execute(&selected_cases, &mut registry, preflight_failure)
        .await?;
    let fallback_cleanup = suite_execution.fallback_cleanup;
    let mut case_executions = suite_execution
        .cases
        .into_iter()
        .map(|case| (case.execution, case.cleanup))
        .collect::<Vec<_>>();
    for (execution, _) in &mut case_executions {
        let planned = plan
            .cases
            .iter()
            .find(|case| case.id == execution.report.case_id)
            .expect("executed case belongs to the plan");
        execution.report.capabilities = preflight
            .capability_matrix
            .iter()
            .filter(|check| {
                planned
                    .requires
                    .iter()
                    .any(|required| required == check.capability.as_str())
            })
            .cloned()
            .collect();
    }
    artifacts.write_json("cleanup-report.json", &fallback_cleanup)?;

    for (execution, cleanup) in &mut case_executions {
        reconcile_case_cleanup(
            cleanup,
            &fallback_cleanup,
            &artifact_root
                .join("cases")
                .join(&execution.report.case_id)
                .join(RESOURCE_REGISTRY_FILE),
        );
        finalize_case_report(
            &mut execution.report,
            cleanup,
            &plan,
            &runtime.suite.metadata.name,
            &artifact_root,
        )?;
    }

    let mut case_report_paths = Vec::with_capacity(case_executions.len());
    let mut forbidden_case_secrets = Vec::new();
    for (execution, cleanup) in &case_executions {
        artifacts.create_case_dir(&execution.report.case_id)?;
        let case_relative = Path::new("cases").join(&execution.report.case_id);
        let case_dir = artifact_root.join(&case_relative);
        let case_report_path = case_dir.join("case-report.json");
        artifacts.write_json(case_relative.join("case-report.json"), &execution.report)?;
        artifacts.write_json(case_relative.join("cleanup-report.json"), cleanup)?;
        artifacts.write_json_lines(
            case_relative.join("operation-history.jsonl"),
            &execution.report.assertions,
        )?;
        case_report_paths.push(artifacts.relative_path(&case_report_path)?);
        forbidden_case_secrets.extend(execution.forbidden_secrets.iter().cloned());
    }
    let junit_cases = case_executions
        .iter()
        .map(|(execution, _)| &execution.report)
        .collect::<Vec<_>>();
    artifacts.write_text(
        PROTOCOL_JUNIT_FILE,
        &protocol_junit_xml(
            &runtime.suite.metadata.name,
            &junit_cases,
            fallback_cleanup.succeeded,
        ),
    )?;
    let flake_history = update_protocol_flake_history(&artifact_root, &plan, &case_executions)?;
    artifacts.write_json(PROTOCOL_FLAKE_HISTORY_FILE, &flake_history)?;

    let passed = case_executions.iter().all(|(execution, cleanup)| {
        execution.report.status != ProtocolCaseStatus::Failed && cleanup.succeeded
    }) && fallback_cleanup.succeeded;
    let first_failure = case_executions.iter().find(|(execution, cleanup)| {
        execution.report.status == ProtocolCaseStatus::Failed || !cleanup.succeeded
    });
    let failure_summary = if let Some((execution, cleanup)) = first_failure {
        let stage = execution
            .report
            .failure_phase
            .clone()
            .unwrap_or_else(|| "case".to_string());
        let classification = execution
            .report
            .failure_classification
            .clone()
            .unwrap_or_else(|| "protocol-case-failure".to_string());
        let case_base = format!("cases/{}", execution.report.case_id);
        let mut evidence = vec![
            format!("{case_base}/case-report.json"),
            format!("{case_base}/cleanup-report.json"),
            RESOURCE_REGISTRY_FILE.to_string(),
        ];
        if !cleanup.succeeded || !fallback_cleanup.succeeded {
            evidence.push("cleanup-report.json".to_string());
        }
        let failure = ProtocolFailureSummary {
            api_version: runtime.suite.api_version.clone(),
            kind: "ProtocolFailureSummary".to_string(),
            stage,
            classification,
            case_id: Some(execution.report.case_id.clone()),
            evidence,
        };
        artifacts.write_json("protocol-failure-summary.json", &failure)?;
        Some("protocol-failure-summary.json".to_string())
    } else if !fallback_cleanup.succeeded {
        artifacts.write_json(
            "protocol-failure-summary.json",
            &ProtocolFailureSummary {
                api_version: runtime.suite.api_version.clone(),
                kind: "ProtocolFailureSummary".to_string(),
                stage: "cleanup".to_string(),
                classification: "cleanup-failure".to_string(),
                case_id: None,
                evidence: vec![
                    "cleanup-report.json".to_string(),
                    RESOURCE_REGISTRY_FILE.to_string(),
                ],
            },
        )?;
        Some("protocol-failure-summary.json".to_string())
    } else {
        None
    };
    let case_results = case_executions
        .iter()
        .zip(&case_report_paths)
        .map(|((execution, _), report_path)| {
            ProtocolCaseResultSummary::from_report(&execution.report, report_path.clone())
                .context("final protocol case report omitted reproduction metadata")
        })
        .collect::<Result<Vec<_>>>()?;
    let mut summary = ProtocolSuiteSummary {
        api_version: runtime.suite.api_version.clone(),
        kind: "ProtocolSuiteSummary".to_string(),
        suite: runtime.suite.metadata.name.clone(),
        run_id: plan.run_id.clone(),
        profile: runtime.suite.execution.profile,
        target_fingerprint: plan.target.fingerprint.sha256.clone(),
        capability_matrix: preflight.capability_matrix.clone(),
        status: if passed {
            ProtocolCaseStatus::Passed
        } else {
            ProtocolCaseStatus::Failed
        },
        plan: "protocol-suite-plan.json".to_string(),
        preflight: "preflight-summary.json".to_string(),
        registry: RESOURCE_REGISTRY_FILE.to_string(),
        cleanup: "cleanup-report.json".to_string(),
        compatibility_coverage: None,
        flaky_history: PROTOCOL_FLAKE_HISTORY_FILE.to_string(),
        case_reports: case_report_paths,
        case_results,
        failure_summary,
    };
    artifacts.write_json("protocol-suite-summary.json", &summary)?;

    let mut forbidden = vec![
        runtime.credentials.access_key().to_string(),
        runtime.credentials.secret_key().to_string(),
    ];
    if let Some(token) = runtime.credentials.session_token() {
        forbidden.push(token.to_string());
    }
    if let Some(external_identity) = &runtime.external_identity {
        forbidden.extend(external_identity.forbidden_secrets());
    }
    forbidden.append(&mut probe_forbidden_secrets);
    forbidden.extend(forbidden_case_secrets);
    if let Err(error) = validate_phase_one_artifacts(&artifact_root, &forbidden) {
        artifacts.write_json(
            "protocol-failure-summary.json",
            &ProtocolFailureSummary {
                api_version: runtime.suite.api_version.clone(),
                kind: "ProtocolFailureSummary".to_string(),
                stage: "artifact-validation".to_string(),
                classification: "artifact-contract-failure".to_string(),
                case_id: first_failure.map(|(execution, _)| execution.report.case_id.clone()),
                evidence: vec![
                    "protocol-artifact-validation-report.json".to_string(),
                    "protocol-suite-summary.json".to_string(),
                ],
            },
        )?;
        summary.status = ProtocolCaseStatus::Failed;
        summary.failure_summary = Some("protocol-failure-summary.json".to_string());
        artifacts.write_json("protocol-suite-summary.json", &summary)?;
        print_protocol_summary(&summary, &artifact_root, false, fallback_cleanup.succeeded);
        return Err(error).with_context(|| {
            format!(
                "validate Phase 1 protocol artifacts at {}",
                artifact_root.display()
            )
        });
    }

    print_protocol_summary(&summary, &artifact_root, true, fallback_cleanup.succeeded);
    if !passed {
        bail!(
            "protocol suite failed; artifacts preserved at {}",
            artifact_root.display()
        );
    }
    println!(
        "protocol suite {} passed; artifacts: {}",
        runtime.suite.metadata.name,
        artifact_root.display()
    );
    Ok(())
}

fn print_protocol_summary(
    summary: &ProtocolSuiteSummary,
    artifact_root: &Path,
    artifacts_valid: bool,
    cleanup_succeeded: bool,
) {
    let cleanup_succeeded = cleanup_succeeded
        && summary
            .case_results
            .iter()
            .all(|case| case.cleanup_succeeded);
    let count = |outcome| {
        summary
            .case_results
            .iter()
            .filter(|case| case.outcome == outcome)
            .count()
    };
    eprintln!(
        "protocol result {:?}: passed={} failed={} not-run={} skipped={} expected-divergence={}; cleanup={}; artifacts={}",
        summary.status,
        count(ProtocolCaseOutcome::Passed),
        count(ProtocolCaseOutcome::Failed),
        count(ProtocolCaseOutcome::NotRun),
        count(ProtocolCaseOutcome::CapabilitySkipped),
        count(ProtocolCaseOutcome::ExpectedDivergence),
        if cleanup_succeeded {
            "passed"
        } else {
            "failed"
        },
        if artifacts_valid { "valid" } else { "invalid" },
    );
    let executable = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("s3chaos"));
    let executable = shell_quote(&executable.display().to_string());
    let workflow_root = artifact_root
        .parent()
        .filter(|root| root.join("record.json").is_file());
    if let Some(root) = workflow_root {
        eprintln!(
            "report: {executable} report {}",
            shell_quote(&root.display().to_string())
        );
    } else {
        eprintln!(
            "validate: {executable} protocol-validate-artifacts {}",
            shell_quote(&artifact_root.display().to_string())
        );
        eprintln!(
            "report: {}",
            artifact_root.join("protocol-suite-summary.json").display()
        );
    }
    for case in &summary.case_results {
        if case.outcome != ProtocolCaseOutcome::Failed && case.cleanup_succeeded {
            continue;
        }
        eprintln!(
            "failed case: {} ({})",
            case.case_id,
            case.failure_classification
                .as_deref()
                .unwrap_or("cleanup-failure")
        );
        if let Some(root) = workflow_root {
            eprintln!(
                "reproduce: {executable} reproduce {} --case {}",
                shell_quote(&root.display().to_string()),
                shell_quote(&case.case_id)
            );
        } else {
            eprintln!(
                "reproduce: {executable} protocol-suite-reproduce {} {}",
                shell_quote(&artifact_root.display().to_string()),
                shell_quote(&case.case_id)
            );
        }
    }
}

fn claim_exact_protocol_run_root(plan: &mut ProtocolSuitePlan, root: &Path) -> Result<()> {
    ensure!(
        !root.as_os_str().is_empty(),
        "RUSTFS_PROTOCOL_TEST_RUN_ROOT must not be empty"
    );
    let root_text = root
        .to_str()
        .context("protocol run root must be UTF-8")?
        .to_string();
    if let Some(parent) = root.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent).context("create protocol run parent directory")?;
    }
    fs::create_dir(root)
        .with_context(|| format!("claim new protocol run root {}", root.display()))?;
    plan.artifact_root = root_text;
    for case in &mut plan.cases {
        case.artifact_dir = root.join("cases").join(&case.id).display().to_string();
    }
    Ok(())
}

fn reconcile_case_cleanup(
    cleanup: &mut ProtocolCleanupReport,
    fallback_cleanup: &ProtocolCleanupReport,
    registry_path: &Path,
) {
    if !registry_path.is_file() {
        return;
    }
    let registry = match ResourceRegistry::load_path(registry_path) {
        Ok(registry) => registry,
        Err(error) => {
            let registry_id = format!("registry:{}", registry_path.display());
            let mut failure = ProtocolCleanupReport::empty(&cleanup.api_version);
            if let Some(attempt) = fallback_cleanup
                .attempts
                .iter()
                .find(|attempt| attempt.resource_id == registry_id)
            {
                failure.attempts.push(attempt.clone());
                failure.leftovers.push(registry_id);
                failure.succeeded = false;
            } else {
                failure = registry_failure(&cleanup.api_version, registry_path, error);
            }
            append_cleanup_without_duplicates(cleanup, failure);
            return;
        }
    };
    let resource_ids = registry
        .resources
        .iter()
        .map(|resource| resource.id.as_str())
        .collect::<BTreeSet<_>>();
    let matching_fallback = ProtocolCleanupReport {
        api_version: cleanup.api_version.clone(),
        kind: "ProtocolCleanupReport".to_string(),
        attempts: fallback_cleanup
            .attempts
            .iter()
            .filter(|attempt| resource_ids.contains(attempt.resource_id.as_str()))
            .cloned()
            .collect(),
        leftovers: Vec::new(),
        succeeded: true,
    };
    append_cleanup_without_duplicates(cleanup, matching_fallback);
    cleanup.leftovers = registry
        .pending_cleanup()
        .map(|resource| resource.id.clone())
        .collect();
    cleanup.succeeded = cleanup.leftovers.is_empty();
}

fn append_cleanup_without_duplicates(
    cleanup: &mut ProtocolCleanupReport,
    other: ProtocolCleanupReport,
) {
    for attempt in other.attempts {
        if !cleanup.attempts.iter().any(|current| {
            current.resource_id == attempt.resource_id
                && current.succeeded == attempt.succeeded
                && current.retry_count == attempt.retry_count
                && current.error == attempt.error
        }) {
            cleanup.attempts.push(attempt);
        }
    }
    for leftover in other.leftovers {
        if !cleanup.leftovers.contains(&leftover) {
            cleanup.leftovers.push(leftover);
        }
    }
    cleanup.succeeded = cleanup.succeeded && other.succeeded;
}

fn finalize_case_report(
    report: &mut crate::protocol::reporting::ProtocolCaseReport,
    cleanup: &ProtocolCleanupReport,
    plan: &ProtocolSuitePlan,
    suite: &str,
    artifact_root: &Path,
) -> Result<()> {
    let planned = plan
        .cases
        .iter()
        .find(|case| case.id == report.case_id)
        .with_context(|| format!("case {} is absent from protocol plan", report.case_id))?;
    let case_base = format!("cases/{}", report.case_id);
    apply_cleanup_diagnostics(report, cleanup);
    report.evidence = vec![
        format!("{case_base}/case-report.json"),
        format!("{case_base}/cleanup-report.json"),
        format!("{case_base}/operation-history.jsonl"),
    ];
    if artifact_root
        .join(&case_base)
        .join(RESOURCE_REGISTRY_FILE)
        .is_file()
    {
        report
            .evidence
            .push(format!("{case_base}/{RESOURCE_REGISTRY_FILE}"));
    }
    report.reproduction = Some(ProtocolReproduction {
        command: format!(
            "s3chaos protocol-suite-reproduce {} {}",
            shell_quote(&artifact_root.display().to_string()),
            shell_quote(&report.case_id)
        ),
        suite: suite.to_string(),
        case_id: report.case_id.clone(),
        variant_id: report.variant_id.clone(),
        seed: "deterministic-no-randomized-order".to_string(),
        original_run_id: plan.run_id.clone(),
        target_fingerprint: plan.target.fingerprint.sha256.clone(),
        capability_profile: planned.requires.clone(),
    });
    Ok(())
}

fn apply_cleanup_diagnostics(
    report: &mut crate::protocol::reporting::ProtocolCaseReport,
    cleanup: &ProtocolCleanupReport,
) {
    report.cleanup_succeeded = cleanup.succeeded;
    report.cleanup_failure = (!cleanup.succeeded).then(|| ProtocolCaseCleanupFailure {
        classification: "cleanup-failure".to_string(),
        message: format!(
            "protocol cleanup failed with {} leftover resource(s)",
            cleanup.leftovers.len()
        ),
        leftovers: cleanup.leftovers.clone(),
    });
    if !cleanup.succeeded && report.outcome != ProtocolCaseOutcome::Failed {
        report.status = ProtocolCaseStatus::Failed;
        report.outcome = ProtocolCaseOutcome::Failed;
        report.failure_phase = Some("cleanup".to_string());
        report.failure_classification = Some("cleanup-failure".to_string());
        report.failure = report
            .cleanup_failure
            .as_ref()
            .map(|failure| failure.message.clone());
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn update_protocol_flake_history(
    artifact_root: &Path,
    plan: &ProtocolSuitePlan,
    cases: &[(ProtocolCaseExecution, ProtocolCleanupReport)],
) -> Result<ProtocolFlakeHistory> {
    let artifact_base = artifact_root
        .parent()
        .and_then(Path::parent)
        .context("protocol artifact root is missing suite/base parents")?;
    // Keyed by target fingerprint as well as profile so a run redirected to a per-candidate
    // endpoint never mixes its outcomes into the shared target's flake signals.
    let history_relative = Path::new(".history").join(format!(
        "{}-{}.json",
        plan.profile, plan.target.fingerprint.sha256
    ));
    let history_path = artifact_base.join(&history_relative);
    let mut entries = if history_path.is_file() {
        let existing: ProtocolFlakeHistory =
            serde_json::from_str(&fs::read_to_string(&history_path).with_context(|| {
                format!("read protocol flake history {}", history_path.display())
            })?)?;
        ensure!(
            existing.profile == plan.profile,
            "protocol flake history profile changed unexpectedly"
        );
        existing.entries
    } else {
        Vec::new()
    };
    entries.extend(
        cases
            .iter()
            .map(|(execution, _)| ProtocolFlakeHistoryEntry {
                run_id: plan.run_id.clone(),
                source_revision: plan.source_revision.clone(),
                case_id: execution.report.case_id.clone(),
                variant_id: execution.report.variant_id.clone(),
                status: protocol_flake_status(&execution.report),
                implicit_retry_count: 0,
            }),
    );
    if entries.len() > 2_000 {
        entries.drain(..entries.len() - 2_000);
    }
    let signals = protocol_flake_signals(&entries);
    let history = ProtocolFlakeHistory {
        api_version: "rustfs.com/s3chaos/v1alpha1".to_string(),
        kind: "ProtocolFlakeHistory".to_string(),
        profile: plan.profile,
        entries,
        signals,
    };
    let writer = ProtocolArtifactWriter::file(artifact_base);
    writer.create_dir(".history")?;
    writer.write_json(history_relative, &history)?;
    Ok(history)
}

pub async fn cleanup_protocol_artifact_root(artifact_root: impl AsRef<Path>) -> Result<()> {
    let artifact_root = artifact_root.as_ref();
    ensure_dedicated_target_acknowledgement()?;
    let root_registry_path = artifact_root.join(RESOURCE_REGISTRY_FILE);
    let mut root_registry = load_cleanup_registry(&root_registry_path)?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let expected = root_registry.target_fingerprint.clone();
    let admin = RustfsAdminClient::new(&expected.endpoint, &expected.region, credentials.clone())?;
    let s3 =
        ProtocolS3Client::for_admin(&expected.endpoint, &expected.region, &credentials).await?;
    verify_cleanup_target(&admin, &expected).await?;

    let artifacts = ProtocolArtifactWriter::file(artifact_root);
    let mut combined = ProtocolCleanupReport::empty(&root_registry.api_version);
    let cases_dir = artifact_root.join("cases");
    if cases_dir.is_dir() {
        let mut entries = Vec::new();
        match fs::read_dir(&cases_dir) {
            Ok(read_dir) => {
                for entry in read_dir {
                    match entry {
                        Ok(entry) => entries.push(entry),
                        Err(error) => combined.append(registry_failure(
                            &root_registry.api_version,
                            &cases_dir,
                            error,
                        )),
                    }
                }
            }
            Err(error) => combined.append(registry_failure(
                &root_registry.api_version,
                &cases_dir,
                error,
            )),
        }
        entries.sort_by_key(std::fs::DirEntry::file_name);
        for entry in entries {
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(error) => {
                    combined.append(registry_failure(
                        &root_registry.api_version,
                        &entry.path(),
                        error,
                    ));
                    continue;
                }
            };
            if !file_type.is_dir() || file_type.is_symlink() {
                combined.append(registry_failure(
                    &root_registry.api_version,
                    &entry.path(),
                    "protocol case artifact must be a non-symlink directory",
                ));
                continue;
            }
            let registry_path = entry.path().join(RESOURCE_REGISTRY_FILE);
            if !registry_path.is_file() {
                continue;
            }
            let mut case_registry = match load_cleanup_registry(&registry_path) {
                Ok(registry) => registry,
                Err(error) => {
                    combined.append(registry_failure(
                        &root_registry.api_version,
                        &registry_path,
                        error,
                    ));
                    continue;
                }
            };
            if case_registry.run_id != root_registry.run_id
                || case_registry.target_fingerprint != expected
            {
                combined.append(registry_failure(
                    &root_registry.api_version,
                    &registry_path,
                    "refuse cleanup because case registry ownership differs from the suite",
                ));
                continue;
            }
            let external_identity = match external_identity_for_registry(&case_registry) {
                Ok(provider) => provider,
                Err(error) => {
                    combined.append(registry_failure(
                        &root_registry.api_version,
                        &registry_path,
                        error,
                    ));
                    continue;
                }
            };
            let coordinator = ProtocolCleanupCoordinator::new(
                artifact_root,
                &admin,
                &s3,
                external_identity
                    .as_ref()
                    .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
                &root_registry.api_version,
            );
            let cleanup = coordinator.cleanup_registry(&mut case_registry).await;
            let report_relative = Path::new("cases")
                .join(entry.file_name())
                .join("cleanup-report.json");
            if let Err(error) = artifacts.write_json(&report_relative, &cleanup) {
                combined.append(registry_failure(
                    &root_registry.api_version,
                    &artifact_root.join(report_relative),
                    error,
                ));
            }
            combined.append(cleanup);
        }
    }
    let root_external_identity = external_identity_for_registry(&root_registry)?;
    let api_version = root_registry.api_version.clone();
    let root_coordinator = ProtocolCleanupCoordinator::new(
        artifact_root,
        &admin,
        &s3,
        root_external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        &api_version,
    );
    combined.append(root_coordinator.cleanup_registry(&mut root_registry).await);
    let report_path = artifact_root.join("cleanup-report.json");
    artifacts.write_json("cleanup-report.json", &combined)?;
    ensure!(
        combined.succeeded,
        "protocol cleanup left {} resource(s); inspect {}",
        combined.leftovers.len(),
        report_path.display()
    );
    println!(
        "protocol cleanup completed from artifact root: {}",
        artifact_root.display()
    );
    Ok(())
}

#[async_trait::async_trait]
impl ProtocolCaseLifecycle for LiveProtocolCaseLifecycle<'_> {
    fn case_started(&self, case_id: &str, total: usize) {
        eprintln!("protocol case started: {case_id} ({total} selected)");
    }

    fn case_finished(
        &self,
        execution: &ProtocolCaseExecution,
        cleanup: &ProtocolCleanupReport,
        completed: usize,
        total: usize,
    ) {
        eprintln!(
            "protocol case {completed}/{total}: {} {:?}; {} ms; cleanup={}",
            execution.report.case_id,
            execution.report.outcome,
            execution.report.duration_millis,
            if cleanup.succeeded {
                "passed"
            } else {
                "failed"
            }
        );
    }

    async fn run_case(
        &self,
        case: &ProtocolSuitePlanCase,
    ) -> Result<(ProtocolCaseExecution, ProtocolCleanupReport)> {
        let case_dir = self.artifact_root.join("cases").join(&case.id);
        self.artifacts.create_case_dir(&case.id)?;
        let mut registry =
            ResourceRegistry::create(&case_dir, self.run_id, self.fingerprint.clone())?;
        registry.bind_case(
            &case.id,
            case.contract
                .as_ref()
                .map(|contract| contract.variant_id.as_str())
                .unwrap_or(DEFAULT_PROTOCOL_VARIANT),
        )?;
        registry.set_versioned_cleanup(case.requires.iter().any(|item| item == "versioning"))?;
        let case_namer = self.namer.for_worker(case.worker_index);
        let execution = run_protocol_case(
            &case.id,
            &case_namer,
            &mut registry,
            ProtocolCaseServices {
                admin: self.admin,
                admin_s3: self.s3,
                sts: self.sts,
                external_identity: self.external_identity,
                web_identity_sts: self.web_identity_sts,
                actor_clients: self.actor_clients,
                contracts: self.contracts,
            },
        )
        .await;
        let cleanup = self.cleanup.cleanup_registry(&mut registry).await;
        if cleanup.api_version != self.api_version {
            bail!("case {} cleanup apiVersion changed unexpectedly", case.id);
        }
        Ok((execution, cleanup))
    }
}

pub async fn cleanup_protocol_registry_path(registry_path: impl AsRef<Path>) -> Result<()> {
    let registry_path = registry_path.as_ref();
    ensure!(
        registry_path.file_name().and_then(|name| name.to_str()) == Some(RESOURCE_REGISTRY_FILE),
        "standalone protocol cleanup requires a file named {RESOURCE_REGISTRY_FILE}"
    );
    let parent = artifact_parent(registry_path, "resource registry path has no parent")?;
    cleanup_protocol_registry(
        registry_path.to_path_buf(),
        parent.join("cleanup-report.json"),
    )
    .await
}

async fn cleanup_protocol_registry(registry_path: PathBuf, report_path: PathBuf) -> Result<()> {
    ensure_dedicated_target_acknowledgement()?;
    let mut registry = load_cleanup_registry(&registry_path)?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let expected = registry.target_fingerprint.clone();
    let admin = RustfsAdminClient::new(&expected.endpoint, &expected.region, credentials.clone())?;
    let s3 =
        ProtocolS3Client::for_admin(&expected.endpoint, &expected.region, &credentials).await?;
    verify_cleanup_target(&admin, &expected).await?;
    let external_identity = external_identity_for_registry(&registry)?;
    let api_version = registry.api_version.clone();
    let report_parent = artifact_parent(&report_path, "cleanup report path has no parent")?;
    let coordinator = ProtocolCleanupCoordinator::new(
        report_parent,
        &admin,
        &s3,
        external_identity
            .as_ref()
            .map(|provider| provider as &dyn ProtocolExternalIdentityPort),
        &api_version,
    );
    let cleanup = coordinator.cleanup_registry(&mut registry).await;
    let report_name = report_path
        .file_name()
        .context("cleanup report path has no file name")?;
    ProtocolArtifactWriter::file(report_parent).write_json(Path::new(report_name), &cleanup)?;
    ensure!(
        cleanup.succeeded,
        "protocol cleanup left {} resource(s); inspect {}",
        cleanup.leftovers.len(),
        report_path.display()
    );
    println!(
        "protocol cleanup completed from registry: {}",
        registry_path.display()
    );
    Ok(())
}

fn artifact_parent<'a>(path: &'a Path, missing_parent: &'static str) -> Result<&'a Path> {
    let parent = path.parent().context(missing_parent)?;
    Ok(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })
}

fn external_identity_for_registry(
    registry: &ResourceRegistry,
) -> Result<Option<KeycloakExternalIdentityProvider>> {
    let identities = registry
        .pending_cleanup()
        .filter(|resource| {
            resource.kind
                == crate::protocol::fixture::registry::ResourceKind::ExternalIdentitySubject
        })
        .map(|resource| {
            resource
                .external_identity
                .clone()
                .context("external identity registry entry omitted its provider coordinates")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        identities.len() <= 1,
        "resource registry contains multiple external identity coordinates"
    );
    let Some(expected) = identities.into_iter().next() else {
        return Ok(None);
    };
    ensure!(
        expected.provider == "keycloak",
        "unsupported external identity provider {} in resource registry",
        expected.provider
    );
    let provider = KeycloakExternalIdentityProvider::from_env(&expected.profile)?;
    let actual = provider.coordinates();
    ensure!(
        actual == expected,
        "refuse external identity cleanup because configured provider coordinates differ from the registry: registry={expected:?} adapter={actual:?}"
    );
    Ok(Some(provider))
}

async fn verify_cleanup_target(
    admin: &impl ProtocolAdminServerPort,
    expected: &TargetFingerprint,
) -> Result<()> {
    ensure!(
        !expected.deployment_id.starts_with("s3-endpoint:"),
        "refuse standalone protocol cleanup because the artifact has no verifiable deployment fingerprint"
    );
    let info = admin.server_info().await?;
    let actual = TargetFingerprint::new(
        &expected.endpoint,
        &expected.region,
        info.deployment_id,
        info.mode,
        info.region,
    )?;
    ensure!(
        actual == *expected,
        "refuse protocol cleanup because the live target fingerprint differs from the registry"
    );
    Ok(())
}

fn validate_phase_one_artifacts(root: &Path, forbidden: &[String]) -> Result<()> {
    validate_protocol_artifacts_and_write_report(root, forbidden).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_cleanup_diagnostics, artifact_parent, reconcile_case_cleanup,
        validate_phase_one_artifacts,
    };
    use crate::protocol::{
        cases::ProtocolCaseExecution,
        catalog::{
            ProtocolCapability, ProtocolCapabilityCheck, ProtocolCapabilitySource,
            ProtocolCapabilityState,
        },
        fixture::registry::{RESOURCE_REGISTRY_FILE, ResourceRegistry},
        ports::{ProtocolAdminError, ProtocolAdminServerPort, ProtocolServerInfo},
        preflight::{ProtocolPreflightSummary, ProtocolStaleResourceScan},
        reporting::{
            PROTOCOL_FLAKE_HISTORY_FILE, PROTOCOL_JUNIT_FILE, ProtocolAssertion,
            ProtocolCaseOutcome, ProtocolCaseReport, ProtocolCaseResultSummary, ProtocolCaseStatus,
            ProtocolCleanupReport, ProtocolFailureSummary, ProtocolFlakeHistory,
            ProtocolFlakeHistoryEntry, ProtocolReproduction, ProtocolSuiteSummary,
            protocol_flake_signals, protocol_flake_status, protocol_junit_xml,
        },
        runner::artifacts::ProtocolArtifactWriter,
        suite::{ProtocolSuite, protocol_suite_template_yaml},
        suite_plan::{ProtocolSuitePlan, TargetFingerprint},
    };
    use async_trait::async_trait;
    use std::{fs, path::Path};

    #[derive(Clone, Default)]
    struct CleanupAdmin;

    #[async_trait]
    impl ProtocolAdminServerPort for CleanupAdmin {
        async fn server_info(&self) -> Result<ProtocolServerInfo, ProtocolAdminError> {
            Ok(ProtocolServerInfo {
                deployment_id: "deployment".to_string(),
                mode: None,
                region: None,
            })
        }
    }

    #[test]
    fn relative_registry_path_uses_current_directory_as_artifact_parent() {
        assert_eq!(
            artifact_parent(
                Path::new(RESOURCE_REGISTRY_FILE),
                "resource registry path has no parent"
            )
            .expect("relative registry parent"),
            Path::new(".")
        );
    }

    #[test]
    fn cleanup_failure_does_not_overwrite_primary_case_failure() {
        let mut report = ProtocolCaseExecution::harness_failed("case", "primary failure").report;
        let cleanup = ProtocolCleanupReport {
            api_version: report.api_version.clone(),
            kind: "ProtocolCleanupReport".to_string(),
            attempts: Vec::new(),
            leftovers: vec!["object:key".to_string()],
            succeeded: false,
        };

        apply_cleanup_diagnostics(&mut report, &cleanup);

        assert_eq!(report.failure_phase.as_deref(), Some("harness"));
        assert_eq!(
            report.failure_classification.as_deref(),
            Some("protocol-case-failure")
        );
        assert_eq!(report.failure.as_deref(), Some("primary failure"));
        let cleanup_failure = report.cleanup_failure.expect("cleanup failure");
        assert_eq!(cleanup_failure.classification, "cleanup-failure");
        assert_eq!(cleanup_failure.leftovers, vec!["object:key"]);
    }

    #[test]
    fn cleanup_only_failure_becomes_the_primary_case_failure() {
        let mut report = ProtocolCaseExecution::harness_failed("case", "unused").report;
        report.status = ProtocolCaseStatus::Passed;
        report.outcome = ProtocolCaseOutcome::Passed;
        report.failure_phase = None;
        report.failure = None;
        report.failure_classification = None;
        let cleanup = ProtocolCleanupReport {
            api_version: report.api_version.clone(),
            kind: "ProtocolCleanupReport".to_string(),
            attempts: Vec::new(),
            leftovers: vec!["bucket:test".to_string()],
            succeeded: false,
        };

        apply_cleanup_diagnostics(&mut report, &cleanup);

        assert_eq!(report.status, ProtocolCaseStatus::Failed);
        assert_eq!(report.outcome, ProtocolCaseOutcome::Failed);
        assert_eq!(report.failure_phase.as_deref(), Some("cleanup"));
        assert_eq!(
            report.failure_classification.as_deref(),
            Some("cleanup-failure")
        );
    }

    #[test]
    fn corrupt_case_registry_is_recorded_without_aborting_diagnostics() {
        let directory = tempfile::tempdir().expect("tempdir");
        let registry_path = directory.path().join(RESOURCE_REGISTRY_FILE);
        fs::write(&registry_path, "{\"apiVersion\":").expect("corrupt registry");
        let mut cleanup = ProtocolCleanupReport::empty("rustfs.com/s3chaos/v1alpha1");
        let fallback = crate::protocol::runner::cleanup::registry_failure(
            "rustfs.com/s3chaos/v1alpha1",
            &registry_path,
            "fallback could not load registry",
        );

        reconcile_case_cleanup(&mut cleanup, &fallback, &registry_path);

        assert!(!cleanup.succeeded);
        assert_eq!(cleanup.attempts.len(), 1);
        assert_eq!(cleanup.leftovers.len(), 1);
        serde_json::to_vec(&cleanup).expect("cleanup diagnostics remain serializable");
    }

    #[test]
    fn flake_history_is_partitioned_by_target_fingerprint() {
        let base = tempfile::tempdir().expect("tempdir");
        let suite: ProtocolSuite =
            serde_yaml_ng::from_str(protocol_suite_template_yaml()).expect("template suite");
        let resolved = suite.resolve().expect("resolved suite");
        let preflight = || crate::protocol::suite_plan::ProtocolSuitePlanPreflight {
            endpoint_reachable: true,
            admin_api_reachable: true,
            external_identity: None,
            capability_matrix: Vec::new(),
            stale_buckets: Vec::new(),
            stale_identities: Vec::new(),
            stale_resource_policy: "record-only-phase-1".to_string(),
            mutating_permission_probe:
                crate::protocol::suite_plan::ProtocolMutatingProbeSummary::not_run(),
        };
        let plan_for = |deployment: &str, run_id: &str| {
            let fingerprint = TargetFingerprint::new(
                "http://127.0.0.1:9000",
                "us-east-1",
                deployment,
                None,
                None,
            )
            .expect("fingerprint");
            ProtocolSuitePlan::build(&resolved, fingerprint, preflight(), base.path(), run_id)
                .expect("plan")
        };
        let outcome = || {
            vec![(
                ProtocolCaseExecution::harness_failed("case", "executor failed"),
                ProtocolCleanupReport::empty("rustfs.com/s3chaos/v1alpha1"),
            )]
        };

        let shared_first = plan_for("shared-target", "run-1");
        let shared_second = plan_for("shared-target", "run-2");
        let candidate = plan_for("candidate-target", "run-3");
        for plan in [&shared_first, &shared_second, &candidate] {
            super::update_protocol_flake_history(&plan.artifact_root(), plan, &outcome())
                .expect("history update");
        }

        let history_file = |plan: &ProtocolSuitePlan| {
            base.path().join(".history").join(format!(
                "{}-{}.json",
                plan.profile, plan.target.fingerprint.sha256
            ))
        };
        assert_ne!(history_file(&shared_first), history_file(&candidate));
        let shared: ProtocolFlakeHistory = serde_json::from_str(
            &fs::read_to_string(history_file(&shared_second)).expect("shared"),
        )
        .expect("shared history");
        assert_eq!(
            shared
                .entries
                .iter()
                .map(|entry| entry.run_id.as_str())
                .collect::<Vec<_>>(),
            ["run-1", "run-2"]
        );
        let isolated: ProtocolFlakeHistory =
            serde_json::from_str(&fs::read_to_string(history_file(&candidate)).expect("candidate"))
                .expect("candidate history");
        assert_eq!(
            isolated
                .entries
                .iter()
                .map(|entry| entry.run_id.as_str())
                .collect::<Vec<_>>(),
            ["run-3"]
        );
    }

    #[test]
    fn exact_run_root_relocates_case_paths_and_refuses_existing_artifacts() {
        let base = tempfile::tempdir().expect("temporary run directory");
        let suite: ProtocolSuite =
            serde_yaml_ng::from_str(protocol_suite_template_yaml()).expect("suite");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let preflight = crate::protocol::suite_plan::ProtocolSuitePlanPreflight {
            endpoint_reachable: true,
            admin_api_reachable: true,
            external_identity: None,
            capability_matrix: Vec::new(),
            stale_buckets: Vec::new(),
            stale_identities: Vec::new(),
            stale_resource_policy: "fail".into(),
            mutating_permission_probe:
                crate::protocol::suite_plan::ProtocolMutatingProbeSummary::not_run(),
        };
        let mut plan = ProtocolSuitePlan::build(
            &suite.resolve().expect("resolved suite"),
            fingerprint,
            preflight,
            base.path(),
            "run",
        )
        .expect("plan");
        let exact = base.path().join("workflow/artifacts");
        super::claim_exact_protocol_run_root(&mut plan, &exact).expect("claim exact root");
        assert_eq!(plan.artifact_root(), exact);
        assert!(
            plan.cases
                .iter()
                .all(|case| Path::new(&case.artifact_dir) == exact.join("cases").join(&case.id))
        );
        fs::write(exact.join("preserved"), b"original evidence").expect("original artifact");
        assert!(super::claim_exact_protocol_run_root(&mut plan, &exact).is_err());
        assert_eq!(
            fs::read(exact.join("preserved")).expect("preserved artifact"),
            b"original evidence"
        );
    }

    #[test]
    fn flaky_history_is_a_signal_without_implicit_retries() {
        let entries = [
            ProtocolFlakeHistoryEntry {
                run_id: "passed-run".to_string(),
                source_revision: Some("revision".to_string()),
                case_id: "case".to_string(),
                variant_id: "default".to_string(),
                status: ProtocolCaseStatus::Passed,
                implicit_retry_count: 0,
            },
            ProtocolFlakeHistoryEntry {
                run_id: "failed-run".to_string(),
                source_revision: Some("revision".to_string()),
                case_id: "case".to_string(),
                variant_id: "default".to_string(),
                status: ProtocolCaseStatus::Failed,
                implicit_retry_count: 0,
            },
        ];
        let signals = protocol_flake_signals(&entries);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].flaky);
        assert_eq!(signals[0].passed, 1);
        assert_eq!(signals[0].failed, 1);
        assert!(entries.iter().all(|entry| entry.implicit_retry_count == 0));
    }

    #[test]
    fn flaky_history_does_not_treat_unexecuted_cases_as_failures() {
        let preflight = ProtocolCaseExecution::preflight_failed("case", "preflight failed");
        let not_run = ProtocolCaseExecution::not_run("case", "suite timed out");
        let harness_failure = ProtocolCaseExecution::harness_failed("case", "executor failed");

        assert_eq!(
            protocol_flake_status(&preflight.report),
            ProtocolCaseStatus::Skipped
        );
        assert_eq!(
            protocol_flake_status(&not_run.report),
            ProtocolCaseStatus::Skipped
        );
        assert_eq!(
            protocol_flake_status(&harness_failure.report),
            ProtocolCaseStatus::Failed
        );
    }

    #[tokio::test]
    async fn standalone_cleanup_rejects_synthetic_s3_fingerprint() {
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "s3-endpoint:http://127.0.0.1:9000",
            None,
            None,
        )
        .expect("fingerprint");

        let error = super::verify_cleanup_target(&CleanupAdmin, &fingerprint)
            .await
            .expect_err("synthetic fingerprints must fail closed");

        assert!(
            error
                .to_string()
                .contains("no verifiable deployment fingerprint")
        );
    }

    #[test]
    fn artifact_sanity_check_accepts_linked_secret_free_run() {
        let base = tempfile::tempdir().expect("tempdir");
        let suite = serde_yaml_ng::from_str::<ProtocolSuite>(protocol_suite_template_yaml())
            .expect("suite")
            .resolve()
            .expect("resolved");
        let fingerprint = TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "deployment",
            None,
            None,
        )
        .expect("fingerprint");
        let capability_matrix = [
            ProtocolCapability::S3,
            ProtocolCapability::AdminApi,
            ProtocolCapability::BucketPolicy,
            ProtocolCapability::Identity,
        ]
        .into_iter()
        .map(|capability| ProtocolCapabilityCheck {
            capability,
            source: ProtocolCapabilitySource::BuiltIn,
            state: ProtocolCapabilityState::Pass,
            reason: "available".to_string(),
        })
        .collect::<Vec<_>>();
        let preflight = ProtocolPreflightSummary {
            api_version: suite.api_version.clone(),
            kind: "ProtocolPreflightSummary".to_string(),
            target_fingerprint: fingerprint.clone(),
            endpoint_reachable: true,
            admin_api_reachable: true,
            external_identity: None,
            selected_cases: vec!["bucket-policy-authenticated-user-rw".to_string()],
            capability_matrix: capability_matrix.clone(),
            stale_resources: ProtocolStaleResourceScan {
                bucket_prefix: "s3c".to_string(),
                identity_prefix: "s3chaos".to_string(),
                buckets: Vec::new(),
                identities: Vec::new(),
                policy: "record-only-phase-1".to_string(),
            },
            mutating_permission_probe:
                crate::protocol::suite_plan::ProtocolMutatingProbeSummary::not_run(),
        };
        let plan = ProtocolSuitePlan::build(
            &suite,
            fingerprint.clone(),
            (&preflight).into(),
            base.path(),
            "run",
        )
        .expect("plan");
        let root = plan.artifact_root();
        let case_dir = root.join("cases/bucket-policy-authenticated-user-rw");
        let artifacts = ProtocolArtifactWriter::file(&root);
        let suite_source = tempfile::NamedTempFile::new().expect("suite source");
        fs::write(suite_source.path(), protocol_suite_template_yaml()).expect("suite source");
        artifacts
            .initialize_run(suite_source.path())
            .expect("initialize artifacts");
        artifacts
            .create_case_dir("bucket-policy-authenticated-user-rw")
            .expect("case dir");
        artifacts
            .write_json("protocol-suite-plan.json", &plan)
            .expect("plan artifact");
        artifacts
            .write_json("preflight-summary.json", &preflight)
            .expect("preflight artifact");
        ResourceRegistry::create(&root, "run", fingerprint.clone()).expect("registry");
        let mut case_registry = ResourceRegistry::create(&case_dir, "run", fingerprint)
            .expect("case resource registry");
        case_registry
            .bind_case(
                "bucket-policy-authenticated-user-rw",
                crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT,
            )
            .expect("bind case resource contract");
        let cleanup = ProtocolCleanupReport {
            api_version: suite.api_version.clone(),
            kind: "ProtocolCleanupReport".to_string(),
            attempts: Vec::new(),
            leftovers: Vec::new(),
            succeeded: true,
        };
        artifacts
            .write_json("cleanup-report.json", &cleanup)
            .expect("cleanup artifact");
        let case_report = ProtocolCaseReport {
            api_version: suite.api_version.clone(),
            kind: "ProtocolCaseReport".to_string(),
            case_id: "bucket-policy-authenticated-user-rw".to_string(),
            variant_id: crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT.to_string(),
            domain: crate::protocol::catalog::ProtocolDomain::Authorization,
            status: ProtocolCaseStatus::Passed,
            outcome: ProtocolCaseOutcome::Passed,
            duration_millis: 125,
            capabilities: capability_matrix.clone(),
            actors: Vec::new(),
            assertions: Vec::new(),
            failure_phase: None,
            failure: None,
            failure_classification: None,
            cleanup_succeeded: true,
            cleanup_failure: None,
            evidence: vec![
                "cases/bucket-policy-authenticated-user-rw/case-report.json".to_string(),
                "cases/bucket-policy-authenticated-user-rw/cleanup-report.json".to_string(),
                "cases/bucket-policy-authenticated-user-rw/operation-history.jsonl".to_string(),
                format!(
                    "cases/bucket-policy-authenticated-user-rw/{RESOURCE_REGISTRY_FILE}"
                ),
            ],
            reproduction: Some(ProtocolReproduction {
                command: "s3chaos protocol-suite-reproduce 'artifacts' 'bucket-policy-authenticated-user-rw'".to_string(),
                suite: plan.suite.clone(),
                case_id: "bucket-policy-authenticated-user-rw".to_string(),
                variant_id: crate::protocol::catalog::DEFAULT_PROTOCOL_VARIANT.to_string(),
                seed: "deterministic-no-randomized-order".to_string(),
                original_run_id: plan.run_id.clone(),
                target_fingerprint: plan.target.fingerprint.sha256.clone(),
                capability_profile: plan.cases[0].requires.clone(),
            }),
        };
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/case-report.json",
                &case_report,
            )
            .expect("case artifact");
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/cleanup-report.json",
                &cleanup,
            )
            .expect("case cleanup artifact");
        artifacts
            .write_json_lines::<ProtocolAssertion>(
                "cases/bucket-policy-authenticated-user-rw/operation-history.jsonl",
                &[],
            )
            .expect("case history artifact");
        let flake_entry = ProtocolFlakeHistoryEntry {
            run_id: plan.run_id.clone(),
            source_revision: plan.source_revision.clone(),
            case_id: case_report.case_id.clone(),
            variant_id: case_report.variant_id.clone(),
            status: protocol_flake_status(&case_report),
            implicit_retry_count: 0,
        };
        let flake_history = ProtocolFlakeHistory {
            api_version: suite.api_version.clone(),
            kind: "ProtocolFlakeHistory".to_string(),
            profile: plan.profile,
            entries: vec![flake_entry.clone()],
            signals: protocol_flake_signals(&[flake_entry]),
        };
        artifacts
            .write_json(PROTOCOL_FLAKE_HISTORY_FILE, &flake_history)
            .expect("flake history artifact");
        let case_report_path =
            "cases/bucket-policy-authenticated-user-rw/case-report.json".to_string();
        let summary = ProtocolSuiteSummary {
            api_version: suite.api_version,
            kind: "ProtocolSuiteSummary".to_string(),
            suite: suite.metadata.name,
            run_id: "run".to_string(),
            profile: plan.profile,
            target_fingerprint: plan.target.fingerprint.sha256.clone(),
            capability_matrix,
            status: ProtocolCaseStatus::Passed,
            plan: "protocol-suite-plan.json".to_string(),
            preflight: "preflight-summary.json".to_string(),
            registry: "resource-registry.json".to_string(),
            cleanup: "cleanup-report.json".to_string(),
            compatibility_coverage: None,
            flaky_history: PROTOCOL_FLAKE_HISTORY_FILE.to_string(),
            case_reports: vec![case_report_path.clone()],
            case_results: vec![
                ProtocolCaseResultSummary::from_report(&case_report, case_report_path.clone())
                    .expect("case result"),
            ],
            failure_summary: None,
        };
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("summary artifact");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&case_report], cleanup.succeeded),
            )
            .expect("JUnit artifact");

        validate_phase_one_artifacts(&root, &["not-present-secret".to_string()])
            .expect("valid artifacts");

        let mut legacy_summary = summary.clone();
        legacy_summary.compatibility_coverage = Some("compatibility-coverage.json".to_string());
        artifacts
            .write_json(
                "compatibility-coverage.json",
                &serde_json::json!({
                    "apiVersion": "rustfs.com/s3chaos/v1alpha1",
                    "kind": "ProtocolCompatibilityCoverageReport"
                }),
            )
            .expect("legacy coverage artifact");
        artifacts
            .write_json("protocol-suite-summary.json", &legacy_summary)
            .expect("legacy summary artifact");
        validate_phase_one_artifacts(&root, &[]).expect("legacy summary remains readable");
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("restore current summary");

        let mut inconsistent_flake_history = flake_history.clone();
        inconsistent_flake_history.signals.clear();
        artifacts
            .write_json(PROTOCOL_FLAKE_HISTORY_FILE, &inconsistent_flake_history)
            .expect("inconsistent flake history");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_json(PROTOCOL_FLAKE_HISTORY_FILE, &flake_history)
            .expect("restore flake history");

        let mut inconsistent_summary = summary.clone();
        inconsistent_summary.case_results[0].duration_millis += 1;
        artifacts
            .write_json("protocol-suite-summary.json", &inconsistent_summary)
            .expect("inconsistent summary");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("restore summary");

        let mut invalid_evidence_report = case_report.clone();
        invalid_evidence_report
            .evidence
            .push("../escape".to_string());
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/case-report.json",
                &invalid_evidence_report,
            )
            .expect("invalid evidence report");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/case-report.json",
                &case_report,
            )
            .expect("restore case report");

        let mut inconsistent_case_cleanup = cleanup.clone();
        inconsistent_case_cleanup.leftovers = vec!["unregistered-resource".to_string()];
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/cleanup-report.json",
                &inconsistent_case_cleanup,
            )
            .expect("inconsistent cleanup report");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/cleanup-report.json",
                &cleanup,
            )
            .expect("restore case cleanup report");

        let case_registry_path = case_dir.join(RESOURCE_REGISTRY_FILE);
        let case_registry_relative =
            Path::new("cases/bucket-policy-authenticated-user-rw").join(RESOURCE_REGISTRY_FILE);
        let valid_case_registry = case_registry.clone();
        fs::remove_file(&case_registry_path).expect("remove case registry");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());

        let mut not_run_report = case_report.clone();
        not_run_report.status = ProtocolCaseStatus::Failed;
        not_run_report.outcome = ProtocolCaseOutcome::NotRun;
        not_run_report.duration_millis = 0;
        not_run_report.failure_phase = Some("not-run".to_string());
        not_run_report.failure = Some("prior wave timed out".to_string());
        not_run_report.failure_classification = Some("not-run".to_string());
        not_run_report
            .evidence
            .retain(|path| !path.ends_with(RESOURCE_REGISTRY_FILE));
        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/case-report.json",
                &not_run_report,
            )
            .expect("not-run case report");
        let not_run_flake_entry = ProtocolFlakeHistoryEntry {
            run_id: plan.run_id.clone(),
            source_revision: plan.source_revision.clone(),
            case_id: not_run_report.case_id.clone(),
            variant_id: not_run_report.variant_id.clone(),
            status: protocol_flake_status(&not_run_report),
            implicit_retry_count: 0,
        };
        artifacts
            .write_json(
                PROTOCOL_FLAKE_HISTORY_FILE,
                &ProtocolFlakeHistory {
                    api_version: summary.api_version.clone(),
                    kind: "ProtocolFlakeHistory".to_string(),
                    profile: plan.profile,
                    entries: vec![not_run_flake_entry.clone()],
                    signals: protocol_flake_signals(&[not_run_flake_entry]),
                },
            )
            .expect("not-run flake history");
        artifacts
            .write_json(
                "protocol-failure-summary.json",
                &ProtocolFailureSummary {
                    api_version: summary.api_version.clone(),
                    kind: "ProtocolFailureSummary".to_string(),
                    stage: "not-run".to_string(),
                    classification: "not-run".to_string(),
                    case_id: Some(not_run_report.case_id.clone()),
                    evidence: vec![
                        "cases/bucket-policy-authenticated-user-rw/case-report.json".to_string(),
                    ],
                },
            )
            .expect("not-run failure summary");
        let mut not_run_summary = summary.clone();
        not_run_summary.status = ProtocolCaseStatus::Failed;
        not_run_summary.case_results = vec![
            ProtocolCaseResultSummary::from_report(&not_run_report, case_report_path.clone())
                .expect("not-run case result"),
        ];
        not_run_summary.failure_summary = Some("protocol-failure-summary.json".to_string());
        artifacts
            .write_json("protocol-suite-summary.json", &not_run_summary)
            .expect("not-run suite summary");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&not_run_report], cleanup.succeeded),
            )
            .expect("not-run JUnit artifact");
        validate_phase_one_artifacts(&root, &[])
            .expect("never-started case does not require a registry");

        artifacts
            .write_json(
                "cases/bucket-policy-authenticated-user-rw/case-report.json",
                &case_report,
            )
            .expect("restore case report");
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("restore suite summary");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&case_report], cleanup.succeeded),
            )
            .expect("restore JUnit after not-run fixture");
        artifacts
            .write_json(PROTOCOL_FLAKE_HISTORY_FILE, &flake_history)
            .expect("restore flake history after not-run fixture");
        fs::remove_file(root.join("protocol-failure-summary.json"))
            .expect("remove not-run failure summary");
        artifacts
            .write_json(&case_registry_relative, &valid_case_registry)
            .expect("restore case registry");

        artifacts
            .write_text(&case_registry_relative, "{\"apiVersion\":")
            .expect("partial registry fixture");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_json(&case_registry_relative, &valid_case_registry)
            .expect("restore registry after partial write fixture");

        let reject_registry_tampering = |tampered: &ResourceRegistry| {
            artifacts
                .write_json(&case_registry_relative, tampered)
                .expect("write tampered case registry");
            assert!(validate_phase_one_artifacts(&root, &[]).is_err());
            artifacts
                .write_json(&case_registry_relative, &valid_case_registry)
                .expect("restore valid case registry");
        };

        let mut tampered = valid_case_registry.clone();
        tampered.contract = None;
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered.contract.as_mut().expect("contract").case_id = "different-case".to_string();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered.contract.as_mut().expect("contract").variant_id = "different-variant".to_string();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered
            .contract
            .as_mut()
            .expect("contract")
            .ownership
            .pop();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered
            .contract
            .as_mut()
            .expect("contract")
            .cleanup_scopes
            .pop();
        reject_registry_tampering(&tampered);

        let mut tampered = valid_case_registry.clone();
        tampered
            .contract
            .as_mut()
            .expect("contract")
            .lock_requirements
            .pop();
        reject_registry_tampering(&tampered);

        validate_phase_one_artifacts(&root, &[]).expect("restored registry contract");

        let mut failed_cleanup = cleanup.clone();
        failed_cleanup.succeeded = false;
        failed_cleanup.leftovers = vec!["suite-resource".to_string()];
        artifacts
            .write_json("cleanup-report.json", &failed_cleanup)
            .expect("failed suite cleanup artifact");
        artifacts
            .write_json(
                "protocol-failure-summary.json",
                &ProtocolFailureSummary {
                    api_version: summary.api_version.clone(),
                    kind: "ProtocolFailureSummary".to_string(),
                    stage: "cleanup".to_string(),
                    classification: "cleanup-failed".to_string(),
                    case_id: None,
                    evidence: vec!["cleanup-report.json".to_string()],
                },
            )
            .expect("suite cleanup failure summary");
        let mut failed_summary = summary.clone();
        failed_summary.status = ProtocolCaseStatus::Failed;
        failed_summary.failure_summary = Some("protocol-failure-summary.json".to_string());
        artifacts
            .write_json("protocol-suite-summary.json", &failed_summary)
            .expect("failed suite summary");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&case_report], true),
            )
            .expect("incorrect passing suite-cleanup JUnit artifact");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&case_report], failed_cleanup.succeeded),
            )
            .expect("failed suite-cleanup JUnit artifact");
        validate_phase_one_artifacts(&root, &[]).expect("suite cleanup failure is linked to JUnit");

        artifacts
            .write_json("cleanup-report.json", &cleanup)
            .expect("restore cleanup artifact");
        artifacts
            .write_json("protocol-suite-summary.json", &summary)
            .expect("restore suite summary");
        fs::remove_file(root.join("protocol-failure-summary.json"))
            .expect("remove suite cleanup failure summary");
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&case_report], cleanup.succeeded),
            )
            .expect("restore passing JUnit artifact");
        fs::remove_file(root.join(PROTOCOL_JUNIT_FILE)).expect("remove JUnit artifact");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_text(PROTOCOL_JUNIT_FILE, "<testsuite/>")
            .expect("tampered JUnit");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        artifacts
            .write_text(
                PROTOCOL_JUNIT_FILE,
                &protocol_junit_xml(&summary.suite, &[&case_report], cleanup.succeeded),
            )
            .expect("restore JUnit artifact");
        validate_phase_one_artifacts(&root, &[]).expect("restored JUnit artifacts");
        artifacts
            .write_text(
                "credential-leak.json",
                r#"{"secretKey":"unknown-to-validator"}"#,
            )
            .expect("leak fixture");
        assert!(validate_phase_one_artifacts(&root, &[]).is_err());
        let report: crate::protocol::reporting::ProtocolArtifactValidationReport =
            serde_json::from_str(
                &fs::read_to_string(root.join(
                    crate::protocol::artifact_validation::PROTOCOL_ARTIFACT_VALIDATION_REPORT,
                ))
                .expect("validation report"),
            )
            .expect("parse validation report");
        assert!(!report.valid);
    }
}
