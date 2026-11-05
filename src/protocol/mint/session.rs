// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    fs::{self, File},
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::{process::Command, sync::watch, time::timeout};
use uuid::Uuid;

use super::{
    API_VERSION, MintCapturedRun, MintGateStatus, MintInfrastructureFailure, MintInventory,
    MintKnownFailures, MintMode, MintProfile, MintProfileSpec,
    artifacts::{ensure_mint_artifact_tree_safe, sanitize_mint_bytes},
    target::{
        MintNamespaceProof, MintTargetDiagnostic, MintTargetProof, MintTargetSpec,
        MintTargetTeardownProof, collect_mint_target_diagnostics, mint_endpoint_authority,
        prove_mint_namespace, teardown_mint_target, timestamp_now, verify_mint_target_ready,
    },
    validate_mint_artifacts_and_write_report, write_mint_artifacts,
};
use crate::protocol::{
    credentials::{CredentialProvider, EnvCredentialProvider},
    runner::artifacts::ProtocolArtifactWriter,
};

const TARGET_SPEC_FILE: &str = "mint-target-spec.json";
const NAMESPACE_PROOF_FILE: &str = "mint-namespace-proof.json";
const TARGET_PROOF_FILE: &str = "mint-target-proof.json";
const LIFECYCLE_FILE: &str = "mint-session-lifecycle.json";
const CLEANUP_REPORT_FILE: &str = "mint-cleanup-report.json";
const SESSION_SUMMARY_FILE: &str = "mint-session-summary.json";
const SESSION_JUNIT_FILE: &str = "mint-session-junit.xml";
const SESSION_EXIT_CODE_FILE: &str = "mint-session-exit-code.txt";
const SESSION_CREDENTIAL_SCAN_FILE: &str = "mint-session-credential-scan.json";
const MINT_PUBLICATION_ERROR_FILE: &str = "mint-publication-error.txt";
pub const MINT_SESSION_VALIDATION_FILE: &str = "mint-session-validation.json";
const MINT_ARTIFACT_DIR: &str = "mint";
const KUBERNETES_ARTIFACT_DIR: &str = "kubernetes";
const MAX_CAPTURE_BYTES: u64 = 64 * 1024 * 1024;
const ADMIN_ACCESS_KEY_ENV: &str = "RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY";
const ADMIN_SECRET_KEY_ENV: &str = "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY";
const ADMIN_SESSION_TOKEN_ENV: &str = "RUSTFS_PROTOCOL_TEST_ADMIN_SESSION_TOKEN";

#[derive(Debug, Clone)]
pub struct MintSessionRequest {
    pub artifact_root: PathBuf,
    pub target: MintTargetSpec,
    pub profile_name: String,
    pub mint_image: String,
    pub mint_platform: String,
    pub mint_mode: MintMode,
    pub mint_suites: Vec<String>,
    pub inventory: MintInventory,
    pub known_failures: MintKnownFailures,
    pub forbidden_material: Vec<String>,
}

/// Reuses the recorded Mint inputs with an independently verified new target.
pub fn mint_reproduction_request(
    original_root: impl AsRef<Path>,
    target: MintTargetSpec,
    artifact_root: impl Into<PathBuf>,
) -> Result<MintSessionRequest> {
    let original_root = original_root.as_ref();
    ensure_safe_session_root(original_root)?;
    ensure_mint_artifact_tree_safe(original_root, &[])?;
    let original_target: MintTargetSpec = read_json(&original_root.join(TARGET_SPEC_FILE))?;
    original_target.validate_contract()?;
    target.validate_at(&timestamp_now()?)?;
    ensure!(
        target.namespace_uid != original_target.namespace_uid,
        "Mint reproduction requires a new temporary namespace UID"
    );
    let mint_root = original_root.join(MINT_ARTIFACT_DIR);
    let profile: MintProfile = read_json(&mint_root.join("mint-profile.json"))?;
    ensure!(
        profile.target_fingerprint == format!("sha256:{}", original_target.target_fingerprint)
            && profile.region == original_target.region,
        "recorded Mint profile does not match its original target"
    );
    let request = MintSessionRequest {
        artifact_root: artifact_root.into(),
        target,
        profile_name: profile.name,
        mint_image: profile.image,
        mint_platform: profile.platform,
        mint_mode: profile.mode,
        mint_suites: profile.suites,
        inventory: read_json(&mint_root.join("mint-inventory.json"))?,
        known_failures: read_json(&mint_root.join("mint-known-failures.json"))?,
        forbidden_material: [
            ADMIN_ACCESS_KEY_ENV,
            ADMIN_SECRET_KEY_ENV,
            ADMIN_SESSION_TOKEN_ENV,
        ]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .filter(|value| !value.is_empty())
        .collect(),
    };
    ensure!(
        !request.artifact_root.exists(),
        "Mint reproduction artifact root already exists"
    );
    validate_request(&request)?;
    Ok(request)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintSessionPublication {
    pub gate_exit_code: i32,
    pub cleanup_exit_code: i32,
    pub terminal_summary: String,
    pub artifact_root: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MintSessionPhase {
    Initialized,
    OwnershipVerified,
    TargetVerified,
    MintFinished,
    DiagnosticsCollected,
    TeardownRequested,
    Finished,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MintProcessDisposition {
    NotRun,
    Completed,
    TimedOut,
    Interrupted,
    StartFailed,
    RuntimeFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MintTeardownStatus {
    NotRun,
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MintSessionGateStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MintSessionFailureCode {
    OwnershipRejected,
    TargetPreflightFailed,
    MintStartFailed,
    MintRuntimeFailed,
    MintTimedOut,
    MintInterrupted,
    MintGateFailed,
    MintPublicationFailed,
    DiagnosticCollectionFailed,
    ContainerCleanupFailed,
    TargetTeardownFailed,
    RecoveryCleanup,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintSessionLifecycle {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    run_id: String,
    phase: MintSessionPhase,
    updated_at: String,
    container_name: String,
    namespace_proof_persisted: bool,
    target_proof_persisted: bool,
    mint_artifacts_published: bool,
    admin_session_token_used: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintCleanupReport {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    status: MintTeardownStatus,
    container_name: String,
    container_absent: bool,
    namespace_absent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    teardown_proof: Option<MintTargetTeardownProof>,
    failure_codes: Vec<MintSessionFailureCode>,
    errors: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintSessionArtifactReferences {
    target_spec: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    namespace_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_proof: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mint: Option<String>,
    kubernetes: String,
    lifecycle: String,
    cleanup_report: String,
    junit: String,
    exit_code: String,
    credential_scan: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintSessionSummary {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    run_id: String,
    process_disposition: MintProcessDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    container_exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mint_gate_status: Option<MintGateStatus>,
    diagnostics_collected: bool,
    teardown_status: MintTeardownStatus,
    gate_status: MintSessionGateStatus,
    failure_codes: Vec<MintSessionFailureCode>,
    artifacts: MintSessionArtifactReferences,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintSessionCredentialFile {
    path: String,
    redacted: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MintSessionCredentialScan {
    #[serde(rename = "apiVersion")]
    api_version: String,
    kind: String,
    run_id: String,
    redaction_token: String,
    detected: bool,
    files: Vec<MintSessionCredentialFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintSessionValidationReport {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub artifact_root: String,
    pub valid: bool,
    pub errors: Vec<String>,
}

#[derive(Debug)]
struct OwnedMintCapture {
    process_disposition: MintProcessDisposition,
    container_started: bool,
    container_exit_code: Option<i32>,
    infrastructure_failure: Option<MintInfrastructureFailure>,
    log: Option<Vec<u8>>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

struct CaptureDirectory {
    root: PathBuf,
}

impl CaptureDirectory {
    fn new() -> Result<Self> {
        let root = std::env::temp_dir().join(format!("s3chaos-mint-capture-{}", Uuid::new_v4()));
        fs::create_dir(&root)
            .with_context(|| format!("create Mint capture directory {}", root.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        }
        fs::create_dir(root.join("log"))?;
        Ok(Self { root })
    }

    fn log(&self) -> PathBuf {
        self.root.join("log/log.json")
    }

    fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }

    fn stdout(&self) -> PathBuf {
        self.root.join("stdout.log")
    }

    fn stderr(&self) -> PathBuf {
        self.root.join("stderr.log")
    }
}

impl Drop for CaptureDirectory {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700));
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub async fn run_mint_session(request: MintSessionRequest) -> Result<MintSessionPublication> {
    ensure!(
        std::env::var("RUSTFS_PROTOCOL_TEST_DEDICATED").as_deref() == Ok("1"),
        "set RUSTFS_PROTOCOL_TEST_DEDICATED=1 only for a verified ephemeral Mint target"
    );
    let started_at = timestamp_now()?;
    request.target.validate_at(&started_at)?;
    validate_request(&request)?;
    claim_session_root(&request.artifact_root)?;
    let writer = ProtocolArtifactWriter::file(&request.artifact_root);
    writer.create_dir(KUBERNETES_ARTIFACT_DIR)?;
    write_safe_json(
        &writer,
        TARGET_SPEC_FILE,
        &request.target,
        &request.forbidden_material,
    )?;
    let mut lifecycle = MintSessionLifecycle {
        api_version: API_VERSION.to_string(),
        kind: "MintSessionLifecycle".to_string(),
        run_id: request.target.run_id.clone(),
        phase: MintSessionPhase::Initialized,
        updated_at: started_at.clone(),
        container_name: request.target.container_name(),
        namespace_proof_persisted: false,
        target_proof_persisted: false,
        mint_artifacts_published: false,
        admin_session_token_used: admin_session_token_used(),
    };
    write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;
    let mut cancellation = install_process_cancellation();

    let namespace_proof = match prove_mint_namespace(&request.target, &started_at).await {
        Ok(proof) => proof,
        Err(error) => {
            let publication = finish_without_ownership(
                &request,
                &writer,
                &mut lifecycle,
                MintSessionFailureCode::OwnershipRejected,
                &error,
            )?;
            return Ok(publication);
        }
    };
    let session_result: Result<MintSessionPublication> = async {
        write_safe_json(
            &writer,
            NAMESPACE_PROOF_FILE,
            &namespace_proof,
            &request.forbidden_material,
        )?;
        lifecycle.namespace_proof_persisted = true;
        lifecycle.phase = MintSessionPhase::OwnershipVerified;
        write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;

        let mut failure_codes = Vec::new();
        let mut target_proof = None;
        if cancellation_requested(&cancellation) {
            failure_codes.push(MintSessionFailureCode::MintInterrupted);
        } else {
            match verify_mint_target_ready(&request.target, &namespace_proof, &timestamp_now()?)
                .await
            {
                Ok(proof) => {
                    write_safe_json(
                        &writer,
                        TARGET_PROOF_FILE,
                        &proof,
                        &request.forbidden_material,
                    )?;
                    lifecycle.target_proof_persisted = true;
                    lifecycle.phase = MintSessionPhase::TargetVerified;
                    write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;
                    target_proof = Some(proof);
                }
                Err(error) => {
                    failure_codes.push(MintSessionFailureCode::TargetPreflightFailed);
                    write_failure_detail(
                        &writer,
                        "kubernetes/target-preflight-error.txt",
                        &error,
                        &request.forbidden_material,
                    )?;
                }
            }
        }

        let mut capture = OwnedMintCapture {
            process_disposition: MintProcessDisposition::NotRun,
            container_started: false,
            container_exit_code: None,
            infrastructure_failure: None,
            log: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        let mut mint_gate_status = None;
        if target_proof.is_some()
            && failure_codes.is_empty()
            && cancellation_requested(&cancellation)
        {
            failure_codes.push(MintSessionFailureCode::MintInterrupted);
        }
        if target_proof.is_some() && failure_codes.is_empty() {
            capture = run_mint_container(&request, &mut cancellation).await;
            match capture.process_disposition {
                MintProcessDisposition::TimedOut => {
                    failure_codes.push(MintSessionFailureCode::MintTimedOut)
                }
                MintProcessDisposition::Interrupted => {
                    failure_codes.push(MintSessionFailureCode::MintInterrupted)
                }
                MintProcessDisposition::StartFailed => {
                    failure_codes.push(MintSessionFailureCode::MintStartFailed)
                }
                MintProcessDisposition::RuntimeFailed => {
                    failure_codes.push(MintSessionFailureCode::MintRuntimeFailed)
                }
                MintProcessDisposition::NotRun | MintProcessDisposition::Completed => {}
            }
            let profile = MintProfile::new(MintProfileSpec {
                name: request.profile_name.clone(),
                image: request.mint_image.clone(),
                platform: request.mint_platform.clone(),
                mode: request.mint_mode,
                suites: request.mint_suites.clone(),
                region: request.target.region.clone(),
                target_fingerprint: format!(
                    "sha256:{}",
                    request
                        .target
                        .target_fingerprint
                        .trim_start_matches("sha256:")
                ),
            })?;
            match write_mint_artifacts(
                request.artifact_root.join(MINT_ARTIFACT_DIR),
                &profile,
                &request.inventory,
                &request.known_failures,
                MintCapturedRun {
                    container_started: capture.container_started,
                    container_exit_code: capture.container_exit_code,
                    infrastructure_failure: capture.infrastructure_failure,
                    log: capture.log.as_deref(),
                    stdout: &capture.stdout,
                    stderr: &capture.stderr,
                },
                &timestamp_now()?,
                &request.forbidden_material,
            ) {
                Ok(publication) => {
                    mint_gate_status = Some(publication.evaluation.gate_status);
                    lifecycle.mint_artifacts_published = true;
                    if publication.evaluation.gate_status == MintGateStatus::Failed {
                        failure_codes.push(MintSessionFailureCode::MintGateFailed);
                    }
                }
                Err(error) => {
                    failure_codes.push(MintSessionFailureCode::MintPublicationFailed);
                    write_failure_detail(
                        &writer,
                        MINT_PUBLICATION_ERROR_FILE,
                        &error,
                        &request.forbidden_material,
                    )
                    .with_context(|| format!("preserve Mint publication failure: {error:#}"))?;
                }
            }
            lifecycle.phase = MintSessionPhase::MintFinished;
            write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;
        }

        let diagnostics = collect_mint_target_diagnostics(&request.target).await;
        let diagnostics_collected = write_diagnostics(
            &writer,
            &diagnostics,
            &request.forbidden_material,
            &request.target.run_id,
        )?;
        if !diagnostics_collected {
            failure_codes.push(MintSessionFailureCode::DiagnosticCollectionFailed);
        }
        lifecycle.phase = MintSessionPhase::DiagnosticsCollected;
        write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;

        lifecycle.phase = MintSessionPhase::TeardownRequested;
        write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;
        let mut cleanup_errors = Vec::new();
        let container_absent = match remove_owned_mint_container(&request.target).await {
            Ok(()) => true,
            Err(error) => {
                failure_codes.push(MintSessionFailureCode::ContainerCleanupFailed);
                cleanup_errors.push(safe_error_message(&error, &request.forbidden_material));
                false
            }
        };
        let teardown =
            teardown_mint_target(&request.target, &namespace_proof, &timestamp_now()?).await;
        let (teardown_proof, namespace_absent) = match teardown {
            Ok(proof) => (Some(proof), true),
            Err(error) => {
                failure_codes.push(MintSessionFailureCode::TargetTeardownFailed);
                cleanup_errors.push(safe_error_message(&error, &request.forbidden_material));
                (None, false)
            }
        };
        let cleanup = MintCleanupReport {
            api_version: API_VERSION.to_string(),
            kind: "MintCleanupReport".to_string(),
            status: if container_absent && namespace_absent {
                MintTeardownStatus::Passed
            } else {
                MintTeardownStatus::Failed
            },
            container_name: request.target.container_name(),
            container_absent,
            namespace_absent,
            teardown_proof,
            failure_codes: failure_codes
                .iter()
                .copied()
                .filter(|code| {
                    matches!(
                        code,
                        MintSessionFailureCode::ContainerCleanupFailed
                            | MintSessionFailureCode::TargetTeardownFailed
                    )
                })
                .collect(),
            errors: cleanup_errors,
        };
        write_safe_json(
            &writer,
            CLEANUP_REPORT_FILE,
            &cleanup,
            &request.forbidden_material,
        )?;

        lifecycle.phase = MintSessionPhase::Finished;
        write_lifecycle(&writer, &mut lifecycle, &request.forbidden_material)?;
        let summary = build_summary(
            &request.target.run_id,
            &lifecycle,
            &capture,
            mint_gate_status,
            diagnostics_collected,
            cleanup.status,
            failure_codes,
        );
        let publication = publish_session_summary(
            &request.artifact_root,
            &writer,
            &summary,
            &request.forbidden_material,
        )?;
        validate_mint_session_artifacts_and_write_report(
            &request.artifact_root,
            &request.forbidden_material,
        )?;
        Ok(publication)
    }
    .await;
    match session_result {
        Ok(publication) => Ok(publication),
        Err(error) => {
            let cleanup = emergency_teardown_after_internal_error(
                &request,
                &writer,
                &namespace_proof,
                &error,
            )
            .await;
            match cleanup {
                Ok(()) => Err(error).context(
                    "Mint session failed internally after ownership verification; emergency target teardown completed",
                ),
                Err(cleanup_error) => bail!(
                    "Mint session failed internally after ownership verification: {error:#}; emergency teardown also failed for context {:?}, namespace {:?}, UID {}: {cleanup_error:#}; replay protocol-mint-cleanup from {}",
                    request.target.context,
                    request.target.namespace,
                    request.target.namespace_uid,
                    request.artifact_root.display()
                ),
            }
        }
    }
}

async fn emergency_teardown_after_internal_error(
    request: &MintSessionRequest,
    writer: &ProtocolArtifactWriter,
    namespace_proof: &MintNamespaceProof,
    error: &anyhow::Error,
) -> Result<()> {
    let diagnostics = collect_mint_target_diagnostics(&request.target).await;
    let _ = write_diagnostics(
        writer,
        &diagnostics,
        &request.forbidden_material,
        &request.target.run_id,
    );
    let _ = write_failure_detail(
        writer,
        "kubernetes/internal-session-error.txt",
        error,
        &request.forbidden_material,
    );
    let container = remove_owned_mint_container(&request.target).await;
    let namespace = teardown_mint_target(&request.target, namespace_proof, &timestamp_now()?).await;
    match (container, namespace) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(container), Ok(_)) => {
            Err(container).context("remove exact Mint container during emergency teardown")
        }
        (Ok(()), Err(namespace)) => {
            Err(namespace).context("delete exact Mint namespace during emergency teardown")
        }
        (Err(container), Err(namespace)) => bail!(
            "remove exact Mint container: {container:#}; delete exact Mint namespace: {namespace:#}"
        ),
    }
}

pub async fn cleanup_mint_session(
    artifact_root: impl AsRef<Path>,
    forbidden_material: &[String],
) -> Result<MintSessionPublication> {
    let artifact_root = artifact_root.as_ref();
    ensure_safe_session_root(artifact_root)?;
    let spec: MintTargetSpec = read_json(&artifact_root.join(TARGET_SPEC_FILE))?;
    spec.validate_contract()?;
    let namespace_proof: MintNamespaceProof =
        read_json(&artifact_root.join(NAMESPACE_PROOF_FILE)).context(
            "Mint cleanup requires a persisted namespace ownership proof; refusing unproven deletion",
        )?;
    let writer = ProtocolArtifactWriter::file(artifact_root);
    let session_token_used = interrupted_session_token_used(artifact_root);
    let existing_cleanup =
        read_json::<MintCleanupReport>(&artifact_root.join(CLEANUP_REPORT_FILE)).ok();
    if let Some(existing) = existing_cleanup.as_ref()
        && cleanup_proves_target_absent(&spec, existing)
        && validate_mint_session_artifacts_and_write_report(artifact_root, forbidden_material)
            .is_ok()
    {
        let summary: MintSessionSummary = read_json(&artifact_root.join(SESSION_SUMMARY_FILE))?;
        return Ok(publication_from_summary(artifact_root, &summary));
    }

    let previously_absent =
        existing_cleanup.filter(|cleanup| cleanup_proves_target_absent(&spec, cleanup));
    let (diagnostics_collected, cleanup, mut failure_codes) = if let Some(cleanup) =
        previously_absent
    {
        let diagnostics_collected =
            read_diagnostics_collected(artifact_root, &spec.run_id).unwrap_or(false);
        let mut failure_codes = vec![MintSessionFailureCode::RecoveryCleanup];
        failure_codes.extend(cleanup.failure_codes.iter().copied());
        if !diagnostics_collected {
            failure_codes.push(MintSessionFailureCode::DiagnosticCollectionFailed);
        }
        (diagnostics_collected, cleanup, failure_codes)
    } else {
        let scan_available =
            recovery_scan_material_available(forbidden_material, session_token_used);
        let mut diagnostics = if scan_available {
            collect_mint_target_diagnostics(&spec).await
        } else {
            vec![MintTargetDiagnostic {
                    file_name: "recovery-diagnostics-skipped.txt".to_string(),
                    contents: b"Recovery diagnostics were not captured because the original credential material was unavailable for redaction.\n".to_vec(),
                    succeeded: false,
                }]
        };
        if scan_available {
            for diagnostic in &mut diagnostics {
                diagnostic.file_name = format!("recovery-{}", diagnostic.file_name);
            }
        }
        let diagnostics_collected =
            write_diagnostics(&writer, &diagnostics, forbidden_material, &spec.run_id)
                .unwrap_or(false);
        let container = remove_owned_mint_container(&spec).await;
        let container_absent = container.is_ok();
        let teardown = teardown_mint_target(&spec, &namespace_proof, &timestamp_now()?).await;
        let namespace_absent = teardown.is_ok();
        let cleanup_errors = container
            .as_ref()
            .err()
            .into_iter()
            .chain(teardown.as_ref().err())
            .map(|error| safe_error_message(error, forbidden_material))
            .collect::<Vec<_>>();
        let mut failure_codes = vec![MintSessionFailureCode::RecoveryCleanup];
        if !diagnostics_collected {
            failure_codes.push(MintSessionFailureCode::DiagnosticCollectionFailed);
        }
        if !container_absent {
            failure_codes.push(MintSessionFailureCode::ContainerCleanupFailed);
        }
        if !namespace_absent {
            failure_codes.push(MintSessionFailureCode::TargetTeardownFailed);
        }
        let cleanup = MintCleanupReport {
            api_version: API_VERSION.to_string(),
            kind: "MintCleanupReport".to_string(),
            status: if container_absent && namespace_absent {
                MintTeardownStatus::Passed
            } else {
                MintTeardownStatus::Failed
            },
            container_name: spec.container_name(),
            container_absent,
            namespace_absent,
            teardown_proof: teardown.ok(),
            failure_codes: failure_codes.clone(),
            errors: cleanup_errors,
        };
        write_safe_json(&writer, CLEANUP_REPORT_FILE, &cleanup, forbidden_material)?;
        (diagnostics_collected, cleanup, failure_codes)
    };
    let mint_artifacts_published = artifact_root.join(MINT_ARTIFACT_DIR).is_dir()
        && validate_mint_artifacts_and_write_report(
            artifact_root.join(MINT_ARTIFACT_DIR),
            forbidden_material,
        )
        .is_ok();
    let lifecycle = MintSessionLifecycle {
        api_version: API_VERSION.to_string(),
        kind: "MintSessionLifecycle".to_string(),
        run_id: spec.run_id.clone(),
        phase: MintSessionPhase::Finished,
        updated_at: timestamp_now()?,
        container_name: spec.container_name(),
        namespace_proof_persisted: true,
        target_proof_persisted: artifact_root.join(TARGET_PROOF_FILE).is_file(),
        mint_artifacts_published,
        admin_session_token_used: session_token_used,
    };
    write_safe_json(&writer, LIFECYCLE_FILE, &lifecycle, forbidden_material)?;
    failure_codes.push(MintSessionFailureCode::RecoveryCleanup);
    let previous_summary =
        read_json::<MintSessionSummary>(&artifact_root.join(SESSION_SUMMARY_FILE)).ok();
    let recovered_exit_code = lifecycle
        .mint_artifacts_published
        .then(|| read_mint_container_exit_code(artifact_root))
        .flatten();
    let capture = OwnedMintCapture {
        process_disposition: previous_summary
            .as_ref()
            .map(|summary| summary.process_disposition)
            .unwrap_or(if recovered_exit_code.is_some() {
                MintProcessDisposition::Completed
            } else {
                MintProcessDisposition::Interrupted
            }),
        container_started: lifecycle.mint_artifacts_published,
        container_exit_code: recovered_exit_code,
        infrastructure_failure: recovered_exit_code.and_then(mint_infrastructure_failure),
        log: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let mint_gate_status = lifecycle
        .mint_artifacts_published
        .then(|| read_mint_gate_status(artifact_root))
        .flatten();
    let summary = build_summary(
        &spec.run_id,
        &lifecycle,
        &capture,
        mint_gate_status,
        diagnostics_collected,
        cleanup.status,
        failure_codes,
    );
    let publication =
        publish_session_summary(artifact_root, &writer, &summary, forbidden_material)?;
    validate_mint_session_artifacts_and_write_report(artifact_root, forbidden_material)?;
    Ok(publication)
}

pub fn validate_mint_session_artifacts_and_write_report(
    artifact_root: impl AsRef<Path>,
    forbidden_material: &[String],
) -> Result<MintSessionValidationReport> {
    let artifact_root = artifact_root.as_ref();
    ensure_safe_session_root(artifact_root)?;
    let validation = validate_mint_session_artifacts(artifact_root, forbidden_material);
    let error = validation.as_ref().err().map(ToString::to_string);
    let redaction_token = Uuid::new_v4().to_string();
    let errors = error
        .map(|error| {
            let (safe, _) =
                sanitize_mint_bytes(error.as_bytes(), forbidden_material, &redaction_token);
            vec![String::from_utf8_lossy(&safe).into_owned()]
        })
        .unwrap_or_default();
    let report = MintSessionValidationReport {
        api_version: API_VERSION.to_string(),
        kind: "MintSessionValidationReport".to_string(),
        artifact_root: artifact_root.display().to_string(),
        valid: validation.is_ok(),
        errors,
    };
    write_safe_json(
        &ProtocolArtifactWriter::file(artifact_root),
        MINT_SESSION_VALIDATION_FILE,
        &report,
        forbidden_material,
    )?;
    if let Err(error) = validation {
        bail!(
            "Mint session artifact validation failed: {error}; report: {}",
            artifact_root.join(MINT_SESSION_VALIDATION_FILE).display()
        );
    }
    Ok(report)
}

fn finish_without_ownership(
    request: &MintSessionRequest,
    writer: &ProtocolArtifactWriter,
    lifecycle: &mut MintSessionLifecycle,
    failure_code: MintSessionFailureCode,
    error: &anyhow::Error,
) -> Result<MintSessionPublication> {
    write_diagnostics(
        writer,
        &[MintTargetDiagnostic {
            file_name: "ownership-preflight-error.txt".to_string(),
            contents: format!("Mint ownership preflight failed: {error:#}\n").into_bytes(),
            succeeded: false,
        }],
        &request.forbidden_material,
        &request.target.run_id,
    )?;
    let cleanup = MintCleanupReport {
        api_version: API_VERSION.to_string(),
        kind: "MintCleanupReport".to_string(),
        status: MintTeardownStatus::NotRun,
        container_name: request.target.container_name(),
        container_absent: true,
        namespace_absent: false,
        teardown_proof: None,
        failure_codes: vec![failure_code],
        errors: Vec::new(),
    };
    write_safe_json(
        writer,
        CLEANUP_REPORT_FILE,
        &cleanup,
        &request.forbidden_material,
    )?;
    lifecycle.phase = MintSessionPhase::Finished;
    write_lifecycle(writer, lifecycle, &request.forbidden_material)?;
    let capture = OwnedMintCapture {
        process_disposition: MintProcessDisposition::NotRun,
        container_started: false,
        container_exit_code: None,
        infrastructure_failure: None,
        log: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let summary = build_summary(
        &request.target.run_id,
        lifecycle,
        &capture,
        None,
        false,
        MintTeardownStatus::NotRun,
        vec![failure_code],
    );
    let publication = publish_session_summary(
        &request.artifact_root,
        writer,
        &summary,
        &request.forbidden_material,
    )?;
    validate_mint_session_artifacts_and_write_report(
        &request.artifact_root,
        &request.forbidden_material,
    )?;
    Ok(publication)
}

fn validate_request(request: &MintSessionRequest) -> Result<()> {
    ensure!(
        !request.profile_name.trim().is_empty(),
        "Mint profile name is required"
    );
    ensure!(
        !request.mint_platform.trim().is_empty(),
        "Mint platform is required"
    );
    ensure!(
        !request.mint_suites.is_empty(),
        "Mint suite set is required"
    );
    ensure!(
        request.mint_image.contains("@sha256:"),
        "Mint image must be pinned by digest"
    );
    let (image_repository, _) = request
        .mint_image
        .rsplit_once('@')
        .context("Mint image must contain an immutable digest")?;
    ensure!(
        !image_repository.starts_with('-')
            && !image_repository.contains('@')
            && !image_repository
                .chars()
                .any(|character| character.is_whitespace() || character.is_control()),
        "Mint image repository contains unsafe characters"
    );
    let profile = MintProfile::new(MintProfileSpec {
        name: request.profile_name.clone(),
        image: request.mint_image.clone(),
        platform: request.mint_platform.clone(),
        mode: request.mint_mode,
        suites: request.mint_suites.clone(),
        region: request.target.region.clone(),
        target_fingerprint: format!("sha256:{}", request.target.target_fingerprint),
    })?;
    super::evaluate_mint_run(
        &profile,
        &request.inventory,
        &request.known_failures,
        super::MintRunObservation {
            container_started: false,
            exit_code: None,
            infrastructure_failure: Some(MintInfrastructureFailure::ContainerStart),
            log: None,
        },
        "2000-01-01",
    )?;
    Ok(())
}

fn claim_session_root(root: &Path) -> Result<()> {
    ensure!(
        root.file_name().is_some(),
        "Mint session artifact root must identify a new run directory"
    );
    if let Some(parent) = root
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(root).with_context(|| {
        format!(
            "claim Mint session artifact root {}; the run directory must not already exist",
            root.display()
        )
    })
}

fn write_lifecycle(
    writer: &ProtocolArtifactWriter,
    lifecycle: &mut MintSessionLifecycle,
    forbidden_material: &[String],
) -> Result<()> {
    lifecycle.updated_at = timestamp_now()?;
    write_safe_json(writer, LIFECYCLE_FILE, lifecycle, forbidden_material)
}

fn write_safe_json(
    writer: &ProtocolArtifactWriter,
    path: &str,
    value: &impl Serialize,
    forbidden_material: &[String],
) -> Result<()> {
    let contents = serde_json::to_vec(value)?;
    let (_, redacted) = sanitize_mint_bytes(&contents, forbidden_material, "safety-check");
    ensure!(
        !redacted,
        "refuse to publish Mint session artifact {path} because it contains credential material"
    );
    writer.write_json(path, value)
}

fn write_diagnostics(
    writer: &ProtocolArtifactWriter,
    diagnostics: &[MintTargetDiagnostic],
    forbidden_material: &[String],
    run_id: &str,
) -> Result<bool> {
    let redaction_token = Uuid::new_v4().to_string();
    let mut files = Vec::with_capacity(diagnostics.len());
    let mut succeeded = true;
    for diagnostic in diagnostics {
        let (contents, redacted) =
            sanitize_mint_bytes(&diagnostic.contents, forbidden_material, &redaction_token);
        let relative = format!("{KUBERNETES_ARTIFACT_DIR}/{}", diagnostic.file_name);
        writer.write_bytes(&relative, &contents)?;
        files.push(MintSessionCredentialFile {
            path: relative,
            redacted,
        });
        succeeded &= diagnostic.succeeded;
    }
    let scan = MintSessionCredentialScan {
        api_version: API_VERSION.to_string(),
        kind: "MintSessionCredentialScan".to_string(),
        run_id: run_id.to_string(),
        redaction_token,
        detected: files.iter().any(|file| file.redacted),
        files,
    };
    write_safe_json(
        writer,
        SESSION_CREDENTIAL_SCAN_FILE,
        &scan,
        forbidden_material,
    )?;
    let marker = format!("run-id={run_id}\ndiagnostics-collected={succeeded}\n");
    writer.write_text(
        format!("{KUBERNETES_ARTIFACT_DIR}/collection-status.txt"),
        &marker,
    )?;
    Ok(succeeded)
}

fn write_failure_detail(
    writer: &ProtocolArtifactWriter,
    path: &str,
    error: &anyhow::Error,
    forbidden_material: &[String],
) -> Result<()> {
    let redaction_token = Uuid::new_v4().to_string();
    let (contents, _) = sanitize_mint_bytes(
        format!("{error:#}\n").as_bytes(),
        forbidden_material,
        &redaction_token,
    );
    writer.write_bytes(path, &contents)
}

fn safe_error_message(error: &anyhow::Error, forbidden_material: &[String]) -> String {
    let redaction_token = Uuid::new_v4().to_string();
    let (contents, _) = sanitize_mint_bytes(
        format!("{error:#}").as_bytes(),
        forbidden_material,
        &redaction_token,
    );
    String::from_utf8_lossy(&contents).into_owned()
}

fn build_summary(
    run_id: &str,
    lifecycle: &MintSessionLifecycle,
    capture: &OwnedMintCapture,
    mint_gate_status: Option<MintGateStatus>,
    diagnostics_collected: bool,
    teardown_status: MintTeardownStatus,
    mut failure_codes: Vec<MintSessionFailureCode>,
) -> MintSessionSummary {
    failure_codes.sort();
    failure_codes.dedup();
    let passed = capture.process_disposition == MintProcessDisposition::Completed
        && mint_gate_status == Some(MintGateStatus::Passed)
        && diagnostics_collected
        && teardown_status == MintTeardownStatus::Passed
        && lifecycle.namespace_proof_persisted
        && lifecycle.target_proof_persisted
        && lifecycle.mint_artifacts_published
        && failure_codes.is_empty();
    MintSessionSummary {
        api_version: API_VERSION.to_string(),
        kind: "MintSessionSummary".to_string(),
        run_id: run_id.to_string(),
        process_disposition: capture.process_disposition,
        container_exit_code: capture.container_exit_code,
        mint_gate_status,
        diagnostics_collected,
        teardown_status,
        gate_status: if passed {
            MintSessionGateStatus::Passed
        } else {
            MintSessionGateStatus::Failed
        },
        failure_codes,
        artifacts: MintSessionArtifactReferences {
            target_spec: TARGET_SPEC_FILE.to_string(),
            namespace_proof: lifecycle
                .namespace_proof_persisted
                .then(|| NAMESPACE_PROOF_FILE.to_string()),
            target_proof: lifecycle
                .target_proof_persisted
                .then(|| TARGET_PROOF_FILE.to_string()),
            mint: lifecycle
                .mint_artifacts_published
                .then(|| MINT_ARTIFACT_DIR.to_string()),
            kubernetes: KUBERNETES_ARTIFACT_DIR.to_string(),
            lifecycle: LIFECYCLE_FILE.to_string(),
            cleanup_report: CLEANUP_REPORT_FILE.to_string(),
            junit: SESSION_JUNIT_FILE.to_string(),
            exit_code: SESSION_EXIT_CODE_FILE.to_string(),
            credential_scan: SESSION_CREDENTIAL_SCAN_FILE.to_string(),
        },
    }
}

fn publish_session_summary(
    artifact_root: &Path,
    writer: &ProtocolArtifactWriter,
    summary: &MintSessionSummary,
    forbidden_material: &[String],
) -> Result<MintSessionPublication> {
    let junit = session_junit(summary);
    let exit_code = i32::from(summary.gate_status == MintSessionGateStatus::Failed);
    write_safe_json(writer, SESSION_SUMMARY_FILE, summary, forbidden_material)?;
    let (_, junit_redacted) =
        sanitize_mint_bytes(junit.as_bytes(), forbidden_material, "session-junit-check");
    ensure!(
        !junit_redacted,
        "Mint session JUnit contains credential material"
    );
    writer.write_text(SESSION_JUNIT_FILE, &junit)?;
    writer.write_text(SESSION_EXIT_CODE_FILE, &format!("{exit_code}\n"))?;
    Ok(MintSessionPublication {
        gate_exit_code: exit_code,
        cleanup_exit_code: i32::from(summary.teardown_status == MintTeardownStatus::Failed),
        terminal_summary: session_terminal_summary(summary, artifact_root),
        artifact_root: artifact_root.to_path_buf(),
    })
}

async fn run_mint_container(
    request: &MintSessionRequest,
    cancellation: &mut watch::Receiver<bool>,
) -> OwnedMintCapture {
    if cancellation_requested(cancellation) {
        return interrupted_before_container_start();
    }
    let mut docker_process_started = false;
    match run_mint_container_inner(request, cancellation, &mut docker_process_started).await {
        Ok(capture) => capture,
        Err(error) => OwnedMintCapture {
            process_disposition: if docker_process_started {
                MintProcessDisposition::RuntimeFailed
            } else {
                MintProcessDisposition::StartFailed
            },
            container_started: docker_process_started,
            container_exit_code: None,
            infrastructure_failure: Some(if docker_process_started {
                MintInfrastructureFailure::ContainerRuntime
            } else {
                MintInfrastructureFailure::ContainerStart
            }),
            log: None,
            stdout: Vec::new(),
            stderr: format!("Mint container start failed: {error}\n").into_bytes(),
        },
    }
}

async fn run_mint_container_inner(
    request: &MintSessionRequest,
    cancellation: &mut watch::Receiver<bool>,
    docker_process_started: &mut bool,
) -> Result<OwnedMintCapture> {
    let capture = CaptureDirectory::new()?;
    let stdout = File::create(capture.stdout())?;
    let stderr = File::create(capture.stderr())?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let mut command = Command::new("docker");
    command
        .kill_on_drop(true)
        .args(["run", "--rm", "--name"])
        .arg(request.target.container_name())
        .args([
            "--label",
            &format!("rustfs.com/mint-run-id={}", request.target.run_id),
        ])
        .args([
            "--label",
            &format!(
                "rustfs.com/mint-namespace-uid={}",
                request.target.namespace_uid
            ),
        ])
        .args(["--platform", &request.mint_platform])
        .args(["--env", "SERVER_ENDPOINT"])
        .args(["--env", "ACCESS_KEY"])
        .args(["--env", "SECRET_KEY"])
        .args(["--env", "ENABLE_HTTPS"])
        .args(["--env", "SERVER_REGION"])
        .args(["--env", "MINT_MODE"])
        .args(["--volume"])
        .arg(format!("{}:/mint/log", capture.log_dir().display()))
        .arg(&request.mint_image)
        .args(&request.mint_suites)
        .env("SERVER_ENDPOINT", &request.target.server_endpoint)
        .env("ACCESS_KEY", credentials.access_key())
        .env("SECRET_KEY", credentials.secret_key())
        .env(
            "ENABLE_HTTPS",
            if request.target.enable_https {
                "1"
            } else {
                "0"
            },
        )
        .env("SERVER_REGION", &request.target.region)
        .env("MINT_MODE", mint_mode_name(request.mint_mode))
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr));
    if cancellation_requested(cancellation) {
        return Ok(interrupted_before_container_start());
    }
    let mut child = command.spawn().context("start pinned Mint container")?;
    *docker_process_started = true;
    let mut process_disposition;
    let status = tokio::select! {
        status = child.wait() => {
            process_disposition = MintProcessDisposition::Completed;
            status.context("wait for Mint container")?
        }
        _ = tokio::time::sleep(Duration::from_secs(request.target.timeouts.mint_seconds)) => {
            process_disposition = MintProcessDisposition::TimedOut;
            let _ = child.start_kill();
            let _ = timeout(
                Duration::from_secs(request.target.timeouts.operation_seconds),
                child.wait(),
            )
            .await;
            return capture_after_interruption(request, &capture, process_disposition).await;
        }
        changed = cancellation.changed() => {
            changed.context("listen for Mint cancellation")?;
            process_disposition = MintProcessDisposition::Interrupted;
            let _ = child.start_kill();
            let _ = timeout(
                Duration::from_secs(request.target.timeouts.operation_seconds),
                child.wait(),
            )
            .await;
            return capture_after_interruption(request, &capture, process_disposition).await;
        }
    };
    let exit_code = status.code();
    if exit_code.is_none() {
        process_disposition = MintProcessDisposition::RuntimeFailed;
    }
    let infrastructure_failure = exit_code
        .and_then(mint_infrastructure_failure)
        .or((exit_code.is_none()).then_some(MintInfrastructureFailure::ContainerRuntime));
    let container_started = !matches!(
        infrastructure_failure,
        Some(MintInfrastructureFailure::ContainerStart)
    );
    Ok(OwnedMintCapture {
        process_disposition,
        container_started,
        container_exit_code: exit_code,
        infrastructure_failure,
        log: read_optional_bounded(&capture.log())?,
        stdout: read_bounded(&capture.stdout())?,
        stderr: read_bounded(&capture.stderr())?,
    })
}

fn interrupted_before_container_start() -> OwnedMintCapture {
    OwnedMintCapture {
        process_disposition: MintProcessDisposition::Interrupted,
        container_started: false,
        container_exit_code: None,
        infrastructure_failure: None,
        log: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    }
}

async fn capture_after_interruption(
    request: &MintSessionRequest,
    capture: &CaptureDirectory,
    process_disposition: MintProcessDisposition,
) -> Result<OwnedMintCapture> {
    let _ = remove_owned_mint_container(&request.target).await;
    Ok(OwnedMintCapture {
        process_disposition,
        container_started: true,
        container_exit_code: None,
        infrastructure_failure: Some(MintInfrastructureFailure::ContainerRuntime),
        log: read_optional_bounded(&capture.log())?,
        stdout: read_bounded(&capture.stdout())?,
        stderr: read_bounded(&capture.stderr())?,
    })
}

async fn remove_owned_mint_container(spec: &MintTargetSpec) -> Result<()> {
    let name = spec.container_name();
    let inspect = bounded_docker_output(
        spec,
        &[
            "inspect",
            "--format",
            "{{ index .Config.Labels \"rustfs.com/mint-run-id\" }}|{{ index .Config.Labels \"rustfs.com/mint-namespace-uid\" }}",
            &name,
        ],
    )
    .await?;
    if !inspect.status.success() {
        ensure!(
            docker_inspect_reports_absent(&inspect.stderr),
            "failed to inspect the exact Mint container before cleanup"
        );
        return Ok(());
    }
    ensure!(
        docker_container_ownership_matches(spec, &inspect.stdout),
        "refuse to delete a Docker container whose Mint run-id or namespace-UID label does not match"
    );
    let removed = bounded_docker_output(spec, &["rm", "-f", &name]).await?;
    ensure!(
        removed.status.success(),
        "failed to remove the exact Mint container"
    );
    Ok(())
}

fn docker_container_ownership_matches(spec: &MintTargetSpec, labels: &[u8]) -> bool {
    String::from_utf8_lossy(labels).trim() == format!("{}|{}", spec.run_id, spec.namespace_uid)
}

fn docker_inspect_reports_absent(stderr: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(stderr).trim().to_ascii_lowercase();
    [
        "error: no such object:",
        "error: no such container:",
        "error response from daemon: no such object:",
        "error response from daemon: no such container:",
    ]
    .iter()
    .any(|prefix| stderr.starts_with(prefix))
}

async fn bounded_docker_output(
    spec: &MintTargetSpec,
    args: &[&str],
) -> Result<std::process::Output> {
    let mut command = Command::new("docker");
    command.kill_on_drop(true).args(args);
    timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        command.output(),
    )
    .await
    .context("time out running bounded Docker cleanup command")?
    .context("run bounded Docker cleanup command")
}

fn install_process_cancellation() -> watch::Receiver<bool> {
    let (sender, receiver) = watch::channel(false);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
            if let Ok(mut terminate) = terminate {
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {}
                    _ = terminate.recv() => {}
                }
            } else {
                let _ = tokio::signal::ctrl_c().await;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = sender.send(true);
    });
    receiver
}

fn cancellation_requested(cancellation: &watch::Receiver<bool>) -> bool {
    *cancellation.borrow()
}

fn admin_session_token_used() -> bool {
    std::env::var(ADMIN_SESSION_TOKEN_ENV).is_ok_and(|value| !value.is_empty())
}

fn interrupted_session_token_used(artifact_root: &Path) -> bool {
    read_json::<MintSessionLifecycle>(&artifact_root.join(LIFECYCLE_FILE))
        .map(|lifecycle| lifecycle.admin_session_token_used)
        .unwrap_or(true)
}

fn recovery_scan_material_available(
    forbidden_material: &[String],
    session_token_used: bool,
) -> bool {
    [
        Some(ADMIN_ACCESS_KEY_ENV),
        Some(ADMIN_SECRET_KEY_ENV),
        session_token_used.then_some(ADMIN_SESSION_TOKEN_ENV),
    ]
    .into_iter()
    .flatten()
    .all(|name| {
        std::env::var(name).is_ok_and(|value| {
            !value.is_empty() && forbidden_material.iter().any(|material| material == &value)
        })
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect Mint capture {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "Mint capture {} must be a regular file, not a symlink",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_CAPTURE_BYTES,
        "Mint capture {} exceeds the {MAX_CAPTURE_BYTES} byte limit",
        path.display()
    );
    fs::read(path).with_context(|| format!("read Mint capture {}", path.display()))
}

fn read_optional_bounded(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::symlink_metadata(path) {
        Ok(_) => read_bounded(path).map(Some),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("inspect Mint log {}", path.display())),
    }
}

fn mint_infrastructure_failure(exit_code: i32) -> Option<MintInfrastructureFailure> {
    if (125..=127).contains(&exit_code) {
        Some(MintInfrastructureFailure::ContainerStart)
    } else if exit_code >= 128 {
        Some(MintInfrastructureFailure::ContainerRuntime)
    } else {
        None
    }
}

fn mint_mode_name(mode: MintMode) -> &'static str {
    match mode {
        MintMode::Core => "core",
        MintMode::Full => "full",
    }
}

fn validate_mint_session_artifacts(
    artifact_root: &Path,
    forbidden_material: &[String],
) -> Result<()> {
    for required in [
        TARGET_SPEC_FILE,
        LIFECYCLE_FILE,
        CLEANUP_REPORT_FILE,
        SESSION_SUMMARY_FILE,
        SESSION_JUNIT_FILE,
        SESSION_EXIT_CODE_FILE,
        SESSION_CREDENTIAL_SCAN_FILE,
        "kubernetes/collection-status.txt",
    ] {
        ensure!(
            artifact_root.join(required).is_file(),
            "required Mint session artifact {required} is missing"
        );
    }
    let spec: MintTargetSpec = read_json(&artifact_root.join(TARGET_SPEC_FILE))?;
    spec.validate_contract()?;
    let lifecycle: MintSessionLifecycle = read_json(&artifact_root.join(LIFECYCLE_FILE))?;
    let cleanup: MintCleanupReport = read_json(&artifact_root.join(CLEANUP_REPORT_FILE))?;
    let summary: MintSessionSummary = read_json(&artifact_root.join(SESSION_SUMMARY_FILE))?;
    let credential_scan: MintSessionCredentialScan =
        read_json(&artifact_root.join(SESSION_CREDENTIAL_SCAN_FILE))?;
    ensure!(
        lifecycle.api_version == API_VERSION
            && lifecycle.kind == "MintSessionLifecycle"
            && cleanup.api_version == API_VERSION
            && cleanup.kind == "MintCleanupReport"
            && summary.api_version == API_VERSION
            && summary.kind == "MintSessionSummary"
            && credential_scan.api_version == API_VERSION
            && credential_scan.kind == "MintSessionCredentialScan",
        "invalid Mint session artifact contract"
    );
    ensure!(
        lifecycle.run_id == spec.run_id
            && lifecycle.container_name == spec.container_name()
            && lifecycle.phase == MintSessionPhase::Finished,
        "Mint session lifecycle is not terminal or disagrees with target identity"
    );
    if summary
        .failure_codes
        .contains(&MintSessionFailureCode::MintPublicationFailed)
    {
        ensure!(
            artifact_root.join(MINT_PUBLICATION_ERROR_FILE).is_file(),
            "Mint publication failure lacks its sanitized error artifact"
        );
    }
    ensure!(
        credential_scan.run_id == spec.run_id
            && !credential_scan.redaction_token.is_empty()
            && credential_scan.detected == credential_scan.files.iter().any(|file| file.redacted),
        "Mint session credential scan disagrees with target identity or file results"
    );
    for file in &credential_scan.files {
        let path = Path::new(&file.path);
        ensure!(
            path.components()
                .all(|component| matches!(component, std::path::Component::Normal(_)))
                && file.path.starts_with("kubernetes/"),
            "Mint credential scan contains an unsafe diagnostic path"
        );
        ensure!(
            artifact_root.join(path).is_file(),
            "Mint credential scan references a missing diagnostic"
        );
    }
    ensure!(
        fs::read_to_string(artifact_root.join("kubernetes/collection-status.txt"))?
            == format!(
                "run-id={}\ndiagnostics-collected={}\n",
                spec.run_id, summary.diagnostics_collected
            ),
        "Mint Kubernetes collection marker disagrees with session summary"
    );
    if lifecycle.namespace_proof_persisted {
        let proof: MintNamespaceProof = read_json(&artifact_root.join(NAMESPACE_PROOF_FILE))?;
        ensure!(
            proof.context == spec.context
                && proof.namespace == spec.namespace
                && proof.namespace_uid == spec.namespace_uid
                && proof.run_id == spec.run_id,
            "Mint namespace proof disagrees with target spec"
        );
    }
    if lifecycle.target_proof_persisted {
        let proof: MintTargetProof = read_json(&artifact_root.join(TARGET_PROOF_FILE))?;
        let (expected_endpoint_host, expected_service_port) = mint_endpoint_authority(&spec)?;
        let proved_pod_uids = proof
            .rustfs_pods
            .iter()
            .map(|pod| pod.uid.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let expected_endpoint = if spec.server_endpoint.contains("://") {
            spec.server_endpoint.clone()
        } else {
            format!(
                "{}://{}",
                if spec.enable_https { "https" } else { "http" },
                spec.server_endpoint
            )
        };
        ensure!(
            proof.api_version == API_VERSION
                && proof.kind == "MintTargetProof"
                && proof.namespace.context == spec.context
                && proof.namespace.namespace == spec.namespace
                && proof.namespace.namespace_uid == spec.namespace_uid
                && proof.namespace.run_id == spec.run_id
                && proof.namespace.expires_at == spec.expires_at
                && proof.server.endpoint == expected_endpoint
                && proof.server.sha256 == spec.target_fingerprint
                && proof.server.region == spec.region
                && proof.rustfs_image_digest == spec.rustfs_image_digest
                && proof.service.name == spec.service_name
                && proof.service.port == expected_service_port
                && proof.service.endpoint_host == expected_endpoint_host
                && !proof.service.uid.is_empty()
                && strictly_sorted_unique(&proof.service.endpoint_slice_uids)
                && strictly_sorted_unique(&proof.service.backend_pod_uids)
                && !proof.service.endpoint_slice_uids.is_empty()
                && !proof.service.backend_pod_uids.is_empty()
                && proof
                    .service
                    .endpoint_slice_uids
                    .iter()
                    .chain(&proof.service.backend_pod_uids)
                    .all(|uid| !uid.is_empty())
                && proof
                    .service
                    .backend_pod_uids
                    .iter()
                    .all(|uid| proved_pod_uids.contains(uid.as_str()))
                && proof.delete_allowed
                && !proof.rustfs_pods.is_empty()
                && proof.namespace_pod_count >= proof.rustfs_pods.len()
                && proof.rustfs_pods.iter().all(|pod| {
                    pod.ready
                        && !pod.name.is_empty()
                        && !pod.uid.is_empty()
                        && pod
                            .image_id
                            .rsplit_once('@')
                            .map(|(_, digest)| digest)
                            .unwrap_or(pod.image_id.as_str())
                            == spec.rustfs_image_digest
                }),
            "Mint target proof disagrees with target spec"
        );
    }
    if lifecycle.mint_artifacts_published {
        ensure!(
            artifact_root.join(MINT_ARTIFACT_DIR).is_dir(),
            "Mint artifact directory is missing"
        );
        validate_mint_artifacts_and_write_report(
            artifact_root.join(MINT_ARTIFACT_DIR),
            forbidden_material,
        )?;
        let profile: MintProfile = read_json(
            &artifact_root
                .join(MINT_ARTIFACT_DIR)
                .join("mint-profile.json"),
        )?;
        let mint_summary: serde_json::Value = read_json(
            &artifact_root
                .join(MINT_ARTIFACT_DIR)
                .join("mint-summary.json"),
        )?;
        let mint_exit_code = mint_summary
            .pointer("/observation/containerExitCode")
            .and_then(serde_json::Value::as_i64)
            .map(i32::try_from)
            .transpose()
            .context("Mint container exit code exceeds i32")?;
        ensure!(
            profile.region == spec.region
                && profile.target_fingerprint == format!("sha256:{}", spec.target_fingerprint)
                && read_mint_gate_status(artifact_root) == summary.mint_gate_status
                && mint_exit_code == summary.container_exit_code,
            "Mint result profile or gate disagrees with the verified target session"
        );
    } else {
        ensure!(
            summary.mint_gate_status.is_none(),
            "Mint session without published Mint artifacts cannot claim a Mint gate"
        );
    }
    let expected_summary_gate = if summary.process_disposition == MintProcessDisposition::Completed
        && summary.mint_gate_status == Some(MintGateStatus::Passed)
        && summary.diagnostics_collected
        && summary.teardown_status == MintTeardownStatus::Passed
        && lifecycle.namespace_proof_persisted
        && lifecycle.target_proof_persisted
        && lifecycle.mint_artifacts_published
        && summary.failure_codes.is_empty()
    {
        MintSessionGateStatus::Passed
    } else {
        MintSessionGateStatus::Failed
    };
    ensure!(
        summary.run_id == spec.run_id
            && summary.gate_status == expected_summary_gate
            && summary.teardown_status == cleanup.status
            && summary.artifacts == expected_artifact_references(&lifecycle),
        "Mint session summary disagrees with lifecycle or cleanup evidence"
    );
    ensure!(
        cleanup.container_name == spec.container_name(),
        "Mint cleanup report disagrees with target container identity"
    );
    ensure!(
        cleanup
            .failure_codes
            .iter()
            .all(|code| summary.failure_codes.contains(code)),
        "Mint cleanup failures are missing from the session summary"
    );
    if cleanup.status == MintTeardownStatus::Passed {
        ensure!(
            cleanup_proves_target_absent(&spec, &cleanup),
            "successful Mint cleanup report lacks verified-absent proof"
        );
    } else if cleanup.status == MintTeardownStatus::NotRun {
        ensure!(
            !lifecycle.namespace_proof_persisted
                && cleanup.errors.is_empty()
                && summary
                    .failure_codes
                    .contains(&MintSessionFailureCode::OwnershipRejected),
            "Mint cleanup may be not-run only when ownership was rejected before mutation"
        );
    } else {
        ensure!(
            !cleanup.errors.is_empty()
                && ((!cleanup.container_absent
                    && cleanup
                        .failure_codes
                        .contains(&MintSessionFailureCode::ContainerCleanupFailed))
                    || (!cleanup.namespace_absent
                        && cleanup
                            .failure_codes
                            .contains(&MintSessionFailureCode::TargetTeardownFailed))),
            "failed Mint cleanup lacks a concrete container or namespace failure"
        );
    }
    ensure!(
        fs::read_to_string(artifact_root.join(SESSION_JUNIT_FILE))? == session_junit(&summary),
        "Mint session JUnit disagrees with summary"
    );
    let expected_exit = i32::from(summary.gate_status == MintSessionGateStatus::Failed);
    ensure!(
        fs::read_to_string(artifact_root.join(SESSION_EXIT_CODE_FILE))?
            == format!("{expected_exit}\n"),
        "Mint session exit code disagrees with summary"
    );
    ensure_mint_artifact_tree_safe(artifact_root, forbidden_material)?;
    Ok(())
}

fn strictly_sorted_unique(values: &[String]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn expected_artifact_references(lifecycle: &MintSessionLifecycle) -> MintSessionArtifactReferences {
    MintSessionArtifactReferences {
        target_spec: TARGET_SPEC_FILE.to_string(),
        namespace_proof: lifecycle
            .namespace_proof_persisted
            .then(|| NAMESPACE_PROOF_FILE.to_string()),
        target_proof: lifecycle
            .target_proof_persisted
            .then(|| TARGET_PROOF_FILE.to_string()),
        mint: lifecycle
            .mint_artifacts_published
            .then(|| MINT_ARTIFACT_DIR.to_string()),
        kubernetes: KUBERNETES_ARTIFACT_DIR.to_string(),
        lifecycle: LIFECYCLE_FILE.to_string(),
        cleanup_report: CLEANUP_REPORT_FILE.to_string(),
        junit: SESSION_JUNIT_FILE.to_string(),
        exit_code: SESSION_EXIT_CODE_FILE.to_string(),
        credential_scan: SESSION_CREDENTIAL_SCAN_FILE.to_string(),
    }
}

fn ensure_safe_session_root(root: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect Mint session artifact root {}", root.display()))?;
    ensure!(
        metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
        "Mint session artifact root must be a directory, not a symlink"
    );
    Ok(())
}

fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect Mint session artifact {}", path.display()))?;
    ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "Mint session artifact {} must be a regular file",
        path.display()
    );
    ensure!(
        metadata.len() <= MAX_CAPTURE_BYTES,
        "Mint session artifact {} exceeds the size limit",
        path.display()
    );
    let contents = fs::read(path)?;
    serde_json::from_slice(&contents)
        .with_context(|| format!("parse Mint session artifact {}", path.display()))
}

fn read_mint_gate_status(root: &Path) -> Option<MintGateStatus> {
    let value: serde_json::Value =
        read_json(&root.join(MINT_ARTIFACT_DIR).join("mint-summary.json")).ok()?;
    match value.get("gateStatus")?.as_str()? {
        "passed" => Some(MintGateStatus::Passed),
        "failed" => Some(MintGateStatus::Failed),
        _ => None,
    }
}

fn read_mint_container_exit_code(root: &Path) -> Option<i32> {
    let value: serde_json::Value =
        read_json(&root.join(MINT_ARTIFACT_DIR).join("mint-summary.json")).ok()?;
    let value = value.pointer("/observation/containerExitCode")?.as_i64()?;
    i32::try_from(value).ok()
}

fn read_diagnostics_collected(root: &Path, run_id: &str) -> Option<bool> {
    let contents = fs::read_to_string(root.join("kubernetes/collection-status.txt")).ok()?;
    if contents == format!("run-id={run_id}\ndiagnostics-collected=true\n") {
        Some(true)
    } else if contents == format!("run-id={run_id}\ndiagnostics-collected=false\n") {
        Some(false)
    } else {
        None
    }
}

fn cleanup_proves_target_absent(spec: &MintTargetSpec, cleanup: &MintCleanupReport) -> bool {
    cleanup.status == MintTeardownStatus::Passed
        && cleanup.container_name == spec.container_name()
        && cleanup.container_absent
        && cleanup.namespace_absent
        && cleanup.errors.is_empty()
        && cleanup.teardown_proof.as_ref().is_some_and(|proof| {
            proof.api_version == API_VERSION
                && proof.kind == "MintTargetTeardownProof"
                && proof.context == spec.context
                && proof.namespace == spec.namespace
                && proof.namespace_uid == spec.namespace_uid
                && proof.namespace_absent
        })
}

fn session_junit(summary: &MintSessionSummary) -> String {
    let cases = [
        (
            "target-preflight",
            summary.artifacts.namespace_proof.is_some()
                && summary.artifacts.target_proof.is_some()
                && !summary.failure_codes.iter().any(|code| {
                    matches!(
                        code,
                        MintSessionFailureCode::OwnershipRejected
                            | MintSessionFailureCode::TargetPreflightFailed
                    )
                }),
        ),
        (
            "mint-gate",
            summary.mint_gate_status == Some(MintGateStatus::Passed),
        ),
        ("diagnostics", summary.diagnostics_collected),
        (
            "target-teardown",
            summary.teardown_status == MintTeardownStatus::Passed,
        ),
        (
            "session-gate",
            summary.gate_status == MintSessionGateStatus::Passed,
        ),
    ];
    let failures = cases.iter().filter(|(_, passed)| !passed).count();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"s3chaos-mint-session\" tests=\"{}\" failures=\"{failures}\">\n",
        cases.len()
    );
    for (name, passed) in cases {
        xml.push_str(&format!(
            "  <testcase name=\"{name}\" classname=\"s3chaos.protocol.mint.session\">\n"
        ));
        if !passed {
            xml.push_str(
                "    <failure type=\"mint-session-gate\" message=\"mint-session-gate\"/>\n",
            );
        }
        xml.push_str("  </testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    xml
}

fn session_terminal_summary(summary: &MintSessionSummary, artifact_root: &Path) -> String {
    format!(
        "Mint session {}: gate={} process={} teardown={}\nartifacts: {}\n",
        summary.run_id,
        enum_name(summary.gate_status),
        enum_name(summary.process_disposition),
        enum_name(summary.teardown_status),
        artifact_root.display()
    )
}

fn enum_name(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string())
}

fn publication_from_summary(root: &Path, summary: &MintSessionSummary) -> MintSessionPublication {
    MintSessionPublication {
        gate_exit_code: i32::from(summary.gate_status == MintSessionGateStatus::Failed),
        cleanup_exit_code: i32::from(summary.teardown_status == MintTeardownStatus::Failed),
        terminal_summary: session_terminal_summary(summary, root),
        artifact_root: root.to_path_buf(),
    }
}

#[cfg(test)]
fn placeholder_inventory() -> MintInventory {
    serde_yaml_ng::from_str(
        "apiVersion: rustfs.com/s3chaos/v1alpha1\nkind: MintInventory\nimageDigest: sha256:0000000000000000000000000000000000000000000000000000000000000000\nplatform: linux/amd64\nmode: core\nsuites: [recovery]\nfunctions:\n  - suite: recovery\n    function: recovery\n    allowNa: false\n",
    )
    .expect("static placeholder inventory")
}

#[cfg(test)]
fn placeholder_known_failures() -> MintKnownFailures {
    serde_yaml_ng::from_str(
        "apiVersion: rustfs.com/s3chaos/v1alpha1\nkind: MintKnownFailures\nimageDigest: sha256:0000000000000000000000000000000000000000000000000000000000000000\nplatform: linux/amd64\nmode: core\nsuites: [recovery]\nentries: []\n",
    )
    .expect("static placeholder known failures")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{
        mint::target::{MintPodProof, MintServiceProof},
        suite_plan::TargetFingerprint,
    };

    fn lifecycle() -> MintSessionLifecycle {
        MintSessionLifecycle {
            api_version: API_VERSION.to_string(),
            kind: "MintSessionLifecycle".to_string(),
            run_id: "mint-run".to_string(),
            phase: MintSessionPhase::Finished,
            updated_at: "2026-08-24T01:00:00Z".to_string(),
            container_name: "s3chaos-mint-mint-run-11111111".to_string(),
            namespace_proof_persisted: true,
            target_proof_persisted: true,
            mint_artifacts_published: true,
            admin_session_token_used: false,
        }
    }

    fn request() -> MintSessionRequest {
        let target: MintTargetSpec = serde_yaml_ng::from_str(include_str!(
            "../../../protocol/mint/ephemeral-target.example.yaml"
        ))
        .expect("example target");
        MintSessionRequest {
            artifact_root: PathBuf::from("artifacts"),
            target,
            profile_name: "mint-core".to_string(),
            mint_image:
                "minio/mint@sha256:0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
            mint_platform: "linux/amd64".to_string(),
            mint_mode: MintMode::Core,
            mint_suites: vec!["recovery".to_string()],
            inventory: placeholder_inventory(),
            known_failures: placeholder_known_failures(),
            forbidden_material: Vec::new(),
        }
    }

    #[test]
    fn reproduction_reuses_recorded_mint_inputs_with_a_fresh_namespace() {
        let original = request();
        let root = tempfile::tempdir().expect("original run");
        let mint_root = root.path().join(MINT_ARTIFACT_DIR);
        fs::create_dir(&mint_root).expect("Mint artifacts");
        let profile = MintProfile::new(MintProfileSpec {
            name: original.profile_name.clone(),
            image: original.mint_image.clone(),
            platform: original.mint_platform.clone(),
            mode: original.mint_mode,
            suites: original.mint_suites.clone(),
            region: original.target.region.clone(),
            target_fingerprint: format!("sha256:{}", original.target.target_fingerprint),
        })
        .expect("original profile");
        for (name, value) in [
            (
                TARGET_SPEC_FILE.to_string(),
                serde_json::to_value(&original.target).expect("target JSON"),
            ),
            (
                "mint/mint-profile.json".to_string(),
                serde_json::to_value(&profile).expect("profile JSON"),
            ),
            (
                "mint/mint-inventory.json".to_string(),
                serde_json::to_value(&original.inventory).expect("inventory JSON"),
            ),
            (
                "mint/mint-known-failures.json".to_string(),
                serde_json::to_value(&original.known_failures).expect("known failures JSON"),
            ),
        ] {
            fs::write(
                root.path().join(name),
                serde_json::to_vec(&value).expect("JSON"),
            )
            .expect("recorded input");
        }
        let mut target = original.target.clone();
        let now = time::OffsetDateTime::now_utc();
        target.created_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .expect("created time");
        target.expires_at = (now + time::Duration::hours(12))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("expiry");
        let destination = root.path().join("reproduction");
        assert!(mint_reproduction_request(root.path(), target.clone(), &destination).is_err());
        target.namespace_uid = Uuid::new_v4().to_string();
        let replay = mint_reproduction_request(root.path(), target.clone(), &destination)
            .expect("new target request");
        assert_eq!(replay.target, target);
        assert_eq!(replay.mint_image, original.mint_image);
        assert_eq!(replay.inventory, original.inventory);
        assert_eq!(replay.known_failures, original.known_failures);
        assert!(!destination.exists());
        assert_eq!(
            fs::read_dir(root.path()).expect("original entries").count(),
            2
        );
    }

    fn capture(disposition: MintProcessDisposition) -> OwnedMintCapture {
        OwnedMintCapture {
            process_disposition: disposition,
            container_started: true,
            container_exit_code: Some(0),
            infrastructure_failure: None,
            log: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
        }
    }

    #[tokio::test]
    async fn cancellation_before_spawn_never_starts_docker() {
        let (sender, mut cancellation) = watch::channel(false);
        sender.send(true).expect("request cancellation");
        let capture = run_mint_container(&request(), &mut cancellation).await;
        assert_eq!(
            capture.process_disposition,
            MintProcessDisposition::Interrupted
        );
        assert!(!capture.container_started);
        assert_eq!(capture.container_exit_code, None);
    }

    #[test]
    fn recovery_without_original_scan_material_skips_live_captures() {
        assert!(!recovery_scan_material_available(&[], false));
        assert!(!recovery_scan_material_available(&[], true));
    }

    #[test]
    fn publication_error_detail_is_redacted_before_persistence() {
        let root = std::env::temp_dir().join(format!("s3chaos-mint-error-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("artifact root");
        let writer = ProtocolArtifactWriter::file(&root);
        let error = anyhow::anyhow!("Mint output contained recovery-secret");
        write_failure_detail(
            &writer,
            MINT_PUBLICATION_ERROR_FILE,
            &error,
            &["recovery-secret".to_string()],
        )
        .expect("sanitized failure detail");
        let persisted =
            fs::read_to_string(root.join(MINT_PUBLICATION_ERROR_FILE)).expect("failure detail");
        assert!(!persisted.contains("recovery-secret"));
        assert!(persisted.contains("REDACTED"));
        fs::remove_dir_all(root).expect("remove test artifacts");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn recovery_rejects_a_symlink_root_before_reading_artifacts() {
        use std::os::unix::fs::symlink;

        let root = std::env::temp_dir().join(format!("s3chaos-mint-root-test-{}", Uuid::new_v4()));
        let link = root.with_extension("link");
        fs::create_dir(&root).expect("artifact root");
        symlink(&root, &link).expect("artifact symlink");
        let error = cleanup_mint_session(&link, &[])
            .await
            .expect_err("symlink root must be rejected");
        assert!(error.to_string().contains("not a symlink"));
        fs::remove_file(link).expect("remove symlink");
        fs::remove_dir_all(root).expect("remove test artifacts");
    }

    #[test]
    fn overall_gate_requires_mint_diagnostics_and_teardown() {
        let summary = build_summary(
            &request().target.run_id,
            &lifecycle(),
            &capture(MintProcessDisposition::Completed),
            Some(MintGateStatus::Passed),
            true,
            MintTeardownStatus::Passed,
            Vec::new(),
        );
        assert_eq!(summary.gate_status, MintSessionGateStatus::Passed);

        let teardown_failed = build_summary(
            &request().target.run_id,
            &lifecycle(),
            &capture(MintProcessDisposition::Completed),
            Some(MintGateStatus::Passed),
            true,
            MintTeardownStatus::Failed,
            vec![MintSessionFailureCode::TargetTeardownFailed],
        );
        assert_eq!(teardown_failed.gate_status, MintSessionGateStatus::Failed);
    }

    #[test]
    fn interrupted_mint_stays_failed_after_successful_cleanup() {
        for (disposition, code) in [
            (
                MintProcessDisposition::Interrupted,
                MintSessionFailureCode::MintInterrupted,
            ),
            (
                MintProcessDisposition::TimedOut,
                MintSessionFailureCode::MintTimedOut,
            ),
            (
                MintProcessDisposition::StartFailed,
                MintSessionFailureCode::MintStartFailed,
            ),
            (
                MintProcessDisposition::RuntimeFailed,
                MintSessionFailureCode::MintRuntimeFailed,
            ),
        ] {
            let summary = build_summary(
                &request().target.run_id,
                &lifecycle(),
                &capture(disposition),
                Some(MintGateStatus::Failed),
                true,
                MintTeardownStatus::Passed,
                vec![code],
            );
            assert_eq!(summary.gate_status, MintSessionGateStatus::Failed);
            assert_eq!(summary.teardown_status, MintTeardownStatus::Passed);
            assert!(session_junit(&summary).contains("failures=\"2\""));
        }
    }

    #[test]
    fn example_target_contract_is_static_and_exact() {
        let raw = include_str!("../../../protocol/mint/ephemeral-target.example.yaml");
        let target = MintTargetSpec::from_yaml(raw, "2026-08-24T01:00:00Z")
            .expect("example target contract");
        assert_eq!(
            target.container_name(),
            "s3chaos-mint-mint-20260824-001-11111111"
        );
        assert!(docker_container_ownership_matches(
            &target,
            format!("{}|{}\n", target.run_id, target.namespace_uid).as_bytes()
        ));
        assert!(!docker_container_ownership_matches(
            &target,
            format!("{}|22222222-2222-4222-8222-222222222222", target.run_id).as_bytes()
        ));
        assert!(docker_inspect_reports_absent(
            b"error: no such object: s3chaos-mint-run"
        ));
        assert!(docker_inspect_reports_absent(
            b"Error response from daemon: No such container: s3chaos-mint-run"
        ));
        assert!(!docker_inspect_reports_absent(
            b"permission denied while trying to connect to the Docker daemon"
        ));
        assert!(!docker_inspect_reports_absent(
            b"permission denied: no such object: s3chaos-mint-run"
        ));
    }

    #[tokio::test]
    async fn session_recovery_rebuilds_terminal_artifacts_and_binds_namespace_uid() {
        let root =
            std::env::temp_dir().join(format!("s3chaos-mint-session-test-{}", Uuid::new_v4()));
        fs::create_dir(&root).expect("session root");
        let writer = ProtocolArtifactWriter::file(&root);
        writer
            .create_dir(KUBERNETES_ARTIFACT_DIR)
            .expect("Kubernetes dir");
        let request = request();
        write_safe_json(&writer, TARGET_SPEC_FILE, &request.target, &[]).expect("target spec");
        let namespace_proof = MintNamespaceProof {
            context: request.target.context.clone(),
            namespace: request.target.namespace.clone(),
            namespace_uid: request.target.namespace_uid.clone(),
            run_id: request.target.run_id.clone(),
            expires_at: request.target.expires_at.clone(),
            verified_at: "2026-08-24T01:00:00Z".to_string(),
        };
        write_safe_json(&writer, NAMESPACE_PROOF_FILE, &namespace_proof, &[])
            .expect("namespace proof");
        let target_proof = MintTargetProof {
            api_version: API_VERSION.to_string(),
            kind: "MintTargetProof".to_string(),
            namespace: namespace_proof.clone(),
            namespace_pod_count: 1,
            rustfs_pods: vec![MintPodProof {
                name: "rustfs-0".to_string(),
                uid: "pod-uid".to_string(),
                node_name: "node-1".to_string(),
                image_id: format!("rustfs/rustfs@{}", request.target.rustfs_image_digest),
                ready: true,
                restart_count: 0,
            }],
            service: MintServiceProof {
                name: request.target.service_name.clone(),
                uid: "service-uid".to_string(),
                port: request.target.service_port,
                endpoint_host: "rustfs-mint.example".to_string(),
                endpoint_slice_uids: vec!["endpoint-slice-uid".to_string()],
                backend_pod_uids: vec!["pod-uid".to_string()],
            },
            rustfs_image_digest: request.target.rustfs_image_digest.clone(),
            delete_allowed: true,
            server: TargetFingerprint {
                endpoint: "http://rustfs-mint.example:9000".to_string(),
                region: request.target.region.clone(),
                deployment_id: "deployment".to_string(),
                server_mode: Some("distributed".to_string()),
                reported_region: Some(request.target.region.clone()),
                sha256: request.target.target_fingerprint.clone(),
            },
            verified_at: "2026-08-24T01:00:00Z".to_string(),
        };
        write_safe_json(&writer, TARGET_PROOF_FILE, &target_proof, &[]).expect("target proof");

        let profile = MintProfile::new(MintProfileSpec {
            name: request.profile_name.clone(),
            image: request.mint_image.clone(),
            platform: request.mint_platform.clone(),
            mode: request.mint_mode,
            suites: request.mint_suites.clone(),
            region: request.target.region.clone(),
            target_fingerprint: format!("sha256:{}", request.target.target_fingerprint),
        })
        .expect("profile");
        write_mint_artifacts(
            root.join(MINT_ARTIFACT_DIR),
            &profile,
            &request.inventory,
            &request.known_failures,
            MintCapturedRun {
                container_started: true,
                container_exit_code: Some(0),
                infrastructure_failure: None,
                log: Some(br#"{"name":"recovery","function":"recovery","status":"PASS"}"#),
                stdout: b"",
                stderr: b"",
            },
            "2026-08-24T01:00:00Z",
            &[],
        )
        .expect("Mint artifacts");
        write_diagnostics(
            &writer,
            &[MintTargetDiagnostic {
                file_name: "resources.txt".to_string(),
                contents: b"ready\n".to_vec(),
                succeeded: true,
            }],
            &[],
            &request.target.run_id,
        )
        .expect("diagnostics");
        let mut lifecycle = lifecycle();
        lifecycle.run_id.clone_from(&request.target.run_id);
        lifecycle.container_name = request.target.container_name();
        write_safe_json(&writer, LIFECYCLE_FILE, &lifecycle, &[]).expect("lifecycle");
        let teardown_proof = MintTargetTeardownProof {
            api_version: API_VERSION.to_string(),
            kind: "MintTargetTeardownProof".to_string(),
            context: request.target.context.clone(),
            namespace: request.target.namespace.clone(),
            namespace_uid: request.target.namespace_uid.clone(),
            requested_at: "2026-08-24T01:00:00Z".to_string(),
            verified_absent_at: "2026-08-24T01:01:00Z".to_string(),
            namespace_absent: true,
        };
        let mut cleanup = MintCleanupReport {
            api_version: API_VERSION.to_string(),
            kind: "MintCleanupReport".to_string(),
            status: MintTeardownStatus::Passed,
            container_name: request.target.container_name(),
            container_absent: true,
            namespace_absent: true,
            teardown_proof: Some(teardown_proof),
            failure_codes: Vec::new(),
            errors: Vec::new(),
        };
        write_safe_json(&writer, CLEANUP_REPORT_FILE, &cleanup, &[]).expect("cleanup");
        let summary = build_summary(
            &request.target.run_id,
            &lifecycle,
            &capture(MintProcessDisposition::Completed),
            Some(MintGateStatus::Passed),
            true,
            MintTeardownStatus::Passed,
            Vec::new(),
        );
        publish_session_summary(&root, &writer, &summary, &[]).expect("summary");
        validate_mint_session_artifacts_and_write_report(&root, &[]).expect("valid session");

        for terminal in [
            SESSION_SUMMARY_FILE,
            SESSION_JUNIT_FILE,
            SESSION_EXIT_CODE_FILE,
        ] {
            fs::remove_file(root.join(terminal)).expect("simulate crash before terminal artifact");
        }
        let recovered = cleanup_mint_session(&root, &[])
            .await
            .expect("recover already-absent target");
        assert_eq!(recovered.cleanup_exit_code, 0);
        assert_eq!(recovered.gate_exit_code, 1);
        validate_mint_session_artifacts_and_write_report(&root, &[])
            .expect("valid recovered session");

        cleanup
            .teardown_proof
            .as_mut()
            .expect("teardown proof")
            .namespace_uid = "22222222-2222-4222-8222-222222222222".to_string();
        write_safe_json(&writer, CLEANUP_REPORT_FILE, &cleanup, &[]).expect("tampered cleanup");
        assert!(validate_mint_session_artifacts_and_write_report(&root, &[]).is_err());
        fs::remove_dir_all(root).expect("remove test artifacts");
    }
}
