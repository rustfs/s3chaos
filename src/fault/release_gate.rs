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

//! Release gate for a RustFS tag.
//!
//! One entry point plans smoke, standard, or full coverage, runs the cases
//! this host can actually execute, and writes JSON, JUnit, and Markdown.
//! Skips carry a stable reason code. A live run fails when a required case
//! was skipped because the cluster was missing. Dry-run and known platform
//! limits (arm64 toda, no device-mapper, physical power) do not.

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Duration,
};

use super::scenarios::{self, FaultBackend, FaultScenarioStatus};

const SCHEMA_VERSION: u32 = 1;
const DEFAULT_REGRESSION_PERCENT: f64 = 20.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReleaseTier {
    Smoke,
    Standard,
    Full,
}

impl ReleaseTier {
    pub fn parse(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "smoke" => Ok(Self::Smoke),
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            other => bail!("release-gate tier must be smoke, standard, or full, got {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Standard => "standard",
            Self::Full => "full",
        }
    }

    fn includes(self, case: Self) -> bool {
        (self as u8) >= (case as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CaseStatus {
    Pass,
    Fail,
    Skip,
    Pending,
}

impl CaseStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
            Self::Pending => "PENDING",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReleaseGateRequest {
    pub version: String,
    pub prev_version: Option<String>,
    pub image: Option<String>,
    pub git_sha: Option<String>,
    pub tier: ReleaseTier,
    pub dry_run: bool,
    pub fetch: bool,
    pub output_dir: PathBuf,
    pub artifact_dir: PathBuf,
    pub arch: String,
    pub cluster: bool,
    pub device_mapper: bool,
    pub toda_usable: bool,
    pub endpoint: Option<String>,
    pub regression_percent: f64,
}

impl ReleaseGateRequest {
    pub fn from_env() -> Result<Self> {
        Self::from_map(&std::env::vars().collect())
    }

    pub fn from_map(env: &BTreeMap<String, String>) -> Result<Self> {
        let version = env
            .get("RUSTFS_VERSION")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .context("RUSTFS_VERSION is required, for example 1.0.1-preview.11")?;
        validate_release_tag(&version)?;
        let prev_version = optional_tag(env, "RUSTFS_PREV_VERSION")?;
        let tier = ReleaseTier::parse(
            env.get("RELEASE_GATE_TIER")
                .map(String::as_str)
                .unwrap_or("standard"),
        )?;
        let dry_run = bool_value(env.get("RELEASE_GATE_DRY_RUN"), false)?;
        let fetch = bool_value(env.get("RELEASE_GATE_FETCH"), false)?;
        let arch = env
            .get("RUSTFS_RELEASE_GATE_ARCH")
            .cloned()
            .unwrap_or_else(|| std::env::consts::ARCH.to_string());
        let toda_default = matches!(arch.as_str(), "x86_64" | "amd64");
        let toda_usable = bool_value(env.get("RUSTFS_RELEASE_GATE_TODA"), toda_default)?;
        let cluster = bool_value(env.get("RUSTFS_RELEASE_GATE_HAS_CLUSTER"), false)?;
        let device_mapper = bool_value(env.get("RUSTFS_RELEASE_GATE_HAS_DM"), false)?;
        let output_dir = env
            .get("RELEASE_GATE_OUTPUT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("target/release-gate").join(sanitize_token(&version)));
        let artifact_dir = env
            .get("RUSTFS_ARTIFACT_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| output_dir.join("artifacts"));
        let regression_percent = env
            .get("RUSTFS_WARP_REGRESSION_PERCENT")
            .map(|value| {
                value.parse::<f64>().with_context(|| {
                    format!("RUSTFS_WARP_REGRESSION_PERCENT must be a number, got {value}")
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_REGRESSION_PERCENT);
        ensure_percent(regression_percent)?;
        Ok(Self {
            version,
            prev_version,
            image: env
                .get("RUSTFS_IMAGE")
                .cloned()
                .filter(|value| !value.is_empty()),
            git_sha: env
                .get("RUSTFS_GIT_SHA")
                .cloned()
                .filter(|value| !value.is_empty()),
            tier,
            dry_run,
            fetch,
            output_dir,
            artifact_dir,
            arch,
            cluster,
            device_mapper,
            toda_usable,
            endpoint: env
                .get("RUSTFS_ENDPOINT")
                .or_else(|| env.get("RUSTFS_PROTOCOL_TEST_ENDPOINT"))
                .cloned()
                .filter(|value| !value.is_empty()),
            regression_percent,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ChecksumRow {
    pub name: String,
    pub expected_sha256: String,
    pub actual_sha256: String,
    pub matches: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaseRow {
    pub id: String,
    pub title: String,
    pub tier: String,
    pub surfaces: String,
    pub status: String,
    pub reason: String,
    #[serde(skip)]
    counts_as_failure: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReleaseGateReport {
    pub schema_version: u32,
    pub verdict: String,
    pub mode: String,
    pub tier: String,
    pub rustfs_version: String,
    pub rustfs_prev_version: Option<String>,
    pub rustfs_image: Option<String>,
    pub git_sha: Option<String>,
    pub arch: String,
    pub artifact_checksums: Vec<ChecksumRow>,
    pub cases: Vec<CaseRow>,
}

pub async fn run_release_gate(mut request: ReleaseGateRequest) -> Result<ReleaseGateReport> {
    fs::create_dir_all(&request.output_dir)?;
    fs::create_dir_all(&request.artifact_dir)?;
    let mut fetch_error = None;
    if request.fetch {
        match fetch_release_assets(&request.version, &request.artifact_dir).await {
            Ok(sha) => {
                if request.git_sha.is_none() {
                    request.git_sha = sha;
                }
            }
            Err(error) => fetch_error = Some(format!("{error:#}")),
        }
    }
    let mut report = plan_release_gate(&request);
    if let Some(error) = fetch_error {
        report.cases.insert(
            0,
            CaseRow {
                id: "release-fetch".to_string(),
                title: "Fetch the published release assets".to_string(),
                tier: request.tier.as_str().to_string(),
                surfaces: "ci-amd64,mac-mini-arm64".to_string(),
                status: CaseStatus::Fail.as_str().to_string(),
                reason: error,
                counts_as_failure: true,
            },
        );
    }
    execute_pending(&mut report, &request)?;
    finalize_verdict(&mut report);
    write_reports(&request.output_dir, &report)?;
    Ok(report)
}

pub fn plan_release_gate(request: &ReleaseGateRequest) -> ReleaseGateReport {
    let mut cases = Vec::new();
    for spec in case_specs() {
        if !request.tier.includes(spec.tier) {
            continue;
        }
        cases.push(planned_row(
            spec.id,
            spec.title,
            spec.tier,
            spec.surfaces,
            preliminary_skip(spec.id, spec.action, request),
            request,
        ));
    }
    for scenario in scenarios::scenario_catalog() {
        let tier = scenario_tier(scenario.scenario, scenario.backend, scenario.status);
        if !request.tier.includes(tier) {
            continue;
        }
        let id = format!("fault:{}", scenario.scenario);
        cases.push(planned_row(
            &id,
            scenario.description,
            tier,
            scenario_surfaces(scenario.backend, scenario.status),
            fault_skip(scenario.scenario, request),
            request,
        ));
    }
    ReleaseGateReport {
        schema_version: SCHEMA_VERSION,
        verdict: "pending".to_string(),
        mode: if request.dry_run { "dry-run" } else { "live" }.to_string(),
        tier: request.tier.as_str().to_string(),
        rustfs_version: request.version.clone(),
        rustfs_prev_version: request.prev_version.clone(),
        rustfs_image: request.image.clone(),
        git_sha: request.git_sha.clone(),
        arch: request.arch.clone(),
        artifact_checksums: Vec::new(),
        cases,
    }
}

fn execute_pending(report: &mut ReleaseGateReport, request: &ReleaseGateRequest) -> Result<()> {
    let checksums = evaluate_checksums(&request.artifact_dir).unwrap_or_default();
    report.artifact_checksums = checksums.clone();
    let version_output = read_optional(&request.artifact_dir.join("rustfs-version.txt"));
    if report.git_sha.is_none() {
        report.git_sha = version_output.as_deref().and_then(parse_git_sha);
    }
    for case in &mut report.cases {
        if case.status != CaseStatus::Pending.as_str() {
            continue;
        }
        let outcome = execute_case(&case.id, request, &checksums, version_output.as_deref());
        case.status = outcome.status.as_str().to_string();
        case.reason = outcome.reason;
        case.counts_as_failure = outcome.status == CaseStatus::Fail
            || (outcome.status == CaseStatus::Skip && !skip_is_passing(&case.reason, request));
    }
    score_post_fault_checksums(report, request);
    Ok(())
}

fn score_post_fault_checksums(report: &mut ReleaseGateReport, request: &ReleaseGateRequest) {
    let Some(index) = report
        .cases
        .iter()
        .position(|case| case.id == "post-fault-checksums")
    else {
        return;
    };
    if report.cases[index].status != CaseStatus::Pass.as_str()
        && report.cases[index].status != CaseStatus::Pending.as_str()
    {
        return;
    }
    let outcome = if request.dry_run {
        Outcome {
            status: CaseStatus::Skip,
            reason:
                "SKIP-dry-run: object checksums are checked inside each fault scenario when it runs"
                    .to_string(),
        }
    } else if !request.cluster {
        Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-no-cluster: object checksums are checked inside each fault scenario when it runs".to_string(),
        }
    } else {
        let fault_failed = report.cases.iter().any(|case| {
            case.id.starts_with("fault:")
                && (case.status == CaseStatus::Fail.as_str()
                    || (case.status == CaseStatus::Skip.as_str() && case.counts_as_failure))
        });
        let fault_passed = report
            .cases
            .iter()
            .any(|case| case.id.starts_with("fault:") && case.status == CaseStatus::Pass.as_str());
        if fault_failed || !fault_passed {
            Outcome {
                status: CaseStatus::Fail,
                reason: "fault scenarios in this tier did not all pass, so post-fault checksum coverage is incomplete".to_string(),
            }
        } else {
            Outcome {
                status: CaseStatus::Pass,
                reason: "every fault scenario that ran in this tier passed, including its object checksum checks".to_string(),
            }
        }
    };
    let failure = outcome.status == CaseStatus::Fail
        || (outcome.status == CaseStatus::Skip && !skip_is_passing(&outcome.reason, request));
    let case = &mut report.cases[index];
    case.status = outcome.status.as_str().to_string();
    case.reason = outcome.reason;
    case.counts_as_failure = failure;
}

struct Outcome {
    status: CaseStatus,
    reason: String,
}

fn execute_case(
    id: &str,
    request: &ReleaseGateRequest,
    checksums: &[ChecksumRow],
    version_output: Option<&str>,
) -> Outcome {
    match id {
        "release-artifact-checksums" => checksum_outcome(checksums),
        "release-artifact-version" => version_outcome(version_output, &request.version),
        "release-artifact-dynamic-deps" => dynamic_dep_outcome(&request.artifact_dir),
        "post-fault-checksums" => Outcome {
            status: CaseStatus::Pass,
            reason: "each executable fault scenario checks committed object checksums before, during, and after the fault".to_string(),
        },
        "quorum-edge-cold-read" => evidence_or_live(request, "quorum-edge-cold-read.json", classify_quorum_edge_file),
        "large-object-get-integrity" => evidence_or_live(request, "large-object-get.json", classify_large_get_file),
        "upgrade-stability" => evidence_or_upgrade(request, false),
        "upgrade-rollback" => evidence_or_upgrade(request, true),
        "warp-regression-vs-previous" => warp_outcome(request),
        "s3-lifecycle-rule" => evidence_or_live(request, "lifecycle-rule.json", classify_lifecycle_file),
        "expand-pools" => evidence_or_skip(request, "expand-status.json", "SKIP-planned", classify_expand_file),
        "admin-decommission-complete" => {
            evidence_or_skip(request, "decommission-status.json", "SKIP-planned", classify_decommission_file)
        }
        "admin-rebalance-complete" => {
            evidence_or_skip(request, "rebalance-status.json", "SKIP-planned", classify_rebalance_file)
        }
        "disk-full-fill" => run_host_disk(request, "fill", "disk-full-fill.json", classify_disk_fill_file),
        "volume-remount-ro" => {
            run_host_disk(request, "remount", "volume-remount-ro.json", classify_remount_file)
        }
        "dm-error" => evidence_or_skip(request, "dm-error.json", "SKIP-no-dm", classify_dm_error_file),
        "fresh-install" => fresh_install_outcome(request),
        "physical-power" => Outcome {
            status: CaseStatus::Skip,
            reason: "DEFERRED-physical-power: process kill -9 and graceful stop are the in-repo proxy; a PSU cycle is not automated".to_string(),
        },
        other if other.starts_with("fault:") => run_fault_scenario(request, other.trim_start_matches("fault:")),
        other if other.starts_with("protocol:") => {
            run_protocol_suite(request, other.trim_start_matches("protocol:"))
        }
        other => Outcome {
            status: CaseStatus::Fail,
            reason: format!("release gate has no executor for {other}"),
        },
    }
}

fn run_fault_scenario(request: &ReleaseGateRequest, scenario: &str) -> Outcome {
    if request.dry_run || !request.cluster {
        let reason = if request.dry_run {
            "SKIP-dry-run"
        } else {
            "SKIP-no-cluster"
        };
        return Outcome {
            status: CaseStatus::Skip,
            reason: reason.to_string(),
        };
    }
    let script = PathBuf::from("scripts/fault-test.sh");
    let mut command = Command::new("bash");
    command.arg(&script).arg("run").arg(scenario);
    if let Some(image) = &request.image {
        command.env("RUSTFS_FAULT_TEST_SERVER_IMAGE", image);
    }
    match command.status() {
        Ok(status) if status.success() => Outcome {
            status: CaseStatus::Pass,
            reason: format!("fault scenario {scenario} passed"),
        },
        Ok(status) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("fault scenario {scenario} exited {status}"),
        },
        Err(error) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("failed to start fault scenario {scenario}: {error}"),
        },
    }
}

fn run_protocol_suite(request: &ReleaseGateRequest, suite: &str) -> Outcome {
    if request.dry_run || !request.cluster {
        let reason = if request.dry_run {
            "SKIP-dry-run"
        } else {
            "SKIP-no-cluster"
        };
        return Outcome {
            status: CaseStatus::Skip,
            reason: reason.to_string(),
        };
    }
    match Command::new("bash")
        .arg("scripts/protocol-test.sh")
        .arg("suite-run")
        .arg(suite)
        .status()
    {
        Ok(status) if status.success() => Outcome {
            status: CaseStatus::Pass,
            reason: format!("protocol suite {suite} passed"),
        },
        Ok(status) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("protocol suite {suite} exited {status}"),
        },
        Err(error) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("failed to start protocol suite {suite}: {error}"),
        },
    }
}

fn fresh_install_outcome(request: &ReleaseGateRequest) -> Outcome {
    if let Some(text) = read_optional(&request.artifact_dir.join("fresh-install.json")) {
        return classify_fresh_install(&text);
    }
    if request.dry_run || !request.cluster {
        let reason = if request.dry_run {
            "SKIP-dry-run"
        } else {
            "SKIP-no-cluster"
        };
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!(
                "{reason}: fresh install checks /health on the new image after the tenant becomes Ready"
            ),
        };
    }
    Outcome {
        status: CaseStatus::Fail,
        reason: "fresh-install.json is required on a live cluster; tenant preflight does not prove a new-image install".to_string(),
    }
}

fn evidence_or_live(
    request: &ReleaseGateRequest,
    file_name: &str,
    classify: fn(&str) -> Outcome,
) -> Outcome {
    if let Some(text) = read_optional(&request.artifact_dir.join(file_name)) {
        return classify(&text);
    }
    if request.dry_run {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("SKIP-dry-run: no {file_name} evidence in the artifact directory"),
        };
    }
    if !request.cluster {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!(
                "SKIP-no-cluster: no {file_name} evidence and no cluster to produce it"
            ),
        };
    }
    Outcome {
        status: CaseStatus::Fail,
        reason: format!(
            "live cluster has no {file_name} evidence; the Mac Mini run must write that file under the artifact directory"
        ),
    }
}

fn evidence_or_upgrade(request: &ReleaseGateRequest, rollback: bool) -> Outcome {
    let file_name = if rollback {
        "upgrade-rollback.json"
    } else {
        "upgrade-stability.json"
    };
    if let Some(text) = read_optional(&request.artifact_dir.join(file_name)) {
        return classify_upgrade_file(&text, rollback);
    }
    if request.prev_version.is_none() {
        return Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-no-prev-version: set RUSTFS_PREV_VERSION to compare upgrade and rollback"
                .to_string(),
        };
    }
    if request.dry_run || !request.cluster {
        let reason = if request.dry_run {
            "SKIP-dry-run"
        } else {
            "SKIP-no-cluster"
        };
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("{reason}: upgrade evidence {file_name} was not provided"),
        };
    }
    let script = PathBuf::from("scripts/release-gate-upgrade.sh");
    let mode = if rollback { "rollback" } else { "upgrade" };
    match Command::new("bash")
        .arg(&script)
        .arg(mode)
        .env("RUSTFS_VERSION", &request.version)
        .env(
            "RUSTFS_PREV_VERSION",
            request.prev_version.clone().unwrap_or_default(),
        )
        .env("RUSTFS_IMAGE", request.image.clone().unwrap_or_default())
        .env("RELEASE_GATE_ARTIFACT_DIR", &request.artifact_dir)
        .status()
    {
        Ok(status) => {
            if let Some(text) = read_optional(&request.artifact_dir.join(file_name)) {
                return classify_upgrade_file(&text, rollback);
            }
            if status.code() == Some(2) {
                Outcome {
                    status: CaseStatus::Skip,
                    reason: format!(
                        "SKIP-no-mc: upgrade script exited 2; mc or the tenant was not available for {mode}"
                    ),
                }
            } else if status.success() {
                Outcome {
                    status: CaseStatus::Fail,
                    reason: format!("{script:?} succeeded without writing {file_name}"),
                }
            } else {
                Outcome {
                    status: CaseStatus::Fail,
                    reason: format!("upgrade script {mode} exited {status}"),
                }
            }
        }
        Err(error) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("failed to start upgrade script: {error}"),
        },
    }
}

fn evidence_or_skip(
    request: &ReleaseGateRequest,
    file_name: &str,
    absent_code: &str,
    classify: fn(&str) -> Outcome,
) -> Outcome {
    if let Some(text) = read_optional(&request.artifact_dir.join(file_name)) {
        return classify(&text);
    }
    if absent_code == "SKIP-no-dm" && !request.device_mapper {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("SKIP-no-dm: no {file_name} evidence"),
        };
    }
    if request.dry_run {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("SKIP-dry-run: no {file_name} evidence"),
        };
    }
    if !request.cluster {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("SKIP-no-cluster: no {file_name} evidence"),
        };
    }
    Outcome {
        status: CaseStatus::Fail,
        reason: format!(
            "live cluster has no {file_name} evidence; the campaign must write that file before this case can pass"
        ),
    }
}

fn run_host_disk(
    request: &ReleaseGateRequest,
    mode: &str,
    file_name: &str,
    classify: fn(&str) -> Outcome,
) -> Outcome {
    if let Some(text) = read_optional(&request.artifact_dir.join(file_name)) {
        return classify(&text);
    }
    if request.dry_run {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("SKIP-dry-run: no {file_name} evidence"),
        };
    }
    if !request.cluster {
        return Outcome {
            status: CaseStatus::Skip,
            reason: format!("SKIP-no-cluster: no {file_name} evidence"),
        };
    }
    match Command::new("bash")
        .arg("scripts/release-gate-host-disk.sh")
        .arg(mode)
        .env("RELEASE_GATE_ARTIFACT_DIR", &request.artifact_dir)
        .status()
    {
        Ok(status) => {
            if let Some(text) = read_optional(&request.artifact_dir.join(file_name)) {
                return classify(&text);
            }
            if status.code() == Some(2) {
                Outcome {
                    status: CaseStatus::Skip,
                    reason: format!(
                        "SKIP-no-privileged: host disk {mode} could not remount or fill the volume without privileges"
                    ),
                }
            } else if status.success() {
                Outcome {
                    status: CaseStatus::Fail,
                    reason: format!("host disk {mode} succeeded without writing {file_name}"),
                }
            } else {
                Outcome {
                    status: CaseStatus::Fail,
                    reason: format!("host disk {mode} exited {status}"),
                }
            }
        }
        Err(error) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("failed to start host disk {mode}: {error}"),
        },
    }
}

fn warp_outcome(request: &ReleaseGateRequest) -> Outcome {
    if let Some(text) = read_optional(&request.artifact_dir.join("warp-compare.json")) {
        return classify_warp_file(&text, request.regression_percent);
    }
    if request.prev_version.is_none() {
        return Outcome {
            status: CaseStatus::Skip,
            reason:
                "SKIP-no-baseline: warp regression needs RUSTFS_PREV_VERSION and warp-compare.json"
                    .to_string(),
        };
    }
    if request.dry_run {
        return Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-dry-run: warp-compare.json was not provided".to_string(),
        };
    }
    if !request.cluster {
        return Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-no-cluster: warp-compare.json was not provided".to_string(),
        };
    }
    Outcome {
        status: CaseStatus::Fail,
        reason: "live cluster has no warp-compare.json; record current and baseline ops/s before this case can pass".to_string(),
    }
}

fn checksum_outcome(checksums: &[ChecksumRow]) -> Outcome {
    if checksums.is_empty() {
        return Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-no-artifact: SHA256SUMS or downloaded assets were not in the artifact directory".to_string(),
        };
    }
    let mismatches = checksums.iter().filter(|row| !row.matches).count();
    if mismatches == 0 {
        Outcome {
            status: CaseStatus::Pass,
            reason: format!("{} artifact checksums match SHA256SUMS", checksums.len()),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!("{mismatches} artifact checksums did not match SHA256SUMS"),
        }
    }
}

fn version_outcome(output: Option<&str>, tag: &str) -> Outcome {
    let Some(output) = output else {
        return Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-no-artifact: rustfs-version.txt was not captured".to_string(),
        };
    };
    if version_matches_tag(output, tag) {
        Outcome {
            status: CaseStatus::Pass,
            reason: format!("--version output contains {tag}"),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!("--version output does not contain {tag}: {output}"),
        }
    }
}

fn dynamic_dep_outcome(artifact_dir: &Path) -> Outcome {
    let ldd = read_optional(&artifact_dir.join("rustfs-ldd.txt"));
    let otool = read_optional(&artifact_dir.join("rustfs-otool.txt"));
    if ldd.is_none() && otool.is_none() {
        return Outcome {
            status: CaseStatus::Skip,
            reason: "SKIP-no-artifact: neither rustfs-ldd.txt nor rustfs-otool.txt was captured"
                .to_string(),
        };
    }
    let mut foreign = Vec::new();
    if let Some(text) = ldd {
        foreign.extend(non_system_dynamic_deps(DynTool::Ldd, &text));
    }
    if let Some(text) = otool {
        foreign.extend(non_system_dynamic_deps(DynTool::Otool, &text));
    }
    if foreign.is_empty() {
        Outcome {
            status: CaseStatus::Pass,
            reason: "release binaries link only system dynamic libraries".to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!("non-system dynamic dependencies: {}", foreign.join(", ")),
        }
    }
}

fn finalize_verdict(report: &mut ReleaseGateReport) {
    let failed = report.cases.iter().any(|case| case.counts_as_failure);
    report.verdict = if failed { "fail" } else { "pass" }.to_string();
}

fn write_reports(output_dir: &Path, report: &ReleaseGateReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("encode release-gate json")?;
    fs::write(output_dir.join("release-gate.json"), json + "\n")?;
    fs::write(output_dir.join("release-gate.junit.xml"), junit(report))?;
    fs::write(output_dir.join("RELEASE_GATE.md"), markdown(report))?;
    println!(
        "release gate {}: {}",
        report.verdict,
        output_dir.join("RELEASE_GATE.md").display()
    );
    Ok(())
}

fn markdown(report: &ReleaseGateReport) -> String {
    let mut text = String::new();
    text.push_str("# RustFS release gate\n\n");
    text.push_str(&format!(
        "- Verdict: **{}**\n",
        report.verdict.to_ascii_uppercase()
    ));
    text.push_str(&format!("- Mode: {}\n", report.mode));
    text.push_str(&format!("- Tier: {}\n", report.tier));
    text.push_str(&format!("- Version: {}\n", report.rustfs_version));
    text.push_str(&format!(
        "- Previous: {}\n",
        report.rustfs_prev_version.as_deref().unwrap_or("-")
    ));
    text.push_str(&format!(
        "- Image: {}\n",
        report.rustfs_image.as_deref().unwrap_or("-")
    ));
    text.push_str(&format!(
        "- Git SHA: {}\n",
        report.git_sha.as_deref().unwrap_or("-")
    ));
    text.push_str(&format!("- Arch: {}\n\n", report.arch));
    if !report.artifact_checksums.is_empty() {
        text.push_str("## Artifact checksums\n\n");
        text.push_str("| File | SHA256 | Match |\n| --- | --- | --- |\n");
        for row in &report.artifact_checksums {
            text.push_str(&format!(
                "| {} | {} | {} |\n",
                row.name,
                row.actual_sha256,
                if row.matches { "yes" } else { "no" }
            ));
        }
        text.push('\n');
    }
    text.push_str("## Cases\n\n");
    text.push_str("| Case | Tier | Runs on | Result | Reason |\n| --- | --- | --- | --- | --- |\n");
    for case in &report.cases {
        text.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            case.id,
            case.tier,
            case.surfaces,
            case.status,
            case.reason.replace('|', "\\|")
        ));
    }
    text.push('\n');
    text
}

fn junit(report: &ReleaseGateReport) -> String {
    let tests = report.cases.len();
    let failures = report
        .cases
        .iter()
        .filter(|case| case.status == "FAIL" || case.counts_as_failure)
        .count();
    let skipped = report
        .cases
        .iter()
        .filter(|case| case.status == "SKIP" && !case.counts_as_failure)
        .count();
    let mut xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"rustfs-release-gate\" tests=\"{tests}\" failures=\"{failures}\" skipped=\"{skipped}\">\n"
    );
    for case in &report.cases {
        xml.push_str(&format!(
            "  <testcase classname=\"release-gate\" name=\"{}\">",
            xml_escape(&case.id)
        ));
        if case.status == "FAIL" || case.counts_as_failure {
            xml.push_str(&format!(
                "<failure message=\"{}\">{}</failure>",
                xml_escape(&case.reason),
                xml_escape(&case.reason)
            ));
        } else if case.status == "SKIP" {
            xml.push_str(&format!(
                "<skipped message=\"{}\"/>",
                xml_escape(&case.reason)
            ));
        }
        xml.push_str("</testcase>\n");
    }
    xml.push_str("</testsuite>\n");
    xml
}

#[derive(Clone, Copy)]
struct CaseSpec {
    id: &'static str,
    title: &'static str,
    tier: ReleaseTier,
    surfaces: &'static str,
    action: Action,
}

#[derive(Clone, Copy)]
enum Action {
    Check,
    Protocol,
}

fn planned_row(
    id: &str,
    title: &str,
    tier: ReleaseTier,
    surfaces: &str,
    skip: Option<&str>,
    request: &ReleaseGateRequest,
) -> CaseRow {
    let (status, reason, failure) = match skip {
        Some(reason) => (
            CaseStatus::Skip,
            reason.to_string(),
            !skip_is_passing(reason, request),
        ),
        None => (CaseStatus::Pending, "not executed yet".to_string(), false),
    };
    CaseRow {
        id: id.to_string(),
        title: title.to_string(),
        tier: tier.as_str().to_string(),
        surfaces: surfaces.to_string(),
        status: status.as_str().to_string(),
        reason,
        counts_as_failure: failure,
    }
}

fn case_specs() -> Vec<CaseSpec> {
    vec![
        CaseSpec {
            id: "release-artifact-checksums",
            title: "Release asset checksums match SHA256SUMS",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "release-artifact-version",
            title: "rustfs --version matches the release tag",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "release-artifact-dynamic-deps",
            title: "Release binaries have no non-system dynamic dependencies",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "fresh-install",
            title: "Fresh install of the new release becomes ready",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "protocol:protocol/examples/smoke.yaml",
            title: "S3 functional and compatibility smoke",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Protocol,
        },
        CaseSpec {
            id: "large-object-get-integrity",
            title: "Large object GET length and sha256, detecting truncation",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "post-fault-checksums",
            title: "Data checksums after every fault",
            tier: ReleaseTier::Smoke,
            surfaces: "ci-amd64,mac-mini-arm64,manual",
            action: Action::Check,
        },
        CaseSpec {
            id: "protocol:protocol/examples/full-regression.yaml",
            title: "S3 protocol regression including versioning",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Protocol,
        },
        CaseSpec {
            id: "s3-lifecycle-rule",
            title: "ILM lifecycle rule import, list, and GET",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "warp-regression-vs-previous",
            title: "warp PUT/GET/mixed regression against the previous release",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "upgrade-stability",
            title: "Rolling upgrade from the previous release keeps data, metadata, and config",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "upgrade-rollback",
            title: "Rollback to the previous release keeps the upgraded dataset",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "quorum-edge-cold-read",
            title: "Quorum-edge reads on every survivor, including a cold bucket",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "expand-pools",
            title: "Pool expand keeps object integrity",
            tier: ReleaseTier::Full,
            surfaces: "mac-mini-arm64,manual",
            action: Action::Check,
        },
        CaseSpec {
            id: "admin-rebalance-complete",
            title: "Rebalance reaches a terminal success state",
            tier: ReleaseTier::Full,
            surfaces: "mac-mini-arm64,manual",
            action: Action::Check,
        },
        CaseSpec {
            id: "admin-decommission-complete",
            title: "Decommission waits for complete:true",
            tier: ReleaseTier::Full,
            surfaces: "mac-mini-arm64,manual",
            action: Action::Check,
        },
        CaseSpec {
            id: "disk-full-fill",
            title: "Disk full by filling the volume, without IOChaos",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "volume-remount-ro",
            title: "Remount the data volume read-only, without IOChaos",
            tier: ReleaseTier::Standard,
            surfaces: "ci-amd64,mac-mini-arm64",
            action: Action::Check,
        },
        CaseSpec {
            id: "dm-error",
            title: "device-mapper error target",
            tier: ReleaseTier::Full,
            surfaces: "manual",
            action: Action::Check,
        },
        CaseSpec {
            id: "physical-power",
            title: "Physical PSU power loss",
            tier: ReleaseTier::Full,
            surfaces: "manual",
            action: Action::Check,
        },
    ]
}

fn scenario_tier(name: &str, backend: FaultBackend, status: FaultScenarioStatus) -> ReleaseTier {
    if matches!(name, "pod-kill-one" | "pod-graceful-restart-one") {
        return ReleaseTier::Smoke;
    }
    if name == "clock-skew" {
        return ReleaseTier::Standard;
    }
    if !status.is_executable()
        || matches!(
            backend,
            FaultBackend::DeviceMapper | FaultBackend::PlannedReliabilityWorkflow
        )
        || matches!(
            name,
            "warp-under-chaos"
                | "io-latency"
                | "io-read-mistake"
                | "quorum-p-io-fault"
                | "quorum-p-plus-one-io-fault"
                | "node-crash-proxy"
        )
    {
        return ReleaseTier::Full;
    }
    ReleaseTier::Standard
}

fn scenario_surfaces(backend: FaultBackend, status: FaultScenarioStatus) -> &'static str {
    if !status.is_executable() {
        return "manual";
    }
    match backend {
        FaultBackend::DeviceMapper => "manual",
        FaultBackend::ChaosMeshIoChaos | FaultBackend::MinioWarpWithChaos => "ci-amd64",
        _ => "ci-amd64,mac-mini-arm64",
    }
}

fn preliminary_skip(
    id: &str,
    action: Action,
    request: &ReleaseGateRequest,
) -> Option<&'static str> {
    match action {
        Action::Protocol if request.dry_run => Some("SKIP-dry-run"),
        Action::Protocol if !request.cluster => Some("SKIP-no-cluster"),
        Action::Protocol => None,
        Action::Check if id == "physical-power" => Some("DEFERRED-physical-power"),
        Action::Check => None,
    }
}

fn fault_skip(name: &str, request: &ReleaseGateRequest) -> Option<&'static str> {
    let spec = scenarios::scenario_catalog()
        .iter()
        .find(|spec| spec.scenario == name)?;
    if spec.scenario == "clock-skew" {
        return Some("SKIP-timechaos");
    }
    if !spec.status.is_executable() {
        return Some("SKIP-planned");
    }
    if matches!(
        spec.backend,
        FaultBackend::ChaosMeshIoChaos | FaultBackend::MinioWarpWithChaos
    ) && !request.toda_usable
    {
        return Some("SKIP-toda-arm64");
    }
    if spec.backend == FaultBackend::DeviceMapper && !request.device_mapper {
        return Some("SKIP-no-dm");
    }
    if request.dry_run {
        return Some("SKIP-dry-run");
    }
    if !request.cluster {
        return Some("SKIP-no-cluster");
    }
    None
}

fn skip_is_passing(reason: &str, request: &ReleaseGateRequest) -> bool {
    let code = reason.split(':').next().unwrap_or(reason).trim();
    match code {
        "SKIP-dry-run" => request.dry_run,
        "SKIP-toda-arm64" => !request.toda_usable,
        "SKIP-no-dm" => !request.device_mapper,
        "DEFERRED-physical-power"
        | "SKIP-planned"
        | "SKIP-timechaos"
        | "SKIP-no-artifact"
        | "SKIP-no-baseline"
        | "SKIP-no-otool"
        | "SKIP-no-mc"
        | "SKIP-no-unzip"
        | "SKIP-no-privileged" => true,
        "SKIP-no-prev-version" => request.prev_version.is_none(),
        "SKIP-no-cluster" => request.dry_run,
        _ => false,
    }
}

#[derive(Clone, Copy)]
enum DynTool {
    Ldd,
    Otool,
}

fn non_system_dynamic_deps(tool: DynTool, output: &str) -> Vec<String> {
    match tool {
        DynTool::Ldd => ldd_foreign(output),
        DynTool::Otool => otool_foreign(output),
    }
}

fn ldd_foreign(output: &str) -> Vec<String> {
    let lower = output.to_ascii_lowercase();
    if lower.contains("not a dynamic executable") || lower.contains("statically linked") {
        return Vec::new();
    }
    let mut foreign = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("linux-vdso") || line.contains("ld-linux") {
            continue;
        }
        let path = line
            .split("=>")
            .nth(1)
            .map(str::trim)
            .unwrap_or(line)
            .split_whitespace()
            .next()
            .unwrap_or(line);
        if path == "not" {
            continue;
        }
        if is_linux_system_path(path) {
            continue;
        }
        foreign.push(path.to_string());
    }
    foreign
}

fn otool_foreign(output: &str) -> Vec<String> {
    let mut foreign = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.ends_with(':') {
            continue;
        }
        let path = line.split_whitespace().next().unwrap_or(line);
        if path.starts_with("/usr/lib/")
            || path.starts_with("/System/Library/")
            || path.starts_with("@rpath/")
            || path.starts_with("@executable_path/")
            || path.starts_with("@loader_path/")
        {
            continue;
        }
        foreign.push(path.to_string());
    }
    foreign
}

fn is_linux_system_path(path: &str) -> bool {
    path.starts_with("/lib/")
        || path.starts_with("/lib64/")
        || path.starts_with("/usr/lib/")
        || path.starts_with("/usr/lib64/")
}

pub fn version_matches_tag(output: &str, tag: &str) -> bool {
    let tag = tag.trim().trim_start_matches('v');
    if tag.is_empty() {
        return false;
    }
    output
        .split(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '.' | '_' | '+' | '-'))
        .any(|token| token.trim_start_matches('v') == tag)
}

pub fn parse_git_sha(output: &str) -> Option<String> {
    output
        .split_whitespace()
        .find(|token| {
            let token = token.trim_matches(|ch: char| !ch.is_ascii_hexdigit());
            (7..=40).contains(&token.len()) && token.chars().all(|ch| ch.is_ascii_hexdigit())
        })
        .map(|token| {
            token
                .trim_matches(|ch: char| !ch.is_ascii_hexdigit())
                .to_string()
        })
}

pub fn parse_sha256sums(text: &str) -> Result<Vec<(String, String)>> {
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let (hash, name) = line.split_once(' ').context(format!(
            "SHA256SUMS line {} is missing a separator",
            index + 1
        ))?;
        let name = name.trim().trim_start_matches('*').trim();
        if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
            bail!("SHA256SUMS line {} has no sha256", index + 1);
        }
        if name.is_empty() || name.contains('/') || name.contains("..") {
            bail!("SHA256SUMS line {} has an unsafe file name", index + 1);
        }
        rows.push((hash.to_ascii_lowercase(), name.to_string()));
    }
    if rows.is_empty() {
        bail!("SHA256SUMS is empty");
    }
    Ok(rows)
}

pub fn warp_regressed(current_ops: f64, baseline_ops: f64, threshold_percent: f64) -> Result<bool> {
    ensure_percent(threshold_percent)?;
    if !current_ops.is_finite()
        || !baseline_ops.is_finite()
        || baseline_ops <= 0.0
        || current_ops < 0.0
    {
        bail!("warp ops/s must be finite and the baseline must be positive");
    }
    Ok(current_ops < baseline_ops * (1.0 - threshold_percent / 100.0))
}

#[derive(Debug, Clone, Deserialize)]
struct QuorumSurvivor {
    name: String,
    cold_bucket: bool,
    get_ok: u64,
    get_attempted: u64,
    wrong_sha256: u64,
    put_rejected: u64,
    put_attempted: u64,
    health_live: u16,
    health_ready: u16,
}

fn classify_quorum_edge_file(text: &str) -> Outcome {
    let survivors = match serde_json::from_str::<QuorumFile>(text) {
        Ok(parsed) => parsed.survivors,
        Err(error) => {
            return Outcome {
                status: CaseStatus::Fail,
                reason: format!("quorum-edge evidence is not the expected JSON: {error}"),
            };
        }
    };
    let mut reasons = Vec::new();
    if survivors.len() < 2 {
        reasons.push("expected a probe of each survivor, got fewer than 2".to_string());
    }
    if !survivors.iter().any(|survivor| survivor.cold_bucket) {
        reasons.push("no survivor was marked as a cold metadata bucket".to_string());
    }
    for survivor in &survivors {
        if survivor.get_attempted == 0
            || survivor.get_ok != survivor.get_attempted
            || survivor.wrong_sha256 != 0
        {
            reasons.push(format!(
                "{} cold-or-warm GET {}/{} wrong_sha256 {}",
                survivor.name, survivor.get_ok, survivor.get_attempted, survivor.wrong_sha256
            ));
        }
        if survivor.put_attempted == 0 || survivor.put_rejected != survivor.put_attempted {
            reasons.push(format!(
                "{} writes were not all rejected ({}/{})",
                survivor.name, survivor.put_rejected, survivor.put_attempted
            ));
        }
        if survivor.health_live != 200 {
            reasons.push(format!(
                "{} /health/live={}",
                survivor.name, survivor.health_live
            ));
        }
        if survivor.health_ready != 200 {
            reasons.push(format!(
                "{} /health/ready={} (readiness removed the survivor from a Kubernetes Service)",
                survivor.name, survivor.health_ready
            ));
        }
    }
    if reasons.is_empty() {
        Outcome {
            status: CaseStatus::Pass,
            reason: "every survivor served the cold bucket, rejected writes, and stayed ready"
                .to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: reasons.join("; "),
        }
    }
}

#[derive(serde::Deserialize)]
struct QuorumFile {
    survivors: Vec<QuorumSurvivor>,
}

fn classify_large_get_file(text: &str) -> Outcome {
    let parsed = match serde_json::from_str::<LargeGet>(text) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Outcome {
                status: CaseStatus::Fail,
                reason: format!("large-object evidence is not the expected JSON: {error}"),
            };
        }
    };
    if parsed.actual_len != parsed.expected_len || parsed.actual_sha256 != parsed.expected_sha256 {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!(
                "large GET truncated or corrupt: len {}/{} sha256 {} vs {}",
                parsed.actual_len,
                parsed.expected_len,
                parsed.actual_sha256,
                parsed.expected_sha256
            ),
        }
    } else if parsed.expected_len < 8 * 1024 * 1024 {
        Outcome {
            status: CaseStatus::Fail,
            reason: "large GET must cover at least 8 MiB".to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Pass,
            reason: format!("large GET {} bytes matched sha256", parsed.actual_len),
        }
    }
}

#[derive(serde::Deserialize)]
struct LargeGet {
    expected_len: u64,
    actual_len: u64,
    expected_sha256: String,
    actual_sha256: String,
}

fn classify_upgrade_file(text: &str, rollback: bool) -> Outcome {
    let parsed = match serde_json::from_str::<UpgradeEvidence>(text) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Outcome {
                status: CaseStatus::Fail,
                reason: format!("upgrade evidence is not the expected JSON: {error}"),
            };
        }
    };
    let mut reasons = Vec::new();
    if !parsed.objects_match {
        reasons.push("objects".to_string());
    }
    if !parsed.multipart_match {
        reasons.push("multipart".to_string());
    }
    if !parsed.versions_match {
        reasons.push("versions".to_string());
    }
    if !parsed.lifecycle_match {
        reasons.push("lifecycle".to_string());
    }
    if !parsed.policy_match {
        reasons.push("bucket policy".to_string());
    }
    if parsed.client_errors > parsed.error_threshold {
        reasons.push(format!(
            "client errors {} exceeded {}",
            parsed.client_errors, parsed.error_threshold
        ));
    }
    if rollback && parsed.rolled_back != Some(true) {
        reasons.push("rollback did not complete".to_string());
    }
    if reasons.is_empty() {
        Outcome {
            status: CaseStatus::Pass,
            reason: "dataset, metadata, and config survived".to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!("upgrade mismatch: {}", reasons.join(", ")),
        }
    }
}

#[derive(serde::Deserialize)]
struct UpgradeEvidence {
    objects_match: bool,
    multipart_match: bool,
    versions_match: bool,
    lifecycle_match: bool,
    policy_match: bool,
    client_errors: u64,
    error_threshold: u64,
    rolled_back: Option<bool>,
}

fn classify_warp_file(text: &str, threshold: f64) -> Outcome {
    let parsed = match serde_json::from_str::<WarpCompare>(text) {
        Ok(parsed) => parsed,
        Err(error) => {
            return Outcome {
                status: CaseStatus::Fail,
                reason: format!("warp evidence is not the expected JSON: {error}"),
            };
        }
    };
    match warp_regressed(parsed.current_ops, parsed.baseline_ops, threshold) {
        Ok(false) => Outcome {
            status: CaseStatus::Pass,
            reason: format!(
                "current {:.3} ops/s is within {threshold}% of baseline {:.3}",
                parsed.current_ops, parsed.baseline_ops
            ),
        },
        Ok(true) => Outcome {
            status: CaseStatus::Fail,
            reason: format!(
                "current {:.3} ops/s regressed more than {threshold}% from baseline {:.3}",
                parsed.current_ops, parsed.baseline_ops
            ),
        },
        Err(error) => Outcome {
            status: CaseStatus::Fail,
            reason: format!("{error:#}"),
        },
    }
}

#[derive(serde::Deserialize)]
struct WarpCompare {
    current_ops: f64,
    baseline_ops: f64,
}

fn classify_lifecycle_file(text: &str) -> Outcome {
    flag_file(
        text,
        &["rule_accepted", "listed_enabled", "get_matches"],
        "lifecycle rule was accepted and reads back",
    )
}

fn classify_expand_file(text: &str) -> Outcome {
    let parsed = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(parsed) => parsed,
        Err(error) => return bad_json(error),
    };
    let before = parsed.get("pools_before").and_then(|value| value.as_u64());
    let after = parsed.get("pools_after").and_then(|value| value.as_u64());
    let integrity = parsed.get("integrity_ok").and_then(|value| value.as_bool()) == Some(true);
    if matches!((before, after), (Some(before), Some(after)) if after > before) && integrity {
        Outcome {
            status: CaseStatus::Pass,
            reason: format!("pools grew from {before:?} to {after:?} and object integrity held"),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: "expand must increase the pool count and keep object integrity".to_string(),
        }
    }
}

fn classify_decommission_file(text: &str) -> Outcome {
    let parsed = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(parsed) => parsed,
        Err(error) => return bad_json(error),
    };
    if parsed.get("complete").and_then(|value| value.as_bool()) == Some(true)
        && parsed.get("integrity_ok").and_then(|value| value.as_bool()) != Some(false)
    {
        Outcome {
            status: CaseStatus::Pass,
            reason: "decommission reported complete:true".to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: "decommission did not reach complete:true".to_string(),
        }
    }
}

fn classify_rebalance_file(text: &str) -> Outcome {
    flag_file(
        text,
        &["stopped", "integrity_ok"],
        "rebalance stopped with object integrity",
    )
}

fn classify_disk_fill_file(text: &str) -> Outcome {
    flag_file(
        text,
        &["enospc_observed", "reads_ok", "recovered"],
        "filling the volume returned ENOSPC, reads survived, and the volume recovered",
    )
}

fn classify_remount_file(text: &str) -> Outcome {
    flag_file(
        text,
        &["remounted_ro", "writes_rejected", "reads_ok", "restored"],
        "the volume was remounted read-only and then restored",
    )
}

fn classify_dm_error_file(text: &str) -> Outcome {
    flag_file(
        text,
        &["table_has_error_target", "reads_survived", "recovered"],
        "dm-error was injected and the volume recovered",
    )
}

fn classify_fresh_install(text: &str) -> Outcome {
    let parsed = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(parsed) => parsed,
        Err(error) => return bad_json(error),
    };
    let health = parsed.get("health").and_then(|value| value.as_u64());
    let live = parsed.get("live").and_then(|value| value.as_u64());
    if health == Some(200) && live == Some(200) {
        Outcome {
            status: CaseStatus::Pass,
            reason: "fresh install /health and /health/live returned 200".to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!("fresh install health={health:?} live={live:?}"),
        }
    }
}

fn flag_file(text: &str, keys: &[&str], pass_reason: &str) -> Outcome {
    let parsed = match serde_json::from_str::<serde_json::Value>(text) {
        Ok(parsed) => parsed,
        Err(error) => return bad_json(error),
    };
    let missing = keys
        .iter()
        .filter(|key| parsed.get(**key).and_then(|value| value.as_bool()) != Some(true))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Outcome {
            status: CaseStatus::Pass,
            reason: pass_reason.to_string(),
        }
    } else {
        Outcome {
            status: CaseStatus::Fail,
            reason: format!("missing or false: {}", missing.join(", ")),
        }
    }
}

fn bad_json(error: serde_json::Error) -> Outcome {
    Outcome {
        status: CaseStatus::Fail,
        reason: format!("evidence JSON could not be parsed: {error}"),
    }
}

fn evaluate_checksums(artifact_dir: &Path) -> Result<Vec<ChecksumRow>> {
    let sums_path = artifact_dir.join("SHA256SUMS");
    if !sums_path.is_file() {
        return Ok(Vec::new());
    }
    let text =
        fs::read_to_string(&sums_path).with_context(|| format!("read {}", sums_path.display()))?;
    let mut rows = Vec::new();
    for (expected, name) in parse_sha256sums(&text)? {
        let path = artifact_dir.join(&name);
        if !path.is_file() {
            continue;
        }
        let actual = sha256_file(&path)?;
        rows.push(ChecksumRow {
            name,
            matches: actual == expected,
            expected_sha256: expected,
            actual_sha256: actual,
        });
    }
    Ok(rows)
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(hex::encode(hasher.finalize()))
}

async fn fetch_release_assets(tag: &str, dest: &Path) -> Result<Option<String>> {
    let client = reqwest::Client::builder()
        .user_agent("s3chaos-release-gate")
        .timeout(Duration::from_secs(180))
        .build()
        .context("build release-gate HTTP client")?;
    let api = format!("https://api.github.com/repos/rustfs/rustfs/releases/tags/{tag}");
    let response = client
        .get(&api)
        .send()
        .await
        .with_context(|| format!("GET {api}"))?;
    let status = response.status();
    let release = response
        .json::<serde_json::Value>()
        .await
        .context("decode GitHub release JSON")?;
    if !status.is_success() {
        bail!("GitHub release {tag} returned {status}: {release}");
    }
    let assets = release
        .get("assets")
        .and_then(|value| value.as_array())
        .context("release JSON has no assets")?;
    let sha = release
        .get("target_commitish")
        .and_then(|value| value.as_str())
        .filter(|value| {
            (7..=40).contains(&value.len()) && value.chars().all(|ch| ch.is_ascii_hexdigit())
        })
        .map(str::to_string);
    for asset in assets {
        let name = asset
            .get("name")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let url = asset
            .get("browser_download_url")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if !want_asset(name) || !trusted_release_url(url) {
            continue;
        }
        let path = release_asset_path(dest, name)?;
        let bytes = client
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {url}"))?
            .error_for_status()
            .with_context(|| format!("download {name}"))?
            .bytes()
            .await
            .with_context(|| format!("read {name}"))?;
        fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
    }
    Ok(sha)
}

fn want_asset(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "sha256sums" || lower.contains("linux") || lower.ends_with(".txt")
}

fn trusted_release_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://github.com/rustfs/rustfs/releases/download/") else {
        return false;
    };
    !rest.is_empty()
        && !rest
            .chars()
            .any(|ch| matches!(ch, ' ' | '\n' | '\r' | '\\' | '@'))
}

fn release_asset_path(dest: &Path, name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name == "."
        || name == ".."
    {
        bail!("release asset name {name:?} is not a single file name");
    }
    let path = dest.join(name);
    if path.parent() != Some(dest) {
        bail!("release asset name {name:?} escapes the artifact directory");
    }
    Ok(path)
}

fn read_optional(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn validate_release_tag(tag: &str) -> Result<()> {
    if tag.len() > 128
        || !tag
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '+' | '-'))
    {
        bail!("RUSTFS_VERSION {tag:?} is not a release tag");
    }
    Ok(())
}

fn optional_tag(env: &BTreeMap<String, String>, name: &str) -> Result<Option<String>> {
    let Some(value) = env
        .get(name)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    validate_release_tag(value)?;
    Ok(Some(value.to_string()))
}

fn bool_value(value: Option<&String>, default: bool) -> Result<bool> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" | "" => Ok(false),
        other => bail!("expected a boolean, got {other}"),
    }
}

fn ensure_percent(value: f64) -> Result<()> {
    if value.is_finite() && (0.0..=100.0).contains(&value) {
        Ok(())
    } else {
        bail!("regression percent must be between 0 and 100")
    }
}

fn sanitize_token(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(tier: &str, dry_run: bool) -> ReleaseGateRequest {
        let mut env = BTreeMap::new();
        env.insert("RUSTFS_VERSION".to_string(), "1.0.1-preview.11".to_string());
        env.insert("RELEASE_GATE_TIER".to_string(), tier.to_string());
        env.insert(
            "RELEASE_GATE_DRY_RUN".to_string(),
            if dry_run { "1" } else { "0" }.to_string(),
        );
        env.insert(
            "RUSTFS_RELEASE_GATE_ARCH".to_string(),
            "aarch64".to_string(),
        );
        ReleaseGateRequest::from_map(&env).expect("request")
    }

    #[test]
    fn arm64_full_dry_run_skips_toda_dm_and_power_explicitly() {
        let mut request = request("full", true);
        request.toda_usable = false;
        request.device_mapper = false;
        let report = plan_release_gate(&request);
        let reason = |id: &str| {
            report
                .cases
                .iter()
                .find(|case| case.id == id)
                .unwrap_or_else(|| panic!("missing {id}"))
                .reason
                .clone()
        };
        assert!(
            reason("fault:io-eio").starts_with("SKIP-toda-arm64"),
            "{}",
            reason("fault:io-eio")
        );
        assert!(reason("fault:disk-full").starts_with("SKIP-toda-arm64"));
        assert!(reason("fault:dm-flakey").starts_with("SKIP-no-dm"));
        assert!(reason("fault:clock-skew").starts_with("SKIP-timechaos"));
        assert!(reason("physical-power").starts_with("DEFERRED-physical-power"));
        assert!(reason("fault:pod-kill-one").starts_with("SKIP-dry-run"));
        assert!(reason("fault:admin-decommission").starts_with("SKIP-planned"));
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "quorum-edge-cold-read")
        );
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "large-object-get-integrity")
        );
        assert!(report.cases.iter().any(|case| case.id == "disk-full-fill"));
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "volume-remount-ro")
        );
    }

    #[test]
    fn live_run_without_a_cluster_fails_the_gate() {
        let mut request = request("smoke", false);
        request.cluster = false;
        request.toda_usable = true;
        let mut report = plan_release_gate(&request);
        execute_pending(&mut report, &request).expect("execute");
        finalize_verdict(&mut report);
        assert_eq!(report.verdict, "fail");
        let kill = report
            .cases
            .iter()
            .find(|case| case.id == "fault:pod-kill-one")
            .expect("pod-kill");
        assert!(kill.reason.starts_with("SKIP-no-cluster"));
        assert!(kill.counts_as_failure);
    }

    #[test]
    fn dry_run_without_artifacts_is_a_plan_pass() {
        let dir = tempfile::tempdir().expect("temp");
        let mut request = request("full", true);
        request.artifact_dir = dir.path().to_path_buf();
        request.output_dir = dir.path().join("out");
        let mut report = plan_release_gate(&request);
        execute_pending(&mut report, &request).expect("execute");
        finalize_verdict(&mut report);
        assert_eq!(
            report.verdict,
            "pass",
            "{:?}",
            report
                .cases
                .iter()
                .filter(|case| case.counts_as_failure)
                .collect::<Vec<_>>()
        );
        let checksums = report
            .cases
            .iter()
            .find(|case| case.id == "post-fault-checksums")
            .expect("checksum row");
        assert!(
            checksums.reason.starts_with("SKIP-dry-run"),
            "{}",
            checksums.reason
        );
    }

    #[test]
    fn release_assets_stay_inside_the_artifact_directory() {
        let dir = tempfile::tempdir().expect("temp");
        assert!(release_asset_path(dir.path(), "../SHA256SUMS").is_err());
        assert!(release_asset_path(dir.path(), "/tmp/linux.txt").is_err());
        assert!(trusted_release_url(
            "https://github.com/rustfs/rustfs/releases/download/v1/SHA256SUMS"
        ));
        assert!(!trusted_release_url("https://example.com/SHA256SUMS"));
    }

    #[test]
    fn live_cluster_without_fresh_install_evidence_fails() {
        let dir = tempfile::tempdir().expect("temp");
        let mut request = request("smoke", false);
        request.cluster = true;
        request.artifact_dir = dir.path().to_path_buf();
        let outcome = fresh_install_outcome(&request);
        assert_eq!(outcome.status, CaseStatus::Fail);
        let expand = execute_case("expand-pools", &request, &[], None);
        assert_eq!(expand.status, CaseStatus::Fail, "{}", expand.reason);
        request.device_mapper = false;
        let dm = execute_case("dm-error", &request, &[], None);
        assert!(dm.reason.starts_with("SKIP-no-dm"), "{}", dm.reason);
    }

    #[test]
    fn preview11_cold_survivor_is_a_regression_failure() {
        let text = r#"{
            "survivors": [
                {"name":"n3","cold_bucket":false,"get_ok":600,"get_attempted":600,"wrong_sha256":0,"put_rejected":20,"put_attempted":20,"health_live":200,"health_ready":503},
                {"name":"n4","cold_bucket":true,"get_ok":0,"get_attempted":600,"wrong_sha256":0,"put_rejected":20,"put_attempted":20,"health_live":200,"health_ready":503}
            ]
        }"#;
        let outcome = classify_quorum_edge_file(text);
        assert_eq!(outcome.status, CaseStatus::Fail);
        assert!(outcome.reason.contains("n4"), "{}", outcome.reason);
        assert!(
            outcome.reason.contains("/health/ready"),
            "{}",
            outcome.reason
        );
    }

    #[test]
    fn healthy_quorum_edge_probe_passes() {
        let text = r#"{
            "survivors": [
                {"name":"n3","cold_bucket":false,"get_ok":30,"get_attempted":30,"wrong_sha256":0,"put_rejected":4,"put_attempted":4,"health_live":200,"health_ready":200},
                {"name":"n4","cold_bucket":true,"get_ok":30,"get_attempted":30,"wrong_sha256":0,"put_rejected":4,"put_attempted":4,"health_live":200,"health_ready":200}
            ]
        }"#;
        assert_eq!(classify_quorum_edge_file(text).status, CaseStatus::Pass);
    }

    #[test]
    fn truncated_large_get_fails_and_full_body_passes() {
        let truncated = r#"{"expected_len":8388608,"actual_len":4096,"expected_sha256":"abc","actual_sha256":"abc"}"#;
        assert_eq!(classify_large_get_file(truncated).status, CaseStatus::Fail);
        let ok = r#"{"expected_len":8388608,"actual_len":8388608,"expected_sha256":"abc","actual_sha256":"abc"}"#;
        assert_eq!(classify_large_get_file(ok).status, CaseStatus::Pass);
    }

    #[test]
    fn homebrew_xz_is_a_non_system_dependency() {
        let otool = "rustfs:\n\t/opt/homebrew/opt/xz/lib/liblzma.5.dylib (compatibility version 13.0.0, current version 13.2.0)\n\t/usr/lib/libSystem.B.dylib\n";
        let foreign = non_system_dynamic_deps(DynTool::Otool, otool);
        assert_eq!(
            foreign,
            vec!["/opt/homebrew/opt/xz/lib/liblzma.5.dylib".to_string()]
        );
        let ldd = "\tlinux-vdso.so.1 (0x0000)\n\tlibc.so.6 => /lib/aarch64-linux-gnu/libc.so.6 (0x0000)\n\t/lib/ld-linux-aarch64.so.1 (0x0000)\n";
        assert!(non_system_dynamic_deps(DynTool::Ldd, ldd).is_empty());
    }

    #[test]
    fn checksums_and_version_match_the_published_tag() {
        let sums = parse_sha256sums(
            "25c76639c7e3e9490f5c849680d7e9bb0c14bf2c7be6a9bed6fcd2307db7b2bf  rustfs-macos-aarch64.zip\n",
        )
        .expect("sums");
        assert_eq!(sums[0].1, "rustfs-macos-aarch64.zip");
        assert!(version_matches_tag(
            "rustfs 1.0.1-preview.11\nbuild macos-aarch64\ngit commit 0913686b12845eefc69a2f4ed4ee6a8161e25742\n",
            "1.0.1-preview.11"
        ));
        assert!(!version_matches_tag("rustfs @df64242", "1.0.1-preview.11"));
        assert!(!version_matches_tag("rustfs 1.0.1-preview.11", "1"));
        assert_eq!(
            parse_git_sha("git commit 0913686b12845eefc69a2f4ed4ee6a8161e25742"),
            Some("0913686b12845eefc69a2f4ed4ee6a8161e25742".to_string())
        );
    }

    #[test]
    fn warp_regression_uses_the_threshold() {
        assert!(!warp_regressed(90.0, 100.0, 20.0).expect("compare"));
        assert!(warp_regressed(70.0, 100.0, 20.0).expect("compare"));
    }

    #[test]
    fn decommission_requires_complete_true() {
        assert_eq!(
            classify_decommission_file(r#"{"complete":false,"integrity_ok":true}"#).status,
            CaseStatus::Fail
        );
        assert_eq!(
            classify_decommission_file(r#"{"complete":true,"integrity_ok":true}"#).status,
            CaseStatus::Pass
        );
    }

    #[test]
    fn upgrade_evidence_rejects_a_metadata_miss_and_a_noisy_client() {
        let bad = r#"{"objects_match":true,"multipart_match":true,"versions_match":false,"lifecycle_match":true,"policy_match":true,"client_errors":0,"error_threshold":5,"rolled_back":true}"#;
        assert_eq!(classify_upgrade_file(bad, true).status, CaseStatus::Fail);
        let ok = r#"{"objects_match":true,"multipart_match":true,"versions_match":true,"lifecycle_match":true,"policy_match":true,"client_errors":1,"error_threshold":5,"rolled_back":true}"#;
        assert_eq!(classify_upgrade_file(ok, true).status, CaseStatus::Pass);
    }

    #[test]
    fn smoke_tier_does_not_include_device_mapper() {
        let report = plan_release_gate(&request("smoke", true));
        assert!(report.cases.iter().all(|case| case.id != "fault:dm-flakey"));
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "fault:pod-kill-one")
        );
        assert!(
            report
                .cases
                .iter()
                .any(|case| case.id == "release-artifact-dynamic-deps")
        );
    }
}
