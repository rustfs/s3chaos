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

use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use time::{Date, macros::format_description};

const API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
const PROFILE_KIND: &str = "MintProfile";
const INVENTORY_KIND: &str = "MintInventory";
const KNOWN_FAILURES_KIND: &str = "MintKnownFailures";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintMode {
    Core,
    Full,
}

impl FromStr for MintMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "core" => Ok(Self::Core),
            "full" => Ok(Self::Full),
            _ => bail!("unsupported Mint mode {value:?}; expected core or full"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintProfile {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub name: String,
    pub image: String,
    pub platform: String,
    pub mode: MintMode,
    pub suites: Vec<String>,
    pub region: String,
    pub target_fingerprint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintProfileSpec {
    pub name: String,
    pub image: String,
    pub platform: String,
    pub mode: MintMode,
    pub suites: Vec<String>,
    pub region: String,
    pub target_fingerprint: String,
}

impl MintProfile {
    pub fn new(spec: MintProfileSpec) -> Result<Self> {
        let profile = Self {
            api_version: API_VERSION.to_string(),
            kind: PROFILE_KIND.to_string(),
            name: spec.name,
            image: spec.image,
            platform: spec.platform,
            mode: spec.mode,
            suites: spec.suites,
            region: spec.region,
            target_fingerprint: spec.target_fingerprint,
        };
        validate_profile(&profile)?;
        Ok(profile)
    }

    pub fn from_yaml(raw: &str) -> Result<Self> {
        let profile = serde_yaml_ng::from_str(raw).context("parse Mint profile")?;
        validate_profile(&profile)?;
        Ok(profile)
    }

    pub fn image_digest(&self) -> Result<&str> {
        let (repository, digest) = self
            .image
            .rsplit_once('@')
            .context("Mint profile image must include an immutable digest")?;
        ensure_nonempty("Mint image repository", repository)?;
        validate_sha256("Mint image digest", digest)?;
        Ok(digest)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintFunctionInventory {
    pub suite: String,
    pub function: String,
    pub allow_na: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintInventory {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub image_digest: String,
    pub platform: String,
    pub mode: MintMode,
    pub suites: Vec<String>,
    pub functions: Vec<MintFunctionInventory>,
}

impl MintInventory {
    pub fn from_yaml(raw: &str) -> Result<Self> {
        let inventory = serde_yaml_ng::from_str(raw).context("parse Mint inventory")?;
        validate_inventory(&inventory)?;
        Ok(inventory)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintKnownFailure {
    pub suite: String,
    pub function: String,
    pub reason: String,
    pub owner: String,
    pub issue: String,
    pub introduced_at: String,
    pub review_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintKnownFailures {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub image_digest: String,
    pub platform: String,
    pub mode: MintMode,
    pub suites: Vec<String>,
    pub entries: Vec<MintKnownFailure>,
}

impl MintKnownFailures {
    pub fn from_yaml(raw: &str) -> Result<Self> {
        let known_failures = serde_yaml_ng::from_str(raw).context("parse Mint known failures")?;
        validate_known_failures(&known_failures)?;
        Ok(known_failures)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintLogStatus {
    #[serde(rename = "PASS")]
    Passed,
    #[serde(rename = "FAIL")]
    Failed,
    #[serde(rename = "NA")]
    NotApplicable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintLogRecord {
    pub suite: String,
    pub function: String,
    pub status: MintLogStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintLogParseFailure {
    pub document_index: usize,
    pub byte_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintLogParseResult {
    pub records: Vec<MintLogRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure: Option<MintLogParseFailure>,
}

#[derive(Debug, Deserialize)]
struct RawMintLogRecord {
    name: String,
    function: String,
    status: MintLogStatus,
}

pub fn parse_mint_log(raw: &[u8]) -> MintLogParseResult {
    let mut stream = serde_json::Deserializer::from_slice(raw).into_iter::<RawMintLogRecord>();
    let mut records = Vec::new();
    let mut failure = None;

    while let Some(item) = stream.next() {
        let document_index = records.len();
        match item {
            Ok(record) if !record.name.trim().is_empty() && !record.function.trim().is_empty() => {
                records.push(MintLogRecord {
                    suite: record.name,
                    function: record.function,
                    status: record.status,
                });
            }
            Ok(_) | Err(_) => {
                failure = Some(MintLogParseFailure {
                    document_index,
                    byte_offset: stream.byte_offset(),
                });
                break;
            }
        }
    }

    MintLogParseResult { records, failure }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintInfrastructureFailure {
    ContainerStart,
    Network,
    ContainerRuntime,
    LogCollection,
}

#[derive(Debug, Clone, Copy)]
pub struct MintRunObservation<'a> {
    pub container_started: bool,
    pub exit_code: Option<i32>,
    pub log: Option<&'a [u8]>,
    pub infrastructure_failure: Option<MintInfrastructureFailure>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintExecutionStatus {
    Complete,
    Incomplete,
    InfrastructureFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintCompatibilityStatus {
    Passed,
    Failed,
    KnownFailed,
    NotEvaluated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintGateStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintFunctionStatus {
    Passed,
    Failed,
    KnownFailed,
    NotApplicable,
    NotRun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintKnownFailureReference {
    pub reason: String,
    pub owner: String,
    pub issue: String,
    pub introduced_at: String,
    pub review_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintFunctionResult {
    pub suite: String,
    pub function: String,
    pub status: MintFunctionStatus,
    pub observed_count: usize,
    pub passed_count: usize,
    pub failed_count: usize,
    pub not_applicable_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub known_failure: Option<MintKnownFailureReference>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MintResultCounts {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub known_failed: usize,
    pub not_applicable: usize,
    pub not_run: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MintDiagnosticCode {
    BaselineDrift,
    BaselineExpired,
    BaselineNotActive,
    ContainerStartFailed,
    ContainerRuntimeFailed,
    ExitCodeMissing,
    LogCollectionFailed,
    LogEmpty,
    LogMissing,
    LogParseFailed,
    MissingFunction,
    NetworkUnreachable,
    NonzeroExitWithoutFailure,
    UnexpectedFailure,
    UnexpectedFunction,
    UnexpectedNotApplicable,
    ZeroExitWithFailure,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintDiagnostic {
    pub code: MintDiagnosticCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suite: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
}

impl MintDiagnostic {
    fn run(code: MintDiagnosticCode) -> Self {
        Self {
            code,
            suite: None,
            function: None,
        }
    }

    fn function(code: MintDiagnosticCode, key: &MintFunctionKey) -> Self {
        Self {
            code,
            suite: Some(key.suite.clone()),
            function: Some(key.function.clone()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MintEvaluation {
    pub profile: MintProfile,
    pub execution_status: MintExecutionStatus,
    pub compatibility_status: MintCompatibilityStatus,
    pub gate_status: MintGateStatus,
    pub counts: MintResultCounts,
    pub results: Vec<MintFunctionResult>,
    pub diagnostics: Vec<MintDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct MintFunctionKey {
    suite: String,
    function: String,
}

impl MintFunctionKey {
    fn new(suite: &str, function: &str) -> Self {
        Self {
            suite: suite.to_string(),
            function: function.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct ObservedCounts {
    passed: usize,
    failed: usize,
    not_applicable: usize,
}

impl ObservedCounts {
    fn total(self) -> usize {
        self.passed + self.failed + self.not_applicable
    }
}

pub fn evaluate_mint_run(
    profile: &MintProfile,
    inventory: &MintInventory,
    known_failures: &MintKnownFailures,
    observation: MintRunObservation<'_>,
    evaluation_date: &str,
) -> Result<MintEvaluation> {
    validate_contract(profile, inventory, known_failures)?;
    let evaluation_date = parse_date(evaluation_date, "evaluation date")?;
    let mut diagnostics = Vec::new();
    let mut infrastructure_failed = false;
    let mut incomplete = false;

    if !observation.container_started {
        diagnostics.push(MintDiagnostic::run(
            MintDiagnosticCode::ContainerStartFailed,
        ));
        infrastructure_failed = true;
    }
    if observation.exit_code.is_none() {
        diagnostics.push(MintDiagnostic::run(MintDiagnosticCode::ExitCodeMissing));
        infrastructure_failed = true;
    }
    if let Some(failure) = observation.infrastructure_failure {
        diagnostics.push(MintDiagnostic::run(match failure {
            MintInfrastructureFailure::ContainerStart => MintDiagnosticCode::ContainerStartFailed,
            MintInfrastructureFailure::Network => MintDiagnosticCode::NetworkUnreachable,
            MintInfrastructureFailure::ContainerRuntime => {
                MintDiagnosticCode::ContainerRuntimeFailed
            }
            MintInfrastructureFailure::LogCollection => MintDiagnosticCode::LogCollectionFailed,
        }));
        infrastructure_failed = true;
    }

    let parsed = match observation.log {
        Some(raw) => {
            let parsed = parse_mint_log(raw);
            if raw.iter().all(u8::is_ascii_whitespace) {
                diagnostics.push(MintDiagnostic::run(MintDiagnosticCode::LogEmpty));
                infrastructure_failed = true;
            }
            if parsed.failure.is_some() {
                diagnostics.push(MintDiagnostic::run(MintDiagnosticCode::LogParseFailed));
                infrastructure_failed = true;
            }
            parsed
        }
        None => {
            diagnostics.push(MintDiagnostic::run(MintDiagnosticCode::LogMissing));
            infrastructure_failed = true;
            MintLogParseResult {
                records: Vec::new(),
                failure: None,
            }
        }
    };

    let inventory_by_key = inventory
        .functions
        .iter()
        .map(|function| {
            (
                MintFunctionKey::new(&function.suite, &function.function),
                function,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let known_by_key = known_failures
        .entries
        .iter()
        .map(|entry| (MintFunctionKey::new(&entry.suite, &entry.function), entry))
        .collect::<BTreeMap<_, _>>();
    let mut observed_by_key = BTreeMap::<MintFunctionKey, ObservedCounts>::new();
    let mut unknown_failed = false;

    for record in &parsed.records {
        let key = MintFunctionKey::new(&record.suite, &record.function);
        let counts = observed_by_key.entry(key.clone()).or_default();
        match record.status {
            MintLogStatus::Passed => counts.passed += 1,
            MintLogStatus::Failed => counts.failed += 1,
            MintLogStatus::NotApplicable => counts.not_applicable += 1,
        }
        if !inventory_by_key.contains_key(&key) {
            diagnostics.push(MintDiagnostic::function(
                MintDiagnosticCode::UnexpectedFunction,
                &key,
            ));
            incomplete = true;
            unknown_failed |= record.status == MintLogStatus::Failed;
        }
    }

    let mut results = Vec::with_capacity(inventory.functions.len());
    let mut has_pass = false;
    let mut has_known_failure = false;
    let mut has_unexpected_failure = unknown_failed;

    for function in &inventory.functions {
        let key = MintFunctionKey::new(&function.suite, &function.function);
        let observed = observed_by_key.get(&key).copied().unwrap_or_default();
        let known_failure = known_by_key.get(&key).copied();
        if observed.not_applicable > 0 && !function.allow_na {
            diagnostics.push(MintDiagnostic::function(
                MintDiagnosticCode::UnexpectedNotApplicable,
                &key,
            ));
            incomplete = true;
        }
        let status = if observed.failed > 0 {
            if known_failure.is_some() {
                has_known_failure = true;
                MintFunctionStatus::KnownFailed
            } else {
                diagnostics.push(MintDiagnostic::function(
                    MintDiagnosticCode::UnexpectedFailure,
                    &key,
                ));
                has_unexpected_failure = true;
                MintFunctionStatus::Failed
            }
        } else if observed.passed > 0 {
            has_pass = true;
            MintFunctionStatus::Passed
        } else if observed.not_applicable > 0 {
            MintFunctionStatus::NotApplicable
        } else {
            diagnostics.push(MintDiagnostic::function(
                MintDiagnosticCode::MissingFunction,
                &key,
            ));
            incomplete = true;
            MintFunctionStatus::NotRun
        };

        results.push(MintFunctionResult {
            suite: function.suite.clone(),
            function: function.function.clone(),
            status,
            observed_count: observed.total(),
            passed_count: observed.passed,
            failed_count: observed.failed,
            not_applicable_count: observed.not_applicable,
            known_failure: known_failure.map(known_failure_reference),
        });
    }

    for (key, entry) in &known_by_key {
        let introduced_at = parse_date(&entry.introduced_at, "known failure introducedAt")?;
        let review_by = parse_date(&entry.review_by, "known failure reviewBy")?;
        if evaluation_date < introduced_at {
            diagnostics.push(MintDiagnostic::function(
                MintDiagnosticCode::BaselineNotActive,
                key,
            ));
        }
        if evaluation_date > review_by {
            diagnostics.push(MintDiagnostic::function(
                MintDiagnosticCode::BaselineExpired,
                key,
            ));
        }
        if observed_by_key
            .get(key)
            .is_none_or(|counts| counts.failed == 0)
        {
            diagnostics.push(MintDiagnostic::function(
                MintDiagnosticCode::BaselineDrift,
                key,
            ));
        }
    }

    let any_observed_failure = has_known_failure || has_unexpected_failure;
    match observation.exit_code {
        Some(0) if any_observed_failure => {
            diagnostics.push(MintDiagnostic::run(MintDiagnosticCode::ZeroExitWithFailure));
            infrastructure_failed = true;
        }
        Some(code) if code != 0 && !any_observed_failure => {
            diagnostics.push(MintDiagnostic::run(
                MintDiagnosticCode::NonzeroExitWithoutFailure,
            ));
            infrastructure_failed = true;
        }
        _ => {}
    }

    let mut seen_diagnostics = BTreeSet::new();
    diagnostics.retain(|diagnostic| {
        seen_diagnostics.insert((
            diagnostic.code,
            diagnostic.suite.clone(),
            diagnostic.function.clone(),
        ))
    });

    let execution_status = if infrastructure_failed {
        MintExecutionStatus::InfrastructureFailed
    } else if incomplete {
        MintExecutionStatus::Incomplete
    } else {
        MintExecutionStatus::Complete
    };
    let compatibility_status = if has_unexpected_failure {
        MintCompatibilityStatus::Failed
    } else if has_known_failure {
        MintCompatibilityStatus::KnownFailed
    } else if has_pass {
        MintCompatibilityStatus::Passed
    } else {
        MintCompatibilityStatus::NotEvaluated
    };
    let gate_status = if execution_status == MintExecutionStatus::Complete
        && !has_unexpected_failure
        && diagnostics.is_empty()
    {
        MintGateStatus::Passed
    } else {
        MintGateStatus::Failed
    };
    let counts = count_results(&results);

    Ok(MintEvaluation {
        profile: profile.clone(),
        execution_status,
        compatibility_status,
        gate_status,
        counts,
        results,
        diagnostics,
    })
}

fn known_failure_reference(entry: &MintKnownFailure) -> MintKnownFailureReference {
    MintKnownFailureReference {
        reason: entry.reason.clone(),
        owner: entry.owner.clone(),
        issue: entry.issue.clone(),
        introduced_at: entry.introduced_at.clone(),
        review_by: entry.review_by.clone(),
    }
}

fn count_results(results: &[MintFunctionResult]) -> MintResultCounts {
    let mut counts = MintResultCounts {
        total: results.len(),
        ..MintResultCounts::default()
    };
    for result in results {
        match result.status {
            MintFunctionStatus::Passed => counts.passed += 1,
            MintFunctionStatus::Failed => counts.failed += 1,
            MintFunctionStatus::KnownFailed => counts.known_failed += 1,
            MintFunctionStatus::NotApplicable => counts.not_applicable += 1,
            MintFunctionStatus::NotRun => counts.not_run += 1,
        }
    }
    counts
}

fn validate_contract(
    profile: &MintProfile,
    inventory: &MintInventory,
    known_failures: &MintKnownFailures,
) -> Result<()> {
    validate_profile(profile)?;
    validate_inventory(inventory)?;
    validate_known_failures(known_failures)?;
    ensure!(
        inventory.image_digest == profile.image_digest()?,
        "Mint inventory image digest does not match profile"
    );
    ensure!(
        inventory.platform == profile.platform,
        "Mint inventory platform does not match profile"
    );
    ensure!(
        inventory.mode == profile.mode,
        "Mint inventory mode does not match profile"
    );
    ensure!(
        exact_set(&inventory.suites) == exact_set(&profile.suites),
        "Mint inventory suite set does not match profile"
    );
    ensure!(
        known_failures.image_digest == inventory.image_digest,
        "Mint known-failure image digest does not match inventory"
    );
    ensure!(
        known_failures.platform == inventory.platform,
        "Mint known-failure platform does not match inventory"
    );
    ensure!(
        known_failures.mode == inventory.mode,
        "Mint known-failure mode does not match inventory"
    );
    ensure!(
        exact_set(&known_failures.suites) == exact_set(&inventory.suites),
        "Mint known-failure suite set does not match inventory"
    );

    let inventory_keys = inventory
        .functions
        .iter()
        .map(|entry| MintFunctionKey::new(&entry.suite, &entry.function))
        .collect::<BTreeSet<_>>();
    for entry in &known_failures.entries {
        let key = MintFunctionKey::new(&entry.suite, &entry.function);
        ensure!(
            inventory_keys.contains(&key),
            "Mint known failure {}/{} is absent from inventory",
            entry.suite,
            entry.function
        );
    }
    Ok(())
}

fn validate_profile(profile: &MintProfile) -> Result<()> {
    validate_header(&profile.api_version, &profile.kind, PROFILE_KIND)?;
    ensure_nonempty("Mint profile name", &profile.name)?;
    profile.image_digest()?;
    ensure_nonempty("Mint platform", &profile.platform)?;
    validate_suites(&profile.suites)?;
    ensure_nonempty("Mint region", &profile.region)?;
    validate_sha256("Mint target fingerprint", &profile.target_fingerprint)?;
    Ok(())
}

fn validate_inventory(inventory: &MintInventory) -> Result<()> {
    validate_header(&inventory.api_version, &inventory.kind, INVENTORY_KIND)?;
    validate_sha256("Mint inventory image digest", &inventory.image_digest)?;
    ensure_nonempty("Mint inventory platform", &inventory.platform)?;
    validate_suites(&inventory.suites)?;
    ensure!(
        !inventory.functions.is_empty(),
        "Mint inventory must contain at least one function"
    );
    let suites = exact_set(&inventory.suites);
    let mut keys = BTreeSet::new();
    let mut function_suites = BTreeSet::new();
    for function in &inventory.functions {
        validate_exact_key(&function.suite, &function.function)?;
        ensure!(
            suites.contains(&function.suite),
            "Mint inventory function {}/{} references an undeclared suite",
            function.suite,
            function.function
        );
        ensure!(
            keys.insert(MintFunctionKey::new(&function.suite, &function.function)),
            "duplicate Mint inventory function {}/{}",
            function.suite,
            function.function
        );
        function_suites.insert(function.suite.as_str());
    }
    for suite in &inventory.suites {
        ensure!(
            function_suites.contains(suite.as_str()),
            "Mint inventory suite {suite} has no functions"
        );
    }
    Ok(())
}

fn validate_known_failures(known_failures: &MintKnownFailures) -> Result<()> {
    validate_header(
        &known_failures.api_version,
        &known_failures.kind,
        KNOWN_FAILURES_KIND,
    )?;
    validate_sha256(
        "Mint known-failure image digest",
        &known_failures.image_digest,
    )?;
    ensure_nonempty("Mint known-failure platform", &known_failures.platform)?;
    validate_suites(&known_failures.suites)?;
    let suites = exact_set(&known_failures.suites);
    let mut keys = BTreeSet::new();
    for entry in &known_failures.entries {
        validate_exact_key(&entry.suite, &entry.function)?;
        ensure!(
            suites.contains(&entry.suite),
            "Mint known failure {}/{} references an undeclared suite",
            entry.suite,
            entry.function
        );
        ensure!(
            keys.insert(MintFunctionKey::new(&entry.suite, &entry.function)),
            "duplicate Mint known failure {}/{}",
            entry.suite,
            entry.function
        );
        ensure_nonempty("Mint known-failure reason", &entry.reason)?;
        ensure_nonempty("Mint known-failure owner", &entry.owner)?;
        ensure_nonempty("Mint known-failure issue", &entry.issue)?;
        let introduced_at = parse_date(&entry.introduced_at, "known failure introducedAt")?;
        let review_by = parse_date(&entry.review_by, "known failure reviewBy")?;
        ensure!(
            introduced_at <= review_by,
            "Mint known-failure introducedAt must not be after reviewBy"
        );
    }
    Ok(())
}

fn validate_header(api_version: &str, kind: &str, expected_kind: &str) -> Result<()> {
    ensure!(
        api_version == API_VERSION && kind == expected_kind,
        "invalid Mint {expected_kind} contract"
    );
    Ok(())
}

fn validate_suites(suites: &[String]) -> Result<()> {
    ensure!(!suites.is_empty(), "Mint suite set must not be empty");
    let mut unique = BTreeSet::new();
    for suite in suites {
        ensure_nonempty("Mint suite", suite)?;
        ensure!(
            !suite.contains('*') && !suite.contains('?'),
            "Mint suites must be exact names, not patterns"
        );
        ensure!(unique.insert(suite), "duplicate Mint suite {suite}");
    }
    Ok(())
}

fn validate_exact_key(suite: &str, function: &str) -> Result<()> {
    ensure_nonempty("Mint function suite", suite)?;
    ensure_nonempty("Mint function", function)?;
    ensure!(
        !suite.contains('*')
            && !suite.contains('?')
            && !function.contains('*')
            && !function.contains('?'),
        "Mint suite/function keys must be exact names, not patterns"
    );
    Ok(())
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .with_context(|| format!("{label} must use sha256"))?;
    ensure!(
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must contain 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    Ok(())
}

fn exact_set(values: &[String]) -> BTreeSet<&String> {
    values.iter().collect()
}

fn parse_date(value: &str, label: &str) -> Result<Date> {
    Date::parse(value, format_description!("[year]-[month]-[day]"))
        .with_context(|| format!("parse {label} {value:?} as YYYY-MM-DD"))
}

mod artifacts;
mod session;
mod target;

pub use artifacts::{
    MINT_ARTIFACT_VALIDATION_FILE, MintArtifactPublication, MintCapturedRun,
    validate_mint_artifacts_and_write_report, write_mint_artifacts,
};
pub use session::{
    MINT_SESSION_VALIDATION_FILE, MintSessionPublication, MintSessionRequest,
    MintSessionValidationReport, cleanup_mint_session, mint_reproduction_request, run_mint_session,
    validate_mint_session_artifacts_and_write_report,
};
pub use target::{
    MintTargetDiscovery, MintTargetSpec, MintTargetTimeouts, discover_mint_target, timestamp_now,
    verify_mint_target,
};

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:08a05e68893c68be2a83b6f79556853ed6aa3c6c9e64c823a00853e4e55d2200";
    const FINGERPRINT: &str =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn profile() -> MintProfile {
        MintProfile {
            api_version: API_VERSION.to_string(),
            kind: PROFILE_KIND.to_string(),
            name: "mint-core".to_string(),
            image: format!("minio/mint:edge@{DIGEST}"),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["minio-go".to_string()],
            region: "us-east-1".to_string(),
            target_fingerprint: FINGERPRINT.to_string(),
        }
    }

    fn inventory() -> MintInventory {
        MintInventory {
            api_version: API_VERSION.to_string(),
            kind: INVENTORY_KIND.to_string(),
            image_digest: DIGEST.to_string(),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["minio-go".to_string()],
            functions: vec![
                MintFunctionInventory {
                    suite: "minio-go".to_string(),
                    function: "make-bucket".to_string(),
                    allow_na: false,
                },
                MintFunctionInventory {
                    suite: "minio-go".to_string(),
                    function: "object-lock".to_string(),
                    allow_na: true,
                },
            ],
        }
    }

    fn known_failures(entries: Vec<MintKnownFailure>) -> MintKnownFailures {
        MintKnownFailures {
            api_version: API_VERSION.to_string(),
            kind: KNOWN_FAILURES_KIND.to_string(),
            image_digest: DIGEST.to_string(),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["minio-go".to_string()],
            entries,
        }
    }

    fn known(function: &str, review_by: &str) -> MintKnownFailure {
        MintKnownFailure {
            suite: "minio-go".to_string(),
            function: function.to_string(),
            reason: "tracked RustFS difference".to_string(),
            owner: "protocol".to_string(),
            issue: "https://github.com/rustfs/rustfs/issues/1".to_string(),
            introduced_at: "2026-01-01".to_string(),
            review_by: review_by.to_string(),
        }
    }

    #[test]
    fn repository_default_contract_is_exact_and_evaluable() {
        let inventory = MintInventory::from_yaml(include_str!(
            "../../protocol/mint/aws-sdk-php-core-inventory.yaml"
        ))
        .expect("repository inventory");
        let known_failures = MintKnownFailures::from_yaml(include_str!(
            "../../protocol/mint/aws-sdk-php-core-known-failures.yaml"
        ))
        .expect("repository known failures");
        let profile = MintProfile::new(MintProfileSpec {
            name: "rustfs-mint-core".to_string(),
            image: format!("minio/mint:edge@{DIGEST}"),
            platform: "linux/amd64".to_string(),
            mode: MintMode::Core,
            suites: vec!["aws-sdk-php".to_string()],
            region: "us-east-1".to_string(),
            target_fingerprint: FINGERPRINT.to_string(),
        })
        .expect("profile");
        let mut log = Vec::new();
        for function in &inventory.functions {
            serde_json::to_writer(
                &mut log,
                &serde_json::json!({
                    "name": function.suite,
                    "function": function.function,
                    "status": "PASS"
                }),
            )
            .expect("log record");
            log.push(b'\n');
        }

        let evaluation = evaluate_mint_run(
            &profile,
            &inventory,
            &known_failures,
            observation(Some(&log), Some(0)),
            "2026-08-24",
        )
        .expect("evaluate default contract");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Complete);
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::Passed
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Passed);
        assert_eq!(evaluation.counts.total, 13);
    }

    fn observation(log: Option<&[u8]>, exit_code: Option<i32>) -> MintRunObservation<'_> {
        MintRunObservation {
            container_started: true,
            exit_code,
            log,
            infrastructure_failure: None,
        }
    }

    #[test]
    fn parses_concatenated_documents_and_ignores_upstream_extensions() {
        let parsed = parse_mint_log(
            br#"{"name":"minio-go","function":"make-bucket","status":"PASS","duration":12}
{"name":"minio-go","function":"object-lock","status":"NA","args":{"region":"us-east-1"}}"#,
        );

        assert_eq!(parsed.failure, None);
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[0].status, MintLogStatus::Passed);
        assert_eq!(parsed.records[1].status, MintLogStatus::NotApplicable);
    }

    #[test]
    fn malformed_tail_preserves_valid_records_and_fails_execution() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"PASS"}
{"name":"minio-go","function":"object-lock","status":}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(
            evaluation.execution_status,
            MintExecutionStatus::InfrastructureFailed
        );
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::Passed
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
        assert!(
            evaluation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == MintDiagnosticCode::LogParseFailed)
        );
    }

    #[test]
    fn active_exact_known_failure_is_visible_and_allows_gate() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"FAIL"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(vec![known("make-bucket", "2026-12-31")]),
            observation(Some(log), Some(1)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Complete);
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::KnownFailed
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Passed);
        assert_eq!(evaluation.counts.known_failed, 1);
        assert_eq!(evaluation.counts.not_applicable, 1);
        assert!(evaluation.diagnostics.is_empty());
    }

    #[test]
    fn unexpected_failure_blocks_gate() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"FAIL"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(1)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Complete);
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::Failed
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
        assert_eq!(evaluation.counts.failed, 1);
    }

    #[test]
    fn missing_log_is_infrastructure_failure_and_not_evaluated() {
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(None, Some(1)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(
            evaluation.execution_status,
            MintExecutionStatus::InfrastructureFailed
        );
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::NotEvaluated
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
        assert_eq!(evaluation.counts.not_run, 2);
    }

    #[test]
    fn missing_required_function_is_incomplete() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"PASS"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Incomplete);
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::Passed
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
        assert_eq!(evaluation.counts.not_run, 1);
    }

    #[test]
    fn expired_and_stale_baseline_blocks_gate() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"PASS"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(vec![known("make-bucket", "2026-06-30")]),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Complete);
        assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
        assert!(
            evaluation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == MintDiagnosticCode::BaselineExpired)
        );
        assert!(
            evaluation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == MintDiagnosticCode::BaselineDrift)
        );
    }

    #[test]
    fn nonzero_exit_without_valid_failure_is_infrastructure_failure() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"PASS"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(1)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(
            evaluation.execution_status,
            MintExecutionStatus::InfrastructureFailed
        );
        assert!(evaluation.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == MintDiagnosticCode::NonzeroExitWithoutFailure
        }));
    }

    #[test]
    fn zero_exit_with_failure_is_infrastructure_failure() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"FAIL"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(
            evaluation.execution_status,
            MintExecutionStatus::InfrastructureFailed
        );
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::Failed
        );
        assert!(
            evaluation
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == MintDiagnosticCode::ZeroExitWithFailure)
        );
    }

    #[test]
    fn unexpected_na_makes_execution_incomplete() {
        let log = br#"{"name":"minio-go","function":"make-bucket","status":"NA"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Incomplete);
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::NotEvaluated
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
        assert!(
            evaluation.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == MintDiagnosticCode::UnexpectedNotApplicable
            })
        );
    }

    #[test]
    fn disallowed_na_cannot_be_masked_by_pass_or_known_failure() {
        let passed_log = br#"{"name":"minio-go","function":"make-bucket","status":"PASS"}
{"name":"minio-go","function":"make-bucket","status":"NA"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let passed = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(passed_log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate pass and NA");

        let known_failed_log = br#"{"name":"minio-go","function":"make-bucket","status":"FAIL"}
{"name":"minio-go","function":"make-bucket","status":"NA"}
{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let known_failed = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(vec![known("make-bucket", "2026-12-31")]),
            observation(Some(known_failed_log), Some(1)),
            "2026-08-23",
        )
        .expect("evaluate known failure and NA");

        for evaluation in [passed, known_failed] {
            assert_eq!(evaluation.execution_status, MintExecutionStatus::Incomplete);
            assert_eq!(evaluation.gate_status, MintGateStatus::Failed);
            assert!(evaluation.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == MintDiagnosticCode::UnexpectedNotApplicable
            }));
        }
    }

    #[test]
    fn allowed_na_can_complete_without_claiming_compatibility_pass() {
        let mut inventory = inventory();
        inventory.functions.remove(0);
        let log = br#"{"name":"minio-go","function":"object-lock","status":"NA"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory,
            &known_failures(Vec::new()),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(evaluation.execution_status, MintExecutionStatus::Complete);
        assert_eq!(
            evaluation.compatibility_status,
            MintCompatibilityStatus::NotEvaluated
        );
        assert_eq!(evaluation.gate_status, MintGateStatus::Passed);
    }

    #[test]
    fn contract_rejects_digest_suite_and_wildcard_drift() {
        let mut wrong_inventory = inventory();
        wrong_inventory.image_digest =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        assert!(
            evaluate_mint_run(
                &profile(),
                &wrong_inventory,
                &known_failures(Vec::new()),
                observation(None, None),
                "2026-08-23"
            )
            .is_err()
        );

        let mut wrong_baseline = known_failures(vec![known("make-*", "2026-12-31")]);
        wrong_baseline.suites = vec!["minio-go".to_string()];
        assert!(
            MintKnownFailures::from_yaml(&serde_yaml_ng::to_string(&wrong_baseline).unwrap())
                .is_err()
        );

        let uppercase_digest = DIGEST
            .to_ascii_uppercase()
            .replacen("SHA256:", "sha256:", 1);
        let mut uppercase_profile = profile();
        uppercase_profile.image = format!("minio/mint:edge@{uppercase_digest}");
        assert!(
            evaluate_mint_run(
                &uppercase_profile,
                &inventory(),
                &known_failures(Vec::new()),
                observation(None, None),
                "2026-08-23"
            )
            .is_err()
        );
    }

    #[test]
    fn inventory_requires_a_function_for_every_declared_suite() {
        let mut incomplete_inventory = inventory();
        incomplete_inventory.suites.push("awscli".to_string());

        let error = MintInventory::from_yaml(
            &serde_yaml_ng::to_string(&incomplete_inventory).expect("serialize inventory"),
        )
        .expect_err("suite without functions must fail");
        assert!(error.to_string().contains("suite awscli has no functions"));
    }

    #[test]
    fn repeated_unknown_function_produces_one_drift_diagnostic() {
        let log = br#"{"name":"minio-go","function":"new-function","status":"PASS"}
{"name":"minio-go","function":"new-function","status":"PASS"}"#;
        let evaluation = evaluate_mint_run(
            &profile(),
            &inventory(),
            &known_failures(Vec::new()),
            observation(Some(log), Some(0)),
            "2026-08-23",
        )
        .expect("evaluate");

        assert_eq!(
            evaluation
                .diagnostics
                .iter()
                .filter(|diagnostic| { diagnostic.code == MintDiagnosticCode::UnexpectedFunction })
                .count(),
            1
        );
    }

    #[test]
    fn yaml_profile_requires_pinned_image_and_target_fingerprint() {
        let yaml = format!(
            r#"apiVersion: {API_VERSION}
kind: {PROFILE_KIND}
name: mint-core
image: minio/mint:edge@{DIGEST}
platform: linux/amd64
mode: core
suites: [minio-go]
region: us-east-1
targetFingerprint: {FINGERPRINT}
"#
        );
        let parsed = MintProfile::from_yaml(&yaml).expect("profile");
        assert_eq!(parsed.image_digest().expect("digest"), DIGEST);

        let unpinned = yaml.replace(&format!("minio/mint:edge@{DIGEST}"), "minio/mint:edge");
        assert!(MintProfile::from_yaml(&unpinned).is_err());

        let mut unvalidated = profile();
        unvalidated.image = "minio/mint:edge".to_string();
        assert!(unvalidated.image_digest().is_err());
    }
}
