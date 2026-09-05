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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use crate::fault::{
    plan::FaultInjectionParameters,
    reporting::{FailureClassification, FailureSeverity, ResponsibilityDomain},
    scenarios::{FaultDetectorContract, FaultScenarioStatus, scenario_spec},
    workload::{WorkloadHotspot, WorkloadOperationMix, WorkloadPayloadDistribution},
};

pub const FAULT_SUITE_API_VERSION: &str = "rustfs.com/s3chaos/v1alpha1";
pub const FAULT_SUITE_KIND: &str = "FaultSuite";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultSuite {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: FaultSuiteMetadata,
    #[serde(default)]
    pub budgets: FaultSuiteBudgets,
    #[serde(
        rename = "workloadProfiles",
        default,
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub workload_profiles: BTreeMap<String, FaultSuiteWorkloadOverride>,
    #[serde(default)]
    pub scenarios: Vec<FaultSuiteScenario>,
    #[serde(default)]
    pub observability: FaultSuiteObservability,
    #[serde(default)]
    pub artifacts: FaultSuiteArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FaultSuiteMetadata {
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultSuiteBudgets {
    #[serde(default = "default_stop_on_first_failure")]
    pub stop_on_first_failure: bool,
    #[serde(default = "default_continue_on_severities")]
    pub continue_on_severities: Vec<FailureSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_stable_window_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultSuiteScenario {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<FaultInjectionParameters>,
    #[serde(default = "default_repetitions")]
    pub repetitions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault_duration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<FaultSuiteWorkloadOverride>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_failure: Option<FaultExpectedFailure>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultExpectedFailure {
    pub classification: FailureClassification,
    pub severity: FailureSeverity,
    pub responsibility_domain: ResponsibilityDomain,
    pub evidence_refs: Vec<FaultExpectedEvidenceRef>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum FaultExpectedEvidenceRef {
    #[serde(rename = "recovery-stability-report.json")]
    RecoveryStabilityReport,
    #[serde(rename = "checker-pre-recommit-report.json")]
    CheckerPreRecommitReport,
    #[serde(rename = "checker-report.json")]
    CheckerReport,
    #[serde(rename = "fault-evidence.json")]
    FaultEvidence,
    #[serde(rename = "run-events.jsonl")]
    RunEvents,
}

impl FaultExpectedEvidenceRef {
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::RecoveryStabilityReport => "recovery-stability-report.json",
            Self::CheckerPreRecommitReport => "checker-pre-recommit-report.json",
            Self::CheckerReport => "checker-report.json",
            Self::FaultEvidence => "fault-evidence.json",
            Self::RunEvents => "run-events.jsonl",
        }
    }
}

impl FaultExpectedFailure {
    pub(crate) fn validate(&self, scenario: &str) -> Result<()> {
        ensure!(
            self.classification.is_s3_model(),
            "scenario {scenario} expectedFailure.classification must be a product S3-model classification, got {}",
            self.classification.as_str()
        );
        ensure!(
            self.severity == self.classification.severity(),
            "scenario {scenario} expectedFailure.severity {:?} does not match classification {} severity {:?}",
            self.severity,
            self.classification.as_str(),
            self.classification.severity()
        );
        ensure!(
            self.responsibility_domain == self.classification.responsibility_domain(),
            "scenario {scenario} expectedFailure.responsibilityDomain {:?} does not match classification {} responsibility {:?}",
            self.responsibility_domain,
            self.classification.as_str(),
            self.classification.responsibility_domain()
        );
        ensure!(
            !self.evidence_refs.is_empty(),
            "scenario {scenario} expectedFailure.evidenceRefs must not be empty"
        );
        let unique = self.evidence_refs.iter().copied().collect::<BTreeSet<_>>();
        ensure!(
            unique.len() == self.evidence_refs.len(),
            "scenario {scenario} expectedFailure.evidenceRefs contains duplicates"
        );
        let final_checker = unique.contains(&FaultExpectedEvidenceRef::CheckerReport);
        let recovery = unique.contains(&FaultExpectedEvidenceRef::RecoveryStabilityReport)
            || unique.contains(&FaultExpectedEvidenceRef::CheckerPreRecommitReport);
        ensure!(
            !(final_checker && recovery),
            "scenario {scenario} expectedFailure.evidenceRefs combines mutually exclusive checker stages"
        );
        ensure!(
            self.classification != FailureClassification::RecoveryTailReadLatency || !final_checker,
            "scenario {scenario} recovery_tail_read_latency requires pre-recommit recovery evidence"
        );
        Ok(())
    }

    pub(crate) fn validate_observed(
        &self,
        classification: &str,
        severity: FailureSeverity,
        responsibility_domain: Option<ResponsibilityDomain>,
        evidence_refs: &[String],
    ) -> Result<()> {
        ensure!(
            classification == self.classification.as_str(),
            "expected classification {}, observed {classification}",
            self.classification.as_str()
        );
        ensure!(
            severity == self.severity,
            "expected severity {:?}, observed {:?}",
            self.severity,
            severity
        );
        ensure!(
            responsibility_domain == Some(self.responsibility_domain),
            "expected responsibility {:?}, observed {:?}",
            self.responsibility_domain,
            responsibility_domain
        );
        ensure!(
            !evidence_refs.is_empty(),
            "expected failure has no primary evidence refs"
        );
        let observed = evidence_refs
            .iter()
            .filter_map(|reference| Path::new(reference).file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect::<BTreeSet<_>>();
        for expected in &self.evidence_refs {
            ensure!(
                observed.contains(expected.file_name()),
                "expected failure is missing primary evidence ref {}",
                expected.file_name()
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultSuiteWorkloadOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_weights: Option<WorkloadOperationMix>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_distribution: Option<WorkloadPayloadDistribution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hotspot: Option<WorkloadHotspot>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultSuiteObservability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chaos_dashboard: Option<FaultSuiteDashboardMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultSuiteDashboardMode {
    Disabled,
    Optional,
    Required,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultSuiteArtifacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<FaultSuiteArtifactMode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultSuiteArtifactMode {
    Default,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedFaultSuite {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub metadata: FaultSuiteMetadata,
    pub budgets: ResolvedFaultSuiteBudgets,
    #[serde(
        rename = "workloadProfiles",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub workload_profiles: BTreeMap<String, ResolvedFaultSuiteWorkloadOverride>,
    pub scenarios: Vec<ResolvedFaultSuiteScenario>,
    pub observability: FaultSuiteObservability,
    pub artifacts: FaultSuiteArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFaultSuiteBudgets {
    pub stop_on_first_failure: bool,
    pub continue_on_severities: Vec<FailureSeverity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_client_disruptions: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_stable_window_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFaultSuiteScenario {
    pub name: String,
    pub params: FaultInjectionParameters,
    pub repetitions: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault_duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload_profile: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<ResolvedFaultSuiteWorkloadOverride>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_failure: Option<FaultExpectedFailure>,
    pub priority: String,
    pub isolation: String,
    pub backend: String,
    pub impact_policy: String,
    pub requires_static_storage: bool,
    pub requires_chaos_mesh: bool,
    pub crds: Vec<String>,
    pub required_tools: Vec<String>,
    pub detector: FaultDetectorContract,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFaultSuiteWorkloadOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub concurrency: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation_weights: Option<WorkloadOperationMix>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_distribution: Option<WorkloadPayloadDistribution>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hotspot: Option<WorkloadHotspot>,
}

impl FaultSuite {
    pub fn from_yaml_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
        serde_yaml_ng::from_str(&raw)
            .with_context(|| format!("parse suite yaml {}", path.display()))
    }

    pub fn resolve(&self) -> Result<ResolvedFaultSuite> {
        self.validate_header()?;
        validate_resource_name(&self.metadata.name)?;

        ensure!(
            !self.scenarios.is_empty(),
            "FaultSuite {} must include at least one scenario",
            self.metadata.name
        );

        let budget_duration = self
            .budgets
            .max_duration
            .as_deref()
            .map(parse_duration_seconds)
            .transpose()?;
        let continue_on_severities =
            normalized_continue_on_severities(&self.budgets.continue_on_severities)?;
        if let Some(stable_window) = self.budgets.recovery_stable_window_seconds {
            ensure!(
                stable_window > 0,
                "budgets.recoveryStableWindowSeconds must be greater than zero"
            );
        }
        if matches!(
            self.observability.chaos_dashboard,
            Some(FaultSuiteDashboardMode::Required)
        ) {
            bail!(
                "observability.chaosDashboard=required is not implemented; install the dashboard separately and use optional or disabled"
            );
        }
        if matches!(
            self.artifacts.required,
            Some(FaultSuiteArtifactMode::Default)
        ) {
            bail!("artifacts.required=default is not implemented; omit it or use strict");
        }

        let workload_profiles = self
            .workload_profiles
            .iter()
            .map(|(name, workload)| {
                validate_workload_profile_name(name)?;
                Ok((
                    name.clone(),
                    ResolvedFaultSuiteWorkloadOverride::from_suite_workload(
                        &format!("workloadProfiles.{name}"),
                        workload,
                    )?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let scenarios = self
            .scenarios
            .iter()
            .map(|scenario| {
                ResolvedFaultSuiteScenario::from_suite_scenario(scenario, &workload_profiles)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(ResolvedFaultSuite {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            metadata: self.metadata.clone(),
            budgets: ResolvedFaultSuiteBudgets {
                stop_on_first_failure: self.budgets.stop_on_first_failure,
                continue_on_severities,
                max_duration_seconds: budget_duration,
                max_client_disruptions: self.budgets.max_client_disruptions,
                recovery_stable_window_seconds: self.budgets.recovery_stable_window_seconds,
            },
            workload_profiles,
            scenarios,
            observability: self.observability.clone(),
            artifacts: self.artifacts.clone(),
        })
    }

    fn validate_header(&self) -> Result<()> {
        ensure!(
            self.api_version == FAULT_SUITE_API_VERSION,
            "FaultSuite apiVersion {:?} does not match {FAULT_SUITE_API_VERSION}",
            self.api_version
        );
        ensure!(
            self.kind == FAULT_SUITE_KIND,
            "FaultSuite kind {:?} does not match {FAULT_SUITE_KIND}",
            self.kind
        );
        Ok(())
    }
}

impl ResolvedFaultSuite {
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }
}

impl ResolvedFaultSuiteWorkloadOverride {
    fn from_suite_workload(context: &str, workload: &FaultSuiteWorkloadOverride) -> Result<Self> {
        validate_workload_override(context, workload)?;
        Ok(Self {
            objects: workload.objects,
            concurrency: workload.concurrency,
            operation_weights: workload.operation_weights,
            payload_distribution: workload.payload_distribution.clone(),
            hotspot: workload.hotspot,
        })
    }
}

impl ResolvedFaultSuiteScenario {
    fn from_suite_scenario(
        scenario: &FaultSuiteScenario,
        workload_profiles: &BTreeMap<String, ResolvedFaultSuiteWorkloadOverride>,
    ) -> Result<Self> {
        let spec = scenario_spec(&scenario.name)?;
        ensure!(
            spec.status == FaultScenarioStatus::Executable,
            "scenario {} is not executable",
            scenario.name
        );
        ensure!(
            scenario.repetitions > 0,
            "scenario {} repetitions must be greater than zero",
            scenario.name
        );
        if let Some(percent) = scenario.percent {
            ensure!(
                (1..=100).contains(&percent),
                "scenario {} percent must be between 1 and 100",
                scenario.name
            );
            ensure!(
                spec.percent_supported,
                "scenario {} does not support percent override",
                scenario.name
            );
        }
        ensure!(
            scenario.workload_profile.is_none() || scenario.workload.is_none(),
            "scenario {} must not set both workloadProfile and workload",
            scenario.name
        );
        if let Some(expected_failure) = &scenario.expected_failure {
            expected_failure.validate(&scenario.name)?;
        }
        let params = scenario.params.clone().unwrap_or_default();
        if let Some(params) = &scenario.params {
            params.validate_explicit_for_schema(spec.param_schema)?;
        }
        let fault_duration_seconds = scenario
            .fault_duration
            .as_deref()
            .map(parse_duration_seconds)
            .transpose()?;
        let workload = if let Some(profile_name) = &scenario.workload_profile {
            validate_workload_profile_name(profile_name)?;
            Some(
                workload_profiles
                    .get(profile_name)
                    .cloned()
                    .with_context(|| {
                        format!(
                            "scenario {} workloadProfile {:?} does not match any workloadProfiles entry",
                            scenario.name, profile_name
                        )
                    })?,
            )
        } else {
            scenario
                .workload
                .as_ref()
                .map(|workload| {
                    ResolvedFaultSuiteWorkloadOverride::from_suite_workload(
                        &format!("scenario {} workload", scenario.name),
                        workload,
                    )
                })
                .transpose()?
        };

        Ok(Self {
            name: scenario.name.clone(),
            params,
            repetitions: scenario.repetitions,
            fault_duration_seconds,
            percent: scenario.percent,
            workload_profile: scenario.workload_profile.clone(),
            workload,
            expected_failure: scenario.expected_failure.clone(),
            priority: spec.priority.as_str().to_string(),
            isolation: spec.isolation.as_str().to_string(),
            backend: spec.backend.as_str().to_string(),
            impact_policy: spec.impact_policy.as_str().to_string(),
            requires_static_storage: spec.requires_static_storage(),
            requires_chaos_mesh: spec.requires_chaos_mesh(),
            crds: spec.crds.iter().map(|crd| (*crd).to_string()).collect(),
            required_tools: spec
                .required_tools
                .iter()
                .map(|tool| (*tool).to_string())
                .collect(),
            detector: spec.detector.contract(),
        })
    }
}

pub fn resolve_fault_suite_yaml(path: impl AsRef<Path>) -> Result<ResolvedFaultSuite> {
    FaultSuite::from_yaml_path(path)?.resolve()
}

pub fn fault_suite_template_yaml() -> String {
    r#"apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 2h
  stopOnFirstFailure: true
  continueOnSeverities:
    - degraded
  maxClientDisruptions: 20
  recoveryStableWindowSeconds: 60
observability:
  chaosDashboard: optional
artifacts:
  required: strict
workloadProfiles:
  smoke:
    objects: 40000
    concurrency: 80
    operationWeights:
      put: 1
      overwrite: 1
      get: 1
      list: 1
      delete: 1
      multipart: 1
    payloadDistribution:
      - sizeBytes: 4096
        weight: 85
      - sizeBytes: 16384
        weight: 10
      - sizeBytes: 8388608
        weight: 4
      - sizeBytes: 16777216
        weight: 1
    hotspot:
      objectPercent: 10
      operationPercent: 70
scenarios:
  - name: io-eio
    faultDuration: 10m
    percent: 20
    workloadProfile: smoke
  - name: network-delay
    faultDuration: 8m
    workloadProfile: smoke
    params:
      kind: networkDelay
      latency: 200ms
      jitter: 50ms
      correlationPercent: 25
"#
    .to_string()
}

fn validate_workload_override(context: &str, workload: &FaultSuiteWorkloadOverride) -> Result<()> {
    ensure!(
        workload_has_fields(
            workload.objects,
            workload.concurrency,
            workload.operation_weights,
            workload.payload_distribution.as_ref(),
            workload.hotspot,
        ),
        "{context} must set objects/concurrency, operationWeights, payloadDistribution, or hotspot"
    );
    validate_workload_fields(
        context,
        workload.objects,
        workload.concurrency,
        workload.operation_weights,
        workload.payload_distribution.as_ref(),
        workload.hotspot,
    )
}

fn validate_workload_fields(
    context: &str,
    objects: Option<usize>,
    concurrency: Option<usize>,
    operation_weights: Option<WorkloadOperationMix>,
    payload_distribution: Option<&WorkloadPayloadDistribution>,
    hotspot: Option<WorkloadHotspot>,
) -> Result<()> {
    ensure!(
        workload_has_fields(
            objects,
            concurrency,
            operation_weights,
            payload_distribution,
            hotspot,
        ),
        "{context} must set objects/concurrency, operationWeights, payloadDistribution, or hotspot"
    );
    if let Some(operation_weights) = operation_weights {
        operation_weights.validate()?;
    }
    if let Some(payload_distribution) = payload_distribution {
        payload_distribution.validate()?;
    }
    if let Some(hotspot) = hotspot {
        hotspot.validate()?;
    }
    match (objects, concurrency) {
        (Some(objects), Some(concurrency)) => {
            ensure!(objects >= 12, "{context}.objects must be at least 12");
            ensure!(
                concurrency > 0,
                "{context}.concurrency must be greater than zero"
            );
            ensure!(
                concurrency <= objects,
                "{context}.concurrency must be <= {context}.objects"
            );
            if let Some(operation_weights) = operation_weights {
                let mixed_count = objects - objects / 2;
                let total_weight = operation_weights.total_weight();
                ensure!(
                    mixed_count as u64 >= total_weight,
                    "{context}.operationWeights total {} requires at least that many mixed-workload objects, got {mixed_count}",
                    total_weight
                );
            }
        }
        (None, None) => {}
        _ => bail!("{context} must set both objects and concurrency"),
    }
    Ok(())
}

fn workload_has_fields(
    objects: Option<usize>,
    concurrency: Option<usize>,
    operation_weights: Option<WorkloadOperationMix>,
    payload_distribution: Option<&WorkloadPayloadDistribution>,
    hotspot: Option<WorkloadHotspot>,
) -> bool {
    objects.is_some()
        || concurrency.is_some()
        || operation_weights.is_some()
        || payload_distribution.is_some()
        || hotspot.is_some()
}

fn parse_duration_seconds(raw: &str) -> Result<u64> {
    let value = raw.trim();
    ensure!(!value.is_empty(), "duration must not be empty");
    let (digits, multiplier) = match value.chars().last().expect("non-empty") {
        's' | 'S' => (&value[..value.len() - 1], 1),
        'm' | 'M' => (&value[..value.len() - 1], 60),
        'h' | 'H' => (&value[..value.len() - 1], 60 * 60),
        ch if ch.is_ascii_digit() => (value, 1),
        _ => bail!("duration {value:?} must use seconds, m, or h"),
    };
    let amount = digits
        .parse::<u64>()
        .with_context(|| format!("parse duration {value:?}"))?;
    ensure!(amount > 0, "duration {value:?} must be greater than zero");
    amount
        .checked_mul(multiplier)
        .with_context(|| format!("duration {value:?} overflowed"))
}

fn validate_resource_name(name: &str) -> Result<()> {
    validate_identifier("FaultSuite metadata.name", name)
}

fn validate_workload_profile_name(name: &str) -> Result<()> {
    validate_identifier("workloadProfile name", name)
}

fn validate_identifier(context: &str, name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "{context} must not be empty");
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "{context} must contain lowercase ASCII letters, digits, or '-'"
    );
    ensure!(
        !name.starts_with('-') && !name.ends_with('-'),
        "{context} must not start or end with '-'"
    );
    Ok(())
}

fn default_stop_on_first_failure() -> bool {
    true
}

fn default_continue_on_severities() -> Vec<FailureSeverity> {
    vec![FailureSeverity::Degraded]
}

fn default_repetitions() -> usize {
    1
}

fn normalized_continue_on_severities(
    severities: &[FailureSeverity],
) -> Result<Vec<FailureSeverity>> {
    let mut normalized = Vec::new();
    for severity in severities {
        ensure!(
            !normalized.contains(severity),
            "budgets.continueOnSeverities contains duplicate severity {:?}",
            severity
        );
        normalized.push(*severity);
    }
    normalized.sort();
    Ok(normalized)
}

impl Default for FaultSuiteBudgets {
    fn default() -> Self {
        Self {
            stop_on_first_failure: true,
            continue_on_severities: default_continue_on_severities(),
            max_duration: None,
            max_client_disruptions: None,
            recovery_stable_window_seconds: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FaultExpectedEvidenceRef, FaultSuite, parse_duration_seconds};
    use crate::fault::{
        plan::FaultInjectionParameters,
        reporting::{FailureClassification, FailureSeverity, ResponsibilityDomain},
        scenarios::{
            ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO, DetectorQualification,
            QUORUM_P_IO_FAULT_SCENARIO,
        },
    };

    #[test]
    fn resolves_valid_fault_suite() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 2h
  stopOnFirstFailure: true
  maxClientDisruptions: 10
  recoveryStableWindowSeconds: 60
observability:
  chaosDashboard: optional
artifacts:
  required: strict
scenarios:
  - name: io-eio
    faultDuration: 10m
    percent: 20
    workload:
      objects: 64
      concurrency: 8
  - name: network-delay
    repetitions: 2
    params:
      kind: networkDelay
      latency: 350ms
      jitter: 25ms
      correlationPercent: 10
"#,
        )
        .expect("suite yaml");

        let resolved = suite.resolve().expect("resolved suite");

        assert_eq!(resolved.budgets.max_duration_seconds, Some(7200));
        assert_eq!(
            resolved.budgets.continue_on_severities,
            vec![FailureSeverity::Degraded]
        );
        assert_eq!(resolved.scenarios.len(), 2);
        assert_eq!(resolved.scenarios[0].fault_duration_seconds, Some(600));
        assert_eq!(resolved.scenarios[0].priority, "p0");
        assert_eq!(resolved.scenarios[1].repetitions, 2);
        assert_eq!(
            resolved.scenarios[1].params,
            FaultInjectionParameters::NetworkDelay {
                latency: "350ms".to_string(),
                jitter: "25ms".to_string(),
                correlation_percent: 10,
            }
        );
        assert!(resolved.scenarios[0].requires_chaos_mesh);
    }

    #[test]
    fn accepts_explicit_continue_on_severities() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  stopOnFirstFailure: true
  continueOnSeverities:
    - degraded
scenarios:
  - name: io-eio
"#,
        )
        .expect("suite yaml");

        let resolved = suite.resolve().expect("resolved suite");

        assert_eq!(
            resolved.budgets.continue_on_severities,
            vec![FailureSeverity::Degraded]
        );
    }

    #[test]
    fn resolves_typed_expected_failure_contract() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: vulnerable-mode-calibration
scenarios:
  - name: io-eio
    expectedFailure:
      classification: data_corruption
      severity: fail_correctness
      responsibilityDomain: product
      evidenceRefs:
        - checker-report.json
        - fault-evidence.json
        - run-events.jsonl
"#,
        )
        .expect("suite yaml")
        .resolve()
        .expect("resolved diagnostic suite");

        let scenario = &suite.scenarios[0];
        let expected = scenario
            .expected_failure
            .as_ref()
            .expect("expected failure");
        assert_eq!(
            expected.classification,
            FailureClassification::DataCorruption
        );
        assert_eq!(expected.severity, FailureSeverity::FailCorrectness);
        assert_eq!(
            expected.responsibility_domain,
            ResponsibilityDomain::Product
        );
        assert_eq!(
            expected.evidence_refs,
            vec![
                FaultExpectedEvidenceRef::CheckerReport,
                FaultExpectedEvidenceRef::FaultEvidence,
                FaultExpectedEvidenceRef::RunEvents,
            ]
        );
        assert_eq!(
            scenario.detector.qualification,
            DetectorQualification::GateCandidate
        );
    }

    #[test]
    fn rejects_expected_failure_with_unknown_classification() {
        let error = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: calibration
scenarios:
  - name: io-eio
    expectedFailure:
      classification: data_corrupton
      severity: fail_correctness
      responsibilityDomain: product
      evidenceRefs: [checker-report.json]
"#,
        )
        .expect_err("unknown typed classification");

        assert!(error.to_string().contains("data_corrupton"));
    }

    #[test]
    fn rejects_expected_failure_without_product_signal_or_evidence() {
        let no_signal = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: calibration
scenarios:
  - name: io-eio
    expectedFailure:
      classification: no_signal
      severity: needs_investigation
      responsibilityDomain: unknown
      evidenceRefs: [run-events.jsonl]
"#,
        )
        .expect("typed yaml")
        .resolve()
        .expect_err("no signal is not a detector hit");
        assert!(no_signal.to_string().contains("product S3-model"));

        let missing_evidence = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: calibration
scenarios:
  - name: io-eio
    expectedFailure:
      classification: data_corruption
      severity: fail_correctness
      responsibilityDomain: product
      evidenceRefs: []
"#,
        )
        .expect("typed yaml")
        .resolve()
        .expect_err("evidence is mandatory");
        assert!(missing_evidence.to_string().contains("must not be empty"));
    }

    #[test]
    fn rejects_expected_failure_inconsistent_with_classification() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: calibration
scenarios:
  - name: io-eio
    expectedFailure:
      classification: data_corruption
      severity: fail_availability
      responsibilityDomain: product
      evidenceRefs: [checker-report.json]
"#,
        )
        .expect("typed yaml");

        let error = suite.resolve().expect_err("mismatched severity");
        assert!(error.to_string().contains("does not match classification"));
    }

    #[test]
    fn rejects_expected_evidence_that_cannot_be_emitted_together() {
        for evidence_refs in [
            vec![
                FaultExpectedEvidenceRef::CheckerReport,
                FaultExpectedEvidenceRef::CheckerPreRecommitReport,
            ],
            vec![
                FaultExpectedEvidenceRef::CheckerReport,
                FaultExpectedEvidenceRef::RecoveryStabilityReport,
            ],
        ] {
            let expected = super::FaultExpectedFailure {
                classification: FailureClassification::DataCorruption,
                severity: FailureSeverity::FailCorrectness,
                responsibility_domain: ResponsibilityDomain::Product,
                evidence_refs,
            };
            assert!(
                expected
                    .validate("io-eio")
                    .unwrap_err()
                    .to_string()
                    .contains("mutually exclusive")
            );
        }
        let mut expected = super::FaultExpectedFailure {
            classification: FailureClassification::RecoveryTailReadLatency,
            severity: FailureSeverity::Degraded,
            responsibility_domain: ResponsibilityDomain::Product,
            evidence_refs: vec![FaultExpectedEvidenceRef::CheckerReport],
        };
        assert!(expected.validate("io-eio").is_err());
        expected.evidence_refs = vec![
            FaultExpectedEvidenceRef::CheckerPreRecommitReport,
            FaultExpectedEvidenceRef::RecoveryStabilityReport,
        ];
        expected
            .validate("io-eio")
            .expect("reachable recovery stage");
    }

    #[test]
    fn expected_failure_requires_every_declared_evidence_ref() {
        let expected = super::FaultExpectedFailure {
            classification: FailureClassification::DataCorruption,
            severity: FailureSeverity::FailCorrectness,
            responsibility_domain: ResponsibilityDomain::Product,
            evidence_refs: vec![
                FaultExpectedEvidenceRef::CheckerReport,
                FaultExpectedEvidenceRef::FaultEvidence,
            ],
        };
        let refs = vec!["attempt/case/checker-report.json".to_string()];

        let error = expected
            .validate_observed(
                "data_corruption",
                FailureSeverity::FailCorrectness,
                Some(ResponsibilityDomain::Product),
                &refs,
            )
            .expect_err("missing fault evidence");

        assert!(error.to_string().contains("fault-evidence.json"));
    }

    #[test]
    fn rejects_duplicate_continue_on_severities() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  continueOnSeverities:
    - degraded
    - degraded
scenarios:
  - name: io-eio
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("duplicate severity");

        assert!(
            error
                .to_string()
                .contains("continueOnSeverities contains duplicate")
        );
    }

    #[test]
    fn rejects_legacy_scenario_duration_field() {
        let error = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    duration: 10m
"#,
        )
        .expect_err("legacy duration field should be rejected");

        assert!(error.to_string().contains("duration"));
    }

    #[test]
    fn accepts_operation_weights_without_object_override() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      operationWeights:
        put: 2
        overwrite: 1
        get: 3
        list: 1
        delete: 1
        multipart: 1
"#,
        )
        .expect("suite yaml");

        let resolved = suite.resolve().expect("resolved suite");

        let workload = resolved.scenarios[0].workload.as_ref().expect("workload");
        assert_eq!(
            workload.operation_weights.expect("operation weights").get,
            3
        );
    }

    #[test]
    fn accepts_payload_distribution_and_hotspot_without_object_override() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      payloadDistribution:
        - sizeBytes: 1024
          weight: 1
        - sizeBytes: 4096
          weight: 3
      hotspot:
        objectPercent: 10
        operationPercent: 70
"#,
        )
        .expect("suite yaml");

        let resolved = suite.resolve().expect("resolved suite");

        let workload = resolved.scenarios[0].workload.as_ref().expect("workload");
        assert_eq!(
            workload
                .payload_distribution
                .as_ref()
                .expect("payload distribution")
                .classes[1]
                .size_bytes,
            4096
        );
        assert_eq!(workload.hotspot.expect("hotspot").operation_percent, 70);
    }

    #[test]
    fn accepts_reusable_workload_profiles() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
workloadProfiles:
  smoke:
    objects: 64
    concurrency: 8
    operationWeights:
      put: 2
      overwrite: 1
      get: 4
      list: 1
      delete: 1
      multipart: 1
    payloadDistribution:
      - sizeBytes: 1024
        weight: 1
    hotspot:
      objectPercent: 10
      operationPercent: 70
scenarios:
  - name: io-eio
    faultDuration: 20m
    workloadProfile: smoke
"#,
        )
        .expect("suite yaml");

        let resolved = suite.resolve().expect("resolved suite");

        assert!(resolved.workload_profiles.contains_key("smoke"));
        assert_eq!(
            resolved.scenarios[0].workload_profile.as_deref(),
            Some("smoke")
        );
        assert_eq!(resolved.scenarios[0].fault_duration_seconds, Some(1200));
        let workload = resolved.scenarios[0].workload.as_ref().expect("workload");
        assert_eq!(workload.objects, Some(64));
        assert_eq!(workload.concurrency, Some(8));
        assert_eq!(
            workload.operation_weights.expect("operation weights").get,
            4
        );
        assert_eq!(workload.hotspot.expect("hotspot").operation_percent, 70);
    }

    #[test]
    fn rejects_percent_override_for_fixed_target_scenario() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: pod-kill-one
    percent: 10
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("percent unsupported");

        assert!(
            error
                .to_string()
                .contains("does not support percent override")
        );
    }

    #[test]
    fn rejects_planned_scenario_names() {
        for scenario in [
            QUORUM_P_IO_FAULT_SCENARIO,
            ADMIN_DECOMMISSION_SCENARIO,
            ADMIN_REBALANCE_SCENARIO,
        ] {
            let suite = serde_yaml_ng::from_str::<FaultSuite>(&format!(
                r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: {scenario}
"#
            ))
            .expect("suite yaml");

            let error = suite.resolve().expect_err("planned scenario");

            assert!(error.to_string().contains("not executable"));
        }
    }

    #[test]
    fn rejects_partial_workload_override() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      objects: 64
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("partial workload");

        assert!(
            error
                .to_string()
                .contains("must set both objects and concurrency")
        );
    }

    #[test]
    fn rejects_invalid_workload_profile_definitions() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
workloadProfiles:
  smoke:
    objects: 64
scenarios:
  - name: io-eio
    workloadProfile: smoke
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("partial workload profile");
        assert!(
            error
                .to_string()
                .contains("workloadProfiles.smoke must set both objects and concurrency")
        );

        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workloadProfile: missing
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unknown workload profile");
        assert!(
            error
                .to_string()
                .contains("does not match any workloadProfiles entry")
        );
    }

    #[test]
    fn rejects_workload_profile_and_inline_workload_together() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
workloadProfiles:
  smoke:
    objects: 64
    concurrency: 8
scenarios:
  - name: io-eio
    workloadProfile: smoke
    workload:
      objects: 72
      concurrency: 9
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("mixed workload sources");

        assert!(error.to_string().contains("must not set both"));
    }

    #[test]
    fn rejects_unsupported_scenario_params() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    params:
      kind: networkDelay
      latency: 200ms
      jitter: 50ms
      correlationPercent: 25
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unsupported params");

        assert!(error.to_string().contains("does not support typed params"));
    }

    #[test]
    fn rejects_unsafe_scenario_params() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: network-loss
    params:
      kind: networkLoss
      lossPercent: 0
      correlationPercent: 25
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unsafe params");

        assert!(error.to_string().contains("lossPercent"));
    }

    #[test]
    fn rejects_unsafe_operation_weights() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      operationWeights:
        put: 0
        overwrite: 1
        get: 1
        list: 1
        delete: 1
        multipart: 1
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unsafe operation weights");

        assert!(error.to_string().contains("operationWeights.put"));
    }

    #[test]
    fn rejects_unsafe_payload_distribution_and_hotspot() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      payloadDistribution:
        - sizeBytes: 0
          weight: 1
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unsafe payload distribution");
        assert!(error.to_string().contains("payloadDistribution.sizeBytes"));

        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      hotspot:
        objectPercent: 10
        operationPercent: 0
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unsafe hotspot");
        assert!(error.to_string().contains("hotspot.operationPercent"));
    }

    #[test]
    fn rejects_extreme_operation_weights_before_total_check() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      objects: 64
      concurrency: 8
      operationWeights:
        put: 4294967295
        overwrite: 4294967295
        get: 4294967295
        list: 4294967295
        delete: 4294967295
        multipart: 4294967295
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("extreme operation weights");

        assert!(error.to_string().contains("operationWeights.put"));
    }

    #[test]
    fn rejects_unknown_suite_fields() {
        let error = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuraton: 1h
scenarios:
  - name: io-eio
"#,
        )
        .expect_err("unknown budget field");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_unknown_scenario_fields() {
        let error = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    worklod:
      objects: 64
      concurrency: 8
"#,
        )
        .expect_err("unknown scenario field");

        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn rejects_unimplemented_suite_modes() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
observability:
  chaosDashboard: required
artifacts:
  required: default
scenarios:
  - name: io-eio
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unimplemented mode");

        assert!(error.to_string().contains("chaosDashboard=required"));
    }

    #[test]
    fn rejects_unimplemented_artifact_default_mode() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
artifacts:
  required: default
scenarios:
  - name: io-eio
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unimplemented artifact mode");

        assert!(error.to_string().contains("artifacts.required=default"));
    }

    #[test]
    fn parses_duration_units() {
        assert_eq!(parse_duration_seconds("30").unwrap(), 30);
        assert_eq!(parse_duration_seconds("30s").unwrap(), 30);
        assert_eq!(parse_duration_seconds("10m").unwrap(), 600);
        assert_eq!(parse_duration_seconds("2h").unwrap(), 7200);
        assert!(parse_duration_seconds("0s").is_err());
        assert!(parse_duration_seconds("1d").is_err());
    }
}
