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
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::fault::{
    plan::FaultInjectionParameters,
    scenarios::{FaultScenarioStatus, scenario_spec},
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
    pub duration: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload: Option<FaultSuiteWorkloadOverride>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub duration_profiles: Vec<FaultSuiteWorkloadDurationProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FaultSuiteWorkloadDurationProfile {
    pub min_duration: String,
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
    pub scenarios: Vec<ResolvedFaultSuiteScenario>,
    pub observability: FaultSuiteObservability,
    pub artifacts: FaultSuiteArtifacts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFaultSuiteBudgets {
    pub stop_on_first_failure: bool,
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
    pub duration_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workload: Option<ResolvedFaultSuiteWorkloadOverride>,
    pub priority: String,
    pub isolation: String,
    pub backend: String,
    pub impact_policy: String,
    pub requires_static_storage: bool,
    pub requires_chaos_mesh: bool,
    pub crds: Vec<String>,
    pub required_tools: Vec<String>,
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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub duration_profiles: Vec<ResolvedFaultSuiteWorkloadDurationProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedFaultSuiteWorkloadDurationProfile {
    pub min_duration_seconds: u64,
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

        let scenarios = self
            .scenarios
            .iter()
            .map(ResolvedFaultSuiteScenario::from_suite_scenario)
            .collect::<Result<Vec<_>>>()?;

        Ok(ResolvedFaultSuite {
            api_version: self.api_version.clone(),
            kind: self.kind.clone(),
            metadata: self.metadata.clone(),
            budgets: ResolvedFaultSuiteBudgets {
                stop_on_first_failure: self.budgets.stop_on_first_failure,
                max_duration_seconds: budget_duration,
                max_client_disruptions: self.budgets.max_client_disruptions,
                recovery_stable_window_seconds: self.budgets.recovery_stable_window_seconds,
            },
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
    fn from_suite_workload(name: &str, workload: &FaultSuiteWorkloadOverride) -> Result<Self> {
        validate_workload_override(name, workload)?;
        let mut seen_min_durations = BTreeSet::new();
        let mut duration_profiles = workload
            .duration_profiles
            .iter()
            .enumerate()
            .map(|(index, profile)| {
                let resolved =
                    ResolvedFaultSuiteWorkloadDurationProfile::from_suite_profile(
                        name, index, profile,
                    )?;
                ensure!(
                    seen_min_durations.insert(resolved.min_duration_seconds),
                    "scenario {name} workload.durationProfiles[{index}].minDuration duplicates an earlier threshold"
                );
                Ok(resolved)
            })
            .collect::<Result<Vec<_>>>()?;
        duration_profiles.sort_by_key(|profile| profile.min_duration_seconds);

        Ok(Self {
            objects: workload.objects,
            concurrency: workload.concurrency,
            operation_weights: workload.operation_weights,
            payload_distribution: workload.payload_distribution.clone(),
            hotspot: workload.hotspot,
            duration_profiles,
        })
    }

    pub fn duration_profile_for(
        &self,
        duration_seconds: u64,
    ) -> Option<&ResolvedFaultSuiteWorkloadDurationProfile> {
        self.duration_profiles
            .iter()
            .rev()
            .find(|profile| profile.min_duration_seconds <= duration_seconds)
    }
}

impl ResolvedFaultSuiteWorkloadDurationProfile {
    fn from_suite_profile(
        name: &str,
        index: usize,
        profile: &FaultSuiteWorkloadDurationProfile,
    ) -> Result<Self> {
        let min_duration_seconds =
            parse_duration_seconds(&profile.min_duration).with_context(|| {
                format!("scenario {name} workload.durationProfiles[{index}].minDuration")
            })?;
        validate_workload_fields(
            name,
            &format!("workload.durationProfiles[{index}]"),
            profile.objects,
            profile.concurrency,
            profile.operation_weights,
            profile.payload_distribution.as_ref(),
            profile.hotspot,
        )?;

        Ok(Self {
            min_duration_seconds,
            objects: profile.objects,
            concurrency: profile.concurrency,
            operation_weights: profile.operation_weights,
            payload_distribution: profile.payload_distribution.clone(),
            hotspot: profile.hotspot,
        })
    }
}

impl ResolvedFaultSuiteScenario {
    fn from_suite_scenario(scenario: &FaultSuiteScenario) -> Result<Self> {
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
        if let Some(workload) = &scenario.workload {
            validate_workload_override(&scenario.name, workload)?;
        }
        let params = scenario.params.clone().unwrap_or_default();
        if let Some(params) = &scenario.params {
            params.validate_explicit_for_schema(spec.param_schema)?;
        }
        let duration_seconds = scenario
            .duration
            .as_deref()
            .map(parse_duration_seconds)
            .transpose()?;
        let workload = scenario
            .workload
            .as_ref()
            .map(|workload| {
                ResolvedFaultSuiteWorkloadOverride::from_suite_workload(&scenario.name, workload)
            })
            .transpose()?;
        if let (Some(duration_seconds), Some(workload)) = (duration_seconds, workload.as_ref()) {
            ensure!(
                workload.duration_profiles.is_empty()
                    || workload.duration_profile_for(duration_seconds).is_some(),
                "scenario {} workload.durationProfiles must include at least one minDuration <= scenario duration {}s",
                scenario.name,
                duration_seconds
            );
        }

        Ok(Self {
            name: scenario.name.clone(),
            params,
            repetitions: scenario.repetitions,
            duration_seconds,
            percent: scenario.percent,
            workload,
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
  maxClientDisruptions: 20
  recoveryStableWindowSeconds: 60
observability:
  chaosDashboard: optional
artifacts:
  required: strict
scenarios:
  - name: io-eio
    duration: 10m
    percent: 20
    workload:
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
      durationProfiles:
        - minDuration: 10m
          objects: 80000
          concurrency: 120
  - name: network-delay
    duration: 8m
    params:
      kind: networkDelay
      latency: 200ms
      jitter: 50ms
      correlationPercent: 25
"#
    .to_string()
}

fn validate_workload_override(name: &str, workload: &FaultSuiteWorkloadOverride) -> Result<()> {
    ensure!(
        workload_has_fields(
            workload.objects,
            workload.concurrency,
            workload.operation_weights,
            workload.payload_distribution.as_ref(),
            workload.hotspot,
        ) || !workload.duration_profiles.is_empty(),
        "scenario {name} workload override must set objects/concurrency, operationWeights, payloadDistribution, hotspot, or durationProfiles"
    );
    if workload_has_fields(
        workload.objects,
        workload.concurrency,
        workload.operation_weights,
        workload.payload_distribution.as_ref(),
        workload.hotspot,
    ) {
        validate_workload_fields(
            name,
            "workload",
            workload.objects,
            workload.concurrency,
            workload.operation_weights,
            workload.payload_distribution.as_ref(),
            workload.hotspot,
        )?;
    }
    Ok(())
}

fn validate_workload_fields(
    name: &str,
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
        "scenario {name} {context} must set objects/concurrency, operationWeights, payloadDistribution, or hotspot"
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
            ensure!(
                objects >= 12,
                "scenario {name} {context}.objects must be at least 12"
            );
            ensure!(
                concurrency > 0,
                "scenario {name} {context}.concurrency must be greater than zero"
            );
            ensure!(
                concurrency <= objects,
                "scenario {name} {context}.concurrency must be <= {context}.objects"
            );
            if let Some(operation_weights) = operation_weights {
                let mixed_count = objects - objects / 2;
                let total_weight = operation_weights.total_weight();
                ensure!(
                    mixed_count as u64 >= total_weight,
                    "scenario {name} {context}.operationWeights total {} requires at least that many mixed-workload objects, got {mixed_count}",
                    total_weight
                );
            }
        }
        (None, None) => {}
        _ => bail!("scenario {name} {context} must set both objects and concurrency"),
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
    ensure!(
        !name.is_empty(),
        "FaultSuite metadata.name must not be empty"
    );
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'),
        "FaultSuite metadata.name must contain lowercase ASCII letters, digits, or '-'"
    );
    ensure!(
        !name.starts_with('-') && !name.ends_with('-'),
        "FaultSuite metadata.name must not start or end with '-'"
    );
    Ok(())
}

fn default_stop_on_first_failure() -> bool {
    true
}

fn default_repetitions() -> usize {
    1
}

impl Default for FaultSuiteBudgets {
    fn default() -> Self {
        Self {
            stop_on_first_failure: true,
            max_duration: None,
            max_client_disruptions: None,
            recovery_stable_window_seconds: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FaultSuite, parse_duration_seconds};
    use crate::fault::plan::FaultInjectionParameters;

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
    duration: 10m
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
        assert_eq!(resolved.scenarios.len(), 2);
        assert_eq!(resolved.scenarios[0].duration_seconds, Some(600));
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
    fn accepts_duration_based_workload_profiles() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    duration: 20m
    workload:
      objects: 64
      concurrency: 8
      durationProfiles:
        - minDuration: 15m
          objects: 96
          concurrency: 12
          operationWeights:
            put: 2
            overwrite: 1
            get: 4
            list: 1
            delete: 1
            multipart: 1
        - minDuration: 5m
          payloadDistribution:
            - sizeBytes: 1024
              weight: 1
"#,
        )
        .expect("suite yaml");

        let resolved = suite.resolve().expect("resolved suite");

        let profiles = &resolved.scenarios[0]
            .workload
            .as_ref()
            .expect("workload")
            .duration_profiles;
        assert_eq!(profiles[0].min_duration_seconds, 300);
        assert_eq!(profiles[1].min_duration_seconds, 900);
        assert_eq!(profiles[1].objects, Some(96));
        assert_eq!(
            profiles[1]
                .operation_weights
                .expect("operation weights")
                .get,
            4
        );
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
    fn rejects_invalid_duration_based_workload_profiles() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      durationProfiles:
        - minDuration: 10m
          objects: 64
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("partial duration profile");
        assert!(
            error
                .to_string()
                .contains("durationProfiles[0] must set both objects and concurrency")
        );

        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    workload:
      durationProfiles:
        - minDuration: 10m
          objects: 64
          concurrency: 8
        - minDuration: 10m
          objects: 72
          concurrency: 9
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("duplicate duration profile");
        assert!(
            error
                .to_string()
                .contains("duplicates an earlier threshold")
        );
    }

    #[test]
    fn rejects_unreachable_duration_based_workload_profiles() {
        let suite = serde_yaml_ng::from_str::<FaultSuite>(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
scenarios:
  - name: io-eio
    duration: 10m
    workload:
      durationProfiles:
        - minDuration: 15m
          objects: 64
          concurrency: 8
"#,
        )
        .expect("suite yaml");

        let error = suite.resolve().expect_err("unreachable duration profile");
        assert!(
            error
                .to_string()
                .contains("must include at least one minDuration <= scenario duration 600s")
        );
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
