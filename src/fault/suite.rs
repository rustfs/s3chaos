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
use std::fs;
use std::path::Path;

use crate::fault::{
    plan::FaultInjectionParameters,
    scenarios::{FaultScenarioStatus, scenario_spec},
    workload::WorkloadOperationMix,
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
    pub workload: Option<FaultSuiteWorkloadOverride>,
    pub priority: String,
    pub isolation: String,
    pub backend: String,
    pub impact_policy: String,
    pub requires_static_storage: bool,
    pub requires_chaos_mesh: bool,
    pub crds: Vec<String>,
    pub required_tools: Vec<String>,
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
        params.validate_for_scenario(&scenario.name)?;
        let duration_seconds = scenario
            .duration
            .as_deref()
            .map(parse_duration_seconds)
            .transpose()?;

        Ok(Self {
            name: scenario.name.clone(),
            params,
            repetitions: scenario.repetitions,
            duration_seconds,
            percent: scenario.percent,
            workload: scenario.workload.clone(),
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
        workload.objects.is_some()
            || workload.concurrency.is_some()
            || workload.operation_weights.is_some(),
        "scenario {name} workload override must set objects/concurrency or operationWeights"
    );
    if let Some(operation_weights) = workload.operation_weights {
        operation_weights.validate()?;
    }
    match (workload.objects, workload.concurrency) {
        (Some(objects), Some(concurrency)) => {
            ensure!(
                objects >= 12,
                "scenario {name} workload.objects must be at least 12"
            );
            ensure!(
                concurrency > 0,
                "scenario {name} workload.concurrency must be greater than zero"
            );
            ensure!(
                concurrency <= objects,
                "scenario {name} workload.concurrency must be <= workload.objects"
            );
            if let Some(operation_weights) = workload.operation_weights {
                let mixed_count = objects - objects / 2;
                let total_weight = operation_weights.total_weight();
                ensure!(
                    mixed_count as u64 >= total_weight,
                    "scenario {name} workload.operationWeights total {} requires at least that many mixed-workload objects, got {mixed_count}",
                    total_weight
                );
            }
        }
        (None, None) => {}
        _ => bail!("scenario {name} workload override must set both objects and concurrency"),
    }
    Ok(())
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
