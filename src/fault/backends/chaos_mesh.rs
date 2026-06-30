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

use anyhow::{Result, ensure};
use std::time::Duration;

use crate::framework::config::ClusterTestConfig;

mod runtime;

pub use runtime::{
    ChaosGuard, apply_iochaos, apply_networkchaos, apply_podchaos, apply_stresschaos,
    cleanup_managed_chaos, cleanup_managed_iochaos, cleanup_managed_networkchaos,
    cleanup_managed_podchaos, cleanup_managed_stresschaos, cleanup_run, cleanup_run_kind,
    require_iochaos_crd, require_networkchaos_crd, require_podchaos_crd, require_stresschaos_crd,
};

pub(crate) const RUN_ID_LABEL: &str = "rustfs-fault-test/run-id";
const SCENARIO_LABEL: &str = "rustfs-fault-test/scenario";
pub(crate) const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
pub(crate) const MANAGED_BY_VALUE: &str = "s3chaos";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoChaosAction {
    Fault {
        errno: u8,
    },
    Latency {
        delay: String,
    },
    Mistake {
        filling: String,
        max_occurrences: u8,
        max_length: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoLatencyParameters {
    pub methods: Vec<String>,
    pub delay: String,
    pub percent: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub container_name: String,
    pub volume_path: String,
    pub methods: Vec<String>,
    pub action: IoChaosAction,
    pub percent: u8,
    pub duration: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PodChaosAction {
    PodKill,
    PodFailure { duration: Duration },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub action: PodChaosAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkChaosAction {
    Partition,
    Delay {
        latency: String,
        jitter: String,
        correlation: String,
    },
    Loss {
        loss: String,
        correlation: String,
    },
    Corrupt {
        corrupt: String,
        correlation: String,
    },
    Duplicate {
        duplicate: String,
        correlation: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkDelayParameters {
    pub latency: String,
    pub jitter: String,
    pub correlation_percent: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub action: NetworkChaosAction,
    pub duration: Duration,
}

#[derive(Debug, Clone)]
pub enum StressChaosAction {
    Cpu { workers: u32, load: u32 },
    Memory { workers: u32, size: String },
}

#[derive(Debug, Clone)]
pub struct StressChaosSpec {
    pub name: String,
    pub namespace: String,
    pub run_id: String,
    pub scenario: String,
    pub target_namespace: String,
    pub tenant_name: String,
    pub action: StressChaosAction,
    pub duration: Duration,
}

impl IoChaosSpec {
    pub fn eio_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-eio-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            methods: vec!["READ".to_string(), "WRITE".to_string()],
            action: IoChaosAction::Fault { errno: 5 },
            percent,
            duration,
        })
    }

    pub fn read_mistake_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-mistake-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            methods: vec!["READ".to_string()],
            action: IoChaosAction::Mistake {
                filling: "random".to_string(),
                max_occurrences: 1,
                max_length: 4096,
            },
            percent,
            duration,
        })
    }

    pub fn latency_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        parameters: IoLatencyParameters,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&parameters.percent),
            "IOChaos percent must be in 1..=100, got {}",
            parameters.percent
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );
        ensure!(
            !parameters.methods.is_empty(),
            "IOChaos methods must not be empty"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-io-latency-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            methods: parameters.methods,
            action: IoChaosAction::Latency {
                delay: parameters.delay,
            },
            percent: parameters.percent,
            duration,
        })
    }

    pub fn enospc_on_rustfs_volume(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        volume_path: impl Into<String>,
        percent: u8,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            (1..=100).contains(&percent),
            "IOChaos percent must be in 1..=100, got {percent}"
        );
        ensure!(
            duration > Duration::ZERO,
            "IOChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        let scenario = scenario.into();

        Ok(Self {
            name: format!("rustfs-fault-enospc-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario,
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            container_name: "rustfs".to_string(),
            volume_path: volume_path.into(),
            methods: vec!["WRITE".to_string()],
            action: IoChaosAction::Fault { errno: 28 },
            percent,
            duration,
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let methods = self
            .methods
            .iter()
            .map(|method| format!("    - {method}"))
            .collect::<Vec<_>>()
            .join("\n");
        let seconds = self.duration.as_secs();
        let action = self.action_manifest();

        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: IOChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
{action}
  mode: one
  selector:
    namespaces:
      - {target_namespace}
    labelSelectors:
      rustfs.tenant: {tenant_name}
  containerNames:
    - {container_name}
  volumePath: {volume_path}
  path: {volume_path}/**/*
  methods:
{methods}
  percent: {percent}
  duration: "{seconds}s"
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            tenant_name = self.tenant_name,
            container_name = self.container_name,
            volume_path = self.volume_path,
            methods = methods,
            percent = self.percent,
            action = action,
        )
    }

    fn action_manifest(&self) -> String {
        match &self.action {
            IoChaosAction::Fault { errno } => {
                format!("  action: fault\n  errno: {errno}")
            }
            IoChaosAction::Latency { delay } => {
                format!("  action: latency\n  delay: {delay}")
            }
            IoChaosAction::Mistake {
                filling,
                max_occurrences,
                max_length,
            } => format!(
                r#"  action: mistake
  mistake:
    filling: {filling}
    maxOccurrences: {max_occurrences}
    maxLength: {max_length}"#
            ),
        }
    }
}

impl PodChaosSpec {
    pub fn kill_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
    ) -> Self {
        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Self {
            name: format!("rustfs-fault-pod-kill-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action: PodChaosAction::PodKill,
        }
    }

    pub fn fail_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
    ) -> Result<Self> {
        ensure!(
            duration > Duration::ZERO,
            "PodChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-pod-failure-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action: PodChaosAction::PodFailure { duration },
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let action = self.action_manifest();
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
{action}
  mode: one
  selector:
    namespaces:
      - {target_namespace}
    labelSelectors:
      rustfs.tenant: {tenant_name}
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            tenant_name = self.tenant_name,
            action = action,
        )
    }

    fn action_manifest(&self) -> String {
        match self.action {
            PodChaosAction::PodKill => "  action: pod-kill".to_string(),
            PodChaosAction::PodFailure { duration } => {
                format!(
                    "  action: pod-failure\n  duration: \"{}s\"",
                    duration.as_secs()
                )
            }
        }
    }
}

impl NetworkChaosSpec {
    pub fn partition_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-partition",
            NetworkChaosAction::Partition,
        )
    }

    pub fn delay_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        parameters: NetworkDelayParameters,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-delay",
            NetworkChaosAction::Delay {
                latency: parameters.latency,
                jitter: parameters.jitter,
                correlation: parameters.correlation_percent.to_string(),
            },
        )
    }

    pub fn loss_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        loss_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-loss",
            NetworkChaosAction::Loss {
                loss: loss_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    pub fn corrupt_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        corrupt_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-corrupt",
            NetworkChaosAction::Corrupt {
                corrupt: corrupt_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    pub fn duplicate_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        duplicate_percent: u8,
        correlation_percent: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "net-duplicate",
            NetworkChaosAction::Duplicate {
                duplicate: duplicate_percent.to_string(),
                correlation: correlation_percent.to_string(),
            },
        )
    }

    fn one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        name_action: &str,
        action: NetworkChaosAction,
    ) -> Result<Self> {
        ensure!(
            duration > Duration::ZERO,
            "NetworkChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-{name_action}-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action,
            duration,
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let seconds = self.duration.as_secs();
        let action = self.action_manifest();
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
{action}
  mode: one
  selector:
    namespaces:
      - {target_namespace}
    labelSelectors:
      rustfs.tenant: {tenant_name}
  direction: both
  target:
    mode: all
    selector:
      namespaces:
        - {target_namespace}
      labelSelectors:
        rustfs.tenant: {tenant_name}
  duration: "{seconds}s"
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            tenant_name = self.tenant_name,
            action = action,
        )
    }

    fn action_manifest(&self) -> String {
        match &self.action {
            NetworkChaosAction::Partition => "  action: partition".to_string(),
            NetworkChaosAction::Delay {
                latency,
                jitter,
                correlation,
            } => format!(
                r#"  action: delay
  delay:
    latency: "{latency}"
    jitter: "{jitter}"
    correlation: "{correlation}""#
            ),
            NetworkChaosAction::Loss { loss, correlation } => format!(
                r#"  action: loss
  loss:
    loss: "{loss}"
    correlation: "{correlation}""#
            ),
            NetworkChaosAction::Corrupt {
                corrupt,
                correlation,
            } => format!(
                r#"  action: corrupt
  corrupt:
    corrupt: "{corrupt}"
    correlation: "{correlation}""#
            ),
            NetworkChaosAction::Duplicate {
                duplicate,
                correlation,
            } => format!(
                r#"  action: duplicate
  duplicate:
    duplicate: "{duplicate}"
    correlation: "{correlation}""#
            ),
        }
    }
}

impl StressChaosSpec {
    pub fn cpu_on_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        workers: u32,
        load: u8,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "stress-cpu",
            StressChaosAction::Cpu {
                workers,
                load: load.into(),
            },
        )
    }

    pub fn memory_on_one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        workers: u32,
        size: impl Into<String>,
    ) -> Result<Self> {
        Self::one_rustfs_pod(
            config,
            chaos_namespace,
            run_id,
            scenario,
            duration,
            "stress-memory",
            StressChaosAction::Memory {
                workers,
                size: size.into(),
            },
        )
    }

    fn one_rustfs_pod(
        config: &ClusterTestConfig,
        chaos_namespace: impl Into<String>,
        run_id: impl Into<String>,
        scenario: impl Into<String>,
        duration: Duration,
        name_action: &str,
        action: StressChaosAction,
    ) -> Result<Self> {
        ensure!(
            duration > Duration::ZERO,
            "StressChaos duration must be positive"
        );

        let run_id = run_id.into();
        let short_run_id = run_id.chars().take(12).collect::<String>();
        Ok(Self {
            name: format!("rustfs-fault-{name_action}-{short_run_id}"),
            namespace: chaos_namespace.into(),
            run_id,
            scenario: scenario.into(),
            target_namespace: config.test_namespace.clone(),
            tenant_name: config.tenant_name.clone(),
            action,
            duration,
        })
    }

    pub fn with_name_suffix(mut self, suffix: &str) -> Self {
        self.name.push_str(suffix);
        self
    }

    pub fn manifest(&self) -> String {
        let seconds = self.duration.as_secs();
        let stressors = self.stressors_manifest();
        format!(
            r#"apiVersion: chaos-mesh.org/v1alpha1
kind: StressChaos
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {run_id_label}: "{run_id}"
    {scenario_label}: "{scenario}"
    {managed_by_label}: {managed_by_value}
spec:
  mode: one
  selector:
    namespaces:
      - {target_namespace}
    labelSelectors:
      rustfs.tenant: {tenant_name}
  stressors:
{stressors}
  duration: "{seconds}s"
"#,
            name = self.name,
            namespace = self.namespace,
            run_id_label = RUN_ID_LABEL,
            run_id = self.run_id,
            scenario_label = SCENARIO_LABEL,
            scenario = self.scenario,
            managed_by_label = MANAGED_BY_LABEL,
            managed_by_value = MANAGED_BY_VALUE,
            target_namespace = self.target_namespace,
            tenant_name = self.tenant_name,
            stressors = stressors,
        )
    }

    fn stressors_manifest(&self) -> String {
        match &self.action {
            StressChaosAction::Cpu { workers, load } => format!(
                r#"    cpu:
      workers: {workers}
      load: {load}"#
            ),
            StressChaosAction::Memory { workers, size } => format!(
                r#"    memory:
      workers: {workers}
      size: "{size}""#
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IoChaosSpec, IoLatencyParameters, NetworkChaosSpec, NetworkDelayParameters, PodChaosSpec,
        StressChaosSpec, runtime::chaos_experiment_is_active,
    };
    use crate::fault::config::FaultTestConfig;
    use std::time::Duration;

    #[test]
    fn iochaos_manifest_targets_rustfs_workload_only() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-eio",
            "/data/rustfs0",
            20,
            Duration::from_secs(60),
        )
        .expect("valid io chaos");
        let manifest = spec.manifest();

        assert!(manifest.contains("kind: IOChaos"));
        assert!(manifest.contains("namespace: chaos-mesh"));
        assert!(manifest.contains("rustfs.tenant: fault-test-tenant"));
        assert!(manifest.contains("rustfs-fault-test/run-id"));
        assert!(manifest.contains("s3chaos"));
        assert!(manifest.contains("containerNames:\n    - rustfs"));
        assert!(manifest.contains("volumePath: /data/rustfs0"));
        assert!(manifest.contains("errno: 5"));
        assert!(manifest.contains("percent: 20"));
    }

    #[test]
    fn enospc_manifest_targets_only_volume_writes() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::enospc_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "disk-full",
            "/data/rustfs0",
            100,
            Duration::from_secs(60),
        )
        .expect("valid enospc chaos");
        let manifest = spec.manifest();

        assert!(manifest.contains("errno: 28"));
        assert!(manifest.contains("methods:\n    - WRITE"));
        assert!(manifest.contains("percent: 100"));
        assert!(!manifest.contains("    - READ"));
    }

    #[test]
    fn io_latency_manifest_targets_volume_reads_and_writes() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::latency_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-latency",
            "/data/rustfs0",
            IoLatencyParameters {
                methods: vec!["READ".to_string()],
                delay: "400ms".to_string(),
                percent: 20,
            },
            Duration::from_secs(60),
        )
        .expect("valid latency chaos");
        let manifest = spec.manifest();

        assert!(manifest.contains("action: latency"));
        assert!(manifest.contains("delay: 400ms"));
        assert!(manifest.contains("methods:\n    - READ"));
        assert!(!manifest.contains("    - WRITE"));
    }

    #[test]
    fn pod_failure_manifest_uses_duration() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = PodChaosSpec::fail_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "pod-failure",
            Duration::from_secs(60),
        )
        .expect("valid pod failure");
        let manifest = spec.manifest();

        assert!(manifest.contains("kind: PodChaos"));
        assert!(manifest.contains("action: pod-failure"));
        assert!(manifest.contains("duration: \"60s\""));
        assert!(manifest.contains("rustfs.tenant: fault-test-tenant"));
    }

    #[test]
    fn network_delay_and_loss_manifests_use_targeted_actions() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let delay = NetworkChaosSpec::delay_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-delay",
            Duration::from_secs(60),
            NetworkDelayParameters {
                latency: "350ms".to_string(),
                jitter: "75ms".to_string(),
                correlation_percent: 15,
            },
        )
        .expect("valid network delay")
        .manifest();
        let loss = NetworkChaosSpec::loss_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "network-loss",
            Duration::from_secs(60),
            40,
            10,
        )
        .expect("valid network loss")
        .manifest();

        assert!(delay.contains("action: delay"));
        assert!(delay.contains("latency: \"350ms\""));
        assert!(delay.contains("jitter: \"75ms\""));
        assert!(delay.contains("correlation: \"15\""));
        assert!(loss.contains("action: loss"));
        assert!(loss.contains("loss: \"40\""));
        assert!(loss.contains("correlation: \"10\""));
    }

    #[test]
    fn stress_manifests_target_one_rustfs_pod() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let cpu = StressChaosSpec::cpu_on_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "stress-cpu",
            Duration::from_secs(60),
            2,
            65,
        )
        .expect("valid cpu stress")
        .manifest();
        let memory = StressChaosSpec::memory_on_one_rustfs_pod(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "stress-memory",
            Duration::from_secs(60),
            3,
            "768MiB",
        )
        .expect("valid memory stress")
        .manifest();

        assert!(cpu.contains("kind: StressChaos"));
        assert!(cpu.contains("cpu:"));
        assert!(cpu.contains("workers: 2"));
        assert!(cpu.contains("load: 65"));
        assert!(memory.contains("memory:"));
        assert!(memory.contains("workers: 3"));
        assert!(memory.contains("size: \"768MiB\""));
        assert!(memory.contains("rustfs.tenant: fault-test-tenant"));
    }

    #[test]
    fn chaos_name_suffix_keeps_run_label_stable() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let spec = IoChaosSpec::eio_on_rustfs_volume(
            &config.cluster,
            "chaos-mesh",
            "run-1234567890",
            "io-eio",
            "/data/rustfs0",
            20,
            Duration::from_secs(60),
        )
        .expect("valid io chaos")
        .with_name_suffix("-01");
        let manifest = spec.manifest();

        assert_eq!(spec.name, "rustfs-fault-io-eio-run-12345678-01");
        assert!(manifest.contains("name: rustfs-fault-io-eio-run-12345678-01"));
        assert!(manifest.contains("rustfs-fault-test/run-id: \"run-1234567890\""));
    }

    #[test]
    fn iochaos_active_requires_selected_and_injected_not_recovered() {
        let status = r#"{
          "status": {
            "conditions": [
              {"type": "Selected", "status": "True"},
              {"type": "AllInjected", "status": "True"},
              {"type": "AllRecovered", "status": "False"}
            ]
          }
        }"#;

        assert!(chaos_experiment_is_active(status).expect("valid status"));
    }

    #[test]
    fn chaos_experiment_active_rejects_unselected_experiment() {
        let status = r#"{
          "status": {
            "conditions": [
              {"type": "Selected", "status": "False"},
              {"type": "AllInjected", "status": "True"}
            ]
          }
        }"#;

        assert!(!chaos_experiment_is_active(status).expect("valid status"));
    }
}
