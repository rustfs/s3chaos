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

use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::time::Duration;

use crate::fault::{
    config::{DEFAULT_RUSTFS_VOLUME_PATH, FaultTestConfig, validate_rustfs_volume_path},
    scenarios::{
        DISK_FULL_SCENARIO, DM_FLAKEY_SCENARIO, FaultBackend, FaultScenario, FaultScenarioSpec,
        IO_EIO_SCENARIO, IO_LATENCY_SCENARIO, IO_READ_MISTAKE_SCENARIO, NETWORK_CORRUPT_SCENARIO,
        NETWORK_DELAY_SCENARIO, NETWORK_DUPLICATE_SCENARIO, NETWORK_LOSS_SCENARIO,
        NETWORK_PARTITION_ONE_SCENARIO, POD_FAILURE_SCENARIO, POD_KILL_ONE_SCENARIO,
        STRESS_CPU_SCENARIO, STRESS_MEMORY_SCENARIO, WARP_UNDER_CHAOS_SCENARIO,
    },
};

pub const DEFAULT_RUSTFS_DATA_VOLUME: &str = DEFAULT_RUSTFS_VOLUME_PATH;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultWorkloadMode {
    S3Mixed,
    S3MixedWithWarp,
}

impl FaultWorkloadMode {
    pub fn runs_warp(self) -> bool {
        matches!(self, Self::S3MixedWithWarp)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    RustfsVolumeIoError,
    RustfsVolumeLatency,
    RustfsVolumeReadMistake,
    RustfsVolumeEnospc,
    RustfsServerPodKill,
    RustfsServerPodFailure,
    RustfsServerNetworkPartition,
    RustfsServerNetworkDelay,
    RustfsServerNetworkLoss,
    RustfsServerNetworkCorrupt,
    RustfsServerNetworkDuplicate,
    RustfsServerCpuStress,
    RustfsServerMemoryStress,
    RustfsBlockDeviceFlakey,
}

impl FaultKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RustfsVolumeIoError => "rustfs_volume_io_error",
            Self::RustfsVolumeLatency => "rustfs_volume_latency",
            Self::RustfsVolumeReadMistake => "rustfs_volume_read_mistake",
            Self::RustfsVolumeEnospc => "rustfs_volume_enospc",
            Self::RustfsServerPodKill => "rustfs_server_pod_kill",
            Self::RustfsServerPodFailure => "rustfs_server_pod_failure",
            Self::RustfsServerNetworkPartition => "rustfs_server_network_partition",
            Self::RustfsServerNetworkDelay => "rustfs_server_network_delay",
            Self::RustfsServerNetworkLoss => "rustfs_server_network_loss",
            Self::RustfsServerNetworkCorrupt => "rustfs_server_network_corrupt",
            Self::RustfsServerNetworkDuplicate => "rustfs_server_network_duplicate",
            Self::RustfsServerCpuStress => "rustfs_server_cpu_stress",
            Self::RustfsServerMemoryStress => "rustfs_server_memory_stress",
            Self::RustfsBlockDeviceFlakey => "rustfs_block_device_flakey",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultTarget {
    RustfsVolume { path: String },
    RustfsServerPod,
    RustfsServerPeerNetwork,
    RustfsServerResource,
    DedicatedBlockDevice,
}

impl FaultTarget {
    pub fn summary(&self) -> String {
        match self {
            Self::RustfsVolume { path } => format!("one RustFS volume at {path}"),
            Self::RustfsServerPod => "one RustFS server Pod".to_string(),
            Self::RustfsServerPeerNetwork => {
                "one RustFS server Pod partitioned from its peers".to_string()
            }
            Self::RustfsServerResource => {
                "one RustFS server Pod under resource pressure".to_string()
            }
            Self::DedicatedBlockDevice => "one dedicated block-device-backed PV".to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultSelection {
    Percent(u8),
    FixedTargets(u32),
}

impl FaultSelection {
    pub fn summary(self) -> String {
        match self {
            Self::Percent(percent) => format!("{percent}%"),
            Self::FixedTargets(count) => format!("{count} target(s)"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum IoMethod {
    Read,
    Write,
}

impl IoMethod {
    pub fn as_chaos_mesh_method(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", deny_unknown_fields)]
pub enum FaultInjectionParameters {
    #[default]
    Default,
    IoLatency {
        delay: String,
        methods: Vec<IoMethod>,
    },
    NetworkDelay {
        latency: String,
        jitter: String,
        #[serde(rename = "correlationPercent")]
        correlation_percent: u8,
    },
    NetworkLoss {
        #[serde(rename = "lossPercent")]
        loss_percent: u8,
        #[serde(rename = "correlationPercent")]
        correlation_percent: u8,
    },
    NetworkCorrupt {
        #[serde(rename = "corruptPercent")]
        corrupt_percent: u8,
        #[serde(rename = "correlationPercent")]
        correlation_percent: u8,
    },
    NetworkDuplicate {
        #[serde(rename = "duplicatePercent")]
        duplicate_percent: u8,
        #[serde(rename = "correlationPercent")]
        correlation_percent: u8,
    },
    StressCpu {
        workers: u32,
        load: u8,
    },
    StressMemory {
        workers: u32,
        size: String,
    },
}

impl FaultInjectionParameters {
    pub fn resolve_for_kind(&self, kind: FaultKind) -> Result<Self> {
        let resolved = if matches!(self, Self::Default) {
            Self::default_for_kind(kind)
        } else {
            self.clone()
        };
        resolved.validate_for_kind(kind)?;
        Ok(resolved)
    }

    pub fn validate_for_scenario(&self, scenario: &str) -> Result<()> {
        if matches!(self, Self::Default) {
            return Ok(());
        }
        let kind = match scenario {
            IO_LATENCY_SCENARIO => FaultKind::RustfsVolumeLatency,
            NETWORK_DELAY_SCENARIO => FaultKind::RustfsServerNetworkDelay,
            NETWORK_LOSS_SCENARIO => FaultKind::RustfsServerNetworkLoss,
            NETWORK_CORRUPT_SCENARIO => FaultKind::RustfsServerNetworkCorrupt,
            NETWORK_DUPLICATE_SCENARIO => FaultKind::RustfsServerNetworkDuplicate,
            STRESS_CPU_SCENARIO => FaultKind::RustfsServerCpuStress,
            STRESS_MEMORY_SCENARIO => FaultKind::RustfsServerMemoryStress,
            _ => bail!("scenario {scenario:?} does not support typed params yet"),
        };
        self.validate_for_kind(kind)
    }

    pub fn io_latency(&self) -> Result<(String, Vec<String>)> {
        match self {
            Self::IoLatency { delay, methods } => Ok((
                delay.clone(),
                methods
                    .iter()
                    .map(|method| method.as_chaos_mesh_method().to_string())
                    .collect(),
            )),
            other => bail!("expected ioLatency parameters, got {:?}", other),
        }
    }

    pub fn network_delay(&self) -> Result<(String, String, u8)> {
        match self {
            Self::NetworkDelay {
                latency,
                jitter,
                correlation_percent,
            } => Ok((latency.clone(), jitter.clone(), *correlation_percent)),
            other => bail!("expected networkDelay parameters, got {:?}", other),
        }
    }

    pub fn network_loss(&self) -> Result<(u8, u8)> {
        match self {
            Self::NetworkLoss {
                loss_percent,
                correlation_percent,
            } => Ok((*loss_percent, *correlation_percent)),
            other => bail!("expected networkLoss parameters, got {:?}", other),
        }
    }

    pub fn network_corrupt(&self) -> Result<(u8, u8)> {
        match self {
            Self::NetworkCorrupt {
                corrupt_percent,
                correlation_percent,
            } => Ok((*corrupt_percent, *correlation_percent)),
            other => bail!("expected networkCorrupt parameters, got {:?}", other),
        }
    }

    pub fn network_duplicate(&self) -> Result<(u8, u8)> {
        match self {
            Self::NetworkDuplicate {
                duplicate_percent,
                correlation_percent,
            } => Ok((*duplicate_percent, *correlation_percent)),
            other => bail!("expected networkDuplicate parameters, got {:?}", other),
        }
    }

    pub fn stress_cpu(&self) -> Result<(u32, u8)> {
        match self {
            Self::StressCpu { workers, load } => Ok((*workers, *load)),
            other => bail!("expected stressCpu parameters, got {:?}", other),
        }
    }

    pub fn stress_memory(&self) -> Result<(u32, String)> {
        match self {
            Self::StressMemory { workers, size } => Ok((*workers, size.clone())),
            other => bail!("expected stressMemory parameters, got {:?}", other),
        }
    }

    fn default_for_kind(kind: FaultKind) -> Self {
        match kind {
            FaultKind::RustfsVolumeLatency => Self::IoLatency {
                delay: "250ms".to_string(),
                methods: vec![IoMethod::Read, IoMethod::Write],
            },
            FaultKind::RustfsServerNetworkDelay => Self::NetworkDelay {
                latency: "200ms".to_string(),
                jitter: "50ms".to_string(),
                correlation_percent: 25,
            },
            FaultKind::RustfsServerNetworkLoss => Self::NetworkLoss {
                loss_percent: 25,
                correlation_percent: 25,
            },
            FaultKind::RustfsServerNetworkCorrupt => Self::NetworkCorrupt {
                corrupt_percent: 5,
                correlation_percent: 25,
            },
            FaultKind::RustfsServerNetworkDuplicate => Self::NetworkDuplicate {
                duplicate_percent: 10,
                correlation_percent: 25,
            },
            FaultKind::RustfsServerCpuStress => Self::StressCpu {
                workers: 1,
                load: 80,
            },
            FaultKind::RustfsServerMemoryStress => Self::StressMemory {
                workers: 1,
                size: "512MiB".to_string(),
            },
            _ => Self::Default,
        }
    }

    fn validate_for_kind(&self, kind: FaultKind) -> Result<()> {
        match (kind, self) {
            (_, Self::Default) => Ok(()),
            (FaultKind::RustfsVolumeLatency, Self::IoLatency { delay, methods }) => {
                validate_duration_token("params.delay", delay, false, 60_000)?;
                validate_io_methods(methods)?;
                Ok(())
            }
            (
                FaultKind::RustfsServerNetworkDelay,
                Self::NetworkDelay {
                    latency,
                    jitter,
                    correlation_percent,
                },
            ) => {
                validate_duration_token("params.latency", latency, false, 60_000)?;
                validate_duration_token("params.jitter", jitter, true, 60_000)?;
                validate_correlation(*correlation_percent)?;
                Ok(())
            }
            (
                FaultKind::RustfsServerNetworkLoss,
                Self::NetworkLoss {
                    loss_percent,
                    correlation_percent,
                },
            ) => {
                validate_percent("params.lossPercent", *loss_percent)?;
                validate_correlation(*correlation_percent)?;
                Ok(())
            }
            (
                FaultKind::RustfsServerNetworkCorrupt,
                Self::NetworkCorrupt {
                    corrupt_percent,
                    correlation_percent,
                },
            ) => {
                validate_percent("params.corruptPercent", *corrupt_percent)?;
                validate_correlation(*correlation_percent)?;
                Ok(())
            }
            (
                FaultKind::RustfsServerNetworkDuplicate,
                Self::NetworkDuplicate {
                    duplicate_percent,
                    correlation_percent,
                },
            ) => {
                validate_percent("params.duplicatePercent", *duplicate_percent)?;
                validate_correlation(*correlation_percent)?;
                Ok(())
            }
            (FaultKind::RustfsServerCpuStress, Self::StressCpu { workers, load }) => {
                validate_workers(*workers)?;
                ensure!(
                    (1..=100).contains(load),
                    "params.load must be between 1 and 100"
                );
                Ok(())
            }
            (FaultKind::RustfsServerMemoryStress, Self::StressMemory { workers, size }) => {
                validate_workers(*workers)?;
                validate_memory_size(size)?;
                Ok(())
            }
            _ => bail!(
                "parameters kind {:?} is not supported by fault kind {}",
                self,
                kind.as_str()
            ),
        }
    }
}

fn validate_io_methods(methods: &[IoMethod]) -> Result<()> {
    ensure!(!methods.is_empty(), "params.methods must not be empty");
    let unique = methods.iter().copied().collect::<BTreeSet<_>>();
    ensure!(
        unique.len() == methods.len(),
        "params.methods must not contain duplicates"
    );
    Ok(())
}

fn validate_duration_token(field: &str, value: &str, allow_zero: bool, max_ms: u64) -> Result<u64> {
    let value = value.trim();
    ensure!(!value.is_empty(), "{field} must not be empty");
    let (digits, multiplier) = if let Some(digits) = value.strip_suffix("ms") {
        (digits, 1)
    } else if let Some(digits) = value.strip_suffix('s') {
        (digits, 1_000)
    } else {
        bail!("{field} must use ms or s units, got {value:?}");
    };
    let amount = digits
        .parse::<u64>()
        .map_err(|error| anyhow::anyhow!("parse {field} {value:?}: {error}"))?;
    ensure!(
        allow_zero || amount > 0,
        "{field} must be greater than zero"
    );
    let millis = amount
        .checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("{field} overflowed"))?;
    ensure!(millis <= max_ms, "{field} must be <= {max_ms}ms");
    Ok(millis)
}

fn validate_percent(field: &str, value: u8) -> Result<()> {
    ensure!(
        (1..=100).contains(&value),
        "{field} must be between 1 and 100"
    );
    Ok(())
}

fn validate_correlation(value: u8) -> Result<()> {
    ensure!(
        value <= 100,
        "params.correlationPercent must be between 0 and 100"
    );
    Ok(())
}

fn validate_workers(value: u32) -> Result<()> {
    ensure!(
        (1..=16).contains(&value),
        "params.workers must be between 1 and 16"
    );
    Ok(())
}

fn validate_memory_size(value: &str) -> Result<()> {
    let value = value.trim();
    let mib = if let Some(amount) = value.strip_suffix("MiB") {
        amount
            .parse::<u64>()
            .map_err(|error| anyhow::anyhow!("parse params.size {value:?}: {error}"))?
    } else if let Some(amount) = value.strip_suffix("GiB") {
        amount
            .parse::<u64>()
            .map_err(|error| anyhow::anyhow!("parse params.size {value:?}: {error}"))?
            .checked_mul(1024)
            .ok_or_else(|| anyhow::anyhow!("params.size overflowed"))?
    } else {
        bail!("params.size must use MiB or GiB units, got {value:?}");
    };
    ensure!(
        (64..=8192).contains(&mib),
        "params.size must be between 64MiB and 8192MiB"
    );
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultInjection {
    kind: FaultKind,
    backend: FaultBackend,
    target: FaultTarget,
    selection: FaultSelection,
    duration: Duration,
    parameters: FaultInjectionParameters,
}

impl FaultInjection {
    pub fn new(
        kind: FaultKind,
        backend: FaultBackend,
        target: FaultTarget,
        selection: FaultSelection,
        duration: Duration,
    ) -> Result<Self> {
        Self::new_with_parameters(
            kind,
            backend,
            target,
            selection,
            duration,
            FaultInjectionParameters::Default,
        )
    }

    pub fn new_with_parameters(
        kind: FaultKind,
        backend: FaultBackend,
        target: FaultTarget,
        selection: FaultSelection,
        duration: Duration,
        parameters: FaultInjectionParameters,
    ) -> Result<Self> {
        ensure!(
            fault_kind_accepts_backend(kind, backend),
            "fault kind {} cannot run with backend {:?}",
            kind.as_str(),
            backend
        );
        ensure!(
            fault_kind_accepts_selection(kind, selection),
            "fault kind {} cannot run with selection {:?}",
            kind.as_str(),
            selection
        );
        ensure!(
            fault_kind_accepts_target(kind, &target),
            "fault kind {} cannot run with target {:?}",
            kind.as_str(),
            target
        );
        if let FaultTarget::RustfsVolume { path } = &target {
            validate_rustfs_volume_path(path)?;
        }
        ensure!(duration > Duration::ZERO, "fault duration must be positive");
        let parameters = parameters.resolve_for_kind(kind)?;

        Ok(Self {
            kind,
            backend,
            target,
            selection,
            duration,
            parameters,
        })
    }

    pub fn kind(&self) -> FaultKind {
        self.kind
    }

    pub fn backend(&self) -> FaultBackend {
        self.backend
    }

    pub fn target(&self) -> &FaultTarget {
        &self.target
    }

    pub fn selection(&self) -> FaultSelection {
        self.selection
    }

    pub fn percent(&self) -> Result<u8> {
        match self.selection {
            FaultSelection::Percent(percent) => Ok(percent),
            other => bail!(
                "fault kind {} requires a percent selection, got {:?}",
                self.kind.as_str(),
                other
            ),
        }
    }

    pub fn duration(&self) -> Duration {
        self.duration
    }

    pub fn parameters(&self) -> &FaultInjectionParameters {
        &self.parameters
    }

    pub fn rustfs_volume_path(&self) -> Result<&str> {
        match &self.target {
            FaultTarget::RustfsVolume { path } => Ok(path),
            other => bail!(
                "fault kind {} requires a RustFS volume target, got {:?}",
                self.kind.as_str(),
                other
            ),
        }
    }
}

fn fault_kind_accepts_backend(kind: FaultKind, backend: FaultBackend) -> bool {
    matches!(
        (kind, backend),
        (
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos | FaultBackend::MinioWarpWithChaos
        ) | (
            FaultKind::RustfsVolumeLatency
                | FaultKind::RustfsVolumeReadMistake
                | FaultKind::RustfsVolumeEnospc,
            FaultBackend::ChaosMeshIoChaos
        ) | (
            FaultKind::RustfsServerPodKill | FaultKind::RustfsServerPodFailure,
            FaultBackend::ChaosMeshPodChaos
        ) | (
            FaultKind::RustfsServerNetworkPartition
                | FaultKind::RustfsServerNetworkDelay
                | FaultKind::RustfsServerNetworkLoss
                | FaultKind::RustfsServerNetworkCorrupt
                | FaultKind::RustfsServerNetworkDuplicate,
            FaultBackend::ChaosMeshNetworkChaos
        ) | (
            FaultKind::RustfsServerCpuStress | FaultKind::RustfsServerMemoryStress,
            FaultBackend::ChaosMeshStressChaos
        ) | (
            FaultKind::RustfsBlockDeviceFlakey,
            FaultBackend::DeviceMapper
        )
    )
}

fn fault_kind_accepts_selection(kind: FaultKind, selection: FaultSelection) -> bool {
    match kind {
        FaultKind::RustfsVolumeIoError
        | FaultKind::RustfsVolumeLatency
        | FaultKind::RustfsVolumeReadMistake
        | FaultKind::RustfsVolumeEnospc => match selection {
            FaultSelection::Percent(percent) => (1..=100).contains(&percent),
            FaultSelection::FixedTargets(_) => false,
        },
        FaultKind::RustfsServerPodKill
        | FaultKind::RustfsServerPodFailure
        | FaultKind::RustfsServerNetworkPartition
        | FaultKind::RustfsServerNetworkDelay
        | FaultKind::RustfsServerNetworkLoss
        | FaultKind::RustfsServerNetworkCorrupt
        | FaultKind::RustfsServerNetworkDuplicate
        | FaultKind::RustfsServerCpuStress
        | FaultKind::RustfsServerMemoryStress
        | FaultKind::RustfsBlockDeviceFlakey => match selection {
            FaultSelection::FixedTargets(count) => count > 0,
            FaultSelection::Percent(_) => false,
        },
    }
}

fn fault_kind_accepts_target(kind: FaultKind, target: &FaultTarget) -> bool {
    match kind {
        FaultKind::RustfsVolumeIoError
        | FaultKind::RustfsVolumeLatency
        | FaultKind::RustfsVolumeReadMistake
        | FaultKind::RustfsVolumeEnospc => matches!(target, FaultTarget::RustfsVolume { .. }),
        FaultKind::RustfsServerPodKill | FaultKind::RustfsServerPodFailure => {
            matches!(target, FaultTarget::RustfsServerPod)
        }
        FaultKind::RustfsServerNetworkPartition
        | FaultKind::RustfsServerNetworkDelay
        | FaultKind::RustfsServerNetworkLoss
        | FaultKind::RustfsServerNetworkCorrupt
        | FaultKind::RustfsServerNetworkDuplicate => {
            matches!(target, FaultTarget::RustfsServerPeerNetwork)
        }
        FaultKind::RustfsServerCpuStress | FaultKind::RustfsServerMemoryStress => {
            matches!(target, FaultTarget::RustfsServerResource)
        }
        FaultKind::RustfsBlockDeviceFlakey => matches!(target, FaultTarget::DedicatedBlockDevice),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPlan {
    pub scenario: String,
    pub case_name: &'static str,
    pub workload_mode: FaultWorkloadMode,
    faults: Vec<FaultInjection>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPlanOptions {
    pub rustfs_volume_path: String,
    pub scenario_parameters: FaultInjectionParameters,
}

impl FaultPlanOptions {
    pub fn from_config(config: &FaultTestConfig) -> Self {
        Self {
            rustfs_volume_path: config.rustfs_volume_path.clone(),
            scenario_parameters: config.scenario_parameters.clone(),
        }
    }
}

impl Default for FaultPlanOptions {
    fn default() -> Self {
        Self {
            rustfs_volume_path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            scenario_parameters: FaultInjectionParameters::Default,
        }
    }
}

impl FaultPlan {
    pub fn new(
        scenario: impl Into<String>,
        case_name: &'static str,
        workload_mode: FaultWorkloadMode,
        faults: Vec<FaultInjection>,
    ) -> Result<Self> {
        ensure!(
            !faults.is_empty(),
            "fault plan must contain at least one fault"
        );
        ensure!(
            faults.len() == 1,
            "composite fault plans require an explicit composition policy before they can be executed safely"
        );

        Ok(Self {
            scenario: scenario.into(),
            case_name,
            workload_mode,
            faults,
        })
    }

    pub fn from_scenario(scenario: &FaultScenario, spec: &FaultScenarioSpec) -> Result<Self> {
        Self::from_scenario_with_options(scenario, spec, FaultPlanOptions::default())
    }

    pub fn from_scenario_with_options(
        scenario: &FaultScenario,
        spec: &FaultScenarioSpec,
        options: FaultPlanOptions,
    ) -> Result<Self> {
        ensure!(
            scenario.name == spec.scenario,
            "fault scenario/spec mismatch: scenario={}, spec={}",
            scenario.name,
            spec.scenario
        );

        let workload_mode = if spec.backend == FaultBackend::MinioWarpWithChaos {
            FaultWorkloadMode::S3MixedWithWarp
        } else {
            FaultWorkloadMode::S3Mixed
        };
        let fault = match scenario.name.as_str() {
            IO_EIO_SCENARIO => volume_fault(
                FaultKind::RustfsVolumeIoError,
                spec,
                scenario,
                &options.rustfs_volume_path,
                &options.scenario_parameters,
            )?,
            POD_KILL_ONE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerPodKill,
                spec.backend,
                FaultTarget::RustfsServerPod,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            POD_FAILURE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerPodFailure,
                spec.backend,
                FaultTarget::RustfsServerPod,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            NETWORK_PARTITION_ONE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerNetworkPartition,
                spec.backend,
                FaultTarget::RustfsServerPeerNetwork,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            NETWORK_DELAY_SCENARIO => network_fault(
                FaultKind::RustfsServerNetworkDelay,
                spec,
                scenario,
                &options.scenario_parameters,
            )?,
            NETWORK_LOSS_SCENARIO => network_fault(
                FaultKind::RustfsServerNetworkLoss,
                spec,
                scenario,
                &options.scenario_parameters,
            )?,
            NETWORK_CORRUPT_SCENARIO => network_fault(
                FaultKind::RustfsServerNetworkCorrupt,
                spec,
                scenario,
                &options.scenario_parameters,
            )?,
            NETWORK_DUPLICATE_SCENARIO => network_fault(
                FaultKind::RustfsServerNetworkDuplicate,
                spec,
                scenario,
                &options.scenario_parameters,
            )?,
            IO_READ_MISTAKE_SCENARIO => volume_fault(
                FaultKind::RustfsVolumeReadMistake,
                spec,
                scenario,
                &options.rustfs_volume_path,
                &options.scenario_parameters,
            )?,
            IO_LATENCY_SCENARIO => volume_fault(
                FaultKind::RustfsVolumeLatency,
                spec,
                scenario,
                &options.rustfs_volume_path,
                &options.scenario_parameters,
            )?,
            DISK_FULL_SCENARIO => volume_fault(
                FaultKind::RustfsVolumeEnospc,
                spec,
                scenario,
                &options.rustfs_volume_path,
                &options.scenario_parameters,
            )?,
            STRESS_CPU_SCENARIO => resource_fault(
                FaultKind::RustfsServerCpuStress,
                spec,
                scenario,
                &options.scenario_parameters,
            )?,
            STRESS_MEMORY_SCENARIO => resource_fault(
                FaultKind::RustfsServerMemoryStress,
                spec,
                scenario,
                &options.scenario_parameters,
            )?,
            DM_FLAKEY_SCENARIO => FaultInjection::new(
                FaultKind::RustfsBlockDeviceFlakey,
                spec.backend,
                FaultTarget::DedicatedBlockDevice,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            WARP_UNDER_CHAOS_SCENARIO => volume_fault(
                FaultKind::RustfsVolumeIoError,
                spec,
                scenario,
                &options.rustfs_volume_path,
                &options.scenario_parameters,
            )?,
            other => bail!("scenario {other:?} has no fault plan mapping"),
        };

        Self::new(
            scenario.name.clone(),
            scenario.case_name,
            workload_mode,
            vec![fault],
        )
    }

    pub fn faults(&self) -> &[FaultInjection] {
        &self.faults
    }

    pub fn required_backends(&self) -> Vec<FaultBackend> {
        let mut backends = Vec::new();
        for fault in &self.faults {
            let backend = fault.backend();
            if !backends.contains(&backend) {
                backends.push(backend);
            }
        }
        backends
    }

    pub fn requires_static_storage(&self) -> bool {
        self.faults
            .iter()
            .any(|fault| fault.backend() == FaultBackend::DeviceMapper)
    }

    pub fn backend_summary(&self) -> String {
        self.required_backends()
            .into_iter()
            .map(|backend| format!("{backend:?}"))
            .collect::<Vec<_>>()
            .join(" + ")
    }

    pub fn target_summary(&self) -> String {
        self.faults
            .iter()
            .map(|fault| {
                format!(
                    "{} via {}",
                    fault.target().summary(),
                    fault.selection().summary()
                )
            })
            .collect::<Vec<_>>()
            .join(" + ")
    }
}

fn volume_fault(
    kind: FaultKind,
    spec: &FaultScenarioSpec,
    scenario: &FaultScenario,
    volume_path: &str,
    parameters: &FaultInjectionParameters,
) -> Result<FaultInjection> {
    FaultInjection::new_with_parameters(
        kind,
        spec.backend,
        FaultTarget::RustfsVolume {
            path: volume_path.to_string(),
        },
        FaultSelection::Percent(scenario.percent),
        scenario.duration,
        parameters.resolve_for_kind(kind)?,
    )
}

fn network_fault(
    kind: FaultKind,
    spec: &FaultScenarioSpec,
    scenario: &FaultScenario,
    parameters: &FaultInjectionParameters,
) -> Result<FaultInjection> {
    FaultInjection::new_with_parameters(
        kind,
        spec.backend,
        FaultTarget::RustfsServerPeerNetwork,
        FaultSelection::FixedTargets(1),
        scenario.duration,
        parameters.resolve_for_kind(kind)?,
    )
}

fn resource_fault(
    kind: FaultKind,
    spec: &FaultScenarioSpec,
    scenario: &FaultScenario,
    parameters: &FaultInjectionParameters,
) -> Result<FaultInjection> {
    FaultInjection::new_with_parameters(
        kind,
        spec.backend,
        FaultTarget::RustfsServerResource,
        FaultSelection::FixedTargets(1),
        scenario.duration,
        parameters.resolve_for_kind(kind)?,
    )
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_RUSTFS_DATA_VOLUME, FaultInjection, FaultInjectionParameters, FaultKind, FaultPlan,
        FaultSelection, FaultTarget, FaultWorkloadMode,
    };
    use crate::fault::{
        config::FaultTestConfig,
        scenarios::{
            FaultBackend, FaultScenario, WARP_UNDER_CHAOS_SCENARIO, scenario_catalog, scenario_spec,
        },
    };
    use std::time::Duration;

    #[test]
    fn scenario_plan_maps_io_eio_to_rustfs_volume_fault() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");

        let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");

        assert_eq!(plan.workload_mode, FaultWorkloadMode::S3Mixed);
        assert_eq!(
            plan.required_backends(),
            vec![FaultBackend::ChaosMeshIoChaos]
        );
        assert_eq!(plan.faults().len(), 1);
        assert_eq!(plan.faults()[0].kind(), FaultKind::RustfsVolumeIoError);
        assert_eq!(
            plan.faults()[0].target(),
            &FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string()
            }
        );
    }

    #[test]
    fn warp_scenario_keeps_performance_mode_out_of_fault_kind() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = WARP_UNDER_CHAOS_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");

        let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");

        assert!(plan.workload_mode.runs_warp());
        assert_eq!(plan.faults()[0].kind(), FaultKind::RustfsVolumeIoError);
        assert_eq!(
            plan.required_backends(),
            vec![FaultBackend::MinioWarpWithChaos]
        );
    }

    #[test]
    fn every_cataloged_scenario_has_one_current_fault_plan() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");

        for spec in scenario_catalog() {
            config.scenario = spec.scenario.to_string();
            let scenario = FaultScenario::from_config(&config).expect("scenario");
            let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");

            assert_eq!(
                plan.faults().len(),
                1,
                "{} should remain an independent single-fault scenario",
                spec.scenario
            );
        }
    }

    #[test]
    fn plan_rejects_multi_faults_without_composition_policy() {
        let first = FaultInjection::new(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            },
            FaultSelection::Percent(20),
            Duration::from_secs(60),
        )
        .expect("first fault");
        let second = FaultInjection::new(
            FaultKind::RustfsServerNetworkPartition,
            FaultBackend::ChaosMeshNetworkChaos,
            FaultTarget::RustfsServerPeerNetwork,
            FaultSelection::FixedTargets(1),
            Duration::from_secs(60),
        )
        .expect("second fault");

        let result = FaultPlan::new(
            "composite",
            "fault_composite",
            FaultWorkloadMode::S3Mixed,
            vec![first, second],
        );

        assert!(result.is_err());
    }

    #[test]
    fn fault_injection_rejects_backend_kind_mismatch() {
        let result = FaultInjection::new(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshNetworkChaos,
            FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            },
            FaultSelection::Percent(20),
            Duration::from_secs(60),
        );

        assert!(result.is_err());
    }

    #[test]
    fn fault_injection_new_resolves_default_parameters_for_parameterized_kind() {
        let injection = FaultInjection::new(
            FaultKind::RustfsServerNetworkDelay,
            FaultBackend::ChaosMeshNetworkChaos,
            FaultTarget::RustfsServerPeerNetwork,
            FaultSelection::FixedTargets(1),
            Duration::from_secs(60),
        )
        .expect("network delay fault");

        assert_eq!(
            injection.parameters(),
            &FaultInjectionParameters::NetworkDelay {
                latency: "200ms".to_string(),
                jitter: "50ms".to_string(),
                correlation_percent: 25,
            }
        );
    }

    #[test]
    fn fixed_target_faults_reject_percent_selection() {
        let result = FaultInjection::new(
            FaultKind::RustfsServerPodKill,
            FaultBackend::ChaosMeshPodChaos,
            FaultTarget::RustfsServerPod,
            FaultSelection::Percent(20),
            Duration::from_secs(60),
        );

        assert!(result.is_err());
    }

    #[test]
    fn fault_injection_rejects_kind_target_mismatch() {
        let result = FaultInjection::new(
            FaultKind::RustfsServerPodKill,
            FaultBackend::ChaosMeshPodChaos,
            FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            },
            FaultSelection::FixedTargets(1),
            Duration::from_secs(60),
        );

        assert!(result.is_err());
    }
}
