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
use std::time::Duration;

use crate::fault::{
    admin_topology::{AdminTopologyKind, AdminTopologyPlan},
    config::{DEFAULT_RUSTFS_VOLUME_PATH, FaultTestConfig, validate_rustfs_volume_path},
    quorum::{ErasureSetShape, MAX_ERASURE_SET_SHARDS, QuorumCaseClass, QuorumVolumeBoundary},
    scenarios::{
        ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO, CLUSTER_COLD_RESTART_SCENARIO,
        DISK_FULL_SCENARIO, DM_DROP_WRITES_AFTER_ACK_DELETE_MARKER_SCENARIO,
        DM_DROP_WRITES_AFTER_ACK_MULTIPART_COMPLETE_SCENARIO,
        DM_DROP_WRITES_AFTER_ACK_OVERWRITE_SCENARIO, DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO,
        DM_DROP_WRITES_AFTER_ACK_ZERO_BYTE_PUT_SCENARIO, DM_FLAKEY_SCENARIO,
        DM_FLAKEY_VERSIONED_HOT_SCENARIO, FRESH_VOLUME_REPLACEMENT_SCENARIO, FaultBackend,
        FaultParameterSchema, FaultScenario, FaultScenarioSpec, IO_EIO_SCENARIO,
        IO_LATENCY_SCENARIO, IO_READ_MISTAKE_SCENARIO, NETWORK_CORRUPT_SCENARIO,
        NETWORK_DELAY_SCENARIO, NETWORK_DUPLICATE_SCENARIO, NETWORK_LOSS_SCENARIO,
        NETWORK_PARTITION_ONE_SCENARIO, NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
        NODE_CRASH_PROXY_SCENARIO, ON_DISK_BITROT_SCENARIO, POD_CRASH_VERSIONED_HOT_SCENARIO,
        POD_FAILURE_QUORUM_EDGE_SCENARIO, POD_FAILURE_SCENARIO, POD_GRACEFUL_RESTART_ONE_SCENARIO,
        POD_KILL_ONE_SCENARIO, QUORUM_P_IO_FAULT_SCENARIO, QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
        ROLLING_RESTART_ALL_SCENARIO, STALE_DISK_RETURN_DETECT_SCENARIO, STRESS_CPU_SCENARIO,
        STRESS_MEMORY_SCENARIO, WARP_UNDER_CHAOS_SCENARIO, scenario_spec,
    },
    storage_recovery::StorageRecoveryCase,
};

pub const DEFAULT_RUSTFS_DATA_VOLUME: &str = DEFAULT_RUSTFS_VOLUME_PATH;

/// Pod count the write-quorum-loss partition isolates. Meaningful only on the
/// runtime-proven tenant topology (4 symmetric servers in one erasure set):
/// isolating 2 of 4 servers removes half the drives, so the data+1 write quorum
/// is unreachable while the data read quorum can still be served by the
/// surviving half. The runner preflight derives exact shard counts and rejects
/// other topologies instead of letting the count silently lose that meaning.
pub const WRITE_QUORUM_LOSS_PARTITION_TARGETS: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultWorkloadMode {
    S3Mixed,
    S3MixedWithWarp,
    AckTriggeredQuietMutation,
}

/// The top-level execution route for a fault-test scenario.
///
/// `FaultPlan` remains the injection contract. Admin reliability cases use a
/// distinct plan so neither the runner nor persisted artifacts need to invent
/// a no-op fault merely to enter the common test lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionPlan {
    Injection(FaultPlan),
    Admin(AdminExecutionPlan),
    StorageRecovery(StorageRecoveryExecutionPlan),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExecutionKind {
    Injection,
    Admin,
    StorageRecovery,
}

impl ExecutionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Injection => "injection",
            Self::Admin => "admin",
            Self::StorageRecovery => "storage-recovery",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminExecutionPlan {
    pub scenario: String,
    pub case_name: &'static str,
    pub workload_mode: FaultWorkloadMode,
    pub operation_timeout: Duration,
    pub topology: AdminTopologyPlan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRecoveryExecutionPlan {
    pub scenario: String,
    pub case_name: &'static str,
    pub workload_mode: FaultWorkloadMode,
    pub operation_timeout: Duration,
    pub case: StorageRecoveryCase,
}

impl ExecutionPlan {
    pub fn from_scenario_with_options(
        scenario: &FaultScenario,
        spec: &FaultScenarioSpec,
        options: FaultPlanOptions,
    ) -> Result<Self> {
        match scenario.name.as_str() {
            FRESH_VOLUME_REPLACEMENT_SCENARIO
            | ON_DISK_BITROT_SCENARIO
            | STALE_DISK_RETURN_DETECT_SCENARIO => {
                ensure!(
                    spec.backend == FaultBackend::PlannedReliabilityWorkflow,
                    "storage-recovery scenario {} must use the planned reliability workflow backend",
                    scenario.name
                );
                ensure!(
                    matches!(
                        options.scenario_parameters,
                        FaultInjectionParameters::Default
                    ),
                    "storage-recovery scenario {} does not accept fault-injection parameters",
                    scenario.name
                );
                let case = options.storage_recovery_case.context(
                    "RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE is required for planned storage qualification",
                )?;
                ensure!(
                    case.scenario() == scenario.name,
                    "storage-recovery case {} does not belong to scenario {}",
                    case.as_str(),
                    scenario.name
                );
                Ok(Self::StorageRecovery(StorageRecoveryExecutionPlan {
                    scenario: scenario.name.clone(),
                    case_name: scenario.case_name,
                    workload_mode: FaultWorkloadMode::S3Mixed,
                    operation_timeout: scenario.duration,
                    case,
                }))
            }
            ADMIN_DECOMMISSION_SCENARIO | ADMIN_REBALANCE_SCENARIO => {
                ensure!(
                    spec.backend == FaultBackend::PlannedReliabilityWorkflow,
                    "admin scenario {} must use the planned reliability workflow backend",
                    scenario.name
                );
                ensure!(
                    scenario.name == spec.scenario,
                    "admin scenario/spec mismatch: scenario={}, spec={}",
                    scenario.name,
                    spec.scenario
                );
                ensure!(
                    matches!(
                        options.scenario_parameters,
                        FaultInjectionParameters::Default
                    ),
                    "admin scenario {} does not accept fault-injection parameters",
                    scenario.name
                );
                Ok(Self::Admin(AdminExecutionPlan {
                    scenario: scenario.name.clone(),
                    case_name: scenario.case_name,
                    workload_mode: FaultWorkloadMode::S3Mixed,
                    operation_timeout: scenario.duration,
                    topology: AdminTopologyPlan::for_scenario(&scenario.name)?,
                }))
            }
            _ => {
                FaultPlan::from_scenario_with_options(scenario, spec, options).map(Self::Injection)
            }
        }
    }

    pub fn kind(&self) -> ExecutionKind {
        match self {
            Self::Injection(_) => ExecutionKind::Injection,
            Self::Admin(_) => ExecutionKind::Admin,
            Self::StorageRecovery(_) => ExecutionKind::StorageRecovery,
        }
    }

    pub fn scenario(&self) -> &str {
        match self {
            Self::Injection(plan) => &plan.scenario,
            Self::Admin(plan) => &plan.scenario,
            Self::StorageRecovery(plan) => &plan.scenario,
        }
    }

    pub fn case_name(&self) -> &'static str {
        match self {
            Self::Injection(plan) => plan.case_name,
            Self::Admin(plan) => plan.case_name,
            Self::StorageRecovery(plan) => plan.case_name,
        }
    }

    pub fn workload_mode(&self) -> FaultWorkloadMode {
        match self {
            Self::Injection(plan) => plan.workload_mode,
            Self::Admin(plan) => plan.workload_mode,
            Self::StorageRecovery(plan) => plan.workload_mode,
        }
    }

    pub fn injection(&self) -> Option<&FaultPlan> {
        match self {
            Self::Injection(plan) => Some(plan),
            Self::Admin(_) | Self::StorageRecovery(_) => None,
        }
    }

    pub fn admin(&self) -> Option<&AdminExecutionPlan> {
        match self {
            Self::Injection(_) => None,
            Self::Admin(plan) => Some(plan),
            Self::StorageRecovery(_) => None,
        }
    }

    pub fn storage_recovery(&self) -> Option<&StorageRecoveryExecutionPlan> {
        match self {
            Self::StorageRecovery(plan) => Some(plan),
            Self::Injection(_) | Self::Admin(_) => None,
        }
    }

    pub fn requires_static_storage(&self) -> bool {
        matches!(self, Self::StorageRecovery(_))
            || self
                .injection()
                .is_some_and(FaultPlan::requires_static_storage)
    }

    pub fn backend_summary(&self) -> String {
        match self {
            Self::Injection(plan) => plan.backend_summary(),
            Self::Admin(_) | Self::StorageRecovery(_) => FaultBackend::PlannedReliabilityWorkflow
                .as_str()
                .to_string(),
        }
    }

    pub fn target_summary(&self) -> String {
        match self {
            Self::Injection(plan) => plan.target_summary(),
            Self::Admin(plan) => match plan.topology.kind {
                AdminTopologyKind::Decommission => format!(
                    "owned admin pool {}",
                    plan.topology
                        .target_pool_name
                        .as_deref()
                        .expect("decommission plan has a target pool")
                ),
                AdminTopologyKind::Rebalance => "owned two-pool admin topology".to_string(),
            },
            Self::StorageRecovery(plan) => {
                format!("owned storage recovery case {}", plan.case.as_str())
            }
        }
    }
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
    RustfsBlockDeviceDropWritesCrash,
    RustfsServerPodGracefulRestart,
    RustfsServerRollingRestart,
    RustfsServerColdRestart,
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
            Self::RustfsBlockDeviceDropWritesCrash => "rustfs_block_device_drop_writes_crash",
            Self::RustfsServerPodGracefulRestart => "rustfs_server_pod_graceful_restart",
            Self::RustfsServerRollingRestart => "rustfs_server_rolling_restart",
            Self::RustfsServerColdRestart => "rustfs_server_cold_restart",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultTarget {
    RustfsVolume {
        path: String,
    },
    RustfsServerPod,
    RustfsServerPeerNetwork,
    RustfsServerResource,
    DedicatedBlockDevice,
    /// The whole Tenant StatefulSet: every RustFS server Pod in turn or at
    /// once. Plans select it as `FixedTargets(1)`, meaning one StatefulSet;
    /// the Pod set is proven live from that StatefulSet at apply time.
    RustfsServerStatefulSet,
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
            Self::RustfsServerStatefulSet => {
                "every RustFS server Pod of the Tenant StatefulSet".to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultSelection {
    Percent(u8),
    FixedTargets(u32),
    RuntimeQuorum(QuorumVolumeBoundary),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeTargetSelection {
    One,
    FixedTargets(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VolumeFaultTargeting {
    pub target_selection: VolumeTargetSelection,
    pub io_sampling_percent: u8,
}

impl VolumeFaultTargeting {
    fn from_legacy_selection(selection: FaultSelection) -> Self {
        match selection {
            FaultSelection::Percent(percent) => Self {
                target_selection: VolumeTargetSelection::One,
                io_sampling_percent: percent,
            },
            FaultSelection::FixedTargets(count) => Self {
                target_selection: VolumeTargetSelection::FixedTargets(count),
                io_sampling_percent: 100,
            },
            FaultSelection::RuntimeQuorum(_) => {
                unreachable!("runtime quorum selection must be resolved before rendering")
            }
        }
    }
}

impl FaultSelection {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Percent(_) => "percent",
            Self::FixedTargets(_) => "fixed-targets",
            Self::RuntimeQuorum(_) => "runtime-quorum",
        }
    }

    pub fn value(self) -> u32 {
        match self {
            Self::Percent(percent) => u32::from(percent),
            Self::FixedTargets(count) => count,
            Self::RuntimeQuorum(boundary) => u32::from(boundary.beyond_read_tolerance),
        }
    }

    pub fn summary(self) -> String {
        match self {
            Self::Percent(percent) => format!("{percent}%"),
            Self::FixedTargets(count) => format!("{count} target(s)"),
            Self::RuntimeQuorum(boundary) => format!(
                "runtime {} read tolerance{}",
                match boundary.class {
                    QuorumCaseClass::Payload => "payload",
                    QuorumCaseClass::Metadata => "metadata",
                },
                if boundary.beyond_read_tolerance {
                    " + 1"
                } else {
                    ""
                }
            ),
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
    QuorumIo {
        class: QuorumCaseClass,
    },
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
        self.validate_for_schema(scenario_spec(scenario)?.param_schema)
    }

    pub fn validate_explicit_for_schema(&self, schema: FaultParameterSchema) -> Result<()> {
        ensure!(
            !matches!(self, Self::Default),
            "params.kind=default is implicit; omit params or set a supported typed params kind"
        );
        self.validate_for_schema(schema)
    }

    pub fn validate_for_schema(&self, schema: FaultParameterSchema) -> Result<()> {
        if matches!(self, Self::Default) {
            return Ok(());
        }
        let kind = match schema {
            FaultParameterSchema::QuorumIo => {
                ensure!(
                    matches!(self, Self::QuorumIo { .. }),
                    "quorum IO scenarios require params.kind=quorumIo"
                );
                return Ok(());
            }
            FaultParameterSchema::IoLatency => FaultKind::RustfsVolumeLatency,
            FaultParameterSchema::NetworkDelay => FaultKind::RustfsServerNetworkDelay,
            FaultParameterSchema::NetworkLoss => FaultKind::RustfsServerNetworkLoss,
            FaultParameterSchema::NetworkCorrupt => FaultKind::RustfsServerNetworkCorrupt,
            FaultParameterSchema::NetworkDuplicate => FaultKind::RustfsServerNetworkDuplicate,
            FaultParameterSchema::StressCpu => FaultKind::RustfsServerCpuStress,
            FaultParameterSchema::StressMemory => FaultKind::RustfsServerMemoryStress,
            FaultParameterSchema::None => bail!("scenario does not support typed params yet"),
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

    pub fn quorum_case(&self) -> Result<QuorumCaseClass> {
        match self {
            Self::QuorumIo { class } => Ok(*class),
            other => bail!("expected quorumIo parameters, got {:?}", other),
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
            (FaultKind::RustfsVolumeIoError, Self::QuorumIo { .. }) => Ok(()),
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
    volume_targeting: Option<VolumeFaultTargeting>,
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
        let volume_targeting = matches!(target, FaultTarget::RustfsVolume { .. })
            .then(|| match selection {
                FaultSelection::RuntimeQuorum(_) => None,
                other => Some(VolumeFaultTargeting::from_legacy_selection(other)),
            })
            .flatten();

        Ok(Self {
            kind,
            backend,
            target,
            selection,
            duration,
            parameters,
            volume_targeting,
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

    pub fn target_summary(&self) -> String {
        match (&self.target, self.selection) {
            (FaultTarget::RustfsVolume { path }, FaultSelection::FixedTargets(count)) => {
                format!("{count} RustFS volume target(s) at {path}")
            }
            (FaultTarget::RustfsVolume { path }, FaultSelection::RuntimeQuorum(boundary)) => {
                format!(
                    "{} at {path}",
                    FaultSelection::RuntimeQuorum(boundary).summary()
                )
            }
            _ => self.target.summary(),
        }
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

    pub fn volume_targeting(&self) -> Result<VolumeFaultTargeting> {
        self.volume_targeting.with_context(|| {
            format!(
                "fault kind {} does not have RustFS volume targeting",
                self.kind.as_str()
            )
        })
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

    pub fn resolve_runtime_quorum(&self, shape: &ErasureSetShape) -> Result<Self> {
        let FaultSelection::RuntimeQuorum(boundary) = self.selection else {
            bail!("fault selection is not a runtime quorum boundary")
        };
        let count = boundary.target_count(shape)?;
        Self::new_with_parameters(
            self.kind,
            self.backend,
            self.target.clone(),
            FaultSelection::FixedTargets(count),
            self.duration,
            self.parameters.clone(),
        )
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
            FaultKind::RustfsBlockDeviceFlakey | FaultKind::RustfsBlockDeviceDropWritesCrash,
            FaultBackend::DeviceMapper
        ) | (
            FaultKind::RustfsServerPodGracefulRestart
                | FaultKind::RustfsServerRollingRestart
                | FaultKind::RustfsServerColdRestart,
            FaultBackend::KubernetesLifecycle
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
            // RustFS supports erasure sets up to 16 shards. Exact candidate
            // availability is proved at preflight and actual selection is
            // proved at runtime, so the typed selector can cover that full
            // supported width without an unrelated eight-target cutoff.
            FaultSelection::FixedTargets(count) => (1..=MAX_ERASURE_SET_SHARDS).contains(&count),
            FaultSelection::RuntimeQuorum(_) => kind == FaultKind::RustfsVolumeIoError,
        },
        // NetworkPartition has its own fixed-count renderer. The cap is a
        // sanity bound, and the topology preconditions (which counts actually
        // break quorum) are enforced by the scenario's runner preflight.
        FaultKind::RustfsServerNetworkPartition => match selection {
            FaultSelection::FixedTargets(count) => (1..=8).contains(&count),
            FaultSelection::Percent(_) => false,
            FaultSelection::RuntimeQuorum(_) => false,
        },
        // PodChaos pod-failure renders the declared count, so the quorum-edge
        // scenario can take P servers offline at the same instant. The cap is
        // a sanity bound; which counts actually cross the quorum boundary is
        // proved by the scenario's runtime topology proof.
        FaultKind::RustfsServerPodFailure => match selection {
            FaultSelection::FixedTargets(count) => (1..=MAX_ERASURE_SET_SHARDS).contains(&count),
            FaultSelection::Percent(_) => false,
            FaultSelection::RuntimeQuorum(_) => false,
        },
        // Every other kind is rendered single-target (`mode: one`) and never
        // reads the count. Accepting FixedTargets(n > 1) here would let a plan
        // declare an n-pod blast radius that the backend silently narrows to
        // one — a weaker fault than requested, i.e. a false sense of coverage.
        FaultKind::RustfsServerPodKill
        | FaultKind::RustfsServerNetworkDelay
        | FaultKind::RustfsServerNetworkLoss
        | FaultKind::RustfsServerNetworkCorrupt
        | FaultKind::RustfsServerNetworkDuplicate
        | FaultKind::RustfsServerCpuStress
        | FaultKind::RustfsServerMemoryStress
        | FaultKind::RustfsBlockDeviceFlakey
        | FaultKind::RustfsBlockDeviceDropWritesCrash => match selection {
            FaultSelection::FixedTargets(count) => count == 1,
            FaultSelection::Percent(_) => false,
            FaultSelection::RuntimeQuorum(_) => false,
        },
        // One Pod, or one whole StatefulSet: the backend proves the exact
        // Pod set at apply time from the live StatefulSet.
        FaultKind::RustfsServerPodGracefulRestart
        | FaultKind::RustfsServerRollingRestart
        | FaultKind::RustfsServerColdRestart => match selection {
            FaultSelection::FixedTargets(count) => count == 1,
            FaultSelection::Percent(_) => false,
            FaultSelection::RuntimeQuorum(_) => false,
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
        FaultKind::RustfsBlockDeviceFlakey | FaultKind::RustfsBlockDeviceDropWritesCrash => {
            matches!(target, FaultTarget::DedicatedBlockDevice)
        }
        FaultKind::RustfsServerPodGracefulRestart => {
            matches!(target, FaultTarget::RustfsServerPod)
        }
        FaultKind::RustfsServerRollingRestart | FaultKind::RustfsServerColdRestart => {
            matches!(target, FaultTarget::RustfsServerStatefulSet)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPlan {
    pub scenario: String,
    pub case_name: &'static str,
    pub workload_mode: FaultWorkloadMode,
    fault: FaultInjection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultPlanOptions {
    pub rustfs_volume_path: String,
    pub scenario_parameters: FaultInjectionParameters,
    pub storage_recovery_case: Option<StorageRecoveryCase>,
}

impl FaultPlanOptions {
    pub fn from_config(config: &FaultTestConfig) -> Self {
        Self {
            rustfs_volume_path: config.rustfs_volume_path.clone(),
            scenario_parameters: config.scenario_parameters.clone(),
            storage_recovery_case: config.storage_recovery_case,
        }
    }
}

impl Default for FaultPlanOptions {
    fn default() -> Self {
        Self {
            rustfs_volume_path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            scenario_parameters: FaultInjectionParameters::Default,
            storage_recovery_case: None,
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
            fault: faults.into_iter().next().expect("validated single fault"),
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

        let workload_mode =
            if crate::fault::scenarios::acknowledged_mutation_kind(&scenario.name).is_some() {
                FaultWorkloadMode::AckTriggeredQuietMutation
            } else if spec.backend == FaultBackend::MinioWarpWithChaos {
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
            POD_KILL_ONE_SCENARIO | POD_CRASH_VERSIONED_HOT_SCENARIO => FaultInjection::new(
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
            POD_FAILURE_QUORUM_EDGE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerPodFailure,
                spec.backend,
                FaultTarget::RustfsServerPod,
                // Same boundary as the write-quorum partition: the runtime
                // proof verifies that failing these servers removes enough
                // shards to break write quorum while preserving read quorum,
                // and any other layout fails closed.
                FaultSelection::FixedTargets(WRITE_QUORUM_LOSS_PARTITION_TARGETS),
                scenario.duration,
            )?,
            NETWORK_PARTITION_ONE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerNetworkPartition,
                spec.backend,
                FaultTarget::RustfsServerPeerNetwork,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerNetworkPartition,
                spec.backend,
                FaultTarget::RustfsServerPeerNetwork,
                // The runtime proof verifies that two of the four symmetric
                // servers remove enough shards to break write quorum while
                // preserving read quorum; other layouts fail closed.
                FaultSelection::FixedTargets(WRITE_QUORUM_LOSS_PARTITION_TARGETS),
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
            DM_FLAKEY_VERSIONED_HOT_SCENARIO
            | NODE_CRASH_PROXY_SCENARIO
            | DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO
            | DM_DROP_WRITES_AFTER_ACK_OVERWRITE_SCENARIO
            | DM_DROP_WRITES_AFTER_ACK_DELETE_MARKER_SCENARIO
            | DM_DROP_WRITES_AFTER_ACK_ZERO_BYTE_PUT_SCENARIO
            | DM_DROP_WRITES_AFTER_ACK_MULTIPART_COMPLETE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsBlockDeviceDropWritesCrash,
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
            QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO => {
                let parameters = match options.scenario_parameters {
                    FaultInjectionParameters::Default => FaultInjectionParameters::QuorumIo {
                        class: QuorumCaseClass::Payload,
                    },
                    ref parameters => parameters.clone(),
                };
                let class = parameters.quorum_case()?;
                FaultInjection::new_with_parameters(
                    FaultKind::RustfsVolumeIoError,
                    spec.backend,
                    FaultTarget::RustfsVolume {
                        path: options.rustfs_volume_path.clone(),
                    },
                    FaultSelection::RuntimeQuorum(QuorumVolumeBoundary {
                        class,
                        beyond_read_tolerance: scenario.name == QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
                    }),
                    scenario.duration,
                    parameters,
                )?
            }
            POD_GRACEFUL_RESTART_ONE_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerPodGracefulRestart,
                spec.backend,
                FaultTarget::RustfsServerPod,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            ROLLING_RESTART_ALL_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerRollingRestart,
                spec.backend,
                FaultTarget::RustfsServerStatefulSet,
                FaultSelection::FixedTargets(1),
                scenario.duration,
            )?,
            CLUSTER_COLD_RESTART_SCENARIO => FaultInjection::new(
                FaultKind::RustfsServerColdRestart,
                spec.backend,
                FaultTarget::RustfsServerStatefulSet,
                FaultSelection::FixedTargets(1),
                scenario.duration,
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

    pub fn fault(&self) -> &FaultInjection {
        &self.fault
    }

    pub fn faults(&self) -> &[FaultInjection] {
        std::slice::from_ref(&self.fault)
    }

    pub fn required_backends(&self) -> Vec<FaultBackend> {
        vec![self.fault.backend()]
    }

    pub fn requires_static_storage(&self) -> bool {
        self.fault.backend() == FaultBackend::DeviceMapper
    }

    pub fn backend_summary(&self) -> String {
        format!("{:?}", self.fault.backend())
    }

    pub fn target_summary(&self) -> String {
        format!(
            "{} via {}",
            self.fault.target_summary(),
            self.fault.selection().summary()
        )
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
        DEFAULT_RUSTFS_DATA_VOLUME, ExecutionKind, ExecutionPlan, FaultInjection,
        FaultInjectionParameters, FaultKind, FaultPlan, FaultPlanOptions, FaultSelection,
        FaultTarget, FaultWorkloadMode,
    };
    use crate::fault::{
        config::FaultTestConfig,
        quorum::{ErasureSetShape, QuorumCaseClass, QuorumVolumeBoundary},
        scenarios::{
            ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_DELETE_MARKER_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_MULTIPART_COMPLETE_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_OVERWRITE_SCENARIO, DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_ZERO_BYTE_PUT_SCENARIO, DM_FLAKEY_VERSIONED_HOT_SCENARIO,
            FaultBackend, FaultParameterSchema, FaultScenario, WARP_UNDER_CHAOS_SCENARIO,
            executable_scenario_catalog, scenario_spec,
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
    fn lifecycle_scenarios_map_to_the_kubectl_backend_and_statefulset_targets() {
        use crate::fault::scenarios::{
            CLUSTER_COLD_RESTART_SCENARIO, POD_GRACEFUL_RESTART_ONE_SCENARIO,
            ROLLING_RESTART_ALL_SCENARIO,
        };
        for (name, kind, target) in [
            (
                POD_GRACEFUL_RESTART_ONE_SCENARIO,
                FaultKind::RustfsServerPodGracefulRestart,
                FaultTarget::RustfsServerPod,
            ),
            (
                ROLLING_RESTART_ALL_SCENARIO,
                FaultKind::RustfsServerRollingRestart,
                FaultTarget::RustfsServerStatefulSet,
            ),
            (
                CLUSTER_COLD_RESTART_SCENARIO,
                FaultKind::RustfsServerColdRestart,
                FaultTarget::RustfsServerStatefulSet,
            ),
        ] {
            let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
            config.scenario = name.to_string();
            let scenario = FaultScenario::from_config(&config).expect("scenario");
            let spec = scenario_spec(name).expect("spec");
            let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");
            assert_eq!(plan.workload_mode, FaultWorkloadMode::S3Mixed, "{name}");
            assert_eq!(
                plan.required_backends(),
                vec![FaultBackend::KubernetesLifecycle],
                "{name}"
            );
            assert!(!plan.requires_static_storage());
            assert_eq!(plan.faults()[0].kind(), kind, "{name}");
            assert_eq!(plan.faults()[0].target(), &target, "{name}");
            assert_eq!(
                plan.faults()[0].selection(),
                FaultSelection::FixedTargets(1)
            );
            // Lifecycle kinds never run through a Chaos Mesh backend or with a
            // blast radius other than the proven StatefulSet.
            assert!(
                FaultInjection::new(
                    kind,
                    FaultBackend::ChaosMeshPodChaos,
                    target.clone(),
                    FaultSelection::FixedTargets(1),
                    Duration::from_secs(60),
                )
                .is_err()
            );
            assert!(
                FaultInjection::new(
                    kind,
                    FaultBackend::KubernetesLifecycle,
                    target,
                    FaultSelection::Percent(100),
                    Duration::from_secs(60),
                )
                .is_err()
            );
        }
        assert!(
            FaultInjection::new(
                FaultKind::RustfsServerRollingRestart,
                FaultBackend::KubernetesLifecycle,
                FaultTarget::RustfsServerPod,
                FaultSelection::FixedTargets(1),
                Duration::from_secs(60),
            )
            .is_err()
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
    fn versioned_dm_scenario_uses_drop_writes_crash_semantics() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = DM_FLAKEY_VERSIONED_HOT_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");

        let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");

        assert_eq!(
            plan.faults()[0].kind(),
            FaultKind::RustfsBlockDeviceDropWritesCrash
        );
        assert_eq!(plan.required_backends(), vec![FaultBackend::DeviceMapper]);
    }

    #[test]
    fn ack_triggered_cases_share_one_typed_backend_plan() {
        let mut config = FaultTestConfig::for_test("real-cluster", "rustfs-fault-dm");
        for name in [
            DM_DROP_WRITES_AFTER_ACK_PUT_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_OVERWRITE_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_DELETE_MARKER_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_ZERO_BYTE_PUT_SCENARIO,
            DM_DROP_WRITES_AFTER_ACK_MULTIPART_COMPLETE_SCENARIO,
        ] {
            config.scenario = name.to_string();
            let scenario = FaultScenario::from_config(&config).expect("scenario");
            let spec = scenario_spec(name).expect("spec");
            let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");

            assert_eq!(
                plan.workload_mode,
                FaultWorkloadMode::AckTriggeredQuietMutation
            );
            assert_eq!(plan.required_backends(), vec![FaultBackend::DeviceMapper]);
            assert_eq!(
                plan.faults()[0].kind(),
                FaultKind::RustfsBlockDeviceDropWritesCrash
            );
            assert_eq!(
                plan.faults()[0].selection(),
                FaultSelection::FixedTargets(1)
            );
            assert_eq!(
                plan.faults()[0].parameters(),
                &FaultInjectionParameters::Default,
                "{name} must not encode its mutation kind in backend parameters"
            );
        }
    }

    #[test]
    fn every_cataloged_scenario_has_one_current_fault_plan() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");

        for spec in executable_scenario_catalog() {
            config.scenario = spec.scenario.to_string();
            let scenario = FaultScenario::from_config(&config).expect("scenario");
            let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan");

            assert_eq!(
                plan.faults().len(),
                1,
                "{} should remain an independent single-fault scenario",
                spec.scenario
            );
            assert_parameters_match_catalog_schema(
                spec.scenario,
                plan.faults()[0].parameters(),
                spec.param_schema,
            );
        }
    }

    fn assert_parameters_match_catalog_schema(
        scenario: &str,
        parameters: &FaultInjectionParameters,
        schema: FaultParameterSchema,
    ) {
        match schema {
            FaultParameterSchema::None => assert_eq!(
                parameters,
                &FaultInjectionParameters::Default,
                "{scenario} should not expose typed fault parameters"
            ),
            _ => parameters
                .validate_for_schema(schema)
                .unwrap_or_else(|error| {
                    panic!(
                        "{scenario} catalog schema {schema:?} does not match plan parameters {parameters:?}: {error}"
                    )
                }),
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
    fn multi_target_selection_is_limited_to_rendered_fault_families() {
        // NetworkPartition accepts the same bounded fixed-count selector.
        for (count, ok) in [(1u32, true), (2, true), (8, true), (0, false), (9, false)] {
            let result = FaultInjection::new(
                FaultKind::RustfsServerNetworkPartition,
                FaultBackend::ChaosMeshNetworkChaos,
                FaultTarget::RustfsServerPeerNetwork,
                FaultSelection::FixedTargets(count),
                Duration::from_secs(60),
            );
            assert_eq!(
                result.is_ok(),
                ok,
                "partition FixedTargets({count}) acceptance mismatch"
            );
        }

        for kind in [
            FaultKind::RustfsVolumeIoError,
            FaultKind::RustfsVolumeLatency,
            FaultKind::RustfsVolumeReadMistake,
            FaultKind::RustfsVolumeEnospc,
        ] {
            for (count, ok) in [
                (1u32, true),
                (2, true),
                (8, true),
                (16, true),
                (0, false),
                (17, false),
            ] {
                let result = FaultInjection::new(
                    kind,
                    FaultBackend::ChaosMeshIoChaos,
                    FaultTarget::RustfsVolume {
                        path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
                    },
                    FaultSelection::FixedTargets(count),
                    Duration::from_secs(60),
                );
                assert_eq!(
                    result.is_ok(),
                    ok,
                    "volume {kind:?} FixedTargets({count}) acceptance mismatch"
                );
            }
        }

        // Every other pod/network kind still renders `mode: one` and ignores
        // the count, so a multi-target selection must be rejected instead of
        // silently narrowing the declared blast radius to a single Pod.
        let multi_pod_kill = FaultInjection::new(
            FaultKind::RustfsServerPodKill,
            FaultBackend::ChaosMeshPodChaos,
            FaultTarget::RustfsServerPod,
            FaultSelection::FixedTargets(2),
            Duration::from_secs(60),
        );
        assert!(
            multi_pod_kill.is_err(),
            "multi-target pod kill must stay rejected until its render honors the count"
        );
    }

    #[test]
    fn fixed_volume_injection_separates_target_count_from_io_sampling() {
        let fault = FaultInjection::new(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            },
            FaultSelection::FixedTargets(3),
            Duration::from_secs(60),
        )
        .expect("fixed volume injection");
        let plan = FaultPlan::new(
            "io-eio",
            "fault_case",
            FaultWorkloadMode::S3Mixed,
            vec![fault],
        )
        .expect("fixed volume plan");

        let [fault] = plan.faults() else {
            panic!("fixed volume plan must contain one typed fault")
        };
        assert_eq!(fault.kind(), FaultKind::RustfsVolumeIoError);
        assert_eq!(fault.selection(), FaultSelection::FixedTargets(3));
        assert_eq!(
            fault.volume_targeting().expect("volume targeting"),
            super::VolumeFaultTargeting {
                target_selection: super::VolumeTargetSelection::FixedTargets(3),
                io_sampling_percent: 100,
            }
        );
        assert_eq!(
            fault.target_summary(),
            "3 RustFS volume target(s) at /data/rustfs0"
        );
    }

    #[test]
    fn runtime_quorum_selection_resolves_without_changing_the_semantic_plan() {
        let boundary = QuorumVolumeBoundary {
            class: QuorumCaseClass::Metadata,
            beyond_read_tolerance: true,
        };
        let semantic = FaultInjection::new_with_parameters(
            FaultKind::RustfsVolumeIoError,
            FaultBackend::ChaosMeshIoChaos,
            FaultTarget::RustfsVolume {
                path: DEFAULT_RUSTFS_DATA_VOLUME.to_string(),
            },
            FaultSelection::RuntimeQuorum(boundary),
            Duration::from_secs(60),
            FaultInjectionParameters::QuorumIo {
                class: QuorumCaseClass::Metadata,
            },
        )
        .expect("semantic quorum injection");
        let shape =
            ErasureSetShape::from_runtime_single_set(8, 1, &[1], &[8], 2).expect("runtime shape");

        let resolved = semantic
            .resolve_runtime_quorum(&shape)
            .expect("resolved quorum injection");

        assert_eq!(
            semantic.selection(),
            FaultSelection::RuntimeQuorum(boundary)
        );
        assert_eq!(resolved.selection(), FaultSelection::FixedTargets(5));
        assert_eq!(resolved.parameters(), semantic.parameters());
        assert_eq!(resolved.kind(), semantic.kind());
        assert_eq!(resolved.target(), semantic.target());
    }

    #[test]
    fn write_quorum_loss_scenario_plans_multi_target_partition() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = super::NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario should resolve");
        let spec = scenario_spec(&scenario.name).expect("catalog spec");
        let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan should build");

        let faults = plan.faults();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].kind(), FaultKind::RustfsServerNetworkPartition);
        assert_eq!(
            faults[0].selection(),
            FaultSelection::FixedTargets(super::WRITE_QUORUM_LOSS_PARTITION_TARGETS),
            "the quorum-loss plan must declare the two-server blast radius"
        );
    }

    #[test]
    fn quorum_edge_scenario_plans_multi_target_pod_failure() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = super::POD_FAILURE_QUORUM_EDGE_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario should resolve");
        let spec = scenario_spec(&scenario.name).expect("catalog spec");
        let plan = FaultPlan::from_scenario(&scenario, spec).expect("plan should build");

        let faults = plan.faults();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0].kind(), FaultKind::RustfsServerPodFailure);
        assert_eq!(faults[0].target(), &FaultTarget::RustfsServerPod);
        assert_eq!(
            faults[0].selection(),
            FaultSelection::FixedTargets(super::WRITE_QUORUM_LOSS_PARTITION_TARGETS),
            "the quorum-edge plan must declare the same P-server blast radius"
        );
        // The single-Pod scenario keeps its one-target radius.
        let mut single = FaultTestConfig::for_test("real-cluster", "fast-csi");
        single.scenario = super::POD_FAILURE_SCENARIO.to_string();
        let single_scenario = FaultScenario::from_config(&single).expect("scenario");
        let single_spec = scenario_spec(&single_scenario.name).expect("catalog spec");
        let single_plan =
            FaultPlan::from_scenario(&single_scenario, single_spec).expect("plan should build");
        assert_eq!(
            single_plan.fault().selection(),
            FaultSelection::FixedTargets(1)
        );
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

    #[test]
    fn admin_scenarios_have_a_distinct_execution_plan_without_faults() {
        for name in [ADMIN_REBALANCE_SCENARIO, ADMIN_DECOMMISSION_SCENARIO] {
            let spec = scenario_spec(name).expect("catalog spec");
            let scenario = FaultScenario {
                name: name.to_string(),
                case_name: spec.case_name,
                duration: Duration::from_secs(60),
                percent: 1,
                object_count: 40,
            };

            let plan = ExecutionPlan::from_scenario_with_options(
                &scenario,
                spec,
                FaultPlanOptions::default(),
            )
            .expect("admin execution plan");

            assert_eq!(plan.kind(), ExecutionKind::Admin);
            assert!(plan.injection().is_none());
            assert_eq!(plan.scenario(), name);
            assert!(!plan.target_summary().is_empty());
        }
    }

    #[test]
    fn admin_plan_rejects_injection_parameters() {
        let spec = scenario_spec(ADMIN_REBALANCE_SCENARIO).expect("catalog spec");
        let scenario = FaultScenario {
            name: ADMIN_REBALANCE_SCENARIO.to_string(),
            case_name: spec.case_name,
            duration: Duration::from_secs(60),
            percent: 1,
            object_count: 40,
        };
        let error = ExecutionPlan::from_scenario_with_options(
            &scenario,
            spec,
            FaultPlanOptions {
                scenario_parameters: FaultInjectionParameters::NetworkLoss {
                    loss_percent: 1,
                    correlation_percent: 0,
                },
                ..FaultPlanOptions::default()
            },
        )
        .expect_err("admin plan must not hide injection parameters");

        assert!(error.to_string().contains("does not accept"));
    }
}
