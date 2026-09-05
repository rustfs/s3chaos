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
use std::time::Duration;

use crate::fault::{
    config::FaultTestConfig,
    plan::FaultInjectionParameters,
    quorum::QuorumCaseClass,
    workload::{
        WorkloadHotspot, WorkloadOperationMix, WorkloadPayloadClass, WorkloadPayloadDistribution,
    },
};

pub const IO_EIO_SCENARIO: &str = "io-eio";
pub const POD_KILL_ONE_SCENARIO: &str = "pod-kill-one";
pub const NETWORK_PARTITION_ONE_SCENARIO: &str = "network-partition-one";
pub const NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO: &str =
    "network-partition-write-quorum-loss";
pub const NETWORK_DELAY_SCENARIO: &str = "network-delay";
pub const NETWORK_LOSS_SCENARIO: &str = "network-loss";
pub const NETWORK_CORRUPT_SCENARIO: &str = "network-corrupt";
pub const NETWORK_DUPLICATE_SCENARIO: &str = "network-duplicate";
pub const IO_READ_MISTAKE_SCENARIO: &str = "io-read-mistake";
pub const IO_LATENCY_SCENARIO: &str = "io-latency";
pub const DISK_FULL_SCENARIO: &str = "disk-full";
pub const POD_FAILURE_SCENARIO: &str = "pod-failure";
pub const STRESS_CPU_SCENARIO: &str = "stress-cpu";
pub const STRESS_MEMORY_SCENARIO: &str = "stress-memory";
pub const DM_FLAKEY_SCENARIO: &str = "dm-flakey";
pub const DM_FLAKEY_VERSIONED_HOT_SCENARIO: &str = "dm-flakey-versioned-hot";
pub const POD_CRASH_VERSIONED_HOT_SCENARIO: &str = "pod-crash-versioned-hot";
pub const WARP_UNDER_CHAOS_SCENARIO: &str = "warp-under-chaos";
pub const QUORUM_P_IO_FAULT_SCENARIO: &str = "quorum-p-io-fault";
pub const QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO: &str = "quorum-p-plus-one-io-fault";
pub const FRESH_VOLUME_REPLACEMENT_SCENARIO: &str = "fresh-volume-replacement";
pub const ADMIN_DECOMMISSION_SCENARIO: &str = "admin-decommission";
pub const ADMIN_REBALANCE_SCENARIO: &str = "admin-rebalance";
pub const ON_DISK_BITROT_SCENARIO: &str = "on-disk-bitrot";
pub const STALE_DISK_RETURN_DETECT_SCENARIO: &str = "stale-disk-return-detect";

const IOCHAOS_CRD: &str = "iochaos.chaos-mesh.org";
const PODCHAOS_CRD: &str = "podchaos.chaos-mesh.org";
const NETWORKCHAOS_CRD: &str = "networkchaos.chaos-mesh.org";
const STRESSCHAOS_CRD: &str = "stresschaos.chaos-mesh.org";
const DEFAULT_TARGET_PROOF: &[&str] = &[
    "run artifacts must include the selected Kubernetes object or host device identity before the fault is activated",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultScenarioStatus {
    Executable,
    Planned,
}

impl FaultScenarioStatus {
    pub fn is_executable(self) -> bool {
        matches!(self, Self::Executable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultScenarioWorkloadProfile {
    Default,
    VersionedHotMutations,
}

impl FaultScenarioWorkloadProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::VersionedHotMutations => "versioned-hot-mutations",
        }
    }

    pub fn explicit_name(self) -> Option<&'static str> {
        match self {
            Self::Default => None,
            other => Some(other.as_str()),
        }
    }

    pub fn expected_versioning(self, env_value: bool) -> bool {
        env_value || matches!(self, Self::VersionedHotMutations)
    }

    fn apply_to_config(self, config: &mut FaultTestConfig) {
        match self {
            Self::Default => {}
            Self::VersionedHotMutations => {
                config.workload_versioning = true;
                config.workload_operation_mix =
                    versioned_hot_mutation_mix(config.workload.object_count);
                config.workload_payload_distribution = Some(versioned_hot_payload_distribution());
                config.workload_hotspot = Some(WorkloadHotspot {
                    object_percent: 10,
                    operation_percent: 80,
                });
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultPriority {
    P0,
    P1,
    P2,
    P3,
}

impl FaultPriority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::P0 => "p0",
            Self::P1 => "p1",
            Self::P2 => "p2",
            Self::P3 => "p3",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultBackend {
    ChaosMeshIoChaos,
    ChaosMeshPodChaos,
    ChaosMeshNetworkChaos,
    ChaosMeshStressChaos,
    DeviceMapper,
    MinioWarpWithChaos,
    PlannedReliabilityWorkflow,
}

impl FaultBackend {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ChaosMeshIoChaos => "chaos-mesh-io-chaos",
            Self::ChaosMeshPodChaos => "chaos-mesh-pod-chaos",
            Self::ChaosMeshNetworkChaos => "chaos-mesh-network-chaos",
            Self::ChaosMeshStressChaos => "chaos-mesh-stress-chaos",
            Self::DeviceMapper => "device-mapper",
            Self::MinioWarpWithChaos => "minio-warp-with-chaos",
            Self::PlannedReliabilityWorkflow => "planned-reliability-workflow",
        }
    }

    pub fn accepts_percent(self) -> bool {
        matches!(self, Self::ChaosMeshIoChaos | Self::MinioWarpWithChaos)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FaultParameterSchema {
    None,
    QuorumIo,
    IoLatency,
    NetworkDelay,
    NetworkLoss,
    NetworkCorrupt,
    NetworkDuplicate,
    StressCpu,
    StressMemory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultIsolation {
    FreshTenant,
    ReusableTenant,
    DedicatedLinuxBlockDevice,
}

impl FaultIsolation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FreshTenant => "fresh-tenant",
            Self::ReusableTenant => "reusable-tenant",
            Self::DedicatedLinuxBlockDevice => "dedicated-linux-block-device",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FaultImpactPolicy {
    ClientDisruptionRequired,
    ClientDisruptionOptional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DurabilityBugFamily {
    CommitMetadataLoss,
    DataShardLoss,
    SilentDataCorruption,
    VersionLineageLoss,
    QuorumViolation,
    RecoveryAvailabilityRegression,
    HealRegression,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorQualification {
    GateCandidate,
    DiagnosticOnly,
}

pub const FAULT_DETECTOR_CONTRACT_REVISION: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FaultDetectorSpec {
    pub qualification: DetectorQualification,
    pub detects: &'static [DurabilityBugFamily],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FaultDetectorContract {
    pub revision: u8,
    pub qualification: DetectorQualification,
    pub detects: Vec<DurabilityBugFamily>,
}

impl FaultDetectorContract {
    pub fn validate(&self) -> Result<()> {
        match self.revision {
            1 => self.validate_revision_1(),
            revision => {
                bail!("fault detector revision {revision} is unsupported; supported revisions: 1")
            }
        }
    }

    fn validate_revision_1(&self) -> Result<()> {
        ensure!(
            !self.detects.is_empty(),
            "fault detector must declare at least one durability bug family"
        );
        ensure!(
            self.detects.windows(2).all(|pair| pair[0] < pair[1]),
            "fault detector bug families must be a sorted unique canonical set"
        );
        Ok(())
    }
}

impl FaultDetectorSpec {
    const fn gate_candidate(detects: &'static [DurabilityBugFamily]) -> Self {
        Self {
            qualification: DetectorQualification::GateCandidate,
            detects,
        }
    }

    const fn diagnostic_only(detects: &'static [DurabilityBugFamily]) -> Self {
        Self {
            qualification: DetectorQualification::DiagnosticOnly,
            detects,
        }
    }

    fn validate(self, scenario: &str) -> Result<()> {
        ensure!(
            !self.detects.is_empty(),
            "fault scenario {scenario} detector must declare at least one durability bug family"
        );
        let mut normalized = self.detects.to_vec();
        normalized.sort();
        normalized.dedup();
        ensure!(
            normalized.len() == self.detects.len(),
            "fault scenario {scenario} detector contains duplicate durability bug families"
        );
        Ok(())
    }

    pub fn contract(self) -> FaultDetectorContract {
        let mut detects = self.detects.to_vec();
        detects.sort();
        detects.dedup();
        FaultDetectorContract {
            revision: FAULT_DETECTOR_CONTRACT_REVISION,
            qualification: self.qualification,
            detects,
        }
    }
}

impl FaultImpactPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ClientDisruptionRequired => "client-disruption-required",
            Self::ClientDisruptionOptional => "client-disruption-optional",
        }
    }

    pub fn requires_client_disruption(self) -> bool {
        matches!(self, Self::ClientDisruptionRequired)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FaultScenarioSpec {
    pub scenario: &'static str,
    pub case_name: &'static str,
    pub description: &'static str,
    pub priority: FaultPriority,
    pub backend: FaultBackend,
    pub status: FaultScenarioStatus,
    pub workload_profile: FaultScenarioWorkloadProfile,
    pub detector: FaultDetectorSpec,
    pub isolation: FaultIsolation,
    pub crds: &'static [&'static str],
    pub required_tools: &'static [&'static str],
    pub percent_supported: bool,
    pub param_schema: FaultParameterSchema,
    pub impact_policy: FaultImpactPolicy,
    pub boundary: &'static str,
    pub ci_phase: &'static str,
    pub target: &'static str,
    pub target_proof: &'static [&'static str],
    pub validation: &'static str,
    pub observability: &'static str,
    pub conflict_domain: &'static str,
}

impl FaultScenarioSpec {
    pub fn requires_static_storage(self) -> bool {
        self.isolation == FaultIsolation::DedicatedLinuxBlockDevice
    }

    pub fn requires_chaos_mesh(self) -> bool {
        !self.crds.is_empty()
    }

    pub fn requires_erasure_set_proof(self) -> bool {
        matches!(
            self.scenario,
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO
                | QUORUM_P_IO_FAULT_SCENARIO
                | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        )
    }
}

fn versioned_hot_mutation_mix(object_count: usize) -> WorkloadOperationMix {
    let mixed_count = object_count - object_count / 2;
    if mixed_count >= 10 {
        WorkloadOperationMix {
            put: 1,
            overwrite: 2,
            get: 1,
            list: 1,
            delete: 2,
            multipart: 3,
        }
    } else {
        WorkloadOperationMix::default()
    }
}

fn versioned_hot_payload_distribution() -> WorkloadPayloadDistribution {
    WorkloadPayloadDistribution {
        classes: vec![
            WorkloadPayloadClass {
                size_bytes: 4 * 1024,
                weight: 25,
            },
            WorkloadPayloadClass {
                size_bytes: 64 * 1024,
                weight: 25,
            },
            WorkloadPayloadClass {
                size_bytes: 2 * 1024 * 1024,
                weight: 30,
            },
            WorkloadPayloadClass {
                size_bytes: 8 * 1024 * 1024,
                weight: 20,
            },
        ],
    }
}

pub const FAULT_SCENARIO_CATALOG: &[FaultScenarioSpec] = &[
    FaultScenarioSpec {
        scenario: IO_EIO_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_io_eio_preserves_committed_objects",
        description: "Inject Chaos Mesh IOChaos EIO into one RustFS data volume and verify committed S3 objects remain readable with matching hashes after recovery.",
        priority: FaultPriority::P0,
        backend: FaultBackend::ChaosMeshIoChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &[],
        percent_supported: true,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/fault-injection",
        ci_phase: "faults",
        target: "one RustFS container data volume selected by tenant label and configured RustFS volume path",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "prefill succeeds before injection, mixed PUT/GET workload runs while IOChaos is active, committed PUTs are GET+sha256 verified after recovery, and successful GETs cannot return corrupt bytes",
        observability: "history.jsonl, workload-summary.json, checker-report.json, chaos-manifest.yaml, chaos-describe*.txt, Kubernetes snapshot artifacts",
        conflict_domain: "fresh Tenant/PVC/PV fixture and run-scoped IOChaos cleanup",
    },
    FaultScenarioSpec {
        scenario: POD_KILL_ONE_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::RecoveryAvailabilityRegression,
        ]),
        case_name: "fault_pod_kill_one_preserves_committed_objects",
        description: "Inject Chaos Mesh PodChaos against one RustFS Pod and verify StatefulSet recovery preserves committed S3 objects.",
        priority: FaultPriority::P0,
        backend: FaultBackend::ChaosMeshPodChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[PODCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/pod-recovery",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "the killed Pod is recreated, Tenant returns Ready, committed PUTs remain readable with matching hashes, and failed or unknown operations are recorded without becoming correctness failures",
        observability: "history.jsonl, workload-summary.json, checker-report.json, podchaos manifest/describe/yaml, Pod restart counts, current and previous RustFS logs",
        conflict_domain: "run-scoped PodChaos resource and one target Pod; can reuse a ready Tenant after the prior scenario has cleaned up",
    },
    FaultScenarioSpec {
        scenario: NETWORK_PARTITION_ONE_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_network_partition_one_preserves_committed_objects",
        description: "Inject Chaos Mesh NetworkChaos that partitions one RustFS Pod from its peers and verify recovery does not lose or corrupt committed objects.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshNetworkChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[NETWORKCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/network-partition",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with peer traffic disrupted inside the e2e namespace",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "network disruption is active during workload, successful reads never return wrong hashes, committed PUTs remain readable after heal, and Tenant recovers Ready",
        observability: "history.jsonl, workload-summary.json, checker-report.json, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
        conflict_domain: "run-scoped NetworkChaos resource; must not overlap with PodChaos or IOChaos in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::QuorumViolation,
            DurabilityBugFamily::CommitMetadataLoss,
        ]),
        case_name: "fault_network_partition_write_quorum_loss_preserves_committed_state",
        description: "Partition two of the four RustFS Pods from all peers at once after a bounded-age RustFS admin runtime snapshot proves their server/drive membership in one symmetric erasure set, driving the cluster below write quorum while read quorum can survive, and verify committed state is intact after heal.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshNetworkChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[NETWORKCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/network-partition-write-quorum",
        ci_phase: "faults",
        target: "exactly two RustFS Pods selected by tenant label, fully isolated from the remaining peers (and each other); actual injected source records at activation and after workload must identify servers whose runtime drive membership crosses the write-quorum boundary while retaining read quorum",
        target_proof: &[
            "live target proof must bind Tenant geometry and unique Ready Pod identities to bounded-age RustFS admin runtime set/parity and server/drive data before fault activation",
            "the selected target set must contain exactly two RustFS Pods",
        ],
        validation: "the runner stages multipart uploads before the fault, binds Tenant server/volume width and unique Ready Pod identities to RustFS admin runtime set/parity and drive-membership data fetched by a signed request no more than five seconds before fault apply, then proves the actual two-Pod partition leaves read quorum but not write quorum at activation and after workload; every PUT, DELETE, and staged multipart completion during the outage is recorded in history and must fail, time out, or remain unknown; 404 is not quorum-loss evidence; successful reads never return wrong hashes; after heal every committed object and version is re-readable with intact content (post-return zero-loss), and Tenant recovers Ready",
        observability: "history.jsonl, workload-summary.json, checker-report.json, checker-pre-recommit-report.json, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
        conflict_domain: "run-scoped NetworkChaos resource; must not overlap with PodChaos or IOChaos in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: NETWORK_DELAY_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_network_delay_preserves_object_model",
        description: "Inject NetworkChaos delay into one RustFS Pod peer path and verify the S3 object model remains explainable.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshNetworkChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[NETWORKCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::NetworkDelay,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/network-delay",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with delayed peer traffic inside the e2e namespace",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value, stable live keys are listed, and recovery preserves the object model",
        observability: "history.jsonl, checker reports, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
        conflict_domain: "run-scoped NetworkChaos resource; must not overlap with other network faults in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: NETWORK_LOSS_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_network_loss_preserves_object_model",
        description: "Inject NetworkChaos packet loss into one RustFS Pod peer path and verify object-model correctness after recovery.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshNetworkChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[NETWORKCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::NetworkLoss,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/network-loss",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with lossy peer traffic inside the e2e namespace",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value, failed operations are explainable, and recovery preserves the object model",
        observability: "history.jsonl, checker reports, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
        conflict_domain: "run-scoped NetworkChaos resource; must not overlap with other network faults in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: NETWORK_CORRUPT_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[DurabilityBugFamily::SilentDataCorruption]),
        case_name: "fault_network_corrupt_preserves_object_model",
        description: "Inject NetworkChaos packet corruption into one RustFS Pod peer path and verify successful S3 reads never return corrupt bytes.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshNetworkChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[NETWORKCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::NetworkCorrupt,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/network-corrupt",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with corrupted peer traffic inside the e2e namespace",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value and recovery preserves the object model",
        observability: "history.jsonl, checker reports, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
        conflict_domain: "run-scoped NetworkChaos resource; must not overlap with other network faults in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: NETWORK_DUPLICATE_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[DurabilityBugFamily::SilentDataCorruption]),
        case_name: "fault_network_duplicate_preserves_object_model",
        description: "Inject NetworkChaos packet duplication into one RustFS Pod peer path and verify object-model correctness after recovery.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshNetworkChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[NETWORKCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::NetworkDuplicate,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/network-duplicate",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with duplicated peer traffic inside the e2e namespace",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value and recovery preserves the object model",
        observability: "history.jsonl, checker reports, networkchaos manifest/describe/yaml, endpoints, events, and RustFS logs",
        conflict_domain: "run-scoped NetworkChaos resource; must not overlap with other network faults in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: IO_READ_MISTAKE_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[DurabilityBugFamily::SilentDataCorruption]),
        case_name: "fault_io_read_mistake_rejects_corrupt_reads",
        description: "Inject Chaos Mesh IOChaos mistake on RustFS read paths and verify RustFS never returns corrupt object bytes as successful S3 reads.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshIoChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &[],
        percent_supported: true,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/data-integrity",
        ci_phase: "faults",
        target: "one RustFS data volume read path selected by tenant label and configured RustFS volume path",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful GET responses must match the committed hash; RustFS may fail or repair reads but must not return wrong bytes with a successful status",
        observability: "history.jsonl, checker-report.json with successful_corrupted_reads, iochaos manifest/describe/yaml, RustFS logs, events",
        conflict_domain: "fresh Tenant/PVC/PV fixture and run-scoped IOChaos mistake resource",
    },
    FaultScenarioSpec {
        scenario: IO_LATENCY_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_io_latency_preserves_object_model",
        description: "Inject Chaos Mesh IOChaos latency on RustFS data paths and verify delayed storage does not corrupt the S3 object model.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshIoChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &[],
        percent_supported: true,
        param_schema: FaultParameterSchema::IoLatency,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/storage-latency",
        ci_phase: "faults",
        target: "one RustFS data volume selected by tenant label with READ/WRITE operations delayed",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value, timed out operations remain explainable, and recovery preserves the object model",
        observability: "history.jsonl, checker reports, iochaos manifest/describe/yaml, RustFS logs, events",
        conflict_domain: "fresh Tenant/PVC/PV fixture and run-scoped IOChaos latency resource",
    },
    FaultScenarioSpec {
        scenario: DISK_FULL_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::CommitMetadataLoss,
            DurabilityBugFamily::DataShardLoss,
        ]),
        case_name: "fault_disk_full_preserves_committed_objects",
        description: "Inject ENOSPC on writes to one RustFS data volume and verify committed objects survive storage pressure and recovery.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshIoChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &[],
        percent_supported: true,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/storage-pressure",
        ci_phase: "faults",
        target: "one RustFS data volume selected by tenant label with WRITE operations returning ENOSPC",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "new writes may fail with ENOSPC, but previously committed PUTs remain readable after IOChaos recovery",
        observability: "history.jsonl, checker-report.json, fault-evidence.json, IOChaos manifest/status, events, RustFS logs",
        conflict_domain: "fresh Tenant/PVC/PV fixture and run-scoped IOChaos cleanup without consuming node disk capacity",
    },
    FaultScenarioSpec {
        scenario: POD_FAILURE_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::RecoveryAvailabilityRegression,
        ]),
        case_name: "fault_pod_failure_preserves_object_model",
        description: "Inject Chaos Mesh PodChaos pod-failure against one RustFS Pod and verify object-model correctness after recovery.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshPodChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[PODCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/pod-failure",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label and failed for the scenario duration",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "the failed Pod recovers, Tenant returns Ready, and the S3 object model remains explainable",
        observability: "history.jsonl, checker reports, podchaos manifest/describe/yaml, Pod restart counts, current and previous RustFS logs",
        conflict_domain: "run-scoped PodChaos resource and one target Pod; can reuse a ready Tenant after the prior scenario has cleaned up",
    },
    FaultScenarioSpec {
        scenario: STRESS_CPU_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_stress_cpu_preserves_object_model",
        description: "Inject Chaos Mesh CPU StressChaos into one RustFS Pod and verify object-model correctness under resource pressure.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshStressChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[STRESSCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::StressCpu,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/cpu-pressure",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with CPU stressors",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value and recovery preserves the object model",
        observability: "history.jsonl, checker reports, stresschaos manifest/describe/yaml, metrics-adjacent Kubernetes snapshots, events, and RustFS logs",
        conflict_domain: "run-scoped StressChaos resource; should not overlap with other stress faults in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: STRESS_MEMORY_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_stress_memory_preserves_object_model",
        description: "Inject Chaos Mesh memory StressChaos into one RustFS Pod and verify object-model correctness under memory pressure.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshStressChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[STRESSCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::StressMemory,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/memory-pressure",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label with memory stressors",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "successful reads match a committed value and recovery preserves the object model",
        observability: "history.jsonl, checker reports, stresschaos manifest/describe/yaml, metrics-adjacent Kubernetes snapshots, events, and RustFS logs",
        conflict_domain: "run-scoped StressChaos resource; should not overlap with other stress faults in the same Tenant",
    },
    FaultScenarioSpec {
        scenario: DM_FLAKEY_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_dm_flakey_preserves_committed_objects",
        description: "Use a device-mapper flakey or error target for a dedicated test volume and verify RustFS handles block-device instability without data corruption.",
        priority: FaultPriority::P3,
        backend: FaultBackend::DeviceMapper,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::DedicatedLinuxBlockDevice,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-workload/block-device-fault",
        ci_phase: "faults",
        target: "one dedicated Linux block-device-backed PV used only by the e2e Tenant",
        target_proof: &[
            "host-storage proof must bind exact node/device/PV allowlists to the live Pod/PVC/PV/mount/mapper identities before mutation",
            "host-storage proof must record the device-mapper rollback, node-quarantine, and post-cleanup observation contract",
        ],
        validation: "committed objects remain readable after the device fault is removed, and successful reads never return corrupt bytes",
        observability: "host-storage-proof.json, host-storage-post-cleanup.json, history.jsonl, checker-report.json, dmsetup table/status, kernel logs, PV mapping, events, RustFS logs",
        conflict_domain: "dedicated Linux runner or lab host with an explicitly assigned block device; never part of shared test storage",
    },
    FaultScenarioSpec {
        scenario: DM_FLAKEY_VERSIONED_HOT_SCENARIO,
        detector: FaultDetectorSpec::diagnostic_only(&[
            DurabilityBugFamily::CommitMetadataLoss,
            DurabilityBugFamily::VersionLineageLoss,
        ]),
        case_name: "fault_dm_flakey_versioned_hot_preserves_version_lineage",
        description: "Exercise a single-volume soft-power-loss durability proxy: silently drop block writes, crash the owning Pod, unmount to discard cached state, restore and remount the device, then verify versioned hot-key lineage after recovery.",
        priority: FaultPriority::P1,
        backend: FaultBackend::DeviceMapper,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::VersionedHotMutations,
        isolation: FaultIsolation::DedicatedLinuxBlockDevice,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/single-volume-soft-power-loss",
        ci_phase: "faults",
        target: "one dedicated Linux block-device-backed PV used only by the e2e Tenant, with versioned S3 mutations concentrated on hot keys",
        target_proof: &[
            "host-storage proof must bind exact node/device/PV allowlists and rollback/quarantine/post-cleanup contracts before mutation",
            "dmsetup table/status must prove an always-down flakey drop_writes table on the dedicated mapped device",
            "the owning Pod must be force-deleted while drop_writes remains active and the filesystem must be unmounted before the healthy table is restored",
            "the mapped filesystem must be remounted and the owning Pod identity must change before recovery verification",
            "run-spec workload.versioning must be true and workload.hotspot must be present",
        ],
        validation: "the crash window contains at least one versioned mutation acknowledged while drop_writes is active; after forced Pod loss, unmount, healthy-table restore and remount, all committed object versions are re-read by versionId, delete markers remain latest, and successful reads never return corrupt bytes; because only one EC volume is lost this is a negative-control proxy, not quorum-loss proof",
        observability: "run-spec.json/yaml, host-storage-proof.json, host-storage-post-cleanup.json, workload-plan.json, history.jsonl, crash-window-evidence.json, dm-crash-boundary.json, dm-crash-recovered.json, checker-report.json, dmsetup table/status, mount identity, Pod UID transition, events, RustFS logs",
        conflict_domain: "dedicated Linux runner or lab host with an explicitly assigned block device; never part of shared test storage",
    },
    FaultScenarioSpec {
        scenario: POD_CRASH_VERSIONED_HOT_SCENARIO,
        detector: FaultDetectorSpec::diagnostic_only(&[
            DurabilityBugFamily::VersionLineageLoss,
            DurabilityBugFamily::RecoveryAvailabilityRegression,
        ]),
        case_name: "fault_pod_crash_versioned_hot_preserves_version_lineage",
        description: "Negative-control recovery test: kill one RustFS Pod while forcing versioned hot-key overwrite/delete/MPU checks; single-Pod loss stays within EC redundancy, so a green run validates recovery plumbing but is not physical-durability evidence.",
        priority: FaultPriority::P1,
        backend: FaultBackend::ChaosMeshPodChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::VersionedHotMutations,
        isolation: FaultIsolation::ReusableTenant,
        crds: &[PODCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/versioned-pod-recovery",
        ci_phase: "faults",
        target: "one RustFS Pod selected by tenant label, with versioned S3 mutations concentrated on hot keys during pod restart",
        target_proof: &[
            "podchaos manifest/describe output must identify exactly one selected RustFS Pod",
            "the selected Pod UID must disappear and its replacement UID or restart evidence must be recorded",
            "run-spec workload.versioning must be true and workload.hotspot must be present",
        ],
        validation: "the killed Pod is recreated, Tenant returns Ready, all committed object versions are re-read by versionId, delete markers remain latest for deleted keys, hot overwrite/delete/MPU operations are exercised, and successful reads never return corrupt bytes",
        observability: "run-spec.json/yaml, workload-plan.json, history.jsonl, workload-summary.json, checker-report.json, podchaos manifest/describe/yaml, Pod restart counts, current and previous RustFS logs",
        conflict_domain: "run-scoped PodChaos resource and one target Pod; can reuse a ready Tenant after prior scenario cleanup",
    },
    FaultScenarioSpec {
        scenario: WARP_UNDER_CHAOS_SCENARIO,
        detector: FaultDetectorSpec::diagnostic_only(&[
            DurabilityBugFamily::RecoveryAvailabilityRegression,
        ]),
        case_name: "fault_warp_under_chaos_reports_performance_separately",
        description: "Run MinIO Warp during a selected chaos scenario while keeping performance output separate from the correctness verdict.",
        priority: FaultPriority::P3,
        backend: FaultBackend::MinioWarpWithChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &["warp"],
        percent_supported: true,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-workload/performance-under-chaos",
        ci_phase: "faults",
        target: "RustFS S3 endpoint under an explicitly selected fault backend",
        target_proof: DEFAULT_TARGET_PROOF,
        validation: "Warp throughput or latency changes are reported separately; correctness still comes only from history and checker reports",
        observability: "warp report, history.jsonl, checker-report.json, selected chaos manifest/describe/yaml, RustFS logs",
        conflict_domain: "performance-only run with isolated bucket prefix and no shared correctness threshold",
    },
    FaultScenarioSpec {
        scenario: QUORUM_P_IO_FAULT_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::SilentDataCorruption,
        ]),
        case_name: "fault_quorum_p_io_fault_preserves_read_quorum",
        description: "Inject storage faults into the runtime-derived read tolerance P for one typed payload or metadata quorum case and verify the boundary without corrupt reads.",
        priority: FaultPriority::P0,
        backend: FaultBackend::ChaosMeshIoChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::QuorumIo,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-reliability/quorum-targeting",
        ci_phase: "faults",
        target: "the runtime-derived read tolerance P for payload or metadata volumes in one RustFS erasure set",
        target_proof: &[
            "artifact must prove erasure-set topology and P value before fault activation",
            "artifact must bind every candidate and selected Pod/container/PVC/PV/mount to exactly one RustFS drive UUID in the same set",
            "artifact must prove the complete non-target drive set",
        ],
        validation: "the stable typed cohort remains readable at P failed volumes; each mutation must fail without a success ACK when its write quorum exceeds the remaining shard count, and permitted writes must not leave half-committed versions",
        observability: "runtime topology and volume binding proof, actual IOChaos controller targets at activation and after workload, workload history, checker reports, RustFS logs",
        conflict_domain: "fresh Tenant with topology-owned volume selection; must not share erasure-set targeting with other active faults",
    },
    FaultScenarioSpec {
        scenario: QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::QuorumViolation,
            DurabilityBugFamily::CommitMetadataLoss,
        ]),
        case_name: "fault_quorum_p_plus_one_io_fault_rejects_past_write_quorum",
        description: "Inject storage faults into the runtime-derived read tolerance P+1 for one typed payload or metadata quorum case and verify operations fail cleanly past quorum.",
        priority: FaultPriority::P0,
        backend: FaultBackend::ChaosMeshIoChaos,
        status: FaultScenarioStatus::Executable,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[IOCHAOS_CRD],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::QuorumIo,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-reliability/quorum-targeting",
        ci_phase: "faults",
        target: "the runtime-derived read tolerance P+1 for payload or metadata volumes in one RustFS erasure set",
        target_proof: &[
            "artifact must prove erasure-set topology, P value, and P+1 target count before fault activation",
            "artifact must bind every candidate and selected Pod/container/PVC/PV/mount to exactly one RustFS drive UUID in the same set",
            "artifact must prove the complete non-target drive set",
        ],
        validation: "P+1 rejects every mutation whose write quorum exceeds the remaining shard count, deriving PUT, DELETE marker, and multipart completion expectations separately from proven runtime geometry; prior committed versions remain readable after recovery and no successful read returns corrupt bytes",
        observability: "runtime topology and volume binding proof, actual IOChaos controller targets at activation and after workload, workload history, checker reports, RustFS logs",
        conflict_domain: "fresh Tenant with topology-owned volume selection; must not share erasure-set targeting with other active faults",
    },
    FaultScenarioSpec {
        scenario: FRESH_VOLUME_REPLACEMENT_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::HealRegression,
        ]),
        case_name: "fault_fresh_volume_replacement_heals_empty_disk",
        description: "Planned fresh-volume replacement flow: replace one RustFS volume with a proven empty generation, observe RustFS automatic replacement or admin-deep heal, and force reads through the replacement.",
        priority: FaultPriority::P0,
        backend: FaultBackend::PlannedReliabilityWorkflow,
        status: FaultScenarioStatus::Planned,
        workload_profile: FaultScenarioWorkloadProfile::VersionedHotMutations,
        isolation: FaultIsolation::FreshTenant,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-reliability/volume-replacement",
        ci_phase: "planned",
        target: "one RustFS PVC/PV replaced by a fresh empty volume and the owning Pod restarted",
        target_proof: &[
            "artifact must prove old PVC/PV identity and replacement PVC/PV identity",
            "artifact must prove the replacement volume starts empty before RustFS can access it",
            "artifact must bind automatic replacement or admin-deep progress to the replacement drive and erasure set",
            "artifact must leave exactly read quorum online so every successful verification read requires the repaired drive",
            "current force-read adapter supports exactly one RustFS volume per server; multi-volume server topology must fail closed until per-volume runtime targeting is implemented",
        ],
        validation: "RustFS reformats or adopts the fresh volume safely, the selected heal mode converges, forced reads prove data exists on the replacement, all committed object versions remain readable, and deleted keys do not resurrect",
        observability: "disk-generation-proof.json, heal-summary.json, heal-progress.jsonl, version-shard-mapping.json, force-read-proof.json, workload history, checker reports, RustFS logs",
        conflict_domain: "fresh Tenant/PVC/PV fixture; replacement must never target shared or pre-existing storage",
    },
    FaultScenarioSpec {
        scenario: ADMIN_DECOMMISSION_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::HealRegression,
        ]),
        case_name: "fault_admin_decommission_preserves_object_model",
        description: "Planned admin operation flow: decommission a pool or target set under continuous workload after a multi-pool Tenant shape exists.",
        priority: FaultPriority::P1,
        backend: FaultBackend::PlannedReliabilityWorkflow,
        status: FaultScenarioStatus::Planned,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-reliability/admin-decommission",
        ci_phase: "planned",
        target: "one RustFS pool or decommission target set inside a multi-pool fault-test Tenant",
        target_proof: &[
            "artifact must prove the Tenant has the required multi-pool topology",
            "artifact must record the exact pool or target set selected for decommission",
        ],
        validation: "decommission reaches a safe terminal state, committed object versions remain readable, and workload failures are explainable by the operation window",
        observability: "admin operation transcript with secrets redacted, pool topology proof, workload history, checker reports, RustFS logs",
        conflict_domain: "fresh multi-pool Tenant fixture; must not decommission shared or pre-existing resources",
    },
    FaultScenarioSpec {
        scenario: ADMIN_REBALANCE_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::DataShardLoss,
            DurabilityBugFamily::HealRegression,
        ]),
        case_name: "fault_admin_rebalance_preserves_object_model",
        description: "Planned admin operation flow: run RustFS rebalance under continuous workload after the topology adapter can prove the target scope.",
        priority: FaultPriority::P1,
        backend: FaultBackend::PlannedReliabilityWorkflow,
        status: FaultScenarioStatus::Planned,
        workload_profile: FaultScenarioWorkloadProfile::Default,
        isolation: FaultIsolation::FreshTenant,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-reliability/admin-rebalance",
        ci_phase: "planned",
        target: "RustFS rebalance operation scoped to the fault-test Tenant topology",
        target_proof: &[
            "artifact must prove topology before and after rebalance",
            "artifact must record the rebalance operation identity or status cursor",
        ],
        validation: "rebalance completes or reports an explainable terminal state, committed object versions remain readable, and no successful read returns corrupt bytes",
        observability: "admin operation transcript with secrets redacted, topology snapshots, workload history, checker reports, RustFS logs",
        conflict_domain: "fresh Tenant topology owned by the test run; must not rebalance shared resources",
    },
    FaultScenarioSpec {
        scenario: ON_DISK_BITROT_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::SilentDataCorruption,
            DurabilityBugFamily::HealRegression,
        ]),
        case_name: "fault_on_disk_bitrot_is_rejected_and_healed",
        description: "Planned on-disk bitrot flow: use a stable RustFS diagnostic mapping to mutate one proven shard, verify corrupt bytes are rejected, observe scanner or admin-deep heal, and force reads through the repaired drive.",
        priority: FaultPriority::P0,
        backend: FaultBackend::PlannedReliabilityWorkflow,
        status: FaultScenarioStatus::Planned,
        workload_profile: FaultScenarioWorkloadProfile::VersionedHotMutations,
        isolation: FaultIsolation::DedicatedLinuxBlockDevice,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionRequired,
        boundary: "rustfs-reliability/on-disk-bitrot",
        ci_phase: "planned",
        target: "one shard file on one dedicated host volume, selected after mapping an object version to its on-disk shard",
        target_proof: &[
            "artifact must prove object-version to shard-file mapping through a versioned RustFS diagnostic API; S3Chaos must not infer private on-disk paths",
            "artifact must record pre/post sha256 or byte-range evidence for the mutated shard",
            "artifact must bind the mutation-window GET to a typed RustFS checksum-mismatch observation for that exact shard before heal",
            "artifact must bind scanner/admin progress to a cluster-definitive observer and reject no-op heal evidence",
            "artifact must leave exactly read quorum online so every successful verification read requires the repaired drive",
            "current force-read adapter supports exactly one RustFS volume per server; multi-volume server topology must fail closed until per-volume runtime targeting is implemented",
        ],
        validation: "corrupt shard reads are rejected or repaired without returning bad bytes, the selected heal mode repairs the shard, forced reads match committed object hashes, and committed versions remain readable after repair",
        observability: "shard-mutation-proof.json, heal-summary.json, heal-progress.jsonl, version-shard-mapping.json, force-read-proof.json, workload history, checker reports, RustFS logs",
        conflict_domain: "dedicated host volume and object prefix owned by the test run; must never mutate shared data",
    },
    FaultScenarioSpec {
        scenario: STALE_DISK_RETURN_DETECT_SCENARIO,
        detector: FaultDetectorSpec::gate_candidate(&[
            DurabilityBugFamily::CommitMetadataLoss,
            DurabilityBugFamily::VersionLineageLoss,
        ]),
        case_name: "fault_stale_disk_return_preserves_latest_versions",
        description: "Planned stale-generation flow: detach one proven disk generation, commit overwrites and delete markers while it is absent, reattach that exact generation, and include dangling cleanup in the same recovery verdict.",
        priority: FaultPriority::P0,
        backend: FaultBackend::PlannedReliabilityWorkflow,
        status: FaultScenarioStatus::Planned,
        workload_profile: FaultScenarioWorkloadProfile::VersionedHotMutations,
        isolation: FaultIsolation::DedicatedLinuxBlockDevice,
        crds: &[],
        required_tools: &[],
        percent_supported: false,
        param_schema: FaultParameterSchema::None,
        impact_policy: FaultImpactPolicy::ClientDisruptionOptional,
        boundary: "rustfs-reliability/stale-disk-return",
        ci_phase: "planned",
        target: "one dedicated RustFS volume generation detached and later reattached to the same proven logical slot",
        target_proof: &[
            "artifact must bind the detached and returned PV, device, filesystem, and RustFS drive identities to the same storage generation",
            "artifact must bind raw Local PV/PVC/Pod/Node and helper/runtime/mount-namespace generations, run bounded exact-mountpoint host sampling from detach through mutations, and bracket every committed mutation ACK with absent samples",
            "the workload and recovery recommit must preserve one real-time mutation order per object key and record monotonic begin/end event sequences; an ambiguous delete makes the exact latest-state proof inconclusive, while ambiguous data writes are resolved through exact version listing and content probes",
            "post-return checking must bind the immutable workload prefix plus its exact read-only GET/LIST suffix and reject any concurrent or later PUT, DELETE, or multipart completion",
            "artifact must classify the complete pre-cleanup inventory as committed, recoverable-unknown, or uncommitted-dangling and retain both protected classes",
        ],
        validation: "after the stale generation rejoins, latest version IDs and delete markers never roll back, successful reads match committed hashes, and dangling cleanup does not delete recoverable committed fragments",
        observability: "disk-generation-proof.json, shard-inventory-before.json, shard-inventory-after.json, dangling-cleanup-proof.json, workload history, version-aware checker reports, Kubernetes snapshots, RustFS logs",
        conflict_domain: "dedicated host volume and fresh Tenant owned by the run; no other fault or cleanup may touch the detached generation",
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FaultScenario {
    pub name: String,
    pub case_name: &'static str,
    pub duration: Duration,
    pub percent: u8,
    pub object_count: usize,
}

impl FaultScenario {
    pub fn from_config(config: &FaultTestConfig) -> Result<Self> {
        let spec = scenario_spec(&config.scenario)?;
        ensure!(
            spec.status.is_executable(),
            "fault scenario {:?} is cataloged as {:?} but is not executable yet; case {}, backend {:?}, validation: {}",
            config.scenario,
            spec.status,
            spec.case_name,
            spec.backend,
            spec.validation
        );
        ensure!(
            (1..=100).contains(&config.percent),
            "RUSTFS_FAULT_TEST_PERCENT must be in 1..=100, got {}",
            config.percent
        );
        ensure!(
            config.duration > Duration::ZERO,
            "RUSTFS_FAULT_TEST_DURATION_SECONDS must be greater than zero"
        );
        if spec.backend == FaultBackend::MinioWarpWithChaos {
            // Warp is followed by an S3 access wait and the correctness workload.
            // Reserve headroom here; the runtime active-state check remains the
            // authority because setup and workload time depend on the target.
            ensure!(
                config.warp_duration > Duration::ZERO
                    && config
                        .duration
                        .checked_sub(config.cluster.timeout)
                        .is_some_and(|remaining| config.warp_duration < remaining),
                "RUSTFS_FAULT_TEST_WARP_DURATION_SECONDS must be positive and leave more than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS ({}s) inside the fault duration ({}s) for post-Warp operations; shorten Warp or increase faultDuration",
                config.cluster.timeout.as_secs(),
                config.duration.as_secs()
            );
        }
        config.workload.validate()?;
        config.workload_operation_mix.validate()?;
        if let Some(payload_distribution) = &config.workload_payload_distribution {
            payload_distribution.validate()?;
        }
        if let Some(hotspot) = config.workload_hotspot {
            hotspot.validate()?;
        }
        let mixed_count = config.workload.object_count - config.workload.object_count / 2;
        let total_weight = config.workload_operation_mix.total_weight();
        ensure!(
            mixed_count as u64 >= total_weight,
            "workload operationWeights total {} requires at least that many mixed-workload objects, got {}",
            total_weight,
            mixed_count
        );
        ensure!(
            !config.percent_overridden || spec.percent_supported,
            "RUSTFS_FAULT_TEST_PERCENT only applies to percent-based IOChaos scenarios; scenario {:?} targets {:?} with a fixed target count",
            spec.scenario,
            spec.backend
        );

        Ok(Self {
            name: spec.scenario.to_string(),
            case_name: spec.case_name,
            duration: config.duration,
            percent: config.percent,
            object_count: config.workload.object_count,
        })
    }

    pub fn prefill_count(&self) -> usize {
        self.object_count / 2
    }

    pub fn mixed_workload_count(&self) -> usize {
        self.object_count - self.prefill_count()
    }
}

pub fn scenario_catalog() -> &'static [FaultScenarioSpec] {
    FAULT_SCENARIO_CATALOG
}

pub fn executable_scenario_catalog() -> impl Iterator<Item = &'static FaultScenarioSpec> {
    FAULT_SCENARIO_CATALOG
        .iter()
        .filter(|scenario| scenario.status.is_executable())
}

pub fn scenario_catalog_json() -> Result<String> {
    for spec in scenario_catalog() {
        spec.detector.validate(spec.scenario)?;
    }
    Ok(serde_json::to_string_pretty(scenario_catalog())?)
}

pub fn apply_catalog_defaults(config: &mut FaultTestConfig) -> Result<()> {
    let spec = scenario_spec(&config.scenario)?;
    spec.workload_profile.apply_to_config(config);
    if matches!(
        config.scenario.as_str(),
        QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
    ) && matches!(
        config.scenario_parameters,
        FaultInjectionParameters::Default
    ) {
        config.scenario_parameters = FaultInjectionParameters::QuorumIo {
            class: QuorumCaseClass::Payload,
        };
    }
    if matches!(
        config.scenario.as_str(),
        QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
    ) {
        config.workload_versioning = true;
        match config.scenario_parameters {
            FaultInjectionParameters::QuorumIo {
                class: QuorumCaseClass::Payload,
            } => config.workload_directory_marker_percent = 0,
            FaultInjectionParameters::QuorumIo {
                class: QuorumCaseClass::Metadata,
            } => {
                // Make the typed metadata case deterministic: every prefilled
                // key is a zero-byte directory marker, so the P-boundary read
                // oracle cannot pass on a payload object or become vacuous.
                config.workload_directory_marker_percent = 100;
                config.workload_operation_mix = WorkloadOperationMix {
                    put: 1,
                    overwrite: 2,
                    get: 1,
                    list: 1,
                    delete: 4,
                    multipart: 1,
                };
            }
            _ => {}
        }
    }
    Ok(())
}

pub fn expected_workload_versioning_for_scenario(scenario: &str, env_value: bool) -> Result<bool> {
    let spec = scenario_spec(scenario)?;
    Ok(spec.workload_profile.expected_versioning(env_value)
        || matches!(
            scenario,
            QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        ))
}

pub(in crate::fault) fn requires_prefault_multipart_staging(scenario: &str) -> bool {
    matches!(
        scenario,
        NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO
            | QUORUM_P_IO_FAULT_SCENARIO
            | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
    )
}

pub fn scenario_spec(name: &str) -> Result<&'static FaultScenarioSpec> {
    let spec = FAULT_SCENARIO_CATALOG
        .iter()
        .find(|scenario| scenario.scenario == name)
        .ok_or_else(|| {
            let supported = FAULT_SCENARIO_CATALOG
                .iter()
                .map(|scenario| scenario.scenario)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::anyhow!("unsupported fault scenario {name:?}; catalog contains: {supported}")
        })?;
    spec.detector.validate(spec.scenario)?;
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::{
        DM_FLAKEY_VERSIONED_HOT_SCENARIO, DetectorQualification, DurabilityBugFamily,
        FaultDetectorContract, FaultParameterSchema, FaultScenario, FaultScenarioStatus,
        FaultScenarioWorkloadProfile, IO_EIO_SCENARIO, IO_LATENCY_SCENARIO, NETWORK_DELAY_SCENARIO,
        NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO, POD_CRASH_VERSIONED_HOT_SCENARIO,
        POD_KILL_ONE_SCENARIO, QUORUM_P_IO_FAULT_SCENARIO, QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
        STALE_DISK_RETURN_DETECT_SCENARIO, WARP_UNDER_CHAOS_SCENARIO, apply_catalog_defaults,
        executable_scenario_catalog, expected_workload_versioning_for_scenario,
        requires_prefault_multipart_staging, scenario_catalog, scenario_catalog_json,
        scenario_spec,
    };
    use crate::fault::config::{FaultTestConfig, FaultWorkloadProfile};
    use crate::fault::plan::FaultInjectionParameters;
    use crate::fault::quorum::QuorumCaseClass;
    use crate::fault::workload::{
        WorkloadHotspot, WorkloadOperationMix, WorkloadPayloadClass, WorkloadPayloadDistribution,
    };
    use std::time::Duration;

    #[test]
    fn default_fault_scenario_is_io_eio_with_split_workload() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let scenario = FaultScenario::from_config(&config).expect("valid scenario");

        assert_eq!(scenario.name, IO_EIO_SCENARIO);
        assert_eq!(
            scenario.case_name,
            "fault_io_eio_preserves_committed_objects"
        );
        assert_eq!(scenario.duration, Duration::from_secs(7200));
        assert_eq!(scenario.percent, 20);
        assert_eq!(scenario.prefill_count(), 20000);
        assert_eq!(scenario.mixed_workload_count(), 20000);
    }

    #[test]
    fn non_warp_scenario_ignores_ambient_warp_duration() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.duration = Duration::from_secs(60);
        config.warp_duration = Duration::MAX;
        assert!(FaultScenario::from_config(&config).is_ok());
    }

    #[test]
    fn unsupported_fault_scenario_is_rejected() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = "operator-restart".to_string();

        assert!(FaultScenario::from_config(&config).is_err());
    }

    #[test]
    fn workload_concurrency_must_fit_the_object_count() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.workload = FaultWorkloadProfile {
            object_count: 4,
            concurrency: 5,
        };

        assert!(FaultScenario::from_config(&config).is_err());
    }

    #[test]
    fn fixed_target_scenarios_reject_percent_override() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = POD_KILL_ONE_SCENARIO.to_string();
        config.percent = 50;
        config.percent_overridden = true;

        assert!(FaultScenario::from_config(&config).is_err());
    }

    #[test]
    fn executable_cataloged_fault_scenarios_are_selectable() {
        for spec in executable_scenario_catalog() {
            let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
            config.scenario = spec.scenario.to_string();
            apply_catalog_defaults(&mut config).expect("catalog defaults");

            assert_eq!(spec.status, FaultScenarioStatus::Executable);
            assert!(
                FaultScenario::from_config(&config).is_ok(),
                "{} should be selectable through the real-cluster fault-test entrypoint",
                spec.scenario
            );
        }

        assert_eq!(executable_scenario_catalog().count(), 20);
        assert_eq!(scenario_catalog().len(), 25);
        assert_eq!(
            scenario_catalog()
                .iter()
                .filter(|scenario| scenario.status == FaultScenarioStatus::Planned)
                .count(),
            5
        );
    }

    #[test]
    fn planned_cataloged_fault_scenarios_are_not_selectable() {
        let planned = scenario_catalog()
            .iter()
            .find(|scenario| scenario.status == FaultScenarioStatus::Planned)
            .expect("planned catalog entry");
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = planned.scenario.to_string();

        let error = FaultScenario::from_config(&config).expect_err("planned scenario");

        assert!(error.to_string().contains("not executable yet"));
        assert_eq!(planned.status, FaultScenarioStatus::Planned);
        assert_eq!(
            scenario_spec(STALE_DISK_RETURN_DETECT_SCENARIO)
                .expect("planned stale-disk scenario")
                .status,
            FaultScenarioStatus::Planned
        );
    }

    #[test]
    fn versioned_hot_mutation_profile_updates_runtime_config() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = POD_CRASH_VERSIONED_HOT_SCENARIO.to_string();

        apply_catalog_defaults(&mut config).expect("catalog defaults");

        assert!(config.workload_versioning);
        assert_eq!(
            config.workload_operation_mix,
            WorkloadOperationMix {
                put: 1,
                overwrite: 2,
                get: 1,
                list: 1,
                delete: 2,
                multipart: 3,
            }
        );
        assert_eq!(
            config.workload_hotspot,
            Some(WorkloadHotspot {
                object_percent: 10,
                operation_percent: 80,
            })
        );
        assert_eq!(
            config.workload_payload_distribution,
            Some(WorkloadPayloadDistribution {
                classes: vec![
                    WorkloadPayloadClass {
                        size_bytes: 4 * 1024,
                        weight: 25,
                    },
                    WorkloadPayloadClass {
                        size_bytes: 64 * 1024,
                        weight: 25,
                    },
                    WorkloadPayloadClass {
                        size_bytes: 2 * 1024 * 1024,
                        weight: 30,
                    },
                    WorkloadPayloadClass {
                        size_bytes: 8 * 1024 * 1024,
                        weight: 20,
                    },
                ],
            })
        );
        assert!(FaultScenario::from_config(&config).is_ok());
    }

    #[test]
    fn versioned_hot_mutation_profile_keeps_small_rehearsals_valid() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = DM_FLAKEY_VERSIONED_HOT_SCENARIO.to_string();
        config.workload = FaultWorkloadProfile::new(12, 2).expect("small workload");

        apply_catalog_defaults(&mut config).expect("catalog defaults");

        assert!(config.workload_versioning);
        assert_eq!(
            config.workload_operation_mix,
            WorkloadOperationMix::default()
        );
        assert!(FaultScenario::from_config(&config).is_ok());
    }

    #[test]
    fn catalog_versioning_expectation_includes_scenario_defaults() {
        assert!(
            expected_workload_versioning_for_scenario(POD_CRASH_VERSIONED_HOT_SCENARIO, false)
                .expect("scenario")
        );
        assert!(
            expected_workload_versioning_for_scenario(IO_EIO_SCENARIO, true).expect("scenario")
        );
        assert!(
            expected_workload_versioning_for_scenario(QUORUM_P_IO_FAULT_SCENARIO, false)
                .expect("scenario")
        );
        assert!(
            !expected_workload_versioning_for_scenario(IO_EIO_SCENARIO, false).expect("scenario")
        );
        assert_eq!(
            scenario_spec(POD_CRASH_VERSIONED_HOT_SCENARIO)
                .expect("scenario")
                .workload_profile,
            FaultScenarioWorkloadProfile::VersionedHotMutations
        );
    }

    #[test]
    fn write_quorum_cases_stage_multipart_before_fault_activation() {
        assert!(requires_prefault_multipart_staging(
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO
        ));
        assert!(requires_prefault_multipart_staging(
            QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        ));
        assert!(requires_prefault_multipart_staging(
            QUORUM_P_IO_FAULT_SCENARIO
        ));
    }

    #[test]
    fn catalog_declares_typed_parameter_schema() {
        assert_eq!(
            scenario_spec(NETWORK_DELAY_SCENARIO)
                .expect("network delay")
                .param_schema,
            FaultParameterSchema::NetworkDelay
        );
        assert_eq!(
            scenario_spec(IO_LATENCY_SCENARIO)
                .expect("io latency")
                .param_schema,
            FaultParameterSchema::IoLatency
        );
        assert_eq!(
            scenario_spec(IO_EIO_SCENARIO).expect("io eio").param_schema,
            FaultParameterSchema::None
        );
        for scenario in [
            QUORUM_P_IO_FAULT_SCENARIO,
            QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
        ] {
            assert_eq!(
                scenario_spec(scenario)
                    .expect("quorum scenario")
                    .param_schema,
                FaultParameterSchema::QuorumIo
            );
        }
    }

    #[test]
    fn metadata_quorum_defaults_exercise_versioned_metadata_mutations() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO.to_string();
        config.scenario_parameters = FaultInjectionParameters::QuorumIo {
            class: QuorumCaseClass::Metadata,
        };

        apply_catalog_defaults(&mut config).expect("quorum metadata defaults");

        assert!(config.workload_versioning);
        assert_eq!(config.workload_directory_marker_percent, 100);
        assert_eq!(
            config.workload_operation_mix,
            WorkloadOperationMix {
                put: 1,
                overwrite: 2,
                get: 1,
                list: 1,
                delete: 4,
                multipart: 1,
            }
        );

        let mut payload = FaultTestConfig::for_test("real-cluster", "fast-csi");
        payload.scenario = QUORUM_P_IO_FAULT_SCENARIO.to_string();
        payload.workload_directory_marker_percent = 100;
        payload.scenario_parameters = FaultInjectionParameters::QuorumIo {
            class: QuorumCaseClass::Payload,
        };
        apply_catalog_defaults(&mut payload).expect("quorum payload defaults");
        assert_eq!(payload.workload_directory_marker_percent, 0);
    }

    #[test]
    fn catalog_explicitly_identifies_erasure_set_proof_scenarios() {
        let requiring_proof = scenario_catalog()
            .iter()
            .filter(|scenario| scenario.requires_erasure_set_proof())
            .map(|scenario| scenario.scenario)
            .collect::<Vec<_>>();

        assert_eq!(
            requiring_proof,
            vec![
                NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO,
                QUORUM_P_IO_FAULT_SCENARIO,
                QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
            ]
        );
    }

    #[test]
    fn fault_scenario_catalog_has_unique_clear_and_observable_cases() {
        let mut names = std::collections::HashSet::new();
        let mut case_names = std::collections::HashSet::new();

        for scenario in scenario_catalog() {
            assert!(names.insert(scenario.scenario));
            assert!(case_names.insert(scenario.case_name));
            assert!(!scenario.description.is_empty());
            scenario
                .detector
                .validate(scenario.scenario)
                .expect("valid detector contract");
            assert_eq!(
                scenario.percent_supported,
                scenario.backend.accepts_percent()
                    && scenario.param_schema != FaultParameterSchema::QuorumIo
            );
            assert!(!scenario.boundary.is_empty());
            assert!(!scenario.ci_phase.is_empty());
            assert!(!scenario.target.is_empty());
            assert!(!scenario.target_proof.is_empty());
            assert!(!scenario.validation.is_empty());
            assert!(!scenario.observability.is_empty());
            assert!(!scenario.conflict_domain.is_empty());
        }
    }

    #[test]
    fn catalog_marks_negative_controls_as_diagnostic_only() {
        for name in [
            DM_FLAKEY_VERSIONED_HOT_SCENARIO,
            POD_CRASH_VERSIONED_HOT_SCENARIO,
            WARP_UNDER_CHAOS_SCENARIO,
        ] {
            let detector = scenario_spec(name).expect("scenario").detector;
            assert_eq!(
                detector.qualification,
                DetectorQualification::DiagnosticOnly
            );
            assert!(!detector.detects.is_empty());
        }
        assert!(
            scenario_spec(DM_FLAKEY_VERSIONED_HOT_SCENARIO)
                .expect("scenario")
                .detector
                .detects
                .contains(&DurabilityBugFamily::CommitMetadataLoss)
        );
    }

    #[test]
    fn detector_contract_keeps_revision_one_and_rejects_unknown_revisions() {
        let revision_one = FaultDetectorContract {
            revision: 1,
            qualification: DetectorQualification::GateCandidate,
            detects: vec![DurabilityBugFamily::SilentDataCorruption],
        };
        revision_one
            .validate()
            .expect("revision 1 remains supported");

        let unknown = FaultDetectorContract {
            revision: 2,
            ..revision_one
        };
        let error = unknown.validate().expect_err("unknown revision");
        assert!(error.to_string().contains("supported revisions: 1"));
    }

    #[test]
    fn catalog_exports_machine_readable_json() {
        let json = scenario_catalog_json().expect("catalog json");
        let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");

        assert!(value.as_array().expect("array").len() >= 10);
        assert!(json.contains("\"scenario\": \"io-eio\""));
        assert!(json.contains("\"scenario\": \"quorum-p-io-fault\""));
        assert!(json.contains("\"status\": \"planned\""));
        assert!(json.contains("\"workload_profile\""));
        assert!(json.contains("\"target_proof\""));
        assert!(json.contains("\"crds\""));
        assert!(json.contains("\"impact_policy\""));
        assert!(json.contains("\"qualification\": \"gate-candidate\""));
        assert!(json.contains("\"data-shard-loss\""));
    }
}
