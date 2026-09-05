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

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::fault::{
    config::FaultTestConfig,
    plan::{FaultPlan, FaultTarget},
    quorum::{ErasureSetHealth, ErasureSetMembership, ErasureSetShape, QuorumVolumeTargetProof},
    reporting::ResponsibilityDomain,
    scenarios::{FaultScenario, FaultScenarioSpec},
};

const PREFLIGHT_SUMMARY_SCHEMA_VERSION: u8 = 1;
pub(crate) const TARGET_PROOF_SCHEMA_VERSION: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightStatus {
    Passed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightSummary {
    pub schema_version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub status: PreflightStatus,
    pub scenario_set: Vec<String>,
    pub checked_at_ms: u64,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub storage_class: String,
    pub phases: Vec<PreflightPhase>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightPhase {
    pub name: String,
    pub status: PreflightStatus,
    pub checks: Vec<PreflightCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PreflightCheck {
    pub name: String,
    pub status: PreflightStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
    pub responsibility_domain: ResponsibilityDomain,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProofStatus {
    Satisfied,
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetProofLevel {
    SelectorIntent,
    ConfiguredHostTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProof {
    pub schema_version: u8,
    pub status: TargetProofStatus,
    pub proof_level: TargetProofLevel,
    pub generated_at_ms: u64,
    pub scenario: String,
    pub case_name: String,
    pub run_id: String,
    pub namespace: String,
    pub tenant: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_pods: Vec<TargetResolvedPodProof>,
    pub faults: Vec<TargetProofFault>,
    pub requirements: Vec<TargetProofRequirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProofFault {
    pub name: String,
    pub kind: String,
    pub backend: String,
    pub target_kind: String,
    pub target_summary: String,
    pub selection: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub selection_kind: String,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub selection_value: u32,
    pub conflict_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pod_selector: Option<TargetPodSelectorProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_target: Option<TargetHostProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erasure_set: Option<TargetErasureSetProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetPodSelectorProof {
    pub namespace: String,
    pub tenant: String,
    pub selector: String,
    pub exact_pods_resolved: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetResolvedPodProof {
    pub name: String,
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rustfs_container_id: Option<String>,
    #[serde(default)]
    pub ready: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persistent_volume_claims: Vec<TargetPersistentVolumeClaimProof>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume_mounts: Vec<TargetVolumeMountProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetVolumeMountProof {
    pub container_name: String,
    pub mount_path: String,
    pub volume_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_volume_claim: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetPersistentVolumeClaimProof {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub persistent_volume: Option<TargetPersistentVolumeProof>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetPersistentVolumeProof {
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub uid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_node_affinity: Option<TargetNodeAffinityProof>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_or_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetNodeAffinityProof {
    pub well_formed: bool,
    pub terms: Vec<TargetNodeSelectorTermProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetNodeSelectorTermProof {
    pub match_expressions: Vec<TargetNodeSelectorRequirementProof>,
    pub match_fields: Vec<TargetNodeSelectorRequirementProof>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetNodeSelectorRequirementProof {
    pub key: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetHostProof {
    pub node: String,
    pub mapper_name: String,
    pub mount_path: String,
    pub has_fault_table: bool,
    pub has_recovery_table: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetErasureSetProof {
    pub required: bool,
    pub resolved: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployment_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shape: Option<ErasureSetShape>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ErasureSetHealth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub membership: Option<ErasureSetMembership>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_quorum: Option<QuorumVolumeTargetProof>,
    #[serde(default, skip_serializing_if = "is_zero_u64")]
    pub observed_at_ms: u64,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetProofRequirement {
    pub name: String,
    pub status: PreflightStatus,
    pub message: String,
}

impl PreflightSummary {
    pub fn single_run(
        config: &FaultTestConfig,
        scenario: &str,
        run_id: &str,
        phases: Vec<PreflightPhase>,
    ) -> Self {
        let status = if phases
            .iter()
            .any(|phase| phase.status == PreflightStatus::Failed)
        {
            PreflightStatus::Failed
        } else {
            PreflightStatus::Passed
        };

        Self {
            schema_version: PREFLIGHT_SUMMARY_SCHEMA_VERSION,
            run_id: Some(run_id.to_string()),
            status,
            scenario_set: vec![scenario.to_string()],
            checked_at_ms: now_ms(),
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            storage_class: config.cluster.storage_class.clone(),
            phases,
        }
    }
}

impl PreflightPhase {
    pub fn new(name: impl Into<String>, checks: Vec<PreflightCheck>) -> Self {
        let status = if checks
            .iter()
            .any(|check| check.status == PreflightStatus::Failed)
        {
            PreflightStatus::Failed
        } else {
            PreflightStatus::Passed
        };
        Self {
            name: name.into(),
            status,
            checks,
        }
    }
}

impl PreflightCheck {
    pub fn passed(
        name: impl Into<String>,
        message: impl Into<String>,
        responsibility_domain: ResponsibilityDomain,
    ) -> Self {
        Self {
            name: name.into(),
            status: PreflightStatus::Passed,
            expected: None,
            actual: None,
            responsibility_domain,
            message: message.into(),
        }
    }

    pub fn failed(
        name: impl Into<String>,
        message: impl Into<String>,
        responsibility_domain: ResponsibilityDomain,
    ) -> Self {
        Self {
            name: name.into(),
            status: PreflightStatus::Failed,
            expected: None,
            actual: None,
            responsibility_domain,
            message: message.into(),
        }
    }
}

impl TargetProof {
    pub fn from_plan(
        config: &FaultTestConfig,
        scenario: &FaultScenario,
        spec: &FaultScenarioSpec,
        plan: &FaultPlan,
        run_id: &str,
    ) -> Self {
        let faults = plan
            .faults()
            .iter()
            .enumerate()
            .map(|(index, fault)| TargetProofFault {
                name: format!("{}-{:02}-{}", scenario.name, index, fault.kind().as_str()),
                kind: fault.kind().as_str().to_string(),
                backend: fault.backend().as_str().to_string(),
                target_kind: target_kind(fault.target()).to_string(),
                target_summary: fault.target_summary(),
                selection: fault.selection().summary(),
                selection_kind: fault.selection().kind().to_string(),
                selection_value: fault.selection().value(),
                conflict_domain: spec.conflict_domain.to_string(),
                pod_selector: pod_selector_proof(config, fault.target()),
                volume_path: volume_path(fault.target()),
                host_target: host_target_proof(config, fault.target()),
                erasure_set: erasure_set_proof(spec),
            })
            .collect::<Vec<_>>();
        let mut requirements = target_requirements(config, spec, plan);
        if erasure_set_proof(spec).is_some() {
            requirements.push(TargetProofRequirement {
                name: ERASURE_SET_PROOF_REQUIREMENT.to_string(),
                status: PreflightStatus::Failed,
                message: "same-erasure-set runtime observation is pending".to_string(),
            });
        }
        let status = if requirements
            .iter()
            .any(|requirement| requirement.status == PreflightStatus::Failed)
        {
            TargetProofStatus::Missing
        } else {
            TargetProofStatus::Satisfied
        };
        let proof_level = if faults.iter().any(|fault| fault.host_target.is_some()) {
            TargetProofLevel::ConfiguredHostTarget
        } else {
            TargetProofLevel::SelectorIntent
        };

        Self {
            schema_version: TARGET_PROOF_SCHEMA_VERSION,
            status,
            proof_level,
            generated_at_ms: now_ms(),
            scenario: scenario.name.clone(),
            case_name: scenario.case_name.to_string(),
            run_id: run_id.to_string(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            resolved_pods: Vec::new(),
            faults,
            requirements,
        }
    }

    pub fn with_resolved_pods(self, pods: impl IntoIterator<Item = (String, String)>) -> Self {
        let proofs = pods
            .into_iter()
            .map(|(name, uid)| TargetResolvedPodProof::new(name, uid))
            .collect::<Vec<_>>();
        self.with_resolved_pod_proofs(proofs)
    }

    pub fn with_resolved_pod_proofs(
        mut self,
        pods: impl IntoIterator<Item = TargetResolvedPodProof>,
    ) -> Self {
        self.resolved_pods = pods.into_iter().collect();
        self.resolved_pods.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| left.uid.cmp(&right.uid))
        });
        for fault in &mut self.faults {
            if let Some(selector) = &mut fault.pod_selector {
                selector.exact_pods_resolved = !self.resolved_pods.is_empty();
                selector.note = if selector.exact_pods_resolved {
                    "preflight resolved current RustFS target pods; backend selectors still apply at injection time".to_string()
                } else {
                    "preflight proves selector intent but did not resolve current pods".to_string()
                };
            }
        }
        self.record_runtime_target_requirements();
        self
    }

    /// Marks the same-erasure-set requirement as satisfied after the runner's
    /// live topology proof has passed. The proof itself runs in the runner
    /// (it reads the live Tenant's pool geometry, which the plan-time proof
    /// cannot see); this only records its outcome so the fail-closed
    /// requirement reflects evidence instead of rejecting the scenario
    /// unconditionally.
    pub fn with_erasure_set_topology_proven(
        mut self,
        shape: ErasureSetShape,
        health: ErasureSetHealth,
        membership: ErasureSetMembership,
        deployment_id: impl Into<String>,
        observed_at_ms: u64,
    ) -> Result<Self> {
        shape.validate()?;
        health.require_all_online(shape.total_shards)?;
        membership.validate(&shape)?;
        let deployment_id = deployment_id.into();
        anyhow::ensure!(
            !deployment_id.trim().is_empty(),
            "deployment id must not be empty"
        );
        anyhow::ensure!(observed_at_ms > 0, "observation timestamp must be positive");
        anyhow::ensure!(
            self.faults.iter().any(|fault| fault.erasure_set.is_some()),
            "target proof does not require erasure-set evidence"
        );
        anyhow::ensure!(
            self.resolved_pods.len() == usize::try_from(shape.server_count)?,
            "resolved pod count does not match runtime erasure-set server count"
        );
        let pod_names = self
            .resolved_pods
            .iter()
            .map(|pod| pod.name.as_str())
            .collect::<BTreeSet<_>>();
        let pod_uids = self
            .resolved_pods
            .iter()
            .map(|pod| pod.uid.as_str())
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            pod_names.len() == self.resolved_pods.len()
                && pod_uids.len() == self.resolved_pods.len()
                && pod_names.iter().all(|name| !name.trim().is_empty())
                && pod_uids.iter().all(|uid| !uid.trim().is_empty()),
            "runtime erasure-set proof requires unique non-empty Pod names and UIDs"
        );
        anyhow::ensure!(
            self.resolved_pods.iter().all(|pod| pod.ready),
            "runtime erasure-set proof requires every resolved pod to be Ready"
        );
        let membership_pods = membership
            .members
            .iter()
            .map(|member| member.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            membership_pods == pod_names,
            "runtime erasure-set membership does not match the resolved RustFS Pods"
        );
        for fault in &mut self.faults {
            if let Some(proof) = &mut fault.erasure_set {
                proof.resolved = true;
                proof.source = Some("rustfs-admin-server-info".to_string());
                proof.deployment_id = Some(deployment_id.clone());
                proof.shape = Some(shape.clone());
                proof.health = Some(health);
                proof.membership = Some(membership.clone());
                proof.volume_quorum = None;
                proof.observed_at_ms = observed_at_ms;
                proof.note = ERASURE_SET_PROOF_RESOLVED_NOTE.to_string();
            }
        }
        for requirement in &mut self.requirements {
            if requirement.name == ERASURE_SET_PROOF_REQUIREMENT {
                requirement.status = PreflightStatus::Passed;
                requirement.message = ERASURE_SET_PROOF_RESOLVED_NOTE.to_string();
            }
        }
        self.generated_at_ms = now_ms();
        self.status = if self
            .requirements
            .iter()
            .any(|requirement| requirement.status == PreflightStatus::Failed)
        {
            TargetProofStatus::Missing
        } else {
            TargetProofStatus::Satisfied
        };
        Ok(self)
    }

    pub fn with_volume_quorum_proven(mut self, quorum: QuorumVolumeTargetProof) -> Result<Self> {
        let erasure_set = self
            .faults
            .iter()
            .find_map(|fault| fault.erasure_set.as_ref())
            .context("target proof does not contain erasure-set evidence")?;
        let shape = erasure_set
            .shape
            .as_ref()
            .context("target proof erasure-set shape is unresolved")?;
        let membership = erasure_set
            .membership
            .as_ref()
            .context("target proof erasure-set membership is unresolved")?;
        quorum.validate(shape, membership)?;
        self.validate_volume_quorum_bindings(&quorum)?;
        let erasure_set = self
            .faults
            .iter_mut()
            .find_map(|fault| fault.erasure_set.as_mut())
            .context("target proof does not contain erasure-set evidence")?;
        erasure_set.volume_quorum = Some(quorum);
        for requirement in &mut self.requirements {
            if requirement.name == "volume_quorum_bindings" {
                requirement.status = PreflightStatus::Passed;
                requirement.message = "bound every one-volume-per-server Pod/container/PVC/PV/mount to its sole RustFS drive UUID and resolved the typed quorum target count".to_string();
            }
        }
        self.generated_at_ms = now_ms();
        self.status = if self
            .requirements
            .iter()
            .any(|requirement| requirement.status == PreflightStatus::Failed)
        {
            TargetProofStatus::Missing
        } else {
            TargetProofStatus::Satisfied
        };
        Ok(self)
    }

    pub(crate) fn validate_volume_quorum_bindings(
        &self,
        quorum: &QuorumVolumeTargetProof,
    ) -> Result<()> {
        let volume_path = self
            .faults
            .iter()
            .find(|fault| fault.selection_kind == "runtime-quorum")
            .and_then(|fault| fault.volume_path.as_deref())
            .context("volume quorum target proof has no runtime-quorum volume path")?;
        anyhow::ensure!(
            quorum.candidates.len() == self.resolved_pods.len(),
            "volume quorum bindings do not cover every resolved Pod"
        );
        for binding in &quorum.candidates {
            anyhow::ensure!(
                binding.mount_path == volume_path,
                "volume quorum binding for Pod {:?} does not use the fault target mount path",
                binding.pod_name
            );
            let matches = self
                .resolved_pods
                .iter()
                .filter(|pod| pod.name == binding.pod_name)
                .collect::<Vec<_>>();
            let [pod] = matches.as_slice() else {
                anyhow::bail!(
                    "volume quorum binding for Pod {:?} must match exactly one resolved Pod",
                    binding.pod_name
                )
            };
            anyhow::ensure!(
                pod.uid == binding.pod_uid
                    && pod.rustfs_container_id.as_deref() == Some(binding.container_id.as_str()),
                "volume quorum binding for Pod {:?} does not match its resolved Pod UID/container ID",
                binding.pod_name
            );
            let mounts = pod
                .volume_mounts
                .iter()
                .filter(|mount| {
                    mount.container_name == "rustfs"
                        && mount.mount_path == binding.mount_path
                        && mount.persistent_volume_claim.as_deref()
                            == Some(binding.persistent_volume_claim.as_str())
                })
                .collect::<Vec<_>>();
            anyhow::ensure!(
                mounts.len() == 1,
                "volume quorum binding for Pod {:?} does not match exactly one resolved RustFS mount/PVC",
                binding.pod_name
            );
            let claims = pod
                .persistent_volume_claims
                .iter()
                .filter(|claim| {
                    claim.name == binding.persistent_volume_claim
                        && claim.volume_name.as_deref() == Some(binding.persistent_volume.as_str())
                        && claim.persistent_volume.as_ref().map(|pv| pv.name.as_str())
                            == Some(binding.persistent_volume.as_str())
                })
                .count();
            anyhow::ensure!(
                claims == 1,
                "volume quorum binding for Pod {:?} does not match exactly one resolved PVC/PV",
                binding.pod_name
            );
        }
        Ok(())
    }

    pub fn preflight_check(&self) -> PreflightCheck {
        match self.status {
            TargetProofStatus::Satisfied => PreflightCheck::passed(
                "target_proof",
                "target proof artifact describes every planned fault target",
                ResponsibilityDomain::Harness,
            ),
            TargetProofStatus::Missing => PreflightCheck::failed(
                "target_proof",
                "target proof is missing required target evidence",
                ResponsibilityDomain::Harness,
            ),
        }
    }

    pub fn require_satisfied(&self) -> Result<()> {
        anyhow::ensure!(
            self.status == TargetProofStatus::Satisfied,
            "target-proof.json did not satisfy all target requirements"
        );
        Ok(())
    }

    fn record_runtime_target_requirements(&mut self) {
        let requires_selector = self.faults.iter().any(|fault| fault.pod_selector.is_some());
        let requires_host_target = self.faults.iter().any(|fault| fault.host_target.is_some());
        let requires_volume_binding = self
            .faults
            .iter()
            .any(|fault| fault.volume_path.is_some() || fault.host_target.is_some());
        if requires_selector || requires_host_target {
            self.requirements.push(TargetProofRequirement {
                name: "target_pods_resolved".to_string(),
                status: if self.resolved_pods.is_empty() {
                    PreflightStatus::Failed
                } else {
                    PreflightStatus::Passed
                },
                message: if self.resolved_pods.is_empty() {
                    "no current RustFS pods matched the target selector".to_string()
                } else {
                    format!(
                        "resolved {} current RustFS target pod(s)",
                        self.resolved_pods.len()
                    )
                },
            });
            let pods_have_nodes = self
                .resolved_pods
                .iter()
                .all(|pod| pod.node.as_deref().is_some_and(|node| !node.is_empty()));
            self.requirements.push(TargetProofRequirement {
                name: "target_pod_nodes_resolved".to_string(),
                status: if pods_have_nodes {
                    PreflightStatus::Passed
                } else {
                    PreflightStatus::Failed
                },
                message: if pods_have_nodes {
                    "resolved target pod node placement".to_string()
                } else {
                    "target pod node placement is missing".to_string()
                },
            });
        }
        if requires_volume_binding {
            let volume_bindings_resolved = !self.resolved_pods.is_empty()
                && self.resolved_pods.iter().all(target_pod_has_bound_volume);
            self.requirements.push(TargetProofRequirement {
                name: "target_volume_bindings_resolved".to_string(),
                status: if volume_bindings_resolved {
                    PreflightStatus::Passed
                } else {
                    PreflightStatus::Failed
                },
                message: if volume_bindings_resolved {
                    "resolved target pod PVC/PV/node/device-or-path bindings".to_string()
                } else {
                    "target pod PVC/PV/node/device-or-path binding proof is incomplete".to_string()
                },
            });
            if let Some(required_targets) = self
                .faults
                .iter()
                .filter(|fault| {
                    fault.volume_path.is_some() && fault.selection_kind == "fixed-targets"
                })
                .map(|fault| fault.selection_value)
                .max()
            {
                let volume_path = self
                    .faults
                    .iter()
                    .find(|fault| {
                        fault.volume_path.is_some() && fault.selection_kind == "fixed-targets"
                    })
                    .and_then(|fault| fault.volume_path.as_deref())
                    .unwrap_or_default();
                let eligible_candidates = self
                    .resolved_pods
                    .iter()
                    .filter(|pod| pod.ready && target_pod_has_fixed_volume(pod, volume_path))
                    .count();
                // The IOChaos tenant selector may choose any resolved Pod.
                let enough_candidates = eligible_candidates == self.resolved_pods.len()
                    && usize::try_from(required_targets)
                        .is_ok_and(|required| required > 0 && eligible_candidates >= required);
                self.requirements.push(TargetProofRequirement {
                    name: "fixed_volume_target_candidates_resolved".to_string(),
                    status: if enough_candidates {
                        PreflightStatus::Passed
                    } else {
                        PreflightStatus::Failed
                    },
                    message: format!(
                        "proved {} of {} selector Pod(s) for {} fixed volume target(s)",
                        eligible_candidates,
                        self.resolved_pods.len(),
                        required_targets
                    ),
                });
            }
            if self
                .faults
                .iter()
                .any(|fault| fault.selection_kind == "runtime-quorum")
            {
                self.requirements.push(TargetProofRequirement {
                    name: "volume_quorum_bindings".to_string(),
                    status: PreflightStatus::Failed,
                    message: "runtime quorum count and drive-to-volume bindings are pending live RustFS topology observation".to_string(),
                });
            }
        }
        self.status = if self
            .requirements
            .iter()
            .any(|requirement| requirement.status == PreflightStatus::Failed)
        {
            TargetProofStatus::Missing
        } else {
            TargetProofStatus::Satisfied
        };
    }
}

impl TargetResolvedPodProof {
    pub fn new(name: impl Into<String>, uid: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            uid: uid.into(),
            rustfs_container_id: None,
            ready: false,
            node: None,
            node_labels: BTreeMap::new(),
            persistent_volume_claims: Vec::new(),
            volume_mounts: Vec::new(),
        }
    }

    pub fn with_node(mut self, node: impl Into<String>) -> Self {
        self.node = Some(node.into());
        self
    }

    pub fn with_rustfs_container_id(mut self, container_id: impl Into<String>) -> Self {
        self.rustfs_container_id = Some(container_id.into());
        self
    }

    pub fn with_node_labels(mut self, node_labels: BTreeMap<String, String>) -> Self {
        self.node_labels = node_labels;
        self
    }

    pub fn with_ready(mut self, ready: bool) -> Self {
        self.ready = ready;
        self
    }

    pub fn with_persistent_volume_claims(
        mut self,
        persistent_volume_claims: Vec<TargetPersistentVolumeClaimProof>,
    ) -> Self {
        self.persistent_volume_claims = persistent_volume_claims;
        self
    }

    pub fn with_volume_mounts(mut self, volume_mounts: Vec<TargetVolumeMountProof>) -> Self {
        self.volume_mounts = volume_mounts;
        self
    }
}

pub(crate) fn target_pod_has_bound_volume(pod: &TargetResolvedPodProof) -> bool {
    !pod.persistent_volume_claims.is_empty()
        && pod.persistent_volume_claims.iter().all(|claim| {
            claim
                .volume_name
                .as_deref()
                .is_some_and(|volume| !volume.is_empty())
                && claim.persistent_volume.as_ref().is_some_and(|pv| {
                    !pv.name.is_empty()
                        && pv
                            .device_or_path
                            .as_deref()
                            .is_some_and(|path| !path.is_empty())
                })
        })
}

pub(crate) fn target_pod_has_fixed_volume(
    pod: &TargetResolvedPodProof,
    expected_mount_path: &str,
) -> bool {
    if expected_mount_path.is_empty()
        || pod
            .rustfs_container_id
            .as_deref()
            .is_none_or(|id| id.trim().is_empty())
    {
        return false;
    }
    if pod.node.as_deref().is_none_or(str::is_empty) || pod.node_labels.is_empty() {
        return false;
    }
    pod.volume_mounts.iter().any(|mount| {
        if mount.container_name != "rustfs"
            || mount.mount_path != expected_mount_path
            || mount.volume_name.is_empty()
        {
            return false;
        }
        let Some(claim_name) = mount.persistent_volume_claim.as_deref() else {
            return false;
        };
        pod.persistent_volume_claims.iter().any(|claim| {
            claim.name == claim_name
                && claim
                    .volume_name
                    .as_deref()
                    .is_some_and(|volume_name| !volume_name.is_empty())
                && claim.persistent_volume.as_ref().is_some_and(|pv| {
                    claim.volume_name.as_deref() == Some(pv.name.as_str())
                        && pv
                            .device_or_path
                            .as_deref()
                            .is_some_and(|path| !path.is_empty())
                        && match pv.source.as_deref() {
                            Some("local") | Some("host-path") => pv
                                .required_node_affinity
                                .as_ref()
                                .is_some_and(|affinity| node_affinity_matches(pod, affinity)),
                            Some("csi") => pv
                                .required_node_affinity
                                .as_ref()
                                .is_none_or(|affinity| node_affinity_matches(pod, affinity)),
                            _ => false,
                        }
                })
        })
    })
}

fn node_affinity_matches(pod: &TargetResolvedPodProof, affinity: &TargetNodeAffinityProof) -> bool {
    if !affinity.well_formed || affinity.terms.len() != 1 {
        return false;
    }
    let term = &affinity.terms[0];
    if !term.match_fields.is_empty() || term.match_expressions.is_empty() {
        return false;
    }
    term.match_expressions.iter().all(|requirement| {
        requirement.operator == "In"
            && !requirement.key.is_empty()
            && !requirement.values.is_empty()
            && pod
                .node_labels
                .get(&requirement.key)
                .is_some_and(|value| requirement.values.contains(value))
    })
}

fn target_requirements(
    config: &FaultTestConfig,
    spec: &FaultScenarioSpec,
    plan: &FaultPlan,
) -> Vec<TargetProofRequirement> {
    let mut requirements = vec![TargetProofRequirement {
        name: "catalog_target_intent".to_string(),
        status: PreflightStatus::Passed,
        message: spec.target.to_string(),
    }];

    for fault in plan.faults() {
        if matches!(fault.target(), FaultTarget::DedicatedBlockDevice) {
            requirements.extend([
                host_requirement("dm_name", config.dm_name.as_deref()),
                host_requirement("dm_node", config.dm_node.as_deref()),
                host_requirement("dm_mount_path", config.dm_mount_path.as_deref()),
                host_requirement("dm_fault_table", config.dm_fault_table.as_deref()),
            ]);
        }
    }

    requirements
}

fn host_requirement(name: &str, value: Option<&str>) -> TargetProofRequirement {
    let status = if value.is_some_and(|value| !value.trim().is_empty()) {
        PreflightStatus::Passed
    } else {
        PreflightStatus::Failed
    };
    TargetProofRequirement {
        name: name.to_string(),
        status,
        message: match status {
            PreflightStatus::Passed => "configured".to_string(),
            PreflightStatus::Failed => "required for dedicated block-device target".to_string(),
        },
    }
}

fn target_kind(target: &FaultTarget) -> &'static str {
    match target {
        FaultTarget::RustfsVolume { .. } => "rustfs-volume",
        FaultTarget::RustfsServerPod => "rustfs-server-pod",
        FaultTarget::RustfsServerPeerNetwork => "rustfs-server-peer-network",
        FaultTarget::RustfsServerResource => "rustfs-server-resource",
        FaultTarget::DedicatedBlockDevice => "dedicated-block-device",
    }
}

fn pod_selector_proof(
    config: &FaultTestConfig,
    target: &FaultTarget,
) -> Option<TargetPodSelectorProof> {
    match target {
        FaultTarget::RustfsVolume { .. }
        | FaultTarget::RustfsServerPod
        | FaultTarget::RustfsServerPeerNetwork
        | FaultTarget::RustfsServerResource => Some(TargetPodSelectorProof {
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            selector: format!("rustfs.tenant={}", config.cluster.tenant_name),
            exact_pods_resolved: false,
            note: "preflight proves the selector intent; runtime pod identity is captured in fault-evidence.json".to_string(),
        }),
        FaultTarget::DedicatedBlockDevice => None,
    }
}

fn volume_path(target: &FaultTarget) -> Option<String> {
    match target {
        FaultTarget::RustfsVolume { path } => Some(path.clone()),
        FaultTarget::RustfsServerPod
        | FaultTarget::RustfsServerPeerNetwork
        | FaultTarget::RustfsServerResource
        | FaultTarget::DedicatedBlockDevice => None,
    }
}

fn host_target_proof(config: &FaultTestConfig, target: &FaultTarget) -> Option<TargetHostProof> {
    if !matches!(target, FaultTarget::DedicatedBlockDevice) {
        return None;
    }
    Some(TargetHostProof {
        node: config.dm_node.clone().unwrap_or_default(),
        mapper_name: config.dm_name.clone().unwrap_or_default(),
        mount_path: config.dm_mount_path.clone().unwrap_or_default(),
        has_fault_table: config.dm_fault_table.is_some(),
        has_recovery_table: config.dm_recovery_table.is_some(),
    })
}

fn erasure_set_proof(spec: &FaultScenarioSpec) -> Option<TargetErasureSetProof> {
    spec.requires_erasure_set_proof()
        .then(|| TargetErasureSetProof {
            required: true,
            resolved: false,
            source: None,
            deployment_id: None,
            shape: None,
            health: None,
            membership: None,
            volume_quorum: None,
            observed_at_ms: 0,
            note: ERASURE_SET_PROOF_PENDING_NOTE.to_string(),
        })
}

const ERASURE_SET_PROOF_PENDING_NOTE: &str =
    "same-erasure-set runtime observation is pending for this scenario";
const ERASURE_SET_PROOF_RESOLVED_NOTE: &str =
    "same-erasure-set topology proven from RustFS admin runtime geometry before fault apply";
pub const ERASURE_SET_PROOF_REQUIREMENT: &str = "same_erasure_set_target_proof";

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

#[cfg(test)]
mod tests {
    use super::{
        PreflightStatus, TargetNodeAffinityProof, TargetNodeSelectorRequirementProof,
        TargetNodeSelectorTermProof, TargetPersistentVolumeClaimProof, TargetPersistentVolumeProof,
        TargetProof, TargetProofStatus, TargetResolvedPodProof, TargetVolumeMountProof,
        target_pod_has_fixed_volume,
    };
    use crate::fault::{
        config::FaultTestConfig,
        plan::{FaultPlan, FaultPlanOptions},
        quorum::{ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape},
        scenarios::{FaultScenario, scenario_spec},
    };
    use std::collections::BTreeMap;

    #[test]
    fn target_proof_captures_selector_intent_for_chaos_mesh_targets() {
        let mut config = FaultTestConfig::for_test("k3d-lab", "local-path");
        config.scenario = "pod-kill-one".to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            spec,
            FaultPlanOptions::from_config(&config),
        )
        .expect("plan");

        let proof = TargetProof::from_plan(&config, &scenario, spec, &plan, "run-1")
            .with_resolved_pod_proofs([
                TargetResolvedPodProof::new("rustfs-0", "uid-0").with_node("node-a")
            ]);

        assert_eq!(proof.status, TargetProofStatus::Satisfied);
        assert_eq!(proof.faults.len(), 1);
        assert_eq!(proof.resolved_pods.len(), 1);
        assert_eq!(
            proof.faults[0].pod_selector.as_ref().unwrap().selector,
            "rustfs.tenant=fault-test-tenant"
        );
        assert!(
            proof.faults[0]
                .pod_selector
                .as_ref()
                .unwrap()
                .exact_pods_resolved
        );
        assert_eq!(proof.preflight_check().status, PreflightStatus::Passed);
    }

    #[test]
    fn target_proof_fails_closed_for_incomplete_host_target() {
        let mut config = FaultTestConfig::for_test("k3d-lab", "local-path");
        config.scenario = "dm-flakey".to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            spec,
            FaultPlanOptions::from_config(&config),
        )
        .expect("plan");

        let proof = TargetProof::from_plan(&config, &scenario, spec, &plan, "run-1");

        assert_eq!(proof.status, TargetProofStatus::Missing);
        assert!(proof.require_satisfied().is_err());
    }

    #[test]
    fn percent_volume_proof_accepts_csi_pv_without_hostname_affinity() {
        let mut config = FaultTestConfig::for_test("k3d-lab", "fast-csi");
        config.scenario = "io-eio".to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            spec,
            FaultPlanOptions::from_config(&config),
        )
        .expect("percent plan");
        let pod = TargetResolvedPodProof::new("rustfs-0", "uid-0")
            .with_node("node-a")
            .with_ready(true)
            .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                name: "data-rustfs-0".to_string(),
                uid: "pvc-uid-0".to_string(),
                volume_name: Some("pv-csi".to_string()),
                storage_class: Some("fast-csi".to_string()),
                persistent_volume: Some(TargetPersistentVolumeProof {
                    name: "pv-csi".to_string(),
                    uid: "pv-uid-0".to_string(),
                    source: Some("csi".to_string()),
                    required_node_affinity: None,
                    node: None,
                    device_or_path: Some("csi-volume-handle".to_string()),
                }),
            }]);

        let proof = TargetProof::from_plan(&config, &scenario, spec, &plan, "run-1")
            .with_resolved_pod_proofs([pod]);

        assert_eq!(proof.status, TargetProofStatus::Satisfied);
        assert!(proof.require_satisfied().is_ok());
    }

    fn fixed_volume_pod(
        source: &str,
        affinity: Option<TargetNodeAffinityProof>,
        node_labels: BTreeMap<String, String>,
    ) -> TargetResolvedPodProof {
        let mut pod = TargetResolvedPodProof::new("rustfs-0", "uid-0")
            .with_node("node-a")
            .with_node_labels(node_labels)
            .with_ready(true)
            .with_volume_mounts(vec![TargetVolumeMountProof {
                container_name: "rustfs".to_string(),
                mount_path: "/data/rustfs0".to_string(),
                volume_name: "data".to_string(),
                persistent_volume_claim: Some("data-rustfs-0".to_string()),
            }])
            .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                name: "data-rustfs-0".to_string(),
                uid: "pvc-uid-0".to_string(),
                volume_name: Some("pv-a".to_string()),
                storage_class: Some("fast-csi".to_string()),
                persistent_volume: Some(TargetPersistentVolumeProof {
                    name: "pv-a".to_string(),
                    uid: "pv-uid-0".to_string(),
                    source: Some(source.to_string()),
                    required_node_affinity: affinity,
                    node: None,
                    device_or_path: Some("volume-handle".to_string()),
                }),
            }]);
        pod.rustfs_container_id = Some("containerd://rustfs-0".to_string());
        pod
    }

    fn affinity(terms: Vec<Vec<(&str, &str, Vec<&str>)>>) -> TargetNodeAffinityProof {
        TargetNodeAffinityProof {
            well_formed: true,
            terms: terms
                .into_iter()
                .map(|requirements| TargetNodeSelectorTermProof {
                    match_expressions: requirements
                        .into_iter()
                        .map(
                            |(key, operator, values)| TargetNodeSelectorRequirementProof {
                                key: key.to_string(),
                                operator: operator.to_string(),
                                values: values.into_iter().map(str::to_string).collect(),
                            },
                        )
                        .collect(),
                    match_fields: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn fixed_volume_topology_honors_hostname_in_value_or_semantics() {
        let pod = fixed_volume_pod(
            "local",
            Some(affinity(vec![vec![(
                "kubernetes.io/hostname",
                "In",
                vec!["node-b", "node-a"],
            )]])),
            BTreeMap::from([("kubernetes.io/hostname".to_string(), "node-a".to_string())]),
        );

        assert!(target_pod_has_fixed_volume(&pod, "/data/rustfs0"));
    }

    #[test]
    fn fixed_volume_topology_checks_csi_zone_labels() {
        let required = Some(affinity(vec![vec![(
            "topology.kubernetes.io/zone",
            "In",
            vec!["zone-a"],
        )]]));
        let matching = fixed_volume_pod(
            "csi",
            required.clone(),
            BTreeMap::from([(
                "topology.kubernetes.io/zone".to_string(),
                "zone-a".to_string(),
            )]),
        );
        let mismatched = fixed_volume_pod(
            "csi",
            required,
            BTreeMap::from([(
                "topology.kubernetes.io/zone".to_string(),
                "zone-b".to_string(),
            )]),
        );

        assert!(target_pod_has_fixed_volume(&matching, "/data/rustfs0"));
        assert!(!target_pod_has_fixed_volume(&mismatched, "/data/rustfs0"));
    }

    #[test]
    fn fixed_volume_topology_rejects_unsupported_affinity_semantics() {
        let labels = BTreeMap::from([("kubernetes.io/hostname".to_string(), "node-a".to_string())]);
        let mut match_fields =
            affinity(vec![vec![("kubernetes.io/hostname", "In", vec!["node-a"])]]);
        match_fields.terms[0]
            .match_fields
            .push(TargetNodeSelectorRequirementProof {
                key: "metadata.name".to_string(),
                operator: "In".to_string(),
                values: vec!["node-a".to_string()],
            });
        let mut malformed = affinity(vec![vec![("kubernetes.io/hostname", "In", vec!["node-a"])]]);
        malformed.well_formed = false;
        for unsupported in [
            affinity(vec![vec![(
                "kubernetes.io/hostname",
                "NotIn",
                vec!["node-b"],
            )]]),
            affinity(vec![vec![("kubernetes.io/hostname", "Exists", Vec::new())]]),
            affinity(vec![
                vec![("kubernetes.io/hostname", "In", vec!["node-a"])],
                vec![("topology.kubernetes.io/zone", "In", vec!["zone-a"])],
            ]),
            match_fields,
            malformed,
        ] {
            let pod = fixed_volume_pod("local", Some(unsupported), labels.clone());
            assert!(!target_pod_has_fixed_volume(&pod, "/data/rustfs0"));
        }
    }

    #[test]
    fn write_quorum_loss_target_proof_requires_and_records_topology_proof() {
        let mut config = FaultTestConfig::for_test("k3d-lab", "local-path");
        config.scenario =
            crate::fault::scenarios::NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO.to_string();
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let spec = scenario_spec(&scenario.name).expect("spec");
        let plan = FaultPlan::from_scenario_with_options(
            &scenario,
            spec,
            FaultPlanOptions::from_config(&config),
        )
        .expect("plan");

        // Fail-closed until the runner's live topology proof has passed: the
        // spec targets an erasure set, so the requirement starts Failed.
        let unproven = TargetProof::from_plan(&config, &scenario, spec, &plan, "run-1")
            .with_resolved_pod_proofs([
                TargetResolvedPodProof::new("rustfs-0", "uid-0").with_node("node-a")
            ]);
        assert_eq!(unproven.status, TargetProofStatus::Missing);
        assert!(unproven.require_satisfied().is_err());

        // Once the runner records the passed proof, the same evidence set is
        // satisfied — the requirement flips instead of staying unconditional.
        let proven = TargetProof::from_plan(&config, &scenario, spec, &plan, "run-1")
            .with_resolved_pod_proofs((0..4).map(|index| {
                TargetResolvedPodProof::new(format!("rustfs-{index}"), format!("uid-{index}"))
                    .with_node(format!("node-{index}"))
                    .with_ready(true)
            }))
            .with_erasure_set_topology_proven(
                ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4)
                    .expect("runtime shape"),
                ErasureSetHealth::from_runtime(8, 8, 0, 0).expect("runtime health"),
                ErasureSetMembership::from_runtime(
                    &ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4)
                        .expect("runtime shape"),
                    (0..4)
                        .map(|index| ErasureSetMember {
                            pod_name: format!("rustfs-{index}"),
                            server_endpoint: format!("http://rustfs-{index}.rustfs:9000"),
                            shard_ids: vec![format!("drive-{index}-a"), format!("drive-{index}-b")],
                        })
                        .collect(),
                )
                .expect("runtime membership"),
                "deployment-1",
                1,
            )
            .expect("valid runtime proof");
        assert_eq!(proven.status, TargetProofStatus::Satisfied);
        assert!(proven.require_satisfied().is_ok());
        let requirement = proven
            .requirements
            .iter()
            .find(|requirement| requirement.name == super::ERASURE_SET_PROOF_REQUIREMENT)
            .expect("erasure-set requirement present");
        assert_eq!(requirement.status, PreflightStatus::Passed);
        assert!(
            proven
                .faults
                .iter()
                .all(|fault| fault.erasure_set.as_ref().is_some_and(|p| {
                    p.resolved
                        && p.shape
                            .as_ref()
                            .is_some_and(|shape| shape.total_shards == 8)
                }))
        );
    }
}
