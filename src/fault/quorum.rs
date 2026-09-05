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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const RUNTIME_TOPOLOGY_MAX_AGE_MS: u64 = 5_000;
pub const MAX_ERASURE_SET_SHARDS: u32 = 16;

pub fn require_fresh_runtime_observation(
    observed_at_ms: u64,
    fault_apply_at_ms: u64,
) -> Result<()> {
    ensure!(
        observed_at_ms > 0 && observed_at_ms <= fault_apply_at_ms,
        "runtime topology observation must precede fault application"
    );
    let age_ms = fault_apply_at_ms - observed_at_ms;
    ensure!(
        age_ms <= RUNTIME_TOPOLOGY_MAX_AGE_MS,
        "runtime topology observation is {age_ms}ms old at fault application; maximum is {RUNTIME_TOPOLOGY_MAX_AGE_MS}ms"
    );
    Ok(())
}

/// The S3 mutation whose successful response establishes a new version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuorumMutationClass {
    PutObject,
    MultipartComplete,
    DeleteMarker,
}

/// The already-persisted version shape used by metadata read/merge paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedVersionClass {
    DataObject,
    DeleteMarker,
    ZeroLengthObject,
}

/// The persisted S3 representation whose quorum boundary a volume fault must
/// exercise. Payload and metadata objects use different parity rules in
/// RustFS, so callers must select one explicitly rather than reusing a single
/// hard-coded target count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QuorumCaseClass {
    Payload,
    Metadata,
}

impl QuorumCaseClass {
    pub fn requirements(self, shape: &ErasureSetShape) -> Result<QuorumRequirements> {
        match self {
            Self::Payload => shape.payload_quorum(),
            Self::Metadata => QuorumRequirements::for_persisted_version(
                shape.total_shards,
                shape.payload_parity_shards,
                PersistedVersionClass::DeleteMarker,
            ),
        }
    }
}

/// A semantic volume selection resolved only after the live RustFS erasure
/// geometry has been authenticated and proven fresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumVolumeBoundary {
    pub class: QuorumCaseClass,
    pub beyond_read_tolerance: bool,
}

impl QuorumVolumeBoundary {
    pub fn unavailable_mutations(
        self,
        shape: &ErasureSetShape,
    ) -> Result<Vec<QuorumMutationClass>> {
        shape.validate()?;
        let remaining_shards = shape.total_shards - self.target_count(shape)?;
        let mut unavailable = Vec::new();
        for mutation in [
            QuorumMutationClass::PutObject,
            QuorumMutationClass::DeleteMarker,
            QuorumMutationClass::MultipartComplete,
        ] {
            let requirements = QuorumRequirements::for_mutation(
                shape.total_shards,
                shape.payload_parity_shards,
                mutation,
            )?;
            if remaining_shards < requirements.write_quorum {
                unavailable.push(mutation);
            }
        }
        Ok(unavailable)
    }

    pub fn target_count(self, shape: &ErasureSetShape) -> Result<u32> {
        let requirements = self.class.requirements(shape)?;
        let target_count = requirements
            .read_tolerance
            .checked_add(u32::from(self.beyond_read_tolerance))
            .ok_or_else(|| anyhow::anyhow!("quorum volume target count overflow"))?;
        ensure!(
            target_count > 0 && target_count < shape.total_shards,
            "quorum volume target count {target_count} must leave at least one shard online"
        );
        Ok(target_count)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumVolumeBinding {
    pub pod_name: String,
    pub pod_uid: String,
    pub container_id: String,
    pub mount_path: String,
    pub persistent_volume_claim: String,
    pub persistent_volume: String,
    pub drive_uuid: String,
    pub pool_index: u32,
    pub set_index: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumVolumeTargetProof {
    pub boundary: QuorumVolumeBoundary,
    pub requirements: QuorumRequirements,
    pub target_count: u32,
    pub candidates: Vec<QuorumVolumeBinding>,
}

/// One bounded `/rustfs/admin/v3/info` observation made while the volume
/// fault is active. This proves endpoint health only at the observation
/// boundary; it is not evidence of continuous health between observations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumHealthObservation {
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub deployment_id: String,
    pub shape: ErasureSetShape,
    pub drives: Vec<QuorumDriveHealth>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumDriveHealth {
    pub pod_name: String,
    pub server_endpoint: String,
    pub drive_uuid: String,
    pub state: String,
    pub pool_index: i32,
    pub set_index: i32,
}

impl QuorumHealthObservation {
    pub fn validate(
        &self,
        deployment_id: &str,
        shape: &ErasureSetShape,
        membership: &ErasureSetMembership,
        target: &QuorumVolumeTargetProof,
        selected_pods: &BTreeSet<String>,
    ) -> Result<()> {
        ensure!(
            self.started_at_ms > 0 && self.started_at_ms <= self.completed_at_ms,
            "quorum health observation has an invalid request interval"
        );
        ensure!(
            !deployment_id.trim().is_empty() && self.deployment_id == deployment_id,
            "quorum health observation deployment identity changed"
        );
        ensure!(
            &self.shape == shape,
            "quorum health observation erasure geometry changed"
        );
        target.validate(shape, membership)?;
        ensure!(
            selected_pods.len() == usize::try_from(target.target_count)?
                && selected_pods.iter().all(|pod| target
                    .candidates
                    .iter()
                    .any(|candidate| &candidate.pod_name == pod)),
            "quorum health observation selected Pods do not match the exact target boundary"
        );

        let candidates = target
            .candidates
            .iter()
            .map(|candidate| (candidate.pod_name.as_str(), candidate))
            .collect::<BTreeMap<_, _>>();
        let members = membership
            .members
            .iter()
            .map(|member| (member.pod_name.as_str(), member))
            .collect::<BTreeMap<_, _>>();
        let mut observed = BTreeMap::new();
        for drive in &self.drives {
            ensure!(
                !drive.pod_name.trim().is_empty()
                    && !drive.server_endpoint.trim().is_empty()
                    && !drive.drive_uuid.trim().is_empty()
                    && !drive.state.trim().is_empty()
                    && observed.insert(drive.pod_name.as_str(), drive).is_none(),
                "quorum health observation contains an empty or duplicate drive identity"
            );
        }
        ensure!(
            observed.len() == candidates.len(),
            "quorum health observation does not cover every proven drive candidate"
        );
        for (pod_name, candidate) in candidates {
            let member = members.get(pod_name).ok_or_else(|| {
                anyhow::anyhow!("quorum health candidate Pod {pod_name:?} has no membership row")
            })?;
            let drive = observed.get(pod_name).ok_or_else(|| {
                anyhow::anyhow!("quorum health observation omitted Pod {pod_name:?}")
            })?;
            ensure!(
                member.shard_ids.as_slice() == [candidate.drive_uuid.as_str()]
                    && drive.server_endpoint == member.server_endpoint
                    && drive.drive_uuid == candidate.drive_uuid
                    && drive.pool_index == i32::try_from(shape.pool_index)?
                    && drive.set_index == i32::try_from(shape.set_index)?,
                "quorum health observation identity for Pod {pod_name:?} changed"
            );
            if !selected_pods.contains(pod_name) {
                ensure!(
                    drive.state == "ok",
                    "non-target quorum drive {:?} for Pod {pod_name:?} is not healthy: {:?}",
                    drive.drive_uuid,
                    drive.state
                );
            }
        }
        Ok(())
    }

    pub fn require_within(&self, window_start_ms: u64, window_end_ms: u64) -> Result<()> {
        ensure!(
            window_start_ms <= window_end_ms
                && self.started_at_ms >= window_start_ms
                && self.completed_at_ms <= window_end_ms,
            "quorum health observation is outside its bounded fault window"
        );
        Ok(())
    }
}

impl QuorumVolumeTargetProof {
    pub fn from_runtime(
        shape: &ErasureSetShape,
        membership: &ErasureSetMembership,
        boundary: QuorumVolumeBoundary,
        mut candidates: Vec<QuorumVolumeBinding>,
    ) -> Result<Self> {
        candidates.sort_by(|left, right| left.pod_name.cmp(&right.pod_name));
        let proof = Self {
            boundary,
            requirements: boundary.class.requirements(shape)?,
            target_count: boundary.target_count(shape)?,
            candidates,
        };
        proof.validate(shape, membership)?;
        Ok(proof)
    }

    pub fn validate(
        &self,
        shape: &ErasureSetShape,
        membership: &ErasureSetMembership,
    ) -> Result<()> {
        shape.validate()?;
        membership.validate(shape)?;
        ensure!(
            shape.volumes_per_server == 1 && shape.server_count == shape.total_shards,
            "volume quorum proof requires exactly one RustFS volume per server"
        );
        ensure!(
            self.requirements == self.boundary.class.requirements(shape)?,
            "volume quorum requirements do not match the typed runtime geometry"
        );
        ensure!(
            self.target_count == self.boundary.target_count(shape)?,
            "volume quorum target count does not match the runtime geometry"
        );
        ensure!(
            self.candidates.len() == usize::try_from(shape.total_shards)?,
            "volume quorum proof must bind every shard candidate"
        );

        let unique = |values: Vec<&str>, label: &str| -> Result<()> {
            ensure!(
                values.iter().all(|value| !value.trim().is_empty())
                    && values.iter().copied().collect::<BTreeSet<_>>().len() == values.len(),
                "volume quorum proof requires unique non-empty {label}"
            );
            Ok(())
        };
        unique(
            self.candidates
                .iter()
                .map(|binding| binding.pod_name.as_str())
                .collect(),
            "Pod names",
        )?;
        unique(
            self.candidates
                .iter()
                .map(|binding| binding.pod_uid.as_str())
                .collect(),
            "Pod UIDs",
        )?;
        unique(
            self.candidates
                .iter()
                .map(|binding| binding.container_id.as_str())
                .collect(),
            "container IDs",
        )?;
        unique(
            self.candidates
                .iter()
                .map(|binding| binding.persistent_volume_claim.as_str())
                .collect(),
            "PVC names",
        )?;
        unique(
            self.candidates
                .iter()
                .map(|binding| binding.persistent_volume.as_str())
                .collect(),
            "PV names",
        )?;
        unique(
            self.candidates
                .iter()
                .map(|binding| binding.drive_uuid.as_str())
                .collect(),
            "drive UUIDs",
        )?;

        let members = membership
            .members
            .iter()
            .map(|member| (member.pod_name.as_str(), member))
            .collect::<std::collections::BTreeMap<_, _>>();
        for binding in &self.candidates {
            ensure!(
                binding.pool_index == shape.pool_index
                    && binding.set_index == shape.set_index
                    && !binding.mount_path.trim().is_empty(),
                "volume quorum binding for Pod {:?} is outside the proven set or has no mount",
                binding.pod_name
            );
            let member = members.get(binding.pod_name.as_str()).ok_or_else(|| {
                anyhow::anyhow!(
                    "volume quorum binding Pod {:?} is absent from runtime membership",
                    binding.pod_name
                )
            })?;
            ensure!(
                member.shard_ids.as_slice() == [binding.drive_uuid.as_str()],
                "volume quorum binding for Pod {:?} does not identify its sole runtime drive UUID",
                binding.pod_name
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QuorumRequirements {
    pub total_shards: u32,
    pub data_shards: u32,
    pub parity_shards: u32,
    pub read_quorum: u32,
    pub write_quorum: u32,
    pub read_tolerance: u32,
    pub write_tolerance: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErasureSetHealth {
    pub online_shards: u32,
    pub offline_shards: u32,
    pub unknown_shards: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErasureSetMembership {
    pub members: Vec<ErasureSetMember>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErasureSetMember {
    pub pod_name: String,
    pub server_endpoint: String,
    pub shard_ids: Vec<String>,
}

impl ErasureSetMembership {
    pub fn from_runtime(
        shape: &ErasureSetShape,
        mut members: Vec<ErasureSetMember>,
    ) -> Result<Self> {
        members.sort_by(|left, right| left.pod_name.cmp(&right.pod_name));
        let membership = Self { members };
        membership.validate(shape)?;
        Ok(membership)
    }

    pub fn validate(&self, shape: &ErasureSetShape) -> Result<()> {
        ensure!(
            self.members.len() == usize::try_from(shape.server_count)?,
            "erasure-set membership server count does not match the runtime shape"
        );
        let pod_names = self
            .members
            .iter()
            .map(|member| member.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            pod_names.len() == self.members.len()
                && pod_names.iter().all(|name| !name.trim().is_empty()),
            "erasure-set membership requires unique non-empty Pod names"
        );
        let server_endpoints = self
            .members
            .iter()
            .map(|member| member.server_endpoint.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            server_endpoints.len() == self.members.len()
                && server_endpoints
                    .iter()
                    .all(|endpoint| !endpoint.trim().is_empty()),
            "erasure-set membership requires unique non-empty server endpoints"
        );
        let mut shard_ids = BTreeSet::new();
        for member in &self.members {
            ensure!(
                member.shard_ids.len() == usize::try_from(shape.volumes_per_server)?,
                "Pod {:?} owns {} runtime shards, expected {}",
                member.pod_name,
                member.shard_ids.len(),
                shape.volumes_per_server
            );
            for shard_id in &member.shard_ids {
                ensure!(
                    !shard_id.trim().is_empty() && shard_ids.insert(shard_id),
                    "erasure-set membership contains an empty or duplicate shard id"
                );
            }
        }
        ensure!(
            shard_ids.len() == usize::try_from(shape.total_shards)?,
            "erasure-set membership shard count does not match the runtime shape"
        );
        Ok(())
    }

    pub fn require_selected_boundary<'a>(
        &self,
        shape: &ErasureSetShape,
        selected_pods: impl IntoIterator<Item = &'a str>,
    ) -> Result<()> {
        self.validate(shape)?;
        let selected_pods = selected_pods.into_iter().collect::<BTreeSet<_>>();
        ensure!(
            !selected_pods.is_empty(),
            "selected Pod set must not be empty"
        );
        let known_pods = self
            .members
            .iter()
            .map(|member| member.pod_name.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            selected_pods.is_subset(&known_pods),
            "selected Pod set contains a server outside the runtime erasure set"
        );
        let removed_shards = self
            .members
            .iter()
            .filter(|member| selected_pods.contains(member.pod_name.as_str()))
            .try_fold(0_u32, |count, member| {
                count
                    .checked_add(u32::try_from(member.shard_ids.len())?)
                    .ok_or_else(|| anyhow::anyhow!("selected shard count overflow"))
            })?;
        shape.require_removed_shard_boundary(removed_shards)
    }
}

impl ErasureSetHealth {
    pub fn from_runtime(
        total_shards: u32,
        online_shards: usize,
        offline_shards: usize,
        unknown_shards: usize,
    ) -> Result<Self> {
        let health = Self {
            online_shards: u32::try_from(online_shards)?,
            offline_shards: u32::try_from(offline_shards)?,
            unknown_shards: u32::try_from(unknown_shards)?,
        };
        health.require_all_online(total_shards)?;
        Ok(health)
    }

    pub fn require_all_online(self, total_shards: u32) -> Result<()> {
        let observed_shards = self
            .online_shards
            .checked_add(self.offline_shards)
            .and_then(|count| count.checked_add(self.unknown_shards))
            .ok_or_else(|| anyhow::anyhow!("runtime drive-health count overflow"))?;
        ensure!(
            observed_shards == total_shards,
            "runtime drive health covers {observed_shards} shards, expected {total_shards}"
        );
        ensure!(
            self.online_shards == total_shards
                && self.offline_shards == 0
                && self.unknown_shards == 0,
            "runtime erasure set must be fully online before injection: online={} offline={} unknown={} total={total_shards}",
            self.online_shards,
            self.offline_shards,
            self.unknown_shards
        );
        Ok(())
    }
}

impl QuorumRequirements {
    pub fn for_mutation(
        total_shards: u32,
        payload_parity_shards: u32,
        class: QuorumMutationClass,
    ) -> Result<Self> {
        match class {
            QuorumMutationClass::PutObject | QuorumMutationClass::MultipartComplete => {
                Self::payload(total_shards, payload_parity_shards)
            }
            QuorumMutationClass::DeleteMarker => Self::metadata(total_shards),
        }
    }

    pub fn for_persisted_version(
        total_shards: u32,
        payload_parity_shards: u32,
        class: PersistedVersionClass,
    ) -> Result<Self> {
        match class {
            PersistedVersionClass::DataObject => Self::payload(total_shards, payload_parity_shards),
            PersistedVersionClass::DeleteMarker | PersistedVersionClass::ZeroLengthObject => {
                Self::metadata(total_shards)
            }
        }
    }

    fn payload(total_shards: u32, payload_parity_shards: u32) -> Result<Self> {
        ensure!(
            (2..=MAX_ERASURE_SET_SHARDS).contains(&total_shards),
            "erasure set must contain between 2 and {MAX_ERASURE_SET_SHARDS} shards"
        );
        ensure!(
            payload_parity_shards <= total_shards / 2,
            "payload parity {payload_parity_shards} exceeds half of {total_shards} shards"
        );

        Self::from_geometry(total_shards, payload_parity_shards)
    }

    fn metadata(total_shards: u32) -> Result<Self> {
        ensure!(
            (2..=MAX_ERASURE_SET_SHARDS).contains(&total_shards),
            "erasure set must contain between 2 and {MAX_ERASURE_SET_SHARDS} shards"
        );
        Self::from_geometry(total_shards, total_shards / 2)
    }

    fn from_geometry(total_shards: u32, parity_shards: u32) -> Result<Self> {
        let data_shards = total_shards - parity_shards;
        let read_quorum = data_shards;
        let write_quorum = if data_shards == parity_shards {
            data_shards + 1
        } else {
            data_shards
        };

        Ok(Self {
            total_shards,
            data_shards,
            parity_shards,
            read_quorum,
            write_quorum,
            read_tolerance: total_shards - read_quorum,
            write_tolerance: total_shards - write_quorum,
        })
    }

    pub fn validate(self) -> Result<()> {
        let expected = Self::payload(self.total_shards, self.parity_shards)?;
        ensure!(
            self == expected,
            "quorum requirements do not match the shard geometry"
        );
        Ok(())
    }
}

/// A topology shape whose one-set mapping is proven by the source named in the
/// surrounding target-proof artifact. Indices are explicit so future multi-pool
/// evidence cannot silently reuse a single-set assumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErasureSetShape {
    pub pool_index: u32,
    pub set_index: u32,
    pub server_count: u32,
    pub volumes_per_server: u32,
    pub total_shards: u32,
    pub payload_data_shards: u32,
    pub payload_parity_shards: u32,
}

impl ErasureSetShape {
    pub fn from_runtime_single_set(
        server_count: usize,
        volumes_per_server: u64,
        total_sets: &[usize],
        drives_per_set: &[usize],
        payload_parity_shards: usize,
    ) -> Result<Self> {
        ensure!(
            total_sets == [1] && drives_per_set.len() == 1,
            "runtime topology must report exactly one pool containing one erasure set"
        );

        let tenant_shards = usize::try_from(
            u64::try_from(server_count)?
                .checked_mul(volumes_per_server)
                .ok_or_else(|| anyhow::anyhow!("runtime topology shard count overflow"))?,
        )?;
        ensure!(
            drives_per_set[0] == tenant_shards,
            "runtime drives-per-set {} does not match tenant server/volume width {tenant_shards}",
            drives_per_set[0]
        );
        let total_shards = u32::try_from(drives_per_set[0])?;
        let payload_parity_shards = u32::try_from(payload_parity_shards)?;
        let payload_data_shards = total_shards.checked_sub(payload_parity_shards).ok_or_else(
            || {
                anyhow::anyhow!(
                    "runtime payload parity {payload_parity_shards} exceeds {total_shards} shards"
                )
            },
        )?;
        let shape = Self {
            pool_index: 0,
            set_index: 0,
            server_count: u32::try_from(server_count)?,
            volumes_per_server: u32::try_from(volumes_per_server)?,
            total_shards,
            payload_data_shards,
            payload_parity_shards,
        };
        shape.validate()?;
        Ok(shape)
    }

    pub fn payload_quorum(&self) -> Result<QuorumRequirements> {
        QuorumRequirements::for_mutation(
            self.total_shards,
            self.payload_parity_shards,
            QuorumMutationClass::PutObject,
        )
    }

    pub fn require_server_partition_boundary(&self, target_servers: u32) -> Result<()> {
        ensure!(
            target_servers > 0 && target_servers < self.server_count,
            "partition target count must be smaller than the server count"
        );
        let removed_shards = target_servers
            .checked_mul(self.volumes_per_server)
            .ok_or_else(|| anyhow::anyhow!("partition shard count overflow"))?;
        self.require_removed_shard_boundary(removed_shards)
    }

    fn require_removed_shard_boundary(&self, removed_shards: u32) -> Result<()> {
        let remaining_shards = self
            .total_shards
            .checked_sub(removed_shards)
            .ok_or_else(|| {
                anyhow::anyhow!("partition removes more shards than the set contains")
            })?;
        let quorum = self.payload_quorum()?;
        ensure!(
            remaining_shards >= quorum.read_quorum && remaining_shards < quorum.write_quorum,
            "partition leaves {remaining_shards} shards; the intended boundary requires at least {} for reads but fewer than {} for writes",
            quorum.read_quorum,
            quorum.write_quorum
        );
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(self.server_count > 0, "server_count must be positive");
        ensure!(
            self.volumes_per_server > 0,
            "volumes_per_server must be positive"
        );
        ensure!(
            self.server_count.checked_mul(self.volumes_per_server) == Some(self.total_shards),
            "server_count * volumes_per_server must equal total_shards"
        );
        let quorum = self.payload_quorum()?;
        ensure!(
            quorum.data_shards == self.payload_data_shards,
            "payload_data_shards does not match the quorum model"
        );
        ensure!(
            quorum.parity_shards == self.payload_parity_shards,
            "payload_parity_shards does not match the quorum model"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape,
        PersistedVersionClass, QuorumCaseClass, QuorumDriveHealth, QuorumHealthObservation,
        QuorumMutationClass, QuorumRequirements, QuorumVolumeBinding, QuorumVolumeBoundary,
        QuorumVolumeTargetProof, require_fresh_runtime_observation,
    };

    #[test]
    fn semantic_volume_boundaries_resolve_from_runtime_geometry() {
        let shape =
            ErasureSetShape::from_runtime_single_set(8, 1, &[1], &[8], 2).expect("runtime shape");

        assert_eq!(
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Payload,
                beyond_read_tolerance: false,
            }
            .target_count(&shape)
            .expect("payload P"),
            2
        );
        assert_eq!(
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Payload,
                beyond_read_tolerance: true,
            }
            .target_count(&shape)
            .expect("payload P+1"),
            3
        );
        assert_eq!(
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Metadata,
                beyond_read_tolerance: false,
            }
            .target_count(&shape)
            .expect("metadata P"),
            4
        );
        assert_eq!(
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Metadata,
                beyond_read_tolerance: true,
            }
            .target_count(&shape)
            .expect("metadata P+1"),
            5
        );
    }

    #[test]
    fn unavailable_mutations_follow_each_write_quorum_at_p_and_p_plus_one() {
        for (shards, parity, class, beyond, reject_data, reject_delete) in [
            (4, 2, QuorumCaseClass::Payload, false, true, true),
            (4, 2, QuorumCaseClass::Payload, true, true, true),
            (8, 4, QuorumCaseClass::Payload, true, true, true),
            (8, 2, QuorumCaseClass::Payload, false, false, false),
            (8, 2, QuorumCaseClass::Payload, true, true, false),
            (12, 4, QuorumCaseClass::Payload, true, true, false),
            (8, 2, QuorumCaseClass::Metadata, false, true, true),
            (8, 2, QuorumCaseClass::Metadata, true, true, true),
        ] {
            let shape =
                ErasureSetShape::from_runtime_single_set(shards, 1, &[1], &[shards], parity)
                    .expect("runtime shape");
            let unavailable = QuorumVolumeBoundary {
                class,
                beyond_read_tolerance: beyond,
            }
            .unavailable_mutations(&shape)
            .expect("mutation quorum");
            assert_eq!(
                unavailable.contains(&QuorumMutationClass::PutObject),
                reject_data
            );
            assert_eq!(
                unavailable.contains(&QuorumMutationClass::MultipartComplete),
                reject_data
            );
            assert_eq!(
                unavailable.contains(&QuorumMutationClass::DeleteMarker),
                reject_delete
            );
        }
    }

    #[test]
    fn volume_quorum_proof_requires_complete_unique_one_volume_bindings() {
        let shape =
            ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 2).expect("runtime shape");
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..4)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![format!("drive-{index}")],
                })
                .collect(),
        )
        .expect("membership");
        let candidates = (0..4)
            .map(|index| QuorumVolumeBinding {
                pod_name: format!("rustfs-{index}"),
                pod_uid: format!("uid-{index}"),
                container_id: format!("containerd://container-{index}"),
                mount_path: "/data/rustfs0".to_string(),
                persistent_volume_claim: format!("data-rustfs-{index}"),
                persistent_volume: format!("pv-{index}"),
                drive_uuid: format!("drive-{index}"),
                pool_index: 0,
                set_index: 0,
            })
            .collect::<Vec<_>>();
        let boundary = QuorumVolumeBoundary {
            class: QuorumCaseClass::Metadata,
            beyond_read_tolerance: false,
        };

        let proof = QuorumVolumeTargetProof::from_runtime(
            &shape,
            &membership,
            boundary,
            candidates.clone(),
        )
        .expect("complete proof");
        assert_eq!(proof.target_count, 2);

        let mut missing = candidates.clone();
        missing.pop();
        assert!(
            QuorumVolumeTargetProof::from_runtime(&shape, &membership, boundary, missing).is_err()
        );
        let mut duplicate_drive = candidates;
        duplicate_drive[3].drive_uuid = duplicate_drive[2].drive_uuid.clone();
        assert!(
            QuorumVolumeTargetProof::from_runtime(&shape, &membership, boundary, duplicate_drive,)
                .is_err()
        );
    }

    #[test]
    fn quorum_health_guards_bind_complete_topology_and_non_targets() {
        let shape =
            ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 2).expect("runtime shape");
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..4)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    shard_ids: vec![format!("drive-{index}")],
                })
                .collect(),
        )
        .expect("membership");
        let target = QuorumVolumeTargetProof::from_runtime(
            &shape,
            &membership,
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Metadata,
                beyond_read_tolerance: false,
            },
            (0..4)
                .map(|index| QuorumVolumeBinding {
                    pod_name: format!("rustfs-{index}"),
                    pod_uid: format!("uid-{index}"),
                    container_id: format!("containerd://container-{index}"),
                    mount_path: "/data/rustfs0".to_string(),
                    persistent_volume_claim: format!("data-rustfs-{index}"),
                    persistent_volume: format!("pv-{index}"),
                    drive_uuid: format!("drive-{index}"),
                    pool_index: 0,
                    set_index: 0,
                })
                .collect(),
        )
        .expect("target proof");
        let selected = ["rustfs-0".to_string(), "rustfs-1".to_string()]
            .into_iter()
            .collect::<BTreeSet<_>>();
        let observation = QuorumHealthObservation {
            started_at_ms: 110,
            completed_at_ms: 120,
            deployment_id: "deployment-1".to_string(),
            shape: shape.clone(),
            drives: (0..4)
                .map(|index| QuorumDriveHealth {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}:9000"),
                    drive_uuid: format!("drive-{index}"),
                    state: if index < 2 { "offline" } else { "ok" }.to_string(),
                    pool_index: 0,
                    set_index: 0,
                })
                .collect(),
        };
        observation
            .validate("deployment-1", &shape, &membership, &target, &selected)
            .expect("selected drives may be faulted while every non-target is healthy");
        observation
            .require_within(100, 130)
            .expect("bounded request interval");

        let mut missing = observation.clone();
        missing.drives.pop();
        assert!(
            missing
                .validate("deployment-1", &shape, &membership, &target, &selected)
                .is_err()
        );
        let mut offline_non_target = observation.clone();
        offline_non_target.drives[2].state = "offline".to_string();
        assert!(
            offline_non_target
                .validate("deployment-1", &shape, &membership, &target, &selected)
                .is_err()
        );
        let mut swapped_identity = observation.clone();
        swapped_identity.drives.swap(0, 1);
        swapped_identity.drives[0].pod_name = "rustfs-0".to_string();
        swapped_identity.drives[1].pod_name = "rustfs-1".to_string();
        assert!(
            swapped_identity
                .validate("deployment-1", &shape, &membership, &target, &selected)
                .is_err()
        );
        assert!(
            observation
                .validate("deployment-2", &shape, &membership, &target, &selected)
                .is_err()
        );
        let mut drifted_shape = shape.clone();
        drifted_shape.payload_parity_shards = 1;
        assert!(
            observation
                .validate(
                    "deployment-1",
                    &drifted_shape,
                    &membership,
                    &target,
                    &selected
                )
                .is_err()
        );
        assert!(observation.require_within(111, 130).is_err());
        assert!(observation.require_within(100, 119).is_err());
    }

    #[test]
    fn mutations_and_persisted_versions_use_distinct_boundaries() {
        let payload = QuorumRequirements::for_mutation(12, 4, QuorumMutationClass::PutObject)
            .expect("PUT quorum");
        assert_eq!(payload.read_quorum, 8);
        assert_eq!(payload.write_quorum, 8);
        assert_eq!(payload.read_tolerance, 4);
        assert_eq!(payload.write_tolerance, 4);

        let multipart =
            QuorumRequirements::for_mutation(12, 4, QuorumMutationClass::MultipartComplete)
                .expect("MPU quorum");
        assert_eq!(multipart, payload);

        let delete = QuorumRequirements::for_mutation(12, 4, QuorumMutationClass::DeleteMarker)
            .expect("delete-marker quorum");
        assert_eq!(delete.read_quorum, 6);
        assert_eq!(delete.write_quorum, 7);

        for class in [
            PersistedVersionClass::DeleteMarker,
            PersistedVersionClass::ZeroLengthObject,
        ] {
            let metadata = QuorumRequirements::for_persisted_version(12, 4, class)
                .expect("persisted metadata quorum");
            assert_eq!(metadata.data_shards, 6);
            assert_eq!(metadata.parity_shards, 6);
            assert_eq!(metadata.read_quorum, 6);
            assert_eq!(metadata.write_quorum, 7);
            assert_eq!(metadata.read_tolerance, 6);
            assert_eq!(metadata.write_tolerance, 5);
        }
    }

    #[test]
    fn quorum_validation_rejects_inconsistent_geometry_without_overflow() {
        let valid =
            QuorumRequirements::for_mutation(8, 4, QuorumMutationClass::PutObject).expect("quorum");
        valid.validate().expect("valid geometry");
        let mut wrong_quorum = valid;
        wrong_quorum.write_quorum = 1;
        wrong_quorum.write_tolerance = 7;
        assert!(wrong_quorum.validate().is_err());
        let mut overflowing = valid;
        overflowing.data_shards = u32::MAX;
        assert!(overflowing.validate().is_err());
        let mut too_wide = valid;
        too_wide.total_shards = u32::MAX;
        assert!(too_wide.validate().is_err());
    }

    #[test]
    fn zero_length_put_commit_and_persisted_read_do_not_share_quorum() {
        let commit = QuorumRequirements::for_mutation(12, 4, QuorumMutationClass::PutObject)
            .expect("zero-length PUT commit still uses payload geometry");
        let persisted = QuorumRequirements::for_persisted_version(
            12,
            4,
            PersistedVersionClass::ZeroLengthObject,
        )
        .expect("persisted zero-length version uses metadata geometry");

        assert_eq!(commit.write_quorum, 8);
        assert_eq!(persisted.read_quorum, 6);
        assert_eq!(persisted.write_quorum, 7);
    }

    #[test]
    fn rejects_impossible_payload_geometry() {
        assert!(QuorumRequirements::for_mutation(0, 0, QuorumMutationClass::PutObject).is_err());
        assert!(QuorumRequirements::for_mutation(8, 5, QuorumMutationClass::PutObject).is_err());
    }

    #[test]
    fn runtime_shape_accepts_only_observed_single_set_topologies() {
        let four = ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 2)
            .expect("four-drive shape");
        assert_eq!(four.total_shards, 4);
        assert_eq!(four.payload_data_shards, 2);
        assert_eq!(four.payload_parity_shards, 2);

        let eight = ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4)
            .expect("eight-drive shape");
        assert_eq!(eight.total_shards, 8);
        assert_eq!(eight.payload_data_shards, 4);
        assert_eq!(eight.payload_parity_shards, 4);

        assert!(eight.require_server_partition_boundary(2).is_ok());
        assert!(ErasureSetShape::from_runtime_single_set(4, 2, &[2], &[4], 2).is_err());
        assert!(ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 8).is_err());
        assert!(
            ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 2)
                .expect("runtime EC6+2 shape")
                .require_server_partition_boundary(2)
                .is_err()
        );
    }

    #[test]
    fn runtime_health_requires_every_declared_shard_online() {
        assert!(ErasureSetHealth::from_runtime(8, 8, 0, 0).is_ok());
        assert!(ErasureSetHealth::from_runtime(8, 7, 1, 0).is_err());
        assert!(ErasureSetHealth::from_runtime(8, 7, 0, 1).is_err());
        assert!(ErasureSetHealth::from_runtime(8, 7, 0, 0).is_err());
    }

    #[test]
    fn runtime_observation_age_is_fail_closed() {
        assert!(require_fresh_runtime_observation(1_000, 6_000).is_ok());
        assert!(require_fresh_runtime_observation(1_000, 6_001).is_err());
        assert!(require_fresh_runtime_observation(0, 1).is_err());
        assert!(require_fresh_runtime_observation(2, 1).is_err());
    }

    #[test]
    fn runtime_membership_binds_selected_pods_to_owned_shards() {
        let shape =
            ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4).expect("runtime shape");
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            (0..4)
                .map(|index| ErasureSetMember {
                    pod_name: format!("rustfs-{index}"),
                    server_endpoint: format!("http://rustfs-{index}.rustfs:9000"),
                    shard_ids: vec![format!("drive-{index}-a"), format!("drive-{index}-b")],
                })
                .collect(),
        )
        .expect("runtime membership");

        assert!(
            membership
                .require_selected_boundary(&shape, ["rustfs-0", "rustfs-1"])
                .is_ok()
        );
        let uneven = ErasureSetMembership::from_runtime(
            &shape,
            vec![
                ErasureSetMember {
                    pod_name: "rustfs-0".to_string(),
                    server_endpoint: "http://rustfs-0.rustfs:9000".to_string(),
                    shard_ids: vec!["d0".to_string()],
                },
                ErasureSetMember {
                    pod_name: "rustfs-1".to_string(),
                    server_endpoint: "http://rustfs-1.rustfs:9000".to_string(),
                    shard_ids: vec!["d1".to_string()],
                },
                ErasureSetMember {
                    pod_name: "rustfs-2".to_string(),
                    server_endpoint: "http://rustfs-2.rustfs:9000".to_string(),
                    shard_ids: vec!["d2".to_string(), "d3".to_string(), "d4".to_string()],
                },
                ErasureSetMember {
                    pod_name: "rustfs-3".to_string(),
                    server_endpoint: "http://rustfs-3.rustfs:9000".to_string(),
                    shard_ids: vec!["d5".to_string(), "d6".to_string(), "d7".to_string()],
                },
            ],
        );
        assert!(uneven.is_err());
    }
}
