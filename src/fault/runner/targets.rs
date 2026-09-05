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

use super::now_ms;
use crate::{
    fault::{
        backends::chaos_mesh,
        config::FaultTestConfig,
        plan::{FaultKind, FaultPlan, FaultSelection},
        pods::{fixed_volume_container_ids, rustfs_pod_identities, rustfs_target_inventory},
        preflight::{TargetProof, TargetResolvedPodProof, target_pod_has_fixed_volume},
        quorum::{
            ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape,
            QuorumDriveHealth, QuorumHealthObservation, QuorumVolumeBinding, QuorumVolumeBoundary,
            QuorumVolumeTargetProof,
        },
        reporting::{FaultStatusSnapshot, PodIdentity},
    },
    framework::kubectl::Kubectl,
    rustfs::read_erasure_layout,
};
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn plan_requires_volume_bindings(plan: &FaultPlan) -> bool {
    plan.faults().iter().any(|fault| {
        matches!(
            fault.target(),
            crate::fault::plan::FaultTarget::RustfsVolume { .. }
                | crate::fault::plan::FaultTarget::DedicatedBlockDevice
        )
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ObservedErasureSet {
    pub(super) source: &'static str,
    pub(super) deployment_id: String,
    pub(super) shape: ErasureSetShape,
    pub(super) health: ErasureSetHealth,
    pub(super) membership: ErasureSetMembership,
    pub(super) observed_at_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ObservedVolumeQuorum {
    pub(super) topology: ObservedErasureSet,
    pub(super) volume_quorum: QuorumVolumeTargetProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TenantPoolGeometry {
    server_count: usize,
    volumes_per_server: u64,
}

pub(super) async fn require_write_quorum_loss_topology(
    config: &FaultTestConfig,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    target_servers: u32,
    pods: &[PodIdentity],
) -> Result<ObservedErasureSet> {
    // Age the combined proof from its oldest input: Tenant geometry is read
    // before the admin layout, so a slow second read must not refresh the
    // apparent age of the first observation.
    let observed_at_ms = now_ms();
    let cluster = &config.cluster;
    let output = Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command(["get", "tenant", cluster.tenant_name.as_str(), "-o", "json"])
        .run_checked()
        .context("reading tenant pool geometry for the write-quorum-loss topology proof")?;
    let tenant: serde_json::Value =
        serde_json::from_str(&output.stdout).context("decoding tenant topology JSON")?;
    let tenant = tenant_single_pool_geometry(&tenant, config.expected_rustfs_pod_count)?;
    let runtime = read_erasure_layout(endpoint, "us-east-1", access_key, secret_key)
        .await
        .context("reading RustFS admin erasure layout")?;
    let shape = ErasureSetShape::from_runtime_single_set(
        tenant.server_count,
        tenant.volumes_per_server,
        &runtime.total_sets,
        &runtime.drives_per_set,
        runtime.standard_parity,
    )
    .context("RustFS runtime does not report a single erasure set matching the Tenant")?;
    let health = ErasureSetHealth::from_runtime(
        shape.total_shards,
        runtime.online_drives,
        runtime.offline_drives,
        runtime.unknown_drives,
    )
    .context("RustFS runtime erasure set is not fully online before fault injection")?;
    let membership = runtime_single_set_membership(&runtime, &shape, pods)?;
    shape.require_server_partition_boundary(target_servers)?;
    Ok(ObservedErasureSet {
        source: "rustfs-admin-server-info",
        deployment_id: runtime.deployment_id,
        shape,
        health,
        membership,
        observed_at_ms,
    })
}

pub(super) async fn require_volume_quorum_topology(
    config: &FaultTestConfig,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    boundary: QuorumVolumeBoundary,
    resolved_pods: &[TargetResolvedPodProof],
    volume_path: &str,
) -> Result<ObservedVolumeQuorum> {
    let observed_at_ms = now_ms();
    let cluster = &config.cluster;
    let output = Kubectl::new(cluster)
        .namespaced(&cluster.test_namespace)
        .command(["get", "tenant", cluster.tenant_name.as_str(), "-o", "json"])
        .run_checked()
        .context("reading tenant pool geometry for the volume quorum proof")?;
    let tenant: serde_json::Value =
        serde_json::from_str(&output.stdout).context("decoding tenant topology JSON")?;
    let tenant = tenant_single_pool_geometry(&tenant, config.expected_rustfs_pod_count)?;
    ensure!(
        tenant.volumes_per_server == 1,
        "volume quorum proof requires a FreshTenant with exactly one volume per server; observed {}",
        tenant.volumes_per_server
    );
    let runtime = read_erasure_layout(endpoint, "us-east-1", access_key, secret_key)
        .await
        .context("reading RustFS admin erasure layout for the volume quorum proof")?;
    let shape = ErasureSetShape::from_runtime_single_set(
        tenant.server_count,
        tenant.volumes_per_server,
        &runtime.total_sets,
        &runtime.drives_per_set,
        runtime.standard_parity,
    )
    .context("RustFS runtime does not report one set matching the one-volume-per-server Tenant")?;
    let health = ErasureSetHealth::from_runtime(
        shape.total_shards,
        runtime.online_drives,
        runtime.offline_drives,
        runtime.unknown_drives,
    )
    .context("RustFS runtime erasure set is not fully online before volume fault injection")?;
    let identities = resolved_pods
        .iter()
        .map(|pod| PodIdentity {
            name: pod.name.clone(),
            uid: pod.uid.clone(),
        })
        .collect::<Vec<_>>();
    let membership = runtime_single_set_membership(&runtime, &shape, &identities)?;
    let candidates =
        bind_runtime_drives_to_volumes(&shape, &membership, resolved_pods, volume_path)?;
    let volume_quorum =
        QuorumVolumeTargetProof::from_runtime(&shape, &membership, boundary, candidates)?;
    Ok(ObservedVolumeQuorum {
        topology: ObservedErasureSet {
            source: "rustfs-admin-server-info",
            deployment_id: runtime.deployment_id,
            shape,
            health,
            membership,
            observed_at_ms,
        },
        volume_quorum,
    })
}

pub(super) async fn observe_volume_quorum_health(
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    target_proof: &TargetProof,
    selected_pods: &BTreeSet<String>,
) -> Result<QuorumHealthObservation> {
    let erasure_set = target_proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .context("volume quorum health guard has no proven erasure set")?;
    let expected_shape = erasure_set
        .shape
        .as_ref()
        .context("volume quorum health guard has no proven erasure geometry")?;
    let expected_membership = erasure_set
        .membership
        .as_ref()
        .context("volume quorum health guard has no proven membership")?;
    let target = erasure_set
        .volume_quorum
        .as_ref()
        .context("volume quorum health guard has no proven volume candidates")?;
    let deployment_id = erasure_set
        .deployment_id
        .as_deref()
        .context("volume quorum health guard has no deployment identity")?;
    let candidate_pods = target
        .candidates
        .iter()
        .map(|candidate| candidate.pod_name.as_str())
        .collect::<BTreeSet<_>>();
    let started_at_ms = now_ms();
    let runtime = read_erasure_layout(endpoint, "us-east-1", access_key, secret_key)
        .await
        .context("reading bounded RustFS quorum health observation")?;
    let completed_at_ms = now_ms();
    let shape = ErasureSetShape::from_runtime_single_set(
        usize::try_from(expected_shape.server_count)?,
        u64::from(expected_shape.volumes_per_server),
        &runtime.total_sets,
        &runtime.drives_per_set,
        runtime.standard_parity,
    )
    .context("quorum health observation erasure geometry changed")?;
    let mut drives = Vec::new();
    for server in runtime.servers {
        let pod_name = runtime_server_pod_name(&server.endpoint, &candidate_pods)?;
        for drive in server.drives {
            drives.push(QuorumDriveHealth {
                pod_name: pod_name.clone(),
                server_endpoint: server.endpoint.clone(),
                drive_uuid: drive.uuid,
                state: drive.state,
                pool_index: drive.pool_index,
                set_index: drive.set_index,
            });
        }
    }
    let observation = QuorumHealthObservation {
        started_at_ms,
        completed_at_ms,
        deployment_id: runtime.deployment_id,
        shape,
        drives,
    };
    observation.validate(
        deployment_id,
        expected_shape,
        expected_membership,
        target,
        selected_pods,
    )?;
    Ok(observation)
}

fn bind_runtime_drives_to_volumes(
    shape: &ErasureSetShape,
    membership: &ErasureSetMembership,
    pods: &[TargetResolvedPodProof],
    volume_path: &str,
) -> Result<Vec<QuorumVolumeBinding>> {
    ensure!(
        shape.volumes_per_server == 1,
        "drive-to-volume binding is only sound with one volume per server"
    );
    let pods = pods
        .iter()
        .map(|pod| (pod.name.as_str(), pod))
        .collect::<BTreeMap<_, _>>();
    membership
        .members
        .iter()
        .map(|member| {
            let pod = pods.get(member.pod_name.as_str()).with_context(|| {
                format!("runtime drive member Pod {:?} has no resolved Kubernetes proof", member.pod_name)
            })?;
            ensure!(
                pod.ready && target_pod_has_fixed_volume(pod, volume_path),
                "Pod {:?} lacks the Ready Pod/container/PVC/PV/mount proof required for volume quorum",
                pod.name
            );
            let matching_mounts = pod
                .volume_mounts
                .iter()
                .filter(|mount| mount.container_name == "rustfs" && mount.mount_path == volume_path)
                .collect::<Vec<_>>();
            let [mount] = matching_mounts.as_slice() else {
                bail!(
                    "Pod {:?} must expose exactly one RustFS mount at {volume_path:?}",
                    pod.name
                )
            };
            let claim_name = mount
                .persistent_volume_claim
                .as_deref()
                .context("RustFS target mount is not backed by a PVC")?;
            let matching_claims = pod
                .persistent_volume_claims
                .iter()
                .filter(|claim| claim.name == claim_name)
                .collect::<Vec<_>>();
            let [claim] = matching_claims.as_slice() else {
                bail!("Pod {:?} target mount must resolve to exactly one PVC", pod.name)
            };
            let pv = claim
                .persistent_volume
                .as_ref()
                .context("RustFS target PVC has no bound PV proof")?;
            ensure!(
                claim.volume_name.as_deref() == Some(pv.name.as_str()),
                "Pod {:?} target PVC/PV names are inconsistent",
                pod.name
            );
            let [drive_uuid] = member.shard_ids.as_slice() else {
                bail!(
                    "Pod {:?} must own exactly one runtime drive UUID for one-volume-per-server proof",
                    pod.name
                )
            };
            Ok(QuorumVolumeBinding {
                pod_name: pod.name.clone(),
                pod_uid: pod.uid.clone(),
                container_id: pod
                    .rustfs_container_id
                    .clone()
                    .context("RustFS target Pod has no container ID")?,
                mount_path: mount.mount_path.clone(),
                persistent_volume_claim: claim.name.clone(),
                persistent_volume: pv.name.clone(),
                drive_uuid: drive_uuid.clone(),
                pool_index: shape.pool_index,
                set_index: shape.set_index,
            })
        })
        .collect()
}

fn runtime_single_set_membership(
    runtime: &crate::rustfs::RustfsErasureLayout,
    shape: &ErasureSetShape,
    pods: &[PodIdentity],
) -> Result<ErasureSetMembership> {
    let candidate_pods = pods
        .iter()
        .map(|pod| pod.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        candidate_pods.len() == pods.len()
            && candidate_pods.iter().all(|name| !name.trim().is_empty()),
        "runtime topology proof requires unique non-empty candidate Pod names"
    );

    let members = runtime
        .servers
        .iter()
        .map(|server| {
            let pod_name = runtime_server_pod_name(&server.endpoint, &candidate_pods)?;
            let shard_ids = server
                .drives
                .iter()
                .map(|drive| {
                    ensure!(
                        drive.state == "ok",
                        "RustFS runtime drive {:?} for Pod {pod_name:?} is not healthy: {:?}",
                        drive.uuid, drive.state
                    );
                    ensure!(
                        drive.pool_index == i32::try_from(shape.pool_index)?
                            && drive.set_index == i32::try_from(shape.set_index)?,
                        "RustFS runtime drive {:?} for Pod {pod_name:?} is outside the proven pool/set",
                        drive.uuid
                    );
                    ensure!(
                        !drive.uuid.trim().is_empty(),
                        "RustFS runtime drive for Pod {pod_name:?} has an empty UUID"
                    );
                    Ok(drive.uuid.clone())
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(ErasureSetMember {
                pod_name,
                server_endpoint: server.endpoint.clone(),
                shard_ids,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ErasureSetMembership::from_runtime(shape, members)
        .context("RustFS server/drive membership does not match the proven erasure-set shape")
}

fn runtime_server_pod_name(endpoint: &str, candidate_pods: &BTreeSet<&str>) -> Result<String> {
    let endpoint_with_scheme = if endpoint.contains("://") {
        endpoint.to_string()
    } else {
        format!("http://{endpoint}")
    };
    let url = reqwest::Url::parse(&endpoint_with_scheme)
        .with_context(|| format!("parse RustFS server endpoint {endpoint:?}"))?;
    let host = url
        .host_str()
        .with_context(|| format!("RustFS server endpoint {endpoint:?} has no host"))?;
    let matching_pods = candidate_pods
        .iter()
        .filter(|pod| host == **pod || host.starts_with(&format!("{}.", pod)))
        .copied()
        .collect::<Vec<_>>();
    ensure!(
        matching_pods.len() == 1,
        "RustFS server endpoint {endpoint:?} does not identify exactly one resolved Pod"
    );
    Ok(matching_pods[0].to_string())
}

fn tenant_single_pool_geometry(
    tenant: &serde_json::Value,
    expected_server_count: usize,
) -> Result<TenantPoolGeometry> {
    let pools = tenant
        .pointer("/spec/pools")
        .and_then(serde_json::Value::as_array)
        .context("tenant spec.pools must be an array")?;
    ensure!(
        pools.len() == 1,
        "quorum topology proof requires exactly one tenant pool, found {}",
        pools.len()
    );
    let pool = &pools[0];
    let server_count = pool
        .get("servers")
        .and_then(serde_json::Value::as_u64)
        .context("tenant spec.pools[0].servers must be a positive integer")?;
    let server_count = usize::try_from(server_count)?;
    ensure!(
        server_count == expected_server_count,
        "tenant pool server count {server_count} does not match configured expected RustFS pod count {expected_server_count}"
    );
    let volumes_per_server = pool
        .pointer("/persistence/volumesPerServer")
        .and_then(serde_json::Value::as_u64)
        .context("tenant spec.pools[0].persistence.volumesPerServer must be a positive integer")?;
    Ok(TenantPoolGeometry {
        server_count,
        volumes_per_server,
    })
}

pub(super) fn fixed_volume_target_count(plan: &FaultPlan) -> Option<u32> {
    let [fault] = plan.faults() else {
        return None;
    };
    if !matches!(
        fault.kind(),
        FaultKind::RustfsVolumeIoError
            | FaultKind::RustfsVolumeLatency
            | FaultKind::RustfsVolumeReadMistake
            | FaultKind::RustfsVolumeEnospc
    ) {
        return None;
    }
    match fault.selection() {
        FaultSelection::FixedTargets(count) => Some(count),
        FaultSelection::Percent(_) | FaultSelection::RuntimeQuorum(_) => None,
    }
}

pub(super) fn volume_quorum_boundary(plan: &FaultPlan) -> Option<QuorumVolumeBoundary> {
    let [fault] = plan.faults() else {
        return None;
    };
    match fault.selection() {
        FaultSelection::RuntimeQuorum(boundary) => Some(boundary),
        FaultSelection::Percent(_) | FaultSelection::FixedTargets(_) => None,
    }
}

pub(super) fn requires_fixed_volume_runtime_proof(plan: &FaultPlan) -> bool {
    fixed_volume_target_count(plan).is_some() || volume_quorum_boundary(plan).is_some()
}

#[derive(Default)]
pub(super) struct FixedVolumeTargets {
    pub(super) pods: Vec<PodIdentity>,
    pub(super) records: BTreeSet<String>,
    pub(super) containers: BTreeMap<String, String>,
}

pub(super) fn require_active_fixed_volume_targets(
    config: &FaultTestConfig,
    run_id: &str,
    injection: &crate::fault::plan::FaultInjection,
    scenario: &str,
    pods_before: &[PodIdentity],
    target_proof: &TargetProof,
    snapshots: &[FaultStatusSnapshot],
) -> Result<FixedVolumeTargets> {
    let expected_targets = match injection.selection() {
        FaultSelection::FixedTargets(count) => count,
        FaultSelection::Percent(_) | FaultSelection::RuntimeQuorum(_) => {
            bail!("fixed volume runtime proof requires a resolved fixed-target volume fault")
        }
    };
    let volume_path = injection.rustfs_volume_path()?;
    ensure!(
        snapshots.len() == 1,
        "fixed volume plan requires exactly one runtime fault snapshot"
    );
    let inventory = rustfs_target_inventory(&config.cluster, false, false)
        .context("resolve RustFS container identities while fixed-target IOChaos is active")?;
    let pods_active = inventory.identities;
    let proof_identities = unique_pod_identity_pairs(
        "target-proof RustFS Pods",
        target_proof
            .resolved_pods
            .iter()
            .map(|pod| (pod.name.clone(), pod.uid.clone()))
            .collect(),
    )?;
    let active_identities = unique_runtime_pod_identities("active RustFS Pods", &pods_active)?;
    let before_identities = unique_runtime_pod_identities("pre-fault RustFS Pods", pods_before)?;
    ensure!(
        active_identities == before_identities && active_identities == proof_identities,
        "RustFS Pod identities changed between target proof and IOChaos activation"
    );
    let candidate_pod_ids = target_proof
        .resolved_pods
        .iter()
        .filter(|pod| pod.ready && target_pod_has_fixed_volume(pod, volume_path))
        .map(|pod| format!("{}/{}", config.cluster.test_namespace, pod.name))
        .collect::<BTreeSet<_>>();
    ensure!(
        candidate_pod_ids.len() == proof_identities.len(),
        "fixed volume target proof must cover every selector Pod"
    );
    let runtime_contract = chaos_mesh::volume_fault_runtime_contract(injection)?;
    let snapshot = &snapshots[0];
    ensure!(
        snapshot.resource_kind.as_deref() == Some("iochaos"),
        "fixed volume runtime snapshot is not an IOChaos resource"
    );
    let resource = snapshot
        .chaos_status
        .as_ref()
        .context("fixed volume runtime snapshot has no IOChaos object")?;
    ensure!(
        snapshot.resource_name.as_deref()
            == resource
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str),
        "fixed volume runtime snapshot resource name is inconsistent"
    );
    let record_ids = chaos_mesh::validate_fixed_volume_snapshot(
        resource,
        &chaos_mesh::VolumeTargetEvidenceContract {
            chaos_namespace: &config.chaos_namespace,
            target_namespace: &config.cluster.test_namespace,
            tenant: &config.cluster.tenant_name,
            run_id,
            scenario,
            volume_path,
            expected_targets,
            candidate_pod_ids: &candidate_pod_ids,
            runtime: &runtime_contract,
        },
    )?;
    let selected_pods = selected_fixed_volume_pod_identities(
        &config.cluster.test_namespace,
        pods_active,
        &record_ids,
        expected_targets,
    )?;
    let selected_names = selected_pods.iter().map(|pod| pod.name.clone()).collect();
    let containers = fixed_volume_container_ids(&inventory.pod_proofs, &selected_names)?;
    let expected_containers =
        fixed_volume_container_ids(&target_proof.resolved_pods, &selected_names)?;
    // IOChaos is attached to a container's mount namespace; a restart preserves
    // the Pod UID while replacing that namespace and invalidating its proof.
    ensure!(
        containers == expected_containers,
        "fixed volume RustFS container identities changed after target proof"
    );
    if let Some(volume_quorum) = target_proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .and_then(|proof| proof.volume_quorum.as_ref())
    {
        ensure!(
            volume_quorum.target_count == expected_targets,
            "resolved IOChaos target count does not match the proven runtime quorum boundary"
        );
        let selected_names = selected_pods
            .iter()
            .map(|pod| pod.name.as_str())
            .collect::<BTreeSet<_>>();
        let selected_drives = volume_quorum
            .candidates
            .iter()
            .filter(|binding| selected_names.contains(binding.pod_name.as_str()))
            .map(|binding| binding.drive_uuid.as_str())
            .collect::<BTreeSet<_>>();
        let non_target_drives = volume_quorum
            .candidates
            .iter()
            .filter(|binding| !selected_names.contains(binding.pod_name.as_str()))
            .map(|binding| binding.drive_uuid.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            selected_drives.len() == usize::try_from(expected_targets)?
                && selected_drives.is_disjoint(&non_target_drives)
                && selected_drives.len() + non_target_drives.len()
                    == volume_quorum.candidates.len(),
            "actual IOChaos selection does not partition every proven same-set drive into exact target and non-target sets"
        );
    }
    Ok(FixedVolumeTargets {
        pods: selected_pods,
        records: record_ids,
        containers,
    })
}

fn unique_runtime_pod_identities(
    label: &str,
    pods: &[PodIdentity],
) -> Result<BTreeSet<(String, String)>> {
    unique_pod_identity_pairs(
        label,
        pods.iter()
            .map(|pod| (pod.name.clone(), pod.uid.clone()))
            .collect(),
    )
}

fn unique_pod_identity_pairs(
    label: &str,
    identity_pairs: Vec<(String, String)>,
) -> Result<BTreeSet<(String, String)>> {
    ensure!(!identity_pairs.is_empty(), "{label} must not be empty");
    let identities = identity_pairs.iter().cloned().collect::<BTreeSet<_>>();
    let names = identity_pairs
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    let uids = identity_pairs
        .iter()
        .map(|(_, uid)| uid.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        identity_pairs
            .iter()
            .all(|(name, uid)| !name.trim().is_empty() && !uid.trim().is_empty())
            && identities.len() == identity_pairs.len()
            && names.len() == identity_pairs.len()
            && uids.len() == identity_pairs.len(),
        "{label} must contain unique non-empty Pod names and UIDs"
    );
    Ok(identities)
}

fn selected_fixed_volume_pod_identities(
    namespace: &str,
    pods: Vec<PodIdentity>,
    record_ids: &BTreeSet<String>,
    expected_targets: u32,
) -> Result<Vec<PodIdentity>> {
    let selected_pod_ids = record_ids
        .iter()
        .map(|record_id| chaos_mesh::iochaos_record_pod_id(record_id))
        .collect::<Result<BTreeSet<_>>>()?;
    let selected_pods = pods
        .into_iter()
        .filter(|pod| selected_pod_ids.contains(&format!("{namespace}/{}", pod.name)))
        .collect::<Vec<_>>();
    ensure!(
        selected_pods.len() == usize::try_from(expected_targets)?,
        "IOChaos controller targets do not resolve to exactly {expected_targets} live Pod identities"
    );
    unique_runtime_pod_identities("selected fixed volume Pods", &selected_pods)?;
    Ok(selected_pods)
}

pub(super) fn write_quorum_partition_target_count(plan: &FaultPlan) -> Result<u32> {
    let [fault] = plan.faults() else {
        bail!("write-quorum-loss topology proof requires exactly one planned fault")
    };
    match fault.selection() {
        FaultSelection::FixedTargets(count) => Ok(count),
        FaultSelection::Percent(_) => {
            bail!("write-quorum-loss topology proof requires a fixed target count")
        }
        FaultSelection::RuntimeQuorum(_) => {
            bail!("write-quorum-loss topology proof does not accept volume quorum selection")
        }
    }
}

pub(super) fn require_active_write_quorum_partition(
    config: &FaultTestConfig,
    run_id: &str,
    plan: &FaultPlan,
    pods_before: &[PodIdentity],
    target_proof: &TargetProof,
    snapshots: &[FaultStatusSnapshot],
) -> Result<(Vec<PodIdentity>, BTreeSet<String>)> {
    ensure!(
        snapshots.len() == 1,
        "write-quorum-loss plan requires exactly one runtime fault snapshot"
    );
    let pods_active = rustfs_pod_identities(&config.cluster)
        .context("resolve RustFS Pod identities while NetworkChaos is active")?;
    let identity_set = |pods: &[PodIdentity]| {
        pods.iter()
            .map(|pod| (pod.name.clone(), pod.uid.clone()))
            .collect::<BTreeSet<_>>()
    };
    ensure!(
        identity_set(&pods_active) == identity_set(pods_before),
        "RustFS Pod identities changed between target proof and NetworkChaos activation"
    );
    let candidate_pod_ids = pods_active
        .iter()
        .map(|pod| format!("{}/{}", config.cluster.test_namespace, pod.name))
        .collect::<BTreeSet<_>>();
    let snapshot = &snapshots[0];
    ensure!(
        snapshot.resource_kind.as_deref() == Some("networkchaos"),
        "write-quorum-loss runtime snapshot is not a NetworkChaos resource"
    );
    let resource = snapshot
        .chaos_status
        .as_ref()
        .context("write-quorum-loss runtime snapshot has no NetworkChaos object")?;
    ensure!(
        snapshot.resource_name.as_deref()
            == resource
                .pointer("/metadata/name")
                .and_then(serde_json::Value::as_str),
        "write-quorum-loss runtime snapshot resource name is inconsistent"
    );
    let targets = chaos_mesh::validate_network_partition_snapshot(
        resource,
        &chaos_mesh::NetworkPartitionEvidenceContract {
            chaos_namespace: &config.chaos_namespace,
            target_namespace: &config.cluster.test_namespace,
            tenant: &config.cluster.tenant_name,
            run_id,
            scenario: &plan.scenario,
            expected_source_targets: write_quorum_partition_target_count(plan)?,
            candidate_pod_ids: &candidate_pod_ids,
        },
    )?;
    let erasure_set = target_proof
        .faults
        .iter()
        .find_map(|fault| fault.erasure_set.as_ref())
        .context("target proof has no runtime erasure-set evidence")?;
    let shape = erasure_set
        .shape
        .as_ref()
        .context("target proof runtime erasure-set evidence has no shape")?;
    let membership = erasure_set
        .membership
        .as_ref()
        .context("target proof runtime erasure-set evidence has no server/drive membership")?;
    let namespace_prefix = format!("{}/", config.cluster.test_namespace);
    let selected_pods = targets
        .iter()
        .map(|target| {
            target.strip_prefix(&namespace_prefix).with_context(|| {
                format!("NetworkChaos selected target {target:?} is outside the test namespace")
            })
        })
        .collect::<Result<Vec<_>>>()?;
    membership
        .require_selected_boundary(shape, selected_pods)
        .context("actual NetworkChaos source targets do not cross the write-quorum boundary")?;
    Ok((pods_active, targets))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{
        fault::{
            preflight::{
                TargetPersistentVolumeClaimProof, TargetPersistentVolumeProof,
                TargetResolvedPodProof, TargetVolumeMountProof,
            },
            quorum::{ErasureSetMember, ErasureSetMembership, ErasureSetShape},
            reporting::PodIdentity,
        },
        rustfs::{RustfsDriveLayout, RustfsErasureLayout, RustfsServerLayout},
    };

    fn volume_pod(index: usize) -> TargetResolvedPodProof {
        TargetResolvedPodProof::new(format!("rustfs-{index}"), format!("uid-{index}"))
            .with_ready(true)
            .with_node(format!("node-{index}"))
            .with_node_labels(BTreeMap::from([(
                "kubernetes.io/hostname".to_string(),
                format!("node-{index}"),
            )]))
            .with_rustfs_container_id(format!("containerd://container-{index}"))
            .with_persistent_volume_claims(vec![TargetPersistentVolumeClaimProof {
                name: format!("data-rustfs-{index}"),
                uid: format!("pvc-uid-{index}"),
                volume_name: Some(format!("pv-{index}")),
                storage_class: Some("fast-csi".to_string()),
                persistent_volume: Some(TargetPersistentVolumeProof {
                    name: format!("pv-{index}"),
                    uid: format!("pv-uid-{index}"),
                    source: Some("csi".to_string()),
                    required_node_affinity: None,
                    node: None,
                    device_or_path: Some(format!("csi://volume-{index}")),
                }),
            }])
            .with_volume_mounts(vec![TargetVolumeMountProof {
                container_name: "rustfs".to_string(),
                mount_path: "/data/rustfs0".to_string(),
                volume_name: "data".to_string(),
                persistent_volume_claim: Some(format!("data-rustfs-{index}")),
            }])
    }

    #[test]
    fn runtime_drive_binding_requires_exactly_one_proven_volume_per_server() {
        let shape = ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 2).expect("shape");
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
        let pods = (0..4).map(volume_pod).collect::<Vec<_>>();

        let bindings = bind_runtime_drives_to_volumes(&shape, &membership, &pods, "/data/rustfs0")
            .expect("drive bindings");
        assert_eq!(bindings.len(), 4);
        assert_eq!(bindings[2].drive_uuid, "drive-2");
        assert_eq!(bindings[2].persistent_volume, "pv-2");

        let mut ambiguous = pods;
        let duplicate_mount = ambiguous[0].volume_mounts[0].clone();
        ambiguous[0].volume_mounts.push(duplicate_mount);
        assert!(
            bind_runtime_drives_to_volumes(&shape, &membership, &ambiguous, "/data/rustfs0")
                .is_err()
        );
    }

    #[test]
    fn fixed_volume_controller_targets_resolve_to_exact_pod_identities() {
        let pods = (0..3)
            .map(|index| PodIdentity {
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
            })
            .collect::<Vec<_>>();
        let records = [
            "faults/rustfs-0/rustfs".to_string(),
            "faults/rustfs-2/rustfs".to_string(),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            selected_fixed_volume_pod_identities("faults", pods.clone(), &records, 2)
                .expect("selected identities"),
            [pods[0].clone(), pods[2].clone()]
        );
        let missing = ["faults/rustfs-9/rustfs".to_string()].into_iter().collect();
        assert!(selected_fixed_volume_pod_identities("faults", pods, &missing, 1).is_err());

        assert!(
            unique_pod_identity_pairs(
                "target-proof RustFS Pods",
                vec![
                    ("rustfs-0".to_string(), "uid-0".to_string()),
                    ("rustfs-0".to_string(), "uid-replacement".to_string()),
                ],
            )
            .is_err()
        );
        assert!(
            unique_pod_identity_pairs(
                "target-proof RustFS Pods",
                vec![("rustfs-0".to_string(), String::new())],
            )
            .is_err()
        );
    }
    #[test]
    fn tenant_geometry_requires_one_pool_and_matches_configured_server_count() {
        let tenant = |servers, volumes_per_server| {
            serde_json::json!({
                "spec": {
                    "pools": [{
                        "servers": servers,
                        "persistence": { "volumesPerServer": volumes_per_server }
                    }]
                }
            })
        };

        assert_eq!(
            tenant_single_pool_geometry(&tenant(4, 1), 4).expect("tenant geometry"),
            super::TenantPoolGeometry {
                server_count: 4,
                volumes_per_server: 1,
            }
        );
        assert_eq!(
            tenant_single_pool_geometry(&tenant(4, 2), 4).expect("tenant geometry"),
            super::TenantPoolGeometry {
                server_count: 4,
                volumes_per_server: 2,
            }
        );

        // Config/live disagreement cannot be treated as proof.
        assert!(tenant_single_pool_geometry(&tenant(4, 1), 5).is_err());
        // Multi-pool and incomplete Tenant resources fail closed.
        let multi_pool = serde_json::json!({
            "spec": {
                "pools": [
                    {"servers": 4, "persistence": {"volumesPerServer": 1}},
                    {"servers": 4, "persistence": {"volumesPerServer": 1}}
                ]
            }
        });
        assert!(tenant_single_pool_geometry(&multi_pool, 4).is_err());
        assert!(tenant_single_pool_geometry(&serde_json::json!({"spec": {}}), 4).is_err());
    }
    #[test]
    fn runtime_membership_resolves_server_endpoints_to_pods_and_drives() {
        let shape = ErasureSetShape::from_runtime_single_set(4, 2, &[1], &[8], 4).expect("shape");
        let pods = (0..4)
            .map(|index| PodIdentity {
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
            })
            .collect::<Vec<_>>();
        let servers = (0..4)
            .map(|index| RustfsServerLayout {
                endpoint: format!("http://rustfs-{index}.rustfs.test.svc:9000"),
                drives: (0..2)
                    .map(|drive| RustfsDriveLayout {
                        uuid: format!("drive-{index}-{drive}"),
                        state: "ok".to_string(),
                        pool_index: 0,
                        set_index: 0,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        let runtime = RustfsErasureLayout {
            deployment_id: "deployment-1".to_string(),
            standard_parity: 4,
            total_sets: vec![1],
            drives_per_set: vec![8],
            online_drives: 8,
            offline_drives: 0,
            unknown_drives: 0,
            servers,
        };

        let membership =
            runtime_single_set_membership(&runtime, &shape, &pods).expect("membership");
        assert_eq!(membership.members.len(), 4);
        assert!(
            membership
                .require_selected_boundary(&shape, ["rustfs-0", "rustfs-1"])
                .is_ok()
        );
        for state in ["offline", "unformatted", "unknown", ""] {
            let mut unhealthy = runtime.clone();
            unhealthy.servers[0].drives[0].state = state.to_string();
            assert!(
                runtime_single_set_membership(&unhealthy, &shape, &pods).is_err(),
                "aggregate online count must not override individual drive state {state:?}"
            );
        }

        let candidates = pods.iter().map(|pod| pod.name.as_str()).collect();
        assert_eq!(
            runtime_server_pod_name("rustfs-0.rustfs.test.svc:9000", &candidates)
                .expect("pod name"),
            "rustfs-0"
        );
    }
}
