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
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::{
    fault::{
        preflight::{
            TargetNodeAffinityProof, TargetNodeSelectorRequirementProof,
            TargetNodeSelectorTermProof, TargetPersistentVolumeClaimProof,
            TargetPersistentVolumeProof, TargetResolvedPodProof, TargetVolumeMountProof,
        },
        reporting::PodIdentity,
    },
    framework::{config::ClusterTestConfig, kubectl::Kubectl},
};

pub(crate) struct RustfsTargetInventory {
    pub(crate) identities: Vec<PodIdentity>,
    pub(crate) pod_proofs: Vec<TargetResolvedPodProof>,
}

pub(crate) fn rustfs_pod_identities(config: &ClusterTestConfig) -> Result<Vec<PodIdentity>> {
    let pods = rustfs_pods_json(config)?;
    let selector = rustfs_tenant_selector(config);
    let items = pod_items(&pods)?;
    pod_identities_from_items(items, &selector, &config.test_namespace)
}

pub(crate) fn rustfs_target_inventory(
    config: &ClusterTestConfig,
    include_volume_bindings: bool,
    include_node_labels: bool,
) -> Result<RustfsTargetInventory> {
    let pods = rustfs_pods_json(config)?;
    let selector = rustfs_tenant_selector(config);
    let items = pod_items(&pods)?;
    let identities = pod_identities_from_items(items, &selector, &config.test_namespace)?;
    let volume_maps = if include_volume_bindings {
        Some((pvc_map(config)?, pv_map(config)?))
    } else {
        None
    };
    let node_labels = if include_node_labels {
        Some(node_label_map(config)?)
    } else {
        None
    };
    let pod_proofs = items
        .iter()
        .filter_map(|item| match &volume_maps {
            Some((pvcs, pvs)) => {
                target_pod_proof(item, Some(pvcs), Some(pvs), node_labels.as_ref())
            }
            None => target_pod_proof(item, None, None, node_labels.as_ref()),
        })
        .collect();

    Ok(RustfsTargetInventory {
        identities,
        pod_proofs,
    })
}

fn rustfs_pods_json(config: &ClusterTestConfig) -> Result<Value> {
    let selector = format!("rustfs.tenant={}", config.tenant_name);
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pod", "-l", &selector, "-o", "json"])
        .run_checked()?;
    serde_json::from_str::<Value>(&output.stdout).context("parse RustFS pod list json")
}

fn pod_items(value: &Value) -> Result<&[Value]> {
    value
        .pointer("/items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .context("RustFS pod list did not contain an items array")
}

fn pod_identities_from_items(
    items: &[Value],
    selector: &str,
    namespace: &str,
) -> Result<Vec<PodIdentity>> {
    let pods = items
        .iter()
        .filter_map(|item| {
            let metadata = item.get("metadata")?;
            Some(PodIdentity {
                name: metadata.get("name")?.as_str()?.to_string(),
                uid: metadata.get("uid")?.as_str()?.to_string(),
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        !pods.is_empty(),
        "no RustFS pods found for selector {selector} in namespace {namespace}",
    );
    Ok(pods)
}

pub(crate) fn rustfs_tenant_selector(config: &ClusterTestConfig) -> String {
    format!("rustfs.tenant={}", config.tenant_name)
}

fn pvc_map(config: &ClusterTestConfig) -> Result<BTreeMap<String, Value>> {
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pvc", "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<Value>(&output.stdout).context("parse PVC list json")?;
    Ok(items_by_metadata_name(&value))
}

fn pv_map(config: &ClusterTestConfig) -> Result<BTreeMap<String, Value>> {
    let output = Kubectl::new(config)
        .command(["get", "pv", "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<Value>(&output.stdout).context("parse PV list json")?;
    Ok(items_by_metadata_name(&value))
}

fn node_label_map(
    config: &ClusterTestConfig,
) -> Result<BTreeMap<String, BTreeMap<String, String>>> {
    let output = Kubectl::new(config)
        .command(["get", "node", "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<Value>(&output.stdout).context("parse Node list json")?;
    Ok(value
        .pointer("/items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|node| {
            let name = node.pointer("/metadata/name").and_then(Value::as_str)?;
            let labels = node
                .pointer("/metadata/labels")
                .and_then(Value::as_object)?
                .iter()
                .map(|(key, value)| Some((key.clone(), value.as_str()?.to_string())))
                .collect::<Option<BTreeMap<_, _>>>()?;
            Some((name.to_string(), labels))
        })
        .collect())
}

fn items_by_metadata_name(value: &Value) -> BTreeMap<String, Value> {
    value
        .pointer("/items")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            let name = item.pointer("/metadata/name").and_then(Value::as_str)?;
            Some((name.to_string(), item.clone()))
        })
        .collect()
}

fn target_pod_proof(
    pod: &Value,
    pvcs: Option<&BTreeMap<String, Value>>,
    pvs: Option<&BTreeMap<String, Value>>,
    node_labels: Option<&BTreeMap<String, BTreeMap<String, String>>>,
) -> Option<TargetResolvedPodProof> {
    let metadata = pod.get("metadata")?;
    let name = metadata.get("name")?.as_str()?.to_string();
    let uid = metadata.get("uid")?.as_str()?.to_string();
    let mut proof = TargetResolvedPodProof::new(name, uid).with_ready(pod_is_ready(pod));
    proof.rustfs_container_id = pod
        .pointer("/status/containerStatuses")
        .and_then(Value::as_array)
        .and_then(|statuses| {
            let mut rustfs = statuses
                .iter()
                .filter(|status| status.get("name").and_then(Value::as_str) == Some("rustfs"));
            let status = rustfs.next()?;
            if rustfs.next().is_some() || !status.pointer("/state/running")?.is_object() {
                return None;
            }
            status.get("containerID")?.as_str()
        })
        .filter(|id| !id.trim().is_empty())
        .map(str::to_string);
    if let Some(node) = pod.pointer("/spec/nodeName").and_then(Value::as_str) {
        proof = proof.with_node(node);
        if let Some(labels) = node_labels.and_then(|nodes| nodes.get(node)) {
            proof = proof.with_node_labels(labels.clone());
        }
    }
    let claims = match (pvcs, pvs) {
        (Some(pvcs), Some(pvs)) => persistent_volume_claim_names(pod)
            .into_iter()
            .map(|claim| target_pvc_proof(&claim, pvcs, pvs))
            .collect(),
        _ => Vec::new(),
    };
    let volume_mounts = match (pvcs, pvs) {
        (Some(_), Some(_)) => target_volume_mounts(pod),
        _ => Vec::new(),
    };
    Some(
        proof
            .with_persistent_volume_claims(claims)
            .with_volume_mounts(volume_mounts),
    )
}

pub(crate) fn fixed_volume_container_ids(
    pods: &[TargetResolvedPodProof],
    selected_pod_names: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>> {
    let mut containers = BTreeMap::new();
    for pod in pods
        .iter()
        .filter(|pod| selected_pod_names.contains(&pod.name))
    {
        let id = pod
            .rustfs_container_id
            .as_deref()
            .filter(|id| !id.trim().is_empty())
            .with_context(|| {
                format!(
                    "fixed volume target {} has no running RustFS container ID",
                    pod.name
                )
            })?;
        ensure!(
            containers
                .insert(pod.name.clone(), id.to_string())
                .is_none(),
            "fixed volume target {} has duplicate Pod records",
            pod.name
        );
    }
    ensure!(
        containers.len() == selected_pod_names.len(),
        "fixed volume container identities do not cover the selected Pods"
    );
    Ok(containers)
}

pub(crate) fn pod_is_ready(pod: &Value) -> bool {
    pod.pointer("/metadata/deletionTimestamp").is_none()
        && pod
            .pointer("/status/conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|condition| {
                condition.get("type").and_then(Value::as_str) == Some("Ready")
                    && condition.get("status").and_then(Value::as_str) == Some("True")
            })
}

fn persistent_volume_claim_names(pod: &Value) -> Vec<String> {
    let mut claims = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|volume| {
            volume
                .pointer("/persistentVolumeClaim/claimName")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<Vec<_>>();
    claims.sort();
    claims.dedup();
    claims
}

fn target_volume_mounts(pod: &Value) -> Vec<TargetVolumeMountProof> {
    let volume_claims = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|volume| {
            let name = volume.get("name").and_then(Value::as_str)?;
            let claim = volume
                .pointer("/persistentVolumeClaim/claimName")
                .and_then(Value::as_str)
                .map(str::to_string);
            Some((name.to_string(), claim))
        })
        .collect::<BTreeMap<_, _>>();
    let mut mounts = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|container| {
            let container_name = container
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            container
                .get("volumeMounts")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|mount| {
                    let volume_name = mount.get("name").and_then(Value::as_str)?;
                    let mount_path = mount.get("mountPath").and_then(Value::as_str)?;
                    Some(TargetVolumeMountProof {
                        container_name: container_name.clone(),
                        mount_path: mount_path.to_string(),
                        volume_name: volume_name.to_string(),
                        persistent_volume_claim: volume_claims.get(volume_name).cloned().flatten(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    mounts.sort_by(|left, right| {
        left.container_name
            .cmp(&right.container_name)
            .then_with(|| left.mount_path.cmp(&right.mount_path))
            .then_with(|| left.volume_name.cmp(&right.volume_name))
    });
    mounts
}

fn target_pvc_proof(
    claim: &str,
    pvcs: &BTreeMap<String, Value>,
    pvs: &BTreeMap<String, Value>,
) -> TargetPersistentVolumeClaimProof {
    let pvc = pvcs.get(claim);
    let uid = pvc
        .and_then(|value| value.pointer("/metadata/uid"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let volume_name = pvc
        .and_then(|value| value.pointer("/spec/volumeName"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let storage_class = pvc
        .and_then(|value| value.pointer("/spec/storageClassName"))
        .and_then(Value::as_str)
        .map(str::to_string);
    let persistent_volume = volume_name
        .as_deref()
        .and_then(|volume| pvs.get(volume).map(|pv| target_pv_proof(volume, pv)));

    TargetPersistentVolumeClaimProof {
        name: claim.to_string(),
        uid,
        volume_name,
        storage_class,
        persistent_volume,
    }
}

fn target_pv_proof(name: &str, pv: &Value) -> TargetPersistentVolumeProof {
    let required_node_affinity = pv_required_node_affinity(pv);
    TargetPersistentVolumeProof {
        name: name.to_string(),
        uid: pv
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        source: pv_source(pv).map(str::to_string),
        node: required_node_affinity
            .as_ref()
            .and_then(unique_hostname_affinity),
        required_node_affinity,
        device_or_path: pv_device_or_path(pv),
    }
}

fn pv_source(pv: &Value) -> Option<&'static str> {
    if pv.pointer("/spec/local/path").is_some() {
        Some("local")
    } else if pv.pointer("/spec/hostPath/path").is_some() {
        Some("host-path")
    } else if pv.pointer("/spec/csi/volumeHandle").is_some() {
        Some("csi")
    } else {
        None
    }
}

fn pv_required_node_affinity(pv: &Value) -> Option<TargetNodeAffinityProof> {
    let required = pv.pointer("/spec/nodeAffinity/required")?;
    let terms = required.get("nodeSelectorTerms").and_then(Value::as_array);
    let mut well_formed = terms.is_some();
    let terms = terms
        .into_iter()
        .flatten()
        .map(|term| TargetNodeSelectorTermProof {
            match_expressions: node_selector_requirements(
                term.get("matchExpressions"),
                &mut well_formed,
            ),
            match_fields: node_selector_requirements(term.get("matchFields"), &mut well_formed),
        })
        .collect();
    Some(TargetNodeAffinityProof { well_formed, terms })
}

fn node_selector_requirements(
    value: Option<&Value>,
    well_formed: &mut bool,
) -> Vec<TargetNodeSelectorRequirementProof> {
    let Some(value) = value else {
        return Vec::new();
    };
    let Some(requirements) = value.as_array() else {
        *well_formed = false;
        return Vec::new();
    };
    requirements
        .iter()
        .map(|requirement| {
            let key = requirement.get("key").and_then(Value::as_str);
            let operator = requirement.get("operator").and_then(Value::as_str);
            let values = requirement.get("values").and_then(Value::as_array);
            let parsed_values = values.map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            });
            if key.is_none()
                || operator.is_none()
                || values.is_some_and(|items| {
                    parsed_values
                        .as_ref()
                        .is_none_or(|parsed| parsed.len() != items.len())
                })
            {
                *well_formed = false;
            }
            TargetNodeSelectorRequirementProof {
                key: key.unwrap_or_default().to_string(),
                operator: operator.unwrap_or_default().to_string(),
                values: parsed_values.unwrap_or_default(),
            }
        })
        .collect()
}

fn unique_hostname_affinity(affinity: &TargetNodeAffinityProof) -> Option<String> {
    if !affinity.well_formed || affinity.terms.len() != 1 {
        return None;
    }
    let matches = affinity.terms[0]
        .match_expressions
        .iter()
        .filter(|requirement| {
            requirement.key == "kubernetes.io/hostname"
                && requirement.operator == "In"
                && requirement.values.len() == 1
        })
        .collect::<Vec<_>>();
    (matches.len() == 1).then(|| matches[0].values[0].clone())
}

fn pv_device_or_path(pv: &Value) -> Option<String> {
    pv.pointer("/spec/local/path")
        .or_else(|| pv.pointer("/spec/hostPath/path"))
        .or_else(|| pv.pointer("/spec/csi/volumeHandle"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

pub(crate) fn wait_for_rustfs_pod_replacement(
    config: &ClusterTestConfig,
    before: &[PodIdentity],
    timeout: Duration,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut last_snapshot = Vec::new();
    let mut last_error = "not checked yet".to_string();

    loop {
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for PodChaos to replace a RustFS pod after {timeout:?}\nbefore: {before:?}\nlast: {last_snapshot:?}\nlast error: {last_error}",
            );
        }

        match rustfs_pod_identities(config) {
            Ok(current) => {
                if pod_replacement_observed(before, &current) {
                    return Ok(());
                }
                last_snapshot = current;
                last_error = "none".to_string();
            }
            Err(error) => {
                last_error = error.to_string();
            }
        }

        sleep(Duration::from_secs(1));
    }
}

pub(crate) fn pod_deletion_observed(before: &[PodIdentity], current: &[PodIdentity]) -> bool {
    let current_uids = current
        .iter()
        .map(|pod| pod.uid.as_str())
        .collect::<BTreeSet<_>>();
    !before.is_empty()
        && before
            .iter()
            .any(|pod| !current_uids.contains(pod.uid.as_str()))
}

pub(crate) fn pod_replacement_observed(before: &[PodIdentity], current: &[PodIdentity]) -> bool {
    if before.is_empty() || current.is_empty() {
        return false;
    }

    let before_uids = before
        .iter()
        .map(|pod| pod.uid.as_str())
        .collect::<BTreeSet<_>>();
    let current_uids = current
        .iter()
        .map(|pod| pod.uid.as_str())
        .collect::<BTreeSet<_>>();
    let old_uid_removed = before_uids.iter().any(|uid| !current_uids.contains(uid));
    let new_uid_added = current_uids.iter().any(|uid| !before_uids.contains(uid));

    old_uid_removed && new_uid_added
}

#[cfg(test)]
mod tests {
    use super::{
        fixed_volume_container_ids, items_by_metadata_name, persistent_volume_claim_names,
        pod_deletion_observed, pod_replacement_observed, target_pod_proof,
    };
    use crate::fault::{preflight::target_pod_has_fixed_volume, reporting::PodIdentity};
    use serde_json::json;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn fixed_volume_identity_tracks_the_running_rustfs_container() {
        let mut pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-0"},
            "status": {"containerStatuses": [
                {"name": "sidecar", "containerID": "containerd://sidecar", "state": {"running": {}}},
                {"name": "rustfs", "containerID": "containerd://original", "state": {"running": {}}}
            ]}
        });
        let selected = BTreeSet::from(["rustfs-0".to_string()]);
        let original = target_pod_proof(&pod, None, None, None).expect("Pod proof");
        let expected = fixed_volume_container_ids(std::slice::from_ref(&original), &selected)
            .expect("running container identity does not require readiness during IOChaos");
        assert_eq!(expected["rustfs-0"], "containerd://original");

        pod["status"]["containerStatuses"][1]["containerID"] = json!("containerd://replacement");
        let restarted = target_pod_proof(&pod, None, None, None).expect("restarted Pod");
        assert_eq!(restarted.uid, original.uid);
        assert_ne!(
            fixed_volume_container_ids(&[restarted], &selected).unwrap(),
            expected
        );

        for state in [json!({"waiting": {}}), json!({"terminated": {}}), json!({})] {
            pod["status"]["containerStatuses"][1]["state"] = state;
            let stopped = target_pod_proof(&pod, None, None, None).expect("stopped Pod");
            assert!(fixed_volume_container_ids(&[stopped], &selected).is_err());
        }
        pod["status"]["containerStatuses"][1]["state"] = json!({"running": {}});
        for id in [json!(null), json!(""), json!(" ")] {
            pod["status"]["containerStatuses"][1]["containerID"] = id;
            let missing =
                target_pod_proof(&pod, None, None, None).expect("Pod without container ID");
            assert!(fixed_volume_container_ids(&[missing], &selected).is_err());
        }
        assert!(fixed_volume_container_ids(&[], &selected).is_err());
        assert!(fixed_volume_container_ids(&[original.clone(), original], &selected).is_err());
    }

    #[test]
    fn pod_replacement_requires_old_uid_removed_and_new_uid_added() {
        let before = vec![
            PodIdentity {
                name: "rustfs-0".to_string(),
                uid: "uid-a".to_string(),
            },
            PodIdentity {
                name: "rustfs-1".to_string(),
                uid: "uid-b".to_string(),
            },
        ];

        assert!(!pod_replacement_observed(&before, &before));
        assert!(!pod_replacement_observed(&before, &before[..1]));
        assert!(!pod_deletion_observed(&before, &before));
        assert!(pod_deletion_observed(&before, &before[..1]));
        assert!(pod_replacement_observed(
            &before,
            &[
                PodIdentity {
                    name: "rustfs-0".to_string(),
                    uid: "uid-c".to_string(),
                },
                before[1].clone(),
            ],
        ));
    }

    #[test]
    fn target_pod_proof_links_pod_pvc_pv_node_and_path() {
        let pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-a"},
            "spec": {
                "nodeName": "node-a",
                "containers": [{
                    "name": "rustfs",
                    "volumeMounts": [{"name": "data", "mountPath": "/data/rustfs0"}]
                }],
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": "data-rustfs-0"}
                }]
            },
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{"name": "rustfs", "containerID": "containerd://original", "state": {"running": {}}}]
            }
        });
        let pvc_list = json!({
            "items": [{
                "metadata": {"name": "data-rustfs-0", "uid": "pvc-uid-a"},
                "spec": {
                    "volumeName": "pv-a",
                    "storageClassName": "fast-local"
                }
            }]
        });
        let pv_list = json!({
            "items": [{
                "metadata": {"name": "pv-a", "uid": "pv-uid-a"},
                "spec": {
                    "local": {"path": "/mnt/rustfs0"},
                    "nodeAffinity": {
                        "required": {
                            "nodeSelectorTerms": [{
                                "matchExpressions": [{
                                    "key": "kubernetes.io/hostname",
                                    "operator": "In",
                                    "values": ["node-b", "node-a"]
                                }]
                            }]
                        }
                    }
                }
            }]
        });
        let pvcs = items_by_metadata_name(&pvc_list);
        let pvs = items_by_metadata_name(&pv_list);
        let node_labels = BTreeMap::from([(
            "node-a".to_string(),
            BTreeMap::from([("kubernetes.io/hostname".to_string(), "node-a".to_string())]),
        )]);

        let proof =
            target_pod_proof(&pod, Some(&pvcs), Some(&pvs), Some(&node_labels)).expect("proof");

        assert_eq!(persistent_volume_claim_names(&pod), vec!["data-rustfs-0"]);
        assert!(proof.ready);
        assert_eq!(proof.node.as_deref(), Some("node-a"));
        assert_eq!(proof.persistent_volume_claims.len(), 1);
        let claim = &proof.persistent_volume_claims[0];
        assert_eq!(claim.uid, "pvc-uid-a");
        assert_eq!(claim.volume_name.as_deref(), Some("pv-a"));
        let pv = claim.persistent_volume.as_ref().expect("pv");
        assert_eq!(pv.uid, "pv-uid-a");
        assert_eq!(pv.source.as_deref(), Some("local"));
        assert_eq!(pv.node, None, "multi-value affinity has no singleton node");
        assert_eq!(
            pv.required_node_affinity
                .as_ref()
                .expect("node affinity")
                .terms[0]
                .match_expressions[0]
                .values,
            ["node-b", "node-a"]
        );
        assert_eq!(pv.device_or_path.as_deref(), Some("/mnt/rustfs0"));
        assert!(target_pod_has_fixed_volume(&proof, "/data/rustfs0"));
    }

    #[test]
    fn unrelated_pvc_does_not_prove_empty_dir_volume_target() {
        let pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-a"},
            "spec": {
                "nodeName": "node-a",
                "containers": [{
                    "name": "rustfs",
                    "volumeMounts": [
                        {"name": "data", "mountPath": "/data/rustfs0"},
                        {"name": "logs", "mountPath": "/var/log/rustfs"}
                    ]
                }],
                "volumes": [
                    {"name": "data", "emptyDir": {}},
                    {"name": "logs", "persistentVolumeClaim": {"claimName": "logs-rustfs-0"}}
                ]
            },
            "status": {
                "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{"name": "rustfs", "containerID": "containerd://original", "state": {"running": {}}}]
            }
        });
        let pvc_list = json!({
            "items": [{
                "metadata": {"name": "logs-rustfs-0", "uid": "pvc-uid-logs"},
                "spec": {"volumeName": "pv-logs", "storageClassName": "fast-csi"}
            }]
        });
        let pv_list = json!({
            "items": [{
                "metadata": {"name": "pv-logs", "uid": "pv-uid-logs"},
                "spec": {"csi": {"volumeHandle": "logs-handle"}}
            }]
        });

        let proof = target_pod_proof(
            &pod,
            Some(&items_by_metadata_name(&pvc_list)),
            Some(&items_by_metadata_name(&pv_list)),
            None,
        )
        .expect("proof");

        assert_eq!(proof.persistent_volume_claims.len(), 1);
        assert!(
            !target_pod_has_fixed_volume(&proof, "/data/rustfs0"),
            "an unrelated logs PVC must not prove the emptyDir data mount"
        );
    }

    #[test]
    fn target_pod_proof_can_skip_volume_binding_enrichment() {
        let pod = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-a"},
            "spec": {
                "nodeName": "node-a",
                "volumes": [{
                    "name": "data",
                    "persistentVolumeClaim": {"claimName": "data-rustfs-0"}
                }]
            }
        });

        let proof = target_pod_proof(&pod, None, None, None).expect("proof");

        assert_eq!(proof.name, "rustfs-0");
        assert_eq!(proof.node.as_deref(), Some("node-a"));
        assert!(proof.persistent_volume_claims.is_empty());
    }
}
