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
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;

use crate::framework::config::PodManagementPolicy;

#[derive(Debug, Clone)]
pub struct TenantTemplate {
    pub namespace: String,
    pub name: String,
    pub image: String,
    pub storage_class: String,
    pub credential_secret_name: String,
    pub servers: i32,
    pub volumes_per_server: i32,
    pub storage_request: String,
    // Empty preserves the legacy primary-pool fields above. `replace_pools`
    // switches rendering to the typed multi-pool model atomically.
    pools: Vec<TenantPoolTemplate>,
    pub pod_management_policy: Option<PodManagementPolicy>,
    pub unsafe_bypass_disk_check: bool,
    pub node_selector: Option<BTreeMap<String, String>>,
    pub spread_across_hosts: bool,
    pub rustfs_env: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantPoolTemplate {
    pub name: String,
    pub servers: i32,
    pub volumes_per_server: i32,
    pub storage_request: String,
    pub storage_class: String,
    pub node_selector: Option<BTreeMap<String, String>>,
    pub spread_across_hosts: bool,
}

impl TenantPoolTemplate {
    pub fn new(
        name: impl Into<String>,
        servers: i32,
        volumes_per_server: i32,
        storage_request: impl Into<String>,
        storage_class: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            servers,
            volumes_per_server,
            storage_request: storage_request.into(),
            storage_class: storage_class.into(),
            node_selector: None,
            spread_across_hosts: true,
        }
    }
}

impl TenantTemplate {
    pub fn kind_local(
        namespace: impl Into<String>,
        name: impl Into<String>,
        image: impl Into<String>,
        storage_class: impl Into<String>,
        credential_secret_name: impl Into<String>,
    ) -> Self {
        let storage_class = storage_class.into();
        Self {
            namespace: namespace.into(),
            name: name.into(),
            image: image.into(),
            storage_class,
            credential_secret_name: credential_secret_name.into(),
            servers: 4,
            volumes_per_server: 2,
            storage_request: "10Gi".to_string(),
            pools: Vec::new(),
            pod_management_policy: Some(PodManagementPolicy::Parallel),
            unsafe_bypass_disk_check: true,
            node_selector: Some(
                [("rustfs-storage".to_string(), "true".to_string())]
                    .into_iter()
                    .collect(),
            ),
            spread_across_hosts: false,
            rustfs_env: Vec::new(),
        }
    }

    pub fn real_cluster(
        namespace: impl Into<String>,
        name: impl Into<String>,
        image: impl Into<String>,
        storage_class: impl Into<String>,
        credential_secret_name: impl Into<String>,
    ) -> Self {
        let storage_class = storage_class.into();
        Self {
            namespace: namespace.into(),
            name: name.into(),
            image: image.into(),
            storage_class,
            credential_secret_name: credential_secret_name.into(),
            servers: 4,
            volumes_per_server: 1,
            storage_request: "100Gi".to_string(),
            pools: Vec::new(),
            pod_management_policy: Some(PodManagementPolicy::Parallel),
            unsafe_bypass_disk_check: false,
            node_selector: None,
            spread_across_hosts: true,
            rustfs_env: Vec::new(),
        }
    }

    pub fn replace_pools(&mut self, pools: Vec<TenantPoolTemplate>) -> Result<()> {
        ensure!(
            !pools.is_empty(),
            "Tenant typed pool replacement must not be empty"
        );
        self.pools = pools;
        Ok(())
    }

    pub fn manifest(&self) -> Result<String> {
        let legacy_pools;
        let pools = if self.pools.is_empty() {
            legacy_pools = vec![TenantPoolTemplate {
                name: "primary".to_string(),
                servers: self.servers,
                volumes_per_server: self.volumes_per_server,
                storage_request: self.storage_request.clone(),
                storage_class: self.storage_class.clone(),
                node_selector: self.node_selector.clone(),
                spread_across_hosts: self.spread_across_hosts,
            }];
            &legacy_pools
        } else {
            &self.pools
        };
        let mut pool_names = std::collections::BTreeSet::new();
        let rendered_pools = pools
            .iter()
            .map(|pool| {
                ensure!(
                    !pool.name.trim().is_empty() && pool_names.insert(pool.name.as_str()),
                    "Tenant pool names must be non-empty and unique"
                );
                ensure!(
                    pool.servers > 0,
                    "Tenant pool {:?} must have servers > 0",
                    pool.name
                );
                ensure!(
                    pool.volumes_per_server > 0,
                    "Tenant pool {:?} must have volumesPerServer > 0",
                    pool.name
                );
                ensure!(
                    !pool.storage_request.trim().is_empty()
                        && !pool.storage_class.trim().is_empty(),
                    "Tenant pool {:?} must declare storage request and class",
                    pool.name
                );
                let mut value = Map::new();
                value.insert("name".to_string(), json!(pool.name));
                value.insert("servers".to_string(), json!(pool.servers));
                value.insert(
                    "persistence".to_string(),
                    json!({
                        "volumesPerServer": pool.volumes_per_server,
                        "volumeClaimTemplate": {
                            "accessModes": ["ReadWriteOnce"],
                            "resources": {"requests": {"storage": pool.storage_request}},
                            "storageClassName": pool.storage_class,
                        }
                    }),
                );
                if let Some(node_selector) = &pool.node_selector {
                    value.insert("nodeSelector".to_string(), json!(node_selector));
                }
                if pool.spread_across_hosts {
                    value.insert(
                        "affinity".to_string(),
                        fault_tenant_pool_pod_anti_affinity(&self.name, &pool.name),
                    );
                }
                Ok(Value::Object(value))
            })
            .collect::<Result<Vec<_>>>()?;

        let mut env = vec![json!({
            "name": "RUST_LOG",
            "value": "info",
        })];
        if self.unsafe_bypass_disk_check {
            env.push(json!({
                "name": "RUSTFS_UNSAFE_BYPASS_DISK_CHECK",
                "value": "true",
            }));
        }
        for (name, value) in &self.rustfs_env {
            env.push(json!({
                "name": name,
                "value": value,
            }));
        }

        let mut spec = Map::new();
        spec.insert("pools".to_string(), Value::Array(rendered_pools));
        spec.insert("image".to_string(), json!(self.image));
        spec.insert("imagePullPolicy".to_string(), json!("IfNotPresent"));
        if let Some(policy) = self.pod_management_policy {
            spec.insert("podManagementPolicy".to_string(), json!(policy.as_str()));
        }
        spec.insert(
            "credsSecret".to_string(),
            json!({
                "name": self.credential_secret_name,
            }),
        );
        spec.insert("env".to_string(), Value::Array(env));

        let manifest = json!({
            "apiVersion": "rustfs.com/v1alpha1",
            "kind": "Tenant",
            "metadata": {
                "name": self.name,
                "namespace": self.namespace,
            },
            "spec": Value::Object(spec),
        });

        Ok(serde_yaml_ng::to_string(&manifest)?)
    }
}

fn fault_tenant_pool_pod_anti_affinity(tenant_name: &str, pool_name: &str) -> Value {
    json!({
        "podAntiAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": [{
                "labelSelector": {
                    "matchLabels": {
                        "rustfs.tenant": tenant_name,
                        "rustfs.pool": pool_name,
                    }
                },
                "topologyKey": "kubernetes.io/hostname",
            }]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::{TenantPoolTemplate, TenantTemplate};

    #[test]
    fn kind_local_tenant_uses_local_image_policy_and_disk_bypass() {
        let manifest = TenantTemplate::kind_local(
            "s3chaos",
            "tenant-a",
            "rustfs/rustfs:e2e",
            "local-storage",
            "tenant-a-credentials",
        )
        .manifest()
        .expect("tenant manifest");

        assert!(manifest.contains("namespace: s3chaos"));
        assert!(manifest.contains("image: rustfs/rustfs:e2e"));
        assert!(manifest.contains("name: tenant-a-credentials"));
        assert!(manifest.contains("storageClassName: local-storage"));
        assert!(manifest.contains("imagePullPolicy: IfNotPresent"));
        assert!(manifest.contains("RUSTFS_UNSAFE_BYPASS_DISK_CHECK"));

        let value: serde_json::Value = serde_yaml_ng::from_str(&manifest).expect("valid yaml");
        assert_eq!(
            value
                .pointer("/spec/pools/0/nodeSelector/rustfs-storage")
                .and_then(serde_json::Value::as_str),
            Some("true")
        );
        assert!(
            value
                .pointer("/spec/pools/0/persistence/volumeClaimTemplate/spec")
                .is_none()
        );
        assert!(value.pointer("/spec/pools/0/scheduling").is_none());
    }

    #[test]
    fn real_cluster_tenant_uses_fault_storage_spread_and_disk_checks() {
        let manifest = TenantTemplate::real_cluster(
            "rustfs-fault-test",
            "fault-test-tenant",
            "rustfs/rustfs:latest",
            "fast-csi",
            "fault-test-tenant-credentials",
        )
        .manifest()
        .expect("tenant manifest");

        assert!(manifest.contains("volumesPerServer: 1"));
        assert!(manifest.contains("topologyKey: kubernetes.io/hostname"));
        assert!(manifest.contains("storage: 100Gi"));
        assert!(!manifest.contains("rustfs-storage"));
        assert!(!manifest.contains("RUSTFS_UNSAFE_BYPASS_DISK_CHECK"));

        let value: serde_json::Value = serde_yaml_ng::from_str(&manifest).expect("valid yaml");
        assert_eq!(
            value
                .pointer("/spec/pools/0/persistence/volumeClaimTemplate/storageClassName")
                .and_then(serde_json::Value::as_str),
            Some("fast-csi")
        );
        assert_eq!(
            value
                .pointer("/spec/pools/0/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/0/topologyKey")
                .and_then(serde_json::Value::as_str),
            Some("kubernetes.io/hostname")
        );
        assert!(
            value
                .pointer("/spec/pools/0/persistence/volumeClaimTemplate/spec")
                .is_none()
        );
        assert!(value.pointer("/spec/pools/0/scheduling").is_none());
    }

    #[test]
    fn tenant_manifest_includes_extra_rustfs_env() {
        let mut template = TenantTemplate::real_cluster(
            "rustfs-fault-test",
            "fault-test-tenant",
            "rustfs/rustfs:latest",
            "fast-csi",
            "fault-test-tenant-credentials",
        );
        template.rustfs_env = vec![(
            "RUSTFS_GET_METADATA_EARLY_STOP_ENABLE".to_string(),
            "true".to_string(),
        )];

        let manifest = template.manifest().expect("tenant manifest");
        let value: serde_json::Value = serde_yaml_ng::from_str(&manifest).expect("valid yaml");

        assert_eq!(
            value
                .pointer("/spec/env/1/name")
                .and_then(serde_json::Value::as_str),
            Some("RUSTFS_GET_METADATA_EARLY_STOP_ENABLE")
        );
        assert_eq!(
            value
                .pointer("/spec/env/1/value")
                .and_then(serde_json::Value::as_str),
            Some("true")
        );
    }

    #[test]
    fn tenant_manifest_renders_typed_multi_pool_topology() {
        let mut template = TenantTemplate::real_cluster(
            "rustfs-fault-test",
            "fault-test-tenant",
            "rustfs/rustfs:latest",
            "fast-csi",
            "fault-test-tenant-credentials",
        );
        template
            .replace_pools(vec![
                TenantPoolTemplate::new("primary", 4, 1, "20Gi", "fast-csi"),
                TenantPoolTemplate::new("decommission-target", 4, 1, "10Gi", "fast-csi"),
            ])
            .expect("replace pools");

        let manifest = template.manifest().expect("multi-pool manifest");
        let value: serde_json::Value = serde_yaml_ng::from_str(&manifest).expect("valid yaml");
        let pools = value["spec"]["pools"].as_array().expect("pools");
        assert_eq!(pools.len(), 2);
        assert_eq!(pools[0]["name"], "primary");
        assert_eq!(pools[1]["name"], "decommission-target");
        assert_eq!(pools[1]["servers"], 4);
        assert_eq!(
            pools[1]["affinity"]["podAntiAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
                [0]["labelSelector"]["matchLabels"]["rustfs.pool"],
            "decommission-target"
        );
        assert_eq!(
            pools[1]["persistence"]["volumeClaimTemplate"]["storageClassName"],
            "fast-csi"
        );
    }

    #[test]
    fn tenant_manifest_rejects_duplicate_pool_names() {
        let mut template = TenantTemplate::real_cluster("ns", "tenant", "image", "sc", "secret");
        template
            .replace_pools(vec![
                TenantPoolTemplate::new("duplicate", 4, 1, "10Gi", "sc"),
                TenantPoolTemplate::new("duplicate", 4, 1, "10Gi", "sc"),
            ])
            .expect("replace pools");
        assert!(template.manifest().is_err());
    }
}
