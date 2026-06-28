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

use anyhow::Result;
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
    pub pod_management_policy: Option<PodManagementPolicy>,
    pub unsafe_bypass_disk_check: bool,
    pub node_selector: Option<BTreeMap<String, String>>,
    pub spread_across_hosts: bool,
}

impl TenantTemplate {
    pub fn kind_local(
        namespace: impl Into<String>,
        name: impl Into<String>,
        image: impl Into<String>,
        storage_class: impl Into<String>,
        credential_secret_name: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            image: image.into(),
            storage_class: storage_class.into(),
            credential_secret_name: credential_secret_name.into(),
            servers: 4,
            volumes_per_server: 2,
            storage_request: "10Gi".to_string(),
            pod_management_policy: Some(PodManagementPolicy::Parallel),
            unsafe_bypass_disk_check: true,
            node_selector: Some(
                [("rustfs-storage".to_string(), "true".to_string())]
                    .into_iter()
                    .collect(),
            ),
            spread_across_hosts: false,
        }
    }

    pub fn real_cluster(
        namespace: impl Into<String>,
        name: impl Into<String>,
        image: impl Into<String>,
        storage_class: impl Into<String>,
        credential_secret_name: impl Into<String>,
    ) -> Self {
        Self {
            namespace: namespace.into(),
            name: name.into(),
            image: image.into(),
            storage_class: storage_class.into(),
            credential_secret_name: credential_secret_name.into(),
            servers: 4,
            volumes_per_server: 1,
            storage_request: "100Gi".to_string(),
            pod_management_policy: Some(PodManagementPolicy::Parallel),
            unsafe_bypass_disk_check: false,
            node_selector: None,
            spread_across_hosts: true,
        }
    }

    pub fn manifest(&self) -> Result<String> {
        let mut scheduling = Map::new();
        if let Some(node_selector) = &self.node_selector {
            scheduling.insert("nodeSelector".to_string(), json!(node_selector));
        }
        if self.spread_across_hosts {
            scheduling.insert(
                "affinity".to_string(),
                fault_tenant_pod_anti_affinity(&self.name),
            );
        }

        let mut pool = Map::new();
        pool.insert("name".to_string(), json!("primary"));
        pool.insert("servers".to_string(), json!(self.servers));
        pool.insert(
            "persistence".to_string(),
            json!({
                "volumesPerServer": self.volumes_per_server,
                "volumeClaimTemplate": {
                    "spec": {
                        "accessModes": ["ReadWriteOnce"],
                        "resources": {
                            "requests": {
                                "storage": self.storage_request,
                            }
                        },
                        "storageClassName": self.storage_class,
                    }
                }
            }),
        );
        if !scheduling.is_empty() {
            pool.insert("scheduling".to_string(), Value::Object(scheduling));
        }

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

        let mut spec = Map::new();
        spec.insert("pools".to_string(), json!([Value::Object(pool)]));
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

fn fault_tenant_pod_anti_affinity(tenant_name: &str) -> Value {
    json!({
        "podAntiAffinity": {
            "requiredDuringSchedulingIgnoredDuringExecution": [{
                "labelSelector": {
                    "matchLabels": {
                        "rustfs.tenant": tenant_name,
                    }
                },
                "topologyKey": "kubernetes.io/hostname",
            }]
        }
    })
}

#[cfg(test)]
mod tests {
    use super::TenantTemplate;

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
                .pointer("/spec/pools/0/scheduling/nodeSelector/rustfs-storage")
                .and_then(serde_json::Value::as_str),
            Some("true")
        );
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
    }
}
