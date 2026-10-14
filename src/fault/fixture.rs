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
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::framework::{
    command::CommandOutput,
    config::ClusterTestConfig,
    kubectl::Kubectl,
    resources::{
        credential_secret_manifest, credential_secret_name,
        reset_tenant_resources as reset_generic_tenant_resources,
    },
    tenant_factory::{TenantPoolTemplate, TenantTemplate},
};

use crate::fault::{
    admin_topology::DECOMMISSION_TARGET_POOL_NAME,
    scenarios::{ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO},
};

const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const FAULT_TEST_MANAGER: &str = "s3chaos";
const FAULT_TEST_TENANT_ANNOTATION: &str = "rustfs.com/fault-test-tenant";
const FAULT_TEST_RUN_ANNOTATION: &str = "rustfs.com/fault-test-run";
const RUNTIME_DEFAULT_IMAGE_ACK_ANNOTATION: &str = "operator.rustfs.com/runtime-default-image-ack";
pub const ADMIN_FIXTURE_ARTIFACT: &str = "admin-fixture.json";
pub const ADMIN_PRIMARY_POOL_NAME: &str = "primary";
pub const ADMIN_EXPANSION_POOL_NAME: &str = "expansion";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminFixturePlan {
    pub scenario: String,
    pub initial_pool_name: String,
    pub expansion_pool_name: String,
    pub servers_per_pool: usize,
    pub volumes_per_server: usize,
}

impl AdminFixturePlan {
    pub fn for_scenario(scenario: &str, servers_per_pool: usize) -> Result<Self> {
        ensure!(
            servers_per_pool > 0,
            "admin fixture requires servers per pool"
        );
        let initial_pool_name = match scenario {
            ADMIN_DECOMMISSION_SCENARIO => DECOMMISSION_TARGET_POOL_NAME,
            ADMIN_REBALANCE_SCENARIO => ADMIN_PRIMARY_POOL_NAME,
            other => bail!("scenario {other:?} is not an admin fixture case"),
        };
        Ok(Self {
            scenario: scenario.to_string(),
            initial_pool_name: initial_pool_name.to_string(),
            expansion_pool_name: ADMIN_EXPANSION_POOL_NAME.to_string(),
            servers_per_pool,
            volumes_per_server: 1,
        })
    }

    fn pools(&self, expanded: bool, config: &ClusterTestConfig) -> Result<Vec<TenantPoolTemplate>> {
        ensure!(
            self.initial_pool_name != self.expansion_pool_name,
            "admin fixture pool names must be distinct"
        );
        let servers = i32::try_from(self.servers_per_pool)
            .context("admin fixture server count exceeds Tenant schema")?;
        let volumes = i32::try_from(self.volumes_per_server)
            .context("admin fixture volume count exceeds Tenant schema")?;
        let pool = |name: &str| {
            let mut pool = TenantPoolTemplate::new(
                name,
                servers,
                volumes,
                &config.tenant_storage_request,
                &config.storage_class,
            );
            pool.spread_across_hosts = config.tenant_spread_across_hosts;
            pool
        };
        let mut pools = vec![pool(&self.initial_pool_name)];
        if expanded {
            pools.push(pool(&self.expansion_pool_name));
        }
        Ok(pools)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminFixturePhase {
    PrimaryReady,
    PrefillComplete,
    ExpansionApplied,
    TopologyStable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminFixtureObservation {
    pub phase: AdminFixturePhase,
    pub observed_at_ms: u64,
    pub tenant_uid: String,
    pub pool_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefilled_objects: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminFixtureEvidence {
    pub schema_version: u8,
    pub scenario: String,
    pub run_id: String,
    pub tenant: String,
    pub plan: AdminFixturePlan,
    pub observations: Vec<AdminFixtureObservation>,
}

impl AdminFixtureEvidence {
    pub fn validate_complete(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "admin fixture schema is unsupported"
        );
        ensure!(
            !self.run_id.trim().is_empty() && !self.tenant.trim().is_empty(),
            "admin fixture evidence lacks run or Tenant identity"
        );
        ensure!(
            self.scenario == self.plan.scenario,
            "admin fixture scenario does not match its plan"
        );
        let expected_phases = [
            AdminFixturePhase::PrimaryReady,
            AdminFixturePhase::PrefillComplete,
            AdminFixturePhase::ExpansionApplied,
            AdminFixturePhase::TopologyStable,
        ];
        ensure!(
            self.observations.len() == expected_phases.len(),
            "admin fixture evidence must contain exactly four staged observations"
        );
        let tenant_uid = self
            .observations
            .first()
            .map(|observation| observation.tenant_uid.as_str())
            .unwrap_or_default();
        ensure!(
            !tenant_uid.is_empty(),
            "admin fixture Tenant UID is missing"
        );
        let mut last_observed_at_ms = 0;
        for (observation, expected_phase) in self.observations.iter().zip(expected_phases) {
            ensure!(
                observation.phase == expected_phase
                    && observation.observed_at_ms > last_observed_at_ms
                    && observation.tenant_uid == tenant_uid,
                "admin fixture phase order, timestamp, or Tenant generation changed"
            );
            last_observed_at_ms = observation.observed_at_ms;
        }
        let initial = vec![self.plan.initial_pool_name.clone()];
        let expanded = vec![
            self.plan.initial_pool_name.clone(),
            self.plan.expansion_pool_name.clone(),
        ];
        ensure!(
            self.observations[0].pool_names == initial
                && self.observations[1].pool_names == initial,
            "admin fixture must prefill while only the initial pool exists"
        );
        ensure!(
            self.observations[1]
                .prefilled_objects
                .is_some_and(|count| count > 0),
            "admin fixture prefill observation must prove a non-empty cohort"
        );
        ensure!(
            self.observations[2].pool_names == expanded
                && self.observations[3].pool_names == expanded,
            "admin fixture must observe the exact two-pool topology after expansion"
        );
        ensure!(
            self.observations
                .iter()
                .enumerate()
                .all(|(index, observation)| index == 1 || observation.prefilled_objects.is_none()),
            "admin fixture prefill count belongs only to the prefill phase"
        );
        Ok(())
    }
}

pub fn namespace_manifest(config: &ClusterTestConfig) -> String {
    format!(
        r#"apiVersion: v1
kind: Namespace
metadata:
  name: {namespace}
  labels:
    {managed_by_label}: {manager}
  annotations:
    {tenant_annotation}: {tenant_name}
"#,
        namespace = config.test_namespace,
        managed_by_label = MANAGED_BY_LABEL,
        manager = FAULT_TEST_MANAGER,
        tenant_annotation = FAULT_TEST_TENANT_ANNOTATION,
        tenant_name = config.tenant_name,
    )
}

pub fn tenant_manifest(config: &ClusterTestConfig, volumes_per_server: u32) -> Result<String> {
    let mut template = TenantTemplate::real_cluster(
        &config.test_namespace,
        &config.tenant_name,
        &config.rustfs_image,
        &config.storage_class,
        credential_secret_name(config),
    );
    template.rustfs_env.clone_from(&config.rustfs_env);
    template.volumes_per_server =
        i32::try_from(volumes_per_server).context("Tenant volume count exceeds schema")?;
    template.metadata_annotations.insert(
        RUNTIME_DEFAULT_IMAGE_ACK_ANNOTATION.to_string(),
        config.rustfs_image.clone(),
    );
    // Topology knobs that a single-node/lab cluster otherwise had to patch in
    // source (backlog#1037): the defaults preserve the production 4-node shape.
    template.storage_request = config.tenant_storage_request.clone();
    template.spread_across_hosts = config.tenant_spread_across_hosts;
    template.unsafe_bypass_disk_check = config.tenant_unsafe_bypass_disk_check;
    template.manifest()
}

pub fn admin_tenant_manifest(
    config: &ClusterTestConfig,
    plan: &AdminFixturePlan,
    expanded: bool,
    run_id: &str,
) -> Result<String> {
    ensure!(!run_id.trim().is_empty(), "admin fixture run ID is empty");
    let mut template = TenantTemplate::real_cluster(
        &config.test_namespace,
        &config.tenant_name,
        &config.rustfs_image,
        &config.storage_class,
        credential_secret_name(config),
    );
    template.rustfs_env.clone_from(&config.rustfs_env);
    template.storage_request = config.tenant_storage_request.clone();
    template.spread_across_hosts = config.tenant_spread_across_hosts;
    template.unsafe_bypass_disk_check = config.tenant_unsafe_bypass_disk_check;
    template.replace_pools(plan.pools(expanded, config)?)?;
    let mut manifest = serde_yaml_ng::from_str::<Value>(&template.manifest()?)?;
    manifest
        .pointer_mut("/metadata")
        .and_then(Value::as_object_mut)
        .context("admin Tenant manifest lacks metadata")?
        .insert(
            "annotations".to_string(),
            serde_json::json!({ FAULT_TEST_RUN_ANNOTATION: run_id }),
        );
    Ok(serde_yaml_ng::to_string(&manifest)?)
}

pub fn apply_tenant_resources(config: &ClusterTestConfig, volumes_per_server: u32) -> Result<()> {
    let kubectl = Kubectl::new(config);
    if !ensure_namespace_owned_or_absent(config)? {
        kubectl
            .create_yaml_command(namespace_manifest(config))
            .run_checked()
            .with_context(|| {
                format!(
                    "create dedicated fault-test namespace {:?}",
                    config.test_namespace
                )
            })?;
    }
    kubectl
        .apply_yaml_command(credential_secret_manifest(config))
        .run_checked()?;
    kubectl
        .apply_yaml_command(tenant_manifest(config, volumes_per_server)?)
        .run_checked()?;
    Ok(())
}

pub fn apply_admin_tenant_stage(
    config: &ClusterTestConfig,
    plan: &AdminFixturePlan,
    expanded: bool,
    run_id: &str,
) -> Result<()> {
    let kubectl = Kubectl::new(config);
    let namespace_exists = ensure_namespace_owned_or_absent(config)?;
    if expanded {
        ensure!(
            namespace_exists,
            "admin fixture expansion requires the owned primary Tenant stage"
        );
        let output = Kubectl::new(config)
            .namespaced(&config.test_namespace)
            .command(["get", "tenant", &config.tenant_name, "-o", "json"])
            .run_checked()
            .context("inspect staged admin Tenant before expansion")?;
        validate_admin_tenant_run_ownership(&output.stdout, &config.tenant_name, run_id)
            .context("refuse expansion of a Tenant owned by another attempt")?;
    } else if !namespace_exists {
        kubectl
            .create_yaml_command(namespace_manifest(config))
            .run_checked()
            .with_context(|| {
                format!(
                    "create dedicated admin fault-test namespace {:?}",
                    config.test_namespace
                )
            })?;
    }
    kubectl
        .apply_yaml_command(credential_secret_manifest(config))
        .run_checked()?;
    kubectl
        .apply_yaml_command(admin_tenant_manifest(config, plan, expanded, run_id)?)
        .run_checked()?;
    Ok(())
}

pub fn capture_admin_fixture_observation(
    config: &ClusterTestConfig,
    phase: AdminFixturePhase,
    prefilled_objects: Option<usize>,
) -> Result<AdminFixtureObservation> {
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "tenant", &config.tenant_name, "-o", "json"])
        .run_checked()
        .context("capture staged admin Tenant")?;
    let tenant = serde_json::from_str::<Value>(&output.stdout)
        .context("decode staged admin Tenant GET response")?;
    let tenant_uid = tenant
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .context("staged admin Tenant GET lacks metadata.uid")?;
    let pool_names = tenant
        .pointer("/spec/pools")
        .and_then(Value::as_array)
        .context("staged admin Tenant GET lacks spec.pools")?
        .iter()
        .map(|pool| {
            pool.get("name")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .context("staged admin Tenant pool lacks name")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(AdminFixtureObservation {
        phase,
        observed_at_ms: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default()
            .max(1),
        tenant_uid: tenant_uid.to_string(),
        pool_names,
        prefilled_objects,
    })
}

pub fn reset_owned_admin_tenant_resources(config: &ClusterTestConfig, run_id: &str) -> Result<()> {
    ensure!(!run_id.trim().is_empty(), "admin fixture run ID is empty");
    if !ensure_namespace_owned_or_absent(config)? {
        return Ok(());
    }
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "tenant", &config.tenant_name, "-o", "json"])
        .run()?;
    match output.code {
        Some(0) => {
            validate_admin_tenant_run_ownership(&output.stdout, &config.tenant_name, run_id)?
        }
        _ if is_not_found(&output) => return Ok(()),
        _ => bail!(
            "failed to inspect staged admin Tenant {:?} before cleanup\nexit: {:?}\nstdout:\n{}\nstderr:\n{}",
            config.tenant_name,
            output.code,
            output.stdout,
            output.stderr
        ),
    }
    reset_generic_tenant_resources(config)
}

pub fn reset_tenant_resources(config: &ClusterTestConfig) -> Result<()> {
    if !ensure_namespace_owned_or_absent(config)? {
        return Ok(());
    }
    reset_generic_tenant_resources(config)
}

fn ensure_namespace_owned_or_absent(config: &ClusterTestConfig) -> Result<bool> {
    let output = Kubectl::new(config)
        .command(["get", "namespace", &config.test_namespace, "-o", "json"])
        .run()?;

    match output.code {
        Some(0) => {
            validate_namespace_ownership(
                &output.stdout,
                &config.test_namespace,
                &config.tenant_name,
            )?;
            Ok(true)
        }
        _ if is_not_found(&output) => Ok(false),
        _ => bail!(
            "failed to inspect fault-test namespace {:?} before destructive operation\nexit: {:?}\nstdout:\n{}\nstderr:\n{}",
            config.test_namespace,
            output.code,
            output.stdout,
            output.stderr
        ),
    }
}

fn validate_namespace_ownership(raw: &str, namespace: &str, tenant_name: &str) -> Result<()> {
    let value = serde_json::from_str::<Value>(raw)
        .with_context(|| format!("parse namespace {namespace:?} json"))?;
    let manager = value
        .pointer("/metadata/labels/app.kubernetes.io~1managed-by")
        .and_then(Value::as_str);
    let owned_tenant = value
        .pointer("/metadata/annotations/rustfs.com~1fault-test-tenant")
        .and_then(Value::as_str);

    ensure!(
        manager == Some(FAULT_TEST_MANAGER) && owned_tenant == Some(tenant_name),
        "refusing destructive fault-test operation in namespace {namespace:?}: expected label \
         {MANAGED_BY_LABEL}={FAULT_TEST_MANAGER:?} and annotation \
         {FAULT_TEST_TENANT_ANNOTATION}={tenant_name:?}, got manager={manager:?}, \
         tenant={owned_tenant:?}; use a dedicated namespace or explicitly label and annotate it \
         only after verifying that it contains no non-test workloads"
    );
    Ok(())
}

fn validate_admin_tenant_run_ownership(raw: &str, tenant_name: &str, run_id: &str) -> Result<()> {
    let value = serde_json::from_str::<Value>(raw)
        .with_context(|| format!("parse staged admin Tenant {tenant_name:?} json"))?;
    let observed_name = value.pointer("/metadata/name").and_then(Value::as_str);
    let observed_run = value
        .pointer("/metadata/annotations/rustfs.com~1fault-test-run")
        .and_then(Value::as_str);
    ensure!(
        observed_name == Some(tenant_name) && observed_run == Some(run_id),
        "refusing cleanup of staged admin Tenant {tenant_name:?}: expected run annotation \
         {FAULT_TEST_RUN_ANNOTATION}={run_id:?}, got name={observed_name:?}, run={observed_run:?}"
    );
    Ok(())
}

fn is_not_found(output: &CommandOutput) -> bool {
    output.stderr.contains("NotFound")
        || output.stderr.contains("not found")
        || output.stdout.contains("NotFound")
        || output.stdout.contains("not found")
}

#[cfg(test)]
mod tests {
    use super::{
        ADMIN_EXPANSION_POOL_NAME, AdminFixtureEvidence, AdminFixtureObservation,
        AdminFixturePhase, AdminFixturePlan, admin_tenant_manifest, namespace_manifest,
        tenant_manifest, validate_admin_tenant_run_ownership, validate_namespace_ownership,
    };
    use crate::fault::{
        admin_topology::DECOMMISSION_TARGET_POOL_NAME, config::FaultTestConfig,
        scenarios::ADMIN_DECOMMISSION_SCENARIO,
    };

    #[test]
    fn fault_tenant_manifest_uses_real_cluster_defaults() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = tenant_manifest(&config.cluster, 1).expect("fault tenant manifest");

        assert!(manifest.contains("namespace: rustfs-fault-test"));
        assert!(manifest.contains("storageClassName: fast-csi"));
        assert!(manifest.contains("storage: 100Gi"));
        assert!(manifest.contains("operator.rustfs.com/runtime-default-image-ack"));
        assert!(manifest.contains("rustfs/rustfs:test"));
        let value: serde_json::Value = serde_yaml_ng::from_str(&manifest).expect("valid YAML");
        assert_eq!(
            value
                .pointer("/metadata/annotations/operator.rustfs.com~1runtime-default-image-ack")
                .and_then(serde_json::Value::as_str),
            Some("rustfs/rustfs:test")
        );
        assert!(!manifest.contains("rustfs-storage"));
        assert!(!manifest.contains("RUSTFS_UNSAFE_BYPASS_DISK_CHECK"));
        assert!(manifest.contains("topologyKey: kubernetes.io/hostname"));
    }

    #[test]
    fn fault_tenant_manifest_honors_single_node_topology() {
        let mut config = FaultTestConfig::for_test("minikube", "standard");
        config.cluster.tenant_storage_request = "2Gi".to_string();
        config.cluster.tenant_spread_across_hosts = false;
        config.cluster.tenant_unsafe_bypass_disk_check = true;

        let manifest = tenant_manifest(&config.cluster, 1).expect("fault tenant manifest");

        // Single-node knobs come from config without editing source: small PVC,
        // no host anti-affinity, and the disk-check bypass env present.
        assert!(manifest.contains("storage: 2Gi"));
        assert!(!manifest.contains("topologyKey"));
        assert!(manifest.contains("RUSTFS_UNSAFE_BYPASS_DISK_CHECK"));
    }

    #[test]
    fn fault_tenant_manifest_includes_extra_rustfs_env() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.cluster.rustfs_env = vec![(
            "RUSTFS_GET_METADATA_EARLY_STOP_ENABLE".to_string(),
            "true".to_string(),
        )];

        let manifest = tenant_manifest(&config.cluster, 1).expect("fault tenant manifest");
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
    fn admin_fixture_manifest_stages_one_pool_before_expansion() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let plan =
            AdminFixturePlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO, 4).expect("fixture plan");
        let initial: serde_json::Value = serde_yaml_ng::from_str(
            &admin_tenant_manifest(&config.cluster, &plan, false, "run-1")
                .expect("initial manifest"),
        )
        .expect("initial yaml");
        let expanded: serde_json::Value = serde_yaml_ng::from_str(
            &admin_tenant_manifest(&config.cluster, &plan, true, "run-1")
                .expect("expanded manifest"),
        )
        .expect("expanded yaml");

        assert_eq!(initial["spec"]["pools"].as_array().expect("pools").len(), 1);
        assert_eq!(
            initial["spec"]["pools"][0]["name"],
            DECOMMISSION_TARGET_POOL_NAME
        );
        assert_eq!(
            expanded["spec"]["pools"].as_array().expect("pools").len(),
            2
        );
        assert_eq!(
            expanded["spec"]["pools"][1]["name"],
            ADMIN_EXPANSION_POOL_NAME
        );
        assert_eq!(
            initial["metadata"]["annotations"]["rustfs.com/fault-test-run"],
            "run-1"
        );
    }

    #[test]
    fn same_pod_fault_fixture_requests_two_volumes_per_server() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest: serde_json::Value = serde_yaml_ng::from_str(
            &tenant_manifest(&config.cluster, 2).expect("two-volume fixture"),
        )
        .expect("Tenant YAML");
        assert_eq!(
            manifest.pointer("/spec/pools/0/servers"),
            Some(&serde_json::json!(4))
        );
        assert_eq!(
            manifest.pointer("/spec/pools/0/persistence/volumesPerServer"),
            Some(&serde_json::json!(2))
        );
    }

    #[test]
    fn admin_tenant_cleanup_requires_the_exact_run_annotation() {
        let tenant = serde_json::json!({
            "metadata": {
                "name": "tenant-a",
                "annotations": {"rustfs.com/fault-test-run": "run-a"}
            }
        });
        let raw = serde_json::to_string(&tenant).expect("tenant json");

        validate_admin_tenant_run_ownership(&raw, "tenant-a", "run-a").expect("owned Tenant");
        assert!(validate_admin_tenant_run_ownership(&raw, "tenant-a", "run-b").is_err());
        assert!(validate_admin_tenant_run_ownership(&raw, "tenant-b", "run-a").is_err());
    }

    #[test]
    fn admin_fixture_evidence_requires_prefill_before_expansion() {
        let plan =
            AdminFixturePlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO, 4).expect("fixture plan");
        let initial = vec![plan.initial_pool_name.clone()];
        let expanded = vec![
            plan.initial_pool_name.clone(),
            plan.expansion_pool_name.clone(),
        ];
        let observation =
            |phase, observed_at_ms, pools, prefilled_objects| AdminFixtureObservation {
                phase,
                observed_at_ms,
                tenant_uid: "tenant-uid".to_string(),
                pool_names: pools,
                prefilled_objects,
            };
        let mut evidence = AdminFixtureEvidence {
            schema_version: 1,
            scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
            run_id: "fault-run".to_string(),
            tenant: "fault-test-tenant".to_string(),
            plan,
            observations: vec![
                observation(AdminFixturePhase::PrimaryReady, 1, initial.clone(), None),
                observation(AdminFixturePhase::PrefillComplete, 2, initial, Some(20)),
                observation(
                    AdminFixturePhase::ExpansionApplied,
                    3,
                    expanded.clone(),
                    None,
                ),
                observation(AdminFixturePhase::TopologyStable, 4, expanded, None),
            ],
        };

        evidence.validate_complete().expect("valid staged fixture");
        evidence.observations.swap(1, 2);
        assert!(evidence.validate_complete().is_err());
    }

    #[test]
    fn fault_namespace_manifest_records_destructive_test_ownership() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = namespace_manifest(&config.cluster);

        assert!(manifest.contains("name: rustfs-fault-test"));
        assert!(manifest.contains("app.kubernetes.io/managed-by: s3chaos"));
        assert!(manifest.contains("rustfs.com/fault-test-tenant: fault-test-tenant"));
    }

    #[test]
    fn fault_namespace_ownership_requires_matching_manager_and_tenant() {
        let owned = r#"{
            "metadata": {
                "labels": {
                    "app.kubernetes.io/managed-by": "s3chaos"
                },
                "annotations": {
                    "rustfs.com/fault-test-tenant": "fault-test-tenant"
                }
            }
        }"#;
        assert!(
            validate_namespace_ownership(owned, "rustfs-fault-test", "fault-test-tenant").is_ok()
        );

        let unowned = r#"{"metadata":{"labels":{},"annotations":{}}}"#;
        assert!(
            validate_namespace_ownership(unowned, "rustfs-fault-test", "fault-test-tenant")
                .is_err()
        );

        assert!(
            validate_namespace_ownership(owned, "rustfs-fault-test", "another-tenant").is_err()
        );
    }
}
