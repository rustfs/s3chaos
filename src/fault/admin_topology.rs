// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0

//! Fault-owned policy and a typed RustFS adapter for destructive pool
//! operations. The port deliberately excludes IAM administration: callers see
//! only the capabilities required by the topology reliability cases.

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use http::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::fault::{
    scenarios::{ADMIN_DECOMMISSION_SCENARIO, ADMIN_REBALANCE_SCENARIO},
    workload::WorkloadPlan,
};
use crate::framework::port_forward::{
    KubernetesRawGetSnapshot, PortForwardGuard, PortForwardTargetSnapshot,
};
use crate::rustfs::{RustfsAdminResponse, RustfsAdminTransport};

pub const ADMIN_PREFIX: &str = "/rustfs/admin/v3";
pub const ADMIN_TOPOLOGY_PROOF_ARTIFACT: &str = "admin-topology-proof.json";
pub const ADMIN_OPERATION_ARTIFACT: &str = "admin-operation.json";
pub const ADMIN_OPERATION_PROGRESS_ARTIFACT: &str = "admin-operation-progress.jsonl";
pub const DECOMMISSION_TARGET_POOL_NAME: &str = "decommission-target";
pub const RUSTFS_DECOMMISSION_CAPACITY_PERCENT: u64 = 130;
const ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS: u64 = 5_000;

const DEFAULT_CLUSTER_DOMAIN: &str = "cluster.local";
const DEFAULT_POOL_DATA_PATH: &str = "/data";
const ADMIN_DECOMMISSION_CASE_NAME: &str = "fault_admin_decommission_preserves_object_model";
const ADMIN_REBALANCE_CASE_NAME: &str = "fault_admin_rebalance_preserves_object_model";
const POOL_USED_RATIO_TOLERANCE: f64 = 0.000_001;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdminTopologyKind {
    Decommission,
    Rebalance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTopologyPlan {
    pub kind: AdminTopologyKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_name: Option<String>,
}

impl AdminTopologyPlan {
    pub fn for_scenario(scenario: &str) -> Result<Self> {
        match scenario {
            ADMIN_DECOMMISSION_SCENARIO => Ok(Self {
                kind: AdminTopologyKind::Decommission,
                target_pool_name: Some(DECOMMISSION_TARGET_POOL_NAME.to_string()),
            }),
            ADMIN_REBALANCE_SCENARIO => Ok(Self {
                kind: AdminTopologyKind::Rebalance,
                target_pool_name: None,
            }),
            other => bail!("scenario {other:?} is not an admin topology case"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminAttemptIdentity {
    pub run_id: String,
    pub case_name: String,
    pub tenant_uid: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminAttemptWindow {
    pub started_at_ms: u64,
    pub evaluated_at_ms: u64,
}

impl AdminAttemptWindow {
    fn validate(self) -> Result<()> {
        ensure!(
            self.started_at_ms > 0 && self.started_at_ms <= self.evaluated_at_ms,
            "admin attempt time window is invalid"
        );
        Ok(())
    }

    fn contains(self, observed_at_ms: u64) -> bool {
        (self.started_at_ms..=self.evaluated_at_ms).contains(&observed_at_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminTopologyBuildContext {
    run_id: String,
    case_name: String,
    cluster_domain: String,
    /// Fail-closed storage reserve for the finite workload.
    workload_max_bytes: u64,
    runtime: AdminRuntimeBinding,
}

impl AdminTopologyBuildContext {
    pub fn new(
        run_id: impl Into<String>,
        case_name: impl Into<String>,
        workload: &WorkloadPlan,
        runtime: AdminRuntimeBinding,
    ) -> Result<Self> {
        let prefilled_count = workload.object_count / 2;
        let mixed_count = workload.object_count - prefilled_count;
        ensure!(
            mixed_count as u64 >= workload.operation_mix.total_weight(),
            "admin workload must execute at least one complete operation-mix cycle"
        );
        let context = Self {
            run_id: run_id.into(),
            case_name: case_name.into(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            workload_max_bytes: workload.mixed_write_upper_bound(prefilled_count, mixed_count)?,
            runtime,
        };
        ensure!(
            context.workload_max_bytes > 0,
            "admin workload storage budget must be positive"
        );
        Ok(context)
    }

    pub fn with_cluster_domain(mut self, cluster_domain: impl Into<String>) -> Result<Self> {
        let cluster_domain = cluster_domain.into();
        ensure!(
            !cluster_domain.trim().is_empty(),
            "admin topology cluster domain must not be empty"
        );
        self.cluster_domain = cluster_domain;
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminPool {
    #[serde(default)]
    pub id: usize,
    #[serde(default, rename = "cmdline")]
    pub expression: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub decommission_status: String,
    #[serde(default)]
    pub rebalance_status: String,
    #[serde(default)]
    pub total_size: u64,
    #[serde(default)]
    pub current_size: u64,
    #[serde(default)]
    pub used_size: u64,
    #[serde(default)]
    pub used: f64,
    #[serde(default, rename = "decommissionInfo")]
    pub decommission: Option<DecommissionProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DecommissionProgress {
    #[serde(default)]
    pub start_time: Option<String>,
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub failed: bool,
    #[serde(default)]
    pub canceled: bool,
    #[serde(default)]
    pub queued: bool,
    #[serde(default)]
    pub objects_decommissioned: u64,
    #[serde(default)]
    pub objects_decommissioned_failed: u64,
    #[serde(default)]
    pub bytes_decommissioned: u64,
    #[serde(default)]
    pub bytes_decommissioned_failed: u64,
    #[serde(default)]
    pub waiting_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecommissionPoolStatus {
    pub id: usize,
    #[serde(default, rename = "cmdline")]
    pub expression: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub pool_status: String,
    #[serde(default, rename = "decommissionInfo")]
    pub decommission: Option<DecommissionProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceStart {
    pub id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceCleanupWarnings {
    #[serde(default)]
    pub count: u64,
    #[serde(default, rename = "lastMsg")]
    pub last_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalancePoolStatus {
    pub id: usize,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub stopping: bool,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub cleanup_warnings: RebalanceCleanupWarnings,
    #[serde(default)]
    pub progress: Option<RebalanceProgress>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceProgress {
    #[serde(default, rename = "objects")]
    pub objects: u64,
    #[serde(default, rename = "versions")]
    pub versions: u64,
    #[serde(default)]
    pub bytes: u64,
    #[serde(default)]
    pub remaining_buckets: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceStatus {
    pub id: String,
    #[serde(default)]
    pub pools: Vec<RebalancePoolStatus>,
    #[serde(default)]
    pub stopped_at: Option<String>,
    #[serde(default)]
    pub stop_propagation: RebalanceStopPropagationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct RebalanceStopPropagationStatus {
    #[serde(default)]
    pub failed_peers: Vec<String>,
    #[serde(default)]
    pub terminal_reload_failed_peers: Vec<String>,
    #[serde(default)]
    pub pending_terminal_reload: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequestEvidence {
    pub target: AdminRequestTarget,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_probe: Option<AdminRuntimeBinding>,
    pub method: String,
    pub path: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub query: BTreeMap<String, String>,
    pub status: u16,
    pub started_at_ms: u64,
    pub observed_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_body: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminEndpointIdentity {
    kubernetes_context: String,
    cluster_uid: String,
    port_forward_command: String,
    port_forward_started_at_ms: u64,
    cluster_started_at_ms: u64,
    cluster_observed_at_ms: u64,
    cluster_response_sha256: String,
    cluster_response_body: String,
    namespace: String,
    service_name: String,
    service_uid: String,
    service_resource_version: String,
    service_started_at_ms: u64,
    service_observed_at_ms: u64,
    service_response_sha256: String,
    service_response_body: String,
    tenant_name: String,
    tenant_uid: String,
    tenant_resource_version: String,
    tenant_started_at_ms: u64,
    tenant_observed_at_ms: u64,
    tenant_response_sha256: String,
    tenant_response_body: String,
    local_endpoint: String,
    remote_port: u16,
}

impl AdminEndpointIdentity {
    fn capture_within(&self, window: AdminAttemptWindow) -> bool {
        window.contains(self.cluster_started_at_ms)
            && window.contains(self.cluster_observed_at_ms)
            && window.contains(self.service_started_at_ms)
            && window.contains(self.service_observed_at_ms)
            && window.contains(self.tenant_started_at_ms)
            && window.contains(self.tenant_observed_at_ms)
    }

    fn from_live_port_forward(port_forward: &mut PortForwardGuard) -> Result<Self> {
        let snapshot = port_forward.capture_target()?;
        let service: Value = serde_json::from_str(snapshot.service_response_body())
            .context("decode captured Kubernetes Service GET response")?;
        let tenant_name = required_string(&service, "/spec/selector/rustfs.tenant")?;
        let tenant = port_forward.capture_namespaced_resource("tenant", &tenant_name)?;
        Self::from_port_forward_snapshot(&snapshot, &tenant)
    }

    fn from_port_forward_snapshot(
        snapshot: &PortForwardTargetSnapshot,
        tenant_snapshot: &KubernetesRawGetSnapshot,
    ) -> Result<Self> {
        let cluster_response_body = snapshot.cluster_response_body().to_string();
        let cluster: Value = serde_json::from_str(&cluster_response_body)
            .context("decode captured Kubernetes cluster identity response")?;
        let service_response_body = snapshot.service_response_body().to_string();
        let service: Value = serde_json::from_str(&service_response_body)
            .context("decode captured Kubernetes Service GET response")?;
        let service_name = snapshot
            .spec()
            .service
            .strip_prefix("svc/")
            .filter(|name| !name.is_empty())
            .context("admin port-forward target is not a named Service")?;
        let tenant_response_body = tenant_snapshot.response_body().to_string();
        let tenant: Value = serde_json::from_str(&tenant_response_body)
            .context("decode captured Kubernetes Tenant GET response")?;
        let (cluster_started_at_ms, cluster_observed_at_ms) = snapshot.cluster_interval_ms();
        let (service_started_at_ms, service_observed_at_ms) = snapshot.service_interval_ms();
        let (tenant_started_at_ms, tenant_observed_at_ms) = tenant_snapshot.interval_ms();
        let identity = Self {
            kubernetes_context: snapshot.kubernetes_context().to_string(),
            cluster_uid: required_string(&cluster, "/metadata/uid")?,
            port_forward_command: snapshot.command_display().to_string(),
            port_forward_started_at_ms: snapshot.port_forward_started_at_ms(),
            cluster_started_at_ms,
            cluster_observed_at_ms,
            cluster_response_sha256: sha256_hex(cluster_response_body.as_bytes()),
            cluster_response_body,
            namespace: snapshot.spec().namespace.clone(),
            service_name: service_name.to_string(),
            service_uid: required_string(&service, "/metadata/uid")?,
            service_resource_version: required_string(&service, "/metadata/resourceVersion")?,
            service_started_at_ms,
            service_observed_at_ms,
            service_response_sha256: sha256_hex(service_response_body.as_bytes()),
            service_response_body,
            tenant_name: required_string(&tenant, "/metadata/name")?,
            tenant_uid: required_string(&tenant, "/metadata/uid")?,
            tenant_resource_version: required_string(&tenant, "/metadata/resourceVersion")?,
            tenant_started_at_ms,
            tenant_observed_at_ms,
            tenant_response_sha256: sha256_hex(tenant_response_body.as_bytes()),
            tenant_response_body,
            local_endpoint: snapshot.spec().local_base_url(),
            remote_port: snapshot.spec().remote_port,
        };
        identity.validate()?;
        Ok(identity)
    }

    fn validate(&self) -> Result<()> {
        let endpoint = reqwest::Url::parse(&self.local_endpoint)
            .context("parse admin port-forward endpoint identity")?;
        let local_port = endpoint
            .port()
            .context("admin port-forward endpoint has no explicit local port")?;
        let expected_command = format!(
            "kubectl --context {} -n {} port-forward svc/{} {}:{}",
            self.kubernetes_context,
            self.namespace,
            self.service_name,
            local_port,
            self.remote_port
        );
        ensure!(
            !self.kubernetes_context.trim().is_empty()
                && !self.cluster_uid.trim().is_empty()
                && self.port_forward_command == expected_command
                && self.port_forward_started_at_ms > 0
                && self.port_forward_started_at_ms <= self.cluster_started_at_ms
                && self.cluster_started_at_ms <= self.cluster_observed_at_ms
                && self.cluster_observed_at_ms <= self.service_started_at_ms
                && self.service_started_at_ms <= self.service_observed_at_ms
                && self.service_observed_at_ms <= self.tenant_started_at_ms
                && self.tenant_started_at_ms <= self.tenant_observed_at_ms
                && self.cluster_response_sha256
                    == sha256_hex(self.cluster_response_body.as_bytes())
                && !self.namespace.trim().is_empty()
                && !self.service_name.trim().is_empty()
                && !self.service_uid.trim().is_empty()
                && !self.service_resource_version.trim().is_empty()
                && self.service_response_sha256
                    == sha256_hex(self.service_response_body.as_bytes())
                && endpoint.scheme() == "http"
                && endpoint.host_str() == Some("127.0.0.1")
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && self.local_endpoint == format!("http://127.0.0.1:{local_port}")
                && self.remote_port == 9000,
            "admin endpoint is not an exact loopback port-forward to the current Tenant I/O service"
        );
        let cluster: Value = serde_json::from_str(&self.cluster_response_body)
            .context("decode captured Kubernetes cluster identity response")?;
        ensure!(
            required_string(&cluster, "/apiVersion")? == "v1"
                && required_string(&cluster, "/kind")? == "Namespace"
                && required_string(&cluster, "/metadata/name")? == "kube-system"
                && required_string(&cluster, "/metadata/uid")? == self.cluster_uid,
            "Kubernetes cluster UID does not match the captured kube-system Namespace GET response"
        );
        let service: Value = serde_json::from_str(&self.service_response_body)
            .context("decode captured Kubernetes Service GET response")?;
        ensure!(
            required_string(&service, "/apiVersion")? == "v1"
                && required_string(&service, "/kind")? == "Service"
                && required_string(&service, "/metadata/namespace")? == self.namespace
                && required_string(&service, "/metadata/name")? == self.service_name
                && required_string(&service, "/metadata/uid")? == self.service_uid
                && required_string(&service, "/metadata/resourceVersion")?
                    == self.service_resource_version
                && service
                    .pointer("/spec/ports")
                    .and_then(Value::as_array)
                    .is_some_and(|ports| {
                        ports.iter().any(|port| {
                            port.get("port").and_then(Value::as_u64)
                                == Some(u64::from(self.remote_port))
                        })
                    }),
            "admin port-forward Service identity fields do not match its captured Kubernetes response"
        );
        let tenant: Value = serde_json::from_str(&self.tenant_response_body)
            .context("decode captured Kubernetes Tenant GET response")?;
        ensure!(
            !self.tenant_name.trim().is_empty()
                && !self.tenant_uid.trim().is_empty()
                && !self.tenant_resource_version.trim().is_empty()
                && self.tenant_response_sha256 == sha256_hex(self.tenant_response_body.as_bytes())
                && required_string(&tenant, "/metadata/namespace")? == self.namespace
                && required_string(&tenant, "/metadata/name")? == self.tenant_name
                && required_string(&tenant, "/metadata/uid")? == self.tenant_uid
                && required_string(&tenant, "/metadata/resourceVersion")?
                    == self.tenant_resource_version
                && service
                    .pointer("/spec/selector/rustfs.tenant")
                    .and_then(Value::as_str)
                    == Some(self.tenant_name.as_str()),
            "admin endpoint Tenant identity does not match its live port-forward Service or captured Tenant GET"
        );
        Ok(())
    }

    fn validate_for_tenant(&self, namespace: &str, tenant: &str, tenant_uid: &str) -> Result<()> {
        self.validate()?;
        ensure!(
            self.namespace == namespace
                && self.service_name == format!("{tenant}-io")
                && self.tenant_name == tenant
                && self.tenant_uid == tenant_uid
                && serde_json::from_str::<Value>(&self.service_response_body)
                    .ok()
                    .and_then(|service| {
                        service
                            .pointer("/spec/selector/rustfs.tenant")
                            .and_then(Value::as_str)
                            .map(str::to_string)
                    })
                    .as_deref()
                    == Some(tenant),
            "admin port-forward service does not belong to the proven Tenant"
        );
        Ok(())
    }

    fn require_same_live_target(&self, current: &Self) -> Result<()> {
        self.validate()?;
        current.validate()?;
        let bound_tenant = self.tenant_receipt()?;
        let current_tenant = current.tenant_receipt()?;
        ensure!(
            self.kubernetes_context == current.kubernetes_context
                && self.cluster_uid == current.cluster_uid
                && self.port_forward_command == current.port_forward_command
                && self.namespace == current.namespace
                && self.service_name == current.service_name
                && self.service_uid == current.service_uid
                && self.tenant_name == current.tenant_name
                && self.tenant_uid == current.tenant_uid
                && self.local_endpoint == current.local_endpoint
                && self.remote_port == current.remote_port
                && bound_tenant.pointer("/spec") == current_tenant.pointer("/spec"),
            "admin port-forward live Kubernetes target drifted after endpoint binding"
        );
        Ok(())
    }

    fn tenant_receipt(&self) -> Result<Value> {
        self.validate()?;
        serde_json::from_str(&self.tenant_response_body)
            .context("decode authenticated admin endpoint Tenant GET receipt")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRequestTarget {
    pub endpoint: AdminEndpointIdentity,
    pub deployment_id: String,
}

impl AdminRequestTarget {
    fn require_same_runtime_identity(&self, current: &Self) -> Result<()> {
        self.endpoint.require_same_live_target(&current.endpoint)?;
        ensure!(
            self.deployment_id == current.deployment_id,
            "RustFS deployment changed across admin evidence"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRuntimeBinding {
    pub target: AdminRequestTarget,
    pub status: u16,
    pub started_at_ms: u64,
    pub observed_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    pub response_sha256: String,
    pub response_body: String,
}

impl AdminRuntimeBinding {
    fn from_response(
        endpoint: AdminEndpointIdentity,
        response: &RustfsAdminResponse,
        started_at_ms: u64,
        observed_at_ms: u64,
    ) -> Result<Self> {
        require_success(response, &format!("{ADMIN_PREFIX}/info"))?;
        let response_body = String::from_utf8(response.body.clone())
            .context("RustFS admin info response is not UTF-8 JSON")?;
        let deployment_id = deployment_id_from_info(&response_body)?;
        let binding = Self {
            target: AdminRequestTarget {
                endpoint,
                deployment_id,
            },
            status: response.status,
            started_at_ms,
            observed_at_ms,
            request_id: response.request_id.clone(),
            response_sha256: sha256_hex(response_body.as_bytes()),
            response_body,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<()> {
        self.target.endpoint.validate()?;
        ensure!(
            (200..300).contains(&self.status)
                && self.target.endpoint.tenant_observed_at_ms <= self.started_at_ms
                && self.started_at_ms > 0
                && self.started_at_ms <= self.observed_at_ms
                && !self.target.deployment_id.trim().is_empty()
                && self.response_sha256 == sha256_hex(self.response_body.as_bytes())
                && deployment_id_from_info(&self.response_body)? == self.target.deployment_id,
            "RustFS deployment binding is incomplete or inconsistent with its captured admin info response"
        );
        Ok(())
    }

    fn require_same_runtime(&self, current: &Self) -> Result<()> {
        self.validate()?;
        current.validate()?;
        self.target.require_same_runtime_identity(&current.target)?;
        ensure!(
            self.observed_at_ms <= current.started_at_ms,
            "RustFS deployment changed before a destructive admin request"
        );
        Ok(())
    }
}

impl AdminRequestEvidence {
    fn validate(&self) -> Result<()> {
        self.target.endpoint.validate()?;
        ensure!(
            !self.target.deployment_id.trim().is_empty()
                && self.started_at_ms > 0
                && self.target.endpoint.tenant_observed_at_ms <= self.started_at_ms
                && self.started_at_ms <= self.observed_at_ms,
            "admin request evidence lacks a deployment or an ordered request interval"
        );
        if self.method != Method::GET.as_str() {
            ensure!(
                self.runtime_probe.is_some(),
                "destructive admin request lacks its fresh RustFS runtime probe"
            );
        }
        if let Some(probe) = &self.runtime_probe {
            probe.validate()?;
            ensure!(
                probe.target == self.target && probe.observed_at_ms <= self.started_at_ms,
                "admin request is not preceded by its exact fresh RustFS runtime probe"
            );
        }
        ensure!(
            matches!(
                (&self.response_sha256, &self.response_body),
                (Some(digest), Some(body)) if digest == &sha256_hex(body.as_bytes())
            ) || (self.response_sha256.is_none() && self.response_body.is_none()),
            "admin request response body and digest are incomplete or inconsistent"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminCall<T> {
    pub value: T,
    pub request: AdminRequestEvidence,
}

struct AdminRequestPreflight {
    target: AdminRequestTarget,
    runtime_probe: Option<AdminRuntimeBinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KubernetesTenantGetEvidence {
    pub kubernetes_context: String,
    pub cluster_uid: String,
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub resource_version: String,
    pub started_at_ms: u64,
    pub observed_at_ms: u64,
    pub response_sha256: String,
    pub response_body: String,
}

impl KubernetesTenantGetEvidence {
    pub fn from_response(
        kubernetes_context: &str,
        cluster_uid: &str,
        response_body: &[u8],
        started_at_ms: u64,
        observed_at_ms: u64,
    ) -> Result<Self> {
        let response_body = String::from_utf8(response_body.to_vec())
            .context("Kubernetes Tenant GET response is not UTF-8 JSON")?;
        let tenant: Value = serde_json::from_str(&response_body)
            .context("decode Kubernetes Tenant GET response")?;
        let evidence = Self {
            kubernetes_context: kubernetes_context.to_string(),
            cluster_uid: cluster_uid.to_string(),
            namespace: required_string(&tenant, "/metadata/namespace")?,
            name: required_string(&tenant, "/metadata/name")?,
            uid: required_string(&tenant, "/metadata/uid")?,
            resource_version: required_string(&tenant, "/metadata/resourceVersion")?,
            started_at_ms,
            observed_at_ms,
            response_sha256: sha256_hex(response_body.as_bytes()),
            response_body,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            !self.namespace.trim().is_empty()
                && !self.kubernetes_context.trim().is_empty()
                && !self.cluster_uid.trim().is_empty()
                && !self.name.trim().is_empty()
                && !self.uid.trim().is_empty()
                && !self.resource_version.trim().is_empty()
                && self.started_at_ms > 0
                && self.started_at_ms <= self.observed_at_ms,
            "Kubernetes Tenant GET evidence lacks namespace/name/UID/resourceVersion or an ordered startedAt/observedAt interval"
        );
        ensure!(
            self.response_sha256 == sha256_hex(self.response_body.as_bytes()),
            "Kubernetes Tenant GET response digest does not match its captured body"
        );
        let tenant: Value = serde_json::from_str(&self.response_body)
            .context("decode captured Kubernetes Tenant GET response")?;
        ensure!(
            required_string(&tenant, "/metadata/namespace")? == self.namespace
                && required_string(&tenant, "/metadata/name")? == self.name
                && required_string(&tenant, "/metadata/uid")? == self.uid
                && required_string(&tenant, "/metadata/resourceVersion")? == self.resource_version,
            "Kubernetes Tenant GET identity fields do not match its captured response"
        );
        Ok(())
    }

    fn tenant_receipt(&self) -> Result<Value> {
        self.validate()?;
        serde_json::from_str(&self.response_body)
            .context("decode authenticated Kubernetes Tenant GET receipt")
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminPoolSnapshot {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub tenant_get: KubernetesTenantGetEvidence,
    pub runtime: AdminRuntimeBinding,
    pub observed_at_ms: u64,
    pub request: AdminRequestEvidence,
    pub pools: Vec<AdminPool>,
}

impl AdminPoolSnapshot {
    pub fn from_list(
        run_id: impl Into<String>,
        case_name: impl Into<String>,
        tenant_response_body: &[u8],
        runtime: AdminRuntimeBinding,
        tenant_started_at_ms: u64,
        tenant_observed_at_ms: u64,
        call: AdminCall<Vec<AdminPool>>,
    ) -> Result<Self> {
        let tenant_get = KubernetesTenantGetEvidence::from_response(
            &runtime.target.endpoint.kubernetes_context,
            &runtime.target.endpoint.cluster_uid,
            tenant_response_body,
            tenant_started_at_ms,
            tenant_observed_at_ms,
        )?;
        let snapshot = Self {
            attempt: AdminAttemptIdentity {
                run_id: run_id.into(),
                case_name: case_name.into(),
                tenant_uid: tenant_get.uid.clone(),
            },
            tenant_get,
            runtime,
            observed_at_ms: call.request.observed_at_ms,
            request: call.request,
            pools: call.value,
        };
        snapshot.validate_list_request()?;
        Ok(snapshot)
    }

    fn validate_list_request(&self) -> Result<()> {
        validate_attempt_identity(&self.attempt)?;
        self.tenant_get.validate()?;
        self.runtime.validate()?;
        self.request.validate()?;
        let request_runtime = self
            .request
            .runtime_probe
            .as_ref()
            .context("pools/list request lacks a fresh RustFS runtime probe")?;
        self.runtime
            .target
            .require_same_runtime_identity(&request_runtime.target)?;
        self.runtime.target.endpoint.validate_for_tenant(
            &self.tenant_get.namespace,
            &self.tenant_get.name,
            &self.tenant_get.uid,
        )?;
        ensure!(
            self.tenant_get.uid == self.attempt.tenant_uid
                && self.observed_at_ms == self.request.observed_at_ms
                && self.request.started_at_ms > 0
                && self.request.started_at_ms <= self.request.observed_at_ms
                && self.tenant_get.observed_at_ms < self.request.started_at_ms
                && self.tenant_get.observed_at_ms
                    <= request_runtime.target.endpoint.cluster_started_at_ms
                && request_runtime.observed_at_ms <= self.request.started_at_ms
                && self.request.method == "GET"
                && self.request.path == "/rustfs/admin/v3/pools/list"
                && self.request.query.is_empty()
                && (200..300).contains(&self.request.status),
            "pool snapshot is not bound to one Kubernetes Tenant GET and one successful pools/list observation"
        );
        ensure!(
            self.request.target == request_runtime.target
                && self.tenant_get.kubernetes_context
                    == self.runtime.target.endpoint.kubernetes_context
                && self.tenant_get.cluster_uid == self.runtime.target.endpoint.cluster_uid
                && self.tenant_get.namespace == self.runtime.target.endpoint.namespace,
            "pool snapshot Tenant GET, port-forward endpoint, deployment, and pools/list request are not one runtime identity"
        );
        let wire_pools = parse_captured_json_response::<Vec<AdminPool>>(
            &self.request,
            "RustFS pools/list response",
        )?;
        ensure!(
            wire_pools == self.pools,
            "pool snapshot fields do not match the captured RustFS pools/list response"
        );
        Ok(())
    }
}

#[async_trait]
pub trait AdminTopologyPort: Send + Sync {
    async fn list_pools(&self) -> Result<AdminCall<Vec<AdminPool>>>;
    async fn start_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>>;
    async fn decommission_status(
        &self,
        pool_id: usize,
        expression: &str,
    ) -> Result<AdminCall<DecommissionPoolStatus>>;
    async fn cancel_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>>;
    async fn clear_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>>;
    async fn start_rebalance(&self) -> Result<AdminCall<RebalanceStart>>;
    async fn rebalance_status(&self) -> Result<AdminCall<RebalanceStatus>>;
    async fn stop_rebalance(&self) -> Result<AdminCall<()>>;
}

#[derive(Debug)]
pub struct RustfsAdminTopologyAdapter {
    transport: RustfsAdminTransport,
    runtime: AdminRuntimeBinding,
    port_forward: Option<Mutex<PortForwardGuard>>,
}

impl RustfsAdminTopologyAdapter {
    pub async fn connect(
        mut port_forward: PortForwardGuard,
        region: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        let endpoint = AdminEndpointIdentity::from_live_port_forward(&mut port_forward)?;
        Self::connect_bound(endpoint, region, access_key, secret_key, Some(port_forward)).await
    }

    async fn connect_bound(
        endpoint: AdminEndpointIdentity,
        region: &str,
        access_key: &str,
        secret_key: &str,
        port_forward: Option<PortForwardGuard>,
    ) -> Result<Self> {
        let transport = RustfsAdminTransport::new(
            &endpoint.local_endpoint,
            region,
            access_key,
            secret_key,
            None,
            "s3chaos-fault-admin-topology",
        )?;
        let runtime = probe_runtime_binding(&transport, endpoint).await?;
        Ok(Self {
            transport,
            runtime,
            port_forward: port_forward.map(Mutex::new),
        })
    }

    #[cfg(test)]
    async fn connect_for_test(
        endpoint: AdminEndpointIdentity,
        region: &str,
        access_key: &str,
        secret_key: &str,
    ) -> Result<Self> {
        Self::connect_bound(endpoint, region, access_key, secret_key, None).await
    }

    fn ensure_port_forward_target(&self) -> Result<AdminEndpointIdentity> {
        let Some(port_forward) = &self.port_forward else {
            return Ok(self.runtime.target.endpoint.clone());
        };
        let mut port_forward = port_forward
            .lock()
            .map_err(|_| anyhow::anyhow!("admin port-forward guard lock is poisoned"))?;
        let current = AdminEndpointIdentity::from_live_port_forward(&mut port_forward)?;
        self.runtime
            .target
            .endpoint
            .require_same_live_target(&current)?;
        Ok(current)
    }

    pub fn runtime_binding(&self) -> &AdminRuntimeBinding {
        &self.runtime
    }

    pub async fn probe_runtime_binding(&self) -> Result<AdminRuntimeBinding> {
        let endpoint = self.ensure_port_forward_target()?;
        probe_runtime_binding(&self.transport, endpoint).await
    }

    async fn ensure_request_target(
        &self,
        method: &Method,
        path: &str,
    ) -> Result<AdminRequestPreflight> {
        let endpoint = self.ensure_port_forward_target()?;
        let target = AdminRequestTarget {
            endpoint,
            deployment_id: self.runtime.target.deployment_id.clone(),
        };
        let runtime_probe = if *method != Method::GET || path == "/rustfs/admin/v3/pools/list" {
            let current = probe_runtime_binding(&self.transport, target.endpoint.clone()).await?;
            self.runtime.require_same_runtime(&current)?;
            Some(current)
        } else {
            None
        };
        let target = runtime_probe
            .as_ref()
            .map_or(target, |probe| probe.target.clone());
        Ok(AdminRequestPreflight {
            target,
            runtime_probe,
        })
    }

    async fn json<T: for<'de> Deserialize<'de>>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<AdminCall<T>> {
        let preflight = self.ensure_request_target(&method, path).await?;
        let started_at_ms = now_ms();
        let response = self
            .transport
            .request(method.clone(), path, query, Vec::new(), None)
            .await?;
        let observed_at_ms = now_ms();
        require_success(&response, path)?;
        let request = request_evidence(
            preflight,
            method,
            path,
            query,
            &response,
            (started_at_ms, observed_at_ms),
            Some(&response.body),
        );
        let value = serde_json::from_slice(&response.body)
            .with_context(|| format!("decode RustFS admin response for {path}"))?;
        Ok(AdminCall { value, request })
    }

    async fn empty(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<AdminCall<()>> {
        let preflight = self.ensure_request_target(&method, path).await?;
        let started_at_ms = now_ms();
        let response = self
            .transport
            .request(method.clone(), path, query, Vec::new(), None)
            .await?;
        let observed_at_ms = now_ms();
        require_success(&response, path)?;
        Ok(AdminCall {
            value: (),
            request: request_evidence(
                preflight,
                method,
                path,
                query,
                &response,
                (started_at_ms, observed_at_ms),
                None,
            ),
        })
    }
}

fn request_evidence(
    preflight: AdminRequestPreflight,
    method: Method,
    path: &str,
    query: &[(&str, &str)],
    response: &RustfsAdminResponse,
    observed_interval_ms: (u64, u64),
    response_body: Option<&[u8]>,
) -> AdminRequestEvidence {
    let AdminRequestPreflight {
        target,
        runtime_probe,
    } = preflight;
    AdminRequestEvidence {
        target,
        runtime_probe,
        method: method.to_string(),
        path: path.to_string(),
        query: query
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect(),
        status: response.status,
        started_at_ms: observed_interval_ms.0,
        observed_at_ms: observed_interval_ms.1,
        request_id: response.request_id.clone(),
        response_sha256: response_body.map(sha256_hex),
        response_body: response_body.map(|body| String::from_utf8_lossy(body).into_owned()),
    }
}

async fn probe_runtime_binding(
    transport: &RustfsAdminTransport,
    endpoint: AdminEndpointIdentity,
) -> Result<AdminRuntimeBinding> {
    let started_at_ms = now_ms();
    let response = transport
        .request(
            Method::GET,
            &format!("{ADMIN_PREFIX}/info"),
            &[],
            Vec::new(),
            None,
        )
        .await?;
    let observed_at_ms = now_ms();
    AdminRuntimeBinding::from_response(endpoint, &response, started_at_ms, observed_at_ms)
}

fn deployment_id_from_info(response_body: &str) -> Result<String> {
    serde_json::from_str::<Value>(response_body)
        .context("decode captured RustFS admin info response")?
        .pointer("/info/deploymentID")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .context("RustFS admin info response is missing deploymentID")
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn require_success(response: &RustfsAdminResponse, path: &str) -> Result<()> {
    ensure!(
        (200..300).contains(&response.status),
        "RustFS admin request {path} failed: status={} request_id={}",
        response.status,
        response.request_id.as_deref().unwrap_or("unknown")
    );
    Ok(())
}

fn validate_pool_expression(expression: &str) -> Result<()> {
    ensure!(
        !expression.trim().is_empty(),
        "pool expression must not be empty"
    );
    Ok(())
}

#[async_trait]
impl AdminTopologyPort for RustfsAdminTopologyAdapter {
    async fn list_pools(&self) -> Result<AdminCall<Vec<AdminPool>>> {
        self.json(Method::GET, "/rustfs/admin/v3/pools/list", &[])
            .await
    }

    async fn start_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.empty(
            Method::POST,
            "/rustfs/admin/v3/pools/decommission",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn decommission_status(
        &self,
        pool_id: usize,
        expression: &str,
    ) -> Result<AdminCall<DecommissionPoolStatus>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.json(
            Method::GET,
            "/rustfs/admin/v3/decommission/status",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn cancel_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.empty(
            Method::POST,
            "/rustfs/admin/v3/pools/cancel",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn clear_decommission(&self, pool_id: usize, expression: &str) -> Result<AdminCall<()>> {
        validate_pool_expression(expression)?;
        let pool_id = pool_id.to_string();
        self.empty(
            Method::POST,
            "/rustfs/admin/v3/pools/clear",
            &[("pool", pool_id.as_str()), ("by-id", "true")],
        )
        .await
    }

    async fn start_rebalance(&self) -> Result<AdminCall<RebalanceStart>> {
        self.json(Method::POST, "/rustfs/admin/v3/rebalance/start", &[])
            .await
    }

    async fn rebalance_status(&self) -> Result<AdminCall<RebalanceStatus>> {
        self.json(Method::GET, "/rustfs/admin/v3/rebalance/status", &[])
            .await
    }

    async fn stop_rebalance(&self) -> Result<AdminCall<()>> {
        self.empty(Method::POST, "/rustfs/admin/v3/rebalance/stop", &[])
            .await
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantPoolProof {
    pub name: String,
    pub tenant_uid: String,
    pub stateful_set_name: String,
    pub expected_endpoint_set: String,
    pub internode_scheme: String,
    pub cluster_domain: String,
    pub data_path: String,
    pub runtime_pool_id: usize,
    pub servers: u64,
    pub volumes_per_server: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminTopologyProof {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub scenario: String,
    pub tenant: String,
    pub namespace: String,
    pub runtime: AdminRuntimeBinding,
    pub tenant_pools: Vec<TenantPoolProof>,
    pub runtime_pools: Vec<AdminPool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_expression: Option<String>,
    pub remaining_free_bytes: u64,
    pub target_used_bytes: u64,
    pub workload_max_bytes: u64,
    pub capacity_guard_percent: u64,
    pub required_remaining_free_bytes: u64,
    pub mutually_exclusive: bool,
    pub satisfied: bool,
}

impl AdminTopologyProof {
    pub fn build(
        plan: &AdminTopologyPlan,
        scenario: &str,
        tenant: &Value,
        runtime_pools: Vec<AdminPool>,
        context: &AdminTopologyBuildContext,
    ) -> Result<Self> {
        ensure!(
            AdminTopologyPlan::for_scenario(scenario)? == *plan,
            "admin topology plan does not match scenario {scenario}"
        );
        validate_build_context(scenario, context)?;
        let receipt_tenant = context.runtime.target.endpoint.tenant_receipt()?;
        ensure!(
            tenant == &receipt_tenant,
            "Tenant topology input does not match the authenticated raw Tenant GET receipt"
        );
        let (tenant_name, tenant_uid, namespace, tenant_pools) = tenant_pool_proofs_from_receipt(
            &receipt_tenant,
            &context.cluster_domain,
            &runtime_pools,
        )?;
        context.runtime.target.endpoint.validate_for_tenant(
            &namespace,
            &tenant_name,
            &tenant_uid,
        )?;
        validate_runtime_pools(&tenant_pools, &runtime_pools)?;
        let mutually_exclusive = true;
        let target_pool_id = plan
            .target_pool_name
            .as_deref()
            .map(|target_name| {
                tenant_pools
                    .iter()
                    .find(|pool| pool.name == target_name)
                    .map(|pool| pool.runtime_pool_id)
                    .with_context(|| format!("Tenant target pool {target_name:?} does not exist"))
            })
            .transpose()?;
        let capacity =
            topology_capacity(target_pool_id, &runtime_pools, context.workload_max_bytes)?;
        let proof = Self {
            attempt: AdminAttemptIdentity {
                run_id: context.run_id.clone(),
                case_name: context.case_name.clone(),
                tenant_uid: tenant_uid.clone(),
            },
            scenario: scenario.to_string(),
            tenant: tenant_name,
            namespace,
            runtime: context.runtime.clone(),
            tenant_pools,
            runtime_pools,
            target_pool_id,
            target_pool_expression: capacity.target_pool_expression,
            remaining_free_bytes: capacity.remaining_free_bytes,
            target_used_bytes: capacity.target_used_bytes,
            workload_max_bytes: context.workload_max_bytes,
            capacity_guard_percent: RUSTFS_DECOMMISSION_CAPACITY_PERCENT,
            required_remaining_free_bytes: capacity.required_remaining_free_bytes,
            mutually_exclusive,
            satisfied: true,
        };
        proof.require_satisfied()?;
        Ok(proof)
    }

    pub fn require_satisfied(&self) -> Result<()> {
        ensure!(
            self.satisfied && self.mutually_exclusive,
            "admin topology proof is not satisfied"
        );
        ensure!(
            !self.tenant.trim().is_empty()
                && !self.attempt.tenant_uid.trim().is_empty()
                && !self.namespace.trim().is_empty(),
            "admin topology proof lacks Tenant identity"
        );
        validate_attempt_identity(&self.attempt)?;
        self.runtime.validate()?;
        self.runtime.target.endpoint.validate_for_tenant(
            &self.namespace,
            &self.tenant,
            &self.attempt.tenant_uid,
        )?;
        let receipt_tenant = self.runtime.target.endpoint.tenant_receipt()?;
        validate_tenant_receipt_against_proof(self, &receipt_tenant)?;
        for pool in &self.tenant_pools {
            ensure!(
                pool.tenant_uid == self.attempt.tenant_uid,
                "Tenant pool {:?} UID does not match the topology attempt",
                pool.name
            );
            let (stateful_set_name, expected_endpoint_set) = expected_pool_endpoint_set(
                &self.tenant,
                &pool.name,
                &self.namespace,
                &pool.internode_scheme,
                &pool.cluster_domain,
                &pool.data_path,
                (pool.servers, pool.volumes_per_server),
            )?;
            ensure!(
                pool.stateful_set_name == stateful_set_name
                    && pool.expected_endpoint_set == expected_endpoint_set,
                "Tenant pool {:?} endpoint ownership fields are inconsistent",
                pool.name
            );
        }
        let plan = AdminTopologyPlan::for_scenario(&self.scenario)?;
        validate_runtime_pools(&self.tenant_pools, &self.runtime_pools)?;
        let expected_target_id = plan
            .target_pool_name
            .as_deref()
            .map(|target_name| {
                self.tenant_pools
                    .iter()
                    .find(|pool| pool.name == target_name)
                    .map(|pool| pool.runtime_pool_id)
                    .with_context(|| {
                        format!("decommission target {target_name:?} lacks a Tenant pool binding")
                    })
            })
            .transpose()?;
        ensure!(
            self.target_pool_id == expected_target_id,
            "admin topology proof target does not match its named Tenant pool binding"
        );
        ensure!(
            self.capacity_guard_percent == RUSTFS_DECOMMISSION_CAPACITY_PERCENT,
            "admin topology proof uses the wrong RustFS capacity guard"
        );
        let capacity = topology_capacity(
            expected_target_id,
            &self.runtime_pools,
            self.workload_max_bytes,
        )?;
        ensure!(
            self.target_pool_expression == capacity.target_pool_expression
                && self.target_used_bytes == capacity.target_used_bytes
                && self.remaining_free_bytes == capacity.remaining_free_bytes
                && self.required_remaining_free_bytes == capacity.required_remaining_free_bytes,
            "admin topology proof capacity or target facts do not match its runtime snapshot"
        );
        Ok(())
    }
}

fn validate_build_context(scenario: &str, context: &AdminTopologyBuildContext) -> Result<()> {
    ensure!(
        context.case_name == expected_case_name(scenario)?,
        "admin topology build context case does not match scenario {scenario:?}"
    );
    ensure!(
        !context.run_id.trim().is_empty() && !context.cluster_domain.trim().is_empty(),
        "admin topology build context lacks run or cluster-domain identity"
    );
    ensure!(
        context.workload_max_bytes > 0,
        "admin topology workload must have a positive bounded byte budget"
    );
    context.runtime.validate()?;
    Ok(())
}

fn validate_attempt_identity(identity: &AdminAttemptIdentity) -> Result<()> {
    ensure!(
        !identity.run_id.trim().is_empty()
            && !identity.case_name.trim().is_empty()
            && !identity.tenant_uid.trim().is_empty(),
        "admin artifact lacks runId, caseName, or tenantUid"
    );
    Ok(())
}

fn expected_case_name(scenario: &str) -> Result<&'static str> {
    match scenario {
        ADMIN_DECOMMISSION_SCENARIO => Ok(ADMIN_DECOMMISSION_CASE_NAME),
        ADMIN_REBALANCE_SCENARIO => Ok(ADMIN_REBALANCE_CASE_NAME),
        other => bail!("scenario {other:?} is not an admin topology case"),
    }
}

fn tenant_pool_proofs_from_receipt(
    tenant: &Value,
    cluster_domain: &str,
    runtime_pools: &[AdminPool],
) -> Result<(String, String, String, Vec<TenantPoolProof>)> {
    let tenant_name = required_string(tenant, "/metadata/name")?;
    let tenant_uid = required_string(tenant, "/metadata/uid")?;
    let namespace = required_string(tenant, "/metadata/namespace")?;
    let pools = tenant
        .pointer("/spec/pools")
        .and_then(Value::as_array)
        .context("authenticated Tenant GET receipt spec.pools must be an array")?
        .iter()
        .map(|pool| {
            tenant_pool_proof(
                pool,
                &tenant_name,
                &tenant_uid,
                &namespace,
                tenant,
                cluster_domain,
                runtime_pools,
            )
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((tenant_name, tenant_uid, namespace, pools))
}

fn validate_tenant_receipt_against_proof(proof: &AdminTopologyProof, tenant: &Value) -> Result<()> {
    let cluster_domains = proof
        .tenant_pools
        .iter()
        .map(|pool| pool.cluster_domain.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        cluster_domains.len() == 1,
        "Tenant pool proofs do not use one cluster domain"
    );
    let cluster_domain = *cluster_domains
        .first()
        .context("admin topology proof contains no Tenant pool")?;
    let (receipt_name, receipt_uid, receipt_namespace, receipt_pools) =
        tenant_pool_proofs_from_receipt(tenant, cluster_domain, &proof.runtime_pools)?;
    ensure!(
        receipt_name == proof.tenant
            && receipt_uid == proof.attempt.tenant_uid
            && receipt_namespace == proof.namespace
            && receipt_pools == proof.tenant_pools,
        "admin topology proof does not match its authenticated raw Tenant GET receipt"
    );
    Ok(())
}

fn tenant_pool_proof(
    pool: &Value,
    tenant_name: &str,
    tenant_uid: &str,
    namespace: &str,
    tenant: &Value,
    cluster_domain: &str,
    runtime_pools: &[AdminPool],
) -> Result<TenantPoolProof> {
    let name = required_field_string(pool, "name")?;
    let servers = required_field_u64(pool, "servers")?;
    let volumes_per_server = pool
        .pointer("/persistence/volumesPerServer")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .context("Tenant pool persistence.volumesPerServer must be positive")?;
    let scheme = if tenant
        .pointer("/spec/tls/enableInternodeHttps")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        "https".to_string()
    } else {
        "http".to_string()
    };
    let base_path = pool
        .pointer("/persistence/path")
        .and_then(Value::as_str)
        .unwrap_or(DEFAULT_POOL_DATA_PATH)
        .trim_end_matches('/')
        .to_string();
    ensure!(
        !base_path.is_empty() && base_path.starts_with('/'),
        "Tenant pool {name:?} persistence.path must be an absolute non-root path"
    );
    let (stateful_set_name, expected_endpoint_set) = expected_pool_endpoint_set(
        tenant_name,
        &name,
        namespace,
        &scheme,
        cluster_domain,
        &base_path,
        (servers, volumes_per_server),
    )?;
    let matches = runtime_pools
        .iter()
        .filter(|runtime| runtime.expression.trim() == expected_endpoint_set)
        .collect::<Vec<_>>();
    ensure!(
        matches.len() == 1,
        "Tenant pool {name:?} owned by UID {tenant_uid:?} maps to {} RustFS runtime cmdlines; expected exactly one match for {expected_endpoint_set:?}",
        matches.len()
    );

    Ok(TenantPoolProof {
        name,
        tenant_uid: tenant_uid.to_string(),
        stateful_set_name,
        expected_endpoint_set,
        internode_scheme: scheme,
        cluster_domain: cluster_domain.to_string(),
        data_path: base_path,
        runtime_pool_id: matches[0].id,
        servers,
        volumes_per_server,
    })
}

fn expected_pool_endpoint_set(
    tenant_name: &str,
    pool_name: &str,
    namespace: &str,
    scheme: &str,
    cluster_domain: &str,
    data_path: &str,
    shape: (u64, u64),
) -> Result<(String, String)> {
    ensure!(
        matches!(scheme, "http" | "https")
            && !tenant_name.trim().is_empty()
            && !pool_name.trim().is_empty()
            && !namespace.trim().is_empty()
            && !cluster_domain.trim().is_empty()
            && data_path.starts_with('/')
            && data_path != "/",
        "Tenant pool endpoint identity fields are invalid"
    );
    let last_server = shape
        .0
        .checked_sub(1)
        .context("pool server range underflow")?;
    let last_volume = shape
        .1
        .checked_sub(1)
        .context("pool volume range underflow")?;
    let stateful_set_name = format!("{tenant_name}-{pool_name}");
    let endpoint_set = format!(
        "{scheme}://{stateful_set_name}-{{0...{last_server}}}.{tenant_name}-hl.{namespace}.svc.{cluster_domain}:9000{data_path}/rustfs{{0...{last_volume}}}"
    );
    Ok((stateful_set_name, endpoint_set))
}

fn validate_runtime_pools(
    tenant_pools: &[TenantPoolProof],
    runtime_pools: &[AdminPool],
) -> Result<()> {
    ensure!(
        tenant_pools.len() == 2,
        "admin topology cases require a fresh Tenant with exactly two pools"
    );
    let names = tenant_pools
        .iter()
        .map(|pool| pool.name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        names.len() == tenant_pools.len(),
        "Tenant pool names must be unique"
    );
    let tenant_runtime_ids = tenant_pools
        .iter()
        .map(|pool| pool.runtime_pool_id)
        .collect::<BTreeSet<_>>();
    ensure!(
        tenant_runtime_ids.len() == tenant_pools.len(),
        "Tenant pool runtime IDs must be unique"
    );
    ensure!(
        tenant_pools.iter().all(|pool| {
            !pool.name.trim().is_empty()
                && !pool.tenant_uid.trim().is_empty()
                && !pool.stateful_set_name.trim().is_empty()
                && !pool.expected_endpoint_set.trim().is_empty()
                && matches!(pool.internode_scheme.as_str(), "http" | "https")
                && !pool.cluster_domain.trim().is_empty()
                && !pool.data_path.trim().is_empty()
                && pool.servers > 0
                && pool.volumes_per_server > 0
        }),
        "Tenant pool binding identity or positive server/volume counts are missing"
    );
    ensure!(
        tenant_pools.iter().all(|pool| {
            runtime_pools.iter().any(|runtime| {
                runtime.id == pool.runtime_pool_id
                    && runtime.expression.trim() == pool.expected_endpoint_set
            })
        }),
        "Tenant pool endpoint sets do not bind to exact RustFS runtime cmdlines"
    );
    ensure!(
        runtime_pools.len() == tenant_pools.len(),
        "RustFS runtime pool count {} does not match Tenant pool count {}",
        runtime_pools.len(),
        tenant_pools.len()
    );
    validate_pool_wire_invariants("runtime", runtime_pools)?;
    ensure!(
        runtime_pools.iter().all(pool_is_idle),
        "a pool is unhealthy, another topology operation is active, or a failure is uncleared"
    );
    Ok(())
}

struct TopologyCapacity {
    target_pool_expression: Option<String>,
    target_used_bytes: u64,
    remaining_free_bytes: u64,
    required_remaining_free_bytes: u64,
}

fn topology_capacity(
    target_pool_id: Option<usize>,
    runtime_pools: &[AdminPool],
    workload_max_bytes: u64,
) -> Result<TopologyCapacity> {
    ensure!(
        workload_max_bytes > 0,
        "admin operation must reserve a positive bounded workload budget"
    );
    if let Some(target_id) = target_pool_id {
        let target = runtime_pools
            .iter()
            .find(|pool| pool.id == target_id)
            .with_context(|| format!("target pool ID {target_id} does not exist"))?;
        let remaining_free = runtime_pools
            .iter()
            .filter(|pool| pool.id != target_id)
            .try_fold(0_u64, |total, pool| total.checked_add(pool.current_size))
            .context("remaining pool free capacity overflowed")?;
        ensure!(
            target.used_size > 0,
            "decommission target pool must contain data so the case proves migration"
        );
        let guarded_target_bytes = target
            .used_size
            .checked_mul(RUSTFS_DECOMMISSION_CAPACITY_PERCENT)
            .and_then(|value| value.checked_add(99))
            .map(|value| value / 100)
            .context("decommission capacity guard overflowed")?;
        let required_remaining_free = guarded_target_bytes
            .checked_add(workload_max_bytes)
            .context("decommission workload headroom overflowed")?;
        ensure!(
            remaining_free >= required_remaining_free,
            "remaining pools have {remaining_free} free bytes but RustFS requires at least {required_remaining_free} bytes for target pool {target_id}: {} used bytes at {}% plus {workload_max_bytes} bounded workload bytes",
            target.used_size,
            RUSTFS_DECOMMISSION_CAPACITY_PERCENT
        );
        Ok(TopologyCapacity {
            target_pool_expression: Some(target.expression.clone()),
            target_used_bytes: target.used_size,
            remaining_free_bytes: remaining_free,
            required_remaining_free_bytes: required_remaining_free,
        })
    } else {
        let remaining_free = runtime_pools
            .iter()
            .try_fold(0_u64, |total, pool| total.checked_add(pool.current_size))
            .context("pool free capacity overflowed")?;
        ensure!(
            remaining_free >= workload_max_bytes,
            "runtime pools lack free capacity for the bounded admin workload"
        );
        Ok(TopologyCapacity {
            target_pool_expression: None,
            target_used_bytes: 0,
            remaining_free_bytes: remaining_free,
            required_remaining_free_bytes: workload_max_bytes,
        })
    }
}

fn pool_is_idle(pool: &AdminPool) -> bool {
    let pool_healthy = matches!(
        pool.status.to_ascii_lowercase().as_str(),
        "active" | "ready"
    );
    pool_healthy
        && pool.decommission_status.eq_ignore_ascii_case("none")
        && matches!(
            pool.rebalance_status.to_ascii_lowercase().as_str(),
            "none" | "completed"
        )
        && pool.decommission.is_none()
}

fn pool_is_decommissioned_target(
    pool: &AdminPool,
    operation_id: &str,
    objects_moved: Option<u64>,
    bytes_moved: Option<u64>,
) -> bool {
    pool.status.eq_ignore_ascii_case("decommissioned")
        && pool.decommission_status.eq_ignore_ascii_case("complete")
        && matches!(
            pool.rebalance_status.to_ascii_lowercase().as_str(),
            "none" | "completed"
        )
        && pool.decommission.as_ref().is_some_and(|progress| {
            progress.complete
                && !progress.failed
                && !progress.canceled
                && !progress.queued
                && progress.objects_decommissioned_failed == 0
                && progress.bytes_decommissioned_failed == 0
                && progress.start_time.as_deref().is_some_and(|start_time| {
                    !start_time.trim().is_empty()
                        && operation_id == format!("decommission:{}:{start_time}", pool.id)
                })
                && objects_moved == Some(progress.objects_decommissioned)
                && bytes_moved == Some(progress.bytes_decommissioned)
        })
}

fn validate_pre_start_snapshot(
    proof: &AdminTopologyProof,
    snapshot: &AdminPoolSnapshot,
    operation_requests: &[AdminRequestEvidence],
) -> Result<()> {
    snapshot.validate_list_request()?;
    validate_request_targets(operation_requests, &proof.runtime.target)?;
    ensure!(
        snapshot.attempt == proof.attempt,
        "pre-start pool snapshot does not belong to the current run/case/Tenant attempt"
    );
    ensure!(
        snapshot.runtime == proof.runtime,
        "pre-start topology and destructive request transcript are not bound to the proven RustFS endpoint and deployment"
    );
    ensure!(
        snapshot.tenant_get.namespace == proof.namespace
            && snapshot.tenant_get.name == proof.tenant
            && snapshot.tenant_get.uid == proof.attempt.tenant_uid,
        "pre-start Kubernetes Tenant GET does not match the proven Tenant identity"
    );
    validate_tenant_receipt_against_proof(proof, &snapshot.tenant_get.tenant_receipt()?)?;
    validate_runtime_pools(&proof.tenant_pools, &snapshot.pools)?;
    let capacity = topology_capacity(
        proof.target_pool_id,
        &snapshot.pools,
        proof.workload_max_bytes,
    )?;
    ensure!(
        capacity.target_pool_expression == proof.target_pool_expression,
        "pre-start pool snapshot target identity drifted after preflight"
    );
    let (start_started_at_ms, _, _) =
        validate_start_before_status(operation_requests, &proof.scenario, proof.target_pool_id)?;
    let (start_path, _) = admin_request_paths(&proof.scenario)?;
    let start_runtime_probe = operation_requests
        .iter()
        .find(|request| request.method == "POST" && request.path == start_path)
        .and_then(|request| request.runtime_probe.as_ref())
        .context("admin start request lacks its fresh RustFS runtime probe")?;
    ensure!(
        snapshot.runtime.observed_at_ms < snapshot.tenant_get.started_at_ms
            && snapshot.tenant_get.observed_at_ms < snapshot.request.started_at_ms
            && snapshot.request.observed_at_ms
                < start_runtime_probe.target.endpoint.cluster_started_at_ms
            && start_runtime_probe.observed_at_ms <= start_started_at_ms
            && snapshot.tenant_get.observed_at_ms < start_started_at_ms
            && start_started_at_ms - snapshot.tenant_get.observed_at_ms
                <= ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS
            && start_started_at_ms - snapshot.observed_at_ms <= ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS,
        "pre-start Tenant GET and pools/list intervals are stale, overlapping, or not complete before admin start"
    );
    Ok(())
}

fn validate_post_operation_snapshot(
    proof: &AdminTopologyProof,
    snapshot: &AdminPoolSnapshot,
    operation_requests: &[AdminRequestEvidence],
) -> Result<()> {
    snapshot.validate_list_request()?;
    proof
        .runtime
        .target
        .require_same_runtime_identity(&snapshot.runtime.target)?;
    validate_request_targets(operation_requests, &proof.runtime.target)?;
    ensure!(
        snapshot.attempt == proof.attempt,
        "post-operation pool snapshot does not belong to the current run/case/Tenant attempt"
    );
    ensure!(
        snapshot.tenant_get.namespace == proof.namespace
            && snapshot.tenant_get.name == proof.tenant
            && snapshot.tenant_get.uid == proof.attempt.tenant_uid,
        "post-operation Kubernetes Tenant GET does not match the proven Tenant identity"
    );
    validate_tenant_receipt_against_proof(proof, &snapshot.tenant_get.tenant_receipt()?)?;
    validate_pool_wire_invariants("after", &snapshot.pools)?;
    let (_, _, terminal_status_observed_at_ms) =
        validate_start_before_status(operation_requests, &proof.scenario, proof.target_pool_id)?;
    ensure!(
        terminal_status_observed_at_ms < snapshot.runtime.target.endpoint.cluster_started_at_ms
            && snapshot.runtime.target.endpoint.tenant_observed_at_ms
                <= snapshot.runtime.started_at_ms
            && snapshot.runtime.observed_at_ms < snapshot.tenant_get.started_at_ms
            && snapshot.tenant_get.observed_at_ms < snapshot.request.started_at_ms
            && snapshot.observed_at_ms >= snapshot.request.started_at_ms,
        "post-operation Tenant GET and pools/list were not observed in order after terminal status"
    );
    Ok(())
}

fn required_string(value: &Value, pointer: &str) -> Result<String> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .with_context(|| format!("{pointer} must be a non-empty string"))
}

fn required_field_string(value: &Value, field: &str) -> Result<String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .with_context(|| format!("Tenant pool {field} must be a non-empty string"))
}

fn required_field_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .with_context(|| format!("Tenant pool {field} must be a positive integer"))
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminOperationEvidence {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub scenario: String,
    pub operation_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_id: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_pool_expression: Option<String>,
    pub terminal_state: String,
    pub completed: bool,
    pub failed: bool,
    pub canceled_or_stopped: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub participating_pool_ids: Vec<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects_moved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions_moved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_moved: Option<u64>,
    pub requests: Vec<AdminRequestEvidence>,
    pub pools_before: AdminPoolSnapshot,
    pub pools_after: AdminPoolSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminOperationProgressSample {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub operation_id: String,
    pub status_request_id: String,
    pub observed_at_ms: u64,
    pub state: String,
    pub completed: bool,
    pub failed: bool,
    pub canceled_or_stopped: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub objects_moved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions_moved: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_moved: Option<u64>,
}

impl AdminOperationEvidence {
    pub fn from_decommission(
        proof: &AdminTopologyProof,
        pools_before: AdminPoolSnapshot,
        status: DecommissionPoolStatus,
        requests: Vec<AdminRequestEvidence>,
        pools_after: AdminPoolSnapshot,
    ) -> Result<Self> {
        proof.require_satisfied()?;
        validate_pre_start_snapshot(proof, &pools_before, &requests)?;
        validate_post_operation_snapshot(proof, &pools_after, &requests)?;
        let target_pool_id = proof
            .target_pool_id
            .context("decommission topology proof has no target pool ID")?;
        let target_pool_expression = proof
            .target_pool_expression
            .clone()
            .context("decommission topology proof has no target expression")?;
        ensure!(
            status.id == target_pool_id && status.expression == target_pool_expression,
            "decommission status does not match the proven target pool"
        );
        let progress = status
            .decommission
            .as_ref()
            .context("decommission status is missing operation progress")?;
        let start_time = progress
            .start_time
            .as_deref()
            .filter(|value| !value.trim().is_empty())
            .context("decommission status is missing operation start time")?;
        let state = status.status.to_ascii_lowercase();
        let failed = progress.failed
            || progress.objects_decommissioned_failed > 0
            || progress.bytes_decommissioned_failed > 0
            || state == "failed";
        let canceled = progress.canceled || state == "canceled";
        let completed = status.pool_status.eq_ignore_ascii_case("decommissioned")
            && progress.complete
            && !progress.queued
            && !failed
            && !canceled
            && (progress.objects_decommissioned > 0 || progress.bytes_decommissioned > 0);
        let terminal_control_requested = requests.iter().any(is_cancel_or_stop_request);
        Ok(Self {
            attempt: proof.attempt.clone(),
            scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
            operation_id: format!("decommission:{target_pool_id}:{start_time}"),
            target_pool_id: Some(target_pool_id),
            target_pool_expression: Some(target_pool_expression),
            terminal_state: state.clone(),
            completed,
            failed,
            canceled_or_stopped: canceled || terminal_control_requested,
            participating_pool_ids: vec![target_pool_id],
            objects_moved: Some(progress.objects_decommissioned),
            versions_moved: None,
            bytes_moved: Some(progress.bytes_decommissioned),
            requests,
            pools_before,
            pools_after,
        })
    }

    pub fn from_rebalance(
        proof: &AdminTopologyProof,
        pools_before: AdminPoolSnapshot,
        start: &RebalanceStart,
        status: RebalanceStatus,
        requests: Vec<AdminRequestEvidence>,
        pools_after: AdminPoolSnapshot,
    ) -> Result<Self> {
        proof.require_satisfied()?;
        validate_pre_start_snapshot(proof, &pools_before, &requests)?;
        validate_post_operation_snapshot(proof, &pools_after, &requests)?;
        ensure!(
            !start.id.trim().is_empty() && status.id == start.id,
            "rebalance status operation ID does not match the start response"
        );
        ensure!(
            status.pools.len() == proof.runtime_pools.len(),
            "rebalance status raw pool count does not match the proven topology"
        );
        let status_pool_ids = status
            .pools
            .iter()
            .map(|pool| pool.id)
            .collect::<BTreeSet<_>>();
        ensure!(
            status_pool_ids.len() == status.pools.len()
                && proof
                    .runtime_pools
                    .iter()
                    .all(|pool| status_pool_ids.contains(&pool.id)),
            "rebalance status does not cover every proven runtime pool exactly once"
        );
        let stopped = status.stopped_at.is_some()
            || status
                .pools
                .iter()
                .any(|pool| pool.stopping || pool.status.eq_ignore_ascii_case("stopped"))
            || status.stop_propagation.pending_terminal_reload
            || requests.iter().any(is_cancel_or_stop_request);
        let failed = status.pools.iter().any(|pool| {
            pool.last_error
                .as_deref()
                .is_some_and(|error| !error.is_empty())
                || pool.cleanup_warnings.count > 0
                || pool
                    .cleanup_warnings
                    .last_message
                    .as_deref()
                    .is_some_and(|warning| !warning.is_empty())
                || matches!(
                    pool.status.to_ascii_lowercase().as_str(),
                    "failed" | "blocked"
                )
        }) || !status.stop_propagation.failed_peers.is_empty()
            || !status
                .stop_propagation
                .terminal_reload_failed_peers
                .is_empty();
        let participating = status
            .pools
            .iter()
            .filter(|pool| pool.progress.is_some())
            .collect::<Vec<_>>();
        let participating_pool_ids = participating.iter().map(|pool| pool.id).collect::<Vec<_>>();
        let (objects_moved, versions_moved, bytes_moved) = participating.iter().try_fold(
            (0_u64, 0_u64, 0_u64),
            |(objects, versions, bytes), pool| {
                let progress = pool.progress.as_ref().expect("participants have progress");
                Ok::<_, anyhow::Error>((
                    objects
                        .checked_add(progress.objects)
                        .context("rebalance object progress overflowed")?,
                    versions
                        .checked_add(progress.versions)
                        .context("rebalance version progress overflowed")?,
                    bytes
                        .checked_add(progress.bytes)
                        .context("rebalance byte progress overflowed")?,
                ))
            },
        )?;
        let moved = objects_moved > 0 || versions_moved > 0 || bytes_moved > 0;
        let participants_completed = !participating.is_empty()
            && participating
                .iter()
                .all(|pool| pool.status.eq_ignore_ascii_case("completed"));
        let nonparticipants_terminal = status
            .pools
            .iter()
            .filter(|pool| pool.progress.is_none())
            .all(|pool| {
                matches!(
                    pool.status.to_ascii_lowercase().as_str(),
                    "none" | "completed"
                )
            });
        let completed =
            moved && participants_completed && nonparticipants_terminal && !failed && !stopped;
        let terminal_state = if failed {
            "failed"
        } else if stopped {
            "stopped"
        } else if completed {
            "completed"
        } else {
            "incomplete"
        };
        Ok(Self {
            attempt: proof.attempt.clone(),
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            operation_id: start.id.clone(),
            target_pool_id: None,
            target_pool_expression: None,
            terminal_state: terminal_state.to_string(),
            completed,
            failed,
            canceled_or_stopped: stopped,
            participating_pool_ids,
            objects_moved: Some(objects_moved),
            versions_moved: Some(versions_moved),
            bytes_moved: Some(bytes_moved),
            requests,
            pools_before,
            pools_after,
        })
    }

    pub fn require_success(&self, attempt_window: AdminAttemptWindow) -> Result<()> {
        attempt_window.validate()?;
        validate_attempt_identity(&self.attempt)?;
        ensure!(
            self.attempt.case_name == expected_case_name(&self.scenario)?,
            "admin operation caseName does not match its scenario"
        );
        ensure!(
            !self.operation_id.trim().is_empty(),
            "admin operation identity is missing"
        );
        ensure!(self.completed, "admin operation did not complete");
        let expected_terminal_state = match self.scenario.as_str() {
            ADMIN_DECOMMISSION_SCENARIO => "complete",
            ADMIN_REBALANCE_SCENARIO => "completed",
            other => bail!("unsupported admin operation scenario {other:?}"),
        };
        ensure!(
            self.terminal_state
                .eq_ignore_ascii_case(expected_terminal_state),
            "admin operation terminal state is not complete"
        );
        ensure!(!self.failed, "admin operation reached a failed state");
        ensure!(
            !self.canceled_or_stopped,
            "canceled/stopped admin operation cannot pass"
        );
        ensure!(
            !self.requests.iter().any(is_cancel_or_stop_request),
            "admin operation transcript contains a cancel/stop request"
        );
        ensure!(
            self.requests
                .iter()
                .all(|request| (200..300).contains(&request.status)),
            "admin operation evidence contains a failed HTTP request"
        );
        self.pools_before
            .runtime
            .target
            .require_same_runtime_identity(&self.pools_after.runtime.target)?;
        validate_request_targets(&self.requests, &self.pools_before.runtime.target)?;
        validate_request_timing(&self.requests, attempt_window)?;
        let (start_started_at_ms, _, terminal_status_observed_at_ms) =
            validate_start_before_status(&self.requests, &self.scenario, self.target_pool_id)?;
        self.validate_terminal_status_response()?;
        self.pools_before.validate_list_request()?;
        validate_request_timing(
            std::slice::from_ref(&self.pools_before.request),
            attempt_window,
        )?;
        ensure!(
            self.pools_before.attempt == self.attempt
                && attempt_window.contains(self.pools_before.runtime.started_at_ms)
                && attempt_window.contains(self.pools_before.runtime.observed_at_ms)
                && attempt_window.contains(self.pools_before.tenant_get.started_at_ms)
                && attempt_window.contains(self.pools_before.tenant_get.observed_at_ms)
                && attempt_window.contains(self.pools_before.request.started_at_ms)
                && attempt_window.contains(self.pools_before.request.observed_at_ms)
                && self.pools_before.runtime.observed_at_ms
                    < self.pools_before.tenant_get.started_at_ms
                && self.pools_before.tenant_get.observed_at_ms
                    < self.pools_before.request.started_at_ms
                && self.pools_before.request.observed_at_ms < start_started_at_ms
                && start_started_at_ms - self.pools_before.tenant_get.observed_at_ms
                    <= ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS
                && attempt_window.contains(self.pools_before.observed_at_ms)
                && start_started_at_ms - self.pools_before.observed_at_ms
                    <= ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS,
            "pre-start Tenant/pool snapshot identity or observation time is invalid"
        );
        validate_pool_wire_invariants("before", &self.pools_before.pools)?;
        self.pools_after.validate_list_request()?;
        validate_request_timing(
            std::slice::from_ref(&self.pools_after.request),
            attempt_window,
        )?;
        ensure!(
            self.pools_after.attempt == self.attempt
                && self
                    .pools_after
                    .runtime
                    .target
                    .endpoint
                    .capture_within(attempt_window)
                && attempt_window.contains(self.pools_after.runtime.started_at_ms)
                && attempt_window.contains(self.pools_after.runtime.observed_at_ms)
                && attempt_window.contains(self.pools_after.tenant_get.started_at_ms)
                && attempt_window.contains(self.pools_after.tenant_get.observed_at_ms)
                && attempt_window.contains(self.pools_after.request.started_at_ms)
                && attempt_window.contains(self.pools_after.request.observed_at_ms)
                && attempt_window.contains(self.pools_after.observed_at_ms)
                && terminal_status_observed_at_ms
                    < self
                        .pools_after
                        .runtime
                        .target
                        .endpoint
                        .cluster_started_at_ms
                && self.pools_after.runtime.observed_at_ms
                    < self.pools_after.tenant_get.started_at_ms
                && self.pools_after.tenant_get.observed_at_ms
                    < self.pools_after.request.started_at_ms,
            "post-operation pool snapshot identity or observation time is invalid"
        );
        validate_pool_wire_invariants("after", &self.pools_after.pools)?;
        if self.scenario == ADMIN_DECOMMISSION_SCENARIO {
            let target_id = self
                .target_pool_id
                .context("decommission target ID is missing")?;
            let expression = self
                .target_pool_expression
                .as_deref()
                .filter(|value| !value.is_empty())
                .context("decommission target expression is missing")?;
            let target_id_string = target_id.to_string();
            ensure!(
                self.participating_pool_ids == [target_id]
                    && self.versions_moved.is_none()
                    && (self.objects_moved.is_some_and(|value| value > 0)
                        || self.bytes_moved.is_some_and(|value| value > 0)),
                "decommission evidence lacks the exact target participant or positive movement"
            );
            ensure!(
                self.requests.iter().any(|request| {
                    request.method == "POST"
                        && request.path == format!("{ADMIN_PREFIX}/pools/decommission")
                        && request.query.len() == 2
                        && request.query.get("pool") == Some(&target_id_string)
                        && request
                            .query
                            .get("by-id")
                            .is_some_and(|value| value == "true")
                }) && self.requests.iter().any(|request| {
                    request.method == "GET"
                        && request.path == format!("{ADMIN_PREFIX}/decommission/status")
                        && request.query.len() == 2
                        && request.query.get("pool") == Some(&target_id_string)
                        && request
                            .query
                            .get("by-id")
                            .is_some_and(|value| value == "true")
                }),
                "decommission evidence must contain exact start and status requests for the proven pool ID"
            );
            ensure!(
                self.pools_before
                    .pools
                    .iter()
                    .any(|pool| pool.id == target_id && pool.expression == expression),
                "decommission target was not present in the before topology"
            );
            ensure!(
                self.pools_after
                    .pools
                    .iter()
                    .all(|pool| pool.id != target_id)
                    || self.pools_after.pools.iter().any(|pool| {
                        pool.id == target_id
                            && pool.expression == expression
                            && pool_is_decommissioned_target(
                                pool,
                                &self.operation_id,
                                self.objects_moved,
                                self.bytes_moved,
                            )
                    }),
                "decommission target remains active after the claimed completion"
            );
            ensure!(
                self.pools_after.pools.iter().all(|after| {
                    self.pools_before.pools.iter().any(|before| {
                        before.id == after.id && before.expression == after.expression
                    })
                }) && self
                    .pools_before
                    .pools
                    .iter()
                    .filter(|before| before.id != target_id)
                    .all(|before| {
                        self.pools_after.pools.iter().any(|after| {
                            after.id == before.id && after.expression == before.expression
                        })
                    }),
                "decommission changed a non-target pool identity or introduced a new pool"
            );
            ensure!(
                self.pools_after
                    .pools
                    .iter()
                    .filter(|pool| pool.id != target_id)
                    .all(pool_is_idle),
                "a surviving non-target pool is not healthy and idle after decommission"
            );
        } else if self.scenario == ADMIN_REBALANCE_SCENARIO {
            ensure!(
                self.target_pool_id.is_none() && self.target_pool_expression.is_none(),
                "rebalance evidence must not claim a single target pool"
            );
            ensure!(
                !self.participating_pool_ids.is_empty()
                    && (self.objects_moved.is_some_and(|value| value > 0)
                        || self.versions_moved.is_some_and(|value| value > 0)
                        || self.bytes_moved.is_some_and(|value| value > 0)),
                "rebalance evidence lacks a participating pool or positive movement signal"
            );
            let participating_ids = self
                .participating_pool_ids
                .iter()
                .copied()
                .collect::<BTreeSet<_>>();
            ensure!(
                participating_ids.len() == self.participating_pool_ids.len()
                    && participating_ids
                        .iter()
                        .all(|id| { self.pools_before.pools.iter().any(|pool| pool.id == *id) }),
                "rebalance participating pool IDs are duplicated or outside the proven topology"
            );
            ensure!(
                self.requests.iter().any(|request| {
                    request.method == "POST"
                        && request.path == format!("{ADMIN_PREFIX}/rebalance/start")
                        && request.query.is_empty()
                }) && self.requests.iter().any(|request| {
                    request.method == "GET"
                        && request.path == format!("{ADMIN_PREFIX}/rebalance/status")
                        && request.query.is_empty()
                }),
                "rebalance evidence must contain start and status requests"
            );
            ensure!(
                self.pools_before.pools.len() == self.pools_after.pools.len()
                    && self.pools_before.pools.iter().all(|before| {
                        self.pools_after.pools.iter().any(|after| {
                            after.id == before.id && after.expression == before.expression
                        })
                    }),
                "rebalance changed pool identity or topology scope"
            );
            ensure!(
                self.pools_after.pools.iter().all(pool_is_idle),
                "a pool is not healthy and idle after rebalance"
            );
        } else {
            bail!("unsupported admin operation scenario {:?}", self.scenario);
        }
        Ok(())
    }

    fn validate_terminal_status_response(&self) -> Result<()> {
        let (_, status_path) = admin_request_paths(&self.scenario)?;
        let terminal_request = self
            .requests
            .iter()
            .rev()
            .find(|request| request.method == "GET" && request.path == status_path)
            .context("admin operation lacks a terminal status response")?;
        match self.scenario.as_str() {
            ADMIN_DECOMMISSION_SCENARIO => {
                let status = parse_captured_json_response::<DecommissionPoolStatus>(
                    terminal_request,
                    "RustFS decommission status response",
                )?;
                let target_pool_id = self
                    .target_pool_id
                    .context("decommission terminal response lacks a target pool")?;
                let expression = self
                    .target_pool_expression
                    .as_deref()
                    .context("decommission terminal response lacks a target expression")?;
                let projection = project_decommission_status(
                    &status,
                    target_pool_id,
                    expression,
                    &self.operation_id,
                )?;
                ensure!(
                    self.terminal_state.eq_ignore_ascii_case(&projection.state)
                        && self.completed == projection.completed
                        && self.failed == projection.failed
                        && self.canceled_or_stopped == projection.canceled
                        && self.participating_pool_ids == [target_pool_id]
                        && self.objects_moved == Some(projection.objects_moved)
                        && self.versions_moved.is_none()
                        && self.bytes_moved == Some(projection.bytes_moved),
                    "decommission operation fields are not derived from the terminal RustFS status response"
                );
            }
            ADMIN_REBALANCE_SCENARIO => {
                let start_request = self
                    .requests
                    .iter()
                    .find(|request| {
                        request.method == "POST"
                            && request.path == "/rustfs/admin/v3/rebalance/start"
                    })
                    .context("rebalance operation lacks its start response")?;
                let start = parse_captured_json_response::<RebalanceStart>(
                    start_request,
                    "RustFS rebalance start response",
                )?;
                ensure!(
                    start.id == self.operation_id,
                    "rebalance operation ID does not match the captured RustFS start response"
                );
                let status = parse_captured_json_response::<RebalanceStatus>(
                    terminal_request,
                    "RustFS rebalance status response",
                )?;
                let projection = project_rebalance_status(
                    &status,
                    &self.pools_before.pools,
                    self.requests.iter().any(is_cancel_or_stop_request),
                )?;
                ensure!(
                    status.id == self.operation_id
                        && self.terminal_state.eq_ignore_ascii_case(projection.state)
                        && self.completed == projection.completed
                        && self.failed == projection.failed
                        && self.canceled_or_stopped == projection.stopped
                        && self.participating_pool_ids == projection.participating_pool_ids
                        && self.objects_moved == Some(projection.objects_moved)
                        && self.versions_moved == Some(projection.versions_moved)
                        && self.bytes_moved == Some(projection.bytes_moved),
                    "rebalance operation fields are not derived from the terminal RustFS status response"
                );
            }
            other => bail!("unsupported admin operation scenario {other:?}"),
        }
        Ok(())
    }
}

#[derive(Debug)]
struct DecommissionStatusProjection {
    state: String,
    completed: bool,
    failed: bool,
    canceled: bool,
    objects_moved: u64,
    bytes_moved: u64,
}

fn project_decommission_status(
    status: &DecommissionPoolStatus,
    target_pool_id: usize,
    target_pool_expression: &str,
    operation_id: &str,
) -> Result<DecommissionStatusProjection> {
    ensure!(
        status.id == target_pool_id && status.expression == target_pool_expression,
        "decommission status response does not match the proven target"
    );
    let progress = status
        .decommission
        .as_ref()
        .context("decommission status response lacks operation progress")?;
    let state = status.status.to_ascii_lowercase();
    ensure!(
        matches!(
            state.as_str(),
            "queued" | "running" | "complete" | "failed" | "canceled"
        ),
        "decommission status response has unknown state {:?}",
        status.status
    );
    let start_time = progress
        .start_time
        .as_deref()
        .filter(|value| !value.trim().is_empty());
    if state == "queued" {
        if let Some(start_time) = start_time {
            ensure!(
                operation_id == format!("decommission:{target_pool_id}:{start_time}"),
                "queued decommission status response belongs to a different operation"
            );
        }
    } else {
        let start_time = start_time.context(
            "running or terminal decommission status response lacks operation start time",
        )?;
        ensure!(
            operation_id == format!("decommission:{target_pool_id}:{start_time}"),
            "decommission status response belongs to a different operation"
        );
    }
    let failed = progress.failed
        || progress.objects_decommissioned_failed > 0
        || progress.bytes_decommissioned_failed > 0
        || state == "failed";
    let canceled = progress.canceled || state == "canceled";
    match state.as_str() {
        "queued" => ensure!(
            progress.queued && !progress.complete && !failed && !canceled,
            "queued decommission status response has contradictory flags"
        ),
        "running" => ensure!(
            !progress.queued && !progress.complete && !failed && !canceled,
            "running decommission status response has contradictory flags"
        ),
        "complete" => ensure!(
            !progress.queued && progress.complete && !failed && !canceled,
            "terminal decommission status response has failure, cancellation, queue, or failed-fragment evidence"
        ),
        "failed" | "canceled" => {}
        _ => unreachable!("state allowlist checked above"),
    }
    let completed = state == "complete"
        && status.pool_status.eq_ignore_ascii_case("decommissioned")
        && progress.complete
        && !progress.queued
        && !failed
        && !canceled
        && (progress.objects_decommissioned > 0 || progress.bytes_decommissioned > 0);
    Ok(DecommissionStatusProjection {
        state,
        completed,
        failed,
        canceled,
        objects_moved: progress.objects_decommissioned,
        bytes_moved: progress.bytes_decommissioned,
    })
}

#[derive(Debug)]
struct RebalanceStatusProjection {
    state: &'static str,
    completed: bool,
    failed: bool,
    stopped: bool,
    participating_pool_ids: Vec<usize>,
    objects_moved: u64,
    versions_moved: u64,
    bytes_moved: u64,
}

fn project_rebalance_status(
    status: &RebalanceStatus,
    runtime_pools: &[AdminPool],
    terminal_control_requested: bool,
) -> Result<RebalanceStatusProjection> {
    ensure!(
        status.pools.len() == runtime_pools.len(),
        "rebalance status raw pool count does not match the proven topology"
    );
    let status_pool_ids = status
        .pools
        .iter()
        .map(|pool| pool.id)
        .collect::<BTreeSet<_>>();
    ensure!(
        status_pool_ids.len() == status.pools.len()
            && runtime_pools
                .iter()
                .all(|pool| status_pool_ids.contains(&pool.id)),
        "rebalance status does not cover every proven runtime pool exactly once"
    );
    ensure!(
        status.pools.iter().all(|pool| matches!(
            pool.status.to_ascii_lowercase().as_str(),
            "none" | "started" | "stopping" | "stopped" | "completed" | "failed" | "blocked"
        )),
        "rebalance status response contains an unknown pool state"
    );
    let stopped = status.stopped_at.is_some()
        || status
            .pools
            .iter()
            .any(|pool| pool.stopping || pool.status.eq_ignore_ascii_case("stopped"))
        || status.stop_propagation.pending_terminal_reload
        || terminal_control_requested;
    let failed = status.pools.iter().any(|pool| {
        pool.last_error
            .as_deref()
            .is_some_and(|error| !error.is_empty())
            || pool.cleanup_warnings.count > 0
            || pool
                .cleanup_warnings
                .last_message
                .as_deref()
                .is_some_and(|warning| !warning.is_empty())
            || matches!(
                pool.status.to_ascii_lowercase().as_str(),
                "failed" | "blocked"
            )
    }) || !status.stop_propagation.failed_peers.is_empty()
        || !status
            .stop_propagation
            .terminal_reload_failed_peers
            .is_empty();
    let participating = status
        .pools
        .iter()
        .filter(|pool| pool.progress.is_some())
        .collect::<Vec<_>>();
    let participating_pool_ids = participating.iter().map(|pool| pool.id).collect::<Vec<_>>();
    let (objects_moved, versions_moved, bytes_moved) = participating.iter().try_fold(
        (0_u64, 0_u64, 0_u64),
        |(objects, versions, bytes), pool| {
            let progress = pool.progress.as_ref().expect("participants have progress");
            Ok::<_, anyhow::Error>((
                objects
                    .checked_add(progress.objects)
                    .context("rebalance object progress overflowed")?,
                versions
                    .checked_add(progress.versions)
                    .context("rebalance version progress overflowed")?,
                bytes
                    .checked_add(progress.bytes)
                    .context("rebalance byte progress overflowed")?,
            ))
        },
    )?;
    let moved = objects_moved > 0 || versions_moved > 0 || bytes_moved > 0;
    let participants_completed = !participating.is_empty()
        && participating
            .iter()
            .all(|pool| pool.status.eq_ignore_ascii_case("completed"));
    let nonparticipants_terminal = status
        .pools
        .iter()
        .filter(|pool| pool.progress.is_none())
        .all(|pool| {
            matches!(
                pool.status.to_ascii_lowercase().as_str(),
                "none" | "completed"
            )
        });
    let completed =
        moved && participants_completed && nonparticipants_terminal && !failed && !stopped;
    let state = if failed {
        "failed"
    } else if stopped {
        "stopped"
    } else if completed {
        "completed"
    } else {
        "started"
    };
    Ok(RebalanceStatusProjection {
        state,
        completed,
        failed,
        stopped,
        participating_pool_ids,
        objects_moved,
        versions_moved,
        bytes_moved,
    })
}

fn parse_captured_json_response<T: for<'de> Deserialize<'de>>(
    request: &AdminRequestEvidence,
    label: &str,
) -> Result<T> {
    let response_body = request
        .response_body
        .as_deref()
        .with_context(|| format!("{label} body is missing"))?;
    let response_sha256 = request
        .response_sha256
        .as_deref()
        .with_context(|| format!("{label} digest is missing"))?;
    ensure!(
        response_sha256 == sha256_hex(response_body.as_bytes()),
        "{label} digest does not match its captured body"
    );
    serde_json::from_str(response_body).with_context(|| format!("decode captured {label}"))
}

fn validate_request_timing(
    requests: &[AdminRequestEvidence],
    attempt_window: AdminAttemptWindow,
) -> Result<()> {
    ensure!(
        !requests.is_empty(),
        "admin operation request transcript is empty"
    );
    for request in requests {
        request.validate()?;
        ensure!(
            attempt_window.contains(request.started_at_ms)
                && attempt_window.contains(request.observed_at_ms)
                && request.target.endpoint.capture_within(attempt_window)
                && request.runtime_probe.as_ref().is_none_or(|probe| {
                    attempt_window.contains(probe.started_at_ms)
                        && attempt_window.contains(probe.observed_at_ms)
                        && attempt_window.contains(probe.target.endpoint.cluster_started_at_ms)
                        && attempt_window.contains(probe.target.endpoint.cluster_observed_at_ms)
                        && attempt_window.contains(probe.target.endpoint.service_started_at_ms)
                        && attempt_window.contains(probe.target.endpoint.service_observed_at_ms)
                        && attempt_window.contains(probe.target.endpoint.tenant_started_at_ms)
                        && attempt_window.contains(probe.target.endpoint.tenant_observed_at_ms)
                }),
            "admin request or runtime-probe interval falls outside the current attempt window"
        );
    }
    ensure!(
        requests
            .windows(2)
            .all(|pair| pair[0].observed_at_ms < pair[1].target.endpoint.cluster_started_at_ms),
        "admin request and runtime-probe transcript intervals overlap or are not ordered"
    );
    Ok(())
}

fn validate_request_targets(
    requests: &[AdminRequestEvidence],
    expected: &AdminRequestTarget,
) -> Result<()> {
    for request in requests {
        expected.require_same_runtime_identity(&request.target)?;
    }
    Ok(())
}

fn validate_start_before_status(
    requests: &[AdminRequestEvidence],
    scenario: &str,
    target_pool_id: Option<usize>,
) -> Result<(u64, u64, u64)> {
    let (start_path, status_path) = admin_request_paths(scenario)?;
    validate_operation_request_allowlist(requests, scenario, target_pool_id)?;
    let exact_query = |request: &AdminRequestEvidence| {
        has_exact_operation_query(request, scenario, target_pool_id)
    };
    ensure!(
        requests
            .iter()
            .filter(|request| request.path == start_path || request.path == status_path)
            .all(|request| {
                ((request.path == start_path && request.method == "POST")
                    || (request.path == status_path && request.method == "GET"))
                    && exact_query(request)
            }),
        "admin start/status transcript contains a request for the wrong operation target"
    );
    let starts = requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.method == "POST" && request.path == start_path)
        .collect::<Vec<_>>();
    let [(start_index, start)] = starts.as_slice() else {
        bail!("admin operation must contain exactly one start request")
    };
    let statuses = requests
        .iter()
        .enumerate()
        .filter(|(_, request)| request.method == "GET" && request.path == status_path)
        .collect::<Vec<_>>();
    ensure!(
        !statuses.is_empty()
            && statuses.iter().all(|(status_index, status)| {
                status_index > start_index && status.started_at_ms >= start.observed_at_ms
            }),
        "admin status requests must follow the start request"
    );
    let last_status = statuses
        .last()
        .map(|(_, request)| *request)
        .expect("non-empty checked above");
    Ok((
        start.started_at_ms,
        start.observed_at_ms,
        last_status.observed_at_ms,
    ))
}

fn validate_operation_request_allowlist(
    requests: &[AdminRequestEvidence],
    scenario: &str,
    target_pool_id: Option<usize>,
) -> Result<()> {
    let (start_path, status_path) = admin_request_paths(scenario)?;
    ensure!(
        requests.iter().all(|request| {
            let is_start = request.method == "POST" && request.path == start_path;
            let is_status = request.method == "GET" && request.path == status_path;
            let is_rollback = request.method == "POST"
                && match scenario {
                    ADMIN_DECOMMISSION_SCENARIO => request.path == "/rustfs/admin/v3/pools/cancel",
                    ADMIN_REBALANCE_SCENARIO => request.path == "/rustfs/admin/v3/rebalance/stop",
                    _ => false,
                };
            (is_start || is_status || is_rollback)
                && has_exact_operation_query(request, scenario, target_pool_id)
        }),
        "admin operation transcript contains an unknown, cross-scenario, or non-allowlisted mutation request"
    );
    Ok(())
}

fn has_exact_operation_query(
    request: &AdminRequestEvidence,
    scenario: &str,
    target_pool_id: Option<usize>,
) -> bool {
    match scenario {
        ADMIN_DECOMMISSION_SCENARIO => target_pool_id.is_some_and(|target_pool_id| {
            request.query.len() == 2
                && request.query.get("pool") == Some(&target_pool_id.to_string())
                && request
                    .query
                    .get("by-id")
                    .is_some_and(|value| value == "true")
        }),
        ADMIN_REBALANCE_SCENARIO => request.query.is_empty(),
        _ => false,
    }
}

fn admin_request_paths(scenario: &str) -> Result<(&'static str, &'static str)> {
    match scenario {
        ADMIN_DECOMMISSION_SCENARIO => Ok((
            "/rustfs/admin/v3/pools/decommission",
            "/rustfs/admin/v3/decommission/status",
        )),
        ADMIN_REBALANCE_SCENARIO => Ok((
            "/rustfs/admin/v3/rebalance/start",
            "/rustfs/admin/v3/rebalance/status",
        )),
        other => bail!("unsupported admin operation scenario {other:?}"),
    }
}

fn is_cancel_or_stop_request(request: &AdminRequestEvidence) -> bool {
    request.method == "POST"
        && matches!(
            request.path.as_str(),
            "/rustfs/admin/v3/pools/cancel" | "/rustfs/admin/v3/rebalance/stop"
        )
}

fn validate_pool_wire_invariants(label: &str, pools: &[AdminPool]) -> Result<()> {
    ensure!(!pools.is_empty(), "admin {label} pool snapshot is empty");
    let ids = pools.iter().map(|pool| pool.id).collect::<BTreeSet<_>>();
    let expressions = pools
        .iter()
        .map(|pool| pool.expression.trim())
        .collect::<BTreeSet<_>>();
    ensure!(
        ids.len() == pools.len()
            && expressions.len() == pools.len()
            && expressions.iter().all(|expression| !expression.is_empty()),
        "admin {label} pool snapshot contains duplicate or empty identities"
    );
    ensure!(
        pools.iter().all(|pool| {
            if pool.total_size == 0 {
                return false;
            }
            let expected_used = pool.used_size as f64 / pool.total_size as f64;
            pool.current_size
                .checked_add(pool.used_size)
                .is_some_and(|total| total == pool.total_size)
                && pool.used.is_finite()
                && (0.0..=1.0).contains(&pool.used)
                && (pool.used - expected_used).abs() <= POOL_USED_RATIO_TOLERANCE
        }),
        "admin {label} pool snapshot contains inconsistent total/free/used capacity or used ratio"
    );
    Ok(())
}

pub fn validate_admin_operation_progress(
    operation: &AdminOperationEvidence,
    samples: &[AdminOperationProgressSample],
    attempt_window: AdminAttemptWindow,
) -> Result<()> {
    attempt_window.validate()?;
    ensure!(!samples.is_empty(), "admin operation progress is empty");
    validate_request_timing(&operation.requests, attempt_window)?;
    let (_, start_observed_at_ms, terminal_status_observed_at_ms) = validate_start_before_status(
        &operation.requests,
        &operation.scenario,
        operation.target_pool_id,
    )?;
    let (_, status_path) = admin_request_paths(&operation.scenario)?;
    let status_requests = operation
        .requests
        .iter()
        .filter(|request| request.method == "GET" && request.path == status_path)
        .collect::<Vec<_>>();
    let status_request_ids = status_requests
        .iter()
        .map(|request| {
            request
                .request_id
                .as_deref()
                .filter(|request_id| !request_id.trim().is_empty())
                .context("admin status request lacks a response request ID")
        })
        .collect::<Result<BTreeSet<_>>>()?;
    ensure!(
        status_request_ids.len() == status_requests.len(),
        "admin status requests must have unique response request IDs"
    );
    ensure!(
        samples.iter().all(|sample| {
            sample.operation_id == operation.operation_id && sample.attempt == operation.attempt
        }),
        "admin operation progress identity differs from the operation attempt"
    );
    ensure!(
        samples.iter().all(|sample| {
            attempt_window.contains(sample.observed_at_ms)
                && sample.observed_at_ms >= start_observed_at_ms
        }),
        "admin operation progress falls outside the current operation/attempt window"
    );
    let states = samples
        .iter()
        .map(|sample| parse_progress_state(&operation.scenario, sample))
        .collect::<Result<Vec<_>>>()?;
    let mut used_status_request_ids = BTreeSet::new();
    for (index, (sample, state)) in samples.iter().zip(&states).enumerate() {
        let source = status_requests
            .get(index)
            .context("admin progress sample count exceeds the status GET response set")?;
        ensure!(
            !sample.status_request_id.trim().is_empty()
                && used_status_request_ids.insert(sample.status_request_id.as_str()),
            "admin progress sample lacks a unique status request ID"
        );
        let matches = status_requests
            .iter()
            .filter(|request| {
                request.request_id.as_deref() == Some(sample.status_request_id.as_str())
                    && (200..300).contains(&request.status)
                    && request.observed_at_ms == sample.observed_at_ms
            })
            .count();
        ensure!(
            matches == 1
                && source.request_id.as_deref() == Some(sample.status_request_id.as_str())
                && source.observed_at_ms == sample.observed_at_ms,
            "admin progress sample is not sequence-bound to one successful status GET response"
        );
        match operation.scenario.as_str() {
            ADMIN_DECOMMISSION_SCENARIO => {
                let status = parse_captured_json_response::<DecommissionPoolStatus>(
                    source,
                    "RustFS decommission status response",
                )?;
                let projection = project_decommission_status(
                    &status,
                    operation
                        .target_pool_id
                        .context("decommission progress lacks a target pool")?,
                    operation
                        .target_pool_expression
                        .as_deref()
                        .context("decommission progress lacks a target expression")?,
                    &operation.operation_id,
                )?;
                ensure!(
                    sample.state.eq_ignore_ascii_case(&projection.state)
                        && sample.completed == projection.completed
                        && sample.failed == projection.failed
                        && sample.canceled_or_stopped == projection.canceled
                        && sample.objects_moved == Some(projection.objects_moved)
                        && sample.versions_moved.is_none()
                        && sample.bytes_moved == Some(projection.bytes_moved),
                    "decommission progress sample is not derived from its RustFS status response"
                );
            }
            ADMIN_REBALANCE_SCENARIO => {
                let status = parse_captured_json_response::<RebalanceStatus>(
                    source,
                    "RustFS rebalance status response",
                )?;
                let projection =
                    project_rebalance_status(&status, &operation.pools_before.pools, false)?;
                ensure!(
                    status.id == operation.operation_id
                        && sample.state.eq_ignore_ascii_case(projection.state)
                        && sample.completed == projection.completed
                        && sample.failed == projection.failed
                        && sample.canceled_or_stopped == projection.stopped
                        && sample.objects_moved == Some(projection.objects_moved)
                        && sample.versions_moved == Some(projection.versions_moved)
                        && sample.bytes_moved == Some(projection.bytes_moved),
                    "rebalance progress sample is not derived from its RustFS status response"
                );
            }
            other => bail!("unsupported admin operation scenario {other:?}"),
        }
        ensure!(
            !state.terminal || index + 1 == samples.len(),
            "admin terminal progress sample must be the final sample"
        );
    }
    ensure!(
        used_status_request_ids == status_request_ids,
        "admin progress samples do not cover the exact status GET response set"
    );
    ensure!(
        samples
            .windows(2)
            .zip(states.windows(2))
            .all(|(pair, state_pair)| {
                pair[0].observed_at_ms <= pair[1].observed_at_ms
                    && state_pair[0].rank <= state_pair[1].rank
                    && optional_counter_nondecreasing(pair[0].objects_moved, pair[1].objects_moved)
                    && optional_counter_nondecreasing(
                        pair[0].versions_moved,
                        pair[1].versions_moved,
                    )
                    && optional_counter_nondecreasing(pair[0].bytes_moved, pair[1].bytes_moved)
            }),
        "admin operation progress state, timestamps, or counters regressed"
    );
    let terminal = samples.last().expect("non-empty checked above");
    let terminal_state = states.last().expect("non-empty checked above");
    ensure!(
        terminal_state.terminal
            && terminal.observed_at_ms == terminal_status_observed_at_ms
            && terminal
                .state
                .eq_ignore_ascii_case(&operation.terminal_state)
            && terminal.completed == operation.completed
            && terminal.failed == operation.failed
            && terminal.canceled_or_stopped == operation.canceled_or_stopped,
        "admin operation terminal progress does not match the terminal status observation"
    );
    ensure!(
        terminal.objects_moved == operation.objects_moved
            && terminal.versions_moved == operation.versions_moved
            && terminal.bytes_moved == operation.bytes_moved,
        "admin operation terminal progress counters do not match operation evidence"
    );
    if operation.scenario == ADMIN_REBALANCE_SCENARIO {
        ensure!(
            terminal.objects_moved.is_some_and(|value| value > 0)
                || terminal.versions_moved.is_some_and(|value| value > 0)
                || terminal.bytes_moved.is_some_and(|value| value > 0),
            "rebalance terminal progress lacks a positive movement signal"
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct ValidatedProgressState {
    rank: u8,
    terminal: bool,
}

fn parse_progress_state(
    scenario: &str,
    sample: &AdminOperationProgressSample,
) -> Result<ValidatedProgressState> {
    ensure!(
        !sample.failed && !sample.canceled_or_stopped,
        "failed/canceled/stopped admin progress cannot pass"
    );
    let state = sample.state.to_ascii_lowercase();
    let parsed = match (scenario, state.as_str()) {
        (ADMIN_DECOMMISSION_SCENARIO, "queued") => ValidatedProgressState {
            rank: 0,
            terminal: false,
        },
        (ADMIN_DECOMMISSION_SCENARIO, "running") => ValidatedProgressState {
            rank: 1,
            terminal: false,
        },
        (ADMIN_DECOMMISSION_SCENARIO, "complete") => ValidatedProgressState {
            rank: 2,
            terminal: true,
        },
        (ADMIN_REBALANCE_SCENARIO, "started") => ValidatedProgressState {
            rank: 0,
            terminal: false,
        },
        (ADMIN_REBALANCE_SCENARIO, "completed") => ValidatedProgressState {
            rank: 1,
            terminal: true,
        },
        (ADMIN_DECOMMISSION_SCENARIO | ADMIN_REBALANCE_SCENARIO, _) => {
            bail!(
                "unknown admin progress state {:?} for {scenario}",
                sample.state
            )
        }
        _ => bail!("unsupported admin operation scenario {scenario:?}"),
    };
    ensure!(
        sample.completed == parsed.terminal,
        "admin progress completion flag does not match its state"
    );
    match scenario {
        ADMIN_DECOMMISSION_SCENARIO => ensure!(
            sample.versions_moved.is_none(),
            "decommission progress must not report a rebalance version counter"
        ),
        ADMIN_REBALANCE_SCENARIO => ensure!(
            sample.objects_moved.is_some()
                && sample.versions_moved.is_some()
                && sample.bytes_moved.is_some(),
            "rebalance progress requires complete movement counters"
        ),
        _ => unreachable!("scenario checked above"),
    }
    Ok(parsed)
}

fn optional_counter_nondecreasing(before: Option<u64>, after: Option<u64>) -> bool {
    match (before, after) {
        (Some(before), Some(after)) => before <= after,
        (None, Some(_)) | (None, None) => true,
        (Some(_), None) => false,
    }
}

pub fn validate_admin_topology_artifacts(
    scenario: &str,
    expected_attempt: &AdminAttemptIdentity,
    attempt_window: AdminAttemptWindow,
    proof: &AdminTopologyProof,
    operation: &AdminOperationEvidence,
) -> Result<()> {
    attempt_window.validate()?;
    let _ = AdminTopologyPlan::for_scenario(scenario)?;
    validate_attempt_identity(expected_attempt)?;
    ensure!(
        expected_attempt.case_name == expected_case_name(scenario)?,
        "expected admin attempt caseName does not match the scenario"
    );
    ensure!(
        proof.scenario == scenario,
        "admin topology proof scenario mismatch"
    );
    ensure!(
        operation.scenario == scenario,
        "admin operation evidence scenario mismatch"
    );
    ensure!(
        proof.attempt == *expected_attempt && operation.attempt == *expected_attempt,
        "admin topology artifacts do not belong to the current run/case/Tenant attempt"
    );
    ensure!(
        proof.runtime == operation.pools_before.runtime,
        "admin topology artifacts changed the pre-start RustFS runtime receipt"
    );
    proof
        .runtime
        .target
        .require_same_runtime_identity(&operation.pools_after.runtime.target)?;
    validate_request_targets(&operation.requests, &proof.runtime.target)?;
    proof.require_satisfied()?;
    operation.require_success(attempt_window)?;
    validate_pre_start_snapshot(proof, &operation.pools_before, &operation.requests)?;
    validate_post_operation_snapshot(proof, &operation.pools_after, &operation.requests)?;
    if scenario == ADMIN_DECOMMISSION_SCENARIO {
        ensure!(
            operation.target_pool_id == proof.target_pool_id,
            "decommission target ID drifted after preflight"
        );
        ensure!(
            operation.target_pool_expression == proof.target_pool_expression,
            "decommission target expression drifted after preflight"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use axum::{
        Router,
        routing::{get, post},
    };
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use super::*;

    const TEST_RUN_ID: &str = "run-admin-1";
    const TEST_WORKLOAD_MAX_BYTES: u64 = 100;

    fn attempt_window() -> AdminAttemptWindow {
        AdminAttemptWindow {
            started_at_ms: 50,
            evaluated_at_ms: 300,
        }
    }

    fn case_name(scenario: &str) -> &'static str {
        expected_case_name(scenario).unwrap()
    }

    fn endpoint_identity() -> AdminEndpointIdentity {
        let cluster_response_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "kube-system", "uid": "cluster-uid"}
        })
        .to_string();
        let service_response_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant-io",
                "uid": "service-uid",
                "resourceVersion": "service-rv-1"
            },
            "spec": {
                "ports": [{"port": 9000}],
                "selector": {"rustfs.tenant": "fault-tenant"}
            }
        })
        .to_string();
        let tenant_response_body = serde_json::to_string(&tenant()).expect("serialize Tenant");
        AdminEndpointIdentity {
            kubernetes_context: "kind-admin-test".to_string(),
            cluster_uid: "cluster-uid".to_string(),
            port_forward_command: "kubectl --context kind-admin-test -n fault-ns port-forward svc/fault-tenant-io 19000:9000".to_string(),
            port_forward_started_at_ms: 10,
            cluster_started_at_ms: 20,
            cluster_observed_at_ms: 21,
            cluster_response_sha256: sha256_hex(cluster_response_body.as_bytes()),
            cluster_response_body,
            namespace: "fault-ns".to_string(),
            service_name: "fault-tenant-io".to_string(),
            service_uid: "service-uid".to_string(),
            service_resource_version: "service-rv-1".to_string(),
            service_started_at_ms: 22,
            service_observed_at_ms: 23,
            service_response_sha256: sha256_hex(service_response_body.as_bytes()),
            service_response_body,
            tenant_name: "fault-tenant".to_string(),
            tenant_uid: "tenant-uid".to_string(),
            tenant_resource_version: "tenant-rv-1".to_string(),
            tenant_started_at_ms: 24,
            tenant_observed_at_ms: 25,
            tenant_response_sha256: sha256_hex(tenant_response_body.as_bytes()),
            tenant_response_body,
            local_endpoint: "http://127.0.0.1:19000".to_string(),
            remote_port: 9000,
        }
    }

    fn request_target() -> AdminRequestTarget {
        AdminRequestTarget {
            endpoint: endpoint_identity(),
            deployment_id: "deployment-1".to_string(),
        }
    }

    #[test]
    fn endpoint_identity_rejects_self_consistent_cross_cluster_tenant_substitution() {
        let mut endpoint = endpoint_identity();
        let cluster_response_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Namespace",
            "metadata": {"name": "kube-system", "uid": "cluster-b-uid"}
        })
        .to_string();
        let service_response_body = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant-io",
                "uid": "service-b-uid",
                "resourceVersion": "service-b-rv"
            },
            "spec": {
                "ports": [{"port": 9000}],
                "selector": {"rustfs.tenant": "fault-tenant"}
            }
        })
        .to_string();
        let tenant_response_body = serde_json::json!({
            "metadata": {
                "namespace": "fault-ns",
                "name": "fault-tenant",
                "uid": "tenant-b-uid",
                "resourceVersion": "tenant-b-rv"
            }
        })
        .to_string();
        endpoint.kubernetes_context = "kind-cluster-b".to_string();
        endpoint.cluster_uid = "cluster-b-uid".to_string();
        endpoint.port_forward_command = "kubectl --context kind-cluster-b -n fault-ns port-forward svc/fault-tenant-io 19000:9000".to_string();
        endpoint.cluster_response_sha256 = sha256_hex(cluster_response_body.as_bytes());
        endpoint.cluster_response_body = cluster_response_body;
        endpoint.service_uid = "service-b-uid".to_string();
        endpoint.service_resource_version = "service-b-rv".to_string();
        endpoint.service_response_sha256 = sha256_hex(service_response_body.as_bytes());
        endpoint.service_response_body = service_response_body;
        endpoint.tenant_uid = "tenant-b-uid".to_string();
        endpoint.tenant_resource_version = "tenant-b-rv".to_string();
        endpoint.tenant_response_sha256 = sha256_hex(tenant_response_body.as_bytes());
        endpoint.tenant_response_body = tenant_response_body;

        endpoint
            .validate()
            .expect("self-consistent cluster B identity");
        assert!(
            endpoint
                .validate_for_tenant("fault-ns", "fault-tenant", "tenant-uid")
                .is_err(),
            "a live endpoint from cluster B must not bind to cluster A's original Tenant UID"
        );
    }

    #[test]
    fn endpoint_identity_rejects_loopback_port_not_owned_by_its_guard_command() {
        let mut endpoint = endpoint_identity();
        endpoint.local_endpoint = "http://127.0.0.1:19001".to_string();

        assert!(endpoint.validate().is_err());
    }

    fn runtime_binding(started_at_ms: u64, observed_at_ms: u64) -> AdminRuntimeBinding {
        let response_body = r#"{"info":{"deploymentID":"deployment-1"}}"#.to_string();
        AdminRuntimeBinding {
            target: request_target(),
            status: 200,
            started_at_ms,
            observed_at_ms,
            request_id: Some("admin-info-request".to_string()),
            response_sha256: sha256_hex(response_body.as_bytes()),
            response_body,
        }
    }

    fn request_runtime_probe(request_started_at_ms: u64) -> AdminRuntimeBinding {
        let mut binding = runtime_binding(
            request_started_at_ms.saturating_sub(1),
            request_started_at_ms.saturating_sub(1),
        );
        let endpoint = &mut binding.target.endpoint;
        endpoint.cluster_started_at_ms = request_started_at_ms.saturating_sub(3);
        endpoint.cluster_observed_at_ms = request_started_at_ms.saturating_sub(3);
        endpoint.service_started_at_ms = request_started_at_ms.saturating_sub(2);
        endpoint.service_observed_at_ms = request_started_at_ms.saturating_sub(2);
        endpoint.tenant_started_at_ms = request_started_at_ms.saturating_sub(1);
        endpoint.tenant_observed_at_ms = request_started_at_ms.saturating_sub(1);
        binding
    }

    fn fresh_request_target(request_started_at_ms: u64) -> AdminRequestTarget {
        request_runtime_probe(request_started_at_ms).target
    }

    fn mutation_runtime_probe(request_started_at_ms: u64) -> Option<AdminRuntimeBinding> {
        Some(request_runtime_probe(request_started_at_ms))
    }

    fn context(scenario: &str) -> AdminTopologyBuildContext {
        AdminTopologyBuildContext {
            run_id: TEST_RUN_ID.to_string(),
            case_name: case_name(scenario).to_string(),
            cluster_domain: DEFAULT_CLUSTER_DOMAIN.to_string(),
            workload_max_bytes: TEST_WORKLOAD_MAX_BYTES,
            runtime: runtime_binding(60, 70),
        }
    }

    fn context_with_tenant(scenario: &str, tenant: &Value) -> AdminTopologyBuildContext {
        let mut context = context(scenario);
        let body = serde_json::to_string(tenant).expect("serialize Tenant receipt");
        let endpoint = &mut context.runtime.target.endpoint;
        endpoint.tenant_name = required_string(tenant, "/metadata/name").expect("Tenant name");
        endpoint.tenant_uid = required_string(tenant, "/metadata/uid").expect("Tenant UID");
        endpoint.tenant_resource_version =
            required_string(tenant, "/metadata/resourceVersion").expect("Tenant resourceVersion");
        endpoint.tenant_response_sha256 = sha256_hex(body.as_bytes());
        endpoint.tenant_response_body = body;
        context
    }

    #[test]
    fn build_context_derives_capacity_only_from_a_complete_workload_plan() {
        let complete = WorkloadPlan::seeded(42, 12, 1);
        let context = AdminTopologyBuildContext::new(
            TEST_RUN_ID,
            case_name(ADMIN_DECOMMISSION_SCENARIO),
            &complete,
            runtime_binding(60, 70),
        )
        .expect("complete workload context");
        assert_eq!(
            context.workload_max_bytes,
            complete
                .mixed_write_upper_bound(6, 6)
                .expect("derived workload bound")
        );

        let incomplete = WorkloadPlan::seeded(42, 2, 1);
        assert!(
            AdminTopologyBuildContext::new(
                TEST_RUN_ID,
                case_name(ADMIN_DECOMMISSION_SCENARIO),
                &incomplete,
                runtime_binding(60, 70),
            )
            .is_err()
        );
    }

    fn attempt(scenario: &str) -> AdminAttemptIdentity {
        AdminAttemptIdentity {
            run_id: TEST_RUN_ID.to_string(),
            case_name: case_name(scenario).to_string(),
            tenant_uid: "tenant-uid".to_string(),
        }
    }

    fn pool_expression(pool_name: &str) -> String {
        format!(
            "http://fault-tenant-{pool_name}-{{0...3}}.fault-tenant-hl.fault-ns.svc.cluster.local:9000/data/rustfs{{0...0}}"
        )
    }

    fn with_json_response<T: Serialize>(
        mut request: AdminRequestEvidence,
        value: &T,
    ) -> AdminRequestEvidence {
        let body = serde_json::to_string(value).expect("serialize RustFS admin fixture");
        request.response_sha256 = Some(sha256_hex(body.as_bytes()));
        request.response_body = Some(body);
        request
    }

    fn sync_pool_snapshot_response(snapshot: &mut AdminPoolSnapshot) {
        snapshot.request = with_json_response(snapshot.request.clone(), &snapshot.pools);
    }

    fn rebalance_requests() -> Vec<AdminRequestEvidence> {
        let mut requests = vec![
            AdminRequestEvidence {
                target: fresh_request_target(95),
                runtime_probe: mutation_runtime_probe(95),
                method: "POST".to_string(),
                path: format!("{ADMIN_PREFIX}/rebalance/start"),
                query: BTreeMap::new(),
                status: 200,
                started_at_ms: 95,
                observed_at_ms: 100,
                request_id: Some("rebalance-start-request".to_string()),
                response_sha256: None,
                response_body: None,
            },
            AdminRequestEvidence {
                target: fresh_request_target(195),
                runtime_probe: None,
                method: "GET".to_string(),
                path: format!("{ADMIN_PREFIX}/rebalance/status"),
                query: BTreeMap::new(),
                status: 200,
                started_at_ms: 195,
                observed_at_ms: 200,
                request_id: Some("rebalance-status-request".to_string()),
                response_sha256: None,
                response_body: None,
            },
        ];
        requests[0] = with_json_response(
            requests[0].clone(),
            &RebalanceStart {
                id: "rebalance-1".to_string(),
            },
        );
        requests[1] = with_json_response(
            requests[1].clone(),
            &completed_rebalance_status("rebalance-1"),
        );
        requests
    }

    fn rebalance_progress_requests() -> Vec<AdminRequestEvidence> {
        let mut requests = rebalance_requests();
        requests[0] = with_json_response(
            requests[0].clone(),
            &RebalanceStart {
                id: "rebalance-123".to_string(),
            },
        );
        requests[1].request_id = Some("rebalance-status-request-2".to_string());
        requests.insert(
            1,
            AdminRequestEvidence {
                target: fresh_request_target(110),
                runtime_probe: None,
                method: "GET".to_string(),
                path: format!("{ADMIN_PREFIX}/rebalance/status"),
                query: BTreeMap::new(),
                status: 200,
                started_at_ms: 110,
                observed_at_ms: 120,
                request_id: Some("rebalance-status-request-1".to_string()),
                response_sha256: None,
                response_body: None,
            },
        );
        let mut started = completed_rebalance_status("rebalance-123");
        started.pools[0].status = "Started".to_string();
        started.pools[0].progress = Some(RebalanceProgress {
            objects: 1,
            versions: 1,
            bytes: 10,
            remaining_buckets: 1,
        });
        let mut completed = completed_rebalance_status("rebalance-123");
        completed.pools[0].progress = Some(RebalanceProgress {
            objects: 2,
            versions: 2,
            bytes: 20,
            remaining_buckets: 0,
        });
        requests[1] = with_json_response(requests[1].clone(), &started);
        requests[2] = with_json_response(requests[2].clone(), &completed);
        requests
    }

    fn decommission_requests(pool_id: usize) -> Vec<AdminRequestEvidence> {
        let pool_id = pool_id.to_string();
        let mut requests = vec![
            AdminRequestEvidence {
                target: fresh_request_target(95),
                runtime_probe: mutation_runtime_probe(95),
                method: "POST".to_string(),
                path: format!("{ADMIN_PREFIX}/pools/decommission"),
                query: BTreeMap::from([
                    ("by-id".to_string(), "true".to_string()),
                    ("pool".to_string(), pool_id.clone()),
                ]),
                status: 200,
                started_at_ms: 95,
                observed_at_ms: 100,
                request_id: Some("decommission-start-request".to_string()),
                response_sha256: None,
                response_body: None,
            },
            AdminRequestEvidence {
                target: fresh_request_target(195),
                runtime_probe: None,
                method: "GET".to_string(),
                path: format!("{ADMIN_PREFIX}/decommission/status"),
                query: BTreeMap::from([
                    ("by-id".to_string(), "true".to_string()),
                    ("pool".to_string(), pool_id.clone()),
                ]),
                status: 200,
                started_at_ms: 195,
                observed_at_ms: 200,
                request_id: Some("decommission-status-request".to_string()),
                response_sha256: None,
                response_body: None,
            },
        ];
        let status = DecommissionPoolStatus {
            id: pool_id.parse().expect("pool id"),
            expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
            status: "complete".to_string(),
            pool_status: "decommissioned".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned: 1,
                bytes_decommissioned: 200,
                ..Default::default()
            }),
        };
        requests[1] = with_json_response(requests[1].clone(), &status);
        requests
    }

    fn decommission_progress_requests(pool_id: usize) -> Vec<AdminRequestEvidence> {
        let mut requests = decommission_requests(pool_id);
        requests[1].request_id = Some("decommission-status-request-3".to_string());
        let pool_id = pool_id.to_string();
        for (index, started_at_ms, observed_at_ms) in
            [(1, 105, 110), (2, 140, 150)].into_iter().rev()
        {
            requests.insert(
                1,
                AdminRequestEvidence {
                    target: fresh_request_target(started_at_ms),
                    runtime_probe: None,
                    method: "GET".to_string(),
                    path: format!("{ADMIN_PREFIX}/decommission/status"),
                    query: BTreeMap::from([
                        ("by-id".to_string(), "true".to_string()),
                        ("pool".to_string(), pool_id.clone()),
                    ]),
                    status: 200,
                    started_at_ms,
                    observed_at_ms,
                    request_id: Some(format!("decommission-status-request-{index}")),
                    response_sha256: None,
                    response_body: None,
                },
            );
        }
        let statuses = [
            DecommissionPoolStatus {
                id: pool_id.parse().expect("pool id"),
                expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
                status: "queued".to_string(),
                pool_status: "decommissioning".to_string(),
                decommission: Some(DecommissionProgress {
                    start_time: None,
                    queued: true,
                    ..Default::default()
                }),
            },
            DecommissionPoolStatus {
                id: pool_id.parse().expect("pool id"),
                expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
                status: "running".to_string(),
                pool_status: "decommissioning".to_string(),
                decommission: Some(DecommissionProgress {
                    start_time: Some("2026-09-05T00:00:00Z".to_string()),
                    objects_decommissioned: 1,
                    bytes_decommissioned: 100,
                    ..Default::default()
                }),
            },
            DecommissionPoolStatus {
                id: pool_id.parse().expect("pool id"),
                expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
                status: "complete".to_string(),
                pool_status: "decommissioned".to_string(),
                decommission: Some(DecommissionProgress {
                    start_time: Some("2026-09-05T00:00:00Z".to_string()),
                    complete: true,
                    objects_decommissioned: 2,
                    bytes_decommissioned: 200,
                    ..Default::default()
                }),
            },
        ];
        for (request, status) in requests.iter_mut().skip(1).zip(&statuses) {
            *request = with_json_response(request.clone(), status);
        }
        requests
    }

    fn pre_start_snapshot(scenario: &str, pools: Vec<AdminPool>) -> AdminPoolSnapshot {
        pool_snapshot(scenario, pools, 90)
    }

    fn post_operation_snapshot(scenario: &str, pools: Vec<AdminPool>) -> AdminPoolSnapshot {
        pool_snapshot(scenario, pools, 210)
    }

    fn pool_snapshot(
        scenario: &str,
        pools: Vec<AdminPool>,
        observed_at_ms: u64,
    ) -> AdminPoolSnapshot {
        let (tenant_started_at_ms, tenant_observed_at_ms) = if observed_at_ms < 200 {
            (
                observed_at_ms.saturating_sub(10),
                observed_at_ms.saturating_sub(5),
            )
        } else {
            (
                observed_at_ms.saturating_sub(5),
                observed_at_ms.saturating_sub(4),
            )
        };
        let list_started_at_ms = observed_at_ms;
        let request = with_json_response(
            AdminRequestEvidence {
                target: fresh_request_target(list_started_at_ms),
                runtime_probe: Some(request_runtime_probe(list_started_at_ms)),
                method: "GET".to_string(),
                path: format!("{ADMIN_PREFIX}/pools/list"),
                query: BTreeMap::new(),
                status: 200,
                started_at_ms: list_started_at_ms,
                observed_at_ms,
                request_id: None,
                response_sha256: None,
                response_body: None,
            },
            &pools,
        );
        let tenant_response_body = serde_json::to_string(&tenant()).expect("serialize Tenant");
        let runtime = if observed_at_ms < 200 {
            runtime_binding(60, 70)
        } else {
            request_runtime_probe(205)
        };
        AdminPoolSnapshot {
            attempt: attempt(scenario),
            tenant_get: KubernetesTenantGetEvidence {
                kubernetes_context: "kind-admin-test".to_string(),
                cluster_uid: "cluster-uid".to_string(),
                namespace: "fault-ns".to_string(),
                name: "fault-tenant".to_string(),
                uid: "tenant-uid".to_string(),
                resource_version: "tenant-rv-1".to_string(),
                started_at_ms: tenant_started_at_ms,
                observed_at_ms: tenant_observed_at_ms,
                response_sha256: sha256_hex(tenant_response_body.as_bytes()),
                response_body: tenant_response_body,
            },
            runtime,
            observed_at_ms,
            request,
            pools,
        }
    }

    fn completed_rebalance_status(id: &str) -> RebalanceStatus {
        RebalanceStatus {
            id: id.to_string(),
            pools: vec![
                RebalancePoolStatus {
                    id: 0,
                    status: "Completed".to_string(),
                    stopping: false,
                    last_error: None,
                    cleanup_warnings: RebalanceCleanupWarnings::default(),
                    progress: Some(RebalanceProgress {
                        objects: 2,
                        versions: 3,
                        bytes: 128,
                        remaining_buckets: 0,
                    }),
                },
                RebalancePoolStatus {
                    id: 1,
                    status: "None".to_string(),
                    stopping: false,
                    last_error: None,
                    cleanup_warnings: RebalanceCleanupWarnings::default(),
                    progress: None,
                },
            ],
            stopped_at: None,
            stop_propagation: RebalanceStopPropagationStatus::default(),
        }
    }

    fn tenant() -> Value {
        serde_json::json!({
            "metadata": {
                "name": "fault-tenant",
                "uid": "tenant-uid",
                "namespace": "fault-ns",
                "resourceVersion": "tenant-rv-1"
            },
            "spec": {"pools": [
                {"name": "primary", "servers": 4, "persistence": {"volumesPerServer": 1}},
                {"name": "decommission-target", "servers": 4, "persistence": {"volumesPerServer": 1}}
            ]}
        })
    }

    fn pools() -> Vec<AdminPool> {
        vec![
            AdminPool {
                id: 0,
                expression: pool_expression("primary"),
                status: "active".to_string(),
                decommission_status: "none".to_string(),
                rebalance_status: "none".to_string(),
                total_size: 2_000,
                current_size: 1_500,
                used_size: 500,
                used: 0.25,
                decommission: None,
            },
            AdminPool {
                id: 1,
                expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
                status: "active".to_string(),
                decommission_status: "none".to_string(),
                rebalance_status: "none".to_string(),
                total_size: 1_000,
                current_size: 800,
                used_size: 200,
                used: 0.2,
                decommission: None,
            },
        ]
    }

    #[tokio::test]
    async fn adapter_captures_rustfs_admin_x_request_id() {
        let app = Router::new()
            .route(
                "/rustfs/admin/v3/info",
                get(|| async {
                    (
                        [("x-request-id", "rustfs-admin-info-request-1")],
                        r#"{"info":{"deploymentID":"deployment-1"}}"#,
                    )
                }),
            )
            .route(
                "/rustfs/admin/v3/pools/list",
                get(|| async { ([("x-request-id", "rustfs-admin-request-1")], "[]") }),
            );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("mock listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("mock address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });
        let mut endpoint_identity = endpoint_identity();
        let local_port = reqwest::Url::parse(&endpoint)
            .expect("mock endpoint")
            .port()
            .expect("mock port");
        endpoint_identity.port_forward_command = format!(
            "kubectl --context kind-admin-test -n fault-ns port-forward svc/fault-tenant-io {local_port}:9000"
        );
        endpoint_identity.local_endpoint = endpoint;
        let adapter = RustfsAdminTopologyAdapter::connect_for_test(
            endpoint_identity,
            "us-east-1",
            "access",
            "secret",
        )
        .await
        .expect("adapter");

        let response = adapter.list_pools().await.expect("pool list");
        assert_eq!(
            adapter.runtime_binding().target.deployment_id,
            "deployment-1"
        );
        assert_eq!(
            response.request.request_id.as_deref(),
            Some("rustfs-admin-request-1")
        );
        assert_eq!(response.request.response_body.as_deref(), Some("[]"));
        assert!(response.request.runtime_probe.is_some());
        assert_eq!(
            response.request.target,
            response.request.runtime_probe.unwrap().target
        );
        server.abort();
    }

    #[tokio::test]
    async fn destructive_admin_request_requires_fresh_stable_runtime() {
        let info_calls = Arc::new(AtomicUsize::new(0));
        let destructive_calls = Arc::new(AtomicUsize::new(0));
        let runtime_drifted = Arc::new(AtomicBool::new(false));
        let app = Router::new()
            .route(
                "/rustfs/admin/v3/info",
                get({
                    let info_calls = info_calls.clone();
                    let runtime_drifted = runtime_drifted.clone();
                    move || {
                        info_calls.fetch_add(1, Ordering::SeqCst);
                        let drifted = runtime_drifted.load(Ordering::SeqCst);
                        async move {
                            if drifted {
                                r#"{"info":{"deploymentID":"replacement-deployment"}}"#
                            } else {
                                r#"{"info":{"deploymentID":"deployment-1"}}"#
                            }
                        }
                    }
                }),
            )
            .route(
                "/rustfs/admin/v3/rebalance/start",
                post({
                    let destructive_calls = destructive_calls.clone();
                    move || {
                        destructive_calls.fetch_add(1, Ordering::SeqCst);
                        async { r#"{"id":"rebalance-1"}"# }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("mock listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("mock address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock server");
        });
        let mut endpoint_identity = endpoint_identity();
        let local_port = reqwest::Url::parse(&endpoint)
            .expect("mock endpoint")
            .port()
            .expect("mock port");
        endpoint_identity.port_forward_command = format!(
            "kubectl --context kind-admin-test -n fault-ns port-forward svc/fault-tenant-io {local_port}:9000"
        );
        endpoint_identity.local_endpoint = endpoint;
        let adapter = RustfsAdminTopologyAdapter::connect_for_test(
            endpoint_identity,
            "us-east-1",
            "access",
            "secret",
        )
        .await
        .expect("adapter");

        let started = adapter
            .start_rebalance()
            .await
            .expect("stable deployment permits destructive request");
        assert_eq!(started.value.id, "rebalance-1");
        let runtime_probe = started
            .request
            .runtime_probe
            .as_ref()
            .expect("destructive request retains its fresh runtime probe");
        assert_eq!(runtime_probe.target, started.request.target);
        assert!(runtime_probe.observed_at_ms <= started.request.started_at_ms);
        assert_eq!(
            runtime_probe.response_sha256,
            sha256_hex(runtime_probe.response_body.as_bytes())
        );
        assert_eq!(info_calls.load(Ordering::SeqCst), 2);
        assert_eq!(destructive_calls.load(Ordering::SeqCst), 1);

        runtime_drifted.store(true, Ordering::SeqCst);
        let error = adapter
            .start_rebalance()
            .await
            .expect_err("deployment drift must block a destructive request");
        assert!(error.to_string().contains("RustFS deployment changed"));
        assert_eq!(info_calls.load(Ordering::SeqCst), 3);
        assert_eq!(destructive_calls.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[test]
    fn pool_snapshot_derives_tenant_uid_from_fresh_kubernetes_get() {
        let mut current_tenant = tenant();
        current_tenant["metadata"]["resourceVersion"] = Value::String("tenant-rv-2".to_string());
        let current_pools = pools();
        let snapshot = AdminPoolSnapshot::from_list(
            TEST_RUN_ID,
            case_name(ADMIN_REBALANCE_SCENARIO),
            serde_json::to_string(&current_tenant)
                .expect("Tenant JSON")
                .as_bytes(),
            runtime_binding(60, 70),
            75,
            80,
            AdminCall {
                value: current_pools.clone(),
                request: with_json_response(
                    AdminRequestEvidence {
                        target: fresh_request_target(85),
                        runtime_probe: Some(request_runtime_probe(85)),
                        method: "GET".to_string(),
                        path: format!("{ADMIN_PREFIX}/pools/list"),
                        query: BTreeMap::new(),
                        status: 200,
                        started_at_ms: 85,
                        observed_at_ms: 90,
                        request_id: None,
                        response_sha256: None,
                        response_body: None,
                    },
                    &current_pools,
                ),
            },
        )
        .expect("snapshot derives Tenant identity from the Kubernetes resource");

        assert_eq!(snapshot.attempt.tenant_uid, "tenant-uid");
        assert_eq!(snapshot.tenant_get.resource_version, "tenant-rv-2");
        assert_eq!(snapshot.tenant_get.observed_at_ms, 80);

        let mut recreated_tenant = current_tenant.clone();
        recreated_tenant["metadata"]["uid"] = Value::String("replacement-tenant-uid".to_string());
        assert!(
            AdminPoolSnapshot::from_list(
                TEST_RUN_ID,
                case_name(ADMIN_REBALANCE_SCENARIO),
                serde_json::to_string(&recreated_tenant)
                    .expect("Tenant JSON")
                    .as_bytes(),
                runtime_binding(60, 70),
                75,
                80,
                AdminCall {
                    value: current_pools.clone(),
                    request: with_json_response(
                        AdminRequestEvidence {
                            target: fresh_request_target(85),
                            runtime_probe: Some(request_runtime_probe(85)),
                            method: "GET".to_string(),
                            path: format!("{ADMIN_PREFIX}/pools/list"),
                            query: BTreeMap::new(),
                            status: 200,
                            started_at_ms: 85,
                            observed_at_ms: 90,
                            request_id: None,
                            response_sha256: None,
                            response_body: None,
                        },
                        &current_pools,
                    ),
                },
            )
            .is_err(),
            "a recreated Tenant UID must not replace the guard-bound original Tenant"
        );

        assert!(
            AdminPoolSnapshot::from_list(
                TEST_RUN_ID,
                case_name(ADMIN_REBALANCE_SCENARIO),
                serde_json::to_string(&current_tenant)
                    .expect("Tenant JSON")
                    .as_bytes(),
                runtime_binding(60, 70),
                80,
                85,
                AdminCall {
                    value: current_pools.clone(),
                    request: with_json_response(
                        AdminRequestEvidence {
                            target: fresh_request_target(85),
                            runtime_probe: Some(request_runtime_probe(85)),
                            method: "GET".to_string(),
                            path: format!("{ADMIN_PREFIX}/pools/list"),
                            query: BTreeMap::new(),
                            status: 200,
                            started_at_ms: 85,
                            observed_at_ms: 90,
                            request_id: None,
                            response_sha256: None,
                            response_body: None,
                        },
                        &current_pools,
                    ),
                },
            )
            .is_err(),
            "Tenant GET completion equal to pools/list start is ambiguous and must fail closed"
        );
    }

    #[test]
    fn live_target_allows_status_updates_but_rejects_complete_tenant_spec_drift() {
        let bound = endpoint_identity();
        let mut current = bound.clone();
        let mut current_tenant = current.tenant_receipt().expect("Tenant receipt");
        current_tenant["metadata"]["resourceVersion"] = serde_json::json!("tenant-rv-2");
        current.tenant_resource_version = "tenant-rv-2".to_string();
        current.tenant_response_body = serde_json::to_string(&current_tenant).expect("Tenant JSON");
        current.tenant_response_sha256 = sha256_hex(current.tenant_response_body.as_bytes());
        bound
            .require_same_live_target(&current)
            .expect("status-only resourceVersion change");

        current_tenant["spec"]["pools"][0]["servers"] = serde_json::json!(8);
        current.tenant_response_body =
            serde_json::to_string(&current_tenant).expect("drifted Tenant JSON");
        current.tenant_response_sha256 = sha256_hex(current.tenant_response_body.as_bytes());
        assert!(
            bound.require_same_live_target(&current).is_err(),
            "same-UID Tenant pool drift must invalidate the live target"
        );

        for (field, value) in [
            ("image", serde_json::json!("rustfs/rustfs:replacement")),
            (
                "configuration",
                serde_json::json!({"name": "replacement-config"}),
            ),
            (
                "env",
                serde_json::json!([{"name": "RUSTFS_LOG_LEVEL", "value": "debug"}]),
            ),
        ] {
            let mut current = bound.clone();
            let mut current_tenant = current.tenant_receipt().expect("Tenant receipt");
            current_tenant["spec"][field] = value;
            current.tenant_response_body =
                serde_json::to_string(&current_tenant).expect("drifted Tenant JSON");
            current.tenant_response_sha256 = sha256_hex(current.tenant_response_body.as_bytes());
            assert!(
                bound.require_same_live_target(&current).is_err(),
                "same-UID Tenant {field} drift must invalidate the live target"
            );
        }
    }

    #[test]
    fn decommission_preflight_binds_exact_pool_and_capacity() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .expect("proof");
        assert_eq!(proof.target_pool_id, Some(1));
        assert_eq!(
            proof.target_pool_expression.as_deref(),
            Some(pool_expression(DECOMMISSION_TARGET_POOL_NAME).as_str())
        );
        assert_eq!(proof.remaining_free_bytes, 1_500);
        assert_eq!(proof.target_used_bytes, 200);
        assert_eq!(proof.required_remaining_free_bytes, 360);
    }

    #[test]
    fn preflight_maps_named_pools_by_runtime_cmdline_not_spec_order() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let mut reversed = tenant();
        reversed["spec"]["pools"].as_array_mut().unwrap().reverse();

        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &reversed,
            pools(),
            &context_with_tenant(ADMIN_DECOMMISSION_SCENARIO, &reversed),
        )
        .expect("name/cmdline binding");

        assert_eq!(proof.target_pool_id, Some(1));
        assert_eq!(proof.tenant_pools[0].name, DECOMMISSION_TARGET_POOL_NAME);
        assert_eq!(proof.tenant_pools[0].runtime_pool_id, 1);

        let mut mismatched = pools();
        mismatched[1].expression = "/data/unowned".to_string();
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &tenant(),
                mismatched,
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err()
        );
    }

    #[test]
    fn topology_rejects_same_uid_spec_not_proven_by_tenant_receipt() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let authenticated = tenant();
        let context = context_with_tenant(ADMIN_DECOMMISSION_SCENARIO, &authenticated);
        let mut drifts = Vec::new();

        let mut pool_drift = authenticated.clone();
        pool_drift["spec"]["pools"][0]["servers"] = serde_json::json!(8);
        drifts.push(("pool shape", pool_drift));

        let mut tls_drift = authenticated.clone();
        tls_drift["spec"]["tls"]["enableInternodeHttps"] = serde_json::json!(true);
        drifts.push(("internode TLS", tls_drift));

        let mut path_drift = authenticated.clone();
        path_drift["spec"]["pools"][0]["persistence"]["path"] = serde_json::json!("/forged");
        drifts.push(("pool path", path_drift));

        for (name, drifted) in drifts {
            let error = AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &drifted,
                pools(),
                &context,
            )
            .expect_err("an unreceipted same-UID Tenant spec must fail closed");
            assert!(
                error
                    .to_string()
                    .contains("authenticated raw Tenant GET receipt"),
                "unexpected {name} drift error: {error:#}"
            );
        }

        let mut forged = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &authenticated,
            pools(),
            &context,
        )
        .expect("receipt-bound proof");
        let primary = forged
            .tenant_pools
            .iter_mut()
            .find(|pool| pool.name == "primary")
            .expect("primary pool");
        primary.data_path = "/forged".to_string();
        let (_, expression) = expected_pool_endpoint_set(
            &forged.tenant,
            &primary.name,
            &forged.namespace,
            &primary.internode_scheme,
            &primary.cluster_domain,
            &primary.data_path,
            (primary.servers, primary.volumes_per_server),
        )
        .expect("forged endpoint");
        primary.expected_endpoint_set = expression.clone();
        forged
            .runtime_pools
            .iter_mut()
            .find(|pool| pool.id == primary.runtime_pool_id)
            .expect("primary runtime pool")
            .expression = expression;
        assert!(
            forged.require_satisfied().is_err(),
            "a self-consistent proof projection must not override its raw Tenant receipt"
        );
    }

    #[test]
    fn decommission_accepts_runtime_target_pool_zero() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let mut runtime = pools();
        runtime[0].id = 1;
        runtime[1].id = 0;
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            runtime,
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .expect("RustFS may assign the named target runtime pool ID zero");
        assert_eq!(proof.target_pool_id, Some(0));

        let status = DecommissionPoolStatus {
            id: 0,
            expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
            status: "complete".to_string(),
            pool_status: "decommissioned".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned: 1,
                bytes_decommissioned: 200,
                ..Default::default()
            }),
        };
        let survivor = proof
            .runtime_pools
            .iter()
            .find(|pool| pool.id == 1)
            .cloned()
            .unwrap();
        let operation = AdminOperationEvidence::from_decommission(
            &proof,
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone()),
            status,
            decommission_requests(0),
            post_operation_snapshot(ADMIN_DECOMMISSION_SCENARIO, vec![survivor]),
        )
        .expect("operation evidence");

        validate_admin_topology_artifacts(
            ADMIN_DECOMMISSION_SCENARIO,
            &attempt(ADMIN_DECOMMISSION_SCENARIO),
            attempt_window(),
            &proof,
            &operation,
        )
        .expect("runtime target pool zero is valid when cmdline-bound");
    }

    #[test]
    fn decommission_capacity_enforces_130_percent_plus_workload_boundary() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let mut exact = pools();
        exact[0].total_size = 730;
        exact[0].current_size = 230;
        exact[0].used_size = 500;
        exact[0].used = 500.0 / 730.0;
        exact[1].current_size = 900;
        exact[1].used_size = 100;
        exact[1].used = 0.1;
        AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            exact.clone(),
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .expect("130 percent guard plus 100-byte workload");

        exact[0].current_size = 229;
        exact[0].used_size = 501;
        exact[0].used = 501.0 / 730.0;
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &tenant(),
                exact,
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err()
        );
    }

    #[test]
    fn pre_start_snapshot_rejects_stale_or_drifted_topology() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .unwrap();
        let status = DecommissionPoolStatus {
            id: 1,
            expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
            status: "complete".to_string(),
            pool_status: "decommissioned".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned: 1,
                bytes_decommissioned: 200,
                ..Default::default()
            }),
        };

        let mut stale =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        stale.observed_at_ms = 1;
        stale.request.observed_at_ms = 1;
        let mut late_requests = decommission_requests(1);
        late_requests[0].observed_at_ms = ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS + 2;
        late_requests[1].observed_at_ms = ADMIN_PRE_START_SNAPSHOT_MAX_AGE_MS + 3;
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                stale,
                status.clone(),
                late_requests,
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err()
        );

        let mut wrong_attempt =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        wrong_attempt.attempt.tenant_uid = "old-tenant-uid".to_string();
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                wrong_attempt,
                status.clone(),
                decommission_requests(1),
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err()
        );

        for tenant_drift in [
            "uid",
            "name",
            "resource-version",
            "at-start",
            "spec-pools",
            "spec-tls",
            "spec-path",
        ] {
            let mut drifted =
                pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
            match tenant_drift {
                "uid" => drifted.tenant_get.uid = "replacement-tenant-uid".to_string(),
                "name" => drifted.tenant_get.name = "replacement-tenant".to_string(),
                "resource-version" => drifted.tenant_get.resource_version.clear(),
                "at-start" => drifted.tenant_get.observed_at_ms = 100,
                spec_drift => {
                    let mut receipt = tenant();
                    match spec_drift {
                        "spec-pools" => {
                            receipt["spec"]["pools"][0]["servers"] = serde_json::json!(8)
                        }
                        "spec-tls" => {
                            receipt["spec"]["tls"]["enableInternodeHttps"] = serde_json::json!(true)
                        }
                        "spec-path" => {
                            receipt["spec"]["pools"][0]["persistence"]["path"] =
                                serde_json::json!("/forged")
                        }
                        _ => unreachable!(),
                    }
                    let body = serde_json::to_string(&receipt).expect("drifted Tenant receipt");
                    drifted.tenant_get.response_sha256 = sha256_hex(body.as_bytes());
                    drifted.tenant_get.response_body = body;
                }
            }
            assert!(
                AdminOperationEvidence::from_decommission(
                    &proof,
                    drifted,
                    status.clone(),
                    decommission_requests(1),
                    post_operation_snapshot(
                        ADMIN_DECOMMISSION_SCENARIO,
                        vec![proof.runtime_pools[0].clone()],
                    ),
                )
                .is_err(),
                "pre-start Tenant GET drift {tenant_drift:?} must fail closed"
            );
        }

        let mut unhealthy =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        unhealthy.pools[0].rebalance_status = "started".to_string();
        sync_pool_snapshot_response(&mut unhealthy);
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                unhealthy,
                status.clone(),
                decommission_requests(1),
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err()
        );

        let mut list_overlaps_start =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        list_overlaps_start.observed_at_ms = 95;
        list_overlaps_start.request.observed_at_ms = 95;
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                list_overlaps_start,
                status.clone(),
                decommission_requests(1),
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err(),
            "the pre-start pools/list response must complete before admin start begins"
        );

        let mut tenant_get_equals_list_start =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        tenant_get_equals_list_start.tenant_get.observed_at_ms =
            tenant_get_equals_list_start.request.started_at_ms;
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                tenant_get_equals_list_start,
                status.clone(),
                decommission_requests(1),
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err(),
            "pre-start Tenant GET must complete strictly before pools/list starts"
        );

        let mut insufficient =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        insufficient.pools[0].current_size = 100;
        insufficient.pools[0].used_size = 1_900;
        insufficient.pools[0].used = 0.95;
        sync_pool_snapshot_response(&mut insufficient);
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                insufficient,
                status.clone(),
                decommission_requests(1),
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err()
        );

        let mut replaced =
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone());
        replaced.pools[0].expression = "/replacement-pool".to_string();
        sync_pool_snapshot_response(&mut replaced);
        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                replaced,
                status.clone(),
                decommission_requests(1),
                post_operation_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err()
        );

        assert!(
            AdminOperationEvidence::from_decommission(
                &proof,
                pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone()),
                status,
                decommission_requests(1),
                pre_start_snapshot(
                    ADMIN_DECOMMISSION_SCENARIO,
                    vec![proof.runtime_pools[0].clone()],
                ),
            )
            .is_err(),
            "a copied pre-start list cannot prove post-operation pool health"
        );
    }

    #[test]
    fn preflight_rejects_single_pool_capacity_and_active_operation() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let mut single = tenant();
        single["spec"]["pools"].as_array_mut().unwrap().truncate(1);
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &single,
                vec![pools()[0].clone()],
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err()
        );

        for (field, value) in [
            ("decommission", "completed"),
            ("decommission", "idle"),
            ("rebalance", "complete"),
            ("rebalance", "idle"),
        ] {
            let mut invalid_lifecycle = pools();
            if field == "decommission" {
                invalid_lifecycle[0].decommission_status = value.to_string();
            } else {
                invalid_lifecycle[0].rebalance_status = value.to_string();
            }
            assert!(
                AdminTopologyProof::build(
                    &plan,
                    ADMIN_DECOMMISSION_SCENARIO,
                    &tenant(),
                    invalid_lifecycle,
                    &context(ADMIN_DECOMMISSION_SCENARIO),
                )
                .is_err(),
                "cross-field or unknown {field} state {value:?} must fail closed"
            );
        }

        let mut insufficient = pools();
        insufficient[0].current_size = 100;
        insufficient[0].used_size = 1_900;
        insufficient[0].used = 0.95;
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &tenant(),
                insufficient,
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err()
        );

        let mut inconsistent_sizes = pools();
        inconsistent_sizes[0].used_size = 499;
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &tenant(),
                inconsistent_sizes,
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err(),
            "individually bounded capacities with an inconsistent total must fail closed"
        );

        let mut inconsistent_ratio = pools();
        inconsistent_ratio[0].used = 0.4;
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &tenant(),
                inconsistent_ratio,
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err(),
            "a wire used ratio inconsistent with usedSize/totalSize must fail closed"
        );

        let mut active = pools();
        active[0].rebalance_status = "Started".to_string();
        assert!(
            AdminTopologyProof::build(
                &plan,
                ADMIN_DECOMMISSION_SCENARIO,
                &tenant(),
                active,
                &context(ADMIN_DECOMMISSION_SCENARIO),
            )
            .is_err()
        );
    }

    #[test]
    fn artifact_validation_rejects_cancel_and_target_drift() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .unwrap();
        let mut operation = AdminOperationEvidence {
            attempt: attempt(ADMIN_DECOMMISSION_SCENARIO),
            scenario: ADMIN_DECOMMISSION_SCENARIO.to_string(),
            operation_id: "decommission:1:2026-09-05T00:00:00Z".to_string(),
            target_pool_id: Some(1),
            target_pool_expression: proof.target_pool_expression.clone(),
            terminal_state: "complete".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            participating_pool_ids: vec![1],
            objects_moved: Some(1),
            versions_moved: None,
            bytes_moved: Some(200),
            requests: decommission_requests(1),
            pools_before: pre_start_snapshot(
                ADMIN_DECOMMISSION_SCENARIO,
                proof.runtime_pools.clone(),
            ),
            pools_after: post_operation_snapshot(
                ADMIN_DECOMMISSION_SCENARIO,
                vec![proof.runtime_pools[0].clone()],
            ),
        };
        validate_admin_topology_artifacts(
            ADMIN_DECOMMISSION_SCENARIO,
            &attempt(ADMIN_DECOMMISSION_SCENARIO),
            attempt_window(),
            &proof,
            &operation,
        )
        .unwrap();
        assert_ne!(
            proof.runtime.target, operation.pools_after.runtime.target,
            "post-operation runtime must retain its fresh observation receipt"
        );
        assert_ne!(
            operation.pools_after.runtime.target, operation.pools_after.request.target,
            "pools/list must retain its own later observation receipt"
        );
        let mut missing_runtime_probe = operation.clone();
        missing_runtime_probe.requests[0].runtime_probe = None;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &missing_runtime_probe,
            )
            .is_err(),
            "destructive request must retain its fresh RustFS runtime probe"
        );
        let mut stale_endpoint_probe = operation.clone();
        let initial_endpoint = proof.runtime.target.endpoint.clone();
        stale_endpoint_probe.requests[0].target.endpoint = initial_endpoint.clone();
        stale_endpoint_probe.requests[0]
            .runtime_probe
            .as_mut()
            .expect("runtime probe")
            .target
            .endpoint = initial_endpoint;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &stale_endpoint_probe,
            )
            .is_err(),
            "fresh /info cannot reuse a Kubernetes endpoint receipt older than the pre-start snapshot"
        );
        let mut late_runtime_probe = operation.clone();
        late_runtime_probe.requests[0]
            .runtime_probe
            .as_mut()
            .expect("runtime probe")
            .observed_at_ms = late_runtime_probe.requests[0].started_at_ms + 1;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &late_runtime_probe,
            )
            .is_err(),
            "runtime probe must complete before its destructive request starts"
        );
        let mut zero_movement = operation.clone();
        zero_movement.objects_moved = Some(0);
        zero_movement.bytes_moved = Some(0);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &zero_movement,
            )
            .is_err()
        );
        let mut contradictory_target = operation.clone();
        let mut retained_target = proof.runtime_pools[1].clone();
        retained_target.status = "decommissioned".to_string();
        retained_target.decommission_status = "failed".to_string();
        retained_target.decommission = Some(DecommissionProgress {
            complete: true,
            failed: true,
            ..Default::default()
        });
        contradictory_target.pools_after.pools.push(retained_target);
        sync_pool_snapshot_response(&mut contradictory_target.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &contradictory_target,
            )
            .is_err()
        );
        let mut missing_target_state = operation.clone();
        let mut retained_target = proof.runtime_pools[1].clone();
        retained_target.status = "decommissioned".to_string();
        retained_target.decommission_status = "complete".to_string();
        retained_target.decommission = None;
        missing_target_state.pools_after.pools.push(retained_target);
        sync_pool_snapshot_response(&mut missing_target_state.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &missing_target_state,
            )
            .is_err()
        );
        let mut retained_complete = operation.clone();
        let mut retained_target = proof.runtime_pools[1].clone();
        retained_target.status = "decommissioned".to_string();
        retained_target.decommission_status = "complete".to_string();
        retained_target.decommission = Some(DecommissionProgress {
            start_time: Some("2026-09-05T00:00:00Z".to_string()),
            complete: true,
            objects_decommissioned: 1,
            bytes_decommissioned: 200,
            ..Default::default()
        });
        retained_complete.pools_after.pools.push(retained_target);
        retained_complete.pools_after.request = with_json_response(
            retained_complete.pools_after.request.clone(),
            &retained_complete.pools_after.pools,
        );
        validate_admin_topology_artifacts(
            ADMIN_DECOMMISSION_SCENARIO,
            &attempt(ADMIN_DECOMMISSION_SCENARIO),
            attempt_window(),
            &proof,
            &retained_complete,
        )
        .expect("a retained target may prove the exact completed decommission operation");

        for failed_counter in ["objects", "bytes"] {
            let mut failed_fragment = retained_complete.clone();
            let progress = failed_fragment.pools_after.pools[1]
                .decommission
                .as_mut()
                .unwrap();
            if failed_counter == "objects" {
                progress.objects_decommissioned_failed = 1;
            } else {
                progress.bytes_decommissioned_failed = 1;
            }
            sync_pool_snapshot_response(&mut failed_fragment.pools_after);
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_DECOMMISSION_SCENARIO,
                    &attempt(ADMIN_DECOMMISSION_SCENARIO),
                    attempt_window(),
                    &proof,
                    &failed_fragment,
                )
                .is_err(),
                "retained target {failed_counter} failures must fail closed"
            );
        }

        let mut missing_start_time = retained_complete.clone();
        missing_start_time.pools_after.pools[1]
            .decommission
            .as_mut()
            .unwrap()
            .start_time = None;
        sync_pool_snapshot_response(&mut missing_start_time.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &missing_start_time,
            )
            .is_err(),
            "a retained completed target must expose the operation start time"
        );
        for state in ["failed", "blocked"] {
            let mut unhealthy = operation.clone();
            unhealthy.pools_after.pools[0].status = state.to_string();
            sync_pool_snapshot_response(&mut unhealthy.pools_after);
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_DECOMMISSION_SCENARIO,
                    &attempt(ADMIN_DECOMMISSION_SCENARIO),
                    attempt_window(),
                    &proof,
                    &unhealthy,
                )
                .is_err(),
                "surviving pool state {state:?} must fail closed"
            );
        }
        for lifecycle in ["started", "stopping"] {
            let mut busy = operation.clone();
            busy.pools_after.pools[0].rebalance_status = lifecycle.to_string();
            sync_pool_snapshot_response(&mut busy.pools_after);
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_DECOMMISSION_SCENARIO,
                    &attempt(ADMIN_DECOMMISSION_SCENARIO),
                    attempt_window(),
                    &proof,
                    &busy,
                )
                .is_err(),
                "surviving pool lifecycle {lifecycle:?} must fail closed"
            );
        }
        operation.requests[0]
            .query
            .insert("pool".to_string(), "0".to_string());
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &operation,
            )
            .is_err()
        );
        operation.requests[0]
            .query
            .insert("pool".to_string(), "1".to_string());
        operation.canceled_or_stopped = true;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &operation,
            )
            .is_err()
        );
        operation.canceled_or_stopped = false;
        operation.requests.push(AdminRequestEvidence {
            target: fresh_request_target(240),
            runtime_probe: mutation_runtime_probe(240),
            method: "POST".to_string(),
            path: format!("{ADMIN_PREFIX}/pools/cancel"),
            query: BTreeMap::from([
                ("by-id".to_string(), "true".to_string()),
                ("pool".to_string(), "1".to_string()),
            ]),
            status: 200,
            started_at_ms: 240,
            observed_at_ms: 250,
            request_id: None,
            response_sha256: None,
            response_body: None,
        });
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &operation,
            )
            .is_err()
        );
        operation.requests.pop();
        for (path, query) in [
            (format!("{ADMIN_PREFIX}/rebalance/start"), BTreeMap::new()),
            (
                format!("{ADMIN_PREFIX}/pools/clear"),
                BTreeMap::from([
                    ("by-id".to_string(), "true".to_string()),
                    ("pool".to_string(), "1".to_string()),
                ]),
            ),
        ] {
            let mut injected_mutation = operation.clone();
            injected_mutation.requests.push(AdminRequestEvidence {
                target: fresh_request_target(240),
                runtime_probe: mutation_runtime_probe(240),
                method: "POST".to_string(),
                path,
                query,
                status: 200,
                started_at_ms: 240,
                observed_at_ms: 250,
                request_id: Some("unexpected-mutation-request".to_string()),
                response_sha256: None,
                response_body: None,
            });
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_DECOMMISSION_SCENARIO,
                    &attempt(ADMIN_DECOMMISSION_SCENARIO),
                    attempt_window(),
                    &proof,
                    &injected_mutation,
                )
                .is_err(),
                "a successful operation transcript must reject cross-scenario or clear mutations"
            );
        }
        operation.target_pool_expression = Some("/wrong".to_string());
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_DECOMMISSION_SCENARIO,
                &attempt(ADMIN_DECOMMISSION_SCENARIO),
                attempt_window(),
                &proof,
                &operation,
            )
            .is_err()
        );
    }

    #[test]
    fn progress_requires_one_operation_and_successful_terminal_sample() {
        let operation = AdminOperationEvidence {
            attempt: attempt(ADMIN_REBALANCE_SCENARIO),
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            operation_id: "rebalance-123".to_string(),
            target_pool_id: None,
            target_pool_expression: None,
            terminal_state: "completed".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            participating_pool_ids: vec![0],
            objects_moved: Some(2),
            versions_moved: Some(2),
            bytes_moved: Some(20),
            requests: rebalance_progress_requests(),
            pools_before: pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, pools()),
            pools_after: post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, pools()),
        };
        let mut samples = vec![
            AdminOperationProgressSample {
                attempt: attempt(ADMIN_REBALANCE_SCENARIO),
                operation_id: operation.operation_id.clone(),
                status_request_id: "rebalance-status-request-1".to_string(),
                observed_at_ms: 120,
                state: "started".to_string(),
                completed: false,
                failed: false,
                canceled_or_stopped: false,
                objects_moved: Some(1),
                versions_moved: Some(1),
                bytes_moved: Some(10),
            },
            AdminOperationProgressSample {
                attempt: attempt(ADMIN_REBALANCE_SCENARIO),
                operation_id: operation.operation_id.clone(),
                status_request_id: "rebalance-status-request-2".to_string(),
                observed_at_ms: 200,
                state: "completed".to_string(),
                completed: true,
                failed: false,
                canceled_or_stopped: false,
                objects_moved: Some(2),
                versions_moved: Some(2),
                bytes_moved: Some(20),
            },
        ];
        let valid_samples = samples.clone();

        validate_admin_operation_progress(&operation, &samples, attempt_window())
            .expect("terminal progress");
        samples[0].operation_id = "different".to_string();
        assert!(validate_admin_operation_progress(&operation, &samples, attempt_window()).is_err());
        samples[0].operation_id.clone_from(&operation.operation_id);
        samples[0].attempt.run_id = "different-run".to_string();
        assert!(validate_admin_operation_progress(&operation, &samples, attempt_window()).is_err());
        samples[0].attempt = operation.attempt.clone();
        samples[1].canceled_or_stopped = true;
        assert!(validate_admin_operation_progress(&operation, &samples, attempt_window()).is_err());

        let mut unknown = valid_samples.clone();
        unknown[0].state = "running".to_string();
        assert!(validate_admin_operation_progress(&operation, &unknown, attempt_window()).is_err());

        let mut unbound = valid_samples.clone();
        unbound.insert(
            1,
            AdminOperationProgressSample {
                status_request_id: "unknown-status-request".to_string(),
                observed_at_ms: 150,
                state: "started".to_string(),
                ..unbound[0].clone()
            },
        );
        assert!(validate_admin_operation_progress(&operation, &unbound, attempt_window()).is_err());

        let mut repeated_terminal_operation = operation.clone();
        repeated_terminal_operation
            .requests
            .push(AdminRequestEvidence {
                target: fresh_request_target(205),
                runtime_probe: None,
                method: "GET".to_string(),
                path: format!("{ADMIN_PREFIX}/rebalance/status"),
                query: BTreeMap::new(),
                status: 200,
                started_at_ms: 205,
                observed_at_ms: 210,
                request_id: Some("rebalance-status-request-3".to_string()),
                response_sha256: None,
                response_body: None,
            });
        let mut repeated_terminal = valid_samples.clone();
        repeated_terminal.push(AdminOperationProgressSample {
            status_request_id: "rebalance-status-request-3".to_string(),
            observed_at_ms: 210,
            ..repeated_terminal[1].clone()
        });
        assert!(
            validate_admin_operation_progress(
                &repeated_terminal_operation,
                &repeated_terminal,
                attempt_window(),
            )
            .is_err(),
            "a terminal state cannot be followed by another terminal sample"
        );

        let mut regressed = valid_samples.clone();
        let mut early_terminal = regressed[1].clone();
        early_terminal.observed_at_ms = 150;
        early_terminal.objects_moved = Some(1);
        early_terminal.versions_moved = Some(1);
        early_terminal.bytes_moved = Some(10);
        let mut resumed = regressed[0].clone();
        resumed.observed_at_ms = 175;
        regressed.insert(1, early_terminal);
        regressed.insert(2, resumed);
        assert!(
            validate_admin_operation_progress(&operation, &regressed, attempt_window()).is_err()
        );

        let mut mismatched_terminal = valid_samples.clone();
        mismatched_terminal[1].observed_at_ms = 199;
        assert!(
            validate_admin_operation_progress(&operation, &mismatched_terminal, attempt_window(),)
                .is_err()
        );

        let mut outside_attempt = operation.clone();
        outside_attempt.requests[0].started_at_ms = 49;
        assert!(
            validate_admin_operation_progress(&outside_attempt, &valid_samples, attempt_window(),)
                .is_err()
        );

        let mut status_before_start = operation.clone();
        status_before_start.requests.swap(0, 1);
        assert!(
            validate_admin_operation_progress(
                &status_before_start,
                &valid_samples,
                attempt_window(),
            )
            .is_err()
        );

        let mut overlapping_requests = operation.clone();
        overlapping_requests.requests[1].started_at_ms = 99;
        assert!(
            validate_admin_operation_progress(
                &overlapping_requests,
                &valid_samples,
                attempt_window(),
            )
            .is_err(),
            "status transport may not overlap the start transport"
        );
    }

    #[test]
    fn decommission_progress_uses_queued_running_complete_state_machine() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .unwrap();
        let status = DecommissionPoolStatus {
            id: 1,
            expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
            status: "complete".to_string(),
            pool_status: "decommissioned".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned: 2,
                bytes_decommissioned: 200,
                ..Default::default()
            }),
        };
        let operation = AdminOperationEvidence::from_decommission(
            &proof,
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone()),
            status,
            decommission_progress_requests(1),
            post_operation_snapshot(
                ADMIN_DECOMMISSION_SCENARIO,
                vec![proof.runtime_pools[0].clone()],
            ),
        )
        .unwrap();
        let mut samples = [
            ("queued", false, 110, 0, 0, "decommission-status-request-1"),
            (
                "running",
                false,
                150,
                1,
                100,
                "decommission-status-request-2",
            ),
            (
                "complete",
                true,
                200,
                2,
                200,
                "decommission-status-request-3",
            ),
        ]
        .into_iter()
        .map(
            |(state, completed, observed_at_ms, objects_moved, bytes_moved, status_request_id)| {
                AdminOperationProgressSample {
                    attempt: attempt(ADMIN_DECOMMISSION_SCENARIO),
                    operation_id: operation.operation_id.clone(),
                    status_request_id: status_request_id.to_string(),
                    observed_at_ms,
                    state: state.to_string(),
                    completed,
                    failed: false,
                    canceled_or_stopped: false,
                    objects_moved: Some(objects_moved),
                    versions_moved: None,
                    bytes_moved: Some(bytes_moved),
                }
            },
        )
        .collect::<Vec<_>>();

        validate_admin_operation_progress(&operation, &samples, attempt_window())
            .expect("valid decommission state progression");

        let mut wrong_terminal_request = operation.clone();
        wrong_terminal_request.requests.push(AdminRequestEvidence {
            target: fresh_request_target(205),
            runtime_probe: None,
            method: "GET".to_string(),
            path: format!("{ADMIN_PREFIX}/decommission/status"),
            query: BTreeMap::from([
                ("by-id".to_string(), "true".to_string()),
                ("pool".to_string(), "0".to_string()),
            ]),
            status: 200,
            started_at_ms: 205,
            observed_at_ms: 210,
            request_id: Some("wrong-pool-status-request".to_string()),
            response_sha256: None,
            response_body: None,
        });
        let mut wrong_target_samples = samples.clone();
        wrong_target_samples.last_mut().unwrap().status_request_id =
            "wrong-pool-status-request".to_string();
        wrong_target_samples.last_mut().unwrap().observed_at_ms = 210;
        assert!(
            validate_admin_operation_progress(
                &wrong_terminal_request,
                &wrong_target_samples,
                attempt_window(),
            )
            .is_err(),
            "terminal progress cannot bind to a status request for another pool"
        );

        samples[0].state = "started".to_string();
        assert!(validate_admin_operation_progress(&operation, &samples, attempt_window()).is_err());
    }

    #[test]
    fn rebalance_requires_stable_pool_identity() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_REBALANCE_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_REBALANCE_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_REBALANCE_SCENARIO),
        )
        .unwrap();
        let mut operation = AdminOperationEvidence {
            attempt: attempt(ADMIN_REBALANCE_SCENARIO),
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            operation_id: "rebalance-123".to_string(),
            target_pool_id: None,
            target_pool_expression: None,
            terminal_state: "completed".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            participating_pool_ids: vec![0],
            objects_moved: Some(2),
            versions_moved: Some(2),
            bytes_moved: Some(20),
            requests: vec![
                AdminRequestEvidence {
                    target: fresh_request_target(95),
                    runtime_probe: mutation_runtime_probe(95),
                    method: "POST".to_string(),
                    path: format!("{ADMIN_PREFIX}/rebalance/start"),
                    query: BTreeMap::new(),
                    status: 200,
                    started_at_ms: 95,
                    observed_at_ms: 100,
                    request_id: Some("rebalance-start-request".to_string()),
                    response_sha256: None,
                    response_body: None,
                },
                AdminRequestEvidence {
                    target: fresh_request_target(195),
                    runtime_probe: None,
                    method: "GET".to_string(),
                    path: format!("{ADMIN_PREFIX}/rebalance/status"),
                    query: BTreeMap::new(),
                    status: 200,
                    started_at_ms: 195,
                    observed_at_ms: 200,
                    request_id: Some("rebalance-status-request".to_string()),
                    response_sha256: None,
                    response_body: None,
                },
            ],
            pools_before: pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            pools_after: post_operation_snapshot(
                ADMIN_REBALANCE_SCENARIO,
                proof.runtime_pools.clone(),
            ),
        };
        let mut terminal_status = completed_rebalance_status("rebalance-123");
        terminal_status.pools[0].progress = Some(RebalanceProgress {
            objects: 2,
            versions: 2,
            bytes: 20,
            remaining_buckets: 0,
        });
        operation.requests[0] = with_json_response(
            operation.requests[0].clone(),
            &RebalanceStart {
                id: "rebalance-123".to_string(),
            },
        );
        operation.requests[1] = with_json_response(operation.requests[1].clone(), &terminal_status);
        validate_admin_topology_artifacts(
            ADMIN_REBALANCE_SCENARIO,
            &attempt(ADMIN_REBALANCE_SCENARIO),
            attempt_window(),
            &proof,
            &operation,
        )
        .unwrap();

        let mut missing_start_raw = operation.clone();
        missing_start_raw.requests[0].response_body = None;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &missing_start_raw,
            )
            .is_err(),
            "rebalance start must retain its raw RustFS response"
        );
        let mut drifted_start = operation.clone();
        drifted_start.requests[0] = with_json_response(
            drifted_start.requests[0].clone(),
            &RebalanceStart {
                id: "rebalance-other".to_string(),
            },
        );
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &drifted_start,
            )
            .is_err(),
            "rebalance operation ID must come from the captured start response"
        );

        let mut false_single_target = operation.clone();
        false_single_target.target_pool_id = Some(0);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &false_single_target,
            )
            .is_err()
        );

        for observed_at_ms in [199, 200] {
            let mut not_after_terminal = operation.clone();
            not_after_terminal.pools_after.observed_at_ms = observed_at_ms;
            not_after_terminal.pools_after.request.observed_at_ms = observed_at_ms;
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_REBALANCE_SCENARIO,
                    &attempt(ADMIN_REBALANCE_SCENARIO),
                    attempt_window(),
                    &proof,
                    &not_after_terminal,
                )
                .is_err(),
                "post-operation snapshot at {observed_at_ms} must be strictly after terminal status"
            );
        }
        let mut wrong_after_attempt = operation.clone();
        wrong_after_attempt.pools_after.attempt.tenant_uid = "old-tenant-uid".to_string();
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &wrong_after_attempt,
            )
            .is_err()
        );
        let mut failed_after_list = operation.clone();
        failed_after_list.pools_after.request.status = 500;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &failed_after_list,
            )
            .is_err()
        );
        let mut tenant_get_not_after_terminal = operation.clone();
        tenant_get_not_after_terminal
            .pools_after
            .tenant_get
            .started_at_ms = 200;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &tenant_get_not_after_terminal,
            )
            .is_err(),
            "post-operation Tenant GET must begin strictly after terminal status completes"
        );
        let mut tenant_get_equals_list_start = operation.clone();
        tenant_get_equals_list_start
            .pools_after
            .tenant_get
            .observed_at_ms = tenant_get_equals_list_start
            .pools_after
            .request
            .started_at_ms;
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &tenant_get_equals_list_start,
            )
            .is_err(),
            "post-operation Tenant GET must complete strictly before pools/list starts"
        );
        for state in ["failed", "blocked"] {
            let mut unhealthy = operation.clone();
            unhealthy.pools_after.pools[1].status = state.to_string();
            sync_pool_snapshot_response(&mut unhealthy.pools_after);
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_REBALANCE_SCENARIO,
                    &attempt(ADMIN_REBALANCE_SCENARIO),
                    attempt_window(),
                    &proof,
                    &unhealthy,
                )
                .is_err(),
                "post-rebalance pool state {state:?} must fail closed"
            );
        }
        for lifecycle in ["started", "stopping"] {
            let mut busy = operation.clone();
            busy.pools_after.pools[1].rebalance_status = lifecycle.to_string();
            sync_pool_snapshot_response(&mut busy.pools_after);
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_REBALANCE_SCENARIO,
                    &attempt(ADMIN_REBALANCE_SCENARIO),
                    attempt_window(),
                    &proof,
                    &busy,
                )
                .is_err(),
                "post-rebalance pool lifecycle {lifecycle:?} must fail closed"
            );
        }
        let mut completed_without_info = operation.clone();
        completed_without_info.pools_after.pools[1].decommission_status = "complete".to_string();
        sync_pool_snapshot_response(&mut completed_without_info.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &completed_without_info,
            )
            .is_err(),
            "an active idle pool cannot claim completed decommission without operation info"
        );
        for (field, value) in [("total", 0), ("current", 2_001), ("used", 2_001)] {
            let mut invalid_capacity = operation.clone();
            match field {
                "total" => invalid_capacity.pools_after.pools[0].total_size = value,
                "current" => invalid_capacity.pools_after.pools[0].current_size = value,
                "used" => invalid_capacity.pools_after.pools[0].used_size = value,
                _ => unreachable!(),
            }
            sync_pool_snapshot_response(&mut invalid_capacity.pools_after);
            assert!(
                validate_admin_topology_artifacts(
                    ADMIN_REBALANCE_SCENARIO,
                    &attempt(ADMIN_REBALANCE_SCENARIO),
                    attempt_window(),
                    &proof,
                    &invalid_capacity,
                )
                .is_err(),
                "invalid post-rebalance {field} capacity must fail closed"
            );
        }
        let mut inconsistent_sizes = operation.clone();
        inconsistent_sizes.pools_after.pools[0].used_size = 499;
        sync_pool_snapshot_response(&mut inconsistent_sizes.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &inconsistent_sizes,
            )
            .is_err(),
            "post-operation capacity parts cannot contradict the reported total"
        );
        let mut inconsistent_ratio = operation.clone();
        inconsistent_ratio.pools_after.pools[0].used = 0.4;
        sync_pool_snapshot_response(&mut inconsistent_ratio.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &inconsistent_ratio,
            )
            .is_err(),
            "post-operation used ratio must match usedSize/totalSize"
        );
        operation.pools_after.pools[1].expression = "/different".to_string();
        sync_pool_snapshot_response(&mut operation.pools_after);
        assert!(
            validate_admin_topology_artifacts(
                ADMIN_REBALANCE_SCENARIO,
                &attempt(ADMIN_REBALANCE_SCENARIO),
                attempt_window(),
                &proof,
                &operation,
            )
            .is_err()
        );
    }

    #[test]
    fn typed_status_models_match_rustfs_admin_wire_format() {
        let decommission: DecommissionPoolStatus = serde_json::from_str(
            r#"{"id":1,"cmdline":"/data/pool1/disk{1...4}","status":"running","poolStatus":"decommissioning","decommissionInfo":{"startTime":"2026-09-05T00:00:00Z","complete":false,"objectsDecommissioned":3}}"#,
        ).unwrap();
        assert_eq!(decommission.id, 1);
        assert_eq!(decommission.decommission.unwrap().objects_decommissioned, 3);

        let rebalance: RebalanceStatus = serde_json::from_str(
            r#"{"id":"rebalance-1","pools":[{"id":0,"status":"Completed","cleanupWarnings":{"count":0},"progress":{"objects":2,"versions":3,"bytes":128,"remainingBuckets":7}}]}"#,
        ).unwrap();
        assert_eq!(rebalance.id, "rebalance-1");
        assert_eq!(rebalance.pools[0].progress.as_ref().unwrap().versions, 3);
        assert_eq!(
            rebalance.pools[0]
                .progress
                .as_ref()
                .unwrap()
                .remaining_buckets,
            7
        );
    }

    #[test]
    fn decommission_terminal_builder_rejects_failed_moves_or_blocked_pool() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_DECOMMISSION_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_DECOMMISSION_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_DECOMMISSION_SCENARIO),
        )
        .unwrap();
        let status = DecommissionPoolStatus {
            id: 1,
            expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
            status: "complete".to_string(),
            pool_status: "decommissioned".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned_failed: 1,
                ..Default::default()
            }),
        };
        let evidence = AdminOperationEvidence::from_decommission(
            &proof,
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone()),
            status,
            decommission_requests(1),
            post_operation_snapshot(
                ADMIN_DECOMMISSION_SCENARIO,
                vec![proof.runtime_pools[0].clone()],
            ),
        )
        .unwrap();
        assert!(!evidence.completed);
        assert!(evidence.require_success(attempt_window()).is_err());

        let blocked = DecommissionPoolStatus {
            id: 1,
            expression: pool_expression(DECOMMISSION_TARGET_POOL_NAME),
            status: "complete".to_string(),
            pool_status: "blocked".to_string(),
            decommission: Some(DecommissionProgress {
                start_time: Some("2026-09-05T00:00:00Z".to_string()),
                complete: true,
                objects_decommissioned: 1,
                bytes_decommissioned: 200,
                ..Default::default()
            }),
        };
        let evidence = AdminOperationEvidence::from_decommission(
            &proof,
            pre_start_snapshot(ADMIN_DECOMMISSION_SCENARIO, proof.runtime_pools.clone()),
            blocked,
            decommission_requests(1),
            post_operation_snapshot(
                ADMIN_DECOMMISSION_SCENARIO,
                vec![proof.runtime_pools[0].clone()],
            ),
        )
        .unwrap();
        assert!(!evidence.completed);
        assert!(evidence.require_success(attempt_window()).is_err());
    }

    #[test]
    fn rebalance_accepts_completed_participant_and_none_nonparticipant() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_REBALANCE_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_REBALANCE_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_REBALANCE_SCENARIO),
        )
        .unwrap();
        let start = RebalanceStart {
            id: "rebalance-1".to_string(),
        };

        let mut status = completed_rebalance_status(&start.id);
        status.pools[0].progress.as_mut().unwrap().remaining_buckets = 7;
        let evidence = AdminOperationEvidence::from_rebalance(
            &proof,
            pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            &start,
            status,
            rebalance_requests(),
            post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
        )
        .expect("real RustFS mixed terminal status");

        assert_eq!(evidence.participating_pool_ids, vec![0]);
        assert_eq!(evidence.bytes_moved, Some(128));
        evidence
            .require_success(attempt_window())
            .expect("successful rebalance");
    }

    #[test]
    fn rebalance_rejects_zero_movement_extra_or_duplicate_pool_status() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_REBALANCE_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_REBALANCE_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_REBALANCE_SCENARIO),
        )
        .unwrap();
        let start = RebalanceStart {
            id: "rebalance-1".to_string(),
        };
        let mut no_movement = completed_rebalance_status(&start.id);
        no_movement.pools[0].progress = Some(RebalanceProgress::default());
        let evidence = AdminOperationEvidence::from_rebalance(
            &proof,
            pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            &start,
            no_movement,
            rebalance_requests(),
            post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
        )
        .expect("status remains representable");
        assert!(!evidence.completed);
        assert!(evidence.require_success(attempt_window()).is_err());

        let mut extra = completed_rebalance_status(&start.id);
        extra.pools.push(RebalancePoolStatus {
            id: 2,
            status: "None".to_string(),
            stopping: false,
            last_error: None,
            cleanup_warnings: RebalanceCleanupWarnings::default(),
            progress: None,
        });
        assert!(
            AdminOperationEvidence::from_rebalance(
                &proof,
                pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
                &start,
                extra,
                rebalance_requests(),
                post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            )
            .is_err()
        );

        for pool_index in [0, 1] {
            let mut cross_spelled = completed_rebalance_status(&start.id);
            cross_spelled.pools[pool_index].status = "Complete".to_string();
            let evidence = AdminOperationEvidence::from_rebalance(
                &proof,
                pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
                &start,
                cross_spelled,
                rebalance_requests(),
                post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            )
            .expect("unknown wire status remains representable as failed evidence");
            assert!(evidence.require_success(attempt_window()).is_err());
        }

        let mut duplicate = completed_rebalance_status(&start.id);
        duplicate.pools[1].id = 0;
        assert!(
            AdminOperationEvidence::from_rebalance(
                &proof,
                pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
                &start,
                duplicate,
                rebalance_requests(),
                post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            )
            .is_err()
        );
    }

    #[test]
    fn rebalance_terminal_builder_fails_closed_on_cleanup_warning() {
        let plan = AdminTopologyPlan::for_scenario(ADMIN_REBALANCE_SCENARIO).unwrap();
        let proof = AdminTopologyProof::build(
            &plan,
            ADMIN_REBALANCE_SCENARIO,
            &tenant(),
            pools(),
            &context(ADMIN_REBALANCE_SCENARIO),
        )
        .unwrap();
        let start = RebalanceStart {
            id: "rebalance-1".to_string(),
        };
        let status = RebalanceStatus {
            id: start.id.clone(),
            pools: vec![
                RebalancePoolStatus {
                    id: 0,
                    status: "Completed".to_string(),
                    stopping: false,
                    last_error: None,
                    cleanup_warnings: RebalanceCleanupWarnings {
                        count: 1,
                        last_message: Some("cleanup failed".to_string()),
                    },
                    progress: None,
                },
                RebalancePoolStatus {
                    id: 1,
                    status: "Completed".to_string(),
                    stopping: false,
                    last_error: None,
                    cleanup_warnings: RebalanceCleanupWarnings::default(),
                    progress: None,
                },
            ],
            stopped_at: None,
            stop_propagation: RebalanceStopPropagationStatus::default(),
        };
        let evidence = AdminOperationEvidence::from_rebalance(
            &proof,
            pre_start_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
            &start,
            status,
            rebalance_requests(),
            post_operation_snapshot(ADMIN_REBALANCE_SCENARIO, proof.runtime_pools.clone()),
        )
        .unwrap();
        assert!(evidence.failed);
        assert!(evidence.require_success(attempt_window()).is_err());
    }
}
