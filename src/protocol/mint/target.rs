// Copyright 2025 RustFS Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use k8s_openapi::api::{
    authorization::v1::{ResourceAttributes, SelfSubjectAccessReview, SelfSubjectAccessReviewSpec},
    core::v1::{Namespace, Pod, Service},
    discovery::v1::EndpointSlice,
};
use kube::{
    Api, Client, Error as KubeError, ResourceExt,
    api::{DeleteParams, ListParams, PostParams, Preconditions, PropagationPolicy},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::{process::Command, time::timeout};
use uuid::Uuid;

use super::API_VERSION;
use crate::{
    framework::kube_client::client_for_context,
    protocol::{
        clients::admin::RustfsAdminClient,
        credentials::{CredentialProvider, EnvCredentialProvider},
        suite_plan::TargetFingerprint,
    },
};

const TARGET_KIND: &str = "MintEphemeralTarget";
const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const TARGET_MANAGER: &str = "s3chaos-mint";
const RUN_ID_LABEL: &str = "rustfs.com/mint-run-id";
const EXPIRES_AT_ANNOTATION: &str = "rustfs.com/mint-expires-at";
const MAX_LEASE_SECONDS: i64 = 24 * 60 * 60;
const MAX_DIAGNOSTIC_BYTES: usize = 8 * 1024 * 1024;
const TARGET_PREFLIGHT_OPERATIONS: u64 = 5;
const DIAGNOSTIC_OPERATIONS: u64 = 5;
// The interruption path bounds Docker CLI termination, removes the owned
// container immediately, and performs the normal idempotent cleanup retry.
const CONTAINER_CLEANUP_OPERATIONS: u64 = 5;
const NAMESPACE_TEARDOWN_OPERATIONS: u64 = 2;
const SESSION_OPERATION_BUDGET_MULTIPLIER: u64 = TARGET_PREFLIGHT_OPERATIONS
    + DIAGNOSTIC_OPERATIONS
    + CONTAINER_CLEANUP_OPERATIONS
    + NAMESPACE_TEARDOWN_OPERATIONS;
const ADMIN_PREFLIGHT_SECONDS: u64 = 15;
const SESSION_LOCAL_OVERHEAD_SECONDS: u64 = 60;
const ENDPOINT_SLICE_SERVICE_LABEL: &str = "kubernetes.io/service-name";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetTimeouts {
    pub operation_seconds: u64,
    pub mint_seconds: u64,
    pub teardown_seconds: u64,
}

impl Default for MintTargetTimeouts {
    fn default() -> Self {
        Self {
            operation_seconds: 30,
            mint_seconds: 3_600,
            teardown_seconds: 300,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetDiscovery {
    pub context: String,
    pub namespace: String,
    pub service_name: String,
    pub server_endpoint: Option<String>,
    pub service_port: Option<u16>,
    #[serde(default)]
    pub enable_https: bool,
    pub region: String,
    pub rustfs_container: String,
    #[serde(default)]
    pub timeouts: MintTargetTimeouts,
}

/// Discovers an already-owned temporary target without modifying its resources.
pub async fn discover_mint_target(request: MintTargetDiscovery) -> Result<MintTargetSpec> {
    validate_timeouts(request.timeouts)?;
    validate_dns_label("Mint namespace", &request.namespace)?;
    validate_dns_label("Mint Service name", &request.service_name)?;
    validate_dns_label("RustFS container name", &request.rustfs_container)?;
    ensure_nonempty("Mint Kubernetes context", &request.context)?;
    ensure!(
        request.server_endpoint.is_some() || request.service_port.is_some(),
        "Mint discovery requires an explicit server endpoint or Service port"
    );
    let client = client_for_context(&request.context).await?;
    let deadline = Duration::from_secs(request.timeouts.operation_seconds);
    let namespace = timeout(
        deadline,
        Api::<Namespace>::all(client.clone()).get(&request.namespace),
    )
    .await
    .context("time out discovering Mint namespace")??;
    let pods = timeout(
        deadline,
        Api::<Pod>::namespaced(client.clone(), &request.namespace).list(&ListParams::default()),
    )
    .await
    .context("time out discovering Mint pods")??;
    let service = timeout(
        deadline,
        Api::<Service>::namespaced(client.clone(), &request.namespace).get(&request.service_name),
    )
    .await
    .context("time out discovering Mint Service")??;
    let slices = timeout(
        deadline,
        Api::<EndpointSlice>::namespaced(client, &request.namespace).list(
            &ListParams::default().labels(&format!(
                "{ENDPOINT_SLICE_SERVICE_LABEL}={}",
                request.service_name
            )),
        ),
    )
    .await
    .context("time out discovering Mint EndpointSlices")??;
    let now = timestamp_now()?;
    let mut spec = discovered_target_spec(
        &request,
        &namespace,
        &pods.items,
        &service,
        &slices.items,
        &now,
    )?;
    let fingerprint = timeout(
        Duration::from_secs(ADMIN_PREFLIGHT_SECONDS),
        read_mint_target_identity(&spec.server_endpoint, spec.enable_https, &spec.region),
    )
    .await
    .context("time out discovering Mint server identity")??;
    spec.target_fingerprint = fingerprint.sha256;
    let proof = validate_namespace_ownership(&spec, &namespace, &now)?;
    verify_mint_target_ready(&spec, &proof, &timestamp_now()?).await?;
    Ok(spec)
}

fn discovered_target_spec(
    request: &MintTargetDiscovery,
    namespace: &Namespace,
    pods: &[Pod],
    service: &Service,
    slices: &[EndpointSlice],
    now: &str,
) -> Result<MintTargetSpec> {
    ensure!(
        namespace.name_any() == request.namespace,
        "Mint namespace name changed during discovery"
    );
    let run_id = namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(RUN_ID_LABEL))
        .context("Mint namespace has no run-id label")?
        .clone();
    let expires_at = namespace
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(EXPIRES_AT_ANNOTATION))
        .context("Mint namespace has no lease expiry annotation")?
        .clone();
    let created_at = namespace
        .metadata
        .creation_timestamp
        .as_ref()
        .context("Mint namespace has no creation timestamp")?
        .0
        .to_rfc3339();
    let (server_endpoint, service_port) = match &request.server_endpoint {
        Some(endpoint) => {
            let endpoint = crate::protocol::suite::resolve_protocol_endpoint(
                &mint_admin_endpoint(endpoint, request.enable_https)?,
            )?;
            let url = reqwest::Url::parse(&endpoint).context("parse discovered Mint endpoint")?;
            let port = url
                .port_or_known_default()
                .context("Mint endpoint has no port")?;
            ensure!(
                request.service_port.is_none_or(|expected| expected == port),
                "Mint endpoint and explicit Service port disagree"
            );
            (
                format!(
                    "{}:{port}",
                    url.host().context("Mint endpoint has no host")?
                ),
                port,
            )
        }
        None => {
            let port = request
                .service_port
                .context("Mint discovery requires an explicit endpoint or Service port")?;
            (
                format!("{}.{}.svc:{port}", request.service_name, request.namespace),
                port,
            )
        }
    };
    let image_id = pods
        .iter()
        .filter_map(|pod| pod.status.as_ref())
        .filter_map(|status| status.container_statuses.as_ref())
        .flatten()
        .find(|container| container.name == request.rustfs_container)
        .context("Mint namespace has no matching RustFS container")?
        .image_id
        .clone();
    let image_digest = image_id
        .rsplit_once('@')
        .map_or(image_id.as_str(), |(_, digest)| digest)
        .to_string();
    let spec = MintTargetSpec {
        api_version: API_VERSION.to_string(),
        kind: TARGET_KIND.to_string(),
        run_id,
        context: request.context.clone(),
        namespace: request.namespace.clone(),
        namespace_uid: namespace
            .metadata
            .uid
            .clone()
            .context("Mint namespace has no UID")?,
        created_at,
        expires_at,
        server_endpoint,
        service_name: request.service_name.clone(),
        service_port,
        enable_https: request.enable_https,
        region: request.region.clone(),
        // Resource ownership is checked before credentials are sent to this endpoint.
        target_fingerprint: "0".repeat(64),
        rustfs_image_digest: image_digest,
        rustfs_container: request.rustfs_container.clone(),
        timeouts: request.timeouts,
    };
    spec.validate_at(now)?;
    validate_namespace_ownership(&spec, namespace, now)?;
    let proved_pods = validate_target_pods(&spec, pods)?;
    validate_target_service(&spec, service, slices, &proved_pods)?;
    Ok(spec)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetSpec {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub run_id: String,
    pub context: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub created_at: String,
    pub expires_at: String,
    pub server_endpoint: String,
    pub service_name: String,
    pub service_port: u16,
    pub enable_https: bool,
    pub region: String,
    pub target_fingerprint: String,
    pub rustfs_image_digest: String,
    pub rustfs_container: String,
    #[serde(default)]
    pub timeouts: MintTargetTimeouts,
}

impl MintTargetSpec {
    pub fn from_yaml(raw: &str, now: &str) -> Result<Self> {
        let spec: Self =
            serde_yaml_ng::from_str(raw).context("parse Mint ephemeral target spec")?;
        spec.validate_at(now)?;
        Ok(spec)
    }

    pub fn validate_at(&self, now: &str) -> Result<()> {
        self.validate_active_at(now)?;
        let expires_at = parse_timestamp(&self.expires_at, "Mint target expiresAt")?;
        let now = parse_timestamp(now, "current time")?;
        let required_seconds = self.required_session_seconds()?;
        ensure!(
            (expires_at - now).whole_seconds() >= required_seconds,
            "Mint target lease has insufficient remaining time: require {required_seconds}s for preflight, Mint, diagnostics, and teardown"
        );
        Ok(())
    }

    fn validate_active_at(&self, now: &str) -> Result<()> {
        self.validate_contract()?;
        let created_at = parse_timestamp(&self.created_at, "Mint target createdAt")?;
        let expires_at = parse_timestamp(&self.expires_at, "Mint target expiresAt")?;
        let now = parse_timestamp(now, "current time")?;
        ensure!(created_at <= now, "Mint target lease is not active yet");
        ensure!(now < expires_at, "Mint target lease has expired");
        Ok(())
    }

    fn required_session_seconds(&self) -> Result<i64> {
        let seconds = self
            .timeouts
            .operation_seconds
            .checked_mul(SESSION_OPERATION_BUDGET_MULTIPLIER)
            .and_then(|value| value.checked_add(self.timeouts.mint_seconds))
            .and_then(|value| value.checked_add(self.timeouts.teardown_seconds))
            .and_then(|value| value.checked_add(ADMIN_PREFLIGHT_SECONDS))
            .and_then(|value| value.checked_add(SESSION_LOCAL_OVERHEAD_SECONDS))
            .context("Mint session timeout budget overflow")?;
        i64::try_from(seconds).context("Mint session timeout budget exceeds i64")
    }

    pub fn validate_contract(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION && self.kind == TARGET_KIND,
            "invalid Mint ephemeral target contract"
        );
        validate_dns_label("Mint run id", &self.run_id)?;
        validate_dns_label("Mint namespace", &self.namespace)?;
        ensure_nonempty("Mint Kubernetes context", &self.context)?;
        ensure!(
            !self.context.contains(['\n', '\r', '\0']),
            "Mint Kubernetes context contains unsafe characters"
        );
        Uuid::parse_str(&self.namespace_uid)
            .context("Mint namespaceUid must be a Kubernetes UUID")?;
        ensure_nonempty("Mint server endpoint", &self.server_endpoint)?;
        validate_dns_label("Mint Service name", &self.service_name)?;
        ensure!(self.service_port > 0, "Mint Service port must be positive");
        ensure!(
            !self.server_endpoint.contains(['@', '\n', '\r', '\0'])
                && !self.server_endpoint.chars().any(char::is_whitespace),
            "Mint server endpoint contains credentials or unsafe characters"
        );
        let endpoint = mint_admin_endpoint(&self.server_endpoint, self.enable_https)?;
        let endpoint = reqwest::Url::parse(&endpoint).context("parse Mint server endpoint")?;
        ensure!(
            endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.host_str().is_some()
                && endpoint.port_or_known_default() == Some(self.service_port)
                && endpoint.path() == "/"
                && endpoint.query().is_none()
                && endpoint.fragment().is_none(),
            "Mint server endpoint must contain only an HTTP(S) authority on servicePort"
        );
        ensure_nonempty("Mint region", &self.region)?;
        validate_raw_sha256("Mint target fingerprint", &self.target_fingerprint)?;
        validate_prefixed_sha256("RustFS image digest", &self.rustfs_image_digest)?;
        validate_dns_label("RustFS container name", &self.rustfs_container)?;
        validate_timeouts(self.timeouts)?;

        let created_at = parse_timestamp(&self.created_at, "Mint target createdAt")?;
        let expires_at = parse_timestamp(&self.expires_at, "Mint target expiresAt")?;
        ensure!(
            created_at < expires_at,
            "Mint target lease must have positive duration"
        );
        ensure!(
            (expires_at - created_at).whole_seconds() <= MAX_LEASE_SECONDS,
            "Mint target lease must not exceed 24 hours"
        );
        Ok(())
    }

    pub fn container_name(&self) -> String {
        let uid_prefix = self.namespace_uid.get(..8).unwrap_or(&self.namespace_uid);
        format!("s3chaos-mint-{}-{uid_prefix}", self.run_id)
    }

    fn run_selector(&self) -> String {
        format!("{RUN_ID_LABEL}={}", self.run_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintNamespaceProof {
    pub context: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub run_id: String,
    pub expires_at: String,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintPodProof {
    pub name: String,
    pub uid: String,
    pub node_name: String,
    pub image_id: String,
    pub ready: bool,
    pub restart_count: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintServiceProof {
    pub name: String,
    pub uid: String,
    pub port: u16,
    pub endpoint_host: String,
    pub endpoint_slice_uids: Vec<String>,
    pub backend_pod_uids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetProof {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub namespace: MintNamespaceProof,
    pub namespace_pod_count: usize,
    pub rustfs_pods: Vec<MintPodProof>,
    pub service: MintServiceProof,
    pub rustfs_image_digest: String,
    pub delete_allowed: bool,
    pub server: TargetFingerprint,
    pub verified_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintTargetDiagnostic {
    pub file_name: String,
    pub contents: Vec<u8>,
    pub succeeded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MintTargetTeardownProof {
    #[serde(rename = "apiVersion")]
    pub api_version: String,
    pub kind: String,
    pub context: String,
    pub namespace: String,
    pub namespace_uid: String,
    pub requested_at: String,
    pub verified_absent_at: String,
    pub namespace_absent: bool,
}

pub async fn prove_mint_namespace(spec: &MintTargetSpec, now: &str) -> Result<MintNamespaceProof> {
    spec.validate_at(now)?;
    let client = client_for_context(&spec.context)
        .await
        .with_context(|| format!("connect to Kubernetes context {:?}", spec.context))?;
    let namespaces: Api<Namespace> = Api::all(client);
    let namespace = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        namespaces.get(&spec.namespace),
    )
    .await
    .context("time out reading Mint namespace ownership")??;
    validate_namespace_ownership(spec, &namespace, now)
}

pub async fn verify_mint_target_ready(
    spec: &MintTargetSpec,
    namespace_proof: &MintNamespaceProof,
    now: &str,
) -> Result<MintTargetProof> {
    validate_namespace_proof(spec, namespace_proof)?;
    spec.validate_active_at(now)?;
    let client = client_for_context(&spec.context)
        .await
        .with_context(|| format!("connect to Kubernetes context {:?}", spec.context))?;
    let pods_api: Api<Pod> = Api::namespaced(client.clone(), &spec.namespace);
    let pods = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        pods_api.list(&ListParams::default()),
    )
    .await
    .context("time out reading Mint namespace pods")??;
    let rustfs_pods = validate_target_pods(spec, &pods.items)?;
    let services: Api<Service> = Api::namespaced(client.clone(), &spec.namespace);
    let service = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        services.get(&spec.service_name),
    )
    .await
    .context("time out reading Mint Service ownership")??;
    let endpoint_slices: Api<EndpointSlice> = Api::namespaced(client.clone(), &spec.namespace);
    let slices = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        endpoint_slices.list(&ListParams::default().labels(&format!(
            "{ENDPOINT_SLICE_SERVICE_LABEL}={}",
            spec.service_name
        ))),
    )
    .await
    .context("time out reading Mint Service EndpointSlices")??;
    let service = validate_target_service(spec, &service, &slices.items, &rustfs_pods)?;
    ensure_namespace_delete_allowed(client, spec).await?;
    let server = timeout(
        Duration::from_secs(ADMIN_PREFLIGHT_SECONDS),
        inspect_mint_target(
            &spec.server_endpoint,
            spec.enable_https,
            &spec.region,
            &spec.target_fingerprint,
        ),
    )
    .await
    .context("time out querying the Mint target identity")??;

    Ok(MintTargetProof {
        api_version: API_VERSION.to_string(),
        kind: "MintTargetProof".to_string(),
        namespace: namespace_proof.clone(),
        namespace_pod_count: pods.items.len(),
        rustfs_pods,
        service,
        rustfs_image_digest: spec.rustfs_image_digest.clone(),
        delete_allowed: true,
        server,
        verified_at: now.to_string(),
    })
}

pub async fn collect_mint_target_diagnostics(spec: &MintTargetSpec) -> Vec<MintTargetDiagnostic> {
    let selector = spec.run_selector();
    let commands = [
        ("resources.txt", vec!["get", "all,pvc", "-o", "wide"], true),
        (
            "events.txt",
            vec!["get", "events", "--sort-by=.lastTimestamp"],
            true,
        ),
        (
            "rustfs-pods.txt",
            vec!["get", "pods", "-l", &selector, "-o", "wide"],
            true,
        ),
        (
            "rustfs-current.log",
            vec![
                "logs",
                "-l",
                &selector,
                "-c",
                &spec.rustfs_container,
                "--tail=500",
                "--prefix",
            ],
            true,
        ),
        (
            "rustfs-previous.log",
            vec![
                "logs",
                "-l",
                &selector,
                "-c",
                &spec.rustfs_container,
                "--previous",
                "--tail=500",
                "--prefix",
            ],
            false,
        ),
    ];

    let mut diagnostics = Vec::with_capacity(commands.len());
    for (file_name, args, required) in commands {
        let (contents, succeeded) =
            run_bounded_kubectl(spec, &args)
                .await
                .unwrap_or_else(|error| {
                    (
                        format!("diagnostic collection failed: {error}\n").into_bytes(),
                        false,
                    )
                });
        diagnostics.push(MintTargetDiagnostic {
            file_name: file_name.to_string(),
            contents,
            succeeded: succeeded || !required,
        });
    }
    diagnostics
}

pub async fn teardown_mint_target(
    spec: &MintTargetSpec,
    namespace_proof: &MintNamespaceProof,
    requested_at: &str,
) -> Result<MintTargetTeardownProof> {
    validate_namespace_proof(spec, namespace_proof)?;
    parse_timestamp(requested_at, "Mint teardown requestedAt")?;
    let client = client_for_context(&spec.context)
        .await
        .with_context(|| format!("connect to Kubernetes context {:?}", spec.context))?;
    let namespaces: Api<Namespace> = Api::all(client);

    let current = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        namespaces.get_opt(&spec.namespace),
    )
    .await
    .context("time out rechecking Mint namespace before teardown")??;
    if let Some(namespace) = current {
        validate_namespace_identity(spec, &namespace)?;
        let delete_params = DeleteParams {
            grace_period_seconds: Some(0),
            propagation_policy: Some(PropagationPolicy::Foreground),
            preconditions: Some(Preconditions {
                uid: Some(namespace_proof.namespace_uid.clone()),
                resource_version: None,
            }),
            ..DeleteParams::default()
        };
        let deletion = timeout(
            Duration::from_secs(spec.timeouts.operation_seconds),
            namespaces.delete(&spec.namespace, &delete_params),
        )
        .await
        .context("time out requesting Mint namespace deletion")?;
        if let Err(error) = deletion {
            ensure!(
                kube_error_is_not_found(&error),
                "delete exact Mint namespace: {error}"
            );
        }
    }

    timeout(Duration::from_secs(spec.timeouts.teardown_seconds), async {
        loop {
            match namespaces.get_opt(&spec.namespace).await {
                Ok(None) => return Ok::<(), anyhow::Error>(()),
                Ok(Some(namespace)) => {
                    validate_namespace_identity(spec, &namespace)?;
                }
                Err(error) if kube_error_is_not_found(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    })
    .await
    .context("time out waiting for Mint namespace to become absent")??;

    Ok(MintTargetTeardownProof {
        api_version: API_VERSION.to_string(),
        kind: "MintTargetTeardownProof".to_string(),
        context: spec.context.clone(),
        namespace: spec.namespace.clone(),
        namespace_uid: namespace_proof.namespace_uid.clone(),
        requested_at: requested_at.to_string(),
        verified_absent_at: timestamp_now()?,
        namespace_absent: true,
    })
}

pub async fn inspect_mint_target(
    server_endpoint: &str,
    enable_https: bool,
    region: &str,
    expected_fingerprint: &str,
) -> Result<TargetFingerprint> {
    let observed = read_mint_target_identity(server_endpoint, enable_https, region).await?;
    ensure!(
        observed.sha256 == expected_fingerprint,
        "refuse Mint because the dedicated target fingerprint changed: expected {expected_fingerprint}, observed {}",
        observed.sha256
    );
    Ok(observed)
}

async fn read_mint_target_identity(
    server_endpoint: &str,
    enable_https: bool,
    region: &str,
) -> Result<TargetFingerprint> {
    let endpoint = mint_admin_endpoint(server_endpoint, enable_https)?;
    let credentials = EnvCredentialProvider.resolve("root")?;
    let server_info = RustfsAdminClient::new(&endpoint, region, credentials)?
        .server_info()
        .await
        .context("query the live RustFS target identity for Mint")?;
    TargetFingerprint::new(
        endpoint,
        region,
        server_info.deployment_id,
        server_info.mode,
        server_info.region,
    )
}

pub async fn verify_mint_target(
    server_endpoint: &str,
    enable_https: bool,
    region: &str,
    expected_fingerprint: &str,
) -> Result<String> {
    let observed =
        inspect_mint_target(server_endpoint, enable_https, region, expected_fingerprint).await?;
    Ok(format!("sha256:{}", observed.sha256))
}

fn validate_namespace_ownership(
    spec: &MintTargetSpec,
    namespace: &Namespace,
    now: &str,
) -> Result<MintNamespaceProof> {
    spec.validate_active_at(now)?;
    validate_namespace_ownership_without_lease_time(spec, namespace)?;
    Ok(MintNamespaceProof {
        context: spec.context.clone(),
        namespace: spec.namespace.clone(),
        namespace_uid: spec.namespace_uid.clone(),
        run_id: spec.run_id.clone(),
        expires_at: spec.expires_at.clone(),
        verified_at: now.to_string(),
    })
}

fn validate_namespace_ownership_without_lease_time(
    spec: &MintTargetSpec,
    namespace: &Namespace,
) -> Result<()> {
    validate_namespace_identity(spec, namespace)?;
    ensure!(
        namespace.metadata.deletion_timestamp.is_none(),
        "refuse Mint target operation because namespace deletion is already in progress"
    );
    Ok(())
}

fn validate_namespace_identity(spec: &MintTargetSpec, namespace: &Namespace) -> Result<()> {
    let uid = namespace.metadata.uid.as_deref();
    let manager = namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(MANAGED_BY_LABEL))
        .map(String::as_str);
    let run_id = namespace
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(RUN_ID_LABEL))
        .map(String::as_str);
    let expires_at = namespace
        .metadata
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(EXPIRES_AT_ANNOTATION))
        .map(String::as_str);
    ensure!(
        namespace.name_any() == spec.namespace
            && uid == Some(spec.namespace_uid.as_str())
            && manager == Some(TARGET_MANAGER)
            && run_id == Some(spec.run_id.as_str())
            && expires_at == Some(spec.expires_at.as_str()),
        "refuse Mint target operation because namespace identity or ownership does not match the exact target spec"
    );
    Ok(())
}

fn validate_namespace_proof(spec: &MintTargetSpec, proof: &MintNamespaceProof) -> Result<()> {
    ensure!(
        proof.context == spec.context
            && proof.namespace == spec.namespace
            && proof.namespace_uid == spec.namespace_uid
            && proof.run_id == spec.run_id
            && proof.expires_at == spec.expires_at,
        "Mint namespace proof does not match the exact target spec"
    );
    Ok(())
}

fn validate_target_pods(spec: &MintTargetSpec, pods: &[Pod]) -> Result<Vec<MintPodProof>> {
    ensure!(!pods.is_empty(), "Mint target namespace has no pods");
    let mut rustfs_pods = Vec::new();
    for pod in pods {
        let pod_run_id = pod
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(RUN_ID_LABEL))
            .map(String::as_str);
        ensure!(
            pod_run_id == Some(spec.run_id.as_str()),
            "Mint target namespace contains a pod outside run ownership: {}",
            pod.name_any()
        );
        let Some(status) = &pod.status else {
            continue;
        };
        let Some(container_status) = status.container_statuses.as_ref().and_then(|statuses| {
            statuses
                .iter()
                .find(|status| status.name == spec.rustfs_container)
        }) else {
            continue;
        };
        let ready_condition = status.conditions.as_ref().is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        });
        let image_digest = container_status
            .image_id
            .rsplit_once('@')
            .map(|(_, digest)| digest)
            .unwrap_or(container_status.image_id.as_str());
        ensure!(
            image_digest == spec.rustfs_image_digest,
            "RustFS pod {} runs imageID {:?}, expected digest {}",
            pod.name_any(),
            container_status.image_id,
            spec.rustfs_image_digest
        );
        ensure!(
            container_status.ready && ready_condition,
            "RustFS pod {} is not Ready",
            pod.name_any()
        );
        let uid = pod
            .metadata
            .uid
            .clone()
            .with_context(|| format!("RustFS pod {} has no Kubernetes UID", pod.name_any()))?;
        rustfs_pods.push(MintPodProof {
            name: pod.name_any(),
            uid,
            node_name: pod
                .spec
                .as_ref()
                .and_then(|spec| spec.node_name.clone())
                .unwrap_or_default(),
            image_id: container_status.image_id.clone(),
            ready: true,
            restart_count: container_status.restart_count,
        });
    }
    ensure!(
        !rustfs_pods.is_empty(),
        "Mint target namespace has no Ready RustFS containers named {:?}",
        spec.rustfs_container
    );
    rustfs_pods.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(rustfs_pods)
}

fn validate_target_service(
    spec: &MintTargetSpec,
    service: &Service,
    endpoint_slices: &[EndpointSlice],
    rustfs_pods: &[MintPodProof],
) -> Result<MintServiceProof> {
    let service_uid = service
        .metadata
        .uid
        .clone()
        .context("Mint Service has no Kubernetes UID")?;
    let run_id = service
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(RUN_ID_LABEL))
        .map(String::as_str);
    let service_spec = service.spec.as_ref().context("Mint Service has no spec")?;
    let selector_run_id = service_spec
        .selector
        .as_ref()
        .and_then(|selector| selector.get(RUN_ID_LABEL))
        .map(String::as_str);
    ensure!(
        service.name_any() == spec.service_name
            && run_id == Some(spec.run_id.as_str())
            && selector_run_id == Some(spec.run_id.as_str()),
        "Mint Service identity, ownership, or run selector does not match the exact target spec"
    );

    let matching_ports = service_spec
        .ports
        .as_deref()
        .unwrap_or_default()
        .iter()
        .filter(|port| {
            port.port == i32::from(spec.service_port)
                && port.protocol.as_deref().unwrap_or("TCP") == "TCP"
        })
        .collect::<Vec<_>>();
    ensure!(
        matching_ports.len() == 1,
        "Mint Service must expose exactly one TCP port {}",
        spec.service_port
    );
    let service_port_name = matching_ports[0]
        .name
        .as_deref()
        .filter(|name| !name.is_empty());

    let (endpoint_host, endpoint_port) = mint_endpoint_authority(spec)?;
    ensure!(
        endpoint_port == spec.service_port,
        "Mint server endpoint port {endpoint_port} does not match Service port {}",
        spec.service_port
    );
    let mut service_addresses = BTreeSet::from([
        normalize_endpoint_host(&spec.service_name),
        normalize_endpoint_host(&format!("{}.{}", spec.service_name, spec.namespace)),
        normalize_endpoint_host(&format!("{}.{}.svc", spec.service_name, spec.namespace)),
        normalize_endpoint_host(&format!(
            "{}.{}.svc.cluster.local",
            spec.service_name, spec.namespace
        )),
    ]);
    for address in service_spec
        .cluster_ip
        .iter()
        .chain(service_spec.cluster_ips.iter().flatten())
        .chain(service_spec.external_ips.iter().flatten())
    {
        if !address.is_empty() && address != "None" {
            service_addresses.insert(normalize_endpoint_host(address));
        }
    }
    if let Some(ingresses) = service
        .status
        .as_ref()
        .and_then(|status| status.load_balancer.as_ref())
        .and_then(|load_balancer| load_balancer.ingress.as_ref())
    {
        for ingress in ingresses {
            for address in ingress.ip.iter().chain(ingress.hostname.iter()) {
                service_addresses.insert(normalize_endpoint_host(address));
            }
        }
    }
    ensure!(
        service_addresses.contains(&endpoint_host),
        "Mint server endpoint host {endpoint_host:?} is not an address or DNS name of Service {:?}",
        spec.service_name
    );

    ensure!(
        !endpoint_slices.is_empty(),
        "Mint Service has no EndpointSlices"
    );
    let proved_pods = rustfs_pods
        .iter()
        .map(|pod| (pod.uid.as_str(), pod.name.as_str()))
        .collect::<BTreeMap<_, _>>();
    let mut endpoint_slice_uids = BTreeSet::new();
    let mut backend_pod_uids = BTreeSet::new();
    let mut ready_backends = 0usize;
    for slice in endpoint_slices {
        let slice_uid =
            slice.metadata.uid.clone().with_context(|| {
                format!("EndpointSlice {} has no Kubernetes UID", slice.name_any())
            })?;
        let service_label = slice
            .metadata
            .labels
            .as_ref()
            .and_then(|labels| labels.get(ENDPOINT_SLICE_SERVICE_LABEL))
            .map(String::as_str);
        let owned_by_service = slice
            .metadata
            .owner_references
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|owner| {
                owner.api_version == "v1"
                    && owner.kind == "Service"
                    && owner.name == spec.service_name
                    && owner.uid == service_uid
                    && owner.controller == Some(true)
            });
        ensure!(
            service_label == Some(spec.service_name.as_str()) && owned_by_service,
            "EndpointSlice {} is not owned by the exact Mint Service UID",
            slice.name_any()
        );
        let exposes_service_port = slice
            .ports
            .as_deref()
            .unwrap_or_default()
            .iter()
            .any(|port| {
                port.port.is_some()
                    && port.protocol.as_deref().unwrap_or("TCP") == "TCP"
                    && match service_port_name {
                        Some(name) => port.name.as_deref() == Some(name),
                        None => port.name.as_deref().is_none_or(str::is_empty),
                    }
            });
        ensure!(
            exposes_service_port,
            "EndpointSlice {} does not expose the selected Mint Service port",
            slice.name_any()
        );
        endpoint_slice_uids.insert(slice_uid);

        for endpoint in &slice.endpoints {
            let target = endpoint.target_ref.as_ref().with_context(|| {
                format!(
                    "EndpointSlice {} contains an endpoint without a targetRef",
                    slice.name_any()
                )
            })?;
            let target_uid = target.uid.as_deref().with_context(|| {
                format!(
                    "EndpointSlice {} contains a Pod targetRef without a UID",
                    slice.name_any()
                )
            })?;
            let expected_name = proved_pods.get(target_uid).with_context(|| {
                format!(
                    "EndpointSlice {} targets unproved Pod UID {target_uid}",
                    slice.name_any()
                )
            })?;
            ensure!(
                target
                    .api_version
                    .as_deref()
                    .is_none_or(|api_version| api_version == "v1")
                    && target.kind.as_deref() == Some("Pod")
                    && target.namespace.as_deref() == Some(spec.namespace.as_str())
                    && target.name.as_deref() == Some(*expected_name),
                "EndpointSlice {} targetRef does not identify the proved RustFS Pod",
                slice.name_any()
            );
            backend_pod_uids.insert(target_uid.to_string());
            if endpoint
                .conditions
                .as_ref()
                .and_then(|conditions| conditions.ready)
                == Some(true)
            {
                ready_backends += 1;
            }
        }
    }
    ensure!(
        ready_backends > 0,
        "Mint Service has no Ready RustFS backend"
    );

    Ok(MintServiceProof {
        name: spec.service_name.clone(),
        uid: service_uid,
        port: spec.service_port,
        endpoint_host,
        endpoint_slice_uids: endpoint_slice_uids.into_iter().collect(),
        backend_pod_uids: backend_pod_uids.into_iter().collect(),
    })
}

async fn ensure_namespace_delete_allowed(client: Client, spec: &MintTargetSpec) -> Result<()> {
    let reviews: Api<SelfSubjectAccessReview> = Api::all(client);
    let review = SelfSubjectAccessReview {
        spec: SelfSubjectAccessReviewSpec {
            resource_attributes: Some(ResourceAttributes {
                group: Some(String::new()),
                resource: Some("namespaces".to_string()),
                version: Some("v1".to_string()),
                verb: Some("delete".to_string()),
                name: Some(spec.namespace.clone()),
                ..ResourceAttributes::default()
            }),
            ..SelfSubjectAccessReviewSpec::default()
        },
        ..SelfSubjectAccessReview::default()
    };
    let response = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        reviews.create(&PostParams::default(), &review),
    )
    .await
    .context("time out checking Mint namespace delete permission")??;
    let status = response
        .status
        .context("Kubernetes returned no namespace delete authorization status")?;
    ensure!(
        status.allowed,
        "Kubernetes identity cannot delete the exact Mint namespace"
    );
    Ok(())
}

async fn run_bounded_kubectl(spec: &MintTargetSpec, args: &[&str]) -> Result<(Vec<u8>, bool)> {
    let mut command = Command::new("kubectl");
    command
        .kill_on_drop(true)
        .arg("--context")
        .arg(&spec.context)
        .arg("-n")
        .arg(&spec.namespace)
        .args(args);
    let output = timeout(
        Duration::from_secs(spec.timeouts.operation_seconds),
        command.output(),
    )
    .await
    .with_context(|| format!("time out collecting kubectl diagnostic {args:?}"))??;
    let mut contents = format!("exit: {:?}\n\nstdout:\n", output.status.code()).into_bytes();
    contents.extend_from_slice(&output.stdout);
    contents.extend_from_slice(b"\n\nstderr:\n");
    contents.extend_from_slice(&output.stderr);
    ensure!(
        contents.len() <= MAX_DIAGNOSTIC_BYTES,
        "kubectl diagnostic {args:?} exceeds the {MAX_DIAGNOSTIC_BYTES} byte limit"
    );
    Ok((contents, output.status.success()))
}

fn mint_admin_endpoint(server_endpoint: &str, enable_https: bool) -> Result<String> {
    ensure!(
        !server_endpoint.trim().is_empty(),
        "Mint server endpoint must not be empty"
    );
    let scheme = if enable_https { "https" } else { "http" };
    if server_endpoint.contains("://") {
        let expected_prefix = format!("{scheme}://");
        ensure!(
            server_endpoint.starts_with(&expected_prefix),
            "Mint endpoint scheme disagrees with target enableHttps"
        );
        Ok(server_endpoint.to_string())
    } else {
        Ok(format!("{scheme}://{server_endpoint}"))
    }
}

pub(crate) fn mint_endpoint_authority(spec: &MintTargetSpec) -> Result<(String, u16)> {
    let endpoint = reqwest::Url::parse(&mint_admin_endpoint(
        &spec.server_endpoint,
        spec.enable_https,
    )?)
    .context("parse Mint server endpoint authority")?;
    let host = endpoint
        .host_str()
        .context("Mint server endpoint has no host")?;
    let port = endpoint
        .port_or_known_default()
        .context("Mint server endpoint has no explicit or scheme-default port")?;
    Ok((normalize_endpoint_host(host), port))
}

fn normalize_endpoint_host(host: &str) -> String {
    host.trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn validate_timeouts(timeouts: MintTargetTimeouts) -> Result<()> {
    ensure!(
        (5..=300).contains(&timeouts.operation_seconds),
        "Mint target operationSeconds must be between 5 and 300"
    );
    ensure!(
        (60..=14_400).contains(&timeouts.mint_seconds),
        "Mint target mintSeconds must be between 60 and 14400"
    );
    ensure!(
        (30..=1_800).contains(&timeouts.teardown_seconds),
        "Mint target teardownSeconds must be between 30 and 1800"
    );
    Ok(())
}

fn validate_dns_label(label: &str, value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= 63
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && value
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && value
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric),
        "{label} must be a lowercase DNS label"
    );
    Ok(())
}

fn validate_raw_sha256(label: &str, value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} must be exactly 64 lowercase hexadecimal characters"
    );
    Ok(())
}

fn validate_prefixed_sha256(label: &str, value: &str) -> Result<()> {
    let digest = value
        .strip_prefix("sha256:")
        .with_context(|| format!("{label} must start with sha256:"))?;
    validate_raw_sha256(label, digest)?;
    ensure!(
        !value.starts_with("sha256:sha256:"),
        "{label} contains a duplicate sha256 prefix"
    );
    Ok(())
}

fn ensure_nonempty(label: &str, value: &str) -> Result<()> {
    ensure!(!value.trim().is_empty(), "{label} must not be empty");
    Ok(())
}

fn parse_timestamp(value: &str, label: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(value, &Rfc3339)
        .with_context(|| format!("parse {label} {value:?} as RFC3339"))
}

pub fn timestamp_now() -> Result<String> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("format current UTC timestamp")
}

fn kube_error_is_not_found(error: &KubeError) -> bool {
    matches!(error, KubeError::Api(response) if response.code == 404)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::{
        core::v1::{
            ContainerStatus, ObjectReference, PodCondition, PodSpec, PodStatus, ServicePort,
            ServiceSpec,
        },
        discovery::v1::{Endpoint, EndpointConditions, EndpointPort},
    };
    use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
    use std::collections::BTreeMap;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
    const FINGERPRINT: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const UID: &str = "11111111-1111-4111-8111-111111111111";

    fn spec() -> MintTargetSpec {
        MintTargetSpec {
            api_version: API_VERSION.to_string(),
            kind: TARGET_KIND.to_string(),
            run_id: "mint-20260824-001".to_string(),
            context: "rustfs-mint".to_string(),
            namespace: "rustfs-mint-20260824-001".to_string(),
            namespace_uid: UID.to_string(),
            created_at: "2026-08-24T00:00:00Z".to_string(),
            expires_at: "2026-08-24T12:00:00Z".to_string(),
            server_endpoint: "rustfs.rustfs-mint-20260824-001.svc:9000".to_string(),
            service_name: "rustfs".to_string(),
            service_port: 9000,
            enable_https: false,
            region: "us-east-1".to_string(),
            target_fingerprint: FINGERPRINT.to_string(),
            rustfs_image_digest: DIGEST.to_string(),
            rustfs_container: "rustfs".to_string(),
            timeouts: MintTargetTimeouts::default(),
        }
    }

    fn discovery_request(spec: &MintTargetSpec) -> MintTargetDiscovery {
        MintTargetDiscovery {
            context: spec.context.clone(),
            namespace: spec.namespace.clone(),
            service_name: spec.service_name.clone(),
            server_endpoint: Some(spec.server_endpoint.clone()),
            service_port: Some(spec.service_port),
            enable_https: spec.enable_https,
            region: spec.region.clone(),
            rustfs_container: spec.rustfs_container.clone(),
            timeouts: spec.timeouts,
        }
    }

    #[test]
    fn discovery_collects_live_identity_and_preserves_resource_metadata() {
        let expected = spec();
        let request = discovery_request(&expected);
        let mut namespace = namespace(&expected);
        namespace.metadata.creation_timestamp =
            Some(serde_json::from_str("\"2026-08-24T00:00:00Z\"").expect("timestamp"));
        let original = serde_json::to_value(&namespace).expect("namespace before discovery");
        let pod = pod(&expected, "rustfs-0");
        let discovered = discovered_target_spec(
            &request,
            &namespace,
            std::slice::from_ref(&pod),
            &service(&expected),
            &[endpoint_slice(&expected, &pod)],
            "2026-08-24T01:00:00Z",
        )
        .expect("discover target");
        assert_eq!(discovered.namespace_uid, expected.namespace_uid);
        assert_eq!(discovered.run_id, expected.run_id);
        assert_eq!(discovered.expires_at, expected.expires_at);
        assert_eq!(discovered.rustfs_image_digest, expected.rustfs_image_digest);
        assert_eq!(discovered.server_endpoint, expected.server_endpoint);
        assert_eq!(
            serde_json::to_value(namespace).expect("namespace after discovery"),
            original
        );
    }

    #[test]
    fn discovery_rejects_foreign_endpoint_expired_lease_and_unowned_resources() {
        let expected = spec();
        let mut request = discovery_request(&expected);
        let mut namespace = namespace(&expected);
        namespace.metadata.creation_timestamp =
            Some(serde_json::from_str("\"2026-08-24T00:00:00Z\"").expect("timestamp"));
        let pod = pod(&expected, "rustfs-0");
        let service = service(&expected);
        let slices = [endpoint_slice(&expected, &pod)];
        let discover = |request: &MintTargetDiscovery, namespace: &Namespace, now: &str| {
            discovered_target_spec(
                request,
                namespace,
                std::slice::from_ref(&pod),
                &service,
                &slices,
                now,
            )
        };
        request.server_endpoint = Some("unrelated.example:9000".into());
        assert!(discover(&request, &namespace, "2026-08-24T01:00:00Z").is_err());
        request.server_endpoint = Some(expected.server_endpoint.clone());
        request.service_port = Some(9001);
        assert!(discover(&request, &namespace, "2026-08-24T01:00:00Z").is_err());
        request.service_port = Some(expected.service_port);
        assert!(discover(&request, &namespace, "2026-08-24T13:00:00Z").is_err());
        namespace
            .metadata
            .labels
            .as_mut()
            .expect("labels")
            .remove(MANAGED_BY_LABEL);
        assert!(discover(&request, &namespace, "2026-08-24T01:00:00Z").is_err());
    }

    #[tokio::test]
    async fn discovery_requires_explicit_endpoint_or_port_before_connecting() {
        let mut request = discovery_request(&spec());
        request.server_endpoint = None;
        request.service_port = None;
        let error = discover_mint_target(request)
            .await
            .expect_err("missing endpoint selection");
        assert!(
            error
                .to_string()
                .contains("explicit server endpoint or Service port")
        );
    }

    fn namespace(spec: &MintTargetSpec) -> Namespace {
        Namespace {
            metadata: ObjectMeta {
                name: Some(spec.namespace.clone()),
                uid: Some(spec.namespace_uid.clone()),
                labels: Some(BTreeMap::from([
                    (MANAGED_BY_LABEL.to_string(), TARGET_MANAGER.to_string()),
                    (RUN_ID_LABEL.to_string(), spec.run_id.clone()),
                ])),
                annotations: Some(BTreeMap::from([(
                    EXPIRES_AT_ANNOTATION.to_string(),
                    spec.expires_at.clone(),
                )])),
                ..ObjectMeta::default()
            },
            ..Namespace::default()
        }
    }

    fn pod(spec: &MintTargetSpec, name: &str) -> Pod {
        Pod {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                uid: Some(format!("{name}-uid")),
                labels: Some(BTreeMap::from([(
                    RUN_ID_LABEL.to_string(),
                    spec.run_id.clone(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(PodSpec {
                node_name: Some("node-1".to_string()),
                ..PodSpec::default()
            }),
            status: Some(PodStatus {
                conditions: Some(vec![PodCondition {
                    status: "True".to_string(),
                    type_: "Ready".to_string(),
                    ..PodCondition::default()
                }]),
                container_statuses: Some(vec![ContainerStatus {
                    image: "rustfs/rustfs:unused".to_string(),
                    image_id: format!("docker-pullable://rustfs/rustfs@{DIGEST}"),
                    name: spec.rustfs_container.clone(),
                    ready: true,
                    restart_count: 0,
                    ..ContainerStatus::default()
                }]),
                ..PodStatus::default()
            }),
        }
    }

    fn service(spec: &MintTargetSpec) -> Service {
        Service {
            metadata: ObjectMeta {
                name: Some(spec.service_name.clone()),
                uid: Some("service-uid".to_string()),
                labels: Some(BTreeMap::from([(
                    RUN_ID_LABEL.to_string(),
                    spec.run_id.clone(),
                )])),
                ..ObjectMeta::default()
            },
            spec: Some(ServiceSpec {
                cluster_ip: Some("10.96.0.10".to_string()),
                ports: Some(vec![ServicePort {
                    name: Some("s3".to_string()),
                    port: i32::from(spec.service_port),
                    protocol: Some("TCP".to_string()),
                    ..ServicePort::default()
                }]),
                selector: Some(BTreeMap::from([(
                    RUN_ID_LABEL.to_string(),
                    spec.run_id.clone(),
                )])),
                ..ServiceSpec::default()
            }),
            ..Service::default()
        }
    }

    fn endpoint_slice(spec: &MintTargetSpec, pod: &Pod) -> EndpointSlice {
        EndpointSlice {
            address_type: "IPv4".to_string(),
            endpoints: vec![Endpoint {
                addresses: vec!["10.42.0.10".to_string()],
                conditions: Some(EndpointConditions {
                    ready: Some(true),
                    ..EndpointConditions::default()
                }),
                target_ref: Some(ObjectReference {
                    api_version: Some("v1".to_string()),
                    kind: Some("Pod".to_string()),
                    name: pod.metadata.name.clone(),
                    namespace: Some(spec.namespace.clone()),
                    uid: pod.metadata.uid.clone(),
                    ..ObjectReference::default()
                }),
                ..Endpoint::default()
            }],
            metadata: ObjectMeta {
                name: Some("rustfs-abcde".to_string()),
                uid: Some("endpoint-slice-uid".to_string()),
                labels: Some(BTreeMap::from([(
                    ENDPOINT_SLICE_SERVICE_LABEL.to_string(),
                    spec.service_name.clone(),
                )])),
                owner_references: Some(vec![OwnerReference {
                    api_version: "v1".to_string(),
                    controller: Some(true),
                    kind: "Service".to_string(),
                    name: spec.service_name.clone(),
                    uid: "service-uid".to_string(),
                    ..OwnerReference::default()
                }]),
                ..ObjectMeta::default()
            },
            ports: Some(vec![EndpointPort {
                name: Some("s3".to_string()),
                port: Some(9000),
                protocol: Some("TCP".to_string()),
                ..EndpointPort::default()
            }]),
        }
    }

    #[test]
    fn target_spec_requires_a_current_short_lived_exact_lease() {
        spec()
            .validate_at("2026-08-24T01:00:00Z")
            .expect("active lease");
        assert_eq!(spec().required_session_seconds().expect("budget"), 4_485);
        assert!(spec().validate_at("2026-08-24T13:00:00Z").is_err());
        let insufficient = spec()
            .validate_at("2026-08-24T11:00:00Z")
            .expect_err("lease cannot cover a full Mint session");
        assert!(
            insufficient
                .to_string()
                .contains("insufficient remaining time")
        );
        let mut long = spec();
        long.expires_at = "2026-08-26T00:00:00Z".to_string();
        assert!(long.validate_at("2026-08-24T01:00:00Z").is_err());

        let mut prefixed_fingerprint = spec();
        prefixed_fingerprint.target_fingerprint = format!("sha256:{FINGERPRINT}");
        assert!(prefixed_fingerprint.validate_contract().is_err());

        let mut unprefixed_image = spec();
        unprefixed_image.rustfs_image_digest = DIGEST.trim_start_matches("sha256:").to_string();
        assert!(unprefixed_image.validate_contract().is_err());

        let mut credential_endpoint = spec();
        credential_endpoint.server_endpoint = "admin:secret@rustfs.example:9000".to_string();
        assert!(credential_endpoint.validate_contract().is_err());

        let mut wrong_service_port = spec();
        wrong_service_port.service_port = 9001;
        assert!(wrong_service_port.validate_contract().is_err());
    }

    #[test]
    fn namespace_ownership_requires_uid_run_and_expiry() {
        let spec = spec();
        validate_namespace_ownership(&spec, &namespace(&spec), "2026-08-24T01:00:00Z")
            .expect("owned namespace");

        let mut wrong = namespace(&spec);
        wrong.metadata.uid = Some("22222222-2222-4222-8222-222222222222".to_string());
        assert!(validate_namespace_ownership(&spec, &wrong, "2026-08-24T01:00:00Z").is_err());
    }

    #[test]
    fn pod_proof_rejects_foreign_unready_and_image_drift() {
        let spec = spec();
        assert_eq!(
            validate_target_pods(&spec, &[pod(&spec, "rustfs-0")])
                .expect("ready pod")
                .len(),
            1
        );

        let mut foreign = pod(&spec, "foreign");
        foreign.metadata.labels = None;
        assert!(validate_target_pods(&spec, &[foreign]).is_err());

        let mut drifted = pod(&spec, "drifted");
        drifted
            .status
            .as_mut()
            .and_then(|status| status.container_statuses.as_mut())
            .expect("statuses")[0]
            .image_id =
            "rustfs/rustfs@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                .to_string();
        assert!(validate_target_pods(&spec, &[drifted]).is_err());

        let mut missing_uid = pod(&spec, "missing-uid");
        missing_uid.metadata.uid = None;
        assert!(validate_target_pods(&spec, &[missing_uid]).is_err());
    }

    #[test]
    fn service_proof_binds_endpoint_slices_to_proved_pod_uids() {
        let spec = spec();
        let pod = pod(&spec, "rustfs-0");
        let pod_proofs = validate_target_pods(&spec, std::slice::from_ref(&pod)).expect("pods");
        let service = service(&spec);
        let slice = endpoint_slice(&spec, &pod);
        let proof =
            validate_target_service(&spec, &service, std::slice::from_ref(&slice), &pod_proofs)
                .expect("Service-backed endpoint");
        assert_eq!(proof.backend_pod_uids, vec!["rustfs-0-uid"]);

        let mut omitted_api_version = endpoint_slice(&spec, &pod);
        omitted_api_version.endpoints[0]
            .target_ref
            .as_mut()
            .expect("targetRef")
            .api_version = None;
        validate_target_service(&spec, &service, &[omitted_api_version], &pod_proofs)
            .expect("Kubernetes may omit core/v1 from an EndpointSlice targetRef");

        let mut wrong_api_version = endpoint_slice(&spec, &pod);
        wrong_api_version.endpoints[0]
            .target_ref
            .as_mut()
            .expect("targetRef")
            .api_version = Some("apps/v1".to_string());
        assert!(
            validate_target_service(&spec, &service, &[wrong_api_version], &pod_proofs).is_err()
        );

        let mut foreign = slice;
        foreign.endpoints[0]
            .target_ref
            .as_mut()
            .expect("targetRef")
            .uid = Some("foreign-pod-uid".to_string());
        assert!(validate_target_service(&spec, &service, &[foreign], &pod_proofs).is_err());

        let mut foreign_owner = endpoint_slice(&spec, &pod);
        foreign_owner
            .metadata
            .owner_references
            .as_mut()
            .expect("ownerReferences")[0]
            .uid = "foreign-service-uid".to_string();
        assert!(validate_target_service(&spec, &service, &[foreign_owner], &pod_proofs).is_err());

        let mut outside = spec.clone();
        outside.server_endpoint = "different.example:9000".to_string();
        assert!(
            validate_target_service(
                &outside,
                &service,
                &[endpoint_slice(&spec, &pod)],
                &pod_proofs
            )
            .is_err()
        );
    }

    #[test]
    fn admin_endpoint_matches_target_transport() {
        assert_eq!(
            mint_admin_endpoint("rustfs.example:9000", false).expect("HTTP endpoint"),
            "http://rustfs.example:9000"
        );
        assert_eq!(
            mint_admin_endpoint("https://rustfs.example:9000", true).expect("HTTPS endpoint"),
            "https://rustfs.example:9000"
        );
        assert!(mint_admin_endpoint("https://rustfs.example:9000", false).is_err());
    }
}
