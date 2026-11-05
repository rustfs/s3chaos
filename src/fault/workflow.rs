// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

//! Durable ownership for supervised fault runs. A missing heartbeat never
//! transfers ownership: only the original supervisor can complete execution.

use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};
use k8s_openapi::api::{
    coordination::v1::{Lease, LeaseSpec},
    core::v1::Namespace,
};
use kube::{
    Api, Client, Config, ResourceExt,
    api::{DeleteParams, ListParams, Patch, PatchParams, PostParams, Preconditions},
    config::{KubeConfigOptions, Kubeconfig},
    core::{ApiResource, DynamicObject, GroupVersionKind, ObjectMeta},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::framework::{
    config::ClusterTestConfig,
    kubectl::Kubectl,
    process_identity::{ProcessIdentity, parent_pid},
};

const SESSION_FILE: &str = "fault-session.json";
const LEASE_NAMESPACE: &str = "kube-system";
const LEASE_NAME: &str = "s3chaos-fault-session";
pub(crate) const RUN_ANNOTATION: &str = "s3chaos.rustfs.com/session-run";
const MANAGER: &str = "app.kubernetes.io/managed-by";
const TENANT_ANNOTATION: &str = "rustfs.com/fault-test-tenant";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Ownership {
    Created,
    Reused,
    External,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ResourceRecord {
    api_version: String,
    kind: String,
    namespace: Option<String>,
    name: String,
    uid: Option<String>,
    ownership: Ownership,
    /// Unknown includes a request accepted remotely without a local response.
    state: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Session {
    schema_version: u32,
    run_id: String,
    context: String,
    api_server: String,
    ca_sha256: String,
    cluster_uid: String,
    namespace: String,
    tenant: String,
    chaos_namespace: String,
    operator_namespace: String,
    supervisor: ProcessIdentity,
    lease_uid: Option<String>,
    status: String,
    exit_code: Option<i32>,
    keep_resources: bool,
    resources: BTreeMap<String, ResourceRecord>,
}

fn persist(root: &Path, session: &Session) -> Result<()> {
    durable_json(root, SESSION_FILE, session)
}

fn durable_json(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    let destination = root.join(name);
    let temporary = root.join(format!(".{name}-{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        file.write_all(&serde_json::to_vec_pretty(value)?)?;
        file.sync_all()?;
        fs::rename(&temporary, &destination)?;
        File::open(root)?.sync_all()?;
        Ok::<_, anyhow::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.context("persist fault session before changing cluster resources")
}

fn load(root: &Path) -> Result<Session> {
    let session: Session = serde_json::from_slice(&fs::read(root.join(SESSION_FILE))?)?;
    ensure!(
        session.schema_version == 1,
        "unsupported fault session version"
    );
    ensure!(!session.run_id.is_empty(), "fault session has no run ID");
    Ok(session)
}

fn journal_lock(root: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join(".fault-session-lock"))?;
    file.lock()?;
    Ok(file)
}

pub(crate) fn record_images(config: &ClusterTestConfig, pods: &Value) -> Result<()> {
    let Some(root) = std::env::var_os("S3CHAOS_RUN_ROOT").map(PathBuf::from) else {
        return Ok(());
    };
    let Some(images) = ready_images(pods) else {
        return Ok(());
    };
    let _lock = journal_lock(&root)?;
    let path = root.join("fault-image.json");
    let previous: Option<Value> = match fs::read(&path) {
        Ok(bytes) => Some(serde_json::from_slice(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let value = image_record(previous.as_ref(), &config.rustfs_image, images)?;
    if previous.as_ref() != Some(&value) {
        durable_json(&root, "fault-image.json", &value)?;
    }
    Ok(())
}

fn image_record(
    previous: Option<&Value>,
    requested: &str,
    images: Vec<(String, String)>,
) -> Result<Value> {
    let mut observed = std::collections::BTreeSet::new();
    if let Some(previous) = previous {
        ensure!(
            previous["requestedImage"].as_str() == Some(requested),
            "requested RustFS image changed within the recorded run"
        );
        for container in previous["containers"]
            .as_array()
            .context("recorded image containers are missing")?
        {
            observed.insert((
                container["image"]
                    .as_str()
                    .context("recorded container image is missing")?
                    .to_string(),
                container["imageID"]
                    .as_str()
                    .context("recorded image ID is missing")?
                    .to_string(),
            ));
        }
    }
    observed.extend(images);
    Ok(
        json!({"requestedImage": requested, "containers": observed.into_iter().map(|(image, image_id)| json!({"image":image,"imageID":image_id})).collect::<Vec<_>>()}),
    )
}

fn ready_images(pods: &Value) -> Option<Vec<(String, String)>> {
    let items = pods["items"].as_array().filter(|items| !items.is_empty())?;
    items
        .iter()
        .map(|pod| {
            if pod["status"]["phase"] != "Running"
                || !pod["metadata"]["deletionTimestamp"].is_null()
            {
                return None;
            }
            let container = pod["spec"]["containers"]
                .as_array()?
                .iter()
                .find(|container| container["name"] == "rustfs")?;
            let status = pod["status"]["containerStatuses"]
                .as_array()?
                .iter()
                .find(|container| container["name"] == "rustfs" && container["ready"] == true)?;
            Some((
                container["image"].as_str()?.to_string(),
                status["imageID"].as_str().unwrap_or_default().to_string(),
            ))
        })
        .collect()
}

fn key(kind: &str, namespace: Option<&str>, name: &str) -> String {
    format!("{kind}/{}/{name}", namespace.unwrap_or_default())
}

fn record(value: &Value, ownership: Ownership, state: &str) -> Result<ResourceRecord> {
    Ok(ResourceRecord {
        api_version: value["apiVersion"]
            .as_str()
            .context("resource API version is missing")?
            .to_string(),
        kind: value["kind"]
            .as_str()
            .context("resource kind is missing")?
            .to_string(),
        namespace: value["metadata"]["namespace"].as_str().map(str::to_string),
        name: value["metadata"]["name"]
            .as_str()
            .context("resource name is missing")?
            .to_string(),
        uid: value["metadata"]["uid"].as_str().map(str::to_string),
        ownership,
        state: state.to_string(),
    })
}

fn owned(value: &Value, run_id: &str) -> bool {
    value["metadata"]["annotations"][RUN_ANNOTATION].as_str() == Some(run_id)
}

fn validate_identity(entry: &ResourceRecord, value: &Value, run_id: &str) -> Result<()> {
    ensure!(
        owned(value, run_id),
        "resource {} belongs to another run",
        entry.name
    );
    let uid = value["metadata"]["uid"]
        .as_str()
        .context("resource UID is missing")?;
    if let Some(expected) = &entry.uid {
        ensure!(
            uid == expected,
            "resource {} was replaced: recorded UID {}, current UID {uid}",
            entry.name,
            expected
        );
    } else {
        ensure!(
            entry.ownership == Ownership::Created && entry.state == "unknown",
            "resource {} has no creation proof",
            entry.name
        );
    }
    Ok(())
}

async fn connection(context: &str) -> Result<(Client, String, String)> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = Config::from_custom_kubeconfig(
        Kubeconfig::read()?,
        &KubeConfigOptions {
            context: Some(context.to_string()),
            ..Default::default()
        },
    )
    .await?;
    let endpoint = config.cluster_url.to_string();
    let mut digest = Sha256::new();
    for cert in config.root_cert.iter().flatten() {
        digest.update(cert);
    }
    let ca = hex::encode(digest.finalize());
    Ok((Client::try_from(config)?, endpoint, ca))
}

async fn verified_client(session: &Session) -> Result<Client> {
    let (client, endpoint, ca) = connection(&session.context).await?;
    ensure!(
        endpoint == session.api_server && ca == session.ca_sha256,
        "cluster endpoint or CA differs from the recorded fault session"
    );
    let system: Namespace = Api::all(client.clone()).get(LEASE_NAMESPACE).await?;
    ensure!(
        system.uid().as_deref() == Some(session.cluster_uid.as_str()),
        "cluster UID differs from the recorded fault session"
    );
    Ok(client)
}

fn lease_owned(lease: &Lease, session: &Session) -> Result<()> {
    ensure!(
        lease
            .spec
            .as_ref()
            .and_then(|s| s.holder_identity.as_deref())
            == Some(session.run_id.as_str()),
        "cluster is reserved by another fault run; expired sessions are never taken over automatically"
    );
    if let Some(uid) = &session.lease_uid {
        ensure!(
            lease.uid().as_deref() == Some(uid),
            "fault session Lease was replaced"
        );
    }
    Ok(())
}

async fn require_lease(client: Client, session: &mut Session, root: &Path) -> Result<Lease> {
    let lease: Lease = Api::namespaced(client, LEASE_NAMESPACE)
        .get(LEASE_NAME)
        .await?;
    lease_owned(&lease, session)?;
    if session.lease_uid.is_none() {
        session.lease_uid = lease.uid();
        persist(root, session)?;
    }
    Ok(lease)
}

/// Called by the foreground shell after read-only preflight, before any fixture mutation.
pub async fn begin(root: &Path, run_id: &str, supervisor_pid: u32) -> Result<()> {
    ensure!(
        !run_id.is_empty()
            && run_id.len() <= 128
            && run_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)),
        "invalid fault run ID"
    );
    ensure!(
        parent_pid() == Some(supervisor_pid),
        "fault session must be started by its supervisor"
    );
    ensure!(
        !root.join(SESSION_FILE).exists(),
        "fault session already exists; use its report or cleanup command"
    );
    fs::create_dir_all(root)?;
    let mut reservation = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(root.join(".fault-session-owner"))
        .context("run directory is already reserved")?;
    reservation.write_all(run_id.as_bytes())?;
    reservation.sync_all()?;
    File::open(root)?.sync_all()?;
    let context = std::env::var("S3CHAOS_TARGET_CONTEXT")
        .or_else(|_| std::env::var("RUSTFS_FAULT_TEST_EXPECTED_CONTEXT"))
        .context("fault session requires an explicit context")?;
    let (client, api_server, ca_sha256) = connection(&context).await?;
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let cluster_uid = namespaces
        .get(LEASE_NAMESPACE)
        .await?
        .uid()
        .context("cluster namespace has no UID")?;
    let mut session = Session {
        schema_version: 1,
        run_id: run_id.to_string(),
        context,
        api_server,
        ca_sha256,
        cluster_uid,
        namespace: std::env::var("RUSTFS_FAULT_TEST_NAMESPACE")
            .unwrap_or_else(|_| "rustfs-fault-test".into()),
        tenant: std::env::var("RUSTFS_FAULT_TEST_TENANT")
            .unwrap_or_else(|_| "fault-test-tenant".into()),
        chaos_namespace: std::env::var("RUSTFS_FAULT_TEST_CHAOS_NAMESPACE")
            .unwrap_or_else(|_| "chaos-mesh".into()),
        operator_namespace: std::env::var("RUSTFS_FAULT_TEST_OPERATOR_NAMESPACE")
            .unwrap_or_else(|_| "rustfs-system".into()),
        supervisor: ProcessIdentity::for_pid(supervisor_pid)
            .context("cannot establish supervisor identity on this host")?,
        lease_uid: None,
        status: "preparing".into(),
        exit_code: None,
        keep_resources: std::env::var("S3CHAOS_KEEP_RESOURCES").is_ok_and(|value| value == "1"),
        resources: BTreeMap::new(),
    };
    persist(root, &session)?;
    let leases: Api<Lease> = Api::namespaced(client.clone(), LEASE_NAMESPACE);
    // Create is deliberately exclusive. Even an expired Lease needs recovery by its owner.
    let lease = Lease {
        metadata: ObjectMeta {
            name: Some(LEASE_NAME.into()),
            annotations: Some(BTreeMap::from([(RUN_ANNOTATION.into(), run_id.into())])),
            ..Default::default()
        },
        spec: Some(LeaseSpec {
            holder_identity: Some(run_id.into()),
            ..Default::default()
        }),
    };
    let created = leases
        .create(&PostParams::default(), &lease)
        .await
        .context("reserve cluster for fault run; a previous run may require recovery")?;
    session.lease_uid = created.uid();
    persist(root, &session)?;
    match namespaces.get_opt(&session.namespace).await? {
        Some(existing) => {
            let value = serde_json::to_value(&existing)?;
            ensure!(
                value["metadata"]["labels"][MANAGER] == "s3chaos"
                    && value["metadata"]["annotations"][TENANT_ANNOTATION].as_str()
                        == Some(session.tenant.as_str()),
                "existing namespace is not an owned fault fixture"
            );
            ensure!(
                value["metadata"]["annotations"][RUN_ANNOTATION]
                    .as_str()
                    .is_none_or(|owner| owner == run_id),
                "namespace is retained by a previous fault run; clean that run before reusing it"
            );
            let entry = record(&value, Ownership::Reused, "present")?;
            session
                .resources
                .insert(key(&entry.kind, None, &entry.name), entry);
            persist(root, &session)?;
        }
        None => {
            let value = json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":session.namespace,"labels":{MANAGER:"s3chaos"},"annotations":{TENANT_ANNOTATION:session.tenant,RUN_ANNOTATION:run_id}}});
            let entry = record(&value, Ownership::Created, "unknown")?;
            let resource_key = key(&entry.kind, None, &entry.name);
            session.resources.insert(resource_key.clone(), entry);
            persist(root, &session)?;
            let created = namespaces
                .create(&PostParams::default(), &serde_json::from_value(value)?)
                .await?;
            session.resources.insert(
                resource_key,
                record(
                    &serde_json::to_value(created)?,
                    Ownership::Created,
                    "present",
                )?,
            );
            persist(root, &session)?;
        }
    }
    session.status = "running".into();
    persist(root, &session)
}

/// Apply one fixture object, recording an unknown outcome before the API call.
/// Payloads (including Secret data) never enter the ownership journal.
pub(crate) fn apply_fixture_resource(config: &ClusterTestConfig, yaml: String) -> Result<()> {
    let Some(root) = std::env::var_os("S3CHAOS_RUN_ROOT").map(PathBuf::from) else {
        Kubectl::new(config)
            .apply_yaml_command(yaml)
            .run_checked()?;
        return Ok(());
    };
    let _lock = journal_lock(&root)?;
    let mut session = load(&root)?;
    ensure!(
        session.status == "running"
            && session.context == config.context
            && session.namespace == config.test_namespace,
        "fixture does not match its running session"
    );
    let mut value: Value = serde_yaml_ng::from_str(&yaml)?;
    let kind = value["kind"]
        .as_str()
        .context("fixture kind is missing")?
        .to_string();
    let name = value["metadata"]["name"]
        .as_str()
        .context("fixture name is missing")?
        .to_string();
    let namespace = value["metadata"]["namespace"].as_str().map(str::to_string);
    ensure!(
        namespace.as_deref() == Some(session.namespace.as_str())
            || namespace.as_deref() == Some(session.chaos_namespace.as_str()),
        "resource namespace is outside the fault session"
    );
    let kubectl = Kubectl::new(config).namespaced(
        namespace
            .as_deref()
            .context("resource namespace is missing")?,
    );
    let observed = kubectl
        .command(["get", &kind, &name, "--ignore-not-found", "-o", "json"])
        .run_checked()?;
    let existing: Option<Value> = if observed.stdout.trim().is_empty() {
        None
    } else {
        Some(serde_json::from_str(&observed.stdout)?)
    };
    let resource_key = key(&kind, namespace.as_deref(), &name);
    let mut ownership = Ownership::Created;
    if let Some(existing) = &existing {
        ownership = Ownership::Reused;
        if let Some(prior) = session.resources.get(&resource_key)
            && prior.ownership == Ownership::Created
        {
            validate_identity(prior, existing, &session.run_id)?;
            ownership = Ownership::Created;
        }
    }
    if ownership == Ownership::Created {
        value["metadata"]["annotations"][RUN_ANNOTATION] = json!(session.run_id);
    }
    let mut entry = record(&value, ownership, "unknown")?;
    entry.uid = existing
        .as_ref()
        .and_then(|v| v["metadata"]["uid"].as_str())
        .map(str::to_string);
    session
        .resources
        .insert(resource_key.clone(), entry.clone());
    persist(&root, &session)?;
    let verb = if existing.is_none() {
        "create"
    } else {
        "apply"
    };
    let output = kubectl
        .command([verb, "-f", "-", "-o", "json"])
        .stdin(serde_json::to_string(&value)?)
        .run_checked()?;
    let returned: Value = serde_json::from_str(&output.stdout)?;
    if entry.ownership == Ownership::Created {
        validate_identity(&entry, &returned, &session.run_id)?;
    }
    entry.uid = returned["metadata"]["uid"].as_str().map(str::to_string);
    ensure!(entry.uid.is_some(), "fixture API response has no UID");
    entry.state = "present".into();
    session.resources.insert(resource_key, entry);
    persist(&root, &session)
}

fn dynamic_api(client: Client, entry: &ResourceRecord) -> Result<Api<DynamicObject>> {
    let (group, version) = entry
        .api_version
        .split_once('/')
        .unwrap_or(("", &entry.api_version));
    let mut resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, &entry.kind));
    if group == "chaos-mesh.org" && entry.kind != "Schedule" {
        resource.plural = entry.kind.to_ascii_lowercase();
    }
    Ok(match &entry.namespace {
        Some(namespace) => Api::namespaced_with(client, namespace, &resource),
        None => Api::all_with(client, &resource),
    })
}

fn deletion(value: &Value) -> Result<DeleteParams> {
    Ok(DeleteParams {
        preconditions: Some(Preconditions {
            uid: Some(
                value["metadata"]["uid"]
                    .as_str()
                    .context("delete requires a UID")?
                    .to_string(),
            ),
            resource_version: Some(
                value["metadata"]["resourceVersion"]
                    .as_str()
                    .context("delete requires a resourceVersion")?
                    .to_string(),
            ),
        }),
        ..Default::default()
    })
}

async fn remove_record(
    client: Client,
    root: &Path,
    session: &mut Session,
    resource_key: &str,
) -> Result<()> {
    delete_record(client, root, session, resource_key, true).await
}

async fn delete_record(
    client: Client,
    root: &Path,
    session: &mut Session,
    resource_key: &str,
    wait: bool,
) -> Result<()> {
    let entry = session.resources[resource_key].clone();
    if entry.ownership != Ownership::Created
        || matches!(entry.state.as_str(), "deleted" | "retained")
    {
        return Ok(());
    }
    if entry.kind == "Namespace"
        && session.resources.values().any(|resource| {
            resource.namespace.as_deref() == Some(entry.name.as_str())
                && resource.ownership != Ownership::Created
                && resource.state != "deleted"
        })
    {
        session
            .resources
            .get_mut(resource_key)
            .expect("record exists")
            .state = "retained".into();
        return persist(root, session);
    }
    let api = dynamic_api(client, &entry)?;
    let Some(current) = api.get_opt(&entry.name).await? else {
        session
            .resources
            .get_mut(resource_key)
            .expect("record exists")
            .state = "deleted".into();
        return persist(root, session);
    };
    let value = serde_json::to_value(&current)?;
    validate_identity(&entry, &value, &session.run_id)?;
    let record = session
        .resources
        .get_mut(resource_key)
        .expect("record exists");
    record.uid = current.uid();
    record.state = "deleting".into();
    persist(root, session)?;
    api.delete(&entry.name, &deletion(&value)?).await?;
    if !wait {
        return Ok(());
    }
    for _ in 0..60 {
        let observed = api.get_opt(&entry.name).await?;
        if observed.is_none() {
            session
                .resources
                .get_mut(resource_key)
                .expect("record exists")
                .state = "deleted".into();
            return persist(root, session);
        }
        ensure!(
            observed.as_ref().and_then(ResourceExt::uid) == current.uid(),
            "resource {} was replaced while deletion was pending",
            entry.name
        );
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    bail!(
        "resource {} is still terminating; retry cleanup after its controller finishes",
        entry.name
    )
}

fn visit_artifacts(root: &Path, visit: &mut impl FnMut(&Path) -> Result<()>) -> Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_symlink() {
            continue;
        }
        if ty.is_dir() {
            visit_artifacts(&entry.path(), visit)?;
        } else if ty.is_file() {
            visit(&entry.path())?;
        }
    }
    Ok(())
}

fn targets_namespace(value: &Value, namespace: &str) -> bool {
    match value {
        Value::Object(fields) => {
            fields
                .get("namespaces")
                .and_then(Value::as_array)
                .is_some_and(|names| names.iter().any(|name| name.as_str() == Some(namespace)))
                || fields
                    .get("pods")
                    .and_then(Value::as_object)
                    .is_some_and(|pods| pods.contains_key(namespace))
                || fields
                    .values()
                    .any(|child| targets_namespace(child, namespace))
        }
        Value::Array(values) => values
            .iter()
            .any(|child| targets_namespace(child, namespace)),
        _ => false,
    }
}

async fn remove_chaos_records(
    client: Client,
    root: &Path,
    session: &mut Session,
    kind: Option<&str>,
    name: Option<&str>,
) -> Result<()> {
    let mut keys: Vec<_> = session
        .resources
        .iter()
        .filter(|(_, record)| {
            record.api_version == "chaos-mesh.org/v1alpha1"
                && kind.is_none_or(|kind| record.kind.eq_ignore_ascii_case(kind))
                && name.is_none_or(|name| record.name == name)
        })
        .map(|(key, record)| (record.kind != "Schedule", key.clone()))
        .collect();
    keys.sort();
    for (_, key) in keys {
        delete_record(client.clone(), root, session, &key, name.is_none()).await?;
    }
    Ok(())
}

async fn require_chaos_recovered(client: Client, session: &Session) -> Result<()> {
    for kind in [
        "Schedule",
        "IOChaos",
        "PodChaos",
        "NetworkChaos",
        "StressChaos",
        "TimeChaos",
    ] {
        let entry = ResourceRecord {
            api_version: "chaos-mesh.org/v1alpha1".into(),
            kind: kind.into(),
            namespace: Some(session.chaos_namespace.clone()),
            name: String::new(),
            uid: None,
            ownership: Ownership::External,
            state: "external".into(),
        };
        let api = dynamic_api(client.clone(), &entry)?;
        let objects = match api
            .list(&ListParams::default().labels("app.kubernetes.io/managed-by=s3chaos"))
            .await
        {
            Ok(objects) => objects,
            Err(kube::Error::Api(error)) if error.code == 404 => continue,
            Err(error) => return Err(error.into()),
        };
        for object in objects {
            let value = serde_json::to_value(&object)?;
            ensure!(
                !owned(&value, &session.run_id)
                    && !targets_namespace(&value["spec"], &session.namespace),
                "unresolved Chaos resource {kind}/{} still targets this session; retain its reservation",
                object.name_any()
            );
        }
    }
    Ok(())
}

/// Remove only Chaos resources recorded before this session sent their creation request.
pub async fn cleanup_chaos(root: &Path) -> Result<()> {
    let _lock = journal_lock(root)?;
    cleanup_chaos_inner(root).await
}

async fn cleanup_chaos_inner(root: &Path) -> Result<()> {
    let mut session = load(root)?;
    let client = verified_client(&session).await?;
    require_lease(client.clone(), &mut session, root).await?;
    remove_chaos_records(client.clone(), root, &mut session, None, None).await?;
    require_chaos_recovered(client, &session).await
}

/// Used by synchronous ChaosGuard calls; `*` selects the recorded resources of one kind.
pub async fn cleanup_chaos_resource(root: &Path, kind: &str, name: &str) -> Result<()> {
    let _lock = journal_lock(root)?;
    let mut session = load(root)?;
    let client = verified_client(&session).await?;
    require_lease(client.clone(), &mut session, root).await?;
    remove_chaos_records(
        client,
        root,
        &mut session,
        Some(kind),
        (name != "*").then_some(name),
    )
    .await
}

pub(crate) fn validate_chaos_snapshot(kind: &str, name: &str, value: &Value) -> Result<()> {
    let Some(root) = std::env::var_os("S3CHAOS_RUN_ROOT").map(PathBuf::from) else {
        return Ok(());
    };
    let _lock = journal_lock(&root)?;
    let session = load(&root)?;
    let entry = session
        .resources
        .values()
        .find(|entry| {
            entry.kind.eq_ignore_ascii_case(kind)
                && entry.name == name
                && entry.namespace.as_deref() == Some(session.chaos_namespace.as_str())
        })
        .context("Chaos resource has no session ownership record")?;
    ensure!(
        entry.ownership == Ownership::Created,
        "cannot change finalizers of a reused Chaos resource"
    );
    validate_identity(entry, value, &session.run_id)
}

fn require_storage_recovered(root: &Path) -> Result<()> {
    visit_artifacts(root, &mut |path| {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        ensure!(
            !name.starts_with(".host-mutation-") && !name.starts_with(".quorum-dm-"),
            "host recovery is unresolved at {}; preserve the helper and its recovery proof",
            path.display()
        );
        if name == "quorum-dm-targets.json" {
            let value: Value = serde_json::from_slice(&fs::read(path)?)?;
            for target in value["targets"]
                .as_array()
                .context("quorum DM targets are missing")?
            {
                let marker = Path::new(
                    target["stateFile"]
                        .as_str()
                        .context("quorum DM target lacks its recovery marker")?,
                );
                ensure!(
                    !marker.try_exists()?,
                    "quorum DM recovery is unresolved at {}",
                    marker.display()
                );
            }
        }
        Ok(())
    })
}

async fn require_operator_recovered(client: Client, session: &Session, root: &Path) -> Result<()> {
    let mut required = false;
    visit_artifacts(root, &mut |path| {
        if matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("target-proof.json" | "run-spec.json" | "suite-plan.json")
        ) {
            let text = fs::read_to_string(path)?;
            required |= text.contains("cluster-cold-restart");
        }
        Ok(())
    })?;
    if !required {
        return Ok(());
    }
    let api: Api<k8s_openapi::api::apps::v1::Deployment> =
        Api::namespaced(client, &session.operator_namespace);
    for deployment in api.list(&ListParams::default()).await? {
        ensure!(
            deployment
                .metadata
                .annotations
                .as_ref()
                .is_none_or(|a| !a.contains_key("s3chaos.rustfs.com/operator-paused-replicas")),
            "operator recovery must finish before releasing the fault session"
        );
    }
    Ok(())
}

/// Only the original foreground supervisor can attest that its child group exited.
pub async fn finish(root: &Path, exit_code: i32) -> Result<()> {
    let mut session = load(root)?;
    ensure!(
        parent_pid() == Some(session.supervisor.pid)
            && ProcessIdentity::for_pid(session.supervisor.pid).as_ref()
                == Some(&session.supervisor),
        "only the original supervisor can complete execution; lost runs retain their reservation"
    );
    session.status = "finished".into();
    session.exit_code = Some(exit_code);
    persist(root, &session)?;
    let cleaned = if exit_code == 0 && !session.keep_resources {
        cleanup(root).await
    } else {
        Ok(())
    };
    let retained = load(root)?
        .resources
        .values()
        .any(|resource| resource.state == "retained");
    let execution = match exit_code {
        0 => "passed",
        130 => "interrupted",
        _ => "failed",
    };
    durable_json(
        root,
        "fault-workflow-result.json",
        &json!({
            "schemaVersion": 1, "runId": session.run_id,
            "status": if cleaned.is_err() { "failed" } else { execution },
            "execution": execution,
            "artifactValidation": if exit_code == 0 { "passed" } else { "unknown" },
            "cleanup": if cleaned.is_err() { "failed" } else if exit_code == 0 && !session.keep_resources && !retained { "cleaned" } else { "retained" },
            "exitCode": if cleaned.is_err() && exit_code == 0 { 1 } else { exit_code },
        }),
    )?;
    cleaned
}

/// Cleanup never treats process absence, Lease expiry, or a historical PID as recovery proof.
pub async fn cleanup(root: &Path) -> Result<()> {
    let _lock = journal_lock(root)?;
    let mut session = load(root)?;
    if session.status == "cleaned" {
        return Ok(());
    }
    if session.status == "releasing" {
        return release(root, session).await;
    }
    ensure!(
        session.status == "finished",
        "run has no supervisor completion receipt; verify its execution and recovery before cleanup"
    );
    require_storage_recovered(root)?;
    let client = verified_client(&session).await?;
    require_lease(client.clone(), &mut session, root).await?;
    cleanup_chaos_inner(root).await?;
    session = load(root)?;
    require_operator_recovered(client.clone(), &session, root).await?;
    let keys: Vec<_> = session
        .resources
        .iter()
        .filter(|(_, r)| r.api_version != "chaos-mesh.org/v1alpha1")
        .map(|(key, _)| key.clone())
        .collect();
    // Tenant finalizers must complete while their credential Secret still exists.
    for kind in ["Tenant", "Secret", "Namespace"] {
        for resource_key in &keys {
            if session.resources[resource_key].kind == kind {
                remove_record(client.clone(), root, &mut session, resource_key).await?;
            }
        }
    }
    verify_retained_namespace(client.clone(), &session).await?;
    release_retained_namespaces(client.clone(), &session).await?;
    session.status = "releasing".into();
    persist(root, &session)?;
    release(root, session).await
}

async fn verify_retained_namespace(client: Client, session: &Session) -> Result<()> {
    let retained_namespace = session.resources.values().any(|entry| {
        entry.kind == "Namespace"
            && (entry.ownership == Ownership::Reused || entry.state == "retained")
    });
    let created_tenant = session
        .resources
        .values()
        .any(|entry| entry.kind == "Tenant" && entry.ownership == Ownership::Created);
    if retained_namespace && created_tenant {
        for (api_version, kind) in [
            ("v1", "Pod"),
            ("v1", "PersistentVolumeClaim"),
            ("apps/v1", "StatefulSet"),
        ] {
            let entry = ResourceRecord {
                api_version: api_version.into(),
                kind: kind.into(),
                namespace: Some(session.namespace.clone()),
                name: String::new(),
                uid: None,
                ownership: Ownership::External,
                state: "external".into(),
            };
            let remaining = dynamic_api(client.clone(), &entry)?
                .list(&ListParams::default().labels(&format!("rustfs.tenant={}", session.tenant)))
                .await?;
            ensure!(
                remaining.items.is_empty(),
                "retained namespace {} still contains {} resources for Tenant {}; preserve them until their controller completes cleanup",
                session.namespace,
                kind,
                session.tenant
            );
        }
    }
    Ok(())
}

async fn release_retained_namespaces(client: Client, session: &Session) -> Result<()> {
    let namespaces: Api<Namespace> = Api::all(client);
    for entry in session
        .resources
        .values()
        .filter(|entry| entry.kind == "Namespace" && entry.state == "retained")
    {
        let Some(current) = namespaces.get_opt(&entry.name).await? else {
            continue;
        };
        ensure!(
            entry.uid.is_some() && current.uid() == entry.uid,
            "retained namespace {} was replaced",
            entry.name
        );
        if current
            .metadata
            .annotations
            .as_ref()
            .is_some_and(|annotations| annotations.contains_key(RUN_ANNOTATION))
        {
            validate_identity(entry, &serde_json::to_value(&current)?, &session.run_id)?;
            let version = current
                .metadata
                .resource_version
                .context("retained namespace has no resourceVersion")?;
            let updated = namespaces.patch(&entry.name, &PatchParams::default(), &Patch::Merge(json!({"metadata":{"uid":entry.uid,"resourceVersion":version,"annotations":{RUN_ANNOTATION:Value::Null}}}))).await?;
            ensure!(
                updated.uid() == entry.uid
                    && updated
                        .metadata
                        .annotations
                        .as_ref()
                        .is_none_or(|annotations| !annotations.contains_key(RUN_ANNOTATION)),
                "retained namespace ownership was not released"
            );
        }
    }
    Ok(())
}

async fn release(root: &Path, mut session: Session) -> Result<()> {
    let client = verified_client(&session).await?;
    let api: Api<Lease> = Api::namespaced(client, LEASE_NAMESPACE);
    if let Some(lease) = api.get_opt(LEASE_NAME).await? {
        // All recorded cleanup completed before the release intent was synced.
        // A different UID means our deletion completed and a later run acquired it.
        if lease.uid() == session.lease_uid {
            lease_owned(&lease, &session)?;
            api.delete(LEASE_NAME, &deletion(&serde_json::to_value(lease)?)?)
                .await?;
        }
    }
    session.status = "cleaned".into();
    persist(root, &session)
}

/// Legacy broad cleanup cannot run concurrently with a supervised session.
pub async fn require_idle(context: &str) -> Result<()> {
    let (client, _, _) = connection(context).await?;
    let lease = Api::<Lease>::namespaced(client, LEASE_NAMESPACE)
        .get_opt(LEASE_NAME)
        .await?;
    ensure!(
        lease.is_none(),
        "a fault session owns this cluster; use cleanup-run with its exact run root"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(uid: &str, run_id: &str) -> Value {
        json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"test","uid":uid,"resourceVersion":"7","annotations":{RUN_ANNOTATION:run_id}}})
    }

    fn session() -> Session {
        Session {
            schema_version: 1,
            run_id: "run-a".into(),
            context: "test".into(),
            api_server: "http://127.0.0.1:9".into(),
            ca_sha256: String::new(),
            cluster_uid: "cluster".into(),
            namespace: "test".into(),
            tenant: "tenant".into(),
            chaos_namespace: "chaos".into(),
            operator_namespace: "operator".into(),
            supervisor: ProcessIdentity {
                pid: 1,
                start_ticks: "1".into(),
                boot_id: "boot".into(),
                namespace: Some("test".into()),
            },
            lease_uid: Some("lease-a".into()),
            status: "finished".into(),
            exit_code: Some(0),
            keep_resources: false,
            resources: BTreeMap::new(),
        }
    }

    #[test]
    fn image_evidence_keeps_all_observed_ids_and_excludes_pod_secrets() {
        let pods = json!({"items":[{"metadata":{"name":"pod", "annotations":{"token":"sensitive"}},"spec":{"containers":[{"name":"rustfs","image":"repo:tag","env":[{"name":"PASSWORD","value":"sensitive"}]},{"name":"sidecar","image":"unrelated"}]},"status":{"phase":"Running","containerStatuses":[{"name":"rustfs","ready":true,"imageID":"containerd://sha256:bare-config"}]}}]});
        let first = image_record(None, "repo:tag", ready_images(&pods).unwrap()).unwrap();
        let second = image_record(
            Some(&first),
            "repo:tag",
            vec![("repo:tag".into(), "repo@sha256:manifest".into())],
        )
        .unwrap();
        assert_eq!(second["containers"].as_array().unwrap().len(), 2);
        let text = serde_json::to_string(&second).unwrap();
        assert!(
            !text.contains("sensitive") && !text.contains("sidecar") && !text.contains("PASSWORD")
        );
        assert!(text.contains("containerd://sha256:bare-config"));
        assert!(image_record(Some(&second), "repo:other", vec![]).is_err());
    }

    #[test]
    fn incomplete_pod_readiness_does_not_publish_an_image_observation() {
        assert!(ready_images(&json!({"items":[]})).is_none());
        assert!(ready_images(&json!({"items":[{"status":{"phase":"Pending"}}]})).is_none());
    }

    #[test]
    fn replacement_with_the_same_name_is_not_owned() {
        let entry = record(&object("old", "run-a"), Ownership::Created, "present").unwrap();
        assert!(validate_identity(&entry, &object("new", "run-a"), "run-a").is_err());
        assert!(validate_identity(&entry, &object("old", "run-b"), "run-a").is_err());
    }

    #[test]
    fn unknown_creation_requires_the_original_run_annotation() {
        let mut entry = record(&object("old", "run-a"), Ownership::Created, "unknown").unwrap();
        entry.uid = None;
        assert!(validate_identity(&entry, &object("received", "run-a"), "run-a").is_ok());
        assert!(validate_identity(&entry, &object("received", "run-b"), "run-a").is_err());
        entry.ownership = Ownership::Reused;
        assert!(validate_identity(&entry, &object("received", "run-a"), "run-a").is_err());
    }

    #[test]
    fn deletion_requires_uid_and_resource_version() {
        let params = deletion(&object("uid-a", "run-a")).unwrap();
        let preconditions = params.preconditions.unwrap();
        assert_eq!(preconditions.uid.as_deref(), Some("uid-a"));
        assert_eq!(preconditions.resource_version.as_deref(), Some("7"));
        assert!(deletion(&json!({"metadata":{"name":"test"}})).is_err());
    }

    #[test]
    fn an_expired_lease_does_not_authorize_takeover() {
        let lease: Lease = serde_json::from_value(json!({"apiVersion":"coordination.k8s.io/v1","kind":"Lease","metadata":{"name":LEASE_NAME,"uid":"lease-a"},"spec":{"holderIdentity":"old-run","leaseDurationSeconds":1,"renewTime":"2000-01-01T00:00:00Z"}})).unwrap();
        assert!(lease_owned(&lease, &session()).is_err());
    }

    #[tokio::test]
    async fn reused_and_external_resources_never_issue_delete_requests() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::try_from(Config::new("http://127.0.0.1:9".parse().unwrap())).unwrap();
        let root = tempfile::tempdir().unwrap();
        for ownership in [Ownership::Reused, Ownership::External] {
            let mut session = session();
            session.resources.insert(
                "resource".into(),
                record(&object("existing", "someone-else"), ownership, "present").unwrap(),
            );
            remove_record(client.clone(), root.path(), &mut session, "resource")
                .await
                .unwrap();
            assert_eq!(session.resources["resource"].state, "present");
        }
    }

    #[tokio::test]
    async fn a_created_namespace_retains_reused_and_external_children_without_api_deletion() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let client = Client::try_from(Config::new("http://127.0.0.1:9".parse().unwrap())).unwrap();
        let root = tempfile::tempdir().unwrap();
        for ownership in [Ownership::Reused, Ownership::External] {
            let mut session = session();
            session.resources.insert(
                "namespace".into(),
                record(
                    &object("namespace-uid", "run-a"),
                    Ownership::Created,
                    "present",
                )
                .unwrap(),
            );
            session.resources.insert("secret".into(), record(&json!({"apiVersion":"v1","kind":"Secret","metadata":{"namespace":"test","name":"credentials","uid":"external-uid"}}), ownership, "present").unwrap());
            remove_record(client.clone(), root.path(), &mut session, "namespace")
                .await
                .unwrap();
            assert_eq!(session.resources["namespace"].state, "retained");
            assert_eq!(session.resources["secret"].state, "present");
            remove_record(client.clone(), root.path(), &mut session, "namespace")
                .await
                .unwrap();
            assert_eq!(
                load(root.path()).unwrap().resources["namespace"].state,
                "retained"
            );
        }
    }

    #[tokio::test]
    async fn repeated_completed_cleanup_is_offline_and_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let mut session = session();
        session.status = "cleaned".into();
        persist(root.path(), &session).unwrap();
        cleanup(root.path()).await.unwrap();
        cleanup(root.path()).await.unwrap();
        assert_eq!(load(root.path()).unwrap().status, "cleaned");
    }

    #[tokio::test]
    async fn lost_supervisor_is_not_treated_as_completed_execution() {
        let root = tempfile::tempdir().unwrap();
        let mut session = session();
        session.status = "running".into();
        persist(root.path(), &session).unwrap();
        let error = cleanup(root.path()).await.unwrap_err();
        assert!(error.to_string().contains("completion receipt"));
        assert_eq!(load(root.path()).unwrap().status, "running");
    }

    #[test]
    fn unresolved_host_markers_preserve_the_session() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(".host-mutation-a.json"), b"{}").unwrap();
        assert!(require_storage_recovered(root.path()).is_err());
    }

    #[test]
    fn durable_session_replacement_keeps_a_complete_record() {
        let root = tempfile::tempdir().unwrap();
        let mut session = session();
        persist(root.path(), &session).unwrap();
        session.status = "releasing".into();
        persist(root.path(), &session).unwrap();
        assert_eq!(load(root.path()).unwrap().status, "releasing");
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    }
}
