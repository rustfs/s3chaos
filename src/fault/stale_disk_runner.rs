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

//! Fail-closed execution route for the planned stale-disk-return qualification.

use std::{
    net::SocketAddr,
    sync::mpsc::{self, Receiver, RecvTimeoutError},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use http::Method;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
};

use crate::{
    fault::{
        backends::host::{
            StaleDmTableSample, cancel_stale_dm_watch, capture_stale_dm_watch,
            observe_stale_host_runtime_identity, preflight_stale_disk_mutation, prepare_stale_disk,
            prepare_stale_dm_watch,
        },
        checker::check_s3_history,
        config::FaultTestConfig,
        events::RunEventStatus,
        fixture,
        history::{OperationKind, OperationOutcome, Recorder},
        host_storage::{DmStatusSnapshot, HOST_STORAGE_PROOF_ARTIFACT, HostStorageMutationProof},
        plan::{ExecutionPlan, StorageRecoveryExecutionPlan},
        pods::rustfs_target_inventory,
        preflight::{PreflightCheck, PreflightPhase},
        quorum::{QuorumCaseClass, QuorumVolumeBoundary},
        recovery_health::RECOVERY_HEALTH_ARTIFACT,
        reporting::ResponsibilityDomain,
        runner::{
            access::{ensure_s3_access, prepare_fault_fixture, s3_access, wait_for_ready_tenant},
            initialize_fault_run,
            targets::require_volume_quorum_topology,
            write_preflight_summary,
        },
        scenarios::{FaultIsolation, FaultScenario, STALE_DISK_RETURN_DETECT_SCENARIO},
        shutdown::RunDeadline,
        storage_recovery::{
            AckLossPutEvidence, ClassifiedVersionFragments, CommittedMutationEvidence,
            DANGLING_CLEANUP_PROOF_ARTIFACT, DISK_GENERATION_PROOF_ARTIFACT,
            DanglingCleanupEvidence, DanglingCleanupProof, DiskAbsenceObservation,
            DiskAbsenceWatchEvidence, DiskPresenceState, FragmentRecoverability,
            HostDiskStateSample, KubernetesLocalPvBindingEvidence,
            KubernetesLocalPvBindingResponse, PostReturnCheckerEvidence, RawDiskStateEvidence,
            RawDiskStateResponse, RustfsDanglingCleanupResponse, RustfsDiskAbsenceWatchResponse,
            RustfsStaleDiskOperationReceipt, SHARD_INVENTORY_AFTER_ARTIFACT,
            SHARD_INVENTORY_BEFORE_ARTIFACT, ShardInventoryScanReceipt, ShardInventorySnapshot,
            ShardInventorySource, StaleDiskLifecycleAction, StaleDiskLifecycleEvidence,
            StaleDiskOperationEvidence, StaleDiskReturnEvidence, StaleDiskReturnProof,
            StaleMutationKind, StorageRecoveryArtifactIdentity, StorageRecoveryCase,
            StorageVolumeIdentity,
        },
        storage_recovery_helper::{
            StaleOfflineExpectedVersion, StaleOfflineHelperOperation, StaleOfflineHelperRequest,
            StaleOfflineHelperResponse, StaleOwnedOrphanReceipt,
        },
        storage_recovery_lease::{KubernetesStorageLeaseAdapter, StorageRecoveryCleanupProof},
        storage_recovery_runtime::{
            CurrentStorageObservation, HostFlockProof, KubectlStorageRecoveryAttemptGuard,
            KubectlStorageRecoveryHostAdapter, KubernetesLeaseProof, KubernetesResourceVersions,
            OwnedStorageContext, StorageRecoveryExclusiveAccess, StorageRecoveryHostOperation,
            StorageRecoveryOperationReceipt, host_generation_sha256, storage_scope_sha256,
        },
        workload::{
            ObjectSpec, S3WorkloadClient,
            execution::{
                POST_RECOVERY_WRITE_HISTORY_ARTIFACT, POST_RECOVERY_WRITE_REPORT_ARTIFACT,
                prefill_objects,
            },
        },
    },
    framework::{
        artifacts::ArtifactCollector, kube_client::client_for_context, kubectl::Kubectl, resources,
    },
    rustfs::{RustfsAdminResponse, RustfsAdminTransport},
};

const ACK_LOSS_PROXY_IO_TIMEOUT: Duration = Duration::from_secs(10);
const ACK_LOSS_PROXY_MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const ACK_LOSS_PROXY_MAX_RESPONSE_BYTES: usize = 64 * 1024;
const STALE_RUNTIME_EVIDENCE_ARTIFACT: &str = "stale-runtime-evidence.json";
const STALE_HELPER_TRANSCRIPT_ARTIFACT: &str = "stale-helper-transcript.json";
const STALE_ADMIN_HEAL_ARTIFACT: &str = "stale-admin-heal.json";
const STALE_HEAL_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RawStaleAdminReceipt {
    api_revision: String,
    http_status: u16,
    request_id: Option<String>,
    response_sha256: String,
    response_body: String,
    started_at_ms: u64,
    completed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StalePathHealEvidence {
    operation_id: String,
    bucket: String,
    object_key: String,
    dry_run: bool,
    remove: bool,
    pool_index: u32,
    set_index: u32,
    start: RawStaleAdminReceipt,
    status_samples: Vec<RawStaleAdminReceipt>,
    terminal_summary: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealStartBody {
    client_token: String,
    client_address: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HealStatusBody {
    summary: String,
    #[serde(rename = "detail", default)]
    failure_detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct StableInventoryCapture {
    first: crate::fault::storage_recovery::RustfsShardInventoryResponse,
    second: crate::fault::storage_recovery::RustfsShardInventoryResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaleKubernetesGeneration {
    tenant_uid: String,
    resource_versions: KubernetesResourceVersions,
    helper_pod_uid: String,
}

#[derive(Clone, Copy)]
struct StaleOwnershipEnvironment<'a> {
    config: &'a FaultTestConfig,
    collector: &'a ArtifactCollector,
    scenario: &'a FaultScenario,
    volume: &'a StorageVolumeIdentity,
    lease: &'a KubernetesStorageLeaseAdapter,
}

fn stale_ownership_environment<'a>(
    config: &'a FaultTestConfig,
    collector: &'a ArtifactCollector,
    scenario: &'a FaultScenario,
    volume: &'a StorageVolumeIdentity,
    lease: &'a KubernetesStorageLeaseAdapter,
) -> StaleOwnershipEnvironment<'a> {
    StaleOwnershipEnvironment {
        config,
        collector,
        scenario,
        volume,
        lease,
    }
}

struct StableStaleInventoryRequest<'a> {
    identity: &'a StorageRecoveryArtifactIdentity,
    expected_versions: &'a [StaleOfflineExpectedVersion],
    orphan: &'a StaleOwnedOrphanReceipt,
    include_orphan: bool,
}

struct StaleHealRequest<'a> {
    admin: &'a RustfsAdminTransport,
    identity: &'a StorageRecoveryArtifactIdentity,
    object_key: &'a str,
    dry_run: bool,
    deadline: RunDeadline,
}

fn observe_stale_kubernetes_generation(
    config: &FaultTestConfig,
    volume: &StorageVolumeIdentity,
    helper_pod: &str,
) -> Result<StaleKubernetesGeneration> {
    let read = |kubectl: Kubectl, kind: &str, name: &str| -> Result<serde_json::Value> {
        let output = kubectl
            .command(["get", kind, name, "-o", "json"])
            .run_checked()?;
        serde_json::from_str(&output.stdout)
            .with_context(|| format!("decode current {kind} {name:?}"))
    };
    let namespaced = || Kubectl::new(&config.cluster).namespaced(&volume.namespace);
    let tenant = read(namespaced(), "tenant", &volume.tenant)?;
    let pod = read(namespaced(), "pod", &volume.pod)?;
    let pvc = read(
        namespaced(),
        "persistentvolumeclaim",
        &volume.persistent_volume_claim,
    )?;
    let pv = read(
        Kubectl::new(&config.cluster),
        "persistentvolume",
        &volume.persistent_volume,
    )?;
    let node = read(Kubectl::new(&config.cluster), "node", &volume.node)?;
    let helper = read(namespaced(), "pod", helper_pod)?;
    let metadata = |value: &serde_json::Value, field: &str| -> Result<String> {
        value
            .pointer(&format!("/metadata/{field}"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
            .with_context(|| format!("Kubernetes object lacks metadata.{field}"))
    };
    ensure!(
        metadata(&pod, "uid")? == volume.pod_uid
            && metadata(&pvc, "uid")? == volume.persistent_volume_claim_uid
            && metadata(&pv, "uid")? == volume.persistent_volume_uid
            && metadata(&node, "uid")? == volume.node_uid,
        "stale storage Kubernetes UID generation drifted"
    );
    Ok(StaleKubernetesGeneration {
        tenant_uid: metadata(&tenant, "uid")?,
        resource_versions: KubernetesResourceVersions {
            tenant: metadata(&tenant, "resourceVersion")?,
            pod: metadata(&pod, "resourceVersion")?,
            persistent_volume_claim: metadata(&pvc, "resourceVersion")?,
            persistent_volume: metadata(&pv, "resourceVersion")?,
            node: metadata(&node, "resourceVersion")?,
            helper_pod: metadata(&helper, "resourceVersion")?,
        },
        helper_pod_uid: metadata(&helper, "uid")?,
    })
}

async fn acquire_stale_ownership(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    identity: &StorageRecoveryArtifactIdentity,
    volume: &StorageVolumeIdentity,
    disk: &crate::fault::backends::host::DmFlakeyGuard,
) -> Result<(
    KubernetesStorageLeaseAdapter,
    OwnedStorageContext,
    KubectlStorageRecoveryAttemptGuard,
)> {
    let attempt_id = uuid::Uuid::new_v4().to_string();
    let helper_pod = disk.stale_helper_pod_name().to_string();
    let generation = observe_stale_kubernetes_generation(config, volume, &helper_pod)?;
    let host_generation = disk.stale_host_generation(
        &volume.target_mount_namespace_id,
        &volume.filesystem_uuid,
        &volume.rustfs_drive_uuid,
    )?;
    let observed_at_ms = now_ms()?.max(volume.observed_at_ms);
    let placeholder_lease = KubernetesLeaseProof {
        name: String::new(),
        uid: String::new(),
        resource_version: String::new(),
        holder_identity: String::new(),
        scope_sha256: String::new(),
        acquired_at_ms: 1,
        renew_at_ms: 1,
        expires_at_ms: u64::MAX,
    };
    let mut context = OwnedStorageContext {
        identity: identity.clone(),
        case: StorageRecoveryCase::StaleDiskReturn,
        attempt_id: attempt_id.clone(),
        cluster_context: config.cluster.context.clone(),
        tenant_uid: generation.tenant_uid.clone(),
        scope_sha256: String::new(),
        volume: StorageVolumeIdentity {
            observed_at_ms,
            ..volume.clone()
        },
        resource_versions: generation.resource_versions.clone(),
        host_generation,
        exclusive_access: StorageRecoveryExclusiveAccess {
            kubernetes_lease: placeholder_lease,
            host_flock: HostFlockProof {
                node: volume.node.clone(),
                node_uid: volume.node_uid.clone(),
                path: String::new(),
                device_id: String::new(),
                inode: 1,
                scope_sha256: String::new(),
                acquired_at_ms: 1,
            },
        },
        helper_pod_name: helper_pod.clone(),
        helper_pod_uid: generation.helper_pod_uid.clone(),
        observed_at_ms,
    };
    context.scope_sha256 = storage_scope_sha256(&context);
    let client = client_for_context(&context.cluster_context)
        .await
        .context("build Kubernetes client for stale storage Lease")?;
    let lease = KubernetesStorageLeaseAdapter::new(
        client,
        &volume.namespace,
        &context.scope_sha256,
        &identity.run_id,
        &attempt_id,
        Duration::from_secs(300),
    )?;
    let (lock_device_id, lock_inode, lock_acquired_at_ms) =
        disk.prepare_stale_session_lock(&context.scope_sha256)?;
    let lease_proof = lease.acquire().await?;
    let owned_at_ms = now_ms()?
        .max(lock_acquired_at_ms)
        .max(lease_proof.renew_at_ms);
    context.volume.observed_at_ms = owned_at_ms;
    context.observed_at_ms = owned_at_ms;
    context.exclusive_access = StorageRecoveryExclusiveAccess {
        kubernetes_lease: lease_proof,
        host_flock: HostFlockProof {
            node: volume.node.clone(),
            node_uid: volume.node_uid.clone(),
            path: format!(
                "{}/storage-{}.lock",
                crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HOST_LOCK_DIRECTORY,
                context.scope_sha256
            ),
            device_id: lock_device_id,
            inode: lock_inode,
            scope_sha256: context.scope_sha256.clone(),
            acquired_at_ms: owned_at_ms,
        },
    };
    let post_acquire = (|| -> Result<KubectlStorageRecoveryHostAdapter> {
        context.validate()?;
        let current_generation = observe_stale_kubernetes_generation(config, volume, &helper_pod)?;
        ensure!(
            current_generation == generation,
            "stale Kubernetes generation changed while acquiring exclusive ownership"
        );
        let current_host_generation = disk.stale_host_generation(
            &volume.target_mount_namespace_id,
            &volume.filesystem_uuid,
            &volume.rustfs_drive_uuid,
        )?;
        ensure!(
            current_host_generation == context.host_generation,
            "stale host generation changed while acquiring exclusive ownership"
        );
        collector.write_text(
            scenario.case_name,
            "owned-storage-context.json",
            &serde_json::to_string_pretty(&context)?,
        )?;
        KubectlStorageRecoveryHostAdapter::new(
            &config.cluster,
            volume.namespace.clone(),
            helper_pod,
            config.request_timeout,
        )
    })();
    let adapter = match post_acquire {
        Ok(adapter) => adapter,
        Err(primary) => {
            let abort = StorageRecoveryCleanupProof::AbortedBeforeMutation {
                observed_at_ms: now_ms()?.max(context.observed_at_ms),
            };
            return match lease
                .release(&context, &context.exclusive_access.kubernetes_lease, &abort)
                .await
            {
                Ok(()) => Err(primary),
                Err(release) => Err(primary.context(format!(
                    "release stale Lease after ownership setup failure also failed: {release:#}"
                ))),
            };
        }
    };
    let helper = match adapter.begin_attempt(&context).await {
        Ok(helper) => helper,
        Err(primary) => {
            let abort = StorageRecoveryCleanupProof::AbortedBeforeMutation {
                observed_at_ms: now_ms()?.max(context.observed_at_ms),
            };
            return match lease
                .release(&context, &context.exclusive_access.kubernetes_lease, &abort)
                .await
            {
                Ok(()) => Err(primary),
                Err(release) => Err(primary.context(format!(
                    "release pre-mutation stale Lease also failed: {release:#}"
                ))),
            };
        }
    };
    Ok((lease, context, helper))
}

async fn renew_stale_ownership(
    environment: StaleOwnershipEnvironment<'_>,
    disk: &mut crate::fault::backends::host::DmFlakeyGuard,
    context: &mut OwnedStorageContext,
    expect_isolated: bool,
) -> Result<()> {
    disk.ensure_stale_owned_state(expect_isolated)?;
    let generation = observe_stale_kubernetes_generation(
        environment.config,
        environment.volume,
        &context.helper_pod_name,
    )?;
    ensure!(
        generation.tenant_uid == context.tenant_uid
            && generation.resource_versions == context.resource_versions
            && generation.helper_pod_uid == context.helper_pod_uid,
        "stale Kubernetes generation drifted before Lease heartbeat"
    );
    let host_generation = disk.stale_host_generation(
        &environment.volume.target_mount_namespace_id,
        &environment.volume.filesystem_uuid,
        &environment.volume.rustfs_drive_uuid,
    )?;
    ensure!(
        host_generation == context.host_generation,
        "stale physical host generation drifted before Lease heartbeat"
    );
    let (lock_device_id, lock_inode) = disk.observe_stale_session_lock(&context.scope_sha256)?;
    ensure!(
        lock_device_id == context.exclusive_access.host_flock.device_id
            && lock_inode == context.exclusive_access.host_flock.inode,
        "stale persistent helper flock identity drifted"
    );
    let proof = environment
        .lease
        .renew(&context.exclusive_access.kubernetes_lease)
        .await?;
    let observed_at_ms = now_ms()?
        .max(proof.renew_at_ms)
        .max(context.observed_at_ms + 1);
    context.exclusive_access.kubernetes_lease = proof;
    context.volume.observed_at_ms = observed_at_ms;
    context.observed_at_ms = observed_at_ms;
    context.validate()?;
    let current = CurrentStorageObservation {
        cluster_context: context.cluster_context.clone(),
        tenant_uid: context.tenant_uid.clone(),
        scope_sha256: context.scope_sha256.clone(),
        volume: context.volume.clone(),
        resource_versions: context.resource_versions.clone(),
        host_generation: context.host_generation.clone(),
        helper_pod_name: context.helper_pod_name.clone(),
        helper_pod_uid: context.helper_pod_uid.clone(),
        kubernetes_lease_uid: context.exclusive_access.kubernetes_lease.uid.clone(),
        kubernetes_lease_resource_version: context
            .exclusive_access
            .kubernetes_lease
            .resource_version
            .clone(),
        kubernetes_lease_holder: context
            .exclusive_access
            .kubernetes_lease
            .holder_identity
            .clone(),
        host_lock_device_id: lock_device_id,
        host_lock_inode: lock_inode,
        observed_at_ms,
    };
    context.require_current(&current)?;
    environment.collector.write_text(
        environment.scenario.case_name,
        "owned-storage-context.json",
        &serde_json::to_string_pretty(context)?,
    )?;
    Ok(())
}

fn stale_dm_operation(
    proof: &HostStorageMutationProof,
    context: &OwnedStorageContext,
    reattach: bool,
) -> Result<StorageRecoveryHostOperation> {
    let fields = (
        proof.target.mapper_name.clone(),
        host_generation_sha256(&context.host_generation)?,
        proof.tables.recovery_table.clone(),
        proof.tables.fault_table.clone(),
    );
    let operation = if reattach {
        StorageRecoveryHostOperation::ReattachDeviceMapper {
            mapping_name: fields.0,
            expected_generation_sha256: fields.1,
            recovery_table: fields.2,
            isolation_table: fields.3,
        }
    } else {
        StorageRecoveryHostOperation::DetachDeviceMapper {
            mapping_name: fields.0,
            expected_generation_sha256: fields.1,
            recovery_table: fields.2,
            isolation_table: fields.3,
        }
    };
    operation.validate()?;
    Ok(operation)
}

fn persist_storage_receipt(
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    name: &str,
    receipt: &StorageRecoveryOperationReceipt,
) -> Result<()> {
    collector.write_text(
        scenario.case_name,
        name,
        &serde_json::to_string_pretty(receipt)?,
    )?;
    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StaleRuntimeEvidence {
    schema_version: u8,
    run_id: String,
    scenario: String,
    target_persistent_volume: String,
    target_canonical_device: String,
    activated_at_ms: u64,
    restored_at_ms: u64,
    overwrite_operation_id: String,
    delete_marker_operation_id: String,
    ack_loss: AckLossPutEvidence,
    checker_passed: bool,
}

struct TenantCleanupGuard<'a> {
    config: &'a crate::framework::config::ClusterTestConfig,
    armed: bool,
}

impl<'a> TenantCleanupGuard<'a> {
    fn new(config: &'a crate::framework::config::ClusterTestConfig) -> Self {
        Self {
            config,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TenantCleanupGuard<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Err(error) = fixture::reset_tenant_resources(self.config)
        {
            eprintln!("warning: stale-disk Tenant cleanup failed during cancellation: {error:#}");
        }
    }
}

struct StaleWatchGuard {
    cancel: Option<Box<dyn FnOnce() -> Result<()> + Send>>,
    result: Receiver<Result<Vec<StaleDmTableSample>>>,
    task: Option<thread::JoinHandle<()>>,
}

impl StaleWatchGuard {
    fn start(config: FaultTestConfig, proof: HostStorageMutationProof) -> Result<Self> {
        // Clear a stale sentinel before spawning. The watch itself never
        // clears it, so cancellation wins even if the remote command starts
        // after the controller has already begun recovery.
        prepare_stale_dm_watch(&config, &proof)?;
        let watch_config = config.clone();
        let watch_proof = proof.clone();
        Self::spawn(
            move || cancel_stale_dm_watch(&config, &proof),
            move || capture_stale_dm_watch(&watch_config, &watch_proof, 600),
        )
    }

    fn spawn(
        cancel: impl FnOnce() -> Result<()> + Send + 'static,
        watch: impl FnOnce() -> Result<Vec<StaleDmTableSample>> + Send + 'static,
    ) -> Result<Self> {
        let (sender, result) = mpsc::sync_channel(1);
        let task = thread::Builder::new()
            .name("s3chaos-stale-dm-watch".to_string())
            .spawn(move || {
                let _ = sender.send(watch());
            })
            .context("start bounded stale device-mapper watch")?;
        Ok(Self {
            cancel: Some(Box::new(cancel)),
            result,
            task: Some(task),
        })
    }

    fn cancel_and_finish(&mut self, timeout: Duration) -> Result<Vec<StaleDmTableSample>> {
        let cancel = self
            .cancel
            .take()
            .context("stale device-mapper watch cancellation was already requested")?;
        let deadline = Instant::now() + timeout;
        let (cancel_sender, cancel_result) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("s3chaos-stale-dm-watch-cancel".to_string())
            .spawn(move || {
                let _ = cancel_sender.send(cancel());
            })
            .context("start bounded stale device-mapper watch cancellation")?;
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("stale device-mapper watch cancellation deadline elapsed")?;
        match cancel_result.recv_timeout(remaining) {
            Ok(result) => result?,
            Err(RecvTimeoutError::Timeout) => {
                bail!("stale device-mapper watch cancellation exceeded its deadline")
            }
            Err(RecvTimeoutError::Disconnected) => {
                bail!("stale device-mapper watch cancellation exited without a result")
            }
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("stale device-mapper watch finish deadline elapsed")?;
        let result = match self.result.recv_timeout(remaining) {
            Ok(result) => result,
            Err(RecvTimeoutError::Timeout) => {
                bail!("stale device-mapper watch did not stop before its cancellation deadline")
            }
            Err(RecvTimeoutError::Disconnected) => {
                bail!("stale device-mapper watch exited without a result")
            }
        };
        self.task
            .take()
            .expect("stale watch task is present")
            .join()
            .map_err(|_| anyhow::anyhow!("stale device-mapper watch panicked"))?;
        result
    }
}

impl Drop for StaleWatchGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            let cancel = self.cancel.take();
            // Never make unwinding wait for the remote watch's 30 second
            // bound. Normal error handling reattaches first and calls the
            // bounded finish path; this detached fallback is only for panic.
            let _ = thread::Builder::new()
                .name("s3chaos-stale-dm-watch-cancel".to_string())
                .spawn(move || {
                    if let Some(cancel) = cancel {
                        let _ = cancel();
                    }
                    let _ = task.join();
                });
        }
    }
}

#[derive(Debug)]
pub struct AckLossProxyCapture {
    proxy_endpoint: SocketAddr,
    request_sha256: String,
    request_value_sha256: String,
    request_bytes: usize,
    upstream_http_status: u16,
    upstream_request_id: String,
    upstream_version_id: String,
    accepted_at_ms: u64,
    upstream_completed_at_ms: u64,
    connection_closed_at_ms: u64,
}

impl AckLossProxyCapture {
    pub fn bind_operation(
        self,
        record: &crate::fault::history::OperationRecord,
    ) -> Result<AckLossPutEvidence> {
        let value_sha256 = record
            .value_sha256
            .clone()
            .context("ACK-loss PUT history lacks its value digest")?;
        let size_bytes = record
            .size_bytes
            .context("ACK-loss PUT history lacks its decoded byte size")?;
        ensure!(
            self.request_bytes >= size_bytes && self.request_value_sha256 == value_sha256,
            "ACK-loss proxy request does not match the workload PUT body"
        );
        Ok(AckLossPutEvidence {
            operation_id: record.id.clone(),
            proxy_endpoint: self.proxy_endpoint.to_string(),
            request_count: 1,
            retries_disabled: true,
            request_sha256: self.request_sha256,
            value_sha256: self.request_value_sha256,
            size_bytes,
            upstream_http_status: self.upstream_http_status,
            upstream_request_id: self.upstream_request_id,
            upstream_version_id: self.upstream_version_id,
            accepted_at_ms: self.accepted_at_ms,
            upstream_completed_at_ms: self.upstream_completed_at_ms,
            client_response_bytes: 0,
            connection_closed_at_ms: self.connection_closed_at_ms,
        })
    }
}

pub struct AckLossProxy {
    endpoint: SocketAddr,
    capture: oneshot::Receiver<Result<AckLossProxyCapture>>,
    task: Option<JoinHandle<()>>,
}

impl AckLossProxy {
    pub async fn bind(upstream_endpoint: &str) -> Result<Self> {
        let upstream = loopback_http_endpoint(upstream_endpoint)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind one-shot ACK-loss proxy")?;
        let endpoint = listener.local_addr()?;
        let (sender, capture) = oneshot::channel();
        let task = tokio::spawn(async move {
            let result = serve_ack_loss_once(listener, endpoint, upstream).await;
            let _ = sender.send(result);
        });
        Ok(Self {
            endpoint,
            capture,
            task: Some(task),
        })
    }

    pub fn endpoint(&self) -> String {
        format!("http://{}", self.endpoint)
    }

    pub async fn capture(mut self) -> Result<AckLossProxyCapture> {
        let capture = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, &mut self.capture)
            .await
            .context("ACK-loss proxy capture timed out")?
            .context("ACK-loss proxy task ended without a capture")??;
        self.task
            .take()
            .expect("ACK-loss proxy task is present")
            .await
            .context("ACK-loss proxy task panicked")?;
        Ok(capture)
    }
}

impl Drop for AckLossProxy {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn serve_ack_loss_once(
    listener: TcpListener,
    proxy_endpoint: SocketAddr,
    upstream: SocketAddr,
) -> Result<AckLossProxyCapture> {
    let (mut client, peer) = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, listener.accept())
        .await
        .context("ACK-loss proxy accept timed out")??;
    ensure!(
        peer.ip().is_loopback(),
        "ACK-loss proxy accepted a non-loopback client"
    );
    let accepted_at_ms = now_ms()?;
    let request = read_content_length_message(
        &mut client,
        ACK_LOSS_PROXY_MAX_REQUEST_BYTES,
        "ACK-loss request",
    )
    .await?;
    let request_sha256 = hex::encode(Sha256::digest(&request));
    let request_value_sha256 = parse_put_request_sha256(&request)?;
    let mut server = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, TcpStream::connect(upstream))
        .await
        .context("ACK-loss upstream connect timed out")??;
    tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, server.write_all(&request))
        .await
        .context("ACK-loss upstream request timed out")??;
    server.flush().await?;
    let response = read_content_length_message(
        &mut server,
        ACK_LOSS_PROXY_MAX_RESPONSE_BYTES,
        "ACK-loss response",
    )
    .await?;
    let upstream_completed_at_ms = now_ms()?;
    let (status, request_id, version_id) = parse_put_response(&response)?;
    // The defining action: do not forward any upstream response byte.
    client.shutdown().await?;
    let connection_closed_at_ms = now_ms()?;
    Ok(AckLossProxyCapture {
        proxy_endpoint,
        request_sha256,
        request_value_sha256,
        request_bytes: request.len(),
        upstream_http_status: status,
        upstream_request_id: request_id,
        upstream_version_id: version_id,
        accepted_at_ms,
        upstream_completed_at_ms,
        connection_closed_at_ms,
    })
}

fn parse_put_request_sha256(request: &[u8]) -> Result<String> {
    let header_end = request
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("ACK-loss request lacks complete headers")?;
    let headers =
        std::str::from_utf8(&request[..header_end]).context("ACK-loss request is not UTF-8")?;
    ensure!(
        headers
            .lines()
            .next()
            .is_some_and(|line| line.starts_with("PUT /") && line.ends_with(" HTTP/1.1")),
        "ACK-loss proxy request is not one HTTP/1.1 PUT"
    );
    let digest = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("x-amz-content-sha256"))
        .map(|(_, value)| value.trim())
        .context("ACK-loss PUT lacks x-amz-content-sha256")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "ACK-loss PUT content digest is not SHA-256 hex"
    );
    Ok(digest.to_ascii_lowercase())
}

async fn read_content_length_message(
    stream: &mut TcpStream,
    max_bytes: usize,
    label: &str,
) -> Result<Vec<u8>> {
    let mut message = Vec::new();
    let header_end = loop {
        ensure!(
            message.len() < max_bytes,
            "{label} headers exceed byte budget"
        );
        let mut chunk = [0_u8; 4096];
        let count = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .with_context(|| format!("{label} read timed out"))??;
        ensure!(count > 0, "{label} ended before complete headers");
        message.extend_from_slice(&chunk[..count]);
        if let Some(index) = message.windows(4).position(|window| window == b"\r\n\r\n") {
            break index + 4;
        }
    };
    let headers = std::str::from_utf8(&message[..header_end])
        .with_context(|| format!("{label} headers are not UTF-8"))?;
    ensure!(
        !headers.lines().any(|line| {
            line.split_once(':')
                .is_some_and(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        }),
        "{label} uses unsupported transfer encoding"
    );
    let content_length = headers
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>())
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(
        content_length.len() <= 1,
        "{label} contains duplicate Content-Length"
    );
    let expected = header_end + content_length.first().copied().unwrap_or(0);
    ensure!(expected <= max_bytes, "{label} exceeds byte budget");
    ensure!(
        message.len() <= expected,
        "{label} contains pipelined or trailing bytes"
    );
    while message.len() < expected {
        let remaining = expected - message.len();
        let mut chunk = vec![0_u8; remaining.min(4096)];
        let count = tokio::time::timeout(ACK_LOSS_PROXY_IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .with_context(|| format!("{label} body read timed out"))??;
        ensure!(count > 0, "{label} ended before its declared body");
        message.extend_from_slice(&chunk[..count]);
    }
    Ok(message)
}

fn parse_put_response(response: &[u8]) -> Result<(u16, String, String)> {
    let headers = std::str::from_utf8(response).context("ACK-loss response is not UTF-8")?;
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("ACK-loss response lacks status")?
        .parse::<u16>()?;
    ensure!(
        (200..300).contains(&status),
        "ACK-loss upstream PUT did not succeed"
    );
    let header = |name: &str| {
        headers.lines().find_map(|line| {
            line.split_once(':')
                .filter(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.trim().to_string())
        })
    };
    let request_id = header("x-amz-request-id").context("upstream PUT lacks request id")?;
    let version_id = header("x-amz-version-id").context("upstream PUT lacks version id")?;
    ensure!(
        !request_id.is_empty() && !version_id.is_empty() && version_id != "null",
        "upstream PUT returned an empty request or version identity"
    );
    Ok((status, request_id, version_id))
}

fn loopback_http_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let authority = endpoint
        .strip_prefix("http://")
        .context("ACK-loss proxy requires a plaintext localhost upstream")?;
    ensure!(
        !authority.contains('/') && !authority.contains('@'),
        "ACK-loss upstream endpoint has an unsupported path or userinfo"
    );
    let address = authority
        .parse::<SocketAddr>()
        .context("ACK-loss upstream endpoint is not an explicit socket address")?;
    ensure!(
        address.ip().is_loopback() && address.port() > 0,
        "ACK-loss upstream must be an explicit loopback port-forward"
    );
    Ok(address)
}

fn now_ms() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock before UNIX epoch")?
        .as_millis() as u64)
}

fn sha256_text(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

async fn execute_stale_helper(
    helper: &mut KubectlStorageRecoveryAttemptGuard,
    context: &OwnedStorageContext,
    request: StaleOfflineHelperRequest,
) -> Result<StaleOfflineHelperResponse> {
    helper.execute_stale(context, &request).await
}

fn stale_helper_request(
    identity: &StorageRecoveryArtifactIdentity,
    volume: &StorageVolumeIdentity,
    operation: StaleOfflineHelperOperation,
) -> StaleOfflineHelperRequest {
    StaleOfflineHelperRequest {
        run_id: identity.run_id.clone(),
        scenario: identity.scenario.clone(),
        volume_root: crate::fault::storage_recovery_helper::STORAGE_HELPER_VOLUME_ROOT.to_string(),
        deployment_id: volume.rustfs_deployment_id.clone(),
        drive_uuid: volume.rustfs_drive_uuid.clone(),
        filesystem_uuid: volume.filesystem_uuid.clone(),
        bucket: identity.bucket.clone(),
        operation,
    }
}

async fn scan_stale_inventory(
    helper: &mut KubectlStorageRecoveryAttemptGuard,
    context: &OwnedStorageContext,
    identity: &StorageRecoveryArtifactIdentity,
    volume: &StorageVolumeIdentity,
    expected_versions: &[StaleOfflineExpectedVersion],
    orphan: &StaleOwnedOrphanReceipt,
    include_orphan: bool,
) -> Result<crate::fault::storage_recovery::RustfsShardInventoryResponse> {
    match execute_stale_helper(
        helper,
        context,
        stale_helper_request(
            identity,
            volume,
            StaleOfflineHelperOperation::Inventory {
                snapshot_id: uuid::Uuid::new_v4().to_string(),
                expected_versions: expected_versions.to_vec(),
                orphan: orphan.clone(),
                include_orphan,
            },
        ),
    )
    .await?
    {
        StaleOfflineHelperResponse::Inventory {
            response,
            expected_operation_ids,
        } => {
            ensure!(
                expected_operation_ids
                    == expected_versions
                        .iter()
                        .map(|expected| expected.operation_id.clone())
                        .collect::<Vec<_>>(),
                "offline inventory did not cover the exact expected workload operations"
            );
            Ok(response)
        }
        _ => bail!("stale helper returned a non-inventory response"),
    }
}

async fn stable_stale_inventory(
    environment: StaleOwnershipEnvironment<'_>,
    disk: &mut crate::fault::backends::host::DmFlakeyGuard,
    helper: &mut KubectlStorageRecoveryAttemptGuard,
    context: &mut OwnedStorageContext,
    request: StableStaleInventoryRequest<'_>,
) -> Result<(ShardInventorySnapshot, StableInventoryCapture)> {
    renew_stale_ownership(environment, disk, context, false).await?;
    let first = scan_stale_inventory(
        helper,
        context,
        request.identity,
        environment.volume,
        request.expected_versions,
        request.orphan,
        request.include_orphan,
    )
    .await?;
    thread::sleep(Duration::from_millis(2));
    renew_stale_ownership(environment, disk, context, false).await?;
    let second = scan_stale_inventory(
        helper,
        context,
        request.identity,
        environment.volume,
        request.expected_versions,
        request.orphan,
        request.include_orphan,
    )
    .await?;
    ensure!(
        first.exhausted
            && second.exhausted
            && first.start_cursor.is_none()
            && second.start_cursor.is_none()
            && first.total_count == first.entries.len()
            && second.total_count == second.entries.len()
            && first.entries == second.entries
            && first.scan_completed_at_ms < second.scan_started_at_ms,
        "two exhaustive offline inventories are not stable and strictly ordered"
    );
    let response_body = serde_json::to_string(&second)?;
    let snapshot = ShardInventorySnapshot::from_complete_scan(
        request.identity.clone(),
        environment.volume.clone(),
        ShardInventoryScanReceipt {
            snapshot_id: second.snapshot_id.clone(),
            source: ShardInventorySource::OfflineXl2Inspector,
            api_revision: crate::fault::xl2_inspector::OFFLINE_XL2_INSPECTOR_REVISION.to_string(),
            response_sha256: sha256_text(&response_body),
            response_body,
            started_at_ms: second.scan_started_at_ms,
            completed_at_ms: second.scan_completed_at_ms,
            observed_at_ms: second.scan_completed_at_ms,
        },
    )?;
    Ok((snapshot, StableInventoryCapture { first, second }))
}

fn raw_stale_admin_receipt(
    api_revision: &str,
    started_at_ms: u64,
    completed_at_ms: u64,
    response: RustfsAdminResponse,
) -> Result<RawStaleAdminReceipt> {
    ensure!(
        (200..300).contains(&response.status),
        "stale path heal returned HTTP {}",
        response.status
    );
    let response_body = String::from_utf8(response.body).context("heal response is not UTF-8")?;
    Ok(RawStaleAdminReceipt {
        api_revision: api_revision.to_string(),
        http_status: response.status,
        request_id: response.request_id,
        response_sha256: sha256_text(&response_body),
        response_body,
        started_at_ms,
        completed_at_ms,
    })
}

async fn run_stale_path_heal(
    environment: StaleOwnershipEnvironment<'_>,
    disk: &mut crate::fault::backends::host::DmFlakeyGuard,
    owned_context: &mut OwnedStorageContext,
    request: StaleHealRequest<'_>,
) -> Result<StalePathHealEvidence> {
    let operation_id = uuid::Uuid::new_v4().to_string();
    let path = format!(
        "/rustfs/admin/v3/heal/{}/{}",
        percent_encode_path_segment(&request.identity.bucket),
        percent_encode_path_segment(request.object_key)
    );
    let request_body = serde_json::to_vec(&serde_json::json!({
        "recursive": false,
        "dryRun": request.dry_run,
        "remove": true,
        "recreate": false,
        "scanMode": 0,
        "updateParity": false,
        "nolock": false,
        "pool": environment.volume.pool_index,
        "set": environment.volume.set_index,
    }))?;
    let mut owned_token = None::<String>;
    let attempt = async {
        request.deadline.check()?;
        renew_stale_ownership(environment, disk, owned_context, false).await?;
        let started_at_ms = now_ms()?;
        // Deliberately omit forceStart: a pre-existing overlapping heal must
        // fail instead of being cancelled by this qualification run.
        let response = request
            .admin
            .request(
                Method::POST,
                &path,
                &[],
                request_body,
                Some("application/json"),
            )
            .await?;
        let completed_at_ms = now_ms()?.max(started_at_ms + 1);
        let start = raw_stale_admin_receipt(
            "v3/heal/path-start",
            started_at_ms,
            completed_at_ms,
            response,
        )?;
        let start_body = serde_json::from_str::<HealStartBody>(&start.response_body)
            .context("decode stale path heal start")?;
        ensure!(
            !start_body.client_token.trim().is_empty()
                && !start_body.client_address.trim().is_empty(),
            "stale path heal start lacks an owned client token or address"
        );
        owned_token = Some(start_body.client_token.clone());
        let mut status_samples = Vec::new();
        loop {
            request.deadline.check()?;
            renew_stale_ownership(environment, disk, owned_context, false).await?;
            let status_started_at_ms = now_ms()?;
            let response = request
                .admin
                .request(
                    Method::POST,
                    &path,
                    &[("clientToken", start_body.client_token.as_str())],
                    Vec::new(),
                    None,
                )
                .await?;
            let status_completed_at_ms = now_ms()?.max(status_started_at_ms + 1);
            let status = raw_stale_admin_receipt(
                "v3/heal/path-status",
                status_started_at_ms,
                status_completed_at_ms,
                response,
            )?;
            let body = serde_json::from_str::<HealStatusBody>(&status.response_body)
                .context("decode stale path heal status")?;
            let summary = body.summary.clone();
            status_samples.push(status);
            match summary.as_str() {
                "running" => tokio::time::sleep(STALE_HEAL_POLL_INTERVAL).await,
                "finished" if body.failure_detail.is_empty() => {
                    owned_token = None;
                    return Ok(StalePathHealEvidence {
                        operation_id,
                        bucket: request.identity.bucket.clone(),
                        object_key: request.object_key.to_string(),
                        dry_run: request.dry_run,
                        remove: true,
                        pool_index: environment.volume.pool_index,
                        set_index: environment.volume.set_index,
                        start,
                        status_samples,
                        terminal_summary: summary,
                    });
                }
                other => bail!(
                    "owned stale path heal ended in unsupported state {other:?}: {}",
                    body.failure_detail
                ),
            }
        }
    }
    .await;
    if let Err(primary) = attempt {
        let Some(token) = owned_token else {
            return Err(primary);
        };
        if let Err(ownership) = renew_stale_ownership(environment, disk, owned_context, false).await
        {
            return Err(primary.context(format!(
                "owned path-heal cancellation skipped because storage ownership could not be renewed: {ownership:#}"
            )));
        }
        let cancel = request
            .admin
            .request(
                Method::POST,
                &path,
                &[("forceStop", "true"), ("clientToken", token.as_str())],
                Vec::new(),
                None,
            )
            .await;
        return match cancel {
            Ok(response) if (200..300).contains(&response.status) => Err(primary),
            Ok(response) => Err(primary.context(format!(
                "owned path-heal cancellation also returned HTTP {}",
                response.status
            ))),
            Err(cancel) => Err(primary.context(format!(
                "owned path-heal cancellation also failed: {cancel:#}"
            ))),
        };
    }
    unreachable!("successful path heal returns from its terminal status branch")
}

fn percent_encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            write!(&mut encoded, "%{byte:02X}").expect("write to String");
        }
    }
    encoded
}

async fn resolve_stale_volume_identity(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    endpoint: &str,
    access_key: &str,
    secret_key: &str,
    host_proof: &HostStorageMutationProof,
) -> Result<StorageVolumeIdentity> {
    let inventory = rustfs_target_inventory(&config.cluster, true, true)?;
    let topology = require_volume_quorum_topology(
        config,
        endpoint,
        access_key,
        secret_key,
        QuorumVolumeBoundary {
            class: QuorumCaseClass::Payload,
            beyond_read_tolerance: false,
        },
        &inventory.pod_proofs,
        &config.rustfs_volume_path,
    )
    .await?;
    let candidates = topology
        .volume_quorum
        .candidates
        .iter()
        .filter(|candidate| {
            candidate.pod_name == host_proof.target.pod
                && candidate.pod_uid == host_proof.target.pod_uid
                && candidate.persistent_volume_claim == host_proof.target.persistent_volume_claim
                && candidate.persistent_volume == host_proof.target.persistent_volume
                && candidate.mount_path == host_proof.target.container_mount_path
        })
        .collect::<Vec<_>>();
    let [candidate] = candidates.as_slice() else {
        anyhow::bail!(
            "stale-disk target does not map to exactly one live RustFS pool/set/drive candidate"
        )
    };
    let target_proof_body = serde_json::to_string_pretty(&topology)?;
    let target_proof_sha256 = sha256_text(&target_proof_body);
    collector.write_text(scenario.case_name, "target-proof.json", &target_proof_body)?;
    let host_proof_body = serde_json::to_string_pretty(host_proof)?;
    let host_storage_proof_sha256 = sha256_text(&host_proof_body);
    let runtime =
        observe_stale_host_runtime_identity(config, host_proof, candidate.container_id.as_str())?;

    let tenant = Kubectl::new(&config.cluster)
        .namespaced(&config.cluster.test_namespace)
        .command([
            "get",
            "tenant",
            config.cluster.tenant_name.as_str(),
            "-o",
            "json",
        ])
        .run_checked()?;
    let tenant = serde_json::from_str::<serde_json::Value>(&tenant.stdout)
        .context("decode stale-disk Tenant identity")?;
    let tenant_uid = tenant
        .pointer("/metadata/uid")
        .and_then(serde_json::Value::as_str)
        .context("stale-disk Tenant lacks metadata.uid")?;
    ensure!(
        tenant
            .pointer("/metadata/name")
            .and_then(serde_json::Value::as_str)
            == Some(config.cluster.tenant_name.as_str())
            && tenant
                .pointer("/metadata/namespace")
                .and_then(serde_json::Value::as_str)
                == Some(config.cluster.test_namespace.as_str())
            && !tenant_uid.trim().is_empty(),
        "stale-disk Tenant identity does not match the fresh fixture"
    );

    let volume = StorageVolumeIdentity {
        target_proof_sha256,
        host_storage_proof_sha256,
        rustfs_deployment_id: topology.topology.deployment_id,
        namespace: config.cluster.test_namespace.clone(),
        tenant: config.cluster.tenant_name.clone(),
        pod: host_proof.target.pod.clone(),
        pod_uid: host_proof.target.pod_uid.clone(),
        rustfs_container_id: candidate.container_id.clone(),
        volume_name: host_proof.target.volume_name.clone(),
        persistent_volume_claim: host_proof.target.persistent_volume_claim.clone(),
        persistent_volume_claim_uid: host_proof.target.persistent_volume_claim_uid.clone(),
        persistent_volume: host_proof.target.persistent_volume.clone(),
        persistent_volume_uid: host_proof.target.persistent_volume_uid.clone(),
        node: host_proof.target.node.clone(),
        node_uid: host_proof.target.node_uid.clone(),
        storage_class: config.cluster.storage_class.clone(),
        local_volume_path: host_proof.target.persistent_volume_path.clone(),
        mount_path: host_proof.target.container_mount_path.clone(),
        canonical_device: host_proof.target.canonical_device.clone(),
        target_mount_namespace_id: runtime.target_mount_namespace_id,
        filesystem_uuid: runtime.filesystem_uuid,
        rustfs_drive_uuid: candidate.drive_uuid.clone(),
        pool_index: candidate.pool_index,
        set_index: candidate.set_index,
        observed_at_ms: now_ms()?,
    };
    volume.validate()?;
    collector.write_text(
        scenario.case_name,
        "stale-volume-identity.json",
        &serde_json::to_string_pretty(&serde_json::json!({
            "tenantUid": tenant_uid,
            "volume": volume,
        }))?,
    )?;
    Ok(volume)
}

fn kubernetes_binding_evidence(
    config: &FaultTestConfig,
    volume: &StorageVolumeIdentity,
) -> Result<(KubernetesLocalPvBindingEvidence, u64)> {
    let read = |kubectl: Kubectl, kind: &str, name: &str| -> Result<String> {
        Ok(kubectl
            .command(["get", kind, name, "-o", "json"])
            .run_checked()?
            .stdout)
    };
    let pv = read(
        Kubectl::new(&config.cluster),
        "persistentvolume",
        &volume.persistent_volume,
    )?;
    let namespaced = || Kubectl::new(&config.cluster).namespaced(&volume.namespace);
    let pvc = read(
        namespaced(),
        "persistentvolumeclaim",
        &volume.persistent_volume_claim,
    )?;
    let pod = read(namespaced(), "pod", &volume.pod)?;
    let node = read(Kubectl::new(&config.cluster), "node", &volume.node)?;
    let observed_at_ms = now_ms()?;
    let response = KubernetesLocalPvBindingResponse {
        observed_at_ms,
        persistent_volume_sha256: sha256_text(&pv),
        persistent_volume_body: pv,
        persistent_volume_claim_sha256: sha256_text(&pvc),
        persistent_volume_claim_body: pvc,
        pod_sha256: sha256_text(&pod),
        pod_body: pod,
        node_sha256: sha256_text(&node),
        node_body: node,
    };
    let response_body = serde_json::to_string(&response)?;
    Ok((
        KubernetesLocalPvBindingEvidence {
            response_sha256: sha256_text(&response_body),
            response_body,
        },
        observed_at_ms,
    ))
}

fn raw_dm_state_evidence(
    proof: &HostStorageMutationProof,
    volume: &StorageVolumeIdentity,
    table: &str,
    suspended: bool,
    observed_at_ms: u64,
) -> Result<RawDiskStateEvidence> {
    let host_storage_proof_body = serde_json::to_string_pretty(proof)?;
    let response = RawDiskStateResponse::DeviceMapperTable {
        host_storage_proof_sha256: sha256_text(&host_storage_proof_body),
        host_storage_proof_body,
        observer_namespace: proof.observer_namespace.clone(),
        observer_pod: proof.observer_pod.clone(),
        mapper_name: proof.target.mapper_name.clone(),
        argv: vec![
            "dmsetup".to_string(),
            "table".to_string(),
            "--showkeys".to_string(),
            proof.target.mapper_name.clone(),
        ],
        exit_code: 0,
        stdout: table.to_string(),
        stderr: String::new(),
        suspended,
        observed_at_ms,
        canonical_device: volume.canonical_device.clone(),
    };
    let response_body = serde_json::to_string(&response)?;
    Ok(RawDiskStateEvidence {
        response_sha256: sha256_text(&response_body),
        response_body,
    })
}

struct StaleLifecycleObservation<'a> {
    action: StaleDiskLifecycleAction,
    operation_id: String,
    started_at_ms: u64,
    snapshot: &'a DmStatusSnapshot,
}

fn lifecycle_operation_evidence(
    config: &FaultTestConfig,
    identity: &StorageRecoveryArtifactIdentity,
    volume: &StorageVolumeIdentity,
    proof: &HostStorageMutationProof,
    observation: StaleLifecycleObservation<'_>,
) -> Result<StaleDiskOperationEvidence> {
    let (kubernetes_binding_evidence, completed_at_ms) =
        kubernetes_binding_evidence(config, volume)?;
    let receipt = RustfsStaleDiskOperationReceipt {
        operation_id: observation.operation_id,
        action: observation.action,
        persistent_volume: volume.persistent_volume.clone(),
        persistent_volume_uid: volume.persistent_volume_uid.clone(),
        canonical_device: volume.canonical_device.clone(),
        filesystem_uuid: volume.filesystem_uuid.clone(),
        rustfs_drive_uuid: volume.rustfs_drive_uuid.clone(),
        target_proof_sha256: volume.target_proof_sha256.clone(),
        host_storage_proof_sha256: volume.host_storage_proof_sha256.clone(),
        started_at_ms: observation.started_at_ms,
        completed_at_ms,
        kubernetes_binding_evidence,
        host_result_evidence: raw_dm_state_evidence(
            proof,
            volume,
            &observation.snapshot.table,
            observation.snapshot.suspended,
            completed_at_ms,
        )?,
    };
    ensure!(
        identity.scenario == STALE_DISK_RETURN_DETECT_SCENARIO,
        "stale lifecycle identity is bound to another scenario"
    );
    let response_body = serde_json::to_string(&receipt)?;
    Ok(StaleDiskOperationEvidence {
        response_sha256: sha256_text(&response_body),
        response_body,
    })
}

fn receipt_from_evidence(
    evidence: &StaleDiskOperationEvidence,
) -> Result<RustfsStaleDiskOperationReceipt> {
    serde_json::from_str(&evidence.response_body).context("decode local stale lifecycle receipt")
}

fn watch_observation(
    identity: &StorageRecoveryArtifactIdentity,
    volume: &StorageVolumeIdentity,
    proof: &HostStorageMutationProof,
    observation_id: String,
    detach_operation_id: String,
    first: (&DmStatusSnapshot, u64, KubernetesLocalPvBindingEvidence),
    samples: Vec<StaleDmTableSample>,
) -> Result<DiskAbsenceObservation> {
    let mut evidence_samples = vec![HostDiskStateSample {
        cursor: String::new(),
        observed_at_ms: first.1,
        state: DiskPresenceState::Present,
        raw_evidence: raw_dm_state_evidence(
            proof,
            volume,
            &first.0.table,
            first.0.suspended,
            first.1,
        )?,
    }];
    evidence_samples[0].cursor = evidence_samples[0].raw_evidence.response_sha256.clone();
    for sample in samples {
        let state = if crate::fault::host_storage::dm_tables_match(
            &sample.table,
            &proof.tables.recovery_table,
        )? {
            DiskPresenceState::Present
        } else {
            DiskPresenceState::Absent
        };
        let raw = raw_dm_state_evidence(
            proof,
            volume,
            &sample.table,
            sample.suspended,
            sample.observed_at_ms,
        )?;
        evidence_samples.push(HostDiskStateSample {
            cursor: raw.response_sha256.clone(),
            observed_at_ms: sample.observed_at_ms,
            state,
            raw_evidence: raw,
        });
    }
    let watch_started_at_ms = first.1;
    let watch_ended_at_ms = evidence_samples
        .last()
        .context("stale disk watch has no samples")?
        .observed_at_ms;
    let response = RustfsDiskAbsenceWatchResponse {
        observation_id: observation_id.clone(),
        detachment_operation_id: detach_operation_id.clone(),
        persistent_volume: volume.persistent_volume.clone(),
        persistent_volume_uid: volume.persistent_volume_uid.clone(),
        canonical_device: volume.canonical_device.clone(),
        filesystem_uuid: volume.filesystem_uuid.clone(),
        rustfs_drive_uuid: volume.rustfs_drive_uuid.clone(),
        target_proof_sha256: volume.target_proof_sha256.clone(),
        host_storage_proof_sha256: volume.host_storage_proof_sha256.clone(),
        watch_started_at_ms,
        watch_ended_at_ms,
        poll_interval_ms: 100,
        samples: evidence_samples,
        closed_normally: true,
    };
    let response_body = serde_json::to_string(&response)?;
    ensure!(
        identity.run_id == proof.run_id,
        "stale disk watch is bound to another run"
    );
    Ok(DiskAbsenceObservation {
        observation_id,
        detachment_operation_id: detach_operation_id,
        persistent_volume: volume.persistent_volume.clone(),
        persistent_volume_uid: volume.persistent_volume_uid.clone(),
        canonical_device: volume.canonical_device.clone(),
        filesystem_uuid: volume.filesystem_uuid.clone(),
        rustfs_drive_uuid: volume.rustfs_drive_uuid.clone(),
        target_proof_sha256: volume.target_proof_sha256.clone(),
        host_storage_proof_sha256: volume.host_storage_proof_sha256.clone(),
        watch_started_at_ms,
        watch_ended_at_ms,
        kubernetes_binding_evidence: first.2,
        host_watch_evidence: DiskAbsenceWatchEvidence {
            response_sha256: sha256_text(&response_body),
            response_body,
        },
    })
}

fn pre_reattach_watch_samples(
    samples: Vec<StaleDmTableSample>,
    reattach_started_at_ms: u64,
) -> Result<(Vec<StaleDmTableSample>, usize)> {
    let complete_count = samples.len();
    let evidence = samples
        .into_iter()
        .filter(|sample| sample.observed_at_ms < reattach_started_at_ms)
        .collect::<Vec<_>>();
    ensure!(
        !evidence.is_empty(),
        "stale device-mapper watch has no absence sample before reattachment"
    );
    let post_reattach_count = complete_count - evidence.len();
    Ok((evidence, post_reattach_count))
}

pub(crate) async fn run_stale_disk_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &StorageRecoveryExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        config.qualify_planned_storage
            && scenario.name == STALE_DISK_RETURN_DETECT_SCENARIO
            && plan.case == StorageRecoveryCase::StaleDiskReturn
            && plan.scenario == scenario.name,
        "stale-disk qualification requires the exact planned-storage gate and typed case"
    );
    ensure!(
        !config.use_cluster_ip,
        "stale-disk qualification requires a localhost S3 port-forward for byte-preserving ACK loss"
    );
    let context = initialize_fault_run(config, collector, scenario, execution_plan, run_id)?;
    let mut completion = context
        .events
        .completion_guard("run", "stale-disk run did not complete");
    deadline.check()?;
    prepare_fault_fixture(
        &config.cluster,
        FaultIsolation::DedicatedLinuxBlockDevice,
        1,
    )?;
    let mut tenant_cleanup = TenantCleanupGuard::new(&config.cluster);
    deadline.run(wait_for_ready_tenant(&config.cluster)).await?;

    let (endpoint, mut port_forward) = s3_access(config)?;
    deadline
        .run(ensure_s3_access(
            &mut port_forward,
            &config.cluster,
            &endpoint,
        ))
        .await?;
    let (access_key, secret_key) = resources::test_credentials();
    let s3 = S3WorkloadClient::new(
        &endpoint,
        &context.bucket,
        access_key,
        secret_key,
        config.request_timeout,
    )
    .await?;
    ensure!(
        s3.create_bucket(&context.history).await? == OperationOutcome::Ok,
        "stale-disk bucket creation did not succeed"
    );
    ensure!(
        s3.enable_bucket_versioning(&context.history).await? == OperationOutcome::Ok,
        "stale-disk qualification requires enabled bucket versioning"
    );
    let prefilled = deadline
        .run(prefill_objects(
            &s3,
            &context.history,
            &context.run_id,
            &context.workload_plan,
            context.workload_plan.object_count,
            config.prefill_concurrency,
            0,
        ))
        .await?;
    ensure!(
        prefilled.len() >= 4,
        "stale-disk workload requires four distinct prefilled keys"
    );

    // The destructive target is resolved only after the fresh Tenant is Ready.
    // `prepare_stale_disk` repeats the Kubernetes/PV/DM observations immediately
    // before activation and its guard owns bounded rollback on every exit.
    let host_proof = preflight_stale_disk_mutation(config, scenario, run_id)?;
    host_proof.validate()?;
    let mut disk = prepare_stale_disk(
        config,
        collector,
        scenario.case_name,
        &scenario.name,
        run_id,
        &host_proof,
    )?;
    disk.require_stale_offline_helper()?;
    let prepared_proof = disk.stale_host_proof().clone();
    let proof_json = serde_json::to_string_pretty(&prepared_proof)?;
    collector.write_text(scenario.case_name, HOST_STORAGE_PROOF_ARTIFACT, &proof_json)?;
    let volume = resolve_stale_volume_identity(
        config,
        collector,
        scenario,
        &endpoint,
        access_key,
        secret_key,
        &prepared_proof,
    )
    .await?;
    let identity = StorageRecoveryArtifactIdentity {
        run_id: context.run_id.clone(),
        scenario: scenario.name.clone(),
        case_name: scenario.case_name.to_string(),
        bucket: context.bucket.clone(),
    };
    let admin = RustfsAdminTransport::new(
        &endpoint,
        "us-east-1",
        access_key,
        secret_key,
        None,
        "s3chaos-stale-disk-return",
    )?;
    write_preflight_summary(
        collector,
        scenario,
        config,
        run_id,
        &[PreflightPhase::new(
            "stale-storage-target",
            vec![PreflightCheck::passed(
                "dedicated_dm_generation",
                "fresh Tenant Local PV, RustFS pool/set/drive, DM table, filesystem, and allowlists are exactly bound",
                ResponsibilityDomain::Harness,
            )],
        )],
    )?;
    let (lease, mut owned_context, helper) =
        acquire_stale_ownership(config, collector, scenario, &identity, &volume, &disk).await?;
    let mut helper = Some(helper);
    // Cancellation after this point must retain the staged Tenant until the
    // persistent helper supplies a cleanup proof and releases its Lease.
    tenant_cleanup.disarm();

    let mut owned_orphan = None::<StaleOwnedOrphanReceipt>;
    let mut detach_attempted = false;
    let mut reattach_storage_receipt = None::<StorageRecoveryOperationReceipt>;
    let mut reattach_owned_context = None::<OwnedStorageContext>;
    let mut watch = None::<StaleWatchGuard>;
    let primary = async {
        deadline.check()?;
        let first_snapshot = disk.snapshot("stale-watch-start")?;
        let (first_binding, watch_started_at_ms) = kubernetes_binding_evidence(config, &volume)?;
        watch = Some(StaleWatchGuard::start(
            config.clone(),
            prepared_proof.clone(),
        )?);
        thread::sleep(Duration::from_millis(250));

        renew_stale_ownership(
            stale_ownership_environment(config, collector, scenario, &volume, &lease),
            &mut disk,
            &mut owned_context,
            false,
        )
        .await?;
        let detach_context = owned_context.clone();
        let detach_operation = stale_dm_operation(&prepared_proof, &detach_context, false)?;
        disk.begin_stale_helper_mutation()?;
        detach_attempted = true;
        let storage_detach = helper
            .as_mut()
            .context("stale persistent helper session is unavailable before detach")?
            .execute(&detach_context, &detach_operation)
            .await?;
        persist_storage_receipt(
            collector,
            scenario,
            "stale-storage-detach-receipt.json",
            &storage_detach,
        )?;
        disk.arm_stale_helper_fallback()?;
        let activated_at_ms = storage_detach.completed_at_ms;
        context.history.mark_fault_active_at(activated_at_ms);
        renew_stale_ownership(
            stale_ownership_environment(config, collector, scenario, &volume, &lease),
            &mut disk,
            &mut owned_context,
            true,
        )
        .await?;
        thread::sleep(Duration::from_millis(250));
        let detach_snapshot = disk.snapshot("stale-detached")?;
        let detach_operation_id = storage_detach.operation_id.clone();
        let detach_evidence = lifecycle_operation_evidence(
            config,
            &identity,
            &volume,
            &prepared_proof,
            StaleLifecycleObservation {
                action: StaleDiskLifecycleAction::Detach,
                operation_id: detach_operation_id.clone(),
                started_at_ms: storage_detach.started_at_ms,
                snapshot: &detach_snapshot,
            },
        )?;
        let detach_receipt = receipt_from_evidence(&detach_evidence)?;

        let overwrite = prefilled[0].prepare_overwrite(1);
        let overwrite_record = s3.put_object_record(&overwrite, &context.history).await?;
        require_committed_version(&overwrite_record, "stale-disk overwrite")?;
        let delete_record = s3
            .delete_object_record(&prefilled[1].key, &context.history)
            .await?;
        require_committed_version(&delete_record, "stale-disk delete marker")?;

        let ack_object = prefilled[2].prepare_overwrite(2);
        let proxy = AckLossProxy::bind(&endpoint).await?;
        let ack_client = S3WorkloadClient::new_without_retries(
            proxy.endpoint(),
            &context.bucket,
            access_key,
            secret_key,
            config.request_timeout,
        )
        .await?;
        let ack_record = ack_client
            .put_object_record(&ack_object, &context.history)
            .await?;
        ensure!(
            matches!(
                ack_record.outcome,
                OperationOutcome::Unknown | OperationOutcome::Timeout | OperationOutcome::Failed
            ) && ack_record.http_status.is_none(),
            "ACK-loss PUT unexpectedly exposed a client-visible response"
        );
        let ack_loss = proxy.capture().await?.bind_operation(&ack_record)?;
        let mutation_window_ended_at_ms = [
            overwrite_record.ended_at_ms,
            delete_record.ended_at_ms,
            ack_record.ended_at_ms,
        ]
        .into_iter()
        .max()
        .context("stale mutation window has no operations")?;
        renew_stale_ownership(
            stale_ownership_environment(config, collector, scenario, &volume, &lease),
            &mut disk,
            &mut owned_context,
            true,
        )
        .await?;
        let storage_reattach_context = owned_context.clone();
        let reattach_operation =
            stale_dm_operation(&prepared_proof, &storage_reattach_context, true)?;
        let storage_reattach = helper
            .as_mut()
            .context("stale persistent helper session is unavailable before reattach")?
            .execute(&storage_reattach_context, &reattach_operation)
            .await?;
        persist_storage_receipt(
            collector,
            scenario,
            "stale-storage-reattach-receipt.json",
            &storage_reattach,
        )?;
        disk.accept_stale_helper_reattach()?;
        reattach_owned_context = Some(storage_reattach_context);
        reattach_storage_receipt = Some(storage_reattach.clone());
        let watch_samples = watch
            .as_mut()
            .context("stale device-mapper watch is unavailable")?
            .cancel_and_finish(Duration::from_secs(3))?;
        let (watch_samples, post_reattach_sample_count) =
            pre_reattach_watch_samples(watch_samples, storage_reattach.started_at_ms)?;
        let absence_observation_id = uuid::Uuid::new_v4().to_string();
        let absence = watch_observation(
            &identity,
            &volume,
            &prepared_proof,
            absence_observation_id.clone(),
            detach_operation_id.clone(),
            (&first_snapshot, watch_started_at_ms, first_binding),
            watch_samples,
        )?;
        collector.write_text(
            scenario.case_name,
            "stale-active-operations.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "runId": context.run_id,
                "activatedAtMs": activated_at_ms,
                "overwrite": overwrite_record,
                "deleteMarker": delete_record,
                "ackLoss": ack_loss,
                "absence": absence,
                "postReattachDiagnosticSampleCount": post_reattach_sample_count,
            }))?,
        )?;
        let recovery_snapshot = disk
            .recovery_snapshot()
            .context("stale disk restore lacks its recovery snapshot")?;
        let reattach_operation_id = storage_reattach.operation_id.clone();
        let reattach_evidence = lifecycle_operation_evidence(
            config,
            &identity,
            &volume,
            &prepared_proof,
            StaleLifecycleObservation {
                action: StaleDiskLifecycleAction::Reattach,
                operation_id: reattach_operation_id.clone(),
                started_at_ms: storage_reattach.started_at_ms,
                snapshot: recovery_snapshot,
            },
        )?;
        let reattach_receipt = receipt_from_evidence(&reattach_evidence)?;
        context.history.mark_fault_ended_now();
        renew_stale_ownership(
            stale_ownership_environment(config, collector, scenario, &volume, &lease),
            &mut disk,
            &mut owned_context,
            false,
        )
        .await?;
        deadline
            .run(ensure_s3_access(
                &mut port_forward,
                &config.cluster,
                &endpoint,
            ))
            .await?;
        let recovered_topology = require_volume_quorum_topology(
            config,
            &endpoint,
            access_key,
            secret_key,
            QuorumVolumeBoundary {
                class: QuorumCaseClass::Payload,
                beyond_read_tolerance: false,
            },
            &rustfs_target_inventory(&config.cluster, true, true)?.pod_proofs,
            &config.rustfs_volume_path,
        )
        .await?;
        ensure!(
            recovered_topology.topology.deployment_id == volume.rustfs_deployment_id
                && recovered_topology
                    .volume_quorum
                    .candidates
                    .iter()
                    .any(|candidate| candidate.drive_uuid == volume.rustfs_drive_uuid
                        && candidate.pool_index == volume.pool_index
                        && candidate.set_index == volume.set_index),
            "returned storage generation is absent from the recovered RustFS topology"
        );
        collector.write_text(
            scenario.case_name,
            RECOVERY_HEALTH_ARTIFACT,
            &serde_json::to_string_pretty(&recovered_topology)?,
        )?;
        // This is intentionally the first S3 activity after proving the exact
        // returned pool/set/drive generation. It is the version-aware verdict
        // for the complete fault-window history, before any recommit is made.
        let checker = deadline
            .run(check_s3_history(
                &s3,
                &context.history,
                true,
                context.workload_plan.concurrency,
                true,
            ))
            .await?;
        ensure!(checker.passed, "post-return S3 checker failed");
        let checker_body = serde_json::to_string(&checker)?;
        let returned_generation = StorageVolumeIdentity {
            observed_at_ms: reattach_receipt.completed_at_ms,
            ..volume.clone()
        };
        let committed_mutations = vec![
            CommittedMutationEvidence {
                operation_id: overwrite_record.id.clone(),
                kind: StaleMutationKind::Overwrite,
                object_key: overwrite_record
                    .key
                    .clone()
                    .context("stale overwrite lacks object key")?,
                version_id: overwrite_record
                    .version_id
                    .clone()
                    .context("stale overwrite lacks version id")?,
                acknowledged_at_ms: overwrite_record.ended_at_ms,
                absence_observation_id: absence_observation_id.clone(),
            },
            CommittedMutationEvidence {
                operation_id: delete_record.id.clone(),
                kind: StaleMutationKind::DeleteMarker,
                object_key: delete_record
                    .key
                    .clone()
                    .context("stale delete lacks object key")?,
                version_id: delete_record
                    .version_id
                    .clone()
                    .context("stale delete lacks version id")?,
                acknowledged_at_ms: delete_record.ended_at_ms,
                absence_observation_id,
            },
        ];
        let stale = StaleDiskReturnProof::prove(
            identity.clone(),
            volume.clone(),
            returned_generation.clone(),
            StaleDiskReturnEvidence {
                detached_at_ms: detach_receipt.completed_at_ms,
                mutation_window_ended_at_ms,
                returned_at_ms: reattach_receipt.completed_at_ms,
                detachment_operation_id: detach_operation_id,
                reattachment_operation_id: reattach_operation_id,
                lifecycle_evidence: StaleDiskLifecycleEvidence {
                    detach: detach_evidence,
                    reattach: reattach_evidence,
                },
                absence_observations: vec![absence],
                committed_mutations,
                post_return_checker: PostReturnCheckerEvidence {
                    response_sha256: sha256_text(&checker_body),
                    response_body: checker_body,
                },
            },
            &context.history.records(),
        )?;
        collector.write_text(
            scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&checker)?,
        )?;
        collector.write_text(
            scenario.case_name,
            DISK_GENERATION_PROOF_ARTIFACT,
            &serde_json::to_string_pretty(&stale)?,
        )?;

        let post_history_path = collector
            .case_dir(scenario.case_name)
            .join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT);
        let post_history = Recorder::create(post_history_path, &scenario.name, &context.run_id)?;
        let post_object = ObjectSpec::prepare_post_recovery(
            &context.run_id,
            0,
            context.workload_plan.size_at(0),
            context.workload_plan.seed ^ 0x5354_414c_455f_504f,
        );
        let post_record = s3.put_object_record(&post_object, &post_history).await?;
        require_committed_version(&post_record, "post-return write probe")?;
        collector.write_text(
            scenario.case_name,
            POST_RECOVERY_WRITE_REPORT_ARTIFACT,
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "scenario": scenario.name,
                "runId": context.run_id,
                "startedAtMs": post_record.started_at_ms,
                "completedAtMs": post_record.ended_at_ms,
                "objectCount": 1,
                "operationId": post_record.id,
                "key": post_record.key,
                "versionId": post_record.version_id,
                "passed": true,
            }))?,
        )?;

        let writes_quiesced_at_ms = now_ms()?.max(post_record.ended_at_ms + 1);
        thread::sleep(Duration::from_millis(2));
        let orphan_version_id = uuid::Uuid::new_v4().to_string();
        renew_stale_ownership(
            stale_ownership_environment(
                config,
                collector,
                scenario,
                &returned_generation,
                &lease,
            ),
            &mut disk,
            &mut owned_context,
            false,
        )
        .await?;
        let orphan = match execute_stale_helper(
            helper
                .as_mut()
                .context("stale persistent helper session is unavailable for orphan injection")?,
            &owned_context,
            stale_helper_request(
                &identity,
                &returned_generation,
                StaleOfflineHelperOperation::InjectOrphan {
                    object_key: prefilled[3].key.clone(),
                    version_id: orphan_version_id,
                },
            ),
        )
        .await?
        {
            StaleOfflineHelperResponse::OrphanInjected { receipt } => receipt,
            _ => bail!("stale helper returned a non-injection response"),
        };
        ensure!(
            orphan.created_at_ms > writes_quiesced_at_ms,
            "run-owned orphan injection is not ordered after S3 write quiescence"
        );
        owned_orphan = Some(orphan.clone());
        collector.write_text(
            scenario.case_name,
            STALE_HELPER_TRANSCRIPT_ARTIFACT,
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "injection": orphan,
            }))?,
        )?;

        let inventory_prefix = ObjectSpec::key_prefix(&context.run_id);
        let mut expected_versions = context
            .history
            .records()
            .into_iter()
            .filter(|record| {
                matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                )
                    && record.outcome == OperationOutcome::Ok
                    && record.http_status.is_some_and(|status| (200..300).contains(&status))
                    && record
                        .key
                        .as_deref()
                        .is_some_and(|key| key.starts_with(&inventory_prefix))
            })
            .map(|record| {
                Ok(StaleOfflineExpectedVersion {
                    operation_id: record.id,
                    object_key: record.key.context("committed inventory write lacks object key")?,
                    version_id: record
                        .version_id
                        .filter(|version_id| version_id != "null")
                        .context("committed inventory write lacks a version id")?,
                    object_sha256: record
                        .value_sha256
                        .context("committed inventory write lacks a content hash")?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        expected_versions.push(StaleOfflineExpectedVersion {
            operation_id: ack_record.id.clone(),
            object_key: ack_record
                .key
                .clone()
                .context("ACK-loss PUT lacks object key")?,
            version_id: ack_loss.upstream_version_id.clone(),
            object_sha256: ack_object.spec.sha256.clone(),
        });
        let dry_run = run_stale_path_heal(
            stale_ownership_environment(
                config,
                collector,
                scenario,
                &returned_generation,
                &lease,
            ),
            &mut disk,
            &mut owned_context,
            StaleHealRequest {
                admin: &admin,
                identity: &identity,
                object_key: &orphan.object_key,
                dry_run: true,
                deadline,
            },
        )
        .await?;
        collector.write_text(
            scenario.case_name,
            STALE_ADMIN_HEAL_ARTIFACT,
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "dryRun": dry_run,
            }))?,
        )?;

        let (before_inventory, before_capture) = stable_stale_inventory(
            stale_ownership_environment(
                config,
                collector,
                scenario,
                &returned_generation,
                &lease,
            ),
            &mut disk,
            helper
                .as_mut()
                .context("stale persistent helper session is unavailable for inventory")?,
            &mut owned_context,
            StableStaleInventoryRequest {
                identity: &identity,
                expected_versions: &expected_versions,
                orphan: &orphan,
                include_orphan: true,
            },
        )
        .await?;
        collector.write_text(
            scenario.case_name,
            SHARD_INVENTORY_BEFORE_ARTIFACT,
            &serde_json::to_string_pretty(&before_inventory)?,
        )?;
        collector.write_text(
            scenario.case_name,
            STALE_HELPER_TRANSCRIPT_ARTIFACT,
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "injection": orphan,
                "before": before_capture,
            }))?,
        )?;

        thread::sleep(Duration::from_millis(2));
        let live = run_stale_path_heal(
            stale_ownership_environment(
                config,
                collector,
                scenario,
                &returned_generation,
                &lease,
            ),
            &mut disk,
            &mut owned_context,
            StaleHealRequest {
                admin: &admin,
                identity: &identity,
                object_key: &orphan.object_key,
                dry_run: false,
                deadline,
            },
        )
        .await?;
        collector.write_text(
            scenario.case_name,
            STALE_ADMIN_HEAL_ARTIFACT,
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "dryRun": dry_run,
                "live": live,
            }))?,
        )?;

        thread::sleep(Duration::from_millis(2));
        let (after_inventory, after_capture) = stable_stale_inventory(
            stale_ownership_environment(
                config,
                collector,
                scenario,
                &returned_generation,
                &lease,
            ),
            &mut disk,
            helper
                .as_mut()
                .context("stale persistent helper session is unavailable for inventory")?,
            &mut owned_context,
            StableStaleInventoryRequest {
                identity: &identity,
                expected_versions: &expected_versions,
                orphan: &orphan,
                include_orphan: false,
            },
        )
        .await?;
        collector.write_text(
            scenario.case_name,
            SHARD_INVENTORY_AFTER_ARTIFACT,
            &serde_json::to_string_pretty(&after_inventory)?,
        )?;
        collector.write_text(
            scenario.case_name,
            STALE_HELPER_TRANSCRIPT_ARTIFACT,
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "injection": orphan,
                "before": before_capture,
                "after": after_capture,
            }))?,
        )?;
        // The helper proved the exact inode-bound orphan is now absent. Do not
        // attempt fallback deletion if a later evidence-validation step fails.
        owned_orphan = None;

        let fragments_for = |object_key: &str, version_id: &str| -> Result<Vec<String>> {
            let fragment_ids = before_capture
                .second
                .entries
                .iter()
                .filter(|entry| {
                    entry.object_key == object_key && entry.version_id == version_id
                })
                .map(|entry| entry.fragment_id.clone())
                .collect::<Vec<_>>();
            ensure!(
                !fragment_ids.is_empty(),
                "offline inventory did not resolve target-drive fragments for {object_key:?} version {version_id:?}"
            );
            Ok(fragment_ids)
        };
        let dry_body = serde_json::to_string(&dry_run)?;
        let live_body = serde_json::to_string(&live)?;
        let cleanup_started_at_ms = live.start.started_at_ms;
        let cleanup_completed_at_ms = live
            .status_samples
            .last()
            .context("live path heal lacks terminal status")?
            .completed_at_ms;
        let cleanup_response = RustfsDanglingCleanupResponse {
            operation_id: live.operation_id.clone(),
            bucket: identity.bucket.clone(),
            drive_uuid: returned_generation.rustfs_drive_uuid.clone(),
            filesystem_uuid: returned_generation.filesystem_uuid.clone(),
            before_inventory_snapshot_id: before_inventory.receipt.snapshot_id.clone(),
            started_at_ms: cleanup_started_at_ms,
            completed_at_ms: cleanup_completed_at_ms,
            deletion_authority: "offline-inventory-delta-and-injection-receipt".to_string(),
            dry_run_evidence: DanglingCleanupEvidence {
                response_sha256: sha256_text(&dry_body),
                response_body: dry_body,
            },
            live_evidence: DanglingCleanupEvidence {
                response_sha256: sha256_text(&live_body),
                response_body: live_body,
            },
            removed_fragment_ids: Vec::new(),
        };
        let cleanup_body = serde_json::to_string(&cleanup_response)?;
        let mut classified_versions = expected_versions
            .iter()
            .map(|expected| {
                Ok(ClassifiedVersionFragments {
                    evidence_id: uuid::Uuid::new_v4().to_string(),
                    operation_id: Some(expected.operation_id.clone()),
                    object_key: expected.object_key.clone(),
                    version_id: expected.version_id.clone(),
                    recoverability: if expected.operation_id == ack_record.id {
                        FragmentRecoverability::RecoverableUnknown
                    } else {
                        FragmentRecoverability::Committed
                    },
                    fragment_ids: fragments_for(&expected.object_key, &expected.version_id)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        classified_versions.push(ClassifiedVersionFragments {
            evidence_id: uuid::Uuid::new_v4().to_string(),
            operation_id: None,
            object_key: orphan.object_key.clone(),
            version_id: orphan.version_id.clone(),
            recoverability: FragmentRecoverability::UncommittedDangling,
            fragment_ids: vec![orphan.fragment_id.clone()],
        });
        let cleanup = DanglingCleanupProof {
            schema_version: crate::fault::storage_recovery::STORAGE_RECOVERY_PROOF_SCHEMA_VERSION,
            identity: identity.clone(),
            returned_generation: returned_generation.clone(),
            before_inventory_snapshot_id: before_inventory.receipt.snapshot_id.clone(),
            before_inventory_sha256: before_inventory.entries_sha256.clone(),
            after_inventory_snapshot_id: after_inventory.receipt.snapshot_id.clone(),
            after_inventory_sha256: after_inventory.entries_sha256.clone(),
            cleanup_operation_id: live.operation_id.clone(),
            orphan_injection: orphan.clone(),
            cleanup_evidence: Some(DanglingCleanupEvidence {
                response_sha256: sha256_text(&cleanup_body),
                response_body: cleanup_body,
            }),
            writes_quiesced_at_ms,
            started_at_ms: cleanup_started_at_ms,
            completed_at_ms: cleanup_completed_at_ms,
            ack_loss_puts: vec![ack_loss.clone()],
            classified_versions,
        };
        cleanup.validate_against_stale_return(
            &stale,
            &before_inventory,
            &after_inventory,
            &context.history.records(),
        )?;
        collector.write_text(
            scenario.case_name,
            DANGLING_CLEANUP_PROOF_ARTIFACT,
            &serde_json::to_string_pretty(&cleanup)?,
        )?;
        collector.write_text(
            scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "scenario": scenario.name,
                "runId": context.run_id,
                "prefilledObjects": prefilled.len(),
                "boundedFaultMutations": 3,
                "committedFaultMutations": 2,
                "recoverableUnknownMutations": 1,
                "totalPayloadBytes": context.workload_plan.total_payload_bytes,
            }))?,
        )?;
        collector.write_text(
            scenario.case_name,
            STALE_RUNTIME_EVIDENCE_ARTIFACT,
            &serde_json::to_string_pretty(&StaleRuntimeEvidence {
                schema_version: 1,
                run_id: context.run_id.clone(),
                scenario: scenario.name.clone(),
                target_persistent_volume: prepared_proof.target.persistent_volume.clone(),
                target_canonical_device: prepared_proof.target.canonical_device.clone(),
                activated_at_ms,
                restored_at_ms: reattach_receipt.completed_at_ms,
                overwrite_operation_id: overwrite_record.id,
                delete_marker_operation_id: delete_record.id,
                ack_loss,
                checker_passed: checker.passed,
            })?,
        )?;
        context.events.record(
            "checker-final",
            RunEventStatus::Succeeded,
            "stale disk returned and the version-aware checker passed",
            None,
        )?;
        Ok::<(), anyhow::Error>(())
    }
    .await;

    let mut primary = primary;
    if let Err(error) = &primary {
        let persist = (|| -> Result<()> {
            let body = serde_json::to_string_pretty(&serde_json::json!({
                "runId": context.run_id,
                "scenario": scenario.name,
                "primaryError": format!("{error:#}"),
                "evidencePersistedBeforeRecovery": true,
            }))?;
            collector
                .write_text(scenario.case_name, "stale-runtime-failure.json", &body)
                .map(|_| ())
        })();
        primary = preserve_primary(
            primary,
            persist.context("persist stale-disk primary failure before recovery"),
            "failure evidence persistence",
        );

        if detach_attempted && reattach_storage_receipt.is_none() {
            let owned_reattach = async {
                renew_stale_ownership(
                    stale_ownership_environment(config, collector, scenario, &volume, &lease),
                    &mut disk,
                    &mut owned_context,
                    true,
                )
                .await?;
                let recovery_context = owned_context.clone();
                let operation = stale_dm_operation(&prepared_proof, &recovery_context, true)?;
                let receipt = helper
                    .as_mut()
                    .context("stale persistent helper session is unavailable for error reattach")?
                    .execute(&recovery_context, &operation)
                    .await?;
                persist_storage_receipt(
                    collector,
                    scenario,
                    "stale-storage-error-reattach-receipt.json",
                    &receipt,
                )?;
                disk.accept_stale_helper_reattach()?;
                reattach_owned_context = Some(recovery_context);
                reattach_storage_receipt = Some(receipt);
                Ok::<(), anyhow::Error>(())
            }
            .await;
            primary = preserve_primary(primary, owned_reattach, "owned device reattachment");
            if reattach_storage_receipt.is_none() {
                primary = preserve_primary(
                    primary,
                    disk.restore().context(
                        "perform bounded legacy reattach after owned helper reattach failed",
                    ),
                    "bounded device reattachment fallback",
                );
            }
        }

        if let Some(watch) = watch.as_mut().filter(|watch| watch.task.is_some()) {
            primary = preserve_primary(
                primary,
                watch.cancel_and_finish(Duration::from_secs(3)).map(|_| ()),
                "bounded stale-watch cancellation after device reattachment",
            );
        }

        if reattach_storage_receipt.is_some()
            && let Some(orphan) = owned_orphan.as_ref()
        {
            let fallback = async {
                renew_stale_ownership(
                    stale_ownership_environment(config, collector, scenario, &volume, &lease),
                    &mut disk,
                    &mut owned_context,
                    false,
                )
                .await?;
                let response = execute_stale_helper(
                    helper
                        .as_mut()
                        .context("stale persistent helper session is unavailable for cleanup")?,
                    &owned_context,
                    stale_helper_request(
                        &identity,
                        &volume,
                        StaleOfflineHelperOperation::RemoveOwnedOrphan {
                            orphan: orphan.clone(),
                        },
                    ),
                )
                .await?;
                ensure!(
                    matches!(
                        &response,
                        StaleOfflineHelperResponse::OrphanRemoved { fragment_id, .. }
                            if fragment_id == &orphan.fragment_id
                    ),
                    "fallback helper returned the wrong orphan-removal receipt"
                );
                collector.write_text(
                    scenario.case_name,
                    "stale-orphan-fallback-cleanup.json",
                    &serde_json::to_string_pretty(&response)?,
                )?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            if fallback.is_ok() {
                owned_orphan = None;
            }
            primary = preserve_primary(primary, fallback, "owned orphan fallback cleanup");
        }
    }

    let mut ownership_released = false;
    if !detach_attempted {
        let abort = async {
            renew_stale_ownership(
                stale_ownership_environment(config, collector, scenario, &volume, &lease),
                &mut disk,
                &mut owned_context,
                false,
            )
            .await?;
            let cleanup = StorageRecoveryCleanupProof::AbortedBeforeMutation {
                observed_at_ms: now_ms()?.max(owned_context.observed_at_ms),
            };
            collector.write_text(
                scenario.case_name,
                "storage-recovery-cleanup-proof.json",
                &serde_json::to_string_pretty(&cleanup)?,
            )?;
            helper
                .take()
                .context("stale persistent helper session is unavailable for abort")?
                .finish(&owned_context, &cleanup)
                .await?;
            disk.finish_stale_pre_mutation_cleanup()
        }
        .await;
        ownership_released = abort.is_ok();
        primary = preserve_primary(primary, abort, "pre-mutation ownership release");
    } else if let (Some(receipt), Some(receipt_context), None) = (
        reattach_storage_receipt.as_ref(),
        reattach_owned_context.as_ref(),
        owned_orphan.as_ref(),
    ) {
        let release = async {
            renew_stale_ownership(
                stale_ownership_environment(config, collector, scenario, &volume, &lease),
                &mut disk,
                &mut owned_context,
                false,
            )
            .await?;
            let cleanup = StorageRecoveryCleanupProof::StaleDiskReattached {
                reattach_receipt: Box::new(receipt.clone()),
                reattach_context: Box::new(receipt_context.clone()),
                post_reattach_generation: Box::new(owned_context.host_generation.clone()),
                observed_at_ms: now_ms()?.max(owned_context.observed_at_ms),
            };
            collector.write_text(
                scenario.case_name,
                "storage-recovery-cleanup-proof.json",
                &serde_json::to_string_pretty(&cleanup)?,
            )?;
            helper
                .take()
                .context("stale persistent helper session is unavailable for cleanup")?
                .finish(&owned_context, &cleanup)
                .await?;
            disk.finish_stale_cleanup()
        }
        .await;
        ownership_released = release.is_ok();
        primary = preserve_primary(primary, release, "proof-bound storage ownership release");
    }

    // Evidence above is persisted before either the explicit restore or Drop
    // recovery. Tenant cleanup is attempted last and never hides the primary
    // product/harness failure.
    let cleanup = if ownership_released {
        fixture::reset_tenant_resources(&config.cluster)
    } else {
        Err(anyhow::anyhow!(
            "staged Tenant retained because proof-bound storage ownership release did not complete"
        ))
    };
    let result = match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup.context("clean up stale-disk Tenant")),
        (Err(primary), Err(cleanup)) => {
            Err(primary.context(format!("Tenant cleanup also failed: {cleanup:#}")))
        }
    };
    result?;
    context.events.record(
        "run",
        RunEventStatus::Succeeded,
        "stale-disk run completed successfully",
        None,
    )?;
    completion.complete();
    Ok(())
}

fn require_committed_version(
    record: &crate::fault::history::OperationRecord,
    label: &str,
) -> Result<()> {
    ensure!(
        record.outcome == OperationOutcome::Ok
            && record
                .http_status
                .is_some_and(|status| (200..300).contains(&status))
            && record
                .version_id
                .as_deref()
                .is_some_and(|version_id| !version_id.is_empty() && version_id != "null"),
        "{label} did not produce an explicit committed version"
    );
    Ok(())
}

fn preserve_primary(primary: Result<()>, secondary: Result<()>, label: &str) -> Result<()> {
    match (primary, secondary) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(secondary)) => Err(secondary.context(label.to_string())),
        (Err(primary), Err(secondary)) => {
            Err(primary.context(format!("{label} also failed: {secondary:#}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn ack_loss_proxy_forwards_exact_request_and_drops_response() {
        let upstream = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("upstream listener");
        let upstream_address = upstream.local_addr().expect("upstream address");
        let body_sha256 = hex::encode(Sha256::digest(b"abc"));
        let request = format!(
            "PUT /bucket/key HTTP/1.1\r\nHost: 127.0.0.1\r\nx-amz-content-sha256: {body_sha256}\r\nContent-Length: 3\r\n\r\nabc"
        )
        .into_bytes();
        let expected_request = request.to_vec();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream request");
            let received = read_content_length_message(
                &mut stream,
                ACK_LOSS_PROXY_MAX_REQUEST_BYTES,
                "test request",
            )
            .await
            .expect("complete upstream request");
            assert_eq!(received, expected_request);
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nx-amz-request-id: request-1\r\nx-amz-version-id: version-1\r\n\r\n",
                )
                .await
                .expect("upstream response");
        });
        let proxy = AckLossProxy::bind(&format!("http://{upstream_address}"))
            .await
            .expect("ACK-loss proxy");
        let proxy_address = proxy.endpoint;
        let mut client = TcpStream::connect(proxy_address)
            .await
            .expect("proxy client");
        client.write_all(&request).await.expect("proxy request");
        client.flush().await.expect("flush proxy request");
        let mut response = Vec::new();
        client
            .read_to_end(&mut response)
            .await
            .expect("read dropped response");
        assert!(response.is_empty());

        let capture = proxy.capture().await.expect("proxy capture");
        upstream_task.await.expect("upstream task");
        assert_eq!(capture.upstream_http_status, 200);
        assert_eq!(capture.upstream_request_id, "request-1");
        assert_eq!(capture.upstream_version_id, "version-1");
        assert_eq!(
            capture.request_sha256,
            hex::encode(Sha256::digest(&request))
        );
        assert_eq!(capture.request_value_sha256, body_sha256);
    }

    #[test]
    fn ack_loss_proxy_rejects_non_loopback_or_tls_upstream() {
        assert!(loopback_http_endpoint("https://127.0.0.1:9000").is_err());
        assert!(loopback_http_endpoint("http://192.0.2.1:9000").is_err());
        assert!(loopback_http_endpoint("http://127.0.0.1:9000/path").is_err());
    }

    #[test]
    fn stale_watch_cancellation_joins_only_after_reattach() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (release, released) = mpsc::sync_channel(1);
        let cancel_events = Arc::clone(&events);
        let watch_events = Arc::clone(&events);
        let mut watch = StaleWatchGuard::spawn(
            move || {
                cancel_events.lock().expect("events").push("cancel");
                release.send(()).expect("release watcher");
                Ok(())
            },
            move || {
                released.recv().expect("watch cancellation");
                watch_events.lock().expect("events").push("joined");
                Ok(Vec::new())
            },
        )
        .expect("watch guard");

        events.lock().expect("events").push("reattach");
        let started = std::time::Instant::now();
        watch
            .cancel_and_finish(Duration::from_secs(1))
            .expect("bounded watch finish");
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(
            events.lock().expect("events").as_slice(),
            ["reattach", "cancel", "joined"]
        );
    }

    #[test]
    fn stale_watch_deadline_bounds_a_hung_cancel_command() {
        let mut watch = StaleWatchGuard::spawn(
            || {
                thread::sleep(Duration::from_millis(300));
                Ok(())
            },
            || {
                thread::sleep(Duration::from_millis(300));
                Ok(Vec::new())
            },
        )
        .expect("watch guard");
        let started = Instant::now();
        let error = watch
            .cancel_and_finish(Duration::from_millis(20))
            .expect_err("slow cancellation must time out");
        assert!(error.to_string().contains("cancellation exceeded"));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn stale_watch_evidence_excludes_samples_observed_during_reattach_cleanup() {
        let samples = vec![
            StaleDmTableSample {
                observed_at_ms: 90,
                suspended: false,
                table: "0 8 error".to_string(),
            },
            StaleDmTableSample {
                observed_at_ms: 100,
                suspended: false,
                table: "0 8 linear 8:1 0".to_string(),
            },
            StaleDmTableSample {
                observed_at_ms: 110,
                suspended: false,
                table: "0 8 linear 8:1 0".to_string(),
            },
        ];
        let (evidence, post_reattach) =
            pre_reattach_watch_samples(samples, 100).expect("pre-reattach evidence");
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].observed_at_ms, 90);
        assert_eq!(post_reattach, 2);
    }

    #[test]
    fn stale_watch_drop_never_waits_for_remote_bound() {
        let watch = StaleWatchGuard::spawn(
            || Ok(()),
            || {
                thread::sleep(Duration::from_millis(300));
                Ok(Vec::new())
            },
        )
        .expect("watch guard");
        let started = std::time::Instant::now();
        drop(watch);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
