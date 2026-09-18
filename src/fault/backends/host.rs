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

use super::host_command;
pub use crate::fault::host_storage::{DmStatusSnapshot, DmVolumeMapping};
use crate::fault::host_storage::{dm_tables_match, helper_pod_name};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    thread::sleep,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    fault::{
        config::FaultTestConfig,
        host_storage::{
            DM_FILESYSTEM_CHECK_ARTIFACT, DM_FILESYSTEM_CHECK_SCHEMA_VERSION, DM_STALE_RETURN_KIND,
            DmFilesystemCheck, HOST_STORAGE_PROOF_ARTIFACT, HostStorageAllowlist,
            HostStorageMutationIntent, HostStorageMutationProof, HostStorageNodeSelector,
            HostStoragePersistentVolumeClaimRef, HostStoragePostCleanupObservation,
            HostStorageTargetObservation, normalized_dm_table_sha256,
        },
        plan::{FaultInjection, FaultKind},
        scenarios::FaultScenario,
    },
    framework::{
        artifacts::ArtifactCollector, command::CommandOutput, command::CommandSpec,
        config::ClusterTestConfig, kubectl::Kubectl,
    },
};

const MANAGED_BY_LABEL: &str = "app.kubernetes.io/managed-by";
const MANAGED_BY_VALUE: &str = "s3chaos";
const CRASH_TAINT_KEY: &str = "s3chaos.rustfs.com/dm-crash";
const DM_ATOMIC_ACTIVATION_MARKER: &str = "s3chaos-dm-activation-complete";
const DM_ATOMIC_ACTIVATION_NOT_STARTED_MARKER: &str = "s3chaos-dm-activation-not-started";
const DM_ATOMIC_ACTIVATION_ROLLBACK_MARKER: &str = "s3chaos-dm-activation-rollback-attempted";
const DM_ATOMIC_ACTIVATION_SCRIPT: &str = r#"set -u
name=$1
expected_device=$2
mount_path=$3
recovery_table=$4
fault_table=$5
mutation_started=0

rollback() {
    /usr/sbin/dmsetup suspend --noflush --nolockfs "$name" >/dev/null 2>&1 || true
    /usr/sbin/dmsetup load "$name" --table "$recovery_table" >/dev/null 2>&1 || true
    /usr/sbin/dmsetup resume --noudevsync "$name" >/dev/null 2>&1 || true
}

abort_activation() {
    printf '%s\n' "$1" >&2
    if [ "$mutation_started" -eq 1 ]; then
        rollback
        printf '%s\n' 's3chaos-dm-activation-rollback-attempted'
    else
        printf '%s\n' 's3chaos-dm-activation-not-started'
    fi
    exit 1
}

actual_device=$(/usr/bin/readlink -f "/dev/mapper/$name") || abort_activation "could not resolve device-mapper target"
[ "$actual_device" = "$expected_device" ] || abort_activation "device-mapper canonical device changed after preparation"
mount_source=$(/usr/bin/findmnt -n --raw -o SOURCE --mountpoint "$mount_path") || abort_activation "approved device-mapper mount disappeared after preparation"
mount_device=$(/usr/bin/readlink -f "$mount_source") || abort_activation "could not resolve approved mount source"
[ "$mount_device" = "$expected_device" ] || abort_activation "approved mount no longer uses the prepared device-mapper target"
state=$(/usr/sbin/dmsetup info --columns --noheadings --options suspended "$name" | /usr/bin/tr -d '[:space:]' | /usr/bin/tr '[:upper:]' '[:lower:]') || abort_activation "could not read device-mapper state"
case "$state" in
    active|no|n|0) ;;
    suspended|yes|y|1) abort_activation "device-mapper target was already suspended" ;;
    *) abort_activation "device-mapper target returned an unsupported state" ;;
esac
active_table=$(/usr/sbin/dmsetup table "$name") || abort_activation "could not read device-mapper table"
[ "$active_table" = "$recovery_table" ] || abort_activation "device-mapper recovery table drifted after preparation"

mutation_started=1
/usr/sbin/dmsetup suspend --nolockfs "$name" || abort_activation "could not suspend device-mapper target"
/usr/sbin/dmsetup load "$name" --table "$fault_table" || abort_activation "could not load device-mapper fault table"
/usr/sbin/dmsetup resume --noudevsync "$name" || abort_activation "could not resume device-mapper fault table"

state=$(/usr/sbin/dmsetup info --columns --noheadings --options suspended "$name" | /usr/bin/tr -d '[:space:]' | /usr/bin/tr '[:upper:]' '[:lower:]') || abort_activation "could not verify device-mapper state"
case "$state" in
    active|no|n|0) ;;
    suspended|yes|y|1) abort_activation "device-mapper target remained suspended" ;;
    *) abort_activation "device-mapper target returned an unsupported state" ;;
esac
active_table=$(/usr/sbin/dmsetup table "$name") || abort_activation "could not verify device-mapper table"
[ "$active_table" = "$fault_table" ] || abort_activation "device-mapper fault table did not become active"
printf '%s\n' 's3chaos-dm-activation-complete'
"#;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DmFaultBehavior {
    ErrorInjection,
    DropWritesCrash,
    StaleEio,
}

impl DmFaultBehavior {
    fn requires_crash_boundary(self) -> bool {
        matches!(self, Self::DropWritesCrash)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmSuspendMode {
    Default,
    NoFlush,
    NoLockFs,
    NoFlushNoLockFs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmTransitionPolicy<'a> {
    Apply { recovery_table: &'a str },
    Rollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmMountState {
    Mounted,
    Unmounting,
    Unmounted,
    Mounting,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmFilesystemRecoveryState {
    NotRequired,
    Pending,
    Failed,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmUnmountExpectation {
    FaultTableActive,
    RecoveryTableActive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmPodDeletionMode {
    CrashBoundary,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DmPodReadiness {
    Required,
    MayBeUnready,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DmInitialPodAction {
    DeleteOriginal,
    WaitForOriginal,
    AlreadyQuiesced(Option<String>),
}

impl DmMountState {
    fn proves_expected_mount(self) -> bool {
        matches!(self, Self::Mounted)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DmPodVolumeBinding {
    node: String,
    pod: String,
    pod_uid: String,
    volume_name: String,
    pvc: String,
    container_mount_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DmObservedState {
    suspended: bool,
    active_table: String,
}

trait DmTransitionPort {
    fn observe(&mut self) -> Result<DmObservedState>;
    fn suspend(&mut self, mode: DmSuspendMode) -> Result<()>;
    fn load(&mut self, table: &str) -> Result<()>;
    fn resume(&mut self) -> Result<()>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum HostMutationPhase {
    Prepared,
    Activating,
    Active,
    Rollback,
    RecoveryRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HostMutationState {
    schema_version: u8,
    token: String,
    owner_pid: u32,
    run_id: String,
    phase: HostMutationPhase,
}

#[derive(Debug)]
struct HostMutationLease {
    path: PathBuf,
    state: HostMutationState,
    persisted: bool,
}

impl HostMutationLease {
    fn from_config(config: &FaultTestConfig, run_id: &str) -> Result<Self> {
        let path = config.host_mutation_state_file.clone().context(
            "RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_FILE is required for device-mapper mutation",
        )?;
        let token = config.host_mutation_state_token.clone().context(
            "RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_TOKEN is required for device-mapper mutation",
        )?;
        ensure!(
            path.is_absolute() && path.file_name().is_some(),
            "RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_FILE must be an absolute file path"
        );
        ensure!(
            !token.is_empty()
                && token.len() <= 128
                && token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            "RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_TOKEN contains unsupported characters"
        );
        let parent = path
            .parent()
            .context("host mutation state path has no parent directory")?;
        ensure!(
            parent != Path::new("/")
                && config.cluster.artifacts_dir.starts_with(parent)
                && path.file_name().and_then(|value| value.to_str())
                    == Some(format!(".host-mutation-{token}.json").as_str()),
            "host mutation state must use its token-specific name within the fault artifact tree"
        );
        ensure!(!run_id.trim().is_empty(), "host mutation run id is empty");
        Ok(Self {
            path,
            state: HostMutationState {
                schema_version: 1,
                token,
                owner_pid: std::process::id(),
                run_id: run_id.to_string(),
                phase: HostMutationPhase::Prepared,
            },
            persisted: false,
        })
    }

    fn set_phase(&mut self, phase: HostMutationPhase) -> Result<()> {
        if self.persisted {
            self.require_owned_persisted_state()?;
        } else {
            ensure!(
                !self.path.exists(),
                "refusing to replace a pre-existing host mutation state file"
            );
        }
        self.state.phase = phase;
        let parent = self
            .path
            .parent()
            .context("host mutation state path has no parent directory")?;
        ensure!(
            parent.is_dir(),
            "host mutation state parent directory does not exist"
        );
        let temporary = temporary_state_path(&self.path, self.state.owner_pid);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("create host mutation state temporary file {temporary:?}"))?;
        let encoded = serde_json::to_vec(&self.state)?;
        if let Err(error) = file.write_all(&encoded).and_then(|()| file.sync_all()) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("persist host mutation state");
        }
        drop(file);
        if let Err(error) = fs::rename(&temporary, &self.path) {
            let _ = fs::remove_file(&temporary);
            return Err(error).context("publish host mutation state atomically");
        }
        self.persisted = true;
        Ok(())
    }

    fn clear(&mut self) -> Result<()> {
        if !self.persisted {
            return Ok(());
        }
        self.require_owned_persisted_state()?;
        fs::remove_file(&self.path)
            .with_context(|| format!("remove host mutation state {:?}", self.path))?;
        self.persisted = false;
        Ok(())
    }

    fn require_owned_persisted_state(&self) -> Result<()> {
        let persisted = fs::read(&self.path)
            .with_context(|| format!("read host mutation state {:?} before cleanup", self.path))?;
        let persisted: HostMutationState = serde_json::from_slice(&persisted)
            .context("parse host mutation state before cleanup")?;
        ensure!(
            persisted.token == self.state.token
                && persisted.owner_pid == self.state.owner_pid
                && persisted.run_id == self.state.run_id,
            "host mutation state is owned by another process or run"
        );
        Ok(())
    }
}

fn temporary_state_path(path: &Path, owner_pid: u32) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("host-mutation-state");
    path.with_file_name(format!(".{file_name}.{owner_pid}.tmp"))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmMountSnapshot {
    source: String,
    canonical_source: String,
    filesystem: String,
    options: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmCrashBoundarySnapshot {
    scenario: String,
    run_id: String,
    started_at_ms: u64,
    completed_at_ms: u64,
    taint: String,
    old_pod_uid: String,
    replacement_pod_uid: Option<String>,
    filesystem_unmounted: bool,
    mapper_mounts_absent: bool,
    mount_before: DmMountSnapshot,
    fault: DmStatusSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct DmCrashRecoverySnapshot {
    scenario: String,
    run_id: String,
    recovered_at_ms: u64,
    taint_removed: bool,
    mount: DmMountSnapshot,
    expected_table: String,
    fault: DmStatusSnapshot,
}

#[derive(Debug)]
pub struct DmFlakeyGuard {
    config: ClusterTestConfig,
    collector: ArtifactCollector,
    case_name: String,
    scenario: String,
    run_id: String,
    helper_pod: String,
    dm_name: String,
    behavior: DmFaultBehavior,
    fault_table: String,
    recovery_table: String,
    mapping: DmVolumeMapping,
    mount_snapshot: Option<DmMountSnapshot>,
    node_tainted: bool,
    mount_state: DmMountState,
    crash_boundary_completed: bool,
    recovery_snapshot: Option<DmStatusSnapshot>,
    preflight_proof: HostStorageMutationProof,
    mutation_lease: HostMutationLease,
    fault_applied: bool,
    filesystem_recovery: DmFilesystemRecoveryState,
    stale_cleanup_pending: bool,
    restored: bool,
}

#[derive(Debug)]
pub struct DmFlakeySpec<'a> {
    pub node: &'a str,
    pub mount_path: &'a str,
    pub helper_image: &'a str,
    pub name: &'a str,
    behavior: DmFaultBehavior,
    pub fault_table: Option<&'a str>,
    pub recovery_table: Option<&'a str>,
    pub run_id: &'a str,
}

pub(crate) fn preflight_stale_disk_mutation(
    config: &FaultTestConfig,
    scenario: &FaultScenario,
    run_id: &str,
) -> Result<HostStorageMutationProof> {
    ensure!(
        scenario.name == crate::fault::scenarios::STALE_DISK_RETURN_DETECT_SCENARIO,
        "stale device-mapper preflight is bound to another scenario"
    );
    let spec = stale_dm_spec(config, run_id)?;
    validate_stale_config(config, &spec)?;
    let observer_pod = config
        .dm_observer_pod
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_POD is required")?;
    let observer_namespace = config
        .dm_observer_namespace
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE is required")?;
    let observation = observe_dm_target_read_only(
        &config.cluster,
        &spec,
        &config.rustfs_volume_path,
        observer_namespace,
        observer_pod,
    )?;
    HostStorageMutationProof::prove_device_mapper(
        HostStorageMutationIntent {
            scenario: scenario.name.clone(),
            fault_name: "stale-disk-eio".to_string(),
            fault_kind: DM_STALE_RETURN_KIND.to_string(),
            run_id: run_id.to_string(),
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            observer_namespace: observer_namespace.to_string(),
            observer_pod: observer_pod.to_string(),
            backend_specific_destructive_opt_in: config.device_mapper_destructive_enabled,
            allowlist: HostStorageAllowlist {
                nodes: config.host_mutation_allowed_nodes.clone(),
                devices: config.host_mutation_allowed_devices.clone(),
                persistent_volumes: config.host_mutation_allowed_persistent_volumes.clone(),
            },
            fault_table: None,
        },
        observation,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaleDmTableSample {
    pub(crate) observed_at_ms: u64,
    pub(crate) table: String,
    pub(crate) suspended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StaleHostRuntimeIdentity {
    pub(crate) target_mount_namespace_id: String,
    pub(crate) filesystem_uuid: String,
}

pub(crate) fn observe_stale_host_runtime_identity(
    config: &FaultTestConfig,
    proof: &HostStorageMutationProof,
    target_container_id: &str,
) -> Result<StaleHostRuntimeIdentity> {
    proof.validate()?;
    let cri_container_id = target_container_id
        .strip_prefix("containerd://")
        .context("stale-disk target must use an explicit containerd container id")?;
    ensure!(
        !cri_container_id.trim().is_empty(),
        "stale-disk target container id is empty"
    );
    let inspect = observer_host_command(
        &config.cluster,
        &proof.observer_namespace,
        &proof.observer_pod,
        ["/usr/bin/crictl", "inspect", cri_container_id],
    )?;
    let inspect_json = serde_json::from_str::<Value>(&inspect.stdout)
        .context("parse stale-disk target container runtime response")?;
    ensure!(
        inspect_json.pointer("/status/id").and_then(Value::as_str) == Some(cri_container_id),
        "container runtime response identifies another target container"
    );
    let pid = inspect_json
        .pointer("/info/pid")
        .and_then(Value::as_u64)
        .context("container runtime response lacks target pid")?;
    ensure!(pid > 0, "container runtime returned target pid zero");
    let mount_namespace = observer_host_command(
        &config.cluster,
        &proof.observer_namespace,
        &proof.observer_pod,
        [
            "/usr/bin/readlink".to_string(),
            format!("/proc/{pid}/ns/mnt"),
        ],
    )?
    .stdout
    .trim()
    .to_string();
    let filesystem_uuid = observer_host_command(
        &config.cluster,
        &proof.observer_namespace,
        &proof.observer_pod,
        [
            "/usr/sbin/blkid",
            "-s",
            "UUID",
            "-o",
            "value",
            proof.target.canonical_device.as_str(),
        ],
    )?
    .stdout
    .trim()
    .to_string();
    ensure!(
        mount_namespace.starts_with("mnt:[")
            && mount_namespace.ends_with(']')
            && !filesystem_uuid.is_empty(),
        "stale-disk target lacks mount-namespace or filesystem generation identity"
    );
    Ok(StaleHostRuntimeIdentity {
        target_mount_namespace_id: mount_namespace,
        filesystem_uuid,
    })
}

const STALE_DM_WATCH_SCRIPT: &str = r#"set -eu
name=$1
count=$2
cancel=$3
trap '/usr/bin/rm -f -- "$cancel"' EXIT
i=0
while [ "$i" -lt "$count" ]; do
    [ ! -e "$cancel" ] || break
    observed=$(/usr/bin/date +%s%3N)
    suspended=$(/usr/sbin/dmsetup info --columns --noheadings --options suspended "$name" | /usr/bin/tr -d '[:space:]' | /usr/bin/tr '[:upper:]' '[:lower:]')
    table=$(/usr/sbin/dmsetup table --showkeys "$name")
    case "$suspended" in
        active|no|n|0) suspended=false ;;
        suspended|yes|y|1) suspended=true ;;
        *) exit 71 ;;
    esac
    printf '%s|%s|%s\n' "$observed" "$suspended" "$table"
    i=$((i + 1))
    /usr/bin/sleep 0.05
done"#;

const STALE_DM_WATCH_CANCEL_SCRIPT: &str = r#"set -eu
cancel=$1
case "$cancel" in
    /tmp/s3chaos-stale-watch-*) ;;
    *) exit 72 ;;
esac
: > "$cancel""#;

const STALE_DM_WATCH_PREPARE_SCRIPT: &str = r#"set -eu
cancel=$1
case "$cancel" in
    /tmp/s3chaos-stale-watch-*) ;;
    *) exit 72 ;;
esac
/usr/bin/rm -f -- "$cancel""#;

pub(crate) fn stale_dm_watch_cancel_file(proof: &HostStorageMutationProof) -> Result<String> {
    proof.validate()?;
    let table = normalized_dm_table_sha256(&proof.tables.recovery_table)?;
    Ok(format!(
        "/tmp/s3chaos-stale-watch-{}-{}",
        &table[..24],
        proof.generated_at_ms
    ))
}

pub(crate) fn cancel_stale_dm_watch(
    config: &FaultTestConfig,
    proof: &HostStorageMutationProof,
) -> Result<()> {
    let cancel_file = stale_dm_watch_cancel_file(proof)?;
    let output = observer_host_command(
        &config.cluster,
        &proof.observer_namespace,
        &proof.observer_pod,
        [
            "/bin/sh".to_string(),
            "-c".to_string(),
            STALE_DM_WATCH_CANCEL_SCRIPT.to_string(),
            "s3chaos-stale-watch-cancel".to_string(),
            cancel_file,
        ],
    )?;
    ensure!(
        output.stdout.trim().is_empty() && output.stderr.trim().is_empty(),
        "stale device-mapper watch cancellation wrote unexpected output"
    );
    Ok(())
}

pub(crate) fn prepare_stale_dm_watch(
    config: &FaultTestConfig,
    proof: &HostStorageMutationProof,
) -> Result<()> {
    let cancel_file = stale_dm_watch_cancel_file(proof)?;
    let output = observer_host_command(
        &config.cluster,
        &proof.observer_namespace,
        &proof.observer_pod,
        [
            "/bin/sh".to_string(),
            "-c".to_string(),
            STALE_DM_WATCH_PREPARE_SCRIPT.to_string(),
            "s3chaos-stale-watch-prepare".to_string(),
            cancel_file,
        ],
    )?;
    ensure!(
        output.stdout.trim().is_empty() && output.stderr.trim().is_empty(),
        "stale device-mapper watch preparation wrote unexpected output"
    );
    Ok(())
}

pub(crate) fn capture_stale_dm_watch(
    config: &FaultTestConfig,
    proof: &HostStorageMutationProof,
    sample_count: usize,
) -> Result<Vec<StaleDmTableSample>> {
    proof.validate()?;
    ensure!(
        proof.scenario == crate::fault::scenarios::STALE_DISK_RETURN_DETECT_SCENARIO
            && proof.run_id != "preflight"
            && (3..=2_400).contains(&sample_count),
        "stale device-mapper watch identity or bounded sample count is invalid"
    );
    let cancel_file = stale_dm_watch_cancel_file(proof)?;
    let output = observer_host_command(
        &config.cluster,
        &proof.observer_namespace,
        &proof.observer_pod,
        [
            "/bin/sh".to_string(),
            "-c".to_string(),
            STALE_DM_WATCH_SCRIPT.to_string(),
            "s3chaos-stale-watch".to_string(),
            proof.target.mapper_name.clone(),
            sample_count.to_string(),
            cancel_file,
        ],
    )?;
    ensure!(
        output.stderr.trim().is_empty(),
        "stale device-mapper watch wrote to stderr"
    );
    let samples = output
        .stdout
        .lines()
        .map(|line| {
            let mut fields = line.splitn(3, '|');
            let observed_at_ms = fields
                .next()
                .context("stale DM watch sample lacks a timestamp")?
                .parse::<u64>()
                .context("stale DM watch timestamp is invalid")?;
            let suspended = match fields
                .next()
                .context("stale DM watch sample lacks suspended state")?
            {
                "false" => false,
                "true" => true,
                _ => bail!("stale DM watch returned an invalid suspended state"),
            };
            let table = fields
                .next()
                .context("stale DM watch sample lacks a mapper table")?
                .trim()
                .to_string();
            ensure!(
                !table.is_empty()
                    && (dm_tables_match(&table, &proof.tables.recovery_table)?
                        || dm_tables_match(&table, &proof.tables.fault_table)?),
                "stale DM watch observed an unowned mapper table"
            );
            Ok(StaleDmTableSample {
                observed_at_ms,
                table,
                suspended,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        (3..=sample_count).contains(&samples.len())
            && samples.windows(2).all(|window| {
                window[0].observed_at_ms < window[1].observed_at_ms
                    && window[1].observed_at_ms - window[0].observed_at_ms <= 100
            }),
        "stale device-mapper watch was incomplete or exceeded its 100ms sampling bound"
    );
    Ok(samples)
}

fn validate_stale_config(config: &FaultTestConfig, spec: &DmFlakeySpec<'_>) -> Result<()> {
    ensure!(
        config.device_mapper_destructive_enabled,
        "stale device-mapper mutation requires RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1"
    );
    let observer_pod = config
        .dm_observer_pod
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_POD is required")?;
    let observer_namespace = config
        .dm_observer_namespace
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE is required")?;
    ensure!(
        observer_namespace != config.cluster.test_namespace,
        "stale storage helper must be outside the disposable Tenant namespace"
    );
    ensure!(
        !observer_pod.trim().is_empty(),
        "stale storage helper Pod name is empty"
    );
    require_exact_config_allowlist(
        "RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST",
        &config.host_mutation_allowed_nodes,
        spec.node,
    )?;
    require_exact_config_allowlist(
        "RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST",
        &config.host_mutation_allowed_devices,
        &format!("/dev/mapper/{}", spec.name),
    )?;
    ensure!(
        config.host_mutation_allowed_persistent_volumes.len() == 1
            && !config.host_mutation_allowed_persistent_volumes[0]
                .trim()
                .is_empty(),
        "RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST must contain exactly one PV"
    );
    HostMutationLease::from_config(config, "stale-preflight")?;
    Ok(())
}

pub(crate) struct FaultApplyRequest<'a> {
    pub config: &'a FaultTestConfig,
    pub collector: &'a ArtifactCollector,
    pub scenario: &'a FaultScenario,
    pub injection: &'a FaultInjection,
    pub run_id: &'a str,
    pub host_storage_proof: &'a HostStorageMutationProof,
}

pub(crate) struct HostStoragePreflightRequest<'a> {
    pub config: &'a FaultTestConfig,
    pub scenario: &'a FaultScenario,
    pub injection: &'a FaultInjection,
    pub run_id: &'a str,
    pub fault_name: &'a str,
}

pub(crate) fn prepare_fault(request: &FaultApplyRequest<'_>) -> Result<DmFlakeyGuard> {
    match dm_behavior(request.injection.kind()) {
        Some(behavior) => {
            let spec = dm_flakey_spec(request.config, request.run_id, behavior)?;
            prepare_dm_flakey(
                request.config,
                &spec,
                request.collector,
                request.scenario.case_name,
                &request.scenario.name,
                request.host_storage_proof,
            )
        }
        None => bail!(
            "fault kind {} must be applied by a Chaos Mesh backend",
            request.injection.kind().as_str()
        ),
    }
}

pub(crate) fn validate_config(config: &FaultTestConfig, kind: FaultKind) -> Result<()> {
    let behavior = dm_behavior(kind)
        .with_context(|| format!("fault kind {} is not a device-mapper fault", kind.as_str()))?;
    let spec = dm_flakey_spec(config, "preflight", behavior)?;
    validate_dm_spec(&spec)?;
    ensure!(
        config
            .dm_observer_pod
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty()),
        "RUSTFS_FAULT_TEST_DM_OBSERVER_POD is required for side-effect-free host observation"
    );
    ensure!(
        config
            .dm_observer_namespace
            .as_deref()
            .is_some_and(|name| !name.trim().is_empty()),
        "RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE is required for side-effect-free host observation"
    );
    ensure!(
        config.dm_observer_namespace.as_deref() != Some(config.cluster.test_namespace.as_str()),
        "host observer must be outside the disposable fault Tenant namespace"
    );
    ensure!(
        config.device_mapper_destructive_enabled,
        "device-mapper mutation requires RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1"
    );
    require_exact_config_allowlist(
        "RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST",
        &config.host_mutation_allowed_nodes,
        spec.node,
    )?;
    require_exact_config_allowlist(
        "RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST",
        &config.host_mutation_allowed_devices,
        &format!("/dev/mapper/{}", spec.name),
    )?;
    ensure!(
        config.host_mutation_allowed_persistent_volumes.len() == 1
            && !config.host_mutation_allowed_persistent_volumes[0]
                .trim()
                .is_empty(),
        "RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST must contain exactly one non-empty PV name"
    );
    HostMutationLease::from_config(config, "preflight")?;
    Ok(())
}

pub(crate) fn preflight_mutation(
    request: &HostStoragePreflightRequest<'_>,
) -> Result<HostStorageMutationProof> {
    let behavior = dm_behavior(request.injection.kind()).with_context(|| {
        format!(
            "fault kind {} is not a device-mapper mutation",
            request.injection.kind().as_str()
        )
    })?;
    validate_config(request.config, request.injection.kind())?;
    let spec = dm_flakey_spec(request.config, request.run_id, behavior)?;
    let observer_pod = request
        .config
        .dm_observer_pod
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_POD is required")?;
    let observer_namespace = request
        .config
        .dm_observer_namespace
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE is required")?;
    let observation = observe_dm_target_read_only(
        &request.config.cluster,
        &spec,
        &request.config.rustfs_volume_path,
        observer_namespace,
        observer_pod,
    )?;
    HostStorageMutationProof::prove_device_mapper(
        HostStorageMutationIntent {
            scenario: request.scenario.name.clone(),
            fault_name: request.fault_name.to_string(),
            fault_kind: request.injection.kind().as_str().to_string(),
            run_id: request.run_id.to_string(),
            context: request.config.cluster.context.clone(),
            namespace: request.config.cluster.test_namespace.clone(),
            tenant: request.config.cluster.tenant_name.clone(),
            observer_namespace: observer_namespace.to_string(),
            observer_pod: observer_pod.to_string(),
            backend_specific_destructive_opt_in: request.config.device_mapper_destructive_enabled,
            allowlist: HostStorageAllowlist {
                nodes: request.config.host_mutation_allowed_nodes.clone(),
                devices: request.config.host_mutation_allowed_devices.clone(),
                persistent_volumes: request
                    .config
                    .host_mutation_allowed_persistent_volumes
                    .clone(),
            },
            fault_table: spec.fault_table.map(str::to_string),
        },
        observation,
    )
}

fn dm_behavior(kind: FaultKind) -> Option<DmFaultBehavior> {
    match kind {
        FaultKind::RustfsBlockDeviceFlakey => Some(DmFaultBehavior::ErrorInjection),
        FaultKind::RustfsBlockDeviceDropWritesCrash => Some(DmFaultBehavior::DropWritesCrash),
        _ => None,
    }
}

fn require_exact_config_allowlist(label: &str, values: &[String], expected: &str) -> Result<()> {
    ensure!(
        values.len() == 1 && values[0].trim() == expected,
        "{label} must contain exactly {expected:?}"
    );
    Ok(())
}

fn observe_dm_target_read_only(
    config: &ClusterTestConfig,
    spec: &DmFlakeySpec<'_>,
    rustfs_volume_path: &str,
    observer_namespace: &str,
    observer_pod: &str,
) -> Result<HostStorageTargetObservation> {
    let mapping = verify_dm_volume_mapping(
        config,
        spec.node,
        rustfs_volume_path,
        spec.mount_path,
        DmPodReadiness::Required,
    )?;
    validate_observer_pod(config, spec, observer_namespace, observer_pod)?;
    let mount_source =
        observer_findmnt_field(config, observer_namespace, observer_pod, &mapping, "SOURCE")?;
    let mount_canonical_source = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        ["/usr/bin/readlink", "-f", mount_source.as_str()],
    )?
    .stdout
    .trim()
    .to_string();
    let filesystem =
        observer_findmnt_field(config, observer_namespace, observer_pod, &mapping, "FSTYPE")?;
    let logical_device = format!("/dev/mapper/{}", spec.name);
    let canonical_device = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        ["/usr/bin/readlink", "-f", logical_device.as_str()],
    )?
    .stdout
    .trim()
    .to_string();
    ensure!(
        !canonical_device.is_empty() && canonical_device == mount_canonical_source,
        "fault-test PV mount {:?} on node {:?} does not resolve to device-mapper target {:?}",
        mapping.mount_path,
        mapping.node,
        spec.name
    );
    let original_table = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        ["/usr/sbin/dmsetup", "table", spec.name],
    )?
    .stdout;
    let recovery_table = spec
        .recovery_table
        .map(str::to_string)
        .unwrap_or_else(|| original_table.trim().to_string());
    ensure!(
        !recovery_table.trim().is_empty(),
        "dmsetup returned an empty recovery table for {:?}",
        spec.name
    );
    if spec.recovery_table.is_some() {
        ensure!(
            dm_tables_match(&recovery_table, &original_table)?,
            "configured recovery table must match the active device-mapper table"
        );
    }
    Ok(HostStorageTargetObservation {
        node: mapping.node,
        node_uid: mapping.node_uid,
        node_labels: mapping.node_labels,
        pod: mapping.pod,
        pod_uid: mapping.pod_uid,
        volume_name: mapping.volume_name,
        persistent_volume_claim: mapping.pvc,
        persistent_volume_claim_uid: mapping.pvc_uid,
        persistent_volume_claim_phase: mapping.pvc_phase,
        persistent_volume: mapping.pv,
        persistent_volume_uid: mapping.pv_uid,
        persistent_volume_phase: mapping.pv_phase,
        persistent_volume_claim_ref: mapping.pv_claim_ref,
        node_selector: mapping.node_selector,
        container_mount_path: mapping.container_mount_path,
        persistent_volume_path: mapping.mount_path,
        mapper_name: spec.name.to_string(),
        logical_device,
        canonical_device,
        mount_source,
        mount_canonical_source,
        filesystem,
        recovery_table,
        observed_at_ms: now_ms(),
    })
}

fn validate_observer_pod(
    config: &ClusterTestConfig,
    spec: &DmFlakeySpec<'_>,
    observer_namespace: &str,
    observer_pod: &str,
) -> Result<()> {
    let pod = Kubectl::new(config)
        .namespaced(observer_namespace)
        .command(["get", "pod", observer_pod, "-o", "json"])
        .run_checked()
        .context("reading pre-provisioned host observer Pod")?;
    let pod = serde_json::from_str::<Value>(&pod.stdout).context("parse host observer Pod")?;
    validate_observer_pod_value(&pod, spec.node)?;
    let node = Kubectl::new(config)
        .command(["get", "node", spec.node, "-o", "json"])
        .run_checked()
        .context("reading host observer target node")?;
    let node = serde_json::from_str::<Value>(&node.stdout).context("parse host observer node")?;
    ensure!(
        !node
            .pointer("/spec/taints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|taint| taint.get("key").and_then(Value::as_str) == Some(CRASH_TAINT_KEY)),
        "device-mapper target node already has the crash-containment quarantine taint"
    );
    Ok(())
}

fn validate_observer_pod_value(pod: &Value, expected_node: &str) -> Result<()> {
    ensure!(
        pod.pointer("/spec/nodeName").and_then(Value::as_str) == Some(expected_node),
        "host observer Pod is not pinned to device-mapper target node {:?}",
        expected_node
    );
    ensure!(
        pod.pointer("/metadata/labels/app.kubernetes.io~1managed-by")
            .and_then(Value::as_str)
            == Some(MANAGED_BY_VALUE)
            && pod
                .pointer("/metadata/labels/rustfs.com~1fault-host-observer")
                .and_then(Value::as_str)
                == Some("true"),
        "host observer Pod must carry s3chaos ownership and fault-host-observer labels"
    );
    ensure!(
        pod.pointer("/spec/hostPID").and_then(Value::as_bool) == Some(true),
        "host observer Pod must share the host PID namespace"
    );
    ensure!(
        pod.pointer("/status/conditions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|condition| {
                condition.get("type").and_then(Value::as_str) == Some("Ready")
                    && condition.get("status").and_then(Value::as_str) == Some("True")
            }),
        "host observer Pod is not Ready"
    );
    let containers = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .context("host observer Pod is missing containers")?;
    ensure!(
        containers.len() == 1,
        "host observer Pod must contain exactly one validated container"
    );
    let container = &containers[0];
    ensure!(
        container
            .pointer("/securityContext/privileged")
            .and_then(Value::as_bool)
            == Some(true),
        "host observer container must be privileged"
    );
    let host_volume_name = container
        .pointer("/volumeMounts")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .find(|mount| {
            mount.get("mountPath").and_then(Value::as_str) == Some("/host")
                && mount.get("readOnly").and_then(Value::as_bool) == Some(true)
                && mount.get("mountPropagation").and_then(Value::as_str) == Some("HostToContainer")
        })
        .and_then(|mount| mount.get("name").and_then(Value::as_str));
    let host_volume_name = host_volume_name.context(
        "host observer Pod must expose /host through a read-only privileged volume mount",
    )?;
    ensure!(
        pod.pointer("/spec/volumes")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|volume| {
                volume.get("name").and_then(Value::as_str) == Some(host_volume_name)
                    && volume.pointer("/hostPath/path").and_then(Value::as_str) == Some("/")
                    && volume.pointer("/hostPath/type").and_then(Value::as_str) == Some("Directory")
            }),
        "host observer Pod /host mount must reference the read-only host root"
    );
    ensure!(
        pod.pointer("/spec/restartPolicy").and_then(Value::as_str) == Some("Never"),
        "host observer Pod restartPolicy must be Never"
    );
    Ok(())
}

fn observer_findmnt_field(
    config: &ClusterTestConfig,
    observer_namespace: &str,
    observer_pod: &str,
    mapping: &DmVolumeMapping,
    field: &str,
) -> Result<String> {
    let value = observer_host_command(
        config,
        observer_namespace,
        observer_pod,
        [
            "/usr/bin/findmnt",
            "-n",
            "--raw",
            "-o",
            field,
            "--mountpoint",
            mapping.mount_path.as_str(),
        ],
    )?
    .stdout
    .trim()
    .to_string();
    ensure!(
        !value.is_empty(),
        "host observer findmnt returned empty {field}"
    );
    Ok(value)
}

fn observer_host_command<I, S>(
    config: &ClusterTestConfig,
    observer_namespace: &str,
    observer_pod: &str,
    args: I,
) -> Result<CommandOutput>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    host_command::run_checked(config, observer_namespace, observer_pod, args)
}

fn dm_flakey_spec<'a>(
    config: &'a FaultTestConfig,
    run_id: &'a str,
    behavior: DmFaultBehavior,
) -> Result<DmFlakeySpec<'a>> {
    let name = config
        .dm_name
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_NAME is required for dm-flakey")?;
    let fault_table = match behavior {
        DmFaultBehavior::ErrorInjection => Some(
            config
                .dm_fault_table
                .as_deref()
                .context("RUSTFS_FAULT_TEST_DM_FAULT_TABLE is required for dm-flakey")?,
        ),
        DmFaultBehavior::DropWritesCrash | DmFaultBehavior::StaleEio => None,
    };
    let node = config
        .dm_node
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_NODE is required for dm-flakey")?;
    let mount_path = config
        .dm_mount_path
        .as_deref()
        .context("RUSTFS_FAULT_TEST_DM_MOUNT_PATH is required for dm-flakey")?;
    Ok(DmFlakeySpec {
        node,
        mount_path,
        helper_image: &config.dm_helper_image,
        name,
        behavior,
        fault_table,
        recovery_table: config.dm_recovery_table.as_deref(),
        run_id,
    })
}

pub(crate) fn stale_dm_spec<'a>(
    config: &'a FaultTestConfig,
    run_id: &'a str,
) -> Result<DmFlakeySpec<'a>> {
    let mut spec = dm_flakey_spec(config, run_id, DmFaultBehavior::StaleEio)?;
    spec.recovery_table = config.dm_recovery_table.as_deref();
    Ok(spec)
}

pub fn apply_dm_flakey(
    fault_config: &FaultTestConfig,
    spec: &DmFlakeySpec<'_>,
    collector: &ArtifactCollector,
    case_name: &str,
    scenario: &str,
    preflight_proof: &HostStorageMutationProof,
) -> Result<DmFlakeyGuard> {
    let mut guard = prepare_dm_flakey(
        fault_config,
        spec,
        collector,
        case_name,
        scenario,
        preflight_proof,
    )?;
    guard.activate()?;
    guard.ensure_active("active")?;
    Ok(guard)
}

pub(crate) fn prepare_dm_flakey(
    fault_config: &FaultTestConfig,
    spec: &DmFlakeySpec<'_>,
    collector: &ArtifactCollector,
    case_name: &str,
    scenario: &str,
    preflight_proof: &HostStorageMutationProof,
) -> Result<DmFlakeyGuard> {
    let config = &fault_config.cluster;
    validate_dm_spec(spec)?;
    let mutation_lease = HostMutationLease::from_config(fault_config, spec.run_id)?;
    let mapping = verify_dm_volume_mapping(
        config,
        spec.node,
        &fault_config.rustfs_volume_path,
        spec.mount_path,
        DmPodReadiness::Required,
    )?;
    let helper_pod = helper_pod_name(spec.run_id);
    let manifest = dm_helper_manifest(
        config,
        &helper_pod,
        spec.node,
        spec.helper_image,
        (spec.behavior == DmFaultBehavior::StaleEio).then_some(spec.mount_path),
    );
    collector.write_text(case_name, "dm-helper-manifest.yaml", &manifest)?;
    let mut guard = DmFlakeyGuard {
        config: config.clone(),
        collector: collector.clone(),
        case_name: case_name.to_string(),
        scenario: scenario.to_string(),
        run_id: spec.run_id.to_string(),
        helper_pod,
        dm_name: spec.name.to_string(),
        behavior: spec.behavior,
        fault_table: String::new(),
        recovery_table: String::new(),
        mapping,
        mount_snapshot: None,
        node_tainted: false,
        mount_state: DmMountState::Unknown,
        crash_boundary_completed: false,
        recovery_snapshot: None,
        preflight_proof: preflight_proof.clone(),
        mutation_lease,
        fault_applied: false,
        filesystem_recovery: if spec.behavior.requires_crash_boundary() {
            DmFilesystemRecoveryState::Pending
        } else {
            DmFilesystemRecoveryState::NotRequired
        },
        stale_cleanup_pending: false,
        restored: false,
    };
    let kubectl = Kubectl::new(config).namespaced(&config.test_namespace);
    kubectl
        .command([
            "delete",
            "pod",
            &guard.helper_pod,
            "--ignore-not-found",
            "--wait=true",
        ])
        .run_checked()?;
    kubectl.create_yaml_command(manifest).run_checked()?;
    guard.wait_helper_ready()?;
    // Re-resolve the complete Kubernetes ownership chain immediately before
    // reading host state so the apply proof cannot splice stale Pod/PVC/PV
    // identity onto a new mount or mapper table.
    guard.mapping = verify_dm_volume_mapping(
        config,
        spec.node,
        &fault_config.rustfs_volume_path,
        spec.mount_path,
        DmPodReadiness::Required,
    )?;
    let mount_snapshot = guard.capture_mount_snapshot()?;
    guard.verify_mount_source(&mount_snapshot)?;
    if spec.behavior.requires_crash_boundary() {
        let (checker, _) = filesystem_checker(&mount_snapshot.filesystem)?;
        guard.require_host_executable("/usr/bin/timeout")?;
        guard.require_host_executable(checker)?;
    }
    guard.mount_snapshot = Some(mount_snapshot);
    guard.mount_state = DmMountState::Mounted;

    let original_table = guard.dmsetup(["table", spec.name])?.stdout;
    guard.recovery_table = spec
        .recovery_table
        .map(str::to_string)
        .unwrap_or_else(|| original_table.trim().to_string());
    ensure!(
        !guard.recovery_table.trim().is_empty(),
        "dmsetup returned an empty recovery table for {:?}",
        spec.name
    );
    if spec.recovery_table.is_some() {
        ensure!(
            dm_tables_match(&guard.recovery_table, &original_table)?,
            "configured recovery table must match the device-mapper table that was active before injection; configured {:?}, active {:?}",
            guard.recovery_table,
            original_table
        );
    }
    let apply_observation = guard.target_observation(&guard.recovery_table)?;
    guard
        .preflight_proof
        .require_fresh_at(apply_observation.observed_at_ms)?;
    guard.preflight_proof = guard.preflight_proof.refresh_for_apply(apply_observation)?;
    collector.write_text(
        case_name,
        HOST_STORAGE_PROOF_ARTIFACT,
        &serde_json::to_string_pretty(&guard.preflight_proof)?,
    )?;

    guard.recovery_table = guard.preflight_proof.tables.recovery_table.clone();
    guard.fault_table = guard.preflight_proof.tables.fault_table.clone();
    guard
        .mutation_lease
        .set_phase(HostMutationPhase::Prepared)?;

    Ok(guard)
}

pub(crate) fn prepare_stale_disk(
    fault_config: &FaultTestConfig,
    collector: &ArtifactCollector,
    case_name: &str,
    scenario: &str,
    run_id: &str,
    preflight_proof: &HostStorageMutationProof,
) -> Result<DmFlakeyGuard> {
    let spec = stale_dm_spec(fault_config, run_id)?;
    prepare_dm_flakey(
        fault_config,
        &spec,
        collector,
        case_name,
        scenario,
        preflight_proof,
    )
}

impl DmFlakeyGuard {
    pub(crate) fn activate(&mut self) -> Result<u64> {
        ensure!(
            !self.fault_applied,
            "device-mapper fault was already activated"
        );
        self.preflight_proof
            .require_fresh_at(now_ms())
            .context("prepared host-storage proof became stale before activation")?;
        self.mutation_lease
            .set_phase(HostMutationPhase::Activating)?;
        self.fault_applied = true;
        let activated_at_ms = if self.behavior == DmFaultBehavior::DropWritesCrash {
            let output = self.host_command_unchecked(dm_atomic_activation_args(
                &self.dm_name,
                &self.preflight_proof.target.canonical_device,
                &self.preflight_proof.target.persistent_volume_path,
                &self.recovery_table,
                &self.fault_table,
            ))?;
            if output.code != Some(0) {
                let transaction_state = output.stdout.trim();
                ensure!(
                    matches!(
                        transaction_state,
                        DM_ATOMIC_ACTIVATION_NOT_STARTED_MARKER
                            | DM_ATOMIC_ACTIVATION_ROLLBACK_MARKER
                    ),
                    "device-mapper activation transaction returned no valid failure state: {:?}",
                    output.stdout
                );
                if transaction_state == DM_ATOMIC_ACTIVATION_NOT_STARTED_MARKER {
                    self.fault_applied = false;
                }
                bail!(
                    "device-mapper activation transaction failed: exit={:?}, stdout={}, stderr={}",
                    output.code,
                    output.stdout,
                    output.stderr
                );
            }
            ensure!(
                output.stdout.trim() == DM_ATOMIC_ACTIVATION_MARKER,
                "device-mapper activation transaction returned unexpected output {:?}",
                output.stdout
            );
            now_ms()
        } else {
            let initial_state = <Self as DmTransitionPort>::observe(self)
                .context("observe device-mapper state immediately before fault apply")?;
            let proven_recovery_table = self.recovery_table.clone();
            let suspend_mode = if self.behavior == DmFaultBehavior::StaleEio {
                DmSuspendMode::NoFlush
            } else {
                DmSuspendMode::Default
            };
            self.transition_to_table_from_observed(
                &self.fault_table.clone(),
                suspend_mode,
                DmTransitionPolicy::Apply {
                    recovery_table: &proven_recovery_table,
                },
                initial_state,
            )?;
            now_ms()
        };
        self.mutation_lease.set_phase(HostMutationPhase::Active)?;
        Ok(activated_at_ms)
    }

    pub fn ensure_active(&self, stage: &str) -> Result<DmStatusSnapshot> {
        let snapshot = self.snapshot(stage)?;
        snapshot.validate_proof(&self.preflight_proof, stage, &self.fault_table)?;
        if stage == "active" {
            self.collector.write_text(
                &self.case_name,
                "dm-flakey-active.json",
                &serde_json::to_string_pretty(&snapshot)?,
            )?;
        }
        Ok(snapshot)
    }

    fn observe_dm_state(&self) -> Result<DmObservedState> {
        ensure!(
            self.mapper_canonical_device()? == self.preflight_proof.target.canonical_device,
            "refusing to use a mapper whose canonical device changed after preflight"
        );
        let suspended = self
            .dmsetup([
                "info",
                "--columns",
                "--noheadings",
                "--options",
                "suspended",
                self.dm_name.as_str(),
            ])?
            .stdout
            .trim()
            .to_ascii_lowercase();
        let suspended = match suspended.as_str() {
            "suspended" | "yes" | "y" | "1" => true,
            "active" | "no" | "n" | "0" => false,
            other => bail!("dmsetup returned unsupported suspended state {other:?}"),
        };
        Ok(DmObservedState {
            suspended,
            active_table: self.dmsetup(["table", self.dm_name.as_str()])?.stdout,
        })
    }

    pub fn snapshot(&self, stage: &str) -> Result<DmStatusSnapshot> {
        let state = self.observe_dm_state()?;
        Ok(DmStatusSnapshot {
            stage: stage.to_string(),
            mapper_name: self.dm_name.clone(),
            canonical_device: self.mapper_canonical_device()?,
            suspended: state.suspended,
            observed_at_ms: now_ms(),
            helper_pod: self.helper_pod.clone(),
            mapping: self.mapping.clone(),
            table: state.active_table,
            status: self.dmsetup(["status", self.dm_name.as_str()])?.stdout,
        })
    }

    fn ensure_recovery_table_active(&mut self) -> Result<()> {
        let state = <Self as DmTransitionPort>::observe(self)?;
        ensure!(
            !state.suspended,
            "device-mapper target {:?} remains suspended after recovery",
            self.dm_name
        );
        let snapshot = self.snapshot("recovery-table-verified")?;
        snapshot.validate_proof(
            &self.preflight_proof,
            "recovery-table-verified",
            &self.recovery_table,
        )?;
        Ok(())
    }

    pub(crate) fn ensure_stale_owned_state(&mut self, isolated: bool) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio,
            "stale owned-state verification is bound to another fault policy"
        );
        if isolated {
            self.ensure_active("stale-owned-isolated")?;
        } else {
            self.ensure_recovery_table_active()?;
        }
        Ok(())
    }

    fn persist_post_cleanup_observation(&mut self) -> Result<()> {
        let mount = self.capture_mount_snapshot()?;
        self.verify_mount_source(&mount)?;
        let cleanup_observation = HostStoragePostCleanupObservation {
            schema_version: 1,
            scenario: self.scenario.clone(),
            fault_name: self.preflight_proof.fault_name.clone(),
            run_id: self.run_id.clone(),
            observed_at_ms: now_ms(),
            node: self.mapping.node.clone(),
            persistent_volume: self.mapping.pv.clone(),
            mapper_name: self.dm_name.clone(),
            logical_device: format!("/dev/mapper/{}", self.dm_name),
            canonical_device: self.mapper_canonical_device()?,
            mount_canonical_source: mount.canonical_source.clone(),
            filesystem_mounted: true,
            node_quarantined: self.node_has_crash_taint()?,
            recovery_table_sha256: normalized_dm_table_sha256(
                &self
                    .recovery_snapshot
                    .as_ref()
                    .context("device-mapper recovery snapshot is missing")?
                    .table,
            )?,
        };
        self.preflight_proof
            .validate_post_cleanup(&cleanup_observation)?;
        self.collector.write_text(
            &self.case_name,
            "host-storage-post-cleanup.json",
            &serde_json::to_string_pretty(&cleanup_observation)?,
        )?;
        Ok(())
    }

    pub fn requires_crash_boundary(&self) -> bool {
        self.behavior.requires_crash_boundary()
    }

    pub fn prepare_recovery_boundary(
        &mut self,
        timeout: Duration,
        started_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.requires_crash_boundary(),
            "device-mapper error-injection faults do not have a crash recovery boundary"
        );
        ensure!(
            !self.crash_boundary_completed,
            "device-mapper crash recovery boundary was already completed"
        );
        let fault = self.ensure_active("before-crash-boundary")?;
        let mount_before = self
            .mount_snapshot
            .clone()
            .context("device-mapper mount snapshot is missing")?;

        self.add_node_taint()?;
        let replacement_pod_uid =
            self.force_delete_target_pod(timeout, DmPodDeletionMode::CrashBoundary)?;
        self.ensure_active("before-crash-unmount")?;
        self.unmount_filesystem(timeout, DmUnmountExpectation::FaultTableActive)?;
        self.crash_boundary_completed = true;

        let snapshot = DmCrashBoundarySnapshot {
            scenario: self.scenario.clone(),
            run_id: self.run_id.clone(),
            started_at_ms,
            completed_at_ms: now_ms(),
            taint: self.node_taint(),
            old_pod_uid: self.mapping.pod_uid.clone(),
            replacement_pod_uid,
            filesystem_unmounted: self.mount_state == DmMountState::Unmounted,
            mapper_mounts_absent: true,
            mount_before,
            fault,
        };
        self.collector.write_text(
            &self.case_name,
            "dm-crash-boundary.json",
            &serde_json::to_string_pretty(&snapshot)?,
        )?;
        Ok(())
    }

    pub fn restore(&mut self) -> Result<()> {
        self.restore_with_timeout(self.config.timeout)
    }

    pub(crate) fn restore_with_timeout(&mut self, timeout: Duration) -> Result<()> {
        let incomplete_crash_boundary =
            self.requires_crash_boundary() && !self.crash_boundary_completed;
        let recovery_quiescence = if incomplete_crash_boundary {
            self.ensure_recovery_quiescence(timeout)
                .context("quiesce storage users after an incomplete drop_writes boundary")
        } else {
            Ok(())
        };
        let recovery_table = self.recovery_table.clone();
        let suspend_mode = match self.behavior {
            DmFaultBehavior::ErrorInjection | DmFaultBehavior::StaleEio => DmSuspendMode::NoFlush,
            DmFaultBehavior::DropWritesCrash => DmSuspendMode::NoLockFs,
        };
        if let Err(error) = self.mutation_lease.set_phase(HostMutationPhase::Rollback) {
            eprintln!(
                "warning: failed to mark device-mapper rollback in progress; retaining the active mutation marker: {error:#}"
            );
        }
        self.transition_to_table(&recovery_table, suspend_mode, DmTransitionPolicy::Rollback)?;
        self.ensure_recovery_table_active()?;
        if self.requires_crash_boundary() {
            recovery_quiescence?;
            self.verify_filesystem_integrity(timeout)?;
        }
        if self.node_tainted {
            self.remove_node_taint()?;
        }
        self.recovery_snapshot = Some(self.snapshot("recovered")?);
        self.persist_post_cleanup_observation()?;
        if self.requires_crash_boundary() {
            let snapshot = DmCrashRecoverySnapshot {
                scenario: self.scenario.clone(),
                run_id: self.run_id.clone(),
                recovered_at_ms: now_ms(),
                taint_removed: !self.node_tainted,
                mount: self.capture_mount_snapshot()?,
                expected_table: self.recovery_table.clone(),
                fault: self
                    .recovery_snapshot
                    .clone()
                    .context("device-mapper recovery snapshot is missing")?,
            };
            self.collector.write_text(
                &self.case_name,
                "dm-crash-recovered.json",
                &serde_json::to_string_pretty(&snapshot)?,
            )?;
        }
        self.restored = true;
        if self.behavior == DmFaultBehavior::StaleEio {
            // Stale-return qualification still needs the same run-owned host
            // helper and mutation lease for its offline inventory and exact
            // orphan cleanup. The mapper is already back on the verified
            // recovery table, so Drop must not re-enter mapper recovery.
            self.stale_cleanup_pending = true;
        } else {
            self.mutation_lease.clear()?;
            // Storage recovery is complete before deleting the disposable helper.
            // A lost delete response must not make Drop re-enter mapper recovery
            // through a helper that may already be gone.
            self.delete_helper()?;
        }
        ensure!(
            !incomplete_crash_boundary,
            "drop_writes durability boundary did not force-delete the target Pod and unmount the filesystem while the fault table was active; storage was recovered before reporting this failure"
        );
        Ok(())
    }

    pub fn recovery_snapshot(&self) -> Option<&DmStatusSnapshot> {
        self.recovery_snapshot.as_ref()
    }

    pub(crate) fn stale_host_proof(&self) -> &HostStorageMutationProof {
        &self.preflight_proof
    }

    pub(crate) fn stale_helper_pod_name(&self) -> &str {
        &self.helper_pod
    }

    pub(crate) fn prepare_stale_session_lock(
        &self,
        scope_sha256: &str,
    ) -> Result<(String, u64, u64)> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio
                && !self.restored
                && scope_sha256.len() == 64
                && scope_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "stale helper lock preflight has an invalid generation or scope"
        );
        let lock_path = format!(
            "{}/storage-{}.lock",
            crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HOST_LOCK_DIRECTORY,
            scope_sha256
        );
        let output = self.host_command([
            "/bin/sh",
            "-ceu",
            "umask 077; mkdir -p -- \"$1\"; (set -C; : > \"$2\"); /usr/bin/findmnt -n -o MAJ:MIN --target \"$1\"; /usr/bin/stat -c %i -- \"$2\"",
            "s3chaos-prepare-stale-lock",
            crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HOST_LOCK_DIRECTORY,
            lock_path.as_str(),
        ])?;
        let fields = output.stdout.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2,
            "stale helper lock probe returned malformed output"
        );
        let inode = fields[1]
            .parse::<u64>()
            .context("stale helper lock inode is invalid")?;
        ensure!(
            fields[0].split_once(':').is_some_and(|(major, minor)| {
                major.parse::<u32>().is_ok() && minor.parse::<u32>().is_ok()
            }) && inode > 0,
            "stale helper lock identity is invalid"
        );
        Ok((fields[0].to_string(), inode, now_ms()))
    }

    pub(crate) fn observe_stale_session_lock(&self, scope_sha256: &str) -> Result<(String, u64)> {
        let lock_path = format!(
            "{}/storage-{}.lock",
            crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HOST_LOCK_DIRECTORY,
            scope_sha256
        );
        let identity = self.host_command([
            "/bin/sh",
            "-ceu",
            "/usr/bin/findmnt -n -o MAJ:MIN --target \"$1\"; /usr/bin/stat -c %i -- \"$2\"",
            "s3chaos-observe-stale-lock",
            crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HOST_LOCK_DIRECTORY,
            lock_path.as_str(),
        ])?;
        let fields = identity.stdout.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 2,
            "stale helper lock observation is malformed"
        );
        let inode = fields[1]
            .parse::<u64>()
            .context("stale helper lock observation has an invalid inode")?;
        let contention =
            self.host_command_unchecked(["/usr/bin/flock", "-n", lock_path.as_str(), "/bin/true"])?;
        ensure!(
            contention.code.is_some_and(|code| code != 0),
            "stale helper host flock is not held by the persistent session"
        );
        Ok((fields[0].to_string(), inode))
    }

    pub(crate) fn stale_host_generation(
        &self,
        mount_namespace_id: &str,
        filesystem_uuid: &str,
        rustfs_drive_uuid: &str,
    ) -> Result<crate::fault::storage_recovery_runtime::HostGenerationIdentity> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio
                && (!self.restored || self.recovery_snapshot.is_some()),
            "stale host generation is outside the prepared generation"
        );
        let output = self.host_command([
            "/bin/sh",
            "-ceu",
            "/usr/bin/findmnt -n -o ID --target /target; /usr/bin/findmnt -n -o MAJ:MIN --target /target; /usr/sbin/dmsetup info --columns --noheadings --options uuid \"$1\"",
            "s3chaos-observe-stale-generation",
            self.dm_name.as_str(),
        ])?;
        let fields = output.stdout.split_whitespace().collect::<Vec<_>>();
        ensure!(
            fields.len() == 3,
            "stale host generation probe returned malformed output"
        );
        Ok(
            crate::fault::storage_recovery_runtime::HostGenerationIdentity {
                mount_id: fields[0].to_string(),
                mount_namespace_id: mount_namespace_id.to_string(),
                device_major_minor: fields[1].to_string(),
                device_mapper_uuid: Some(fields[2].to_string()),
                device_mapper_table_sha256: Some(normalized_dm_table_sha256(&self.recovery_table)?),
                filesystem_uuid: filesystem_uuid.to_string(),
                rustfs_drive_uuid: rustfs_drive_uuid.to_string(),
            },
        )
    }

    pub(crate) fn arm_stale_helper_fallback(&mut self) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio && !self.restored,
            "cannot arm stale helper fallback outside the prepared generation"
        );
        self.ensure_active("stale-helper-active")?;
        self.fault_applied = true;
        self.mutation_lease.set_phase(HostMutationPhase::Active)
    }

    pub(crate) fn begin_stale_helper_mutation(&mut self) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio && !self.restored,
            "cannot begin stale helper mutation outside the prepared generation"
        );
        self.ensure_recovery_table_active()?;
        self.fault_applied = true;
        self.mutation_lease.set_phase(HostMutationPhase::Active)
    }

    pub(crate) fn accept_stale_helper_reattach(&mut self) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio && self.fault_applied && !self.restored,
            "cannot accept stale helper reattach outside an active stale generation"
        );
        self.ensure_recovery_table_active()?;
        self.recovery_snapshot = Some(self.snapshot("recovered-by-owned-helper")?);
        self.persist_post_cleanup_observation()?;
        self.restored = true;
        self.stale_cleanup_pending = true;
        Ok(())
    }

    pub(crate) fn require_stale_offline_helper(&self) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio && !self.restored,
            "stale offline helper preflight is outside the prepared stale generation"
        );
        self.host_command([
            "/bin/sh",
            "-c",
            "[ -x \"$1\" ]",
            "s3chaos-require-stale-helper",
            crate::fault::storage_recovery_runtime::STORAGE_RECOVERY_HELPER_PROGRAM,
        ])
        .context("stale offline helper binary is unavailable in the run-owned helper Pod")?;
        Ok(())
    }

    pub(crate) fn finish_stale_cleanup(&mut self) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio
                && self.restored
                && self.recovery_snapshot.is_some(),
            "stale helper cleanup requires a verified returned mapper generation"
        );
        if !self.stale_cleanup_pending {
            return Ok(());
        }
        self.mutation_lease.clear()?;
        self.delete_helper()?;
        self.stale_cleanup_pending = false;
        Ok(())
    }

    pub(crate) fn finish_stale_pre_mutation_cleanup(&mut self) -> Result<()> {
        ensure!(
            self.behavior == DmFaultBehavior::StaleEio && !self.fault_applied && !self.restored,
            "pre-mutation stale cleanup is outside an untouched prepared generation"
        );
        self.mutation_lease.clear()?;
        self.delete_helper()?;
        self.restored = true;
        Ok(())
    }

    fn wait_helper_ready(&self) -> Result<()> {
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command([
                "wait",
                "--for=condition=Ready",
                "pod",
                &self.helper_pod,
                "--timeout=60s",
            ])
            .run_checked()?;
        Ok(())
    }

    fn capture_mount_snapshot(&self) -> Result<DmMountSnapshot> {
        let source = self.findmnt_field("SOURCE")?;
        let filesystem = self.findmnt_field("FSTYPE")?;
        let options = self.findmnt_field("OPTIONS")?;
        let canonical_source = self
            .host_command(["/usr/bin/readlink", "-f", source.as_str()])?
            .stdout
            .trim()
            .to_string();
        ensure!(!filesystem.is_empty(), "target filesystem type is empty");
        ensure!(
            !options.is_empty(),
            "target filesystem mount options are empty"
        );
        Ok(DmMountSnapshot {
            source,
            canonical_source,
            filesystem,
            options,
        })
    }

    fn findmnt_field(&self, field: &str) -> Result<String> {
        let value = self
            .host_command([
                "/usr/bin/findmnt",
                "-n",
                "--raw",
                "-o",
                field,
                "--mountpoint",
                self.mapping.mount_path.as_str(),
            ])?
            .stdout
            .trim()
            .to_string();
        ensure!(
            !value.is_empty(),
            "findmnt returned an empty {field} for {:?}",
            self.mapping.mount_path
        );
        Ok(value)
    }

    fn verify_mount_source(&self, mount: &DmMountSnapshot) -> Result<()> {
        let mapper = self.mapper_canonical_device()?;
        ensure!(
            mount.canonical_source == mapper,
            "fault-test PV mount {:?} on node {:?} is backed by {:?}, not device-mapper target {:?}",
            self.mapping.mount_path,
            self.mapping.node,
            mount.source,
            self.dm_name
        );
        Ok(())
    }

    fn mapper_canonical_device(&self) -> Result<String> {
        let mapper = self
            .host_command([
                "/usr/bin/readlink",
                "-f",
                &format!("/dev/mapper/{}", self.dm_name),
            ])?
            .stdout
            .trim()
            .to_string();
        ensure!(
            !mapper.is_empty(),
            "device-mapper canonical device is empty"
        );
        Ok(mapper)
    }

    fn target_observation(&self, recovery_table: &str) -> Result<HostStorageTargetObservation> {
        let mount = self
            .mount_snapshot
            .as_ref()
            .context("device-mapper mount snapshot is missing")?;
        Ok(HostStorageTargetObservation {
            node: self.mapping.node.clone(),
            node_uid: self.mapping.node_uid.clone(),
            node_labels: self.mapping.node_labels.clone(),
            pod: self.mapping.pod.clone(),
            pod_uid: self.mapping.pod_uid.clone(),
            volume_name: self.mapping.volume_name.clone(),
            persistent_volume_claim: self.mapping.pvc.clone(),
            persistent_volume_claim_uid: self.mapping.pvc_uid.clone(),
            persistent_volume_claim_phase: self.mapping.pvc_phase.clone(),
            persistent_volume: self.mapping.pv.clone(),
            persistent_volume_uid: self.mapping.pv_uid.clone(),
            persistent_volume_phase: self.mapping.pv_phase.clone(),
            persistent_volume_claim_ref: self.mapping.pv_claim_ref.clone(),
            node_selector: self.mapping.node_selector.clone(),
            container_mount_path: self.mapping.container_mount_path.clone(),
            persistent_volume_path: self.mapping.mount_path.clone(),
            mapper_name: self.dm_name.clone(),
            logical_device: format!("/dev/mapper/{}", self.dm_name),
            canonical_device: self.mapper_canonical_device()?,
            mount_source: mount.source.clone(),
            mount_canonical_source: mount.canonical_source.clone(),
            filesystem: mount.filesystem.clone(),
            recovery_table: recovery_table.to_string(),
            observed_at_ms: now_ms(),
        })
    }

    fn node_has_crash_taint(&self) -> Result<bool> {
        let node = Kubectl::new(&self.config)
            .command(["get", "node", self.mapping.node.as_str(), "-o", "json"])
            .run_checked()?;
        let node = serde_json::from_str::<Value>(&node.stdout).context("parse DM target node")?;
        Ok(node
            .pointer("/spec/taints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|taint| taint.get("key").and_then(Value::as_str) == Some(CRASH_TAINT_KEY)))
    }

    fn transition_to_table(
        &mut self,
        table: &str,
        mode: DmSuspendMode,
        policy: DmTransitionPolicy<'_>,
    ) -> Result<()> {
        transition_dm_table(self, table, mode, policy)
    }

    fn transition_to_table_from_observed(
        &mut self,
        table: &str,
        mode: DmSuspendMode,
        policy: DmTransitionPolicy<'_>,
        initial: DmObservedState,
    ) -> Result<()> {
        transition_dm_table_from_observed(self, table, mode, policy, initial)
    }

    fn add_node_taint(&mut self) -> Result<()> {
        let node = Kubectl::new(&self.config)
            .command(["get", "node", self.mapping.node.as_str(), "-o", "json"])
            .run_checked()?;
        let node = serde_json::from_str::<Value>(&node.stdout).context("parse DM target node")?;
        let existing = node
            .pointer("/spec/taints")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .any(|taint| taint.get("key").and_then(Value::as_str) == Some(CRASH_TAINT_KEY));
        ensure!(
            !existing,
            "target node {:?} already has the s3chaos crash-containment taint; refuse to overwrite operator or stale-run state",
            self.mapping.node
        );
        let taint = self.node_taint();
        Kubectl::new(&self.config)
            .command(["taint", "node", self.mapping.node.as_str(), taint.as_str()])
            .run_checked()?;
        self.node_tainted = true;
        Ok(())
    }

    fn remove_node_taint(&mut self) -> Result<()> {
        ensure!(
            !self.requires_crash_boundary() || self.mount_state.proves_expected_mount(),
            "refusing to remove the crash-containment taint without a verified mapper-backed mount; state={:?}",
            self.mount_state
        );
        let removal = format!("{CRASH_TAINT_KEY}-");
        let output = Kubectl::new(&self.config)
            .command([
                "taint",
                "node",
                self.mapping.node.as_str(),
                removal.as_str(),
            ])
            .run()?;
        ensure!(
            output.code == Some(0)
                || format!("{}\n{}", output.stdout, output.stderr)
                    .to_ascii_lowercase()
                    .contains("not found"),
            "failed to remove node taint from {:?}: exit={:?}, stderr={}",
            self.mapping.node,
            output.code,
            output.stderr
        );
        self.node_tainted = false;
        Ok(())
    }

    fn node_taint(&self) -> String {
        let value = self
            .mapping
            .pod_uid
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric())
            .take(16)
            .collect::<String>()
            .to_ascii_lowercase();
        format!("{CRASH_TAINT_KEY}={value}:NoSchedule")
    }

    fn force_delete_target_pod(
        &self,
        timeout: Duration,
        mode: DmPodDeletionMode,
    ) -> Result<Option<String>> {
        match classify_initial_target_pod(
            self.read_target_pod()?.as_ref(),
            &self.mapping.pod,
            &self.mapping.pod_uid,
            &self.mapping.node,
            mode,
        )? {
            DmInitialPodAction::AlreadyQuiesced(replacement_uid) => return Ok(replacement_uid),
            DmInitialPodAction::WaitForOriginal => {}
            DmInitialPodAction::DeleteOriginal => {
                let current = verify_dm_volume_mapping(
                    &self.config,
                    &self.mapping.node,
                    &self.mapping.container_mount_path,
                    &self.mapping.mount_path,
                    DmPodReadiness::MayBeUnready,
                )?;
                ensure!(
                    current == self.mapping,
                    "refusing to delete a RustFS Pod because its UID/PVC/PV/node mapping changed after device-mapper apply"
                );
                force_delete_pod_command(&self.config, &self.mapping.pod, &self.mapping.pod_uid)?
                    .run_checked()?;
            }
        }

        let deadline = Instant::now() + timeout;
        loop {
            let Some(pod) = self.read_target_pod()? else {
                return Ok(None);
            };
            if let Some(replacement_uid) = self.replacement_pod_uid(&pod)? {
                return Ok(Some(replacement_uid));
            }
            ensure!(
                Instant::now() < deadline,
                "target Pod {:?} with uid {:?} did not terminate within {:?}",
                self.mapping.pod,
                self.mapping.pod_uid,
                timeout
            );
            sleep(Duration::from_millis(500));
        }
    }

    fn read_target_pod(&self) -> Result<Option<Value>> {
        let output = Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command([
                "get",
                "pod",
                self.mapping.pod.as_str(),
                "-o",
                "json",
                "--ignore-not-found",
            ])
            .run_checked()?;
        if output.stdout.trim().is_empty() {
            return Ok(None);
        }
        serde_json::from_str::<Value>(&output.stdout)
            .context("parse target or replacement RustFS Pod")
            .map(Some)
    }

    fn replacement_pod_uid(&self, pod: &Value) -> Result<Option<String>> {
        ensure!(
            pod.pointer("/metadata/name").and_then(Value::as_str)
                == Some(self.mapping.pod.as_str()),
            "target or replacement RustFS Pod response has an unexpected name"
        );
        let uid = pod
            .pointer("/metadata/uid")
            .and_then(Value::as_str)
            .context("target or replacement RustFS Pod is missing metadata.uid")?;
        if uid == self.mapping.pod_uid {
            return Ok(None);
        }
        ensure!(
            pod.pointer("/spec/nodeName").and_then(Value::as_str)
                != Some(self.mapping.node.as_str()),
            "replacement Pod {:?} was scheduled on tainted node {:?} before the crash boundary completed",
            self.mapping.pod,
            self.mapping.node
        );
        Ok(Some(uid.to_string()))
    }

    fn unmount_filesystem(
        &mut self,
        timeout: Duration,
        expectation: DmUnmountExpectation,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        let logical_device = format!("/dev/mapper/{}", self.dm_name);
        let canonical_device = self.preflight_proof.target.canonical_device.clone();
        let purpose = match expectation {
            DmUnmountExpectation::FaultTableActive => {
                "while the drop_writes fault table remains active"
            }
            DmUnmountExpectation::RecoveryTableActive => "before the offline filesystem check",
        };
        self.mount_state = DmMountState::Unmounting;
        loop {
            let command =
                self.host_command_unchecked(["/usr/bin/umount", self.mapping.mount_path.as_str()]);
            let command_summary = match &command {
                Ok(output) => format!(
                    "exit={:?}, stdout={}, stderr={}",
                    output.code, output.stdout, output.stderr
                ),
                Err(error) => format!("transport error: {error:#}"),
            };
            let observation_summary = match self.reconcile_mount_state() {
                Ok(DmMountState::Unmounted) => {
                    match self.ensure_mapper_unmounted(&logical_device, &canonical_device) {
                        Ok(()) => return Ok(()),
                        Err(error) => format!("mapper mount check: {error:#}"),
                    }
                }
                Ok(DmMountState::Mounted) => "target mount is still present".to_string(),
                Ok(state) => bail!("unexpected reconciled mount state {state:?}"),
                Err(error) => format!("mountpoint check: {error:#}"),
            };
            ensure!(
                Instant::now() < deadline,
                "timed out fully unmounting mapper {:?} from {:?} {purpose}; last umount {command_summary}; last observation: {observation_summary}",
                self.dm_name,
                self.mapping.mount_path,
            );
            match expectation {
                DmUnmountExpectation::FaultTableActive => {
                    self.ensure_active("waiting-for-crash-unmount")?;
                }
                DmUnmountExpectation::RecoveryTableActive => {
                    self.ensure_recovery_table_active()?;
                }
            }
            sleep(Duration::from_millis(500));
        }
    }

    fn observe_mount_state(&self) -> Result<DmMountState> {
        let output = self.host_command_unchecked([
            "/usr/bin/findmnt",
            "-n",
            "--raw",
            "-o",
            "TARGET",
            "--mountpoint",
            self.mapping.mount_path.as_str(),
        ])?;
        match classify_exact_mountpoint(&self.mapping.mount_path, &output)? {
            DmMountState::Unmounted => Ok(DmMountState::Unmounted),
            DmMountState::Mounted => {
                let mount = self.capture_mount_snapshot()?;
                self.verify_mount_source(&mount)?;
                Ok(DmMountState::Mounted)
            }
            state => bail!("unexpected exact mountpoint state {state:?}"),
        }
    }

    fn reconcile_mount_state(&mut self) -> Result<DmMountState> {
        match self.observe_mount_state() {
            Ok(state) => {
                self.mount_state = state;
                Ok(state)
            }
            Err(error) => {
                self.mount_state = DmMountState::Unknown;
                Err(error)
            }
        }
    }

    fn ensure_filesystem_mounted(&mut self) -> Result<()> {
        match self.reconcile_mount_state()? {
            DmMountState::Mounted => Ok(()),
            DmMountState::Unmounted => self.remount_filesystem(),
            state => bail!("unexpected reconciled mount state {state:?}"),
        }
    }

    fn verify_filesystem_integrity(&mut self, timeout: Duration) -> Result<()> {
        ensure!(
            self.requires_crash_boundary(),
            "offline filesystem verification is only valid after a drop_writes fault"
        );
        self.filesystem_recovery = DmFilesystemRecoveryState::Failed;
        self.ensure_filesystem_mounted()
            .context("mount recovered filesystem to replay its journal")?;
        self.unmount_filesystem(timeout, DmUnmountExpectation::RecoveryTableActive)?;

        let logical_device = format!("/dev/mapper/{}", self.dm_name);
        let (checker, checker_args) = filesystem_checker(
            &self
                .mount_snapshot
                .as_ref()
                .context("device-mapper mount snapshot is missing")?
                .filesystem,
        )?;
        let timeout_seconds = timeout
            .as_secs()
            .saturating_add(u64::from(timeout.subsec_nanos() > 0))
            .max(1);
        let mut command = vec![
            "/usr/bin/timeout".to_string(),
            "--signal=KILL".to_string(),
            format!("{timeout_seconds}s"),
            checker.to_string(),
        ];
        command.extend(checker_args.iter().map(|argument| (*argument).to_string()));
        command.push(logical_device.clone());
        self.ensure_recovery_table_active()?;
        let canonical_device = self.mapper_canonical_device()?;
        ensure!(
            canonical_device == self.preflight_proof.target.canonical_device,
            "device-mapper canonical device changed before its offline filesystem check"
        );
        self.ensure_mapper_unmounted(&logical_device, &canonical_device)?;
        let started_at_ms = now_ms();
        let output = self.host_command_unchecked(command.clone());
        let completed_at_ms = now_ms();
        let (exit_code, stdout, stderr) = match output {
            Ok(output) => (output.code, output.stdout, output.stderr),
            Err(error) => (None, String::new(), format!("{error:#}")),
        };
        let mut check = DmFilesystemCheck {
            schema_version: DM_FILESYSTEM_CHECK_SCHEMA_VERSION,
            scenario: self.scenario.clone(),
            fault_name: self.preflight_proof.fault_name.clone(),
            run_id: self.run_id.clone(),
            node: self.mapping.node.clone(),
            persistent_volume: self.mapping.pv.clone(),
            mapper_name: self.dm_name.clone(),
            logical_device,
            canonical_device,
            mount_path: self.mapping.mount_path.clone(),
            filesystem: self
                .mount_snapshot
                .as_ref()
                .context("device-mapper mount snapshot is missing")?
                .filesystem
                .clone(),
            checker: checker.to_string(),
            arguments: command.into_iter().skip(4).collect(),
            started_at_ms,
            completed_at_ms,
            exit_code,
            stdout,
            stderr,
            clean: exit_code == Some(0),
            mounted_for_recovery: true,
            unmounted_for_check: true,
            remounted_after_check: false,
            remounted_at_ms: None,
        };
        self.write_filesystem_check(&check)?;
        ensure!(
            check.clean,
            "offline filesystem check failed for mapper {:?}: checker={}, exit={:?}, stderr={}",
            self.dm_name,
            check.checker,
            check.exit_code,
            check.stderr
        );

        self.remount_filesystem()
            .context("remount filesystem after a clean offline check")?;
        check.remounted_after_check = true;
        check.remounted_at_ms = Some(now_ms());
        self.write_filesystem_check(&check)?;
        self.filesystem_recovery = DmFilesystemRecoveryState::Verified;
        Ok(())
    }

    fn ensure_recovery_quiescence(&mut self, timeout: Duration) -> Result<()> {
        if !self.node_tainted {
            self.add_node_taint()?;
        }
        self.force_delete_target_pod(timeout, DmPodDeletionMode::Recovery)?;
        Ok(())
    }

    fn ensure_mapper_unmounted(&self, logical_device: &str, canonical_device: &str) -> Result<()> {
        for source in [logical_device, canonical_device] {
            let output = self.host_command_unchecked([
                "/usr/bin/findmnt",
                "-n",
                "--raw",
                "-o",
                "TARGET",
                "--source",
                source,
            ])?;
            validate_unmounted_source(source, &output)?;
        }
        Ok(())
    }

    fn write_filesystem_check(&self, check: &DmFilesystemCheck) -> Result<()> {
        self.collector.write_text(
            &self.case_name,
            DM_FILESYSTEM_CHECK_ARTIFACT,
            &serde_json::to_string_pretty(check)?,
        )?;
        Ok(())
    }

    fn remount_filesystem(&mut self) -> Result<()> {
        let mount = self
            .mount_snapshot
            .clone()
            .context("device-mapper mount snapshot is missing")?;
        let mapper = format!("/dev/mapper/{}", self.dm_name);
        self.mount_state = DmMountState::Mounting;
        let command = self.host_command_unchecked([
            "/usr/bin/mount",
            "-t",
            mount.filesystem.as_str(),
            "-o",
            mount.options.as_str(),
            mapper.as_str(),
            self.mapping.mount_path.as_str(),
        ]);
        let command_summary = match &command {
            Ok(output) => format!(
                "exit={:?}, stdout={}, stderr={}",
                output.code, output.stdout, output.stderr
            ),
            Err(error) => format!("transport error: {error:#}"),
        };
        match self.reconcile_mount_state() {
            Ok(DmMountState::Mounted) => Ok(()),
            Ok(DmMountState::Unmounted) => {
                bail!(
                    "failed to remount {:?} from mapper {:?}; mount {command_summary}",
                    self.mapping.mount_path,
                    mapper
                )
            }
            Ok(state) => bail!("unexpected reconciled mount state {state:?}"),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "reconcile {:?} after remount attempt; mount {command_summary}",
                    self.mapping.mount_path
                )
            }),
        }
    }

    fn dmsetup<I, S>(&self, args: I) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut command = vec!["/usr/sbin/dmsetup".to_string()];
        command.extend(args.into_iter().map(Into::into));
        self.host_command(command)
    }

    fn require_host_executable(&self, executable: &str) -> Result<()> {
        self.host_command([
            "/bin/sh",
            "-c",
            "[ -x \"$1\" ]",
            "s3chaos-require-host-executable",
            executable,
        ])
        .with_context(|| format!("required host executable {executable:?} is unavailable"))?;
        Ok(())
    }

    fn host_command<I, S>(&self, args: I) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        host_command::run_checked(
            &self.config,
            &self.config.test_namespace,
            &self.helper_pod,
            args,
        )
    }

    fn host_command_unchecked<I, S>(&self, args: I) -> Result<CommandOutput>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        host_command::run(
            &self.config,
            &self.config.test_namespace,
            &self.helper_pod,
            args,
        )
    }

    fn delete_helper(&self) -> Result<()> {
        Kubectl::new(&self.config)
            .namespaced(&self.config.test_namespace)
            .command([
                "delete",
                "pod",
                &self.helper_pod,
                "--ignore-not-found",
                "--wait=true",
            ])
            .run_checked()?;
        Ok(())
    }
}

impl DmTransitionPort for DmFlakeyGuard {
    fn observe(&mut self) -> Result<DmObservedState> {
        self.observe_dm_state()
    }

    fn suspend(&mut self, mode: DmSuspendMode) -> Result<()> {
        self.dmsetup(dm_suspend_args(&self.dm_name, mode))?;
        Ok(())
    }

    fn load(&mut self, table: &str) -> Result<()> {
        self.dmsetup(["load", self.dm_name.as_str(), "--table", table])?;
        Ok(())
    }

    fn resume(&mut self) -> Result<()> {
        self.dmsetup(dm_resume_args(&self.dm_name))?;
        Ok(())
    }
}

fn force_delete_pod_command(
    config: &ClusterTestConfig,
    pod: &str,
    pod_uid: &str,
) -> Result<CommandSpec> {
    ensure!(
        !pod.is_empty()
            && pod.chars().all(|ch| ch.is_ascii_lowercase()
                || ch.is_ascii_digit()
                || matches!(ch, '.' | '-')),
        "target Pod name is not safe for the Kubernetes API path"
    );
    ensure!(!pod_uid.trim().is_empty(), "target Pod UID is empty");
    let uri = format!("/api/v1/namespaces/{}/pods/{pod}", config.test_namespace);
    let delete_options = serde_json::json!({
        "apiVersion": "v1",
        "kind": "DeleteOptions",
        "gracePeriodSeconds": 0,
        "propagationPolicy": "Background",
        "preconditions": {"uid": pod_uid},
    });
    Ok(Kubectl::new(config)
        .command(["delete", "--raw", uri.as_str(), "-f", "-"])
        .stdin(serde_json::to_string(&delete_options)?))
}

fn classify_initial_target_pod(
    pod: Option<&Value>,
    expected_pod: &str,
    expected_uid: &str,
    target_node: &str,
    mode: DmPodDeletionMode,
) -> Result<DmInitialPodAction> {
    let Some(pod) = pod else {
        ensure!(
            mode == DmPodDeletionMode::Recovery,
            "target Pod {expected_pod:?} disappeared before the run-owned crash boundary"
        );
        return Ok(DmInitialPodAction::AlreadyQuiesced(None));
    };
    ensure!(
        pod.pointer("/metadata/name").and_then(Value::as_str) == Some(expected_pod),
        "target Pod response has an unexpected name"
    );
    let uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .context("target or replacement RustFS Pod is missing metadata.uid")?;
    if uid != expected_uid {
        ensure!(
            mode == DmPodDeletionMode::Recovery,
            "target Pod {expected_pod:?} was replaced before the run-owned crash boundary"
        );
        ensure!(
            pod.pointer("/spec/nodeName").and_then(Value::as_str) != Some(target_node),
            "replacement Pod {expected_pod:?} was scheduled on tainted node {target_node:?} before the crash boundary completed"
        );
        return Ok(DmInitialPodAction::AlreadyQuiesced(Some(uid.to_string())));
    }
    let terminating = pod
        .pointer("/metadata/deletionTimestamp")
        .is_some_and(|value| !value.is_null());
    ensure!(
        mode == DmPodDeletionMode::Recovery || !terminating,
        "target Pod {expected_pod:?} was already terminating before the run-owned crash boundary"
    );
    Ok(if terminating {
        DmInitialPodAction::WaitForOriginal
    } else {
        DmInitialPodAction::DeleteOriginal
    })
}

impl Drop for DmFlakeyGuard {
    fn drop(&mut self) {
        if self.restored && self.stale_cleanup_pending {
            eprintln!(
                "warning: retaining stale-return helper pod {pod} and host mutation state because cleanup-proof release did not complete",
                pod = self.helper_pod,
            );
        }
        if !self.restored {
            let recovery_table = self.recovery_table.clone();
            let mut mapper_recovered = !self.fault_applied;
            if self.fault_applied && !recovery_table.is_empty() {
                if let Err(error) = self.mutation_lease.set_phase(HostMutationPhase::Rollback) {
                    eprintln!(
                        "warning: failed to mark device-mapper rollback in progress; retaining the active mutation marker: {error:#}"
                    );
                }
                let mode = match self.behavior {
                    DmFaultBehavior::ErrorInjection | DmFaultBehavior::StaleEio => {
                        DmSuspendMode::NoFlush
                    }
                    DmFaultBehavior::DropWritesCrash => DmSuspendMode::NoLockFs,
                };
                match self
                    .transition_to_table(&recovery_table, mode, DmTransitionPolicy::Rollback)
                    .and_then(|()| self.ensure_recovery_table_active())
                {
                    Ok(()) => mapper_recovered = true,
                    Err(error) => {
                        match self.ensure_recovery_table_active() {
                            Ok(()) => {
                                mapper_recovered = true;
                                eprintln!(
                                    "warning: device-mapper rollback reported an error but a fresh observation proved the recovery table active: {error:#}"
                                );
                            }
                            Err(observe_error) => {
                                // A discarded failure here may leave the injected fault table on
                                // a real block device; surface both attempts so operators can
                                // distinguish a transition failure from an observation failure.
                                eprintln!(
                                    "warning: failed to restore device-mapper target {name} to its recovery table on node {node} during guard cleanup: {error:#}; recovery observation: {observe_error:#}",
                                    name = self.dm_name,
                                    node = self.mapping.node,
                                );
                            }
                        }
                    }
                }
            }
            let mut filesystem_recovered = mapper_recovered;
            if self.fault_applied && mapper_recovered {
                let recovery = match self.filesystem_recovery {
                    DmFilesystemRecoveryState::Pending => {
                        let timeout = self.config.timeout;
                        self.ensure_recovery_quiescence(timeout)
                            .and_then(|()| self.verify_filesystem_integrity(timeout))
                    }
                    DmFilesystemRecoveryState::Failed => {
                        filesystem_recovered = false;
                        eprintln!(
                            "warning: offline filesystem verification failed for device-mapper target {name}; leaving {mount} quarantined for manual recovery",
                            name = self.dm_name,
                            mount = self.mapping.mount_path,
                        );
                        Ok(())
                    }
                    DmFilesystemRecoveryState::NotRequired
                    | DmFilesystemRecoveryState::Verified => self.ensure_filesystem_mounted(),
                };
                if let Err(error) = recovery {
                    filesystem_recovered = false;
                    eprintln!(
                        "warning: failed to recover device-mapper filesystem {name} at {mount} during guard cleanup; node {node} remains tainted: {error:#}",
                        name = self.dm_name,
                        mount = self.mapping.mount_path,
                        node = self.mapping.node,
                    );
                }
            }
            if filesystem_recovered
                && self.node_tainted
                && let Err(error) = self.remove_node_taint()
            {
                filesystem_recovered = false;
                eprintln!(
                    "warning: failed to remove crash-containment taint from node {node} during guard cleanup: {error}",
                    node = self.mapping.node,
                );
            }
            if self.fault_applied && !filesystem_recovered && !self.node_tainted {
                match self.add_node_taint() {
                    Ok(()) => eprintln!(
                        "warning: applied NoSchedule to node {node} after device-mapper recovery failed",
                        node = self.mapping.node,
                    ),
                    Err(error) => eprintln!(
                        "warning: failed to quarantine node {node} after device-mapper recovery failed: {error}",
                        node = self.mapping.node,
                    ),
                }
            }
            if filesystem_recovered {
                if let Err(error) = self.mutation_lease.clear() {
                    eprintln!(
                        "warning: failed to clear host mutation state after verified recovery: {error:#}"
                    );
                }
                if let Err(error) = self.delete_helper() {
                    eprintln!(
                        "warning: failed to delete dm-flakey helper pod {pod} during guard cleanup: {error}",
                        pod = self.helper_pod,
                    );
                }
            } else {
                // A recovered active table remains usable even if mount
                // reconciliation failed. Re-suspending it would turn a
                // filesystem observation error into a second storage outage.
                if mapper_requires_containment(self.fault_applied, mapper_recovered)
                    && let Err(error) = contain_unrecovered_mapper(self, &recovery_table)
                {
                    eprintln!(
                        "warning: could not verify suspension of the unrecovered mapper; existing Pod I/O may continue: {error:#}"
                    );
                }
                if let Err(error) = self
                    .mutation_lease
                    .set_phase(HostMutationPhase::RecoveryRequired)
                {
                    eprintln!(
                        "warning: failed to mark manual recovery required; retaining prior mutation state: {error:#}"
                    );
                }
                eprintln!(
                    "warning: leaving dm helper pod {pod} on node {node} for manual recovery because storage cleanup did not complete",
                    pod = self.helper_pod,
                    node = self.mapping.node,
                );
            }
        }
    }
}

fn validate_dm_spec(spec: &DmFlakeySpec<'_>) -> Result<()> {
    ensure!(
        !spec.node.is_empty()
            && spec
                .node
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-')),
        "RUSTFS_FAULT_TEST_DM_NODE must be a valid node name"
    );
    ensure!(
        spec.mount_path.starts_with('/') && spec.mount_path != "/",
        "RUSTFS_FAULT_TEST_DM_MOUNT_PATH must be an absolute non-root path"
    );
    ensure!(
        spec.mount_path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-')),
        "RUSTFS_FAULT_TEST_DM_MOUNT_PATH contains unsupported manifest characters"
    );
    ensure!(
        !spec.name.is_empty()
            && spec
                .name
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '+')),
        "RUSTFS_FAULT_TEST_DM_NAME contains unsupported characters"
    );
    if spec.behavior == DmFaultBehavior::ErrorInjection {
        ensure!(
            spec.fault_table
                .is_some_and(|table| !table.trim().is_empty()),
            "RUSTFS_FAULT_TEST_DM_FAULT_TABLE is required"
        );
    }
    ensure!(
        !spec.helper_image.trim().is_empty()
            && !spec.helper_image.contains(['\n', '\r', ' ', '\t']),
        "RUSTFS_FAULT_TEST_DM_HELPER_IMAGE must be a non-empty image reference"
    );
    Ok(())
}

fn dm_resume_args(name: &str) -> [&str; 3] {
    ["resume", "--noudevsync", name]
}

fn filesystem_checker(filesystem: &str) -> Result<(&'static str, &'static [&'static str])> {
    match filesystem {
        "ext2" | "ext3" | "ext4" => Ok(("/usr/sbin/e2fsck", &["-f", "-n"])),
        "xfs" => Ok(("/usr/sbin/xfs_repair", &["-n"])),
        other => bail!(
            "drop_writes requires an offline read-only filesystem checker; unsupported filesystem {other:?}"
        ),
    }
}

fn mapper_requires_containment(fault_applied: bool, mapper_recovered: bool) -> bool {
    fault_applied && !mapper_recovered
}

fn dm_atomic_activation_args(
    name: &str,
    canonical_device: &str,
    mount_path: &str,
    recovery_table: &str,
    fault_table: &str,
) -> Vec<String> {
    [
        "/bin/sh",
        "-c",
        DM_ATOMIC_ACTIVATION_SCRIPT,
        "s3chaos-dm-activate",
        name,
        canonical_device,
        mount_path,
        recovery_table,
        fault_table,
    ]
    .map(str::to_string)
    .to_vec()
}

fn contain_unrecovered_mapper(
    port: &mut impl DmTransitionPort,
    recovery_table: &str,
) -> Result<()> {
    let observed = port.observe()?;
    if observed.suspended
        || dm_tables_match(&observed.active_table, recovery_table).unwrap_or(false)
    {
        return Ok(());
    }
    let suspended = port.suspend(DmSuspendMode::NoFlushNoLockFs);
    ensure!(
        port.observe()?.suspended,
        "failed mapper remains active after containment suspend: {suspended:?}"
    );
    Ok(())
}

fn dm_suspend_args(name: &str, mode: DmSuspendMode) -> Vec<&str> {
    match mode {
        DmSuspendMode::Default => vec!["suspend", name],
        DmSuspendMode::NoFlush => vec!["suspend", "--noflush", name],
        DmSuspendMode::NoFlushNoLockFs => vec!["suspend", "--noflush", "--nolockfs", name],
        DmSuspendMode::NoLockFs => vec!["suspend", "--nolockfs", name],
    }
}

fn classify_exact_mountpoint(
    expected_mount_path: &str,
    output: &CommandOutput,
) -> Result<DmMountState> {
    match output.code {
        Some(1) if output.stdout.trim().is_empty() && output.stderr.trim().is_empty() => {
            Ok(DmMountState::Unmounted)
        }
        Some(1) => bail!(
            "findmnt did not provide clean no-match evidence for exact mountpoint {:?}: stdout={}, stderr={}",
            expected_mount_path,
            output.stdout,
            output.stderr
        ),
        Some(0) => {
            let targets = output
                .stdout
                .lines()
                .map(str::trim)
                .filter(|target| !target.is_empty())
                .collect::<Vec<_>>();
            ensure!(
                targets.len() == 1,
                "findmnt returned {} targets for exact mountpoint {:?}",
                targets.len(),
                expected_mount_path
            );
            if targets[0] == expected_mount_path {
                Ok(DmMountState::Mounted)
            } else {
                // Some findmnt versions or wrappers may still report the
                // containing filesystem. It is not evidence that the planned
                // path remains a mountpoint.
                Ok(DmMountState::Unmounted)
            }
        }
        _ => bail!(
            "could not determine exact mount state for {:?}: findmnt exit={:?}, stdout={}, stderr={}",
            expected_mount_path,
            output.code,
            output.stdout,
            output.stderr
        ),
    }
}

fn validate_unmounted_source(source: &str, output: &CommandOutput) -> Result<()> {
    ensure!(
        output.code == Some(1)
            && output.stdout.trim().is_empty()
            && output.stderr.trim().is_empty(),
        "device-mapper source {source:?} is still mounted or could not be checked before offline filesystem verification: findmnt exit={:?}, stdout={}, stderr={}",
        output.code,
        output.stdout,
        output.stderr
    );
    Ok(())
}

fn require_transition_initial_state(
    policy: DmTransitionPolicy<'_>,
    initial: &DmObservedState,
) -> Result<()> {
    if let DmTransitionPolicy::Apply { recovery_table } = policy {
        ensure!(
            !initial.suspended,
            "refusing device-mapper fault apply because the target was already suspended"
        );
        ensure!(
            dm_tables_match(&initial.active_table, recovery_table)?,
            "refusing device-mapper fault apply because the active table drifted from the proven recovery table; active={:?}, recovery={:?}",
            initial.active_table,
            recovery_table
        );
    }
    Ok(())
}

fn transition_dm_table(
    port: &mut impl DmTransitionPort,
    requested_table: &str,
    mode: DmSuspendMode,
    policy: DmTransitionPolicy<'_>,
) -> Result<()> {
    let initial = port.observe().context("observe device-mapper state")?;
    transition_dm_table_from_observed(port, requested_table, mode, policy, initial)
}

fn transition_dm_table_from_observed(
    port: &mut impl DmTransitionPort,
    requested_table: &str,
    mode: DmSuspendMode,
    policy: DmTransitionPolicy<'_>,
    initial: DmObservedState,
) -> Result<()> {
    require_transition_initial_state(policy, &initial)?;
    let already_requested = match dm_tables_match(&initial.active_table, requested_table) {
        Ok(matches) => matches,
        Err(_) if policy == DmTransitionPolicy::Rollback => false,
        Err(error) => {
            return Err(error).context("compare device-mapper table before fault apply");
        }
    };
    if !initial.suspended && already_requested {
        return Ok(());
    }

    let mut suspend_error = None;
    if !initial.suspended {
        suspend_error = port.suspend(mode).err().map(|error| format!("{error:#}"));
        let after_suspend = port
            .observe()
            .context("re-observe device-mapper state after suspend attempt")?;
        if let DmTransitionPolicy::Apply { recovery_table } = policy {
            let table_comparison = dm_tables_match(&after_suspend.active_table, recovery_table);
            let table_matches_recovery = table_comparison.as_ref().copied().unwrap_or(false);
            if suspend_error.is_some() || !after_suspend.suspended || !table_matches_recovery {
                let recovery_result = transition_dm_table_from_observed(
                    port,
                    recovery_table,
                    mode,
                    DmTransitionPolicy::Rollback,
                    after_suspend.clone(),
                );
                bail!(
                    "device-mapper fault apply lost its proven pre-load state; suspended={}, active_table={:?}, table_error={:?}, suspend_error={:?}, recovery_result={:?}",
                    after_suspend.suspended,
                    after_suspend.active_table,
                    table_comparison.err().map(|error| format!("{error:#}")),
                    suspend_error,
                    recovery_result.map_err(|error| format!("{error:#}"))
                );
            }
        }
        ensure!(
            after_suspend.suspended,
            "device-mapper target remained active after suspend attempt; suspend error={:?}",
            suspend_error
        );
    }

    let load_error = port
        .load(requested_table)
        .err()
        .map(|error| format!("{error:#}"));
    // Resume is attempted even when load failed. A failed load must not strand
    // I/O behind a suspended mapper, and final observed state is authoritative.
    let resume_error = port.resume().err().map(|error| format!("{error:#}"));
    let final_state = port
        .observe()
        .context("observe device-mapper state after load/resume attempts")?;
    ensure!(
        !final_state.suspended && dm_tables_match(&final_state.active_table, requested_table)?,
        "device-mapper transition did not reach active requested table; suspended={}, active_table={:?}, suspend_error={:?}, load_error={:?}, resume_error={:?}",
        final_state.suspended,
        final_state.active_table,
        suspend_error,
        load_error,
        resume_error
    );
    Ok(())
}

fn verify_dm_volume_mapping(
    config: &ClusterTestConfig,
    node: &str,
    container_mount_path: &str,
    expected_host_mount_path: &str,
    readiness: DmPodReadiness,
) -> Result<DmVolumeMapping> {
    let selector = format!("rustfs.tenant={}", config.tenant_name);
    let pods = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pod", "-l", &selector, "-o", "json"])
        .run_checked()?;
    let pods = serde_json::from_str::<Value>(&pods.stdout).context("parse RustFS pod list")?;
    let binding = resolve_dm_pod_volume(&pods, node, container_mount_path, readiness)?;

    let pvc_json = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pvc", binding.pvc.as_str(), "-o", "json"])
        .run_checked()?;
    let pvc_json =
        serde_json::from_str::<Value>(&pvc_json.stdout).context("parse DM target PVC")?;
    let pv = pvc_json
        .pointer("/spec/volumeName")
        .and_then(Value::as_str)
        .context("DM target PVC is not bound")?;

    let pv_json = Kubectl::new(config)
        .command(["get", "pv", pv, "-o", "json"])
        .run_checked()?;
    let pv_json = serde_json::from_str::<Value>(&pv_json.stdout).context("parse DM target PV")?;
    let node_json = Kubectl::new(config)
        .command(["get", "node", binding.node.as_str(), "-o", "json"])
        .run_checked()?;
    let node_json =
        serde_json::from_str::<Value>(&node_json.stdout).context("parse DM target Node")?;
    complete_dm_volume_mapping(
        &config.test_namespace,
        binding,
        &pvc_json,
        &pv_json,
        &node_json,
        expected_host_mount_path,
    )
}

fn resolve_dm_pod_volume(
    pods: &Value,
    node: &str,
    container_mount_path: &str,
    readiness: DmPodReadiness,
) -> Result<DmPodVolumeBinding> {
    let pods_on_node = pods
        .pointer("/items")
        .and_then(Value::as_array)
        .context("RustFS pod list is missing items")?
        .iter()
        .filter(|item| item.pointer("/spec/nodeName").and_then(Value::as_str) == Some(node))
        .collect::<Vec<_>>();
    ensure!(
        pods_on_node.len() == 1,
        "device-mapper target node {node:?} must host exactly one RustFS fault-test Pod, found {}",
        pods_on_node.len()
    );
    let pod = pods_on_node[0];
    ensure!(
        pod.pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null),
        "DM target Pod is terminating"
    );
    if readiness == DmPodReadiness::Required {
        ensure!(
            pod.pointer("/status/conditions")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .any(|condition| {
                    condition.get("type").and_then(Value::as_str) == Some("Ready")
                        && condition.get("status").and_then(Value::as_str) == Some("True")
                }),
            "DM target Pod is not Ready"
        );
    }
    let pod_name = pod
        .pointer("/metadata/name")
        .and_then(Value::as_str)
        .context("DM target Pod is missing metadata.name")?;
    let pod_uid = pod
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .context("DM target Pod is missing metadata.uid")?;
    let rustfs_containers = pod
        .pointer("/spec/containers")
        .and_then(Value::as_array)
        .context("DM target Pod is missing spec.containers")?
        .iter()
        .filter(|container| container.get("name").and_then(Value::as_str) == Some("rustfs"))
        .collect::<Vec<_>>();
    ensure!(
        rustfs_containers.len() == 1,
        "DM target Pod must contain exactly one rustfs container"
    );
    let matching_mounts = rustfs_containers[0]
        .get("volumeMounts")
        .and_then(Value::as_array)
        .context("RustFS container is missing volumeMounts")?
        .iter()
        .filter(|mount| {
            mount.get("mountPath").and_then(Value::as_str) == Some(container_mount_path)
        })
        .collect::<Vec<_>>();
    ensure!(
        matching_mounts.len() == 1,
        "RustFS container must have exactly one volume mount at {container_mount_path:?}"
    );
    let volume_name = matching_mounts[0]
        .get("name")
        .and_then(Value::as_str)
        .context("target RustFS volumeMount is missing name")?;
    let matching_volumes = pod
        .pointer("/spec/volumes")
        .and_then(Value::as_array)
        .context("DM target Pod is missing spec.volumes")?
        .iter()
        .filter(|volume| volume.get("name").and_then(Value::as_str) == Some(volume_name))
        .collect::<Vec<_>>();
    ensure!(
        matching_volumes.len() == 1,
        "DM target Pod must define exactly one volume named {volume_name:?}"
    );
    let pvc = matching_volumes[0]
        .pointer("/persistentVolumeClaim/claimName")
        .and_then(Value::as_str)
        .context("target RustFS volume does not reference a PVC")?;

    Ok(DmPodVolumeBinding {
        node: node.to_string(),
        pod: pod_name.to_string(),
        pod_uid: pod_uid.to_string(),
        volume_name: volume_name.to_string(),
        pvc: pvc.to_string(),
        container_mount_path: container_mount_path.to_string(),
    })
}

fn complete_dm_volume_mapping(
    namespace: &str,
    binding: DmPodVolumeBinding,
    pvc_json: &Value,
    pv_json: &Value,
    node_json: &Value,
    expected_host_mount_path: &str,
) -> Result<DmVolumeMapping> {
    ensure!(
        pvc_json.pointer("/metadata/name").and_then(Value::as_str) == Some(binding.pvc.as_str())
            && pvc_json
                .pointer("/metadata/namespace")
                .and_then(Value::as_str)
                == Some(namespace),
        "fetched PVC identity does not match the Pod volume reference"
    );
    ensure!(
        pvc_json
            .pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null),
        "DM target PVC is terminating"
    );
    let pvc_phase = pvc_json
        .pointer("/status/phase")
        .and_then(Value::as_str)
        .context("DM target PVC is missing status.phase")?;
    ensure!(
        pvc_phase == "Bound",
        "DM target PVC status.phase must be Bound"
    );
    let pvc_uid = pvc_json
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .context("DM target PVC is missing metadata.uid")?;
    let pv = pvc_json
        .pointer("/spec/volumeName")
        .and_then(Value::as_str)
        .context("DM target PVC is not bound")?;
    ensure!(
        pv_json.pointer("/metadata/name").and_then(Value::as_str) == Some(pv),
        "fetched PV identity does not match the bound PVC"
    );
    ensure!(
        pv_json
            .pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null),
        "DM target PV is terminating"
    );
    let pv_phase = pv_json
        .pointer("/status/phase")
        .and_then(Value::as_str)
        .context("DM target PV is missing status.phase")?;
    ensure!(
        pv_phase == "Bound",
        "DM target PV status.phase must be Bound"
    );
    let pv_uid = pv_json
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .context("DM target PV is missing metadata.uid")?;
    let claim_ref = HostStoragePersistentVolumeClaimRef {
        namespace: pv_json
            .pointer("/spec/claimRef/namespace")
            .and_then(Value::as_str)
            .context("DM target PV claimRef is missing namespace")?
            .to_string(),
        name: pv_json
            .pointer("/spec/claimRef/name")
            .and_then(Value::as_str)
            .context("DM target PV claimRef is missing name")?
            .to_string(),
        uid: pv_json
            .pointer("/spec/claimRef/uid")
            .and_then(Value::as_str)
            .context("DM target PV claimRef is missing uid")?
            .to_string(),
    };
    ensure!(
        claim_ref.namespace == namespace
            && claim_ref.name == binding.pvc
            && claim_ref.uid == pvc_uid,
        "DM target PV claimRef does not exactly match PVC {namespace}/{pvc} uid {pvc_uid}",
        pvc = binding.pvc
    );
    let local_path = pv_json
        .pointer("/spec/local/path")
        .and_then(Value::as_str)
        .context("DM target PV is not a local PV")?;
    ensure!(
        local_path == expected_host_mount_path,
        "DM target PV {pv:?} uses local path {local_path:?}, expected {expected_host_mount_path:?}"
    );
    ensure!(
        node_json.pointer("/metadata/name").and_then(Value::as_str) == Some(binding.node.as_str()),
        "fetched Node identity does not match the target Pod node"
    );
    ensure!(
        node_json
            .pointer("/metadata/deletionTimestamp")
            .is_none_or(Value::is_null),
        "DM target Node is terminating"
    );
    let node_uid = node_json
        .pointer("/metadata/uid")
        .and_then(Value::as_str)
        .context("DM target Node is missing metadata.uid")?;
    ensure!(!node_uid.trim().is_empty(), "DM target Node UID is empty");
    let node_labels = node_json
        .pointer("/metadata/labels")
        .and_then(Value::as_object)
        .context("DM target Node is missing metadata.labels")?
        .iter()
        .map(|(key, value)| {
            let value = value
                .as_str()
                .with_context(|| format!("DM target Node label {key:?} is not a string"))?;
            Ok((key.clone(), value.to_string()))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let node_selector = supported_pv_node_selector(pv_json, &node_labels)?;

    Ok(DmVolumeMapping {
        node: binding.node,
        node_uid: node_uid.to_string(),
        node_labels,
        pod: binding.pod,
        pod_uid: binding.pod_uid,
        volume_name: binding.volume_name,
        pvc: binding.pvc,
        pvc_uid: pvc_uid.to_string(),
        pvc_phase: pvc_phase.to_string(),
        pv: pv.to_string(),
        pv_uid: pv_uid.to_string(),
        pv_phase: pv_phase.to_string(),
        pv_claim_ref: claim_ref,
        node_selector,
        container_mount_path: binding.container_mount_path,
        mount_path: local_path.to_string(),
    })
}

fn supported_pv_node_selector(
    pv: &Value,
    node_labels: &BTreeMap<String, String>,
) -> Result<HostStorageNodeSelector> {
    let terms = pv
        .pointer("/spec/nodeAffinity/required/nodeSelectorTerms")
        .and_then(Value::as_array)
        .context("DM target PV is missing required node selector terms")?;
    ensure!(
        terms.len() == 1,
        "DM target PV must use exactly one supported node selector term"
    );
    ensure!(
        terms[0]
            .get("matchFields")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty),
        "DM target PV matchFields are not supported"
    );
    let expressions = terms[0]
        .get("matchExpressions")
        .and_then(Value::as_array)
        .context("DM target PV selector term is missing matchExpressions")?;
    ensure!(
        expressions.len() == 1,
        "DM target PV must use exactly one hostname match expression; compound AND selectors are not supported"
    );
    let expression = &expressions[0];
    let values = expression
        .get("values")
        .and_then(Value::as_array)
        .context("DM target PV hostname selector is missing values")?;
    let hostname = node_labels
        .get("kubernetes.io/hostname")
        .context("DM target Node is missing kubernetes.io/hostname label")?;
    ensure!(
        !hostname.trim().is_empty(),
        "DM target Node kubernetes.io/hostname label is empty"
    );
    ensure!(
        expression.get("key").and_then(Value::as_str) == Some("kubernetes.io/hostname")
            && expression.get("operator").and_then(Value::as_str) == Some("In")
            && values.len() == 1
            && values[0].as_str() == Some(hostname),
        "DM target PV node selector must exactly match the target Node kubernetes.io/hostname label {hostname:?}"
    );
    Ok(HostStorageNodeSelector {
        key: "kubernetes.io/hostname".to_string(),
        operator: "In".to_string(),
        values: vec![hostname.to_string()],
    })
}

fn dm_helper_manifest(
    config: &ClusterTestConfig,
    name: &str,
    node: &str,
    image: &str,
    target_path: Option<&str>,
) -> String {
    // A private target mount keeps the filesystem alive across host unmounts.
    // Only stale-return helpers need direct access to the retained filesystem.
    let target_mount = target_path.map_or(
        "",
        |_| "        - name: target-volume\n          mountPath: /target\n",
    );
    let target_volume = target_path.map_or_else(String::new, |path| {
        format!("    - name: target-volume\n      hostPath:\n        path: {path}\n        type: Directory\n")
    });
    format!(
        r#"apiVersion: v1
kind: Pod
metadata:
  name: {name}
  namespace: {namespace}
  labels:
    {managed_by_label}: {managed_by_value}
spec:
  nodeName: {node}
  hostPID: true
  restartPolicy: Never
  containers:
    - name: host-tools
      image: {image}
      imagePullPolicy: IfNotPresent
      command: ["sh", "-c", "trap : TERM INT; while :; do sleep 3600 & wait $!; done"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
          mountPropagation: HostToContainer
{target_mount}        - name: helper-journal
          mountPath: /journal
        - name: helper-lock
          mountPath: /var/lock/s3chaos
  volumes:
    - name: host-root
      hostPath:
        path: /
        type: Directory
{target_volume}    - name: helper-journal
      emptyDir: {{}}
    - name: helper-lock
      emptyDir: {{}}
"#,
        namespace = config.test_namespace,
        managed_by_label = MANAGED_BY_LABEL,
        managed_by_value = MANAGED_BY_VALUE,
    )
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{
        DmFaultBehavior, DmFlakeySpec, DmInitialPodAction, DmMountState, DmObservedState,
        DmPodDeletionMode, DmPodReadiness, DmSuspendMode, DmTransitionPolicy, DmTransitionPort,
        HostMutationLease, HostMutationPhase, HostMutationState, classify_exact_mountpoint,
        classify_initial_target_pod, complete_dm_volume_mapping, dm_atomic_activation_args,
        dm_flakey_spec, dm_helper_manifest, dm_resume_args, dm_suspend_args, dm_tables_match,
        filesystem_checker, force_delete_pod_command, helper_pod_name, mapper_requires_containment,
        resolve_dm_pod_volume, supported_pv_node_selector, transition_dm_table, validate_dm_spec,
        validate_observer_pod_value, validate_unmounted_source,
    };
    use crate::fault::config::FaultTestConfig;
    use crate::framework::command::CommandOutput;
    use anyhow::{Result, bail};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    struct FakeDmPort {
        suspended: bool,
        active_table: String,
        inactive_table: Option<String>,
        active_table_after_suspend: Option<String>,
        fail_next_suspend_after_suspending: bool,
        fail_next_resume: bool,
        suspend_calls: usize,
        load_calls: usize,
        loaded_tables: Vec<String>,
        resume_calls: usize,
    }

    impl DmTransitionPort for FakeDmPort {
        fn observe(&mut self) -> Result<DmObservedState> {
            Ok(DmObservedState {
                suspended: self.suspended,
                active_table: self.active_table.clone(),
            })
        }

        fn suspend(&mut self, _mode: DmSuspendMode) -> Result<()> {
            self.suspend_calls += 1;
            if self.suspended {
                bail!("already suspended");
            }
            self.suspended = true;
            if let Some(table) = self.active_table_after_suspend.take() {
                self.active_table = table;
            }
            if self.fail_next_suspend_after_suspending {
                self.fail_next_suspend_after_suspending = false;
                bail!("injected suspend failure after state change");
            }
            Ok(())
        }

        fn load(&mut self, table: &str) -> Result<()> {
            self.load_calls += 1;
            self.loaded_tables.push(table.to_string());
            if !self.suspended {
                bail!("load requires suspended mapper");
            }
            self.inactive_table = Some(table.to_string());
            Ok(())
        }

        fn resume(&mut self) -> Result<()> {
            self.resume_calls += 1;
            if self.fail_next_resume {
                self.fail_next_resume = false;
                bail!("injected resume failure");
            }
            if !self.suspended {
                bail!("mapper is not suspended");
            }
            if let Some(table) = self.inactive_table.take() {
                self.active_table = table;
            }
            self.suspended = false;
            Ok(())
        }
    }

    fn pod_list(ready: bool) -> Value {
        json!({"items": [{
            "metadata": {"name": "rustfs-0", "uid": "pod-uid-a"},
            "spec": {
                "nodeName": "worker-a",
                "containers": [{
                    "name": "rustfs",
                    "volumeMounts": [
                        {"name": "logs", "mountPath": "/logs"},
                        {"name": "data", "mountPath": "/data/rustfs0"}
                    ]
                }],
                "volumes": [
                    {"name": "logs", "persistentVolumeClaim": {"claimName": "logs-rustfs-0"}},
                    {"name": "data", "persistentVolumeClaim": {"claimName": "data-rustfs-0"}}
                ]
            },
            "status": {"conditions": [{"type": "Ready", "status": if ready { "True" } else { "False" }}]}
        }]})
    }

    fn pvc(uid: &str) -> Value {
        json!({
            "metadata": {
                "name": "data-rustfs-0",
                "namespace": "rustfs-fault-test",
                "uid": uid
            },
            "spec": {"volumeName": "pv-a"},
            "status": {"phase": "Bound"}
        })
    }

    fn pv(pv_uid: &str, pvc_uid: &str) -> Value {
        json!({
            "metadata": {"name": "pv-a", "uid": pv_uid},
            "spec": {
                "claimRef": {
                    "namespace": "rustfs-fault-test",
                    "name": "data-rustfs-0",
                    "uid": pvc_uid
                },
                "local": {"path": "/data/rustfs-fault/dm-volume"},
                "nodeAffinity": {"required": {"nodeSelectorTerms": [{
                    "matchExpressions": [{
                        "key": "kubernetes.io/hostname",
                        "operator": "In",
                        "values": ["worker-a"]
                    }]
                }]}}
            },
            "status": {"phase": "Bound"}
        })
    }

    fn node(name: &str, uid: &str, hostname: &str) -> Value {
        json!({
            "metadata": {
                "name": name,
                "uid": uid,
                "labels": {
                    "disk.example.com/class": "nvme",
                    "kubernetes.io/hostname": hostname
                }
            }
        })
    }

    fn observer_pod() -> Value {
        json!({
            "metadata": {"labels": {
                "app.kubernetes.io/managed-by": "s3chaos",
                "rustfs.com/fault-host-observer": "true"
            }},
            "spec": {
                "nodeName": "worker-a",
                "hostPID": true,
                "restartPolicy": "Never",
                "containers": [{
                    "name": "host-tools",
                    "securityContext": {"privileged": true},
                    "volumeMounts": [{
                        "name": "host-root",
                        "mountPath": "/host",
                        "readOnly": true,
                        "mountPropagation": "HostToContainer"
                    }]
                }],
                "volumes": [{
                    "name": "host-root",
                    "hostPath": {"path": "/", "type": "Directory"}
                }]
            },
            "status": {"conditions": [{"type": "Ready", "status": "True"}]}
        })
    }

    #[test]
    fn dm_helper_is_pinned_to_one_node_and_host_root() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = dm_helper_manifest(
            &config.cluster,
            "rustfs-fault-dm-helper-run123",
            "worker-a",
            "busybox:test",
            Some("/var/lib/rustfs-stale"),
        );

        assert!(manifest.contains("nodeName: worker-a"));
        assert!(manifest.contains("privileged: true"));
        assert!(manifest.contains("mountPath: /host"));
        assert!(manifest.contains("mountPath: /target"));
        assert!(manifest.contains("path: /var/lib/rustfs-stale"));
        assert!(manifest.contains("mountPath: /journal"));
        assert!(manifest.contains("mountPath: /var/lock/s3chaos"));
        assert!(manifest.contains("path: /"));
        assert!(manifest.contains("s3chaos"));
    }

    #[test]
    fn dm_crash_helper_does_not_pin_the_target_filesystem() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = dm_helper_manifest(
            &config.cluster,
            "rustfs-fault-dm-helper-run123",
            "worker-a",
            "busybox:test",
            None,
        );
        let pod: serde_json::Value = serde_yaml_ng::from_str(&manifest).unwrap();
        let mounts = pod["spec"]["containers"][0]["volumeMounts"]
            .as_array()
            .unwrap();
        assert!(mounts.iter().all(|mount| mount["name"] != "target-volume"));
        let host = mounts
            .iter()
            .find(|mount| mount["name"] == "host-root")
            .unwrap();
        assert_eq!(host["mountPropagation"], "HostToContainer");
        assert!(
            pod["spec"]["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|volume| volume["name"] != "target-volume")
        );
    }

    #[test]
    fn dm_helper_stays_alive_until_explicitly_deleted() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let manifest = dm_helper_manifest(
            &config.cluster,
            "rustfs-fault-dm-helper-run123",
            "worker-a",
            "busybox:test",
            Some("/var/lib/rustfs-stale"),
        );

        // The guard always tears the pod down explicitly (restore/Drop), so it
        // must never self-terminate: a fixed `sleep 3600` on a restartPolicy:
        // Never pod would Complete mid-run and strand the fault table loaded on
        // the real block device once every kubectl exec starts failing.
        assert!(manifest.contains("while :; do sleep 3600 & wait $!; done"));
        assert!(!manifest.contains("sleep 3600 & wait\""));
    }

    #[test]
    fn host_observer_requires_pid_and_mount_namespace_access() {
        let valid = observer_pod();
        validate_observer_pod_value(&valid, "worker-a").expect("valid host observer");

        let mut no_host_pid = valid.clone();
        no_host_pid["spec"]["hostPID"] = json!(false);
        assert!(validate_observer_pod_value(&no_host_pid, "worker-a").is_err());

        let mut private_mount = valid;
        private_mount["spec"]["containers"][0]["volumeMounts"][0]["mountPropagation"] =
            json!("None");
        assert!(validate_observer_pod_value(&private_mount, "worker-a").is_err());
    }

    #[test]
    fn drop_writes_activation_is_one_preconditioned_host_transaction() {
        let recovery = "0 1024 linear 7:0 0";
        let fault = "0 1024 flakey 7:0 0 0 86400 1 drop_writes";
        let args = dm_atomic_activation_args(
            "mapper-a",
            "/dev/dm-7",
            "/data/rustfs/dm-volume",
            recovery,
            fault,
        );

        assert_eq!(
            &args[3..],
            [
                "s3chaos-dm-activate",
                "mapper-a",
                "/dev/dm-7",
                "/data/rustfs/dm-volume",
                recovery,
                fault,
            ]
        );
        let script = &args[2];
        for required in [
            "actual_device",
            "mount_device",
            "active_table",
            "dmsetup suspend --nolockfs",
            "dmsetup load \"$name\" --table \"$fault_table\"",
            "dmsetup resume --noudevsync",
            super::DM_ATOMIC_ACTIVATION_MARKER,
            super::DM_ATOMIC_ACTIVATION_NOT_STARTED_MARKER,
            super::DM_ATOMIC_ACTIVATION_ROLLBACK_MARKER,
        ] {
            assert!(script.contains(required), "missing {required:?}");
        }
    }

    #[test]
    fn drop_writes_uses_only_offline_read_only_filesystem_checkers() {
        assert_eq!(
            filesystem_checker("ext4").expect("ext4 checker"),
            ("/usr/sbin/e2fsck", &["-f", "-n"][..])
        );
        assert_eq!(
            filesystem_checker("xfs").expect("xfs checker"),
            ("/usr/sbin/xfs_repair", &["-n"][..])
        );
        assert!(filesystem_checker("btrfs").is_err());
    }

    #[test]
    fn recovered_mapper_is_not_suspended_for_a_filesystem_check_failure() {
        assert!(!mapper_requires_containment(true, true));
        assert!(mapper_requires_containment(true, false));
        assert!(!mapper_requires_containment(false, false));
    }

    #[test]
    fn dm_resume_disables_udev_synchronization() {
        assert_eq!(
            dm_resume_args("rustfs-fault-dm"),
            ["resume", "--noudevsync", "rustfs-fault-dm"]
        );
    }

    #[test]
    fn dm_suspend_modes_make_sync_semantics_explicit() {
        assert_eq!(
            dm_suspend_args("rustfs-fault-dm", DmSuspendMode::NoFlush),
            ["suspend", "--noflush", "rustfs-fault-dm"]
        );
        assert_eq!(
            dm_suspend_args("rustfs-fault-dm", DmSuspendMode::NoLockFs),
            ["suspend", "--nolockfs", "rustfs-fault-dm"]
        );
        assert_eq!(
            dm_suspend_args("rustfs-fault-dm", DmSuspendMode::Default),
            ["suspend", "rustfs-fault-dm"]
        );
    }

    #[test]
    fn only_a_reconciled_mapper_mount_allows_taint_removal() {
        assert!(DmMountState::Mounted.proves_expected_mount());
        assert!(!DmMountState::Unmounting.proves_expected_mount());
        assert!(!DmMountState::Unmounted.proves_expected_mount());
        assert!(!DmMountState::Mounting.proves_expected_mount());
        assert!(!DmMountState::Unknown.proves_expected_mount());
    }

    #[test]
    fn exact_mountpoint_does_not_accept_a_parent_filesystem() {
        let parent = CommandOutput {
            code: Some(0),
            stdout: "/\n".to_string(),
            stderr: String::new(),
        };
        assert_eq!(
            classify_exact_mountpoint("/data/rustfs-fault/dm-volume", &parent)
                .expect("classify parent mount"),
            DmMountState::Unmounted
        );

        let exact = CommandOutput {
            code: Some(0),
            stdout: "/data/rustfs-fault/dm-volume\n".to_string(),
            stderr: String::new(),
        };
        assert_eq!(
            classify_exact_mountpoint("/data/rustfs-fault/dm-volume", &exact)
                .expect("classify exact mount"),
            DmMountState::Mounted
        );

        let no_match = CommandOutput {
            code: Some(1),
            stdout: String::new(),
            stderr: String::new(),
        };
        assert_eq!(
            classify_exact_mountpoint("/data/rustfs-fault/dm-volume", &no_match)
                .expect("classify clean no-match"),
            DmMountState::Unmounted
        );
    }

    #[test]
    fn exact_mountpoint_rejects_exit_one_with_command_diagnostics() {
        for output in [
            CommandOutput {
                code: Some(1),
                stdout: String::new(),
                stderr: "error: unable to upgrade connection: container not found".to_string(),
            },
            CommandOutput {
                code: Some(1),
                stdout: "unexpected chroot output".to_string(),
                stderr: String::new(),
            },
        ] {
            assert!(
                classify_exact_mountpoint("/data/rustfs-fault/dm-volume", &output).is_err(),
                "kubectl/chroot/findmnt diagnostics must not prove an unmount"
            );
        }
    }

    #[test]
    fn offline_check_requires_the_mapper_to_have_no_mounts() {
        validate_unmounted_source(
            "/dev/mapper/rustfs-fault-dm",
            &CommandOutput {
                code: Some(1),
                stdout: String::new(),
                stderr: String::new(),
            },
        )
        .expect("clean findmnt no-match proves no mapper mount");

        for output in [
            CommandOutput {
                code: Some(0),
                stdout: "/data/other-mount\n".to_string(),
                stderr: String::new(),
            },
            CommandOutput {
                code: Some(1),
                stdout: String::new(),
                stderr: "findmnt failed".to_string(),
            },
        ] {
            assert!(validate_unmounted_source("/dev/mapper/rustfs-fault-dm", &output).is_err());
        }
    }

    #[test]
    fn dm_table_comparison_uses_semantics_and_full_geometry() {
        assert!(
            dm_tables_match(
                "0 1024  flakey   /dev/loop0 0 1 15\n",
                "0 1024 flakey /dev/loop0 0 1 15 2 error_reads error_writes",
            )
            .expect("compare equivalent flakey tables")
        );
        assert!(
            !dm_tables_match(
                "0 1024 flakey /dev/loop0 0 1 15",
                "0 1024 flakey /dev/loop1 0 1 15",
            )
            .expect("compare different backing devices")
        );
    }

    #[test]
    fn dm_spec_rejects_unbounded_or_unsafe_targets() {
        let valid = DmFlakeySpec {
            node: "worker-a",
            mount_path: "/data/rustfs-fault/dm-volume",
            helper_image: "busybox:test",
            name: "rustfs-fault-dm",
            behavior: DmFaultBehavior::ErrorInjection,
            fault_table: Some("0 1024 flakey /dev/loop0 0 1 15"),
            recovery_table: None,
            run_id: "run-123",
        };
        assert!(validate_dm_spec(&valid).is_ok());

        let root = DmFlakeySpec {
            mount_path: "/",
            ..valid
        };
        assert!(validate_dm_spec(&root).is_err());
    }

    #[test]
    fn forced_pod_delete_is_uid_preconditioned() {
        let config = FaultTestConfig::for_test("real-cluster", "rustfs-fault-dm");
        let command = force_delete_pod_command(&config.cluster, "rustfs-0", "uid-old")
            .expect("delete command");
        let body = serde_json::from_str::<serde_json::Value>(
            command.stdin.as_deref().expect("delete options body"),
        )
        .expect("delete options JSON");

        assert!(command.args.windows(2).any(|args| args
            == [
                "--raw",
                "/api/v1/namespaces/rustfs-fault-test/pods/rustfs-0"
            ]));
        assert_eq!(
            body.pointer("/preconditions/uid")
                .and_then(|value| value.as_str()),
            Some("uid-old")
        );
        assert_eq!(
            body.get("gracePeriodSeconds")
                .and_then(|value| value.as_u64()),
            Some(0)
        );
    }

    #[test]
    fn crash_boundary_requires_a_live_original_pod_but_recovery_is_idempotent() {
        let original = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-old"},
            "spec": {"nodeName": "worker-a"}
        });
        assert_eq!(
            classify_initial_target_pod(
                Some(&original),
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::CrashBoundary,
            )
            .expect("live original Pod"),
            DmInitialPodAction::DeleteOriginal
        );

        let mut terminating = original;
        terminating["metadata"]["deletionTimestamp"] = json!("2026-09-11T00:00:00Z");
        assert!(
            classify_initial_target_pod(
                Some(&terminating),
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::CrashBoundary,
            )
            .is_err()
        );
        assert_eq!(
            classify_initial_target_pod(
                Some(&terminating),
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::Recovery,
            )
            .expect("recovery waits for an in-flight deletion"),
            DmInitialPodAction::WaitForOriginal
        );
        assert!(
            classify_initial_target_pod(
                None,
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::CrashBoundary,
            )
            .is_err()
        );
        assert_eq!(
            classify_initial_target_pod(
                None,
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::Recovery,
            )
            .expect("already absent during recovery"),
            DmInitialPodAction::AlreadyQuiesced(None)
        );

        let replacement = json!({
            "metadata": {"name": "rustfs-0", "uid": "uid-new"},
            "spec": {}
        });
        assert!(
            classify_initial_target_pod(
                Some(&replacement),
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::CrashBoundary,
            )
            .is_err()
        );
        assert_eq!(
            classify_initial_target_pod(
                Some(&replacement),
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::Recovery,
            )
            .expect("pending replacement is quiesced by the node taint"),
            DmInitialPodAction::AlreadyQuiesced(Some("uid-new".to_string()))
        );
        let mut replacement_on_target = replacement;
        replacement_on_target["spec"]["nodeName"] = json!("worker-a");
        assert!(
            classify_initial_target_pod(
                Some(&replacement_on_target),
                "rustfs-0",
                "uid-old",
                "worker-a",
                DmPodDeletionMode::Recovery,
            )
            .is_err()
        );
    }

    #[test]
    fn dm_flakey_spec_maps_explicit_config_fields() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.dm_name = Some("rustfs-fault-dm".to_string());
        config.dm_node = Some("worker-a".to_string());
        config.dm_mount_path = Some("/data/rustfs-fault/dm-volume".to_string());
        config.dm_fault_table = Some("0 1024 flakey /dev/loop0 0 1 15".to_string());
        config.dm_recovery_table = Some("0 1024 linear /dev/loop0 0".to_string());

        let spec =
            dm_flakey_spec(&config, "run-123", DmFaultBehavior::ErrorInjection).expect("dm spec");

        assert_eq!(spec.name, "rustfs-fault-dm");
        assert_eq!(spec.node, "worker-a");
        assert_eq!(spec.mount_path, "/data/rustfs-fault/dm-volume");
        assert_eq!(spec.helper_image, config.dm_helper_image);
        assert_eq!(spec.fault_table, Some("0 1024 flakey /dev/loop0 0 1 15"));
        assert_eq!(spec.recovery_table, Some("0 1024 linear /dev/loop0 0"));
        assert_eq!(spec.run_id, "run-123");
    }

    #[test]
    fn dm_flakey_spec_requires_explicit_target_config() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");

        let error = dm_flakey_spec(&config, "run-123", DmFaultBehavior::ErrorInjection)
            .expect_err("missing dm config");

        assert!(
            error
                .to_string()
                .contains("RUSTFS_FAULT_TEST_DM_NAME is required")
        );
    }

    #[test]
    fn drop_writes_crash_spec_does_not_require_an_external_fault_table() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.dm_name = Some("rustfs-fault-dm".to_string());
        config.dm_node = Some("worker-a".to_string());
        config.dm_mount_path = Some("/data/rustfs-fault/dm-volume".to_string());

        let spec = dm_flakey_spec(&config, "run-123", DmFaultBehavior::DropWritesCrash)
            .expect("drop-writes crash spec");

        assert_eq!(spec.behavior, DmFaultBehavior::DropWritesCrash);
        assert_eq!(spec.fault_table, None);
        assert!(validate_dm_spec(&spec).is_ok());
    }

    #[test]
    fn dm_target_follows_the_rustfs_mount_to_the_exact_pvc() {
        let binding = resolve_dm_pod_volume(
            &pod_list(true),
            "worker-a",
            "/data/rustfs0",
            DmPodReadiness::Required,
        )
        .expect("resolve data mount");
        assert_eq!(binding.volume_name, "data");
        assert_eq!(binding.pvc, "data-rustfs-0");

        let mapping = complete_dm_volume_mapping(
            "rustfs-fault-test",
            binding,
            &pvc("pvc-uid-a"),
            &pv("pv-uid-a", "pvc-uid-a"),
            &node("worker-a", "node-uid-a", "worker-a"),
            "/data/rustfs-fault/dm-volume",
        )
        .expect("complete mapping");
        assert_eq!(mapping.pvc_uid, "pvc-uid-a");
        assert_eq!(mapping.pv_uid, "pv-uid-a");
        assert_eq!(mapping.pv_claim_ref.uid, "pvc-uid-a");
        assert_eq!(
            helper_pod_name("run-ABC-123"),
            "rustfs-fault-dm-helper-runabc123"
        );
    }

    #[test]
    fn dm_apply_mapping_detects_same_name_pvc_and_pv_recreation() {
        let binding = resolve_dm_pod_volume(
            &pod_list(true),
            "worker-a",
            "/data/rustfs0",
            DmPodReadiness::Required,
        )
        .expect("resolve data mount");
        let original = complete_dm_volume_mapping(
            "rustfs-fault-test",
            binding.clone(),
            &pvc("pvc-uid-old"),
            &pv("pv-uid-old", "pvc-uid-old"),
            &node("worker-a", "node-uid-a", "worker-a"),
            "/data/rustfs-fault/dm-volume",
        )
        .expect("original mapping");
        let recreated = complete_dm_volume_mapping(
            "rustfs-fault-test",
            binding,
            &pvc("pvc-uid-new"),
            &pv("pv-uid-new", "pvc-uid-new"),
            &node("worker-a", "node-uid-a", "worker-a"),
            "/data/rustfs-fault/dm-volume",
        )
        .expect("recreated mapping");

        assert_ne!(original, recreated);
    }

    #[test]
    fn dm_mapping_rejects_claim_ref_mismatch_and_compound_topology() {
        let binding = resolve_dm_pod_volume(
            &pod_list(true),
            "worker-a",
            "/data/rustfs0",
            DmPodReadiness::Required,
        )
        .expect("resolve data mount");
        assert!(
            complete_dm_volume_mapping(
                "rustfs-fault-test",
                binding.clone(),
                &pvc("pvc-uid-a"),
                &pv("pv-uid-a", "other-pvc-uid"),
                &node("worker-a", "node-uid-a", "worker-a"),
                "/data/rustfs-fault/dm-volume",
            )
            .is_err()
        );

        let mut compound = pv("pv-uid-a", "pvc-uid-a");
        compound["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"]
            .as_array_mut()
            .expect("expressions")
            .push(json!({"key": "disk.example.com/class", "operator": "In", "values": ["nvme"]}));
        assert!(
            supported_pv_node_selector(
                &compound,
                &BTreeMap::from([("kubernetes.io/hostname".to_string(), "worker-a".to_string(),)]),
            )
            .is_err()
        );
    }

    #[test]
    fn dm_mapping_requires_readiness_during_proof_but_not_before_forced_delete() {
        assert!(
            resolve_dm_pod_volume(
                &pod_list(false),
                "worker-a",
                "/data/rustfs0",
                DmPodReadiness::Required,
            )
            .is_err()
        );
        resolve_dm_pod_volume(
            &pod_list(false),
            "worker-a",
            "/data/rustfs0",
            DmPodReadiness::MayBeUnready,
        )
        .expect("the proven Pod may become unready under the active fault");

        let mut terminating = pod_list(true);
        terminating["items"][0]["metadata"]["deletionTimestamp"] = json!("2026-09-04T00:00:00Z");
        assert!(
            resolve_dm_pod_volume(
                &terminating,
                "worker-a",
                "/data/rustfs0",
                DmPodReadiness::MayBeUnready,
            )
            .is_err()
        );
    }

    #[test]
    fn dm_mapping_requires_bound_pvc_and_pv() {
        let binding = resolve_dm_pod_volume(
            &pod_list(true),
            "worker-a",
            "/data/rustfs0",
            DmPodReadiness::Required,
        )
        .expect("resolve data mount");
        let mut lost_pvc = pvc("pvc-uid-a");
        lost_pvc["status"]["phase"] = json!("Lost");
        assert!(
            complete_dm_volume_mapping(
                "rustfs-fault-test",
                binding.clone(),
                &lost_pvc,
                &pv("pv-uid-a", "pvc-uid-a"),
                &node("worker-a", "node-uid-a", "worker-a"),
                "/data/rustfs-fault/dm-volume",
            )
            .is_err()
        );

        let mut released_pv = pv("pv-uid-a", "pvc-uid-a");
        released_pv["status"]["phase"] = json!("Released");
        assert!(
            complete_dm_volume_mapping(
                "rustfs-fault-test",
                binding,
                &pvc("pvc-uid-a"),
                &released_pv,
                &node("worker-a", "node-uid-a", "worker-a"),
                "/data/rustfs-fault/dm-volume",
            )
            .is_err()
        );
    }

    #[test]
    fn dm_mapping_uses_the_node_hostname_label_and_binds_node_identity() {
        let binding = resolve_dm_pod_volume(
            &pod_list(true),
            "worker-a",
            "/data/rustfs0",
            DmPodReadiness::Required,
        )
        .expect("resolve data mount");
        let mut matching_pv = pv("pv-uid-a", "pvc-uid-a");
        matching_pv["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchExpressions"]
            [0]["values"] = json!(["storage-host-a"]);
        let target_node = node("worker-a", "node-uid-a", "storage-host-a");
        let mapping = complete_dm_volume_mapping(
            "rustfs-fault-test",
            binding.clone(),
            &pvc("pvc-uid-a"),
            &matching_pv,
            &target_node,
            "/data/rustfs-fault/dm-volume",
        )
        .expect("hostname selector matches Node label");
        assert_eq!(mapping.node_uid, "node-uid-a");
        assert_eq!(
            mapping.node_labels["kubernetes.io/hostname"],
            "storage-host-a"
        );

        assert!(
            complete_dm_volume_mapping(
                "rustfs-fault-test",
                binding,
                &pvc("pvc-uid-a"),
                &pv("pv-uid-a", "pvc-uid-a"),
                &target_node,
                "/data/rustfs-fault/dm-volume",
            )
            .is_err(),
            "the Pod node name must not stand in for its hostname label"
        );
    }

    #[test]
    fn dm_apply_rejects_an_initially_suspended_mapper_without_commands() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let mut port = FakeDmPort {
            suspended: true,
            active_table: recovery.to_string(),
            inactive_table: None,
            active_table_after_suspend: None,
            fail_next_suspend_after_suspending: false,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        assert!(
            transition_dm_table(
                &mut port,
                "0 1024 flakey /dev/loop0 0 1 15",
                DmSuspendMode::Default,
                DmTransitionPolicy::Apply {
                    recovery_table: recovery,
                },
            )
            .is_err()
        );
        assert_eq!(
            (port.suspend_calls, port.load_calls, port.resume_calls),
            (0, 0, 0)
        );
        assert!(port.suspended);
        assert_eq!(port.active_table, recovery);
    }

    #[test]
    fn dm_apply_rejects_recovery_table_drift_before_suspending() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let fault = "0 1024 flakey /dev/loop0 0 1 15";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: "0 1024 linear /dev/loop1 0".to_string(),
            inactive_table: None,
            active_table_after_suspend: None,
            fail_next_suspend_after_suspending: false,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        assert!(
            transition_dm_table(
                &mut port,
                fault,
                DmSuspendMode::Default,
                DmTransitionPolicy::Apply {
                    recovery_table: recovery,
                },
            )
            .is_err()
        );
        assert_eq!(
            (port.suspend_calls, port.load_calls, port.resume_calls),
            (0, 0, 0)
        );
    }

    #[test]
    fn dm_apply_suspend_error_recovers_without_loading_the_fault_table() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let fault = "0 1024 flakey /dev/loop0 0 1 15";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: recovery.to_string(),
            inactive_table: None,
            active_table_after_suspend: None,
            fail_next_suspend_after_suspending: true,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        assert!(
            transition_dm_table(
                &mut port,
                fault,
                DmSuspendMode::Default,
                DmTransitionPolicy::Apply {
                    recovery_table: recovery,
                },
            )
            .is_err()
        );
        assert_eq!(port.loaded_tables, [recovery]);
        assert!(!port.loaded_tables.iter().any(|table| table == fault));
        assert!(!port.suspended);
        assert!(dm_tables_match(&port.active_table, recovery).expect("compare recovery table"));
    }

    #[test]
    fn dm_apply_recovers_if_the_table_drifts_during_suspend() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let fault = "0 1024 flakey /dev/loop0 0 1 15";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: recovery.to_string(),
            inactive_table: None,
            active_table_after_suspend: Some("0 1024 linear /dev/loop1 0".to_string()),
            fail_next_suspend_after_suspending: false,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        assert!(
            transition_dm_table(
                &mut port,
                fault,
                DmSuspendMode::Default,
                DmTransitionPolicy::Apply {
                    recovery_table: recovery,
                },
            )
            .is_err()
        );
        assert_eq!(port.loaded_tables, [recovery]);
        assert!(!port.loaded_tables.iter().any(|table| table == fault));
        assert!(!port.suspended);
        assert!(dm_tables_match(&port.active_table, recovery).expect("compare recovery table"));
    }

    #[test]
    fn dm_apply_recovers_if_the_table_becomes_unparseable_during_suspend() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let fault = "0 1024 flakey /dev/loop0 0 1 15";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: recovery.to_string(),
            inactive_table: None,
            active_table_after_suspend: Some("0 1024 error".to_string()),
            fail_next_suspend_after_suspending: false,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        assert!(
            transition_dm_table(
                &mut port,
                fault,
                DmSuspendMode::Default,
                DmTransitionPolicy::Apply {
                    recovery_table: recovery,
                },
            )
            .is_err()
        );
        assert_eq!(port.loaded_tables, [recovery]);
        assert!(!port.suspended);
        assert!(dm_tables_match(&port.active_table, recovery).expect("compare recovery table"));
    }

    #[test]
    fn dm_rollback_overwrites_an_unparseable_active_table() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: "0 1024 error".to_string(),
            inactive_table: None,
            active_table_after_suspend: None,
            fail_next_suspend_after_suspending: false,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        transition_dm_table(
            &mut port,
            recovery,
            DmSuspendMode::NoFlush,
            DmTransitionPolicy::Rollback,
        )
        .expect("rollback must not depend on parsing the damaged active table");

        assert_eq!(port.loaded_tables, [recovery]);
        assert!(!port.suspended);
        assert!(dm_tables_match(&port.active_table, recovery).expect("compare recovery table"));
    }

    #[test]
    fn dm_resume_failure_recovers_from_the_already_suspended_state() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let fault = "0 1024 flakey /dev/loop0 0 1 15";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: recovery.to_string(),
            inactive_table: None,
            active_table_after_suspend: None,
            fail_next_suspend_after_suspending: false,
            fail_next_resume: true,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        assert!(
            transition_dm_table(
                &mut port,
                fault,
                DmSuspendMode::Default,
                DmTransitionPolicy::Apply {
                    recovery_table: recovery,
                },
            )
            .is_err()
        );
        assert!(port.suspended);
        transition_dm_table(
            &mut port,
            recovery,
            DmSuspendMode::NoFlush,
            DmTransitionPolicy::Rollback,
        )
        .expect("recover already-suspended mapper");

        assert!(!port.suspended);
        assert!(dm_tables_match(&port.active_table, recovery).expect("compare recovery table"));
        assert_eq!(port.loaded_tables, [fault, recovery]);
        assert_eq!(
            port.suspend_calls, 1,
            "recovery must not issue another suspend"
        );
    }

    #[test]
    fn host_mutation_lease_is_identity_scoped_and_cleaned() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let state_path = temporary.path().join(".host-mutation-token-a.json");
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.cluster.artifacts_dir = temporary.path().to_path_buf();
        config.host_mutation_state_file = Some(state_path.clone());
        config.host_mutation_state_token = Some("token-a".to_string());
        let mut lease = HostMutationLease::from_config(&config, "run-a").expect("lease");
        lease
            .set_phase(HostMutationPhase::Activating)
            .expect("persist activating state");
        let activating: HostMutationState =
            serde_json::from_slice(&std::fs::read(&state_path).expect("read state"))
                .expect("parse state");
        assert_eq!(activating.phase, HostMutationPhase::Activating);
        lease
            .set_phase(HostMutationPhase::Active)
            .expect("persist active state");
        let state: HostMutationState =
            serde_json::from_slice(&std::fs::read(&state_path).expect("read state"))
                .expect("parse state");
        assert_eq!(state.token, "token-a");
        assert_eq!(state.owner_pid, std::process::id());
        lease.clear().expect("clear owned state");
        assert!(!state_path.exists());

        lease
            .set_phase(HostMutationPhase::Rollback)
            .expect("persist rollback state");
        lease
            .set_phase(HostMutationPhase::RecoveryRequired)
            .expect("retain failed recovery state");
        let unresolved: HostMutationState =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        assert_eq!(unresolved.phase, HostMutationPhase::RecoveryRequired);
        let mut replaced = state;
        replaced.token = "token-b".to_string();
        std::fs::write(
            &state_path,
            serde_json::to_vec(&replaced).expect("serialize replacement"),
        )
        .expect("replace state");
        assert!(lease.clear().is_err());
        assert!(state_path.exists());
    }

    #[test]
    fn failed_mapper_containment_suspends_without_loading_or_resuming() {
        let recovery = "0 1024 linear /dev/loop0 0";
        for (already_suspended, transport_error) in [(false, false), (true, false), (false, true)] {
            let mut port = FakeDmPort {
                suspended: already_suspended,
                active_table: "0 1024 flakey /dev/loop0 0 1 15".to_string(),
                inactive_table: None,
                active_table_after_suspend: None,
                fail_next_suspend_after_suspending: transport_error,
                fail_next_resume: false,
                suspend_calls: 0,
                load_calls: 0,
                loaded_tables: Vec::new(),
                resume_calls: 0,
            };
            super::contain_unrecovered_mapper(&mut port, recovery)
                .expect("suspension must be observed despite a lost command response");
            assert!(port.suspended);
            assert_eq!(port.suspend_calls, usize::from(!already_suspended));
            assert_eq!(port.load_calls, 0);
            assert_eq!(port.resume_calls, 0);
        }
        assert_eq!(
            dm_suspend_args("mapper", DmSuspendMode::NoFlushNoLockFs),
            ["suspend", "--noflush", "--nolockfs", "mapper"]
        );
    }

    #[test]
    fn containment_does_not_suspend_an_active_recovery_table() {
        let recovery = "0 1024 linear /dev/loop0 0";
        let mut port = FakeDmPort {
            suspended: false,
            active_table: recovery.to_string(),
            inactive_table: None,
            active_table_after_suspend: None,
            fail_next_suspend_after_suspending: false,
            fail_next_resume: false,
            suspend_calls: 0,
            load_calls: 0,
            loaded_tables: Vec::new(),
            resume_calls: 0,
        };

        super::contain_unrecovered_mapper(&mut port, recovery)
            .expect("active recovery table is already safe from mapper containment");
        assert!(!port.suspended);
        assert_eq!(port.suspend_calls, 0);
    }

    #[test]
    fn containment_rejects_a_successful_suspend_without_suspended_state() {
        struct UnchangedMapper;
        impl DmTransitionPort for UnchangedMapper {
            fn observe(&mut self) -> anyhow::Result<DmObservedState> {
                Ok(DmObservedState {
                    suspended: false,
                    active_table: String::new(),
                })
            }
            fn suspend(&mut self, _mode: DmSuspendMode) -> anyhow::Result<()> {
                Ok(())
            }
            fn load(&mut self, _table: &str) -> anyhow::Result<()> {
                panic!("containment must not load a table")
            }
            fn resume(&mut self) -> anyhow::Result<()> {
                panic!("containment must not resume IO")
            }
        }
        assert!(
            super::contain_unrecovered_mapper(&mut UnchangedMapper, "0 1024 linear /dev/loop0 0")
                .is_err()
        );
    }
}
