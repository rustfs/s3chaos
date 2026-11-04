// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

//! One-shot PodChaos armed before load and applied after the first S3 request.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use super::{
    chaos_mesh::{self, ChaosGuard, PodChaosSpec},
    lifecycle::{BackgroundTask, wait_for_load},
};
use crate::{
    fault::{
        fault_artifacts::FaultFailureArtifactSource,
        fault_lifecycle::{AppliedFault, FaultLifecyclePort},
        history::{DurabilityCohort, OperationRecord},
        pods::{rustfs_pod_identities, wait_for_rustfs_pod_replacement},
        reporting::{FaultStatusSnapshot, PodIdentity},
    },
    framework::{artifacts::ArtifactCollector, config::ClusterTestConfig},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PodKillEvidence {
    schema_version: u8,
    pub(crate) scenario: String,
    pub(crate) run_id: String,
    pub(crate) pod: PodIdentity,
    pub(crate) namespace: String,
    pub(crate) resource_name: String,
    request_gate_at_ms: u64,
    pub(crate) apply_started_at_ms: u64,
    pub(crate) deletion_observed_at_ms: u64,
    pods_after_deletion: Vec<PodIdentity>,
}

impl PodKillEvidence {
    pub(crate) fn require_workload_window(
        &self,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            started_at_ms <= self.apply_started_at_ms
                && self.deletion_observed_at_ms <= ended_at_ms,
            "Pod kill observation is outside the recorded workload"
        );
        Ok(())
    }

    pub(crate) fn validate(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported Pod kill evidence version"
        );
        ensure!(
            !self.pod.uid.is_empty() && !self.pod.name.is_empty(),
            "Pod kill target identity is missing"
        );
        ensure!(
            self.request_gate_at_ms > 0
                && self.request_gate_at_ms <= self.apply_started_at_ms
                && self.apply_started_at_ms <= self.deletion_observed_at_ms,
            "Pod kill was not triggered after workload began"
        );
        ensure!(
            !self
                .pods_after_deletion
                .iter()
                .any(|pod| pod.uid == self.pod.uid),
            "original Pod UID is still present after the kill"
        );
        let mut intervals = history
            .iter()
            .filter(|record| {
                record.scenario == self.scenario
                    && record.run_id.as_deref() == Some(&self.run_id)
                    && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                    && record.started_at_ms < record.ended_at_ms
            })
            .map(|record| (record.started_at_ms, record.ended_at_ms))
            .collect::<Vec<_>>();
        intervals.sort_unstable();
        // The actual deletion lies somewhere between apply and the first
        // absence observation. Continuous request coverage proves load at any
        // instant in that interval; a gap cannot establish that claim.
        let mut covered_until = self.apply_started_at_ms;
        for (start, end) in intervals {
            if start < covered_until && end > covered_until {
                covered_until = end;
            }
        }
        ensure!(
            covered_until > self.deletion_observed_at_ms,
            "Pod kill has no continuous S3 request overlap across its apply/deletion interval"
        );
        Ok(())
    }
}

pub(crate) fn validate_snapshot(
    snapshot: &serde_json::Value,
    history: &[OperationRecord],
    scenario: &str,
    run_id: &str,
    namespace: &str,
    chaos_namespace: &str,
    before: &[PodIdentity],
) -> Result<PodKillEvidence> {
    let proof: PodKillEvidence = serde_json::from_value(
        snapshot
            .get("pod_kill_status")
            .context("Pod kill snapshot lacks overlap evidence")?
            .clone(),
    )?;
    ensure!(
        proof.scenario == scenario
            && proof.run_id == run_id
            && proof.namespace == namespace
            && before.contains(&proof.pod),
        "Pod kill evidence is outside the run or original Pod generation"
    );
    let resource = snapshot
        .get("chaos_status")
        .context("Pod kill resource is missing")?;
    ensure!(
        snapshot["resource_kind"] == "podchaos"
            && snapshot["resource_name"] == proof.resource_name
            && resource["metadata"]["name"] == proof.resource_name
            && resource["metadata"]["namespace"] == chaos_namespace
            && resource["metadata"]["labels"]["rustfs-fault-test/run-id"] == proof.run_id
            && resource["metadata"]["labels"]["rustfs-fault-test/scenario"] == proof.scenario
            && resource["spec"]["action"] == "pod-kill"
            && resource["spec"]["mode"] == "one"
            && resource["spec"]["selector"]["pods"]
                == serde_json::json!({ &proof.namespace: [&proof.pod.name] }),
        "Pod kill resource does not bind the exact target and run"
    );
    ensure!(
        injection_recorded(resource, &proof.namespace, &proof.pod.name),
        "Pod kill has no successful controller injection record for its target"
    );
    proof.validate(history)?;
    Ok(proof)
}

fn injection_recorded(resource: &serde_json::Value, namespace: &str, pod: &str) -> bool {
    let id = format!("{namespace}/{pod}");
    resource
        .pointer("/status/experiment/containerRecords")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|records| {
            records.iter().any(|record| {
                record["id"] == id
                    && record["injectedCount"]
                        .as_u64()
                        .is_some_and(|count| count > 0)
            })
        })
}

struct Activation {
    guard: ChaosGuard,
    evidence: Option<PodKillEvidence>,
}

struct PodKillFaultHandle {
    config: ClusterTestConfig,
    spec: PodChaosSpec,
    before: Vec<PodIdentity>,
    gate: Arc<AtomicU64>,
    worker: Mutex<Option<BackgroundTask>>,
    activation: Arc<Mutex<Option<Activation>>>,
}

pub(super) fn arm(
    config: &ClusterTestConfig,
    spec: PodChaosSpec,
    before: Vec<PodIdentity>,
) -> Result<AppliedFault> {
    let pod = before
        .iter()
        .find(|pod| Some(&pod.name) == spec.pod_name.as_ref())
        .context("Pod kill lacks an exact original Pod identity")?
        .clone();
    let activation = Arc::new(Mutex::new(None));
    let gate = Arc::new(AtomicU64::new(0));
    let worker_gate = Arc::clone(&gate);
    let worker_activation = Arc::clone(&activation);
    let worker_spec = spec.clone();
    let timeout = config.timeout;
    let mut worker_config = config.clone();
    worker_config.timeout = timeout.min(Duration::from_secs(30));
    let worker = BackgroundTask::spawn(move |cancel| {
        let request_gate_at_ms = wait_for_load(&worker_gate, cancel, timeout.saturating_mul(3))?;
        let current = rustfs_pod_identities(&worker_config)?;
        ensure!(
            current.contains(&pod),
            "Pod kill target changed before injection"
        );
        ensure!(
            !cancel.load(Ordering::SeqCst),
            "Pod kill cancelled before injection"
        );
        let apply_started_at_ms = now_ms();
        let guard = chaos_mesh::apply_podchaos(&worker_config, &worker_spec)?;
        *worker_activation.lock().expect("Pod kill activation mutex") = Some(Activation {
            guard,
            evidence: None,
        });
        let deadline = Instant::now() + timeout;
        let mut deletion_observed_at_ms = None;
        let mut last_observation = "no observation completed".to_string();
        loop {
            ensure!(
                !cancel.load(Ordering::SeqCst),
                "Pod kill cancelled during activation"
            );
            ensure!(
                Instant::now() < deadline,
                "Pod kill activation was not confirmed within {timeout:?}; last observation: {last_observation}"
            );
            let observation: Result<_> = (|| {
                let mut probe_config = worker_config.clone();
                probe_config.timeout = probe_config
                    .timeout
                    .min(deadline.saturating_duration_since(Instant::now()));
                let current = rustfs_pod_identities(&probe_config)
                    .context("observe Pod kill target deletion")?;
                ensure!(
                    !current.iter().any(|observed| observed.uid == pod.uid),
                    "original Pod UID is still present"
                );
                deletion_observed_at_ms.get_or_insert_with(now_ms);
                let state = worker_activation.lock().expect("Pod kill activation mutex");
                ensure!(
                    !cancel.load(Ordering::SeqCst),
                    "Pod kill cancelled during activation"
                );
                let remaining = deadline.saturating_duration_since(Instant::now());
                ensure!(!remaining.is_zero(), "activation deadline elapsed");
                let status = state
                    .as_ref()
                    .context("Pod kill resource is missing")?
                    .guard
                    .json_with_timeout(worker_config.timeout.min(remaining))
                    .context("observe PodChaos injection status")?;
                drop(state);
                ensure!(
                    injection_recorded(
                        &serde_json::from_str(&status)
                            .context("parse PodChaos injection status")?,
                        &worker_spec.target_namespace,
                        &pod.name,
                    ),
                    "controller has not recorded the Pod kill"
                );
                Ok(current)
            })();
            if let Ok(current) = observation {
                ensure!(
                    !cancel.load(Ordering::SeqCst),
                    "Pod kill cancelled during activation"
                );
                ensure!(Instant::now() < deadline, "activation deadline elapsed");
                let evidence = PodKillEvidence {
                    schema_version: 1,
                    scenario: worker_spec.scenario.clone(),
                    run_id: worker_spec.run_id.clone(),
                    pod,
                    namespace: worker_spec.target_namespace.clone(),
                    resource_name: worker_spec.name.clone(),
                    request_gate_at_ms,
                    apply_started_at_ms,
                    deletion_observed_at_ms: deletion_observed_at_ms.expect("observed deletion"),
                    pods_after_deletion: current,
                };
                worker_activation
                    .lock()
                    .expect("Pod kill activation mutex")
                    .as_mut()
                    .context("Pod kill resource is missing")?
                    .evidence = Some(evidence);
                return Ok(());
            } else if let Err(error) = observation {
                last_observation = format!("{error:#}");
            }
            std::thread::sleep(
                Duration::from_millis(20).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    });
    Ok(Box::new(PodKillFaultHandle {
        config: config.clone(),
        spec,
        before,
        gate,
        worker: Mutex::new(Some(worker)),
        activation,
    }))
}

impl PodKillFaultHandle {
    fn require_worker_healthy(&self) -> Result<()> {
        if let Some(worker) = self.worker.lock().expect("Pod kill worker mutex").as_mut() {
            worker.require_healthy()?;
        }
        Ok(())
    }

    fn stop_worker(&self) -> Result<()> {
        if let Some(worker) = self.worker.lock().expect("Pod kill worker mutex").take() {
            worker.stop()?;
        }
        Ok(())
    }
}

impl Drop for PodKillFaultHandle {
    fn drop(&mut self) {
        let _ = self.stop_worker();
        // Joining prevents a delayed worker from creating chaos after cleanup.
        self.activation
            .lock()
            .expect("Pod kill activation mutex")
            .take();
    }
}

impl FaultLifecyclePort for PodKillFaultHandle {
    fn wait_active(&self, _timeout: Duration) -> Result<()> {
        // The resource is armed here. Its actual application and deletion
        // timestamps are required in the post-workload evidence.
        self.require_worker_healthy()
    }

    fn load_gate(&self) -> Option<Arc<AtomicU64>> {
        Some(Arc::clone(&self.gate))
    }

    fn ensure_active(&self, _stage: &str) -> Result<()> {
        self.require_worker_healthy()?;
        ensure!(
            self.activation
                .lock()
                .expect("Pod kill activation mutex")
                .as_ref()
                .is_some_and(|active| active.evidence.is_some()),
            "Pod kill did not complete while workload was running"
        );
        Ok(())
    }

    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
        let activation = self.activation.lock().expect("Pod kill activation mutex");
        let (chaos_status, pod_kill_status) = match activation.as_ref() {
            Some(active) => (
                Some(serde_json::from_str(&active.guard.json()?)?),
                active.evidence.clone(),
            ),
            // An armed snapshot carries the planned selector for survivor
            // routing. Successful injection still requires controller evidence.
            None => (Some(serde_yaml_ng::from_str(&self.spec.manifest())?), None),
        };
        Ok(FaultStatusSnapshot {
            stage: stage.to_string(),
            resource_kind: Some("podchaos".into()),
            resource_name: Some(self.spec.name.clone()),
            chaos_status,
            pod_kill_status,
            dm_status: None,
            lifecycle_status: None,
            quorum_dm_status: None,
        })
    }

    fn delete(&mut self, timeout: Duration) -> Result<()> {
        let stopped = self.stop_worker();
        let mut active = self
            .activation
            .lock()
            .expect("Pod kill activation mutex")
            .take();
        if let Some(active) = active.as_mut() {
            active.guard.delete(timeout)?;
        }
        stopped?;
        wait_for_rustfs_pod_replacement(&self.config, &self.before, timeout)
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        Some(self)
    }
}

impl FaultFailureArtifactSource for PodKillFaultHandle {
    fn collect_failure_artifacts(
        &self,
        collector: &ArtifactCollector,
        case_name: &str,
        suffix: &str,
    ) -> Result<()> {
        let state = self.activation.lock().expect("Pod kill activation mutex");
        if let Some(active) = state.as_ref() {
            super::runtime::collect_chaos_failure_artifacts(
                &active.guard,
                collector,
                case_name,
                suffix,
            )?;
            collector.write_text(
                case_name,
                &format!("pod-kill-{suffix}.json"),
                &serde_json::to_string_pretty(&active.evidence)?,
            )?;
        }
        Ok(())
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock")
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> PodKillEvidence {
        PodKillEvidence {
            schema_version: 1,
            scenario: "pod-kill-one".into(),
            run_id: "run".into(),
            pod: PodIdentity {
                name: "rustfs-1".into(),
                uid: "old".into(),
            },
            namespace: "test".into(),
            resource_name: "kill".into(),
            request_gate_at_ms: 8,
            apply_started_at_ms: 10,
            deletion_observed_at_ms: 30,
            pods_after_deletion: vec![],
        }
    }

    fn request(start: u64, end: u64) -> OperationRecord {
        serde_json::from_value(serde_json::json!({
            "id": format!("request-{start}"), "scenario": "pod-kill-one", "run_id": "run",
            "kind": "put", "bucket": "bucket", "started_at_ms": start, "ended_at_ms": end,
            "outcome": "ok", "durability_cohort": "fault_active"
        }))
        .expect("request")
    }

    fn snapshot() -> serde_json::Value {
        let proof = evidence();
        serde_json::json!({
            "resource_kind": "podchaos", "resource_name": proof.resource_name,
            "pod_kill_status": proof,
            "chaos_status": {
                "metadata": {"name": "kill", "namespace": "chaos-mesh", "labels": {
                    "rustfs-fault-test/run-id": "run", "rustfs-fault-test/scenario": "pod-kill-one"
                }},
                "spec": {"action": "pod-kill", "mode": "one", "selector": {"pods": {"test": ["rustfs-1"]}}},
                "status": {"experiment": {"containerRecords": [{"id": "test/rustfs-1", "injectedCount": 1}]}}
            }
        })
    }

    #[test]
    fn snapshot_binds_overlap_to_the_run_target_and_controller_injection() {
        let validate = |value: &serde_json::Value| {
            validate_snapshot(
                value,
                &[request(9, 31)],
                "pod-kill-one",
                "run",
                "test",
                "chaos-mesh",
                &[evidence().pod],
            )
        };
        validate(&snapshot()).expect("valid evidence");
        for (pointer, replacement) in [
            ("/pod_kill_status", serde_json::Value::Null),
            ("/pod_kill_status/run_id", serde_json::json!("other")),
            ("/pod_kill_status/pod/uid", serde_json::json!("other")),
            ("/pod_kill_status/namespace", serde_json::json!("other")),
            (
                "/chaos_status/metadata/namespace",
                serde_json::json!("other"),
            ),
            (
                "/chaos_status/spec/selector/pods",
                serde_json::json!({"test": ["rustfs-0"]}),
            ),
            (
                "/chaos_status/status/experiment/containerRecords/0/id",
                serde_json::json!("test/rustfs-0"),
            ),
            (
                "/chaos_status/status/experiment/containerRecords/0/injectedCount",
                serde_json::json!(0),
            ),
        ] {
            let mut changed = snapshot();
            *changed.pointer_mut(pointer).expect("field") = replacement;
            assert!(validate(&changed).is_err(), "{pointer}");
        }
    }

    #[test]
    fn backend_waits_for_load_and_cancels_without_late_injection() {
        run_backend_regression("success");
    }

    #[test]
    fn backend_retries_transient_pod_and_controller_queries() {
        for mode in ["pod-retry", "status-retry"] {
            run_backend_regression(mode);
        }
    }

    #[test]
    fn backend_bounds_failed_observations_and_retains_the_last_error() {
        for mode in ["pod-timeout", "status-timeout"] {
            run_backend_regression(mode);
        }
    }

    #[test]
    fn backend_cancels_observation_retries_and_cleans_up() {
        for mode in ["pod-cancel", "status-cancel"] {
            run_backend_regression(mode);
        }
    }

    fn run_backend_regression(mode: &str) {
        use crate::framework::{command::CommandSpec, config::E2eConfig};
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "S3CHAOS_POD_TEST_DIR";
        if let Some(directory) = std::env::var_os(CHILD) {
            if std::env::var("S3CHAOS_POD_TEST_MODE").expect("mode") != mode {
                return;
            }
            let directory = std::path::PathBuf::from(directory);
            let mut config = E2eConfig::defaults().cluster;
            config.test_namespace = "test".into();
            config.timeout = if mode.ends_with("timeout") {
                Duration::from_secs(1)
            } else {
                Duration::from_secs(3)
            };
            let mut spec =
                PodChaosSpec::kill_one_rustfs_pod(&config, "chaos-mesh", "run", "pod-kill-one");
            spec.name = "kill".into();
            spec.pod_name = Some("rustfs-1".into());
            // A cancelled armed handle must never reach kubectl.
            let cancelled = arm(&config, spec.clone(), vec![evidence().pod]).expect("arm");
            cancelled.wait_active(config.timeout).expect("armed");
            assert!(
                cancelled
                    .snapshot("armed")
                    .expect("snapshot")
                    .pod_kill_status
                    .is_none()
            );
            drop(cancelled);
            assert!(!directory.join("calls").exists());
            let mut active = arm(&config, spec, vec![evidence().pod]).expect("arm");
            std::thread::sleep(Duration::from_millis(50));
            assert!(!directory.join("calls").exists());
            let started = Instant::now();
            active
                .load_gate()
                .expect("gate")
                .store(now_ms(), Ordering::SeqCst);
            let deadline = Instant::now() + Duration::from_secs(4);
            let probe = mode.split('-').next().expect("probe kind");
            let attempts = || {
                std::fs::read_to_string(directory.join(format!("{probe}-attempts")))
                    .ok()
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0)
            };
            if mode.ends_with("cancel") {
                while attempts() < 2 {
                    active
                        .wait_active(config.timeout)
                        .expect("retry remains healthy");
                    assert!(Instant::now() < deadline, "backend did not retry");
                    std::thread::sleep(Duration::from_millis(20));
                }
                let cancelled_at = Instant::now();
                drop(active);
                assert!(cancelled_at.elapsed() < Duration::from_secs(1));
                assert!(directory.join("deleted").exists());
                let calls = std::fs::read_to_string(directory.join("calls")).expect("calls");
                assert_eq!(
                    calls
                        .lines()
                        .filter(|line| line.contains(" apply "))
                        .count(),
                    1
                );
                std::thread::sleep(Duration::from_millis(100));
                assert_eq!(
                    calls,
                    std::fs::read_to_string(directory.join("calls")).expect("calls")
                );
                return;
            }
            if mode.ends_with("timeout") {
                let error = loop {
                    if let Err(error) = active.wait_active(config.timeout) {
                        break error.to_string();
                    }
                    assert!(Instant::now() < deadline, "activation exceeded its budget");
                    std::thread::sleep(Duration::from_millis(20));
                };
                assert!(started.elapsed() >= config.timeout);
                assert!(attempts() >= 2, "failed query was not retried");
                assert!(
                    error.contains("activation was not confirmed within"),
                    "{error}"
                );
                assert!(error.contains("last observation: observe Pod"), "{error}");
                // The final probe may exhaust the remaining command budget
                // before the fake API can return its error.
                if error.contains("command timed out after") {
                    assert!(error.contains(": kubectl "), "{error}");
                } else {
                    assert!(error.contains(&format!("{probe} unavailable")), "{error}");
                }
                assert!(active.ensure_active("load").is_err());
                drop(active);
                assert!(directory.join("deleted").exists());
                return;
            }
            while active.ensure_active("load").is_err() {
                assert!(Instant::now() < deadline, "backend never activated");
                std::thread::sleep(Duration::from_millis(20));
            }
            let result = active.snapshot("after-workload").expect("snapshot");
            assert!(result.pod_kill_status.is_some());
            if mode.ends_with("retry") {
                assert!(attempts() >= 3, "transient query failures were not retried");
            }
            let manifest: serde_json::Value = serde_yaml_ng::from_str(
                &std::fs::read_to_string(directory.join("applied")).expect("manifest"),
            )
            .expect("yaml");
            assert_eq!(
                manifest["spec"]["selector"]["pods"],
                serde_json::json!({"test": ["rustfs-1"]})
            );
            active.delete(config.timeout).expect("cleanup");
            assert!(directory.join("deleted").exists());
            return;
        }
        let temporary = tempfile::tempdir().expect("temporary directory");
        std::fs::write(
            temporary.path().join("resource.json"),
            snapshot()["chaos_status"].to_string(),
        )
        .expect("resource");
        let kubectl = temporary.path().join("kubectl");
        std::fs::write(
            &kubectl,
            r#"#!/bin/sh
set -eu
cd "$S3CHAOS_POD_TEST_DIR"
printf '%s\n' "$*" >> calls
probe() {
  count=0
  if [ -f "$1-attempts" ]; then count=$(cat "$1-attempts"); fi
  count=$((count + 1))
  printf '%s\n' "$count" > "$1-attempts.tmp"
  mv "$1-attempts.tmp" "$1-attempts"
  case "$S3CHAOS_POD_TEST_MODE:$1" in
    pod-retry:pod|status-retry:status)
      if [ "$count" -gt 2 ]; then return; fi ;;
    pod-timeout:pod|status-timeout:status|pod-cancel:pod|status-cancel:status) ;;
    *) return ;;
  esac
  printf '%s unavailable\n' "$1" >&2
  exit 1
}
case " $* " in
  *" get pod "*)
    uid=old
    if [ -f applied ]; then probe pod; uid=new; fi
    printf '{"items":[{"metadata":{"name":"rustfs-1","uid":"%s"}}]}\n' "$uid" ;;
  *" apply "*) cat > applied ;;
  *" get podchaos "*) probe status; cat resource.json ;;
  *" delete podchaos "*) touch deleted ;;
  *" wait "*) exit 0 ;;
  *) exit 11 ;;
esac
"#,
        )
        .expect("fake kubectl");
        std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        let test_name = std::thread::current()
            .name()
            .expect("test name")
            .to_string();
        CommandSpec::new("env")
            .args([
                format!(
                    "PATH={}:{}",
                    temporary.path().display(),
                    std::env::var("PATH").expect("PATH")
                ),
                format!("{CHILD}={}", temporary.path().display()),
                format!("S3CHAOS_POD_TEST_MODE={mode}"),
                std::env::current_exe()
                    .expect("test binary")
                    .to_string_lossy()
                    .into_owned(),
                "--exact".into(),
                test_name,
                "--nocapture".into(),
            ])
            .timeout(Duration::from_secs(10))
            .run_checked()
            .expect("isolated backend test");
    }

    #[test]
    fn continuous_requests_cover_the_entire_uncertain_deletion_interval() {
        evidence()
            .validate(&[request(9, 21), request(20, 31)])
            .expect("covered");
        evidence()
            .validate(&[request(9, 31)])
            .expect("one in-flight request");
    }

    #[test]
    fn rejects_kills_before_after_or_between_requests() {
        for history in [
            vec![],
            vec![request(1, 9)],
            vec![request(31, 40)],
            vec![request(9, 20), request(20, 31)],
            vec![request(9, 30)],
        ] {
            assert!(evidence().validate(&history).is_err());
        }
    }

    #[test]
    fn foreign_prefault_and_unchanged_pod_evidence_cannot_pass() {
        let mut record = request(1, 40);
        record.run_id = Some("other".into());
        assert!(evidence().validate(&[record.clone()]).is_err());
        record.run_id = Some("run".into());
        record.durability_cohort = Some(DurabilityCohort::PreFault);
        assert!(evidence().validate(&[record]).is_err());
        let mut proof = evidence();
        proof.pods_after_deletion.push(proof.pod.clone());
        assert!(proof.validate(&[request(1, 40)]).is_err());
    }
}
