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
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::framework::{config::ClusterTestConfig, kubectl::Kubectl};

use super::{
    IoChaosSpec, MANAGED_BY_LABEL, MANAGED_BY_VALUE, NetworkChaosSpec, PodChaosSpec, RUN_ID_LABEL,
    ScheduleSpec, StressChaosSpec, TimeChaosSpec,
};

const IOCHAOS_CRD: &str = "iochaos.chaos-mesh.org";
const PODCHAOS_CRD: &str = "podchaos.chaos-mesh.org";
const NETWORKCHAOS_CRD: &str = "networkchaos.chaos-mesh.org";
const TIMECHAOS_CRD: &str = "timechaos.chaos-mesh.org";
const STRESSCHAOS_CRD: &str = "stresschaos.chaos-mesh.org";
const SCHEDULE_CRD: &str = "schedules.chaos-mesh.org";

#[derive(Debug, Clone)]
pub struct ChaosGuard {
    config: ClusterTestConfig,
    kind: &'static str,
    namespace: String,
    name: String,
    deleted: bool,
}

pub fn require_iochaos_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, IOCHAOS_CRD, "Chaos Mesh IOChaos")
}

pub fn require_podchaos_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, PODCHAOS_CRD, "Chaos Mesh PodChaos")
}

pub fn require_networkchaos_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, NETWORKCHAOS_CRD, "Chaos Mesh NetworkChaos")
}

pub fn require_timechaos_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, TIMECHAOS_CRD, "Chaos Mesh TimeChaos")
}

pub fn require_stresschaos_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, STRESSCHAOS_CRD, "Chaos Mesh StressChaos")
}

pub fn require_schedule_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, SCHEDULE_CRD, "Chaos Mesh Schedule")
}

fn require_crd(config: &ClusterTestConfig, crd: &str, description: &str) -> Result<()> {
    let output = Kubectl::new(config).command(["get", "crd", crd]).run()?;
    ensure!(
        output.code == Some(0),
        "{description} CRD {crd} is required for fault tests; install Chaos Mesh before running faults\nstdout:\n{}\nstderr:\n{}",
        output.stdout,
        output.stderr
    );
    Ok(())
}

pub fn cleanup_run(config: &ClusterTestConfig, namespace: &str, run_id: &str) -> Result<()> {
    if std::env::var_os("S3CHAOS_RUN_ROOT").is_some() {
        for kind in [
            "schedule",
            "iochaos",
            "podchaos",
            "networkchaos",
            "timechaos",
            "stresschaos",
        ] {
            workflow_cleanup(kind, "*", config.timeout)?;
        }
        return Ok(());
    }
    let selector = format!("{RUN_ID_LABEL}={run_id}");
    let timeout = delete_timeout_arg(config);
    for kind in [
        "schedule",
        "iochaos",
        "podchaos",
        "networkchaos",
        "timechaos",
        "stresschaos",
    ] {
        if kind == "timechaos" && !timechaos_is_served(config)? {
            continue;
        }
        Kubectl::new(config)
            .namespaced(namespace)
            .command([
                "delete",
                kind,
                "-l",
                &selector,
                "--ignore-not-found",
                &timeout,
            ])
            .run_checked()?;
    }
    Ok(())
}

pub fn cleanup_run_kind(
    config: &ClusterTestConfig,
    namespace: &str,
    run_id: &str,
    kind: &str,
) -> Result<()> {
    if workflow_cleanup(kind, "*", config.timeout)? {
        return Ok(());
    }
    if kind == "timechaos" && !timechaos_is_served(config)? {
        return Ok(());
    }
    let selector = format!("{RUN_ID_LABEL}={run_id}");
    Kubectl::new(config)
        .namespaced(namespace)
        .command([
            "delete",
            kind,
            "-l",
            &selector,
            "--ignore-not-found",
            &delete_timeout_arg(config),
        ])
        .run_checked()?;
    Ok(())
}

pub fn cleanup_managed_chaos(config: &ClusterTestConfig, namespace: &str) -> Result<()> {
    for kind in [
        "schedule",
        "iochaos",
        "podchaos",
        "networkchaos",
        "timechaos",
        "stresschaos",
    ] {
        cleanup_managed_kind(config, namespace, kind)?;
    }
    Ok(())
}

pub fn cleanup_managed_iochaos(config: &ClusterTestConfig, namespace: &str) -> Result<()> {
    cleanup_managed_kind(config, namespace, "iochaos")
}

pub fn cleanup_managed_podchaos(config: &ClusterTestConfig, namespace: &str) -> Result<()> {
    cleanup_managed_kind(config, namespace, "podchaos")
}

pub fn cleanup_managed_networkchaos(config: &ClusterTestConfig, namespace: &str) -> Result<()> {
    cleanup_managed_kind(config, namespace, "networkchaos")
}

pub fn cleanup_managed_stresschaos(config: &ClusterTestConfig, namespace: &str) -> Result<()> {
    cleanup_managed_kind(config, namespace, "stresschaos")
}

fn cleanup_managed_kind(config: &ClusterTestConfig, namespace: &str, kind: &str) -> Result<()> {
    if workflow_cleanup(kind, "*", config.timeout)? {
        return Ok(());
    }
    if kind == "timechaos" && !timechaos_is_served(config)? {
        return Ok(());
    }
    let selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");
    Kubectl::new(config)
        .namespaced(namespace)
        .command([
            "delete",
            kind,
            "-l",
            &selector,
            "--ignore-not-found",
            &delete_timeout_arg(config),
        ])
        .run_checked()?;
    Ok(())
}

fn timechaos_is_served(config: &ClusterTestConfig) -> Result<bool> {
    let output = Kubectl::new(config)
        .command(["get", "--raw", "/apis/chaos-mesh.org/v1alpha1"])
        .run_checked()?;
    let discovery =
        serde_json::from_str::<Value>(&output.stdout).context("parse Chaos Mesh API discovery")?;
    discovery_serves_timechaos(&discovery)
}

fn discovery_serves_timechaos(discovery: &Value) -> Result<bool> {
    ensure!(
        discovery.get("kind").and_then(Value::as_str) == Some("APIResourceList")
            && discovery.get("groupVersion").and_then(Value::as_str)
                == Some("chaos-mesh.org/v1alpha1"),
        "Chaos Mesh API discovery did not return its APIResourceList"
    );
    let resources = discovery
        .get("resources")
        .and_then(Value::as_array)
        .context("Chaos Mesh API discovery has no resources array")?;
    let mut served = false;
    for resource in resources {
        let name = resource
            .get("name")
            .and_then(Value::as_str)
            .filter(|name| !name.is_empty())
            .context("Chaos Mesh API discovery contains an invalid resource name")?;
        served |= name == "timechaos";
    }
    Ok(served)
}

/// Bounds every label-selector cleanup delete so a chaos CR stuck on a
/// finalizer surfaces a classified timeout instead of hanging the run (and any
/// suite driving it) forever — `kubectl delete` waits indefinitely by default.
fn delete_timeout_arg(config: &ClusterTestConfig) -> String {
    format!("--timeout={}s", config.timeout.as_secs().max(1))
}

fn workflow_cleanup(kind: &str, name: &str, timeout: Duration) -> Result<bool> {
    let Some(root) = std::env::var_os("S3CHAOS_RUN_ROOT") else {
        return Ok(false);
    };
    let binary = std::env::var_os("S3CHAOS_BINARY")
        .map(std::path::PathBuf::from)
        .map_or_else(std::env::current_exe, Ok)?;
    crate::framework::command::CommandSpec::new(
        binary.to_str().context("binary path is not UTF-8")?,
    )
    .args([
        "fault-workflow-chaos-delete",
        root.to_str().context("run root is not UTF-8")?,
        kind,
        name,
    ])
    .timeout(timeout)
    .run_checked()?;
    Ok(true)
}

pub fn apply_iochaos(config: &ClusterTestConfig, spec: &IoChaosSpec) -> Result<ChaosGuard> {
    apply_manifest(
        config,
        &spec.namespace,
        spec.manifest(),
        "iochaos",
        &spec.name,
    )
}

pub fn apply_podchaos(config: &ClusterTestConfig, spec: &PodChaosSpec) -> Result<ChaosGuard> {
    apply_manifest(
        config,
        &spec.namespace,
        spec.manifest(),
        "podchaos",
        &spec.name,
    )
}

pub fn apply_networkchaos(
    config: &ClusterTestConfig,
    spec: &NetworkChaosSpec,
) -> Result<ChaosGuard> {
    apply_manifest(
        config,
        &spec.namespace,
        spec.manifest(),
        "networkchaos",
        &spec.name,
    )
}

pub fn apply_timechaos(config: &ClusterTestConfig, spec: &TimeChaosSpec) -> Result<ChaosGuard> {
    apply_manifest(
        config,
        &spec.namespace,
        spec.manifest(),
        "timechaos",
        &spec.name,
    )
}

pub fn apply_schedule(config: &ClusterTestConfig, spec: &ScheduleSpec) -> Result<ChaosGuard> {
    apply_manifest(
        config,
        &spec.namespace,
        spec.manifest(),
        "schedule",
        &spec.name,
    )
}

pub fn apply_stresschaos(config: &ClusterTestConfig, spec: &StressChaosSpec) -> Result<ChaosGuard> {
    apply_manifest(
        config,
        &spec.namespace,
        spec.manifest(),
        "stresschaos",
        &spec.name,
    )
}

fn apply_manifest(
    config: &ClusterTestConfig,
    namespace: &str,
    manifest: String,
    kind: &'static str,
    name: &str,
) -> Result<ChaosGuard> {
    // An apply timeout can follow server-side creation. Own cleanup before
    // sending the request so an ambiguous response cannot leak this resource.
    let guard = ChaosGuard {
        config: config.clone(),
        kind,
        namespace: namespace.to_string(),
        name: name.to_string(),
        deleted: false,
    };
    crate::fault::workflow::apply_fixture_resource(config, manifest)?;

    Ok(guard)
}

impl ChaosGuard {
    pub fn kind(&self) -> &'static str {
        self.kind
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    pub fn is_kind(&self, kind: &str) -> bool {
        self.kind == kind
    }

    pub fn wait_active(&self, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;

        loop {
            let status_snapshot =
                match self.json_with_timeout(deadline.saturating_duration_since(Instant::now())) {
                    Ok(status) => {
                        if Instant::now() < deadline && chaos_experiment_is_active(&status)? {
                            return Ok(());
                        }
                        status
                    }
                    Err(error) => {
                        format!("failed to read {kind} status: {error}", kind = self.kind)
                    }
                };

            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for {kind}/{name} to become active after {timeout:?}\nlast status:\n{status_snapshot}",
                    kind = self.kind,
                    name = self.name,
                );
            }

            sleep(Duration::from_secs(1).min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    pub fn ensure_active(&self, stage: &str) -> Result<()> {
        let status = self.json()?;
        ensure!(
            chaos_experiment_is_active(&status)?,
            "{kind}/{name} is not active at {stage}; status:\n{status}",
            kind = self.kind,
            name = self.name
        );
        Ok(())
    }

    pub fn describe(&self) -> Result<String> {
        let output = Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command(["describe", self.kind, &self.name])
            .run_checked()?;
        Ok(output.stdout)
    }

    pub fn yaml(&self) -> Result<String> {
        let output = Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command(["get", self.kind, &self.name, "-o", "yaml"])
            .run_checked()?;
        Ok(output.stdout)
    }

    pub fn delete(&mut self, timeout: Duration) -> Result<()> {
        let started = Instant::now();
        self.delete_inner_with_timeout(timeout)?;
        self.wait_deleted(timeout.saturating_sub(started.elapsed()))?;
        self.deleted = true;
        Ok(())
    }

    pub fn replace_finalizers_and_wait_deleted(
        &mut self,
        finalizers: &[String],
        timeout: Duration,
    ) -> Result<()> {
        let current: Value = serde_json::from_str(&self.json()?)?;
        crate::fault::workflow::validate_chaos_snapshot(self.kind, &self.name, &current)?;
        let uid = current["metadata"]["uid"]
            .as_str()
            .context("Chaos resource UID is missing")?;
        let version = current["metadata"]["resourceVersion"]
            .as_str()
            .context("Chaos resource version is missing")?;
        let patch = serde_json::json!([
            {"op":"test","path":"/metadata/uid","value":uid},
            {"op":"test","path":"/metadata/resourceVersion","value":version},
            {"op":"add","path":"/metadata/finalizers","value":finalizers},
        ])
        .to_string();
        Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command(["patch", self.kind, &self.name, "--type=json", "-p", &patch])
            .run_checked()?;
        self.wait_deleted(timeout)?;
        self.deleted = true;
        Ok(())
    }

    pub fn json(&self) -> Result<String> {
        self.json_with_timeout(self.config.timeout)
    }

    pub(crate) fn json_with_timeout(&self, timeout: Duration) -> Result<String> {
        let output = Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command(["get", self.kind, &self.name, "-o", "json"])
            .timeout(timeout.min(self.config.timeout))
            .run_checked()?;
        Ok(output.stdout)
    }

    fn delete_inner(&self) -> Result<()> {
        self.delete_inner_with_timeout(self.config.timeout)
    }

    fn delete_inner_with_timeout(&self, timeout: Duration) -> Result<()> {
        if workflow_cleanup(self.kind, &self.name, timeout)? {
            return Ok(());
        }
        Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command([
                "delete",
                self.kind,
                &self.name,
                "--ignore-not-found",
                "--wait=false",
            ])
            .timeout(timeout)
            .run_checked()?;
        Ok(())
    }

    fn wait_deleted(&self, timeout: Duration) -> Result<()> {
        let resource = format!("{}/{}", self.kind, self.name);
        let timeout_arg = format!("--timeout={}s", timeout.as_secs().max(1));
        let result = Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command([
                "wait",
                "--for=delete",
                resource.as_str(),
                timeout_arg.as_str(),
            ])
            .timeout(timeout)
            .run_checked();
        let error = match result {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };

        bail!(
            "failed waiting for {kind}/{name} deletion within {timeout:?}: {error}",
            kind = self.kind,
            name = self.name,
        )
    }
}

/// A Schedule stays armed after its first tick. It has no AllInjected
/// condition, so the experiment helper cannot describe it. Activation is
/// "the schedule has fired at least once and has not been deleted".
///
/// Chaos Mesh JSON-encodes `ScheduleStatus.LastScheduleTime` as
/// `status.time`, not `status.lastScheduleTime`.
pub fn chaos_schedule_is_armed(raw: &str) -> Result<bool> {
    let value = serde_json::from_str::<Value>(raw).context("parse Chaos Mesh Schedule json")?;
    let deleting = value.pointer("/metadata/deletionTimestamp").is_some();
    let scheduled = value
        .pointer("/status/time")
        .and_then(Value::as_str)
        .is_some_and(|timestamp| !timestamp.is_empty());
    Ok(!deleting && scheduled)
}

pub(super) fn chaos_experiment_is_active(raw: &str) -> Result<bool> {
    let value = serde_json::from_str::<Value>(raw).context("parse Chaos Mesh status json")?;
    let selected = condition_status(&value, "Selected").is_some_and(|status| status == "True");
    let injected = condition_status(&value, "AllInjected")
        .or_else(|| condition_status(&value, "Injected"))
        .is_some_and(|status| status == "True");
    let recovered = condition_status(&value, "AllRecovered").is_some_and(|status| status == "True");

    Ok(selected && injected && !recovered)
}

fn condition_status(value: &Value, condition_type: &str) -> Option<String> {
    value
        .pointer("/status/conditions")?
        .as_array()?
        .iter()
        .find(|condition| condition.get("type").and_then(Value::as_str) == Some(condition_type))?
        .get("status")?
        .as_str()
        .map(str::to_string)
}

impl Drop for ChaosGuard {
    fn drop(&mut self) {
        if !self.deleted
            && let Err(error) = self.delete_inner()
        {
            // A discarded failure here leaks an active chaos CR into later runs;
            // surface it so the leak is at least visible to operators.
            eprintln!(
                "warning: failed to delete leaked {kind}/{name} during guard cleanup: {error}",
                kind = self.kind,
                name = self.name,
            );
        }
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;

    #[test]
    fn apply_timeout_cleans_up_a_resource_created_before_the_response() {
        use crate::framework::{command::CommandSpec, config::E2eConfig};
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "S3CHAOS_APPLY_TIMEOUT_TEST_DIR";
        if let Some(directory) = std::env::var_os(CHILD) {
            let directory = std::path::PathBuf::from(directory);
            let mut config = E2eConfig::defaults().cluster;
            config.timeout = Duration::from_millis(200);
            let spec =
                PodChaosSpec::kill_one_rustfs_pod(&config, "chaos-mesh", "run", "pod-kill-one");
            let start = Instant::now();
            let error = apply_podchaos(&config, &spec).expect_err("ambiguous apply response");
            assert!(error.to_string().contains("timed out"), "{error:#}");
            assert!(start.elapsed() < Duration::from_secs(3));
            assert!(directory.join("created").exists());
            let deleted =
                std::fs::read_to_string(directory.join("deleted")).expect("cleanup request");
            assert!(deleted.contains(&format!(
                "-n chaos-mesh delete podchaos {} --ignore-not-found --wait=false",
                spec.name
            )));
            return;
        }
        let temporary = tempfile::tempdir().expect("temporary directory");
        let kubectl = temporary.path().join("kubectl");
        std::fs::write(
            &kubectl,
            r#"#!/bin/sh
set -eu
case " $* " in
  *" apply "*)
    /bin/cat > "$S3CHAOS_APPLY_TIMEOUT_TEST_DIR/created"
    exec /bin/sleep 30 ;;
  *" delete "*) printf '%s\n' "$*" > "$S3CHAOS_APPLY_TIMEOUT_TEST_DIR/deleted" ;;
  *) exit 11 ;;
esac
"#,
        )
        .expect("fake kubectl");
        std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        CommandSpec::new("env").args([
            format!("PATH={}", temporary.path().display()),
            format!("{CHILD}={}", temporary.path().display()),
            std::env::current_exe().expect("test binary").to_string_lossy().into_owned(),
            "--exact".into(),
            "fault::backends::chaos_mesh::runtime::discovery_tests::apply_timeout_cleans_up_a_resource_created_before_the_response".into(),
            "--nocapture".into(),
        ]).timeout(Duration::from_secs(5)).run_checked().expect("isolated apply timeout test");
    }

    #[test]
    fn stalled_kubectl_cannot_extend_activation_or_deletion_deadlines() {
        use crate::framework::{command::CommandSpec, config::E2eConfig};
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "S3CHAOS_TIMEOUT_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let mut guard = ChaosGuard {
                config: E2eConfig::defaults().cluster,
                kind: "podchaos",
                namespace: "test".into(),
                name: "stalled".into(),
                deleted: true,
            };
            for operation in ["activate", "delete", "wait-delete"] {
                let start = Instant::now();
                let budget = Duration::from_millis(100);
                let result = match operation {
                    "activate" => guard.wait_active(budget),
                    "delete" => guard.delete(budget),
                    _ => guard.wait_deleted(budget),
                };
                let error = result.expect_err(operation);
                assert!(
                    error.to_string().contains("timed out"),
                    "{operation}: {error:#}"
                );
                assert!(start.elapsed() < Duration::from_secs(2), "{operation}");
            }
            return;
        }
        // PATH is changed only in a child test process, never in parallel tests.
        let temporary = tempfile::tempdir().expect("temporary directory");
        let kubectl = temporary.path().join("kubectl");
        std::fs::write(&kubectl, "#!/bin/sh\nexec /bin/sleep 30\n").expect("fake kubectl");
        std::fs::set_permissions(&kubectl, std::fs::Permissions::from_mode(0o755))
            .expect("executable");
        CommandSpec::new("env").args([
            format!("PATH={}", temporary.path().display()), format!("{CHILD}=1"),
            std::env::current_exe().expect("test binary").to_string_lossy().into_owned(),
            "--exact".into(),
            "fault::backends::chaos_mesh::runtime::discovery_tests::stalled_kubectl_cannot_extend_activation_or_deletion_deadlines".into(),
            "--nocapture".into(),
        ]).timeout(Duration::from_secs(5)).run_checked().expect("bounded child test");
    }

    #[test]
    fn timechaos_cleanup_skips_only_a_confirmed_unserved_resource() {
        let mut discovery = serde_json::json!({
            "kind": "APIResourceList", "groupVersion": "chaos-mesh.org/v1alpha1",
            "resources": [{"name": "iochaos"}, {"name": "networkchaos"}]
        });
        assert!(!discovery_serves_timechaos(&discovery).expect("confirmed absent"));
        discovery["resources"]
            .as_array_mut()
            .expect("resources")
            .push(serde_json::json!({"name": "timechaos/status"}));
        assert!(!discovery_serves_timechaos(&discovery).expect("subresource only"));
        discovery["resources"]
            .as_array_mut()
            .expect("resources")
            .push(serde_json::json!({"name": "timechaos"}));
        assert!(discovery_serves_timechaos(&discovery).expect("served"));

        for invalid in [
            serde_json::json!({"kind": "Status", "reason": "Forbidden"}),
            serde_json::json!({"kind": "APIResourceList", "groupVersion": "other/v1", "resources": []}),
            serde_json::json!({"kind": "APIResourceList", "groupVersion": "chaos-mesh.org/v1alpha1"}),
            serde_json::json!({"kind": "APIResourceList", "groupVersion": "chaos-mesh.org/v1alpha1", "resources": [{"kind": "TimeChaos"}]}),
        ] {
            assert!(discovery_serves_timechaos(&invalid).is_err());
        }
    }
}
