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
    StressChaosSpec,
};

const IOCHAOS_CRD: &str = "iochaos.chaos-mesh.org";
const PODCHAOS_CRD: &str = "podchaos.chaos-mesh.org";
const NETWORKCHAOS_CRD: &str = "networkchaos.chaos-mesh.org";
const STRESSCHAOS_CRD: &str = "stresschaos.chaos-mesh.org";

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

pub fn require_stresschaos_crd(config: &ClusterTestConfig) -> Result<()> {
    require_crd(config, STRESSCHAOS_CRD, "Chaos Mesh StressChaos")
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
    let selector = format!("{RUN_ID_LABEL}={run_id}");
    for kind in ["iochaos", "podchaos", "networkchaos", "stresschaos"] {
        Kubectl::new(config)
            .namespaced(namespace)
            .command(["delete", kind, "-l", &selector, "--ignore-not-found"])
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
    let selector = format!("{RUN_ID_LABEL}={run_id}");
    Kubectl::new(config)
        .namespaced(namespace)
        .command(["delete", kind, "-l", &selector, "--ignore-not-found"])
        .run_checked()?;
    Ok(())
}

pub fn cleanup_managed_chaos(config: &ClusterTestConfig, namespace: &str) -> Result<()> {
    for kind in ["iochaos", "podchaos", "networkchaos", "stresschaos"] {
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
    let selector = format!("{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}");
    Kubectl::new(config)
        .namespaced(namespace)
        .command(["delete", kind, "-l", &selector, "--ignore-not-found"])
        .run_checked()?;
    Ok(())
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
    Kubectl::new(config)
        .namespaced(namespace)
        .apply_yaml_command(manifest)
        .run_checked()?;

    Ok(ChaosGuard {
        config: config.clone(),
        kind,
        namespace: namespace.to_string(),
        name: name.to_string(),
        deleted: false,
    })
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
            let status_snapshot = match self.json() {
                Ok(status) => {
                    if chaos_experiment_is_active(&status)? {
                        return Ok(());
                    }
                    status
                }
                Err(error) => {
                    format!("failed to read {kind} status: {error}", kind = self.kind)
                }
            };

            if Instant::now() >= deadline {
                let describe = self.describe().unwrap_or_else(|error| {
                    format!(
                        "failed to describe {kind}/{name}: {error}",
                        kind = self.kind,
                        name = self.name
                    )
                });
                bail!(
                    "timed out waiting for {kind}/{name} to become active after {timeout:?}\nlast status:\n{status_snapshot}\n\ndescribe:\n{describe}",
                    kind = self.kind,
                    name = self.name,
                );
            }

            sleep(Duration::from_secs(1));
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
        self.delete_inner()?;
        self.wait_deleted(timeout)?;
        self.deleted = true;
        Ok(())
    }

    pub fn replace_finalizers_and_wait_deleted(
        &mut self,
        finalizers: &[String],
        timeout: Duration,
    ) -> Result<()> {
        let patch = serde_json::json!({
            "metadata": {
                "finalizers": finalizers,
            },
        })
        .to_string();
        Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command(["patch", self.kind, &self.name, "--type=merge", "-p", &patch])
            .run_checked()?;
        self.wait_deleted(timeout)?;
        self.deleted = true;
        Ok(())
    }

    pub fn json(&self) -> Result<String> {
        let output = Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command(["get", self.kind, &self.name, "-o", "json"])
            .run_checked()?;
        Ok(output.stdout)
    }

    fn delete_inner(&self) -> Result<()> {
        Kubectl::new(&self.config)
            .namespaced(&self.namespace)
            .command([
                "delete",
                self.kind,
                &self.name,
                "--ignore-not-found",
                "--wait=false",
            ])
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
            .run_checked();
        let error = match result {
            Ok(_) => return Ok(()),
            Err(error) => error,
        };

        let status = self.yaml().unwrap_or_else(|error| {
            format!(
                "failed to read {kind}/{name} yaml after delete timeout: {error}",
                kind = self.kind,
                name = self.name
            )
        });
        let describe = self.describe().unwrap_or_else(|error| {
            format!(
                "failed to describe {kind}/{name} after delete timeout: {error}",
                kind = self.kind,
                name = self.name
            )
        });
        bail!(
            "timed out waiting for {kind}/{name} deletion after {timeout:?}: {error}\nlast status:\n{status}\n\ndescribe:\n{describe}",
            kind = self.kind,
            name = self.name,
        )
    }
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
        if !self.deleted {
            let _ = self.delete_inner();
        }
    }
}
