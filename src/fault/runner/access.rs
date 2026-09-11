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

use crate::{
    fault::{
        config::FaultTestConfig, fixture, scenarios::FaultIsolation, workload::wait_for_s3_endpoint,
    },
    framework::{
        config::ClusterTestConfig,
        kube_client,
        kubectl::Kubectl,
        port_forward::{PortForwardGuard, PortForwardSpec},
        wait,
    },
};
use anyhow::{Context, Result, bail, ensure};
use kube::core::DynamicObject;
use std::time::{Duration, Instant};
use tokio::time::sleep as async_sleep;

pub(super) fn prepare_fault_fixture(
    config: &ClusterTestConfig,
    isolation: FaultIsolation,
) -> Result<()> {
    match isolation {
        FaultIsolation::ReusableTenant => fixture::apply_tenant_resources(config)?,
        FaultIsolation::FreshTenant | FaultIsolation::DedicatedLinuxBlockDevice => {
            fixture::reset_tenant_resources(config)?;
            fixture::apply_tenant_resources(config)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodRuntimeState {
    name: String,
    uid: String,
    phase: String,
    containers_ready: bool,
    restart_count: u64,
    terminating: bool,
}

fn rustfs_pod_runtime_states(config: &ClusterTestConfig) -> Result<Vec<PodRuntimeState>> {
    let selector = format!("rustfs.tenant={}", config.tenant_name);
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command(["get", "pod", "-l", &selector, "-o", "json"])
        .run_checked()?;
    let value = serde_json::from_str::<serde_json::Value>(&output.stdout)
        .context("parse RustFS pod list json")?;
    let items = value
        .pointer("/items")
        .and_then(serde_json::Value::as_array)
        .context("RustFS pod list did not contain an items array")?;
    let mut pods = items
        .iter()
        .map(|item| {
            let metadata = item
                .get("metadata")
                .context("RustFS pod did not contain metadata")?;
            let name = metadata
                .get("name")
                .and_then(serde_json::Value::as_str)
                .context("RustFS pod metadata did not contain a name")?;
            let uid = metadata
                .get("uid")
                .and_then(serde_json::Value::as_str)
                .context("RustFS pod metadata did not contain a uid")?;
            let phase = item
                .pointer("/status/phase")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("Unknown");
            let container_statuses = item
                .pointer("/status/containerStatuses")
                .and_then(serde_json::Value::as_array);
            let containers_ready = container_statuses.is_some_and(|statuses| {
                !statuses.is_empty()
                    && statuses.iter().all(|status| {
                        status
                            .get("ready")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false)
                    })
            });
            let restart_count = container_statuses
                .into_iter()
                .flatten()
                .filter_map(|status| status.get("restartCount"))
                .filter_map(serde_json::Value::as_u64)
                .sum();

            Ok(PodRuntimeState {
                name: name.to_string(),
                uid: uid.to_string(),
                phase: phase.to_string(),
                containers_ready,
                restart_count,
                terminating: metadata.get("deletionTimestamp").is_some(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    pods.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(pods)
}

fn stable_pod_fingerprint(
    pods: &[PodRuntimeState],
    expected_pod_count: usize,
) -> Option<Vec<(String, u64)>> {
    if pods.len() != expected_pod_count
        || pods
            .iter()
            .any(|pod| pod.phase != "Running" || !pod.containers_ready || pod.terminating)
    {
        return None;
    }

    Some(
        pods.iter()
            .map(|pod| (pod.uid.clone(), pod.restart_count))
            .collect(),
    )
}

pub(super) async fn wait_for_stable_rustfs_pods(
    config: &ClusterTestConfig,
    expected_pod_count: usize,
    stable_window: Duration,
) -> Result<()> {
    let deadline = Instant::now() + config.timeout;
    let mut stable_since = None;
    let mut stable_fingerprint = None;
    let mut last_snapshot = Vec::new();
    let mut last_error = "not checked yet".to_string();

    eprintln!(
        "waiting for {expected_pod_count} RustFS pods to remain ready without restarts for {stable_window:?}"
    );
    loop {
        if Instant::now() >= deadline {
            bail!(
                "timed out waiting for stable RustFS pods after {:?}\nlast: {last_snapshot:?}\nlast error: {last_error}",
                config.timeout
            );
        }

        match rustfs_pod_runtime_states(config) {
            Ok(current) => {
                if let Some(fingerprint) = stable_pod_fingerprint(&current, expected_pod_count) {
                    if stable_fingerprint.as_ref() != Some(&fingerprint) {
                        stable_since = Some(Instant::now());
                        stable_fingerprint = Some(fingerprint);
                    }
                    if stable_since.is_some_and(|started| started.elapsed() >= stable_window) {
                        eprintln!("RustFS pods remained stable for {stable_window:?}");
                        return Ok(());
                    }
                } else {
                    stable_since = None;
                    stable_fingerprint = None;
                }
                last_snapshot = current;
                last_error = "none".to_string();
            }
            Err(error) => {
                stable_since = None;
                stable_fingerprint = None;
                last_error = error.to_string();
            }
        }

        async_sleep(Duration::from_secs(1)).await;
    }
}

pub(super) async fn wait_for_ready_tenant(config: &ClusterTestConfig) -> Result<DynamicObject> {
    let client = kube_client::default_client().await?;
    let tenants = kube_client::tenant_api(client, &config.test_namespace);
    wait::wait_for_tenant_ready(tenants, &config.tenant_name, config.timeout).await
}

pub(super) fn s3_access(config: &FaultTestConfig) -> Result<(String, Option<PortForwardGuard>)> {
    let cluster = &config.cluster;
    if config.use_cluster_ip {
        let service = format!("{}-io", cluster.tenant_name);
        let output = Kubectl::new(cluster)
            .namespaced(&cluster.test_namespace)
            .command([
                "get".to_string(),
                "service".to_string(),
                service.clone(),
                "-o".to_string(),
                "jsonpath={.spec.clusterIP}".to_string(),
            ])
            .run_checked()
            .with_context(|| format!("read ClusterIP for fault-test service {service:?}"))?;
        let cluster_ip = output.stdout.trim();
        ensure!(
            !cluster_ip.is_empty() && cluster_ip != "None",
            "fault-test service {service:?} does not have a ClusterIP"
        );
        let host = if cluster_ip.contains(':') {
            format!("[{cluster_ip}]")
        } else {
            cluster_ip.to_string()
        };
        return Ok((format!("http://{host}:9000"), None));
    }

    let spec = PortForwardSpec::tenant_io_on_available_port(
        &cluster.test_namespace,
        &cluster.tenant_name,
    )?;
    let endpoint = spec.local_base_url();
    let kubectl = Kubectl::new(cluster);
    Ok((endpoint, Some(spec.start_with_temp_log(&kubectl)?)))
}

pub(super) async fn ensure_s3_access(
    port_forward: &mut Option<PortForwardGuard>,
    config: &ClusterTestConfig,
    endpoint: &str,
) -> Result<()> {
    if let Some(guard) = port_forward {
        if guard.ensure_running().is_err() {
            let local_port = endpoint
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .context("parse local S3 port-forward endpoint")?;
            let spec = PortForwardSpec::tenant_io_with_local_port(
                &config.test_namespace,
                &config.tenant_name,
                local_port,
            );
            let kubectl = Kubectl::new(config);
            *guard = spec.start_with_temp_log(&kubectl)?;
        }
        return wait_for_tenant_s3(guard, endpoint, config.timeout).await;
    }

    wait_for_s3_endpoint(endpoint, config.timeout).await
}

pub(super) async fn wait_for_tenant_s3(
    port_forward: &mut PortForwardGuard,
    endpoint: &str,
    timeout: Duration,
) -> Result<()> {
    port_forward.ensure_running()?;
    wait_for_s3_endpoint(endpoint, timeout)
        .await
        .with_context(|| {
            format!(
                "S3 port-forward was not ready; command: {}; log {}:\n{}",
                port_forward.command_display(),
                port_forward.log_path().display(),
                port_forward.log_contents()
            )
        })
}

/// Prove a freshly spawned port-forward is established: its process is still
/// alive and the local port accepts a TCP connection. `kubectl port-forward`
/// only spawns; bind conflicts, kubeconfig and API server errors exit
/// asynchronously, so `alive` is polled before every connect attempt and its
/// error is returned verbatim. Neither outcome says anything about RustFS:
/// callers classify a failure here as harness, not product.
pub(super) async fn wait_for_local_forward(
    local_port: u16,
    bound: Duration,
    mut alive: impl FnMut() -> Result<()>,
) -> Result<()> {
    let started = std::time::Instant::now();
    loop {
        alive()?;
        let connect = tokio::time::timeout(
            Duration::from_secs(1),
            tokio::net::TcpStream::connect(("127.0.0.1", local_port)),
        )
        .await;
        if matches!(connect, Ok(Ok(_))) {
            return Ok(());
        }
        if started.elapsed() >= bound {
            bail!(
                "port-forward process is running but 127.0.0.1:{local_port} did not accept a TCP connection within {}s",
                bound.as_secs_f64()
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_forward_is_established_once_the_port_accepts_connections() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        wait_for_local_forward(port, Duration::from_secs(5), || Ok(()))
            .await
            .expect("a listening port is an established forward");
    }

    #[tokio::test]
    async fn dead_forward_process_is_reported_before_the_port_is_probed() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        let error = wait_for_local_forward(port, Duration::from_secs(5), || {
            bail!("port-forward exited early with exit status: 1; unable to listen on any of the requested ports")
        })
        .await
        .expect_err("an exited kubectl is a harness failure even when something listens");
        assert!(
            error.to_string().contains("port-forward exited early"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn unbound_port_times_out_as_a_harness_failure() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("listener");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let error = wait_for_local_forward(port, Duration::from_millis(300), || Ok(()))
            .await
            .expect_err("nothing listens on the released port");
        assert!(
            error
                .to_string()
                .contains("did not accept a TCP connection within"),
            "{error:#}"
        );
    }

    #[test]
    fn stable_pod_fingerprint_requires_four_ready_unchanged_pods() {
        let pods = (0..4)
            .map(|index| PodRuntimeState {
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
                phase: "Running".to_string(),
                containers_ready: true,
                restart_count: index,
                terminating: false,
            })
            .collect::<Vec<_>>();

        assert_eq!(
            stable_pod_fingerprint(&pods, 4),
            Some(vec![
                ("uid-0".to_string(), 0),
                ("uid-1".to_string(), 1),
                ("uid-2".to_string(), 2),
                ("uid-3".to_string(), 3),
            ])
        );
        assert!(stable_pod_fingerprint(&pods[..3], 4).is_none());

        let mut unready = pods;
        unready[0].containers_ready = false;
        assert!(stable_pod_fingerprint(&unready, 4).is_none());
    }
}
