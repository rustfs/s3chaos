// Copyright 2025 RustFS Team
// SPDX-License-Identifier: Apache-2.0

//! Bounded observations from the RustFS containers' own network namespaces.

use anyhow::{Context, Result, ensure};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    net::IpAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::fault::recovery_health::RUSTFS_CONTAINER_PORT;
use crate::framework::{config::ClusterTestConfig, kubectl::Kubectl};

pub(crate) const CONNECTIVITY_PROBE_TIMEOUT_MS: u64 = 5_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodNetworkIdentity {
    pub namespace: String,
    pub name: String,
    pub uid: String,
    pub container_id: String,
    pub node: String,
    pub pod_ip: String,
    pub listener_port: u16,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodConnectivityObservation {
    pub source: PodNetworkIdentity,
    pub target: PodNetworkIdentity,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub exit_code: Option<i32>,
    pub http_status: Option<u16>,
    pub connect_seconds: Option<f64>,
    pub remote_ip: Option<String>,
    pub stdout: String,
    pub stderr: String,
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

pub(crate) async fn capture_pod_network_identities(
    config: &ClusterTestConfig,
) -> Result<Vec<PodNetworkIdentity>> {
    let output = Kubectl::new(config)
        .namespaced(&config.test_namespace)
        .command([
            "get",
            "pods",
            "-l",
            &format!("rustfs.tenant={}", config.tenant_name),
            "-o",
            "json",
        ])
        .run_bounded(Duration::from_secs(10))
        .await?;
    ensure!(
        output.code == Some(0),
        "cannot read RustFS Pod network identities: {}",
        output.stderr
    );
    identities_from_pods(&serde_json::from_str(&output.stdout)?, config)
}

fn identities_from_pods(
    value: &Value,
    config: &ClusterTestConfig,
) -> Result<Vec<PodNetworkIdentity>> {
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .context("Pod list has no items")?;
    let mut pods = Vec::new();
    for item in items {
        ensure!(
            item.pointer("/metadata/namespace").and_then(Value::as_str)
                == Some(config.test_namespace.as_str())
                && item
                    .pointer("/metadata/labels/rustfs.tenant")
                    .and_then(Value::as_str)
                    == Some(config.tenant_name.as_str())
                && item
                    .pointer("/metadata/deletionTimestamp")
                    .is_none_or(Value::is_null)
                && item.pointer("/status/phase").and_then(Value::as_str) == Some("Running")
                && item.pointer("/spec/hostNetwork").and_then(Value::as_bool) != Some(true),
            "network observation requires running, tenant-owned Pods with isolated network namespaces"
        );
        let statuses = item
            .pointer("/status/containerStatuses")
            .and_then(Value::as_array)
            .context("Pod has no container status")?;
        let status = statuses
            .iter()
            .filter(|status| status.get("name").and_then(Value::as_str) == Some("rustfs"))
            .collect::<Vec<_>>();
        ensure!(
            status.len() == 1
                && status[0]
                    .pointer("/state/running")
                    .is_some_and(Value::is_object),
            "RustFS container must be running"
        );
        let containers = item
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .context("Pod has no containers")?;
        let container = containers
            .iter()
            .filter(|container| container.get("name").and_then(Value::as_str) == Some("rustfs"))
            .collect::<Vec<_>>();
        ensure!(
            container.len() == 1,
            "Pod must define exactly one RustFS container"
        );
        let ports = container[0]
            .get("ports")
            .and_then(Value::as_array)
            .context("RustFS listener port is not declared")?;
        let matching = ports
            .iter()
            .filter(|port| {
                port.get("containerPort").and_then(Value::as_u64)
                    == Some(u64::from(RUSTFS_CONTAINER_PORT))
                    && port
                        .get("protocol")
                        .and_then(Value::as_str)
                        .is_none_or(|protocol| protocol == "TCP")
            })
            .count();
        ensure!(
            matching == 1,
            "RustFS Pod does not declare the expected S3 TCP listener"
        );
        let field = |path: &str| {
            item.pointer(path)
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
                .map(str::to_string)
                .with_context(|| format!("Pod network identity is missing {path}"))
        };
        let pod_ip = field("/status/podIP")?;
        pod_ip.parse::<IpAddr>().context("PodIP is invalid")?;
        pods.push(PodNetworkIdentity {
            namespace: config.test_namespace.clone(),
            name: field("/metadata/name")?,
            uid: field("/metadata/uid")?,
            container_id: status[0]
                .get("containerID")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .context("RustFS containerID is missing")?
                .to_string(),
            node: field("/spec/nodeName")?,
            pod_ip,
            listener_port: RUSTFS_CONTAINER_PORT,
        });
    }
    pods.sort_by(|left, right| left.name.cmp(&right.name));
    validate_identities(&pods)?;
    Ok(pods)
}

pub(crate) fn validate_identities(pods: &[PodNetworkIdentity]) -> Result<()> {
    ensure!(!pods.is_empty(), "Pod network identity set is empty");
    let mut names = BTreeSet::new();
    let mut uids = BTreeSet::new();
    let mut containers = BTreeSet::new();
    let mut ips = BTreeSet::new();
    for pod in pods {
        ensure!(
            !pod.namespace.is_empty()
                && !pod.name.is_empty()
                && !pod.uid.is_empty()
                && !pod.container_id.is_empty()
                && !pod.node.is_empty()
                && pod.listener_port == RUSTFS_CONTAINER_PORT
                && pod.pod_ip.parse::<IpAddr>().is_ok()
                && names.insert((&pod.namespace, &pod.name))
                && uids.insert(&pod.uid)
                && containers.insert(&pod.container_id)
                && ips.insert(&pod.pod_ip),
            "invalid or duplicated Pod network identity"
        );
    }
    Ok(())
}

pub(crate) async fn require_same_generation(
    config: &ClusterTestConfig,
    pods: &[PodNetworkIdentity],
) -> Result<()> {
    let current = capture_pod_network_identities(config).await?;
    ensure!(
        current == pods,
        "RustFS Pod UID, containerID, PodIP, node, or listener changed during observation"
    );
    Ok(())
}

pub(crate) async fn capture_connectivity(
    config: &ClusterTestConfig,
    pods: &[PodNetworkIdentity],
) -> Result<Vec<PodConnectivityObservation>> {
    require_same_generation(config, pods).await?;
    let pairs = pods
        .iter()
        .flat_map(|source| {
            pods.iter()
                .filter(move |target| source.name != target.name)
                .map(move |target| (source, target))
        })
        .collect::<Vec<_>>();
    // Parallel probes keep the complete four-server matrix within one short
    // fault window. Each curl and its kubectl parent have independent bounds.
    let results = stream::iter(pairs)
        .map(|(source, target)| capture_pair(config, source, target))
        .buffer_unordered(12)
        .collect::<Vec<_>>()
        .await;
    let mut observations = results.into_iter().collect::<Result<Vec<_>>>()?;
    observations.sort_by(|left, right| {
        (&left.source.name, &left.target.name).cmp(&(&right.source.name, &right.target.name))
    });
    require_same_generation(config, pods).await?;
    Ok(observations)
}

async fn capture_pair(
    config: &ClusterTestConfig,
    source: &PodNetworkIdentity,
    target: &PodNetworkIdentity,
) -> Result<PodConnectivityObservation> {
    let address = match target.pod_ip.parse::<IpAddr>()? {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    let started_at_ms = now_ms();
    let output = Kubectl::new(config)
        .namespaced(&source.namespace)
        .command([
            "exec",
            source.name.as_str(),
            "-c",
            "rustfs",
            "--",
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "2",
            "--max-time",
            "3",
            "--output",
            "/dev/null",
            "--write-out",
            "%{http_code}\t%{time_connect}\t%{remote_ip}",
            &format!("http://{address}:{}/health/live", target.listener_port),
        ])
        .run_bounded(Duration::from_millis(CONNECTIVITY_PROBE_TIMEOUT_MS))
        .await?;
    let completed_at_ms = now_ms();
    let (http_status, connect_seconds, remote_ip) = parse_curl_observation(&output.stdout)
        .map(|(status, seconds, ip)| (Some(status), Some(seconds), ip))
        .unwrap_or((None, None, None));
    Ok(PodConnectivityObservation {
        source: source.clone(),
        target: target.clone(),
        started_at_ms,
        completed_at_ms,
        exit_code: output.code,
        http_status,
        connect_seconds,
        remote_ip,
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn parse_curl_observation(stdout: &str) -> Result<(u16, f64, Option<String>)> {
    let fields = stdout
        .trim_end_matches(['\r', '\n'])
        .split('\t')
        .collect::<Vec<_>>();
    ensure!(
        fields.len() == 3
            && fields[0].len() == 3
            && fields[0].bytes().all(|byte| byte.is_ascii_digit()),
        "curl output does not contain exactly three receipt fields"
    );
    let status = fields[0].parse::<u16>()?;
    let seconds = fields[1].parse::<f64>()?;
    ensure!(
        seconds.is_finite() && (0.0..=3.0).contains(&seconds),
        "invalid curl TCP connection timing"
    );
    let ip = if fields[2].is_empty() {
        None
    } else {
        fields[2]
            .parse::<IpAddr>()
            .context("invalid curl remote_ip")?;
        Some(fields[2].to_string())
    };
    Ok((status, seconds, ip))
}

pub(crate) fn validate_connectivity(
    observations: &[PodConnectivityObservation],
    pods: &[PodNetworkIdentity],
    source_pod_names: &BTreeSet<String>,
    peer_pod_names: &BTreeSet<String>,
    partition_active: bool,
) -> Result<()> {
    validate_identities(pods)?;
    let names = pods
        .iter()
        .map(|pod| pod.name.clone())
        .collect::<BTreeSet<_>>();
    ensure!(
        !source_pod_names.is_empty()
            && !peer_pod_names.is_empty()
            && source_pod_names.is_disjoint(peer_pod_names)
            && source_pod_names
                .union(peer_pod_names)
                .cloned()
                .collect::<BTreeSet<_>>()
                == names,
        "connectivity groups must partition the complete Pod identity set"
    );
    let mut pairs = BTreeSet::new();
    for observation in observations {
        let (raw_status, raw_seconds, raw_ip) = parse_curl_observation(&observation.stdout)?;
        ensure!(
            observation.http_status == Some(raw_status)
                && observation.connect_seconds == Some(raw_seconds)
                && observation.remote_ip == raw_ip,
            "curl derived fields differ from raw output"
        );
        ensure!(
            pods.contains(&observation.source)
                && pods.contains(&observation.target)
                && observation.source.name != observation.target.name
                && pairs.insert((&observation.source.name, &observation.target.name))
                && observation.started_at_ms > 0
                && observation.completed_at_ms >= observation.started_at_ms
                && observation.completed_at_ms - observation.started_at_ms
                    <= CONNECTIVITY_PROBE_TIMEOUT_MS,
            "connectivity receipt has an unknown generation, duplicate pair, or invalid interval"
        );
        let cross_group = source_pod_names.contains(&observation.source.name)
            != source_pod_names.contains(&observation.target.name);
        if partition_active && cross_group {
            ensure!(
                observation.exit_code == Some(28)
                    && observation.http_status == Some(0)
                    && observation.connect_seconds == Some(0.0)
                    && observation.remote_ip.is_none(),
                "cross-group TCP connection did not time out before establishment: {} -> {}: {} {}",
                observation.source.name,
                observation.target.name,
                observation.stdout,
                observation.stderr
            );
        } else {
            ensure!(
                observation.exit_code == Some(0)
                    && observation.http_status == Some(200)
                    && observation.connect_seconds.is_some_and(
                        |seconds| seconds.is_finite() && (0.0..=3.0).contains(&seconds)
                    )
                    && observation.remote_ip.as_deref() == Some(observation.target.pod_ip.as_str()),
                "expected healthy Pod connection failed: {} -> {}: {} {}",
                observation.source.name,
                observation.target.name,
                observation.stdout,
                observation.stderr
            );
        }
    }
    ensure!(
        pairs.len() == pods.len() * (pods.len() - 1),
        "connectivity receipts do not cover every ordered Pod pair"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::config::FaultTestConfig;

    fn pods() -> Vec<PodNetworkIdentity> {
        (0..4)
            .map(|index| PodNetworkIdentity {
                namespace: "faults".to_string(),
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
                container_id: format!("containerd://container-{index}"),
                node: format!("node-{index}"),
                pod_ip: format!("10.42.0.{}", index + 1),
                listener_port: 9000,
            })
            .collect()
    }
    fn matrix(pods: &[PodNetworkIdentity], active: bool) -> Vec<PodConnectivityObservation> {
        pods.iter()
            .flat_map(|source| {
                pods.iter()
                    .filter(move |target| source.name != target.name)
                    .map(move |target| {
                        let blocked = active
                            && (source.name.as_str() < "rustfs-2")
                                != (target.name.as_str() < "rustfs-2");
                        PodConnectivityObservation {
                            source: source.clone(),
                            target: target.clone(),
                            started_at_ms: 100,
                            completed_at_ms: 200,
                            exit_code: Some(if blocked { 28 } else { 0 }),
                            http_status: Some(if blocked { 0 } else { 200 }),
                            connect_seconds: Some(if blocked { 0.0 } else { 0.001 }),
                            remote_ip: if blocked {
                                None
                            } else {
                                Some(target.pod_ip.clone())
                            },
                            stdout: if blocked {
                                "000\t0.000000\t".to_string()
                            } else {
                                format!("200\t0.001000\t{}", target.pod_ip)
                            },
                            stderr: if blocked {
                                "curl: (28) Failed to connect within 2000 milliseconds".to_string()
                            } else {
                                String::new()
                            },
                        }
                    })
            })
            .collect()
    }

    #[test]
    fn split_brain_network_probe_rejects_partial_cut_and_lost_intra_group_paths() {
        let pods = pods();
        let source = pods[..2].iter().map(|pod| pod.name.clone()).collect();
        let peers = pods[2..].iter().map(|pod| pod.name.clone()).collect();
        validate_connectivity(&matrix(&pods, false), &pods, &source, &peers, false)
            .expect("healthy baseline");
        let active = matrix(&pods, true);
        validate_connectivity(&active, &pods, &source, &peers, true).expect("proven cut");
        assert!(
            validate_connectivity(&matrix(&pods, false), &pods, &source, &peers, true).is_err()
        );
        let mut failed_intra = active.clone();
        failed_intra[0].exit_code = Some(28);
        failed_intra[0].stdout = "000\t0.000000\t".to_string();
        failed_intra[0].http_status = Some(0);
        failed_intra[0].connect_seconds = Some(0.0);
        failed_intra[0].remote_ip = None;
        assert!(validate_connectivity(&failed_intra, &pods, &source, &peers, true).is_err());
        let mut http_timeout = active.clone();
        let cross = http_timeout
            .iter_mut()
            .find(|receipt| receipt.exit_code == Some(28))
            .expect("cross pair");
        cross.connect_seconds = Some(0.001);
        cross.remote_ip = Some(cross.target.pod_ip.clone());
        cross.stdout = format!("000\t0.001000\t{}", cross.target.pod_ip);
        assert!(validate_connectivity(&http_timeout, &pods, &source, &peers, true).is_err());
        assert!(validate_connectivity(&active[..11], &pods, &source, &peers, true).is_err());
        let mut generation = active.clone();
        generation[0].source.container_id = "replacement".to_string();
        assert!(validate_connectivity(&generation, &pods, &source, &peers, true).is_err());
    }

    #[test]
    fn split_brain_network_probe_binds_derived_fields_to_raw_curl_receipts() {
        let pods = pods();
        let source = pods[..2].iter().map(|pod| pod.name.clone()).collect();
        let peers = pods[2..].iter().map(|pod| pod.name.clone()).collect();
        for raw in [
            "200\tNaN\t10.42.0.2",
            "200\tinf\t10.42.0.2",
            "200\t0.001000",
            "200\t0.001000\t10.42.0.2\textra",
            "500\t0.001000\t10.42.0.2",
        ] {
            let mut receipts = matrix(&pods, true);
            receipts[0].stdout = raw.to_string();
            assert!(
                validate_connectivity(&receipts, &pods, &source, &peers, true).is_err(),
                "{raw}"
            );
        }
        let mut forged = matrix(&pods, true);
        forged[0].http_status = Some(204);
        assert!(validate_connectivity(&forged, &pods, &source, &peers, true).is_err());
    }

    #[test]
    fn network_identity_requires_a_running_owned_container_and_live_listener() {
        let config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        let resource = serde_json::json!({"items": [{
            "metadata": {"namespace": config.cluster.test_namespace, "name": "rustfs-0", "uid": "pod-uid", "labels": {"rustfs.tenant": config.cluster.tenant_name}},
            "spec": {"nodeName": "node-0", "containers": [{"name": "rustfs", "ports": [{"containerPort": 9000, "protocol": "TCP"}]}]},
            "status": {"phase": "Running", "podIP": "10.42.0.1", "containerStatuses": [{"name": "rustfs", "containerID": "containerd://generation", "state": {"running": {}}}]}
        }]});
        identities_from_pods(&resource, &config.cluster).expect("live identity");
        for (path, value) in [
            ("/items/0/spec/hostNetwork", serde_json::json!(true)),
            ("/items/0/status/phase", serde_json::json!("Pending")),
            ("/items/0/status/podIP", serde_json::json!("unresolved")),
            (
                "/items/0/spec/containers/0/ports/0/containerPort",
                serde_json::json!(9001),
            ),
            (
                "/items/0/status/containerStatuses/0/state",
                serde_json::json!({"terminated": {}}),
            ),
        ] {
            let mut changed = resource.clone();
            if path.ends_with("hostNetwork") {
                changed["items"][0]["spec"]["hostNetwork"] = value;
            } else {
                *changed.pointer_mut(path).expect("field") = value;
            }
            assert!(
                identities_from_pods(&changed, &config.cluster).is_err(),
                "{path}"
            );
        }
    }
}
