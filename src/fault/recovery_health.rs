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

//! Post-recovery RustFS health contract.
//!
//! The S3 object-model checker proves that committed data is *readable* after
//! a fault. Reads reconstruct from any read-quorum subset of shards, so a
//! passing checker cannot distinguish a fully healed cluster from one whose
//! returned drive is still `offline`, `unknown`, or `faulty`. This module adds
//! the missing RustFS-side assertion: after the recovery gate, every drive
//! RustFS reported healthy before the fault must report `ok` again, the
//! deployment identity and erasure geometry must be unchanged, and every
//! RustFS Pod must answer its readiness endpoint.
//!
//! The observation is a bounded poll, not continuous monitoring: it proves the
//! cluster reached a healthy state within the recovery timeout.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use crate::rustfs::RustfsErasureLayout;

pub const RECOVERY_HEALTH_ARTIFACT: &str = "recovery-health.json";
/// RustFS readiness path probed on every Pod through the API server Pod proxy.
pub const RUSTFS_READINESS_PATH: &str = "/health/ready";
/// RustFS S3 container port; the same port the tenant port-forward targets.
pub const RUSTFS_CONTAINER_PORT: u16 = 9000;
const HEALTHY_DRIVE_STATE: &str = "ok";

/// The healthy pre-fault RustFS layout. Captured from `/rustfs/admin/v3/info`
/// before the fault is applied, it defines what "recovered" must look like.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryHealthBaseline {
    pub observed_at_ms: u64,
    pub deployment_id: String,
    pub standard_parity: usize,
    pub total_sets: Vec<usize>,
    pub drives_per_set: Vec<usize>,
    /// Sorted RustFS server endpoints.
    pub server_endpoints: Vec<String>,
    /// Sorted drive UUIDs across every server; the recovered cluster must
    /// report exactly this set so a silently replaced or dropped drive fails.
    pub drive_uuids: Vec<String>,
}

impl RecoveryHealthBaseline {
    pub(crate) fn from_layout(layout: &RustfsErasureLayout, observed_at_ms: u64) -> Result<Self> {
        ensure!(observed_at_ms > 0, "baseline observation timestamp is zero");
        ensure!(
            !layout.deployment_id.trim().is_empty(),
            "RustFS baseline has no deployment identity"
        );
        let expected_drives = expected_drive_count(&layout.total_sets, &layout.drives_per_set)?;
        let mut server_endpoints = Vec::with_capacity(layout.servers.len());
        let mut drive_uuids = Vec::with_capacity(expected_drives);
        for server in &layout.servers {
            ensure!(
                !server.endpoint.trim().is_empty(),
                "RustFS baseline has a server without an endpoint"
            );
            server_endpoints.push(server.endpoint.clone());
            for drive in &server.drives {
                ensure!(
                    !drive.uuid.trim().is_empty(),
                    "RustFS baseline server {:?} has a drive without a UUID",
                    server.endpoint
                );
                ensure!(
                    drive.state == HEALTHY_DRIVE_STATE,
                    "RustFS baseline drive {:?} on {:?} is not healthy before the fault: {:?}",
                    drive.uuid,
                    server.endpoint,
                    drive.state
                );
                drive_uuids.push(drive.uuid.clone());
            }
        }
        server_endpoints.sort();
        drive_uuids.sort();
        ensure!(
            layout.online_drives == expected_drives
                && layout.offline_drives == 0
                && layout.unknown_drives == 0,
            "RustFS baseline is not fully online before the fault: online={} offline={} unknown={} expected={expected_drives}",
            layout.online_drives,
            layout.offline_drives,
            layout.unknown_drives
        );
        let baseline = Self {
            observed_at_ms,
            deployment_id: layout.deployment_id.clone(),
            standard_parity: layout.standard_parity,
            total_sets: layout.total_sets.clone(),
            drives_per_set: layout.drives_per_set.clone(),
            server_endpoints,
            drive_uuids,
        };
        baseline.validate()?;
        Ok(baseline)
    }

    /// Structural invariants a baseline must satisfy whether it was captured
    /// live or deserialized from an artifact: identities are sorted and
    /// unique so membership comparison is exact, and the drive set is exactly
    /// the drive count the declared erasure geometry implies. A report whose
    /// baseline silently dropped a drive therefore cannot certify recovery
    /// even when its observation agrees with that shrunken baseline.
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.observed_at_ms > 0,
            "baseline observation timestamp is zero"
        );
        ensure!(
            !self.deployment_id.trim().is_empty(),
            "RustFS baseline has no deployment identity"
        );
        let expected_drives = expected_drive_count(&self.total_sets, &self.drives_per_set)?;
        ensure!(
            !self.server_endpoints.is_empty(),
            "RustFS baseline lists no servers"
        );
        ensure!(
            self.server_endpoints
                .iter()
                .all(|endpoint| !endpoint.trim().is_empty()),
            "RustFS baseline has a server without an endpoint"
        );
        ensure!(
            self.server_endpoints
                .windows(2)
                .all(|pair| pair[0] < pair[1]),
            "RustFS baseline server endpoints are not sorted and unique"
        );
        ensure!(
            self.drive_uuids.iter().all(|uuid| !uuid.trim().is_empty()),
            "RustFS baseline has a drive without a UUID"
        );
        ensure!(
            self.drive_uuids.windows(2).all(|pair| pair[0] < pair[1]),
            "RustFS baseline drive UUIDs are not sorted and unique"
        );
        ensure!(
            self.drive_uuids.len() == expected_drives,
            "RustFS baseline lists {} drives but the erasure layout declares {expected_drives}",
            self.drive_uuids.len()
        );
        Ok(())
    }
}

fn expected_drive_count(total_sets: &[usize], drives_per_set: &[usize]) -> Result<usize> {
    ensure!(
        !total_sets.is_empty() && total_sets.len() == drives_per_set.len(),
        "RustFS erasure layout arrays are empty or inconsistent"
    );
    total_sets
        .iter()
        .zip(drives_per_set)
        .try_fold(0usize, |sum, (sets, drives)| {
            sets.checked_mul(*drives)
                .and_then(|pool| sum.checked_add(pool))
                .ok_or_else(|| anyhow::anyhow!("RustFS erasure layout drive count overflow"))
        })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryDriveState {
    pub server_endpoint: String,
    pub drive_uuid: String,
    pub state: String,
    pub pool_index: i32,
    pub set_index: i32,
}

/// One bounded `/rustfs/admin/v3/info` read taken after the recovery gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryHealthObservation {
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub deployment_id: String,
    pub standard_parity: usize,
    pub total_sets: Vec<usize>,
    pub drives_per_set: Vec<usize>,
    pub online_drives: usize,
    pub offline_drives: usize,
    pub unknown_drives: usize,
    pub drives: Vec<RecoveryDriveState>,
}

impl RecoveryHealthObservation {
    pub(crate) fn from_layout(
        layout: &RustfsErasureLayout,
        started_at_ms: u64,
        completed_at_ms: u64,
    ) -> Self {
        let mut drives = layout
            .servers
            .iter()
            .flat_map(|server| {
                server.drives.iter().map(move |drive| RecoveryDriveState {
                    server_endpoint: server.endpoint.clone(),
                    drive_uuid: drive.uuid.clone(),
                    state: drive.state.clone(),
                    pool_index: drive.pool_index,
                    set_index: drive.set_index,
                })
            })
            .collect::<Vec<_>>();
        drives.sort_by(|left, right| left.drive_uuid.cmp(&right.drive_uuid));
        Self {
            started_at_ms,
            completed_at_ms,
            deployment_id: layout.deployment_id.clone(),
            standard_parity: layout.standard_parity,
            total_sets: layout.total_sets.clone(),
            drives_per_set: layout.drives_per_set.clone(),
            online_drives: layout.online_drives,
            offline_drives: layout.offline_drives,
            unknown_drives: layout.unknown_drives,
            drives,
        }
    }

    /// Every way the observed cluster differs from the healthy baseline. An
    /// empty list means RustFS reports itself fully recovered.
    pub fn violations(&self, baseline: &RecoveryHealthBaseline) -> Vec<String> {
        let mut violations = Vec::new();
        if self.started_at_ms == 0 || self.started_at_ms > self.completed_at_ms {
            violations.push("observation interval is invalid".to_string());
        }
        if self.deployment_id != baseline.deployment_id {
            violations.push(format!(
                "deployment identity changed from {:?} to {:?}",
                baseline.deployment_id, self.deployment_id
            ));
        }
        if self.standard_parity != baseline.standard_parity
            || self.total_sets != baseline.total_sets
            || self.drives_per_set != baseline.drives_per_set
        {
            violations.push(format!(
                "erasure geometry changed: parity {} -> {}, sets {:?} -> {:?}, drives per set {:?} -> {:?}",
                baseline.standard_parity,
                self.standard_parity,
                baseline.total_sets,
                self.total_sets,
                baseline.drives_per_set,
                self.drives_per_set
            ));
        }
        let expected_drives = baseline.drive_uuids.len();
        if self.online_drives != expected_drives
            || self.offline_drives != 0
            || self.unknown_drives != 0
        {
            violations.push(format!(
                "drive counters not fully online: online={} offline={} unknown={} expected={expected_drives}",
                self.online_drives, self.offline_drives, self.unknown_drives
            ));
        }
        if self.drives.len() != expected_drives {
            violations.push(format!(
                "observation lists {} drives but the baseline declares {expected_drives}",
                self.drives.len()
            ));
        }
        let mut observed_uuids = self
            .drives
            .iter()
            .map(|drive| drive.drive_uuid.as_str())
            .collect::<Vec<_>>();
        observed_uuids.sort_unstable();
        observed_uuids.dedup();
        let baseline_uuids = baseline
            .drive_uuids
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if observed_uuids != baseline_uuids {
            let missing = baseline_uuids
                .iter()
                .filter(|uuid| observed_uuids.binary_search(uuid).is_err())
                .copied()
                .collect::<Vec<_>>();
            let added = observed_uuids
                .iter()
                .filter(|uuid| baseline_uuids.binary_search(uuid).is_err())
                .copied()
                .collect::<Vec<_>>();
            violations.push(format!(
                "drive membership changed: missing={missing:?} unexpected={added:?}"
            ));
        }
        let mut observed_endpoints = self
            .drives
            .iter()
            .map(|drive| drive.server_endpoint.as_str())
            .collect::<Vec<_>>();
        observed_endpoints.sort_unstable();
        observed_endpoints.dedup();
        let baseline_endpoints = baseline
            .server_endpoints
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        if observed_endpoints != baseline_endpoints {
            violations.push(format!(
                "server membership changed from {baseline_endpoints:?} to {observed_endpoints:?}"
            ));
        }
        for drive in &self.drives {
            if drive.state != HEALTHY_DRIVE_STATE {
                violations.push(format!(
                    "drive {:?} on {:?} is {:?}, expected {HEALTHY_DRIVE_STATE:?}",
                    drive.drive_uuid, drive.server_endpoint, drive.state
                ));
            }
        }
        violations
    }
}

/// One readiness probe against a RustFS Pod through the API server Pod proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PodReadinessProbe {
    pub pod_name: String,
    pub proxy_path: String,
    pub ready: bool,
    pub observed_at_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// API server proxy path for a Pod's RustFS readiness endpoint. Going through
/// the API server needs no tooling inside the RustFS image and no extra
/// port-forward per Pod.
pub fn readiness_proxy_path(namespace: &str, pod_name: &str) -> String {
    format!(
        "/api/v1/namespaces/{namespace}/pods/{pod_name}:{RUSTFS_CONTAINER_PORT}/proxy{RUSTFS_READINESS_PATH}"
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryHealthReport {
    pub scenario: String,
    pub run_id: String,
    pub baseline: RecoveryHealthBaseline,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub timeout_seconds: u64,
    pub attempts: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_healthy_at_ms: Option<u64>,
    /// The last admin observation taken; the healthy one on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<RecoveryHealthObservation>,
    /// The last readiness probe round taken; all ready on success.
    #[serde(default)]
    pub readiness: Vec<PodReadinessProbe>,
    /// Sorted violations from the final attempt; empty on success.
    #[serde(default)]
    pub violations: Vec<String>,
    pub passed: bool,
}

impl RecoveryHealthReport {
    pub fn require_success(&self) -> Result<()> {
        // A deserialized baseline is re-validated here: the observation is
        // only compared against it, so an inconsistent baseline could
        // otherwise certify a cluster that agrees with a shrunken layout.
        self.baseline
            .validate()
            .context("recovery-health.json baseline is not a valid healthy layout")?;
        ensure!(
            self.passed && self.success_predicate(),
            "RustFS did not report a fully recovered cluster within {}s after {} attempt(s): {}",
            self.timeout_seconds,
            self.attempts,
            if self.violations.is_empty() {
                "no observation completed".to_string()
            } else {
                self.violations.join("; ")
            }
        );
        Ok(())
    }

    fn success_predicate(&self) -> bool {
        self.attempts > 0
            && self.started_at_ms > 0
            && self.started_at_ms <= self.completed_at_ms
            && self.violations.is_empty()
            && self
                .first_healthy_at_ms
                .is_some_and(|at| at >= self.started_at_ms && at <= self.completed_at_ms)
            && self
                .observation
                .as_ref()
                .is_some_and(|observation| observation.violations(&self.baseline).is_empty())
            && !self.readiness.is_empty()
            && self.readiness.iter().all(|probe| probe.ready)
    }

    /// The report must be taken after fault removal began and complete before
    /// recovery is declared finished, so it cannot describe a pre-fault cluster.
    pub fn require_within_recovery_window(
        &self,
        recovery_started_at_ms: u64,
        recovery_ended_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            recovery_started_at_ms <= self.started_at_ms
                && self.completed_at_ms <= recovery_ended_at_ms,
            "recovery-health.json observation window [{}, {}] is outside the recovery window [{recovery_started_at_ms}, {recovery_ended_at_ms}]",
            self.started_at_ms,
            self.completed_at_ms
        );
        ensure!(
            self.baseline.observed_at_ms < recovery_started_at_ms,
            "recovery-health.json baseline was not captured before recovery started"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{
        PodReadinessProbe, RecoveryHealthBaseline, RecoveryHealthObservation, RecoveryHealthReport,
        readiness_proxy_path,
    };
    use crate::rustfs::{RustfsDriveLayout, RustfsErasureLayout, RustfsServerLayout};

    fn healthy_layout() -> RustfsErasureLayout {
        RustfsErasureLayout {
            deployment_id: "deployment-1".to_string(),
            standard_parity: 2,
            total_sets: vec![1],
            drives_per_set: vec![4],
            online_drives: 4,
            offline_drives: 0,
            unknown_drives: 0,
            servers: (0..4)
                .map(|index| RustfsServerLayout {
                    endpoint: format!("http://rustfs-{index}.rustfs:9000"),
                    drives: vec![RustfsDriveLayout {
                        uuid: format!("drive-{index}"),
                        state: "ok".to_string(),
                        pool_index: 0,
                        set_index: 0,
                    }],
                })
                .collect(),
        }
    }

    fn build_report(
        baseline: RecoveryHealthBaseline,
        layout: &RustfsErasureLayout,
    ) -> RecoveryHealthReport {
        let observation = RecoveryHealthObservation::from_layout(layout, 100, 101);
        let violations = observation.violations(&baseline);
        let passed = violations.is_empty();
        RecoveryHealthReport {
            scenario: "io-eio".to_string(),
            run_id: "run-1".to_string(),
            baseline,
            started_at_ms: 100,
            completed_at_ms: 102,
            timeout_seconds: 300,
            attempts: 1,
            first_healthy_at_ms: passed.then_some(101),
            observation: Some(observation),
            readiness: vec![PodReadinessProbe {
                pod_name: "rustfs-0".to_string(),
                proxy_path: readiness_proxy_path("ns", "rustfs-0"),
                ready: true,
                observed_at_ms: 101,
                detail: None,
            }],
            violations,
            passed,
        }
    }

    #[test]
    fn baseline_requires_a_fully_healthy_pre_fault_layout() {
        let baseline = RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        assert_eq!(baseline.drive_uuids.len(), 4);
        assert_eq!(baseline.server_endpoints.len(), 4);

        let mut degraded = healthy_layout();
        degraded.servers[1].drives[0].state = "offline".to_string();
        assert!(RecoveryHealthBaseline::from_layout(&degraded, 1).is_err());

        let mut short = healthy_layout();
        short.servers.pop();
        assert!(RecoveryHealthBaseline::from_layout(&short, 1).is_err());

        let mut counters = healthy_layout();
        counters.unknown_drives = 1;
        assert!(RecoveryHealthBaseline::from_layout(&counters, 1).is_err());
    }

    #[test]
    fn recovered_layout_identical_to_baseline_passes() {
        let baseline = RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        let report = build_report(baseline, &healthy_layout());
        report.require_success().expect("healthy recovery");
        report
            .require_within_recovery_window(50, 200)
            .expect("inside window");
        assert!(report.require_within_recovery_window(101, 200).is_err());
        assert!(report.require_within_recovery_window(50, 101).is_err());
    }

    #[test]
    fn unknown_faulty_or_missing_drives_fail_recovery() {
        let baseline = RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");

        let mut unknown = healthy_layout();
        unknown.servers[2].drives[0].state = "unknown".to_string();
        unknown.online_drives = 3;
        unknown.unknown_drives = 1;
        let report = build_report(baseline.clone(), &unknown);
        let error = report.require_success().expect_err("unknown drive");
        assert!(error.to_string().contains("\"drive-2\""));
        assert!(error.to_string().contains("online=3"));

        // Counters can lie (rustfs/rustfs#5869 family): a per-drive state that
        // is not "ok" fails even when the aggregate counters look green.
        let mut faulty_counters_green = healthy_layout();
        faulty_counters_green.servers[0].drives[0].state = "faulty".to_string();
        assert!(
            build_report(baseline.clone(), &faulty_counters_green)
                .require_success()
                .is_err()
        );

        let mut replaced = healthy_layout();
        replaced.servers[3].drives[0].uuid = "drive-new".to_string();
        let error = build_report(baseline.clone(), &replaced)
            .require_success()
            .expect_err("replaced drive");
        assert!(error.to_string().contains("drive membership changed"));

        let mut redeployed = healthy_layout();
        redeployed.deployment_id = "deployment-2".to_string();
        assert!(
            build_report(baseline.clone(), &redeployed)
                .require_success()
                .is_err()
        );

        let mut reshaped = healthy_layout();
        reshaped.standard_parity = 1;
        assert!(build_report(baseline, &reshaped).require_success().is_err());
    }

    #[test]
    fn a_baseline_that_dropped_a_drive_cannot_certify_recovery() {
        let mut baseline =
            RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        // A report edited so baseline and observation agree on three drives
        // while the declared four-drive geometry is unchanged.
        baseline.drive_uuids.pop();
        baseline.server_endpoints.pop();
        let mut shrunken = healthy_layout();
        shrunken.servers.pop();
        shrunken.online_drives = 3;
        let report = build_report(baseline.clone(), &shrunken);
        assert!(
            report.violations.is_empty() && report.passed,
            "the observation agrees with the shrunken baseline: {:?}",
            report.violations
        );
        let error = report.require_success().expect_err("dropped drive");
        assert!(
            format!("{error:#}").contains("lists 3 drives but the erasure layout declares 4"),
            "{error:#}"
        );
        assert!(
            RecoveryHealthBaseline::from_layout(&shrunken, 1).is_err(),
            "the live capture rejects the same layout"
        );

        let mut unsorted =
            RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        unsorted.drive_uuids.swap(0, 1);
        assert!(unsorted.validate().is_err());
        let mut duplicated =
            RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        duplicated.drive_uuids[1] = duplicated.drive_uuids[0].clone();
        assert!(duplicated.validate().is_err());

        // An observation that lists one drive twice cannot pad its count.
        let mut padded = healthy_layout();
        let duplicate = padded.servers[0].drives[0].clone();
        padded.servers[0].drives.push(duplicate);
        let report = build_report(
            RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline"),
            &padded,
        );
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.contains("observation lists 5 drives")),
            "{:?}",
            report.violations
        );
    }

    #[test]
    fn readiness_failure_or_missing_probes_fail_even_with_healthy_drives() {
        let baseline = RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        let mut report = build_report(baseline, &healthy_layout());
        report.readiness[0].ready = false;
        report.passed = false;
        assert!(report.require_success().is_err());
        report.readiness.clear();
        assert!(report.require_success().is_err());
    }

    #[test]
    fn passed_flag_alone_cannot_claim_success() {
        let baseline = RecoveryHealthBaseline::from_layout(&healthy_layout(), 1).expect("baseline");
        let mut degraded = healthy_layout();
        degraded.servers[0].drives[0].state = "offline".to_string();
        let mut report = build_report(baseline, &degraded);
        report.passed = true;
        report.violations.clear();
        assert!(report.require_success().is_err());
    }

    #[test]
    fn readiness_proxy_path_targets_the_rustfs_port() {
        assert_eq!(
            readiness_proxy_path("rustfs-fault-test", "rustfs-0"),
            "/api/v1/namespaces/rustfs-fault-test/pods/rustfs-0:9000/proxy/health/ready"
        );
    }
}
