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

//! In-run Warp window metrics for `warp-under-chaos`.
//!
//! The campaign records one healthy window before the fault, one window while
//! the fault is active, and short post-recovery windows. Peer binaries are
//! not part of this artifact.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

pub(crate) const WARP_POWERLOSS_METRICS_ARTIFACT: &str = "warp-powerloss-metrics.json";
pub(crate) const WARP_BASELINE_WINDOW_ARTIFACT: &str = "warp-baseline-window.json";
pub(crate) const WARP_DEGRADED_WINDOW_ARTIFACT: &str = "warp-degraded-window.json";
pub(crate) const WARP_METRICS_SCHEMA_VERSION: u8 = 1;
pub(crate) const TTB_BASELINE_RATIO: f64 = 0.90;
pub(crate) const TTB_SUSTAIN_SECONDS: u64 = 30;
pub(crate) const WARP_RECOVERY_WINDOW_SECONDS: u64 = 10;
pub(crate) const WARP_RECOVERY_WINDOW_LIMIT: usize = 12;
const PEER_COMPARE_NOT_IN_CI: &str = "not-in-ci";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WarpWindow {
    pub(crate) ops_per_sec: f64,
    pub(crate) error_percent: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RecoveryWindowRecord {
    pub(crate) seconds: u64,
    pub(crate) ops_per_sec: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum TtbReport {
    Reached { seconds: u64 },
    NotReached { reason: String },
    NotObserved { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum NodeReadyLag {
    NotApplicable { reason: String },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct WarpPowerLossMetrics {
    pub(crate) schema_version: u8,
    pub(crate) scenario: String,
    pub(crate) baseline_ops_per_sec: f64,
    pub(crate) degraded_ops_per_sec: f64,
    pub(crate) drop_percent: f64,
    pub(crate) fault_window_error_percent: f64,
    pub(crate) node_ready_lag: NodeReadyLag,
    pub(crate) ttb_to_90_percent_baseline: TtbReport,
    pub(crate) recovery_windows: Vec<RecoveryWindowRecord>,
    pub(crate) peer_compare: String,
    pub(crate) notes: Vec<String>,
}

pub(crate) fn parse_warp_stdout(stdout: &str) -> Result<WarpWindow> {
    let mut ops = Vec::new();
    let mut errors = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(rate) = parse_average_obj_rate(line) {
            ops.push(rate);
        } else if let Some(percent) = parse_error_percent(line) {
            errors.push(percent);
        }
    }
    ensure!(
        !ops.is_empty() && ops.len() == errors.len(),
        "warp report did not contain paired Average obj/s and Errors lines"
    );
    let total_ops = ops.iter().sum::<f64>();
    ensure!(
        total_ops.is_finite() && total_ops >= 0.0,
        "warp obj/s total is not a finite non-negative rate"
    );
    let weighted_errors = ops
        .iter()
        .zip(errors.iter())
        .map(|(rate, error)| rate * error)
        .sum::<f64>();
    let error_percent = if total_ops == 0.0 {
        errors.iter().copied().sum::<f64>() / errors.len() as f64
    } else {
        weighted_errors / total_ops
    };
    ensure!(
        error_percent.is_finite() && (0.0..=100.0).contains(&error_percent),
        "warp error percent {error_percent} is outside 0..=100"
    );
    Ok(WarpWindow {
        ops_per_sec: round2(total_ops),
        error_percent: round2(error_percent),
    })
}

fn parse_average_obj_rate(line: &str) -> Option<f64> {
    let rest = line.strip_prefix("* Average:")?.trim();
    let (_, rate) = rest.rsplit_once(',')?;
    let rate = rate.trim().strip_suffix("obj/s")?.trim();
    let rate = rate.parse::<f64>().ok()?;
    rate.is_finite().then_some(rate)
}

fn parse_error_percent(line: &str) -> Option<f64> {
    let rest = line.strip_prefix("* Errors:")?.trim();
    let percent = rest.strip_suffix('%')?.trim();
    let percent = percent.parse::<f64>().ok()?;
    percent.is_finite().then_some(percent)
}

pub(crate) fn drop_percent(baseline_ops: f64, degraded_ops: f64) -> Result<f64> {
    ensure!(
        baseline_ops.is_finite() && baseline_ops > 0.0,
        "baseline ops/s must be a positive finite rate"
    );
    ensure!(
        degraded_ops.is_finite() && degraded_ops >= 0.0,
        "degraded ops/s must be a finite non-negative rate"
    );
    Ok(round2((baseline_ops - degraded_ops) / baseline_ops * 100.0))
}

pub(crate) fn evaluate_ttb(
    baseline_ops: f64,
    windows: &[RecoveryWindowRecord],
) -> Result<TtbReport> {
    if windows.is_empty() {
        return Ok(TtbReport::NotObserved {
            reason: "post-recovery warp windows were not sampled".to_string(),
        });
    }
    ensure!(
        baseline_ops.is_finite() && baseline_ops > 0.0,
        "baseline ops/s must be a positive finite rate"
    );
    let floor = baseline_ops * TTB_BASELINE_RATIO;
    let mut sustained = 0u64;
    let mut elapsed = 0u64;
    for window in windows {
        ensure!(
            window.seconds > 0 && window.ops_per_sec.is_finite() && window.ops_per_sec >= 0.0,
            "recovery window must have a positive duration and a finite non-negative ops/s"
        );
        elapsed = elapsed.saturating_add(window.seconds);
        if window.ops_per_sec + f64::EPSILON >= floor {
            sustained = sustained.saturating_add(window.seconds);
            if sustained >= TTB_SUSTAIN_SECONDS {
                return Ok(TtbReport::Reached { seconds: elapsed });
            }
        } else {
            sustained = 0;
        }
    }
    Ok(TtbReport::NotReached {
        reason: format!(
            "post-recovery warp windows did not sustain >={}% of baseline ops/s for {TTB_SUSTAIN_SECONDS}s",
            (TTB_BASELINE_RATIO * 100.0).round()
        ),
    })
}

pub(crate) fn node_ready_lag_for_iochaos() -> NodeReadyLag {
    NodeReadyLag::NotApplicable {
        reason: "warp-under-chaos injects IOChaos EIO on one volume and does not stop a node; node ready lag is a pod-restart power-loss measurement and is not produced by this campaign".to_string(),
    }
}

pub(crate) fn assemble_metrics(
    scenario: &str,
    baseline: &WarpWindow,
    degraded: &WarpWindow,
    recovery_windows: &[RecoveryWindowRecord],
) -> Result<WarpPowerLossMetrics> {
    Ok(WarpPowerLossMetrics {
        schema_version: WARP_METRICS_SCHEMA_VERSION,
        scenario: scenario.to_string(),
        baseline_ops_per_sec: baseline.ops_per_sec,
        degraded_ops_per_sec: degraded.ops_per_sec,
        drop_percent: drop_percent(baseline.ops_per_sec, degraded.ops_per_sec)?,
        fault_window_error_percent: degraded.error_percent,
        node_ready_lag: node_ready_lag_for_iochaos(),
        ttb_to_90_percent_baseline: evaluate_ttb(baseline.ops_per_sec, recovery_windows)?,
        recovery_windows: recovery_windows.to_vec(),
        peer_compare: PEER_COMPARE_NOT_IN_CI.to_string(),
        notes: vec![
            "baseline_ops_per_sec is an in-run Warp window taken before the fault is applied".to_string(),
            "degraded_ops_per_sec and fault_window_error_percent are the Warp window while the fault is active".to_string(),
            "ttb_to_90_percent_baseline uses post-recovery 10s Warp windows and requires three consecutive windows at or above 90% of baseline; NOT_REACHED means those windows were sampled and the bar was not held".to_string(),
            "peer A/B against MinIO or Pigsty SILO is an optional offline lab procedure and is not executed in CI".to_string(),
        ],
    })
}

pub(crate) fn validate_success_metrics(raw: &str, scenario: &str) -> Result<()> {
    let metrics: WarpPowerLossMetrics =
        serde_json::from_str(raw).context("decode warp-powerloss-metrics.json")?;
    ensure!(
        metrics.schema_version == WARP_METRICS_SCHEMA_VERSION,
        "warp-powerloss-metrics.json schema_version must be {WARP_METRICS_SCHEMA_VERSION}"
    );
    ensure!(
        metrics.scenario == scenario,
        "warp-powerloss-metrics.json scenario does not match the run"
    );
    ensure!(
        metrics.baseline_ops_per_sec.is_finite() && metrics.baseline_ops_per_sec > 0.0,
        "warp-powerloss-metrics.json baseline_ops_per_sec must be positive"
    );
    ensure!(
        metrics.degraded_ops_per_sec.is_finite() && metrics.degraded_ops_per_sec >= 0.0,
        "warp-powerloss-metrics.json degraded_ops_per_sec must be finite and non-negative"
    );
    ensure!(
        (metrics.fault_window_error_percent.is_finite())
            && (0.0..=100.0).contains(&metrics.fault_window_error_percent),
        "warp-powerloss-metrics.json fault_window_error_percent must be in 0..=100"
    );
    let expected_drop = drop_percent(metrics.baseline_ops_per_sec, metrics.degraded_ops_per_sec)?;
    ensure!(
        (metrics.drop_percent - expected_drop).abs() <= 0.02,
        "warp-powerloss-metrics.json drop_percent does not match baseline and degraded ops/s"
    );
    let expected_ttb = evaluate_ttb(metrics.baseline_ops_per_sec, &metrics.recovery_windows)?;
    ensure!(
        metrics.ttb_to_90_percent_baseline == expected_ttb,
        "warp-powerloss-metrics.json ttb_to_90_percent_baseline does not match recovery_windows"
    );
    ensure!(
        matches!(
            metrics.ttb_to_90_percent_baseline,
            TtbReport::Reached { .. } | TtbReport::NotReached { .. }
        ),
        "successful warp-under-chaos must record REACHED or NOT_REACHED time-to-baseline"
    );
    ensure!(
        metrics.node_ready_lag == node_ready_lag_for_iochaos(),
        "warp-powerloss-metrics.json node_ready_lag does not match the IOChaos campaign contract"
    );
    ensure!(
        metrics.peer_compare == PEER_COMPARE_NOT_IN_CI,
        "warp-powerloss-metrics.json peer_compare must stay not-in-ci"
    );
    ensure!(
        metrics
            .notes
            .iter()
            .any(|note| note.contains("offline lab")),
        "warp-powerloss-metrics.json must record that peer A/B is offline"
    );
    Ok(())
}

fn round2(value: f64) -> f64 {
    (value * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"
Operation: GET
* Average: 1.00 MiB/s, 100.00 obj/s
* Errors: 0.00%
Operation: PUT
* Average: 2.00 MiB/s, 50.00 obj/s
* Errors: 10.00%
"#;

    #[test]
    fn warp_stdout_parser_weights_error_percent_by_ops() {
        let window = parse_warp_stdout(REPORT).expect("report");
        assert_eq!(window.ops_per_sec, 150.0);
        assert_eq!(window.error_percent, 3.33);
    }

    #[test]
    fn ttb_reaches_after_three_healthy_windows_and_rejects_a_dip() {
        let healthy = RecoveryWindowRecord {
            seconds: 10,
            ops_per_sec: 95.0,
        };
        let reached =
            evaluate_ttb(100.0, &[healthy.clone(), healthy.clone(), healthy.clone()]).expect("ttb");
        assert_eq!(reached, TtbReport::Reached { seconds: 30 });

        let dipped = RecoveryWindowRecord {
            seconds: 10,
            ops_per_sec: 50.0,
        };
        let not_reached = evaluate_ttb(
            100.0,
            &[
                healthy.clone(),
                healthy.clone(),
                dipped,
                healthy.clone(),
                healthy,
            ],
        )
        .expect("ttb");
        assert!(matches!(not_reached, TtbReport::NotReached { .. }));
    }

    #[test]
    fn success_metrics_reject_a_claimed_ttb_the_windows_do_not_support() {
        let baseline = WarpWindow {
            ops_per_sec: 100.0,
            error_percent: 0.0,
        };
        let degraded = WarpWindow {
            ops_per_sec: 40.0,
            error_percent: 12.5,
        };
        let windows = vec![RecoveryWindowRecord {
            seconds: 10,
            ops_per_sec: 20.0,
        }];
        let metrics =
            assemble_metrics("warp-under-chaos", &baseline, &degraded, &windows).expect("metrics");
        assert_eq!(metrics.drop_percent, 60.0);
        assert!(matches!(
            metrics.ttb_to_90_percent_baseline,
            TtbReport::NotReached { .. }
        ));
        let mut raw = serde_json::to_value(&metrics).expect("json");
        raw["ttbTo90PercentBaseline"] = serde_json::json!({"status": "REACHED", "seconds": 10});
        let error = validate_success_metrics(&raw.to_string(), "warp-under-chaos")
            .expect_err("inflated ttb");
        assert!(error.to_string().contains("ttb_to_90_percent_baseline"));
    }

    #[test]
    fn empty_warp_report_is_rejected() {
        assert!(parse_warp_stdout("warp finished\n").is_err());
    }

    #[test]
    fn zero_baseline_cannot_invent_a_drop_percent() {
        assert!(drop_percent(0.0, 1.0).is_err());
    }
}
