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

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use std::{cmp::Reverse, fs, io::Read, path::Path};
use time::{OffsetDateTime, UtcOffset, format_description::well_known::Rfc3339};

use super::runs::ProcessIdentity;
use crate::fault::console::{ConsoleSnapshot, build_console_snapshot};

const MAX_RECORD_BYTES: u64 = 64 * 1024;
const MAX_SUMMARY_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RUN_ENTRIES: usize = 10_000;
const MAX_PAGE_SIZE: usize = 100;

/// Small, credential-free history entry. `root` is the canonical run directory.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunIndexEntry {
    pub schema_version: u32,
    pub id: String,
    pub kind: String,
    pub target: String,
    pub started_at: String,
    #[serde(default)]
    pub finished_at: Option<String>,
    pub state: String,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub result: String,
    pub artifacts: String,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub process: Option<ProcessIdentity>,
    #[serde(default)]
    pub worker_process: Option<ProcessIdentity>,
    #[serde(default)]
    pub root: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunFilter {
    pub kind: Option<String>,
    pub result: Option<String>,
    /// Inclusive UTC date (YYYY-MM-DD).
    pub since: Option<String>,
    /// Inclusive UTC date (YYYY-MM-DD).
    pub until: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunPage {
    pub runs: Vec<RunIndexEntry>,
    pub total: usize,
    pub offset: usize,
    pub limit: usize,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunReport {
    pub root: String,
    pub artifact_root: String,
    pub record: Option<RunIndexEntry>,
    pub kind: String,
    pub result: String,
    /// The runner's own verdict, independent of the outer process lifecycle.
    pub artifact_result: Option<String>,
    pub summary: Option<Value>,
    pub failure: Option<Value>,
    pub cleanup: Option<Value>,
    pub fault: Option<ConsoleSnapshot>,
    pub warnings: Vec<String>,
}

pub fn list_runs(root: impl AsRef<Path>, offset: usize, limit: usize) -> Result<RunPage> {
    list_runs_filtered(root, &RunFilter::default(), offset, limit)
}

pub fn list_runs_filtered(
    root: impl AsRef<Path>,
    filter: &RunFilter,
    offset: usize,
    limit: usize,
) -> Result<RunPage> {
    ensure!(
        (1..=MAX_PAGE_SIZE).contains(&limit),
        "page limit must be between 1 and {MAX_PAGE_SIZE}"
    );
    for date in [&filter.since, &filter.until].into_iter().flatten() {
        time::Date::parse(
            date,
            time::macros::format_description!("[year]-[month]-[day]"),
        )
        .context("history dates must use YYYY-MM-DD")?;
    }
    if !root.as_ref().try_exists()? {
        return Ok(RunPage {
            runs: Vec::new(),
            total: 0,
            offset,
            limit,
            warnings: Vec::new(),
        });
    }
    let root = fs::canonicalize(root.as_ref()).context("open run history directory")?;
    let mut runs = Vec::new();
    let mut warnings = Vec::new();
    if root.join("record.json").exists() {
        runs.push(read_record(&root)?);
    } else {
        for (count, entry) in fs::read_dir(&root)?.enumerate() {
            ensure!(
                count < MAX_RUN_ENTRIES,
                "run history exceeds {MAX_RUN_ENTRIES} entries; select a smaller history directory"
            );
            let entry = entry?;
            if !entry.file_type()?.is_dir() || !entry.path().join("record.json").exists() {
                continue;
            }
            match read_record(&entry.path()) {
                Ok(record) => runs.push(record),
                Err(error) => {
                    warnings.push(format!("{}: {error}", entry.file_name().to_string_lossy()))
                }
            }
        }
    }
    runs.retain(|run| {
        filter.kind.as_ref().is_none_or(|kind| &run.kind == kind)
            && filter
                .result
                .as_ref()
                .is_none_or(|result| &run.result == result)
            && filter.since.as_ref().is_none_or(|since| {
                run.started_at
                    .get(..10)
                    .is_some_and(|date| date >= since.as_str())
            })
            && filter.until.as_ref().is_none_or(|until| {
                run.started_at
                    .get(..10)
                    .is_some_and(|date| date <= until.as_str())
            })
    });
    runs.sort_by_cached_key(|run| {
        (
            Reverse(
                OffsetDateTime::parse(&run.started_at, &Rfc3339)
                    .map(|at| at.unix_timestamp_nanos())
                    .unwrap_or(i128::MIN),
            ),
            run.id.clone(),
        )
    });
    let total = runs.len();
    let runs = runs.into_iter().skip(offset).take(limit).collect();
    Ok(RunPage {
        runs,
        total,
        offset,
        limit,
        warnings,
    })
}

fn read_record(root: &Path) -> Result<RunIndexEntry> {
    let mut record: RunIndexEntry =
        read_json(root, "record.json", MAX_RECORD_BYTES)?.context("run record is missing")?;
    ensure!(
        record.schema_version == 1,
        "unsupported run record schema {}",
        record.schema_version
    );
    ensure!(!record.id.is_empty(), "run record id is empty");
    ensure!(
        matches!(record.kind.as_str(), "fault" | "protocol" | "mint"),
        "unsupported run kind {}",
        record.kind
    );
    ensure!(
        record.artifacts == "artifacts",
        "run artifacts must use the artifacts directory"
    );
    record.started_at = OffsetDateTime::parse(&record.started_at, &Rfc3339)
        .context("invalid run start time")?
        .to_offset(UtcOffset::UTC)
        .format(&Rfc3339)?;
    record.root = fs::canonicalize(root)?.display().to_string();
    if record.result.is_empty() {
        record.result = match record.state.as_str() {
            "preparing" | "running" => record.state.clone(),
            _ => "incomplete".into(),
        };
    }
    if matches!(record.state.as_str(), "preparing" | "running") {
        let state = match record
            .process
            .as_ref()
            .and_then(ProcessIdentity::is_running)
        {
            Some(true) => record.state.as_str(),
            Some(false)
                if record
                    .worker_process
                    .as_ref()
                    .and_then(ProcessIdentity::is_running)
                    == Some(true) =>
            {
                "unknown"
            }
            Some(false) => "incomplete",
            None => "unknown",
        }
        .to_string();
        record.state = state.clone();
        record.result = state;
    }
    Ok(record)
}

/// Reads published runner conclusions without recomputing case verdicts.
pub fn read_run_report(root: impl AsRef<Path>) -> Result<RunReport> {
    let root = fs::canonicalize(root.as_ref()).context("open run directory")?;
    ensure!(root.is_dir(), "run root must be a directory");
    let record = if root.join("record.json").exists() {
        Some(read_record(&root)?)
    } else {
        None
    };
    let artifact_root = record
        .as_ref()
        .map_or_else(|| root.clone(), |record| root.join(&record.artifacts));
    let kind = record
        .as_ref()
        .map(|record| record.kind.clone())
        .unwrap_or_else(|| {
            if artifact_root.join("mint-session-summary.json").exists() {
                "mint"
            } else if artifact_root.join("protocol-suite-summary.json").exists() {
                "protocol"
            } else {
                "fault"
            }
            .into()
        });
    let mut report = RunReport {
        root: root.display().to_string(),
        artifact_root: artifact_root.display().to_string(),
        record,
        kind,
        result: "incomplete".into(),
        artifact_result: None,
        summary: None,
        failure: None,
        cleanup: None,
        fault: None,
        warnings: Vec::new(),
    };
    if artifact_root.exists() {
        let artifact_root = fs::canonicalize(&artifact_root)?;
        ensure!(
            artifact_root.starts_with(&root),
            "artifact directory is outside run root"
        );
        match report.kind.as_str() {
            "protocol" => {
                report.summary = read_json(
                    &artifact_root,
                    "protocol-suite-summary.json",
                    MAX_SUMMARY_BYTES,
                )?;
                report.failure = read_json(
                    &artifact_root,
                    "protocol-failure-summary.json",
                    MAX_SUMMARY_BYTES,
                )?;
                report.cleanup =
                    read_json(&artifact_root, "cleanup-report.json", MAX_SUMMARY_BYTES)?;
                report.artifact_result = summary_result(&report.summary, "status");
            }
            "mint" => {
                report.summary = read_json(
                    &artifact_root,
                    "mint-session-summary.json",
                    MAX_SUMMARY_BYTES,
                )?;
                report.cleanup = read_json(
                    &artifact_root,
                    "mint-cleanup-report.json",
                    MAX_SUMMARY_BYTES,
                )?;
                report.artifact_result = summary_result(&report.summary, "gateStatus");
                report.failure = report
                    .summary
                    .as_ref()
                    .and_then(|summary| summary.get("failureCodes"))
                    .filter(|codes| codes.as_array().is_some_and(|codes| !codes.is_empty()))
                    .map(|codes| serde_json::json!({ "failureCodes": codes }));
            }
            _ => {
                let snapshot = build_console_snapshot(&artifact_root)?;
                let session: Option<Value> =
                    read_json(&artifact_root, "fault-session.json", MAX_SUMMARY_BYTES)?;
                report.summary = read_json(
                    &artifact_root,
                    "fault-workflow-result.json",
                    MAX_SUMMARY_BYTES,
                )?;
                if report.summary.is_some() {
                    report.artifact_result = summary_result(&report.summary, "status");
                    report.cleanup = report
                        .summary
                        .as_ref()
                        .and_then(|summary| summary.get("cleanup"))
                        .map(|cleanup| serde_json::json!({ "status": cleanup }));
                } else if session.is_some() {
                    report.artifact_result = Some("incomplete".into());
                    report.warnings.push("The fault supervisor has not published its final execution and recovery result.".into());
                } else {
                    report.summary = read_json(
                        &artifact_root,
                        "qualification-result.json",
                        MAX_SUMMARY_BYTES,
                    )?;
                    if report.summary.is_some() {
                        report.artifact_result = summary_result(&report.summary, "outcome");
                    } else {
                        report.summary = snapshot
                            .suite_summary
                            .as_ref()
                            .map(|summary| summary.raw.clone());
                        report.artifact_result = summary_result(&report.summary, "status");
                    }
                }
                if let Some(session) = session.as_ref().filter(|session| {
                    session.get("status").and_then(Value::as_str) == Some("cleaned")
                }) {
                    let retained = session
                        .get("resources")
                        .and_then(Value::as_object)
                        .is_some_and(|resources| {
                            resources
                                .values()
                                .any(|resource| resource["state"] == "retained")
                        });
                    report.cleanup = Some(serde_json::json!({
                        "status": if retained { "retained" } else { "cleaned" }
                    }));
                }
                report.fault = Some(snapshot);
            }
        }
    }
    report.result = match &report.record {
        Some(record) if record.state != "finished" => record.result.clone(),
        Some(record) if record.exit_code.is_some_and(|code| code != 0) => "failed".into(),
        Some(record) => report
            .artifact_result
            .clone()
            .unwrap_or_else(|| record.result.clone()),
        None => report
            .artifact_result
            .clone()
            .unwrap_or_else(|| "incomplete".into()),
    };
    if report.failure.is_none() {
        report.failure = report
            .record
            .as_ref()
            .and_then(|record| record.error.as_ref())
            .map(|error| serde_json::json!({ "message": error }));
    }
    if report.artifact_result.is_none() {
        report
            .warnings
            .push("No final runner summary is available.".into());
    }
    Ok(report)
}

fn summary_result(summary: &Option<Value>, key: &str) -> Option<String> {
    summary.as_ref()?.get(key)?.as_str().map(|status| {
        if status == "succeeded" {
            "passed"
        } else {
            status
        }
        .to_string()
    })
}

fn read_json<T: DeserializeOwned>(root: &Path, name: &str, limit: u64) -> Result<Option<T>> {
    let path = root.join(name);
    if !path.try_exists()? {
        return Ok(None);
    }
    let path = fs::canonicalize(path)?;
    let canonical_root = fs::canonicalize(root)?;
    ensure!(
        path.starts_with(&canonical_root),
        "report file is outside run root: {name}"
    );
    ensure!(
        fs::metadata(&path)?.is_file(),
        "report must be a regular file: {name}"
    );
    let file = fs::File::open(&path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "report must be a regular file: {name}");
    ensure!(
        metadata.len() <= limit,
        "report {name} exceeds {limit} byte limit"
    );
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "report {name} exceeds {limit} byte limit"
    );
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse report {name}"))
        .map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn record(root: &Path, id: &str, kind: &str, result: &str) {
        fs::create_dir_all(root.join("artifacts")).unwrap();
        fs::write(root.join("record.json"), serde_json::to_vec(&json!({
            "schemaVersion": 1, "id": id, "kind": kind, "target": "lab", "startedAt": format!("2026-11-{id}T00:00:00Z"),
            "state": "finished", "exitCode": 0, "result": result, "artifacts": "artifacts"
        })).unwrap()).unwrap();
    }

    #[test]
    fn history_before_first_run_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("runs");
        assert_eq!(list_runs(&root, 0, 20).unwrap().total, 0);
        assert!(!root.exists());
    }

    #[test]
    fn history_filters_and_pages_without_reading_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        record(&dir.path().join("old"), "01", "fault", "passed");
        record(&dir.path().join("new"), "02", "protocol", "failed");
        fs::write(
            dir.path().join("new/artifacts/protocol-suite-summary.json"),
            "invalid JSON",
        )
        .unwrap();
        let page = list_runs(dir.path(), 0, 1).unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.runs[0].id, "02");
        let filter = RunFilter {
            kind: Some("fault".into()),
            since: Some("2026-11-01".into()),
            ..Default::default()
        };
        let page = list_runs_filtered(dir.path(), &filter, 0, 20).unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.runs[0].id, "01");
        assert!(
            list_runs_filtered(
                dir.path(),
                &RunFilter {
                    since: Some("invalid".into()),
                    ..Default::default()
                },
                0,
                20
            )
            .is_err()
        );
    }

    #[test]
    fn history_orders_fractional_timestamps_chronologically() {
        let dir = tempfile::tempdir().unwrap();
        for (id, started) in [
            ("01", "2026-11-01T00:00:00Z"),
            ("02", "2026-11-01T00:00:00.1Z"),
        ] {
            let root = dir.path().join(id);
            record(&root, id, "fault", "passed");
            let path = root.join("record.json");
            let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            value["startedAt"] = json!(started);
            fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        }
        assert_eq!(list_runs(dir.path(), 0, 20).unwrap().runs[0].id, "02");
    }

    #[test]
    fn unconfirmed_supervisor_is_unknown_without_updating_the_record() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "fault", "running");
        let path = dir.path().join("record.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["state"] = json!("running");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        assert_eq!(
            list_runs(dir.path(), 0, 20).unwrap().runs[0].result,
            "unknown"
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn supervisor_identity_distinguishes_running_exited_and_remote() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "fault", "running");
        let path = dir.path().join("record.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["state"] = json!("running");
        let mut identity = ProcessIdentity::current().unwrap();
        value["process"] = serde_json::to_value(&identity).unwrap();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read_run_report(dir.path()).unwrap().result, "running");
        identity.start_ticks = "mismatched-process".into();
        value["process"] = serde_json::to_value(&identity).unwrap();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read_run_report(dir.path()).unwrap().result, "incomplete");
        identity.boot_id = "different-host".into();
        value["process"] = serde_json::to_value(&identity).unwrap();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(read_run_report(dir.path()).unwrap().result, "unknown");
    }

    #[test]
    fn exit_zero_without_recorded_result_does_not_pass_history() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "protocol", "");
        assert_eq!(
            list_runs(dir.path(), 0, 20).unwrap().runs[0].result,
            "incomplete"
        );
    }

    #[test]
    fn preparation_failure_is_available_without_runner_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "protocol", "failed");
        let path = dir.path().join("record.json");
        let mut value: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["error"] = json!("missing endpoint");
        value["exitCode"] = json!(1);
        fs::write(path, serde_json::to_vec(&value).unwrap()).unwrap();
        fs::remove_dir(dir.path().join("artifacts")).unwrap();
        let report = read_run_report(dir.path()).unwrap();
        assert_eq!(report.result, "failed");
        assert_eq!(report.failure.unwrap()["message"], "missing endpoint");
    }

    #[test]
    fn native_summary_failure_overrides_passing_cases() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "protocol", "failed");
        fs::write(
            dir.path().join("artifacts/protocol-suite-summary.json"),
            r#"{"status":"failed","caseResults":[{"outcome":"passed"}]}"#,
        )
        .unwrap();
        let report = read_run_report(dir.path()).unwrap();
        assert_eq!(report.result, "failed");
        assert_eq!(report.artifact_result.as_deref(), Some("failed"));
    }

    #[test]
    fn mint_uses_session_gate_and_retains_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "mint", "failed");
        fs::write(
            dir.path().join("artifacts/mint-session-summary.json"),
            r#"{"gateStatus":"failed","mintGateStatus":"passed","teardownStatus":"failed"}"#,
        )
        .unwrap();
        assert_eq!(read_run_report(dir.path()).unwrap().result, "failed");
    }

    #[test]
    fn fault_supervisor_result_preserves_cleanup_failure() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "fault", "failed");
        fs::write(dir.path().join("artifacts/fault-workflow-result.json"), r#"{"status":"failed","execution":"passed","artifactValidation":"passed","cleanup":"failed"}"#).unwrap();
        fs::write(
            dir.path().join("artifacts/suite-summary.json"),
            r#"{"status":"succeeded","attempts":[],"failures":[]}"#,
        )
        .unwrap();
        let report = read_run_report(dir.path()).unwrap();
        assert_eq!(report.result, "failed");
        assert_eq!(report.cleanup.unwrap()["status"], "failed");
        assert_eq!(report.summary.unwrap()["execution"], "passed");
    }

    #[test]
    fn managed_fault_requires_the_supervisors_final_result() {
        let dir = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "fault", "passed");
        fs::write(
            dir.path().join("artifacts/suite-summary.json"),
            r#"{"status":"succeeded","attempts":[],"failures":[]}"#,
        )
        .unwrap();
        fs::write(
            dir.path().join("artifacts/fault-session.json"),
            r#"{"status":"cleaned"}"#,
        )
        .unwrap();
        let report = read_run_report(dir.path()).unwrap();
        assert_eq!(report.artifact_result.as_deref(), Some("incomplete"));
        assert_eq!(report.result, "incomplete");
        assert_eq!(report.cleanup.unwrap()["status"], "cleaned");
        assert!(report.summary.is_none());
    }

    #[test]
    fn manual_fault_cleanup_updates_cleanup_without_changing_the_test_result() {
        for (result, cleanup) in [("passed", "retained"), ("failed", "failed")] {
            let dir = tempfile::tempdir().unwrap();
            record(dir.path(), "01", "fault", result);
            let summary = json!({"status": result, "execution": "passed", "artifactValidation": "passed", "cleanup": cleanup});
            fs::write(
                dir.path().join("artifacts/fault-workflow-result.json"),
                serde_json::to_vec(&summary).unwrap(),
            )
            .unwrap();
            fs::write(
                dir.path().join("artifacts/fault-session.json"),
                r#"{"status":"cleaned"}"#,
            )
            .unwrap();
            let report = read_run_report(dir.path()).unwrap();
            assert_eq!(report.result, result);
            assert_eq!(report.cleanup.unwrap()["status"], "cleaned");
            assert_eq!(report.summary.unwrap(), summary);
        }
    }

    #[test]
    fn completed_fault_cleanup_reports_retained_resources() {
        for result in ["passed", "failed"] {
            let dir = tempfile::tempdir().unwrap();
            record(dir.path(), "01", "fault", result);
            let summary = json!({"status": result, "execution": result, "cleanup": "cleaned"});
            fs::write(
                dir.path().join("artifacts/fault-workflow-result.json"),
                serde_json::to_vec(&summary).unwrap(),
            )
            .unwrap();
            fs::write(
                dir.path().join("artifacts/fault-session.json"),
                r#"{"status":"cleaned","resources":{"namespace":{"state":"retained"},"secret":{"state":"retained"},"tenant":{"state":"deleted"}}}"#,
            )
            .unwrap();
            let report = read_run_report(dir.path()).unwrap();
            assert_eq!(report.result, result);
            assert_eq!(report.cleanup.unwrap()["status"], "retained");
            assert_eq!(report.summary.unwrap(), summary);
        }
    }

    #[test]
    fn qualification_uses_its_published_terminal_result() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("qualification-result.json"),
            r#"{"schemaVersion":1,"outcome":"interrupted","exitCode":130}"#,
        )
        .unwrap();
        let report = read_run_report(dir.path()).unwrap();
        assert_eq!(report.result, "interrupted");
        assert_eq!(report.summary.unwrap()["exitCode"], 130);
    }

    #[test]
    fn legacy_fault_root_retains_runner_verdict() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("suite-summary.json"),
            r#"{"suite":"smoke","status":"failed","attempts":[],"failures":[]}"#,
        )
        .unwrap();
        let report = read_run_report(dir.path()).unwrap();
        assert_eq!(report.result, "failed");
        assert!(report.fault.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn report_rejects_escaping_symlinks_and_oversized_records() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        record(dir.path(), "01", "protocol", "passed");
        fs::write(
            outside.path().join("summary.json"),
            r#"{"status":"passed"}"#,
        )
        .unwrap();
        std::os::unix::fs::symlink(
            outside.path().join("summary.json"),
            dir.path().join("artifacts/protocol-suite-summary.json"),
        )
        .unwrap();
        assert!(
            read_run_report(dir.path())
                .unwrap_err()
                .to_string()
                .contains("outside")
        );
        fs::write(
            dir.path().join("record.json"),
            "x".repeat(MAX_RECORD_BYTES as usize + 1),
        )
        .unwrap();
        assert!(
            list_runs(dir.path(), 0, 20)
                .unwrap_err()
                .to_string()
                .contains("byte limit")
        );
    }
}
