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

use anyhow::{Result, ensure};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio::time::{sleep as async_sleep, timeout};

use crate::fault::{
    history::{OperationKind, OperationOutcome, OperationRecord, Recorder},
    workload::{GetObjectResult, ObjectSpec, S3WorkloadClient, sha256_hex},
};

const MAX_WARNING_SAMPLES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerReport {
    pub scenario: String,
    pub run_id: String,
    pub committed_puts: usize,
    pub expected_live_objects: usize,
    pub verified_live_objects: usize,
    pub missing_committed_objects: Vec<String>,
    pub unavailable_committed_objects: Vec<String>,
    pub unknown_committed_read_failures: Vec<String>,
    pub hash_mismatches: Vec<String>,
    pub successful_corrupted_reads: Vec<String>,
    pub unexpected_visible_deleted_objects: Vec<String>,
    pub unknown_writes_materialized: Vec<String>,
    pub list_history_warning_count: usize,
    pub final_list_warning_count: usize,
    pub list_history_warnings: Vec<String>,
    pub list_warnings: Vec<String>,
    pub final_listed_objects: Option<usize>,
    pub tenant_recovered: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStabilityClassification {
    DataCorruption,
    CommittedObjectUnavailable,
    RecoveryTailReadLatency,
    HarnessError,
}

impl RecoveryStabilityClassification {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DataCorruption => "data_corruption",
            Self::CommittedObjectUnavailable => "committed_object_unavailable",
            Self::RecoveryTailReadLatency => "recovery_tail_read_latency",
            Self::HarnessError => "harness_error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStabilityReport {
    pub immediate_passed: bool,
    pub reread_attempted_keys: Vec<String>,
    pub reread_recovered_keys: Vec<String>,
    pub still_unavailable_keys: Vec<String>,
    pub hash_mismatches: Vec<String>,
    #[serde(default)]
    pub data_corruption_evidence: Vec<String>,
    pub harness_errors: Vec<String>,
    pub max_recovery_seconds: u64,
    pub classification: RecoveryStabilityClassification,
}

impl RecoveryStabilityReport {
    pub(crate) fn harness_error(message: impl Into<String>, max_recovery: Duration) -> Self {
        Self {
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            harness_errors: vec![message.into()],
            max_recovery_seconds: max_recovery.as_secs(),
            classification: RecoveryStabilityClassification::HarnessError,
        }
    }
}

impl CheckerReport {
    pub fn require_success(&self) -> Result<()> {
        ensure!(
            self.passed,
            "fault checker failed for scenario {} run {}: {}",
            self.scenario,
            self.run_id,
            serde_json::to_string_pretty(self)?
        );
        Ok(())
    }
}

pub async fn check_s3_history(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    tenant_recovered: bool,
    concurrency: usize,
) -> Result<CheckerReport> {
    let initial_records = recorder.records();
    let model = object_model(&initial_records);
    let read_anomalies = successful_read_anomalies(&initial_records);
    let list_history_warnings = list_history_warnings(&initial_records);
    let mut report = CheckerReport {
        scenario: recorder.scenario(),
        run_id: recorder.run_id(),
        committed_puts: model.committed_writes,
        expected_live_objects: model.live.len(),
        verified_live_objects: 0,
        missing_committed_objects: Vec::new(),
        unavailable_committed_objects: Vec::new(),
        unknown_committed_read_failures: Vec::new(),
        hash_mismatches: Vec::new(),
        successful_corrupted_reads: read_anomalies.corrupted_reads,
        unexpected_visible_deleted_objects: read_anomalies.visible_deleted_objects,
        unknown_writes_materialized: Vec::new(),
        list_history_warning_count: list_history_warnings.total_count,
        final_list_warning_count: 0,
        list_history_warnings: list_history_warnings.samples,
        list_warnings: Vec::new(),
        final_listed_objects: None,
        tenant_recovered,
        passed: false,
    };

    let mut committed_results =
        stream::iter(model.live.clone().into_iter().map(|(key, expected)| {
            let s3 = s3.clone();
            let recorder = recorder.clone();
            async move {
                let get = s3.get_object_result(&key, &recorder).await?;
                Ok::<_, anyhow::Error>((key, expected, get))
            }
        }))
        .buffer_unordered(concurrency);
    while let Some(result) = committed_results.next().await {
        let (key, expected, get) = result?;
        evaluate_committed_get(&mut report, key, &expected, get);
    }

    let mut unknown_results =
        stream::iter(model.unknown_writes.into_iter().map(|(key, attempted)| {
            let s3 = s3.clone();
            let recorder = recorder.clone();
            async move {
                let get = s3.get_object_result(&key, &recorder).await?;
                Ok::<_, anyhow::Error>((key, attempted, get))
            }
        }))
        .buffer_unordered(concurrency);
    while let Some(result) = unknown_results.next().await {
        let (key, attempted, get) = result?;
        if let Some(body) = get.body {
            let actual_hash = sha256_hex(&body);
            report.unknown_writes_materialized.push(format!(
                "{key}: attempted {}, got {actual_hash}",
                attempted.sha256
            ));
        }
    }

    let run_id = recorder.run_id();
    let prefix = ObjectSpec::key_prefix(&run_id);
    let mut final_list_warnings = WarningSummary::default();
    match s3.list_prefix(&prefix, recorder).await? {
        Some(keys) => {
            report.final_listed_objects = Some(keys.len());
            let listed = keys.into_iter().collect::<BTreeSet<_>>();
            for key in model.live.keys() {
                if !listed.contains(key) {
                    final_list_warnings.push(format!(
                        "LIST prefix {prefix} did not include expected live key {key}"
                    ));
                }
            }
            for key in model.deleted {
                if listed.contains(&key) {
                    final_list_warnings
                        .push(format!("LIST prefix {prefix} included deleted key {key}"));
                }
            }
        }
        None => final_list_warnings.push(format!("LIST prefix {prefix} did not complete")),
    }
    report.final_list_warning_count = final_list_warnings.total_count;
    report.list_warnings = final_list_warnings.samples;

    report.missing_committed_objects.sort();
    report.unavailable_committed_objects.sort();
    report.unknown_committed_read_failures.sort();
    report.hash_mismatches.sort();
    report.unknown_writes_materialized.sort();
    report.unexpected_visible_deleted_objects.sort();
    report.list_history_warnings.sort();
    report.list_warnings.sort();
    report.passed = report.tenant_recovered
        && report.missing_committed_objects.is_empty()
        && report.unavailable_committed_objects.is_empty()
        && report.unknown_committed_read_failures.is_empty()
        && report.hash_mismatches.is_empty()
        && report.successful_corrupted_reads.is_empty()
        && report.unexpected_visible_deleted_objects.is_empty()
        && report.final_list_warning_count == 0;

    Ok(report)
}

pub async fn recovery_stability_reread(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    immediate_report: &CheckerReport,
    immediate_record_start: usize,
    concurrency: usize,
    max_recovery: Duration,
) -> Result<RecoveryStabilityReport> {
    let records = recorder.records();
    let model = object_model(&records[..immediate_record_start.min(records.len())]);
    let immediate_records = records
        .get(immediate_record_start.min(records.len())..)
        .unwrap_or_default();
    let attempted_keys = recovery_tail_candidate_keys(immediate_records, &model);
    let mut hash_mismatches = immediate_report.hash_mismatches.clone();
    hash_mismatches.extend(immediate_report.successful_corrupted_reads.iter().cloned());
    let data_corruption_evidence = immediate_data_corruption_evidence(immediate_report);
    let mut report = RecoveryStabilityReport {
        immediate_passed: immediate_report.passed,
        reread_attempted_keys: attempted_keys.clone(),
        reread_recovered_keys: Vec::new(),
        still_unavailable_keys: immediate_still_unavailable_keys(immediate_report, &attempted_keys),
        hash_mismatches,
        data_corruption_evidence,
        harness_errors: Vec::new(),
        max_recovery_seconds: max_recovery.as_secs(),
        classification: classify_without_reread(immediate_report),
    };

    if immediate_report.passed || attempted_keys.is_empty() || max_recovery.is_zero() {
        finish_recovery_stability_report(&mut report, immediate_report);
        return Ok(report);
    }

    let expected = attempted_keys
        .iter()
        .filter_map(|key| {
            model
                .live
                .get(key)
                .cloned()
                .map(|expected| (key.clone(), expected))
        })
        .collect::<BTreeMap<_, _>>();
    let mut pending = expected.keys().cloned().collect::<BTreeSet<_>>();
    let deadline = Instant::now() + max_recovery;
    let mut delay = Duration::from_secs(1);
    let concurrency = concurrency.max(1);

    'retry: while !pending.is_empty() && report.hash_mismatches.is_empty() {
        if Instant::now() >= deadline {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        async_sleep(delay.min(remaining)).await;
        delay = delay.saturating_mul(2);
        if Instant::now() >= deadline {
            break;
        }
        let pending_keys = pending.iter().cloned().collect::<Vec<_>>();
        let mut batch = stream::iter(pending_keys.into_iter().map(|key| {
            let s3 = s3.clone();
            let recorder = recorder.clone();
            let expected = expected.get(&key).expect("pending key").clone();
            async move {
                let get = s3.get_object_result(&key, &recorder).await;
                (key, expected, get)
            }
        }))
        .buffer_unordered(concurrency);

        while let Some((key, expected, get)) = {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break 'retry;
            }
            match timeout(remaining, batch.next()).await {
                Ok(item) => item,
                Err(_) => break 'retry,
            }
        } {
            match get {
                Ok(get) if committed_get_matches(&expected, &get) => {
                    pending.remove(&key);
                    report.reread_recovered_keys.push(key);
                }
                Ok(get) => {
                    if let Some(body) = get.body {
                        report
                            .hash_mismatches
                            .push(hash_mismatch_message(&key, &expected, &body));
                        pending.remove(&key);
                    }
                }
                Err(error) => {
                    report.still_unavailable_keys.push(key);
                    report.classification = RecoveryStabilityClassification::HarnessError;
                    report
                        .harness_errors
                        .push(format!("reread failed: {error}"));
                    pending.clear();
                    break;
                }
            }
        }

        if pending.is_empty() || !report.hash_mismatches.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
    }

    report.still_unavailable_keys.extend(pending);
    report.reread_recovered_keys.sort();
    report.still_unavailable_keys.sort();
    report.hash_mismatches.sort();
    report.data_corruption_evidence.sort();
    report.harness_errors.sort();
    finish_recovery_stability_report(&mut report, immediate_report);
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedObject {
    sha256: String,
    size_bytes: usize,
}

#[derive(Debug, Default)]
struct ObjectModel {
    live: BTreeMap<String, ExpectedObject>,
    deleted: BTreeSet<String>,
    unknown_writes: BTreeMap<String, ExpectedObject>,
    committed_writes: usize,
}

#[derive(Debug, Default)]
struct ReadAnomalies {
    corrupted_reads: Vec<String>,
    visible_deleted_objects: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct WarningSummary {
    total_count: usize,
    samples: Vec<String>,
}

impl WarningSummary {
    fn push(&mut self, warning: String) {
        self.total_count += 1;
        if self.samples.len() < MAX_WARNING_SAMPLES {
            self.samples.push(warning);
        }
    }
}

fn evaluate_committed_get(
    report: &mut CheckerReport,
    key: String,
    expected: &ExpectedObject,
    get: GetObjectResult,
) {
    match (get.outcome, get.body) {
        (OperationOutcome::Ok, Some(body)) => {
            let actual_hash = sha256_hex(&body);
            if actual_hash != expected.sha256 || body.len() != expected.size_bytes {
                report.hash_mismatches.push(format!(
                    "{key}: expected {} ({} bytes), got {actual_hash} ({} bytes)",
                    expected.sha256,
                    expected.size_bytes,
                    body.len()
                ));
            } else {
                report.verified_live_objects += 1;
            }
        }
        (OperationOutcome::NotFound, None) => report.missing_committed_objects.push(key),
        (OperationOutcome::Failed | OperationOutcome::Timeout, None) => report
            .unavailable_committed_objects
            .push(read_failure_message(
                &key,
                get.outcome,
                get.http_status,
                get.error.as_deref(),
            )),
        (OperationOutcome::Unknown, None) | (OperationOutcome::Ok, None) => report
            .unknown_committed_read_failures
            .push(read_failure_message(
                &key,
                get.outcome,
                get.http_status,
                get.error.as_deref(),
            )),
        (outcome, Some(body)) => report.unknown_committed_read_failures.push(format!(
            "{}: unexpected body for {:?} ({} bytes)",
            key,
            outcome,
            body.len()
        )),
    }
}

fn read_failure_message(
    key: &str,
    outcome: OperationOutcome,
    http_status: Option<u16>,
    error: Option<&str>,
) -> String {
    let status = http_status
        .map(|status| format!(" status={status}"))
        .unwrap_or_default();
    let error = error
        .map(|error| format!(" error={error:?}"))
        .unwrap_or_default();
    format!("{key}: outcome={outcome:?}{status}{error}")
}

fn recovery_tail_candidate_keys(
    immediate_records: &[OperationRecord],
    model: &ObjectModel,
) -> Vec<String> {
    immediate_records
        .iter()
        .filter_map(|record| {
            let key = record.key.as_ref()?;
            (record.kind == OperationKind::Get
                && model.live.contains_key(key)
                && is_recovery_tail_read_failure(
                    record.outcome,
                    record.http_status,
                    record.error.as_deref(),
                ))
            .then(|| key.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

fn is_recovery_tail_read_failure(
    outcome: OperationOutcome,
    http_status: Option<u16>,
    error: Option<&str>,
) -> bool {
    if !matches!(
        outcome,
        OperationOutcome::Timeout | OperationOutcome::Unknown
    ) || http_status != Some(200)
    {
        return false;
    }
    let Some(error) = error else {
        return false;
    };
    let error = error.to_ascii_lowercase();
    error.contains("body read timed out")
        || error.contains("body read timeout")
        || error.contains("streaming error")
}

fn committed_get_matches(expected: &ExpectedObject, get: &GetObjectResult) -> bool {
    get.outcome == OperationOutcome::Ok
        && get.body.as_deref().is_some_and(|body| {
            body.len() == expected.size_bytes && sha256_hex(body) == expected.sha256
        })
}

fn hash_mismatch_message(key: &str, expected: &ExpectedObject, body: &[u8]) -> String {
    let actual_hash = sha256_hex(body);
    format!(
        "{key}: expected {} ({} bytes), got {actual_hash} ({} bytes)",
        expected.sha256,
        expected.size_bytes,
        body.len()
    )
}

fn classify_without_reread(report: &CheckerReport) -> RecoveryStabilityClassification {
    if !report.hash_mismatches.is_empty()
        || !report.successful_corrupted_reads.is_empty()
        || !report.unexpected_visible_deleted_objects.is_empty()
        || !report.unknown_writes_materialized.is_empty()
        || report.final_list_warning_count > 0
    {
        RecoveryStabilityClassification::DataCorruption
    } else if !report.missing_committed_objects.is_empty()
        || !report.unavailable_committed_objects.is_empty()
        || !report.unknown_committed_read_failures.is_empty()
    {
        RecoveryStabilityClassification::CommittedObjectUnavailable
    } else {
        RecoveryStabilityClassification::HarnessError
    }
}

fn immediate_data_corruption_evidence(report: &CheckerReport) -> Vec<String> {
    let mut evidence = Vec::new();
    evidence.extend(
        report
            .unexpected_visible_deleted_objects
            .iter()
            .map(|item| format!("unexpected_visible_deleted_object: {item}")),
    );
    evidence.extend(
        report
            .unknown_writes_materialized
            .iter()
            .map(|item| format!("unknown_write_materialized: {item}")),
    );
    evidence.extend(
        report
            .list_warnings
            .iter()
            .map(|item| format!("final_list_warning: {item}")),
    );
    if report.final_list_warning_count > report.list_warnings.len() {
        evidence.push(format!(
            "final_list_warning_count: {} total, {} sampled",
            report.final_list_warning_count,
            report.list_warnings.len()
        ));
    }
    evidence.sort();
    evidence
}

fn immediate_still_unavailable_keys(
    report: &CheckerReport,
    reread_attempted_keys: &[String],
) -> Vec<String> {
    let attempted = reread_attempted_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut keys = report
        .missing_committed_objects
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    for failure in report
        .unavailable_committed_objects
        .iter()
        .chain(report.unknown_committed_read_failures.iter())
    {
        let key = read_failure_key(failure);
        if !attempted.contains(key.as_str()) {
            keys.insert(key);
        }
    }
    keys.into_iter().collect()
}

fn read_failure_key(message: &str) -> String {
    message
        .split_once(':')
        .map(|(key, _)| key)
        .unwrap_or(message)
        .to_string()
}

fn finish_recovery_stability_report(
    report: &mut RecoveryStabilityReport,
    immediate_report: &CheckerReport,
) {
    if !report.hash_mismatches.is_empty() || !report.data_corruption_evidence.is_empty() {
        report.classification = RecoveryStabilityClassification::DataCorruption;
        return;
    }
    if !report.harness_errors.is_empty() {
        report.classification = RecoveryStabilityClassification::HarnessError;
        return;
    }
    if !report.still_unavailable_keys.is_empty() {
        report.classification = RecoveryStabilityClassification::CommittedObjectUnavailable;
        return;
    }
    if !report.reread_attempted_keys.is_empty()
        && immediate_failures_are_only_reread_candidates(immediate_report, report)
    {
        report.classification = RecoveryStabilityClassification::RecoveryTailReadLatency;
        return;
    }
    report.classification = classify_without_reread(immediate_report);
}

fn immediate_failures_are_only_reread_candidates(
    immediate_report: &CheckerReport,
    recovery_report: &RecoveryStabilityReport,
) -> bool {
    immediate_report.tenant_recovered
        && immediate_report.missing_committed_objects.is_empty()
        && immediate_report.hash_mismatches.is_empty()
        && immediate_report.successful_corrupted_reads.is_empty()
        && immediate_report
            .unexpected_visible_deleted_objects
            .is_empty()
        && immediate_report.unknown_writes_materialized.is_empty()
        && immediate_report.final_list_warning_count == 0
        && immediate_report.unavailable_committed_objects.len()
            + immediate_report.unknown_committed_read_failures.len()
            == recovery_report.reread_attempted_keys.len()
        && recovery_report.reread_recovered_keys.len()
            == recovery_report.reread_attempted_keys.len()
}

fn object_model(records: &[OperationRecord]) -> ObjectModel {
    let mut model = ObjectModel::default();
    for record in records {
        apply_record_to_model(&mut model, record);
    }
    model
}

fn object_model_before(records: &[OperationRecord], started_at_ms: u64) -> ObjectModel {
    let mut model = ObjectModel::default();
    for record in records {
        if record.ended_at_ms < started_at_ms {
            apply_record_to_model(&mut model, record);
        }
    }
    model
}

fn apply_record_to_model(model: &mut ObjectModel, record: &OperationRecord) {
    match record.kind {
        OperationKind::Put | OperationKind::CompleteMultipartUpload
            if record.outcome == OperationOutcome::Ok =>
        {
            if let Some((key, object)) = record_object(record) {
                model.committed_writes += 1;
                model.deleted.remove(&key);
                model.live.insert(key, object);
            }
        }
        OperationKind::Put | OperationKind::CompleteMultipartUpload
            if matches!(
                record.outcome,
                OperationOutcome::Timeout | OperationOutcome::Unknown
            ) =>
        {
            if let Some((key, object)) = record_object(record) {
                model.unknown_writes.insert(key, object);
            }
        }
        OperationKind::Delete if record.outcome == OperationOutcome::Ok => {
            if let Some(key) = record.key.clone() {
                model.live.remove(&key);
                model.deleted.insert(key);
            }
        }
        _ => {}
    }
}

fn list_history_warnings(records: &[OperationRecord]) -> WarningSummary {
    let mut warnings = WarningSummary::default();
    for record in records.iter().filter(|record| {
        record.kind == OperationKind::List && record.outcome == OperationOutcome::Ok
    }) {
        let Some(prefix) = record.key.as_deref() else {
            continue;
        };
        let Some(listed_keys) = record.listed_keys.as_ref() else {
            warnings.push(format!("LIST {} did not record returned keys", record.id));
            continue;
        };
        let listed = listed_keys
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let stable = object_model_before(records, record.started_at_ms);
        for key in stable.live.keys().filter(|key| key.starts_with(prefix)) {
            if !listed.contains(key.as_str()) {
                warnings.push(format!(
                    "LIST {} prefix {prefix} did not include stable live key {key}",
                    record.id
                ));
            }
        }
        for key in stable.deleted.iter().filter(|key| key.starts_with(prefix)) {
            if listed.contains(key.as_str()) {
                warnings.push(format!(
                    "LIST {} prefix {prefix} included stable deleted key {key}",
                    record.id
                ));
            }
        }
    }
    warnings
}

fn successful_read_anomalies(records: &[OperationRecord]) -> ReadAnomalies {
    let mut live = BTreeMap::<String, ExpectedObject>::new();
    let mut anomalies = ReadAnomalies::default();
    for record in records {
        match record.kind {
            OperationKind::Put | OperationKind::CompleteMultipartUpload
                if record.outcome == OperationOutcome::Ok =>
            {
                if let Some((key, object)) = record_object(record) {
                    live.insert(key, object);
                }
            }
            OperationKind::Delete if record.outcome == OperationOutcome::Ok => {
                if let Some(key) = record.key.as_ref() {
                    live.remove(key);
                }
            }
            OperationKind::Get if record.outcome == OperationOutcome::Ok => {
                let Some(key) = record.key.as_ref() else {
                    continue;
                };
                let actual_hash = record.value_sha256.as_deref().unwrap_or_default();
                match live.get(key) {
                    Some(expected) if expected.sha256 != actual_hash => {
                        anomalies.corrupted_reads.push(format!(
                            "{key}: expected {}, got {actual_hash}",
                            expected.sha256
                        ));
                    }
                    None => anomalies
                        .visible_deleted_objects
                        .push(format!("{key}: successful GET had no committed live value")),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    anomalies
}

fn record_object(record: &OperationRecord) -> Option<(String, ExpectedObject)> {
    Some((
        record.key.clone()?,
        ExpectedObject {
            sha256: record.value_sha256.clone()?,
            size_bytes: record.size_bytes?,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        CheckerReport, ExpectedObject, RecoveryStabilityClassification, RecoveryStabilityReport,
        WarningSummary, evaluate_committed_get, finish_recovery_stability_report,
        immediate_still_unavailable_keys, is_recovery_tail_read_failure, list_history_warnings,
        object_model, recovery_tail_candidate_keys, successful_read_anomalies,
    };
    use crate::fault::history::{OperationKind, OperationOutcome, OperationRecord};
    use crate::fault::workload::GetObjectResult;

    fn record(
        id: &str,
        kind: OperationKind,
        key: &str,
        hash: &str,
        outcome: OperationOutcome,
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: "io-eio".to_string(),
            kind,
            bucket: "bucket".to_string(),
            key: Some(key.to_string()),
            value_sha256: Some(hash.to_string()),
            size_bytes: Some(1),
            started_at_ms: 1,
            ended_at_ms: 2,
            outcome,
            http_status: Some(200),
            error: None,
            listed_keys: None,
        }
    }

    fn list_record(
        id: &str,
        prefix: &str,
        started_at_ms: u64,
        ended_at_ms: u64,
        keys: &[&str],
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: "io-eio".to_string(),
            kind: OperationKind::List,
            bucket: "bucket".to_string(),
            key: Some(prefix.to_string()),
            value_sha256: None,
            size_bytes: Some(keys.len()),
            listed_keys: Some(keys.iter().map(|key| key.to_string()).collect()),
            started_at_ms,
            ended_at_ms,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
        }
    }

    #[test]
    fn corrupted_successful_get_is_hard_failure_input() {
        let records = vec![
            record(
                "op-1",
                OperationKind::Put,
                "k",
                "good",
                OperationOutcome::Ok,
            ),
            record("op-2", OperationKind::Get, "k", "bad", OperationOutcome::Ok),
        ];

        let anomalies = successful_read_anomalies(&records);

        assert_eq!(anomalies.corrupted_reads, vec!["k: expected good, got bad"]);
    }

    #[test]
    fn object_model_tracks_overwrite_delete_and_multipart_complete() {
        let records = vec![
            record("op-1", OperationKind::Put, "k1", "v1", OperationOutcome::Ok),
            record("op-2", OperationKind::Put, "k1", "v2", OperationOutcome::Ok),
            record("op-3", OperationKind::Put, "k2", "v1", OperationOutcome::Ok),
            record(
                "op-4",
                OperationKind::Delete,
                "k2",
                "",
                OperationOutcome::Ok,
            ),
            record(
                "op-5",
                OperationKind::CompleteMultipartUpload,
                "k3",
                "mp",
                OperationOutcome::Ok,
            ),
        ];

        let model = object_model(&records);

        assert_eq!(model.committed_writes, 4);
        assert_eq!(model.live.get("k1").expect("k1").sha256, "v2");
        assert!(!model.live.contains_key("k2"));
        assert_eq!(model.live.get("k3").expect("k3").sha256, "mp");
        assert!(model.deleted.contains("k2"));
    }

    #[test]
    fn list_history_checks_stable_keys_and_ignores_overlapping_changes() {
        let records = vec![
            OperationRecord {
                started_at_ms: 1,
                ended_at_ms: 2,
                ..record(
                    "op-1",
                    OperationKind::Put,
                    "fault-test/run-1/stable",
                    "v1",
                    OperationOutcome::Ok,
                )
            },
            OperationRecord {
                started_at_ms: 4,
                ended_at_ms: 7,
                ..record(
                    "op-2",
                    OperationKind::Put,
                    "fault-test/run-1/overlap",
                    "v2",
                    OperationOutcome::Ok,
                )
            },
            list_record("op-3", "fault-test/run-1/", 5, 6, &[]),
        ];

        let warnings = list_history_warnings(&records);

        assert_eq!(warnings.total_count, 1);
        assert_eq!(
            warnings.samples,
            vec![
                "LIST op-3 prefix fault-test/run-1/ did not include stable live key fault-test/run-1/stable"
            ]
        );
        assert!(
            !warnings
                .samples
                .iter()
                .any(|warning| warning.contains("overlap"))
        );
    }

    #[test]
    fn committed_get_timeout_is_unavailable_not_missing() {
        let mut report = empty_report();
        let expected = ExpectedObject {
            sha256: "sha".to_string(),
            size_bytes: 1,
        };

        evaluate_committed_get(
            &mut report,
            "k".to_string(),
            &expected,
            GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: Some(200),
                error: Some("get body read timed out".to_string()),
                body: None,
            },
        );

        assert!(report.missing_committed_objects.is_empty());
        assert_eq!(
            report.unavailable_committed_objects,
            vec!["k: outcome=Timeout status=200 error=\"get body read timed out\""]
        );
    }

    #[test]
    fn recovery_tail_candidates_require_status_200_body_timeout_or_streaming_error() {
        let put = record("op-1", OperationKind::Put, "k", "sha", OperationOutcome::Ok);
        let model = object_model(&[put]);
        let eligible_timeout = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Timeout,
            http_status: Some(200),
            error: Some("get body read timed out".to_string()),
            ..record(
                "op-2",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Timeout,
            )
        };
        let eligible_streaming = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Unknown,
            http_status: Some(200),
            error: Some("get body read failed: streaming error".to_string()),
            ..record(
                "op-3",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Unknown,
            )
        };
        let request_timeout = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Timeout,
            http_status: None,
            error: Some("get object timed out".to_string()),
            ..record(
                "op-4",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Timeout,
            )
        };
        let other_error = OperationRecord {
            kind: OperationKind::Get,
            outcome: OperationOutcome::Unknown,
            http_status: Some(200),
            error: Some("unexpected EOF".to_string()),
            ..record(
                "op-5",
                OperationKind::Get,
                "k",
                "",
                OperationOutcome::Unknown,
            )
        };

        assert!(is_recovery_tail_read_failure(
            eligible_timeout.outcome,
            eligible_timeout.http_status,
            eligible_timeout.error.as_deref()
        ));
        let keys = recovery_tail_candidate_keys(
            &[
                eligible_timeout,
                eligible_streaming,
                request_timeout,
                other_error,
            ],
            &model,
        );

        assert_eq!(keys, vec!["k"]);
    }

    #[test]
    fn recovery_stability_report_classifies_tail_latency_only_when_all_candidates_recover() {
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push("k: outcome=Timeout status=200 error=\"get body read timed out\"".to_string());
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.reread_recovered_keys.push("k".to_string());

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::RecoveryTailReadLatency
        );
    }

    #[test]
    fn recovery_stability_report_keeps_unavailable_and_corrupt_classifications_hard() {
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push("k: outcome=Timeout status=200 error=\"get body read timed out\"".to_string());
        let mut unavailable = recovery_report_with_attempted_key("k");
        unavailable.still_unavailable_keys.push("k".to_string());
        finish_recovery_stability_report(&mut unavailable, &immediate);
        assert_eq!(
            unavailable.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );

        let mut corrupt = recovery_report_with_attempted_key("k");
        corrupt.reread_recovered_keys.push("k".to_string());
        corrupt
            .hash_mismatches
            .push("k: expected sha (1 bytes), got bad (1 bytes)".to_string());
        finish_recovery_stability_report(&mut corrupt, &immediate);
        assert_eq!(
            corrupt.classification,
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn recovery_stability_classifies_list_and_visibility_anomalies_as_data_corruption() {
        let mut final_list_warning = empty_report();
        final_list_warning.final_list_warning_count = 1;
        final_list_warning
            .list_warnings
            .push("LIST prefix did not include expected live key k".to_string());
        assert_eq!(
            super::classify_without_reread(&final_list_warning),
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            super::immediate_data_corruption_evidence(&final_list_warning),
            vec!["final_list_warning: LIST prefix did not include expected live key k"]
        );

        let mut history_list_warning = empty_report();
        history_list_warning.list_history_warning_count = 1;
        history_list_warning
            .list_history_warnings
            .push("LIST op-1 warning during workload".to_string());
        assert_eq!(
            super::classify_without_reread(&history_list_warning),
            RecoveryStabilityClassification::HarnessError
        );

        let mut visible_deleted = empty_report();
        visible_deleted
            .unexpected_visible_deleted_objects
            .push("k: deleted object returned body".to_string());
        assert_eq!(
            super::classify_without_reread(&visible_deleted),
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            super::immediate_data_corruption_evidence(&visible_deleted),
            vec!["unexpected_visible_deleted_object: k: deleted object returned body"]
        );
    }

    #[test]
    fn recovery_stability_keeps_non_candidate_immediate_failures_unavailable() {
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push("k: outcome=Timeout error=\"get object timed out\"".to_string());
        let keys = immediate_still_unavailable_keys(&immediate, &[]);
        let mut recovery = RecoveryStabilityReport {
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: keys,
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            classification: RecoveryStabilityClassification::HarnessError,
        };

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(recovery.still_unavailable_keys, vec!["k"]);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );
    }

    #[test]
    fn warning_summary_caps_samples_but_counts_all() {
        let mut warnings = WarningSummary::default();
        for idx in 0..(super::MAX_WARNING_SAMPLES + 3) {
            warnings.push(format!("warning-{idx}"));
        }

        assert_eq!(warnings.total_count, super::MAX_WARNING_SAMPLES + 3);
        assert_eq!(warnings.samples.len(), super::MAX_WARNING_SAMPLES);
    }

    #[test]
    fn report_requires_clean_correctness_verdict() {
        let report = CheckerReport {
            scenario: "io-eio".to_string(),
            run_id: "run-1".to_string(),
            committed_puts: 1,
            expected_live_objects: 1,
            verified_live_objects: 1,
            missing_committed_objects: Vec::new(),
            unavailable_committed_objects: Vec::new(),
            unknown_committed_read_failures: Vec::new(),
            hash_mismatches: Vec::new(),
            successful_corrupted_reads: Vec::new(),
            unexpected_visible_deleted_objects: Vec::new(),
            unknown_writes_materialized: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: Some(1),
            tenant_recovered: true,
            passed: true,
        };

        assert!(report.require_success().is_ok());
    }

    fn empty_report() -> CheckerReport {
        CheckerReport {
            scenario: "io-eio".to_string(),
            run_id: "run-1".to_string(),
            committed_puts: 0,
            expected_live_objects: 0,
            verified_live_objects: 0,
            missing_committed_objects: Vec::new(),
            unavailable_committed_objects: Vec::new(),
            unknown_committed_read_failures: Vec::new(),
            hash_mismatches: Vec::new(),
            successful_corrupted_reads: Vec::new(),
            unexpected_visible_deleted_objects: Vec::new(),
            unknown_writes_materialized: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: None,
            tenant_recovered: true,
            passed: false,
        }
    }

    fn recovery_report_with_attempted_key(key: &str) -> RecoveryStabilityReport {
        RecoveryStabilityReport {
            immediate_passed: false,
            reread_attempted_keys: vec![key.to_string()],
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            classification: RecoveryStabilityClassification::CommittedObjectUnavailable,
        }
    }
}
