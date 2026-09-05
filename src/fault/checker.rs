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

use anyhow::{Result, anyhow, ensure};
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};
use tokio::time::{sleep as async_sleep, timeout};

use crate::fault::{
    history::{ByteRange, OperationKind, OperationOutcome, OperationRecord, PayloadRef, Recorder},
    workload::{
        GetObjectResult, ObjectSpec, ObjectVersionEntry, S3WorkloadClient, seeded_bytes, sha256_hex,
    },
};

mod read_failure;
pub use read_failure::CommittedReadFailure;

const MAX_WARNING_SAMPLES: usize = 50;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckerReport {
    pub scenario: String,
    pub run_id: String,
    pub committed_puts: usize,
    pub expected_live_objects: usize,
    pub verified_live_objects: usize,
    pub missing_committed_objects: Vec<String>,
    pub unavailable_committed_objects: Vec<CommittedReadFailure>,
    pub unknown_committed_read_failures: Vec<CommittedReadFailure>,
    pub hash_mismatches: Vec<String>,
    pub successful_corrupted_reads: Vec<String>,
    pub unexpected_visible_deleted_objects: Vec<String>,
    #[serde(default)]
    pub unknown_writes_materialized: Vec<String>,
    #[serde(default)]
    pub unknown_writes_preserved_committed: Vec<String>,
    #[serde(default)]
    pub unknown_write_value_conflicts: Vec<String>,
    pub list_history_warning_count: usize,
    pub final_list_warning_count: usize,
    pub list_history_warnings: Vec<String>,
    pub list_warnings: Vec<String>,
    pub final_listed_objects: Option<usize>,
    #[serde(default)]
    pub versioning_expected: bool,
    #[serde(default)]
    pub expected_committed_versions: usize,
    #[serde(default)]
    pub verified_committed_versions: usize,
    #[serde(default)]
    pub verified_committed_version_refs: Vec<String>,
    #[serde(default)]
    pub committed_writes_missing_version_id_count: usize,
    #[serde(default)]
    pub committed_writes_missing_version_id: Vec<String>,
    #[serde(default)]
    pub missing_committed_versions: Vec<String>,
    #[serde(default)]
    pub unavailable_committed_versions: Vec<String>,
    #[serde(default)]
    pub version_hash_mismatches: Vec<String>,
    #[serde(default)]
    pub missing_committed_delete_markers: Vec<String>,
    #[serde(default)]
    pub verified_committed_delete_marker_refs: Vec<String>,
    #[serde(default)]
    pub resurrected_deleted_objects: Vec<String>,
    #[serde(default)]
    pub delete_marker_lineage_incomplete: Vec<String>,
    #[serde(default)]
    pub multipart_upload_lineage_incomplete: Vec<String>,
    /// Committed-present keys whose latest delete was ambiguous and that
    /// returned 404 after recovery: the delete legitimately took effect, so
    /// these are recorded for audit but do not fail the run.
    #[serde(default)]
    pub tolerated_ambiguous_deletes: Vec<String>,
    #[serde(default)]
    pub operation_cohorts: BTreeMap<String, usize>,
    #[serde(default)]
    pub fault_window_relations: BTreeMap<String, usize>,
    pub tenant_recovered: bool,
    pub passed: bool,
}

pub use crate::fault::verdict::RecoveryStabilityClassification;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStabilityReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scenario: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub immediate_passed: bool,
    pub reread_attempted_keys: Vec<String>,
    pub reread_recovered_keys: Vec<String>,
    pub still_unavailable_keys: Vec<String>,
    pub hash_mismatches: Vec<String>,
    #[serde(default)]
    pub data_corruption_evidence: Vec<String>,
    #[serde(default)]
    pub classification_evidence: Vec<String>,
    #[serde(default)]
    pub ambiguous_write_evidence: Vec<String>,
    #[serde(default)]
    pub final_list_warning_count: usize,
    #[serde(default)]
    pub list_warnings: Vec<String>,
    pub harness_errors: Vec<String>,
    pub max_recovery_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovered_within_seconds: Option<u64>,
    pub classification: RecoveryStabilityClassification,
}

impl RecoveryStabilityReport {
    pub(crate) fn harness_error(message: impl Into<String>, max_recovery: Duration) -> Self {
        Self {
            scenario: None,
            run_id: None,
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            classification_evidence: Vec::new(),
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: vec![message.into()],
            max_recovery_seconds: max_recovery.as_secs(),
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::HarnessError,
        }
    }

    pub(crate) fn with_identity(mut self, scenario: &str, run_id: &str) -> Self {
        self.scenario = Some(scenario.to_string());
        self.run_id = Some(run_id.to_string());
        self
    }

    pub(crate) fn evidence_classifications(&self) -> Vec<String> {
        let mut classifications = BTreeSet::new();
        classifications.insert(self.classification.as_str().to_string());
        if !self.hash_mismatches.is_empty() || !self.data_corruption_evidence.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::DataCorruption
                    .as_str()
                    .to_string(),
            );
        }
        for evidence in &self.classification_evidence {
            if let Some(classification) =
                RecoveryStabilityClassification::from_classification_evidence(evidence)
            {
                classifications.insert(classification.as_str().to_string());
            }
        }
        if self
            .still_unavailable_keys
            .iter()
            .any(|key| !key.starts_with("version:"))
        {
            classifications.insert(
                RecoveryStabilityClassification::CommittedObjectUnavailable
                    .as_str()
                    .to_string(),
            );
        }
        if self.classification == RecoveryStabilityClassification::ListUnavailableOrUnknown {
            classifications.insert(
                RecoveryStabilityClassification::ListUnavailableOrUnknown
                    .as_str()
                    .to_string(),
            );
        }
        if !self.ambiguous_write_evidence.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::AmbiguousWriteMaterialized
                    .as_str()
                    .to_string(),
            );
        }
        if !self.reread_attempted_keys.is_empty()
            && self.reread_attempted_keys == self.reread_recovered_keys
            && self.still_unavailable_keys.is_empty()
            && self.hash_mismatches.is_empty()
            && self.classification_evidence.is_empty()
            && self.harness_errors.is_empty()
        {
            classifications.insert(
                RecoveryStabilityClassification::RecoveryTailReadLatency
                    .as_str()
                    .to_string(),
            );
        }
        if !self.harness_errors.is_empty() {
            classifications.insert(
                RecoveryStabilityClassification::HarnessError
                    .as_str()
                    .to_string(),
            );
        }
        classifications.into_iter().collect()
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

    pub(crate) fn failure_classification(&self) -> RecoveryStabilityClassification {
        classify_without_reread(self)
    }
}

pub async fn check_s3_history(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    tenant_recovered: bool,
    concurrency: usize,
    expect_versioning: bool,
) -> Result<CheckerReport> {
    let initial_records = recorder.records();
    let model = object_model(&initial_records);
    let read_anomalies = successful_read_anomalies(&initial_records);
    let list_history_warnings = list_history_warnings(&initial_records);
    let version_lineage = if expect_versioning {
        Some(committed_version_lineage(&initial_records))
    } else {
        None
    };
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
        unknown_writes_materialized: read_anomalies.unknown_writes_materialized,
        unknown_writes_preserved_committed: Vec::new(),
        unknown_write_value_conflicts: read_anomalies.unknown_write_value_conflicts,
        list_history_warning_count: list_history_warnings.total_count,
        final_list_warning_count: 0,
        list_history_warnings: list_history_warnings.samples,
        list_warnings: Vec::new(),
        final_listed_objects: None,
        versioning_expected: expect_versioning,
        expected_committed_versions: 0,
        verified_committed_versions: 0,
        verified_committed_version_refs: Vec::new(),
        committed_writes_missing_version_id_count: 0,
        committed_writes_missing_version_id: Vec::new(),
        missing_committed_versions: Vec::new(),
        unavailable_committed_versions: Vec::new(),
        version_hash_mismatches: Vec::new(),
        missing_committed_delete_markers: Vec::new(),
        verified_committed_delete_marker_refs: Vec::new(),
        resurrected_deleted_objects: Vec::new(),
        delete_marker_lineage_incomplete: Vec::new(),
        multipart_upload_lineage_incomplete: Vec::new(),
        tolerated_ambiguous_deletes: Vec::new(),
        operation_cohorts: operation_cohort_counts(&initial_records),
        fault_window_relations: fault_window_relation_counts(&initial_records),
        tenant_recovered,
        passed: false,
    };

    let final_keys = model
        .live
        .keys()
        .chain(model.unknown_writes.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut final_results = stream::iter(final_keys.into_iter().map(|key| {
        let s3 = s3.clone();
        let recorder = recorder.clone();
        let expected = model.live.get(&key).cloned();
        let unknown_writes = model.unknown_writes.get(&key).cloned().unwrap_or_default();
        async move {
            let get = s3.get_object_result(&key, &recorder).await?;
            Ok::<_, anyhow::Error>((key, expected, unknown_writes, get))
        }
    }))
    .buffer_unordered(concurrency);
    while let Some(result) = final_results.next().await {
        let (key, expected, unknown_writes, get) = result?;
        if expected.is_some()
            && unknown_writes.is_empty()
            && get.outcome == OperationOutcome::NotFound
            && model.ambiguous_delete_pending.contains(&key)
        {
            // The committed object had a later ambiguous (timeout/unknown)
            // delete; a 404 means that delete took effect, which is a
            // legitimate outcome, not a lost committed object.
            report.tolerated_ambiguous_deletes.push(key);
            continue;
        }
        evaluate_final_get(&mut report, key, expected.as_ref(), &unknown_writes, get);
    }

    // Committed deletes are otherwise never re-read: the final GET loop probes
    // only live and ambiguous-write keys, so a deleted key that still serves a
    // body on the GET path (but stays absent from LIST) would pass. Probe the
    // deleted keys that carry no ambiguous write — a materialized ambiguous
    // write on a deleted key is a legitimate outcome already handled above.
    let deleted_probe_keys = model
        .deleted
        .iter()
        .filter(|key| !model.unknown_writes.contains_key(*key))
        .cloned()
        .collect::<Vec<_>>();
    let mut deleted_results = stream::iter(deleted_probe_keys.into_iter().map(|key| {
        let s3 = s3.clone();
        let recorder = recorder.clone();
        async move {
            let get = s3.get_object_result(&key, &recorder).await?;
            Ok::<_, anyhow::Error>((key, get))
        }
    }))
    .buffer_unordered(concurrency);
    while let Some(result) = deleted_results.next().await {
        let (key, get) = result?;
        if let Some(message) = evaluate_deleted_reread(&key, &get) {
            report.resurrected_deleted_objects.push(message);
        }
    }

    let run_id = recorder.run_id();
    let prefix = ObjectSpec::key_prefix(&run_id);

    let mut final_list_warnings = WarningSummary::default();
    if let Some(lineage) = version_lineage {
        report.expected_committed_versions = lineage.versions.len();
        report.committed_writes_missing_version_id_count = lineage.missing_version_id_count;
        report.committed_writes_missing_version_id = lineage.missing_version_id_samples.clone();
        report
            .delete_marker_lineage_incomplete
            .extend(lineage.delete_marker_lineage_incomplete.clone());
        report
            .multipart_upload_lineage_incomplete
            .extend(lineage.multipart_upload_lineage_incomplete.clone());

        let mut version_results = stream::iter(lineage.versions.iter().cloned().map(|version| {
            let s3 = s3.clone();
            let recorder = recorder.clone();
            async move {
                let get = s3
                    .get_object_version_result(&version.key, &version.version_id, &recorder)
                    .await?;
                Ok::<_, anyhow::Error>((version, get))
            }
        }))
        .buffer_unordered(concurrency);
        while let Some(result) = version_results.next().await {
            let (version, get) = result?;
            evaluate_committed_version_get(&mut report, &version, get);
        }

        match s3.list_object_versions(&prefix, recorder).await? {
            Some(entries) => {
                let (missing_versions, multipart_lineage) =
                    missing_committed_version_entries(&lineage.versions, &entries);
                report.missing_committed_versions.extend(missing_versions);
                report
                    .multipart_upload_lineage_incomplete
                    .extend(multipart_lineage);
                let (verified_delete_markers, missing_delete_markers) =
                    committed_delete_marker_presence(&lineage.delete_markers, &entries);
                report.verified_committed_delete_marker_refs = verified_delete_markers;
                report.missing_committed_delete_markers = missing_delete_markers;
                evaluate_deleted_latest_versions(
                    &mut report,
                    &model.deleted,
                    &latest_version_entries(&entries),
                );
                let (materialized, conflicts) = materialized_ambiguous_versions(
                    s3,
                    recorder,
                    &model,
                    &lineage,
                    &entries,
                    concurrency,
                )
                .await?;
                report.unknown_writes_materialized.extend(materialized);
                report.unknown_write_value_conflicts.extend(conflicts);
            }
            None => record_version_list_unavailable(&mut final_list_warnings, &prefix),
        }
    }

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
    report
        .unavailable_committed_objects
        .sort_by(|a, b| a.key().cmp(&b.key()));
    report
        .unknown_committed_read_failures
        .sort_by(|a, b| a.key().cmp(&b.key()));
    report.hash_mismatches.sort();
    sort_dedup(&mut report.unknown_writes_materialized);
    sort_dedup(&mut report.unknown_writes_preserved_committed);
    sort_dedup(&mut report.unknown_write_value_conflicts);
    report.unexpected_visible_deleted_objects.sort();
    report.list_history_warnings.sort();
    report.list_warnings.sort();
    report.committed_writes_missing_version_id.sort();
    report.missing_committed_versions.sort();
    report.unavailable_committed_versions.sort();
    report.version_hash_mismatches.sort();
    report.missing_committed_delete_markers.sort();
    report.verified_committed_version_refs.sort();
    report.verified_committed_delete_marker_refs.sort();
    sort_dedup(&mut report.resurrected_deleted_objects);
    sort_dedup(&mut report.delete_marker_lineage_incomplete);
    sort_dedup(&mut report.multipart_upload_lineage_incomplete);
    report.tolerated_ambiguous_deletes.sort();
    report.passed = report.tenant_recovered
        && report.missing_committed_objects.is_empty()
        && report.unavailable_committed_objects.is_empty()
        && report.unknown_committed_read_failures.is_empty()
        && report.hash_mismatches.is_empty()
        && report.successful_corrupted_reads.is_empty()
        && report.unexpected_visible_deleted_objects.is_empty()
        && report.unknown_writes_materialized.is_empty()
        && report.unknown_write_value_conflicts.is_empty()
        && report.final_list_warning_count == 0
        && report.committed_writes_missing_version_id_count == 0
        && report.missing_committed_versions.is_empty()
        && report.unavailable_committed_versions.is_empty()
        && report.version_hash_mismatches.is_empty()
        && report.missing_committed_delete_markers.is_empty()
        && report.resurrected_deleted_objects.is_empty()
        && report.delete_marker_lineage_incomplete.is_empty()
        && report.multipart_upload_lineage_incomplete.is_empty();

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
    let classification_evidence = immediate_classification_evidence(immediate_report);
    let ambiguous_write_evidence = immediate_ambiguous_write_evidence(immediate_report);
    let still_unavailable_keys =
        immediate_still_unavailable_keys(immediate_report, &attempted_keys)?;
    let mut report = RecoveryStabilityReport {
        scenario: Some(immediate_report.scenario.clone()),
        run_id: Some(immediate_report.run_id.clone()),
        immediate_passed: immediate_report.passed,
        reread_attempted_keys: attempted_keys.clone(),
        reread_recovered_keys: Vec::new(),
        still_unavailable_keys,
        hash_mismatches,
        data_corruption_evidence,
        classification_evidence,
        ambiguous_write_evidence,
        final_list_warning_count: immediate_report.final_list_warning_count,
        list_warnings: immediate_report.list_warnings.clone(),
        harness_errors: Vec::new(),
        max_recovery_seconds: max_recovery.as_secs(),
        recovered_within_seconds: None,
        classification: classify_without_reread(immediate_report),
    };

    if immediate_report.passed || attempted_keys.is_empty() || max_recovery.is_zero() {
        finish_recovery_stability_report(&mut report, immediate_report);
        return Ok(report);
    }

    let expected = attempted_keys
        .iter()
        .filter_map(|key| {
            let expected = model.live.get(key).cloned()?;
            let ambiguous_writes = model.unknown_writes.get(key).cloned().unwrap_or_default();
            Some((key.clone(), (expected, ambiguous_writes)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut pending = expected.keys().cloned().collect::<BTreeSet<_>>();
    let started = Instant::now();
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
            let (expected, ambiguous_writes) = expected.get(&key).expect("pending key").clone();
            async move {
                let get = s3.get_object_result(&key, &recorder).await;
                (key, expected, ambiguous_writes, get)
            }
        }))
        .buffer_unordered(concurrency);

        while let Some((key, expected, ambiguous_writes, get)) = {
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
                Ok(get) => evaluate_recovery_reread_get(
                    &mut report,
                    &mut pending,
                    key,
                    &expected,
                    &ambiguous_writes,
                    get,
                ),
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

        if pending.is_empty() && report.recovered_within_seconds.is_none() {
            report.recovered_within_seconds = Some(started.elapsed().as_secs());
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
    sort_dedup(&mut report.hash_mismatches);
    sort_dedup(&mut report.data_corruption_evidence);
    sort_dedup(&mut report.ambiguous_write_evidence);
    sort_dedup(&mut report.list_warnings);
    sort_dedup(&mut report.harness_errors);
    finish_recovery_stability_report(&mut report, immediate_report);
    Ok(report)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpectedObject {
    sha256: String,
    size_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmbiguousWriteAttempt {
    id: String,
    kind: OperationKind,
    outcome: OperationOutcome,
    object: ExpectedObject,
    /// Generator inputs for regenerating this attempt's body, so a ranged GET
    /// that materialized this ambiguous write can be verified at the slice
    /// level (absent for multipart bodies and legacy records).
    payload_ref: Option<PayloadRef>,
    started_at_ms: u64,
    ended_at_ms: u64,
    superseded_by: Option<SupersedingMutation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SupersedingMutation {
    id: String,
    kind: OperationKind,
    started_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AmbiguousVersionCandidate {
    key: String,
    version_id: String,
    attempts: Vec<AmbiguousWriteAttempt>,
}

#[derive(Debug, Default)]
struct ObjectModel {
    live: BTreeMap<String, ExpectedObject>,
    deleted: BTreeSet<String>,
    unknown_writes: BTreeMap<String, Vec<AmbiguousWriteAttempt>>,
    // Keys still committed-present whose latest delete was ambiguous
    // (timeout/unknown): the object may or may not have been removed, so a
    // post-recovery 404 is a legitimate outcome rather than a lost object.
    ambiguous_delete_pending: BTreeSet<String>,
    committed_writes: usize,
}

#[derive(Debug, Default)]
struct ReadAnomalies {
    corrupted_reads: Vec<String>,
    visible_deleted_objects: Vec<String>,
    unknown_writes_materialized: Vec<String>,
    unknown_write_value_conflicts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommittedVersion {
    key: String,
    version_id: String,
    sha256: String,
    size_bytes: usize,
    kind: OperationKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CommittedDeleteMarker {
    key: String,
    version_id: String,
}

#[derive(Debug, Default)]
struct VersionLineage {
    versions: Vec<CommittedVersion>,
    delete_markers: Vec<CommittedDeleteMarker>,
    missing_version_id_count: usize,
    missing_version_id_samples: Vec<String>,
    delete_marker_lineage_incomplete: Vec<String>,
    multipart_upload_lineage_incomplete: Vec<String>,
}

fn committed_version_lineage(records: &[OperationRecord]) -> VersionLineage {
    let mut lineage = VersionLineage::default();
    for record in records {
        let is_committed_write = matches!(
            record.kind,
            OperationKind::Put | OperationKind::CompleteMultipartUpload
        ) && record.outcome == OperationOutcome::Ok;
        let is_committed_delete =
            record.kind == OperationKind::Delete && record.outcome == OperationOutcome::Ok;
        if !is_committed_write && !is_committed_delete {
            continue;
        }
        let Some(key) = record.key.as_ref() else {
            continue;
        };
        match record.version_id.as_ref() {
            Some(version_id) if is_committed_write => {
                let Some((_, expected)) = record_object(record) else {
                    continue;
                };
                lineage.versions.push(CommittedVersion {
                    key: key.clone(),
                    version_id: version_id.clone(),
                    sha256: expected.sha256,
                    size_bytes: expected.size_bytes,
                    kind: record.kind,
                });
            }
            Some(version_id) if is_committed_delete => {
                lineage.delete_markers.push(CommittedDeleteMarker {
                    key: key.clone(),
                    version_id: version_id.clone(),
                });
            }
            Some(_) => {}
            None => {
                let message = format!(
                    "{}: committed {:?} response omitted x-amz-version-id for {key}",
                    record.id, record.kind
                );
                if is_committed_write {
                    lineage.missing_version_id_count += 1;
                    if lineage.missing_version_id_samples.len() < MAX_WARNING_SAMPLES {
                        lineage.missing_version_id_samples.push(message.clone());
                    }
                    if record.kind == OperationKind::CompleteMultipartUpload
                        && lineage.multipart_upload_lineage_incomplete.len() < MAX_WARNING_SAMPLES
                    {
                        lineage.multipart_upload_lineage_incomplete.push(message);
                    }
                } else if lineage.delete_marker_lineage_incomplete.len() < MAX_WARNING_SAMPLES {
                    lineage.delete_marker_lineage_incomplete.push(message);
                }
            }
        }
    }
    lineage
}

fn evaluate_committed_version_get(
    report: &mut CheckerReport,
    version: &CommittedVersion,
    get: GetObjectResult,
) {
    let reference = format!("{}@{}", version.key, version.version_id);
    match (get.outcome, get.body) {
        (OperationOutcome::Ok, Some(body)) => {
            let actual_hash = sha256_hex(&body);
            if actual_hash != version.sha256 || body.len() != version.size_bytes {
                report.version_hash_mismatches.push(format!(
                    "{reference}: expected {} ({} bytes), got {actual_hash} ({} bytes)",
                    version.sha256,
                    version.size_bytes,
                    body.len()
                ));
            } else {
                report.verified_committed_versions += 1;
                report.verified_committed_version_refs.push(reference);
            }
        }
        (OperationOutcome::NotFound, None) => {
            report.missing_committed_versions.push(reference.clone());
            if version.kind == OperationKind::CompleteMultipartUpload {
                report.multipart_upload_lineage_incomplete.push(format!(
                    "{reference}: committed multipart completion version is missing"
                ));
            }
        }
        (outcome, body) => report
            .unavailable_committed_versions
            .push(read_failure_message(
                &reference,
                outcome,
                get.http_status,
                get.error
                    .as_deref()
                    .or(body.is_some().then_some("unexpected body")),
            )),
    }
}

fn missing_committed_version_entries(
    committed: &[CommittedVersion],
    entries: &[ObjectVersionEntry],
) -> (Vec<String>, Vec<String>) {
    let present = entries
        .iter()
        .filter(|entry| !entry.is_delete_marker)
        .filter_map(|entry| Some((entry.key.as_str(), entry.version_id.as_deref()?)))
        .collect::<BTreeSet<_>>();
    let mut missing = Vec::new();
    let mut multipart_lineage = Vec::new();
    for version in committed {
        if present.contains(&(version.key.as_str(), version.version_id.as_str())) {
            continue;
        }
        let reference = format!("{}@{}", version.key, version.version_id);
        missing.push(format!(
            "{reference}: committed version missing from ListObjectVersions"
        ));
        if version.kind == OperationKind::CompleteMultipartUpload {
            multipart_lineage.push(format!(
                "{reference}: committed multipart completion missing from ListObjectVersions"
            ));
        }
    }
    (missing, multipart_lineage)
}

fn latest_version_entries(entries: &[ObjectVersionEntry]) -> BTreeMap<String, ObjectVersionEntry> {
    let mut latest = BTreeMap::new();
    for entry in entries {
        if entry.is_latest {
            latest.insert(entry.key.clone(), entry.clone());
        }
    }
    latest
}

fn evaluate_deleted_latest_versions(
    report: &mut CheckerReport,
    deleted: &BTreeSet<String>,
    latest: &BTreeMap<String, ObjectVersionEntry>,
) {
    for key in deleted {
        match latest.get(key) {
            Some(entry) if !entry.is_delete_marker => {
                report.resurrected_deleted_objects.push(format!(
                    "{key}: latest version is not a delete marker after committed delete"
                ));
            }
            None => report.delete_marker_lineage_incomplete.push(format!(
                "{key}: ListObjectVersions has no latest entry after committed delete"
            )),
            Some(_) => {}
        }
    }
}

fn committed_delete_marker_presence(
    committed: &[CommittedDeleteMarker],
    entries: &[ObjectVersionEntry],
) -> (Vec<String>, Vec<String>) {
    let present = entries
        .iter()
        .filter(|entry| entry.is_delete_marker)
        .filter_map(|entry| Some((entry.key.clone(), entry.version_id.clone()?)))
        .collect::<BTreeSet<_>>();
    let mut verified = Vec::new();
    let mut missing = Vec::new();
    for marker in committed {
        let reference = format!("{}@{}", marker.key, marker.version_id);
        if present.contains(&(marker.key.clone(), marker.version_id.clone())) {
            verified.push(reference);
        } else {
            missing.push(format!(
                "{reference}: committed delete marker missing from ListObjectVersions"
            ));
        }
    }
    (verified, missing)
}

fn ambiguous_version_candidates(
    model: &ObjectModel,
    lineage: &VersionLineage,
    entries: &[ObjectVersionEntry],
) -> (Vec<AmbiguousVersionCandidate>, Vec<String>) {
    let committed_versions = lineage
        .versions
        .iter()
        .map(|version| (version.key.as_str(), version.version_id.as_str()))
        .collect::<BTreeSet<_>>();
    let mut candidates = Vec::new();
    let mut conflicts = Vec::new();

    for entry in entries.iter().filter(|entry| !entry.is_delete_marker) {
        let attempts = model
            .unknown_writes
            .get(&entry.key)
            .cloned()
            .unwrap_or_default();
        let Some(version_id) = entry.version_id.as_ref() else {
            conflicts.push(uncommitted_version_missing_id_message(
                &entry.key, &attempts,
            ));
            continue;
        };
        if committed_versions.contains(&(entry.key.as_str(), version_id.as_str())) {
            continue;
        }
        candidates.push(AmbiguousVersionCandidate {
            key: entry.key.clone(),
            version_id: version_id.clone(),
            attempts,
        });
    }

    (candidates, conflicts)
}

async fn materialized_ambiguous_versions(
    s3: &S3WorkloadClient,
    recorder: &Recorder,
    model: &ObjectModel,
    lineage: &VersionLineage,
    entries: &[ObjectVersionEntry],
    concurrency: usize,
) -> Result<(Vec<String>, Vec<String>)> {
    let (candidates, mut conflicts) = ambiguous_version_candidates(model, lineage, entries);
    let mut materialized = Vec::new();
    let mut results = stream::iter(candidates.into_iter().map(|candidate| {
        let s3 = s3.clone();
        let recorder = recorder.clone();
        async move {
            let get = s3
                .get_object_version_result(&candidate.key, &candidate.version_id, &recorder)
                .await?;
            Ok::<_, anyhow::Error>((candidate, get))
        }
    }))
    .buffer_unordered(concurrency.max(1));

    while let Some(result) = results.next().await {
        let (candidate, get) = result?;
        evaluate_ambiguous_version_get(&mut materialized, &mut conflicts, &candidate, get);
    }
    Ok((materialized, conflicts))
}

fn evaluate_ambiguous_version_get(
    materialized: &mut Vec<String>,
    conflicts: &mut Vec<String>,
    candidate: &AmbiguousVersionCandidate,
    get: GetObjectResult,
) {
    let Some(body) = get.body.as_deref() else {
        conflicts.push(uncommitted_version_unverified_message(candidate, &get));
        return;
    };
    if get.outcome != OperationOutcome::Ok {
        conflicts.push(uncommitted_version_unverified_message(candidate, &get));
        return;
    }
    if let Some(attempt) = matching_ambiguous_write(&candidate.attempts, body) {
        materialized.push(ambiguous_version_materialized_message(
            &candidate.key,
            &candidate.version_id,
            attempt,
            body,
        ));
        return;
    }
    conflicts.push(uncommitted_version_value_conflict_message(candidate, body));
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

fn record_version_list_unavailable(warnings: &mut WarningSummary, prefix: &str) {
    warnings.push(format!(
        "ListObjectVersions prefix {prefix} did not complete"
    ));
}

fn sort_dedup(values: &mut Vec<String>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
fn evaluate_committed_get(
    report: &mut CheckerReport,
    key: String,
    expected: &ExpectedObject,
    get: GetObjectResult,
) {
    evaluate_final_get(report, key, Some(expected), &[], get);
}

fn evaluate_final_get(
    report: &mut CheckerReport,
    key: String,
    expected: Option<&ExpectedObject>,
    ambiguous_writes: &[AmbiguousWriteAttempt],
    get: GetObjectResult,
) {
    match (get.outcome, get.body) {
        (OperationOutcome::Ok, Some(body)) => {
            if expected.is_some_and(|expected| object_matches(expected, &body)) {
                report.verified_live_objects += 1;
                record_preserved_committed(report, &key, expected, ambiguous_writes, &body);
                return;
            }
            if let Some(attempt) = matching_active_ambiguous_write(ambiguous_writes, &body) {
                report
                    .unknown_writes_materialized
                    .push(ambiguous_write_materialized_message(&key, attempt, &body));
                return;
            }
            if let Some(attempt) = matching_superseded_ambiguous_write(ambiguous_writes, &body) {
                report
                    .unknown_writes_materialized
                    .push(ambiguous_write_materialized_message(&key, attempt, &body));
                report.unknown_write_value_conflicts.push(
                    superseded_ambiguous_write_conflict_message(&key, expected, attempt, &body),
                );
                return;
            }
            if !ambiguous_writes.is_empty() {
                report
                    .unknown_write_value_conflicts
                    .push(unknown_write_value_conflict_message(
                        &key,
                        expected,
                        ambiguous_writes,
                        &body,
                    ));
            } else if let Some(expected) = expected {
                report
                    .hash_mismatches
                    .push(hash_mismatch_message(&key, expected, &body));
            }
        }
        (OperationOutcome::NotFound, None) if expected.is_some() => {
            report.missing_committed_objects.push(key)
        }
        (OperationOutcome::Failed | OperationOutcome::Timeout, None) if expected.is_some() => {
            report
                .unavailable_committed_objects
                .push(CommittedReadFailure::observed(
                    &key,
                    get.outcome,
                    get.http_status,
                    get.error.as_deref(),
                    None,
                ))
        }
        (OperationOutcome::Unknown | OperationOutcome::Ok, None) if expected.is_some() => report
            .unknown_committed_read_failures
            .push(CommittedReadFailure::observed(
                &key,
                get.outcome,
                get.http_status,
                get.error.as_deref(),
                None,
            )),
        (outcome, Some(body)) if expected.is_some() => {
            report
                .unknown_committed_read_failures
                .push(CommittedReadFailure::observed(
                    &key,
                    outcome,
                    get.http_status,
                    get.error.as_deref(),
                    Some(body.len()),
                ));
        }
        _ => {}
    }
}

/// A committed delete (latest committed op for the key was a successful Delete)
/// must not serve a body after recovery. A direct GET that returns one is a
/// resurrection; the correct outcome is not-found, and an unavailable probe
/// response (timeout/error) is not evidence of resurrection either.
fn evaluate_deleted_reread(key: &str, get: &GetObjectResult) -> Option<String> {
    match (get.outcome, get.body.as_deref()) {
        (OperationOutcome::Ok, Some(body)) => Some(format!(
            "{key}: committed delete resurrected on GET ({} bytes)",
            body.len()
        )),
        _ => None,
    }
}

fn evaluate_recovery_reread_get(
    report: &mut RecoveryStabilityReport,
    pending: &mut BTreeSet<String>,
    key: String,
    expected: &ExpectedObject,
    ambiguous_writes: &[AmbiguousWriteAttempt],
    get: GetObjectResult,
) {
    if committed_get_matches(expected, &get) {
        pending.remove(&key);
        report.reread_recovered_keys.push(key);
        return;
    }
    let Some(body) = get.body else {
        return;
    };
    if let Some(attempt) = matching_active_ambiguous_write(ambiguous_writes, &body) {
        pending.remove(&key);
        report
            .ambiguous_write_evidence
            .push(ambiguous_write_materialized_message(&key, attempt, &body));
        return;
    }
    if let Some(attempt) = matching_superseded_ambiguous_write(ambiguous_writes, &body) {
        pending.remove(&key);
        report
            .ambiguous_write_evidence
            .push(ambiguous_write_materialized_message(&key, attempt, &body));
        report.data_corruption_evidence.push(format!(
            "unknown_write_value_conflict: {}",
            superseded_ambiguous_write_conflict_message(&key, Some(expected), attempt, &body)
        ));
        return;
    }
    report
        .hash_mismatches
        .push(hash_mismatch_message(&key, expected, &body));
    pending.remove(&key);
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
                && record.version_id.is_none()
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
    ) {
        return false;
    }
    let Some(error) = error else {
        return false;
    };
    let error = error.to_ascii_lowercase();
    if http_status == Some(200) {
        return error.contains("body read timed out")
            || error.contains("body read timeout")
            || error.contains("streaming error");
    }
    http_status.is_none()
        && (error.contains("get object timed out") || error.contains("request timed out"))
}

fn committed_get_matches(expected: &ExpectedObject, get: &GetObjectResult) -> bool {
    get.outcome == OperationOutcome::Ok
        && get
            .body
            .as_deref()
            .is_some_and(|body| object_matches(expected, body))
}

fn object_matches(expected: &ExpectedObject, body: &[u8]) -> bool {
    body.len() == expected.size_bytes && sha256_hex(body) == expected.sha256
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

fn matching_ambiguous_write<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    body: &[u8],
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .find(|attempt| object_matches(&attempt.object, body))
}

fn matching_active_ambiguous_write<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    body: &[u8],
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_none())
        .find(|attempt| object_matches(&attempt.object, body))
}

fn matching_superseded_ambiguous_write<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    body: &[u8],
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_some())
        .find(|attempt| object_matches(&attempt.object, body))
}

fn matching_active_ambiguous_object<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    actual: &ExpectedObject,
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_none())
        .find(|attempt| attempt.object == *actual)
}

fn matching_superseded_ambiguous_object<'a>(
    attempts: &'a [AmbiguousWriteAttempt],
    actual: &ExpectedObject,
) -> Option<&'a AmbiguousWriteAttempt> {
    attempts
        .iter()
        .rev()
        .filter(|attempt| attempt.superseded_by.is_some())
        .find(|attempt| attempt.object == *actual)
}

fn record_preserved_committed(
    report: &mut CheckerReport,
    key: &str,
    expected: Option<&ExpectedObject>,
    attempts: &[AmbiguousWriteAttempt],
    body: &[u8],
) {
    let Some(expected) = expected else {
        return;
    };
    if attempts.is_empty() {
        return;
    }
    let actual_hash = sha256_hex(body);
    if actual_hash != expected.sha256 || body.len() != expected.size_bytes {
        report
            .unknown_write_value_conflicts
            .push(unknown_write_value_conflict_message(
                key,
                Some(expected),
                attempts,
                body,
            ));
        return;
    }
    let materially_distinct_attempt = attempts.iter().any(|attempt| {
        attempt.object.sha256 != expected.sha256 || attempt.object.size_bytes != expected.size_bytes
    });
    if materially_distinct_attempt {
        let attempts = ambiguous_write_attempt_summary(attempts);
        report.unknown_writes_preserved_committed.push(format!(
            "{key}: observed committed {} ({} bytes) after ambiguous attempts [{attempts}]",
            expected.sha256, expected.size_bytes
        ));
    }
}

fn ambiguous_write_materialized_message(
    key: &str,
    attempt: &AmbiguousWriteAttempt,
    body: &[u8],
) -> String {
    format!(
        "{key}: {} materialized as {} ({} bytes)",
        ambiguous_write_attempt_label(attempt),
        sha256_hex(body),
        body.len()
    )
}

fn ambiguous_write_materialized_from_object_message(
    key: &str,
    attempt: &AmbiguousWriteAttempt,
    actual: &ExpectedObject,
) -> String {
    format!(
        "{key}: {} materialized as {} ({} bytes)",
        ambiguous_write_attempt_label(attempt),
        actual.sha256,
        actual.size_bytes
    )
}

fn ambiguous_version_materialized_message(
    key: &str,
    version_id: &str,
    attempt: &AmbiguousWriteAttempt,
    body: &[u8],
) -> String {
    format!(
        "{key}@{version_id}: {} materialized as version {} ({} bytes)",
        ambiguous_write_attempt_label(attempt),
        sha256_hex(body),
        body.len()
    )
}

fn uncommitted_version_missing_id_message(key: &str, attempts: &[AmbiguousWriteAttempt]) -> String {
    let attempts = ambiguous_write_attempt_summary(attempts);
    format!(
        "{key}: uncommitted non-delete version from ListObjectVersions did not include a version id; ambiguous attempts [{attempts}]"
    )
}

fn uncommitted_version_unverified_message(
    candidate: &AmbiguousVersionCandidate,
    get: &GetObjectResult,
) -> String {
    let attempts = ambiguous_write_attempt_summary(&candidate.attempts);
    format!(
        "{}@{}: uncommitted version could not be verified; outcome={:?} status={:?} error={:?}; ambiguous attempts [{attempts}]",
        candidate.key, candidate.version_id, get.outcome, get.http_status, get.error
    )
}

fn uncommitted_version_value_conflict_message(
    candidate: &AmbiguousVersionCandidate,
    body: &[u8],
) -> String {
    let attempts = ambiguous_write_attempt_summary(&candidate.attempts);
    format!(
        "{}@{}: observed uncommitted version {} ({} bytes), but it matched no ambiguous attempt [{}]",
        candidate.key,
        candidate.version_id,
        sha256_hex(body),
        body.len(),
        attempts
    )
}

fn unknown_write_value_conflict_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempts: &[AmbiguousWriteAttempt],
    body: &[u8],
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    let attempts = ambiguous_write_attempt_summary(attempts);
    format!(
        "{key}: observed {} ({} bytes), expected {committed} or ambiguous attempts [{attempts}]",
        sha256_hex(body),
        body.len()
    )
}

fn superseded_ambiguous_write_conflict_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempt: &AmbiguousWriteAttempt,
    body: &[u8],
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    format!(
        "{key}: observed {} ({} bytes) from superseded ambiguous attempt [{}], expected {committed}",
        sha256_hex(body),
        body.len(),
        ambiguous_write_attempt_label(attempt)
    )
}

fn unknown_write_value_conflict_from_object_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempts: &[AmbiguousWriteAttempt],
    actual: &ExpectedObject,
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    let attempts = ambiguous_write_attempt_summary(attempts);
    format!(
        "{key}: observed {} ({} bytes), expected {committed} or ambiguous attempts [{attempts}]",
        actual.sha256, actual.size_bytes
    )
}

fn superseded_ambiguous_object_conflict_message(
    key: &str,
    expected: Option<&ExpectedObject>,
    attempt: &AmbiguousWriteAttempt,
    actual: &ExpectedObject,
) -> String {
    let committed = expected
        .map(|expected| {
            format!(
                "committed {} ({} bytes)",
                expected.sha256, expected.size_bytes
            )
        })
        .unwrap_or_else(|| "no committed object".to_string());
    format!(
        "{key}: observed {} ({} bytes) from superseded ambiguous attempt [{}], expected {committed}",
        actual.sha256,
        actual.size_bytes,
        ambiguous_write_attempt_label(attempt)
    )
}

fn ambiguous_write_attempt_summary(attempts: &[AmbiguousWriteAttempt]) -> String {
    if attempts.is_empty() {
        return "none".to_string();
    }
    attempts
        .iter()
        .map(ambiguous_write_attempt_label)
        .collect::<Vec<_>>()
        .join(", ")
}

fn ambiguous_write_attempt_label(attempt: &AmbiguousWriteAttempt) -> String {
    let mut label = format!(
        "{} {:?} {:?} {} ({} bytes)",
        attempt.id, attempt.kind, attempt.outcome, attempt.object.sha256, attempt.object.size_bytes
    );
    if let Some(superseded_by) = &attempt.superseded_by {
        label.push_str(&format!(
            " superseded_by={} {:?} started_at_ms={}",
            superseded_by.id, superseded_by.kind, superseded_by.started_at_ms
        ));
    }
    label
}

/// Derive the S3-model classification for a failing checker report. Shared by
/// the recovery-stability path and the final checker verdict so the same
/// evidence never classifies differently depending on which gate caught it.
fn classify_without_reread(report: &CheckerReport) -> RecoveryStabilityClassification {
    if !report.version_hash_mismatches.is_empty() {
        RecoveryStabilityClassification::VersionHashMismatch
    } else if !report.missing_committed_delete_markers.is_empty() {
        RecoveryStabilityClassification::DeleteMarkerMissing
    } else if !report.resurrected_deleted_objects.is_empty()
        || !report.unexpected_visible_deleted_objects.is_empty()
    {
        RecoveryStabilityClassification::DeletedObjectResurrected
    } else if !report.missing_committed_versions.is_empty() {
        RecoveryStabilityClassification::CommittedVersionMissing
    } else if has_data_corruption_signal(report) {
        RecoveryStabilityClassification::DataCorruption
    } else if !report.unavailable_committed_versions.is_empty() {
        RecoveryStabilityClassification::CommittedVersionUnavailable
    } else if has_committed_unavailable_signal(report) {
        RecoveryStabilityClassification::CommittedObjectUnavailable
    } else if has_list_unavailable_or_unknown_signal(report) {
        RecoveryStabilityClassification::ListUnavailableOrUnknown
    } else if !report.delete_marker_lineage_incomplete.is_empty() {
        RecoveryStabilityClassification::DeleteMarkerLineageIncomplete
    } else if !report.multipart_upload_lineage_incomplete.is_empty() {
        RecoveryStabilityClassification::MultipartUploadLineageIncomplete
    } else if report.committed_writes_missing_version_id_count > 0 {
        RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite
    } else if !report.unknown_writes_materialized.is_empty() {
        RecoveryStabilityClassification::AmbiguousWriteMaterialized
    } else {
        RecoveryStabilityClassification::HarnessError
    }
}

fn has_data_corruption_signal(report: &CheckerReport) -> bool {
    !report.hash_mismatches.is_empty()
        || !report.successful_corrupted_reads.is_empty()
        || !report.unknown_write_value_conflicts.is_empty()
        || final_list_content_corruption_signal(report)
}

fn final_list_content_corruption_signal(report: &CheckerReport) -> bool {
    report
        .list_warnings
        .iter()
        .any(|warning| final_list_content_corruption_warning(report, warning))
}

fn final_list_content_corruption_warning(report: &CheckerReport, warning: &str) -> bool {
    if let Some((_, key)) = warning.split_once(" did not include expected live key ") {
        // GET 404 and a matching LIST omission describe the same unavailable
        // object, not an independent content mismatch.
        return !report
            .missing_committed_objects
            .iter()
            .any(|missing| missing == key);
    }
    warning.contains("included deleted key")
}

fn has_committed_unavailable_signal(report: &CheckerReport) -> bool {
    !report.missing_committed_objects.is_empty()
        || !report.unavailable_committed_objects.is_empty()
        || !report.unknown_committed_read_failures.is_empty()
}

fn has_list_unavailable_or_unknown_signal(report: &CheckerReport) -> bool {
    report.final_list_warning_count > 0 && !final_list_content_corruption_signal(report)
}

fn operation_cohort_counts(records: &[OperationRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for cohort in records.iter().filter_map(|record| record.durability_cohort) {
        *counts.entry(cohort.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn fault_window_relation_counts(records: &[OperationRecord]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for relation in records
        .iter()
        .filter_map(|record| record.fault_window_relation)
    {
        *counts.entry(relation.as_str().to_string()).or_insert(0) += 1;
    }
    counts
}

fn immediate_data_corruption_evidence(report: &CheckerReport) -> Vec<String> {
    let mut evidence = Vec::new();
    evidence.extend(
        report
            .unknown_write_value_conflicts
            .iter()
            .map(|item| format!("unknown_write_value_conflict: {item}")),
    );
    let corruption_list_warnings = report
        .list_warnings
        .iter()
        .filter(|item| final_list_content_corruption_warning(report, item))
        .map(|item| format!("final_list_warning: {item}"))
        .collect::<Vec<_>>();
    let corruption_list_warning_count = corruption_list_warnings.len();
    evidence.extend(corruption_list_warnings);
    if final_list_content_corruption_signal(report)
        && report.final_list_warning_count > corruption_list_warning_count
    {
        evidence.push(format!(
            "final_list_content_warning_count: {} total, {} sampled",
            report.final_list_warning_count, corruption_list_warning_count
        ));
    }
    evidence.sort();
    evidence
}

fn immediate_classification_evidence(report: &CheckerReport) -> Vec<String> {
    let mut evidence = Vec::new();
    evidence.extend(
        report
            .version_hash_mismatches
            .iter()
            .map(|item| format!("version_hash_mismatch: {item}")),
    );
    evidence.extend(
        report
            .missing_committed_versions
            .iter()
            .map(|item| format!("missing_committed_version: {item}")),
    );
    evidence.extend(
        report
            .unavailable_committed_versions
            .iter()
            .map(|item| format!("unavailable_committed_version: {item}")),
    );
    evidence.extend(
        report
            .missing_committed_delete_markers
            .iter()
            .map(|item| format!("missing_committed_delete_marker: {item}")),
    );
    evidence.extend(
        report
            .resurrected_deleted_objects
            .iter()
            .chain(report.unexpected_visible_deleted_objects.iter())
            .map(|item| format!("resurrected_deleted_object: {item}")),
    );
    evidence.extend(
        report
            .committed_writes_missing_version_id
            .iter()
            .map(|item| format!("committed_write_missing_version_id: {item}")),
    );
    if report.committed_writes_missing_version_id_count
        > report.committed_writes_missing_version_id.len()
    {
        evidence.push(format!(
            "committed_writes_missing_version_id_count: {} total, {} sampled",
            report.committed_writes_missing_version_id_count,
            report.committed_writes_missing_version_id.len()
        ));
    }
    evidence.extend(
        report
            .delete_marker_lineage_incomplete
            .iter()
            .map(|item| format!("delete_marker_lineage_incomplete: {item}")),
    );
    evidence.extend(
        report
            .multipart_upload_lineage_incomplete
            .iter()
            .map(|item| format!("multipart_upload_lineage_incomplete: {item}")),
    );
    evidence.sort();
    evidence.dedup();
    evidence
}

fn immediate_ambiguous_write_evidence(report: &CheckerReport) -> Vec<String> {
    let mut evidence = report
        .unknown_writes_materialized
        .iter()
        .map(|item| format!("ambiguous_write_materialized: {item}"))
        .collect::<Vec<_>>();
    evidence.sort();
    evidence
}

fn immediate_still_unavailable_keys(
    report: &CheckerReport,
    reread_attempted_keys: &[String],
) -> Result<Vec<String>> {
    let attempted = reread_attempted_keys
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let mut keys = report
        .missing_committed_objects
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    ensure!(
        keys.len() == report.missing_committed_objects.len(),
        "checker report contains duplicate missing committed-object keys"
    );
    let mut observed = keys.clone();
    for failure in report
        .unavailable_committed_objects
        .iter()
        .chain(report.unknown_committed_read_failures.iter())
    {
        let key = failure.key().ok_or_else(|| {
            anyhow!("checker report contains an ambiguous committed-read failure: {failure:?}")
        })?;
        ensure!(
            observed.insert(key.to_string()),
            "checker report contains duplicate committed-read evidence for key {key:?}"
        );
        if !attempted.contains(key) {
            keys.insert(key.to_string());
        }
    }
    keys.extend(
        report
            .unavailable_committed_versions
            .iter()
            .map(|item| format!("version:{item}")),
    );
    Ok(keys.into_iter().collect())
}

fn immediate_recovery_tail_candidate_keys(report: &CheckerReport) -> Option<BTreeSet<String>> {
    let candidates = immediate_recovery_candidate_keys(report).ok()?;
    (candidates.len()
        == report.unavailable_committed_objects.len()
            + report.unknown_committed_read_failures.len())
    .then_some(candidates)
}

fn immediate_recovery_candidate_keys(report: &CheckerReport) -> Result<BTreeSet<String>> {
    let mut keys = BTreeSet::new();
    let mut observed = BTreeSet::new();
    for failure in report
        .unavailable_committed_objects
        .iter()
        .chain(report.unknown_committed_read_failures.iter())
    {
        let key = failure.key().ok_or_else(|| {
            anyhow!("checker report contains an ambiguous committed-read failure: {failure:?}")
        })?;
        ensure!(
            observed.insert(key.to_string()),
            "checker report contains duplicate committed-read evidence for key {key:?}"
        );
        let parsed = failure.evidence().ok_or_else(|| {
            anyhow!("checker report contains an unparseable committed-read failure: {failure:?}")
        })?;
        if is_recovery_tail_read_failure(parsed.outcome, parsed.http_status, parsed.error) {
            keys.insert(parsed.key.to_string());
        }
    }
    Ok(keys)
}

pub(crate) fn recovery_key_sets_are_consistent(report: &RecoveryStabilityReport) -> bool {
    let attempted = report.reread_attempted_keys.iter().collect::<BTreeSet<_>>();
    let recovered = report.reread_recovered_keys.iter().collect::<BTreeSet<_>>();
    let still_unavailable = report
        .still_unavailable_keys
        .iter()
        .collect::<BTreeSet<_>>();
    if attempted.len() != report.reread_attempted_keys.len()
        || recovered.len() != report.reread_recovered_keys.len()
        || still_unavailable.len() != report.still_unavailable_keys.len()
        || !recovered.is_subset(&attempted)
        || !recovered.is_disjoint(&still_unavailable)
    {
        return false;
    }
    let has_non_availability_result = !report.hash_mismatches.is_empty()
        || !report.data_corruption_evidence.is_empty()
        || !report.ambiguous_write_evidence.is_empty()
        || !report.harness_errors.is_empty();
    has_non_availability_result
        || attempted
            .difference(&recovered)
            .all(|key| still_unavailable.contains(key))
}

pub(crate) fn validate_recovery_key_sets(
    report: &RecoveryStabilityReport,
    immediate_report: &CheckerReport,
) -> Result<()> {
    ensure!(
        recovery_key_sets_are_consistent(report),
        "recovery reread key sets are internally inconsistent"
    );
    let attempted = report
        .reread_attempted_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let candidates = immediate_recovery_candidate_keys(immediate_report)?;
    ensure!(
        attempted == candidates,
        "recovery reread_attempted_keys does not equal checker-derived recovery candidates"
    );
    let recovered = report
        .reread_recovered_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let still = report
        .still_unavailable_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let candidate_keys = candidates.iter().cloned().collect::<Vec<_>>();
    let baseline = immediate_still_unavailable_keys(immediate_report, &candidate_keys)?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let allowed = baseline.union(&attempted).cloned().collect::<BTreeSet<_>>();
    ensure!(
        still.is_subset(&allowed),
        "recovery still_unavailable_keys contains keys absent from checker evidence and reread candidates"
    );

    let has_non_availability_result = !report.hash_mismatches.is_empty()
        || !report.data_corruption_evidence.is_empty()
        || !report.ambiguous_write_evidence.is_empty()
        || !report.harness_errors.is_empty();
    if !has_non_availability_result {
        let mut expected = baseline;
        expected.extend(attempted.difference(&recovered).cloned());
        ensure!(
            still == expected,
            "recovery still_unavailable_keys does not equal checker-derived unavailable keys plus attempted-but-not-recovered keys"
        );
    }
    Ok(())
}

fn finish_recovery_stability_report(
    report: &mut RecoveryStabilityReport,
    immediate_report: &CheckerReport,
) {
    report.classification = classify_recovery_stability(report, immediate_report);
}

pub(crate) fn classify_recovery_stability(
    report: &RecoveryStabilityReport,
    immediate_report: &CheckerReport,
) -> RecoveryStabilityClassification {
    let immediate_classification = immediate_report.failure_classification();
    if !report.classification_evidence.is_empty()
        && matches!(
            immediate_classification,
            RecoveryStabilityClassification::CommittedVersionMissing
                | RecoveryStabilityClassification::VersionHashMismatch
                | RecoveryStabilityClassification::DeleteMarkerMissing
                | RecoveryStabilityClassification::DeletedObjectResurrected
        )
    {
        return immediate_classification;
    }
    if !report.hash_mismatches.is_empty() || !report.data_corruption_evidence.is_empty() {
        return RecoveryStabilityClassification::DataCorruption;
    }
    if !report.harness_errors.is_empty() {
        return RecoveryStabilityClassification::HarnessError;
    }
    if !report.classification_evidence.is_empty()
        && immediate_classification == RecoveryStabilityClassification::CommittedVersionUnavailable
    {
        return immediate_classification;
    }
    if !report.still_unavailable_keys.is_empty() {
        return RecoveryStabilityClassification::CommittedObjectUnavailable;
    }
    if !report.ambiguous_write_evidence.is_empty() {
        return RecoveryStabilityClassification::AmbiguousWriteMaterialized;
    }
    if has_list_unavailable_or_unknown_signal(immediate_report) {
        return RecoveryStabilityClassification::ListUnavailableOrUnknown;
    }
    if let Some(classification) = [
        RecoveryStabilityClassification::DeleteMarkerLineageIncomplete,
        RecoveryStabilityClassification::MultipartUploadLineageIncomplete,
        RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite,
    ]
    .into_iter()
    .find(|classification| {
        report
            .classification_evidence
            .iter()
            .any(|evidence| classification.matches_classification_evidence(evidence))
    }) {
        return classification;
    }
    if !report.reread_attempted_keys.is_empty()
        && immediate_failures_are_only_reread_candidates(immediate_report, report)
    {
        return RecoveryStabilityClassification::RecoveryTailReadLatency;
    }
    classify_without_reread(immediate_report)
}

fn immediate_failures_are_only_reread_candidates(
    immediate_report: &CheckerReport,
    recovery_report: &RecoveryStabilityReport,
) -> bool {
    let Some(candidate_keys) = immediate_recovery_tail_candidate_keys(immediate_report) else {
        return false;
    };
    let attempted_keys = recovery_report
        .reread_attempted_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let recovered_keys = recovery_report
        .reread_recovered_keys
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    immediate_report.tenant_recovered
        && immediate_report.missing_committed_objects.is_empty()
        && immediate_report.hash_mismatches.is_empty()
        && immediate_report.successful_corrupted_reads.is_empty()
        && immediate_report
            .unexpected_visible_deleted_objects
            .is_empty()
        && immediate_report.unknown_writes_materialized.is_empty()
        && immediate_report.unknown_write_value_conflicts.is_empty()
        && immediate_report.final_list_warning_count == 0
        && immediate_report.committed_writes_missing_version_id_count == 0
        && immediate_report.missing_committed_versions.is_empty()
        && immediate_report.unavailable_committed_versions.is_empty()
        && immediate_report.version_hash_mismatches.is_empty()
        && immediate_report.missing_committed_delete_markers.is_empty()
        && immediate_report.resurrected_deleted_objects.is_empty()
        && immediate_report.delete_marker_lineage_incomplete.is_empty()
        && immediate_report
            .multipart_upload_lineage_incomplete
            .is_empty()
        && !candidate_keys.is_empty()
        && recovery_key_sets_are_consistent(recovery_report)
        && candidate_keys == attempted_keys
        && attempted_keys == recovered_keys
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
                mark_superseded_ambiguous_writes(model, &key, record);
                model.committed_writes += 1;
                model.deleted.remove(&key);
                model.ambiguous_delete_pending.remove(&key);
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
                model
                    .unknown_writes
                    .entry(key)
                    .or_default()
                    .push(AmbiguousWriteAttempt {
                        id: record.id.clone(),
                        kind: record.kind,
                        outcome: record.outcome,
                        object,
                        payload_ref: record.payload_ref,
                        started_at_ms: record.started_at_ms,
                        ended_at_ms: record.ended_at_ms,
                        superseded_by: None,
                    });
            }
        }
        OperationKind::Delete if record.outcome == OperationOutcome::Ok => {
            if let Some(key) = record.key.clone() {
                mark_superseded_ambiguous_writes(model, &key, record);
                model.ambiguous_delete_pending.remove(&key);
                model.live.remove(&key);
                model.deleted.insert(key);
            }
        }
        OperationKind::Delete
            if matches!(
                record.outcome,
                OperationOutcome::Timeout | OperationOutcome::Unknown
            ) =>
        {
            // An ambiguous delete of a committed object may or may not have
            // taken effect; mark it so a post-recovery 404 is tolerated instead
            // of being reported as a lost committed object.
            if let Some(key) = record.key.clone()
                && model.live.contains_key(&key)
            {
                model.ambiguous_delete_pending.insert(key);
            }
        }
        _ => {}
    }
}

fn mark_superseded_ambiguous_writes(
    model: &mut ObjectModel,
    key: &str,
    superseding_record: &OperationRecord,
) {
    mark_superseded_attempts(&mut model.unknown_writes, key, superseding_record);
}

fn mark_superseded_attempts(
    attempts_by_key: &mut BTreeMap<String, Vec<AmbiguousWriteAttempt>>,
    key: &str,
    superseding_record: &OperationRecord,
) {
    let Some(attempts) = attempts_by_key.get_mut(key) else {
        return;
    };
    for attempt in attempts {
        if attempt.superseded_by.is_none()
            && superseding_record.started_at_ms >= attempt.ended_at_ms
        {
            attempt.superseded_by = Some(SupersedingMutation {
                id: superseding_record.id.clone(),
                kind: superseding_record.kind,
                started_at_ms: superseding_record.started_at_ms,
            });
        }
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

/// A committed value that was stably live when a GET started, carrying the
/// generator inputs so ranged reads can be slice-verified against it (absent
/// for multipart bodies and legacy records).
#[derive(Debug, Clone, PartialEq, Eq)]
struct StableLiveObject {
    object: ExpectedObject,
    payload_ref: Option<PayloadRef>,
}

fn stable_live_objects_at_read_starts(
    records: &[OperationRecord],
) -> BTreeMap<usize, StableLiveObject> {
    let mut reads = records
        .iter()
        .enumerate()
        .filter_map(|(index, record)| {
            if record.kind != OperationKind::Get
                || record.outcome != OperationOutcome::Ok
                || record.version_id.is_some()
            {
                return None;
            }
            Some((index, record.started_at_ms, record.key.as_deref()?))
        })
        .collect::<Vec<_>>();
    reads.sort_by_key(|(_, started_at_ms, _)| *started_at_ms);

    let mut mutations = records
        .iter()
        .filter(|record| {
            record.outcome == OperationOutcome::Ok
                && matches!(
                    record.kind,
                    OperationKind::Put
                        | OperationKind::CompleteMultipartUpload
                        | OperationKind::Delete
                )
        })
        .collect::<Vec<_>>();
    mutations.sort_by_key(|record| record.ended_at_ms);

    let mut live = BTreeMap::<String, StableLiveObject>::new();
    let mut next_mutation = 0;
    let mut stable = BTreeMap::new();
    for (index, started_at_ms, key) in reads {
        while let Some(record) = mutations.get(next_mutation) {
            if record.ended_at_ms >= started_at_ms {
                break;
            }
            match record.kind {
                OperationKind::Put | OperationKind::CompleteMultipartUpload => {
                    if let Some((key, object)) = record_object(record) {
                        live.insert(
                            key,
                            StableLiveObject {
                                object,
                                payload_ref: record.payload_ref,
                            },
                        );
                    }
                }
                OperationKind::Delete => {
                    if let Some(key) = record.key.as_ref() {
                        live.remove(key);
                    }
                }
                _ => {}
            }
            next_mutation += 1;
        }
        if let Some(expected) = live.get(key) {
            stable.insert(index, expected.clone());
        }
    }
    stable
}

/// One committed write's value and completion window, kept per key so a GET
/// racing concurrent overwrites can be told apart from a genuinely corrupt or
/// stale read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CommittedWriteWindow {
    object: ExpectedObject,
    ended_at_ms: u64,
    /// Generator inputs for regenerating this write's exact body (absent for
    /// multipart bodies and legacy records, which cannot be slice-verified).
    payload_ref: Option<PayloadRef>,
}

/// Whether a successful GET that does not match the latest committed value is
/// still a legal concurrent read rather than corruption.
///
/// S3 gives concurrent overwrites of one key no client-observable order, so a
/// GET may legally return:
/// - the value of any committed write whose completion window overlaps the
///   GET itself (`w.ended >= get.started`), or
/// - the previous committed value while the *latest* write was still in
///   flight when the GET started (`latest.ended >= get.started`).
///
/// Both legs keep real stale-read detection intact: if every write finished
/// before the GET started, no exemption applies and an old value is still
/// reported as corruption. This complements `stable_live_objects_at_read_starts`
/// (which exempts a GET that returned the value stable-live at its start,
/// e.g. across an overlapping delete); this function additionally exempts a GET
/// that returned a value whose write window merely overlaps the GET.
fn concurrent_committed_read(
    history: &[CommittedWriteWindow],
    get_started_at_ms: u64,
    actual: &ExpectedObject,
) -> bool {
    let Some((latest, prior)) = history.split_last() else {
        return false;
    };
    let matches = |w: &CommittedWriteWindow| {
        w.object.sha256 == actual.sha256 && w.object.size_bytes == actual.size_bytes
    };
    if prior
        .iter()
        .any(|w| matches(w) && w.ended_at_ms >= get_started_at_ms)
    {
        return true;
    }
    if latest.ended_at_ms >= get_started_at_ms
        && let Some(previous) = prior.last()
    {
        return matches(previous);
    }
    false
}

/// Regenerate the expected slice hash for a reproducible body (seeded generator
/// inputs recorded and the range fits within the object). Returns None when the
/// body is unreproducible (no payload_ref) or the range does not fit.
fn regenerated_slice_sha(
    payload_ref: Option<PayloadRef>,
    size_bytes: usize,
    range: ByteRange,
) -> Option<String> {
    let payload_ref = payload_ref?;
    let size = size_bytes as u64;
    if range.offset >= size || range.length == 0 || range.offset + range.length > size {
        return None;
    }
    let body = seeded_bytes(payload_ref.seed, payload_ref.index, size_bytes);
    let start = range.offset as usize;
    let end = (range.offset + range.length) as usize;
    Some(sha256_hex(&body[start..end]))
}

/// Per-key model state a ranged GET is verified against.
struct RangedReadState<'a> {
    /// Committed writes still on the key's history (a committed delete wipes
    /// this before the GET record is processed).
    history: &'a [CommittedWriteWindow],
    /// Ambiguous (timeout/unknown) write attempts against the key.
    ambiguous: &'a [AmbiguousWriteAttempt],
    /// The committed value stably live when the GET started, if any.
    stable_at_start: Option<&'a StableLiveObject>,
    /// The key's current committed live value, if any.
    live_object: Option<&'a ExpectedObject>,
}

/// Verify a successful ranged GET against the slices it could legally observe.
///
/// Candidates are the committed values the GET could linearize to (latest
/// committed write, writes whose completion window overlaps the GET, the
/// immediately-previous value while the latest write was in flight -- the same
/// legs as `concurrent_committed_read` -- and the value stably live when the
/// GET started, which survives an overlapping committed delete exactly like
/// the whole-object stable-at-read-start exemption) PLUS any ambiguous
/// (timeout/unknown) write, which may have materialized server-side. A slice
/// matching a committed value is clean; matching a materialized pending
/// ambiguous write is `unknown_writes_materialized`, and matching one already
/// superseded by a later committed mutation additionally records
/// `unknown_write_value_conflicts`, mirroring the whole-object path (NOT
/// corruption). A mismatch is only flagged as corruption when every candidate
/// is reproducible and none match; if any candidate body is unreproducible
/// (multipart, legacy) or is a range-spanning ambiguous write, the mismatch is
/// inconclusive -- the slice may belong to that unverifiable body.
fn verify_ranged_get(
    key: &str,
    range: ByteRange,
    record: &OperationRecord,
    state: RangedReadState<'_>,
    anomalies: &mut ReadAnomalies,
) {
    let actual_sha = record.value_sha256.as_deref().unwrap_or_default();
    let actual_len = record.size_bytes.unwrap_or_default() as u64;
    if actual_len != range.length {
        anomalies.corrupted_reads.push(format!(
            "{key}: ranged GET bytes={}-{} returned {} bytes instead of {}",
            range.offset,
            range.offset + range.length - 1,
            actual_len,
            range.length
        ));
        return;
    }

    // Reproducible slice inputs (payload_ref, size) for every committed value
    // the GET could legally observe.
    let mut candidates: Vec<(Option<PayloadRef>, usize)> = Vec::new();
    if let Some((latest, prior)) = state.history.split_last() {
        candidates.push((latest.payload_ref, latest.object.size_bytes));
        for window in prior {
            if window.ended_at_ms >= record.started_at_ms {
                candidates.push((window.payload_ref, window.object.size_bytes));
            }
        }
        if latest.ended_at_ms >= record.started_at_ms
            && let Some(previous) = prior.last()
        {
            candidates.push((previous.payload_ref, previous.object.size_bytes));
        }
    }
    // The value stably live when the GET started is always legally
    // observable, even when a committed delete that overlaps the GET has
    // since wiped the key's committed history (the whole-object path's
    // stable-at-read-start exemption).
    if let Some(stable) = state.stable_at_start {
        candidates.push((stable.payload_ref, stable.object.size_bytes));
    }

    let mut unverifiable = false;
    for (payload_ref, size) in &candidates {
        match regenerated_slice_sha(*payload_ref, *size, range) {
            Some(expected) if expected == actual_sha => return,
            Some(_) => {}
            None => unverifiable = true,
        }
    }

    // An ambiguous write may have materialized: a slice that matches its
    // regenerated body means the write landed. A pending attempt's match is
    // unknown_writes_materialized (not corruption); a superseded attempt's
    // match additionally conflicts with the committed value that superseded
    // it, exactly like the whole-object path. One that spans the range but is
    // unreproducible makes a mismatch inconclusive.
    let mut ambiguous_spans_range = false;
    let mut pending_match: Option<&AmbiguousWriteAttempt> = None;
    let mut superseded_match: Option<&AmbiguousWriteAttempt> = None;
    for attempt in state.ambiguous {
        match regenerated_slice_sha(attempt.payload_ref, attempt.object.size_bytes, range) {
            Some(expected) if expected == actual_sha => {
                if attempt.superseded_by.is_none() {
                    pending_match = Some(attempt);
                } else {
                    superseded_match = Some(attempt);
                }
            }
            Some(_) => {}
            None if range.offset + range.length <= attempt.object.size_bytes as u64 => {
                ambiguous_spans_range = true;
            }
            None => {}
        }
    }
    let actual = ExpectedObject {
        sha256: actual_sha.to_string(),
        size_bytes: record.size_bytes.unwrap_or_default(),
    };
    if let Some(attempt) = pending_match {
        anomalies.unknown_writes_materialized.push(
            ambiguous_write_materialized_from_object_message(key, attempt, &actual),
        );
        return;
    }
    if let Some(attempt) = superseded_match {
        anomalies.unknown_writes_materialized.push(
            ambiguous_write_materialized_from_object_message(key, attempt, &actual),
        );
        anomalies
            .unknown_write_value_conflicts
            .push(superseded_ambiguous_object_conflict_message(
                key,
                state.live_object,
                attempt,
                &actual,
            ));
        return;
    }

    if unverifiable || ambiguous_spans_range {
        return;
    }
    if !state.ambiguous.is_empty() {
        // Ambiguous writes exist but the slice matches neither them nor any
        // committed value: the read is unexplained but not provable
        // corruption, exactly as the whole-object path classifies it.
        anomalies.unknown_write_value_conflicts.push(format!(
            "{key}: ranged GET bytes={}-{} returned slice sha {} matching no committed value while ambiguous writes exist",
            range.offset,
            range.offset + range.length - 1,
            actual_sha
        ));
        return;
    }
    if candidates.is_empty() {
        // No committed value and no ambiguous write. If the key is not live
        // either, a successful ranged read of a never-committed key is a
        // resurrection-class signal.
        if state.live_object.is_none() {
            anomalies.visible_deleted_objects.push(format!(
                "{key}: successful ranged GET had no committed live value"
            ));
        }
        return;
    }
    anomalies.corrupted_reads.push(format!(
        "{key}: ranged GET bytes={}-{} returned slice sha {} matching no committed value",
        range.offset,
        range.offset + range.length - 1,
        actual_sha
    ));
}

fn successful_read_anomalies(records: &[OperationRecord]) -> ReadAnomalies {
    let mut live = BTreeMap::<String, ExpectedObject>::new();
    let mut committed_history = BTreeMap::<String, Vec<CommittedWriteWindow>>::new();
    let mut ambiguous_writes = BTreeMap::<String, Vec<AmbiguousWriteAttempt>>::new();
    let stable_live_at_start = stable_live_objects_at_read_starts(records);
    let mut anomalies = ReadAnomalies::default();
    for (record_index, record) in records.iter().enumerate() {
        match record.kind {
            OperationKind::Put | OperationKind::CompleteMultipartUpload
                if record.outcome == OperationOutcome::Ok =>
            {
                if let Some((key, object)) = record_object(record) {
                    mark_superseded_attempts(&mut ambiguous_writes, &key, record);
                    committed_history
                        .entry(key.clone())
                        .or_default()
                        .push(CommittedWriteWindow {
                            object: object.clone(),
                            ended_at_ms: record.ended_at_ms,
                            payload_ref: record.payload_ref,
                        });
                    live.insert(key, object);
                }
            }
            OperationKind::Put | OperationKind::CompleteMultipartUpload
                if matches!(
                    record.outcome,
                    OperationOutcome::Timeout | OperationOutcome::Unknown
                ) =>
            {
                if let Some((key, object)) = record_object(record) {
                    ambiguous_writes
                        .entry(key)
                        .or_default()
                        .push(AmbiguousWriteAttempt {
                            id: record.id.clone(),
                            kind: record.kind,
                            outcome: record.outcome,
                            object,
                            payload_ref: record.payload_ref,
                            started_at_ms: record.started_at_ms,
                            ended_at_ms: record.ended_at_ms,
                            superseded_by: None,
                        });
                }
            }
            OperationKind::Delete if record.outcome == OperationOutcome::Ok => {
                if let Some(key) = record.key.as_ref() {
                    mark_superseded_attempts(&mut ambiguous_writes, key, record);
                    committed_history.remove(key);
                    live.remove(key);
                }
            }
            OperationKind::Get if record.outcome == OperationOutcome::Ok => {
                // Versioned GETs intentionally read historical versions whose
                // hashes differ from the latest committed value; they are
                // verified against their own lineage entry instead.
                if record.version_id.is_some() {
                    continue;
                }
                let Some(key) = record.key.as_ref() else {
                    continue;
                };
                if let Some(range) = record.range {
                    // A ranged GET's recorded hash describes the slice, so the
                    // whole-object comparison below would always misfire.
                    verify_ranged_get(
                        key,
                        range,
                        record,
                        RangedReadState {
                            history: committed_history
                                .get(key)
                                .map(Vec::as_slice)
                                .unwrap_or_default(),
                            ambiguous: ambiguous_writes
                                .get(key)
                                .map(Vec::as_slice)
                                .unwrap_or_default(),
                            stable_at_start: stable_live_at_start.get(&record_index),
                            live_object: live.get(key),
                        },
                        &mut anomalies,
                    );
                    continue;
                }
                let actual_hash = record.value_sha256.as_deref().unwrap_or_default();
                let actual = ExpectedObject {
                    sha256: actual_hash.to_string(),
                    size_bytes: record.size_bytes.unwrap_or_default(),
                };
                let stable_expected = stable_live_at_start.get(&record_index);
                if stable_expected.is_some_and(|expected| expected.object == actual) {
                    continue;
                }
                let attempts = ambiguous_writes
                    .get(key)
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                match live.get(key) {
                    Some(expected)
                        if expected.sha256 == actual.sha256
                            && expected.size_bytes == actual.size_bytes => {}
                    _ if matching_active_ambiguous_object(attempts, &actual).is_some() => {
                        let attempt = matching_active_ambiguous_object(attempts, &actual)
                            .expect("checked ambiguous object");
                        anomalies.unknown_writes_materialized.push(
                            ambiguous_write_materialized_from_object_message(key, attempt, &actual),
                        );
                    }
                    _ if matching_superseded_ambiguous_object(attempts, &actual).is_some() => {
                        let attempt = matching_superseded_ambiguous_object(attempts, &actual)
                            .expect("checked superseded ambiguous object");
                        anomalies.unknown_writes_materialized.push(
                            ambiguous_write_materialized_from_object_message(key, attempt, &actual),
                        );
                        anomalies.unknown_write_value_conflicts.push(
                            superseded_ambiguous_object_conflict_message(
                                key,
                                live.get(key),
                                attempt,
                                &actual,
                            ),
                        );
                    }
                    Some(expected) if !attempts.is_empty() => {
                        anomalies.unknown_write_value_conflicts.push(
                            unknown_write_value_conflict_from_object_message(
                                key,
                                Some(expected),
                                attempts,
                                &actual,
                            ),
                        );
                    }
                    Some(expected) => {
                        let history = committed_history
                            .get(key)
                            .map(Vec::as_slice)
                            .unwrap_or_default();
                        if !concurrent_committed_read(history, record.started_at_ms, &actual) {
                            anomalies.corrupted_reads.push(format!(
                                "{key}: expected {} ({} bytes), got {} ({} bytes)",
                                expected.sha256,
                                expected.size_bytes,
                                actual.sha256,
                                actual.size_bytes
                            ));
                        }
                    }
                    None if !attempts.is_empty() => anomalies.unknown_write_value_conflicts.push(
                        unknown_write_value_conflict_from_object_message(
                            key, None, attempts, &actual,
                        ),
                    ),
                    None if let Some(expected) = stable_expected => {
                        anomalies.corrupted_reads.push(format!(
                            "{key}: expected {} ({} bytes), got {} ({} bytes)",
                            expected.object.sha256,
                            expected.object.size_bytes,
                            actual.sha256,
                            actual.size_bytes
                        ));
                    }
                    None => anomalies
                        .visible_deleted_objects
                        .push(format!("{key}: successful GET had no committed live value")),
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
        AmbiguousWriteAttempt, CheckerReport, ExpectedObject, RecoveryStabilityClassification,
        RecoveryStabilityReport, WarningSummary, evaluate_committed_get, evaluate_final_get,
        evaluate_recovery_reread_get, finish_recovery_stability_report,
        immediate_still_unavailable_keys, is_recovery_tail_read_failure, list_history_warnings,
        object_model, recovery_tail_candidate_keys, successful_read_anomalies,
        validate_recovery_key_sets,
    };
    use crate::fault::history::{
        ByteRange, OperationKind, OperationOutcome, OperationRecord, PayloadRef,
    };
    use crate::fault::workload::seeded_bytes;
    use crate::fault::workload::{GetObjectResult, sha256_hex};
    use std::collections::{BTreeMap, BTreeSet};

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
            run_id: None,
            kind,
            bucket: "bucket".to_string(),
            key: Some(key.to_string()),
            value_sha256: Some(hash.to_string()),
            size_bytes: Some(1),
            version_id: None,
            payload_ref: None,
            range: None,
            started_at_ms: 1,
            ended_at_ms: 2,
            outcome,
            http_status: Some(200),
            error: None,
            listed_keys: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn timed_record(
        id: &str,
        kind: OperationKind,
        key: &str,
        hash: &str,
        outcome: OperationOutcome,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        OperationRecord {
            started_at_ms,
            ended_at_ms,
            ..record(id, kind, key, hash, outcome)
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
            run_id: None,
            kind: OperationKind::List,
            bucket: "bucket".to_string(),
            key: Some(prefix.to_string()),
            value_sha256: None,
            size_bytes: Some(keys.len()),
            version_id: None,
            listed_keys: Some(keys.iter().map(|key| key.to_string()).collect()),
            payload_ref: None,
            range: None,
            started_at_ms,
            ended_at_ms,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn ambiguous_attempt(id: &str, hash: &str) -> AmbiguousWriteAttempt {
        AmbiguousWriteAttempt {
            id: id.to_string(),
            kind: OperationKind::Put,
            outcome: OperationOutcome::Timeout,
            object: ExpectedObject {
                sha256: hash.to_string(),
                size_bytes: 1,
            },
            payload_ref: None,
            started_at_ms: 1,
            ended_at_ms: 2,
            superseded_by: None,
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

        assert_eq!(
            anomalies.corrupted_reads,
            vec!["k: expected good (1 bytes), got bad (1 bytes)"]
        );
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
    fn ambiguous_delete_marks_committed_key_pending() {
        let model = object_model(&[
            record("op-1", OperationKind::Put, "k", "v1", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Timeout,
            ),
        ]);

        // The object is still committed-present, but the ambiguous delete makes
        // a post-recovery 404 a legitimate outcome.
        assert!(model.live.contains_key("k"));
        assert!(model.ambiguous_delete_pending.contains("k"));
    }

    #[test]
    fn recommit_clears_ambiguous_delete_pending() {
        let model = object_model(&[
            record("op-1", OperationKind::Put, "k", "v1", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Unknown,
            ),
            record("op-3", OperationKind::Put, "k", "v2", OperationOutcome::Ok),
        ]);

        // A fresh committed write supersedes the ambiguous delete: the key is
        // definitively present again, so a 404 would be a real failure.
        assert!(model.live.contains_key("k"));
        assert!(!model.ambiguous_delete_pending.contains("k"));
    }

    #[test]
    fn committed_delete_clears_ambiguous_delete_pending() {
        let model = object_model(&[
            record("op-1", OperationKind::Put, "k", "v1", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Timeout,
            ),
            record("op-3", OperationKind::Delete, "k", "", OperationOutcome::Ok),
        ]);

        // The delete became definitive; the key is deleted (handled by the
        // resurrection probe) and no longer pending-ambiguous.
        assert!(model.deleted.contains("k"));
        assert!(!model.live.contains_key("k"));
        assert!(!model.ambiguous_delete_pending.contains("k"));
    }

    #[test]
    fn ambiguous_delete_of_uncommitted_key_is_not_pending() {
        // A delete with no prior committed write leaves nothing to lose.
        let model = object_model(&[record(
            "op-1",
            OperationKind::Delete,
            "k",
            "",
            OperationOutcome::Timeout,
        )]);

        assert!(model.ambiguous_delete_pending.is_empty());
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
            vec![super::CommittedReadFailure::observed(
                "k",
                OperationOutcome::Timeout,
                Some(200),
                Some("get body read timed out"),
                None
            )]
        );
    }

    #[test]
    fn ambiguous_overwrite_preserving_committed_value_is_not_materialized() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"a".to_vec()),
            },
        );

        assert_eq!(report.verified_live_objects, 1);
        assert!(report.hash_mismatches.is_empty());
        assert!(report.unknown_writes_materialized.is_empty());
        assert_eq!(report.unknown_writes_preserved_committed.len(), 1);
    }

    #[test]
    fn ambiguous_overwrite_materializing_is_not_committed_hash_mismatch() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(report.hash_mismatches.is_empty());
        assert_eq!(report.unknown_writes_materialized.len(), 1);
        assert_eq!(
            super::classify_without_reread(&report),
            RecoveryStabilityClassification::AmbiguousWriteMaterialized
        );
    }

    /// The final checker verdict and the pre-recommit gate must classify the
    /// same evidence identically (review finding C3-3): a committed-loss
    /// report derives committed_object_unavailable, a corruption report
    /// derives data_corruption — never the catch-all product_or_environment.
    #[test]
    fn classify_without_reread_covers_final_verdict_evidence() {
        let mut unavailable = empty_report();
        unavailable.missing_committed_objects.push("k1".to_string());
        assert_eq!(
            super::classify_without_reread(&unavailable),
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );

        let mut corrupted = empty_report();
        corrupted
            .hash_mismatches
            .push("k2: expected a, got b".to_string());
        assert_eq!(
            super::classify_without_reread(&corrupted),
            RecoveryStabilityClassification::DataCorruption
        );

        // No product signal at all falls back to harness_error, not to a
        // product bucket.
        let clean = empty_report();
        assert_eq!(
            super::classify_without_reread(&clean),
            RecoveryStabilityClassification::HarnessError
        );
    }

    #[test]
    fn precise_final_classification_goldens_use_history_derived_evidence() {
        let committed_put = record(
            "put-200",
            OperationKind::Put,
            "put-key",
            &sha256_hex(b"expected"),
            OperationOutcome::Ok,
        );
        let put_model = object_model(std::slice::from_ref(&committed_put));

        let mut object_missing = empty_report();
        evaluate_final_get(
            &mut object_missing,
            "put-key".to_string(),
            put_model.live.get("put-key"),
            &[],
            GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );
        object_missing.final_listed_objects = Some(0);
        object_missing.final_list_warning_count = 1;
        object_missing
            .list_warnings
            .push("LIST prefix fault-test/ did not include expected live key put-key".to_string());

        let mut object_content_mismatch = empty_report();
        evaluate_final_get(
            &mut object_content_mismatch,
            "put-key".to_string(),
            put_model.live.get("put-key"),
            &[],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"different".to_vec()),
            },
        );

        let mut versioned_put = committed_put.clone();
        versioned_put.version_id = Some("version-1".to_string());
        let version_lineage = super::committed_version_lineage(&[versioned_put]);
        let version = version_lineage.versions.first().expect("committed version");
        let mut version_missing = empty_report();
        super::evaluate_committed_version_get(
            &mut version_missing,
            version,
            GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );
        let mut version_content_mismatch = empty_report();
        super::evaluate_committed_version_get(
            &mut version_content_mismatch,
            version,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"different".to_vec()),
            },
        );
        let mut version_unavailable = empty_report();
        super::evaluate_committed_version_get(
            &mut version_unavailable,
            version,
            GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: None,
                error: Some("get object timed out".to_string()),
                body: None,
            },
        );

        let mut committed_delete = record(
            "delete-204",
            OperationKind::Delete,
            "deleted-key",
            "",
            OperationOutcome::Ok,
        );
        committed_delete.version_id = Some("marker-1".to_string());
        let delete_lineage = super::committed_version_lineage(&[committed_delete]);
        let mut delete_marker_missing = empty_report();
        delete_marker_missing.missing_committed_delete_markers =
            super::committed_delete_marker_presence(&delete_lineage.delete_markers, &[]).1;

        let delete_without_marker_id = record(
            "delete-204-no-version-id",
            OperationKind::Delete,
            "deleted-key",
            "",
            OperationOutcome::Ok,
        );
        let incomplete_delete_lineage =
            super::committed_version_lineage(&[delete_without_marker_id]);
        let mut delete_marker_lineage_incomplete = empty_report();
        delete_marker_lineage_incomplete.delete_marker_lineage_incomplete =
            incomplete_delete_lineage.delete_marker_lineage_incomplete;

        let mut deleted_object_resurrected = empty_report();
        deleted_object_resurrected.resurrected_deleted_objects.push(
            super::evaluate_deleted_reread(
                "deleted-key",
                &GetObjectResult {
                    outcome: OperationOutcome::Ok,
                    http_status: Some(200),
                    error: None,
                    body: Some(b"resurrected".to_vec()),
                },
            )
            .expect("resurrection evidence"),
        );

        let committed_multipart = record(
            "mpu-200",
            OperationKind::CompleteMultipartUpload,
            "mpu-key",
            &sha256_hex(b"multipart"),
            OperationOutcome::Ok,
        );
        let incomplete_multipart_lineage =
            super::committed_version_lineage(std::slice::from_ref(&committed_multipart));
        let mut multipart_lineage_incomplete = empty_report();
        multipart_lineage_incomplete.committed_writes_missing_version_id_count =
            incomplete_multipart_lineage.missing_version_id_count;
        multipart_lineage_incomplete.committed_writes_missing_version_id =
            incomplete_multipart_lineage.missing_version_id_samples;
        multipart_lineage_incomplete.multipart_upload_lineage_incomplete =
            incomplete_multipart_lineage.multipart_upload_lineage_incomplete;

        let mut committed_multipart_with_version = committed_multipart;
        committed_multipart_with_version.version_id = Some("mpu-version-1".to_string());
        let multipart_lineage =
            super::committed_version_lineage(&[committed_multipart_with_version]);
        let multipart_version = multipart_lineage
            .versions
            .first()
            .expect("multipart committed version");
        let mut multipart_complete_loss = empty_report();
        super::evaluate_committed_version_get(
            &mut multipart_complete_loss,
            multipart_version,
            GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );

        let mut ambiguous_write = empty_report();
        ambiguous_write
            .unknown_writes_materialized
            .push("timeout-put materialized".to_string());
        let mut list_timeout = empty_report();
        list_timeout.final_list_warning_count = 1;
        list_timeout
            .list_warnings
            .push("LIST prefix fault-test/ did not complete".to_string());
        let mut list_content_mismatch = empty_report();
        list_content_mismatch.final_list_warning_count = 1;
        list_content_mismatch
            .list_warnings
            .push("LIST prefix did not include expected live key put-key".to_string());

        let golden = [
            ("put_200_loss", object_missing.failure_classification()),
            (
                "committed_object_content_mismatch",
                object_content_mismatch.failure_classification(),
            ),
            (
                "committed_version_missing",
                version_missing.failure_classification(),
            ),
            (
                "committed_version_hash_mismatch",
                version_content_mismatch.failure_classification(),
            ),
            (
                "committed_version_timeout",
                version_unavailable.failure_classification(),
            ),
            (
                "delete_204_marker_missing",
                delete_marker_missing.failure_classification(),
            ),
            (
                "delete_204_resurrection",
                deleted_object_resurrected.failure_classification(),
            ),
            (
                "delete_204_missing_marker_id",
                delete_marker_lineage_incomplete.failure_classification(),
            ),
            (
                "committed_mpu_missing_version_id",
                multipart_lineage_incomplete.failure_classification(),
            ),
            (
                "committed_mpu_version_loss",
                multipart_complete_loss.failure_classification(),
            ),
            (
                "ambiguous_write_materialized",
                ambiguous_write.failure_classification(),
            ),
            ("list_timeout", list_timeout.failure_classification()),
            (
                "completed_list_wrong_content",
                list_content_mismatch.failure_classification(),
            ),
        ]
        .map(|(case, classification)| (case, classification.as_str()));

        assert_eq!(
            golden,
            [
                ("put_200_loss", "committed_object_unavailable"),
                ("committed_object_content_mismatch", "data_corruption"),
                ("committed_version_missing", "committed_version_missing"),
                ("committed_version_hash_mismatch", "version_hash_mismatch"),
                ("committed_version_timeout", "committed_version_unavailable"),
                ("delete_204_marker_missing", "delete_marker_missing"),
                ("delete_204_resurrection", "deleted_object_resurrected"),
                (
                    "delete_204_missing_marker_id",
                    "delete_marker_lineage_incomplete"
                ),
                (
                    "committed_mpu_missing_version_id",
                    "multipart_upload_lineage_incomplete"
                ),
                ("committed_mpu_version_loss", "committed_version_missing"),
                (
                    "ambiguous_write_materialized",
                    "ambiguous_write_materialized"
                ),
                ("list_timeout", "list_unavailable_or_unknown"),
                ("completed_list_wrong_content", "data_corruption"),
            ]
        );
    }

    #[test]
    fn superseded_ambiguous_final_get_is_data_corruption_evidence() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let mut attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        attempted.superseded_by = Some(super::SupersedingMutation {
            id: "op-3".to_string(),
            kind: OperationKind::Put,
            started_at_ms: 3,
        });

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(report.hash_mismatches.is_empty());
        assert_eq!(report.unknown_writes_materialized.len(), 1);
        assert_eq!(report.unknown_write_value_conflicts.len(), 1);
        assert_eq!(
            super::classify_without_reread(&report),
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn ambiguous_overwrite_unrelated_value_is_data_corruption_evidence() {
        let mut report = empty_report();
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_final_get(
            &mut report,
            "k".to_string(),
            Some(&committed),
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"c".to_vec()),
            },
        );

        assert!(report.hash_mismatches.is_empty());
        assert_eq!(report.unknown_write_value_conflicts.len(), 1);
        assert_eq!(
            super::classify_without_reread(&report),
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn successful_get_after_timeout_overwrite_is_ambiguous_not_corrupt() {
        let records = vec![
            record("op-1", OperationKind::Put, "k", "old", OperationOutcome::Ok),
            record(
                "op-2",
                OperationKind::Put,
                "k",
                "new",
                OperationOutcome::Timeout,
            ),
            record("op-3", OperationKind::Get, "k", "new", OperationOutcome::Ok),
        ];

        let anomalies = successful_read_anomalies(&records);

        assert!(anomalies.corrupted_reads.is_empty());
        assert_eq!(anomalies.unknown_writes_materialized.len(), 1);
    }

    #[test]
    fn overlapping_get_can_return_pre_delete_value() {
        let records = vec![
            timed_record(
                "op-1",
                OperationKind::Put,
                "k",
                "old",
                OperationOutcome::Ok,
                1,
                2,
            ),
            timed_record(
                "op-3",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Ok,
                12,
                13,
            ),
            timed_record(
                "op-2",
                OperationKind::Get,
                "k",
                "old",
                OperationOutcome::Ok,
                10,
                20,
            ),
        ];

        let anomalies = successful_read_anomalies(&records);

        assert!(anomalies.corrupted_reads.is_empty());
        assert!(anomalies.visible_deleted_objects.is_empty());
    }

    #[test]
    fn post_delete_get_returning_body_is_still_resurrection() {
        let records = vec![
            timed_record(
                "op-1",
                OperationKind::Put,
                "k",
                "old",
                OperationOutcome::Ok,
                1,
                2,
            ),
            timed_record(
                "op-2",
                OperationKind::Delete,
                "k",
                "",
                OperationOutcome::Ok,
                3,
                4,
            ),
            timed_record(
                "op-3",
                OperationKind::Get,
                "k",
                "old",
                OperationOutcome::Ok,
                5,
                6,
            ),
        ];

        let anomalies = successful_read_anomalies(&records);

        assert_eq!(
            anomalies.visible_deleted_objects,
            vec!["k: successful GET had no committed live value"]
        );
    }

    #[test]
    fn later_non_overlapping_ok_write_makes_old_ambiguous_value_a_conflict() {
        let records = vec![
            timed_record(
                "op-1",
                OperationKind::Put,
                "k",
                "old",
                OperationOutcome::Ok,
                1,
                2,
            ),
            timed_record(
                "op-2",
                OperationKind::Put,
                "k",
                "timeout",
                OperationOutcome::Timeout,
                3,
                4,
            ),
            timed_record(
                "op-3",
                OperationKind::Put,
                "k",
                "new",
                OperationOutcome::Ok,
                5,
                6,
            ),
            timed_record(
                "op-4",
                OperationKind::Get,
                "k",
                "timeout",
                OperationOutcome::Ok,
                7,
                8,
            ),
        ];

        let model = object_model(&records);
        let anomalies = successful_read_anomalies(&records);

        assert_eq!(model.live.get("k").expect("live").sha256, "new");
        let attempt = model
            .unknown_writes
            .get("k")
            .expect("ambiguous")
            .first()
            .expect("attempt");
        assert_eq!(
            attempt.superseded_by.as_ref().expect("superseded").id,
            "op-3"
        );
        assert!(anomalies.corrupted_reads.is_empty());
        assert_eq!(anomalies.unknown_writes_materialized.len(), 1);
        assert_eq!(anomalies.unknown_write_value_conflicts.len(), 1);
        assert!(
            anomalies.unknown_write_value_conflicts[0].contains("superseded ambiguous attempt")
        );
    }

    #[test]
    fn recovery_reread_materialized_ambiguous_write_is_not_hash_mismatch() {
        let mut recovery = recovery_report_with_attempted_key("k");
        let mut pending = BTreeSet::from(["k".to_string()]);
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));

        evaluate_recovery_reread_get(
            &mut recovery,
            &mut pending,
            "k".to_string(),
            &committed,
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(pending.is_empty());
        assert!(recovery.hash_mismatches.is_empty());
        assert_eq!(recovery.ambiguous_write_evidence.len(), 1);
    }

    #[test]
    fn recovery_reread_superseded_ambiguous_write_is_correctness_evidence() {
        let mut recovery = recovery_report_with_attempted_key("k");
        let mut pending = BTreeSet::from(["k".to_string()]);
        let committed = ExpectedObject {
            sha256: sha256_hex(b"a"),
            size_bytes: 1,
        };
        let mut attempted = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        attempted.superseded_by = Some(super::SupersedingMutation {
            id: "op-3".to_string(),
            kind: OperationKind::Put,
            started_at_ms: 3,
        });

        evaluate_recovery_reread_get(
            &mut recovery,
            &mut pending,
            "k".to_string(),
            &committed,
            &[attempted],
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );
        finish_recovery_stability_report(&mut recovery, &empty_report());

        assert!(pending.is_empty());
        assert_eq!(recovery.ambiguous_write_evidence.len(), 1);
        assert_eq!(recovery.data_corruption_evidence.len(), 1);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            recovery.evidence_classifications(),
            vec![
                "ambiguous_write_materialized".to_string(),
                "data_corruption".to_string()
            ]
        );
    }

    #[test]
    fn recovery_tail_candidates_include_body_tail_and_request_timeouts() {
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
        assert!(is_recovery_tail_read_failure(
            request_timeout.outcome,
            request_timeout.http_status,
            request_timeout.error.as_deref()
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
        immediate.unavailable_committed_objects.push(
            "k: outcome=Timeout status=200 error=\"get body read timed out\""
                .to_string()
                .into(),
        );
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.reread_recovered_keys.push("k".to_string());

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::RecoveryTailReadLatency
        );
    }

    #[test]
    fn recovery_tail_classification_requires_exact_unique_candidate_keys() {
        let mut immediate = empty_report();
        immediate.unavailable_committed_objects.push(
            "b: outcome=Timeout status=200 error=\"get body read timed out\""
                .to_string()
                .into(),
        );
        immediate.unknown_committed_read_failures.push(
            "a: outcome=Unknown error=\"request timed out before headers\""
                .to_string()
                .into(),
        );
        let mut recovery = recovery_report_with_attempted_key("b");
        recovery.reread_attempted_keys.push("a".to_string());
        recovery.reread_recovered_keys = vec!["a".to_string(), "b".to_string()];

        finish_recovery_stability_report(&mut recovery, &immediate);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::RecoveryTailReadLatency,
            "key-set matching must not depend on vector order"
        );

        recovery.reread_attempted_keys = vec!["a".to_string(), "other".to_string()];
        recovery.reread_recovered_keys = recovery.reread_attempted_keys.clone();
        finish_recovery_stability_report(&mut recovery, &immediate);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable,
            "same counts for different keys must not prove tail recovery"
        );

        recovery.reread_attempted_keys = vec!["a".to_string(), "a".to_string(), "b".to_string()];
        recovery.reread_recovered_keys = recovery.reread_attempted_keys.clone();
        finish_recovery_stability_report(&mut recovery, &immediate);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable,
            "duplicate recovery keys must fail closed"
        );

        immediate
            .unavailable_committed_objects
            .push(immediate.unavailable_committed_objects[0].clone());
        recovery.reread_attempted_keys = vec!["a".to_string(), "b".to_string()];
        recovery.reread_recovered_keys = recovery.reread_attempted_keys.clone();
        finish_recovery_stability_report(&mut recovery, &immediate);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable,
            "duplicate checker evidence must fail closed"
        );
    }

    #[test]
    fn structured_recovery_evidence_preserves_delimiters_in_keys_and_errors() {
        let key = "key: outcome=Timeout: unexpected body for Ok";
        let mut immediate = empty_report();
        immediate
            .unavailable_committed_objects
            .push(super::CommittedReadFailure::observed(
                key,
                OperationOutcome::Timeout,
                Some(200),
                Some("get body read timed out: outcome=Unknown"),
                None,
            ));
        let encoded = serde_json::to_string(&immediate).expect("encode structured evidence");
        let immediate = serde_json::from_str(&encoded).expect("decode structured evidence");
        let mut recovery = recovery_report_with_attempted_key(key);
        recovery.reread_recovered_keys = recovery.reread_attempted_keys.clone();
        finish_recovery_stability_report(&mut recovery, &immediate);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::RecoveryTailReadLatency
        );
        assert!(recovery.still_unavailable_keys.is_empty());
    }

    #[test]
    fn recovery_tail_failure_key_parsing_is_fail_closed_when_ambiguous() {
        let mut immediate = empty_report();
        immediate.unavailable_committed_objects.push(
            "key: outcome=Timeout: outcome=Timeout status=200 error=\"get body read timed out\""
                .to_string()
                .into(),
        );
        let mut recovery = recovery_report_with_attempted_key("key: outcome=Timeout");
        recovery.reread_recovered_keys = recovery.reread_attempted_keys.clone();

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );
    }

    #[test]
    fn recovery_key_sets_reject_ghosts_and_derive_exact_unavailable_set() {
        let mut immediate = empty_report();
        immediate.missing_committed_objects.push("z".to_string());
        immediate.unavailable_committed_objects.extend([
            "a: outcome=Timeout status=200 error=\"get body read timed out\""
                .to_string()
                .into(),
            "b: outcome=Timeout status=200 error=\"get body read timed out\""
                .to_string()
                .into(),
        ]);
        let mut recovery = recovery_report_with_attempted_key("a");
        recovery.reread_attempted_keys.push("b".to_string());
        recovery.reread_recovered_keys.push("a".to_string());
        recovery.still_unavailable_keys = vec!["b".to_string(), "z".to_string()];

        validate_recovery_key_sets(&recovery, &immediate)
            .expect("checker evidence derives the exact multi-key unavailable set");

        recovery.reread_recovered_keys.push("b".to_string());
        recovery.still_unavailable_keys = vec!["ghost".to_string(), "z".to_string()];
        let error = validate_recovery_key_sets(&recovery, &immediate)
            .expect_err("an unrelated still-unavailable key must fail closed");
        assert!(error.to_string().contains("absent from checker evidence"));

        recovery.still_unavailable_keys = vec!["z".to_string(), "z".to_string()];
        assert!(
            validate_recovery_key_sets(&recovery, &immediate).is_err(),
            "duplicate key evidence must fail closed"
        );

        let mut coordinated = recovery_report_with_attempted_key("a");
        coordinated.reread_attempted_keys.push("ghost".to_string());
        coordinated.reread_recovered_keys.push("a".to_string());
        coordinated.still_unavailable_keys =
            vec!["ghost".to_string(), "b".to_string(), "z".to_string()];
        let error = validate_recovery_key_sets(&coordinated, &immediate)
            .expect_err("attempted and still sets cannot introduce a coordinated ghost key");
        assert!(
            error
                .to_string()
                .contains("checker-derived recovery candidates")
        );

        let mut ambiguous_only = empty_report();
        ambiguous_only
            .unknown_writes_materialized
            .push("ambiguous operation became visible".to_string());
        let mut ghost = recovery_report_with_attempted_key("ghost");
        ghost.still_unavailable_keys.push("ghost".to_string());
        let error = validate_recovery_key_sets(&ghost, &ambiguous_only)
            .expect_err("ambiguous-write evidence cannot authorize a ghost reread key");
        assert!(
            error
                .to_string()
                .contains("checker-derived recovery candidates")
        );
    }

    #[test]
    fn recovery_evidence_classifications_preserve_tail_latency_with_ambiguous_evidence() {
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.reread_recovered_keys.push("k".to_string());
        recovery
            .ambiguous_write_evidence
            .push("ambiguous_write_materialized: other op-2".to_string());
        recovery.classification = RecoveryStabilityClassification::AmbiguousWriteMaterialized;

        assert_eq!(
            recovery.evidence_classifications(),
            vec![
                "ambiguous_write_materialized".to_string(),
                "recovery_tail_read_latency".to_string()
            ]
        );
    }

    #[test]
    fn recovery_evidence_classifications_preserve_secondary_precise_signals() {
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.classification = RecoveryStabilityClassification::VersionHashMismatch;
        recovery.classification_evidence = vec![
            "missing_committed_version: k@v1".to_string(),
            "version_hash_mismatch: k@v2".to_string(),
        ];

        assert_eq!(
            recovery.evidence_classifications(),
            vec![
                "committed_version_missing".to_string(),
                "version_hash_mismatch".to_string()
            ]
        );
    }

    #[test]
    fn matching_list_omission_preserves_missing_object_evidence_in_recovery() {
        let mut immediate = empty_report();
        immediate.missing_committed_objects.push("k".to_string());
        immediate.final_list_warning_count = 1;
        immediate
            .list_warnings
            .push("LIST prefix fault-test/ did not include expected live key k".to_string());
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.reread_attempted_keys.clear();
        recovery.still_unavailable_keys =
            immediate_still_unavailable_keys(&immediate, &[]).expect("unambiguous keys");
        recovery.data_corruption_evidence = super::immediate_data_corruption_evidence(&immediate);
        recovery.final_list_warning_count = immediate.final_list_warning_count;
        recovery.list_warnings = immediate.list_warnings.clone();

        finish_recovery_stability_report(&mut recovery, &immediate);

        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::CommittedObjectUnavailable
        );
        assert_eq!(recovery.still_unavailable_keys, vec!["k"]);
        assert!(recovery.data_corruption_evidence.is_empty());
        assert_eq!(recovery.list_warnings, immediate.list_warnings);

        let mut independent_list = immediate.clone();
        independent_list.list_warnings.push(
            "LIST prefix fault-test/ did not include expected live key another-key".to_string(),
        );
        independent_list.final_list_warning_count += 1;
        assert_eq!(
            independent_list.failure_classification(),
            RecoveryStabilityClassification::DataCorruption
        );
        assert!(!super::immediate_data_corruption_evidence(&independent_list).is_empty());
        immediate
            .hash_mismatches
            .push("other-key: checksum mismatch".to_string());
        assert_eq!(
            immediate.failure_classification(),
            RecoveryStabilityClassification::DataCorruption
        );
    }

    #[test]
    fn recovered_reads_reclassify_remaining_lineage_evidence() {
        for (evidence, expected) in [
            (
                "delete_marker_lineage_incomplete: deleted-key",
                RecoveryStabilityClassification::DeleteMarkerLineageIncomplete,
            ),
            (
                "committed_write_missing_version_id: put-key",
                RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite,
            ),
            (
                "multipart_upload_lineage_incomplete: multipart-key",
                RecoveryStabilityClassification::MultipartUploadLineageIncomplete,
            ),
        ] {
            let mut immediate = empty_report();
            immediate
                .unavailable_committed_objects
                .push("k: outcome=Timeout".to_string().into());
            match expected {
                RecoveryStabilityClassification::DeleteMarkerLineageIncomplete => immediate
                    .delete_marker_lineage_incomplete
                    .push("deleted-key".to_string()),
                RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite => {
                    immediate.committed_writes_missing_version_id_count = 1;
                    immediate
                        .committed_writes_missing_version_id
                        .push("put-key".to_string());
                }
                RecoveryStabilityClassification::MultipartUploadLineageIncomplete => immediate
                    .multipart_upload_lineage_incomplete
                    .push("multipart-key".to_string()),
                _ => unreachable!(),
            }
            assert_eq!(
                immediate.failure_classification(),
                RecoveryStabilityClassification::CommittedObjectUnavailable
            );
            let mut recovery = recovery_report_with_attempted_key("k");
            recovery.classification_evidence = super::immediate_classification_evidence(&immediate);
            assert_eq!(recovery.classification_evidence, vec![evidence]);
            recovery.reread_recovered_keys.push("k".to_string());
            recovery.recovered_within_seconds = Some(1);

            finish_recovery_stability_report(&mut recovery, &immediate);

            assert_eq!(recovery.classification, expected);
            assert!(recovery.still_unavailable_keys.is_empty());
            assert!(
                !recovery
                    .evidence_classifications()
                    .contains(&"committed_object_unavailable".to_string())
            );

            recovery.reread_recovered_keys.clear();
            recovery.still_unavailable_keys.push("k".to_string());
            finish_recovery_stability_report(&mut recovery, &immediate);
            assert_eq!(
                recovery.classification,
                RecoveryStabilityClassification::CommittedObjectUnavailable
            );
        }
    }

    #[test]
    fn recovery_stability_report_keeps_unavailable_and_corrupt_classifications_hard() {
        let mut immediate = empty_report();
        immediate.unavailable_committed_objects.push(
            "k: outcome=Timeout status=200 error=\"get body read timed out\""
                .to_string()
                .into(),
        );
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
    fn recovery_stability_hard_version_signals_override_ambiguous_writes() {
        let mut immediate_corrupt = empty_report();
        immediate_corrupt
            .unknown_writes_materialized
            .push("k: op-2 materialized".to_string());
        immediate_corrupt
            .version_hash_mismatches
            .push("k@v1: expected old, got new".to_string());
        let mut corrupt = recovery_report_with_attempted_key("k");
        corrupt.ambiguous_write_evidence =
            super::immediate_ambiguous_write_evidence(&immediate_corrupt);
        corrupt.data_corruption_evidence =
            super::immediate_data_corruption_evidence(&immediate_corrupt);
        corrupt.classification_evidence =
            super::immediate_classification_evidence(&immediate_corrupt);
        finish_recovery_stability_report(&mut corrupt, &immediate_corrupt);
        assert_eq!(
            corrupt.classification,
            RecoveryStabilityClassification::VersionHashMismatch
        );

        let mut immediate_unavailable = empty_report();
        immediate_unavailable
            .unknown_writes_materialized
            .push("k: op-2 materialized".to_string());
        immediate_unavailable
            .unavailable_committed_versions
            .push("k@v1: outcome=Timeout".to_string());
        let keys = immediate_still_unavailable_keys(&immediate_unavailable, &[])
            .expect("well-formed read failure evidence");
        let mut unavailable = recovery_report_with_attempted_key("k");
        unavailable.ambiguous_write_evidence =
            super::immediate_ambiguous_write_evidence(&immediate_unavailable);
        unavailable.classification_evidence =
            super::immediate_classification_evidence(&immediate_unavailable);
        unavailable.still_unavailable_keys = keys;
        finish_recovery_stability_report(&mut unavailable, &immediate_unavailable);
        assert_eq!(
            unavailable.classification,
            RecoveryStabilityClassification::CommittedVersionUnavailable
        );
    }

    #[test]
    fn precise_availability_and_lineage_do_not_mask_stronger_evidence() {
        let mut unavailable_and_corrupt = empty_report();
        unavailable_and_corrupt
            .unavailable_committed_versions
            .push("k@v1: outcome=Timeout".to_string());
        unavailable_and_corrupt
            .hash_mismatches
            .push("k: expected old, got new".to_string());
        let mut recovery = recovery_report_with_attempted_key("k");
        recovery.hash_mismatches = unavailable_and_corrupt.hash_mismatches.clone();
        recovery.classification_evidence =
            super::immediate_classification_evidence(&unavailable_and_corrupt);
        finish_recovery_stability_report(&mut recovery, &unavailable_and_corrupt);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::DataCorruption
        );

        let mut incomplete_and_list_unavailable = empty_report();
        incomplete_and_list_unavailable
            .delete_marker_lineage_incomplete
            .push("delete response omitted marker id".to_string());
        incomplete_and_list_unavailable.final_list_warning_count = 1;
        incomplete_and_list_unavailable
            .list_warnings
            .push("LIST prefix fault-test/ did not complete".to_string());
        let mut recovery =
            RecoveryStabilityReport::harness_error("placeholder", std::time::Duration::ZERO);
        recovery.harness_errors.clear();
        recovery.classification_evidence =
            super::immediate_classification_evidence(&incomplete_and_list_unavailable);
        recovery.final_list_warning_count = 1;
        recovery.list_warnings = incomplete_and_list_unavailable.list_warnings.clone();
        finish_recovery_stability_report(&mut recovery, &incomplete_and_list_unavailable);
        assert_eq!(
            recovery.classification,
            RecoveryStabilityClassification::ListUnavailableOrUnknown
        );
    }

    #[test]
    fn recovery_stability_preserves_precise_non_reread_classifications() {
        let mut version_missing = empty_report();
        version_missing
            .missing_committed_versions
            .push("k@v1".to_string());
        let mut version_unavailable = empty_report();
        version_unavailable
            .unavailable_committed_versions
            .push("k@v1: outcome=Timeout".to_string());
        let mut delete_marker_missing = empty_report();
        delete_marker_missing
            .missing_committed_delete_markers
            .push("k@marker-1".to_string());
        let mut delete_marker_lineage = empty_report();
        delete_marker_lineage
            .delete_marker_lineage_incomplete
            .push("op-delete: missing delete marker id".to_string());
        let mut incomplete_lineage = empty_report();
        incomplete_lineage.committed_writes_missing_version_id_count = 1;
        incomplete_lineage
            .committed_writes_missing_version_id
            .push("op-1: missing version id".to_string());
        let mut multipart_lineage = incomplete_lineage.clone();
        multipart_lineage
            .multipart_upload_lineage_incomplete
            .push("op-1: committed CompleteMultipartUpload missing version id".to_string());
        let mut ambiguous = empty_report();
        ambiguous
            .unknown_writes_materialized
            .push("timeout put materialized".to_string());

        for (immediate, expected) in [
            (
                version_missing,
                RecoveryStabilityClassification::CommittedVersionMissing,
            ),
            (
                version_unavailable,
                RecoveryStabilityClassification::CommittedVersionUnavailable,
            ),
            (
                delete_marker_missing,
                RecoveryStabilityClassification::DeleteMarkerMissing,
            ),
            (
                delete_marker_lineage,
                RecoveryStabilityClassification::DeleteMarkerLineageIncomplete,
            ),
            (
                incomplete_lineage,
                RecoveryStabilityClassification::VersionIdMissingOnCommittedWrite,
            ),
            (
                multipart_lineage,
                RecoveryStabilityClassification::MultipartUploadLineageIncomplete,
            ),
            (
                ambiguous,
                RecoveryStabilityClassification::AmbiguousWriteMaterialized,
            ),
        ] {
            let mut recovery = RecoveryStabilityReport {
                scenario: None,
                run_id: None,
                immediate_passed: false,
                reread_attempted_keys: Vec::new(),
                reread_recovered_keys: Vec::new(),
                still_unavailable_keys: immediate_still_unavailable_keys(&immediate, &[])
                    .expect("unambiguous keys"),
                hash_mismatches: immediate.hash_mismatches.clone(),
                data_corruption_evidence: super::immediate_data_corruption_evidence(&immediate),
                classification_evidence: super::immediate_classification_evidence(&immediate),
                ambiguous_write_evidence: super::immediate_ambiguous_write_evidence(&immediate),
                final_list_warning_count: immediate.final_list_warning_count,
                list_warnings: immediate.list_warnings.clone(),
                harness_errors: Vec::new(),
                max_recovery_seconds: 60,
                recovered_within_seconds: None,
                classification: immediate.failure_classification(),
            };

            finish_recovery_stability_report(&mut recovery, &immediate);

            assert_eq!(recovery.classification, expected);
        }
    }

    #[test]
    fn recovery_stability_keeps_list_timeout_distinct_from_data_corruption() {
        let mut final_list_warning = empty_report();
        final_list_warning.final_list_warning_count = 1;
        final_list_warning
            .list_warnings
            .push("LIST prefix fault-test/ did not complete".to_string());
        assert_eq!(
            super::classify_without_reread(&final_list_warning),
            RecoveryStabilityClassification::ListUnavailableOrUnknown
        );
        assert!(super::immediate_data_corruption_evidence(&final_list_warning).is_empty());

        let mut history_list_warning = empty_report();
        history_list_warning.list_history_warning_count = 1;
        history_list_warning
            .list_history_warnings
            .push("LIST op-1 warning during workload".to_string());
        assert_eq!(
            super::classify_without_reread(&history_list_warning),
            RecoveryStabilityClassification::HarnessError
        );

        let mut final_list_content_warning = empty_report();
        final_list_content_warning.final_list_warning_count = 1;
        final_list_content_warning
            .list_warnings
            .push("LIST prefix did not include expected live key k".to_string());
        assert_eq!(
            super::classify_without_reread(&final_list_content_warning),
            RecoveryStabilityClassification::DataCorruption
        );
        assert_eq!(
            super::immediate_data_corruption_evidence(&final_list_content_warning),
            vec!["final_list_warning: LIST prefix did not include expected live key k"]
        );

        let mut visible_deleted = empty_report();
        visible_deleted
            .unexpected_visible_deleted_objects
            .push("k: deleted object returned body".to_string());
        assert_eq!(
            super::classify_without_reread(&visible_deleted),
            RecoveryStabilityClassification::DeletedObjectResurrected
        );
        assert!(super::immediate_data_corruption_evidence(&visible_deleted).is_empty());
        assert_eq!(
            super::immediate_classification_evidence(&visible_deleted),
            vec!["resurrected_deleted_object: k: deleted object returned body"]
        );
    }

    #[test]
    fn recovery_stability_keeps_non_candidate_immediate_failures_unavailable() {
        let mut immediate = empty_report();
        immediate.unavailable_committed_objects.push(
            "k: outcome=Timeout error=\"get object timed out\""
                .to_string()
                .into(),
        );
        let keys = immediate_still_unavailable_keys(&immediate, &[])
            .expect("well-formed read failure evidence");
        let mut recovery = RecoveryStabilityReport {
            scenario: None,
            run_id: None,
            immediate_passed: false,
            reread_attempted_keys: Vec::new(),
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: keys,
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            classification_evidence: Vec::new(),
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            recovered_within_seconds: None,
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
    fn committed_version_lineage_collects_versions_and_flags_missing_ids() {
        let mut versioned_put =
            record("op-1", OperationKind::Put, "k1", "v1", OperationOutcome::Ok);
        versioned_put.version_id = Some("ver-1".to_string());
        let mut versioned_multipart = record(
            "op-2",
            OperationKind::CompleteMultipartUpload,
            "k2",
            "v2",
            OperationOutcome::Ok,
        );
        versioned_multipart.version_id = Some("ver-2".to_string());
        let unversioned_put = record("op-3", OperationKind::Put, "k3", "v3", OperationOutcome::Ok);
        let mut versioned_delete = record(
            "op-4",
            OperationKind::Delete,
            "k1",
            "",
            OperationOutcome::Ok,
        );
        versioned_delete.version_id = Some("marker-1".to_string());
        let unversioned_delete = record(
            "op-5",
            OperationKind::Delete,
            "k2",
            "",
            OperationOutcome::Ok,
        );
        let failed_put = record(
            "op-6",
            OperationKind::Put,
            "k4",
            "v4",
            OperationOutcome::Timeout,
        );

        let lineage = super::committed_version_lineage(&[
            versioned_put,
            versioned_multipart,
            unversioned_put,
            versioned_delete,
            unversioned_delete,
            failed_put,
        ]);

        assert_eq!(
            lineage
                .versions
                .iter()
                .map(|version| (version.key.as_str(), version.version_id.as_str()))
                .collect::<Vec<_>>(),
            vec![("k1", "ver-1"), ("k2", "ver-2")]
        );
        assert_eq!(
            lineage
                .delete_markers
                .iter()
                .map(|marker| (marker.key.as_str(), marker.version_id.as_str()))
                .collect::<Vec<_>>(),
            vec![("k1", "marker-1")]
        );
        assert_eq!(lineage.missing_version_id_count, 1);
        assert!(
            lineage
                .missing_version_id_samples
                .iter()
                .any(|sample| sample.contains("op-3"))
        );
        assert_eq!(lineage.delete_marker_lineage_incomplete.len(), 1);
        assert!(lineage.delete_marker_lineage_incomplete[0].contains("op-5"));
    }

    #[test]
    fn committed_version_get_classifies_missing_corrupt_and_verified() {
        let version = super::CommittedVersion {
            key: "k".to_string(),
            version_id: "ver-1".to_string(),
            sha256: crate::fault::workload::sha256_hex(b"x"),
            size_bytes: 1,
            kind: OperationKind::Put,
        };

        let mut report = empty_report();
        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"x".to_vec()),
            },
        );
        assert_eq!(report.verified_committed_versions, 1);
        assert_eq!(report.verified_committed_version_refs, vec!["k@ver-1"]);

        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );
        assert_eq!(report.missing_committed_versions, vec!["k@ver-1"]);

        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"y".to_vec()),
            },
        );
        assert_eq!(report.version_hash_mismatches.len(), 1);
        assert!(report.version_hash_mismatches[0].starts_with("k@ver-1"));

        super::evaluate_committed_version_get(
            &mut report,
            &version,
            GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: None,
                error: Some("get object timed out".to_string()),
                body: None,
            },
        );
        assert_eq!(report.unavailable_committed_versions.len(), 1);
    }

    #[test]
    fn complete_version_listing_reports_only_omitted_committed_lineage() {
        let committed = vec![
            super::CommittedVersion {
                key: "put".to_string(),
                version_id: "put-v1".to_string(),
                sha256: "put-sha".to_string(),
                size_bytes: 1,
                kind: OperationKind::Put,
            },
            super::CommittedVersion {
                key: "mpu".to_string(),
                version_id: "mpu-v1".to_string(),
                sha256: "mpu-sha".to_string(),
                size_bytes: 1,
                kind: OperationKind::CompleteMultipartUpload,
            },
        ];
        let entries = vec![crate::fault::workload::ObjectVersionEntry {
            key: "put".to_string(),
            version_id: Some("put-v1".to_string()),
            is_latest: true,
            is_delete_marker: false,
        }];

        let (missing, multipart) = super::missing_committed_version_entries(&committed, &entries);

        assert_eq!(
            missing,
            vec!["mpu@mpu-v1: committed version missing from ListObjectVersions"]
        );
        assert_eq!(
            multipart,
            vec!["mpu@mpu-v1: committed multipart completion missing from ListObjectVersions"]
        );
    }

    #[test]
    fn delete_only_version_list_timeout_is_list_unavailable_not_version_unavailable() {
        let delete = record(
            "delete-204",
            OperationKind::Delete,
            "deleted-key",
            "",
            OperationOutcome::Ok,
        );
        let lineage = super::committed_version_lineage(&[delete]);
        assert!(lineage.versions.is_empty());

        let mut report = empty_report();
        report.delete_marker_lineage_incomplete = lineage.delete_marker_lineage_incomplete;
        let mut warnings = super::WarningSummary::default();
        super::record_version_list_unavailable(&mut warnings, "fault-test/run-1/");
        report.final_list_warning_count = warnings.total_count;
        report.list_warnings = warnings.samples;

        assert!(report.unavailable_committed_versions.is_empty());
        assert_eq!(
            report.failure_classification(),
            RecoveryStabilityClassification::ListUnavailableOrUnknown
        );
    }

    #[test]
    fn resurrected_deleted_objects_require_visible_latest_non_marker() {
        use crate::fault::workload::ObjectVersionEntry;
        use std::collections::BTreeSet;

        let deleted = ["gone", "resurrected", "absent"]
            .iter()
            .map(|key| key.to_string())
            .collect::<BTreeSet<_>>();
        let entries = vec![
            ObjectVersionEntry {
                key: "gone".to_string(),
                version_id: Some("marker-1".to_string()),
                is_latest: true,
                is_delete_marker: true,
            },
            ObjectVersionEntry {
                key: "gone".to_string(),
                version_id: Some("ver-0".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "resurrected".to_string(),
                version_id: Some("ver-1".to_string()),
                is_latest: true,
                is_delete_marker: false,
            },
        ];
        let latest = super::latest_version_entries(&entries);

        let mut report = empty_report();
        super::evaluate_deleted_latest_versions(&mut report, &deleted, &latest);

        assert_eq!(
            report.resurrected_deleted_objects,
            vec![
                "resurrected: latest version is not a delete marker after committed delete"
                    .to_string()
            ]
        );
        assert_eq!(
            report.delete_marker_lineage_incomplete,
            vec!["absent: ListObjectVersions has no latest entry after committed delete"]
        );
    }

    #[test]
    fn listed_delete_marker_without_latest_entry_is_incomplete_lineage() {
        let mut delete = record(
            "delete-200",
            OperationKind::Delete,
            "k",
            "",
            OperationOutcome::Ok,
        );
        delete.version_id = Some("marker-1".to_string());
        let model = object_model(std::slice::from_ref(&delete));
        let lineage = super::committed_version_lineage(&[delete]);
        let entries = vec![crate::fault::workload::ObjectVersionEntry {
            key: "k".to_string(),
            version_id: Some("marker-1".to_string()),
            is_latest: false,
            is_delete_marker: true,
        }];
        let mut report = empty_report();
        let (verified, missing) =
            super::committed_delete_marker_presence(&lineage.delete_markers, &entries);
        report.verified_committed_delete_marker_refs = verified;
        report.missing_committed_delete_markers = missing;
        super::evaluate_deleted_latest_versions(
            &mut report,
            &model.deleted,
            &super::latest_version_entries(&entries),
        );
        assert!(report.missing_committed_delete_markers.is_empty());
        assert!(report.resurrected_deleted_objects.is_empty());
        assert_eq!(report.delete_marker_lineage_incomplete.len(), 1);
        assert_eq!(
            report.failure_classification(),
            RecoveryStabilityClassification::DeleteMarkerLineageIncomplete
        );
    }

    #[test]
    fn missing_committed_delete_markers_are_reported() {
        use crate::fault::workload::ObjectVersionEntry;

        let committed = vec![
            super::CommittedDeleteMarker {
                key: "k".to_string(),
                version_id: "marker-1".to_string(),
            },
            super::CommittedDeleteMarker {
                key: "k".to_string(),
                version_id: "marker-2".to_string(),
            },
        ];
        let entries = vec![
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("marker-1".to_string()),
                is_latest: false,
                is_delete_marker: true,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("old-version".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
        ];

        let (verified, missing) = super::committed_delete_marker_presence(&committed, &entries);

        assert_eq!(verified, vec!["k@marker-1".to_string()]);
        assert_eq!(
            missing,
            vec!["k@marker-2: committed delete marker missing from ListObjectVersions".to_string()]
        );
    }

    #[test]
    fn ambiguous_version_candidates_ignore_committed_versions_but_keep_unknown_versions() {
        use crate::fault::workload::ObjectVersionEntry;

        let mut committed = timed_record(
            "op-1",
            OperationKind::Put,
            "k",
            "committed",
            OperationOutcome::Ok,
            1,
            2,
        );
        committed.version_id = Some("ver-ok".to_string());
        let ambiguous = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "timeout",
            OperationOutcome::Timeout,
            3,
            4,
        );
        let mut later = timed_record(
            "op-3",
            OperationKind::Put,
            "k",
            "later",
            OperationOutcome::Ok,
            5,
            6,
        );
        later.version_id = Some("ver-later".to_string());
        let model = object_model(&[committed.clone(), ambiguous, later.clone()]);
        let lineage = super::committed_version_lineage(&[committed, later]);
        let entries = vec![
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("ver-later".to_string()),
                is_latest: true,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("ver-ok".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("ver-timeout".to_string()),
                is_latest: false,
                is_delete_marker: false,
            },
            ObjectVersionEntry {
                key: "k".to_string(),
                version_id: Some("marker".to_string()),
                is_latest: false,
                is_delete_marker: true,
            },
        ];

        let (candidates, conflicts) =
            super::ambiguous_version_candidates(&model, &lineage, &entries);

        assert!(conflicts.is_empty());
        assert_eq!(
            candidates
                .iter()
                .map(|candidate| candidate.version_id.as_str())
                .collect::<Vec<_>>(),
            vec!["ver-timeout"]
        );
    }

    #[test]
    fn ambiguous_version_get_records_materialized_timeout_version() {
        let attempt = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        let candidate = super::AmbiguousVersionCandidate {
            key: "k".to_string(),
            version_id: "ver-timeout".to_string(),
            attempts: vec![attempt],
        };
        let mut materialized = Vec::new();
        let mut conflicts = Vec::new();

        super::evaluate_ambiguous_version_get(
            &mut materialized,
            &mut conflicts,
            &candidate,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"b".to_vec()),
            },
        );

        assert!(conflicts.is_empty());
        assert_eq!(materialized.len(), 1);
        assert!(materialized[0].contains("k@ver-timeout"));
        assert!(materialized[0].contains("materialized as version"));
    }

    #[test]
    fn ambiguous_version_candidates_report_missing_version_ids() {
        use crate::fault::workload::ObjectVersionEntry;

        let ambiguous = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "timeout",
            OperationOutcome::Timeout,
            3,
            4,
        );
        let model = object_model(&[ambiguous]);
        let lineage = super::committed_version_lineage(&[]);
        let entries = vec![ObjectVersionEntry {
            key: "k".to_string(),
            version_id: None,
            is_latest: false,
            is_delete_marker: false,
        }];

        let (candidates, conflicts) =
            super::ambiguous_version_candidates(&model, &lineage, &entries);

        assert!(candidates.is_empty());
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("did not include a version id"));
    }

    #[test]
    fn uncommitted_version_with_unexpected_body_is_conflict() {
        let attempt = ambiguous_attempt("op-2", &sha256_hex(b"b"));
        let candidate = super::AmbiguousVersionCandidate {
            key: "k".to_string(),
            version_id: "ver-extra".to_string(),
            attempts: vec![attempt],
        };
        let mut materialized = Vec::new();
        let mut conflicts = Vec::new();

        super::evaluate_ambiguous_version_get(
            &mut materialized,
            &mut conflicts,
            &candidate,
            GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"c".to_vec()),
            },
        );

        assert!(materialized.is_empty());
        assert_eq!(conflicts.len(), 1);
        assert!(conflicts[0].contains("matched no ambiguous attempt"));
    }

    #[test]
    fn version_reads_are_excluded_from_plain_read_anomalies() {
        let put = record("op-1", OperationKind::Put, "k", "new", OperationOutcome::Ok);
        let mut old_version_get =
            record("op-2", OperationKind::Get, "k", "old", OperationOutcome::Ok);
        old_version_get.version_id = Some("ver-0".to_string());

        let anomalies = successful_read_anomalies(&[put, old_version_get]);

        assert!(anomalies.corrupted_reads.is_empty());
        assert!(anomalies.visible_deleted_objects.is_empty());
    }

    fn slice_sha(seed: u64, index: usize, size: usize, range: ByteRange) -> String {
        let body = seeded_bytes(seed, index, size);
        sha256_hex(&body[range.offset as usize..(range.offset + range.length) as usize])
    }

    fn committed_put(
        id: &str,
        key: &str,
        seed: u64,
        index: usize,
        size: usize,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        let body = seeded_bytes(seed, index, size);
        let mut record = timed_record(
            id,
            OperationKind::Put,
            key,
            &sha256_hex(&body),
            OperationOutcome::Ok,
            started_at_ms,
            ended_at_ms,
        );
        record.size_bytes = Some(size);
        record.payload_ref = Some(PayloadRef { seed, index });
        record
    }

    fn ranged_get(
        id: &str,
        key: &str,
        range: ByteRange,
        slice_sha256: &str,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        let mut record = timed_record(
            id,
            OperationKind::Get,
            key,
            slice_sha256,
            OperationOutcome::Ok,
            started_at_ms,
            ended_at_ms,
        );
        record.size_bytes = Some(range.length as usize);
        record.range = Some(range);
        record
    }

    /// A ranged GET whose slice matches the regenerated slice of the latest
    /// committed write is clean — and crucially is never compared against the
    /// whole-object hash (which would always mismatch).
    #[test]
    fn ranged_get_matching_latest_slice_is_clean() {
        let range = ByteRange {
            offset: 100,
            length: 64,
        };
        let put = committed_put("op-1", "k", 7, 3, 4096, 10, 11);
        let get = ranged_get("op-2", "k", range, &slice_sha(7, 3, 4096, range), 20, 21);

        let anomalies = successful_read_anomalies(&[put, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "clean ranged read flagged: {:?}",
            anomalies.corrupted_reads
        );
    }

    /// A ranged GET racing a concurrent overwrite may return the earlier
    /// variant's slice — same concurrency legs as whole-object reads.
    #[test]
    fn ranged_get_matching_concurrent_variant_slice_is_clean() {
        let range = ByteRange {
            offset: 5,
            length: 32,
        };
        let first = committed_put("op-1", "k", 7, 3, 4096, 10, 19);
        let second = committed_put("op-2", "k", 99, 3, 4096, 18, 20);
        // GET starts while op-2 is in flight and observes op-1's slice.
        let get = ranged_get("op-3", "k", range, &slice_sha(7, 3, 4096, range), 19, 21);

        let anomalies = successful_read_anomalies(&[first, second, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "concurrent ranged read flagged: {:?}",
            anomalies.corrupted_reads
        );
    }

    /// A slice matching no committed value (after all writes settled) is
    /// corruption, with the range in the message.
    #[test]
    fn ranged_get_slice_matching_nothing_is_corruption() {
        let range = ByteRange {
            offset: 0,
            length: 16,
        };
        let put = committed_put("op-1", "k", 7, 3, 4096, 10, 11);
        let get = ranged_get("op-2", "k", range, &sha256_hex(b"garbage"), 50, 51);

        let anomalies = successful_read_anomalies(&[put, get]);

        assert_eq!(anomalies.corrupted_reads.len(), 1);
        assert!(anomalies.corrupted_reads[0].contains("bytes=0-15"));
    }

    /// If a legally-observable committed body is not reproducible (multipart,
    /// legacy record without payload_ref), a mismatching slice is inconclusive
    /// and must not be flagged.
    #[test]
    fn ranged_get_with_unreproducible_candidate_is_inconclusive() {
        let range = ByteRange {
            offset: 0,
            length: 16,
        };
        let mut mpu = timed_record(
            "op-1",
            OperationKind::CompleteMultipartUpload,
            "k",
            "mpu-body-sha",
            OperationOutcome::Ok,
            10,
            11,
        );
        mpu.size_bytes = Some(4096);
        let get = ranged_get("op-2", "k", range, &sha256_hex(b"whatever"), 50, 51);

        let anomalies = successful_read_anomalies(&[mpu, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "inconclusive ranged read flagged: {:?}",
            anomalies.corrupted_reads
        );
    }

    /// A ranged GET returning the wrong byte count is flagged regardless of
    /// content reproducibility.
    #[test]
    fn ranged_get_length_mismatch_is_corruption() {
        let range = ByteRange {
            offset: 0,
            length: 16,
        };
        let put = committed_put("op-1", "k", 7, 3, 4096, 10, 11);
        let mut get = ranged_get("op-2", "k", range, &sha256_hex(b"short"), 50, 51);
        get.size_bytes = Some(8);

        let anomalies = successful_read_anomalies(&[put, get]);

        assert_eq!(anomalies.corrupted_reads.len(), 1);
        assert!(anomalies.corrupted_reads[0].contains("8 bytes instead of 16"));
    }

    fn ambiguous_put(
        id: &str,
        key: &str,
        seed: u64,
        index: usize,
        size: usize,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        let body = seeded_bytes(seed, index, size);
        let mut record = timed_record(
            id,
            OperationKind::Put,
            key,
            &sha256_hex(&body),
            OperationOutcome::Timeout,
            started_at_ms,
            ended_at_ms,
        );
        record.size_bytes = Some(size);
        record.payload_ref = Some(PayloadRef { seed, index });
        record
    }

    /// Adversarial self-review catch (PR#30 finding): a ranged GET reading a
    /// materialized-but-unconfirmed (timeout) overwrite must classify as
    /// unknown_writes_materialized, exactly like the whole-object path -- NOT
    /// as data corruption.
    #[test]
    fn ranged_get_of_materialized_ambiguous_write_is_not_corruption() {
        let range = ByteRange {
            offset: 100,
            length: 64,
        };
        let committed = committed_put("op-1", "k", 7, 3, 4096, 10, 11);
        // Overwrite times out but landed server-side (seed 99).
        let ambiguous = ambiguous_put("op-2", "k", 99, 3, 4096, 12, 13);
        let get = ranged_get("op-3", "k", range, &slice_sha(99, 3, 4096, range), 50, 51);

        let anomalies = successful_read_anomalies(&[committed, ambiguous, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "materialized ambiguous ranged read flagged as corruption: {:?}",
            anomalies.corrupted_reads
        );
        assert_eq!(
            anomalies.unknown_writes_materialized.len(),
            1,
            "must be classified as a materialized ambiguous write"
        );
    }

    /// Adversarial review catch (PR#30 finding 1): a ranged GET that started
    /// before an overlapping committed delete linearized may legally return
    /// the pre-delete value -- the stable-at-read-start exemption the
    /// whole-object path already has. It must not be flagged as a
    /// resurrection/visible-deleted signal.
    #[test]
    fn ranged_get_racing_overlapping_delete_returning_pre_delete_slice_is_clean() {
        let range = ByteRange {
            offset: 100,
            length: 64,
        };
        let put = committed_put("op-1", "k", 7, 3, 4096, 1, 5);
        let delete = timed_record(
            "op-2",
            OperationKind::Delete,
            "k",
            "",
            OperationOutcome::Ok,
            10,
            15,
        );
        // GET starts at 12, while the delete (ends at 15) is still in flight,
        // and observes the pre-delete slice.
        let get = ranged_get("op-3", "k", range, &slice_sha(7, 3, 4096, range), 12, 20);

        let anomalies = successful_read_anomalies(&[put, delete, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "delete-racing ranged read flagged as corruption: {:?}",
            anomalies.corrupted_reads
        );
        assert!(
            anomalies.visible_deleted_objects.is_empty(),
            "delete-racing ranged read flagged as resurrection: {:?}",
            anomalies.visible_deleted_objects
        );
    }

    /// The stable-at-read-start exemption must not blunt true resurrection
    /// detection: a ranged GET that started AFTER the delete settled and still
    /// returned the deleted value stays flagged.
    #[test]
    fn ranged_get_of_deleted_value_after_settled_delete_is_still_resurrection() {
        let range = ByteRange {
            offset: 100,
            length: 64,
        };
        let put = committed_put("op-1", "k", 7, 3, 4096, 1, 5);
        let delete = timed_record(
            "op-2",
            OperationKind::Delete,
            "k",
            "",
            OperationOutcome::Ok,
            6,
            8,
        );
        // GET starts at 12, long after the delete finished at 8.
        let get = ranged_get("op-3", "k", range, &slice_sha(7, 3, 4096, range), 12, 13);

        let anomalies = successful_read_anomalies(&[put, delete, get]);

        assert_eq!(
            anomalies.visible_deleted_objects,
            vec!["k: successful ranged GET had no committed live value"]
        );
    }

    /// Adversarial review catch (PR#30 finding 2): a ranged GET returning the
    /// slice of a materialized timeout write that a later committed overwrite
    /// already superseded is classified as unknown_writes_materialized plus
    /// unknown_write_value_conflicts, exactly like the whole-object path --
    /// NOT as data corruption.
    #[test]
    fn ranged_get_of_superseded_materialized_ambiguous_write_is_not_corruption() {
        let range = ByteRange {
            offset: 100,
            length: 64,
        };
        let committed = committed_put("op-1", "k", 7, 3, 4096, 10, 11);
        // Overwrite times out but landed server-side (seed 99)...
        let ambiguous = ambiguous_put("op-2", "k", 99, 3, 4096, 12, 13);
        // ...and a later committed overwrite supersedes it.
        let overwrite = committed_put("op-3", "k", 42, 3, 4096, 20, 25);
        // GET races the overwrite and observes the ghost slice.
        let get = ranged_get("op-4", "k", range, &slice_sha(99, 3, 4096, range), 21, 26);

        let anomalies = successful_read_anomalies(&[committed, ambiguous, overwrite, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "superseded materialized ambiguous ranged read flagged as corruption: {:?}",
            anomalies.corrupted_reads
        );
        assert_eq!(
            anomalies.unknown_writes_materialized.len(),
            1,
            "must be classified as a materialized ambiguous write"
        );
        assert_eq!(
            anomalies.unknown_write_value_conflicts.len(),
            1,
            "must also record the conflict with the superseding committed value"
        );
        assert!(
            anomalies.unknown_write_value_conflicts[0].contains("superseded ambiguous attempt")
        );
    }

    /// A ranged GET on a key whose only write is a pending ambiguous one whose
    /// regenerated slice does NOT match is an unknown-write value conflict --
    /// unexplained but not provable corruption, and not a visible-deleted
    /// resurrection signal.
    #[test]
    fn ranged_get_mismatching_only_pending_ambiguous_write_is_unknown_write_conflict() {
        let range = ByteRange {
            offset: 0,
            length: 16,
        };
        let ambiguous = ambiguous_put("op-1", "k", 99, 3, 4096, 10, 11);
        // The ambiguous write is reproducible and its regenerated slice does
        // not match, so the mismatch is not inconclusive; but with an
        // ambiguous write outstanding it is a value conflict, not corruption.
        let get = ranged_get("op-2", "k", range, &sha256_hex(b"other"), 50, 51);

        let anomalies = successful_read_anomalies(&[ambiguous, get]);

        assert!(anomalies.corrupted_reads.is_empty());
        assert!(anomalies.visible_deleted_objects.is_empty());
        assert_eq!(anomalies.unknown_write_value_conflicts.len(), 1);
        assert!(anomalies.unknown_write_value_conflicts[0].contains("ambiguous writes exist"));
    }

    /// A ranged GET on a key whose only write is an unreproducible (no
    /// payload_ref) ambiguous write spanning the range is inconclusive: the
    /// slice may belong to that unverifiable body, so nothing is flagged.
    #[test]
    fn ranged_get_spanned_by_unreproducible_ambiguous_write_is_inconclusive() {
        let range = ByteRange {
            offset: 0,
            length: 16,
        };
        let mut ambiguous = timed_record(
            "op-1",
            OperationKind::CompleteMultipartUpload,
            "k",
            "mpu-body-sha",
            OperationOutcome::Timeout,
            10,
            11,
        );
        ambiguous.size_bytes = Some(4096);
        let get = ranged_get("op-2", "k", range, &sha256_hex(b"other"), 50, 51);

        let anomalies = successful_read_anomalies(&[ambiguous, get]);

        assert!(anomalies.corrupted_reads.is_empty());
        assert!(anomalies.visible_deleted_objects.is_empty());
        assert!(anomalies.unknown_writes_materialized.is_empty());
        assert!(anomalies.unknown_write_value_conflicts.is_empty());
    }

    /// Replays the hotspot race observed on a real cluster (stress-cpu,
    /// ec-shard profile): two committed overwrites of one key with
    /// overlapping completion windows, and a GET issued before the later
    /// write finished that returned the earlier value. S3 gives concurrent
    /// overwrites no client-observable order, so this must not be reported
    /// as corruption.
    #[test]
    fn concurrent_overwrite_read_is_not_corruption() {
        let first = timed_record(
            "op-1",
            OperationKind::Put,
            "k",
            "a",
            OperationOutcome::Ok,
            10,
            19,
        );
        let second = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "b",
            OperationOutcome::Ok,
            18,
            20,
        );
        // GET starts while op-2 is still in flight and observes op-1's value.
        let get = timed_record(
            "op-3",
            OperationKind::Get,
            "k",
            "a",
            OperationOutcome::Ok,
            19,
            21,
        );

        let anomalies = successful_read_anomalies(&[first, second, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "concurrent committed read must not be corruption: {:?}",
            anomalies.corrupted_reads
        );
    }

    /// The exemption must not blunt real stale-read detection: once every
    /// write has settled long before the GET starts, returning an old value
    /// is corruption.
    #[test]
    fn stale_read_after_settled_overwrites_is_corruption() {
        let first = timed_record(
            "op-1",
            OperationKind::Put,
            "k",
            "a",
            OperationOutcome::Ok,
            10,
            11,
        );
        let second = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "b",
            OperationOutcome::Ok,
            12,
            13,
        );
        let get = timed_record(
            "op-3",
            OperationKind::Get,
            "k",
            "a",
            OperationOutcome::Ok,
            50,
            51,
        );

        let anomalies = successful_read_anomalies(&[first, second, get]);

        assert_eq!(
            anomalies.corrupted_reads.len(),
            1,
            "a stale read after settled overwrites must stay flagged"
        );
    }

    /// A GET racing the latest in-flight write may legally observe the
    /// previous committed value even though that previous write finished
    /// before the GET started.
    #[test]
    fn get_racing_latest_write_may_read_previous_value() {
        let first = timed_record(
            "op-1",
            OperationKind::Put,
            "k",
            "a",
            OperationOutcome::Ok,
            10,
            11,
        );
        let second = timed_record(
            "op-2",
            OperationKind::Put,
            "k",
            "b",
            OperationOutcome::Ok,
            18,
            25,
        );
        let get = timed_record(
            "op-3",
            OperationKind::Get,
            "k",
            "a",
            OperationOutcome::Ok,
            20,
            22,
        );

        let anomalies = successful_read_anomalies(&[first, second, get]);

        assert!(
            anomalies.corrupted_reads.is_empty(),
            "reading the previous value while the latest write is in flight is legal: {:?}",
            anomalies.corrupted_reads
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
            unknown_writes_preserved_committed: Vec::new(),
            unknown_write_value_conflicts: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: Some(1),
            versioning_expected: false,
            expected_committed_versions: 0,
            verified_committed_versions: 0,
            verified_committed_version_refs: Vec::new(),
            committed_writes_missing_version_id_count: 0,
            committed_writes_missing_version_id: Vec::new(),
            missing_committed_versions: Vec::new(),
            unavailable_committed_versions: Vec::new(),
            version_hash_mismatches: Vec::new(),
            missing_committed_delete_markers: Vec::new(),
            verified_committed_delete_marker_refs: Vec::new(),
            resurrected_deleted_objects: Vec::new(),
            delete_marker_lineage_incomplete: Vec::new(),
            multipart_upload_lineage_incomplete: Vec::new(),
            tolerated_ambiguous_deletes: Vec::new(),
            operation_cohorts: BTreeMap::new(),
            fault_window_relations: BTreeMap::new(),
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
            unknown_writes_preserved_committed: Vec::new(),
            unknown_write_value_conflicts: Vec::new(),
            list_history_warning_count: 0,
            final_list_warning_count: 0,
            list_history_warnings: Vec::new(),
            list_warnings: Vec::new(),
            final_listed_objects: None,
            versioning_expected: false,
            expected_committed_versions: 0,
            verified_committed_versions: 0,
            verified_committed_version_refs: Vec::new(),
            committed_writes_missing_version_id_count: 0,
            committed_writes_missing_version_id: Vec::new(),
            missing_committed_versions: Vec::new(),
            unavailable_committed_versions: Vec::new(),
            version_hash_mismatches: Vec::new(),
            missing_committed_delete_markers: Vec::new(),
            verified_committed_delete_marker_refs: Vec::new(),
            resurrected_deleted_objects: Vec::new(),
            delete_marker_lineage_incomplete: Vec::new(),
            multipart_upload_lineage_incomplete: Vec::new(),
            tolerated_ambiguous_deletes: Vec::new(),
            operation_cohorts: BTreeMap::new(),
            fault_window_relations: BTreeMap::new(),
            tenant_recovered: true,
            passed: false,
        }
    }

    fn recovery_report_with_attempted_key(key: &str) -> RecoveryStabilityReport {
        RecoveryStabilityReport {
            scenario: None,
            run_id: None,
            immediate_passed: false,
            reread_attempted_keys: vec![key.to_string()],
            reread_recovered_keys: Vec::new(),
            still_unavailable_keys: Vec::new(),
            hash_mismatches: Vec::new(),
            data_corruption_evidence: Vec::new(),
            classification_evidence: Vec::new(),
            ambiguous_write_evidence: Vec::new(),
            final_list_warning_count: 0,
            list_warnings: Vec::new(),
            harness_errors: Vec::new(),
            max_recovery_seconds: 60,
            recovered_within_seconds: None,
            classification: RecoveryStabilityClassification::CommittedObjectUnavailable,
        }
    }

    #[test]
    fn committed_delete_reread_flags_body_as_resurrection() {
        let message = super::evaluate_deleted_reread(
            "gone",
            &GetObjectResult {
                outcome: OperationOutcome::Ok,
                http_status: Some(200),
                error: None,
                body: Some(b"back".to_vec()),
            },
        );

        assert_eq!(
            message.as_deref(),
            Some("gone: committed delete resurrected on GET (4 bytes)")
        );
    }

    #[test]
    fn committed_delete_reread_accepts_not_found_and_unavailable() {
        let not_found = super::evaluate_deleted_reread(
            "gone",
            &GetObjectResult {
                outcome: OperationOutcome::NotFound,
                http_status: Some(404),
                error: None,
                body: None,
            },
        );
        assert!(not_found.is_none());

        // An unavailable probe response (timeout/error) is not proof of
        // resurrection; only a returned body is.
        let unavailable = super::evaluate_deleted_reread(
            "gone",
            &GetObjectResult {
                outcome: OperationOutcome::Timeout,
                http_status: None,
                error: Some("read timed out".to_string()),
                body: None,
            },
        );
        assert!(unavailable.is_none());
    }
}
