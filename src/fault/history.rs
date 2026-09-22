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
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    CreateBucket,
    PutBucketVersioning,
    Put,
    Get,
    Head,
    List,
    ListVersions,
    Delete,
    CreateMultipartUpload,
    UploadPart,
    CompleteMultipartUpload,
    AbortMultipartUpload,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationOutcome {
    Ok,
    NotFound,
    Failed,
    Timeout,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityCohort {
    PreFault,
    FaultActive,
    PostRecovery,
}

impl DurabilityCohort {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PreFault => "pre_fault",
            Self::FaultActive => "fault_active",
            Self::PostRecovery => "post_recovery",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FaultWindowRelation {
    BeforeFault,
    DuringFault,
    AfterFault,
    OverlapsFault,
    Unknown,
}

impl FaultWindowRelation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BeforeFault => "before_fault",
            Self::DuringFault => "during_fault",
            Self::AfterFault => "after_fault",
            Self::OverlapsFault => "overlaps_fault",
            Self::Unknown => "unknown",
        }
    }
}

/// Deterministic payload generator inputs for a committed write. The workload
/// generates every non-multipart body via `seeded_bytes(seed, index, size)`,
/// so recording (seed, index) lets the checker regenerate the exact bytes —
/// the basis for verifying ranged GET slices against any committed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayloadRef {
    pub seed: u64,
    pub index: usize,
}

/// The byte range a ranged GET requested (inclusive start offset, exact
/// length).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ListedVersionEntry {
    pub key: String,
    pub version_id: Option<String>,
    pub is_latest: bool,
    pub is_delete_marker: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    pub id: String,
    pub scenario: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub kind: OperationKind,
    pub bucket: String,
    pub key: Option<String>,
    pub value_sha256: Option<String>,
    pub size_bytes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// Version identity addressed by the request. This is distinct from the
    /// response identity because deleting an existing version creates no new
    /// immutable version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_version_id: Option<String>,
    /// Response delete-marker flag for DELETE operations. Older history
    /// artifacts omit this field and retain their previous interpretation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_delete_marker: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_request_id: Option<String>,
    /// Maximum HTTP attempts configured for this mutation request. New
    /// records set this at the client boundary; legacy records omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_max_attempts: Option<u32>,
    /// HTTP transmissions observed for this request, including retries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mutation_attempts: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_purpose: Option<ReadPurpose>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed_keys: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed_versions: Option<Vec<ListedVersionEntry>>,
    /// Set on committed writes whose body came from the seeded generator;
    /// absent for multipart bodies and legacy artifacts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload_ref: Option<PayloadRef>,
    /// Set on ranged GETs: `value_sha256`/`size_bytes` then describe the
    /// returned slice, not the whole object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<ByteRange>,
    /// Recorder-local event order. Unlike wall-clock milliseconds, these
    /// counters prove whether one request completed before another began.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_sequence: Option<u64>,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub outcome: OperationOutcome,
    pub http_status: Option<u16>,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durability_cohort: Option<DurabilityCohort>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fault_window_relation: Option<FaultWindowRelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReadPurpose {
    CohortProbe,
    MutationVerification { operation_id: String },
}

impl OperationRecord {
    pub(crate) fn verification_of(&self) -> Option<&str> {
        match &self.read_purpose {
            Some(ReadPurpose::MutationVerification { operation_id }) => Some(operation_id),
            _ => None,
        }
    }

    pub(crate) fn is_cohort_probe(&self) -> bool {
        self.read_purpose == Some(ReadPurpose::CohortProbe)
    }
}

pub(crate) fn validate_successful_version_identity_uniqueness<'a>(
    records: impl IntoIterator<Item = &'a OperationRecord>,
) -> Result<()> {
    let mut version_identities = HashSet::new();
    for record in records.into_iter().filter(|record| {
        if record.outcome != OperationOutcome::Ok {
            return false;
        }
        matches!(
            record.kind,
            OperationKind::Put | OperationKind::CompleteMultipartUpload
        ) || (record.kind == OperationKind::Delete
            && record.request_version_id.is_none()
            && record.is_delete_marker != Some(false))
    }) {
        let Some(version_id) = record
            .version_id
            .as_deref()
            .filter(|version_id| !version_id.is_empty() && *version_id != "null")
        else {
            continue;
        };
        let key = record
            .key
            .as_deref()
            .context("successful versioned mutation history record has no key")?;
        ensure!(
            version_identities.insert((record.bucket.as_str(), key, version_id)),
            "history reuses successful immutable S3 version identity {}/{key}@{version_id}",
            record.bucket
        );
    }
    Ok(())
}

pub(crate) fn validate_history_scope_and_order(
    records: &[OperationRecord],
    scenario: &str,
    run_id: &str,
    bucket: &str,
) -> Result<()> {
    validate_history_scope_and_order_mode(records, scenario, run_id, bucket, true)
}

pub(crate) fn validate_partial_history_scope_and_order(
    records: &[OperationRecord],
    scenario: &str,
    run_id: &str,
    bucket: &str,
) -> Result<()> {
    validate_history_scope_and_order_mode(records, scenario, run_id, bucket, false)
}

fn validate_history_scope_and_order_mode(
    records: &[OperationRecord],
    scenario: &str,
    run_id: &str,
    bucket: &str,
    require_contiguous_sequences: bool,
) -> Result<()> {
    ensure!(
        records.iter().all(|record| {
            record.scenario == scenario
                && record.run_id.as_deref() == Some(run_id)
                && record.bucket == bucket
        }),
        "history contains an operation outside the checker run scenario, run id, or bucket"
    );
    validate_successful_version_identity_uniqueness(records)?;

    let expected_event_count = records
        .len()
        .checked_mul(2)
        .context("history event count overflow")?;
    let expected_last_sequence = u64::try_from(expected_event_count)
        .context("history event count does not fit a recorder sequence")?;
    let mut event_sequences = HashSet::with_capacity(expected_event_count);
    let mut operation_ids = HashSet::with_capacity(records.len());
    let mut previous_ended_sequence = None;
    let mut previous_mutation_end_by_key = HashMap::<&str, u64>::new();

    for record in records {
        ensure!(
            !record.id.trim().is_empty() && operation_ids.insert(record.id.as_str()),
            "history contains an empty or duplicate operation id"
        );
        let started_sequence = record
            .started_sequence
            .context("history operation has no recorder start sequence")?;
        let ended_sequence = record
            .ended_sequence
            .context("history operation has no recorder end sequence")?;
        ensure!(
            started_sequence < ended_sequence,
            "history contains an inverted recorder event sequence"
        );
        if let Some(purpose) = &record.read_purpose {
            ensure!(
                record.kind == OperationKind::Get
                    && record.range.is_none()
                    && record.version_id.is_none(),
                "history read purpose requires an unversioned full GET"
            );
            if let ReadPurpose::MutationVerification { operation_id } = purpose {
                ensure!(
                    !operation_id.trim().is_empty(),
                    "history verification has an empty mutation id"
                );
            }
        }
        if let Some(attempts) = record.mutation_attempts {
            ensure!(
                matches!(
                    record.kind,
                    OperationKind::Put
                        | OperationKind::Delete
                        | OperationKind::CompleteMultipartUpload
                ) && record
                    .mutation_max_attempts
                    .is_none_or(|maximum| attempts <= maximum)
                    && (attempts > 0 || record.outcome != OperationOutcome::Ok),
                "history mutation attempt count contradicts its operation, retry ceiling, or outcome"
            );
        }
        for sequence in [started_sequence, ended_sequence] {
            ensure!(
                sequence > 0
                    && (!require_contiguous_sequences || sequence <= expected_last_sequence),
                "history recorder event sequence is outside the permitted monotonic range"
            );
            ensure!(
                event_sequences.insert(sequence),
                "history contains a duplicate recorder event sequence"
            );
        }
        if let Some(previous) = previous_ended_sequence {
            ensure!(
                previous < ended_sequence,
                "history records are not in monotonically increasing completion order"
            );
        }
        previous_ended_sequence = Some(ended_sequence);

        if matches!(
            record.kind,
            OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
        ) {
            let key = record
                .key
                .as_deref()
                .context("object mutation history record has no key")?;
            if let Some(previous_end) = previous_mutation_end_by_key.insert(key, ended_sequence) {
                ensure!(
                    previous_end < started_sequence,
                    "history mutations for key {key:?} overlap; their latest state is ambiguous"
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_history_phase_boundary(
    completed: &[OperationRecord],
    following: &[OperationRecord],
    boundary: &str,
) -> Result<()> {
    if completed.is_empty() || following.is_empty() {
        return Ok(());
    }
    let completed_sequence = completed
        .iter()
        .filter_map(|record| record.ended_sequence)
        .max()
        .context("completed history phase has no recorder end sequence")?;
    let following_sequence = following
        .iter()
        .filter_map(|record| record.started_sequence)
        .min()
        .context("following history phase has no recorder start sequence")?;
    ensure!(
        completed_sequence < following_sequence,
        "history phases overlap at {boundary}; the previous phase had not completed before the next phase began"
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct Recorder {
    inner: Arc<Mutex<RecorderState>>,
}

#[derive(Debug)]
struct RecorderState {
    path: PathBuf,
    scenario: String,
    run_id: String,
    next_id: usize,
    next_event_sequence: u64,
    durability_cohort: DurabilityCohort,
    fault_window: FaultWindow,
    records: Vec<OperationRecord>,
    writer: BufWriter<File>,
}

#[derive(Debug, Default, Clone, Copy)]
struct FaultWindow {
    active_at_ms: Option<u64>,
    ended_at_ms: Option<u64>,
}

impl Recorder {
    pub fn create(
        path: impl Into<PathBuf>,
        scenario: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let writer = BufWriter::new(File::create(&path)?);
        Ok(Self {
            inner: Arc::new(Mutex::new(RecorderState {
                path,
                scenario: scenario.into(),
                run_id: run_id.into(),
                next_id: 1,
                next_event_sequence: 1,
                durability_cohort: DurabilityCohort::PreFault,
                fault_window: FaultWindow::default(),
                records: Vec::new(),
                writer,
            })),
        })
    }

    pub fn begin(
        &self,
        kind: OperationKind,
        bucket: impl Into<String>,
        key: Option<String>,
        value_sha256: Option<String>,
        size_bytes: Option<usize>,
    ) -> OperationRecord {
        let mut state = self.state();
        let id = format!("op-{:06}", state.next_id);
        state.next_id += 1;
        let started_sequence = state.next_event_sequence;
        state.next_event_sequence += 1;
        let started_at_ms = now_ms();

        OperationRecord {
            id,
            scenario: state.scenario.clone(),
            run_id: Some(state.run_id.clone()),
            kind,
            bucket: bucket.into(),
            key,
            value_sha256,
            size_bytes,
            version_id: None,
            request_version_id: None,
            is_delete_marker: None,
            request_id: None,
            extended_request_id: None,
            mutation_max_attempts: None,
            mutation_attempts: None,
            read_purpose: None,
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: Some(started_sequence),
            ended_sequence: None,
            started_at_ms,
            ended_at_ms: started_at_ms,
            outcome: OperationOutcome::Unknown,
            http_status: None,
            error: None,
            durability_cohort: Some(state.durability_cohort),
            fault_window_relation: state
                .fault_window
                .relation_for(started_at_ms, started_at_ms),
        }
    }

    pub fn finish(
        &self,
        mut record: OperationRecord,
        outcome: OperationOutcome,
        http_status: Option<u16>,
        error: Option<String>,
    ) -> Result<OperationRecord> {
        record.ended_at_ms = now_ms();
        record.outcome = outcome;
        record.http_status = http_status;
        record.error = error.map(|message| truncate_error(&message));

        let mut state = self.state();
        record.ended_sequence = Some(state.next_event_sequence);
        state.next_event_sequence += 1;
        record.durability_cohort = Some(state.durability_cohort);
        record.fault_window_relation = state
            .fault_window
            .relation_for(record.started_at_ms, record.ended_at_ms);
        serde_json::to_writer(&mut state.writer, &record)?;
        state.writer.write_all(b"\n")?;
        state.writer.flush()?;
        state.records.push(record.clone());
        Ok(record)
    }

    pub fn records(&self) -> Vec<OperationRecord> {
        self.state().records.clone()
    }

    pub(crate) fn next_event_sequence(&self) -> u64 {
        self.state().next_event_sequence
    }

    pub fn scenario(&self) -> String {
        self.state().scenario.clone()
    }

    pub fn run_id(&self) -> String {
        self.state().run_id.clone()
    }

    pub fn path(&self) -> PathBuf {
        self.state().path.clone()
    }

    pub fn set_durability_cohort(&self, cohort: DurabilityCohort) {
        self.state().durability_cohort = cohort;
    }

    pub fn mark_fault_active_now(&self) -> u64 {
        let at_ms = now_ms();
        self.mark_fault_active_at(at_ms);
        at_ms
    }

    pub(crate) fn mark_fault_active_at(&self, at_ms: u64) {
        let mut state = self.state();
        state.fault_window.active_at_ms = Some(at_ms);
        state.fault_window.ended_at_ms = None;
        state.durability_cohort = DurabilityCohort::FaultActive;
    }

    pub fn mark_fault_ended_now(&self) -> u64 {
        let at_ms = now_ms();
        let mut state = self.state();
        state.fault_window.ended_at_ms = Some(at_ms);
        state.durability_cohort = DurabilityCohort::PostRecovery;
        at_ms
    }

    fn state(&self) -> MutexGuard<'_, RecorderState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl FaultWindow {
    fn relation_for(self, started_at_ms: u64, ended_at_ms: u64) -> Option<FaultWindowRelation> {
        let active_at_ms = self.active_at_ms?;
        let Some(fault_ended_at_ms) = self.ended_at_ms else {
            return Some(if ended_at_ms < active_at_ms {
                FaultWindowRelation::BeforeFault
            } else {
                FaultWindowRelation::DuringFault
            });
        };

        if ended_at_ms < active_at_ms {
            Some(FaultWindowRelation::BeforeFault)
        } else if started_at_ms >= fault_ended_at_ms {
            Some(FaultWindowRelation::AfterFault)
        } else if started_at_ms >= active_at_ms && ended_at_ms <= fault_ended_at_ms {
            Some(FaultWindowRelation::DuringFault)
        } else {
            Some(FaultWindowRelation::OverlapsFault)
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn truncate_error(message: &str) -> String {
    const MAX_ERROR_LEN: usize = 300;
    if message.len() <= MAX_ERROR_LEN {
        message.to_string()
    } else {
        // Slice on a char boundary at or below the byte budget; error messages
        // carry object keys and backend output that can be non-ASCII, and
        // slicing mid-codepoint would panic in the failure-recording path.
        let mut end = MAX_ERROR_LEN;
        while end > 0 && !message.is_char_boundary(end) {
            end -= 1;
        }
        format!("{}...", &message[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DurabilityCohort, OperationKind, OperationOutcome, Recorder,
        validate_history_scope_and_order, validate_partial_history_scope_and_order,
        validate_successful_version_identity_uniqueness,
    };
    use std::collections::BTreeSet;

    #[test]
    fn read_purpose_cannot_hide_a_mutation_from_workload_counts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");
        let mut record = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("k".into()),
            Some("sha".into()),
            Some(1),
        );
        record.read_purpose = Some(super::ReadPurpose::CohortProbe);
        recorder
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("record");
        let error = super::validate_history_scope_and_order(
            &recorder.records(),
            "io-eio",
            "run-1",
            "bucket",
        )
        .expect_err("mutation cannot be a probe GET");
        assert!(
            error
                .to_string()
                .contains("read purpose requires an unversioned full GET")
        );
    }

    #[test]
    fn recorder_writes_jsonl_records() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("history.jsonl");
        let recorder = Recorder::create(&path, "io-eio", "run-1").expect("recorder");
        let record = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("key".to_string()),
            Some("abc".to_string()),
            Some(3),
        );

        recorder
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("finish");

        let content = std::fs::read_to_string(&path).expect("history");
        assert!(content.contains("\"scenario\":\"io-eio\""));
        assert!(content.contains("\"kind\":\"put\""));
        assert_eq!(recorder.records().len(), 1);
        assert_eq!(recorder.path(), path);
    }

    #[test]
    fn next_event_sequence_observes_pending_begin_without_consuming_it() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run-1").expect("recorder");

        assert_eq!(recorder.next_event_sequence(), 1);
        assert_eq!(recorder.next_event_sequence(), 1);
        let pending = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("key".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        assert_eq!(pending.started_sequence, Some(1));
        assert_eq!(recorder.next_event_sequence(), 2);
        assert_eq!(recorder.next_event_sequence(), 2);

        let completed = recorder
            .finish(pending, OperationOutcome::Ok, Some(200), None)
            .expect("finish");
        assert_eq!(completed.ended_sequence, Some(2));
        assert_eq!(recorder.next_event_sequence(), 3);
    }

    #[test]
    fn records_without_version_id_still_deserialize() {
        let legacy = r#"{"id":"op-000001","scenario":"io-eio","kind":"put","bucket":"bucket","key":"k","value_sha256":"abc","size_bytes":3,"started_at_ms":1,"ended_at_ms":2,"outcome":"ok","http_status":200,"error":null}"#;

        let record = serde_json::from_str::<super::OperationRecord>(legacy).expect("legacy record");
        assert_eq!(record.mutation_attempts, None);
        assert_eq!(record.read_purpose, None);

        assert_eq!(record.version_id, None);
        assert_eq!(record.request_version_id, None);
        assert_eq!(record.is_delete_marker, None);
        assert_eq!(record.kind, OperationKind::Put);
    }

    #[test]
    fn repeated_explicit_version_deletes_do_not_claim_new_version_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");
        for _ in 0..2 {
            let mut record = recorder.begin(
                OperationKind::Delete,
                "bucket",
                Some("key".to_string()),
                None,
                None,
            );
            record.request_version_id = Some("version-1".to_string());
            record.version_id = Some("version-1".to_string());
            recorder
                .finish(record, OperationOutcome::Ok, Some(204), None)
                .expect("finish explicit version delete");
        }

        validate_successful_version_identity_uniqueness(&recorder.records())
            .expect("explicit version deletes may repeat the addressed identity");
    }

    #[test]
    fn repeated_created_delete_marker_identity_is_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");
        for _ in 0..2 {
            let mut record = recorder.begin(
                OperationKind::Delete,
                "bucket",
                Some("key".to_string()),
                None,
                None,
            );
            record.version_id = Some("marker-1".to_string());
            record.is_delete_marker = Some(true);
            recorder
                .finish(record, OperationOutcome::Ok, Some(204), None)
                .expect("finish delete marker creation");
        }

        let error = validate_successful_version_identity_uniqueness(&recorder.records())
            .expect_err("created delete marker identities must be unique");
        assert!(error.to_string().contains("marker-1"));
    }

    #[test]
    fn recorder_assigns_unique_ids_across_concurrent_writers() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");
        let writers = (0..8)
            .map(|writer| {
                let recorder = recorder.clone();
                std::thread::spawn(move || {
                    for operation in 0..25 {
                        let record = recorder.begin(
                            OperationKind::Put,
                            "bucket",
                            Some(format!("{writer}-{operation}")),
                            Some("hash".to_string()),
                            Some(4),
                        );
                        recorder
                            .finish(record, OperationOutcome::Ok, Some(200), None)
                            .expect("finish");
                    }
                })
            })
            .collect::<Vec<_>>();
        for writer in writers {
            writer.join().expect("writer thread");
        }

        let records = recorder.records();
        let ids = records
            .iter()
            .map(|record| record.id.as_str())
            .collect::<BTreeSet<_>>();
        let event_sequences = records
            .iter()
            .flat_map(|record| [record.started_sequence, record.ended_sequence])
            .flatten()
            .collect::<BTreeSet<_>>();
        assert_eq!(records.len(), 200);
        assert_eq!(ids.len(), 200);
        assert_eq!(event_sequences.len(), 400);
        assert!(records.iter().all(|record| {
            record
                .started_sequence
                .zip(record.ended_sequence)
                .is_some_and(|(started, ended)| started < ended)
        }));
    }

    #[test]
    fn history_contract_rejects_cross_bucket_and_duplicate_sequences() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "storage", "run-1")
            .expect("recorder");
        let record = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("key".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        recorder
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("finish");
        let record = recorder.begin(
            OperationKind::Get,
            "bucket",
            Some("key".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        recorder
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("finish");
        let records = recorder.records();
        validate_history_scope_and_order(&records, "storage", "run-1", "bucket")
            .expect("valid recorder history");

        let mut cross_bucket = records.clone();
        cross_bucket[0].bucket = "other-bucket".to_string();
        assert!(
            validate_history_scope_and_order(&cross_bucket, "storage", "run-1", "bucket").is_err()
        );

        let mut duplicated_sequence = records.clone();
        duplicated_sequence[1].started_sequence = duplicated_sequence[0].started_sequence;
        assert!(
            validate_history_scope_and_order(&duplicated_sequence, "storage", "run-1", "bucket")
                .is_err()
        );

        let mut reversed_completion = records;
        reversed_completion.swap(0, 1);
        let error =
            validate_history_scope_and_order(&reversed_completion, "storage", "run-1", "bucket")
                .expect_err("completion records must preserve recorder order");
        assert!(error.to_string().contains("completion order"));
    }

    #[test]
    fn partial_history_allows_cancellation_sequence_gaps() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "storage", "run-1")
            .expect("recorder");
        let _canceled = recorder.begin(
            OperationKind::Get,
            "bucket",
            Some("canceled-key".to_string()),
            None,
            None,
        );
        let completed = recorder.begin(
            OperationKind::Get,
            "bucket",
            Some("completed-key".to_string()),
            None,
            None,
        );
        recorder
            .finish(completed, OperationOutcome::NotFound, Some(404), None)
            .expect("finish completed request");
        let records = recorder.records();

        validate_partial_history_scope_and_order(&records, "storage", "run-1", "bucket")
            .expect("partial history permits the canceled request gap");
        assert!(validate_history_scope_and_order(&records, "storage", "run-1", "bucket").is_err());
    }

    #[test]
    fn history_contract_rejects_overlapping_same_key_mutations() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "storage", "run-1")
            .expect("recorder");
        let first = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("hot-key".to_string()),
            Some("first".to_string()),
            Some(4),
        );
        let second = recorder.begin(
            OperationKind::Delete,
            "bucket",
            Some("hot-key".to_string()),
            None,
            None,
        );
        recorder
            .finish(first, OperationOutcome::Ok, Some(200), None)
            .expect("first");
        recorder
            .finish(second, OperationOutcome::Ok, Some(204), None)
            .expect("second");

        let error =
            validate_history_scope_and_order(&recorder.records(), "storage", "run-1", "bucket")
                .expect_err("overlapping same-key mutations must fail closed");
        assert!(error.to_string().contains("mutations for key"));
    }

    #[test]
    fn recorder_marks_durability_cohort_and_fault_window_relation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder = Recorder::create(dir.path().join("history.jsonl"), "io-eio", "run-1")
            .expect("recorder");

        let pre_fault = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("pre".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        let pre_fault = recorder
            .finish(pre_fault, OperationOutcome::Ok, Some(200), None)
            .expect("pre fault");
        recorder.mark_fault_active_now();
        let active = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("active".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        let active = recorder
            .finish(active, OperationOutcome::Ok, Some(200), None)
            .expect("active");
        recorder.mark_fault_ended_now();
        let post = recorder.begin(
            OperationKind::Get,
            "bucket",
            Some("active".to_string()),
            None,
            None,
        );
        let post = recorder
            .finish(post, OperationOutcome::Ok, Some(200), None)
            .expect("post");

        assert_eq!(
            pre_fault.durability_cohort,
            Some(DurabilityCohort::PreFault)
        );
        assert_eq!(
            active.durability_cohort,
            Some(DurabilityCohort::FaultActive)
        );
        assert_eq!(post.durability_cohort, Some(DurabilityCohort::PostRecovery));
        assert_eq!(
            active
                .fault_window_relation
                .map(|relation| relation.as_str()),
            Some("during_fault")
        );
        assert_eq!(
            post.fault_window_relation.map(|relation| relation.as_str()),
            Some("after_fault")
        );
    }

    #[test]
    fn truncate_error_keeps_short_ascii_intact() {
        let message = "boom";
        assert_eq!(super::truncate_error(message), "boom");
    }

    #[test]
    fn truncate_error_does_not_panic_on_multibyte_boundary() {
        // A multi-byte codepoint straddling the 300-byte cut point must not
        // panic and must produce valid UTF-8. '€' is three bytes; padding the
        // prefix to 299 bytes puts the cut in the middle of a codepoint.
        let message = format!("{}{}", "a".repeat(299), "€".repeat(20));
        let truncated = super::truncate_error(&message);

        assert!(truncated.ends_with("..."));
        assert!(truncated.len() <= 303);
        // The 300th byte lands inside '€', so the boundary walk backs up to 299.
        assert_eq!(truncated, format!("{}...", "a".repeat(299)));
    }
}
