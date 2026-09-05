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

use crate::fault::shutdown::RunDeadline;
use crate::fault::{
    history::{
        ByteRange, DurabilityCohort, FaultWindowRelation, OperationKind, OperationOutcome,
        OperationRecord, PayloadRef, Recorder, validate_history_scope_and_order,
    },
    quorum::{QuorumCaseClass, QuorumMutationClass},
    workload::{
        ObjectSpec, S3WorkloadClient, StagedMultipartUpload, WorkloadOperation, WorkloadPlan,
        sha256_hex,
    },
};
use crate::framework::{artifacts::ArtifactCollector, command::CommandSpec};
use anyhow::{Context, Result, bail, ensure};
use futures::{StreamExt, TryStreamExt, stream};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::time::sleep as async_sleep;

pub(in crate::fault) fn run_warp_mixed(
    duration: Duration,
    collector: &ArtifactCollector,
    case_name: &str,
    endpoint: &str,
    bucket: &str,
    access_key: &str,
    secret_key: &str,
) -> Result<()> {
    let host = endpoint
        .strip_prefix("http://")
        .or_else(|| endpoint.strip_prefix("https://"))
        .unwrap_or(endpoint);
    let duration = format!("{}s", duration.as_secs());
    let command = CommandSpec::new("warp").args([
        "mixed".to_string(),
        format!("--host={host}"),
        format!("--access-key={access_key}"),
        format!("--secret-key={secret_key}"),
        format!("--bucket={bucket}"),
        format!("--duration={duration}"),
        "--obj.size=4KiB".to_string(),
        "--tls=false".to_string(),
        "--autoterm".to_string(),
    ]);
    let output = command.run()?;
    let display = command.display().replace(
        &format!("--secret-key={secret_key}"),
        "--secret-key=<redacted>",
    );
    collector.write_text(
        case_name,
        "warp-mixed.txt",
        &format!(
            "$ {}\nexit: {:?}\nstdout:\n{}\nstderr:\n{}",
            display, output.code, output.stdout, output.stderr
        ),
    )?;
    ensure!(
        output.code == Some(0),
        "warp mixed command failed with exit {:?}",
        output.code
    );
    Ok(())
}

const PREFILL_VERIFY_ATTEMPTS: usize = 3;
const PREFILL_VERIFY_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Whether the prefill object at `index` is created as a directory marker.
/// Pure function of (seed, index) so reruns with the same workload seed pick
/// the same keys.
fn is_directory_marker_index(percent: u8, seed: u64, index: usize) -> bool {
    if percent == 0 {
        return false;
    }
    let mut value = seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x4449_524B;
    value ^= value >> 30;
    value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^= value >> 31;
    value % 100 < u64::from(percent)
}

pub(in crate::fault) async fn prefill_objects(
    s3: &S3WorkloadClient,
    history: &Recorder,
    run_id: &str,
    plan: &WorkloadPlan,
    count: usize,
    prefill_concurrency: usize,
    directory_marker_percent: u8,
) -> Result<Vec<ObjectSpec>> {
    let tasks = (0..count).map(|index| {
        let s3 = s3.clone();
        let history = history.clone();
        let run_id = run_id.to_string();
        let size_bytes = plan.size_at(index);
        let seed = plan.seed;
        async move {
            // A deterministic (seed-stable) fraction of prefill objects are
            // zero-byte directory markers so the trailing-slash key path is
            // exercised through the whole fault/recovery cycle.
            let object = if is_directory_marker_index(directory_marker_percent, seed, index) {
                ObjectSpec::prepare_directory_marker(&run_id, index, seed)
            } else {
                ObjectSpec::prepare_seeded(&run_id, index, size_bytes, seed)
            };
            let spec = object.spec.clone();
            let write_outcome = s3.put_object(&object, &history).await?;
            ensure!(
                write_outcome == OperationOutcome::Ok,
                "prefill PUT failed before fault injection for key {}: {:?}",
                spec.key,
                write_outcome
            );
            verify_prefill_object(&s3, &history, &spec).await?;
            Ok::<_, anyhow::Error>((index, spec))
        }
    });
    let mut objects = stream::iter(tasks)
        .buffer_unordered(prefill_concurrency)
        .try_collect::<Vec<_>>()
        .await?;
    objects.sort_by_key(|(index, _)| *index);

    Ok(objects.into_iter().map(|(_, object)| object).collect())
}

async fn verify_prefill_object(
    s3: &S3WorkloadClient,
    history: &Recorder,
    spec: &ObjectSpec,
) -> Result<()> {
    let mut last_outcome = None;
    for attempt in 1..=PREFILL_VERIFY_ATTEMPTS {
        let get = s3.get_object_result(&spec.key, history).await?;
        last_outcome = Some(get.outcome);
        match get.outcome {
            OperationOutcome::Ok => {
                let body = get.body.as_deref().with_context(|| {
                    format!(
                        "prefill GET verification returned no body before fault injection for key {}",
                        spec.key
                    )
                })?;
                ensure!(
                    spec.matches_body(body),
                    "prefill GET verification returned mismatched bytes before fault injection for key {}: expected size={} sha256={}, got size={} sha256={}",
                    spec.key,
                    spec.size_bytes,
                    spec.sha256,
                    body.len(),
                    sha256_hex(body)
                );
                return Ok(());
            }
            OperationOutcome::Timeout | OperationOutcome::Unknown
                if attempt < PREFILL_VERIFY_ATTEMPTS =>
            {
                async_sleep(PREFILL_VERIFY_RETRY_DELAY).await;
            }
            _ => break,
        }
    }

    bail!(
        "prefill GET verification failed before fault injection for key {} after {} attempt(s): {:?}",
        spec.key,
        PREFILL_VERIFY_ATTEMPTS,
        last_outcome
    )
}

pub(in crate::fault) async fn probe_typed_quorum_read_cohort(
    s3: &S3WorkloadClient,
    history: &Recorder,
    prefilled: &[ObjectSpec],
    class: QuorumCaseClass,
    concurrency: usize,
) -> Result<()> {
    let expected_key = |key: &str| match class {
        QuorumCaseClass::Payload => !key.ends_with('/'),
        QuorumCaseClass::Metadata => key.ends_with('/'),
    };
    let cohort = prefilled
        .iter()
        .filter(|object| expected_key(&object.key))
        .collect::<Vec<_>>();
    ensure!(
        !cohort.is_empty(),
        "quorum P {class:?} read cohort is empty"
    );

    stream::iter(cohort)
        .map(|object| async move {
            let get = s3.get_object_result(&object.key, history).await?;
            ensure!(
                get.outcome == OperationOutcome::Ok,
                "quorum P {class:?} probe failed for key {}: {:?}",
                object.key,
                get.outcome
            );
            let body = get.body.as_deref().with_context(|| {
                format!("quorum P {class:?} probe returned no body for key {}", object.key)
            })?;
            ensure!(
                object.matches_body(body),
                "quorum P {class:?} probe returned mismatched bytes for key {}: expected size={} sha256={}, got size={} sha256={}",
                object.key,
                object.size_bytes,
                object.sha256,
                body.len(),
                sha256_hex(body)
            );
            Ok::<(), anyhow::Error>(())
        })
        .buffer_unordered(concurrency.max(1))
        .try_collect::<Vec<_>>()
        .await?;
    Ok(())
}

pub(in crate::fault) async fn stage_write_quorum_multipart_uploads(
    s3: &S3WorkloadClient,
    history: &Recorder,
    run_id: &str,
    plan: &WorkloadPlan,
    indices: std::ops::Range<usize>,
    deadline: RunDeadline,
    staged: &mut BTreeMap<usize, StagedMultipartUpload>,
) -> Result<()> {
    let tasks = multipart_workload_indices(plan, indices.start, indices.len())
        .into_iter()
        .map(|index| {
            let s3 = s3.clone();
            let history = history.clone();
            let run_id = run_id.to_string();
            async move {
                deadline.check()?;
                let object =
                    ObjectSpec::prepare_seeded(&run_id, index, plan.size_at(index), plan.seed);
                let staged = s3
                    .stage_multipart_object(&object, &history)
                    .await
                    .with_context(|| format!("stage multipart workload object at index {index}"))?;
                Ok::<_, anyhow::Error>((index, staged))
            }
        });
    let results = stream::iter(tasks)
        .buffer_unordered(plan.concurrency)
        .collect::<Vec<_>>()
        .await;
    let mut errors = Vec::new();
    for result in results {
        match result {
            Ok((index, upload)) => {
                staged.insert(index, upload);
            }
            Err(error) => errors.push(format!("{error:#}")),
        }
    }
    deadline.check()?;
    ensure!(
        errors.is_empty(),
        "multipart staging failed: {}",
        errors.join("; ")
    );
    ensure!(
        !staged.is_empty(),
        "write-quorum-loss workload contains no multipart completion operation"
    );
    Ok(())
}

pub(in crate::fault) async fn cleanup_staged_multipart_uploads(
    s3: &S3WorkloadClient,
    history: &Recorder,
    staged: BTreeMap<usize, StagedMultipartUpload>,
    concurrency: usize,
) -> Result<()> {
    let results = stream::iter(
        staged
            .into_values()
            .map(|upload| async move { s3.abort_staged_multipart_object(&upload, history).await }),
    )
    .buffer_unordered(concurrency)
    .collect::<Vec<_>>()
    .await;
    let errors = results
        .into_iter()
        .filter_map(Result::err)
        .map(|error| format!("{error:#}"))
        .collect::<Vec<_>>();
    ensure!(
        errors.is_empty(),
        "staged multipart cleanup failed: {}",
        errors.join("; ")
    );
    Ok(())
}

fn multipart_workload_indices(plan: &WorkloadPlan, start_index: usize, count: usize) -> Vec<usize> {
    (0..count)
        .filter(|offset| plan.operation_mix.operation_at(*offset) == WorkloadOperation::Multipart)
        .map(|offset| start_index + offset)
        .collect()
}

pub(in crate::fault) struct TypedQuorumReadExpectation<'a> {
    pub(in crate::fault) scenario: &'a str,
    pub(in crate::fault) run_id: &'a str,
    pub(in crate::fault) bucket: &'a str,
    pub(in crate::fault) class: QuorumCaseClass,
    pub(in crate::fault) workload_plan: &'a WorkloadPlan,
    pub(in crate::fault) cohort_source: TypedQuorumReadCohortSource<'a>,
    pub(in crate::fault) fault_active_at_ms: u64,
    pub(in crate::fault) workload_started_at_ms: u64,
}

pub(in crate::fault) enum TypedQuorumReadCohortSource<'a> {
    RuntimePrefilled(&'a [ObjectSpec]),
    ArtifactHistory,
}

struct ExpectedQuorumRead {
    key: String,
    size_bytes: usize,
    payload_ref: PayloadRef,
    trusted_sha256: Option<String>,
}

#[derive(Default)]
struct QuorumReadObservations<'a> {
    put: Option<&'a OperationRecord>,
    put_count: usize,
    verification: Option<&'a OperationRecord>,
    verification_count: usize,
    probe: Option<&'a OperationRecord>,
    probe_count: usize,
}

fn expected_quorum_reads(
    expected: &TypedQuorumReadExpectation<'_>,
) -> Result<Vec<ExpectedQuorumRead>> {
    let count = expected.workload_plan.object_count / 2;
    ensure!(
        count > 0,
        "quorum P {:?} read cohort is empty",
        expected.class
    );
    let runtime_prefilled = match expected.cohort_source {
        TypedQuorumReadCohortSource::RuntimePrefilled(objects) => {
            ensure!(
                objects.len() == count,
                "quorum P runtime prefill cohort must contain exactly {count} objects, got {}",
                objects.len()
            );
            Some(objects)
        }
        TypedQuorumReadCohortSource::ArtifactHistory => None,
    };
    let empty_sha256 = (expected.class == QuorumCaseClass::Metadata).then(|| sha256_hex(&[]));

    (0..count)
        .map(|index| {
            let (key, size_bytes) = match expected.class {
                QuorumCaseClass::Payload => (
                    ObjectSpec::seeded_key(expected.run_id, index),
                    expected.workload_plan.size_at(index),
                ),
                QuorumCaseClass::Metadata => {
                    (ObjectSpec::directory_marker_key(expected.run_id, index), 0)
                }
            };
            let payload_ref = PayloadRef {
                seed: expected.workload_plan.seed,
                index,
            };
            let trusted_sha256 = if let Some(objects) = runtime_prefilled {
                let object = &objects[index];
                ensure!(
                    object.key == key
                        && object.size_bytes == size_bytes
                        && object.seed == payload_ref.seed
                        && object.index == payload_ref.index,
                    "quorum P runtime prefill object {index} does not match the typed workload plan"
                );
                Some(object.sha256.clone())
            } else {
                empty_sha256.clone()
            };
            Ok(ExpectedQuorumRead {
                key,
                size_bytes,
                payload_ref,
                trusted_sha256,
            })
        })
        .collect()
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(in crate::fault) fn require_typed_quorum_read_survival(
    records: &[OperationRecord],
    expected: &TypedQuorumReadExpectation<'_>,
) -> Result<()> {
    ensure!(
        expected.fault_active_at_ms <= expected.workload_started_at_ms,
        "quorum P read window precedes fault activation"
    );
    let cohort = expected_quorum_reads(expected)?;
    let mut by_key = HashMap::with_capacity(cohort.len());
    for (index, object) in cohort.iter().enumerate() {
        ensure!(
            by_key.insert(object.key.as_str(), index).is_none(),
            "quorum P typed workload plan contains duplicate key {:?}",
            object.key
        );
    }
    let mut observations = (0..cohort.len())
        .map(|_| QuorumReadObservations::default())
        .collect::<Vec<_>>();
    let expected_key = |key: &str| match expected.class {
        QuorumCaseClass::Payload => !key.ends_with('/'),
        QuorumCaseClass::Metadata => key.ends_with('/'),
    };
    let mut typed_probes = 0usize;
    for record in records {
        if record.scenario != expected.scenario
            || record.run_id.as_deref() != Some(expected.run_id)
            || record.bucket != expected.bucket
        {
            continue;
        }
        let Some(key) = record.key.as_deref() else {
            continue;
        };
        let is_active_probe_window = record.durability_cohort
            == Some(DurabilityCohort::FaultActive)
            && record.fault_window_relation == Some(FaultWindowRelation::DuringFault)
            && record.kind == OperationKind::Get
            && record.started_at_ms >= expected.fault_active_at_ms
            && record.ended_at_ms <= expected.workload_started_at_ms;
        if is_active_probe_window && expected_key(key) {
            typed_probes += 1;
        }
        let Some(index) = by_key.get(key).copied() else {
            continue;
        };
        let observation = &mut observations[index];
        if record.durability_cohort == Some(DurabilityCohort::PreFault)
            && matches!(
                record.fault_window_relation,
                None | Some(FaultWindowRelation::BeforeFault)
            )
            && record.outcome == OperationOutcome::Ok
        {
            match record.kind {
                OperationKind::Put => {
                    observation.put_count += 1;
                    observation.put.get_or_insert(record);
                }
                OperationKind::Get => {
                    observation.verification_count += 1;
                    observation.verification.get_or_insert(record);
                }
                _ => {}
            }
        }
        if is_active_probe_window {
            observation.probe_count += 1;
            observation.probe.get_or_insert(record);
        }
    }

    for (object, observation) in cohort.iter().zip(&observations) {
        let Some(prefill_put) = observation.put.filter(|_| observation.put_count == 1) else {
            bail!(
                "quorum P cohort key {:?} requires exactly one deterministic pre-fault PUT, got {}",
                object.key,
                observation.put_count
            )
        };
        ensure!(
            prefill_put.size_bytes == Some(object.size_bytes)
                && prefill_put.payload_ref == Some(object.payload_ref)
                && prefill_put.started_at_ms <= prefill_put.ended_at_ms
                && prefill_put.ended_at_ms <= expected.fault_active_at_ms
                && object
                    .trusted_sha256
                    .as_deref()
                    .is_none_or(|sha256| prefill_put.value_sha256.as_deref() == Some(sha256)),
            "quorum P cohort key {:?} pre-fault PUT does not match the typed workload plan",
            object.key
        );
        let committed_sha256 = prefill_put
            .value_sha256
            .as_deref()
            .filter(|value| is_sha256(value))
            .with_context(|| {
                format!(
                    "quorum P cohort key {:?} pre-fault PUT has no valid SHA-256",
                    object.key
                )
            })?;
        let Some(verification) = observation
            .verification
            .filter(|_| observation.verification_count == 1)
        else {
            bail!(
                "quorum P cohort key {:?} requires exactly one successful pre-fault verification GET, got {}",
                object.key,
                observation.verification_count
            )
        };
        ensure!(
            verification.range.is_none()
                && verification.value_sha256.as_deref() == Some(committed_sha256)
                && verification.size_bytes == Some(object.size_bytes)
                && prefill_put
                    .ended_sequence
                    .zip(verification.started_sequence)
                    .is_some_and(|(put_end, get_start)| put_end < get_start)
                && verification.started_at_ms >= prefill_put.ended_at_ms
                && verification.started_at_ms <= verification.ended_at_ms
                && verification.ended_at_ms <= expected.fault_active_at_ms,
            "quorum P cohort key {:?} pre-fault verification GET does not match the committed PUT",
            object.key
        );
        let Some(probe) = observation.probe.filter(|_| observation.probe_count == 1) else {
            bail!(
                "quorum P cohort key {:?} requires exactly one fault-active probe before mixed workload, got {}",
                object.key,
                observation.probe_count
            )
        };
        ensure!(
            probe.outcome == OperationOutcome::Ok
                && verification
                    .ended_sequence
                    .zip(probe.started_sequence)
                    .is_some_and(|(verify_end, probe_start)| verify_end < probe_start)
                && probe.range.is_none()
                && probe.value_sha256.as_deref() == Some(committed_sha256)
                && probe.size_bytes == Some(object.size_bytes)
                && probe.started_at_ms >= expected.fault_active_at_ms
                && probe.started_at_ms <= probe.ended_at_ms
                && probe.ended_at_ms <= expected.workload_started_at_ms,
            "quorum P cohort key {:?} fault-active probe does not match the committed PUT",
            object.key
        );
    }
    ensure!(
        typed_probes == cohort.len(),
        "quorum P requires one dedicated pre-workload probe per stable {:?} cohort object: expected {}, got {typed_probes}",
        expected.class,
        cohort.len()
    );
    Ok(())
}

pub(in crate::fault) struct MixedWorkloadRequest<'a> {
    pub(in crate::fault) s3: &'a S3WorkloadClient,
    pub(in crate::fault) history: &'a Recorder,
    pub(in crate::fault) scenario: &'a str,
    pub(in crate::fault) run_id: &'a str,
    pub(in crate::fault) plan: &'a WorkloadPlan,
    pub(in crate::fault) prefilled: &'a [ObjectSpec],
    pub(in crate::fault) start_index: usize,
    pub(in crate::fault) count: usize,
    pub(in crate::fault) ranged_get_percent: u8,
    pub(in crate::fault) staged_multipart_uploads:
        Option<&'a BTreeMap<usize, StagedMultipartUpload>>,
    pub(in crate::fault) deadline: RunDeadline,
}

pub(in crate::fault) async fn run_mixed_workload(
    request: &MixedWorkloadRequest<'_>,
) -> Result<MixedWorkloadResult> {
    let MixedWorkloadRequest {
        scenario,
        run_id,
        plan,
        count,
        deadline,
        ..
    } = *request;
    // Mutations of one S3 key must have a real-time order. The checker may
    // otherwise mistake response completion order for the server's
    // linearization order when concurrent overwrite/delete requests overlap.
    let mutation_locks = (0..request.prefilled.len())
        .map(|_| AsyncMutex::new(()))
        .collect::<Vec<_>>();
    let next_mutation_sequence = AtomicU64::new(1);
    let tasks = (0..count).map(|offset| {
        execute_mixed_operation(request, offset, &mutation_locks, &next_mutation_sequence)
    });
    let results = stream::iter(tasks)
        .buffer_unordered(plan.concurrency)
        .collect::<Vec<_>>()
        .await;
    deadline.check()?;
    let mut completed = Vec::with_capacity(count);
    for result in results {
        completed.push(result?);
    }
    // Same-key mutations are serialized above, so completion order is their
    // observed real-time order. Only the final mutation of a key can remain a
    // recommit candidate: replaying an earlier ambiguous PUT after a later
    // overwrite or DELETE would manufacture a new latest value after recovery.
    let unconfirmed_puts = final_unconfirmed_puts(&completed);
    completed.sort_by_key(|result| result.index);

    let mut summary = WorkloadSummary::new(plan, scenario, run_id);
    for result in completed {
        summary.record_all(&result);
    }

    summary.require_exercised()?;
    Ok(MixedWorkloadResult {
        summary,
        unconfirmed_puts,
    })
}

async fn execute_mixed_operation(
    request: &MixedWorkloadRequest<'_>,
    offset: usize,
    mutation_locks: &[AsyncMutex<()>],
    next_mutation_sequence: &AtomicU64,
) -> Result<MixedTaskResult> {
    let MixedWorkloadRequest {
        s3,
        history,
        run_id,
        plan,
        prefilled,
        start_index,
        ranged_get_percent,
        staged_multipart_uploads,
        deadline,
        ..
    } = *request;
    deadline.check()?;
    let index = start_index + offset;
    let size_bytes = plan.size_at(index);
    let seed = plan.seed;
    let existing_offset = plan.existing_object_offset(offset, prefilled.len());
    let existing = prefilled[existing_offset].clone();
    let operation = plan.operation_mix.operation_at(offset);
    let _mutation_guard = match operation {
        WorkloadOperation::Overwrite | WorkloadOperation::Delete => {
            Some(mutation_locks[existing_offset].lock().await)
        }
        _ => None,
    };
    deadline.check()?;
    let staged_multipart = if operation == WorkloadOperation::Multipart {
        staged_multipart_uploads.map(|uploads| {
            uploads
                .get(&index)
                .cloned()
                .with_context(|| format!("missing staged multipart upload for index {index}"))
        })
    } else {
        None
    }
    .transpose();
    let staged_multipart = staged_multipart?;
    let mut result = MixedTaskResult::new(index);
    match operation {
        WorkloadOperation::Put => {
            let object = ObjectSpec::prepare_seeded(run_id, index, size_bytes, seed);
            let spec = object.spec.clone();
            result.mutation_sequence = Some(next_mutation_sequence.fetch_add(1, Ordering::Relaxed));
            let verified = s3.put_and_verify_object(&object, history).await?;
            result.mutation_key = Some(spec.key.clone());
            result.puts.push(verified.write_outcome);
            if let Some(get_outcome) = verified.verify_get_outcome {
                result.gets.push(get_outcome);
            }
            if verified.write_outcome != OperationOutcome::Ok {
                result.unconfirmed_puts.push(RecommitCandidate {
                    object: spec,
                    source_operation_id: verified.write_operation_id,
                });
            }
        }
        WorkloadOperation::Overwrite => {
            let object = existing.prepare_overwrite(index as u64 + 1);
            let spec = object.spec.clone();
            result.mutation_sequence = Some(next_mutation_sequence.fetch_add(1, Ordering::Relaxed));
            let verified = s3.put_and_verify_object(&object, history).await?;
            result.mutation_key = Some(spec.key.clone());
            result.puts.push(verified.write_outcome);
            if let Some(get_outcome) = verified.verify_get_outcome {
                result.gets.push(get_outcome);
            }
            if verified.write_outcome != OperationOutcome::Ok {
                result.unconfirmed_puts.push(RecommitCandidate {
                    object: spec,
                    source_operation_id: verified.write_operation_id,
                });
            }
        }
        WorkloadOperation::Get => {
            // Deterministically (seeded, resume-stable) turn a slice of
            // GETs into ranged reads so the sharded read path is
            // exercised at offsets, not only via whole-object streams.
            let range = ranged_get_range(ranged_get_percent, seed, index, existing.size_bytes);
            let outcome = match range {
                Some(range) => {
                    s3.get_object_range_result(&existing.key, range, history)
                        .await?
                        .outcome
                }
                None => s3.get_object_result(&existing.key, history).await?.outcome,
            };
            result.gets.push(outcome);
        }
        WorkloadOperation::List => {
            let prefix = ObjectSpec::key_prefix(run_id);
            let outcome = if s3.list_prefix(&prefix, history).await?.is_some() {
                OperationOutcome::Ok
            } else {
                OperationOutcome::Unknown
            };
            result.lists.push(outcome);
        }
        WorkloadOperation::Delete => {
            result.mutation_key = Some(existing.key.clone());
            result.mutation_sequence = Some(next_mutation_sequence.fetch_add(1, Ordering::Relaxed));
            let (delete_outcome, verify_get) =
                s3.delete_and_verify_absent(&existing.key, history).await?;
            result.deletes.push(delete_outcome);
            if let Some(get_outcome) = verify_get {
                result.gets.push(get_outcome);
            }
        }
        WorkloadOperation::Multipart => {
            let (spec, complete_record) = match staged_multipart {
                Some(staged) => {
                    let record = s3
                        .complete_staged_multipart_object_record(&staged, history)
                        .await?;
                    (staged.spec, Some(record))
                }
                None => {
                    let object = ObjectSpec::prepare_seeded(run_id, index, size_bytes, seed);
                    let record = s3
                        .complete_multipart_object_record(&object, history)
                        .await?;
                    (object.spec, record)
                }
            };
            let complete_outcome = complete_record
                .as_ref()
                .map_or(OperationOutcome::Unknown, |record| record.outcome);
            result.mutation_key = Some(spec.key.clone());
            result.mutation_sequence = Some(next_mutation_sequence.fetch_add(1, Ordering::Relaxed));
            result.multipart_completes.push(complete_outcome);
            if complete_outcome == OperationOutcome::Ok {
                result
                    .gets
                    .push(s3.get_object_result(&spec.key, history).await?.outcome);
            } else if let Some(record) = complete_record {
                result.unconfirmed_puts.push(RecommitCandidate {
                    object: spec,
                    source_operation_id: record.id,
                });
            }
            let abort_object =
                ObjectSpec::prepare_seeded(run_id, plan.object_count + index, 4 * 1024, seed);
            result
                .multipart_aborts
                .push(s3.abort_multipart_object(&abort_object, history).await?);
        }
    }
    Ok(result)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::fault) struct RecommitCandidate {
    object: ObjectSpec,
    source_operation_id: String,
}

fn final_unconfirmed_puts(completed: &[MixedTaskResult]) -> Vec<RecommitCandidate> {
    let mut pending = BTreeMap::<String, RecommitCandidate>::new();
    let mut mutations = completed
        .iter()
        .filter_map(|result| Some((result.mutation_sequence?, result)))
        .collect::<Vec<_>>();
    mutations.sort_by_key(|(sequence, _)| *sequence);
    for (_, result) in mutations {
        let Some(key) = &result.mutation_key else {
            continue;
        };
        pending.remove(key);
        if let Some(candidate) = result.unconfirmed_puts.last() {
            pending.insert(key.clone(), candidate.clone());
        }
    }
    pending.into_values().collect()
}

/// Decide whether the GET at `index` runs as a ranged read, and derive a
/// deterministic in-bounds byte range for it. Everything is a pure function of
/// (seed, index) so reruns with the same workload seed replay identical
/// operations.
fn ranged_get_range(percent: u8, seed: u64, index: usize, size_bytes: usize) -> Option<ByteRange> {
    if percent == 0 || size_bytes < 2 {
        return None;
    }
    let mix = |salt: u64| -> u64 {
        let mut value = seed ^ (index as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ salt;
        value ^= value >> 30;
        value = value.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        value ^= value >> 27;
        value = value.wrapping_mul(0x94D0_49BB_1331_11EB);
        value ^ (value >> 31)
    };
    if mix(0x52414E47) % 100 >= u64::from(percent) {
        return None;
    }
    let size = size_bytes as u64;
    // Length in [1, size], offset in [0, size - length]: covers single-byte,
    // interior, and suffix reads without ever leaving the object bounds.
    let length = 1 + mix(0x4C454E47) % size;
    let offset = mix(0x4F464653) % (size - length + 1);
    Some(ByteRange { offset, length })
}

pub(in crate::fault) async fn recommit_unconfirmed_objects(
    s3: &S3WorkloadClient,
    history: &Recorder,
    objects: &[RecommitCandidate],
    concurrency: usize,
) -> RecommitReport {
    let tasks = unconfirmed_objects_by_key(objects)
        .into_iter()
        .map(|objects| {
            let s3 = s3.clone();
            let history = history.clone();
            async move {
                let mut attempts = Vec::with_capacity(objects.len());
                for candidate in objects {
                    let prepared = candidate.object.prepare();
                    let attempt = match s3.put_object_record(&prepared, &history).await {
                        Ok(record) => {
                            let verify_get_outcome = if record.outcome == OperationOutcome::Ok {
                                match s3.get_object_result(&candidate.object.key, &history).await {
                                    Ok(get) => Some(get.outcome),
                                    Err(_) => Some(OperationOutcome::Unknown),
                                }
                            } else {
                                None
                            };
                            RecommitAttempt::from_record(candidate, record, verify_get_outcome)
                        }
                        Err(error) => RecommitAttempt::from_harness_error(
                            candidate,
                            format!("record PUT: {error}"),
                        ),
                    };
                    attempts.push(attempt);
                }
                attempts
            }
        });
    let mut attempts = stream::iter(tasks)
        .buffer_unordered(concurrency)
        .collect::<Vec<_>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    attempts.sort_by(|left, right| left.key.cmp(&right.key));
    RecommitReport::from_attempts(attempts).with_identity(&history.scenario(), &history.run_id())
}

fn unconfirmed_objects_by_key(objects: &[RecommitCandidate]) -> Vec<Vec<RecommitCandidate>> {
    let mut by_key = BTreeMap::<String, Vec<RecommitCandidate>>::new();
    for candidate in objects {
        by_key
            .entry(candidate.object.key.clone())
            .or_default()
            .push(candidate.clone());
    }
    by_key.into_values().collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::fault) struct RecommitReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::fault) scenario: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::fault) run_id: Option<String>,
    pub(in crate::fault) attempted: usize,
    pub(in crate::fault) committed: usize,
    pub(in crate::fault) failed: usize,
    pub(in crate::fault) harness_errors: usize,
    attempts: Vec<RecommitAttempt>,
}

impl RecommitReport {
    fn from_attempts(attempts: Vec<RecommitAttempt>) -> Self {
        let committed = attempts
            .iter()
            .filter(|attempt| attempt.outcome == Some(OperationOutcome::Ok))
            .count();
        let failed = attempts
            .iter()
            .filter(|attempt| attempt.is_s3_failure() || attempt.verify_get_failed())
            .count();
        let harness_errors = attempts
            .iter()
            .filter(|attempt| attempt.is_harness_error())
            .count();
        Self {
            scenario: None,
            run_id: None,
            attempted: attempts.len(),
            committed,
            failed,
            harness_errors,
            attempts,
        }
    }

    fn with_identity(mut self, scenario: &str, run_id: &str) -> Self {
        self.scenario = Some(scenario.to_string());
        self.run_id = Some(run_id.to_string());
        self
    }

    pub(in crate::fault) fn has_failures(&self) -> bool {
        self.failed > 0 || self.harness_errors > 0
    }

    pub(in crate::fault) fn failure_classification(&self) -> &'static str {
        if self.harness_errors > 0 {
            "test_harness"
        } else {
            "product_or_environment"
        }
    }

    pub(in crate::fault) fn failure_message(&self) -> String {
        let sample = self
            .attempts
            .iter()
            .filter_map(RecommitAttempt::failure_sample)
            .take(5)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "{} of {} previously unconfirmed PUTs did not commit after recovery; harness_errors={}{}",
            self.failed,
            self.attempted,
            self.harness_errors,
            if sample.is_empty() {
                String::new()
            } else {
                format!("; sample: {sample}")
            }
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RecommitAttempt {
    source_operation_id: String,
    key: String,
    size_bytes: usize,
    sha256: String,
    outcome: Option<OperationOutcome>,
    verify_get_outcome: Option<OperationOutcome>,
    http_status: Option<u16>,
    error: Option<String>,
    harness_error: Option<String>,
}

impl RecommitAttempt {
    fn from_record(
        candidate: RecommitCandidate,
        record: OperationRecord,
        verify_get_outcome: Option<OperationOutcome>,
    ) -> Self {
        let RecommitCandidate {
            object,
            source_operation_id,
        } = candidate;
        Self {
            source_operation_id,
            key: object.key,
            size_bytes: object.size_bytes,
            sha256: object.sha256,
            outcome: Some(record.outcome),
            verify_get_outcome,
            http_status: record.http_status,
            error: record.error,
            harness_error: None,
        }
    }

    fn from_harness_error(candidate: RecommitCandidate, error: String) -> Self {
        let RecommitCandidate {
            object,
            source_operation_id,
        } = candidate;
        Self {
            source_operation_id,
            key: object.key,
            size_bytes: object.size_bytes,
            sha256: object.sha256,
            outcome: None,
            verify_get_outcome: None,
            http_status: None,
            error: None,
            harness_error: Some(error),
        }
    }

    fn is_s3_failure(&self) -> bool {
        matches!(
            self.outcome,
            Some(
                OperationOutcome::NotFound
                    | OperationOutcome::Failed
                    | OperationOutcome::Timeout
                    | OperationOutcome::Unknown
            )
        )
    }

    fn is_harness_error(&self) -> bool {
        self.harness_error.is_some()
    }

    fn verify_get_failed(&self) -> bool {
        self.outcome == Some(OperationOutcome::Ok)
            && self.verify_get_outcome != Some(OperationOutcome::Ok)
    }

    fn failure_sample(&self) -> Option<String> {
        if let Some(error) = &self.harness_error {
            return Some(format!("{}=harness_error({error})", self.key));
        }
        let outcome = self.outcome?;
        if outcome == OperationOutcome::Ok {
            if self.verify_get_failed() {
                return Some(format!(
                    "{}=verify_get({:?})",
                    self.key, self.verify_get_outcome
                ));
            }
            return None;
        }
        let status = self
            .http_status
            .map(|status| format!(" status={status}"))
            .unwrap_or_default();
        let error = self
            .error
            .as_ref()
            .map(|error| format!(" error={error}"))
            .unwrap_or_default();
        Some(format!("{}={outcome:?}{status}{error}", self.key))
    }
}

#[derive(Debug, Clone)]
struct MixedTaskResult {
    index: usize,
    mutation_key: Option<String>,
    mutation_sequence: Option<u64>,
    puts: Vec<OperationOutcome>,
    gets: Vec<OperationOutcome>,
    deletes: Vec<OperationOutcome>,
    lists: Vec<OperationOutcome>,
    multipart_completes: Vec<OperationOutcome>,
    multipart_aborts: Vec<OperationOutcome>,
    unconfirmed_puts: Vec<RecommitCandidate>,
}

impl MixedTaskResult {
    fn new(index: usize) -> Self {
        Self {
            index,
            mutation_key: None,
            mutation_sequence: None,
            puts: Vec::new(),
            gets: Vec::new(),
            deletes: Vec::new(),
            lists: Vec::new(),
            multipart_completes: Vec::new(),
            multipart_aborts: Vec::new(),
            unconfirmed_puts: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub(in crate::fault) struct MixedWorkloadResult {
    pub(in crate::fault) summary: WorkloadSummary,
    pub(in crate::fault) unconfirmed_puts: Vec<RecommitCandidate>,
}

impl MixedWorkloadResult {
    pub(in crate::fault) fn seal_recommit_candidates(
        &mut self,
        s3: &S3WorkloadClient,
        history: &Recorder,
    ) -> Result<()> {
        let records = history.records();
        validate_history_scope_and_order(
            &records,
            &self.summary.scenario,
            &self.summary.run_id,
            s3.bucket(),
        )?;
        let mut records_by_id = HashMap::with_capacity(records.len());
        let mut latest_mutations = HashMap::<&str, (u64, &OperationRecord)>::new();
        for record in &records {
            records_by_id.insert(record.id.as_str(), record);
            if !matches!(
                record.kind,
                OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
            ) {
                continue;
            }
            let key = record
                .key
                .as_deref()
                .context("object mutation history record has no key")?;
            let sequence = record
                .started_sequence
                .context("object mutation history record has no start sequence")?;
            latest_mutations
                .entry(key)
                .and_modify(|latest| {
                    if sequence > latest.0 {
                        *latest = (sequence, record);
                    }
                })
                .or_insert((sequence, record));
        }
        let mut candidates = Vec::with_capacity(self.unconfirmed_puts.len());
        let mut keys = std::collections::BTreeSet::new();
        for candidate in &self.unconfirmed_puts {
            ensure!(
                keys.insert(candidate.object.key.as_str()),
                "recommit candidates contain duplicate key {}",
                candidate.object.key
            );
            let source = records_by_id
                .get(candidate.source_operation_id.as_str())
                .copied()
                .with_context(|| {
                    format!(
                        "recommit candidate {} source operation {} is absent from history",
                        candidate.object.key, candidate.source_operation_id
                    )
                })?;
            ensure!(
                matches!(
                    source.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                ) && source.outcome != OperationOutcome::Ok
                    && source.bucket == s3.bucket()
                    && source.key.as_deref() == Some(candidate.object.key.as_str())
                    && source.value_sha256.as_deref() == Some(candidate.object.sha256.as_str())
                    && source.size_bytes == Some(candidate.object.size_bytes),
                "recommit candidate {} does not match its source operation {}",
                candidate.object.key,
                candidate.source_operation_id
            );
            ensure!(
                latest_mutations
                    .get(candidate.object.key.as_str())
                    .is_some_and(|(_, latest)| latest.id == source.id),
                "recommit candidate {} was superseded by a later mutation",
                candidate.object.key
            );
            candidates.push(RecommitCandidateEvidence {
                source_operation_id: candidate.source_operation_id.clone(),
                key: candidate.object.key.clone(),
                size_bytes: candidate.object.size_bytes,
                sha256: candidate.object.sha256.clone(),
            });
        }
        candidates.sort_by(|left, right| left.key.cmp(&right.key));
        self.summary.recommit_candidates = Some(RecommitCandidateManifest {
            scenario: self.summary.scenario.clone(),
            run_id: self.summary.run_id.clone(),
            bucket: s3.bucket().to_string(),
            history_record_count: records.len(),
            history_sha256: sha256_hex(&serde_json::to_vec(&records)?),
            candidates,
        });
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::fault) struct CrashWindowEvidence {
    pub(in crate::fault) scenario: String,
    pub(in crate::fault) run_id: String,
    pub(in crate::fault) fault_active_at_ms: u64,
    pub(in crate::fault) crash_boundary_started_at_ms: u64,
    pub(in crate::fault) committed_versioned_mutations: usize,
    pub(in crate::fault) trigger_operation_id: String,
    pub(in crate::fault) trigger_kind: OperationKind,
    pub(in crate::fault) trigger_key: String,
    pub(in crate::fault) trigger_version_id: String,
    pub(in crate::fault) trigger_acknowledged_at_ms: u64,
    pub(in crate::fault) ack_to_crash_boundary_ms: u64,
}

pub(in crate::fault) fn crash_window_evidence(
    records: &[OperationRecord],
    scenario: &str,
    run_id: &str,
    fault_active_at_ms: u64,
    crash_boundary_started_at_ms: u64,
) -> Result<CrashWindowEvidence> {
    let committed = records
        .iter()
        .filter(|record| {
            record.scenario == scenario
                && record.outcome == OperationOutcome::Ok
                && record.durability_cohort == Some(DurabilityCohort::FaultActive)
                && matches!(
                    record.kind,
                    OperationKind::Put
                        | OperationKind::Delete
                        | OperationKind::CompleteMultipartUpload
                )
                && record.version_id.is_some()
                && record.ended_at_ms >= fault_active_at_ms
                && record.ended_at_ms <= crash_boundary_started_at_ms
        })
        .collect::<Vec<_>>();
    let trigger = committed
        .iter()
        .max_by_key(|record| record.ended_at_ms)
        .copied()
        .context(
            "drop_writes crash window contained no successfully acknowledged versioned PUT, DELETE marker, or multipart completion; refusing a vacuous durability verdict",
        )?;
    Ok(CrashWindowEvidence {
        scenario: scenario.to_string(),
        run_id: run_id.to_string(),
        fault_active_at_ms,
        crash_boundary_started_at_ms,
        committed_versioned_mutations: committed.len(),
        trigger_operation_id: trigger.id.clone(),
        trigger_kind: trigger.kind,
        trigger_key: trigger
            .key
            .clone()
            .context("crash trigger mutation is missing its object key")?,
        trigger_version_id: trigger
            .version_id
            .clone()
            .context("crash trigger mutation is missing its version id")?,
        trigger_acknowledged_at_ms: trigger.ended_at_ms,
        ack_to_crash_boundary_ms: crash_boundary_started_at_ms.saturating_sub(trigger.ended_at_ms),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::fault) struct WorkloadPlanArtifact<'a> {
    pub(in crate::fault) scenario: &'a str,
    pub(in crate::fault) run_id: &'a str,
    #[serde(flatten)]
    pub(in crate::fault) plan: &'a WorkloadPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::fault) struct RecommitCandidateEvidence {
    pub(in crate::fault) source_operation_id: String,
    pub(in crate::fault) key: String,
    pub(in crate::fault) size_bytes: usize,
    pub(in crate::fault) sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::fault) struct RecommitCandidateManifest {
    pub(in crate::fault) scenario: String,
    pub(in crate::fault) run_id: String,
    pub(in crate::fault) bucket: String,
    pub(in crate::fault) history_record_count: usize,
    pub(in crate::fault) history_sha256: String,
    pub(in crate::fault) candidates: Vec<RecommitCandidateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(in crate::fault) struct WorkloadSummary {
    pub(in crate::fault) scenario: String,
    pub(in crate::fault) run_id: String,
    pub(in crate::fault) seed: u64,
    pub(in crate::fault) object_count: usize,
    pub(in crate::fault) concurrency: usize,
    pub(in crate::fault) total_payload_bytes: u64,
    puts: OutcomeCounts,
    gets: OutcomeCounts,
    deletes: OutcomeCounts,
    lists: OutcomeCounts,
    multipart_completes: OutcomeCounts,
    multipart_aborts: OutcomeCounts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(in crate::fault) recommit_candidates: Option<RecommitCandidateManifest>,
    pub(in crate::fault) recommitted_after_recovery: usize,
}

impl WorkloadSummary {
    fn new(plan: &WorkloadPlan, scenario: &str, run_id: &str) -> Self {
        Self {
            scenario: scenario.to_string(),
            run_id: run_id.to_string(),
            seed: plan.seed,
            object_count: plan.object_count,
            concurrency: plan.concurrency,
            total_payload_bytes: plan.total_payload_bytes,
            puts: OutcomeCounts::default(),
            gets: OutcomeCounts::default(),
            deletes: OutcomeCounts::default(),
            lists: OutcomeCounts::default(),
            multipart_completes: OutcomeCounts::default(),
            multipart_aborts: OutcomeCounts::default(),
            recommit_candidates: None,
            recommitted_after_recovery: 0,
        }
    }

    fn record_all(&mut self, result: &MixedTaskResult) {
        for outcome in &result.puts {
            self.puts.record(*outcome);
        }
        for outcome in &result.gets {
            self.gets.record(*outcome);
        }
        for outcome in &result.deletes {
            self.deletes.record(*outcome);
        }
        for outcome in &result.lists {
            self.lists.record(*outcome);
        }
        for outcome in &result.multipart_completes {
            self.multipart_completes.record(*outcome);
        }
        for outcome in &result.multipart_aborts {
            self.multipart_aborts.record(*outcome);
        }
    }

    fn require_exercised(&self) -> Result<()> {
        ensure!(
            self.puts.total() > 0
                && self.gets.total() > 0
                && self.deletes.total() > 0
                && self.lists.total() > 0
                && self.multipart_completes.total() > 0
                && self.multipart_aborts.total() > 0,
            "fault workload did not exercise every required S3 object path: {self:?}"
        );
        Ok(())
    }

    pub(in crate::fault) fn require_fault_evidence(
        &self,
        require_client_disruption: bool,
    ) -> Result<()> {
        if require_client_disruption {
            ensure!(
                self.disrupted() > 0,
                "fault was applied but the S3 workload observed no client-visible disrupted operation; increase RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS or RUSTFS_FAULT_TEST_PERCENT, or set RUSTFS_FAULT_TEST_REQUIRE_CLIENT_DISRUPTION=0 if this is expected"
            );
        } else if self.disrupted() == 0 {
            eprintln!(
                "fault was applied, but the S3 workload observed no client-visible disrupted operation"
            );
        }
        Ok(())
    }

    pub(in crate::fault) fn require_write_quorum_loss_effect(&self) -> Result<()> {
        self.require_rejected_write_mutations(&[
            ("PUT", &self.puts),
            ("DELETE", &self.deletes),
            ("CompleteMultipartUpload", &self.multipart_completes),
        ])
    }

    pub(in crate::fault) fn require_typed_write_quorum_loss_effect(
        &self,
        unavailable_mutations: &[QuorumMutationClass],
    ) -> Result<()> {
        let mutations = unavailable_mutations
            .iter()
            .map(|mutation| match mutation {
                QuorumMutationClass::PutObject => ("PUT", &self.puts),
                QuorumMutationClass::DeleteMarker => ("DELETE", &self.deletes),
                QuorumMutationClass::MultipartComplete => {
                    ("CompleteMultipartUpload", &self.multipart_completes)
                }
            })
            .collect::<Vec<_>>();
        self.require_rejected_write_mutations(&mutations)
    }

    fn require_rejected_write_mutations(&self, mutations: &[(&str, &OutcomeCounts)]) -> Result<()> {
        ensure!(
            mutations.iter().all(|(_, counts)| counts.total() > 0),
            "write-quorum-loss workload did not exercise every mutation selected by the quorum case"
        );
        for (kind, counts) in mutations {
            ensure!(
                counts.ok == 0 && counts.not_found == 0 && counts.disrupted() > 0,
                "write-quorum-loss {kind} outcomes must all be failed, timed out, or unknown: {counts:?}"
            );
        }
        Ok(())
    }

    pub(in crate::fault) fn disrupted(&self) -> usize {
        self.puts.disrupted()
            + self.gets.disrupted()
            + self.deletes.disrupted()
            + self.lists.disrupted()
            + self.multipart_completes.disrupted()
            + self.multipart_aborts.disrupted()
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize)]
struct OutcomeCounts {
    ok: usize,
    not_found: usize,
    failed: usize,
    timeout: usize,
    unknown: usize,
}

impl OutcomeCounts {
    fn record(&mut self, outcome: OperationOutcome) {
        match outcome {
            OperationOutcome::Ok => self.ok += 1,
            OperationOutcome::NotFound => self.not_found += 1,
            OperationOutcome::Failed => self.failed += 1,
            OperationOutcome::Timeout => self.timeout += 1,
            OperationOutcome::Unknown => self.unknown += 1,
        }
    }

    fn total(&self) -> usize {
        self.ok + self.not_found + self.failed + self.timeout + self.unknown
    }

    pub(in crate::fault) fn disrupted(&self) -> usize {
        self.failed + self.timeout + self.unknown
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::history::{ByteRange, OperationOutcome, OperationRecord};

    use crate::fault::workload::WorkloadPlan;

    use serde_json::json;

    use std::time::Duration;
    /// The ranged-GET sampler must be a pure function of (seed, index): zero
    /// percent and tiny objects never sample, derived ranges always stay in
    /// bounds, and identical inputs replay identically.
    #[test]
    fn ranged_get_range_is_deterministic_and_in_bounds() {
        assert!(super::ranged_get_range(0, 42, 7, 4096).is_none());
        assert!(super::ranged_get_range(100, 42, 7, 1).is_none());

        for index in 0..2000usize {
            if let Some(range) = super::ranged_get_range(100, 42, index, 4096) {
                assert!(
                    range.length >= 1 && range.length <= 4096,
                    "length {range:?}"
                );
                assert!(range.offset + range.length <= 4096, "bounds {range:?}");
            } else {
                panic!("percent=100 must always sample");
            }
        }

        let sampled = (0..2000usize)
            .filter(|index| super::ranged_get_range(30, 42, *index, 4096).is_some())
            .count();
        assert!(
            (300..=900).contains(&sampled),
            "30% sampling grossly off: {sampled}/2000"
        );
        assert_eq!(
            super::ranged_get_range(30, 42, 5, 4096),
            super::ranged_get_range(30, 42, 5, 4096),
            "must replay identically"
        );
        assert_eq!(
            super::ranged_get_range(100, 42, 5, 4096),
            Some(ByteRange {
                offset: super::ranged_get_range(100, 42, 5, 4096).unwrap().offset,
                length: super::ranged_get_range(100, 42, 5, 4096).unwrap().length,
            })
        );
    }
    #[test]
    fn directory_marker_selection_is_deterministic_and_rate_bounded() {
        // 0% never selects; 100% always selects.
        assert!(!super::is_directory_marker_index(0, 42, 7));
        for index in 0..500 {
            assert!(super::is_directory_marker_index(100, 42, index));
        }
        // Same (seed, index) replays identically.
        assert_eq!(
            super::is_directory_marker_index(20, 42, 9),
            super::is_directory_marker_index(20, 42, 9)
        );
        // ~20% selection over a large index range.
        let selected = (0..2000)
            .filter(|index| super::is_directory_marker_index(20, 42, *index))
            .count();
        assert!(
            (200..=600).contains(&selected),
            "20% directory-marker selection grossly off: {selected}/2000"
        );
    }
    #[test]
    fn workload_summary_counts_disrupted_operations() {
        let mut summary =
            WorkloadSummary::new(&WorkloadPlan::seeded(42, 40000, 80), "io-eio", "run-1");
        summary.puts.record(OperationOutcome::Ok);
        summary.gets.record(OperationOutcome::Timeout);
        summary.gets.record(OperationOutcome::NotFound);
        summary.deletes.record(OperationOutcome::Ok);
        summary.lists.record(OperationOutcome::Ok);
        summary.multipart_completes.record(OperationOutcome::Ok);
        summary.multipart_aborts.record(OperationOutcome::Ok);

        assert_eq!(summary.puts.total(), 1);
        assert_eq!(summary.gets.total(), 2);
        assert_eq!(summary.disrupted(), 1);
        assert!(summary.require_exercised().is_ok());
        assert!(summary.require_fault_evidence(true).is_ok());
    }
    #[test]
    fn workload_summary_requires_every_object_operation_family() {
        let mut summary =
            WorkloadSummary::new(&WorkloadPlan::seeded(42, 40000, 80), "io-eio", "run-1");
        summary.puts.record(OperationOutcome::Ok);
        summary.gets.record(OperationOutcome::Ok);
        summary.deletes.record(OperationOutcome::Ok);
        summary.lists.record(OperationOutcome::Ok);
        summary.multipart_completes.record(OperationOutcome::Ok);

        assert!(summary.require_exercised().is_err());

        summary.multipart_aborts.record(OperationOutcome::Ok);
        assert!(summary.require_exercised().is_ok());
    }
    #[test]
    fn workload_summary_can_require_fault_evidence() {
        let summary = WorkloadSummary {
            scenario: "io-eio".to_string(),
            run_id: "run-1".to_string(),
            seed: 42,
            object_count: 40000,
            concurrency: 80,
            total_payload_bytes: 20_337_459_200,
            puts: OutcomeCounts {
                ok: 1,
                ..OutcomeCounts::default()
            },
            gets: OutcomeCounts {
                ok: 1,
                ..OutcomeCounts::default()
            },
            deletes: OutcomeCounts::default(),
            lists: OutcomeCounts::default(),
            multipart_completes: OutcomeCounts::default(),
            multipart_aborts: OutcomeCounts::default(),
            recommit_candidates: None,
            recommitted_after_recovery: 0,
        };

        assert!(summary.require_fault_evidence(false).is_ok());
        assert!(summary.require_fault_evidence(true).is_err());
    }
    #[test]
    fn write_quorum_loss_rejects_any_acknowledged_mutation() {
        let mut summary =
            WorkloadSummary::new(&WorkloadPlan::seeded(42, 40000, 80), "io-eio", "run-1");
        summary.puts.record(OperationOutcome::Failed);
        summary.deletes.record(OperationOutcome::Timeout);
        summary
            .multipart_completes
            .record(OperationOutcome::Unknown);
        assert!(summary.require_write_quorum_loss_effect().is_ok());

        summary.puts.record(OperationOutcome::Ok);
        assert!(summary.require_write_quorum_loss_effect().is_err());

        let mut read_only_disruption =
            WorkloadSummary::new(&WorkloadPlan::seeded(42, 40000, 80), "io-eio", "run-1");
        read_only_disruption.puts.record(OperationOutcome::NotFound);
        read_only_disruption
            .deletes
            .record(OperationOutcome::NotFound);
        read_only_disruption
            .multipart_completes
            .record(OperationOutcome::NotFound);
        read_only_disruption.gets.record(OperationOutcome::Timeout);
        assert_eq!(read_only_disruption.disrupted(), 1);
        assert!(
            read_only_disruption
                .require_write_quorum_loss_effect()
                .is_err()
        );
    }
    #[test]
    fn write_quorum_loss_rejects_invalid_outcomes_in_each_mutation_family() {
        let mut baseline =
            WorkloadSummary::new(&WorkloadPlan::seeded(42, 24, 2), "io-eio", "run-1");
        baseline.puts.record(OperationOutcome::Failed);
        baseline.deletes.record(OperationOutcome::Timeout);
        baseline
            .multipart_completes
            .record(OperationOutcome::Unknown);
        for family in 0..3 {
            for outcome in [OperationOutcome::Ok, OperationOutcome::NotFound] {
                for replace in [true, false] {
                    let mut summary = baseline.clone();
                    let counts = match family {
                        0 => &mut summary.puts,
                        1 => &mut summary.deletes,
                        _ => &mut summary.multipart_completes,
                    };
                    if replace {
                        *counts = OutcomeCounts::default();
                    }
                    counts.record(outcome);
                    assert!(
                        summary.require_write_quorum_loss_effect().is_err(),
                        "{summary:?}"
                    );
                }
            }
        }
    }
    #[test]
    fn typed_write_quorum_loss_follows_runtime_geometry() {
        use crate::fault::quorum::{ErasureSetShape, QuorumVolumeBoundary};
        for (shards, parity, class, beyond, delete_allowed, put_allowed) in [
            (4, 2, QuorumCaseClass::Payload, false, false, false),
            (4, 2, QuorumCaseClass::Payload, true, false, false),
            (8, 4, QuorumCaseClass::Payload, true, false, false),
            (8, 2, QuorumCaseClass::Payload, false, true, true),
            (8, 2, QuorumCaseClass::Payload, true, true, false),
            (12, 4, QuorumCaseClass::Payload, true, true, false),
            (8, 2, QuorumCaseClass::Metadata, false, false, false),
            (8, 2, QuorumCaseClass::Metadata, true, false, false),
        ] {
            let shape =
                ErasureSetShape::from_runtime_single_set(shards, 1, &[1], &[shards], parity)
                    .expect("runtime shape");
            let unavailable = QuorumVolumeBoundary {
                class,
                beyond_read_tolerance: beyond,
            }
            .unavailable_mutations(&shape)
            .expect("mutation quorum");
            let mut payload =
                WorkloadSummary::new(&WorkloadPlan::seeded(42, 24, 2), "io-eio", "run-1");
            payload.puts.record(OperationOutcome::Failed);
            payload.deletes.record(OperationOutcome::Ok);
            payload
                .multipart_completes
                .record(OperationOutcome::Timeout);
            assert_eq!(
                payload
                    .require_typed_write_quorum_loss_effect(&unavailable)
                    .is_ok(),
                delete_allowed,
                "DELETE at {shards}/{parity} {class:?} beyond={beyond}"
            );

            let mut metadata =
                WorkloadSummary::new(&WorkloadPlan::seeded(42, 24, 2), "io-eio", "run-1");
            metadata.puts.record(OperationOutcome::Failed);
            metadata.deletes.record(OperationOutcome::Unknown);
            metadata
                .multipart_completes
                .record(OperationOutcome::Timeout);
            assert!(
                metadata
                    .require_typed_write_quorum_loss_effect(&unavailable)
                    .is_ok()
            );

            metadata.puts.record(OperationOutcome::Ok);
            assert_eq!(
                metadata
                    .require_typed_write_quorum_loss_effect(&unavailable)
                    .is_ok(),
                put_allowed,
                "PUT at {shards}/{parity} {class:?} beyond={beyond}"
            );
        }
    }
    #[test]
    fn quorum_workload_stages_every_planned_multipart_completion() {
        let plan = WorkloadPlan::seeded(42, 24, 4);
        assert_eq!(multipart_workload_indices(&plan, 12, 12), vec![17, 23]);
    }
    #[test]
    fn quorum_p_read_oracle_requires_the_complete_stable_typed_cohort() {
        let run_id = "run-1";
        let plan = WorkloadPlan::seeded(42, 4, 2);
        let expected_objects = (0..plan.object_count / 2)
            .map(|index| ObjectSpec::prepare_directory_marker(run_id, index, plan.seed).spec)
            .collect::<Vec<_>>();
        let expectation = TypedQuorumReadExpectation {
            scenario: "quorum-p-io-fault",
            run_id,
            bucket: "bucket",
            class: QuorumCaseClass::Metadata,
            workload_plan: &plan,
            cohort_source: TypedQuorumReadCohortSource::ArtifactHistory,
            fault_active_at_ms: 100,
            workload_started_at_ms: 130,
        };
        let record = |id: &str,
                      kind: &str,
                      object: &ObjectSpec,
                      cohort: &str,
                      started_at_ms: u64,
                      ended_at_ms: u64| {
            serde_json::from_value::<OperationRecord>(json!({
                "id": id,
                "scenario": "quorum-p-io-fault",
                "run_id": run_id,
                "kind": kind,
                "bucket": "bucket",
                "key": object.key,
                "value_sha256": object.sha256,
                "size_bytes": object.size_bytes,
                "version_id": null,
                "payload_ref": {
                    "seed": object.seed,
                    "index": object.index
                },
                "started_at_ms": started_at_ms,
                "ended_at_ms": ended_at_ms,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": cohort,
                "fault_window_relation": if cohort == "pre_fault" { "before_fault" } else { "during_fault" }
            }))
            .expect("operation record")
        };
        let mut records = Vec::new();
        for (index, object) in expected_objects.iter().enumerate() {
            records.push(record(
                &format!("put-{index}"),
                "put",
                object,
                "pre_fault",
                10 + index as u64 * 10,
                11 + index as u64 * 10,
            ));
            records.push(record(
                &format!("verify-{index}"),
                "get",
                object,
                "pre_fault",
                12 + index as u64 * 10,
                13 + index as u64 * 10,
            ));
            records.push(record(
                &format!("probe-{index}"),
                "get",
                object,
                "fault_active",
                100 + index as u64 * 10,
                101 + index as u64 * 10,
            ));
        }

        records.sort_by_key(|record| record.ended_at_ms);
        for (index, record) in records.iter_mut().enumerate() {
            record.started_sequence = Some(index as u64 * 2 + 1);
            record.ended_sequence = Some(index as u64 * 2 + 2);
        }
        validate_history_scope_and_order(&records, expectation.scenario, run_id, "bucket")
            .expect("valid recorder history");
        assert!(require_typed_quorum_read_survival(&records, &expectation).is_ok());

        let mut same_ms = records.clone();
        for record in &mut same_ms {
            record.started_at_ms = 100;
            record.ended_at_ms = 100;
        }
        assert!(require_typed_quorum_read_survival(&same_ms, &expectation).is_ok());
        for (left_id, right_id) in [("put-0", "verify-0"), ("verify-0", "probe-0")] {
            let mut reversed = same_ms.clone();
            let left = reversed
                .iter()
                .position(|record| record.id == left_id)
                .expect("left");
            let right = reversed
                .iter()
                .position(|record| record.id == right_id)
                .expect("right");
            reversed.swap(left, right);
            for (index, record) in reversed.iter_mut().enumerate() {
                record.started_sequence = Some(index as u64 * 2 + 1);
                record.ended_sequence = Some(index as u64 * 2 + 2);
            }
            validate_history_scope_and_order(&reversed, expectation.scenario, run_id, "bucket")
                .expect("globally valid but causally reversed history");
            assert!(require_typed_quorum_read_survival(&reversed, &expectation).is_err());
        }

        let mut missing_probe = records.clone();
        missing_probe.retain(|record| record.id != "probe-1");
        assert!(require_typed_quorum_read_survival(&missing_probe, &expectation).is_err());

        let mut wrong_hash = records.clone();
        wrong_hash
            .iter_mut()
            .find(|record| record.id == "probe-1")
            .expect("second probe")
            .value_sha256 = Some("wrong-hash".to_string());
        assert!(require_typed_quorum_read_survival(&wrong_hash, &expectation).is_err());

        let mut missing_entire_object = records.clone();
        missing_entire_object.retain(|record| !record.id.ends_with("-1"));
        assert!(
            require_typed_quorum_read_survival(&missing_entire_object, &expectation).is_err(),
            "removing a complete PUT+verification+probe group must not shrink the expected cohort"
        );

        let mut wrong_payload_ref = records.clone();
        wrong_payload_ref
            .iter_mut()
            .find(|record| record.id == "put-1")
            .expect("second PUT")
            .payload_ref = Some(PayloadRef {
            seed: plan.seed,
            index: 0,
        });
        assert!(
            require_typed_quorum_read_survival(&wrong_payload_ref, &expectation).is_err(),
            "artifact validation must bind every key to its deterministic payload identity"
        );

        let mut wrong_runtime_cohort = expected_objects.clone();
        wrong_runtime_cohort[1].key = ObjectSpec::directory_marker_key(run_id, 99);
        let wrong_runtime_expectation = TypedQuorumReadExpectation {
            cohort_source: TypedQuorumReadCohortSource::RuntimePrefilled(&wrong_runtime_cohort),
            ..expectation
        };
        assert!(
            require_typed_quorum_read_survival(&records, &wrong_runtime_expectation).is_err(),
            "runtime validation must reject a prefilled cohort that drifts from the plan"
        );

        let pre_fault_only = records
            .iter()
            .filter(|record| record.durability_cohort == Some(DurabilityCohort::PreFault))
            .cloned()
            .collect::<Vec<_>>();
        assert!(
            require_typed_quorum_read_survival(&pre_fault_only, &expectation).is_err(),
            "pre-fault verification GETs must not masquerade as fault-active probes"
        );

        let mut forged_fault_active_time = records;
        let forged_probe = forged_fault_active_time
            .iter_mut()
            .find(|record| record.id == "probe-1")
            .expect("second probe");
        forged_probe.started_at_ms = 90;
        forged_probe.ended_at_ms = 91;
        assert_eq!(
            forged_probe.durability_cohort,
            Some(DurabilityCohort::FaultActive)
        );
        assert_eq!(
            forged_probe.fault_window_relation,
            Some(FaultWindowRelation::DuringFault)
        );
        assert!(
            require_typed_quorum_read_survival(&forged_fault_active_time, &expectation).is_err(),
            "fault-active labels must not override a probe timestamp before fault activation"
        );
    }
    #[test]
    fn quorum_p_read_oracle_indexes_the_default_scale_without_payload_generation() {
        let run_id = "scale-run";
        let plan = WorkloadPlan::seeded(42, 40_000, 16);
        let committed_sha256 = "a".repeat(64);
        let expectation = TypedQuorumReadExpectation {
            scenario: "quorum-p-io-fault",
            run_id,
            bucket: "bucket",
            class: QuorumCaseClass::Payload,
            workload_plan: &plan,
            cohort_source: TypedQuorumReadCohortSource::ArtifactHistory,
            fault_active_at_ms: 100,
            workload_started_at_ms: 130,
        };
        let record = |id: String,
                      kind: OperationKind,
                      key: String,
                      size_bytes: usize,
                      payload_ref: Option<PayloadRef>,
                      cohort: DurabilityCohort,
                      relation: FaultWindowRelation,
                      started_at_ms: u64,
                      ended_at_ms: u64| OperationRecord {
            id,
            scenario: "quorum-p-io-fault".to_string(),
            run_id: Some(run_id.to_string()),
            kind,
            bucket: "bucket".to_string(),
            key: Some(key),
            value_sha256: Some(committed_sha256.clone()),
            size_bytes: Some(size_bytes),
            version_id: None,
            listed_keys: None,
            listed_versions: None,
            payload_ref,
            range: None,
            started_sequence: None,
            ended_sequence: None,
            started_at_ms,
            ended_at_ms,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: Some(cohort),
            fault_window_relation: Some(relation),
        };
        let mut records = Vec::with_capacity(60_000);
        for index in 0..20_000 {
            let key = ObjectSpec::seeded_key(run_id, index);
            let size_bytes = plan.size_at(index);
            records.push(record(
                format!("put-{index}"),
                OperationKind::Put,
                key.clone(),
                size_bytes,
                Some(PayloadRef {
                    seed: plan.seed,
                    index,
                }),
                DurabilityCohort::PreFault,
                FaultWindowRelation::BeforeFault,
                10,
                11,
            ));
            records.push(record(
                format!("verify-{index}"),
                OperationKind::Get,
                key.clone(),
                size_bytes,
                None,
                DurabilityCohort::PreFault,
                FaultWindowRelation::BeforeFault,
                12,
                13,
            ));
            records.push(record(
                format!("probe-{index}"),
                OperationKind::Get,
                key,
                size_bytes,
                None,
                DurabilityCohort::FaultActive,
                FaultWindowRelation::DuringFault,
                100,
                101,
            ));
        }

        records.sort_by_key(|record| record.ended_at_ms);
        for (index, record) in records.iter_mut().enumerate() {
            record.started_sequence = Some(index as u64 * 2 + 1);
            record.ended_sequence = Some(index as u64 * 2 + 2);
        }
        validate_history_scope_and_order(&records, expectation.scenario, run_id, "bucket")
            .expect("valid recorder history");
        assert!(require_typed_quorum_read_survival(&records, &expectation).is_ok());
    }
    #[test]
    fn recommit_groups_same_key_attempts_in_original_order() {
        let first = ObjectSpec::prepare_seeded("run", 1, 1024, 42).spec;
        let second = first.prepare_overwrite(1).spec;
        let other = ObjectSpec::prepare_seeded("run", 2, 1024, 42).spec;

        let candidate = |object: ObjectSpec, source: &str| RecommitCandidate {
            object,
            source_operation_id: source.to_string(),
        };
        let first_candidate = candidate(first.clone(), "op-1");
        let other_candidate = candidate(other.clone(), "op-2");
        let second_candidate = candidate(second.clone(), "op-3");
        let grouped = unconfirmed_objects_by_key(&[
            first_candidate.clone(),
            other_candidate.clone(),
            second_candidate.clone(),
        ]);
        assert_eq!(grouped.len(), 2);
        let same_key = grouped
            .iter()
            .find(|objects| objects[0].object.key == first.key)
            .expect("same-key retry group");
        assert_eq!(same_key, &[first_candidate, second_candidate]);
        assert_eq!(
            grouped
                .iter()
                .filter(|objects| objects[0].object.key == other.key)
                .count(),
            1
        );
    }
    #[test]
    fn recommit_candidates_follow_the_final_same_key_mutation() {
        let first = ObjectSpec::prepare_seeded("run", 1, 1024, 42).spec;
        let latest = first.prepare_overwrite(2).spec;

        let mut ambiguous_first = MixedTaskResult::new(0);
        ambiguous_first.mutation_key = Some(first.key.clone());
        ambiguous_first.mutation_sequence = Some(10);
        ambiguous_first.unconfirmed_puts.push(RecommitCandidate {
            object: first.clone(),
            source_operation_id: "op-first".to_string(),
        });

        let mut later_delete = MixedTaskResult::new(1);
        later_delete.mutation_key = Some(first.key.clone());
        later_delete.mutation_sequence = Some(20);
        assert!(
            final_unconfirmed_puts(&[ambiguous_first.clone(), later_delete]).is_empty(),
            "a later DELETE must suppress an earlier ambiguous PUT"
        );

        let mut later_committed_overwrite = MixedTaskResult::new(2);
        later_committed_overwrite.mutation_key = Some(first.key.clone());
        later_committed_overwrite.mutation_sequence = Some(30);
        assert!(
            final_unconfirmed_puts(&[ambiguous_first.clone(), later_committed_overwrite,])
                .is_empty(),
            "a later committed overwrite must suppress an earlier ambiguous PUT"
        );

        let mut later_ambiguous_overwrite = MixedTaskResult::new(3);
        later_ambiguous_overwrite.mutation_key = Some(first.key.clone());
        later_ambiguous_overwrite.mutation_sequence = Some(40);
        later_ambiguous_overwrite
            .unconfirmed_puts
            .push(RecommitCandidate {
                object: latest.clone(),
                source_operation_id: "op-latest".to_string(),
            });
        assert_eq!(
            final_unconfirmed_puts(&[later_ambiguous_overwrite, ambiguous_first]),
            vec![RecommitCandidate {
                object: latest,
                source_operation_id: "op-latest".to_string(),
            }],
            "only the final ambiguous write remains eligible, independent of task collection order"
        );
    }
    #[tokio::test]
    async fn recommit_candidate_manifest_binds_the_source_history_checkpoint() {
        let client = S3WorkloadClient::new(
            "http://127.0.0.1:1",
            "bucket",
            "test-access",
            "test-secret",
            Duration::from_secs(1),
        )
        .await
        .expect("client");
        let dir = tempfile::tempdir().expect("tempdir");
        let history =
            Recorder::create(dir.path().join("history.jsonl"), "storage", "run").expect("history");
        let object = ObjectSpec::prepare_seeded("run", 1, 1024, 42).spec;
        let source = history.begin(
            OperationKind::Put,
            "bucket",
            Some(object.key.clone()),
            Some(object.sha256.clone()),
            Some(object.size_bytes),
        );
        let source = history
            .finish(
                source,
                OperationOutcome::Timeout,
                None,
                Some("timeout".to_string()),
            )
            .expect("source record");
        let mut workload = MixedWorkloadResult {
            summary: WorkloadSummary::new(&WorkloadPlan::seeded(42, 24, 2), "storage", "run"),
            unconfirmed_puts: vec![RecommitCandidate {
                object: object.clone(),
                source_operation_id: source.id.clone(),
            }],
        };

        workload
            .seal_recommit_candidates(&client, &history)
            .expect("seal candidates");
        let manifest = workload
            .summary
            .recommit_candidates
            .as_ref()
            .expect("manifest");
        assert_eq!(manifest.history_record_count, 1);
        assert_eq!(manifest.candidates.len(), 1);
        assert_eq!(manifest.candidates[0].source_operation_id, source.id);
        assert_eq!(manifest.candidates[0].key, object.key);
        assert_eq!(
            manifest.history_sha256,
            sha256_hex(&serde_json::to_vec(&history.records()).expect("history JSON"))
        );
    }

    #[tokio::test]
    async fn recommit_candidate_sealing_rejects_cross_bucket_history() {
        let client = S3WorkloadClient::new(
            "http://127.0.0.1:1",
            "bucket",
            "test-access",
            "test-secret",
            Duration::from_secs(1),
        )
        .await
        .expect("client");
        let dir = tempfile::tempdir().expect("tempdir");
        let history =
            Recorder::create(dir.path().join("history.jsonl"), "storage", "run").expect("history");
        let object = ObjectSpec::prepare_seeded("run", 1, 1, 42).spec;
        let source = history.begin(
            OperationKind::Put,
            "bucket",
            Some(object.key.clone()),
            Some(object.sha256.clone()),
            Some(object.size_bytes),
        );
        let source = history
            .finish(
                source,
                OperationOutcome::Timeout,
                None,
                Some("timeout".to_string()),
            )
            .expect("source");
        let foreign = history.begin(
            OperationKind::Delete,
            "other-bucket",
            Some(object.key.clone()),
            None,
            None,
        );
        history
            .finish(foreign, OperationOutcome::Ok, Some(204), None)
            .expect("foreign mutation");
        let mut workload = MixedWorkloadResult {
            summary: WorkloadSummary::new(&WorkloadPlan::seeded(42, 24, 2), "storage", "run"),
            unconfirmed_puts: vec![RecommitCandidate {
                object,
                source_operation_id: source.id,
            }],
        };

        let error = workload
            .seal_recommit_candidates(&client, &history)
            .expect_err("another bucket cannot suppress a run-bucket candidate");
        assert!(error.to_string().contains("outside the checker run"));
    }

    #[tokio::test]
    async fn recommit_candidate_sealing_scales_to_twenty_thousand_candidates() {
        const CANDIDATES: usize = 20_000;
        let client = S3WorkloadClient::new(
            "http://127.0.0.1:1",
            "bucket",
            "test-access",
            "test-secret",
            Duration::from_secs(1),
        )
        .await
        .expect("client");
        let dir = tempfile::tempdir().expect("tempdir");
        let history =
            Recorder::create(dir.path().join("history.jsonl"), "storage", "run").expect("history");
        let mut candidates = Vec::with_capacity(CANDIDATES);
        for index in 0..CANDIDATES {
            let object = ObjectSpec::prepare_seeded("run", index, 1, 42).spec;
            let source = history.begin(
                OperationKind::Put,
                "bucket",
                Some(object.key.clone()),
                Some(object.sha256.clone()),
                Some(object.size_bytes),
            );
            let source = history
                .finish(
                    source,
                    OperationOutcome::Timeout,
                    None,
                    Some("timeout".to_string()),
                )
                .expect("source");
            candidates.push(RecommitCandidate {
                object,
                source_operation_id: source.id,
            });
        }
        let mut workload = MixedWorkloadResult {
            summary: WorkloadSummary::new(
                &WorkloadPlan::seeded(42, CANDIDATES, 8),
                "storage",
                "run",
            ),
            unconfirmed_puts: candidates,
        };

        workload
            .seal_recommit_candidates(&client, &history)
            .expect("linear candidate sealing");
        assert_eq!(
            workload
                .summary
                .recommit_candidates
                .as_ref()
                .expect("manifest")
                .candidates
                .len(),
            CANDIDATES
        );
    }
    #[tokio::test]
    async fn recommit_never_overlaps_requests_for_the_same_key() {
        use axum::{
            Router,
            body::{Body, Bytes},
            http::{Method, Response},
        };
        use std::sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        };

        let active_puts = Arc::new(AtomicUsize::new(0));
        let max_active_puts = Arc::new(AtomicUsize::new(0));
        let stored = Arc::new(Mutex::new(Vec::new()));
        let app = Router::new().fallback({
            let active_puts = active_puts.clone();
            let max_active_puts = max_active_puts.clone();
            let stored = stored.clone();
            move |method: Method, body: Bytes| {
                let active_puts = active_puts.clone();
                let max_active_puts = max_active_puts.clone();
                let stored = stored.clone();
                async move {
                    match method {
                        Method::PUT => {
                            let active = active_puts.fetch_add(1, Ordering::SeqCst) + 1;
                            max_active_puts.fetch_max(active, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(25)).await;
                            *stored.lock().expect("stored body") = body.to_vec();
                            active_puts.fetch_sub(1, Ordering::SeqCst);
                            Response::builder()
                                .status(200)
                                .header("x-amz-version-id", "version")
                                .body(Body::empty())
                                .expect("PUT response")
                        }
                        Method::GET => Response::builder()
                            .status(200)
                            .body(Body::from(stored.lock().expect("stored body").clone()))
                            .expect("GET response"),
                        _ => panic!("unexpected S3 method {method}"),
                    }
                }
            }
        });
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("listener");
        let endpoint = format!("http://{}", listener.local_addr().expect("address"));
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("mock S3");
        });
        let client = S3WorkloadClient::new(
            endpoint,
            "bucket",
            "test-access",
            "test-secret",
            Duration::from_secs(2),
        )
        .await
        .expect("client");
        let dir = tempfile::tempdir().expect("tempdir");
        let history =
            Recorder::create(dir.path().join("history.jsonl"), "storage", "run").expect("history");
        let first = ObjectSpec::prepare_seeded("run", 1, 1024, 42).spec;
        let second = first.prepare_overwrite(1).spec;

        let report = recommit_unconfirmed_objects(
            &client,
            &history,
            &[
                RecommitCandidate {
                    object: first,
                    source_operation_id: "source-1".to_string(),
                },
                RecommitCandidate {
                    object: second,
                    source_operation_id: "source-2".to_string(),
                },
            ],
            2,
        )
        .await;
        assert_eq!(report.attempted, 2);
        assert_eq!(report.committed, 2);
        assert_eq!(max_active_puts.load(Ordering::SeqCst), 1);
        server.abort();
    }
    #[tokio::test]
    async fn multipart_staging_and_cleanup_drain_siblings_after_errors() {
        use crate::fault::{
            history::{OperationKind, Recorder},
            workload::{
                S3WorkloadClient, WorkloadOperationMix, WorkloadPayloadClass,
                WorkloadPayloadDistribution,
            },
        };
        use axum::{
            Router,
            body::{Body, Bytes},
            http::{Method, Response, Uri},
        };
        use std::sync::{Arc, Mutex};
        use tokio::sync::Notify;

        for (fail_stage, expire_during_stage) in [(true, false), (false, false), (false, true)] {
            let second_part_started = Arc::new(Notify::new());
            let aborted = Arc::new(Mutex::new(Vec::new()));
            let observed_aborts = aborted.clone();
            let app = Router::new().fallback(move |method: Method, uri: Uri, _body: Bytes| {
                let second_part_started = second_part_started.clone();
                let aborted = aborted.clone();
                async move {
                    let first = uri.path().ends_with("object-000017");
                    let index = if first { 17 } else { 23 };
                    match method {
                        Method::POST => Response::builder().body(Body::from(format!(
                            "<InitiateMultipartUploadResult><UploadId>upload-{index}</UploadId></InitiateMultipartUploadResult>"
                        ))).expect("create response"),
                        Method::PUT => {
                            if first {
                                second_part_started.notified().await;
                                if fail_stage {
                                    return Response::builder().status(400).body(Body::from(
                                        "<Error><Code>InvalidPart</Code><Message>injected failure</Message></Error>"
                                    )).expect("part error");
                                }
                            } else {
                                second_part_started.notify_one();
                                tokio::time::sleep(Duration::from_millis(if expire_during_stage { 1100 } else { 50 })).await;
                            }
                            Response::builder().header("etag", "etag").body(Body::empty()).expect("part response")
                        }
                        Method::DELETE => {
                            assert!(uri.query().expect("query").contains(&format!("uploadId=upload-{index}")));
                            aborted.lock().expect("aborts").push(index);
                            if first && !fail_stage {
                                Response::builder().status(403).body(Body::from(
                                    "<Error><Code>AccessDenied</Code></Error>"
                                )).expect("abort error")
                            } else {
                                Response::builder().status(204).body(Body::empty()).expect("abort response")
                            }
                        }
                        _ => panic!("unexpected S3 request: {method} {uri}"),
                    }
                }
            });
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("listener");
            let endpoint = format!("http://{}", listener.local_addr().expect("address"));
            let server = tokio::spawn(async move {
                axum::serve(listener, app).await.expect("mock S3");
            });
            let client = S3WorkloadClient::new(
                endpoint,
                "bucket",
                "test-access",
                "test-secret",
                Duration::from_secs(2),
            )
            .await
            .expect("client");
            let dir = tempfile::tempdir().expect("tempdir");
            let history = Recorder::create(dir.path().join("history.jsonl"), "quorum", "run")
                .expect("history");
            let plan = WorkloadPlan::seeded_with_profile(
                42,
                24,
                2,
                WorkloadOperationMix::default(),
                Some(WorkloadPayloadDistribution {
                    classes: vec![WorkloadPayloadClass {
                        size_bytes: 1024,
                        weight: 1,
                    }],
                }),
                None,
            )
            .expect("plan");
            let mut staged = std::collections::BTreeMap::new();
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                super::stage_write_quorum_multipart_uploads(
                    &client,
                    &history,
                    "run",
                    &plan,
                    12..24,
                    RunDeadline::new(expire_during_stage.then_some(1)).expect("deadline"),
                    &mut staged,
                ),
            )
            .await
            .expect("staging is bounded");
            assert_eq!(result.is_err(), fail_stage || expire_during_stage);
            if expire_during_stage {
                assert!(
                    result
                        .expect_err("deadline")
                        .is::<crate::fault::shutdown::SuiteDeadlineExceeded>()
                );
            }
            assert_eq!(
                staged.keys().copied().collect::<Vec<_>>(),
                if fail_stage { vec![23] } else { vec![17, 23] }
            );
            let cleanup = tokio::time::timeout(
                Duration::from_secs(5),
                super::cleanup_staged_multipart_uploads(&client, &history, staged, 2),
            )
            .await
            .expect("cleanup is bounded");
            assert_eq!(cleanup.is_err(), !fail_stage);
            if let Err(error) = cleanup {
                assert!(error.to_string().contains("upload-17"));
            }
            let mut aborted = observed_aborts.lock().expect("observed aborts").clone();
            aborted.sort_unstable();
            assert_eq!(aborted, vec![17, 23]);
            let records = history.records();
            assert_eq!(
                records.len(),
                6,
                "both Create, UploadPart, and Abort attempts must finish"
            );
            assert!(
                records
                    .iter()
                    .any(|record| record.kind == OperationKind::UploadPart
                        && record.key.as_ref().expect("key").ends_with("object-000023")
                        && record.outcome == OperationOutcome::Ok)
            );
            let persisted: Vec<OperationRecord> = std::fs::read_to_string(history.path())
                .expect("persisted history")
                .lines()
                .map(|line| serde_json::from_str(line).expect("record"))
                .collect();
            assert_eq!(
                serde_json::to_value(persisted).expect("persisted records"),
                serde_json::to_value(records).expect("records")
            );
            server.abort();
        }
    }
    #[test]
    fn crash_window_evidence_selects_the_latest_versioned_mutation_ack() {
        let records = [
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-1",
                "scenario": "dm-flakey-versioned-hot",
                "kind": "put",
                "bucket": "bucket",
                "key": "key-a",
                "value_sha256": "abc",
                "size_bytes": 4096,
                "version_id": "version-a",
                "started_at_ms": 110,
                "ended_at_ms": 120,
                "outcome": "ok",
                "http_status": 200,
                "error": null,
                "durability_cohort": "fault_active",
                "fault_window_relation": "during_fault"
            }))
            .expect("first record"),
            serde_json::from_value::<OperationRecord>(json!({
                "id": "op-2",
                "scenario": "dm-flakey-versioned-hot",
                "kind": "delete",
                "bucket": "bucket",
                "key": "key-b",
                "value_sha256": null,
                "size_bytes": null,
                "version_id": "delete-marker-b",
                "started_at_ms": 130,
                "ended_at_ms": 140,
                "outcome": "ok",
                "http_status": 204,
                "error": null,
                "durability_cohort": "fault_active",
                "fault_window_relation": "during_fault"
            }))
            .expect("second record"),
        ];

        let evidence =
            super::crash_window_evidence(&records, "dm-flakey-versioned-hot", "run-1", 100, 150)
                .expect("evidence");

        assert_eq!(evidence.scenario, "dm-flakey-versioned-hot");
        assert_eq!(evidence.run_id, "run-1");
        assert_eq!(evidence.committed_versioned_mutations, 2);
        assert_eq!(evidence.trigger_operation_id, "op-2");
        assert_eq!(evidence.trigger_version_id, "delete-marker-b");
        assert_eq!(evidence.ack_to_crash_boundary_ms, 10);
    }
    #[test]
    fn crash_window_evidence_rejects_a_vacuous_window() {
        assert!(
            super::crash_window_evidence(&[], "dm-flakey-versioned-hot", "run-1", 100, 150,)
                .is_err()
        );
    }
    #[test]
    fn recommit_report_counts_and_summarizes_failed_attempts() {
        let report = RecommitReport::from_attempts(vec![
            RecommitAttempt {
                source_operation_id: "source-a".to_string(),
                key: "object-a".to_string(),
                size_bytes: 4096,
                sha256: "sha-a".to_string(),
                outcome: Some(OperationOutcome::Ok),
                verify_get_outcome: Some(OperationOutcome::Ok),
                http_status: Some(200),
                error: None,
                harness_error: None,
            },
            RecommitAttempt {
                source_operation_id: "source-b".to_string(),
                key: "object-b".to_string(),
                size_bytes: 4096,
                sha256: "sha-b".to_string(),
                outcome: Some(OperationOutcome::Failed),
                verify_get_outcome: None,
                http_status: Some(503),
                error: Some("service unavailable".to_string()),
                harness_error: None,
            },
        ]);

        assert_eq!(report.attempted, 2);
        assert_eq!(report.committed, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(report.harness_errors, 0);
        assert!(report.has_failures());
        assert!(
            report
                .failure_message()
                .contains("object-b=Failed status=503")
        );
        assert_eq!(report.failure_classification(), "product_or_environment");
    }
    #[test]
    fn recommit_report_separates_harness_errors_from_s3_failures() {
        let report = RecommitReport::from_attempts(vec![RecommitAttempt {
            source_operation_id: "source-a".to_string(),
            key: "object-a".to_string(),
            size_bytes: 4096,
            sha256: "sha-a".to_string(),
            outcome: None,
            verify_get_outcome: None,
            http_status: None,
            error: None,
            harness_error: Some("record PUT: disk full".to_string()),
        }]);

        assert_eq!(report.attempted, 1);
        assert_eq!(report.committed, 0);
        assert_eq!(report.failed, 0);
        assert_eq!(report.harness_errors, 1);
        assert!(report.has_failures());
        assert_eq!(report.failure_classification(), "test_harness");
        assert!(
            report
                .failure_message()
                .contains("object-a=harness_error(record PUT: disk full)")
        );
    }
}
