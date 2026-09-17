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

//! Scenario-owned sequencing and S3 overlap evidence for admin rebalance.
//!
//! Fixture staging remains owned by the shared admin workflow layer. This
//! module starts only after that layer has produced a run-owned, two-pool
//! topology proof and exposes one narrow snapshot hook for that integration.

use anyhow::{Context, Result, bail, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    error::Error,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{Instant, sleep, timeout},
};

use crate::fault::{
    admin_runner::{AdminCancelOutcome, AdminCaseDriver, AdminWorkflowObservation},
    admin_topology::{
        ADMIN_OPERATION_ARTIFACT, ADMIN_OPERATION_PROGRESS_ARTIFACT, ADMIN_TOPOLOGY_PROOF_ARTIFACT,
        AdminAttemptIdentity, AdminAttemptWindow, AdminOperationEvidence,
        AdminOperationProgressSample, AdminPoolSnapshot, AdminRequestEvidence,
        AdminTopologyBuildContext, AdminTopologyPort, AdminTopologyProof, RebalanceStart,
        RebalanceStatus, RustfsAdminTopologyAdapter, rebalance_progress_sample,
        validate_admin_operation_progress, validate_admin_pre_start_snapshot,
    },
    checker::{self, CheckerReport},
    config::FaultTestConfig,
    events::RunEventStatus,
    fixture::{
        ADMIN_FIXTURE_ARTIFACT, AdminFixtureEvidence, AdminFixturePhase, AdminFixturePlan,
        apply_admin_tenant_stage, capture_admin_fixture_observation, reset_tenant_resources,
    },
    history::{
        DurabilityCohort, OperationKind, OperationOutcome, OperationRecord,
        validate_history_scope_and_order,
    },
    plan::AdminExecutionPlan,
    pods::rustfs_pod_identities,
    preflight::{PreflightCheck, PreflightPhase, PreflightSummary},
    recovery_health::{RECOVERY_HEALTH_ARTIFACT, RecoveryHealthBaseline},
    reporting::ResponsibilityDomain,
    runner::{
        FaultRunContext, POST_RECOVERY_SEED_SALT, ensure_s3_access, initialize_fault_run,
        observe_recovery_health, s3_access, tenant_port_forward, wait_for_ready_tenant,
        wait_for_stable_rustfs_pods, wait_for_tenant_s3,
    },
    scenarios::{ADMIN_REBALANCE_SCENARIO, FaultScenario},
    shutdown::RunDeadline,
    workload::execution::{
        MixedWorkloadRequest, MixedWorkloadResult, POST_RECOVERY_WRITE_HISTORY_ARTIFACT,
        POST_RECOVERY_WRITE_REPORT_ARTIFACT, PostRecoveryWriteRequest, post_recovery_object_count,
        prefill_objects, recommit_unconfirmed_objects, run_mixed_workload,
        run_post_recovery_write_probe,
    },
    workload::{ObjectSpec, S3WorkloadClient},
};
use crate::framework::{artifacts::ArtifactCollector, port_forward::PortForwardGuard, resources};

pub const ADMIN_REBALANCE_OVERLAP_ARTIFACT: &str = "admin-rebalance-overlap.json";
pub const ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT: &str = "admin-rebalance-transcript.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdminRebalanceLimits {
    pub poll_interval: Duration,
    pub operation_timeout: Duration,
    pub stop_timeout: Duration,
}

impl AdminRebalanceLimits {
    pub fn validate(self) -> Result<()> {
        ensure!(
            !self.poll_interval.is_zero()
                && !self.operation_timeout.is_zero()
                && !self.stop_timeout.is_zero()
                && self.poll_interval <= self.operation_timeout
                && self.poll_interval <= self.stop_timeout,
            "admin rebalance polling and operation/stop deadlines must be positive and ordered"
        );
        Ok(())
    }
}

#[async_trait]
pub trait AdminRebalanceAttemptPort: AdminTopologyPort {
    /// Capture a Tenant GET, runtime binding, and pools/list receipt in that
    /// order. The shared workflow implementation owns the Kubernetes access.
    async fn capture_pool_snapshot(&self) -> Result<AdminPoolSnapshot>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminRebalanceWorkloadReceipt {
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    /// Complete recorder contents at workload completion. The overlap artifact
    /// stores only IDs; the offline validator authenticates them against the
    /// final history and checker audit.
    pub history: Vec<OperationRecord>,
}

#[async_trait]
pub trait AdminRebalanceWorkload: Send + Sync {
    /// Run exactly one finite, byte-budgeted mixed workload. Implementations
    /// must return an error for a partial harness execution.
    async fn run_bounded(&self) -> Result<AdminRebalanceWorkloadReceipt>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRebalanceOverlapEvidence {
    #[serde(flatten)]
    pub attempt: AdminAttemptIdentity,
    pub operation_id: String,
    pub rebalance_started_at_ms: u64,
    pub rebalance_completed_at_ms: u64,
    pub workload_started_at_ms: u64,
    pub workload_ended_at_ms: u64,
    pub workload_first_event_sequence: u64,
    pub workload_last_event_sequence: u64,
    pub workload_operation_ids: Vec<String>,
    pub overlapping_operation_ids: Vec<String>,
    pub overlapping_status_request_ids: Vec<String>,
}

impl AdminRebalanceOverlapEvidence {
    pub fn from_history(
        operation: &AdminOperationEvidence,
        progress: &[AdminOperationProgressSample],
        workload: &AdminRebalanceWorkloadReceipt,
    ) -> Result<Self> {
        ensure!(
            operation.scenario == ADMIN_REBALANCE_SCENARIO,
            "operation is not admin-rebalance"
        );
        let evidence = Self::from_receipts(
            &operation.attempt,
            &operation.operation_id,
            &operation.requests,
            progress,
            workload,
        )?;
        evidence.validate(operation, progress, &workload.history)?;
        Ok(evidence)
    }

    fn from_receipts(
        attempt: &AdminAttemptIdentity,
        operation_id: &str,
        requests: &[AdminRequestEvidence],
        progress: &[AdminOperationProgressSample],
        workload: &AdminRebalanceWorkloadReceipt,
    ) -> Result<Self> {
        validate_overlap_progress_receipts(requests, progress)?;
        let (rebalance_started_at_ms, rebalance_completed_at_ms) = rebalance_window(requests)?;
        let workload_records = workload_records(workload)?;
        let overlapping_status_request_ids = overlapping_status_request_ids(
            requests,
            progress,
            workload.started_at_ms,
            workload.ended_at_ms,
        )?;
        let overlapping_operation_ids = workload_records
            .iter()
            .filter(|record| {
                strict_intervals_overlap(
                    record.started_at_ms,
                    record.ended_at_ms,
                    rebalance_started_at_ms,
                    rebalance_completed_at_ms,
                )
            })
            .map(|record| record.id.clone())
            .collect();
        let evidence = Self {
            attempt: attempt.clone(),
            operation_id: operation_id.to_string(),
            rebalance_started_at_ms,
            rebalance_completed_at_ms,
            workload_started_at_ms: workload.started_at_ms,
            workload_ended_at_ms: workload.ended_at_ms,
            workload_first_event_sequence: workload.first_event_sequence,
            workload_last_event_sequence: workload.last_event_sequence,
            workload_operation_ids: workload_records
                .iter()
                .map(|record| record.id.clone())
                .collect(),
            overlapping_operation_ids,
            overlapping_status_request_ids,
        };
        evidence.validate_receipts(requests, progress, &workload.history)?;
        Ok(evidence)
    }

    pub fn validate(
        &self,
        operation: &AdminOperationEvidence,
        progress: &[AdminOperationProgressSample],
        history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            operation.scenario == ADMIN_REBALANCE_SCENARIO
                && self.attempt == operation.attempt
                && self.operation_id == operation.operation_id,
            "rebalance overlap identity does not match the admin operation"
        );
        self.validate_receipts(&operation.requests, progress, history)
    }

    fn validate_receipts(
        &self,
        requests: &[AdminRequestEvidence],
        progress: &[AdminOperationProgressSample],
        history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            !self.operation_id.trim().is_empty()
                && !progress.is_empty()
                && progress.iter().all(|sample| {
                    sample.attempt == self.attempt && sample.operation_id == self.operation_id
                })
                && progress[..progress.len().saturating_sub(1)]
                    .iter()
                    .all(|sample| {
                        !sample.completed && !sample.failed && !sample.canceled_or_stopped
                    })
                && progress.last().is_some_and(|sample| {
                    sample.completed && !sample.failed && !sample.canceled_or_stopped
                })
                && progress
                    .windows(2)
                    .all(|pair| pair[0].observed_at_ms <= pair[1].observed_at_ms),
            "rebalance overlap progress is not bound to one successful terminal operation"
        );
        validate_overlap_progress_receipts(requests, progress)?;
        ensure!(
            !history.is_empty()
                && history.iter().all(|record| {
                    record.scenario == ADMIN_REBALANCE_SCENARIO
                        && record.run_id.as_deref() == Some(self.attempt.run_id.as_str())
                }),
            "rebalance overlap history does not belong to the current scenario attempt"
        );
        let (rebalance_started_at_ms, rebalance_completed_at_ms) = rebalance_window(requests)?;
        ensure!(
            self.rebalance_started_at_ms == rebalance_started_at_ms
                && self.rebalance_completed_at_ms == rebalance_completed_at_ms
                && strict_intervals_overlap(
                    self.workload_started_at_ms,
                    self.workload_ended_at_ms,
                    self.rebalance_started_at_ms,
                    self.rebalance_completed_at_ms,
                ),
            "bounded S3 workload did not intersect the observed rebalance window"
        );
        let receipt = AdminRebalanceWorkloadReceipt {
            started_at_ms: self.workload_started_at_ms,
            ended_at_ms: self.workload_ended_at_ms,
            first_event_sequence: self.workload_first_event_sequence,
            last_event_sequence: self.workload_last_event_sequence,
            history: history.to_vec(),
        };
        let records = workload_records(&receipt)?;
        ensure!(
            records
                .iter()
                .map(|record| record.id.as_str())
                .eq(self.workload_operation_ids.iter().map(String::as_str)),
            "rebalance overlap operation IDs do not match the authenticated workload history slice"
        );
        let overlapping_operation_ids = records
            .iter()
            .filter(|record| {
                strict_intervals_overlap(
                    record.started_at_ms,
                    record.ended_at_ms,
                    self.rebalance_started_at_ms,
                    self.rebalance_completed_at_ms,
                )
            })
            .map(|record| record.id.as_str())
            .collect::<Vec<_>>();
        ensure!(
            !overlapping_operation_ids.is_empty()
                && overlapping_operation_ids
                    .iter()
                    .copied()
                    .eq(self.overlapping_operation_ids.iter().map(String::as_str)),
            "no complete S3 operation interval overlaps the observed rebalance window"
        );
        let status_request_ids = overlapping_status_request_ids(
            requests,
            progress,
            self.workload_started_at_ms,
            self.workload_ended_at_ms,
        )?;
        ensure!(
            !status_request_ids.is_empty()
                && status_request_ids
                    .iter()
                    .eq(self.overlapping_status_request_ids.iter()),
            "rebalance has no status request receipt intersecting the workload"
        );
        validate_workload_families(history, records)?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct AdminRebalanceExecution {
    pub proof: AdminTopologyProof,
    pub operation: AdminOperationEvidence,
    pub progress: Vec<AdminOperationProgressSample>,
    pub overlap: AdminRebalanceOverlapEvidence,
    pub attempt_window: AdminAttemptWindow,
    workload_history: Vec<OperationRecord>,
}

impl AdminRebalanceExecution {
    pub fn write_artifacts(&self, collector: &ArtifactCollector) -> Result<()> {
        self.proof.require_satisfied()?;
        self.operation.require_success(self.attempt_window)?;
        validate_admin_operation_progress(&self.operation, &self.progress, self.attempt_window)?;
        self.overlap
            .validate(&self.operation, &self.progress, &self.workload_history)
            .context("validate rebalance overlap before artifact write")?;
        let case_name = &self.operation.attempt.case_name;
        collector.write_text(
            case_name,
            ADMIN_TOPOLOGY_PROOF_ARTIFACT,
            &serde_json::to_string_pretty(&self.proof)?,
        )?;
        collector.write_text(
            case_name,
            ADMIN_OPERATION_ARTIFACT,
            &serde_json::to_string_pretty(&self.operation)?,
        )?;
        let progress = self
            .progress
            .iter()
            .map(serde_json::to_string)
            .collect::<std::result::Result<Vec<_>, _>>()?
            .join("\n");
        collector.write_text(
            case_name,
            ADMIN_OPERATION_PROGRESS_ARTIFACT,
            &format!("{progress}\n"),
        )?;
        collector.write_text(
            case_name,
            ADMIN_REBALANCE_OVERLAP_ARTIFACT,
            &serde_json::to_string_pretty(&self.overlap)?,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminRebalanceTranscript {
    pub operation_id: Option<String>,
    pub requests: Vec<AdminRequestEvidence>,
    pub progress: Vec<AdminOperationProgressSample>,
}

impl AdminRebalanceTranscript {
    pub fn validate(
        &self,
        operation: &AdminOperationEvidence,
        progress: &[AdminOperationProgressSample],
    ) -> Result<()> {
        ensure!(
            self.operation_id.as_deref() == Some(operation.operation_id.as_str())
                && self.requests == operation.requests
                && self.progress == progress,
            "rebalance transcript does not match the persisted operation receipts"
        );
        Ok(())
    }
}

#[derive(Debug)]
pub struct AdminRebalanceExecutionError {
    primary: anyhow::Error,
    stop_error: Option<anyhow::Error>,
    transcript: AdminRebalanceTranscript,
}

impl AdminRebalanceExecutionError {
    pub fn primary_error(&self) -> &anyhow::Error {
        &self.primary
    }

    pub fn stop_error(&self) -> Option<&anyhow::Error> {
        self.stop_error.as_ref()
    }

    pub fn transcript(&self) -> &AdminRebalanceTranscript {
        &self.transcript
    }
}

impl fmt::Display for AdminRebalanceExecutionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:#}", self.primary)?;
        if let Some(stop_error) = &self.stop_error {
            write!(formatter, "; rebalance stop also failed: {stop_error:#}")?;
        }
        Ok(())
    }
}

impl Error for AdminRebalanceExecutionError {}

struct TerminalRebalance {
    start: RebalanceStart,
    status: RebalanceStatus,
}

/// Execute the scenario-specific operation phase after the shared staged-pool
/// fixture has produced its topology proof.
pub async fn run_admin_rebalance<P, W>(
    port: &P,
    workload: &W,
    proof: AdminTopologyProof,
    attempt_started_at_ms: u64,
    limits: AdminRebalanceLimits,
) -> std::result::Result<AdminRebalanceExecution, AdminRebalanceExecutionError>
where
    P: AdminRebalanceAttemptPort,
    W: AdminRebalanceWorkload,
{
    let transcript = Arc::new(Mutex::new(AdminRebalanceTranscript::default()));
    let result = run_admin_rebalance_inner(
        port,
        workload,
        proof.clone(),
        attempt_started_at_ms,
        limits,
        Arc::clone(&transcript),
    )
    .await;
    match result {
        Ok(execution) => Ok(execution),
        Err(primary) => {
            let operation_id = transcript_state(&transcript).operation_id;
            let stop_error = if let Some(operation_id) = operation_id {
                stop_owned_rebalance(port, &proof, &operation_id, limits, &transcript)
                    .await
                    .err()
            } else {
                None
            };
            Err(AdminRebalanceExecutionError {
                primary,
                stop_error,
                transcript: transcript_state(&transcript),
            })
        }
    }
}

async fn run_admin_rebalance_inner<P, W>(
    port: &P,
    workload: &W,
    proof: AdminTopologyProof,
    attempt_started_at_ms: u64,
    limits: AdminRebalanceLimits,
    transcript: Arc<Mutex<AdminRebalanceTranscript>>,
) -> Result<AdminRebalanceExecution>
where
    P: AdminRebalanceAttemptPort,
    W: AdminRebalanceWorkload,
{
    limits.validate()?;
    proof.require_satisfied()?;
    ensure!(
        proof.scenario == ADMIN_REBALANCE_SCENARIO
            && proof.tenant_pools.len() == 2
            && proof.runtime_pools.len() == 2,
        "admin-rebalance requires one run-owned topology proof with exactly two pools"
    );
    ensure!(
        attempt_started_at_ms > 0 && attempt_started_at_ms <= now_ms(),
        "admin-rebalance attempt start time is invalid"
    );

    let pools_before = port
        .capture_pool_snapshot()
        .await
        .context("capture fresh pre-start rebalance pool snapshot")?;
    validate_admin_pre_start_snapshot(&proof, &pools_before, now_ms())
        .context("revalidate rebalance topology immediately before start")?;
    let start_call = port
        .start_rebalance()
        .await
        .context("start RustFS rebalance")?;
    ensure!(
        !start_call.value.id.trim().is_empty(),
        "RustFS rebalance start response has no operation ID"
    );
    {
        let mut state = lock_transcript(&transcript);
        state.operation_id = Some(start_call.value.id.clone());
        state.requests.push(start_call.request.clone());
    }

    let poll = poll_rebalance(
        port,
        &proof,
        start_call.value.clone(),
        limits,
        Arc::clone(&transcript),
    );
    let workload_run = workload.run_bounded();
    tokio::pin!(poll);
    tokio::pin!(workload_run);

    let (workload_receipt, terminal) = tokio::select! {
        workload_result = &mut workload_run => {
            let receipt = workload_result.context("bounded admin-rebalance workload failed")?;
            let terminal = poll.await?;
            (receipt, terminal)
        }
        poll_result = &mut poll => {
            let terminal = poll_result?;
            let receipt = workload_run.await.context("bounded admin-rebalance workload failed")?;
            (receipt, terminal)
        }
    };

    let pools_after = port
        .capture_pool_snapshot()
        .await
        .context("capture post-terminal rebalance pool snapshot")?;
    let state = transcript_state(&transcript);
    let operation = AdminOperationEvidence::from_rebalance(
        &proof,
        pools_before,
        &terminal.start,
        terminal.status,
        state.requests,
        pools_after,
    )?;
    let attempt_window = AdminAttemptWindow {
        started_at_ms: attempt_started_at_ms,
        evaluated_at_ms: now_ms(),
    };
    operation.require_success(attempt_window)?;
    validate_admin_operation_progress(&operation, &state.progress, attempt_window)?;
    let overlap = AdminRebalanceOverlapEvidence::from_history(
        &operation,
        &state.progress,
        &workload_receipt,
    )?;

    Ok(AdminRebalanceExecution {
        proof: proof.clone(),
        operation,
        progress: state.progress,
        overlap,
        attempt_window,
        workload_history: workload_receipt.history,
    })
}

async fn poll_rebalance<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    start: RebalanceStart,
    limits: AdminRebalanceLimits,
    transcript: Arc<Mutex<AdminRebalanceTranscript>>,
) -> Result<TerminalRebalance> {
    let deadline = Instant::now() + limits.operation_timeout;
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for RustFS rebalance completion")?;
        let call = timeout(remaining, port.rebalance_status())
            .await
            .context("timed out reading RustFS rebalance status")??;
        {
            lock_transcript(&transcript)
                .requests
                .push(call.request.clone());
        }
        let sample = rebalance_progress_sample(proof, &start.id, &call)?;
        let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
        lock_transcript(&transcript).progress.push(sample);
        if terminal {
            return Ok(TerminalRebalance {
                start,
                status: call.value,
            });
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for RustFS rebalance completion")?;
        sleep(limits.poll_interval.min(remaining)).await;
    }
}

async fn stop_owned_rebalance<P: AdminTopologyPort>(
    port: &P,
    proof: &AdminTopologyProof,
    operation_id: &str,
    limits: AdminRebalanceLimits,
    transcript: &Arc<Mutex<AdminRebalanceTranscript>>,
) -> Result<()> {
    let deadline = Instant::now() + limits.stop_timeout;
    let status = timeout(limits.stop_timeout, port.rebalance_status())
        .await
        .context("timed out proving rebalance ownership before stop")??;
    lock_transcript(transcript)
        .requests
        .push(status.request.clone());
    let sample = rebalance_progress_sample(proof, operation_id, &status)
        .context("refusing to stop a rebalance not owned by this attempt")?;
    let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
    lock_transcript(transcript).progress.push(sample);
    if terminal {
        return Ok(());
    }

    let remaining = deadline
        .checked_duration_since(Instant::now())
        .context("rebalance stop deadline elapsed before stop request")?;
    let stop = timeout(remaining, port.stop_rebalance())
        .await
        .context("timed out stopping owned RustFS rebalance")??;
    lock_transcript(transcript)
        .requests
        .push(stop.request.clone());

    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for stopped RustFS rebalance")?;
        let status = timeout(remaining, port.rebalance_status())
            .await
            .context("timed out reading RustFS rebalance status after stop")??;
        lock_transcript(transcript)
            .requests
            .push(status.request.clone());
        let sample = rebalance_progress_sample(proof, operation_id, &status)?;
        let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
        lock_transcript(transcript).progress.push(sample);
        if terminal {
            return Ok(());
        }
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .context("timed out waiting for stopped RustFS rebalance")?;
        sleep(limits.poll_interval.min(remaining)).await;
    }
}

pub fn validate_admin_rebalance_evidence(
    operation: &AdminOperationEvidence,
    progress: &[AdminOperationProgressSample],
    overlap: &AdminRebalanceOverlapEvidence,
    history: &[OperationRecord],
    checker: &CheckerReport,
) -> Result<()> {
    overlap.validate(operation, progress, history)?;
    ensure!(
        checker.scenario == ADMIN_REBALANCE_SCENARIO && checker.run_id == operation.attempt.run_id,
        "final checker identity does not match the admin-rebalance attempt"
    );
    checker.require_success()?;
    ensure!(
        checker.versioning_expected
            && checker.expected_committed_versions > 0
            && checker.expected_committed_versions == checker.verified_committed_versions
            && !checker.operation_cohorts.is_empty(),
        "final checker did not prove the complete committed versioned workload"
    );
    checker::validate_checker_audit_against_history(checker, history)
        .context("admin-rebalance checker audit does not match history.jsonl")?;
    let audit = checker
        .audit
        .as_ref()
        .context("admin-rebalance checker lacks a history-bound audit")?;
    ensure!(
        audit.history_prefix_record_count + audit.history_suffix_record_count == history.len()
            && audit.list_object_versions_completed == Some(true)
            && audit.data_version_checks.len() == checker.expected_committed_versions
            && !audit.delete_marker_checks.is_empty()
            && audit
                .delete_marker_checks
                .iter()
                .all(|marker| marker.visible_in_list_object_versions),
        "final checker did not cover every committed data version and delete marker"
    );
    Ok(())
}

fn workload_records(receipt: &AdminRebalanceWorkloadReceipt) -> Result<Vec<&OperationRecord>> {
    ensure!(
        receipt.started_at_ms > 0
            && receipt.started_at_ms <= receipt.ended_at_ms
            && receipt.first_event_sequence > 0
            && receipt.first_event_sequence <= receipt.last_event_sequence,
        "bounded workload receipt has an invalid time or recorder sequence window"
    );
    let bucket = receipt
        .history
        .first()
        .map(|record| record.bucket.as_str())
        .context("bounded workload receipt has empty history")?;
    let scenario = receipt
        .history
        .first()
        .map(|record| record.scenario.as_str())
        .expect("non-empty checked above");
    let run_id = receipt
        .history
        .first()
        .and_then(|record| record.run_id.as_deref())
        .context("bounded workload receipt history lacks a run ID")?;
    validate_history_scope_and_order(&receipt.history, scenario, run_id, bucket)?;
    let mut records = Vec::new();
    for record in &receipt.history {
        let started = record
            .started_sequence
            .context("bounded workload history record lacks a start sequence")?;
        let ended = record
            .ended_sequence
            .context("bounded workload history record lacks an end sequence")?;
        let starts_in =
            (receipt.first_event_sequence..=receipt.last_event_sequence).contains(&started);
        let ends_in = (receipt.first_event_sequence..=receipt.last_event_sequence).contains(&ended);
        ensure!(
            starts_in == ends_in,
            "an S3 operation crosses the bounded workload recorder sequence boundary"
        );
        if starts_in {
            ensure!(
                record.started_at_ms >= receipt.started_at_ms
                    && record.ended_at_ms <= receipt.ended_at_ms,
                "an S3 operation falls outside the bounded workload time window"
            );
            records.push(record);
        }
    }
    ensure!(!records.is_empty(), "bounded rebalance workload is empty");
    let observed_first_sequence = records
        .iter()
        .filter_map(|record| record.started_sequence)
        .min();
    let observed_last_sequence = records
        .iter()
        .filter_map(|record| record.ended_sequence)
        .max();
    ensure!(
        observed_first_sequence == Some(receipt.first_event_sequence)
            && observed_last_sequence == Some(receipt.last_event_sequence),
        "bounded workload sequence window is not exactly covered by history"
    );
    Ok(records)
}

fn validate_workload_families(
    history: &[OperationRecord],
    workload: Vec<&OperationRecord>,
) -> Result<()> {
    let successful_versioned_mutation = |record: &OperationRecord| {
        record.outcome == OperationOutcome::Ok
            && record
                .version_id
                .as_deref()
                .is_some_and(|version| !version.is_empty() && version != "null")
    };
    let put_records = workload
        .iter()
        .filter(|record| record.kind == OperationKind::Put)
        .filter(|record| successful_versioned_mutation(record))
        .copied()
        .collect::<Vec<_>>();
    let earlier_data_version = |put: &OperationRecord| {
        let start = put.started_sequence.unwrap_or_default();
        history.iter().any(|record| {
            record.key == put.key
                && record.outcome == OperationOutcome::Ok
                && matches!(
                    record.kind,
                    OperationKind::Put | OperationKind::CompleteMultipartUpload
                )
                && record.ended_sequence.is_some_and(|ended| ended < start)
        })
    };
    ensure!(
        put_records
            .iter()
            .any(|record| !earlier_data_version(record)),
        "bounded rebalance workload has no successful ordinary PUT"
    );
    ensure!(
        put_records
            .iter()
            .any(|record| earlier_data_version(record)),
        "bounded rebalance workload has no successful overwrite"
    );
    ensure!(
        history.iter().any(|record| {
            record.kind == OperationKind::Put
                && record.outcome == OperationOutcome::Ok
                && record.size_bytes == Some(0)
                && record
                    .version_id
                    .as_deref()
                    .is_some_and(|version| !version.is_empty() && version != "null")
        }),
        "versioned rebalance workload has no committed zero-byte object"
    );
    ensure!(
        workload.iter().any(|record| {
            record.kind == OperationKind::Delete && successful_versioned_mutation(record)
        }),
        "bounded rebalance workload has no committed delete marker"
    );
    ensure!(
        workload.iter().any(|record| {
            record.kind == OperationKind::CompleteMultipartUpload
                && successful_versioned_mutation(record)
        }) && workload.iter().any(|record| {
            record.kind == OperationKind::AbortMultipartUpload
                && record.outcome == OperationOutcome::Ok
        }),
        "bounded rebalance workload lacks successful multipart completion or abort activity"
    );
    ensure!(
        history.iter().any(|record| {
            record.kind == OperationKind::PutBucketVersioning
                && record.outcome == OperationOutcome::Ok
        }),
        "admin-rebalance history does not prove bucket versioning was enabled"
    );
    ensure!(
        history.iter().all(|record| {
            !matches!(
                record.kind,
                OperationKind::Put | OperationKind::Delete | OperationKind::CompleteMultipartUpload
            ) || record.outcome != OperationOutcome::Ok
                || record
                    .version_id
                    .as_deref()
                    .is_some_and(|version| !version.is_empty() && version != "null")
        }),
        "a successful admin-rebalance mutation lacks an immutable version ID"
    );
    Ok(())
}

fn rebalance_window(requests: &[AdminRequestEvidence]) -> Result<(u64, u64)> {
    let start = requests
        .iter()
        .find(|request| {
            request.method == "POST" && request.path == "/rustfs/admin/v3/rebalance/start"
        })
        .context("admin-rebalance operation lacks its start receipt")?;
    let terminal = requests
        .iter()
        .rev()
        .find(|request| {
            request.method == "GET" && request.path == "/rustfs/admin/v3/rebalance/status"
        })
        .context("admin-rebalance operation lacks its terminal status receipt")?;
    ensure!(
        start.observed_at_ms < terminal.observed_at_ms,
        "admin-rebalance operation receipt interval is empty or inverted"
    );
    Ok((start.observed_at_ms, terminal.observed_at_ms))
}

fn overlapping_status_request_ids(
    requests: &[AdminRequestEvidence],
    progress: &[AdminOperationProgressSample],
    workload_started_at_ms: u64,
    workload_ended_at_ms: u64,
) -> Result<Vec<String>> {
    let progress_receipts = progress
        .iter()
        .map(|sample| (sample.status_request_id.as_str(), sample.observed_at_ms))
        .collect::<BTreeSet<_>>();
    let request_ids = requests
        .iter()
        .filter(|request| {
            request.method == "GET"
                && request.path == "/rustfs/admin/v3/rebalance/status"
                && strict_intervals_overlap(
                    request.started_at_ms,
                    request.observed_at_ms,
                    workload_started_at_ms,
                    workload_ended_at_ms,
                )
        })
        .map(|request| {
            request
                .request_id
                .clone()
                .filter(|request_id| {
                    progress_receipts.contains(&(request_id.as_str(), request.observed_at_ms))
                })
                .context("overlapping rebalance status request lacks its progress sample")
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(request_ids)
}

fn strict_intervals_overlap(
    first_start: u64,
    first_end: u64,
    second_start: u64,
    second_end: u64,
) -> bool {
    first_start < first_end
        && second_start < second_end
        && first_start < second_end
        && second_start < first_end
}

fn validate_overlap_progress_receipts(
    requests: &[AdminRequestEvidence],
    progress: &[AdminOperationProgressSample],
) -> Result<()> {
    let status_requests = requests
        .iter()
        .filter(|request| {
            request.method == "GET" && request.path == "/rustfs/admin/v3/rebalance/status"
        })
        .collect::<Vec<_>>();
    ensure!(
        status_requests.len() == progress.len()
            && status_requests
                .iter()
                .zip(progress)
                .all(|(request, sample)| {
                    (200..300).contains(&request.status)
                        && request.request_id.as_deref() == Some(sample.status_request_id.as_str())
                        && request.observed_at_ms == sample.observed_at_ms
                }),
        "rebalance overlap progress is not exactly bound to the ordered status receipts"
    );
    Ok(())
}

fn lock_transcript(
    transcript: &Arc<Mutex<AdminRebalanceTranscript>>,
) -> std::sync::MutexGuard<'_, AdminRebalanceTranscript> {
    transcript
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn transcript_state(transcript: &Arc<Mutex<AdminRebalanceTranscript>>) -> AdminRebalanceTranscript {
    lock_transcript(transcript).clone()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

struct LiveRebalanceState {
    context: Option<FaultRunContext>,
    s3: Option<S3WorkloadClient>,
    s3_port_forward: Option<PortForwardGuard>,
    s3_endpoint: Option<String>,
    admin: Option<Arc<RustfsAdminTopologyAdapter>>,
    proof: Option<AdminTopologyProof>,
    pools_before: Option<AdminPoolSnapshot>,
    start_ownership: RebalanceStartOwnership,
    terminal: Option<RebalanceStatus>,
    fixture: AdminFixtureEvidence,
    prefilled: Vec<ObjectSpec>,
    workload: Option<MixedWorkloadResult>,
    workload_receipt: Option<AdminRebalanceWorkloadReceipt>,
    health_baseline: Option<RecoveryHealthBaseline>,
    fixture_owned: bool,
    verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
enum RebalanceStartOwnership {
    #[default]
    NotStarted,
    Ambiguous {
        attempted_at_ms: u64,
    },
    Owned {
        operation_id: String,
    },
}

impl RebalanceStartOwnership {
    fn operation_id(&self) -> Option<&str> {
        match self {
            Self::Owned { operation_id } => Some(operation_id),
            Self::NotStarted | Self::Ambiguous { .. } => None,
        }
    }
}

pub(crate) struct LiveAdminRebalanceDriver {
    config: FaultTestConfig,
    collector: ArtifactCollector,
    scenario: FaultScenario,
    plan: AdminExecutionPlan,
    run_id: String,
    deadline: RunDeadline,
    transcript: Arc<Mutex<AdminRebalanceTranscript>>,
    state: AsyncMutex<LiveRebalanceState>,
}

impl LiveAdminRebalanceDriver {
    pub(crate) fn new(
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        scenario: &FaultScenario,
        plan: &AdminExecutionPlan,
        run_id: &str,
        deadline: RunDeadline,
    ) -> Result<Self> {
        ensure!(
            scenario.name == ADMIN_REBALANCE_SCENARIO
                && plan.scenario == scenario.name
                && plan.case_name == scenario.case_name,
            "live rebalance driver requires the canonical admin-rebalance plan"
        );
        let fixture_plan =
            AdminFixturePlan::for_scenario(&scenario.name, config.expected_rustfs_pod_count)?;
        Ok(Self {
            config: config.clone(),
            collector: collector.clone(),
            scenario: scenario.clone(),
            plan: plan.clone(),
            run_id: run_id.to_string(),
            deadline,
            transcript: Arc::new(Mutex::new(AdminRebalanceTranscript::default())),
            state: AsyncMutex::new(LiveRebalanceState {
                context: None,
                s3: None,
                s3_port_forward: None,
                s3_endpoint: None,
                admin: None,
                proof: None,
                pools_before: None,
                start_ownership: RebalanceStartOwnership::NotStarted,
                terminal: None,
                fixture: AdminFixtureEvidence {
                    schema_version: 1,
                    scenario: scenario.name.clone(),
                    run_id: run_id.to_string(),
                    tenant: config.cluster.tenant_name.clone(),
                    plan: fixture_plan,
                    observations: Vec::new(),
                },
                prefilled: Vec::new(),
                workload: None,
                workload_receipt: None,
                health_baseline: None,
                fixture_owned: false,
                verified: false,
            }),
        })
    }

    async fn prepare_inner(&self) -> Result<()> {
        let execution_plan = crate::fault::plan::ExecutionPlan::Admin(self.plan.clone());
        let context = initialize_fault_run(
            &self.config,
            &self.collector,
            &self.scenario,
            &execution_plan,
            &self.run_id,
        )?;
        let mut fixture = {
            let mut state = self.state.lock().await;
            state.context = Some(context.clone());
            state.fixture.clone()
        };
        self.write_fixture(&fixture)?;

        reset_tenant_resources(&self.config.cluster)
            .context("reset run-owned Tenant before admin rebalance")?;
        self.state.lock().await.fixture_owned = true;
        apply_admin_tenant_stage(&self.config.cluster, &fixture.plan, false, &self.run_id)
            .context("apply primary admin Tenant pool")?;
        wait_for_ready_tenant(&self.config.cluster)
            .await
            .context("wait for primary admin Tenant pool")?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            fixture.plan.servers_per_pool,
            self.config.rustfs_pod_stable_window,
        )
        .await
        .context("wait for stable primary admin Tenant pool")?;
        fixture.observations.push(capture_admin_fixture_observation(
            &self.config.cluster,
            AdminFixturePhase::PrimaryReady,
            None,
        )?);
        self.persist_fixture(&fixture).await?;

        let (endpoint, mut s3_port_forward) = s3_access(&self.config)?;
        ensure_s3_access(&mut s3_port_forward, &self.config.cluster, &endpoint).await?;
        let (access_key, secret_key) = resources::test_credentials();
        let s3 = S3WorkloadClient::new(
            &endpoint,
            &context.bucket,
            access_key,
            secret_key,
            self.config.request_timeout,
        )
        .await?;
        let history = &context.history;
        ensure!(
            s3.create_bucket(history).await? == OperationOutcome::Ok,
            "admin rebalance workload bucket creation failed"
        );
        ensure!(
            self.config.workload_versioning,
            "admin rebalance requires a versioned workload"
        );
        ensure!(
            s3.enable_bucket_versioning(history).await? == OperationOutcome::Ok,
            "admin rebalance workload bucket versioning failed"
        );
        let prefilled = prefill_objects(
            &s3,
            history,
            &self.run_id,
            &context.workload_plan,
            self.scenario.prefill_count(),
            self.config.prefill_concurrency,
            self.config.workload_directory_marker_percent,
        )
        .await
        .context("prefill primary admin Tenant pool")?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        fixture.observations.push(capture_admin_fixture_observation(
            &self.config.cluster,
            AdminFixturePhase::PrefillComplete,
            Some(prefilled.len()),
        )?);
        self.persist_fixture(&fixture).await?;

        apply_admin_tenant_stage(&self.config.cluster, &fixture.plan, true, &self.run_id)
            .context("apply admin Tenant expansion pool")?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        fixture.observations.push(capture_admin_fixture_observation(
            &self.config.cluster,
            AdminFixturePhase::ExpansionApplied,
            None,
        )?);
        self.persist_fixture(&fixture).await?;
        wait_for_ready_tenant(&self.config.cluster)
            .await
            .context("wait for expanded admin Tenant")?;
        let expanded_pod_count = fixture
            .plan
            .servers_per_pool
            .checked_mul(2)
            .context("expanded admin Tenant pod count overflowed")?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            expanded_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await
        .context("wait for stable two-pool admin Tenant")?;
        ensure_s3_access(&mut s3_port_forward, &self.config.cluster, &endpoint)
            .await
            .context("restore S3 access after admin Tenant expansion")?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        fixture.observations.push(capture_admin_fixture_observation(
            &self.config.cluster,
            AdminFixturePhase::TopologyStable,
            None,
        )?);
        fixture.validate_complete()?;
        self.persist_fixture(&fixture).await?;

        let layout =
            crate::rustfs::read_erasure_layout(&endpoint, "us-east-1", access_key, secret_key)
                .await
                .context("capture healthy two-pool RustFS layout")?;
        let health_baseline = RecoveryHealthBaseline::from_layout(&layout, now_ms())
            .context("two-pool RustFS layout is not healthy before rebalance")?;
        context.events.record(
            "recovery-health-baseline",
            RunEventStatus::Succeeded,
            "healthy two-pool RustFS baseline captured before rebalance",
            Some(serde_json::to_value(&health_baseline)?),
        )?;

        let (admin_endpoint, mut admin_forward) = tenant_port_forward(&self.config.cluster)?;
        wait_for_tenant_s3(
            &mut admin_forward,
            &admin_endpoint,
            self.config.cluster.timeout,
        )
        .await?;
        let adapter = Arc::new(
            RustfsAdminTopologyAdapter::connect(admin_forward, "us-east-1", access_key, secret_key)
                .await
                .context("connect fresh RustFS admin topology adapter")?,
        );
        let snapshot = adapter
            .capture_pool_snapshot(&self.run_id, self.scenario.case_name)
            .await
            .context("capture initial rebalance pool snapshot")?;
        let tenant = serde_json::from_str(&snapshot.tenant_get.response_body)
            .context("decode authenticated Tenant receipt for topology proof")?;
        let topology_context = AdminTopologyBuildContext::new(
            &self.run_id,
            self.scenario.case_name,
            &context.workload_plan,
            snapshot.runtime.clone(),
        )?;
        let proof = AdminTopologyProof::build(
            &self.plan.topology,
            &self.scenario.name,
            &tenant,
            snapshot.pools.clone(),
            &topology_context,
        )?;
        validate_admin_pre_start_snapshot(&proof, &snapshot, now_ms())?;
        proof.require_satisfied()?;
        self.collector.write_text(
            self.scenario.case_name,
            ADMIN_TOPOLOGY_PROOF_ARTIFACT,
            &serde_json::to_string_pretty(&proof)?,
        )?;
        let preflight = PreflightSummary::single_run(
            &self.config,
            &self.scenario.name,
            &self.run_id,
            vec![PreflightPhase::new(
                "admin-topology",
                vec![PreflightCheck::passed(
                    "owned_two_pool_topology",
                    "fresh Tenant, deployment, and pools/list receipts bind the owned two-pool topology",
                    ResponsibilityDomain::Harness,
                )],
            )],
        );
        self.collector.write_text(
            self.scenario.case_name,
            "preflight-summary.json",
            &serde_json::to_string_pretty(&preflight)?,
        )?;

        {
            let mut state = self.state.lock().await;
            state.s3 = Some(s3);
            state.s3_port_forward = s3_port_forward;
            state.s3_endpoint = Some(endpoint);
            state.admin = Some(Arc::clone(&adapter));
            state.proof = Some(proof.clone());
            state.pools_before = Some(snapshot);
            state.prefilled = prefilled;
            state.health_baseline = Some(health_baseline);
        }
        Ok(())
    }

    async fn start_inner(&self) -> Result<Instant> {
        let adapter = self
            .state
            .lock()
            .await
            .admin
            .clone()
            .context("rebalance adapter is not prepared")?;
        let started_at = Instant::now();
        let attempted_at_ms = now_ms();
        self.state.lock().await.start_ownership =
            RebalanceStartOwnership::Ambiguous { attempted_at_ms };
        let start = adapter
            .start_rebalance()
            .await
            .context("start RustFS rebalance through the bound adapter")?;
        ensure!(
            !start.value.id.trim().is_empty(),
            "RustFS rebalance start receipt has no operation ID"
        );
        {
            let mut state = self.state.lock().await;
            state.start_ownership = RebalanceStartOwnership::Owned {
                operation_id: start.value.id.clone(),
            };
        }
        {
            let mut transcript = lock_transcript(&self.transcript);
            transcript.operation_id = Some(start.value.id.clone());
            transcript.requests.push(start.request.clone());
        }
        self.write_transcript()?;
        Ok(started_at)
    }

    async fn persist_fixture(&self, fixture: &AdminFixtureEvidence) -> Result<()> {
        self.state.lock().await.fixture = fixture.clone();
        self.write_fixture(fixture)
    }

    async fn observe_inner(&self) -> Result<AdminWorkflowObservation> {
        let (adapter, proof, operation_id) = {
            let state = self.state.lock().await;
            (
                state
                    .admin
                    .clone()
                    .context("rebalance adapter is not ready")?,
                state
                    .proof
                    .clone()
                    .context("rebalance proof is not ready")?,
                state
                    .start_ownership
                    .operation_id()
                    .map(str::to_owned)
                    .context("rebalance operation is not owned")?,
            )
        };
        let call = adapter.rebalance_status().await?;
        let sample = rebalance_progress_sample(&proof, &operation_id, &call)?;
        let terminal = sample.completed || sample.failed || sample.canceled_or_stopped;
        {
            let mut transcript = lock_transcript(&self.transcript);
            transcript.requests.push(call.request.clone());
            transcript.progress.push(sample.clone());
        }
        self.write_transcript()?;
        if terminal {
            self.state.lock().await.terminal = Some(call.value);
            ensure!(
                sample.completed && !sample.failed && !sample.canceled_or_stopped,
                "RustFS rebalance reached an unsuccessful terminal state"
            );
            Ok(AdminWorkflowObservation::Completed)
        } else {
            Ok(AdminWorkflowObservation::Running)
        }
    }

    async fn run_workload_inner(&self) -> Result<()> {
        let (s3, history, plan, prefilled, events) = {
            let state = self.state.lock().await;
            let context = state
                .context
                .as_ref()
                .context("rebalance run is not initialized")?;
            (
                state
                    .s3
                    .clone()
                    .context("rebalance S3 client is not ready")?,
                context.history.clone(),
                context.workload_plan.clone(),
                state.prefilled.clone(),
                context.events.clone(),
            )
        };
        events.record(
            "mixed-workload",
            RunEventStatus::Started,
            "running bounded S3 workload during RustFS rebalance",
            Some(serde_json::json!({
                "object_count": self.scenario.mixed_workload_count(),
                "concurrency": plan.concurrency,
            })),
        )?;
        history.set_durability_cohort(DurabilityCohort::FaultActive);
        let first_event_sequence = history.next_event_sequence();
        let started_at_ms = now_ms();
        let workload = run_mixed_workload(&MixedWorkloadRequest {
            s3: &s3,
            history: &history,
            scenario: &self.scenario.name,
            run_id: &self.run_id,
            plan: &plan,
            prefilled: &prefilled,
            start_index: self.scenario.prefill_count(),
            count: self.scenario.mixed_workload_count(),
            ranged_get_percent: self.config.workload_ranged_get_percent,
            staged_multipart_uploads: None,
            progress_events: None,
            deadline: self.deadline,
        })
        .await?;
        let ended_at_ms = now_ms();
        let last_event_sequence = history
            .next_event_sequence()
            .checked_sub(1)
            .context("bounded rebalance workload recorded no completed operation")?;
        let receipt = AdminRebalanceWorkloadReceipt {
            started_at_ms,
            ended_at_ms,
            first_event_sequence,
            last_event_sequence,
            history: history.records(),
        };
        workload_records(&receipt)?;
        events.record(
            "mixed-workload",
            RunEventStatus::Succeeded,
            "bounded S3 workload completed during RustFS rebalance",
            Some(serde_json::json!({ "disruptions": workload.summary.disrupted() })),
        )?;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let mut state = self.state.lock().await;
        state.workload = Some(workload);
        state.workload_receipt = Some(receipt);
        Ok(())
    }

    async fn verify_inner(&self) -> Result<()> {
        let (
            adapter,
            proof,
            pools_before,
            start,
            terminal,
            workload_receipt,
            s3,
            endpoint,
            baseline,
            history,
            workload_plan,
            events,
            mut workload,
            attempt_started_at_ms,
        ) = {
            let mut state = self.state.lock().await;
            let context = state
                .context
                .as_ref()
                .context("rebalance run is not initialized")?;
            (
                state
                    .admin
                    .clone()
                    .context("rebalance adapter is not ready")?,
                state
                    .proof
                    .clone()
                    .context("rebalance proof is not ready")?,
                state
                    .pools_before
                    .clone()
                    .context("rebalance pre-start snapshot is missing")?,
                state
                    .start_ownership
                    .operation_id()
                    .map(|operation_id| RebalanceStart {
                        id: operation_id.to_string(),
                    })
                    .context("rebalance start receipt is missing")?,
                state
                    .terminal
                    .clone()
                    .context("rebalance terminal receipt is missing")?,
                state
                    .workload_receipt
                    .clone()
                    .context("rebalance workload receipt is missing")?,
                state
                    .s3
                    .clone()
                    .context("rebalance S3 client is not ready")?,
                state
                    .s3_endpoint
                    .clone()
                    .context("rebalance S3 endpoint is missing")?,
                state
                    .health_baseline
                    .clone()
                    .context("rebalance health baseline is missing")?,
                context.history.clone(),
                context.workload_plan.clone(),
                context.events.clone(),
                state
                    .workload
                    .take()
                    .context("rebalance workload result is missing")?,
                state
                    .fixture
                    .observations
                    .first()
                    .map(|observation| observation.observed_at_ms)
                    .context("rebalance fixture has no initial observation")?,
            )
        };
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        let pools_after = adapter
            .capture_pool_snapshot(&self.run_id, self.scenario.case_name)
            .await?;
        let transcript = transcript_state(&self.transcript);
        let attempt_window = AdminAttemptWindow {
            started_at_ms: attempt_started_at_ms,
            evaluated_at_ms: now_ms(),
        };
        let operation = AdminOperationEvidence::from_rebalance(
            &proof,
            pools_before,
            &start,
            terminal,
            transcript.requests,
            pools_after,
        )?;
        operation.require_success(attempt_window)?;
        validate_admin_operation_progress(&operation, &transcript.progress, attempt_window)?;
        let overlap = AdminRebalanceOverlapEvidence::from_history(
            &operation,
            &transcript.progress,
            &workload_receipt,
        )?;
        let execution = AdminRebalanceExecution {
            proof,
            operation,
            progress: transcript.progress,
            overlap,
            attempt_window,
            workload_history: workload_receipt.history,
        };
        execution.write_artifacts(&self.collector)?;

        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config
                .expected_rustfs_pod_count
                .checked_mul(2)
                .context("expanded admin Tenant pod count overflowed")?,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let pods = rustfs_pod_identities(&self.config.cluster)?;
        events.record(
            "recovery-health",
            RunEventStatus::Started,
            "validating RustFS health after rebalance",
            None,
        )?;
        let report = self
            .deadline
            .run(observe_recovery_health(
                &self.config.cluster,
                &endpoint,
                &baseline,
                &pods,
                &self.scenario.name,
                &self.run_id,
                &|report| {
                    self.collector
                        .write_text(
                            self.scenario.case_name,
                            RECOVERY_HEALTH_ARTIFACT,
                            &serde_json::to_string_pretty(report)?,
                        )
                        .map(|_| ())
                },
            ))
            .await?;
        self.collector.write_text(
            self.scenario.case_name,
            RECOVERY_HEALTH_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        report.require_success()?;
        events.record(
            "recovery-health",
            RunEventStatus::Succeeded,
            "RustFS health remained stable after rebalance",
            None,
        )?;

        self.run_post_recovery_probe(&s3, &workload_plan, &events)
            .await?;
        workload.seal_recommit_candidates(&s3, &history)?;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let prechecker =
            checker::check_s3_history(&s3, &history, true, workload_plan.concurrency, true).await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-pre-recommit-report.json",
            &serde_json::to_string_pretty(&prechecker)?,
        )?;
        prechecker.require_success()?;

        let recommit = recommit_unconfirmed_objects(
            &s3,
            &history,
            &workload.unconfirmed_puts,
            workload_plan.concurrency,
            self.deadline,
        )
        .await;
        self.collector.write_text(
            self.scenario.case_name,
            "recommit-report.json",
            &serde_json::to_string_pretty(&recommit)?,
        )?;
        ensure!(!recommit.has_failures(), "{}", recommit.failure_message());
        workload.summary.recommitted_after_recovery = recommit.committed;
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;

        events.record(
            "checker-final",
            RunEventStatus::Started,
            "checking the final object model after rebalance",
            None,
        )?;
        let checker =
            checker::check_s3_history(&s3, &history, true, workload_plan.concurrency, true).await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&checker)?,
        )?;
        checker.require_success()?;
        validate_admin_rebalance_evidence(
            &execution.operation,
            &execution.progress,
            &execution.overlap,
            &history.records(),
            &checker,
        )?;
        events.record(
            "checker-final",
            RunEventStatus::Succeeded,
            "final rebalance object model check passed",
            None,
        )?;
        self.state.lock().await.verified = true;
        Ok(())
    }

    async fn run_post_recovery_probe(
        &self,
        s3: &S3WorkloadClient,
        workload_plan: &crate::fault::workload::WorkloadPlan,
        events: &crate::fault::events::RunEventRecorder,
    ) -> Result<()> {
        let history = crate::fault::history::Recorder::create(
            self.collector
                .case_dir(self.scenario.case_name)
                .join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT),
            &self.scenario.name,
            &self.run_id,
        )?;
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        let object_count = post_recovery_object_count(workload_plan.object_count);
        events.record(
            "post-recovery-write",
            RunEventStatus::Started,
            "probing fresh writes after rebalance",
            Some(serde_json::json!({ "objects": object_count })),
        )?;
        let report = run_post_recovery_write_probe(&PostRecoveryWriteRequest {
            s3,
            history: &history,
            run_id: &self.run_id,
            scope: crate::fault::workload::WriteProbeScope::PostRecovery,
            seed: workload_plan.seed ^ POST_RECOVERY_SEED_SALT,
            object_count,
            concurrency: workload_plan.concurrency,
            deadline: self.deadline,
        })
        .await?;
        self.collector.write_text(
            self.scenario.case_name,
            POST_RECOVERY_WRITE_REPORT_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        report.require_success()?;
        events.record(
            "post-recovery-write",
            RunEventStatus::Succeeded,
            "fresh writes succeeded after rebalance",
            None,
        )?;
        Ok(())
    }

    fn write_fixture(&self, fixture: &AdminFixtureEvidence) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            ADMIN_FIXTURE_ARTIFACT,
            &serde_json::to_string_pretty(fixture)?,
        )?;
        Ok(())
    }

    fn write_transcript(&self) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
            &serde_json::to_string_pretty(&transcript_state(&self.transcript))?,
        )?;
        Ok(())
    }

    async fn preserve_evidence<T>(&self, result: Result<T>) -> Result<T> {
        let fixture = self.state.lock().await.fixture.clone();
        let persisted = self
            .write_fixture(&fixture)
            .and_then(|_| self.write_transcript());
        combine_primary_and_secondary(result, persisted, "persist rebalance transcript")
    }

    async fn verify_completed_overlap_inner(&self) -> Result<()> {
        let (proof, operation_id, workload) = {
            let state = self.state.lock().await;
            ensure!(
                state.terminal.is_some(),
                "fast-completed rebalance lacks its terminal status receipt"
            );
            let operation_id = state
                .start_ownership
                .operation_id()
                .context("fast-completed rebalance is not owned by this attempt")?;
            (
                state
                    .proof
                    .clone()
                    .context("rebalance topology proof is not ready")?,
                operation_id.to_string(),
                state
                    .workload_receipt
                    .clone()
                    .context("fast-completed rebalance lacks its completed workload receipt")?,
            )
        };
        proof.require_satisfied()?;
        let transcript = transcript_state(&self.transcript);
        ensure!(
            transcript.operation_id.as_deref() == Some(operation_id.as_str())
                && transcript.requests.iter().all(|request| {
                    request.target == proof.runtime.target && (200..300).contains(&request.status)
                }),
            "fast-completed rebalance transcript is not bound to the proven runtime target"
        );
        AdminRebalanceOverlapEvidence::from_receipts(
            &proof.attempt,
            &operation_id,
            &transcript.requests,
            &transcript.progress,
            &workload,
        )?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl AdminCaseDriver for LiveAdminRebalanceDriver {
    async fn prepare(&self) -> Result<()> {
        let result = self.prepare_inner().await;
        self.preserve_evidence(result).await
    }

    async fn start(&self) -> Result<Instant> {
        let result = self.start_inner().await;
        self.preserve_evidence(result).await
    }

    async fn observe(&self) -> Result<AdminWorkflowObservation> {
        let result = self.observe_inner().await;
        match result {
            Ok(observation) => Ok(observation),
            Err(error) => match self.preserve_evidence(Err(error)).await {
                Err(error) => Err(error),
                Ok(()) => unreachable!("preserving a failed observation cannot make it succeed"),
            },
        }
    }

    async fn run_workload(&self) -> Result<()> {
        let result = self.run_workload_inner().await;
        self.preserve_evidence(result).await
    }

    async fn verify_completed_overlap(&self) -> Result<()> {
        let result = self.verify_completed_overlap_inner().await;
        self.preserve_evidence(result).await
    }

    async fn verify(&self) -> Result<()> {
        let result = self.verify_inner().await;
        self.preserve_evidence(result).await
    }

    async fn cancel(&self) -> Result<AdminCancelOutcome> {
        let (adapter, proof, ownership) = {
            let state = self.state.lock().await;
            if state.start_ownership == RebalanceStartOwnership::NotStarted {
                return Ok(AdminCancelOutcome::NoOwnedOperation);
            }
            (
                state
                    .admin
                    .clone()
                    .context("rebalance adapter is not ready")?,
                state
                    .proof
                    .clone()
                    .context("rebalance proof is not ready")?,
                state.start_ownership.clone(),
            )
        };
        let operation_id = match ownership {
            RebalanceStartOwnership::NotStarted => unreachable!("handled above"),
            RebalanceStartOwnership::Owned { operation_id } => operation_id,
            RebalanceStartOwnership::Ambiguous { attempted_at_ms } => {
                let status = timeout(self.config.cluster.timeout, adapter.rebalance_status())
                    .await
                    .context("timed out reconciling an ambiguous rebalance start")??;
                ensure!(
                    status.request.started_at_ms >= attempted_at_ms
                        && !status.value.id.trim().is_empty(),
                    "ambiguous rebalance status predates the start attempt or lacks an operation ID"
                );
                let operation_id = status.value.id.clone();
                let sample = rebalance_progress_sample(&proof, &operation_id, &status)
                    .context("ambiguous rebalance status is not bound to the proven topology")?;
                {
                    let mut transcript = lock_transcript(&self.transcript);
                    transcript.requests.push(status.request);
                    transcript.progress.push(sample.clone());
                }
                if sample.completed || sample.failed || sample.canceled_or_stopped {
                    self.write_transcript()?;
                    return Ok(AdminCancelOutcome::NoOwnedOperation);
                }
                self.write_transcript()?;
                bail!(
                    "rebalance start remains ambiguous; refusing to stop an operation without an attempt-bound server identity"
                )
            }
        };
        let result = stop_owned_rebalance(
            adapter.as_ref(),
            &proof,
            &operation_id,
            AdminRebalanceLimits {
                poll_interval: Duration::from_secs(5),
                operation_timeout: self.plan.operation_timeout,
                stop_timeout: self.config.cluster.timeout,
            },
            &self.transcript,
        )
        .await;
        combine_primary_and_secondary(
            result,
            self.write_transcript(),
            "persist cancel transcript",
        )?;
        Ok(AdminCancelOutcome::CanceledOwnedOperation)
    }

    async fn cleanup(&self) -> Result<()> {
        let (fixture, events, verified, fixture_owned, admin, s3_port_forward) = {
            let mut state = self.state.lock().await;
            (
                state.fixture.clone(),
                state.context.as_ref().map(|context| context.events.clone()),
                state.verified,
                state.fixture_owned,
                state.admin.take(),
                state.s3_port_forward.take(),
            )
        };
        drop((admin, s3_port_forward));
        let transcript = transcript_state(&self.transcript);
        let persistence = persist_fixture_evidence(
            &self.collector,
            self.scenario.case_name,
            &fixture,
            &transcript,
        );
        let event = if let Some(events) = events {
            events.record(
                "run",
                if verified && persistence.is_ok() {
                    RunEventStatus::Succeeded
                } else {
                    RunEventStatus::Failed
                },
                if verified && persistence.is_ok() && fixture_owned {
                    "admin rebalance run completed; run-owned fixture preserved for explicit fault-cleanup"
                } else if verified && persistence.is_ok() {
                    "admin rebalance run completed before owning a Tenant fixture"
                } else if persistence.is_err() {
                    "admin rebalance evidence persistence failed; any run-owned fixture remains for explicit fault-cleanup"
                } else if fixture_owned {
                    "admin rebalance run ended before successful verification; run-owned fixture preserved for explicit fault-cleanup"
                } else {
                    "admin rebalance run ended before successful verification or Tenant fixture ownership"
                },
                None,
            )
        } else {
            Ok(())
        };
        combine_primary_and_secondary(persistence, event, "record evidence preservation outcome")
    }
}

fn persist_fixture_evidence(
    collector: &ArtifactCollector,
    case_name: &str,
    fixture: &AdminFixtureEvidence,
    transcript: &AdminRebalanceTranscript,
) -> Result<()> {
    collector.write_text(
        case_name,
        ADMIN_FIXTURE_ARTIFACT,
        &serde_json::to_string_pretty(fixture)?,
    )?;
    collector.write_text(
        case_name,
        ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT,
        &serde_json::to_string_pretty(transcript)?,
    )?;
    Ok(())
}

fn combine_primary_and_secondary<T>(
    primary: Result<T>,
    secondary: Result<()>,
    secondary_label: &str,
) -> Result<T> {
    match (primary, secondary) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(_), Err(secondary)) => Err(secondary.context(secondary_label.to_string())),
        (Err(primary), Err(secondary)) => {
            Err(primary.context(format!("{secondary_label} also failed: {secondary:#}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn cleanup_persists_raw_evidence_without_resetting_the_owned_fixture() {
        let dir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(dir.path());
        let fixture = AdminFixtureEvidence {
            schema_version: 1,
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            run_id: "run-cleanup".to_string(),
            tenant: "owned-tenant".to_string(),
            plan: AdminFixturePlan::for_scenario(ADMIN_REBALANCE_SCENARIO, 4)
                .expect("fixture plan"),
            observations: Vec::new(),
        };
        persist_fixture_evidence(
            &collector,
            "admin-rebalance",
            &fixture,
            &AdminRebalanceTranscript::default(),
        )
        .expect("persist cleanup evidence");

        let case_dir = collector.case_dir("admin-rebalance");
        assert!(case_dir.join(ADMIN_FIXTURE_ARTIFACT).is_file());
        assert!(case_dir.join(ADMIN_REBALANCE_TRANSCRIPT_ARTIFACT).is_file());
    }

    fn record(
        id: &str,
        kind: OperationKind,
        key: Option<&str>,
        size: Option<usize>,
        version: Option<&str>,
        sequence: u64,
    ) -> OperationRecord {
        OperationRecord {
            id: id.to_string(),
            scenario: ADMIN_REBALANCE_SCENARIO.to_string(),
            run_id: Some("run-rebalance".to_string()),
            kind,
            bucket: "bucket".to_string(),
            key: key.map(str::to_string),
            value_sha256: size.map(|_| "hash".to_string()),
            size_bytes: size,
            version_id: version.map(str::to_string),
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: Some(sequence),
            ended_sequence: Some(sequence + 1),
            started_at_ms: 100 + sequence,
            ended_at_ms: 101 + sequence,
            outcome: OperationOutcome::Ok,
            http_status: Some(200),
            error: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn versioned_history() -> Vec<OperationRecord> {
        vec![
            record(
                "versioning",
                OperationKind::PutBucketVersioning,
                None,
                None,
                None,
                1,
            ),
            record(
                "seed",
                OperationKind::Put,
                Some("hot"),
                Some(4),
                Some("v1"),
                3,
            ),
            record(
                "zero",
                OperationKind::Put,
                Some("zero/"),
                Some(0),
                Some("v2"),
                5,
            ),
            record(
                "put",
                OperationKind::Put,
                Some("new"),
                Some(4),
                Some("v3"),
                7,
            ),
            record(
                "overwrite",
                OperationKind::Put,
                Some("hot"),
                Some(4),
                Some("v4"),
                9,
            ),
            record(
                "delete",
                OperationKind::Delete,
                Some("hot"),
                None,
                Some("v5"),
                11,
            ),
            record(
                "multipart",
                OperationKind::CompleteMultipartUpload,
                Some("large"),
                Some(8),
                Some("v6"),
                13,
            ),
            record(
                "abort",
                OperationKind::AbortMultipartUpload,
                Some("aborted"),
                None,
                None,
                15,
            ),
        ]
    }

    fn admin_request(
        method: &str,
        path: &str,
        request_id: &str,
        started_at_ms: u64,
        observed_at_ms: u64,
    ) -> AdminRequestEvidence {
        serde_json::from_value(json!({
            "target": {
                "endpoint": {
                    "kubernetesContext": "kind-admin-test",
                    "clusterUid": "cluster-uid",
                    "portForwardCommand": "kubectl port-forward",
                    "portForwardStartedAtMs": 1,
                    "clusterStartedAtMs": 2,
                    "clusterObservedAtMs": 3,
                    "clusterResponseSha256": "cluster-sha",
                    "clusterResponseBody": "{}",
                    "namespace": "fault-ns",
                    "serviceName": "fault-tenant-io",
                    "serviceUid": "service-uid",
                    "serviceResourceVersion": "service-rv",
                    "serviceStartedAtMs": 4,
                    "serviceObservedAtMs": 5,
                    "serviceResponseSha256": "service-sha",
                    "serviceResponseBody": "{}",
                    "tenantName": "fault-tenant",
                    "tenantUid": "tenant-uid",
                    "tenantResourceVersion": "tenant-rv",
                    "tenantStartedAtMs": 6,
                    "tenantObservedAtMs": 7,
                    "tenantResponseSha256": "tenant-sha",
                    "tenantResponseBody": "{}",
                    "localEndpoint": "http://127.0.0.1:19000",
                    "remotePort": 9000
                },
                "deploymentId": "deployment-1"
            },
            "method": method,
            "path": path,
            "query": {},
            "status": 200,
            "startedAtMs": started_at_ms,
            "observedAtMs": observed_at_ms,
            "requestId": request_id
        }))
        .expect("admin request")
    }

    #[test]
    fn fast_completion_requires_concrete_s3_and_status_receipt_overlap() {
        let attempt = AdminAttemptIdentity {
            run_id: "run-rebalance".to_string(),
            case_name: ADMIN_REBALANCE_SCENARIO.to_string(),
            tenant_uid: "tenant-uid".to_string(),
        };
        let requests = vec![
            admin_request(
                "POST",
                "/rustfs/admin/v3/rebalance/start",
                "start",
                100,
                106,
            ),
            admin_request(
                "GET",
                "/rustfs/admin/v3/rebalance/status",
                "terminal-status",
                107,
                109,
            ),
        ];
        let progress = vec![AdminOperationProgressSample {
            attempt: attempt.clone(),
            operation_id: "rebalance-1".to_string(),
            status_request_id: "terminal-status".to_string(),
            observed_at_ms: 109,
            state: "completed".to_string(),
            completed: true,
            failed: false,
            canceled_or_stopped: false,
            objects_moved: Some(1),
            versions_moved: Some(1),
            bytes_moved: Some(4),
        }];
        let workload = AdminRebalanceWorkloadReceipt {
            started_at_ms: 107,
            ended_at_ms: 117,
            first_event_sequence: 7,
            last_event_sequence: 16,
            history: versioned_history(),
        };

        let evidence = AdminRebalanceOverlapEvidence::from_receipts(
            &attempt,
            "rebalance-1",
            &requests,
            &progress,
            &workload,
        )
        .expect("real fast-completion overlap");
        assert_eq!(evidence.overlapping_operation_ids, ["put"]);
        assert_eq!(evidence.overlapping_status_request_ids, ["terminal-status"]);

        let mut mismatched_progress = progress.clone();
        mismatched_progress[0].observed_at_ms = 110;
        let error = AdminRebalanceOverlapEvidence::from_receipts(
            &attempt,
            "rebalance-1",
            &requests,
            &mismatched_progress,
            &workload,
        )
        .expect_err("progress must be bound to its exact status receipt");
        assert!(error.to_string().contains("ordered status receipts"));

        let mut status_after_workload = requests;
        status_after_workload[1].started_at_ms = 117;
        status_after_workload[1].observed_at_ms = 119;
        let mut progress_after_workload = progress;
        progress_after_workload[0].observed_at_ms = 119;
        let error = AdminRebalanceOverlapEvidence::from_receipts(
            &attempt,
            "rebalance-1",
            &status_after_workload,
            &progress_after_workload,
            &workload,
        )
        .expect_err("status outside workload must not prove overlap");
        assert!(
            error.to_string().contains("status request receipt"),
            "{error:#}"
        );

        let mut zero_length_status = status_after_workload;
        zero_length_status[1].started_at_ms = 108;
        zero_length_status[1].observed_at_ms = 108;
        let mut zero_length_progress = progress_after_workload;
        zero_length_progress[0].observed_at_ms = 108;
        let error = AdminRebalanceOverlapEvidence::from_receipts(
            &attempt,
            "rebalance-1",
            &zero_length_status,
            &zero_length_progress,
            &workload,
        )
        .expect_err("zero-length status interval must not prove overlap");
        assert!(
            error.to_string().contains("status request receipt"),
            "{error:#}"
        );
    }

    #[test]
    fn strict_overlap_rejects_equal_boundaries_and_zero_length_intervals() {
        assert!(strict_intervals_overlap(100, 110, 105, 106));
        assert!(!strict_intervals_overlap(100, 109, 109, 110));
        assert!(!strict_intervals_overlap(100, 100, 99, 101));
        assert!(!strict_intervals_overlap(99, 101, 100, 100));
    }

    #[test]
    fn bounded_workload_requires_every_versioned_mutation_family() {
        let history = versioned_history();
        let receipt = AdminRebalanceWorkloadReceipt {
            started_at_ms: 107,
            ended_at_ms: 117,
            first_event_sequence: 7,
            last_event_sequence: 16,
            history: history.clone(),
        };
        let records = workload_records(&receipt).expect("bounded workload records");
        validate_workload_families(&history, records).expect("complete versioned workload");

        for omitted in ["put", "overwrite", "delete", "multipart", "abort"] {
            let mut incomplete = history.clone();
            incomplete.retain(|record| record.id != omitted);
            for (index, record) in incomplete.iter_mut().enumerate() {
                record.started_sequence = Some(index as u64 * 2 + 1);
                record.ended_sequence = Some(index as u64 * 2 + 2);
            }
            let selected = incomplete
                .iter()
                .filter(|record| !matches!(record.id.as_str(), "versioning" | "seed" | "zero"))
                .collect();
            assert!(
                validate_workload_families(&incomplete, selected).is_err(),
                "missing {omitted} must fail closed"
            );
        }
    }

    #[test]
    fn bounded_workload_rejects_missing_zero_byte_or_version_id() {
        let mut no_zero = versioned_history();
        no_zero[2].size_bytes = Some(1);
        let selected = no_zero.iter().skip(3).collect();
        assert!(validate_workload_families(&no_zero, selected).is_err());

        let mut missing_version = versioned_history();
        missing_version[4].version_id = None;
        let selected = missing_version.iter().skip(3).collect();
        assert!(validate_workload_families(&missing_version, selected).is_err());
    }

    #[test]
    fn workload_receipt_requires_exact_recorder_boundaries() {
        let history = versioned_history();
        let valid = AdminRebalanceWorkloadReceipt {
            started_at_ms: 107,
            ended_at_ms: 117,
            first_event_sequence: 7,
            last_event_sequence: 16,
            history: history.clone(),
        };
        assert_eq!(workload_records(&valid).expect("valid receipt").len(), 5);

        let mut crossing = valid;
        crossing.first_event_sequence = 8;
        assert!(workload_records(&crossing).is_err());
    }

    #[test]
    fn limits_reject_unbounded_or_slower_polling() {
        assert!(
            AdminRebalanceLimits {
                poll_interval: Duration::ZERO,
                operation_timeout: Duration::from_secs(1),
                stop_timeout: Duration::from_secs(1),
            }
            .validate()
            .is_err()
        );
        assert!(
            AdminRebalanceLimits {
                poll_interval: Duration::from_secs(2),
                operation_timeout: Duration::from_secs(1),
                stop_timeout: Duration::from_secs(3),
            }
            .validate()
            .is_err()
        );
    }
}
