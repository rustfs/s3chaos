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

use crate::fault::{
    events::RunEventStatus, fault_lifecycle::AppliedFault, history::DurabilityCohort,
    pods::rustfs_pod_identities, reporting::FaultEvidence,
};
use crate::fault::{reporting::PodIdentity, workload::StagedMultipartUpload};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::time::Instant;

use super::access::{ensure_s3_access, wait_for_ready_tenant, wait_for_stable_rustfs_pods};
use super::{
    ActiveFault, FaultRemoval, FaultRun, FaultWorkload, PreparedWorkload, ProvenTarget, now_ms,
};
use crate::fault::workload::execution::{cleanup_staged_multipart_uploads, crash_window_evidence};

impl FaultRun<'_> {
    pub(super) fn prepare_crash_boundary(
        &self,
        fault: &mut AppliedFault,
        fault_active_at_ms: u64,
    ) -> Result<()> {
        let collector = self.collector;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        if fault.requires_recovery_boundary() {
            events.record(
                "crash-recovery-boundary",
                RunEventStatus::Started,
                "proving an acknowledged mutation and forcing the backend-owned crash boundary",
                None,
            )?;
            let crash_boundary_started_at_ms = now_ms();
            let crash_window_evidence = match crash_window_evidence(
                &history.records(),
                &scenario.name,
                run_id,
                fault_active_at_ms,
                crash_boundary_started_at_ms,
            ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    self.record_failure(
                        "crash-recovery-boundary",
                        "no_signal",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
            collector.write_text(
                scenario.case_name,
                "crash-window-evidence.json",
                &serde_json::to_string_pretty(&crash_window_evidence)?,
            )?;
            if let Err(error) =
                fault.prepare_recovery_boundary(cluster.timeout, crash_boundary_started_at_ms)
            {
                self.record_failure(
                    "crash-recovery-boundary",
                    "environment_or_fault_backend",
                    &error,
                    Some(serde_json::json!({
                        "trigger_operation_id": crash_window_evidence.trigger_operation_id,
                    })),
                    Some((fault, "crash-boundary-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "crash-recovery-boundary",
                RunEventStatus::Succeeded,
                "target Pod was force-deleted and the filesystem was unmounted while drop_writes remained active",
                Some(serde_json::json!({
                    "trigger_operation_id": crash_window_evidence.trigger_operation_id,
                    "ack_to_crash_boundary_ms": crash_window_evidence.ack_to_crash_boundary_ms,
                })),
            )?;
        }
        Ok(())
    }
    pub(super) fn remove_fault(&self, fault: &mut AppliedFault) -> Result<FaultRemoval> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        events.record(
            "fault-delete",
            RunEventStatus::Started,
            "removing applied faults",
            None,
        )?;
        let fault_delete_started_at_ms = history.mark_fault_ended_now();
        // Host-storage cleanup observations are emitted by delete.
        let recovery_started_at_ms = now_ms();
        let fault_delete_started_at = Instant::now();
        if let Err(error) = fault.delete(cluster.timeout) {
            let finalizer_recovery = match fault.recover_delete_timeout(
                &crate::fault::fault_lifecycle::FaultDeleteTimeoutRecoveryRequest {
                    config,
                    collector,
                    case_name: scenario.case_name,
                    run_id,
                    original_error: &error,
                    delete_started_at: fault_delete_started_at,
                },
            ) {
                Ok(recovery) => recovery,
                Err(recovery_error) => {
                    let _ = collector.write_text(
                        scenario.case_name,
                        "iochaos-finalizer-recovery-error.txt",
                        &format!(
                            "failed to evaluate or apply IOChaos finalizer recovery:\n{recovery_error}"
                        ),
                    );
                    None
                }
            };
            if let Some(recovery) = finalizer_recovery {
                events.record(
                    "fault-delete",
                    RunEventStatus::Succeeded,
                    "patched stuck IOChaos finalizer after recovery evidence",
                    Some(serde_json::json!({
                        "warning_artifact": recovery.warning_artifact,
                        "iochaos": recovery.resource_name,
                        "target_nodes": recovery.target_nodes,
                    })),
                )?;
            } else {
                self.record_failure(
                    "fault-delete",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((fault, "delete-failed")),
                )?;
                return Err(error);
            }
        } else {
            events.record(
                "fault-delete",
                RunEventStatus::Succeeded,
                "applied faults were removed",
                None,
            )?;
        }
        Ok(FaultRemoval {
            fault_delete_started_at_ms,
            recovery_started_at_ms,
        })
    }
    pub(super) async fn recover_access(
        &self,
        prepared: &mut PreparedWorkload,
        staged_multipart_uploads: &mut BTreeMap<usize, StagedMultipartUpload>,
    ) -> Result<(Vec<PodIdentity>, u64)> {
        let config = self.config;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        let cleanup_concurrency = self.context.workload_plan.concurrency;
        let PreparedWorkload {
            s3,
            endpoint,
            port_forward,
            prefilled: _,
        } = prepared;
        events.record(
            "tenant-recovery",
            RunEventStatus::Started,
            "waiting for Tenant readiness after fault removal",
            None,
        )?;
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        if let Err(error) = self.deadline.run(wait_for_ready_tenant(cluster)).await {
            self.record_failure(
                "tenant-recovery",
                "product_or_environment",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        events.record(
            "tenant-recovery",
            RunEventStatus::Succeeded,
            "Tenant is Ready after fault removal",
            None,
        )?;
        events.record(
            "pod-stability-after-recovery",
            RunEventStatus::Started,
            "waiting for RustFS pods to remain stable after recovery",
            Some(serde_json::json!({
                "expected_pod_count": config.expected_rustfs_pod_count,
                "stable_window_seconds": config.rustfs_pod_stable_window.as_secs(),
            })),
        )?;
        if let Err(error) = self
            .deadline
            .run(wait_for_stable_rustfs_pods(
                cluster,
                config.expected_rustfs_pod_count,
                config.rustfs_pod_stable_window,
            ))
            .await
        {
            self.record_failure(
                "pod-stability-after-recovery",
                "product_or_environment",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        events.record(
            "pod-stability-after-recovery",
            RunEventStatus::Succeeded,
            "RustFS pods were stable after recovery",
            None,
        )?;
        let pods_after = rustfs_pod_identities(cluster)?;
        events.record(
            "s3-access-after-recovery",
            RunEventStatus::Started,
            "checking S3 access after recovery",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
        if let Err(error) = self
            .deadline
            .run(ensure_s3_access(port_forward, cluster, endpoint))
            .await
        {
            self.record_failure(
                "s3-access-after-recovery",
                "product_or_environment",
                &error,
                Some(serde_json::json!({ "endpoint": endpoint })),
                None,
            )?;
            return Err(error);
        }
        events.record(
            "s3-access-after-recovery",
            RunEventStatus::Succeeded,
            "S3 endpoint is reachable after recovery",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
        cleanup_staged_multipart_uploads(
            s3,
            history,
            std::mem::take(staged_multipart_uploads),
            cleanup_concurrency,
        )
        .await
        .context("cleaning staged uploads before recovery verification")?;
        let recovery_ended_at_ms = now_ms();
        Ok((pods_after, recovery_ended_at_ms))
    }
    pub(super) fn write_recovery_evidence(
        &self,
        target: &ProvenTarget,
        active: &ActiveFault,
        workload: &FaultWorkload,
        removal: &FaultRemoval,
        recovered: &(Vec<PodIdentity>, u64),
    ) -> Result<FaultEvidence> {
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let ProvenTarget {
            pods_before,
            target_proof: _,
            topology_observed_at_ms: _,
            host_storage_proof: _,
            execution_injection: _,
        } = target;
        let ActiveFault {
            fault,
            fault_apply_started_at_ms,
            fault_active_at_ms,
            active_snapshots,
            pods_at_fault_activation,
            active_partition_targets: _,
            active_fixed_volume_targets,
            active_fixed_volume_containers,
        } = active;
        let FaultWorkload {
            workload,
            workload_started_at_ms,
            workload_ended_at_ms,
            require_client_disruption,
            workload_snapshots,
            pods_at_workload_snapshot,
            workload_fixed_volume_targets,
            workload_fixed_volume_containers,
            quorum_health_before_workload,
            quorum_health_after_workload,
        } = workload;
        let FaultRemoval {
            fault_delete_started_at_ms,
            recovery_started_at_ms,
        } = removal;
        let (pods_after, recovery_ended_at_ms) = recovered;
        let evidence = FaultEvidence {
            scenario: scenario.name.clone(),
            run_id: run_id.clone(),
            backend: plan.backend_summary(),
            target: plan.target_summary(),
            injected: true,
            active_during_workload: true,
            recovered: true,
            require_client_disruption: *require_client_disruption,
            client_disruptions: workload.summary.disrupted(),
            workload_plan: workload_plan.clone(),
            pods_before: pods_before.clone(),
            pods_at_fault_activation: pods_at_fault_activation.clone(),
            pods_at_workload_snapshot: pods_at_workload_snapshot.clone(),
            fixed_volume_targets_at_fault_activation: active_fixed_volume_targets
                .iter()
                .cloned()
                .collect(),
            fixed_volume_targets_at_workload_snapshot: workload_fixed_volume_targets
                .iter()
                .cloned()
                .collect(),
            fixed_volume_containers_at_fault_activation: active_fixed_volume_containers.clone(),
            fixed_volume_containers_at_workload_snapshot: workload_fixed_volume_containers.clone(),
            pods_after: pods_after.clone(),
            active_snapshots: active_snapshots.clone(),
            workload_snapshots: workload_snapshots.clone(),
            dm_recovery_snapshot: fault.recovery_dm_snapshot(),
            fault_apply_started_at_ms: Some(*fault_apply_started_at_ms),
            fault_active_at_ms: Some(*fault_active_at_ms),
            workload_started_at_ms: Some(*workload_started_at_ms),
            workload_ended_at_ms: Some(*workload_ended_at_ms),
            fault_delete_started_at_ms: Some(*fault_delete_started_at_ms),
            recovery_started_at_ms: Some(*recovery_started_at_ms),
            recovery_ended_at_ms: Some(*recovery_ended_at_ms),
            quorum_health_before_workload: quorum_health_before_workload.clone(),
            quorum_health_after_workload: quorum_health_after_workload.clone(),
        };
        collector.write_text(
            scenario.case_name,
            "fault-evidence.json",
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        Ok(evidence)
    }
}
