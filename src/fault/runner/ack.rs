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
use serde::Serialize;
use std::collections::BTreeMap;

use crate::fault::backends::runtime::{PreparedHostFault, prepare_host_fault};
use crate::fault::{
    acknowledged_mutation::{
        AckToFaultEvidence, AcknowledgedMutationKind, AcknowledgedMutationTrigger,
        QuietMutationWorkload,
    },
    events::RunEventStatus,
    history::OperationOutcome,
    quorum::require_fresh_runtime_observation,
    reporting::FaultEvidence,
    scenarios::acknowledged_mutation_kind,
    workload::{ObjectSpec, S3WorkloadClient, StagedMultipartCleanupGuard, StagedMultipartUpload},
};

use super::{ActiveFault, FaultRemoval, FaultRun, PreparedWorkload, ProvenTarget, now_ms};

const TRIGGER_OBJECT_OFFSET: usize = 1024;
const TRIGGER_PAYLOAD_BYTES: usize = 4 * 1024;
const MULTIPART_TRIGGER_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct AckTriggeredCrashEvidence {
    scenario: String,
    run_id: String,
    #[serde(flatten)]
    trigger: AckToFaultEvidence,
    crash_boundary_started_at_ms: u64,
    crash_boundary_next_sequence: u64,
    ack_to_crash_boundary_ms: u64,
}

struct PreparedQuietMutation {
    workload: QuietMutationWorkload,
    staged_upload_index: Option<usize>,
    cancellation_cleanup: Option<StagedMultipartCleanupGuard>,
}

struct PreparedAckFault {
    fault: PreparedHostFault,
    started_at_ms: u64,
}

impl FaultRun<'_> {
    pub(super) async fn run_ack_triggered_case(
        &self,
        prepared: &mut PreparedWorkload,
        preflight_phases: &mut Vec<crate::fault::preflight::PreflightPhase>,
        staged_uploads: &mut BTreeMap<usize, StagedMultipartUpload>,
    ) -> Result<()> {
        let PreparedQuietMutation {
            workload,
            staged_upload_index,
            mut cancellation_cleanup,
        } = self
            .prepare_quiet_mutation(&prepared.s3, staged_uploads)
            .await?;
        let result = async {
            let calibration_pods = if self.config.ack_calibration.is_some() {
                Some(self.observe_ack_calibration(&prepared.endpoint).await?)
            } else {
                None
            };
            let target = self
                .deadline
                .run(self.prove_target(&prepared.endpoint, preflight_phases))
                .await?;
            if let Some(pods) = calibration_pods {
                ensure!(
                    pods.len() == target.pods_before.len()
                        && pods
                            .iter()
                            .all(|pod| target.target_proof.resolved_pods.iter().any(
                                |proven| proven.name == pod.name
                                    && proven.uid == pod.uid
                                    && proven.rustfs_container_id.as_deref()
                                        == Some(pod.container_id.as_str())
                            )),
                    "calibration Pod identities changed before target proof"
                );
            }
            self.deadline.check()?;
            let prepared_fault = match self.prepare_ack_fault(&target) {
                Ok(prepared) => prepared,
                Err(error) => {
                    self.record_failure(
                        "fault-prepare",
                        "environment_or_fault_backend",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
            self.deadline.check()?;
            let (mut active, trigger) = self
                .activate_fault_after_ack(&prepared.s3, &target, workload, prepared_fault)
                .await?;
            if let Some(index) = staged_upload_index {
                staged_uploads.remove(&index);
            }
            self.prepare_ack_crash_boundary(&mut active, trigger)?;
            let removal = self.remove_fault(&mut active.fault)?;
            let mut no_staged_uploads = BTreeMap::new();
            let recovered = self
                .recover_access(prepared, &target, &mut no_staged_uploads)
                .await?;
            // Persist the completed lifecycle before the write gate so a
            // probe-detected product failure still leaves fault-evidence.json.
            let mut evidence =
                self.write_ack_recovery_evidence(&target, &active, &removal, &recovered)?;
            self.probe_post_recovery_writes(&prepared.s3).await?;
            self.deadline
                .run(self.verify_recovered_without_recommit(&prepared.s3))
                .await?;
            self.deadline
                .run(self.verify_final_without_recommit(&prepared.s3, &mut evidence))
                .await
        }
        .await;
        if let Some(cleanup) = &mut cancellation_cleanup {
            // Normal errors are handled by the outer registry. Keeping this
            // armed until here makes dropping the run future cancellation-safe.
            cleanup.disarm();
        }
        result
    }

    async fn observe_ack_calibration(
        &self,
        endpoint: &str,
    ) -> Result<Vec<crate::fault::acknowledged_mutation::AckCalibrationPod>> {
        use crate::fault::acknowledged_mutation::{
            ACK_CALIBRATION_ARTIFACT, AckBucketMode, AckCalibrationEvidence, calibration_pod,
        };
        let mode = self
            .config
            .ack_calibration
            .context("calibration mode missing")?;
        crate::fault::acknowledged_mutation::require_calibration_image(
            &self.config.cluster.rustfs_image,
        )?;
        let kubectl = crate::framework::kubectl::Kubectl::new(&self.config.cluster)
            .namespaced(&self.config.cluster.test_namespace);
        let selector = format!("rustfs.tenant={}", self.config.cluster.tenant_name);
        let output = kubectl
            .command(["get", "pods", "-l", &selector, "-o", "json"])
            .run_bounded(self.deadline.bounded_timeout(self.config.request_timeout)?)
            .await?;
        ensure!(output.code == Some(0), "cannot observe calibration Pods");
        let raw: serde_json::Value = serde_json::from_str(&output.stdout)?;
        let pods = raw["items"]
            .as_array()
            .context("calibration Pod list is missing")?
            .iter()
            .map(|pod| calibration_pod(pod, mode, &self.config.cluster.rustfs_image))
            .collect::<Result<Vec<_>>>()?;
        ensure!(!pods.is_empty(), "calibration requires observed Pods");
        ensure!(
            pods.iter().all(|pod| pod.image_id == pods[0].image_id),
            "calibration requires a homogeneous RustFS image digest"
        );
        let (access_key, secret_key) = crate::framework::resources::test_credentials();
        let admin = crate::rustfs::RustfsAdminTransport::new(
            endpoint,
            "us-east-1",
            access_key,
            secret_key,
            None,
            "ack-calibration",
        )?;
        let response = self
            .deadline
            .run(admin.request(
                http::Method::GET,
                &format!("/rustfs/admin/v3/bucket-durability/{}", self.context.bucket),
                &[],
                Vec::new(),
                None,
            ))
            .await?;
        ensure!(
            response.status == 200,
            "calibration bucket durability GET failed: {}",
            response.status
        );
        let bucket_response: AckBucketMode = serde_json::from_slice(&response.body)?;
        ensure!(
            bucket_response.bucket == self.context.bucket
                && bucket_response.mode.as_deref() == Some(mode.as_str()),
            "effective bucket override differs from requested ACK calibration mode"
        );
        let evidence = AckCalibrationEvidence {
            scenario: self.scenario.name.clone(),
            run_id: self.context.run_id.clone(),
            mode,
            observed_at_ms: now_ms(),
            bucket_response,
            pods,
        };
        self.collector.write_text(
            self.scenario.case_name,
            ACK_CALIBRATION_ARTIFACT,
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        Ok(evidence.pods)
    }

    async fn prepare_quiet_mutation(
        &self,
        s3: &S3WorkloadClient,
        staged_uploads: &mut BTreeMap<usize, StagedMultipartUpload>,
    ) -> Result<PreparedQuietMutation> {
        let preparation_timeout = self
            .deadline
            .bounded_timeout(self.config.ack_operation_timeout)?;
        let preparation_deadline = tokio::time::Instant::now()
            .checked_add(preparation_timeout)
            .context("ACK mutation preparation timeout exceeds the monotonic clock range")?;
        let preparation_s3 = s3.for_quiet_mutation(preparation_deadline);
        let kind = acknowledged_mutation_kind(&self.scenario.name)
            .context("ACK-triggered scenario lacks a typed mutation kind")?;
        let index = self
            .context
            .workload_plan
            .object_count
            .checked_add(TRIGGER_OBJECT_OFFSET)
            .context("ACK trigger object index overflowed")?;
        let object = ObjectSpec::prepare_seeded(
            &self.context.run_id,
            index,
            if kind == AcknowledgedMutationKind::MultipartComplete {
                MULTIPART_TRIGGER_PAYLOAD_BYTES
            } else {
                TRIGGER_PAYLOAD_BYTES
            },
            self.context.workload_plan.seed,
        )
        .spec;
        self.context.events.record(
            "ack-mutation-prepare",
            RunEventStatus::Started,
            "preparing the single ACK-triggered mutation without activating the fault",
            Some(serde_json::json!({
                "mutation": kind,
                "preparation_timeout_ms": preparation_timeout.as_millis(),
                "configured_operation_timeout_ms": self.config.ack_operation_timeout.as_millis(),
            })),
        )?;

        let mut staged_upload_index = None;
        let mut cancellation_cleanup = None;
        let workload = match kind {
            AcknowledgedMutationKind::Put => QuietMutationWorkload::put(object),
            AcknowledgedMutationKind::Overwrite | AcknowledgedMutationKind::DeleteMarker => {
                let baseline = preparation_s3
                    .put_object_record(&object.prepare(), &self.context.history)
                    .await
                    .context("create ACK-trigger baseline version")?;
                self.deadline.check()?;
                ensure!(
                    baseline.outcome == OperationOutcome::Ok
                        && baseline
                            .http_status
                            .is_some_and(|status| (200..300).contains(&status))
                        && baseline
                            .version_id
                            .as_deref()
                            .is_some_and(|version| !version.is_empty() && version != "null"),
                    "ACK-trigger baseline PUT did not produce a definite versioned commit"
                );
                if kind == AcknowledgedMutationKind::Overwrite {
                    QuietMutationWorkload::overwrite(object, 1)
                } else {
                    QuietMutationWorkload::delete_marker(object.key.clone())?
                }
            }
            AcknowledgedMutationKind::ZeroBytePut => {
                let empty = ObjectSpec::prepare_seeded(
                    &self.context.run_id,
                    index,
                    0,
                    self.context.workload_plan.seed,
                )
                .spec;
                QuietMutationWorkload::zero_byte_put(empty)?
            }
            AcknowledgedMutationKind::MultipartComplete => {
                let staged = preparation_s3
                    .stage_multipart_object(&object.prepare(), &self.context.history)
                    .await
                    .context("stage ACK-trigger multipart upload")?;
                let cleanup = StagedMultipartCleanupGuard::new(
                    s3.clone(),
                    self.context.history.clone(),
                    staged.clone(),
                );
                self.deadline.check()?;
                staged_uploads.insert(index, staged.clone());
                staged_upload_index = Some(index);
                cancellation_cleanup = Some(cleanup);
                QuietMutationWorkload::staged_multipart_complete(staged)
            }
        };
        self.context.events.record(
            "ack-mutation-prepare",
            RunEventStatus::Succeeded,
            "the ACK mutation is prepared; no fault has been activated",
            Some(serde_json::json!({ "mutation": kind })),
        )?;
        Ok(PreparedQuietMutation {
            workload,
            staged_upload_index,
            cancellation_cleanup,
        })
    }

    async fn activate_fault_after_ack(
        &self,
        s3: &S3WorkloadClient,
        target: &ProvenTarget,
        quiet: QuietMutationWorkload,
        prepared: PreparedAckFault,
    ) -> Result<(ActiveFault, AckToFaultEvidence)> {
        let operation_timeout = self
            .deadline
            .bounded_timeout(self.config.ack_operation_timeout)?;
        let trigger =
            AcknowledgedMutationTrigger::new(operation_timeout, self.config.max_ack_to_fault)?;
        self.context.events.record(
            "ack-trigger",
            RunEventStatus::Started,
            "executing one quiet mutation and arming fault activation only after a definite ACK",
            Some(serde_json::json!({
                "mutation": quiet.kind(),
                "operation_timeout_ms": operation_timeout.as_millis(),
                "configured_operation_timeout_ms": self.config.ack_operation_timeout.as_millis(),
                "max_ack_to_fault_ms": self.config.max_ack_to_fault.as_millis(),
            })),
        )?;

        let PreparedAckFault {
            fault: prepared_fault,
            started_at_ms: fault_prepare_started_at_ms,
        } = prepared;
        let mut prepared_fault = Some(prepared_fault);
        let mut activated = None;
        let result = trigger
            .execute_and_activate_fault(s3, &self.context.history, quiet, || {
                self.deadline.check()?;
                let fault_apply_started_at_ms = now_ms();
                self.context.events.record(
                    "fault-apply",
                    RunEventStatus::Started,
                    "activating the prepared device-mapper fault after the mutation ACK",
                    None,
                )?;
                let activation = prepared_fault
                    .take()
                    .context("prepared device-mapper fault was already consumed")?
                    .activate();
                let (fault, activated_at_ms) = match activation {
                    Ok(activated) => activated,
                    Err(error) => {
                        self.context
                            .events
                            .record(
                                "fault-apply",
                                RunEventStatus::Failed,
                                error.to_string(),
                                None,
                            )
                            .ok();
                        return Err(error);
                    }
                };
                self.context.history.mark_fault_active_at(activated_at_ms);
                activated = Some((fault, fault_apply_started_at_ms, activated_at_ms));
                self.context.events.record(
                    "fault-apply",
                    RunEventStatus::Succeeded,
                    "the prepared device-mapper fault was activated",
                    None,
                )?;
                Ok(activated_at_ms)
            })
            .await;
        let evidence = match result {
            Ok(evidence) => evidence,
            Err(trigger_error) => {
                let error = anyhow::Error::new(trigger_error);
                if let Some((mut fault, _fault_apply_started_at_ms, _activated_at_ms)) = activated {
                    self.record_failure(
                        "ack-trigger",
                        "environment_or_fault_backend",
                        &error,
                        None,
                        Some((&fault, "ack-trigger-failed")),
                    )?;
                    let boundary_started_at_ms = now_ms();
                    let boundary = fault
                        .prepare_recovery_boundary(
                            self.config.cluster.timeout,
                            boundary_started_at_ms,
                        )
                        .context("prepare recovery boundary after late ACK-trigger activation");
                    let removal = self
                        .remove_fault(&mut fault)
                        .context("remove fault after failed ACK trigger");
                    if let Err(cleanup_error) = boundary.and(removal.map(|_| ())) {
                        return Err(error.context(format!(
                            "activated fault cleanup also failed: {cleanup_error:#}"
                        )));
                    }
                } else {
                    self.record_failure("ack-trigger", "test_or_environment", &error, None, None)?;
                }
                return Err(error);
            }
        };
        let (fault, fault_apply_started_at_ms, fault_active_at_ms) =
            activated.context("ACK trigger returned without an activated fault")?;
        self.context.events.record(
            "ack-trigger",
            RunEventStatus::Succeeded,
            "the fault became active after the eligible ACK and within its deadline",
            Some(serde_json::to_value(&evidence)?),
        )?;
        let active = self
            .complete_fault_activation(
                target,
                fault,
                Some(fault_prepare_started_at_ms),
                fault_apply_started_at_ms,
                Some(fault_active_at_ms),
            )
            .await?;
        Ok((active, evidence))
    }

    fn prepare_ack_fault(&self, target: &ProvenTarget) -> Result<PreparedAckFault> {
        self.context.events.record(
            "fault-prepare",
            RunEventStatus::Started,
            "preparing the device-mapper actuator before the quiet mutation",
            None,
        )?;
        let started_at_ms = now_ms();
        if let Some(observed_at_ms) = target.topology_observed_at_ms {
            require_fresh_runtime_observation(observed_at_ms, started_at_ms)
                .context("target topology was stale before ACK fault preparation")?;
        }
        let proof = target
            .host_storage_proof
            .as_ref()
            .context("ACK-triggered device-mapper fault lacks a host-storage proof")?;
        proof
            .require_fresh_at(started_at_ms)
            .context("host-storage proof was stale before ACK fault preparation")?;
        let fault = prepare_host_fault(
            self.config,
            self.collector,
            self.scenario,
            &self.context.run_id,
            proof,
            &target.execution_injection,
        )?;
        self.context.events.record(
            "fault-prepare",
            RunEventStatus::Succeeded,
            "the device-mapper actuator is ready without an active fault",
            None,
        )?;
        Ok(PreparedAckFault {
            fault,
            started_at_ms,
        })
    }

    fn prepare_ack_crash_boundary(
        &self,
        active: &mut ActiveFault,
        trigger: AckToFaultEvidence,
    ) -> Result<()> {
        let started_at_ms = now_ms();
        let crash_boundary_next_sequence = self.context.history.next_event_sequence();
        let evidence = AckTriggeredCrashEvidence {
            scenario: self.scenario.name.clone(),
            run_id: self.context.run_id.clone(),
            ack_to_crash_boundary_ms: started_at_ms
                .saturating_sub(trigger.trigger_acknowledged_at_ms),
            trigger,
            crash_boundary_started_at_ms: started_at_ms,
            crash_boundary_next_sequence,
        };
        self.collector.write_text(
            self.scenario.case_name,
            "ack-to-fault-evidence.json",
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        self.context.events.record(
            "crash-recovery-boundary",
            RunEventStatus::Started,
            "forcing the backend-owned crash boundary immediately after ACK-triggered activation",
            Some(serde_json::json!({
                "trigger_operation_id": evidence.trigger.trigger_operation_id,
                "ack_to_fault_ms": evidence.trigger.ack_to_fault_ms,
            })),
        )?;
        if let Err(error) = active
            .fault
            .prepare_recovery_boundary(self.config.cluster.timeout, started_at_ms)
        {
            self.record_failure(
                "crash-recovery-boundary",
                "environment_or_fault_backend",
                &error,
                Some(serde_json::json!({
                    "trigger_operation_id": evidence.trigger.trigger_operation_id,
                })),
                Some((&active.fault, "crash-boundary-failed")),
            )?;
            return Err(error);
        }
        self.context.events.record(
            "crash-recovery-boundary",
            RunEventStatus::Succeeded,
            "the target Pod was deleted and its filesystem unmounted while drop_writes remained active",
            Some(serde_json::json!({
                "trigger_operation_id": evidence.trigger.trigger_operation_id,
                "ack_to_crash_boundary_ms": evidence.ack_to_crash_boundary_ms,
            })),
        )?;
        Ok(())
    }

    fn write_ack_recovery_evidence(
        &self,
        target: &ProvenTarget,
        active: &ActiveFault,
        removal: &FaultRemoval,
        recovered: &(Vec<crate::fault::reporting::PodIdentity>, u64),
    ) -> Result<FaultEvidence> {
        let (pods_after, recovery_ended_at_ms) = recovered;
        let evidence = FaultEvidence {
            scenario: self.scenario.name.clone(),
            run_id: self.context.run_id.clone(),
            backend: self.plan.backend_summary(),
            target: self.plan.target_summary(),
            injected: true,
            active_during_workload: false,
            recovered: true,
            require_client_disruption: false,
            client_disruptions: 0,
            workload_plan: self.context.workload_plan.clone(),
            pods_before: target.pods_before.clone(),
            pods_at_fault_activation: active.pods_at_fault_activation.clone(),
            pods_at_workload_snapshot: Vec::new(),
            fixed_volume_targets_at_fault_activation: active
                .active_fixed_volume_targets
                .iter()
                .cloned()
                .collect(),
            fixed_volume_targets_at_workload_snapshot: Vec::new(),
            fixed_volume_containers_at_fault_activation: active
                .active_fixed_volume_containers
                .clone(),
            fixed_volume_containers_at_workload_snapshot: Default::default(),
            pods_after: pods_after.clone(),
            active_snapshots: active.active_snapshots.clone(),
            workload_snapshots: Vec::new(),
            dm_recovery_snapshot: active.fault.recovery_dm_snapshot(),
            fault_prepare_started_at_ms: active.fault_prepare_started_at_ms,
            fault_apply_started_at_ms: Some(active.fault_apply_started_at_ms),
            fault_active_at_ms: Some(active.fault_active_at_ms),
            workload_started_at_ms: None,
            workload_ended_at_ms: None,
            fault_delete_started_at_ms: Some(removal.fault_delete_started_at_ms),
            recovery_started_at_ms: Some(removal.recovery_started_at_ms),
            recovery_ended_at_ms: Some(*recovery_ended_at_ms),
            quorum_health_before_workload: None,
            quorum_health_after_workload: None,
        };
        self.collector.write_text(
            self.scenario.case_name,
            "fault-evidence.json",
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        // Ordered before the post-recovery write probe; see
        // `write_recovery_evidence`.
        self.context.events.record(
            "recovery-evidence",
            RunEventStatus::Succeeded,
            "fault-evidence.json persisted with the completed quiet-mutation lifecycle",
            Some(serde_json::json!({
                "recovery_ended_at_ms": evidence.recovery_ended_at_ms,
            })),
        )?;
        Ok(evidence)
    }
}
