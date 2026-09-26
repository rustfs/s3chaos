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

use crate::fault::recovery_health::RUSTFS_CONTAINER_PORT;
use crate::fault::reporting::PodIdentity;
use crate::fault::{reporting::FaultStatusSnapshot, workload::StagedMultipartUpload};
use crate::framework::{
    kubectl::Kubectl,
    port_forward::{PortForwardGuard, PortForwardSpec, replace_port_forward},
};
use crate::{
    fault::{
        events::RunEventStatus,
        fault_lifecycle::AppliedFault,
        history::DurabilityCohort,
        quorum::require_fresh_runtime_observation,
        scenarios::{
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO, POD_FAILURE_QUORUM_EDGE_SCENARIO,
            QUORUM_P_IO_FAULT_SCENARIO, QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO,
            requires_prefault_multipart_staging, requires_quorum_edge_read_survival,
        },
    },
    framework::resources,
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::time::Duration;

use super::access::{
    PortForwardLost, ensure_s3_access, wait_for_local_forward, wait_for_tenant_s3,
};

/// How long a re-pinned `kubectl port-forward` gets to bind its local port
/// and start accepting connections; only the harness side of the endpoint.
const PORT_FORWARD_ESTABLISH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
use super::quorum_activation::{
    QuorumCanaryCleanupGuard, prepare_quorum_fault_activation,
    qualify_prepared_quorum_fault_activation,
};
use super::targets::{
    FixedVolumeTargets, observe_volume_quorum_health, require_active_fixed_volume_targets,
    require_active_pod_failure_quorum_edge, require_active_write_quorum_partition,
    volume_quorum_boundary,
};
use super::{
    ActiveFault, FaultRun, FaultWorkload, PreparedWorkload, ProvenTarget, WorkloadTargetEvidence,
    now_ms, warp_baseline_bucket_name, warp_bucket_name, warp_recovery_bucket_name,
};
use crate::fault::backends::runtime::apply_fault;
use crate::fault::quorum::QUORUM_FAULT_ACTIVATION_ARTIFACT;
use crate::fault::workload::execution::{
    AVAILABILITY_REPORT_ARTIFACT, MixedWorkloadRequest, MixedWorkloadResult,
    QUORUM_EDGE_READ_SURVIVAL_ARTIFACT, QuorumEdgeReadSurvivalReport, ReadProbeSummary,
    TypedQuorumReadCohortSource, TypedQuorumReadExpectation, WarpMixedRequest, probe_read_cohort,
    probe_typed_quorum_read_cohort, require_typed_quorum_read_survival, run_mixed_workload,
    run_warp_mixed,
};

impl FaultRun<'_> {
    pub(super) async fn activate_fault(&self, target: &ProvenTarget) -> Result<ActiveFault> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let ProvenTarget {
            pods_before: _,
            target_proof: _,
            topology_observed_at_ms,
            host_storage_proof,
            execution_injection,
            health_baseline: _,
        } = target;
        events.record(
            "fault-apply",
            RunEventStatus::Started,
            "applying planned faults",
            Some(serde_json::json!({
                "faults": plan.faults().len(),
                "backend": plan.backend_summary(),
            })),
        )?;
        let fault_apply_started_at_ms = now_ms();
        if let Some(observed_at_ms) = *topology_observed_at_ms
            && let Err(error) =
                require_fresh_runtime_observation(observed_at_ms, fault_apply_started_at_ms)
        {
            self.record_failure("fault-apply", "test_or_environment", &error, None, None)?;
            return Err(error);
        }
        if let Some(proof) = &host_storage_proof
            && let Err(error) = proof.require_fresh_at(fault_apply_started_at_ms)
        {
            self.record_failure("fault-apply", "preflight_failed", &error, None, None)?;
            return Err(error);
        }
        let fault = match apply_fault(
            config,
            collector,
            scenario,
            run_id,
            host_storage_proof.as_ref(),
            execution_injection,
        ) {
            Ok(fault) => fault,
            Err(error) => {
                self.record_failure(
                    "fault-apply",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    None,
                )?;
                return Err(error);
            }
        };
        events.record(
            "fault-apply",
            RunEventStatus::Succeeded,
            "planned faults were applied",
            None,
        )?;

        self.complete_fault_activation(target, fault, None, fault_apply_started_at_ms, None)
            .await
    }

    pub(super) async fn complete_fault_activation(
        &self,
        target: &ProvenTarget,
        fault: AppliedFault,
        fault_prepare_started_at_ms: Option<u64>,
        fault_apply_started_at_ms: u64,
        known_fault_active_at_ms: Option<u64>,
    ) -> Result<ActiveFault> {
        let config = self.config;
        let collector = self.collector;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let (fault_active_at_ms, active_snapshots) =
            self.wait_active_fault(&fault, known_fault_active_at_ms)?;
        let quorum_edge_proof = match plan.scenario.as_str() {
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO => {
                Some(require_active_write_quorum_partition(
                    config,
                    run_id,
                    plan,
                    &target.pods_before,
                    &target.target_proof,
                    &active_snapshots,
                ))
            }
            POD_FAILURE_QUORUM_EDGE_SCENARIO => Some(require_active_pod_failure_quorum_edge(
                config,
                run_id,
                plan,
                &target.pods_before,
                &target.target_proof,
                &active_snapshots,
            )),
            _ => None,
        };
        let (pods_at_fault_activation, active_partition_targets) = match quorum_edge_proof {
            Some(Ok(evidence)) => evidence,
            Some(Err(error)) => {
                self.record_failure(
                    "fault-snapshot-active",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((&fault, "active-target-evidence-failed")),
                )?;
                return Err(error);
            }
            None => (Vec::new(), BTreeSet::new()),
        };
        let fixed_volume_runtime_proof =
            if matches!(
                target.execution_injection.selection(),
                crate::fault::plan::FaultSelection::FixedTargets(_)
            ) && target.execution_injection.rustfs_volume_path().is_ok()
            {
                Some(require_active_fixed_volume_targets(
                    config,
                    run_id,
                    &target.execution_injection,
                    &plan.scenario,
                    &target.pods_before,
                    &target.target_proof,
                    &active_snapshots,
                ))
            } else {
                None
            };
        let volume_quorum_scenario = matches!(
            plan.scenario.as_str(),
            QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        );
        let (fixed_volume_targets, quorum_activation, activation_plan) = if volume_quorum_scenario {
            events.record(
                "quorum-fault-activation",
                RunEventStatus::Started,
                "independently probing every controller-selected quorum volume for EIO",
                None,
            )?;
            let controller_validation_error = fixed_volume_runtime_proof
                .as_ref()
                .and_then(|result| result.as_ref().err())
                .map(|error| error.to_string());
            let canary_timeout = std::time::Duration::from_secs(10).min(
                config
                    .cluster
                    .timeout
                    .max(std::time::Duration::from_secs(1)),
            );
            let (evidence, activation_plan) = prepare_quorum_fault_activation(
                &plan.scenario,
                run_id,
                &target.target_proof,
                &active_snapshots,
                controller_validation_error,
            );
            let pods = evidence
                .targets
                .iter()
                .map(|target| PodIdentity {
                    name: target.pod_name.clone(),
                    uid: target.pod_uid.clone(),
                })
                .collect();
            let fixed_volume_targets = FixedVolumeTargets {
                pods,
                records: evidence.selected_record_ids(),
                containers: evidence.selected_containers(),
            };
            let cleanup = QuorumCanaryCleanupGuard::new(
                &config.cluster,
                collector,
                self.scenario.case_name,
                canary_timeout,
                evidence,
            );
            (
                fixed_volume_targets,
                Some(cleanup),
                Some((activation_plan, canary_timeout)),
            )
        } else {
            let evidence = match fixed_volume_runtime_proof {
                Some(Ok(evidence)) => evidence,
                Some(Err(error)) => {
                    self.record_failure(
                        "fault-snapshot-active",
                        "environment_or_fault_backend",
                        &error,
                        None,
                        Some((&fault, "active-volume-target-evidence-failed")),
                    )?;
                    return Err(error);
                }
                None => FixedVolumeTargets::default(),
            };
            (evidence, None, None)
        };
        let FixedVolumeTargets {
            pods: fixed_volume_pods_at_fault_activation,
            records: active_fixed_volume_targets,
            containers: active_fixed_volume_containers,
        } = fixed_volume_targets;
        let pods_at_fault_activation = if fixed_volume_pods_at_fault_activation.is_empty() {
            pods_at_fault_activation
        } else {
            fixed_volume_pods_at_fault_activation
        };
        let mut active = ActiveFault {
            fault,
            fault_prepare_started_at_ms,
            fault_apply_started_at_ms,
            fault_active_at_ms,
            active_snapshots,
            pods_at_fault_activation,
            active_partition_targets,
            active_fixed_volume_targets,
            active_fixed_volume_containers,
            quorum_activation,
            deferred_failure: None,
        };
        if let Some((activation_plan, canary_timeout)) = activation_plan {
            let activation = active
                .quorum_activation
                .as_mut()
                .expect("quorum activation plan has a cleanup guard");
            qualify_prepared_quorum_fault_activation(
                &config.cluster,
                run_id,
                activation,
                activation_plan,
                canary_timeout,
            )
            .await;
            active.deferred_failure = activation.evidence().failure_reason();
        }
        if let Some(activation) = active.quorum_activation.as_ref() {
            let evidence = activation.evidence();
            evidence.validate()?;
            collector.write_text(
                self.scenario.case_name,
                QUORUM_FAULT_ACTIVATION_ARTIFACT,
                &serde_json::to_string_pretty(evidence)?,
            )?;
            let failure = evidence.failure_reason();
            if let Some(reason) = &failure {
                self.write_failure_summary(crate::fault::reporting::FailureSummary::new(
                    &self.scenario.name,
                    "quorum-fault-activation",
                    "fault_not_active",
                    reason.clone(),
                )?)?;
            }
            events.record(
                "quorum-fault-activation",
                if failure.is_some() {
                    RunEventStatus::Failed
                } else {
                    RunEventStatus::Succeeded
                },
                failure.unwrap_or_else(|| {
                    "every selected quorum volume independently returned EIO".to_string()
                }),
                Some(serde_json::json!({
                    "expected_targets": evidence.expected_targets,
                    "controller_records": evidence.controller_records,
                    "canary_targets": evidence.targets.len(),
                    "qualified": evidence.qualified,
                    "artifact": QUORUM_FAULT_ACTIVATION_ARTIFACT,
                })),
            )?;
        }
        events.record(
            "fault-snapshot-active",
            RunEventStatus::Succeeded,
            "active fault status snapshots captured",
            Some(serde_json::json!({ "snapshots": active.active_snapshots.len() })),
        )?;
        Ok(active)
    }
    pub(super) async fn exercise_fault(
        &self,
        prepared: &mut PreparedWorkload,
        target: &ProvenTarget,
        active: &ActiveFault,
        staged_multipart_uploads: &BTreeMap<usize, StagedMultipartUpload>,
    ) -> Result<FaultWorkload> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        let PreparedWorkload {
            s3,
            endpoint,
            port_forward,
            prefilled,
        } = prepared;
        let fault = &active.fault;
        let served_by_pod = self
            .pin_availability_endpoint(target, active, endpoint, port_forward)
            .await?;
        let volume_quorum_scenario = matches!(
            plan.scenario.as_str(),
            QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        );
        let quorum_health_before_workload = if volume_quorum_scenario {
            events.record(
                "quorum-health-before-workload",
                RunEventStatus::Started,
                "capturing the pre-workload RustFS quorum health boundary",
                None,
            )?;
            let selected_pods = active
                .pods_at_fault_activation
                .iter()
                .map(|pod| pod.name.clone())
                .collect::<BTreeSet<_>>();
            let (access_key, secret_key) = resources::test_credentials();
            let observation = match self
                .deadline
                .run(observe_volume_quorum_health(
                    endpoint,
                    access_key,
                    secret_key,
                    &target.target_proof,
                    &selected_pods,
                ))
                .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    self.record_failure(
                        "quorum-health-before-workload",
                        "product_or_environment",
                        &error,
                        None,
                        Some((fault, "quorum-health-before-workload-failed")),
                    )?;
                    return Err(error);
                }
            };
            observation.require_within(active.fault_active_at_ms, now_ms())?;
            events.record(
                "quorum-health-before-workload",
                RunEventStatus::Succeeded,
                "captured one bounded quorum health sample before read probes and mixed mutations",
                Some(serde_json::to_value(&observation)?),
            )?;
            Some(observation)
        } else {
            None
        };
        if crate::fault::backends::lifecycle::expects_total_outage(plan.fault().kind()) {
            // Every RustFS Pod is held down: an unreachable endpoint is the
            // fault's contract, and the workload must then see every request
            // fail (require_total_outage_effect), so the access gate would
            // only ever abort the run here.
            events.record(
                "s3-access-under-fault",
                RunEventStatus::Observed,
                "skipped: the fault is an intentional total outage, so S3 must be unreachable while it is active",
                Some(serde_json::json!({ "endpoint": endpoint })),
            )?;
        } else {
            events.record(
                "s3-access-under-fault",
                RunEventStatus::Started,
                "checking S3 access while faults are active",
                Some(serde_json::json!({ "endpoint": endpoint })),
            )?;
            if let Err(error) = self
                .deadline
                .run(ensure_s3_access(port_forward, cluster, endpoint))
                .await
            {
                self.record_failure(
                    "s3-access-under-fault",
                    "environment_or_workload",
                    &error,
                    Some(serde_json::json!({ "endpoint": endpoint })),
                    Some((fault, "port-forward-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "s3-access-under-fault",
                RunEventStatus::Succeeded,
                "S3 endpoint is reachable while faults are active",
                Some(serde_json::json!({ "endpoint": endpoint })),
            )?;
        }

        self.run_warp_workload(endpoint, port_forward, fault)
            .await?;
        history.set_durability_cohort(DurabilityCohort::FaultActive);
        // A backend that must disrupt under load is released by the first
        // fault-phase S3 request; the trigger stops when this scope ends.
        let _load_trigger = fault.load_gate().map(|gate| {
            let recorder = history.clone();
            LoadTrigger::arm(move || recorder.next_event_sequence(), gate)
        });
        if plan.scenario == QUORUM_P_IO_FAULT_SCENARIO {
            let class = plan.fault().parameters().quorum_case()?;
            events.record(
                "quorum-read-probe",
                RunEventStatus::Started,
                "reading the complete stable typed cohort at the P boundary",
                Some(serde_json::json!({
                    "class": class,
                    "objects": prefilled.len(),
                })),
            )?;
            if let Err(error) = self
                .deadline
                .run(probe_typed_quorum_read_cohort(
                    s3,
                    history,
                    prefilled,
                    class,
                    workload_plan.concurrency,
                ))
                .await
            {
                self.record_failure(
                    "quorum-read-probe",
                    "workload_or_product",
                    &error,
                    None,
                    Some((fault, "quorum-read-probe-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "quorum-read-probe",
                RunEventStatus::Succeeded,
                "every stable typed cohort object remained readable with the committed hash",
                Some(serde_json::json!({ "class": class })),
            )?;
        }
        let availability_read_probe = if self.context.spec.impact_policy.requires_availability() {
            events.record(
                "availability-read-probe",
                RunEventStatus::Started,
                "reading every committed object while the fault is active",
                Some(serde_json::json!({ "objects": prefilled.len() })),
            )?;
            let summary = match self
                .deadline
                .run(probe_read_cohort(
                    s3,
                    history,
                    prefilled,
                    workload_plan.concurrency,
                ))
                .await
            {
                Ok(summary) => summary,
                Err(error) => {
                    self.record_failure(
                        "availability-read-probe",
                        "workload_or_product",
                        &error,
                        None,
                        Some((fault, "availability-read-probe-failed")),
                    )?;
                    return Err(error);
                }
            };
            events.record(
                "availability-read-probe",
                RunEventStatus::Observed,
                "fault-active read probe completed; verdict follows the mixed workload",
                Some(serde_json::json!({
                    "objects": summary.objects,
                    "verified": summary.verified,
                    "failures": summary.failures.len(),
                })),
            )?;
            Some(summary)
        } else {
            None
        };
        if requires_quorum_edge_read_survival(&plan.scenario) {
            events.record(
                "quorum-edge-read-survival",
                RunEventStatus::Started,
                "reading every committed object while the cluster sits at the read-quorum boundary",
                Some(serde_json::json!({ "objects": prefilled.len() })),
            )?;
            let summary = match self
                .deadline
                .run(probe_read_cohort(
                    s3,
                    history,
                    prefilled,
                    workload_plan.concurrency,
                ))
                .await
            {
                Ok(summary) => summary,
                Err(error) => {
                    self.record_failure(
                        "quorum-edge-read-survival",
                        "workload_or_product",
                        &error,
                        None,
                        Some((fault, "quorum-edge-read-survival-failed")),
                    )?;
                    return Err(error);
                }
            };
            collector.write_text(
                scenario.case_name,
                QUORUM_EDGE_READ_SURVIVAL_ARTIFACT,
                &serde_json::to_string_pretty(&QuorumEdgeReadSurvivalReport {
                    scenario: scenario.name.clone(),
                    run_id: run_id.clone(),
                    probe: summary.clone(),
                })?,
            )?;
            // Read quorum is still satisfied by the surviving shards, so an
            // unreadable committed object is a product defect, not the outage
            // this scenario deliberately holds on the write path.
            if let Err(error) = summary.require_complete_survival() {
                self.record_failure(
                    "quorum-edge-read-survival",
                    "availability_regression",
                    &error,
                    Some(serde_json::json!({
                        "objects": summary.objects,
                        "verified": summary.verified,
                        "failures": summary.failures.len(),
                    })),
                    Some((fault, "quorum-edge-read-survival-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "quorum-edge-read-survival",
                RunEventStatus::Succeeded,
                "every committed object stayed readable with its committed bytes at the read-quorum boundary",
                Some(serde_json::json!({ "objects": summary.objects })),
            )?;
        }
        events.record(
            "mixed-workload",
            RunEventStatus::Started,
            "running mixed S3 workload while faults are active",
            Some(serde_json::json!({
                "object_count": scenario.mixed_workload_count(),
                "concurrency": workload_plan.concurrency,
            })),
        )?;
        let workload_started_at_ms = now_ms();
        let workload = match run_mixed_workload(&MixedWorkloadRequest {
            s3,
            history,
            scenario: &scenario.name,
            run_id,
            plan: workload_plan,
            prefilled,
            start_index: scenario.prefill_count(),
            count: scenario.mixed_workload_count(),
            ranged_get_percent: config.workload_ranged_get_percent,
            staged_multipart_uploads: requires_prefault_multipart_staging(&plan.scenario)
                .then_some(staged_multipart_uploads),
            progress_events: Some(events),
            deadline: self.deadline,
        })
        .await
        {
            Ok(workload) => workload,
            Err(error) => {
                self.record_failure(
                    "mixed-workload",
                    "workload_or_product",
                    &error,
                    None,
                    Some((fault, "workload-failed")),
                )?;
                return Err(error);
            }
        };
        let workload_ended_at_ms = now_ms();
        events.record(
            "mixed-workload",
            RunEventStatus::Succeeded,
            "mixed S3 workload completed under active faults",
            Some(serde_json::json!({ "disruptions": workload.summary.disrupted() })),
        )?;
        collector.write_text(
            scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let require_client_disruption = self.require_workload_impact(
            &workload,
            target,
            fault,
            prefilled,
            active.fault_active_at_ms,
            workload_started_at_ms,
        )?;
        self.require_availability(&workload, fault, availability_read_probe, served_by_pod)?;
        events.record(
            "fault-snapshot-after-workload",
            RunEventStatus::Started,
            "capturing fault status snapshots after workload",
            None,
        )?;
        let workload_snapshots = match fault
            .snapshot("after-workload")
            .map(|snapshot| vec![snapshot])
        {
            Ok(snapshots) => snapshots,
            Err(error) => {
                self.record_failure(
                    "fault-snapshot-after-workload",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((fault, "after-workload-snapshot-failed")),
                )?;
                return Err(error);
            }
        };
        let WorkloadTargetEvidence {
            pods_at_workload_snapshot,
            workload_fixed_volume_targets,
            workload_fixed_volume_containers,
        } = self.verify_workload_targets(target, active, &workload_snapshots)?;
        events.record(
            "fault-snapshot-after-workload",
            RunEventStatus::Succeeded,
            "fault status snapshots captured after workload",
            Some(serde_json::json!({ "snapshots": workload_snapshots.len() })),
        )?;
        let quorum_health_after_workload = if volume_quorum_scenario {
            events.record(
                "quorum-health-after-workload",
                RunEventStatus::Started,
                "capturing the post-workload RustFS quorum health boundary",
                None,
            )?;
            let selected_pods = pods_at_workload_snapshot
                .iter()
                .map(|pod| pod.name.clone())
                .collect::<BTreeSet<_>>();
            let (access_key, secret_key) = resources::test_credentials();
            let observation = match self
                .deadline
                .run(observe_volume_quorum_health(
                    endpoint,
                    access_key,
                    secret_key,
                    &target.target_proof,
                    &selected_pods,
                ))
                .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    self.record_failure(
                        "quorum-health-after-workload",
                        "product_or_environment",
                        &error,
                        None,
                        Some((fault, "quorum-health-after-workload-failed")),
                    )?;
                    return Err(error);
                }
            };
            observation.require_within(workload_ended_at_ms, now_ms())?;
            events.record(
                "quorum-health-after-workload",
                RunEventStatus::Succeeded,
                "captured one bounded quorum health sample after workload and controller recheck",
                Some(serde_json::to_value(&observation)?),
            )?;
            Some(observation)
        } else {
            None
        };
        Ok(FaultWorkload {
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
            ran_under_fault: true,
        })
    }

    pub(super) fn skip_unqualified_quorum_workload(
        &self,
        active: &ActiveFault,
    ) -> Result<FaultWorkload> {
        let reason = active
            .deferred_failure
            .as_deref()
            .context("unqualified quorum workload skip lacks a failure reason")?;
        let started_at_ms = now_ms();
        self.context.events.record(
            "mixed-workload",
            RunEventStatus::Observed,
            "skipped typed quorum workload because independent fault activation proof failed",
            Some(serde_json::json!({
                "reason": reason,
                "recovery_will_continue": true,
            })),
        )?;
        let workload = MixedWorkloadResult::skipped_after_unqualified_activation(
            &self.context.workload_plan,
            &self.scenario.name,
            &self.context.run_id,
        );
        self.collector.write_text(
            self.scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        let workload_snapshots = active
            .fault
            .snapshot("after-workload")
            .map(|snapshot| vec![snapshot])
            .unwrap_or_else(|error| {
                self.context
                    .events
                    .record(
                        "fault-snapshot-after-workload",
                        RunEventStatus::Failed,
                        format!("diagnostic snapshot after skipped workload failed: {error:#}"),
                        None,
                    )
                    .ok();
                Vec::new()
            });
        let completed_at_ms = now_ms();
        Ok(FaultWorkload {
            workload,
            workload_started_at_ms: started_at_ms,
            workload_ended_at_ms: completed_at_ms,
            require_client_disruption: self.config.require_client_disruption
                || self.context.spec.impact_policy.requires_client_disruption(),
            workload_snapshots,
            pods_at_workload_snapshot: active.pods_at_fault_activation.clone(),
            workload_fixed_volume_targets: active.active_fixed_volume_targets.clone(),
            workload_fixed_volume_containers: active.active_fixed_volume_containers.clone(),
            quorum_health_before_workload: None,
            quorum_health_after_workload: None,
            ran_under_fault: false,
        })
    }

    pub(super) async fn cleanup_quorum_activation_canaries(&self, active: &mut ActiveFault) {
        let Some(activation) = active.quorum_activation.as_mut() else {
            return;
        };
        self.context
            .events
            .record(
                "quorum-canary-cleanup",
                RunEventStatus::Started,
                "removing run-owned quorum activation canaries after fault removal",
                Some(serde_json::json!({
                    "targets": activation.evidence().targets.len()
                })),
            )
            .ok();
        match activation.cleanup().await {
            Ok(_) => {
                self.context
                    .events
                    .record(
                        "quorum-canary-cleanup",
                        RunEventStatus::Succeeded,
                        "run-owned quorum activation canaries were removed",
                        None,
                    )
                    .ok();
            }
            Err(error) => {
                let reason = format!("quorum activation canary cleanup failed: {error:#}");
                if let Err(persistence) = self.write_failure_summary(
                    crate::fault::reporting::FailureSummary::new(
                        &self.scenario.name,
                        "quorum-canary-cleanup",
                        "test_or_environment",
                        reason.clone(),
                    )
                    .expect("known cleanup classification"),
                ) {
                    eprintln!("persist quorum canary cleanup failure: {persistence:#}");
                }

                active.deferred_failure = Some(match active.deferred_failure.take() {
                    Some(primary) => format!("{primary}; {reason}"),
                    None => reason.clone(),
                });
                self.context
                    .events
                    .record(
                        "quorum-canary-cleanup",
                        RunEventStatus::Failed,
                        reason,
                        None,
                    )
                    .ok();
            }
        }
    }
    pub(super) async fn run_warp_workload(
        &self,
        endpoint: &str,
        port_forward: &mut Option<PortForwardGuard>,
        fault: &AppliedFault,
    ) -> Result<()> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let cluster = &self.config.cluster;
        let (access_key, secret_key) = resources::test_credentials();
        if plan.workload_mode.runs_warp() {
            let warp_bucket = warp_bucket_name(run_id);
            events.record(
                "warp-workload",
                RunEventStatus::Started,
                "running Warp workload under active faults",
                Some(serde_json::json!({ "bucket": warp_bucket })),
            )?;
            let degraded = match run_warp_mixed(
                collector,
                scenario.case_name,
                WarpMixedRequest {
                    duration: config.warp_duration,
                    endpoint,
                    bucket: &warp_bucket,
                    access_key,
                    secret_key,
                    transcript_name: "warp-mixed.txt",
                },
            ) {
                Ok(window) => window,
                Err(error) => {
                    self.record_failure(
                        "warp-workload",
                        "workload_or_product",
                        &error,
                        Some(serde_json::json!({ "bucket": warp_bucket })),
                        Some((fault, "warp-failed")),
                    )?;
                    return Err(error);
                }
            };
            if let Err(error) = self.write_degraded_warp_window(&degraded) {
                self.record_failure(
                    "warp-workload",
                    "workload_or_product",
                    &error,
                    Some(serde_json::json!({ "bucket": warp_bucket })),
                    Some((fault, "warp-metrics-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "warp-workload",
                RunEventStatus::Succeeded,
                "Warp workload completed under active faults",
                Some(serde_json::json!({ "bucket": warp_bucket })),
            )?;

            events.record(
                "post-warp-s3-access",
                RunEventStatus::Started,
                "checking S3 access after Warp workload",
                Some(serde_json::json!({ "endpoint": endpoint })),
            )?;
            if let Err(error) = self
                .deadline
                .run(ensure_s3_access(port_forward, cluster, endpoint))
                .await
            {
                self.record_failure(
                    "post-warp-s3-access",
                    "environment_or_workload",
                    &error,
                    Some(serde_json::json!({ "endpoint": endpoint })),
                    Some((fault, "post-warp-port-forward-failed")),
                )?;
                return Err(error);
            }
            events.record(
                "post-warp-s3-access",
                RunEventStatus::Succeeded,
                "S3 endpoint is reachable after Warp workload",
                Some(serde_json::json!({ "endpoint": endpoint })),
            )?;
        }

        Ok(())
    }

    pub(super) fn capture_warp_baseline(&self, prepared: &PreparedWorkload) -> Result<()> {
        let (access_key, secret_key) = resources::test_credentials();
        let bucket = warp_baseline_bucket_name(&self.context.run_id);
        self.context.events.record(
            "warp-baseline",
            RunEventStatus::Started,
            "running in-run Warp baseline before the fault",
            Some(serde_json::json!({ "bucket": bucket })),
        )?;
        let window = run_warp_mixed(
            self.collector,
            self.scenario.case_name,
            WarpMixedRequest {
                duration: self.config.warp_duration,
                endpoint: &prepared.endpoint,
                bucket: &bucket,
                access_key,
                secret_key,
                transcript_name: "warp-baseline.txt",
            },
        )
        .context("in-run Warp baseline failed")?;
        self.write_json_artifact(
            crate::fault::warp_metrics::WARP_BASELINE_WINDOW_ARTIFACT,
            &window,
        )?;
        self.context.events.record(
            "warp-baseline",
            RunEventStatus::Succeeded,
            "in-run Warp baseline recorded",
            Some(serde_json::json!({
                "bucket": bucket,
                "opsPerSec": window.ops_per_sec,
            })),
        )?;
        Ok(())
    }

    pub(super) fn capture_warp_recovery(&self, prepared: &PreparedWorkload) -> Result<()> {
        let baseline =
            self.read_warp_window(crate::fault::warp_metrics::WARP_BASELINE_WINDOW_ARTIFACT)?;
        let degraded =
            self.read_warp_window(crate::fault::warp_metrics::WARP_DEGRADED_WINDOW_ARTIFACT)?;
        let (access_key, secret_key) = resources::test_credentials();
        let bucket = warp_recovery_bucket_name(&self.context.run_id);
        self.context.events.record(
            "warp-recovery",
            RunEventStatus::Started,
            "sampling post-recovery Warp windows for time-to-baseline",
            Some(serde_json::json!({ "bucket": bucket })),
        )?;
        let mut windows = Vec::new();
        for index in 0..crate::fault::warp_metrics::WARP_RECOVERY_WINDOW_LIMIT {
            self.deadline.check()?;
            let transcript_name = format!("warp-recovery-{index:02}.txt");
            let window = run_warp_mixed(
                self.collector,
                self.scenario.case_name,
                WarpMixedRequest {
                    duration: Duration::from_secs(
                        crate::fault::warp_metrics::WARP_RECOVERY_WINDOW_SECONDS,
                    ),
                    endpoint: &prepared.endpoint,
                    bucket: &bucket,
                    access_key,
                    secret_key,
                    transcript_name: &transcript_name,
                },
            )
            .with_context(|| format!("post-recovery Warp window {index} failed"))?;
            windows.push(crate::fault::warp_metrics::RecoveryWindowRecord {
                seconds: crate::fault::warp_metrics::WARP_RECOVERY_WINDOW_SECONDS,
                ops_per_sec: window.ops_per_sec,
            });
            if matches!(
                crate::fault::warp_metrics::evaluate_ttb(baseline.ops_per_sec, &windows)?,
                crate::fault::warp_metrics::TtbReport::Reached { .. }
            ) {
                break;
            }
        }
        self.write_warp_metrics(&baseline, &degraded, &windows)?;
        self.context.events.record(
            "warp-recovery",
            RunEventStatus::Succeeded,
            "post-recovery Warp windows recorded; NOT_REACHED is a measurement, not a failed run",
            Some(serde_json::json!({ "windows": windows.len() })),
        )?;
        Ok(())
    }

    fn write_degraded_warp_window(
        &self,
        degraded: &crate::fault::warp_metrics::WarpWindow,
    ) -> Result<()> {
        self.write_json_artifact(
            crate::fault::warp_metrics::WARP_DEGRADED_WINDOW_ARTIFACT,
            degraded,
        )?;
        let baseline =
            self.read_warp_window(crate::fault::warp_metrics::WARP_BASELINE_WINDOW_ARTIFACT)?;
        self.write_warp_metrics(&baseline, degraded, &[])
    }

    fn write_warp_metrics(
        &self,
        baseline: &crate::fault::warp_metrics::WarpWindow,
        degraded: &crate::fault::warp_metrics::WarpWindow,
        windows: &[crate::fault::warp_metrics::RecoveryWindowRecord],
    ) -> Result<()> {
        let metrics = crate::fault::warp_metrics::assemble_metrics(
            &self.scenario.name,
            baseline,
            degraded,
            windows,
        )?;
        self.write_json_artifact(
            crate::fault::warp_metrics::WARP_POWERLOSS_METRICS_ARTIFACT,
            &metrics,
        )
    }

    fn write_json_artifact(&self, name: &str, value: &impl serde::Serialize) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            name,
            &serde_json::to_string_pretty(value)?,
        )?;
        Ok(())
    }

    fn read_warp_window(&self, name: &str) -> Result<crate::fault::warp_metrics::WarpWindow> {
        let path = self.collector.case_dir(self.scenario.case_name).join(name);
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("read warp window {}", path.display()))?;
        serde_json::from_str(&raw).with_context(|| format!("decode warp window {name}"))
    }

    pub(super) fn verify_workload_targets(
        &self,
        target: &ProvenTarget,
        active: &ActiveFault,
        workload_snapshots: &[FaultStatusSnapshot],
    ) -> Result<WorkloadTargetEvidence> {
        let config = self.config;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let ProvenTarget {
            pods_before,
            target_proof,
            ..
        } = target;
        let ActiveFault {
            fault,
            active_partition_targets,
            active_fixed_volume_targets,
            pods_at_fault_activation,
            ..
        } = active;
        let revalidated = match plan.scenario.as_str() {
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO => Some((
                "NetworkChaos source targets changed while the quorum workload was running",
                require_active_write_quorum_partition(
                    config,
                    run_id,
                    plan,
                    pods_before,
                    target_proof,
                    workload_snapshots,
                ),
            )),
            POD_FAILURE_QUORUM_EDGE_SCENARIO => Some((
                "PodChaos targets changed while the quorum-edge workload was running",
                require_active_pod_failure_quorum_edge(
                    config,
                    run_id,
                    plan,
                    pods_before,
                    target_proof,
                    workload_snapshots,
                ),
            )),
            _ => None,
        };
        let pods_at_workload_snapshot = if let Some((drift_message, proof)) = revalidated {
            let validation = proof.and_then(|(pods, workload_targets)| {
                ensure!(
                    &workload_targets == active_partition_targets,
                    "{drift_message}"
                );
                Ok(pods)
            });
            match validation {
                Ok(pods) => pods,
                Err(error) => {
                    self.record_failure(
                        "fault-snapshot-after-workload",
                        "environment_or_fault_backend",
                        &error,
                        None,
                        Some((fault, "workload-target-evidence-failed")),
                    )?;
                    return Err(error);
                }
            }
        } else {
            Vec::new()
        };
        let FixedVolumeTargets {
            pods: fixed_volume_pods_at_workload_snapshot,
            records: workload_fixed_volume_targets,
            containers: workload_fixed_volume_containers,
        } = if matches!(
            target.execution_injection.selection(),
            crate::fault::plan::FaultSelection::FixedTargets(_)
        ) && target.execution_injection.rustfs_volume_path().is_ok()
        {
            let validation = require_active_fixed_volume_targets(
                config,
                run_id,
                &target.execution_injection,
                &plan.scenario,
                pods_before,
                target_proof,
                workload_snapshots,
            )
            .and_then(|evidence| {
                ensure!(
                    &evidence.records == active_fixed_volume_targets,
                    "IOChaos selected volume targets changed while the workload was running"
                );
                let active_identities = pods_at_fault_activation
                    .iter()
                    .map(|pod| (&pod.name, &pod.uid))
                    .collect::<BTreeSet<_>>();
                let workload_identities = evidence
                    .pods
                    .iter()
                    .map(|pod| (&pod.name, &pod.uid))
                    .collect::<BTreeSet<_>>();
                ensure!(
                    workload_identities == active_identities,
                    "IOChaos selected Pod identities changed while the workload was running"
                );
                Ok(evidence)
            });
            match validation {
                Ok(evidence) => evidence,
                Err(error) => {
                    self.record_failure(
                        "fault-snapshot-after-workload",
                        "environment_or_fault_backend",
                        &error,
                        None,
                        Some((fault, "workload-volume-target-evidence-failed")),
                    )?;
                    return Err(error);
                }
            }
        } else {
            FixedVolumeTargets::default()
        };
        let pods_at_workload_snapshot = if fixed_volume_pods_at_workload_snapshot.is_empty() {
            pods_at_workload_snapshot
        } else {
            fixed_volume_pods_at_workload_snapshot
        };
        Ok(WorkloadTargetEvidence {
            pods_at_workload_snapshot,
            workload_fixed_volume_targets,
            workload_fixed_volume_containers,
        })
    }
    fn wait_active_fault(
        &self,
        fault: &AppliedFault,
        known_fault_active_at_ms: Option<u64>,
    ) -> Result<(u64, Vec<FaultStatusSnapshot>)> {
        let events = &self.context.events;
        let history = &self.context.history;
        let cluster = &self.config.cluster;
        events.record(
            "wait-active",
            RunEventStatus::Started,
            "waiting for applied faults to become active",
            None,
        )?;
        if let Err(error) = fault.wait_active(cluster.timeout) {
            self.record_failure(
                "wait-active",
                "environment_or_fault_backend",
                &error,
                None,
                Some((fault, "wait-active-failed")),
            )?;
            return Err(error);
        }
        let fault_active_at_ms =
            known_fault_active_at_ms.unwrap_or_else(|| history.mark_fault_active_now());
        events.record(
            "wait-active",
            RunEventStatus::Succeeded,
            "applied faults are active",
            None,
        )?;
        events.record(
            "fault-snapshot-active",
            RunEventStatus::Started,
            "capturing active fault status snapshots",
            None,
        )?;
        let active_snapshots = match fault.snapshot("active").map(|snapshot| vec![snapshot]) {
            Ok(snapshots) => snapshots,
            Err(error) => {
                self.record_failure(
                    "fault-snapshot-active",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((fault, "active-snapshot-failed")),
                )?;
                return Err(error);
            }
        };
        Ok((fault_active_at_ms, active_snapshots))
    }
    /// Scenarios that assert reads survive must prove the service kept
    /// serving: availability scenarios verify the fault-active read probe and
    /// the workload success floor, and quorum-edge scenarios verify the
    /// committed cohort while writes are expected to fail.
    /// The workload endpoint is a `kubectl port-forward` pinned to one Pod for
    /// its lifetime. Such a verdict is only meaningful for a client attached
    /// to a surviving node — a forward to a failed Pod refuses every
    /// connection — so once the fault is active the forward is re-established
    /// to a Pod the controller did not target. A ClusterIP endpoint balances
    /// per connection and needs no pinning.
    async fn pin_availability_endpoint(
        &self,
        target: &ProvenTarget,
        active: &ActiveFault,
        endpoint: &str,
        port_forward: &mut Option<PortForwardGuard>,
    ) -> Result<Option<String>> {
        if !self.context.spec.impact_policy.requires_availability()
            && !requires_quorum_edge_read_survival(&self.plan.scenario)
        {
            return Ok(None);
        }
        // A ClusterIP endpoint needs no target set; resolving one from the
        // controller records is only required when there is a forward to move.
        let targets = if port_forward.is_none() {
            Ok(BTreeSet::new())
        } else {
            injected_source_pod_names(&active.active_snapshots)
        };
        let targets = match targets {
            Ok(targets) => targets,
            Err(error) => {
                let error = error.context("re-pin the S3 port-forward to a surviving Pod");
                self.record_failure(
                    "availability-endpoint",
                    "environment_or_fault_backend",
                    &error,
                    None,
                    Some((&active.fault, "availability-endpoint-failed")),
                )?;
                return Err(error);
            }
        };
        self.repin_endpoint_to_survivor(
            &active.fault,
            &target.pods_before,
            targets,
            endpoint,
            port_forward,
        )
        .await
    }

    /// Re-establish the workload port-forward to a proven Pod outside
    /// `targets` and prove it answers S3 before anything is measured through
    /// it. Records the `availability-endpoint` event either way.
    pub(super) async fn repin_endpoint_to_survivor(
        &self,
        fault: &AppliedFault,
        pods_before: &[PodIdentity],
        targets: BTreeSet<String>,
        endpoint: &str,
        port_forward: &mut Option<PortForwardGuard>,
    ) -> Result<Option<String>> {
        let events = &self.context.events;
        let cluster = &self.config.cluster;
        if port_forward.is_none() {
            events.record(
                "availability-endpoint",
                RunEventStatus::Observed,
                "ClusterIP endpoint balances across ready Pods; no surviving-Pod pinning needed",
                Some(serde_json::json!({ "endpoint": endpoint })),
            )?;
            return Ok(None);
        }
        let pinned = async {
            let survivor = surviving_pod_name(pods_before, &targets)
                .map_err(AvailabilityEndpointFailure::Harness)?;
            let local_port = endpoint
                .rsplit_once(':')
                .and_then(|(_, port)| port.parse::<u16>().ok())
                .context("parse local S3 port-forward endpoint")
                .map_err(AvailabilityEndpointFailure::Harness)?;
            let spec = PortForwardSpec {
                namespace: cluster.test_namespace.clone(),
                service: format!("pod/{survivor}"),
                local_port,
                remote_port: RUSTFS_CONTAINER_PORT,
            };
            // The Service forward is killed before the Pod forward spawns so
            // they never race for the local port, and the Pod forward must
            // answer S3 before the verdict measures anything through it.
            let guard = replace_port_forward(port_forward, || {
                spec.start_with_temp_log(&Kubectl::new(cluster))
            })
            .map_err(AvailabilityEndpointFailure::Harness)?;
            // `kubectl port-forward` only spawns: a bind conflict or API
            // server error exits asynchronously. Prove the process is alive
            // and the local port accepts TCP before anything that fails is
            // attributed to the survivor.
            self.deadline
                .run(wait_for_local_forward(
                    local_port,
                    PORT_FORWARD_ESTABLISH_TIMEOUT,
                    || guard.ensure_running(),
                ))
                .await
                .map_err(AvailabilityEndpointFailure::Harness)?;
            self.deadline
                .run(wait_for_tenant_s3(guard, endpoint, cluster.timeout))
                .await
                .map_err(|error| {
                    AvailabilityEndpointFailure::from_survivor_wait(&survivor, error)
                })?;
            Ok::<_, AvailabilityEndpointFailure>((survivor, targets))
        }
        .await;
        match pinned {
            Ok((survivor, targets)) => {
                events.record(
                    "availability-endpoint",
                    RunEventStatus::Succeeded,
                    "S3 endpoint re-pinned to a surviving RustFS Pod for the availability contract",
                    Some(serde_json::json!({
                        "served_by_pod": survivor,
                        "fault_target_pods": targets,
                        "endpoint": endpoint,
                    })),
                )?;
                Ok(Some(survivor))
            }
            Err(failure) => {
                let classification = failure.classification();
                let details = failure.details();
                let error = failure.into_error();
                self.record_failure(
                    "availability-endpoint",
                    classification,
                    &error,
                    details,
                    Some((fault, "availability-endpoint-failed")),
                )?;
                Err(error)
            }
        }
    }

    fn require_availability(
        &self,
        workload: &MixedWorkloadResult,
        fault: &AppliedFault,
        availability_read_probe: Option<ReadProbeSummary>,
        served_by_pod: Option<String>,
    ) -> Result<()> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let spec = self.context.spec;
        let events = &self.context.events;
        if !spec.impact_policy.requires_availability() {
            ensure!(
                availability_read_probe.is_none(),
                "read probe ran for a scenario without an availability contract"
            );
            return Ok(());
        }
        let read_probe = availability_read_probe
            .context("availability scenario ran its workload without the read probe")?;
        let report = workload.summary.availability_report(
            workload.commit_probe.clone(),
            read_probe,
            config.min_availability_percent,
            served_by_pod,
        );
        report.authenticate_probes(
            &self.context.history.records(),
            self.context.workload_plan.object_count / 2,
        )?;
        collector.write_text(
            scenario.case_name,
            AVAILABILITY_REPORT_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        if let Err(error) = report.require_success() {
            self.record_failure(
                "availability",
                "availability_regression",
                &error,
                Some(serde_json::json!({
                    "min_success_percent": report.min_success_percent,
                    "commit_probe_verified": report.commit_probe.verified,
                    "commit_probe_objects": report.commit_probe.objects,
                    "read_probe_verified": report.read_probe.verified,
                    "read_probe_objects": report.read_probe.objects,
                    "violations": report.violations,
                })),
                Some((fault, "availability-failed")),
            )?;
            return Err(error);
        }
        events.record(
            "availability",
            RunEventStatus::Succeeded,
            "the service kept serving committed reads and the mixed workload under the fault",
            Some(serde_json::json!({
                "min_success_percent": report.min_success_percent,
                "commit_probe_verified": report.commit_probe.verified,
                "commit_probe_objects": report.commit_probe.objects,
                "read_probe_verified": report.read_probe.verified,
                "workload": report.workload,
            })),
        )?;
        Ok(())
    }

    fn require_workload_impact(
        &self,
        workload: &MixedWorkloadResult,
        target: &ProvenTarget,
        fault: &AppliedFault,
        prefilled: &[crate::fault::workload::ObjectSpec],
        fault_active_at_ms: u64,
        workload_started_at_ms: u64,
    ) -> Result<bool> {
        let config = self.config;
        let plan = self.plan;
        let spec = self.context.spec;
        let events = &self.context.events;
        let require_client_disruption =
            config.require_client_disruption || spec.impact_policy.requires_client_disruption();
        let fault_evidence_result = workload
            .summary
            .require_fault_evidence(require_client_disruption)
            .and_then(|()| {
                if matches!(
                    plan.scenario.as_str(),
                    NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO | POD_FAILURE_QUORUM_EDGE_SCENARIO
                ) {
                    workload.summary.require_write_quorum_loss_effect()
                } else if matches!(
                    plan.scenario.as_str(),
                    QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
                ) {
                    let shape = target
                        .target_proof
                        .faults
                        .iter()
                        .find_map(|fault| fault.erasure_set.as_ref())
                        .and_then(|proof| proof.shape.as_ref())
                        .context("volume quorum workload lacks proven runtime geometry")?;
                    let unavailable = volume_quorum_boundary(plan)
                        .context("volume quorum workload lacks a typed boundary")?
                        .unavailable_mutations(shape)?;
                    workload
                        .summary
                        .require_typed_write_quorum_loss_effect(&unavailable)?;
                    if plan.scenario == QUORUM_P_IO_FAULT_SCENARIO {
                        require_typed_quorum_read_survival(
                            &self.context.history.records(),
                            &TypedQuorumReadExpectation {
                                scenario: &plan.scenario,
                                run_id: &self.context.run_id,
                                bucket: &self.context.bucket,
                                class: plan.fault().parameters().quorum_case()?,
                                workload_plan: &self.context.workload_plan,
                                cohort_source: TypedQuorumReadCohortSource::RuntimePrefilled(
                                    prefilled,
                                ),
                                fault_active_at_ms,
                                workload_started_at_ms,
                            },
                        )?;
                    }
                    Ok(())
                } else if plan.fault().kind()
                    == crate::fault::plan::FaultKind::RustfsServerColdRestart
                {
                    // Zero Pods can serve nothing: a single success means the
                    // outage the scenario claims was not held.
                    workload.summary.require_total_outage_effect()
                } else {
                    Ok(())
                }
            });
        if let Err(error) = fault_evidence_result {
            self.record_failure(
                "fault-evidence",
                "test_or_environment",
                &error,
                Some(serde_json::json!({
                    "require_client_disruption": require_client_disruption,
                    "disruptions": workload.summary.disrupted(),
                })),
                Some((fault, "workload-no-fault-evidence")),
            )?;
            return Err(error);
        }
        events.record(
            "fault-evidence",
            RunEventStatus::Observed,
            "workload evidence matched the scenario impact policy",
            Some(serde_json::json!({
                "require_client_disruption": require_client_disruption,
                "disruptions": workload.summary.disrupted(),
            })),
        )?;
        if let Err(error) = fault.ensure_active("after fault workload") {
            self.record_failure(
                "fault-still-active",
                "test_or_environment",
                &error,
                None,
                Some((fault, "workload-outlived-fault")),
            )?;
            return Err(error);
        }
        Ok(require_client_disruption)
    }
}

/// Pod names the Chaos Mesh controller injected as fault sources (selector
/// key "."), read from the active-stage status snapshots. NetworkChaos
/// ".Target" peers are not fault targets and stay eligible as survivors.
fn injected_source_pod_names(snapshots: &[FaultStatusSnapshot]) -> Result<BTreeSet<String>> {
    let mut targets = BTreeSet::new();
    for snapshot in snapshots {
        if let Some(lifecycle) = &snapshot.lifecycle_status {
            targets.extend(lifecycle.target_pods.iter().cloned());
            continue;
        }
        // A harness controller kills a pinned pod while the Schedule object
        // still has no containerRecords. Those pods are the fault targets.
        if let Some(controller_pods) = &snapshot.controller_target_pods {
            targets.extend(controller_pods.iter().cloned());
            continue;
        }
        let Some(status) = &snapshot.chaos_status else {
            continue;
        };
        let records = status
            .pointer("/status/experiment/containerRecords")
            .and_then(serde_json::Value::as_array)
            .with_context(|| {
                format!(
                    "active {} snapshot has no controller records to identify the fault target",
                    snapshot.resource_kind.as_deref().unwrap_or("chaos")
                )
            })?;
        for record in records.iter().filter(|record| {
            record
                .get("selectorKey")
                .and_then(serde_json::Value::as_str)
                == Some(".")
        }) {
            let id = record
                .get("id")
                .and_then(serde_json::Value::as_str)
                .context("controller record has no id")?;
            let pod = id
                .split('/')
                .nth(1)
                .filter(|pod| !pod.is_empty())
                .with_context(|| format!("controller record id {id:?} is not namespace/pod"))?;
            targets.insert(pod.to_string());
        }
    }
    ensure!(
        !targets.is_empty(),
        "active fault snapshots identify no injected target Pod"
    );
    Ok(targets)
}

/// Why the S3 endpoint could not be re-pinned to a surviving Pod. The two
/// causes carry different verdicts: the harness failing to resolve the target
/// or to run `kubectl port-forward` says nothing about RustFS, whereas a
/// forward that is up while the untargeted survivor never answers S3 within
/// the recovery timeout is exactly the loss of availability the scenario
/// exists to detect.
#[derive(Debug)]
enum AvailabilityEndpointFailure {
    Harness(anyhow::Error),
    SurvivorUnready { pod: String, error: anyhow::Error },
}

impl AvailabilityEndpointFailure {
    fn survivor_unready(pod: &str, error: anyhow::Error) -> Self {
        Self::SurvivorUnready {
            pod: pod.to_string(),
            error,
        }
    }

    /// A failed S3 wait through the established forward is the survivor's
    /// only while the forward stayed up; a forward lost mid-wait is harness.
    fn from_survivor_wait(pod: &str, error: anyhow::Error) -> Self {
        if error.is::<PortForwardLost>() {
            Self::Harness(error)
        } else {
            Self::survivor_unready(pod, error)
        }
    }

    fn classification(&self) -> &'static str {
        match self {
            // The suite budget running out while waiting is a harness limit,
            // not evidence about the forward or the survivor.
            Self::Harness(error) | Self::SurvivorUnready { error, .. }
                if error.is::<crate::fault::shutdown::SuiteDeadlineExceeded>() =>
            {
                "test_or_environment"
            }
            Self::Harness(_) => "environment_or_fault_backend",
            Self::SurvivorUnready { .. } => "availability_regression",
        }
    }

    fn details(&self) -> Option<serde_json::Value> {
        match self {
            Self::Harness(_) => None,
            Self::SurvivorUnready { pod, .. } => Some(serde_json::json!({
                "served_by_pod": pod,
                "port_forward": "established",
            })),
        }
    }

    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Harness(error) => error.context("re-pin the S3 port-forward to a surviving Pod"),
            Self::SurvivorUnready { pod, error } => error.context(format!(
                "surviving RustFS Pod {pod} did not serve S3 through its port-forward while the fault was active"
            )),
        }
    }
}

fn surviving_pod_name(pods_before: &[PodIdentity], targets: &BTreeSet<String>) -> Result<String> {
    ensure!(
        targets
            .iter()
            .all(|target| pods_before.iter().any(|pod| &pod.name == target)),
        "fault target Pods {targets:?} are not all members of the proven tenant Pods"
    );
    pods_before
        .iter()
        .map(|pod| pod.name.clone())
        .filter(|name| !targets.contains(name))
        .min()
        .context("every proven RustFS Pod is a fault target; no surviving Pod can serve the availability contract")
}

const LOAD_TRIGGER_POLL: std::time::Duration = std::time::Duration::from_millis(20);

/// Stores the harness time at which the history recorder first moves past
/// its baseline (the first fault-phase S3 request began) into a backend's
/// load gate. Aborted on drop.
struct LoadTrigger(tokio::task::JoinHandle<()>);

impl LoadTrigger {
    fn arm(
        sequence: impl Fn() -> u64 + Send + 'static,
        gate: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        let baseline = sequence();
        Self(tokio::spawn(async move {
            while sequence() <= baseline {
                tokio::time::sleep(LOAD_TRIGGER_POLL).await;
            }
            gate.store(now_ms().max(1), std::sync::atomic::Ordering::SeqCst);
        }))
    }
}

impl Drop for LoadTrigger {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod load_trigger_tests {
    use super::LoadTrigger;
    use std::sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    };
    use std::time::{Duration, Instant};

    #[tokio::test]
    async fn the_gate_opens_only_once_a_fault_phase_request_begins() {
        let sequence = Arc::new(AtomicU64::new(7));
        let gate = Arc::new(AtomicU64::new(0));
        let source = Arc::clone(&sequence);
        let _trigger = LoadTrigger::arm(move || source.load(Ordering::SeqCst), Arc::clone(&gate));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(gate.load(Ordering::SeqCst), 0, "no request has begun yet");
        let before = super::now_ms();
        sequence.fetch_add(1, Ordering::SeqCst);
        let deadline = Instant::now() + Duration::from_secs(5);
        while gate.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "gate never opened");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(gate.load(Ordering::SeqCst) >= before);
    }

    #[tokio::test]
    async fn a_dropped_trigger_never_opens_the_gate() {
        let sequence = Arc::new(AtomicU64::new(0));
        let gate = Arc::new(AtomicU64::new(0));
        let source = Arc::clone(&sequence);
        drop(LoadTrigger::arm(
            move || source.load(Ordering::SeqCst),
            Arc::clone(&gate),
        ));
        sequence.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(gate.load(Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod availability_endpoint_tests {
    use super::{AvailabilityEndpointFailure, injected_source_pod_names, surviving_pod_name};
    use crate::fault::reporting::{
        FailurePhase, FailureSeverity, FailureSummary, FaultStatusSnapshot, PodIdentity,
        ResponsibilityDomain,
    };
    use std::collections::BTreeSet;

    #[test]
    fn a_forward_lost_during_the_survivor_wait_is_harness_not_product() {
        use super::PortForwardLost;
        use anyhow::Context;

        // The shape `wait_for_tenant_s3` produces when the forward exits
        // mid-wait: the lost-forward marker under its readiness context.
        let lost = Err::<(), _>(anyhow::anyhow!(
            "port-forward exited early with exit status: 1"
        ))
        .context(PortForwardLost)
        .context("S3 port-forward was not ready; command: kubectl port-forward")
        .unwrap_err();
        let failure = AvailabilityEndpointFailure::from_survivor_wait("rustfs-1", lost);
        assert!(
            matches!(failure, AvailabilityEndpointFailure::Harness(_)),
            "{failure:?}"
        );
        assert_eq!(failure.classification(), "environment_or_fault_backend");

        let unready = AvailabilityEndpointFailure::from_survivor_wait(
            "rustfs-1",
            anyhow::anyhow!("timed out waiting for S3 endpoint http://127.0.0.1:19000"),
        );
        assert_eq!(unready.classification(), "availability_regression");
    }

    #[test]
    fn survivor_not_serving_s3_is_a_product_availability_failure() {
        let harness = AvailabilityEndpointFailure::Harness(anyhow::anyhow!(
            "failed to start background command: kubectl port-forward"
        ));
        assert_eq!(harness.classification(), "environment_or_fault_backend");
        assert!(harness.details().is_none());
        assert!(
            harness
                .into_error()
                .to_string()
                .contains("re-pin the S3 port-forward")
        );

        let unready = AvailabilityEndpointFailure::survivor_unready(
            "rustfs-1",
            anyhow::anyhow!("S3 port-forward was not ready; command: kubectl ..."),
        );
        assert_eq!(unready.classification(), "availability_regression");
        assert_eq!(
            unready.details().expect("details")["served_by_pod"],
            "rustfs-1"
        );
        let error = unready.into_error();
        assert!(error.to_string().contains("rustfs-1 did not serve S3"));
        let summary = FailureSummary::new(
            "pod-failure",
            "availability-endpoint",
            "availability_regression",
            error.to_string(),
        )
        .expect("allowlisted classification");
        assert_eq!(summary.phase(), Some(FailurePhase::Workload));
        assert_eq!(
            summary.responsibility_domain(),
            Some(ResponsibilityDomain::Product)
        );
        assert_eq!(summary.severity(), FailureSeverity::FailAvailability);
        summary
            .validate_classification_projection()
            .expect("consistent projection");

        // A suite budget running out mid-wait is not product evidence.
        let deadline = AvailabilityEndpointFailure::survivor_unready(
            "rustfs-1",
            crate::fault::shutdown::RunDeadline::new(Some(0))
                .expect("deadline")
                .check()
                .expect_err("expired"),
        );
        assert_eq!(deadline.classification(), "test_or_environment");

        // An asynchronously exiting kubectl (bind conflict, kubeconfig, API
        // server) surfaces through the establishment check as harness.
        let bind_conflict = AvailabilityEndpointFailure::Harness(anyhow::anyhow!(
            "port-forward exited early with exit status: 1; unable to listen on any of the requested ports"
        ));
        assert_eq!(
            bind_conflict.classification(),
            "environment_or_fault_backend"
        );
    }

    fn pods() -> Vec<PodIdentity> {
        (0..4)
            .map(|index| PodIdentity {
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
            })
            .collect()
    }

    fn snapshot(records: serde_json::Value) -> FaultStatusSnapshot {
        FaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: Some("NetworkChaos".to_string()),
            resource_name: Some("chaos-1".to_string()),
            chaos_status: Some(serde_json::json!({
                "status": {"experiment": {"containerRecords": records}}
            })),
            dm_status: None,
            lifecycle_status: None,
            controller_target_pods: None,
        }
    }

    #[test]
    fn lifecycle_snapshots_name_their_restart_targets() {
        use crate::fault::backends::lifecycle::evidence::{
            LifecycleOperation, LifecycleStatusSnapshot,
        };
        let snapshot = FaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: Some("statefulset".to_string()),
            resource_name: Some("tenant-primary".to_string()),
            chaos_status: None,
            dm_status: None,
            lifecycle_status: Some(LifecycleStatusSnapshot {
                operation: LifecycleOperation::Rolling,
                statefulset_name: "tenant-primary".to_string(),
                statefulset_uid: "sts".to_string(),
                spec_replicas: 4,
                ready_replicas: 3,
                target_pods: vec![
                    "rustfs-3".to_string(),
                    "rustfs-2".to_string(),
                    "rustfs-1".to_string(),
                ],
                pods: Vec::new(),
                observed_at_ms: 1,
            }),
            controller_target_pods: None,
        };
        let targets = injected_source_pod_names(&[snapshot]).expect("targets");
        assert_eq!(
            surviving_pod_name(&pods(), &targets).expect("survivor"),
            "rustfs-0"
        );
    }

    #[test]
    fn survivor_excludes_source_targets_but_not_partition_peers() {
        let snapshot = snapshot(serde_json::json!([
            {"id": "ns/rustfs-0", "selectorKey": ".", "phase": "Injected", "injectedCount": 1},
            {"id": "ns/rustfs-1", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1},
            {"id": "ns/rustfs-2", "selectorKey": ".Target", "phase": "Injected", "injectedCount": 1}
        ]));
        let targets = injected_source_pod_names(&[snapshot]).expect("targets");
        assert_eq!(targets, BTreeSet::from(["rustfs-0".to_string()]));
        assert_eq!(
            surviving_pod_name(&pods(), &targets).expect("survivor"),
            "rustfs-1"
        );
    }

    #[test]
    fn missing_records_or_unknown_targets_fail_closed() {
        assert!(injected_source_pod_names(&[snapshot(serde_json::json!([]))]).is_err());
        let foreign = BTreeSet::from(["other-0".to_string()]);
        assert!(surviving_pod_name(&pods(), &foreign).is_err());
        let all = pods()
            .into_iter()
            .map(|pod| pod.name)
            .collect::<BTreeSet<_>>();
        assert!(surviving_pod_name(&pods(), &all).is_err());
        let dm_only = FaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: None,
            resource_name: None,
            chaos_status: None,
            dm_status: None,
            lifecycle_status: None,
            controller_target_pods: None,
        };
        assert!(injected_source_pod_names(&[dm_only]).is_err());
    }

    #[test]
    fn controller_targets_name_the_storm_victim_without_schedule_records() {
        let snapshot = FaultStatusSnapshot {
            stage: "active".to_string(),
            resource_kind: Some("Schedule".to_string()),
            resource_name: Some("pod-restart-storm".to_string()),
            chaos_status: Some(serde_json::json!({
                "status": {"experiment": {}}
            })),
            dm_status: None,
            lifecycle_status: None,
            controller_target_pods: Some(vec!["primary-3".to_string()]),
        };
        let targets = injected_source_pod_names(&[snapshot]).expect("targets");
        assert_eq!(targets, BTreeSet::from(["primary-3".to_string()]));
    }
}
