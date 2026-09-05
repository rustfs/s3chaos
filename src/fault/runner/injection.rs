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

use crate::fault::{reporting::FaultStatusSnapshot, workload::StagedMultipartUpload};
use crate::framework::port_forward::PortForwardGuard;
use crate::{
    fault::{
        events::RunEventStatus,
        fault_lifecycle::AppliedFault,
        history::DurabilityCohort,
        quorum::require_fresh_runtime_observation,
        scenarios::{
            NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO, QUORUM_P_IO_FAULT_SCENARIO,
            QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO, requires_prefault_multipart_staging,
        },
    },
    framework::resources,
};
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

use super::access::ensure_s3_access;
use super::targets::{
    FixedVolumeTargets, observe_volume_quorum_health, require_active_fixed_volume_targets,
    require_active_write_quorum_partition, volume_quorum_boundary,
};
use super::{
    ActiveFault, FaultRun, FaultWorkload, PreparedWorkload, ProvenTarget, WorkloadTargetEvidence,
    now_ms, warp_bucket_name,
};
use crate::fault::backends::runtime::apply_fault;
use crate::fault::workload::execution::{
    MixedWorkloadRequest, MixedWorkloadResult, TypedQuorumReadCohortSource,
    TypedQuorumReadExpectation, probe_typed_quorum_read_cohort, require_typed_quorum_read_survival,
    run_mixed_workload, run_warp_mixed,
};

impl FaultRun<'_> {
    pub(super) fn activate_fault(&self, target: &ProvenTarget) -> Result<ActiveFault> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let ProvenTarget {
            pods_before,
            target_proof,
            topology_observed_at_ms,
            host_storage_proof,
            execution_injection,
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

        let (fault_active_at_ms, active_snapshots) = self.wait_active_fault(&fault)?;
        let (pods_at_fault_activation, active_partition_targets) =
            if plan.scenario == NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
                match require_active_write_quorum_partition(
                    config,
                    run_id,
                    plan,
                    pods_before,
                    target_proof,
                    &active_snapshots,
                ) {
                    Ok(evidence) => evidence,
                    Err(error) => {
                        self.record_failure(
                            "fault-snapshot-active",
                            "environment_or_fault_backend",
                            &error,
                            None,
                            Some((&fault, "active-target-evidence-failed")),
                        )?;
                        return Err(error);
                    }
                }
            } else {
                (Vec::new(), BTreeSet::new())
            };
        let FixedVolumeTargets {
            pods: fixed_volume_pods_at_fault_activation,
            records: active_fixed_volume_targets,
            containers: active_fixed_volume_containers,
        } = if matches!(
            execution_injection.selection(),
            crate::fault::plan::FaultSelection::FixedTargets(_)
        ) && execution_injection.rustfs_volume_path().is_ok()
        {
            match require_active_fixed_volume_targets(
                config,
                run_id,
                execution_injection,
                &plan.scenario,
                pods_before,
                target_proof,
                &active_snapshots,
            ) {
                Ok(evidence) => evidence,
                Err(error) => {
                    self.record_failure(
                        "fault-snapshot-active",
                        "environment_or_fault_backend",
                        &error,
                        None,
                        Some((&fault, "active-volume-target-evidence-failed")),
                    )?;
                    return Err(error);
                }
            }
        } else {
            FixedVolumeTargets::default()
        };
        let pods_at_fault_activation = if fixed_volume_pods_at_fault_activation.is_empty() {
            pods_at_fault_activation
        } else {
            fixed_volume_pods_at_fault_activation
        };
        events.record(
            "fault-snapshot-active",
            RunEventStatus::Succeeded,
            "active fault status snapshots captured",
            Some(serde_json::json!({ "snapshots": active_snapshots.len() })),
        )?;
        Ok(ActiveFault {
            fault,
            fault_apply_started_at_ms,
            fault_active_at_ms,
            active_snapshots,
            pods_at_fault_activation,
            active_partition_targets,
            active_fixed_volume_targets,
            active_fixed_volume_containers,
        })
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

        self.run_warp_workload(endpoint, port_forward, fault)
            .await?;
        history.set_durability_cohort(DurabilityCohort::FaultActive);
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
        })
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
            if let Err(error) = run_warp_mixed(
                config.warp_duration,
                collector,
                scenario.case_name,
                endpoint,
                &warp_bucket,
                access_key,
                secret_key,
            ) {
                self.record_failure(
                    "warp-workload",
                    "workload_or_product",
                    &error,
                    Some(serde_json::json!({ "bucket": warp_bucket })),
                    Some((fault, "warp-failed")),
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
        let pods_at_workload_snapshot =
            if plan.scenario == NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
                let validation = require_active_write_quorum_partition(
                    config,
                    run_id,
                    plan,
                    pods_before,
                    target_proof,
                    workload_snapshots,
                )
                .and_then(|(pods, workload_partition_targets)| {
                    ensure!(
                        &workload_partition_targets == active_partition_targets,
                        "NetworkChaos source targets changed while the quorum workload was running"
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
    fn wait_active_fault(&self, fault: &AppliedFault) -> Result<(u64, Vec<FaultStatusSnapshot>)> {
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
        let fault_active_at_ms = history.mark_fault_active_now();
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
                if plan.scenario == NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
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
