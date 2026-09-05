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
    host_storage::HostStorageMutationProof,
    workload::{ObjectSpec, StagedMultipartUpload},
};
use crate::{
    fault::{
        events::RunEventStatus,
        history::OperationOutcome,
        host_storage::HOST_STORAGE_PROOF_ARTIFACT,
        pods::rustfs_target_inventory,
        preflight::{PreflightCheck, PreflightPhase, TargetProof},
        reporting::FailureSummary,
        scenarios::{
            FaultBackend, NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO, QUORUM_P_IO_FAULT_SCENARIO,
            QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO, requires_prefault_multipart_staging,
        },
        workload::S3WorkloadClient,
    },
    framework::resources,
};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;

use super::access::{
    ensure_s3_access, prepare_fault_fixture, s3_access, wait_for_ready_tenant,
    wait_for_stable_rustfs_pods,
};
use super::targets::{
    plan_requires_volume_bindings, require_volume_quorum_topology,
    require_write_quorum_loss_topology, requires_fixed_volume_runtime_proof,
    volume_quorum_boundary, write_quorum_partition_target_count,
};
use super::{FaultRun, PreparedWorkload, ProvenTarget, write_preflight_summary};
use crate::fault::backends::runtime::{
    cleanup_fault_backends, preflight_host_storage_mutation, require_fault_backends,
};
use crate::fault::workload::execution::{prefill_objects, stage_write_quorum_multipart_uploads};

impl FaultRun<'_> {
    pub(super) fn preflight_backends(
        &self,
        preflight_phases: &mut Vec<PreflightPhase>,
    ) -> Result<()> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        events.record(
            "fault-backend-preflight",
            RunEventStatus::Started,
            "checking required fault backends",
            None,
        )?;
        if let Err(error) = require_fault_backends(config, plan) {
            preflight_phases.push(PreflightPhase::new(
                "fault-backend-preflight",
                vec![PreflightCheck::failed(
                    "required_fault_backends",
                    error.to_string(),
                    crate::fault::reporting::ResponsibilityDomain::FaultBackend,
                )],
            ));
            write_preflight_summary(collector, scenario, config, run_id, preflight_phases).ok();
            self.record_failure(
                "fault-backend-preflight",
                "environment_or_fault_backend",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        preflight_phases.push(PreflightPhase::new(
            "fault-backend-preflight",
            vec![PreflightCheck::passed(
                "required_fault_backends",
                "required fault backends are available",
                crate::fault::reporting::ResponsibilityDomain::FaultBackend,
            )],
        ));
        write_preflight_summary(collector, scenario, config, run_id, preflight_phases)?;
        events.record(
            "fault-backend-preflight",
            RunEventStatus::Succeeded,
            "required fault backends are available",
            None,
        )?;
        events.record(
            "fault-backend-pre-cleanup",
            RunEventStatus::Started,
            "removing stale managed fault resources",
            None,
        )?;
        if let Err(error) = cleanup_fault_backends(config, plan) {
            preflight_phases.push(PreflightPhase::new(
                "fault-backend-pre-cleanup",
                vec![PreflightCheck::failed(
                    "stale_fault_cleanup",
                    error.to_string(),
                    crate::fault::reporting::ResponsibilityDomain::FaultBackend,
                )],
            ));
            write_preflight_summary(collector, scenario, config, run_id, preflight_phases).ok();
            self.record_failure(
                "fault-backend-pre-cleanup",
                "environment_or_fault_backend",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        preflight_phases.push(PreflightPhase::new(
            "fault-backend-pre-cleanup",
            vec![PreflightCheck::passed(
                "stale_fault_cleanup",
                "stale managed fault resources were removed",
                crate::fault::reporting::ResponsibilityDomain::FaultBackend,
            )],
        ));
        write_preflight_summary(collector, scenario, config, run_id, preflight_phases)?;
        events.record(
            "fault-backend-pre-cleanup",
            RunEventStatus::Succeeded,
            "stale managed fault resources were removed",
            None,
        )?;
        Ok(())
    }
    pub(super) async fn prepare_fixture(&self) -> Result<()> {
        let config = self.config;
        let spec = self.context.spec;
        let events = &self.context.events;
        let _cluster = &self.config.cluster;
        events.record(
            "fixture-prepare",
            RunEventStatus::Started,
            "preparing owned fault-test Tenant fixture",
            None,
        )?;
        if let Err(error) = prepare_fault_fixture(&config.cluster, spec.isolation) {
            self.record_failure("fixture-prepare", "test_or_environment", &error, None, None)?;
            return Err(error);
        }
        events.record(
            "fixture-prepare",
            RunEventStatus::Succeeded,
            "owned fault-test Tenant fixture prepared",
            None,
        )?;
        events.record(
            "tenant-ready-before-fault",
            RunEventStatus::Started,
            "waiting for Tenant readiness before fault injection",
            None,
        )?;
        if let Err(error) = wait_for_ready_tenant(&config.cluster).await {
            self.record_failure(
                "tenant-ready-before-fault",
                "product_or_environment",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        events.record(
            "tenant-ready-before-fault",
            RunEventStatus::Succeeded,
            "Tenant is Ready before fault injection",
            None,
        )?;
        events.record(
            "pod-stability-before-fault",
            RunEventStatus::Started,
            "waiting for RustFS pods to remain stable before fault injection",
            Some(serde_json::json!({
                "expected_pod_count": config.expected_rustfs_pod_count,
                "stable_window_seconds": config.rustfs_pod_stable_window.as_secs(),
            })),
        )?;
        if let Err(error) = wait_for_stable_rustfs_pods(
            &config.cluster,
            config.expected_rustfs_pod_count,
            config.rustfs_pod_stable_window,
        )
        .await
        {
            self.record_failure(
                "pod-stability-before-fault",
                "product_or_environment",
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        events.record(
            "pod-stability-before-fault",
            RunEventStatus::Succeeded,
            "RustFS pods were stable before fault injection",
            None,
        )?;
        Ok(())
    }
    pub(super) async fn connect_workload(&self) -> Result<PreparedWorkload> {
        let (access_key, secret_key) = resources::test_credentials();
        let config = self.config;
        let scenario = self.scenario;
        let bucket = &self.context.bucket;
        let events = &self.context.events;
        let cluster = &self.config.cluster;
        events.record(
            "initial-s3-access",
            RunEventStatus::Started,
            "opening initial S3 access path",
            Some(serde_json::json!({ "use_cluster_ip": config.use_cluster_ip })),
        )?;
        let (endpoint, mut port_forward) = match s3_access(config) {
            Ok(access) => access,
            Err(error) => {
                events
                    .record(
                        "initial-s3-access",
                        RunEventStatus::Failed,
                        error.to_string(),
                        None,
                    )
                    .ok();
                self.write_failure_summary(FailureSummary::new(
                    &scenario.name,
                    "s3-endpoint",
                    "test_or_environment",
                    error.to_string(),
                )?)?;
                return Err(error);
            }
        };
        if let Err(error) = ensure_s3_access(&mut port_forward, cluster, &endpoint).await {
            self.record_failure(
                "initial-s3-access",
                "product_or_environment",
                &error,
                Some(serde_json::json!({ "endpoint": endpoint })),
                None,
            )?;
            return Err(error);
        }
        events.record(
            "initial-s3-access",
            RunEventStatus::Succeeded,
            "S3 endpoint is reachable before fault injection",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;

        events.record(
            "s3-client",
            RunEventStatus::Started,
            "constructing S3 workload client",
            Some(serde_json::json!({ "endpoint": endpoint })),
        )?;
        let s3 = match S3WorkloadClient::new(
            &endpoint,
            bucket,
            access_key,
            secret_key,
            config.request_timeout,
        )
        .await
        {
            Ok(client) => client,
            Err(error) => {
                self.record_failure("s3-client", "test_or_environment", &error, None, None)?;
                return Err(error);
            }
        };
        events.record(
            "s3-client",
            RunEventStatus::Succeeded,
            "S3 workload client is ready",
            None,
        )?;
        self.create_workload_bucket(&s3).await?;
        let prefilled = self.prefill_workload(&s3).await?;
        Ok(PreparedWorkload {
            s3,
            endpoint,
            port_forward,
            prefilled,
        })
    }
    pub(super) async fn create_workload_bucket(&self, s3: &S3WorkloadClient) -> Result<()> {
        let config = self.config;
        let scenario = self.scenario;
        let bucket = &self.context.bucket;
        let events = &self.context.events;
        let history = &self.context.history;
        events.record(
            "bucket-create",
            RunEventStatus::Started,
            "creating run-scoped workload bucket",
            Some(serde_json::json!({ "bucket": bucket })),
        )?;
        let bucket_outcome = match s3.create_bucket(history).await {
            Ok(outcome) => outcome,
            Err(error) => {
                self.record_failure(
                    "bucket-create",
                    "test_harness",
                    &error,
                    Some(serde_json::json!({ "bucket": bucket })),
                    None,
                )?;
                return Err(error);
            }
        };
        if bucket_outcome != OperationOutcome::Ok {
            let message =
                format!("fault workload bucket creation did not succeed: {bucket_outcome:?}");
            events
                .record(
                    "bucket-create",
                    RunEventStatus::Failed,
                    message.clone(),
                    Some(serde_json::json!({ "bucket": bucket, "outcome": format!("{bucket_outcome:?}") })),
                )
                .ok();
            self.write_failure_summary(FailureSummary::new(
                &scenario.name,
                "bucket-create",
                "product_or_environment",
                message.clone(),
            )?)?;
            bail!("{message}");
        }
        events.record(
            "bucket-create",
            RunEventStatus::Succeeded,
            "run-scoped workload bucket was created",
            Some(serde_json::json!({ "bucket": bucket })),
        )?;

        if config.workload_versioning {
            let versioning_outcome = s3.enable_bucket_versioning(history).await?;
            if versioning_outcome != OperationOutcome::Ok {
                let message = format!(
                    "fault workload bucket versioning enablement did not succeed: {versioning_outcome:?}"
                );
                events
                    .record(
                        "bucket-create",
                        RunEventStatus::Failed,
                        message.clone(),
                        Some(serde_json::json!({
                            "bucket": bucket,
                            "outcome": format!("{versioning_outcome:?}"),
                        })),
                    )
                    .ok();
                self.write_failure_summary(FailureSummary::new(
                    &scenario.name,
                    "bucket-create",
                    "product_or_environment",
                    message.clone(),
                )?)?;
                bail!("{message}");
            }
            events.record(
                "bucket-create",
                RunEventStatus::Succeeded,
                "run-scoped workload bucket versioning was enabled",
                Some(serde_json::json!({ "bucket": bucket })),
            )?;
        }

        Ok(())
    }
    pub(super) async fn prefill_workload(&self, s3: &S3WorkloadClient) -> Result<Vec<ObjectSpec>> {
        let config = self.config;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        events.record(
            "prefill",
            RunEventStatus::Started,
            "writing and verifying pre-fault objects",
            Some(serde_json::json!({
                "object_count": scenario.prefill_count(),
                "concurrency": config.prefill_concurrency,
            })),
        )?;
        let prefilled = match prefill_objects(
            s3,
            history,
            run_id,
            workload_plan,
            scenario.prefill_count(),
            config.prefill_concurrency,
            config.workload_directory_marker_percent,
        )
        .await
        {
            Ok(prefilled) => prefilled,
            Err(error) => {
                self.record_failure("prefill", "product_or_environment", &error, None, None)?;
                return Err(error);
            }
        };
        events.record(
            "prefill",
            RunEventStatus::Succeeded,
            "pre-fault objects were written and verified",
            Some(serde_json::json!({ "objects": prefilled.len() })),
        )?;
        Ok(prefilled)
    }
    pub(super) async fn stage_uploads(
        &self,
        s3: &S3WorkloadClient,
        staged_multipart_uploads: &mut BTreeMap<usize, StagedMultipartUpload>,
    ) -> Result<()> {
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        if requires_prefault_multipart_staging(&plan.scenario) {
            events.record(
                "multipart-stage",
                RunEventStatus::Started,
                "creating multipart uploads and uploading parts before quorum loss",
                None,
            )?;
            match stage_write_quorum_multipart_uploads(
                s3,
                history,
                run_id,
                workload_plan,
                scenario.prefill_count()
                    ..scenario.prefill_count() + scenario.mixed_workload_count(),
                self.deadline,
                staged_multipart_uploads,
            )
            .await
            {
                Ok(()) => {}
                Err(error) => {
                    self.record_failure(
                        "multipart-stage",
                        "product_or_environment",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
            events.record(
                "multipart-stage",
                RunEventStatus::Succeeded,
                "multipart uploads are ready for completion during quorum loss",
                Some(serde_json::json!({ "uploads": staged_multipart_uploads.len() })),
            )?;
        }
        Ok(())
    }
    pub(super) async fn prove_target(
        &self,
        endpoint: &str,
        preflight_phases: &mut Vec<PreflightPhase>,
    ) -> Result<ProvenTarget> {
        let (access_key, secret_key) = resources::test_credentials();
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let spec = self.context.spec;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let cluster = &self.config.cluster;
        events.record(
            "target-preflight",
            RunEventStatus::Started,
            "validating planned fault target proof",
            Some(serde_json::json!({
                "include_volume_bindings": plan_requires_volume_bindings(plan),
            })),
        )?;
        let target_inventory = match rustfs_target_inventory(
            cluster,
            plan_requires_volume_bindings(plan),
            requires_fixed_volume_runtime_proof(plan),
        ) {
            Ok(inventory) => inventory,
            Err(error) => {
                preflight_phases.push(PreflightPhase::new(
                    "target-proof",
                    vec![PreflightCheck::failed(
                        "target_inventory",
                        error.to_string(),
                        crate::fault::reporting::ResponsibilityDomain::Harness,
                    )],
                ));
                write_preflight_summary(collector, scenario, config, run_id, preflight_phases).ok();
                self.record_failure(
                    "target-preflight",
                    "test_or_environment",
                    &error,
                    None,
                    None,
                )?;
                return Err(error);
            }
        };
        let pods_before = target_inventory.identities;
        let mut target_proof = TargetProof::from_plan(config, scenario, spec, plan, run_id)
            .with_resolved_pod_proofs(target_inventory.pod_proofs);
        let mut topology_observed_at_ms = None;
        let mut execution_injection = plan.fault().clone();
        if plan.scenario == NETWORK_PARTITION_WRITE_QUORUM_LOSS_SCENARIO {
            events.record(
                "write-quorum-loss-topology-proof",
                RunEventStatus::Started,
                "reading RustFS runtime erasure geometry immediately before fault activation",
                None,
            )?;
            let target_servers = write_quorum_partition_target_count(plan)?;
            let observation = match require_write_quorum_loss_topology(
                config,
                endpoint,
                access_key,
                secret_key,
                target_servers,
                &pods_before,
            )
            .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    preflight_phases.push(PreflightPhase::new(
                        "write-quorum-loss-topology-proof",
                        vec![PreflightCheck::failed(
                            "write_quorum_loss_topology",
                            error.to_string(),
                            crate::fault::reporting::ResponsibilityDomain::Environment,
                        )],
                    ));
                    write_preflight_summary(collector, scenario, config, run_id, preflight_phases)
                        .ok();
                    self.record_failure(
                        "write-quorum-loss-topology-proof",
                        "test_or_environment",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
            events.record(
                "write-quorum-loss-topology-proof",
                RunEventStatus::Succeeded,
                "fresh, fully-online RustFS runtime geometry establishes the declared quorum boundary",
                Some(serde_json::to_value(&observation)?),
            )?;
            topology_observed_at_ms = Some(observation.observed_at_ms);
            target_proof = target_proof.with_erasure_set_topology_proven(
                observation.shape,
                observation.health,
                observation.membership,
                observation.deployment_id,
                observation.observed_at_ms,
            )?;
        }
        if matches!(
            plan.scenario.as_str(),
            QUORUM_P_IO_FAULT_SCENARIO | QUORUM_P_PLUS_ONE_IO_FAULT_SCENARIO
        ) {
            events.record(
                "volume-quorum-topology-proof",
                RunEventStatus::Started,
                "binding the typed quorum boundary to live RustFS drives and Kubernetes volumes",
                None,
            )?;
            let boundary = volume_quorum_boundary(plan)
                .context("volume quorum scenario lacks a semantic runtime quorum selector")?;
            let volume_path = plan.fault().rustfs_volume_path()?;
            let observation = match require_volume_quorum_topology(
                config,
                endpoint,
                access_key,
                secret_key,
                boundary,
                &target_proof.resolved_pods,
                volume_path,
            )
            .await
            {
                Ok(observation) => observation,
                Err(error) => {
                    preflight_phases.push(PreflightPhase::new(
                        "volume-quorum-topology-proof",
                        vec![PreflightCheck::failed(
                            "volume_quorum_topology",
                            error.to_string(),
                            crate::fault::reporting::ResponsibilityDomain::Environment,
                        )],
                    ));
                    write_preflight_summary(collector, scenario, config, run_id, preflight_phases)
                        .ok();
                    self.record_failure(
                        "volume-quorum-topology-proof",
                        "test_or_environment",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
            topology_observed_at_ms = Some(observation.topology.observed_at_ms);
            target_proof = target_proof.with_erasure_set_topology_proven(
                observation.topology.shape.clone(),
                observation.topology.health,
                observation.topology.membership.clone(),
                observation.topology.deployment_id.clone(),
                observation.topology.observed_at_ms,
            )?;
            target_proof =
                target_proof.with_volume_quorum_proven(observation.volume_quorum.clone())?;
            execution_injection = plan
                .fault()
                .resolve_runtime_quorum(&observation.topology.shape)?;
            events.record(
                "volume-quorum-topology-proof",
                RunEventStatus::Succeeded,
                "runtime quorum count and complete drive-to-volume candidate set were proven",
                Some(serde_json::to_value(&observation)?),
            )?;
        }
        let host_storage_proof = self.prove_host_storage(preflight_phases).await?;
        collector.write_text(
            scenario.case_name,
            "target-proof.json",
            &serde_json::to_string_pretty(&target_proof)?,
        )?;
        preflight_phases.push(PreflightPhase::new(
            "target-proof",
            vec![target_proof.preflight_check()],
        ));
        write_preflight_summary(collector, scenario, config, run_id, preflight_phases)?;
        if let Err(error) = target_proof.require_satisfied() {
            self.record_failure("target-preflight", "preflight_failed", &error, None, None)?;
            return Err(error);
        }
        events.record(
            "target-preflight",
            RunEventStatus::Succeeded,
            "planned fault target proof is satisfied",
            None,
        )?;
        Ok(ProvenTarget {
            pods_before,
            target_proof,
            topology_observed_at_ms,
            host_storage_proof,
            execution_injection,
        })
    }
    pub(super) async fn prove_host_storage(
        &self,
        preflight_phases: &mut Vec<PreflightPhase>,
    ) -> Result<Option<HostStorageMutationProof>> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let plan = self.plan;
        let run_id = &self.context.run_id;
        let events = &self.context.events;
        let host_storage_required = plan
            .faults()
            .iter()
            .any(|fault| fault.backend() == FaultBackend::DeviceMapper);
        if host_storage_required {
            events.record(
                "host-storage-mutation-preflight",
                RunEventStatus::Started,
                "reading host/storage identities and validating destructive policy",
                None,
            )?;
        }
        let host_storage_proof =
            match preflight_host_storage_mutation(config, scenario, plan, run_id) {
                Ok(proof) => proof,
                Err(error) => {
                    preflight_phases.push(PreflightPhase::new(
                        "host-storage-mutation-proof",
                        vec![PreflightCheck::failed(
                            "host_storage_mutation_proof",
                            error.to_string(),
                            crate::fault::reporting::ResponsibilityDomain::Environment,
                        )],
                    ));
                    write_preflight_summary(collector, scenario, config, run_id, preflight_phases)
                        .ok();
                    self.record_failure(
                        "host-storage-mutation-preflight",
                        "preflight_failed",
                        &error,
                        None,
                        None,
                    )?;
                    return Err(error);
                }
            };
        if let Some(proof) = &host_storage_proof {
            collector.write_text(
                scenario.case_name,
                HOST_STORAGE_PROOF_ARTIFACT,
                &serde_json::to_string_pretty(proof)?,
            )?;
            preflight_phases.push(PreflightPhase::new(
                "host-storage-mutation-proof",
                vec![PreflightCheck::passed(
                    "host_storage_mutation_proof",
                    "exact host node/device/PV allowlists and recovery contract are proven",
                    crate::fault::reporting::ResponsibilityDomain::Harness,
                )],
            ));
            events.record(
                "host-storage-mutation-preflight",
                RunEventStatus::Succeeded,
                "side-effect-free host/storage mutation proof is satisfied",
                None,
            )?;
        }
        Ok(host_storage_proof)
    }
}
