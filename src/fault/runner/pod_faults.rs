// Copyright 2025 RustFS Team
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, time::Duration};

use super::{ActiveFault, FaultRun, PreparedWorkload, ProvenTarget, now_ms};
use crate::{
    fault::{
        backends::chaos_mesh::{
            self, ScopedNetworkPartitionEvidenceContract, TimeChaosEvidenceContract,
        },
        events::RunEventStatus,
        history::{DurabilityCohort, OperationKind, OperationOutcome, OperationRecord, Recorder},
        pod_network::{
            PodConnectivityObservation, PodNetworkIdentity, capture_connectivity,
            capture_pod_network_identities, require_same_generation, validate_connectivity,
            validate_identities,
        },
        preflight::TargetProof,
        scenarios::{CLOCK_SKEW_SCENARIO, NETWORK_SPLIT_BRAIN_SCENARIO},
        spec::FaultRunSpec,
        workload::{ObjectSpec, S3WorkloadClient, WriteProbeScope, execution::probe_read_cohort},
    },
    framework::{kubectl::Kubectl, port_forward::PortForwardSpec, resources},
};

pub(crate) const NETWORK_SPLIT_BRAIN_ARTIFACT: &str = "network-split-brain.json";
pub(crate) const SPLIT_BRAIN_S3_HISTORY_ARTIFACT: &str = "network-split-brain-s3-history.jsonl";
pub(crate) const SPLIT_BRAIN_RECOVERY_HISTORY_ARTIFACT: &str =
    "network-split-brain-recovery-history.jsonl";
pub(crate) const CLOCK_SKEW_ARTIFACT: &str = "clock-skew.json";
const CLOCK_TOLERANCE_MS: i128 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ObservationPhase {
    Baseline,
    Active,
    AfterWorkload,
    Restored,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct HttpClockObservation {
    pub pod: PodNetworkIdentity,
    pub round: u32,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub http_status: u16,
    pub date_header: String,
    pub server_time_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodFaultObservation {
    pub phase: ObservationPhase,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub controller_before: Option<Value>,
    pub controller_after: Option<Value>,
    pub connectivity: Vec<PodConnectivityObservation>,
    pub clocks: Vec<HttpClockObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SplitBrainSideObservation {
    pub pod: PodNetworkIdentity,
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub read_operation_ids: Vec<String>,
    pub write_operation_id: String,
    pub controller_before: Value,
    pub controller_after: Value,
    pub proof_completed_at_ms: u64,
    pub connectivity_after: Vec<PodConnectivityObservation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ClockWorkloadEndpoint {
    pub pod: PodNetworkIdentity,
    pub resource: String,
    pub local_port: u16,
    pub started_at_ms: u64,
    pub established_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SplitBrainProbeRecovery {
    pub started_at_ms: u64,
    pub completed_at_ms: u64,
    pub list_operation_id: String,
    pub read_operation_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodFaultEvidence {
    pub scenario: String,
    pub run_id: String,
    pub namespace: String,
    pub tenant: String,
    pub chaos_namespace: String,
    pub duration_seconds: u64,
    pub pods: Vec<PodNetworkIdentity>,
    pub source_pod_names: BTreeSet<String>,
    pub peer_pod_names: BTreeSet<String>,
    pub offset_seconds: Option<i64>,
    pub clock_workload_endpoint: Option<ClockWorkloadEndpoint>,
    pub probe_recovery: Option<SplitBrainProbeRecovery>,
    pub observations: Vec<PodFaultObservation>,
    pub sides: Vec<SplitBrainSideObservation>,
}

impl FaultRun<'_> {
    pub(super) async fn prepare_pod_fault_observations(
        &self,
        target: &ProvenTarget,
    ) -> Result<Option<PodFaultEvidence>> {
        if !matches!(
            self.plan.scenario.as_str(),
            CLOCK_SKEW_SCENARIO | NETWORK_SPLIT_BRAIN_SCENARIO
        ) {
            return Ok(None);
        }
        let pods = capture_pod_network_identities(&self.config.cluster).await?;
        require_proof_generations(&pods, &target.target_proof)?;
        let split_brain = self.plan.scenario == NETWORK_SPLIT_BRAIN_SCENARIO;
        ensure!(
            if split_brain {
                pods.len() == 4
            } else {
                pods.len() >= 2
            },
            "Pod fault requires its complete target/control set"
        );
        let group_size = if split_brain { 2 } else { pods.len() - 1 };
        let (source, peers) = if split_brain {
            (&pods[..group_size], &pods[group_size..])
        } else {
            (&pods[group_size..], &pods[..group_size])
        };
        let mut evidence = PodFaultEvidence {
            scenario: self.plan.scenario.clone(),
            run_id: self.context.run_id.clone(),
            namespace: self.config.cluster.test_namespace.clone(),
            tenant: self.config.cluster.tenant_name.clone(),
            chaos_namespace: self.config.chaos_namespace.clone(),
            duration_seconds: self.plan.fault().duration().as_secs(),
            source_pod_names: source.iter().map(|pod| pod.name.clone()).collect(),
            peer_pod_names: peers.iter().map(|pod| pod.name.clone()).collect(),
            offset_seconds: if split_brain {
                None
            } else {
                Some(self.plan.fault().parameters().clock_offset_seconds()?)
            },
            clock_workload_endpoint: None,
            probe_recovery: None,
            pods,
            observations: Vec::new(),
            sides: Vec::new(),
        };
        if split_brain {
            evidence.validate_split_brain_topology(&target.target_proof)?;
        }
        self.observe_pod_fault(&mut evidence, ObservationPhase::Baseline, None)
            .await?;
        Ok(Some(evidence))
    }

    pub(super) async fn pin_clock_workload_endpoint(
        &self,
        prepared: &mut PreparedWorkload,
        evidence: &mut PodFaultEvidence,
    ) -> Result<()> {
        if evidence.scenario != CLOCK_SKEW_SCENARIO {
            return Ok(());
        }
        require_same_generation(&self.config.cluster, &evidence.pods).await?;
        let (pod, forward) = evidence.clock_workload_forward()?;
        let started_at_ms = now_ms();
        let mut guard = forward.start(
            &Kubectl::new(&self.config.cluster),
            self.collector
                .case_dir(self.scenario.case_name)
                .join("clock-workload-forward.log"),
        )?;
        guard.wait_ready(Duration::from_secs(10)).await?;
        let endpoint = forward.local_base_url();
        super::access::wait_for_tenant_s3(&mut guard, &endpoint, self.config.cluster.timeout)
            .await?;
        let (access_key, secret_key) = resources::test_credentials();
        let s3 = S3WorkloadClient::new(
            &endpoint,
            &self.context.bucket,
            access_key,
            secret_key,
            self.config.request_timeout,
        )
        .await?;
        require_same_generation(&self.config.cluster, &evidence.pods).await?;
        prepared.s3 = s3;
        prepared.endpoint = endpoint;
        prepared.port_forward = Some(guard);
        evidence.clock_workload_endpoint = Some(ClockWorkloadEndpoint {
            pod,
            resource: forward.service,
            local_port: forward.local_port,
            started_at_ms,
            established_at_ms: now_ms(),
        });
        self.persist_pod_fault_evidence(evidence)?;
        self.context.events.record(
            "clock-workload-endpoint",
            RunEventStatus::Succeeded,
            "mixed workload endpoint directly targets the clock-shifted RustFS Pod",
            Some(serde_json::to_value(&evidence.clock_workload_endpoint)?),
        )?;
        Ok(())
    }

    pub(super) async fn observe_pod_fault(
        &self,
        evidence: &mut PodFaultEvidence,
        phase: ObservationPhase,
        active: Option<&ActiveFault>,
    ) -> Result<()> {
        let started_at_ms = now_ms();
        let before = active
            .map(|active| active.fault.snapshot("pod-observation-before"))
            .transpose()?;
        let before = before
            .map(|snapshot| {
                snapshot
                    .chaos_status
                    .context("Pod fault has no controller snapshot")
            })
            .transpose()?;
        let mut observation = PodFaultObservation {
            phase,
            started_at_ms,
            completed_at_ms: started_at_ms,
            controller_before: before,
            controller_after: None,
            connectivity: Vec::new(),
            clocks: Vec::new(),
        };
        require_same_generation(&self.config.cluster, &evidence.pods).await?;
        if evidence.scenario == NETWORK_SPLIT_BRAIN_SCENARIO {
            observation.connectivity =
                capture_connectivity(&self.config.cluster, &evidence.pods).await?;
        } else {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .no_proxy()
                .build()?;
            let target = evidence.pods.last().context("clock target is missing")?;
            let control = evidence.pods.first().context("clock control is missing")?;
            for pod in [target, control] {
                let forward = PortForwardSpec::pod_on_available_port(
                    &pod.namespace,
                    &pod.name,
                    pod.listener_port,
                )?;
                let mut guard = forward.start(
                    &Kubectl::new(&self.config.cluster),
                    self.collector
                        .case_dir(self.scenario.case_name)
                        .join(format!("clock-forward-{:?}-{}.log", phase, pod.name)),
                )?;
                guard.wait_ready(Duration::from_secs(10)).await?;
                for round in 0..2 {
                    if round > 0 {
                        tokio::time::sleep(Duration::from_millis(1_100)).await;
                    }
                    guard.ensure_running()?;
                    let started_at_ms = now_ms();
                    // The response comes from the already-running RustFS
                    // listener. A process spawned by kubectl exec is outside
                    // TimeChaos's PID-1 lineage and cannot prove its effect.
                    let response = client
                        .get(format!("{}/", forward.local_base_url()))
                        .header("Cache-Control", "no-cache")
                        .send()
                        .await?;
                    let completed_at_ms = now_ms();
                    ensure!(
                        response.headers().get("age").is_none(),
                        "clock observation received a cached HTTP response"
                    );
                    let date_header = response
                        .headers()
                        .get("date")
                        .context("RustFS response has no HTTP Date clock observation")?
                        .to_str()?
                        .to_string();
                    observation.clocks.push(HttpClockObservation {
                        pod: pod.clone(),
                        round,
                        started_at_ms,
                        completed_at_ms,
                        http_status: response.status().as_u16(),
                        server_time_ms: parse_http_date(&date_header)?,
                        date_header,
                    });
                }
            }
        }
        require_same_generation(&self.config.cluster, &evidence.pods).await?;
        observation.controller_after = active
            .map(|active| active.fault.snapshot("pod-observation-after"))
            .transpose()?
            .map(|snapshot| {
                snapshot
                    .chaos_status
                    .context("Pod fault has no controller snapshot")
            })
            .transpose()?;
        observation.completed_at_ms = now_ms();
        evidence.observations.push(observation);
        self.persist_pod_fault_evidence(evidence)?;
        if let Err(error) = evidence.validate_observation(
            evidence
                .observations
                .last()
                .expect("observation was appended"),
        ) {
            let (stage, classification) = match phase {
                ObservationPhase::Baseline => ("target-preflight", "preflight_failed"),
                ObservationPhase::Active => ("fault-snapshot-active", "fault_not_active"),
                ObservationPhase::AfterWorkload => {
                    ("fault-snapshot-after-workload", "fault_not_active")
                }
                ObservationPhase::Restored => ("fault-recovery", "fault_not_recovered"),
            };
            self.record_failure(
                stage,
                classification,
                &error,
                None,
                active.map(|active| (&active.fault, "pod-observation-failed")),
            )?;
            return Err(error);
        }
        self.context.events.record(
            "pod-fault-observation",
            RunEventStatus::Observed,
            format!("captured bounded {phase:?} Pod fault observations"),
            Some(serde_json::json!({"artifact": evidence.artifact_name()})),
        )?;
        Ok(())
    }

    pub(super) async fn probe_split_brain_sides(
        &self,
        evidence: &mut PodFaultEvidence,
        prepared: &PreparedWorkload,
        active: &ActiveFault,
    ) -> Result<Option<String>> {
        if evidence.scenario != NETWORK_SPLIT_BRAIN_SCENARIO {
            return Ok(None);
        }
        let history = Recorder::create(
            self.collector
                .case_dir(self.scenario.case_name)
                .join(SPLIT_BRAIN_S3_HISTORY_ARTIFACT),
            &evidence.scenario,
            &evidence.run_id,
        )?;
        history.set_durability_cohort(DurabilityCohort::FaultActive);
        let (access_key, secret_key) = resources::test_credentials();
        let names = [
            evidence
                .source_pod_names
                .first()
                .context("source side is empty")?,
            evidence
                .peer_pod_names
                .first()
                .context("peer side is empty")?,
        ];
        let cohort = &prepared.prefilled[..prepared.prefilled.len().min(3)];
        ensure!(
            !cohort.is_empty(),
            "split-brain S3 probe has no pre-fault committed objects"
        );
        let mut deferred_failure = None;
        for (index, name) in names.into_iter().enumerate() {
            self.deadline.check()?;
            let pod = evidence
                .pods
                .iter()
                .find(|pod| &pod.name == name)
                .context("side Pod identity is missing")?;
            require_same_generation(&self.config.cluster, &evidence.pods).await?;
            let forward = PortForwardSpec::pod_on_available_port(
                &pod.namespace,
                &pod.name,
                pod.listener_port,
            )?;
            let mut guard = forward.start(
                &Kubectl::new(&self.config.cluster),
                self.collector
                    .case_dir(self.scenario.case_name)
                    .join(format!("split-brain-side-{index}-forward.log")),
            )?;
            guard.wait_ready(Duration::from_secs(10)).await?;
            let s3 = S3WorkloadClient::new_without_retries(
                forward.local_base_url(),
                &self.context.bucket,
                access_key,
                secret_key,
                self.config.request_timeout,
            )
            .await?;
            let s3 = match self.deadline.instant()? {
                Some(deadline) => s3.with_mutation_deadline(deadline),
                None => s3,
            };
            let started_at_ms = now_ms();
            let controller_before = active
                .fault
                .snapshot("split-brain-side-before")?
                .chaos_status
                .context("split-brain has no controller snapshot")?;
            evidence.validate_controller(&controller_before)?;
            let records_before = history.records().len();
            let reads = self
                .deadline
                .run(probe_read_cohort(&s3, &history, cohort, 3))
                .await?;
            let read_operation_ids = history.records()[records_before..]
                .iter()
                .map(|record| record.id.clone())
                .collect();
            let object = ObjectSpec::prepare_write_probe(
                WriteProbeScope::SplitBrain,
                &self.context.run_id,
                index,
                4096,
                self.context.workload_plan.seed,
            );
            let write = s3.put_object_record(&object, &history).await?;
            let completed_at_ms = now_ms();
            let connectivity_after =
                capture_connectivity(&self.config.cluster, &evidence.pods).await?;
            let controller_after = active
                .fault
                .snapshot("split-brain-side-after")?
                .chaos_status
                .context("split-brain has no controller snapshot")?;
            evidence.sides.push(SplitBrainSideObservation {
                pod: pod.clone(),
                started_at_ms,
                completed_at_ms,
                read_operation_ids,
                write_operation_id: write.id.clone(),
                controller_before,
                controller_after,
                connectivity_after,
                proof_completed_at_ms: now_ms(),
            });
            self.persist_pod_fault_evidence(evidence)?;
            require_same_generation(&self.config.cluster, &evidence.pods).await?;
            evidence.validate_side_controller(evidence.sides.last().expect("side was appended"))?;
            let failure = if reads.verified != cohort.len() {
                Some((
                    if reads
                        .failures
                        .iter()
                        .any(|failure| failure.contains("wrong bytes"))
                    {
                        "data_corruption"
                    } else {
                        "availability_regression"
                    },
                    anyhow::anyhow!(
                        "split-brain side {} lost committed reads: {:?}",
                        pod.name,
                        reads.failures
                    ),
                ))
            } else if let Err(error) = require_blocked_write(&write) {
                Some((
                    if write.outcome == OperationOutcome::Ok {
                        "quorum_violation"
                    } else {
                        "environment_or_workload"
                    },
                    error,
                ))
            } else {
                None
            };
            if let Some((classification, error)) = failure {
                self.record_failure(
                    "split-brain-s3-probe",
                    classification,
                    &error,
                    None,
                    Some((&active.fault, "split-brain-s3-probe-failed")),
                )?;
                if classification == "environment_or_workload" {
                    return Err(error);
                }
                deferred_failure.get_or_insert_with(|| format!("{error:#}"));
            }
        }
        Ok(deferred_failure)
    }

    pub(super) async fn verify_split_brain_probe_recovery(
        &self,
        evidence: &mut PodFaultEvidence,
        s3: &S3WorkloadClient,
    ) -> Result<()> {
        if evidence.scenario != NETWORK_SPLIT_BRAIN_SCENARIO {
            return Ok(());
        }
        let history = Recorder::create(
            self.collector
                .case_dir(self.scenario.case_name)
                .join(SPLIT_BRAIN_RECOVERY_HISTORY_ARTIFACT),
            &evidence.scenario,
            &evidence.run_id,
        )?;
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        let started_at_ms = now_ms();
        s3.list_prefix(
            &WriteProbeScope::SplitBrain.key_prefix(&evidence.run_id),
            &history,
        )
        .await?;
        let list_operation_id = history
            .records()
            .last()
            .context("probe LIST has no record")?
            .id
            .clone();
        let mut read_operation_ids = Vec::new();
        for index in 0..2 {
            let object = ObjectSpec::prepare_write_probe(
                WriteProbeScope::SplitBrain,
                &evidence.run_id,
                index,
                4096,
                self.context.workload_plan.seed,
            );
            s3.get_object_result(&object.spec.key, &history).await?;
            read_operation_ids.push(
                history
                    .records()
                    .last()
                    .context("probe GET has no record")?
                    .id
                    .clone(),
            );
        }
        evidence.probe_recovery = Some(SplitBrainProbeRecovery {
            started_at_ms,
            completed_at_ms: now_ms(),
            list_operation_id,
            read_operation_ids,
        });
        self.persist_pod_fault_evidence(evidence)?;
        let records = history.records();
        if let Err(error) = evidence.validate_recovered_probes(
            &records,
            &self.context.bucket,
            self.context.workload_plan.seed,
        ) {
            let classification = if records.iter().any(|record| {
                !matches!(
                    record.outcome,
                    OperationOutcome::Ok | OperationOutcome::NotFound
                )
            }) {
                "availability_regression"
            } else {
                "data_corruption"
            };
            self.record_failure(
                "split-brain-probe-recovery",
                classification,
                &error,
                None,
                None,
            )?;
            return Err(error);
        }
        self.context.events.record(
            "split-brain-probe-recovery",
            RunEventStatus::Succeeded,
            "unconfirmed split-brain writes are absent or contain their exact expected bytes after recovery",
            Some(serde_json::json!({"artifact": SPLIT_BRAIN_RECOVERY_HISTORY_ARTIFACT})),
        )?;
        Ok(())
    }

    pub(super) fn persist_pod_fault_evidence(&self, evidence: &PodFaultEvidence) -> Result<()> {
        self.collector.write_text(
            self.scenario.case_name,
            evidence.artifact_name(),
            &serde_json::to_string_pretty(evidence)?,
        )?;
        Ok(())
    }
}

fn parse_http_date(date: &str) -> Result<i64> {
    let format = time::macros::format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
    );
    let parsed = time::PrimitiveDateTime::parse(date, format)
        .context("parse RustFS HTTP Date")?
        .assume_utc();
    i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000).context("HTTP Date overflow")
}

fn require_proof_generations(pods: &[PodNetworkIdentity], proof: &TargetProof) -> Result<()> {
    validate_identities(pods)?;
    ensure!(
        pods.len() == proof.resolved_pods.len()
            && pods
                .iter()
                .all(|pod| proof.resolved_pods.iter().any(|proved| proved.ready
                    && proved.name == pod.name
                    && proved.uid == pod.uid
                    && proved.rustfs_container_id.as_deref() == Some(pod.container_id.as_str())
                    && proved.node.as_deref() == Some(pod.node.as_str()))),
        "Pod observations differ from preflight Ready Pod/container generations"
    );
    Ok(())
}

fn require_blocked_write(write: &OperationRecord) -> Result<()> {
    ensure!(
        write.kind == OperationKind::Put
            && write.mutation_attempts == Some(1)
            && ((write.outcome == OperationOutcome::Failed && write.http_status == Some(503))
                || (write.outcome == OperationOutcome::Timeout && write.http_status.is_none())),
        "split-brain side acknowledged a write or produced an unrelated failure: {:?} {:?}",
        write.outcome,
        write.http_status
    );
    Ok(())
}

impl PodFaultEvidence {
    fn clock_workload_forward(&self) -> Result<(PodNetworkIdentity, PortForwardSpec)> {
        let pod = self.pods.last().context("clock target is missing")?;
        ensure!(
            self.scenario == CLOCK_SKEW_SCENARIO
                && self.source_pod_names == BTreeSet::from([pod.name.clone()]),
            "clock workload endpoint does not identify the TimeChaos target"
        );
        let forward =
            PortForwardSpec::pod_on_available_port(&pod.namespace, &pod.name, pod.listener_port)?;
        Ok((pod.clone(), forward))
    }

    fn validate_split_brain_topology(&self, proof: &TargetProof) -> Result<()> {
        let topology = proof
            .faults
            .iter()
            .find_map(|fault| fault.erasure_set.as_ref())
            .context("split-brain lacks runtime erasure geometry")?;
        let shape = topology
            .shape
            .as_ref()
            .context("split-brain lacks erasure shape")?;
        let membership = topology
            .membership
            .as_ref()
            .context("split-brain lacks server/drive membership")?;
        shape.require_server_partition_boundary(2)?;
        for names in [&self.source_pod_names, &self.peer_pod_names] {
            membership.require_selected_boundary(shape, names.iter().map(String::as_str))?;
        }
        Ok(())
    }
    fn validate_side_controller(&self, side: &SplitBrainSideObservation) -> Result<()> {
        self.validate_controller(&side.controller_before)?;
        self.validate_controller(&side.controller_after)?;
        ensure!(
            side.controller_before
                .pointer("/metadata/uid")
                .and_then(Value::as_str)
                .is_some_and(|uid| !uid.is_empty())
                && side.controller_before.pointer("/metadata/uid")
                    == side.controller_after.pointer("/metadata/uid"),
            "split-brain controller generation changed across S3 probes"
        );
        let active = self
            .observations
            .iter()
            .find(|observation| observation.phase == ObservationPhase::Active)
            .and_then(|observation| observation.controller_before.as_ref())
            .context("split-brain side has no original active controller proof")?;
        ensure!(
            side.controller_before.pointer("/metadata/uid") == active.pointer("/metadata/uid")
                && side.controller_before.pointer("/metadata/name")
                    == active.pointer("/metadata/name"),
            "split-brain side belongs to a different controller resource"
        );
        validate_connectivity(
            &side.connectivity_after,
            &self.pods,
            &self.source_pod_names,
            &self.peer_pod_names,
            true,
        )?;
        ensure!(
            side.connectivity_after
                .iter()
                .all(|receipt| receipt.started_at_ms >= side.completed_at_ms
                    && receipt.completed_at_ms <= side.proof_completed_at_ms),
            "split-brain post-S3 network proof has an invalid interval"
        );
        Ok(())
    }
    pub(crate) fn artifact_name(&self) -> &'static str {
        if self.scenario == NETWORK_SPLIT_BRAIN_SCENARIO {
            NETWORK_SPLIT_BRAIN_ARTIFACT
        } else {
            CLOCK_SKEW_ARTIFACT
        }
    }

    pub(crate) fn validate_controller(&self, resource: &Value) -> Result<()> {
        if self.scenario == NETWORK_SPLIT_BRAIN_SCENARIO {
            chaos_mesh::validate_scoped_network_partition_snapshot(
                resource,
                &ScopedNetworkPartitionEvidenceContract {
                    chaos_namespace: &self.chaos_namespace,
                    target_namespace: &self.namespace,
                    tenant: &self.tenant,
                    run_id: &self.run_id,
                    scenario: &self.scenario,
                    source_pod_names: &self.source_pod_names,
                    peer_pod_names: &self.peer_pod_names,
                    duration_seconds: self.duration_seconds,
                },
            )
        } else {
            chaos_mesh::validate_timechaos_snapshot(
                resource,
                &TimeChaosEvidenceContract {
                    chaos_namespace: &self.chaos_namespace,
                    target_namespace: &self.namespace,
                    tenant: &self.tenant,
                    run_id: &self.run_id,
                    scenario: &self.scenario,
                    pod_name: self
                        .source_pod_names
                        .first()
                        .context("clock target is missing")?,
                    offset_seconds: self.offset_seconds.context("clock offset is missing")?,
                    duration_seconds: self.duration_seconds,
                },
            )
        }
    }

    fn validate_observation(&self, observation: &PodFaultObservation) -> Result<()> {
        ensure!(
            observation.started_at_ms > 0
                && observation.completed_at_ms >= observation.started_at_ms,
            "invalid Pod observation interval"
        );
        let active = matches!(
            observation.phase,
            ObservationPhase::Active | ObservationPhase::AfterWorkload
        );
        if active {
            for resource in [
                &observation.controller_before,
                &observation.controller_after,
            ] {
                self.validate_controller(
                    resource
                        .as_ref()
                        .context("active Pod observations lack controller proof")?,
                )?;
            }
            let uid = |value: &Option<Value>| {
                value
                    .as_ref()
                    .and_then(|resource| resource.pointer("/metadata/uid"))
                    .and_then(Value::as_str)
                    .filter(|uid| !uid.is_empty())
                    .map(str::to_string)
            };
            ensure!(
                uid(&observation.controller_before).is_some()
                    && uid(&observation.controller_before) == uid(&observation.controller_after),
                "controller resource generation changed during Pod observation"
            );
        } else {
            ensure!(
                observation.controller_before.is_none() && observation.controller_after.is_none(),
                "healthy stage contains active controller evidence"
            );
        }
        if self.scenario == NETWORK_SPLIT_BRAIN_SCENARIO {
            ensure!(
                observation.clocks.is_empty(),
                "split-brain contains clock observations"
            );
            validate_connectivity(
                &observation.connectivity,
                &self.pods,
                &self.source_pod_names,
                &self.peer_pod_names,
                active,
            )?;
            ensure!(
                observation
                    .connectivity
                    .iter()
                    .all(|receipt| receipt.started_at_ms >= observation.started_at_ms
                        && receipt.completed_at_ms <= observation.completed_at_ms),
                "network receipts are outside the observation interval"
            );
        } else {
            ensure!(
                observation.connectivity.is_empty() && observation.clocks.len() == 4,
                "clock stage must contain two fresh target and control samples"
            );
            let target = self.pods.last().context("clock target is missing")?;
            let control = self.pods.first().context("clock control is missing")?;
            for (index, pod) in [target, control].into_iter().enumerate() {
                let rounds = &observation.clocks[index * 2..index * 2 + 2];
                for (round, sample) in rounds.iter().enumerate() {
                    ensure!(
                        sample.pod == *pod
                            && sample.round == round as u32
                            && sample.started_at_ms >= observation.started_at_ms
                            && sample.completed_at_ms <= observation.completed_at_ms
                            && sample.completed_at_ms >= sample.started_at_ms
                            && sample.completed_at_ms - sample.started_at_ms <= 3_000
                            && sample.server_time_ms == parse_http_date(&sample.date_header)?
                            && matches!(sample.http_status, 200 | 400..=499),
                        "HTTP clock receipt has invalid identity, raw date, status, or interval"
                    );
                    let offset_ms = if active && pod == target {
                        i128::from(self.offset_seconds.context("clock offset is missing")?) * 1000
                    } else {
                        0
                    };
                    // HTTP Date has one-second resolution. The actual clock
                    // read lies within the bounded request interval.
                    let lower =
                        i128::from(sample.server_time_ms) - i128::from(sample.completed_at_ms);
                    let upper =
                        i128::from(sample.server_time_ms) + 1000 - i128::from(sample.started_at_ms);
                    ensure!(
                        lower - CLOCK_TOLERANCE_MS <= offset_ms
                            && offset_ms <= upper + CLOCK_TOLERANCE_MS,
                        "RustFS process clock does not match expected offset {offset_ms}ms: observed interval {lower}..{upper}"
                    );
                }
                ensure!(
                    rounds[1].started_at_ms >= rounds[0].completed_at_ms + 1_100
                        && rounds[1].server_time_ms > rounds[0].server_time_ms,
                    "RustFS HTTP Date did not advance across fresh clock samples"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn validate(
        &self,
        proof: &TargetProof,
        spec: &FaultRunSpec,
        history: &[OperationRecord],
        side_history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            self.validate_contract(proof, spec, history, side_history)?
                .is_empty(),
            "split-brain acknowledged a write below the proved write quorum"
        );
        Ok(())
    }

    pub(crate) fn validate_quorum_violation(
        &self,
        proof: &TargetProof,
        spec: &FaultRunSpec,
        history: &[OperationRecord],
        side_history: &[OperationRecord],
    ) -> Result<()> {
        ensure!(
            self.scenario == NETWORK_SPLIT_BRAIN_SCENARIO
                && !self
                    .validate_contract(proof, spec, history, side_history)?
                    .is_empty(),
            "quorum violation lacks an acknowledged write under a proved split-brain cut"
        );
        Ok(())
    }

    fn validate_contract(
        &self,
        proof: &TargetProof,
        spec: &FaultRunSpec,
        history: &[OperationRecord],
        side_history: &[OperationRecord],
    ) -> Result<Vec<String>> {
        ensure!(
            matches!(
                self.scenario.as_str(),
                CLOCK_SKEW_SCENARIO | NETWORK_SPLIT_BRAIN_SCENARIO
            ) && self.scenario == spec.scenario.name
                && self.run_id == spec.metadata.run_id
                && self.namespace == spec.cluster.namespace
                && self.tenant == spec.cluster.tenant
                && self.chaos_namespace == spec.cluster.chaos_namespace
                && spec.faults.len() == 1
                && self.duration_seconds == spec.faults[0].fault_duration_seconds
                && self.pods.iter().all(|pod| pod.namespace == self.namespace)
                && self.pods.windows(2).all(|pair| pair[0].name < pair[1].name)
                && proof.scenario == self.scenario
                && proof.run_id == self.run_id
                && proof.namespace == self.namespace
                && proof.tenant == self.tenant
                && proof.case_name == spec.metadata.name,
            "Pod fault evidence does not identify the persisted run plan"
        );
        require_proof_generations(&self.pods, proof)?;
        ensure!(
            self.observations.len() == 4,
            "Pod fault evidence needs baseline, active, after-workload and restored observations"
        );
        let names = self
            .pods
            .iter()
            .map(|pod| pod.name.clone())
            .collect::<BTreeSet<_>>();
        ensure!(
            self.source_pod_names.is_disjoint(&self.peer_pod_names)
                && self
                    .source_pod_names
                    .union(&self.peer_pod_names)
                    .cloned()
                    .collect::<BTreeSet<_>>()
                    == names,
            "Pod fault groups are not complementary"
        );
        let acknowledged_writes = if self.scenario == NETWORK_SPLIT_BRAIN_SCENARIO {
            ensure!(
                self.pods.len() == 4
                    && self.source_pod_names.len() == 2
                    && self.peer_pod_names.len() == 2
                    && self.offset_seconds.is_none()
                    && self.clock_workload_endpoint.is_none()
                    && self.probe_recovery.is_some(),
                "split-brain must form two pairs"
            );
            self.validate_split_brain_topology(proof)?;
            self.validate_sides(history, side_history, spec)?
        } else {
            let offset = self
                .offset_seconds
                .context("clock evidence is missing its offset")?;
            ensure!(
                self.pods.len() >= 2
                    && self.source_pod_names
                        == BTreeSet::from([self
                            .pods
                            .last()
                            .context("clock target is missing")?
                            .name
                            .clone()])
                    && (60..=600).contains(&offset.unsigned_abs())
                    && offset == spec.faults[0].parameters.clock_offset_seconds()?
                    && self.sides.is_empty()
                    && side_history.is_empty()
                    && self.probe_recovery.is_none(),
                "clock evidence does not match the bounded target/offset plan"
            );
            let endpoint = self
                .clock_workload_endpoint
                .as_ref()
                .context("clock fault has no pinned mixed workload endpoint")?;
            ensure!(
                self.pods.last() == Some(&endpoint.pod)
                    && endpoint.resource == format!("pod/{}", endpoint.pod.name)
                    && endpoint.local_port > 0
                    && endpoint.started_at_ms >= self.observations[0].completed_at_ms
                    && endpoint.established_at_ms >= endpoint.started_at_ms
                    && endpoint.established_at_ms <= self.observations[1].started_at_ms,
                "clock mixed workload endpoint differs from the TimeChaos/Date target or interval"
            );
            Vec::new()
        };
        let mut previous_end = 0;
        let mut controller_uid = None;
        for (observation, phase) in self.observations.iter().zip([
            ObservationPhase::Baseline,
            ObservationPhase::Active,
            ObservationPhase::AfterWorkload,
            ObservationPhase::Restored,
        ]) {
            ensure!(
                observation.phase == phase && observation.started_at_ms >= previous_end,
                "Pod fault observation stages overlap or are out of order"
            );
            self.validate_observation(observation)?;
            previous_end = observation.completed_at_ms;
            if let Some(resource) = &observation.controller_before {
                let uid = resource
                    .pointer("/metadata/uid")
                    .and_then(Value::as_str)
                    .context("controller UID is missing")?;
                ensure!(
                    controller_uid.is_none_or(|expected| expected == uid),
                    "Pod fault controller identity changed across load"
                );
                controller_uid = Some(uid);
            }
        }
        Ok(acknowledged_writes)
    }

    pub(crate) fn validate_recovered_probes(
        &self,
        history: &[OperationRecord],
        bucket: &str,
        seed: u64,
    ) -> Result<()> {
        let recovery = self
            .probe_recovery
            .as_ref()
            .context("split-brain lacks recovered probe state")?;
        ensure!(
            self.scenario == NETWORK_SPLIT_BRAIN_SCENARIO
                && recovery.read_operation_ids.len() == 2
                && history.len() == 3
                && recovery.started_at_ms
                    >= self
                        .observations
                        .last()
                        .context("split-brain lacks restored observations")?
                        .completed_at_ms
                && recovery.completed_at_ms >= recovery.started_at_ms,
            "invalid split-brain probe recovery interval or record count"
        );
        crate::fault::history::validate_history_scope_and_order(
            history,
            &self.scenario,
            &self.run_id,
            bucket,
        )?;
        ensure!(
            history.iter().all(|record| record.durability_cohort
                == Some(DurabilityCohort::PostRecovery)
                && record.started_at_ms >= recovery.started_at_ms
                && record.ended_at_ms <= recovery.completed_at_ms),
            "split-brain recovery records are outside their recovered interval"
        );
        let prefix = WriteProbeScope::SplitBrain.key_prefix(&self.run_id);
        let list = &history[0];
        let keys = list
            .listed_keys
            .as_ref()
            .context("split-brain recovery LIST has no raw keys")?;
        let expected = (0..2)
            .map(|index| {
                ObjectSpec::prepare_write_probe(
                    WriteProbeScope::SplitBrain,
                    &self.run_id,
                    index,
                    4096,
                    seed,
                )
            })
            .collect::<Vec<_>>();
        let allowed = expected
            .iter()
            .map(|object| object.spec.key.as_str())
            .collect::<BTreeSet<_>>();
        ensure!(
            list.id == recovery.list_operation_id
                && list.kind == OperationKind::List
                && list.key.as_deref() == Some(prefix.as_str())
                && list.outcome == OperationOutcome::Ok
                && list.http_status == Some(200)
                && list.size_bytes == Some(keys.len())
                && keys.iter().all(|key| allowed.contains(key.as_str()))
                && keys.iter().collect::<BTreeSet<_>>().len() == keys.len(),
            "split-brain recovery LIST failed or contains a foreign or repeated key"
        );
        for (index, (record, object)) in history[1..].iter().zip(expected).enumerate() {
            ensure!(
                record.id == recovery.read_operation_ids[index]
                    && record.kind == OperationKind::Get
                    && record.key.as_deref() == Some(object.spec.key.as_str())
                    && record.range.is_none()
                    && record.started_at_ms >= list.ended_at_ms
                    && record.started_sequence > list.ended_sequence,
                "split-brain recovered GET is not bound to its probe key after LIST"
            );
            ensure!(
                (record.outcome == OperationOutcome::Ok
                    && record.http_status == Some(200)
                    && record.size_bytes == Some(object.spec.size_bytes)
                    && record.value_sha256.as_deref() == Some(object.spec.sha256.as_str()))
                    || (record.outcome == OperationOutcome::NotFound
                        && record.http_status == Some(404)
                        && record.size_bytes.is_none()
                        && record.value_sha256.is_none()
                        && !keys.contains(&object.spec.key)),
                "recovered split-brain probe object is unavailable, has wrong bytes, or disappeared after LIST"
            );
        }
        Ok(())
    }

    fn validate_sides(
        &self,
        history: &[OperationRecord],
        side_history: &[OperationRecord],
        spec: &FaultRunSpec,
    ) -> Result<Vec<String>> {
        let bucket = spec.metadata.bucket.as_str();
        ensure!(
            self.sides.len() == 2,
            "split-brain requires S3 read/write observations from both pairs"
        );
        crate::fault::history::validate_history_scope_and_order(
            side_history,
            &self.scenario,
            &self.run_id,
            bucket,
        )?;
        let mut used_ids = BTreeSet::new();
        let mut acknowledged_writes = Vec::new();
        let expected_reads = (spec.workload.object_count / 2).min(3);
        for (side_index, (side, names)) in self
            .sides
            .iter()
            .zip([&self.source_pod_names, &self.peer_pod_names])
            .enumerate()
        {
            self.validate_side_controller(side)?;
            ensure!(
                self.pods.contains(&side.pod)
                    && names.contains(&side.pod.name)
                    && expected_reads > 0
                    && side.read_operation_ids.len() == expected_reads
                    && side.completed_at_ms >= side.started_at_ms,
                "split-brain S3 side has an invalid identity or interval"
            );
            for id in &side.read_operation_ids {
                ensure!(
                    used_ids.insert(id.as_str()),
                    "split-brain repeats an S3 probe operation"
                );
                let record = side_history
                    .iter()
                    .find(|record| &record.id == id)
                    .context("split-brain read is missing from history")?;
                ensure!(
                    record.kind == OperationKind::Get
                        && record.bucket == bucket
                        && record.outcome == OperationOutcome::Ok
                        && record
                            .value_sha256
                            .as_ref()
                            .is_some_and(|hash| hash.len() == 64
                                && hash.bytes().all(|byte| byte.is_ascii_hexdigit()))
                        && record.size_bytes.is_some()
                        && record.started_at_ms >= side.started_at_ms
                        && record.ended_at_ms <= side.completed_at_ms,
                    "split-brain committed read did not succeed inside its side interval"
                );
                ensure!(
                    history
                        .iter()
                        .any(|committed| committed.kind == OperationKind::Put
                            && committed.outcome == OperationOutcome::Ok
                            && committed.key == record.key
                            && committed.value_sha256 == record.value_sha256
                            && committed.size_bytes == record.size_bytes
                            && committed.ended_at_ms <= self.observations[0].started_at_ms),
                    "split-brain read bytes do not match a pre-fault committed object"
                );
            }
            ensure!(
                used_ids.insert(&side.write_operation_id),
                "split-brain repeats a write operation"
            );
            let write = side_history
                .iter()
                .find(|record| record.id == side.write_operation_id)
                .context("split-brain write is missing from history")?;
            let expected_object = ObjectSpec::prepare_write_probe(
                WriteProbeScope::SplitBrain,
                &self.run_id,
                side_index,
                4096,
                spec.workload.seed,
            );
            ensure!(
                write.kind == OperationKind::Put
                    && write.bucket == bucket
                    && write.started_at_ms >= side.started_at_ms
                    && write.ended_at_ms <= side.completed_at_ms
                    && write.key.as_deref() == Some(expected_object.spec.key.as_str())
                    && write.value_sha256.as_deref() == Some(expected_object.spec.sha256.as_str())
                    && write.size_bytes == Some(expected_object.spec.size_bytes)
                    && write.mutation_max_attempts == Some(1)
                    && write.mutation_attempts == Some(1),
                "split-brain write is outside its side interval"
            );
            if write.outcome == OperationOutcome::Ok {
                ensure!(
                    write.http_status == Some(200),
                    "acknowledged split-brain PUT has an invalid status"
                );
                acknowledged_writes.push(write.id.clone());
            } else {
                require_blocked_write(write)?;
            }
            ensure!(
                side.started_at_ms >= self.observations[1].completed_at_ms
                    && side.proof_completed_at_ms <= self.observations[2].started_at_ms,
                "split-brain S3 probes are outside controller-proven fault observations"
            );
        }
        ensure!(
            used_ids.len() == side_history.len(),
            "split-brain side history contains unexplained operations"
        );
        Ok(acknowledged_writes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{
        config::{FaultTestConfig, FaultWorkloadProfile},
        plan::FaultPlan,
        preflight::TargetResolvedPodProof,
        quorum::{ErasureSetHealth, ErasureSetMember, ErasureSetMembership, ErasureSetShape},
        scenarios::{FaultScenario, scenario_spec},
        workload::WorkloadPlan,
    };

    fn clock_fixture() -> (PodFaultEvidence, TargetProof, FaultRunSpec) {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = CLOCK_SKEW_SCENARIO.to_string();
        config.duration = Duration::from_secs(120);
        config.workload = FaultWorkloadProfile::new(40, 2).expect("workload");
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(CLOCK_SKEW_SCENARIO).expect("catalog");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("plan");
        let pods = (0..4)
            .map(|index| PodNetworkIdentity {
                namespace: config.cluster.test_namespace.clone(),
                name: format!("rustfs-{index}"),
                uid: format!("uid-{index}"),
                container_id: format!("containerd://container-{index}"),
                node: format!("node-{index}"),
                pod_ip: format!("10.42.0.{}", index + 1),
                listener_port: 9000,
            })
            .collect::<Vec<_>>();
        let proved: Vec<_> = pods
            .iter()
            .map(|pod| {
                let mut proved = TargetResolvedPodProof::new(&pod.name, &pod.uid)
                    .with_ready(true)
                    .with_node(&pod.node);
                proved.rustfs_container_id = Some(pod.container_id.clone());
                proved
            })
            .collect();
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, "run-clock")
            .with_resolved_pod_proofs(proved);
        let workload = WorkloadPlan::seeded(42, 40, 2);
        let spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload,
            "run-clock",
            "bucket",
        );
        let mut controller: Value = serde_yaml_ng::from_str(
            &chaos_mesh::TimeChaosSpec::on_rustfs_pod(
                &config.cluster,
                "chaos-mesh",
                "run-clock",
                CLOCK_SKEW_SCENARIO,
                Duration::from_secs(120),
                "rustfs-3",
                120,
            )
            .expect("TimeChaos")
            .manifest(),
        )
        .expect("manifest");
        controller["metadata"]["uid"] = serde_json::json!("controller-generation");
        controller["status"] = serde_json::json!({"conditions": [{"type": "Selected", "status": "True"}, {"type": "AllInjected", "status": "True"}],
            "experiment": {"desiredPhase": "Run", "containerRecords": [{"id": format!("{}/rustfs-3/rustfs", config.cluster.test_namespace), "selectorKey": ".", "phase": "Injected", "injectedCount": 1}]}});
        let base = u64::try_from(parse_http_date("Wed, 14 Oct 2026 00:00:00 GMT").expect("date"))
            .expect("timestamp");
        let format = time::macros::format_description!(
            "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
        );
        let observations = [
            ObservationPhase::Baseline,
            ObservationPhase::Active,
            ObservationPhase::AfterWorkload,
            ObservationPhase::Restored,
        ]
        .into_iter()
        .enumerate()
        .map(|(phase_index, phase)| {
            let active = matches!(
                phase,
                ObservationPhase::Active | ObservationPhase::AfterWorkload
            );
            let started_at_ms = base + phase_index as u64 * 10_000;
            let clocks = [pods[3].clone(), pods[0].clone()]
                .into_iter()
                .enumerate()
                .flat_map(|(pod_index, pod)| {
                    (0..2).map(move |round| {
                        let started =
                            started_at_ms + pod_index as u64 * 3_000 + u64::from(round) * 1_300;
                        let server_time_ms = (started / 1000) as i64 * 1000
                            + if active && pod_index == 0 { 120_000 } else { 0 };
                        HttpClockObservation {
                            pod: pod.clone(),
                            round,
                            started_at_ms: started,
                            completed_at_ms: started + 50,
                            http_status: 403,
                            server_time_ms,
                            date_header: time::OffsetDateTime::from_unix_timestamp(
                                server_time_ms / 1000,
                            )
                            .expect("date")
                            .format(format)
                            .expect("format"),
                        }
                    })
                })
                .collect();
            PodFaultObservation {
                phase,
                started_at_ms,
                completed_at_ms: started_at_ms + 4_400,
                controller_before: active.then(|| controller.clone()),
                controller_after: active.then(|| controller.clone()),
                connectivity: Vec::new(),
                clocks,
            }
        })
        .collect();
        (
            PodFaultEvidence {
                scenario: CLOCK_SKEW_SCENARIO.to_string(),
                run_id: "run-clock".to_string(),
                namespace: config.cluster.test_namespace.clone(),
                tenant: config.cluster.tenant_name.clone(),
                chaos_namespace: "chaos-mesh".to_string(),
                duration_seconds: 120,
                source_pod_names: BTreeSet::from(["rustfs-3".to_string()]),
                peer_pod_names: pods[..3].iter().map(|pod| pod.name.clone()).collect(),
                offset_seconds: Some(120),
                probe_recovery: None,
                clock_workload_endpoint: Some(ClockWorkloadEndpoint {
                    pod: pods[3].clone(),
                    resource: "pod/rustfs-3".to_string(),
                    local_port: 19_001,
                    started_at_ms: base + 4_500,
                    established_at_ms: base + 4_600,
                }),
                pods,
                observations,
                sides: Vec::new(),
            },
            proof,
            spec,
        )
    }

    #[test]
    fn clock_workload_endpoint_is_bound_to_the_timechaos_and_date_generation() {
        let (evidence, proof, spec) = clock_fixture();
        let (pod, forward) = evidence.clock_workload_forward().expect("direct forward");
        assert_eq!(pod, evidence.pods[3]);
        assert_eq!(forward.service, "pod/rustfs-3");
        assert_eq!(forward.namespace, pod.namespace);
        assert_eq!(forward.remote_port, pod.listener_port);
        assert!(forward.local_port > 0);

        let mut wrong_target = evidence.clone();
        wrong_target.source_pod_names = BTreeSet::from(["rustfs-0".to_string()]);
        assert!(wrong_target.clock_workload_forward().is_err());
        let mut wrong_generation = evidence.clone();
        wrong_generation
            .clock_workload_endpoint
            .as_mut()
            .expect("endpoint")
            .pod
            .container_id = "replacement-container".to_string();
        assert!(wrong_generation.validate(&proof, &spec, &[], &[]).is_err());
        let mut wrong_resource = evidence.clone();
        wrong_resource
            .clock_workload_endpoint
            .as_mut()
            .expect("endpoint")
            .resource = "svc/rustfs-io".to_string();
        assert!(wrong_resource.validate(&proof, &spec, &[], &[]).is_err());
    }

    #[test]
    fn clock_skew_proof_requires_process_offset_control_and_restoration() {
        let (evidence, proof, spec) = clock_fixture();
        evidence
            .validate(&proof, &spec, &[], &[])
            .expect("complete clock proof");
        let mut no_effect = evidence.clone();
        for sample in &mut no_effect.observations[1].clocks[..2] {
            sample.server_time_ms -= 120_000;
            let format = time::macros::format_description!(
                "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] GMT"
            );
            sample.date_header =
                time::OffsetDateTime::from_unix_timestamp(sample.server_time_ms / 1000)
                    .expect("timestamp")
                    .format(format)
                    .expect("date");
        }
        assert!(no_effect.validate(&proof, &spec, &[], &[]).is_err());
        let mut unrestored = evidence.clone();
        unrestored.observations[3].clocks[0].server_time_ms += 120_000;
        assert!(unrestored.validate(&proof, &spec, &[], &[]).is_err());
        let mut wrong_control = evidence.clone();
        wrong_control.observations[1].clocks[2] = wrong_control.observations[1].clocks[0].clone();
        assert!(wrong_control.validate(&proof, &spec, &[], &[]).is_err());
    }

    #[test]
    fn clock_skew_proof_rejects_cached_or_forged_dates_and_changed_generations() {
        let (evidence, proof, spec) = clock_fixture();
        let mut cached = evidence.clone();
        cached.observations[1].clocks[1].server_time_ms =
            cached.observations[1].clocks[0].server_time_ms;
        cached.observations[1].clocks[1].date_header =
            cached.observations[1].clocks[0].date_header.clone();
        assert!(cached.validate(&proof, &spec, &[], &[]).is_err());
        let mut forged = evidence.clone();
        forged.observations[1].clocks[0].server_time_ms += 120_000;
        assert!(forged.validate(&proof, &spec, &[], &[]).is_err());
        let mut incomplete = evidence.clone();
        incomplete.observations.remove(3);
        assert!(incomplete.validate(&proof, &spec, &[], &[]).is_err());
        let mut restarted = evidence.clone();
        restarted.observations[1].clocks[0].pod.container_id = "replacement-container".to_string();
        assert!(restarted.validate(&proof, &spec, &[], &[]).is_err());
        let mut unproven = evidence.clone();
        unproven.observations[1].controller_after = None;
        assert!(unproven.validate(&proof, &spec, &[], &[]).is_err());
        let mut replaced = evidence.clone();
        replaced.observations[2]
            .controller_before
            .as_mut()
            .expect("controller")["metadata"]["uid"] = serde_json::json!("replacement-controller");
        assert!(replaced.validate(&proof, &spec, &[], &[]).is_err());
    }

    #[test]
    fn split_brain_write_probe_rejects_success_auth_failure_and_unsent_timeout() {
        let temp = tempfile::tempdir().expect("temp");
        let recorder = Recorder::create(
            temp.path().join("history.jsonl"),
            NETWORK_SPLIT_BRAIN_SCENARIO,
            "run-split",
        )
        .expect("recorder");
        let mut record = recorder.begin(
            OperationKind::Put,
            "bucket",
            Some("key".to_string()),
            Some("hash".to_string()),
            Some(4),
        );
        record.mutation_max_attempts = Some(1);
        record.mutation_attempts = Some(1);
        let blocked = recorder
            .finish(
                record,
                OperationOutcome::Failed,
                Some(503),
                Some("ServiceUnavailable".to_string()),
            )
            .expect("record");
        require_blocked_write(&blocked).expect("write quorum unavailable");
        let mut acknowledged = blocked.clone();
        acknowledged.outcome = OperationOutcome::Ok;
        acknowledged.http_status = Some(200);
        assert!(require_blocked_write(&acknowledged).is_err());
        let mut unauthorized = blocked.clone();
        unauthorized.http_status = Some(403);
        assert!(require_blocked_write(&unauthorized).is_err());
        let mut timeout = blocked;
        timeout.outcome = OperationOutcome::Timeout;
        timeout.http_status = None;
        require_blocked_write(&timeout).expect("sent request timed out");
        timeout.mutation_attempts = Some(0);
        assert!(require_blocked_write(&timeout).is_err());
    }

    struct SplitBrainChainFixture {
        evidence: PodFaultEvidence,
        proof: TargetProof,
        spec: FaultRunSpec,
        history: Vec<OperationRecord>,
        side_history: Vec<OperationRecord>,
        recovery_history: Vec<OperationRecord>,
    }

    fn split_brain_chain_fixture() -> SplitBrainChainFixture {
        let (mut evidence, _, recovery_history) = split_brain_recovery_fixture(true, true);
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = NETWORK_SPLIT_BRAIN_SCENARIO.to_string();
        config.duration = Duration::from_secs(120);
        config.workload = FaultWorkloadProfile::new(40, 2).expect("workload");
        let scenario = FaultScenario::from_config(&config).expect("scenario");
        let catalog = scenario_spec(&scenario.name).expect("catalog");
        let plan = FaultPlan::from_scenario(&scenario, catalog).expect("plan");
        let shape = ErasureSetShape::from_runtime_single_set(4, 1, &[1], &[4], 2)
            .expect("read quorum in both isolated pairs");
        let membership = ErasureSetMembership::from_runtime(
            &shape,
            evidence
                .pods
                .iter()
                .map(|pod| ErasureSetMember {
                    pod_name: pod.name.clone(),
                    server_endpoint: format!("http://{}.rustfs:9000", pod.name),
                    shard_ids: vec![format!("drive-{}", pod.name)],
                })
                .collect(),
        )
        .expect("runtime membership");
        let proof = TargetProof::from_plan(&config, &scenario, catalog, &plan, &evidence.run_id)
            .with_resolved_pod_proofs(evidence.pods.iter().map(|pod| {
                let mut proof = TargetResolvedPodProof::new(&pod.name, &pod.uid)
                    .with_ready(true)
                    .with_node(&pod.node);
                proof.rustfs_container_id = Some(pod.container_id.clone());
                proof
            }))
            .with_erasure_set_topology_proven(
                shape,
                ErasureSetHealth::from_runtime(4, 4, 0, 0).expect("health"),
                membership,
                "deployment-split",
                900,
            )
            .expect("topology proof");
        let spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &WorkloadPlan::seeded(42, 40, 2),
            &evidence.run_id,
            "bucket",
        );
        evidence.source_pod_names = evidence.pods[..2]
            .iter()
            .map(|pod| pod.name.clone())
            .collect();
        evidence.peer_pod_names = evidence.pods[2..]
            .iter()
            .map(|pod| pod.name.clone())
            .collect();
        let mut controller: Value = serde_yaml_ng::from_str(
            &chaos_mesh::NetworkChaosSpec::partition_between_rustfs_pods(
                &config.cluster,
                &evidence.chaos_namespace,
                &evidence.run_id,
                &evidence.scenario,
                config.duration,
                &evidence.source_pod_names,
                &evidence.peer_pod_names,
            )
            .expect("scoped partition")
            .manifest(),
        )
        .expect("manifest");
        controller["metadata"]["uid"] = serde_json::json!("split-controller-generation");
        let records = evidence
            .pods
            .iter()
            .enumerate()
            .map(|(index, pod)| {
                serde_json::json!({"id": format!("{}/{}", pod.namespace, pod.name),
                "selectorKey": if index < 2 { "." } else { ".Target" },
                "phase": "Injected", "injectedCount": 1})
            })
            .collect::<Vec<_>>();
        controller["status"] = serde_json::json!({"conditions": [
            {"type": "Selected", "status": "True"}, {"type": "AllInjected", "status": "True"}],
            "experiment": {"desiredPhase": "Run", "containerRecords": records}});
        let matrix = |started_at_ms, active| {
            evidence
                .pods
                .iter()
                .flat_map(|source| {
                    evidence
                        .pods
                        .iter()
                        .filter(move |target| source != *target)
                        .map(move |target| {
                            let blocked = active
                                && (source.name.as_str() < "rustfs-2")
                                    != (target.name.as_str() < "rustfs-2");
                            PodConnectivityObservation {
                                source: source.clone(),
                                target: target.clone(),
                                started_at_ms,
                                completed_at_ms: started_at_ms + 50,
                                exit_code: Some(if blocked { 28 } else { 0 }),
                                http_status: Some(if blocked { 0 } else { 200 }),
                                connect_seconds: Some(if blocked { 0.0 } else { 0.001 }),
                                remote_ip: (!blocked).then(|| target.pod_ip.clone()),
                                stdout: if blocked {
                                    "000\t0.000000\t".to_string()
                                } else {
                                    format!("200\t0.001000\t{}", target.pod_ip)
                                },
                                stderr: String::new(),
                            }
                        })
                })
                .collect::<Vec<_>>()
        };
        evidence.observations = [
            ObservationPhase::Baseline,
            ObservationPhase::Active,
            ObservationPhase::AfterWorkload,
            ObservationPhase::Restored,
        ]
        .into_iter()
        .enumerate()
        .map(|(index, phase)| {
            let active = matches!(
                phase,
                ObservationPhase::Active | ObservationPhase::AfterWorkload
            );
            let started_at_ms = (index as u64 + 1) * 1_000;
            PodFaultObservation {
                phase,
                started_at_ms,
                completed_at_ms: started_at_ms + 100,
                controller_before: active.then(|| controller.clone()),
                controller_after: active.then(|| controller.clone()),
                connectivity: matrix(started_at_ms, active),
                clocks: Vec::new(),
            }
        })
        .collect();
        let temp = tempfile::tempdir().expect("temp");
        let committed = Recorder::create(
            temp.path().join("committed.jsonl"),
            &evidence.scenario,
            &evidence.run_id,
        )
        .expect("committed recorder");
        let objects = (0..3)
            .map(|index| ObjectSpec::prepare_seeded(&evidence.run_id, index, 4, 42))
            .collect::<Vec<_>>();
        for object in &objects {
            let record = committed.begin(
                OperationKind::Put,
                "bucket",
                Some(object.spec.key.clone()),
                Some(object.spec.sha256.clone()),
                Some(4),
            );
            committed
                .finish(record, OperationOutcome::Ok, Some(200), None)
                .expect("committed PUT");
        }
        let mut history = committed.records();
        for (index, record) in history.iter_mut().enumerate() {
            record.started_at_ms = 100 + index as u64 * 10;
            record.ended_at_ms = record.started_at_ms + 1;
        }
        let sides = Recorder::create(
            temp.path().join("sides.jsonl"),
            &evidence.scenario,
            &evidence.run_id,
        )
        .expect("side recorder");
        sides.set_durability_cohort(DurabilityCohort::FaultActive);
        for index in 0..2 {
            let mut read_operation_ids = Vec::new();
            for object in &objects {
                let record = sides.begin(
                    OperationKind::Get,
                    "bucket",
                    Some(object.spec.key.clone()),
                    Some(object.spec.sha256.clone()),
                    Some(4),
                );
                read_operation_ids.push(
                    sides
                        .finish(record, OperationOutcome::Ok, Some(200), None)
                        .expect("committed GET")
                        .id,
                );
            }
            let object = ObjectSpec::prepare_write_probe(
                WriteProbeScope::SplitBrain,
                &evidence.run_id,
                index,
                4096,
                42,
            );
            let mut write = sides.begin(
                OperationKind::Put,
                "bucket",
                Some(object.spec.key),
                Some(object.spec.sha256),
                Some(object.spec.size_bytes),
            );
            write.mutation_max_attempts = Some(1);
            write.mutation_attempts = Some(1);
            let write = sides
                .finish(
                    write,
                    if index == 0 {
                        OperationOutcome::Timeout
                    } else {
                        OperationOutcome::Failed
                    },
                    if index == 0 { None } else { Some(503) },
                    None,
                )
                .expect("blocked PUT");
            let started_at_ms = 2_200 + index as u64 * 300;
            evidence.sides.push(SplitBrainSideObservation {
                pod: evidence.pods[index * 2].clone(),
                started_at_ms,
                completed_at_ms: started_at_ms + 100,
                read_operation_ids,
                write_operation_id: write.id,
                controller_before: controller.clone(),
                controller_after: controller.clone(),
                proof_completed_at_ms: started_at_ms + 200,
                connectivity_after: matrix(started_at_ms + 110, true),
            });
        }
        let mut side_history = sides.records();
        for (index, record) in side_history.iter_mut().enumerate() {
            record.started_at_ms = 2_210 + (index / 4) as u64 * 300 + (index % 4) as u64 * 10;
            record.ended_at_ms = record.started_at_ms + 1;
        }
        SplitBrainChainFixture {
            evidence,
            proof,
            spec,
            history,
            side_history,
            recovery_history,
        }
    }

    #[test]
    fn split_brain_complete_chain_distinguishes_blocked_writes_from_quorum_violations() {
        let mut fixture = split_brain_chain_fixture();
        fixture
            .evidence
            .validate(
                &fixture.proof,
                &fixture.spec,
                &fixture.history,
                &fixture.side_history,
            )
            .expect("complete isolated pairs with no ACK");
        assert!(
            fixture
                .evidence
                .validate_quorum_violation(
                    &fixture.proof,
                    &fixture.spec,
                    &fixture.history,
                    &fixture.side_history
                )
                .is_err()
        );
        fixture
            .evidence
            .validate_recovered_probes(&fixture.recovery_history, "bucket", 42)
            .expect("unconfirmed writes materialized with exact generated bytes");
        let write = fixture
            .side_history
            .iter_mut()
            .find(|record| record.kind == OperationKind::Put)
            .expect("side PUT");
        write.outcome = OperationOutcome::Ok;
        write.http_status = Some(200);
        assert!(
            fixture
                .evidence
                .validate(
                    &fixture.proof,
                    &fixture.spec,
                    &fixture.history,
                    &fixture.side_history
                )
                .is_err()
        );
        fixture
            .evidence
            .validate_quorum_violation(
                &fixture.proof,
                &fixture.spec,
                &fixture.history,
                &fixture.side_history,
            )
            .expect("ACK under the proved quorum cut");
        for kind in [
            OperationKind::Delete,
            OperationKind::CompleteMultipartUpload,
        ] {
            let mut wrong_kind = fixture.side_history.clone();
            wrong_kind
                .iter_mut()
                .find(|record| record.kind == OperationKind::Put)
                .expect("side PUT")
                .kind = kind;
            assert!(
                fixture
                    .evidence
                    .validate_quorum_violation(
                        &fixture.proof,
                        &fixture.spec,
                        &fixture.history,
                        &wrong_kind
                    )
                    .is_err()
            );
        }
        let mut wrong_selector = fixture.evidence.clone();
        wrong_selector.sides[0].controller_after["spec"]["selector"]["pods"] =
            serde_json::json!({fixture.evidence.namespace.clone(): ["rustfs-0"]});
        assert!(
            wrong_selector
                .validate_quorum_violation(
                    &fixture.proof,
                    &fixture.spec,
                    &fixture.history,
                    &fixture.side_history
                )
                .is_err()
        );
        let mut changed_generation = fixture.evidence.clone();
        changed_generation.sides[0].pod.container_id = "replacement-container".to_string();
        assert!(
            changed_generation
                .validate_quorum_violation(
                    &fixture.proof,
                    &fixture.spec,
                    &fixture.history,
                    &fixture.side_history
                )
                .is_err()
        );
        let mut wrong_reads = fixture.side_history.clone();
        wrong_reads[0].value_sha256 = Some("f".repeat(64));
        assert!(
            fixture
                .evidence
                .validate_quorum_violation(
                    &fixture.proof,
                    &fixture.spec,
                    &fixture.history,
                    &wrong_reads
                )
                .is_err()
        );
    }

    fn split_brain_recovery_fixture(
        present: bool,
        listed: bool,
    ) -> (PodFaultEvidence, Vec<OperationRecord>, Vec<OperationRecord>) {
        let (mut evidence, _, _) = clock_fixture();
        evidence.scenario = NETWORK_SPLIT_BRAIN_SCENARIO.to_string();
        evidence.run_id = "run-split".to_string();
        evidence.clock_workload_endpoint = None;
        evidence.offset_seconds = None;
        let temp = tempfile::tempdir().expect("temp");
        let writes = Recorder::create(
            temp.path().join("writes.jsonl"),
            &evidence.scenario,
            &evidence.run_id,
        )
        .expect("write recorder");
        writes.set_durability_cohort(DurabilityCohort::FaultActive);
        let objects = (0..2)
            .map(|index| {
                ObjectSpec::prepare_write_probe(
                    WriteProbeScope::SplitBrain,
                    &evidence.run_id,
                    index,
                    4096,
                    42,
                )
            })
            .collect::<Vec<_>>();
        for object in &objects {
            let mut record = writes.begin(
                OperationKind::Put,
                "bucket",
                Some(object.spec.key.clone()),
                Some(object.spec.sha256.clone()),
                Some(object.spec.size_bytes),
            );
            record.mutation_max_attempts = Some(1);
            record.mutation_attempts = Some(1);
            writes
                .finish(
                    record,
                    OperationOutcome::Timeout,
                    None,
                    Some("request timed out".to_string()),
                )
                .expect("timed out PUT");
        }
        let history = Recorder::create(
            temp.path().join("recovery.jsonl"),
            &evidence.scenario,
            &evidence.run_id,
        )
        .expect("recovery recorder");
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        let mut list = history.begin(
            OperationKind::List,
            "bucket",
            Some(WriteProbeScope::SplitBrain.key_prefix(&evidence.run_id)),
            None,
            None,
        );
        let keys = if listed {
            objects
                .iter()
                .map(|object| object.spec.key.clone())
                .collect()
        } else {
            Vec::new()
        };
        list.size_bytes = Some(keys.len());
        list.listed_keys = Some(keys);
        let list = history
            .finish(list, OperationOutcome::Ok, Some(200), None)
            .expect("LIST");
        let mut ids = Vec::new();
        for object in &objects {
            let read = history.begin(
                OperationKind::Get,
                "bucket",
                Some(object.spec.key.clone()),
                present.then(|| object.spec.sha256.clone()),
                present.then_some(object.spec.size_bytes),
            );
            let read = history
                .finish(
                    read,
                    if present {
                        OperationOutcome::Ok
                    } else {
                        OperationOutcome::NotFound
                    },
                    Some(if present { 200 } else { 404 }),
                    None,
                )
                .expect("GET");
            ids.push(read.id);
        }
        let records = history.records();
        evidence
            .observations
            .last_mut()
            .expect("restored")
            .completed_at_ms = list.started_at_ms.saturating_sub(1);
        evidence.probe_recovery = Some(SplitBrainProbeRecovery {
            started_at_ms: list.started_at_ms,
            completed_at_ms: records.last().expect("read").ended_at_ms,
            list_operation_id: list.id,
            read_operation_ids: ids,
        });
        (evidence, writes.records(), records)
    }

    #[test]
    fn split_brain_timeout_accepts_absent_or_exact_committed_probe_bytes_after_recovery() {
        for (present, listed) in [(false, false), (true, true), (true, false)] {
            let (evidence, writes, history) = split_brain_recovery_fixture(present, listed);
            for write in &writes {
                require_blocked_write(write).expect("single transmitted timeout");
                assert!(
                    !write
                        .key
                        .as_ref()
                        .expect("key")
                        .starts_with(&ObjectSpec::key_prefix(&evidence.run_id))
                );
            }
            evidence
                .validate_recovered_probes(&history, "bucket", 42)
                .expect("valid recovered unconfirmed write state");
        }
    }

    #[test]
    fn split_brain_recovery_rejects_wrong_bytes_foreign_keys_and_observed_object_loss() {
        let (evidence, _, history) = split_brain_recovery_fixture(true, true);
        let mut wrong_bytes = history.clone();
        wrong_bytes[1].value_sha256 = Some("f".repeat(64));
        assert!(
            evidence
                .validate_recovered_probes(&wrong_bytes, "bucket", 42)
                .is_err()
        );
        let mut foreign_key = history.clone();
        foreign_key[0]
            .listed_keys
            .as_mut()
            .expect("keys")
            .push(format!(
                "{}foreign",
                WriteProbeScope::SplitBrain.key_prefix(&evidence.run_id)
            ));
        foreign_key[0].size_bytes = Some(3);
        assert!(
            evidence
                .validate_recovered_probes(&foreign_key, "bucket", 42)
                .is_err()
        );
        let mut wrong_read_key = history;
        wrong_read_key[2].key = Some("another-run/foreign".to_string());
        assert!(
            evidence
                .validate_recovered_probes(&wrong_read_key, "bucket", 42)
                .is_err()
        );
        let (evidence, _, disappeared) = split_brain_recovery_fixture(false, true);
        assert!(
            evidence
                .validate_recovered_probes(&disappeared, "bucket", 42)
                .is_err()
        );
    }
}
