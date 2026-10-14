// Copyright 2026 RustFS Team
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

//! A run-owned IAM secret rotation with S3 history as the data oracle.

use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use futures::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    fault::{
        admin_runner::{
            AdminCancelOutcome, AdminCaseDriver, AdminWorkflowObservation, execute_admin_workflow,
            persist_admin_workflow,
        },
        checker::{self, CheckerReport},
        config::FaultTestConfig,
        events::RunEventStatus,
        history::{
            DurabilityCohort, OperationKind, OperationOutcome, OperationRecord, Recorder,
            validate_history_scope_and_order,
        },
        plan::{CredentialRotationExecutionPlan, ExecutionPlan},
        pods::{fixed_volume_container_ids, rustfs_pod_identities, rustfs_target_inventory},
        preflight::{PreflightCheck, PreflightPhase},
        recovery_health::{RECOVERY_HEALTH_ARTIFACT, RecoveryHealthBaseline, RecoveryHealthReport},
        reporting::{PodIdentity, ResponsibilityDomain},
        runner::{
            FaultRunContext, ensure_s3_access, initialize_fault_run, observe_recovery_health,
            s3_access, wait_for_ready_tenant, wait_for_stable_rustfs_pods, wait_for_tenant_s3,
            write_preflight_summary,
        },
        scenarios::{CREDENTIAL_ROTATION_MID_LOAD_SCENARIO, FaultScenario},
        shutdown::RunDeadline,
        workload::{ObjectSpec, S3WorkloadClient, execution::prefill_objects, sha256_hex},
    },
    framework::{
        artifacts::ArtifactCollector,
        kubectl::Kubectl,
        port_forward::{PortForwardGuard, PortForwardSpec},
        resources,
    },
    rustfs::{
        RustfsAdminTransport, SecretString,
        identity_admin::{RustfsIdentityAdminClient, RustfsIdentityInventory},
    },
};

pub(crate) const CREDENTIAL_ROTATION_ARTIFACT: &str = "credential-rotation.json";
const ROTATION_PATH: &str = "/rustfs/admin/v3/set-user-secret-key";
const PROPAGATION_POLL_INTERVAL: Duration = Duration::from_millis(100);
const CANCELLATION_CLEANUP_TIMEOUT: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialIdentityProof {
    pub principal_sha256: String,
    pub credential_sha256: String,
}

#[derive(Debug, Clone)]
struct RotationCredential {
    access_key: SecretString,
    secret_key: SecretString,
}

impl RotationCredential {
    fn generated(access_key: &str) -> Result<Self> {
        let nonce = format!("{}:{}", Uuid::new_v4(), Uuid::new_v4());
        Ok(Self {
            access_key: SecretString::new(access_key)?,
            secret_key: SecretString::new(sha256_hex(nonce.as_bytes()))?,
        })
    }
    fn access_key(&self) -> &str {
        self.access_key.expose()
    }
    fn secret_key(&self) -> &str {
        self.secret_key.expose()
    }
    fn artifact(&self) -> CredentialIdentityProof {
        CredentialIdentityProof {
            principal_sha256: sha256_hex(self.access_key().as_bytes()),
            credential_sha256: sha256_hex(self.secret_key().as_bytes()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SecretRotationReceipt {
    pub method: String,
    pub path: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    /// Next S3 event at each admin boundary. Sampling preserves the recorder's
    /// complete, consecutive sequence of S3 request starts and completions.
    pub started_sequence: u64,
    pub ended_sequence: u64,
    pub accepted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodCredentialProof {
    pub pod_name: String,
    pub pod_uid: String,
    pub old_operation_id: String,
    pub new_operation_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialCleanupEvidence {
    pub attempted: bool,
    pub started_at_ms: Option<u64>,
    pub removal_acknowledged_at_ms: Option<u64>,
    pub pods: Vec<PodIdentityCleanupProof>,
    pub user_absent: bool,
    pub policy_absent: bool,
    pub completed_at_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialPodGeneration {
    pub pod_name: String,
    pub pod_uid: String,
    pub rustfs_container_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodGenerationReceipt {
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub response_body_sha256: String,
    // Only metadata and runtime status are retained; Pod environment values
    // can include credentials unrelated to the run-owned identity.
    pub response: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct IdentityInventoryReceipt {
    pub method: String,
    pub path: String,
    pub started_at_ms: u64,
    pub ended_at_ms: u64,
    pub http_status: u16,
    pub request_id: Option<String>,
    pub response_body_sha256: String,
    pub name_sha256: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialCleanupAuthReceipt {
    pub credential: CredentialIdentityProof,
    pub operation: OperationRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PodIdentityCleanupProof {
    pub pod: CredentialPodGeneration,
    pub endpoint: String,
    pub port_forward_command: String,
    pub before: PodGenerationReceipt,
    pub users: IdentityInventoryReceipt,
    pub policies: IdentityInventoryReceipt,
    pub old_auth: CredentialCleanupAuthReceipt,
    pub new_auth: CredentialCleanupAuthReceipt,
    pub after: PodGenerationReceipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CredentialRotationEvidence {
    pub schema_version: u8,
    pub scenario: String,
    pub run_id: String,
    pub bucket: String,
    pub context: String,
    pub namespace: String,
    pub tenant: String,
    pub tenant_uid: String,
    pub deployment_id: String,
    pub old_credential: CredentialIdentityProof,
    pub new_credential: CredentialIdentityProof,
    pub identity_absent_before_create: bool,
    pub policy_absent_before_create: bool,
    pub policy_sha256: String,
    pub policy_name_sha256: String,
    pub pods_before: Vec<PodIdentity>,
    pub pod_generations_before: Vec<CredentialPodGeneration>,
    pub old_prefill_operation_ids: Vec<String>,
    pub old_workload_operation_ids: Vec<String>,
    pub rotation: Option<SecretRotationReceipt>,
    pub pod_auth: Vec<PodCredentialProof>,
    pub new_put_operation_id: Option<String>,
    pub new_get_operation_id: Option<String>,
    pub new_overwrite_operation_id: Option<String>,
    pub new_delete_operation_id: Option<String>,
    pub new_deleted_get_operation_id: Option<String>,
    pub verified: bool,
    pub cleanup: CredentialCleanupEvidence,
}

impl CredentialRotationEvidence {
    pub(crate) fn validate_history(&self, history: &[OperationRecord]) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.scenario == CREDENTIAL_ROTATION_MID_LOAD_SCENARIO,
            "credential rotation schema or scenario is invalid"
        );
        ensure!(
            [
                &self.run_id,
                &self.bucket,
                &self.context,
                &self.namespace,
                &self.tenant,
                &self.tenant_uid,
                &self.deployment_id
            ]
            .iter()
            .all(|value| !value.trim().is_empty()),
            "credential rotation lacks run or target identity"
        );
        ensure!(
            self.old_credential.principal_sha256.len() == 64
                && self.new_credential.principal_sha256 == self.old_credential.principal_sha256
                && self.old_credential.credential_sha256.len() == 64
                && self.new_credential.credential_sha256.len() == 64
                && self.old_credential.credential_sha256 != self.new_credential.credential_sha256,
            "credential aliases do not prove a distinct old/new run-owned identity"
        );
        ensure!(
            self.identity_absent_before_create
                && self.policy_absent_before_create
                && is_sha256(&self.policy_name_sha256)
                && self.policy_sha256 == sha256_hex(bucket_policy(&self.bucket)?.as_bytes()),
            "credential fixture ownership or bucket policy proof is invalid"
        );
        validate_history_scope_and_order(history, &self.scenario, &self.run_id, &self.bucket)?;
        let by_id = history
            .iter()
            .map(|record| (record.id.as_str(), record))
            .collect::<BTreeMap<_, _>>();
        let record = |id: &str| -> Result<&OperationRecord> {
            by_id
                .get(id)
                .copied()
                .with_context(|| format!("rotation history reference {id} is absent"))
        };
        let rotation = self
            .rotation
            .as_ref()
            .context("secret rotation request receipt is absent")?;
        ensure!(
            rotation.method == "PUT"
                && rotation.path == ROTATION_PATH
                && rotation.accepted
                && rotation.started_at_ms > 0
                && rotation.ended_at_ms >= rotation.started_at_ms
                && rotation.started_sequence > 0
                && rotation.ended_sequence >= rotation.started_sequence,
            "secret rotation lacks a successful bounded request receipt"
        );
        ensure!(
            !self.old_prefill_operation_ids.is_empty(),
            "old credential has no pre-rotation writes"
        );
        ensure!(
            !self.old_workload_operation_ids.is_empty(),
            "rotation has no old-credential workload"
        );
        let mut referenced = BTreeSet::new();
        for id in &self.old_prefill_operation_ids {
            ensure!(
                referenced.insert(id),
                "rotation contains duplicate history references"
            );
            let write = record(id)?;
            require_committed_put(write)?;
            ensure!(
                write
                    .ended_sequence
                    .is_some_and(|sequence| sequence < rotation.started_sequence)
                    && write.ended_at_ms <= rotation.started_at_ms
                    && write.durability_cohort == Some(DurabilityCohort::PreFault),
                "old credential prefill was not committed before secret rotation"
            );
        }
        let mut overlapping = 0;
        for id in &self.old_workload_operation_ids {
            ensure!(
                referenced.insert(id),
                "rotation contains duplicate history references"
            );
            let write = record(id)?;
            ensure!(
                write.kind == OperationKind::Put
                    && write.durability_cohort == Some(DurabilityCohort::FaultActive),
                "old-credential workload reference is not an active-window PUT"
            );
            if write.outcome == OperationOutcome::Ok {
                require_committed_put(write)?;
            } else {
                ensure!(
                    is_auth_rejection(write),
                    "old-credential workload contains a non-auth failure"
                );
            }
            if write
                .started_sequence
                .is_some_and(|sequence| sequence < rotation.ended_sequence)
                && write
                    .ended_sequence
                    .is_some_and(|sequence| sequence >= rotation.started_sequence)
                && write.started_at_ms <= rotation.ended_at_ms
                && write.ended_at_ms >= rotation.started_at_ms
            {
                overlapping += 1;
            }
        }
        ensure!(
            overlapping > 0,
            "no recorded S3 request overlaps the actual secret rotation request"
        );
        let expected_pods = self
            .pods_before
            .iter()
            .map(|pod| (&pod.name, &pod.uid))
            .collect::<BTreeSet<_>>();
        ensure!(
            !expected_pods.is_empty() && expected_pods.len() == self.pods_before.len(),
            "credential rotation has an empty or duplicate Pod target set"
        );
        self.validate_original_generations()?;
        let observed_pods = self
            .pod_auth
            .iter()
            .map(|proof| (&proof.pod_name, &proof.pod_uid))
            .collect::<BTreeSet<_>>();
        ensure!(
            observed_pods == expected_pods && self.pod_auth.len() == expected_pods.len(),
            "old/new authentication does not cover the exact RustFS Pod set"
        );
        let baseline = record(&self.old_prefill_operation_ids[0])?;
        for proof in &self.pod_auth {
            ensure!(
                referenced.insert(&proof.old_operation_id)
                    && referenced.insert(&proof.new_operation_id),
                "per-Pod authentication reuses a history reference"
            );
            let old = record(&proof.old_operation_id)?;
            let new = record(&proof.new_operation_id)?;
            ensure!(
                old.kind == OperationKind::Get
                    && is_auth_rejection(old)
                    && new.kind == OperationKind::Get
                    && new.outcome == OperationOutcome::Ok
                    && old.key == baseline.key
                    && new.key == baseline.key
                    && new.value_sha256 == baseline.value_sha256
                    && new.size_bytes == baseline.size_bytes
                    && [old, new].iter().all(|operation| {
                        operation
                            .started_sequence
                            .is_some_and(|sequence| sequence >= rotation.ended_sequence)
                            && operation.started_at_ms >= rotation.ended_at_ms
                            && operation.durability_cohort == Some(DurabilityCohort::PostRecovery)
                    }),
                "per-Pod old/new authentication proof is invalid or predates rotation"
            );
        }
        let new_put = record(
            self.new_put_operation_id
                .as_deref()
                .context("new-credential PUT proof is absent")?,
        )?;
        let new_get = record(
            self.new_get_operation_id
                .as_deref()
                .context("new-credential GET proof is absent")?,
        )?;
        let overwrite = record(
            self.new_overwrite_operation_id
                .as_deref()
                .context("new-credential overwrite proof is absent")?,
        )?;
        let delete = record(
            self.new_delete_operation_id
                .as_deref()
                .context("new-credential DELETE proof is absent")?,
        )?;
        let deleted_get = record(
            self.new_deleted_get_operation_id
                .as_deref()
                .context("delete visibility proof is absent")?,
        )?;
        require_committed_put(new_put)?;
        require_committed_put(overwrite)?;
        ensure!(
            new_get.kind == OperationKind::Get
                && new_get.outcome == OperationOutcome::Ok
                && new_get.key == new_put.key
                && new_get.value_sha256 == new_put.value_sha256
                && new_get.size_bytes == new_put.size_bytes
                && overwrite.key == new_put.key
                && overwrite.version_id != new_put.version_id
                && overwrite.value_sha256 != new_put.value_sha256
                && delete.kind == OperationKind::Delete
                && delete.outcome == OperationOutcome::Ok
                && delete.key == new_put.key
                && delete.is_delete_marker == Some(true)
                && delete
                    .version_id
                    .as_ref()
                    .is_some_and(|value| !value.is_empty())
                && deleted_get.kind == OperationKind::Get
                && deleted_get.outcome == OperationOutcome::NotFound
                && deleted_get.key == new_put.key,
            "new-credential mutation and version/delete-marker proof is invalid"
        );
        let ordered = [new_put, new_get, overwrite, delete, deleted_get];
        ensure!(
            ordered.iter().all(
                |operation| operation.durability_cohort == Some(DurabilityCohort::PostRecovery)
            ) && ordered[0]
                .started_sequence
                .is_some_and(|sequence| sequence >= rotation.ended_sequence)
                && ordered.windows(2).all(|pair| pair[0]
                    .ended_sequence
                    .zip(pair[1].started_sequence)
                    .is_some_and(|(ended, started)| ended < started)),
            "new-credential operation proofs have invalid history order"
        );
        Ok(())
    }

    fn validate_original_generations(&self) -> Result<()> {
        let mut names = BTreeSet::new();
        let mut uids = BTreeSet::new();
        let mut containers = BTreeSet::new();
        for pod in &self.pod_generations_before {
            ensure!(
                !pod.pod_name.trim().is_empty()
                    && !pod.pod_uid.trim().is_empty()
                    && !pod.rustfs_container_id.trim().is_empty()
                    && names.insert(&pod.pod_name)
                    && uids.insert(&pod.pod_uid)
                    && containers.insert(&pod.rustfs_container_id),
                "credential rotation has an empty or duplicate original Pod generation"
            );
        }
        ensure!(
            !names.is_empty()
                && self.pods_before.len() == names.len()
                && self
                    .pod_generations_before
                    .iter()
                    .map(|pod| (&pod.pod_name, &pod.pod_uid))
                    .collect::<BTreeSet<_>>()
                    == self
                        .pods_before
                        .iter()
                        .map(|pod| (&pod.name, &pod.uid))
                        .collect::<BTreeSet<_>>(),
            "credential rotation original container generations do not cover the Pod set"
        );
        Ok(())
    }

    fn validate_cleanup_pods(&self, history: &[OperationRecord]) -> Result<()> {
        self.validate_original_generations()?;
        let started = self
            .cleanup
            .started_at_ms
            .context("IAM cleanup has no start receipt")?;
        let removed = self
            .cleanup
            .removal_acknowledged_at_ms
            .context("IAM cleanup has no acknowledged removal receipt")?;
        ensure!(
            self.cleanup.attempted
                && started > 0
                && removed >= started
                && history.iter().all(|record| record.ended_at_ms <= started),
            "IAM cleanup removal interval is invalid"
        );
        ensure!(
            self.cleanup.pods.len() == self.pod_generations_before.len(),
            "IAM cleanup does not cover every original Pod generation"
        );
        let probe_key = cleanup_probe_key(self, history);
        let mut seen = BTreeSet::new();
        let mut auth_history = Vec::new();
        for proof in &self.cleanup.pods {
            ensure!(
                seen.insert(&proof.pod.pod_name),
                "IAM cleanup repeats a Pod"
            );
            self.validate_cleanup_pod(proof, &probe_key, removed)?;
            auth_history.extend([
                proof.old_auth.operation.clone(),
                proof.new_auth.operation.clone(),
            ]);
        }
        validate_history_scope_and_order(&auth_history, &self.scenario, &self.run_id, &self.bucket)
    }

    fn validate_cleanup_pod(
        &self,
        proof: &PodIdentityCleanupProof,
        probe_key: &str,
        removed_at_ms: u64,
    ) -> Result<()> {
        ensure!(
            self.pod_generations_before.contains(&proof.pod),
            "IAM cleanup contains a foreign or changed Pod generation"
        );
        let endpoint =
            reqwest::Url::parse(&proof.endpoint).context("invalid IAM cleanup endpoint")?;
        let port = endpoint
            .port()
            .context("IAM cleanup endpoint has no explicit port")?;
        ensure!(
            endpoint.scheme() == "http"
                && endpoint.host_str() == Some("127.0.0.1")
                && endpoint.path() == "/"
                && endpoint.username().is_empty()
                && endpoint.password().is_none()
                && endpoint.query().is_none()
                && endpoint.fragment().is_none()
                && port > 0
                && proof.port_forward_command
                    == format!(
                        "kubectl --context {} -n {} port-forward pod/{} {port}:9000",
                        self.context, self.namespace, proof.pod.pod_name
                    ),
            "IAM cleanup is not bound to the original Pod's direct endpoint"
        );
        for capture in [&proof.before, &proof.after] {
            ensure!(
                capture.started_at_ms >= removed_at_ms
                    && capture.ended_at_ms >= capture.started_at_ms
                    && is_sha256(&capture.response_body_sha256)
                    && pod_generation(&capture.response, &self.namespace, &self.tenant)?
                        == proof.pod,
                "IAM cleanup Pod UID or RustFS container generation changed"
            );
        }
        let inventories = [
            (
                &proof.users,
                "/rustfs/admin/v3/list-users",
                &self.old_credential.principal_sha256,
            ),
            (
                &proof.policies,
                "/rustfs/admin/v3/list-canned-policies",
                &self.policy_name_sha256,
            ),
        ];
        for (receipt, path, identity) in inventories {
            ensure!(
                receipt.method == "GET"
                    && receipt.path == path
                    && receipt.http_status == 200
                    && receipt.started_at_ms >= proof.before.ended_at_ms
                    && receipt.ended_at_ms >= receipt.started_at_ms
                    && receipt.ended_at_ms <= proof.after.started_at_ms
                    && is_sha256(&receipt.response_body_sha256)
                    && receipt.name_sha256.iter().all(|name| is_sha256(name))
                    && receipt.name_sha256.iter().collect::<BTreeSet<_>>().len()
                        == receipt.name_sha256.len()
                    && !receipt.name_sha256.contains(identity),
                "IAM cleanup found a stale user/policy cache or invalid inventory response"
            );
        }
        for (auth, credential) in [
            (&proof.old_auth, &self.old_credential),
            (&proof.new_auth, &self.new_credential),
        ] {
            let record = &auth.operation;
            ensure!(
                &auth.credential == credential
                    && record.scenario == self.scenario
                    && record.run_id.as_deref() == Some(self.run_id.as_str())
                    && record.bucket == self.bucket
                    && record.key.as_deref() == Some(probe_key)
                    && record.kind == OperationKind::Get
                    && record.version_id.is_none()
                    && record.range.is_none()
                    && record.started_at_ms >= proof.before.ended_at_ms
                    && record.ended_at_ms >= record.started_at_ms
                    && record.ended_at_ms <= proof.after.started_at_ms
                    && is_auth_rejection(record),
                "IAM cleanup lacks rejected old/new credentials on the original Pod"
            );
        }
        Ok(())
    }
}

pub(crate) fn validate_credential_rotation_evidence(
    evidence: &CredentialRotationEvidence,
    history: &[OperationRecord],
    checker: &CheckerReport,
) -> Result<()> {
    evidence.validate_history(history)?;
    ensure!(
        evidence.verified
            && evidence.cleanup.attempted
            && evidence.cleanup.user_absent
            && evidence.cleanup.policy_absent
            && evidence
                .cleanup
                .completed_at_ms
                .is_some_and(|value| value > 0),
        "credential rotation lacks successful verification or IAM fixture cleanup"
    );
    evidence.validate_cleanup_pods(history)?;
    ensure!(
        evidence.cleanup.pods.iter().all(|proof| evidence
            .cleanup
            .completed_at_ms
            .is_some_and(|completed| completed >= proof.after.ended_at_ms)),
        "IAM cleanup completion predates a Pod response receipt"
    );
    ensure!(
        checker.scenario == evidence.scenario
            && checker.run_id == evidence.run_id
            && checker.versioning_expected
            && checker.expected_committed_versions > 0
            && checker.expected_live_objects > 0,
        "credential rotation checker lacks the exact nonempty versioned run model"
    );
    ensure!(
        checker.failed_writes_materialized.is_empty(),
        "authentication-rejected old-credential writes became visible"
    );
    checker.require_success()?;
    checker::validate_checker_audit_against_history(checker, history)
}

fn require_committed_put(record: &OperationRecord) -> Result<()> {
    ensure!(
        record.kind == OperationKind::Put
            && record.outcome == OperationOutcome::Ok
            && record
                .version_id
                .as_ref()
                .is_some_and(|value| !value.is_empty())
            && record
                .value_sha256
                .as_ref()
                .is_some_and(|value| value.len() == 64)
            && record.size_bytes.is_some(),
        "rotation PUT lacks committed bytes or version identity"
    );
    Ok(())
}

fn is_auth_rejection(record: &OperationRecord) -> bool {
    record.outcome == OperationOutcome::Failed && matches!(record.http_status, Some(401 | 403))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn cleanup_probe_key(evidence: &CredentialRotationEvidence, history: &[OperationRecord]) -> String {
    history
        .iter()
        .find(|record| {
            evidence.old_prefill_operation_ids.first() == Some(&record.id)
                || (evidence.old_prefill_operation_ids.is_empty()
                    && record.kind == OperationKind::Put
                    && record.outcome == OperationOutcome::Ok)
        })
        .and_then(|record| record.key.clone())
        .unwrap_or_else(|| ObjectSpec::seeded_key(&evidence.run_id, 0))
}

fn pod_generation(
    response: &serde_json::Value,
    namespace: &str,
    tenant: &str,
) -> Result<CredentialPodGeneration> {
    let text = |path: &str| -> Result<String> {
        response
            .pointer(path)
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .map(str::to_string)
            .with_context(|| format!("IAM cleanup Pod response lacks {path}"))
    };
    ensure!(
        text("/metadata/namespace")? == namespace
            && text("/metadata/labels/rustfs.tenant")? == tenant
            && crate::fault::pods::pod_is_ready(response),
        "IAM cleanup Pod is unready or belongs to another namespace/Tenant"
    );
    let statuses = response
        .pointer("/status/containerStatuses")
        .and_then(serde_json::Value::as_array)
        .context("IAM cleanup Pod lacks container status")?;
    let mut rustfs = statuses
        .iter()
        .filter(|status| status.get("name").and_then(serde_json::Value::as_str) == Some("rustfs"));
    let status = rustfs
        .next()
        .context("IAM cleanup Pod lacks RustFS container")?;
    ensure!(
        rustfs.next().is_none()
            && status
                .pointer("/state/running")
                .is_some_and(serde_json::Value::is_object),
        "IAM cleanup RustFS container is not uniquely running"
    );
    let id = status
        .get("containerID")
        .and_then(serde_json::Value::as_str)
        .filter(|id| !id.trim().is_empty())
        .context("IAM cleanup Pod lacks RustFS container ID")?;
    Ok(CredentialPodGeneration {
        pod_name: text("/metadata/name")?,
        pod_uid: text("/metadata/uid")?,
        rustfs_container_id: id.to_string(),
    })
}

fn bucket_policy(bucket: &str) -> Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["s3:*"],
            "Resource": [format!("arn:aws:s3:::{bucket}"), format!("arn:aws:s3:::{bucket}/*")]}]
    }))?)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(1)
        .max(1)
}

struct RotationState {
    // The identity cleanup guard must run while the transport is reachable.
    identity_guard: Option<IdentityCleanupGuard>,
    port_forward: Option<PortForwardGuard>,
    admin: Option<Arc<RustfsIdentityAdminClient>>,
    old_s3: Option<S3WorkloadClient>,
    new_s3: Option<S3WorkloadClient>,
    baseline: Option<RecoveryHealthBaseline>,
    operation_deadline: Option<Instant>,
    finished: bool,
}

struct LiveCredentialRotationDriver {
    config: FaultTestConfig,
    collector: ArtifactCollector,
    scenario: FaultScenario,
    plan: CredentialRotationExecutionPlan,
    context: FaultRunContext,
    deadline: RunDeadline,
    old: RotationCredential,
    new: RotationCredential,
    policy_name: String,
    evidence: Arc<Mutex<CredentialRotationEvidence>>,
    state: tokio::sync::Mutex<RotationState>,
}

impl LiveCredentialRotationDriver {
    fn new(
        config: &FaultTestConfig,
        collector: &ArtifactCollector,
        scenario: &FaultScenario,
        execution_plan: &ExecutionPlan,
        plan: &CredentialRotationExecutionPlan,
        run_id: &str,
        deadline: RunDeadline,
    ) -> Result<Self> {
        ensure!(
            config.workload_versioning && scenario.object_count >= 4,
            "credential rotation requires versioning and at least four objects"
        );
        let context = initialize_fault_run(config, collector, scenario, execution_plan, run_id)?;
        let access_key = format!("rotation-{}", Uuid::new_v4().simple());
        let old = RotationCredential::generated(&access_key)?;
        let new = RotationCredential::generated(&access_key)?;
        ensure!(
            old.secret_key() != new.secret_key(),
            "generated secrets must differ"
        );
        let (admin_access, admin_secret) = resources::test_credentials();
        collector.redact_secrets(&[
            &access_key,
            old.secret_key(),
            new.secret_key(),
            admin_access,
            admin_secret,
        ])?;
        context.history.redact_secrets(&[
            &access_key,
            old.secret_key(),
            new.secret_key(),
            admin_access,
            admin_secret,
        ])?;
        let policy_name = format!("rotation-policy-{}", Uuid::new_v4().simple());
        let evidence = CredentialRotationEvidence {
            schema_version: 1,
            scenario: scenario.name.clone(),
            run_id: run_id.to_string(),
            bucket: context.bucket.clone(),
            context: config.cluster.context.clone(),
            namespace: config.cluster.test_namespace.clone(),
            tenant: config.cluster.tenant_name.clone(),
            tenant_uid: String::new(),
            deployment_id: String::new(),
            old_credential: old.artifact(),
            new_credential: new.artifact(),
            identity_absent_before_create: false,
            policy_absent_before_create: false,
            policy_sha256: sha256_hex(bucket_policy(&context.bucket)?.as_bytes()),
            policy_name_sha256: sha256_hex(policy_name.as_bytes()),
            pods_before: Vec::new(),
            pod_generations_before: Vec::new(),
            old_prefill_operation_ids: Vec::new(),
            old_workload_operation_ids: Vec::new(),
            rotation: None,
            pod_auth: Vec::new(),
            new_put_operation_id: None,
            new_get_operation_id: None,
            new_overwrite_operation_id: None,
            new_delete_operation_id: None,
            new_deleted_get_operation_id: None,
            verified: false,
            cleanup: CredentialCleanupEvidence::default(),
        };
        Ok(Self {
            config: config.clone(),
            collector: collector.clone(),
            scenario: scenario.clone(),
            plan: plan.clone(),
            context,
            deadline,
            old,
            new,
            policy_name,
            evidence: Arc::new(Mutex::new(evidence)),
            state: tokio::sync::Mutex::new(RotationState {
                identity_guard: None,
                port_forward: None,
                admin: None,
                old_s3: None,
                new_s3: None,
                baseline: None,
                operation_deadline: None,
                finished: false,
            }),
        })
    }

    fn evidence(&self) -> std::sync::MutexGuard<'_, CredentialRotationEvidence> {
        self.evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn persist(&self) -> Result<()> {
        write_evidence(&self.collector, self.scenario.case_name, &self.evidence)
    }

    fn redact(&self, error: anyhow::Error) -> anyhow::Error {
        anyhow!(
            self.collector
                .redact_text(&format!("{error:#}"))
                .into_owned()
        )
    }

    async fn preserve<T>(&self, result: Result<T>) -> Result<T> {
        let result = result.map_err(|error| self.redact(error));
        let persisted = self.persist();
        match (result, persisted) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Err(error), Err(persisted)) => {
                Err(error.context(format!("persist rotation evidence: {persisted:#}")))
            }
        }
    }

    async fn prepare_inner(&self) -> Result<()> {
        crate::fault::runner::access::prepare_fault_fixture(
            &self.config.cluster,
            self.context.spec.isolation,
            1,
        )?;
        let tenant = wait_for_ready_tenant(&self.config.cluster).await?;
        let tenant_uid = tenant.metadata.uid.context("rotation Tenant has no UID")?;
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let inventory = rustfs_target_inventory(&self.config.cluster, false, false)?;
        let containers = fixed_volume_container_ids(
            &inventory.pod_proofs,
            &inventory
                .identities
                .iter()
                .map(|pod| pod.name.clone())
                .collect(),
        )?;
        let generations = inventory
            .identities
            .iter()
            .map(|pod| CredentialPodGeneration {
                pod_name: pod.name.clone(),
                pod_uid: pod.uid.clone(),
                rustfs_container_id: containers[&pod.name].clone(),
            })
            .collect();
        let (endpoint, forward) = s3_access(&self.config)?;
        self.state.lock().await.port_forward = forward;
        {
            let mut state = self.state.lock().await;
            ensure_s3_access(&mut state.port_forward, &self.config.cluster, &endpoint).await?;
        }
        let (admin_access, admin_secret) = resources::test_credentials();
        let admin = Arc::new(RustfsIdentityAdminClient::from_transport(
            RustfsAdminTransport::new(
                &endpoint,
                "us-east-1",
                admin_access,
                admin_secret,
                None,
                "s3chaos-fault-identity",
            )?,
        ));
        let layout =
            crate::rustfs::read_erasure_layout(&endpoint, "us-east-1", admin_access, admin_secret)
                .await?;
        ensure!(
            admin
                .users_with_prefix(self.old.access_key())
                .await?
                .is_empty()
                && admin
                    .policies_with_prefix(&self.policy_name)
                    .await?
                    .is_empty(),
            "generated IAM fixture already exists"
        );
        {
            let mut evidence = self.evidence();
            evidence.tenant_uid = tenant_uid;
            evidence.deployment_id = layout.deployment_id.clone();
            evidence.pods_before = inventory.identities;
            evidence.pod_generations_before = generations;
            evidence.validate_original_generations()?;
            evidence.identity_absent_before_create = true;
            evidence.policy_absent_before_create = true;
        }
        self.persist()?;
        // Arm before the first mutation: losing a create response still owns
        // this unique, previously absent identity and requires removal.
        let guard = IdentityCleanupGuard {
            port: Arc::new(LiveIdentityCleanupPort {
                config: self.config.clone(),
                admin: admin.clone(),
                old: self.old.clone(),
                new: self.new.clone(),
                policy_name: self.policy_name.clone(),
                bucket: self.context.bucket.clone(),
            }),
            history: self.context.history.clone(),
            timeout: self
                .config
                .cluster
                .timeout
                .min(CANCELLATION_CLEANUP_TIMEOUT),
            collector: self.collector.clone(),
            case_name: self.scenario.case_name,
            evidence: self.evidence.clone(),
            armed: true,
        };
        {
            let mut state = self.state.lock().await;
            state.admin = Some(admin.clone());
            state.identity_guard = Some(guard);
        }
        admin
            .create_user(self.old.access_key(), self.old.secret_key())
            .await?;
        admin
            .create_policy(&self.policy_name, &bucket_policy(&self.context.bucket)?)
            .await?;
        admin
            .attach_policy(&self.policy_name, self.old.access_key(), false)
            .await?;
        ensure!(
            admin
                .policy_attached(&self.policy_name, self.old.access_key(), false)
                .await?,
            "run-owned bucket policy was not attached"
        );
        let root = S3WorkloadClient::new_without_retries(
            &endpoint,
            &self.context.bucket,
            admin_access,
            admin_secret,
            self.config.request_timeout,
        )
        .await?;
        ensure!(
            root.create_bucket(&self.context.history).await? == OperationOutcome::Ok
                && root.enable_bucket_versioning(&self.context.history).await?
                    == OperationOutcome::Ok,
            "rotation bucket creation or versioning failed"
        );
        let old_s3 = self
            .client(&endpoint, &self.old, self.config.request_timeout)
            .await?;
        let new_s3 = self
            .client(&endpoint, &self.new, self.config.request_timeout)
            .await?;
        let baseline = RecoveryHealthBaseline::from_layout(&layout, now_ms())?;
        self.context.events.record(
            "recovery-health-baseline",
            RunEventStatus::Succeeded,
            "healthy RustFS layout captured before credential rotation",
            Some(serde_json::to_value(&baseline)?),
        )?;
        prefill_objects(
            &old_s3,
            &self.context.history,
            &self.context.run_id,
            &self.context.workload_plan,
            self.scenario.prefill_count(),
            self.config.prefill_concurrency,
            self.config.workload_directory_marker_percent,
        )
        .await?;
        for write in self
            .context
            .history
            .records()
            .iter()
            .filter(|record| record.kind == OperationKind::Put)
        {
            require_committed_put(write)?;
            self.evidence()
                .old_prefill_operation_ids
                .push(write.id.clone());
        }
        {
            let mut state = self.state.lock().await;
            state.old_s3 = Some(old_s3);
            state.new_s3 = Some(new_s3);
            state.baseline = Some(baseline);
        }
        write_preflight_summary(
            &self.collector,
            &self.scenario,
            &self.config,
            &self.context.run_id,
            &[PreflightPhase::new(
                "credential-rotation-fixture",
                vec![PreflightCheck::passed(
                    "run-owned-identity",
                    "fresh Tenant, absent generated IAM identity, bucket-limited policy, versioning and old-secret writes proven",
                    ResponsibilityDomain::Harness,
                )],
            )],
        )?;
        Ok(())
    }

    async fn client(
        &self,
        endpoint: &str,
        credential: &RotationCredential,
        request_timeout: Duration,
    ) -> Result<S3WorkloadClient> {
        S3WorkloadClient::new_without_retries(
            endpoint,
            &self.context.bucket,
            credential.access_key(),
            credential.secret_key(),
            request_timeout,
        )
        .await
    }

    async fn run_workload_inner(&self) -> Result<()> {
        let (old, admin, operation_deadline) = {
            let state = self.state.lock().await;
            (
                state.old_s3.clone().context("old client is not prepared")?,
                state
                    .admin
                    .clone()
                    .context("admin client is not prepared")?,
                state
                    .operation_deadline
                    .context("rotation operation was not started")?,
            )
        };
        self.context.history.mark_fault_active_now();
        self.context.events.record(
            "credential-rotation",
            RunEventStatus::Started,
            "rotating a run-owned IAM secret during bounded S3 PUT requests",
            None,
        )?;
        let old = old.with_mutation_deadline(operation_deadline);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let workload = async {
            // join! polls this future through the first pending S3 send before
            // the rotation future can consume this notification.
            let _ = started_tx.send(());
            stream::iter(self.scenario.prefill_count()..self.scenario.object_count)
                .map(|index| {
                    let old = &old;
                    async move {
                        self.deadline.check()?;
                        let object = ObjectSpec::prepare_seeded(
                            &self.context.run_id,
                            index,
                            self.context.workload_plan.size_at(index),
                            self.context.workload_plan.seed,
                        );
                        let result = old
                            .put_object_record(&object, &self.context.history)
                            .await?;
                        self.evidence()
                            .old_workload_operation_ids
                            .push(result.id.clone());
                        Ok::<_, anyhow::Error>(result)
                    }
                })
                .buffer_unordered(self.context.workload_plan.concurrency)
                .collect::<Vec<_>>()
                .await
        };
        let rotation = async {
            started_rx.await.context("S3 workload did not begin")?;
            let mut receipt = SecretRotationReceipt {
                method: "PUT".to_string(),
                path: ROTATION_PATH.to_string(),
                started_at_ms: now_ms(),
                ended_at_ms: 0,
                started_sequence: self.context.history.next_event_sequence(),
                ended_sequence: 0,
                accepted: false,
            };
            self.evidence().rotation = Some(receipt.clone());
            let result = tokio::time::timeout_at(
                operation_deadline,
                admin.set_user_secret_key(self.new.access_key(), self.new.secret_key()),
            )
            .await;
            receipt.ended_at_ms = now_ms();
            receipt.ended_sequence = self.context.history.next_event_sequence();
            receipt.accepted = matches!(&result, Ok(Ok(())));
            self.evidence().rotation = Some(receipt);
            self.persist()?;
            result.context("secret rotation request exceeded the operation timeout")??;
            Ok::<_, anyhow::Error>(())
        };
        // Each S3 mutation finishes its own terminal history receipt. A failed
        // admin request cannot discard accepted writes in the other future.
        let (workload_result, rotation_result) = tokio::join!(workload, rotation);
        let writes = workload_result.into_iter().collect::<Result<Vec<_>>>()?;
        rotation_result?;
        ensure!(
            writes
                .iter()
                .all(|record| record.outcome == OperationOutcome::Ok || is_auth_rejection(record)),
            "old-credential load encountered a non-authentication failure"
        );
        self.context.history.mark_fault_ended_now();
        self.prove_auth_on_every_pod(operation_deadline).await?;
        self.run_new_credential_mutations(operation_deadline)
            .await?;
        self.evidence()
            .validate_history(&self.context.history.records())?;
        self.context.events.record("credential-rotation", RunEventStatus::Succeeded,
            "secret rotation, request overlap, every-Pod authentication, and new-credential mutations proven", None)?;
        self.state.lock().await.finished = true;
        Ok(())
    }

    async fn prove_auth_on_every_pod(&self, operation_deadline: Instant) -> Result<()> {
        let pods = self.evidence().pods_before.clone();
        let prefilled = self.evidence().old_prefill_operation_ids[0].clone();
        let baseline = self
            .context
            .history
            .records()
            .into_iter()
            .find(|record| record.id == prefilled)
            .context("prefill probe write is missing")?;
        let key = baseline
            .key
            .as_deref()
            .context("prefill probe key is missing")?;
        for pod in pods {
            self.deadline.check()?;
            let spec = PortForwardSpec::pod_on_available_port(
                &self.config.cluster.test_namespace,
                &pod.name,
                9000,
            )?;
            let endpoint = spec.local_base_url();
            let mut forward = spec.start_with_temp_log(&Kubectl::new(&self.config.cluster))?;
            wait_for_tenant_s3(
                &mut forward,
                &endpoint,
                operation_deadline.saturating_duration_since(Instant::now()),
            )
            .await?;
            let request_timeout = self
                .config
                .request_timeout
                .min(operation_deadline.saturating_duration_since(Instant::now()));
            ensure!(
                !request_timeout.is_zero(),
                "credential propagation exceeded the operation timeout"
            );
            let old = self
                .client(&endpoint, &self.old, request_timeout)
                .await?
                .with_request_deadline(operation_deadline);
            let new = self
                .client(&endpoint, &self.new, request_timeout)
                .await?
                .with_request_deadline(operation_deadline);
            loop {
                ensure!(
                    Instant::now() < operation_deadline,
                    "credential propagation exceeded the operation timeout"
                );
                self.deadline.check()?;
                let old_result = old
                    .get_object_recorded_result(key, &self.context.history)
                    .await?;
                let new_result = new
                    .get_object_recorded_result(key, &self.context.history)
                    .await?;
                let records = self.context.history.records();
                let old_record = records
                    .iter()
                    .find(|record| record.id == old_result.operation_id)
                    .context("old auth receipt is absent")?;
                let new_record = records
                    .iter()
                    .find(|record| record.id == new_result.operation_id)
                    .context("new auth receipt is absent")?;
                if is_auth_rejection(old_record) && new_record.outcome == OperationOutcome::Ok {
                    ensure!(
                        new_record.value_sha256 == baseline.value_sha256
                            && new_record.size_bytes == baseline.size_bytes,
                        "new secret returned incorrect committed bytes"
                    );
                    self.evidence().pod_auth.push(PodCredentialProof {
                        pod_name: pod.name,
                        pod_uid: pod.uid,
                        old_operation_id: old_result.operation_id,
                        new_operation_id: new_result.operation_id,
                    });
                    self.persist()?;
                    break;
                }
                ensure!(
                    [old_record, new_record]
                        .iter()
                        .all(|record| record.outcome == OperationOutcome::Ok
                            || is_auth_rejection(record)),
                    "credential propagation probe encountered a non-auth failure"
                );
                tokio::time::sleep(PROPAGATION_POLL_INTERVAL).await;
            }
        }
        let before = self.evidence().pods_before.clone();
        let after = rustfs_pod_identities(&self.config.cluster)?;
        ensure!(
            before
                .iter()
                .map(|pod| (&pod.name, &pod.uid))
                .collect::<BTreeSet<_>>()
                == after
                    .iter()
                    .map(|pod| (&pod.name, &pod.uid))
                    .collect::<BTreeSet<_>>(),
            "RustFS Pod identities changed during credential propagation proof"
        );
        Ok(())
    }

    async fn run_new_credential_mutations(&self, operation_deadline: Instant) -> Result<()> {
        let new = self
            .state
            .lock()
            .await
            .new_s3
            .clone()
            .context("new client is absent")?
            .with_request_deadline(operation_deadline);
        let object = ObjectSpec::prepare_seeded(
            &self.context.run_id,
            self.scenario.object_count,
            self.context.workload_plan.size_at(0).max(1),
            self.context.workload_plan.seed,
        );
        let put = new
            .put_object_record(&object, &self.context.history)
            .await?;
        self.evidence().new_put_operation_id = Some(put.id.clone());
        require_committed_put(&put)?;
        let get = new
            .get_object_recorded_result(&object.spec.key, &self.context.history)
            .await?;
        self.evidence().new_get_operation_id = Some(get.operation_id);
        ensure!(
            get.result.outcome == OperationOutcome::Ok
                && get
                    .result
                    .body
                    .as_deref()
                    .is_some_and(|body| object.spec.matches_body(body)),
            "new credential PUT/GET probe did not return matching bytes"
        );
        let replacement = object.spec.prepare_overwrite(1);
        let overwrite = new
            .put_object_record(&replacement, &self.context.history)
            .await?;
        self.evidence().new_overwrite_operation_id = Some(overwrite.id.clone());
        require_committed_put(&overwrite)?;
        let delete = new
            .delete_object_record(&object.spec.key, &self.context.history)
            .await?;
        self.evidence().new_delete_operation_id = Some(delete.id);
        ensure!(
            delete.outcome == OperationOutcome::Ok && delete.is_delete_marker == Some(true),
            "new credential DELETE did not commit a delete marker"
        );
        let get = new
            .get_object_recorded_result(&object.spec.key, &self.context.history)
            .await?;
        self.evidence().new_deleted_get_operation_id = Some(get.operation_id);
        ensure!(
            get.result.outcome == OperationOutcome::NotFound,
            "new credential delete marker did not hide the current object"
        );
        Ok(())
    }

    async fn verify_inner(&self) -> Result<()> {
        self.evidence()
            .validate_history(&self.context.history.records())?;
        let (s3, baseline) = {
            let state = self.state.lock().await;
            (
                state.new_s3.clone().context("new client is absent")?,
                state
                    .baseline
                    .clone()
                    .context("health baseline is absent")?,
            )
        };
        wait_for_stable_rustfs_pods(
            &self.config.cluster,
            self.config.expected_rustfs_pod_count,
            self.config.rustfs_pod_stable_window,
        )
        .await?;
        let pods = rustfs_pod_identities(&self.config.cluster)?;
        let (endpoint, mut forward) = s3_access(&self.config)?;
        ensure_s3_access(&mut forward, &self.config.cluster, &endpoint).await?;
        self.context.events.record(
            "recovery-health",
            RunEventStatus::Started,
            "checking RustFS health after IAM secret rotation",
            None,
        )?;
        let recovery = observe_recovery_health(
            &self.config.cluster,
            &endpoint,
            &baseline,
            &pods,
            &self.scenario.name,
            &self.context.run_id,
            &|report| {
                self.collector
                    .write_text(
                        self.scenario.case_name,
                        RECOVERY_HEALTH_ARTIFACT,
                        &serde_json::to_string_pretty(report)?,
                    )
                    .map(|_| ())
            },
        )
        .await?;
        self.complete_recovery_health(&recovery)?;
        let checker_start = self.context.history.records().len();
        let report = checker::check_s3_history(
            &s3,
            &self.context.history,
            true,
            self.context.workload_plan.concurrency,
            true,
        )
        .await?;
        self.collector.write_text(
            self.scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&report)?,
        )?;
        let reread = checker::recovery_stability_reread(
            &s3,
            &self.context.history,
            &report,
            checker_start,
            self.context.workload_plan.concurrency,
            self.config.recovery_stability_reread,
        )
        .await?;
        self.collector.write_text(
            self.scenario.case_name,
            "recovery-stability.json",
            &serde_json::to_string_pretty(&reread)?,
        )?;
        ensure!(
            report.failed_writes_materialized.is_empty(),
            "authentication-rejected old-credential writes became visible"
        );
        report.require_success()?;
        checker::validate_checker_audit_against_history(&report, &self.context.history.records())?;
        self.evidence().verified = true;
        self.context.events.record("checker-final", RunEventStatus::Succeeded,
            "all committed versions, historical bytes, and delete markers passed the existing checker", None)?;
        Ok(())
    }

    fn complete_recovery_health(&self, report: &RecoveryHealthReport) -> Result<()> {
        // The observer checkpoints each attempt before setting its terminal verdict.
        self.collector.write_text(
            self.scenario.case_name,
            RECOVERY_HEALTH_ARTIFACT,
            &serde_json::to_string_pretty(report)?,
        )?;
        report.require_success()?;
        self.context.events.record(
            "recovery-health",
            RunEventStatus::Succeeded,
            "RustFS remained healthy after IAM secret rotation",
            None,
        )
    }
}

#[async_trait(?Send)]
impl AdminCaseDriver for LiveCredentialRotationDriver {
    async fn prepare(&self) -> Result<()> {
        self.preserve(self.prepare_inner().await).await
    }
    async fn start(&self) -> Result<Instant> {
        let start = Instant::now();
        let operation = start
            .checked_add(self.plan.operation_timeout)
            .context("rotation deadline overflow")?;
        let operation = self
            .deadline
            .instant()?
            .map_or(operation, |deadline| operation.min(deadline));
        self.state.lock().await.operation_deadline = Some(operation);
        Ok(start)
    }
    async fn observe(&self) -> Result<AdminWorkflowObservation> {
        Ok(if self.state.lock().await.finished {
            AdminWorkflowObservation::Completed
        } else {
            AdminWorkflowObservation::Running
        })
    }
    async fn run_workload(&self) -> Result<()> {
        let result = self.run_workload_inner().await;
        self.state.lock().await.finished = true;
        self.preserve(result).await
    }
    async fn verify_completed_overlap(&self) -> Result<()> {
        self.evidence()
            .validate_history(&self.context.history.records())
    }
    async fn verify(&self) -> Result<()> {
        self.preserve(self.verify_inner().await).await
    }
    async fn cancel(&self) -> Result<AdminCancelOutcome> {
        // Secret updates are atomic and have no cancel endpoint. Removing the
        // run-owned IAM identity reconciles both accepted and ambiguous updates.
        Ok(AdminCancelOutcome::NoOwnedOperation)
    }
    async fn cleanup(&self) -> Result<()> {
        let result = async {
            let mut state = self.state.lock().await;
            if let Some(guard) = state.identity_guard.as_mut() {
                guard.cleanup().await?;
                guard.armed = false;
            }
            drop(state.identity_guard.take());
            if self.evidence().verified {
                self.context.events.record(
                    "run",
                    RunEventStatus::Succeeded,
                    "credential rotation and run-owned IAM cleanup completed",
                    None,
                )?;
            }
            drop(state.port_forward.take());
            Ok(())
        }
        .await;
        self.preserve(result).await
    }
}

#[async_trait]
trait IdentityCleanupPort: Send + Sync {
    fn redact_history(&self, history: &Recorder) -> Result<()>;
    async fn remove_identity(&self) -> Result<()>;
    async fn verify_pod(
        &self,
        pod: &CredentialPodGeneration,
        key: &str,
        history: &Recorder,
        deadline: Instant,
    ) -> Result<PodIdentityCleanupProof>;
}

struct LiveIdentityCleanupPort {
    config: FaultTestConfig,
    admin: Arc<RustfsIdentityAdminClient>,
    old: RotationCredential,
    new: RotationCredential,
    policy_name: String,
    bucket: String,
}

impl LiveIdentityCleanupPort {
    async fn capture_pod(
        &self,
        pod: &CredentialPodGeneration,
        deadline: Instant,
    ) -> Result<PodGenerationReceipt> {
        let started_at_ms = now_ms();
        let output = Kubectl::new(&self.config.cluster)
            .namespaced(&self.config.cluster.test_namespace)
            .command(["get", "pod", &pod.pod_name, "-o", "json"])
            .run_bounded(cleanup_remaining(deadline)?)
            .await?;
        let ended_at_ms = now_ms();
        ensure!(output.code == Some(0), "IAM cleanup Pod query failed");
        let raw: serde_json::Value =
            serde_json::from_str(&output.stdout).context("parse IAM cleanup Pod query response")?;
        let mut metadata = serde_json::json!({
            "name": raw.pointer("/metadata/name"),
            "uid": raw.pointer("/metadata/uid"),
            "namespace": raw.pointer("/metadata/namespace"),
            "labels": { "rustfs.tenant": raw.pointer("/metadata/labels/rustfs.tenant") }
        });
        if let Some(deletion) = raw
            .pointer("/metadata/deletionTimestamp")
            .filter(|value| !value.is_null())
        {
            metadata["deletionTimestamp"] = deletion.clone();
        }
        let response = serde_json::json!({
            "metadata": metadata,
            "status": {
                "conditions": raw.pointer("/status/conditions").and_then(serde_json::Value::as_array)
                    .into_iter().flatten().map(|condition| serde_json::json!({
                        "type": condition.get("type"), "status": condition.get("status")
                    })).collect::<Vec<_>>(),
                "containerStatuses": raw.pointer("/status/containerStatuses").and_then(serde_json::Value::as_array)
                    .into_iter().flatten().map(|container| serde_json::json!({
                        "name": container.get("name"), "containerID": container.get("containerID"),
                        "state": { "running": container.pointer("/state/running") }
                    })).collect::<Vec<_>>()
            }
        });
        Ok(PodGenerationReceipt {
            started_at_ms,
            ended_at_ms,
            response_body_sha256: sha256_hex(output.stdout.as_bytes()),
            response,
        })
    }

    async fn auth_receipt(
        &self,
        endpoint: &str,
        credential: &RotationCredential,
        key: &str,
        history: &Recorder,
        deadline: Instant,
    ) -> Result<CredentialCleanupAuthReceipt> {
        let s3 = S3WorkloadClient::new_without_retries(
            endpoint,
            &self.bucket,
            credential.access_key(),
            credential.secret_key(),
            self.config
                .request_timeout
                .min(cleanup_remaining(deadline)?),
        )
        .await?
        .with_request_deadline(deadline);
        let result = s3.get_object_recorded_result(key, history).await?;
        let operation = history
            .records()
            .into_iter()
            .find(|record| record.id == result.operation_id)
            .context("IAM cleanup authentication response record is absent")?;
        Ok(CredentialCleanupAuthReceipt {
            credential: credential.artifact(),
            operation,
        })
    }
}

#[async_trait]
impl IdentityCleanupPort for LiveIdentityCleanupPort {
    fn redact_history(&self, history: &Recorder) -> Result<()> {
        let (access, secret) = resources::test_credentials();
        history.redact_secrets(&[
            self.old.access_key(),
            self.old.secret_key(),
            self.new.secret_key(),
            access,
            secret,
        ])
    }

    async fn remove_identity(&self) -> Result<()> {
        let user = self.admin.remove_user(self.old.access_key()).await;
        let policy = self.admin.remove_policy(&self.policy_name).await;
        user.and(policy).map_err(Into::into)
    }

    async fn verify_pod(
        &self,
        pod: &CredentialPodGeneration,
        key: &str,
        history: &Recorder,
        deadline: Instant,
    ) -> Result<PodIdentityCleanupProof> {
        cleanup_remaining(deadline)?;
        let spec = PortForwardSpec::pod_on_available_port(
            &self.config.cluster.test_namespace,
            &pod.pod_name,
            9000,
        )?;
        let endpoint = spec.local_base_url();
        let mut forward = spec.start_with_temp_log(&Kubectl::new(&self.config.cluster))?;
        wait_for_tenant_s3(&mut forward, &endpoint, cleanup_remaining(deadline)?).await?;
        let before = self.capture_pod(pod, deadline).await?;
        ensure!(
            pod_generation(
                &before.response,
                &self.config.cluster.test_namespace,
                &self.config.cluster.tenant_name
            )? == *pod,
            "IAM cleanup Pod generation changed before authenticated requests"
        );
        let (access, secret) = resources::test_credentials();
        let admin = RustfsIdentityAdminClient::from_transport(RustfsAdminTransport::new(
            &endpoint,
            "us-east-1",
            access,
            secret,
            None,
            "s3chaos-fault-identity-cleanup",
        )?);
        let started = now_ms();
        let users = inventory_receipt(
            admin.users_inventory().await?,
            "/rustfs/admin/v3/list-users",
            started,
        );
        let started = now_ms();
        let policies = inventory_receipt(
            admin.policies_inventory().await?,
            "/rustfs/admin/v3/list-canned-policies",
            started,
        );
        let old_auth = self
            .auth_receipt(&endpoint, &self.old, key, history, deadline)
            .await?;
        let new_auth = self
            .auth_receipt(&endpoint, &self.new, key, history, deadline)
            .await?;
        let after = self.capture_pod(pod, deadline).await?;
        forward.ensure_running()?;
        Ok(PodIdentityCleanupProof {
            pod: pod.clone(),
            endpoint,
            port_forward_command: forward.command_display().to_string(),
            before,
            users,
            policies,
            old_auth,
            new_auth,
            after,
        })
    }
}

fn inventory_receipt(
    inventory: RustfsIdentityInventory,
    path: &str,
    started_at_ms: u64,
) -> IdentityInventoryReceipt {
    IdentityInventoryReceipt {
        method: "GET".to_string(),
        path: path.to_string(),
        started_at_ms,
        ended_at_ms: now_ms(),
        http_status: inventory.response.status,
        request_id: inventory.response.request_id,
        response_body_sha256: sha256_hex(&inventory.response.body),
        name_sha256: inventory
            .names
            .iter()
            .map(|name| sha256_hex(name.as_bytes()))
            .collect(),
    }
}

fn cleanup_remaining(deadline: Instant) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    ensure!(
        !remaining.is_zero(),
        "IAM identity cleanup exceeded its timeout"
    );
    Ok(remaining)
}

struct IdentityCleanupGuard {
    port: Arc<dyn IdentityCleanupPort>,
    history: Recorder,
    timeout: Duration,
    collector: ArtifactCollector,
    case_name: &'static str,
    evidence: Arc<Mutex<CredentialRotationEvidence>>,
    armed: bool,
}

impl IdentityCleanupGuard {
    async fn cleanup(&self) -> Result<()> {
        cleanup_identity(
            self.port.as_ref(),
            &self.history,
            self.timeout,
            &self.collector,
            self.case_name,
            &self.evidence,
        )
        .await
    }
}

impl Drop for IdentityCleanupGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let port = self.port.clone();
        let history = self.history.clone();
        let timeout = self.timeout;
        let collector = self.collector.clone();
        let case_name = self.case_name;
        let evidence = self.evidence.clone();
        let thread = std::thread::Builder::new()
            .name("s3chaos-identity-cleanup".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("build identity cleanup runtime")?;
                runtime.block_on(async {
                    cleanup_identity(
                        port.as_ref(),
                        &history,
                        timeout,
                        &collector,
                        case_name,
                        &evidence,
                    )
                    .await
                })
            });
        match thread {
            Ok(thread) => match thread.join() {
                Ok(Ok(())) => {}
                _ => eprintln!(
                    "warning: run-owned IAM cancellation cleanup failed; inspect credential-rotation.json"
                ),
            },
            Err(_) => eprintln!(
                "warning: could not start run-owned IAM cancellation cleanup; inspect credential-rotation.json"
            ),
        }
    }
}

async fn cleanup_identity(
    port: &dyn IdentityCleanupPort,
    history: &Recorder,
    timeout: Duration,
    collector: &ArtifactCollector,
    case_name: &str,
    evidence: &Arc<Mutex<CredentialRotationEvidence>>,
) -> Result<()> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .context("IAM cleanup deadline overflow")?;
    let (pods, probe_key, recorder) = {
        let mut value = evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        value.cleanup = CredentialCleanupEvidence {
            attempted: true,
            started_at_ms: Some(now_ms()),
            ..Default::default()
        };
        let recorder = Recorder::create(
            collector
                .case_dir(case_name)
                .join("credential-cleanup-history.jsonl"),
            &value.scenario,
            &value.run_id,
        )?;
        (
            value.pod_generations_before.clone(),
            cleanup_probe_key(&value, &history.records()),
            recorder,
        )
    };
    // The cleanup recorder has a separate read-only history so the final
    // data checker continues to audit precisely the workload it verified.
    port.redact_history(&recorder)?;
    write_evidence(collector, case_name, evidence)?;
    let result = tokio::time::timeout_at(deadline, async {
        port.remove_identity().await?;
        {
            let mut value = evidence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            value.cleanup.removal_acknowledged_at_ms = Some(now_ms());
            value.validate_original_generations()?;
        }
        write_evidence(collector, case_name, evidence)?;
        for pod in &pods {
            let proof = port
                .verify_pod(pod, &probe_key, &recorder, deadline)
                .await?;
            {
                let mut value = evidence
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                value.cleanup.pods.push(proof.clone());
            }
            write_evidence(collector, case_name, evidence)?;
            let value = evidence
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            value.validate_cleanup_pod(
                &proof,
                &probe_key,
                value
                    .cleanup
                    .removal_acknowledged_at_ms
                    .context("IAM removal acknowledgement is absent")?,
            )?;
        }
        let mut evidence = evidence
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        evidence.validate_cleanup_pods(&history.records())?;
        evidence.cleanup.user_absent = true;
        evidence.cleanup.policy_absent = true;
        evidence.cleanup.completed_at_ms = Some(now_ms());
        Ok(())
    })
    .await
    .context("IAM identity cleanup exceeded its timeout")
    .and_then(|result| result);
    let persisted = write_evidence(collector, case_name, evidence);
    result.and(persisted)
}

fn write_evidence(
    collector: &ArtifactCollector,
    case_name: &str,
    evidence: &Arc<Mutex<CredentialRotationEvidence>>,
) -> Result<()> {
    let evidence = evidence
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    collector.write_text(
        case_name,
        CREDENTIAL_ROTATION_ARTIFACT,
        &serde_json::to_string_pretty(&*evidence)?,
    )?;
    Ok(())
}

pub(crate) async fn run_credential_rotation_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &CredentialRotationExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        matches!(execution_plan, ExecutionPlan::CredentialRotation(value) if value == plan)
            && plan.scenario == scenario.name
            && plan.case_name == scenario.case_name,
        "credential rotation runner received a mismatched plan"
    );
    let driver = LiveCredentialRotationDriver::new(
        config,
        collector,
        scenario,
        execution_plan,
        plan,
        run_id,
        deadline,
    )?;
    let execution = execute_admin_workflow(
        &scenario.name,
        run_id,
        &driver,
        deadline,
        Duration::from_millis(100),
        plan.operation_timeout,
        config.cluster.timeout,
    )
    .await;
    persist_admin_workflow(collector, scenario.case_name, execution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{
        admin_runner::{
            ADMIN_WORKFLOW_ARTIFACT, AdminWorkflowEvidence, AdminWorkflowPhaseEvidence,
            AdminWorkflowPhaseStatus,
        },
        artifact_validation::{
            ArtifactValidationOptions, validate_fault_artifacts,
            validate_fault_artifacts_and_write_report,
        },
        checker::{
            CheckerAudit, CheckerDataVersionAudit, CheckerDeleteMarkerAudit,
            checker_expected_current_get_keys, checker_expected_live_keys,
            checker_expected_version_listing, checker_history_records_sha256,
            checker_operation_audits,
        },
        events::RunEvent,
        history::Recorder,
        plan::{ExecutionKind, FaultPlanOptions},
        recovery_health::{PodReadinessProbe, RecoveryDriveState, RecoveryHealthObservation},
        scenarios,
    };

    fn committed_write(
        history: &Recorder,
        object: &crate::fault::workload::PreparedObject,
        version: &str,
    ) -> OperationRecord {
        let mut record = history.begin(
            OperationKind::Put,
            "bucket",
            Some(object.spec.key.clone()),
            Some(object.spec.sha256.clone()),
            Some(object.spec.size_bytes),
        );
        record.version_id = Some(version.to_string());
        history
            .finish(record, OperationOutcome::Ok, Some(200), None)
            .expect("write")
    }

    fn get(
        history: &Recorder,
        bucket: &str,
        key: &str,
        source: Option<&OperationRecord>,
        status: u16,
    ) -> OperationRecord {
        let mut record = history.begin(
            OperationKind::Get,
            bucket,
            Some(key.to_string()),
            None,
            None,
        );
        if let Some(source) = source {
            record.value_sha256 = source.value_sha256.clone();
            record.size_bytes = source.size_bytes;
        }
        let outcome = match status {
            200 => OperationOutcome::Ok,
            404 => OperationOutcome::NotFound,
            _ => OperationOutcome::Failed,
        };
        history
            .finish(
                record,
                outcome,
                Some(status),
                (status != 200).then(|| "service error".to_string()),
            )
            .expect("get")
    }

    fn generation_receipt(
        evidence: &CredentialRotationEvidence,
        pod: &CredentialPodGeneration,
    ) -> PodGenerationReceipt {
        let response = serde_json::json!({
            "metadata": { "name": pod.pod_name, "uid": pod.pod_uid,
                "namespace": evidence.namespace, "labels": { "rustfs.tenant": evidence.tenant } },
            "status": { "conditions": [{"type": "Ready", "status": "True"}],
                "containerStatuses": [{ "name": "rustfs", "containerID": pod.rustfs_container_id,
                    "state": { "running": { "startedAt": "2026-10-14T00:00:00Z" } } }] }
        });
        PodGenerationReceipt {
            started_at_ms: now_ms(),
            ended_at_ms: now_ms(),
            response_body_sha256: sha256_hex(
                serde_json::to_string(&response)
                    .expect("response")
                    .as_bytes(),
            ),
            response,
        }
    }

    fn cleanup_proof(
        evidence: &CredentialRotationEvidence,
        pod: &CredentialPodGeneration,
        key: &str,
        history: &Recorder,
    ) -> PodIdentityCleanupProof {
        let before = generation_receipt(evidence, pod);
        let inventory = |path: &str| IdentityInventoryReceipt {
            method: "GET".to_string(),
            path: path.to_string(),
            started_at_ms: now_ms(),
            ended_at_ms: now_ms(),
            http_status: 200,
            request_id: Some(Uuid::new_v4().to_string()),
            response_body_sha256: sha256_hex(b"{}"),
            name_sha256: Vec::new(),
        };
        let users = inventory("/rustfs/admin/v3/list-users");
        let policies = inventory("/rustfs/admin/v3/list-canned-policies");
        let old_auth = CredentialCleanupAuthReceipt {
            credential: evidence.old_credential.clone(),
            operation: get(history, &evidence.bucket, key, None, 403),
        };
        let new_auth = CredentialCleanupAuthReceipt {
            credential: evidence.new_credential.clone(),
            operation: get(history, &evidence.bucket, key, None, 403),
        };
        let after = generation_receipt(evidence, pod);
        PodIdentityCleanupProof {
            pod: pod.clone(),
            endpoint: "http://127.0.0.1:19000".to_string(),
            port_forward_command: format!(
                "kubectl --context {} -n {} port-forward pod/{} 19000:9000",
                evidence.context, evidence.namespace, pod.pod_name
            ),
            before,
            users,
            policies,
            old_auth,
            new_auth,
            after,
        }
    }

    fn completed_cleanup(
        evidence: &CredentialRotationEvidence,
        history: &[OperationRecord],
        recorder: &Recorder,
    ) -> CredentialCleanupEvidence {
        let started = now_ms();
        let key = cleanup_probe_key(evidence, history);
        let pods = evidence
            .pod_generations_before
            .iter()
            .map(|pod| cleanup_proof(evidence, pod, &key, recorder))
            .collect();
        CredentialCleanupEvidence {
            attempted: true,
            started_at_ms: Some(started),
            removal_acknowledged_at_ms: Some(started),
            pods,
            user_absent: true,
            policy_absent: true,
            completed_at_ms: Some(now_ms()),
        }
    }

    struct TestIdentityCleanupPort {
        fixture: CredentialRotationEvidence,
        stale_peer: bool,
        blocked_peer: bool,
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl IdentityCleanupPort for TestIdentityCleanupPort {
        fn redact_history(&self, history: &Recorder) -> Result<()> {
            history.redact_secrets(&["owned-user", "admin-secret"])
        }

        async fn remove_identity(&self) -> Result<()> {
            self.calls
                .lock()
                .expect("calls")
                .push("remove-user-and-policy".to_string());
            Ok(())
        }

        async fn verify_pod(
            &self,
            pod: &CredentialPodGeneration,
            key: &str,
            history: &Recorder,
            _deadline: Instant,
        ) -> Result<PodIdentityCleanupProof> {
            self.calls.lock().expect("calls").push(pod.pod_name.clone());
            if self.blocked_peer && pod.pod_name == "rustfs-1" {
                std::future::pending::<()>().await;
            }
            let mut proof = cleanup_proof(&self.fixture, pod, key, history);
            if self.stale_peer && pod.pod_name == "rustfs-1" {
                proof
                    .users
                    .name_sha256
                    .push(self.fixture.old_credential.principal_sha256.clone());
                proof
                    .policies
                    .name_sha256
                    .push(self.fixture.policy_name_sha256.clone());
                proof.new_auth.operation.outcome = OperationOutcome::Ok;
                proof.new_auth.operation.http_status = Some(200);
            }
            Ok(proof)
        }
    }

    struct CleanupTestFixture {
        _directory: tempfile::TempDir,
        history: Recorder,
        collector: ArtifactCollector,
        evidence: Arc<Mutex<CredentialRotationEvidence>>,
        port: Arc<TestIdentityCleanupPort>,
    }

    impl CleanupTestFixture {
        fn new(stale_peer: bool, blocked_peer: bool) -> Self {
            let directory = tempfile::tempdir().expect("tempdir");
            let history = Recorder::create(
                directory.path().join("history.jsonl"),
                CREDENTIAL_ROTATION_MID_LOAD_SCENARIO,
                "run-1",
            )
            .expect("history");
            committed_write(
                &history,
                &ObjectSpec::prepare_seeded("run-1", 0, 16, 7),
                "v1",
            );
            let (mut fixture, _) = valid_history();
            fixture.cleanup = CredentialCleanupEvidence::default();
            let port = Arc::new(TestIdentityCleanupPort {
                fixture: fixture.clone(),
                stale_peer,
                blocked_peer,
                calls: Mutex::new(Vec::new()),
            });
            let collector = ArtifactCollector::new(directory.path());
            Self {
                _directory: directory,
                history,
                collector,
                evidence: Arc::new(Mutex::new(fixture)),
                port,
            }
        }

        async fn cleanup(&self, timeout: Duration) -> Result<()> {
            cleanup_identity(
                self.port.as_ref(),
                &self.history,
                timeout,
                &self.collector,
                "rotation-case",
                &self.evidence,
            )
            .await
        }

        fn persisted(&self) -> CredentialRotationEvidence {
            serde_json::from_str(
                &std::fs::read_to_string(
                    self.collector
                        .case_dir("rotation-case")
                        .join(CREDENTIAL_ROTATION_ARTIFACT),
                )
                .expect("artifact"),
            )
            .expect("evidence")
        }
    }

    fn valid_history() -> (CredentialRotationEvidence, Vec<OperationRecord>) {
        valid_history_with_object_count(4)
    }

    fn valid_history_with_object_count(
        object_count: usize,
    ) -> (CredentialRotationEvidence, Vec<OperationRecord>) {
        let dir = tempfile::tempdir().expect("tempdir");
        let history = Recorder::create(
            dir.path().join("history.jsonl"),
            CREDENTIAL_ROTATION_MID_LOAD_SCENARIO,
            "run-1",
        )
        .expect("history");
        let old = RotationCredential::generated("run-owned-user").expect("old credential");
        let new = RotationCredential::generated("run-owned-user").expect("new credential");
        let baseline_object = ObjectSpec::prepare_seeded("run-1", 0, 16, 7);
        let baseline = committed_write(&history, &baseline_object, "prefill-v1");
        let mut prefill_ids = vec![baseline.id.clone()];
        for index in 1..object_count / 2 {
            prefill_ids.push(
                committed_write(
                    &history,
                    &ObjectSpec::prepare_seeded("run-1", index, 16, 7),
                    &format!("prefill-v{}", index + 1),
                )
                .id,
            );
        }
        history.mark_fault_active_now();
        let load_object = ObjectSpec::prepare_seeded("run-1", object_count / 2, 16, 7);
        let mut load = history.begin(
            OperationKind::Put,
            "bucket",
            Some(load_object.spec.key.clone()),
            Some(load_object.spec.sha256.clone()),
            Some(16),
        );
        load.version_id = Some("load-v1".to_string());
        let rotation_started_at = now_ms();
        let rotation_started_sequence = history.next_event_sequence();
        let load = history
            .finish(load, OperationOutcome::Ok, Some(200), None)
            .expect("load completion");
        let rejected = history.begin(
            OperationKind::Put,
            "bucket",
            Some(ObjectSpec::seeded_key("run-1", object_count / 2 + 1)),
            Some(sha256_hex(b"failed-write")),
            Some(12),
        );
        let rejected = history
            .finish(
                rejected,
                OperationOutcome::Failed,
                Some(403),
                Some("SignatureDoesNotMatch".to_string()),
            )
            .expect("rejection");
        let mut workload_ids = vec![load.id.clone(), rejected.id];
        for index in object_count / 2 + 2..object_count {
            workload_ids.push(
                committed_write(
                    &history,
                    &ObjectSpec::prepare_seeded("run-1", index, 16, 7),
                    &format!("load-v{index}"),
                )
                .id,
            );
        }
        let rotation_ended_at = now_ms();
        let rotation_ended_sequence = history.next_event_sequence();
        history.mark_fault_ended_now();
        let mut pod_auth = Vec::new();
        let pods_before = vec![
            PodIdentity {
                name: "rustfs-0".to_string(),
                uid: "uid-0".to_string(),
            },
            PodIdentity {
                name: "rustfs-1".to_string(),
                uid: "uid-1".to_string(),
            },
        ];
        for pod in &pods_before {
            let old = get(&history, "bucket", &baseline_object.spec.key, None, 403);
            let new = get(
                &history,
                "bucket",
                &baseline_object.spec.key,
                Some(&baseline),
                200,
            );
            pod_auth.push(PodCredentialProof {
                pod_name: pod.name.clone(),
                pod_uid: pod.uid.clone(),
                old_operation_id: old.id,
                new_operation_id: new.id,
            });
        }
        let new_object = ObjectSpec::prepare_seeded("run-1", object_count, 16, 7);
        let new_put = committed_write(&history, &new_object, "new-v1");
        let new_get = get(
            &history,
            "bucket",
            &new_object.spec.key,
            Some(&new_put),
            200,
        );
        let overwrite = committed_write(&history, &new_object.spec.prepare_overwrite(1), "new-v2");
        let mut delete = history.begin(
            OperationKind::Delete,
            "bucket",
            Some(new_object.spec.key.clone()),
            None,
            None,
        );
        delete.is_delete_marker = Some(true);
        delete.version_id = Some("delete-v1".to_string());
        let delete = history
            .finish(delete, OperationOutcome::Ok, Some(204), None)
            .expect("delete");
        let deleted_get = get(&history, "bucket", &new_object.spec.key, None, 404);
        let mut evidence = CredentialRotationEvidence {
            schema_version: 1,
            scenario: CREDENTIAL_ROTATION_MID_LOAD_SCENARIO.to_string(),
            run_id: "run-1".to_string(),
            bucket: "bucket".to_string(),
            context: "context".to_string(),
            namespace: "namespace".to_string(),
            tenant: "tenant".to_string(),
            tenant_uid: "tenant-uid".to_string(),
            deployment_id: "deployment".to_string(),
            old_credential: old.artifact(),
            new_credential: new.artifact(),
            identity_absent_before_create: true,
            policy_absent_before_create: true,
            policy_sha256: sha256_hex(bucket_policy("bucket").expect("policy").as_bytes()),
            policy_name_sha256: sha256_hex(b"owned-policy"),
            pod_generations_before: pods_before
                .iter()
                .map(|pod| CredentialPodGeneration {
                    pod_name: pod.name.clone(),
                    pod_uid: pod.uid.clone(),
                    rustfs_container_id: format!("containerd://{}", pod.uid),
                })
                .collect(),
            pods_before,
            old_prefill_operation_ids: prefill_ids,
            old_workload_operation_ids: workload_ids,
            rotation: Some(SecretRotationReceipt {
                method: "PUT".to_string(),
                path: ROTATION_PATH.to_string(),
                started_at_ms: rotation_started_at,
                ended_at_ms: rotation_ended_at,
                started_sequence: rotation_started_sequence,
                ended_sequence: rotation_ended_sequence,
                accepted: true,
            }),
            pod_auth,
            new_put_operation_id: Some(new_put.id),
            new_get_operation_id: Some(new_get.id),
            new_overwrite_operation_id: Some(overwrite.id),
            new_delete_operation_id: Some(delete.id),
            new_deleted_get_operation_id: Some(deleted_get.id),
            verified: true,
            cleanup: CredentialCleanupEvidence::default(),
        };
        let cleanup_history = Recorder::create(
            dir.path().join("cleanup.jsonl"),
            CREDENTIAL_ROTATION_MID_LOAD_SCENARIO,
            "run-1",
        )
        .expect("cleanup recorder");
        evidence.cleanup = completed_cleanup(&evidence, &history.records(), &cleanup_history);
        (evidence, history.records())
    }

    fn rotation_checker_report(history: &mut Vec<OperationRecord>) -> CheckerReport {
        let prefix = history.clone();
        let live = checker_expected_live_keys(&prefix);
        let versions = checker_expected_version_listing(&prefix);
        let started_at_ms = now_ms();
        let template = prefix
            .iter()
            .find(|record| {
                record.kind == OperationKind::Get && record.outcome == OperationOutcome::Ok
            })
            .expect("successful GET")
            .clone();
        let mut suffix = Vec::new();
        let mut append = |mut record: OperationRecord| {
            let index = prefix.len() + suffix.len();
            record.id = format!("checker-{index}");
            record.started_sequence = Some(index as u64 * 2 + 1);
            record.ended_sequence = Some(index as u64 * 2 + 2);
            record.started_at_ms = started_at_ms;
            record.ended_at_ms = started_at_ms;
            suffix.push(record);
        };
        for key in checker_expected_current_get_keys(&prefix) {
            let mut record = template.clone();
            record.key = Some(key.clone());
            if live.contains(&key) {
                let source = prefix
                    .iter()
                    .rev()
                    .find(|record| {
                        record.kind == OperationKind::Put
                            && record.outcome == OperationOutcome::Ok
                            && record.key.as_ref() == Some(&key)
                    })
                    .expect("live commit");
                record.value_sha256 = source.value_sha256.clone();
                record.size_bytes = source.size_bytes;
            } else {
                record.value_sha256 = None;
                record.size_bytes = None;
                record.outcome = OperationOutcome::NotFound;
                record.http_status = Some(404);
            }
            append(record);
        }
        let mut listing = template.clone();
        listing.kind = OperationKind::List;
        listing.key = Some(ObjectSpec::key_prefix("run-1"));
        listing.value_sha256 = None;
        listing.size_bytes = None;
        listing.listed_keys = Some(live.iter().cloned().collect());
        append(listing.clone());
        listing.kind = OperationKind::ListVersions;
        listing.listed_keys = None;
        listing.listed_versions = Some(versions.iter().cloned().collect());
        append(listing);
        let mut data_version_checks = Vec::new();
        let mut delete_marker_checks = Vec::new();
        for version in &versions {
            let version_id = version.version_id.as_ref().expect("version identity");
            if version.is_delete_marker {
                delete_marker_checks.push(CheckerDeleteMarkerAudit {
                    key: version.key.clone(),
                    version_id: version_id.clone(),
                    visible_in_list_object_versions: true,
                });
                continue;
            }
            let source = prefix
                .iter()
                .find(|record| {
                    record.kind == OperationKind::Put
                        && record.outcome == OperationOutcome::Ok
                        && record.key.as_ref() == Some(&version.key)
                        && record.version_id.as_ref() == Some(version_id)
                })
                .expect("committed version");
            let mut record = template.clone();
            record.key = Some(version.key.clone());
            record.version_id = Some(version_id.clone());
            record.value_sha256 = source.value_sha256.clone();
            record.size_bytes = source.size_bytes;
            data_version_checks.push(CheckerDataVersionAudit {
                key: version.key.clone(),
                version_id: version_id.clone(),
                expected_sha256: source.value_sha256.clone().expect("committed digest"),
                observed_sha256: record.value_sha256.clone(),
                outcome: record.outcome,
                http_status: record.http_status,
            });
            append(record);
        }
        data_version_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        delete_marker_checks.sort_by(|left, right| {
            (&left.key, &left.version_id).cmp(&(&right.key, &right.version_id))
        });
        let mut cohorts = BTreeMap::<String, usize>::new();
        let mut relations = BTreeMap::<String, usize>::new();
        for record in &prefix {
            if let Some(cohort) = record.durability_cohort {
                *cohorts.entry(cohort.as_str().to_string()).or_default() += 1;
            }
            if let Some(relation) = record.fault_window_relation {
                *relations.entry(relation.as_str().to_string()).or_default() += 1;
            }
        }
        let report: CheckerReport = serde_json::from_value(serde_json::json!({
            "scenario": CREDENTIAL_ROTATION_MID_LOAD_SCENARIO, "run_id": "run-1",
            "committed_puts": data_version_checks.len(),
            "expected_live_objects": live.len(), "verified_live_objects": live.len(),
            "missing_committed_objects": [], "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [], "hash_mismatches": [],
            "successful_corrupted_reads": [], "unexpected_visible_deleted_objects": [],
            "list_history_warning_count": 0, "final_list_warning_count": 0,
            "list_history_warnings": [], "list_warnings": [], "final_listed_objects": live.len(),
            "versioning_expected": true,
            "expected_committed_versions": data_version_checks.len(),
            "verified_committed_versions": data_version_checks.len(),
            "operation_cohorts": cohorts, "fault_window_relations": relations,
            "tenant_recovered": true, "passed": true,
            "audit": CheckerAudit {
                bucket: template.bucket,
                started_at_ms,
                completed_at_ms: started_at_ms,
                history_prefix_record_count: prefix.len(),
                history_prefix_sha256: checker_history_records_sha256(&prefix).expect("prefix digest"),
                history_suffix_record_count: suffix.len(),
                history_suffix_sha256: checker_history_records_sha256(&suffix).expect("suffix digest"),
                suffix_operations: checker_operation_audits(&suffix),
                data_version_checks,
                delete_marker_checks,
                list_object_versions_completed: Some(true),
            }
        })).expect("checker report");
        history.extend(suffix);
        report
    }

    struct RotationArtifactFixture {
        _directory: tempfile::TempDir,
        driver: LiveCredentialRotationDriver,
        report: RecoveryHealthReport,
        options: ArtifactValidationOptions,
    }

    impl RotationArtifactFixture {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("tempdir");
            let collector = ArtifactCollector::new(directory.path());
            let mut config = FaultTestConfig::for_test("context", "fast-csi");
            config.scenario = CREDENTIAL_ROTATION_MID_LOAD_SCENARIO.to_string();
            config.cluster.test_namespace = "namespace".to_string();
            config.cluster.tenant_name = "tenant".to_string();
            scenarios::apply_catalog_defaults(&mut config).expect("catalog defaults");
            config.workload =
                crate::fault::config::FaultWorkloadProfile::new(12, 2).expect("workload");
            config.workload_seed = Some(7);
            config.workload_payload_distribution =
                Some(crate::fault::workload::WorkloadPayloadDistribution {
                    classes: vec![crate::fault::workload::WorkloadPayloadClass {
                        size_bytes: 16,
                        weight: 1,
                    }],
                });
            config.expected_rustfs_pod_count = 2;
            let scenario = FaultScenario::from_config(&config).expect("scenario");
            let execution = ExecutionPlan::from_scenario_with_options(
                &scenario,
                scenarios::scenario_spec(&scenario.name).expect("catalog"),
                FaultPlanOptions::from_config(&config),
            )
            .expect("execution plan");
            let ExecutionPlan::CredentialRotation(plan) = &execution else {
                panic!("rotation plan");
            };
            let driver = LiveCredentialRotationDriver::new(
                &config,
                &collector,
                &scenario,
                &execution,
                plan,
                "run-1",
                RunDeadline::default(),
            )
            .expect("driver");
            let baseline = RecoveryHealthBaseline {
                observed_at_ms: now_ms(),
                deployment_id: "deployment".to_string(),
                standard_parity: 1,
                total_sets: vec![1],
                drives_per_set: vec![2],
                server_endpoints: vec![
                    "http://rustfs-0:9000".to_string(),
                    "http://rustfs-1:9000".to_string(),
                ],
                drive_uuids: vec!["drive-0".to_string(), "drive-1".to_string()],
            };
            driver
                .context
                .events
                .record(
                    "recovery-health-baseline",
                    RunEventStatus::Succeeded,
                    "captured healthy layout",
                    Some(serde_json::to_value(&baseline).expect("baseline")),
                )
                .expect("baseline event");
            let (mut evidence, mut history) = valid_history_with_object_count(12);
            evidence.bucket.clone_from(&driver.context.bucket);
            evidence.policy_sha256 =
                sha256_hex(bucket_policy(&evidence.bucket).expect("policy").as_bytes());
            for record in &mut history {
                record.bucket.clone_from(&evidence.bucket);
            }
            let observed_at_ms = now_ms();
            let report = RecoveryHealthReport {
                scenario: scenario.name.clone(),
                run_id: "run-1".to_string(),
                baseline: baseline.clone(),
                started_at_ms: observed_at_ms,
                completed_at_ms: observed_at_ms,
                timeout_seconds: config.cluster.timeout.as_secs(),
                attempts: 1,
                first_healthy_at_ms: Some(observed_at_ms),
                observation: Some(RecoveryHealthObservation {
                    started_at_ms: observed_at_ms,
                    completed_at_ms: observed_at_ms,
                    deployment_id: baseline.deployment_id.clone(),
                    standard_parity: 1,
                    total_sets: vec![1],
                    drives_per_set: vec![2],
                    online_drives: 2,
                    offline_drives: 0,
                    unknown_drives: 0,
                    drives: (0..2)
                        .map(|index| RecoveryDriveState {
                            server_endpoint: baseline.server_endpoints[index].clone(),
                            drive_uuid: baseline.drive_uuids[index].clone(),
                            state: "ok".to_string(),
                            pool_index: 0,
                            set_index: 0,
                        })
                        .collect(),
                }),
                readiness: evidence
                    .pods_before
                    .iter()
                    .map(|pod| PodReadinessProbe {
                        pod_name: pod.name.clone(),
                        proxy_path: crate::fault::recovery_health::readiness_proxy_path(
                            "namespace",
                            &pod.name,
                        ),
                        ready: true,
                        observed_at_ms,
                        detail: None,
                    })
                    .collect(),
                violations: Vec::new(),
                passed: true,
            };
            driver
                .context
                .events
                .record(
                    "recovery-health",
                    RunEventStatus::Started,
                    "checking recovered layout",
                    None,
                )
                .expect("recovery event");
            let checker = rotation_checker_report(&mut history);
            let cleanup_history = Recorder::create(
                collector
                    .case_dir(scenario.case_name)
                    .join("credential-cleanup-history.jsonl"),
                &scenario.name,
                "run-1",
            )
            .expect("cleanup recorder");
            evidence.cleanup = completed_cleanup(&evidence, &history, &cleanup_history);
            *driver.evidence() = evidence.clone();
            driver.persist().expect("credential evidence");
            validate_credential_rotation_evidence(&evidence, &history, &checker)
                .expect("complete credential proof");
            let lines = history
                .iter()
                .map(|record| serde_json::to_string(record).expect("record") + "\n")
                .collect::<String>();
            collector
                .write_text(scenario.case_name, "history.jsonl", &lines)
                .expect("history");
            collector
                .write_text(
                    scenario.case_name,
                    "checker-report.json",
                    &serde_json::to_string_pretty(&checker).expect("checker"),
                )
                .expect("checker artifact");
            write_preflight_summary(
                &collector,
                &scenario,
                &config,
                "run-1",
                &[PreflightPhase::new(
                    "credential-rotation-fixture",
                    vec![PreflightCheck::passed(
                        "owned-identity",
                        "validated owned IAM fixture",
                        ResponsibilityDomain::Harness,
                    )],
                )],
            )
            .expect("preflight");
            let workflow = AdminWorkflowEvidence {
                schema_version: 1,
                scenario: scenario.name.clone(),
                run_id: "run-1".to_string(),
                phases: ["start", "operation-workload-overlap", "verify", "cleanup"]
                    .into_iter()
                    .map(|phase| AdminWorkflowPhaseEvidence {
                        phase: phase.to_string(),
                        status: AdminWorkflowPhaseStatus::Succeeded,
                        started_at_ms: observed_at_ms,
                        ended_at_ms: observed_at_ms,
                        error: None,
                    })
                    .collect(),
                completed: true,
                cancel_attempted: false,
                cleanup_succeeded: true,
            };
            collector
                .write_text(
                    scenario.case_name,
                    ADMIN_WORKFLOW_ARTIFACT,
                    &serde_json::to_string_pretty(&workflow).expect("workflow"),
                )
                .expect("workflow artifact");
            for stage in ["credential-rotation", "checker-final", "run"] {
                driver
                    .context
                    .events
                    .record(stage, RunEventStatus::Succeeded, "completed", None)
                    .expect("completion event");
            }
            let options = ArtifactValidationOptions {
                scenario: scenario.name,
                artifact_root: directory.path().to_path_buf(),
                expected_workload_objects: config.workload.object_count,
                expected_workload_concurrency: config.workload.concurrency,
                expected_workload_versioning: config.workload_versioning,
                expected_rustfs_pod_count: config.expected_rustfs_pod_count,
                expected_stable_window_seconds: config.rustfs_pod_stable_window.as_secs(),
                expected_recovery_stability_reread_seconds: config
                    .recovery_stability_reread
                    .as_secs(),
                expected_rustfs_volume_path: config.rustfs_volume_path,
            };
            let fixture = Self {
                _directory: directory,
                driver,
                report,
                options,
            };
            let mut checkpoint = fixture.report.clone();
            checkpoint.passed = false;
            checkpoint.first_healthy_at_ms = None;
            fixture.write_report(&checkpoint);
            fixture
        }

        fn write_report(&self, report: &RecoveryHealthReport) {
            self.driver
                .collector
                .write_text(
                    self.driver.scenario.case_name,
                    RECOVERY_HEALTH_ARTIFACT,
                    &serde_json::to_string_pretty(report).expect("report"),
                )
                .expect("recovery artifact");
        }

        fn persisted_report(&self) -> RecoveryHealthReport {
            serde_json::from_str(
                &std::fs::read_to_string(
                    self.driver
                        .collector
                        .case_dir(self.driver.scenario.case_name)
                        .join(RECOVERY_HEALTH_ARTIFACT),
                )
                .expect("recovery artifact"),
            )
            .expect("recovery report")
        }

        fn recovery_succeeded(&self) -> bool {
            std::fs::read_to_string(
                self.driver
                    .collector
                    .case_dir(self.driver.scenario.case_name)
                    .join("run-events.jsonl"),
            )
            .expect("events")
            .lines()
            .map(|line| serde_json::from_str::<RunEvent>(line).expect("event"))
            .any(|event| {
                event.stage == "recovery-health" && event.status == RunEventStatus::Succeeded
            })
        }
    }

    #[test]
    fn complete_recovery_health_persists_terminal_report_for_full_artifact_validation() {
        let fixture = RotationArtifactFixture::new();
        let checkpoint = fixture.persisted_report();
        assert!(!checkpoint.passed);
        assert_eq!(checkpoint.first_healthy_at_ms, None);
        let error =
            validate_fault_artifacts(&fixture.options).expect_err("intermediate checkpoint");
        assert!(
            error
                .to_string()
                .contains("recovery-health.json did not pass"),
            "{error:#}"
        );
        fixture
            .driver
            .complete_recovery_health(&fixture.report)
            .expect("terminal recovery");
        assert_eq!(fixture.persisted_report(), fixture.report);
        assert!(fixture.recovery_succeeded());
        let validation = validate_fault_artifacts_and_write_report(&fixture.options)
            .expect("complete rotation artifacts");
        assert!(validation.run_succeeded);
        assert_eq!(validation.terminal_stage, "checker-final");
        assert!(validation.committed > 0);
        assert_eq!(validation.client_disruptions, 1);
        for artifact in validation.required_artifacts {
            assert!(
                fixture
                    .driver
                    .collector
                    .case_dir(fixture.driver.scenario.case_name)
                    .join(artifact)
                    .is_file()
            );
        }
    }

    #[test]
    fn full_rotation_artifacts_reject_incomplete_or_degraded_recovery_report() {
        let fixture = RotationArtifactFixture::new();
        fixture
            .driver
            .complete_recovery_health(&fixture.report)
            .expect("terminal recovery");
        validate_fault_artifacts(&fixture.options).expect("healthy artifacts");
        for mutation in 0..9 {
            let mut report = fixture.report.clone();
            match mutation {
                0 => report.passed = false,
                1 => report.first_healthy_at_ms = None,
                2 => report.first_healthy_at_ms = Some(report.started_at_ms - 1),
                3 => {
                    report.observation.as_mut().expect("observation").drives[0].state =
                        "offline".to_string()
                }
                4 => report.readiness[0].ready = false,
                5 => report.run_id = "foreign-run".to_string(),
                6 => {
                    report.readiness.pop();
                }
                7 => report.baseline.observed_at_ms += 1,
                8 => {
                    report.started_at_ms = fixture
                        .driver
                        .evidence()
                        .rotation
                        .as_ref()
                        .expect("rotation")
                        .ended_at_ms
                        - 1
                }
                _ => unreachable!(),
            }
            fixture.write_report(&report);
            assert!(
                validate_fault_artifacts(&fixture.options).is_err(),
                "mutation {mutation} must fail closed"
            );
        }
        fixture.write_report(&fixture.report);
        validate_fault_artifacts(&fixture.options).expect("restored healthy artifacts");
        std::fs::remove_file(
            fixture
                .driver
                .collector
                .case_dir(fixture.driver.scenario.case_name)
                .join(RECOVERY_HEALTH_ARTIFACT),
        )
        .expect("remove fixture report");
        assert!(validate_fault_artifacts(&fixture.options).is_err());
    }

    #[test]
    fn full_rotation_artifacts_require_every_declared_artifact() {
        let fixture = RotationArtifactFixture::new();
        fixture
            .driver
            .complete_recovery_health(&fixture.report)
            .expect("terminal recovery");
        let validation = validate_fault_artifacts(&fixture.options).expect("complete artifacts");
        let case_dir = fixture
            .driver
            .collector
            .case_dir(fixture.driver.scenario.case_name);
        for artifact in validation.required_artifacts {
            let path = case_dir.join(&artifact);
            let saved = case_dir.join(format!("{artifact}.saved"));
            std::fs::rename(&path, &saved).expect("retain fixture artifact");
            let result = validate_fault_artifacts(&fixture.options);
            std::fs::rename(&saved, &path).expect("restore fixture artifact");
            assert!(result.is_err(), "missing {artifact} must fail closed");
        }
        validate_fault_artifacts(&fixture.options).expect("restored complete artifacts");
    }

    #[test]
    fn complete_recovery_health_preserves_failed_report_without_success_event() {
        let fixture = RotationArtifactFixture::new();
        let mut failed = fixture.report.clone();
        failed.passed = false;
        failed.first_healthy_at_ms = None;
        failed.attempts = 2;
        failed
            .violations
            .push("drive-0 remains offline".to_string());
        failed.observation.as_mut().expect("observation").drives[0].state = "offline".to_string();
        assert!(fixture.driver.complete_recovery_health(&failed).is_err());
        assert_eq!(fixture.persisted_report(), failed);
        assert!(!fixture.recovery_succeeded());
        assert!(validate_fault_artifacts(&fixture.options).is_err());
    }

    #[test]
    fn complete_recovery_health_propagates_persistence_failure_without_success_event() {
        let fixture = RotationArtifactFixture::new();
        let path = fixture
            .driver
            .collector
            .case_dir(fixture.driver.scenario.case_name)
            .join(RECOVERY_HEALTH_ARTIFACT);
        std::fs::remove_file(&path).expect("remove fixture checkpoint");
        std::fs::create_dir(&path).expect("block report destination");
        assert!(
            fixture
                .driver
                .complete_recovery_health(&fixture.report)
                .is_err()
        );
        assert!(!fixture.recovery_succeeded());
    }

    #[test]
    fn real_request_overlap_and_every_pod_auth_require_nonempty_history() {
        let (evidence, history) = valid_history();
        evidence.validate_history(&history).expect("valid evidence");
        assert!(evidence.validate_history(&[]).is_err());
        let mut wrong = evidence.clone();
        wrong.old_workload_operation_ids.clear();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong = evidence;
        wrong.pod_auth.pop();
        assert!(wrong.validate_history(&history).is_err());
    }

    #[test]
    fn rotation_without_an_overlapping_request_is_rejected() {
        let (mut evidence, history) = valid_history();
        let receipt = evidence.rotation.as_mut().expect("rotation");
        receipt.started_sequence = history[3].ended_sequence.expect("load end") + 1;
        receipt.ended_sequence = receipt.started_sequence + 1;
        let error = evidence
            .validate_history(&history)
            .expect_err("no overlapping load");
        assert!(
            error
                .to_string()
                .contains("overlaps the actual secret rotation"),
            "{error:#}"
        );
    }

    #[test]
    fn denied_new_credentials_and_still_valid_old_credentials_fail_proof() {
        let (evidence, history) = valid_history();
        for (id, outcome, status) in [
            (
                &evidence.pod_auth[0].old_operation_id,
                OperationOutcome::Ok,
                200,
            ),
            (
                &evidence.pod_auth[0].old_operation_id,
                OperationOutcome::Failed,
                500,
            ),
            (
                &evidence.pod_auth[0].new_operation_id,
                OperationOutcome::Failed,
                403,
            ),
        ] {
            let mut wrong = history.clone();
            let record = wrong
                .iter_mut()
                .find(|record| &record.id == id)
                .expect("record");
            record.outcome = outcome;
            record.http_status = Some(status);
            assert!(evidence.validate_history(&wrong).is_err());
        }
    }

    #[test]
    fn auth_proof_cannot_substitute_another_pod_or_other_committed_bytes() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.pod_auth[0].pod_uid = "replacement-uid".to_string();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong_history = history;
        wrong_history
            .iter_mut()
            .find(|record| record.id == evidence.pod_auth[0].new_operation_id)
            .expect("new auth")
            .value_sha256 = Some(sha256_hex(b"other bytes"));
        assert!(evidence.validate_history(&wrong_history).is_err());
    }

    #[test]
    fn unchanged_secret_and_different_principal_are_rejected() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.new_credential = wrong.old_credential.clone();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong = evidence;
        wrong.new_credential.principal_sha256 = sha256_hex(b"another-user");
        assert!(wrong.validate_history(&history).is_err());
    }

    #[test]
    fn non_auth_load_failure_and_unconfirmed_version_fail_closed() {
        let (evidence, history) = valid_history();
        let mut wrong = history.clone();
        wrong
            .iter_mut()
            .find(|record| record.id == evidence.old_workload_operation_ids[1])
            .expect("rejected load")
            .http_status = Some(500);
        assert!(evidence.validate_history(&wrong).is_err());
        let mut wrong = history;
        wrong
            .iter_mut()
            .find(|record| record.id == evidence.old_prefill_operation_ids[0])
            .expect("prefill")
            .version_id = None;
        assert!(evidence.validate_history(&wrong).is_err());
    }

    #[test]
    fn post_rotation_verification_requires_version_lineage_and_delete_visibility() {
        let (evidence, history) = valid_history();
        let mut wrong = history.clone();
        let original_version = wrong
            .iter()
            .find(|record| Some(&record.id) == evidence.new_put_operation_id.as_ref())
            .expect("new put")
            .version_id
            .clone();
        wrong
            .iter_mut()
            .find(|record| Some(&record.id) == evidence.new_overwrite_operation_id.as_ref())
            .expect("overwrite")
            .version_id = original_version;
        assert!(evidence.validate_history(&wrong).is_err());
        let mut wrong = history.clone();
        wrong
            .iter_mut()
            .find(|record| Some(&record.id) == evidence.new_delete_operation_id.as_ref())
            .expect("delete")
            .is_delete_marker = Some(false);
        assert!(evidence.validate_history(&wrong).is_err());
        let mut wrong = history;
        wrong
            .iter_mut()
            .find(|record| Some(&record.id) == evidence.new_deleted_get_operation_id.as_ref())
            .expect("deleted get")
            .outcome = OperationOutcome::Ok;
        assert!(evidence.validate_history(&wrong).is_err());
    }

    #[test]
    fn history_references_cannot_be_repeated_or_cross_run() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.pod_auth[1].new_operation_id = wrong.pod_auth[0].new_operation_id.clone();
        assert!(wrong.validate_history(&history).is_err());
        let mut wrong = history;
        wrong[0].run_id = Some("other-run".to_string());
        assert!(evidence.validate_history(&wrong).is_err());
    }

    #[test]
    fn checker_empty_model_and_missing_cleanup_cannot_produce_a_pass() {
        let (evidence, history) = valid_history();
        let checker = serde_json::from_value::<CheckerReport>(serde_json::json!({
            "scenario": CREDENTIAL_ROTATION_MID_LOAD_SCENARIO, "run_id": "run-1",
            "committed_puts": 0, "expected_live_objects": 0, "verified_live_objects": 0,
            "missing_committed_objects": [], "unavailable_committed_objects": [],
            "unknown_committed_read_failures": [], "hash_mismatches": [],
            "successful_corrupted_reads": [], "unexpected_visible_deleted_objects": [],
            "list_history_warning_count": 0, "final_list_warning_count": 0,
            "list_history_warnings": [], "list_warnings": [], "final_listed_objects": 0,
            "tenant_recovered": true, "passed": true, "versioning_expected": true
        }))
        .expect("empty checker");
        assert!(validate_credential_rotation_evidence(&evidence, &history, &checker).is_err());
        let mut materialized = checker.clone();
        materialized.expected_live_objects = 1;
        materialized.expected_committed_versions = 1;
        materialized.failed_writes_materialized = vec![ObjectSpec::seeded_key("run-1", 3)];
        let error = validate_credential_rotation_evidence(&evidence, &history, &materialized)
            .expect_err("authentication rejection must not commit data");
        assert!(error.to_string().contains("authentication-rejected"));
        let mut wrong = evidence;
        wrong.cleanup.user_absent = false;
        let error = validate_credential_rotation_evidence(&wrong, &history, &checker)
            .expect_err("unfinished cleanup");
        assert!(
            error.to_string().contains("IAM fixture cleanup"),
            "{error:#}"
        );
    }

    #[test]
    fn credentials_and_debug_output_publish_only_sha256_fingerprints() {
        let old = RotationCredential::generated("generated-access-key").expect("credential");
        let artifact = serde_json::to_string(&old.artifact()).expect("artifact");
        let debug = format!("{old:?}");
        for value in [old.access_key(), old.secret_key()] {
            assert!(!artifact.contains(value));
            assert!(!debug.contains(value));
        }
        assert!(artifact.contains(&sha256_hex(old.access_key().as_bytes())));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancellation_guard_removes_owned_identity_before_transport_is_released() {
        let fixture = CleanupTestFixture::new(false, false);
        let guard = IdentityCleanupGuard {
            port: fixture.port.clone(),
            history: fixture.history.clone(),
            timeout: Duration::from_secs(1),
            collector: fixture.collector.clone(),
            case_name: "rotation-case",
            evidence: fixture.evidence.clone(),
            armed: true,
        };
        drop(guard);
        let persisted = fixture.persisted();
        assert!(
            persisted.cleanup.attempted
                && persisted.cleanup.user_absent
                && persisted.cleanup.policy_absent
        );
        assert!(persisted.cleanup.completed_at_ms.is_some());
        persisted
            .validate_cleanup_pods(&fixture.history.records())
            .expect("complete coverage");
        assert_eq!(
            *fixture.port.calls.lock().expect("calls"),
            ["remove-user-and-policy", "rustfs-0", "rustfs-1"]
        );
        let raw = serde_json::to_string(&persisted).expect("artifact");
        assert!(!raw.contains("owned-user") && !raw.contains("admin-secret"));
    }

    #[tokio::test]
    async fn timed_out_cleanup_preserves_an_incomplete_identity_receipt() {
        let fixture = CleanupTestFixture::new(false, true);
        let result = fixture.cleanup(Duration::from_millis(30)).await;
        assert!(result.is_err());
        let persisted = fixture.persisted();
        assert!(persisted.cleanup.attempted);
        assert!(persisted.cleanup.removal_acknowledged_at_ms.is_some());
        assert_eq!(persisted.cleanup.pods.len(), 1);
        assert!(!persisted.cleanup.user_absent && !persisted.cleanup.policy_absent);
        assert!(persisted.cleanup.completed_at_ms.is_none());
        assert!(
            persisted
                .validate_cleanup_pods(&fixture.history.records())
                .is_err()
        );
    }

    #[tokio::test]
    async fn local_delete_success_with_a_stale_peer_keeps_cleanup_incomplete() {
        let fixture = CleanupTestFixture::new(true, false);
        let error = fixture
            .cleanup(Duration::from_secs(1))
            .await
            .expect_err("stale peer");
        assert!(
            error.to_string().contains("stale user/policy cache"),
            "{error:#}"
        );
        let persisted = fixture.persisted();
        assert!(persisted.cleanup.removal_acknowledged_at_ms.is_some());
        assert_eq!(persisted.cleanup.pods.len(), 2);
        assert_eq!(
            persisted.cleanup.pods[1].new_auth.operation.http_status,
            Some(200)
        );
        assert!(!persisted.cleanup.user_absent && !persisted.cleanup.policy_absent);
        assert!(persisted.cleanup.completed_at_ms.is_none());
        assert!(
            persisted
                .validate_cleanup_pods(&fixture.history.records())
                .is_err()
        );
    }

    #[test]
    fn missing_duplicate_and_foreign_cleanup_coverage_are_rejected() {
        let (evidence, history) = valid_history();
        evidence
            .validate_cleanup_pods(&history)
            .expect("complete coverage");
        let mut wrong = evidence.clone();
        wrong.cleanup.pods.pop();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[1] = wrong.cleanup.pods[0].clone();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence;
        wrong.cleanup.pods[1].pod.pod_name = "foreign-pod".to_string();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
    }

    #[test]
    fn cleanup_requires_nonempty_exact_original_container_coverage() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.pod_generations_before.clear();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.pod_generations_before[1] = wrong.pod_generations_before[0].clone();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.pod_generations_before[1].pod_name = "foreign-pod".to_string();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence;
        wrong.pod_generations_before[1].rustfs_container_id.clear();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
    }

    #[test]
    fn cleanup_requires_unchanged_uid_and_container_generation_on_both_sides() {
        let (evidence, history) = valid_history();
        for before in [false, true] {
            for container in [false, true] {
                let mut wrong = evidence.clone();
                let proof = &mut wrong.cleanup.pods[0];
                let capture = if before {
                    &mut proof.before
                } else {
                    &mut proof.after
                };
                if container {
                    capture.response["status"]["containerStatuses"][0]["containerID"] =
                        "containerd://restart".into();
                } else {
                    capture.response["metadata"]["uid"] = "replacement-uid".into();
                }
                assert!(wrong.validate_cleanup_pods(&history).is_err());
            }
        }
        let mut wrong = evidence;
        wrong.pod_generations_before[0].rustfs_container_id = "containerd://other".to_string();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
    }

    #[test]
    fn cleanup_inventory_and_credential_response_proofs_cannot_be_substituted() {
        let (evidence, history) = valid_history();
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0]
            .users
            .name_sha256
            .push(wrong.old_credential.principal_sha256.clone());
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0]
            .policies
            .name_sha256
            .push(wrong.policy_name_sha256.clone());
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].users.http_status = 503;
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].new_auth = wrong.cleanup.pods[0].old_auth.clone();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].new_auth.operation.http_status = Some(500);
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].new_auth.operation.run_id = Some("other-run".to_string());
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence;
        wrong.cleanup.pods[0].port_forward_command =
            "kubectl port-forward svc/tenant-io 19000:9000".to_string();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
    }

    #[test]
    fn cleanup_rejects_accepted_credentials_foreign_scope_and_unbounded_receipts() {
        let (evidence, history) = valid_history();
        for old in [false, true] {
            let mut wrong = evidence.clone();
            let proof = &mut wrong.cleanup.pods[0];
            let auth = if old {
                &mut proof.old_auth
            } else {
                &mut proof.new_auth
            };
            auth.operation.outcome = OperationOutcome::Ok;
            auth.operation.http_status = Some(200);
            assert!(wrong.validate_cleanup_pods(&history).is_err());
        }
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].after.response["metadata"]["namespace"] = "foreign-namespace".into();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].before.response["metadata"]["labels"]["rustfs.tenant"] =
            "foreign-tenant".into();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.pods[0].users.ended_at_ms = wrong.cleanup.pods[0].after.started_at_ms + 1;
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.removal_acknowledged_at_ms = None;
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence.clone();
        wrong.cleanup.started_at_ms = Some(1);
        assert!(wrong.validate_cleanup_pods(&history).is_err());
        let mut wrong = evidence;
        wrong.cleanup.pods[0].after.response_body_sha256.clear();
        assert!(wrong.validate_cleanup_pods(&history).is_err());
    }

    #[tokio::test]
    async fn failed_cleanup_retry_clears_previous_completion_and_coverage() {
        let fixture = CleanupTestFixture::new(false, true);
        fixture.evidence.lock().expect("evidence").cleanup = valid_history().0.cleanup;
        fixture
            .cleanup(Duration::from_millis(30))
            .await
            .expect_err("blocked peer");
        let persisted = fixture.persisted();
        assert_eq!(persisted.cleanup.pods.len(), 1);
        assert!(persisted.cleanup.completed_at_ms.is_none());
        assert!(!persisted.cleanup.user_absent && !persisted.cleanup.policy_absent);
    }

    #[tokio::test]
    async fn cancelled_cleanup_preserves_partial_peer_coverage_without_completion() {
        let fixture = CleanupTestFixture::new(false, true);
        {
            let cleanup = fixture.cleanup(Duration::from_secs(1));
            tokio::pin!(cleanup);
            assert!(
                tokio::time::timeout(Duration::from_millis(30), &mut cleanup)
                    .await
                    .is_err()
            );
        }
        let persisted = fixture.persisted();
        assert_eq!(persisted.cleanup.pods.len(), 1);
        assert!(persisted.cleanup.completed_at_ms.is_none());
        assert!(!persisted.cleanup.user_absent && !persisted.cleanup.policy_absent);
    }

    #[test]
    fn existing_entrypoints_select_a_typed_versioned_rotation_suite() {
        let mut config = FaultTestConfig::for_test("real-cluster", "fast-csi");
        config.scenario = CREDENTIAL_ROTATION_MID_LOAD_SCENARIO.to_string();
        scenarios::apply_catalog_defaults(&mut config).expect("defaults");
        assert!(config.workload_versioning);
        let scenario = FaultScenario::from_config(&config).expect("executable scenario");
        let plan = ExecutionPlan::from_scenario_with_options(
            &scenario,
            scenarios::scenario_spec(&scenario.name).expect("spec"),
            crate::fault::plan::FaultPlanOptions::from_config(&config),
        )
        .expect("typed plan");
        assert_eq!(plan.kind(), ExecutionKind::CredentialRotation);
        assert!(plan.injection().is_none());
        assert!(!plan.requires_static_storage());
        let suite = crate::fault::suite::resolve_fault_suite_yaml(
            "fault/examples/credential-rotation.yaml",
        )
        .expect("suite");
        assert_eq!(
            suite.scenarios[0].name,
            CREDENTIAL_ROTATION_MID_LOAD_SCENARIO
        );
    }
}
