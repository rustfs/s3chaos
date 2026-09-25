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

//! Acknowledgement-driven mutation execution for durability detectors.
//!
//! This module owns the timing and eligibility rules around the narrow window
//! between an S3 mutation ACK and fault activation. Callers submit exactly one
//! quiet mutation and receive either a fully identified committed version or a
//! typed refusal to arm. Backend-specific fault mechanics stay in the supplied
//! activation callback; the caller receives only stable timing evidence.

use std::{fmt, future::Future, time::Duration};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::fault::{
    history::{OperationKind, OperationOutcome, OperationRecord, Recorder},
    workload::{ObjectSpec, S3WorkloadClient, StagedMultipartUpload},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgedMutationKind {
    Put,
    Overwrite,
    DeleteMarker,
    ZeroBytePut,
    MultipartComplete,
}

impl AcknowledgedMutationKind {
    fn operation_kind(self) -> OperationKind {
        match self {
            Self::Put | Self::Overwrite | Self::ZeroBytePut => OperationKind::Put,
            Self::DeleteMarker => OperationKind::Delete,
            Self::MultipartComplete => OperationKind::CompleteMultipartUpload,
        }
    }
}

/// A calibration request selects both process and newly created bucket policy.
/// It does not itself establish that the detector has been live-qualified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AckCalibrationMode {
    Strict,
    Relaxed,
}

impl AckCalibrationMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Relaxed => "relaxed",
        }
    }

    pub(crate) fn configure(self, server_env: &mut Vec<(String, String)>) -> Result<()> {
        for name in [
            "RUSTFS_DURABILITY_MODE",
            "RUSTFS_NEW_BUCKET_DURABILITY_MODE",
        ] {
            let configured = server_env
                .iter()
                .filter(|(key, _)| key == name)
                .collect::<Vec<_>>();
            anyhow::ensure!(
                configured.len() <= 1 && configured.iter().all(|(_, value)| value == self.as_str()),
                "ACK calibration requires exactly one unambiguous {name}={} value",
                self.as_str()
            );
            if configured.is_empty() {
                server_env.push((name.to_string(), self.as_str().to_string()));
            }
        }
        Ok(())
    }
}

pub(crate) fn require_calibration_image(image: &str) -> Result<()> {
    anyhow::ensure!(
        image
            .rsplit_once("@sha256:")
            .is_some_and(|(name, digest)| !name.is_empty()
                && !name.chars().any(char::is_whitespace)
                && digest.len() == 64
                && digest.bytes().all(|byte| byte.is_ascii_hexdigit())),
        "ACK calibration requires a RustFS image pinned as name@sha256:<64 hex digits>"
    );
    Ok(())
}

pub(crate) const ACK_CALIBRATION_ARTIFACT: &str = "ack-calibration-mode.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AckCalibrationPod {
    pub name: String,
    pub uid: String,
    pub image: String,
    pub image_id: String,
    pub container_id: String,
    pub process_mode: String,
    pub new_bucket_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AckBucketMode {
    pub bucket: String,
    pub mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AckCalibrationEvidence {
    pub scenario: String,
    pub run_id: String,
    pub mode: AckCalibrationMode,
    pub observed_at_ms: u64,
    pub bucket_response: AckBucketMode,
    pub pods: Vec<AckCalibrationPod>,
}

pub(crate) fn calibration_pod(
    pod: &serde_json::Value,
    mode: AckCalibrationMode,
    image: &str,
) -> Result<AckCalibrationPod> {
    use anyhow::{Context, ensure};
    let containers = pod
        .pointer("/spec/containers")
        .and_then(serde_json::Value::as_array)
        .context("calibration Pod lacks containers")?;
    let container = containers
        .iter()
        .find(|container| container["name"] == "rustfs")
        .context("calibration Pod lacks rustfs container")?;
    let env = container["env"]
        .as_array()
        .context("calibration Pod lacks explicit modes")?;
    let observed_mode = |name: &str| -> Result<String> {
        let values = env
            .iter()
            .filter(|entry| entry["name"] == name)
            .collect::<Vec<_>>();
        ensure!(
            values.len() == 1 && values[0]["valueFrom"].is_null(),
            "calibration Pod requires one literal {name}"
        );
        let value = values[0]["value"]
            .as_str()
            .context("calibration mode is not literal")?;
        ensure!(
            value == mode.as_str(),
            "calibration Pod {name} differs from requested mode"
        );
        Ok(value.to_string())
    };
    ensure!(
        container["image"] == image,
        "calibration Pod image differs from run image"
    );
    let statuses = pod
        .pointer("/status/containerStatuses")
        .and_then(serde_json::Value::as_array)
        .context("calibration Pod lacks container statuses")?;
    let status = statuses
        .iter()
        .find(|status| status["name"] == "rustfs")
        .context("calibration Pod lacks rustfs image identity")?;
    ensure!(status["ready"] == true, "calibration Pod is not Ready");
    let image_id = status["imageID"]
        .as_str()
        .context("calibration Pod lacks imageID")?;
    let digest = image_id
        .rsplit_once("sha256:")
        .map(|(_, digest)| digest)
        .context("calibration requires a resolved sha256 image identity")?;
    ensure!(
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "calibration image digest is invalid"
    );
    Ok(AckCalibrationPod {
        name: pod
            .pointer("/metadata/name")
            .and_then(serde_json::Value::as_str)
            .context("calibration Pod lacks name")?
            .to_string(),
        uid: pod
            .pointer("/metadata/uid")
            .and_then(serde_json::Value::as_str)
            .context("calibration Pod lacks UID")?
            .to_string(),
        image: image.to_string(),
        image_id: image_id.to_string(),
        container_id: status["containerID"]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("calibration Pod lacks containerID")?
            .to_string(),
        process_mode: observed_mode("RUSTFS_DURABILITY_MODE")?,
        new_bucket_mode: observed_mode("RUSTFS_NEW_BUCKET_DURABILITY_MODE")?,
    })
}

/// A single mutation with no concurrent traffic, post-ACK verification read,
/// or retry. Avoiding activity after the ACK prevents the calibration workload
/// from accidentally flushing the metadata whose loss it is meant to detect.
#[derive(Debug)]
pub struct QuietMutationWorkload {
    mutation: QuietMutation,
}

#[derive(Debug)]
enum QuietMutation {
    Put(ObjectSpec),
    Overwrite { object: ObjectSpec, variant: u64 },
    DeleteMarker { key: String },
    ZeroBytePut(ObjectSpec),
    MultipartComplete(ObjectSpec),
    StagedMultipartComplete(StagedMultipartUpload),
}

impl QuietMutationWorkload {
    pub fn put(object: ObjectSpec) -> Self {
        Self {
            mutation: QuietMutation::Put(object),
        }
    }

    pub fn overwrite(object: ObjectSpec, variant: u64) -> Self {
        Self {
            mutation: QuietMutation::Overwrite { object, variant },
        }
    }

    pub fn delete_marker(key: impl Into<String>) -> std::result::Result<Self, TriggerError> {
        let key = key.into();
        if key.is_empty() {
            return Err(TriggerError::InvalidConfiguration {
                detail: "quiet delete-marker key must not be empty".to_string(),
            });
        }
        Ok(Self {
            mutation: QuietMutation::DeleteMarker { key },
        })
    }

    pub fn multipart_complete(object: ObjectSpec) -> Self {
        Self {
            mutation: QuietMutation::MultipartComplete(object),
        }
    }

    pub(crate) fn zero_byte_put(object: ObjectSpec) -> std::result::Result<Self, TriggerError> {
        if object.size_bytes != 0 {
            return Err(TriggerError::InvalidConfiguration {
                detail: "quiet zero-byte PUT must use an empty payload".to_string(),
            });
        }
        Ok(Self {
            mutation: QuietMutation::ZeroBytePut(object),
        })
    }

    pub(crate) fn staged_multipart_complete(staged: StagedMultipartUpload) -> Self {
        Self {
            mutation: QuietMutation::StagedMultipartComplete(staged),
        }
    }

    pub fn kind(&self) -> AcknowledgedMutationKind {
        match self.mutation {
            QuietMutation::Put(_) => AcknowledgedMutationKind::Put,
            QuietMutation::Overwrite { .. } => AcknowledgedMutationKind::Overwrite,
            QuietMutation::DeleteMarker { .. } => AcknowledgedMutationKind::DeleteMarker,
            QuietMutation::ZeroBytePut(_) => AcknowledgedMutationKind::ZeroBytePut,
            QuietMutation::MultipartComplete(_) | QuietMutation::StagedMultipartComplete(_) => {
                AcknowledgedMutationKind::MultipartComplete
            }
        }
    }

    async fn execute(
        self,
        client: &S3WorkloadClient,
        recorder: &Recorder,
    ) -> Result<Option<OperationRecord>> {
        match self.mutation {
            QuietMutation::Put(object) => client
                .put_object_record(&object.prepare(), recorder)
                .await
                .map(Some),
            QuietMutation::Overwrite { object, variant } => client
                .put_object_record(&object.prepare_overwrite(variant), recorder)
                .await
                .map(Some),
            QuietMutation::DeleteMarker { key } => {
                client.delete_marker_record(&key, recorder).await
            }
            QuietMutation::ZeroBytePut(object) => client
                .put_object_record(&object.prepare(), recorder)
                .await
                .map(Some),
            QuietMutation::MultipartComplete(object) => {
                client
                    .complete_multipart_object_record(&object.prepare(), recorder)
                    .await
            }
            QuietMutation::StagedMultipartComplete(staged) => {
                let result = client
                    .complete_staged_multipart_object_record(&staged, recorder)
                    .await;
                if !matches!(&result, Ok(record) if record.outcome == OperationOutcome::Ok) {
                    client
                        .abort_staged_multipart_object(&staged, recorder)
                        .await?;
                }
                result.map(Some)
            }
        }
    }
}

/// Executes one quiet mutation and starts a fault only when its completion is
/// a definite versioned commit. Mutation selection, waiting, activation, and
/// the deadline check are one operation so callers cannot accidentally bypass
/// a step. The activation callback returns the time when the actuator became
/// effective, not when activation merely started.
/// The wait deadline disarms activation. Before returning, this waits for
/// history finalization and, when needed, multipart cleanup with its own
/// request timeout. Callers must await completion rather than cancel the future.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcknowledgedMutationTrigger {
    operation_wait_timeout: Duration,
    max_ack_to_fault_ms: u64,
}

impl AcknowledgedMutationTrigger {
    pub fn new(
        operation_wait_timeout: Duration,
        max_ack_to_fault: Duration,
    ) -> std::result::Result<Self, TriggerError> {
        let operation_wait_timeout_ms =
            duration_ms("operation wait timeout", operation_wait_timeout)?;
        let max_ack_to_fault_ms = duration_ms("max ACK-to-fault duration", max_ack_to_fault)?;
        Ok(Self {
            operation_wait_timeout: Duration::from_millis(operation_wait_timeout_ms),
            max_ack_to_fault_ms,
        })
    }

    pub async fn execute_and_activate_fault<F>(
        self,
        client: &S3WorkloadClient,
        recorder: &Recorder,
        workload: QuietMutationWorkload,
        activate_fault: F,
    ) -> std::result::Result<AckToFaultEvidence, TriggerError>
    where
        F: FnOnce() -> Result<u64>,
    {
        let deadline = Instant::now()
            .checked_add(self.operation_wait_timeout)
            .ok_or_else(|| TriggerError::InvalidConfiguration {
                detail: "operation wait timeout exceeds the clock range".to_string(),
            })?;
        let client = client.for_quiet_mutation(deadline);
        let kind = workload.kind();
        let attempt = workload.execute(&client, recorder);
        self.execute_attempt_and_activate(kind, attempt, activate_fault, deadline)
            .await
    }

    async fn execute_attempt_and_activate<A, F>(
        self,
        kind: AcknowledgedMutationKind,
        attempt: A,
        activate_fault: F,
        deadline: Instant,
    ) -> std::result::Result<AckToFaultEvidence, TriggerError>
    where
        A: Future<Output = Result<Option<OperationRecord>>>,
        F: FnOnce() -> Result<u64>,
    {
        let acknowledged = self.wait_for(kind, attempt, deadline).await?;
        let fault_activated_at_ms =
            activate_fault().map_err(|error| TriggerError::FaultActivationFailed {
                operation_id: acknowledged.trigger_operation_id.clone(),
                detail: error.to_string(),
            })?;
        acknowledged.fault_activated_at(fault_activated_at_ms)
    }

    async fn wait_for<F>(
        self,
        kind: AcknowledgedMutationKind,
        attempt: F,
        deadline: Instant,
    ) -> std::result::Result<AcknowledgedMutation, TriggerError>
    where
        F: Future<Output = Result<Option<OperationRecord>>>,
    {
        // The client's mutation requests share this deadline. Await their
        // records and bounded cleanup instead of cancelling an in-flight
        // request between Recorder::begin and finish with another timeout.
        let record = attempt
            .await
            .map_err(|error| TriggerError::WorkloadFailed {
                kind,
                detail: error.to_string(),
            })?;
        if Instant::now() >= deadline {
            return Err(TriggerError::OperationInterrupted {
                wait_timeout_ms: self.operation_wait_timeout.as_millis() as u64,
            });
        }
        let record = record.ok_or(TriggerError::NoSignal { kind })?;

        AcknowledgedMutation::from_record(kind, record, self.max_ack_to_fault_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AcknowledgedMutation {
    trigger_operation_id: String,
    trigger_kind: AcknowledgedMutationKind,
    trigger_key: String,
    trigger_version_id: String,
    trigger_acknowledged_at_ms: u64,
    max_ack_to_fault_ms: u64,
}

impl AcknowledgedMutation {
    fn from_record(
        kind: AcknowledgedMutationKind,
        record: OperationRecord,
        max_ack_to_fault_ms: u64,
    ) -> std::result::Result<Self, TriggerError> {
        if record.kind != kind.operation_kind() {
            return Err(TriggerError::UnexpectedOperation {
                operation_id: record.id,
                expected: kind,
                actual: record.kind,
            });
        }
        if record.outcome != OperationOutcome::Ok {
            return Err(TriggerError::IneligibleOutcome {
                operation_id: record.id,
                outcome: record.outcome,
            });
        }
        if !record
            .http_status
            .is_some_and(|status| (200..300).contains(&status))
        {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "successful mutation is missing a 2xx HTTP status".to_string(),
            });
        }
        if record.ended_at_ms < record.started_at_ms {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "ACK timestamp precedes operation start".to_string(),
            });
        }
        let key = required_commit_field(&record.id, "key", record.key)?;
        let version_id = required_commit_field(&record.id, "version_id", record.version_id)?;
        if version_id.trim().is_empty() || version_id == "null" {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "committed mutation does not identify a versioned object".to_string(),
            });
        }
        if kind == AcknowledgedMutationKind::ZeroBytePut && record.size_bytes != Some(0) {
            return Err(TriggerError::InvalidAcknowledgement {
                operation_id: record.id,
                detail: "zero-byte PUT ACK does not identify an empty payload".to_string(),
            });
        }

        Ok(Self {
            trigger_operation_id: record.id,
            trigger_kind: kind,
            trigger_key: key,
            trigger_version_id: version_id,
            trigger_acknowledged_at_ms: record.ended_at_ms,
            max_ack_to_fault_ms,
        })
    }

    /// Confirms that the fault became active after the ACK and no later than
    /// the configured inclusive deadline.
    fn fault_activated_at(
        &self,
        fault_activated_at_ms: u64,
    ) -> std::result::Result<AckToFaultEvidence, TriggerError> {
        if fault_activated_at_ms < self.trigger_acknowledged_at_ms {
            return Err(TriggerError::FaultPredatesAcknowledgement {
                operation_id: self.trigger_operation_id.clone(),
                acknowledged_at_ms: self.trigger_acknowledged_at_ms,
                fault_activated_at_ms,
            });
        }
        let ack_to_fault_ms = fault_activated_at_ms - self.trigger_acknowledged_at_ms;
        if ack_to_fault_ms > self.max_ack_to_fault_ms {
            return Err(TriggerError::AckToFaultDeadlineExceeded {
                operation_id: self.trigger_operation_id.clone(),
                ack_to_fault_ms,
                max_ack_to_fault_ms: self.max_ack_to_fault_ms,
            });
        }

        Ok(AckToFaultEvidence {
            trigger_operation_id: self.trigger_operation_id.clone(),
            trigger_kind: self.trigger_kind,
            trigger_key: self.trigger_key.clone(),
            trigger_version_id: self.trigger_version_id.clone(),
            trigger_acknowledged_at_ms: self.trigger_acknowledged_at_ms,
            fault_activated_at_ms,
            ack_to_fault_ms,
            max_ack_to_fault_ms: self.max_ack_to_fault_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckToFaultEvidence {
    pub trigger_operation_id: String,
    pub trigger_kind: AcknowledgedMutationKind,
    pub trigger_key: String,
    pub trigger_version_id: String,
    pub trigger_acknowledged_at_ms: u64,
    pub fault_activated_at_ms: u64,
    pub ack_to_fault_ms: u64,
    pub max_ack_to_fault_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriggerError {
    InvalidConfiguration {
        detail: String,
    },
    OperationInterrupted {
        wait_timeout_ms: u64,
    },
    WorkloadFailed {
        kind: AcknowledgedMutationKind,
        detail: String,
    },
    NoSignal {
        kind: AcknowledgedMutationKind,
    },
    UnexpectedOperation {
        operation_id: String,
        expected: AcknowledgedMutationKind,
        actual: OperationKind,
    },
    IneligibleOutcome {
        operation_id: String,
        outcome: OperationOutcome,
    },
    InvalidAcknowledgement {
        operation_id: String,
        detail: String,
    },
    FaultActivationFailed {
        operation_id: String,
        detail: String,
    },
    FaultPredatesAcknowledgement {
        operation_id: String,
        acknowledged_at_ms: u64,
        fault_activated_at_ms: u64,
    },
    AckToFaultDeadlineExceeded {
        operation_id: String,
        ack_to_fault_ms: u64,
        max_ack_to_fault_ms: u64,
    },
}

impl fmt::Display for TriggerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfiguration { detail } => write!(formatter, "{detail}"),
            Self::OperationInterrupted { wait_timeout_ms } => write!(
                formatter,
                "quiet mutation exceeded the {wait_timeout_ms}ms operation wait; fault activation was not armed"
            ),
            Self::WorkloadFailed { kind, detail } => {
                write!(formatter, "quiet {kind:?} mutation failed: {detail}")
            }
            Self::NoSignal { kind } => write!(
                formatter,
                "quiet {kind:?} mutation produced no completed mutation to acknowledge"
            ),
            Self::UnexpectedOperation {
                operation_id,
                expected,
                actual,
            } => write!(
                formatter,
                "operation {operation_id} was {actual:?}, expected {expected:?}"
            ),
            Self::IneligibleOutcome {
                operation_id,
                outcome,
            } => write!(
                formatter,
                "operation {operation_id} ended with {outcome:?} and cannot arm an ACK trigger"
            ),
            Self::InvalidAcknowledgement {
                operation_id,
                detail,
            } => write!(
                formatter,
                "operation {operation_id} is not an eligible ACK: {detail}"
            ),
            Self::FaultActivationFailed {
                operation_id,
                detail,
            } => write!(
                formatter,
                "fault activation for operation {operation_id} failed: {detail}"
            ),
            Self::FaultPredatesAcknowledgement {
                operation_id,
                acknowledged_at_ms,
                fault_activated_at_ms,
            } => write!(
                formatter,
                "fault for operation {operation_id} became active at {fault_activated_at_ms}ms before its ACK at {acknowledged_at_ms}ms"
            ),
            Self::AckToFaultDeadlineExceeded {
                operation_id,
                ack_to_fault_ms,
                max_ack_to_fault_ms,
            } => write!(
                formatter,
                "fault for operation {operation_id} became active {ack_to_fault_ms}ms after its ACK, exceeding maxAckToFaultMs={max_ack_to_fault_ms}"
            ),
        }
    }
}

impl std::error::Error for TriggerError {}

fn duration_ms(name: &str, duration: Duration) -> std::result::Result<u64, TriggerError> {
    let milliseconds =
        u64::try_from(duration.as_millis()).map_err(|_| TriggerError::InvalidConfiguration {
            detail: format!("{name} exceeds the supported millisecond range"),
        })?;
    if milliseconds == 0 {
        return Err(TriggerError::InvalidConfiguration {
            detail: format!("{name} must be at least 1ms"),
        });
    }
    if Duration::from_millis(milliseconds) != duration {
        return Err(TriggerError::InvalidConfiguration {
            detail: format!("{name} must use whole milliseconds"),
        });
    }
    Ok(milliseconds)
}

fn required_commit_field(
    operation_id: &str,
    name: &str,
    value: Option<String>,
) -> std::result::Result<String, TriggerError> {
    value
        .filter(|value| !value.is_empty())
        .ok_or_else(|| TriggerError::InvalidAcknowledgement {
            operation_id: operation_id.to_string(),
            detail: format!("committed versioned mutation is missing {name}"),
        })
}

#[cfg(test)]
mod tests {
    use std::{
        cell::Cell,
        collections::VecDeque,
        future,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use axum::{
        Router,
        body::{Body, Bytes},
        http::{Method, Response, StatusCode, Uri},
    };
    use tokio::time::Instant;

    use super::{
        AcknowledgedMutation, AcknowledgedMutationKind, AcknowledgedMutationTrigger,
        QuietMutationWorkload, TriggerError,
    };
    use crate::fault::{
        history::{OperationKind, OperationOutcome, OperationRecord, Recorder},
        workload::{ObjectSpec, S3WorkloadClient, StagedMultipartCleanupGuard},
    };

    #[test]
    fn calibration_image_requires_an_immutable_digest_reference() {
        assert!(
            super::require_calibration_image(&format!("rustfs/rustfs@sha256:{}", "a".repeat(64)))
                .is_ok()
        );
        for image in [
            "rustfs/rustfs:latest",
            "rustfs/rustfs@sha256:abc",
            "@sha256:",
            "rustfs/rustfs@sha512:abc",
        ] {
            assert!(super::require_calibration_image(image).is_err());
        }
    }

    #[test]
    fn calibration_sets_both_modes_and_rejects_conflicting_or_duplicate_policy() {
        use super::AckCalibrationMode;
        for mode in [AckCalibrationMode::Strict, AckCalibrationMode::Relaxed] {
            let mut env = Vec::new();
            mode.configure(&mut env).unwrap();
            assert_eq!(env.len(), 2);
            assert!(env.iter().all(|(_, value)| value == mode.as_str()));
            mode.configure(&mut env).unwrap();
            assert_eq!(env.len(), 2);
            env.push(env[0].clone());
            assert!(mode.configure(&mut env).is_err());
        }
        let mut env = vec![("RUSTFS_NEW_BUCKET_DURABILITY_MODE".into(), "relaxed".into())];
        assert!(AckCalibrationMode::Strict.configure(&mut env).is_err());
    }

    #[test]
    fn calibration_observation_rejects_bucket_policy_and_image_drift() {
        use super::{AckCalibrationMode, calibration_pod};
        let pod = serde_json::json!({
            "metadata": {"name": "server-0", "uid": "pod-uid"},
            "spec": {"containers": [{"name": "rustfs", "image": "candidate", "env": [
                {"name": "RUSTFS_DURABILITY_MODE", "value": "strict"},
                {"name": "RUSTFS_NEW_BUCKET_DURABILITY_MODE", "value": "strict"}
            ]}]},
            "status": {"containerStatuses": [{"name": "rustfs", "ready": true,
                "containerID": "containerd://process-1",
                "imageID": format!("containerd://sha256:{}", "a".repeat(64))}]}
        });
        assert!(calibration_pod(&pod, AckCalibrationMode::Strict, "candidate").is_ok());
        let mut mismatch = pod.clone();
        mismatch["spec"]["containers"][0]["env"][1]["value"] = serde_json::json!("relaxed");
        assert!(calibration_pod(&mismatch, AckCalibrationMode::Strict, "candidate").is_err());
        assert!(calibration_pod(&pod, AckCalibrationMode::Strict, "other-image").is_err());
        let mut missing_digest = pod;
        missing_digest["status"]["containerStatuses"][0]["imageID"] =
            serde_json::json!("candidate:latest");
        assert!(calibration_pod(&missing_digest, AckCalibrationMode::Strict, "candidate").is_err());
    }

    enum MockReply {
        Ok,
        Hang,
        Error(StatusCode),
    }

    async fn mock_s3(
        replies: Vec<(OperationKind, MockReply)>,
    ) -> (
        S3WorkloadClient,
        Arc<Mutex<Vec<OperationKind>>>,
        tokio::task::JoinHandle<()>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let seen = requests.clone();
        let replies = Arc::new(Mutex::new(VecDeque::from(replies)));
        let app = Router::new().fallback(move |method: Method, uri: Uri, _body: Bytes| {
            let seen = seen.clone();
            let replies = replies.clone();
            async move {
                let query = uri.query().unwrap_or_default();
                let kind = match method {
                    Method::POST if query.contains("uploads") => OperationKind::CreateMultipartUpload,
                    Method::POST => OperationKind::CompleteMultipartUpload,
                    Method::PUT if query.contains("partNumber=") => OperationKind::UploadPart,
                    Method::PUT => OperationKind::Put,
                    Method::DELETE if query.contains("uploadId=") => OperationKind::AbortMultipartUpload,
                    Method::DELETE => OperationKind::Delete,
                    _ => panic!("unexpected S3 request: {method} {uri}"),
                };
                assert_eq!(uri.path(), "/bucket/key");
                if matches!(kind, OperationKind::UploadPart | OperationKind::CompleteMultipartUpload | OperationKind::AbortMultipartUpload) {
                    assert!(query.contains("uploadId=upload-1"));
                }
                seen.lock().expect("requests").push(kind);
                let (expected, reply) = replies.lock().expect("replies").pop_front().expect("unexpected extra request");
                assert_eq!(kind, expected);
                match reply {
                    MockReply::Hang => future::pending().await,
                    MockReply::Error(status) => Response::builder().status(status)
                        .body(Body::from("<Error><Code>InternalError</Code><Message>injected error</Message></Error>"))
                        .expect("error response"),
                    MockReply::Ok => {
                        let body = match kind {
                            OperationKind::CreateMultipartUpload => "<InitiateMultipartUploadResult><Bucket>bucket</Bucket><Key>key</Key><UploadId>upload-1</UploadId></InitiateMultipartUploadResult>",
                            OperationKind::CompleteMultipartUpload => "<CompleteMultipartUploadResult><Bucket>bucket</Bucket><Key>key</Key><ETag>etag</ETag></CompleteMultipartUploadResult>",
                            _ => "",
                        };
                        Response::builder()
                            .status(if method == Method::DELETE { StatusCode::NO_CONTENT } else { StatusCode::OK })
                            .header("x-amz-version-id", "version-1")
                            .header("x-amz-delete-marker", "true")
                            .header("etag", "etag")
                            .body(Body::from(body)).expect("response")
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
            Duration::from_secs(1),
        )
        .await
        .expect("client");
        (client, requests, server)
    }

    fn test_object() -> ObjectSpec {
        let mut spec = ObjectSpec::prepare_seeded("ack", 0, 1024, 7).spec;
        spec.key = "key".into();
        spec
    }

    fn persisted_records(recorder: &Recorder) -> Vec<OperationRecord> {
        let records: Vec<OperationRecord> = std::fs::read_to_string(recorder.path())
            .expect("history")
            .lines()
            .map(|line| serde_json::from_str(line).expect("record"))
            .collect();
        assert_eq!(
            serde_json::to_value(&records).expect("disk records"),
            serde_json::to_value(recorder.records()).expect("memory records")
        );
        records
    }

    #[tokio::test]
    async fn timed_out_s3_mutations_persist_history_and_cleanup_known_uploads() {
        for stalled in [
            OperationKind::Put,
            OperationKind::Delete,
            OperationKind::CreateMultipartUpload,
            OperationKind::UploadPart,
            OperationKind::CompleteMultipartUpload,
        ] {
            let mut expected = match stalled {
                OperationKind::Put
                | OperationKind::Delete
                | OperationKind::CreateMultipartUpload => vec![stalled],
                OperationKind::UploadPart => vec![OperationKind::CreateMultipartUpload, stalled],
                _ => vec![
                    OperationKind::CreateMultipartUpload,
                    OperationKind::UploadPart,
                    stalled,
                ],
            };
            let mut replies = expected
                .iter()
                .map(|kind| {
                    (
                        *kind,
                        if *kind == stalled {
                            MockReply::Hang
                        } else {
                            MockReply::Ok
                        },
                    )
                })
                .collect::<Vec<_>>();
            if matches!(
                stalled,
                OperationKind::UploadPart | OperationKind::CompleteMultipartUpload
            ) {
                expected.push(OperationKind::AbortMultipartUpload);
                replies.push((OperationKind::AbortMultipartUpload, MockReply::Ok));
            }
            let (client, requests, server) = mock_s3(replies).await;
            let dir = tempfile::tempdir().expect("tempdir");
            let recorder =
                Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
            let workload = match stalled {
                OperationKind::Put => QuietMutationWorkload::put(test_object()),
                OperationKind::Delete => {
                    QuietMutationWorkload::delete_marker("key").expect("delete")
                }
                _ => QuietMutationWorkload::multipart_complete(test_object()),
            };
            let trigger = AcknowledgedMutationTrigger::new(
                Duration::from_millis(300),
                Duration::from_secs(1),
            )
            .expect("trigger");
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                trigger.execute_and_activate_fault(&client, &recorder, workload, || {
                    panic!("timed-out mutation armed the fault")
                }),
            )
            .await
            .expect("bounded settling");
            assert_eq!(
                result,
                Err(TriggerError::OperationInterrupted {
                    wait_timeout_ms: 300
                }),
                "{stalled:?}"
            );
            assert_eq!(*requests.lock().expect("requests"), expected);
            let records = persisted_records(&recorder);
            assert_eq!(
                records.iter().map(|record| record.kind).collect::<Vec<_>>(),
                expected
            );
            for record in records {
                assert_eq!(
                    record.outcome,
                    if record.kind == stalled {
                        OperationOutcome::Timeout
                    } else {
                        OperationOutcome::Ok
                    }
                );
                assert!(record.ended_at_ms >= record.started_at_ms);
            }
            server.abort();
        }
    }

    #[tokio::test]
    async fn multipart_cleanup_failure_is_recorded_and_reported_without_arming() {
        for cleanup in [MockReply::Error(StatusCode::FORBIDDEN), MockReply::Hang] {
            let expected_outcome = if matches!(cleanup, MockReply::Hang) {
                OperationOutcome::Timeout
            } else {
                OperationOutcome::Failed
            };
            let (client, requests, server) = mock_s3(vec![
                (OperationKind::CreateMultipartUpload, MockReply::Ok),
                (OperationKind::UploadPart, MockReply::Hang),
                (OperationKind::AbortMultipartUpload, cleanup),
            ])
            .await;
            let dir = tempfile::tempdir().expect("tempdir");
            let recorder =
                Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
            let trigger = AcknowledgedMutationTrigger::new(
                Duration::from_millis(300),
                Duration::from_secs(1),
            )
            .expect("trigger");
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                trigger.execute_and_activate_fault(
                    &client,
                    &recorder,
                    QuietMutationWorkload::multipart_complete(test_object()),
                    || panic!("failed cleanup armed the fault"),
                ),
            )
            .await
            .expect("bounded cleanup");
            let Err(TriggerError::WorkloadFailed { detail, .. }) = result else {
                panic!("expected cleanup error: {result:?}");
            };
            assert!(detail.contains("key key upload upload-1"), "{detail}");
            assert!(
                detail.contains(&format!("{expected_outcome:?}")),
                "{detail}"
            );
            let records = persisted_records(&recorder);
            assert_eq!(records.len(), 3);
            assert_eq!(records[1].outcome, OperationOutcome::Timeout);
            assert_eq!(records[2].outcome, expected_outcome);
            assert_eq!(requests.lock().expect("requests").len(), 3);
            server.abort();
        }
    }

    #[tokio::test]
    async fn prefault_staging_deadline_finishes_history_and_aborts_known_upload() {
        let expected = vec![
            OperationKind::CreateMultipartUpload,
            OperationKind::UploadPart,
            OperationKind::AbortMultipartUpload,
        ];
        let (client, requests, server) = mock_s3(vec![
            (OperationKind::CreateMultipartUpload, MockReply::Ok),
            (OperationKind::UploadPart, MockReply::Hang),
            (OperationKind::AbortMultipartUpload, MockReply::Ok),
        ])
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
        let object = test_object().prepare();
        let quiet = client.for_quiet_mutation(Instant::now() + Duration::from_millis(300));

        tokio::time::timeout(
            Duration::from_secs(5),
            quiet.stage_multipart_object(&object, &recorder),
        )
        .await
        .expect("staging and cleanup are bounded")
        .expect_err("stalled part cannot produce a staged upload");

        assert_eq!(*requests.lock().expect("requests"), expected);
        let records = persisted_records(&recorder);
        assert_eq!(
            records.iter().map(|record| record.kind).collect::<Vec<_>>(),
            expected
        );
        assert_eq!(records[0].outcome, OperationOutcome::Ok);
        assert_eq!(records[1].outcome, OperationOutcome::Timeout);
        assert_eq!(records[2].outcome, OperationOutcome::Ok);
        assert!(records.iter().all(|record| record.ended_sequence.is_some()));
        server.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelling_a_pre_staged_completion_aborts_the_registered_upload() {
        let expected = vec![
            OperationKind::CreateMultipartUpload,
            OperationKind::UploadPart,
            OperationKind::CompleteMultipartUpload,
            OperationKind::AbortMultipartUpload,
        ];
        let (client, requests, server) = mock_s3(vec![
            (OperationKind::CreateMultipartUpload, MockReply::Ok),
            (OperationKind::UploadPart, MockReply::Ok),
            (OperationKind::CompleteMultipartUpload, MockReply::Hang),
            (OperationKind::AbortMultipartUpload, MockReply::Ok),
        ])
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
        let staged = client
            .stage_multipart_object(&test_object().prepare(), &recorder)
            .await
            .expect("staged upload");
        let cleanup =
            StagedMultipartCleanupGuard::new(client.clone(), recorder.clone(), staged.clone());
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_secs(5), Duration::from_secs(1))
                .expect("trigger");

        let cancelled = tokio::time::timeout(
            Duration::from_millis(50),
            trigger.execute_and_activate_fault(
                &client,
                &recorder,
                QuietMutationWorkload::staged_multipart_complete(staged),
                || panic!("cancelled completion armed the fault"),
            ),
        )
        .await;
        assert!(cancelled.is_err(), "completion must still be in flight");
        drop(cleanup);

        assert_eq!(*requests.lock().expect("requests"), expected);
        let records = persisted_records(&recorder);
        assert_eq!(
            records.iter().map(|record| record.kind).collect::<Vec<_>>(),
            vec![
                OperationKind::CreateMultipartUpload,
                OperationKind::UploadPart,
                OperationKind::AbortMultipartUpload,
            ]
        );
        server.abort();
    }

    #[tokio::test]
    async fn quiet_mutation_does_not_retry_retryable_s3_errors() {
        let (client, requests, server) = mock_s3(vec![(
            OperationKind::Put,
            MockReply::Error(StatusCode::INTERNAL_SERVER_ERROR),
        )])
        .await;
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_secs(5), Duration::from_secs(1))
                .expect("trigger");
        let result = trigger
            .execute_and_activate_fault(
                &client,
                &recorder,
                QuietMutationWorkload::put(test_object()),
                || panic!("failed request armed the fault"),
            )
            .await;
        assert!(matches!(
            result,
            Err(TriggerError::IneligibleOutcome { .. })
        ));
        assert_eq!(
            *requests.lock().expect("requests"),
            vec![OperationKind::Put]
        );
        assert_eq!(persisted_records(&recorder).len(), 1);
        server.abort();
    }

    #[tokio::test]
    async fn failed_multipart_completion_aborts_without_retrying_and_accepts_missing_upload() {
        let replies = vec![
            (OperationKind::CreateMultipartUpload, MockReply::Ok),
            (OperationKind::UploadPart, MockReply::Ok),
            (
                OperationKind::CompleteMultipartUpload,
                MockReply::Error(StatusCode::INTERNAL_SERVER_ERROR),
            ),
            (
                OperationKind::AbortMultipartUpload,
                MockReply::Error(StatusCode::NOT_FOUND),
            ),
        ];
        let expected: Vec<_> = replies.iter().map(|(kind, _)| *kind).collect();
        let (client, requests, server) = mock_s3(replies).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_secs(5), Duration::from_secs(1))
                .expect("trigger");
        let result = trigger
            .execute_and_activate_fault(
                &client,
                &recorder,
                QuietMutationWorkload::multipart_complete(test_object()),
                || panic!("failed completion armed the fault"),
            )
            .await;

        assert!(matches!(
            result,
            Err(TriggerError::IneligibleOutcome { .. })
        ));
        assert_eq!(*requests.lock().expect("requests"), expected);
        let records = persisted_records(&recorder);
        assert_eq!(records.len(), 4);
        assert_eq!(records[2].http_status, Some(500));
        assert_eq!(records[3].outcome, OperationOutcome::NotFound);
        server.abort();
    }

    #[tokio::test]
    async fn successful_multipart_ack_activates_without_post_ack_requests() {
        let expected = vec![
            OperationKind::CreateMultipartUpload,
            OperationKind::UploadPart,
            OperationKind::CompleteMultipartUpload,
        ];
        let (client, requests, server) =
            mock_s3(expected.iter().map(|kind| (*kind, MockReply::Ok)).collect()).await;
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_secs(5), Duration::from_secs(1))
                .expect("trigger");
        let activated = Cell::new(false);
        let evidence = trigger
            .execute_and_activate_fault(
                &client,
                &recorder,
                QuietMutationWorkload::multipart_complete(test_object()),
                || {
                    activated.set(true);
                    assert_eq!(*requests.lock().expect("requests"), expected);
                    let records = persisted_records(&recorder);
                    assert_eq!(records.len(), 3);
                    Ok(records[2].ended_at_ms)
                },
            )
            .await
            .expect("acknowledged");
        assert!(activated.get());
        assert_eq!(evidence.trigger_version_id, "version-1");
        assert_eq!(*requests.lock().expect("requests"), expected);
        server.abort();
    }

    fn record(
        kind: OperationKind,
        outcome: OperationOutcome,
        key: Option<&str>,
        version_id: Option<&str>,
        started_at_ms: u64,
        ended_at_ms: u64,
    ) -> OperationRecord {
        OperationRecord {
            run_id: None,
            id: "op-000042".to_string(),
            scenario: "ack-trigger-test".to_string(),
            kind,
            bucket: "bucket".to_string(),
            key: key.map(str::to_string),
            value_sha256: None,
            size_bytes: None,
            version_id: version_id.map(str::to_string),
            request_version_id: None,
            is_delete_marker: None,
            mutation_max_attempts: None,
            mutation_attempts: None,
            read_purpose: None,
            listed_keys: None,
            listed_versions: None,
            payload_ref: None,
            range: None,
            started_sequence: None,
            ended_sequence: None,
            started_at_ms,
            ended_at_ms,
            outcome,
            http_status: Some(200),
            error: None,
            durability_cohort: None,
            fault_window_relation: None,
        }
    }

    fn qualify(
        kind: AcknowledgedMutationKind,
        record: OperationRecord,
    ) -> std::result::Result<AcknowledgedMutation, TriggerError> {
        AcknowledgedMutation::from_record(kind, record, 25)
    }

    #[test]
    fn eligible_versioned_mutations_preserve_trigger_identity() {
        let cases = [
            (
                AcknowledgedMutationKind::Put,
                OperationKind::Put,
                "put-version",
            ),
            (
                AcknowledgedMutationKind::Overwrite,
                OperationKind::Put,
                "overwrite-version",
            ),
            (
                AcknowledgedMutationKind::DeleteMarker,
                OperationKind::Delete,
                "delete-marker-version",
            ),
            (
                AcknowledgedMutationKind::MultipartComplete,
                OperationKind::CompleteMultipartUpload,
                "multipart-version",
            ),
        ];

        for (trigger_kind, operation_kind, version_id) in cases {
            let acknowledged = qualify(
                trigger_kind,
                record(
                    operation_kind,
                    OperationOutcome::Ok,
                    Some("key"),
                    Some(version_id),
                    100,
                    110,
                ),
            )
            .expect("eligible mutation");

            assert_eq!(acknowledged.trigger_operation_id, "op-000042");
            assert_eq!(acknowledged.trigger_kind, trigger_kind);
            assert_eq!(acknowledged.trigger_key, "key");
            assert_eq!(acknowledged.trigger_version_id, version_id);
            assert_eq!(acknowledged.trigger_acknowledged_at_ms, 110);
        }

        let mut zero_byte = record(
            OperationKind::Put,
            OperationOutcome::Ok,
            Some("empty"),
            Some("zero-version"),
            100,
            110,
        );
        zero_byte.size_bytes = Some(0);
        assert!(qualify(AcknowledgedMutationKind::ZeroBytePut, zero_byte).is_ok());
    }

    #[test]
    fn timeout_unknown_and_failed_outcomes_never_arm() {
        for outcome in [
            OperationOutcome::NotFound,
            OperationOutcome::Timeout,
            OperationOutcome::Unknown,
            OperationOutcome::Failed,
        ] {
            let error = qualify(
                AcknowledgedMutationKind::Put,
                record(
                    OperationKind::Put,
                    outcome,
                    Some("key"),
                    Some("version"),
                    100,
                    110,
                ),
            )
            .expect_err("ineligible outcome");

            assert!(matches!(
                error,
                TriggerError::IneligibleOutcome {
                    outcome: actual,
                    ..
                } if actual == outcome
            ));
        }
    }

    #[test]
    fn quiet_workload_declares_one_semantic_mutation() {
        let object = crate::fault::workload::ObjectSpec::prepare_seeded("run", 7, 4096, 42).spec;
        let empty = crate::fault::workload::ObjectSpec::prepare_seeded("run", 8, 0, 42).spec;
        let cases = [
            QuietMutationWorkload::put(object.clone()),
            QuietMutationWorkload::overwrite(object.clone(), 2),
            QuietMutationWorkload::delete_marker(object.key.clone()).expect("delete marker"),
            QuietMutationWorkload::zero_byte_put(empty).expect("zero byte"),
            QuietMutationWorkload::multipart_complete(object.clone()),
        ];

        assert_eq!(cases[0].kind(), AcknowledgedMutationKind::Put);
        assert_eq!(cases[1].kind(), AcknowledgedMutationKind::Overwrite);
        assert_eq!(cases[2].kind(), AcknowledgedMutationKind::DeleteMarker);
        assert_eq!(cases[3].kind(), AcknowledgedMutationKind::ZeroBytePut);
        assert_eq!(cases[4].kind(), AcknowledgedMutationKind::MultipartComplete);
        assert!(QuietMutationWorkload::delete_marker("").is_err());
        assert!(QuietMutationWorkload::zero_byte_put(object).is_err());
    }

    #[test]
    fn zero_byte_trigger_rejects_nonempty_ack_records() {
        let record = record(
            OperationKind::Put,
            OperationOutcome::Ok,
            Some("key"),
            Some("version"),
            100,
            110,
        );
        assert!(matches!(
            qualify(AcknowledgedMutationKind::ZeroBytePut, record),
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));
    }

    #[test]
    fn missing_commit_identity_and_wrong_operation_never_arm() {
        let missing_key = qualify(
            AcknowledgedMutationKind::Put,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                None,
                Some("version"),
                100,
                110,
            ),
        );
        assert!(matches!(
            missing_key,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));

        let missing_version = qualify(
            AcknowledgedMutationKind::DeleteMarker,
            record(
                OperationKind::Delete,
                OperationOutcome::Ok,
                Some("key"),
                None,
                100,
                110,
            ),
        );
        assert!(matches!(
            missing_version,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));

        let null_version = qualify(
            AcknowledgedMutationKind::Put,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("null"),
                100,
                110,
            ),
        );
        assert!(matches!(
            null_version,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));

        let wrong_operation = qualify(
            AcknowledgedMutationKind::MultipartComplete,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("version"),
                100,
                110,
            ),
        );
        assert!(matches!(
            wrong_operation,
            Err(TriggerError::UnexpectedOperation { .. })
        ));
    }

    #[test]
    fn malformed_ack_ordering_never_arms() {
        let result = qualify(
            AcknowledgedMutationKind::Put,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("version"),
                111,
                110,
            ),
        );

        assert!(matches!(
            result,
            Err(TriggerError::InvalidAcknowledgement { .. })
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn wait_timeout_finishes_record_without_arming_even_with_a_late_ack() {
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_millis(10), Duration::from_millis(5))
                .expect("trigger");
        let dir = tempfile::tempdir().expect("tempdir");
        let recorder =
            Recorder::create(dir.path().join("history.jsonl"), "ack", "run").expect("recorder");
        let activated = Cell::new(false);
        let attempt = async {
            let mut record =
                recorder.begin(OperationKind::Put, "bucket", Some("key".into()), None, None);
            tokio::time::sleep(Duration::from_millis(20)).await;
            record.version_id = Some("late-version".into());
            recorder
                .finish(record, OperationOutcome::Ok, Some(200), None)
                .map(Some)
        };

        let result = trigger
            .execute_attempt_and_activate(
                AcknowledgedMutationKind::Put,
                attempt,
                || {
                    activated.set(true);
                    Ok(111)
                },
                Instant::now() + Duration::from_millis(10),
            )
            .await;

        assert_eq!(
            result,
            Err(TriggerError::OperationInterrupted {
                wait_timeout_ms: 10
            })
        );
        assert!(!activated.get());
        assert_eq!(persisted_records(&recorder).len(), 1);
    }

    #[tokio::test]
    async fn completed_workload_without_mutation_is_no_signal() {
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_millis(10), Duration::from_millis(5))
                .expect("trigger");

        let result = trigger
            .wait_for(
                AcknowledgedMutationKind::MultipartComplete,
                future::ready(Ok(None)),
                Instant::now() + Duration::from_millis(10),
            )
            .await;

        assert_eq!(
            result,
            Err(TriggerError::NoSignal {
                kind: AcknowledgedMutationKind::MultipartComplete
            })
        );
    }

    #[tokio::test]
    async fn ineligible_operation_never_invokes_fault_actuator() {
        let trigger =
            AcknowledgedMutationTrigger::new(Duration::from_millis(10), Duration::from_millis(5))
                .expect("trigger");
        let activated = Cell::new(false);
        let attempt = future::ready(Ok(Some(record(
            OperationKind::Put,
            OperationOutcome::Unknown,
            Some("key"),
            Some("version"),
            100,
            110,
        ))));

        let result = trigger
            .execute_attempt_and_activate(
                AcknowledgedMutationKind::Put,
                attempt,
                || {
                    activated.set(true);
                    Ok(111)
                },
                Instant::now() + Duration::from_millis(10),
            )
            .await;

        assert!(matches!(
            result,
            Err(TriggerError::IneligibleOutcome { .. })
        ));
        assert!(!activated.get());
    }

    #[test]
    fn ack_to_fault_deadline_is_inclusive_and_ordered() {
        let acknowledged = qualify(
            AcknowledgedMutationKind::Overwrite,
            record(
                OperationKind::Put,
                OperationOutcome::Ok,
                Some("key"),
                Some("version"),
                100,
                110,
            ),
        )
        .expect("acknowledged");

        let same_millisecond = acknowledged
            .fault_activated_at(110)
            .expect("same millisecond");
        assert_eq!(same_millisecond.ack_to_fault_ms, 0);

        let exact_boundary = acknowledged
            .fault_activated_at(135)
            .expect("inclusive boundary");
        assert_eq!(exact_boundary.ack_to_fault_ms, 25);

        assert!(matches!(
            acknowledged.fault_activated_at(109),
            Err(TriggerError::FaultPredatesAcknowledgement { .. })
        ));
        assert_eq!(
            acknowledged.fault_activated_at(136),
            Err(TriggerError::AckToFaultDeadlineExceeded {
                operation_id: "op-000042".to_string(),
                ack_to_fault_ms: 26,
                max_ack_to_fault_ms: 25,
            })
        );
    }

    #[test]
    fn trigger_durations_must_be_positive_whole_milliseconds() {
        let zero_wait = AcknowledgedMutationTrigger::new(Duration::ZERO, Duration::from_millis(1));
        let submillisecond_deadline = AcknowledgedMutationTrigger::new(
            Duration::from_millis(1),
            Duration::from_nanos(999_999),
        );

        assert!(matches!(
            zero_wait,
            Err(TriggerError::InvalidConfiguration { .. })
        ));
        assert!(matches!(
            submillisecond_deadline,
            Err(TriggerError::InvalidConfiguration { .. })
        ));
    }
}
