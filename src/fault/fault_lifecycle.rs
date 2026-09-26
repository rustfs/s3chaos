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

use crate::{
    fault::{
        config::FaultTestConfig, fault_artifacts::FaultFailureArtifactSource,
        host_storage::DmStatusSnapshot, reporting::FaultStatusSnapshot,
    },
    framework::artifacts::ArtifactCollector,
};
use anyhow::Result;
use std::sync::{Arc, atomic::AtomicU64};
use std::time::{Duration, Instant};

pub(super) trait FaultLifecyclePort: Send {
    fn wait_active(&self, timeout: Duration) -> Result<()>;
    fn ensure_active(&self, stage: &str) -> Result<()>;
    fn requires_recovery_boundary(&self) -> bool {
        false
    }
    fn prepare_recovery_boundary(&mut self, _timeout: Duration, _started_at_ms: u64) -> Result<()> {
        Ok(())
    }
    fn delete(&mut self, timeout: Duration) -> Result<()>;
    fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot>;

    /// Harness-time slot the runner fills when the first fault-phase S3
    /// request starts; a backend whose disruption must land under load waits
    /// on it before acting.
    fn load_gate(&self) -> Option<Arc<AtomicU64>> {
        None
    }

    /// Re-read the fault's own evidence once the recovery gate has passed.
    fn verify_after_recovery(&mut self) -> Result<()> {
        Ok(())
    }

    fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
        None
    }

    fn failure_artifacts(&self) -> Option<&dyn FaultFailureArtifactSource> {
        None
    }

    fn recover_delete_timeout(
        &mut self,
        _request: &FaultDeleteTimeoutRecoveryRequest<'_>,
    ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
        Ok(None)
    }
}

pub(super) type AppliedFault = Box<dyn FaultLifecyclePort>;

/// A fault-removal error that carries its own failure classification. The
/// runner classifies removal failures as environment/backend problems by
/// default; a backend that observed a product defect while removing the
/// fault (for example a RustFS container SIGKILLed at grace expiry) reports it
/// through this type so the verdict is not misattributed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ClassifiedFaultFailure {
    pub(super) classification: &'static str,
    pub(super) message: String,
}

impl std::fmt::Display for ClassifiedFaultFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ClassifiedFaultFailure {}

pub(super) fn removal_failure_classification(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<ClassifiedFaultFailure>()
        .map_or("environment_or_fault_backend", |failure| {
            failure.classification
        })
}

pub(super) struct FaultDeleteTimeoutRecoveryRequest<'a> {
    pub(super) config: &'a FaultTestConfig,
    pub(super) collector: &'a ArtifactCollector,
    pub(super) case_name: &'a str,
    pub(super) run_id: &'a str,
    pub(super) original_error: &'a anyhow::Error,
    pub(super) delete_started_at: Instant,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FaultDeleteTimeoutRecovery {
    pub(super) warning_artifact: &'static str,
    pub(super) resource_name: String,
    pub(super) target_nodes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedFault, FaultDeleteTimeoutRecovery, FaultDeleteTimeoutRecoveryRequest,
        FaultLifecyclePort,
    };
    use crate::fault::{
        backends::host::{DmStatusSnapshot, DmVolumeMapping},
        config::FaultTestConfig,
        host_storage::{HostStorageNodeSelector, HostStoragePersistentVolumeClaimRef},
        reporting::FaultStatusSnapshot,
    };
    use crate::framework::artifacts::ArtifactCollector;
    use anyhow::{Result, anyhow};
    use std::{
        collections::BTreeMap,
        sync::{Arc, Mutex},
        time::{Duration, Instant},
    };

    #[derive(Default)]
    struct RecordingFaultState {
        waits: Vec<(&'static str, Duration)>,
        deletes: Vec<(&'static str, Duration)>,
        recoveries: Vec<&'static str>,
    }

    type SharedRecordingFaultState = Arc<Mutex<RecordingFaultState>>;

    struct RecordingFault {
        name: &'static str,
        state: SharedRecordingFaultState,
        recovery_dm_snapshot: Option<DmStatusSnapshot>,
    }

    impl RecordingFault {
        fn new(name: &'static str, state: SharedRecordingFaultState) -> Self {
            Self {
                name,
                state,
                recovery_dm_snapshot: None,
            }
        }

        fn with_recovery_dm_snapshot(mut self, snapshot: DmStatusSnapshot) -> Self {
            self.recovery_dm_snapshot = Some(snapshot);
            self
        }
    }

    impl FaultLifecyclePort for RecordingFault {
        fn wait_active(&self, timeout: Duration) -> Result<()> {
            self.state
                .lock()
                .expect("state")
                .waits
                .push((self.name, timeout));
            Ok(())
        }

        fn ensure_active(&self, _stage: &str) -> Result<()> {
            Ok(())
        }

        fn delete(&mut self, timeout: Duration) -> Result<()> {
            self.state
                .lock()
                .expect("state")
                .deletes
                .push((self.name, timeout));
            Ok(())
        }

        fn snapshot(&self, stage: &str) -> Result<FaultStatusSnapshot> {
            Ok(FaultStatusSnapshot {
                stage: stage.to_string(),
                resource_kind: Some("recording".to_string()),
                resource_name: Some(self.name.to_string()),
                chaos_status: None,
                dm_status: None,
                lifecycle_status: None,
                controller_target_pods: None,
            })
        }

        fn recovery_dm_snapshot(&self) -> Option<DmStatusSnapshot> {
            self.recovery_dm_snapshot.clone()
        }

        fn recover_delete_timeout(
            &mut self,
            _request: &FaultDeleteTimeoutRecoveryRequest<'_>,
        ) -> Result<Option<FaultDeleteTimeoutRecovery>> {
            self.state.lock().expect("state").recoveries.push(self.name);
            Ok(None)
        }
    }

    fn recording_state() -> SharedRecordingFaultState {
        Arc::new(Mutex::new(RecordingFaultState::default()))
    }

    fn recording_dm_snapshot(stage: &str, helper_pod: &str) -> DmStatusSnapshot {
        DmStatusSnapshot {
            stage: stage.to_string(),
            mapper_name: "rustfs-fault-dm".to_string(),
            canonical_device: "/dev/dm-0".to_string(),
            suspended: false,
            observed_at_ms: 1,
            helper_pod: helper_pod.to_string(),
            mapping: DmVolumeMapping {
                node: "node-a".to_string(),
                node_uid: "node-uid-a".to_string(),
                node_labels: BTreeMap::from([(
                    "kubernetes.io/hostname".to_string(),
                    "node-a".to_string(),
                )]),
                pod: "rustfs-0".to_string(),
                pod_uid: "pod-uid-a".to_string(),
                volume_name: "data".to_string(),
                pvc: "data-rustfs-0".to_string(),
                pvc_uid: "pvc-uid-a".to_string(),
                pvc_phase: "Bound".to_string(),
                pv: "pv-a".to_string(),
                pv_uid: "pv-uid-a".to_string(),
                pv_phase: "Bound".to_string(),
                pv_claim_ref: HostStoragePersistentVolumeClaimRef {
                    namespace: "rustfs-fault-test".to_string(),
                    name: "data-rustfs-0".to_string(),
                    uid: "pvc-uid-a".to_string(),
                },
                node_selector: HostStorageNodeSelector {
                    key: "kubernetes.io/hostname".to_string(),
                    operator: "In".to_string(),
                    values: vec!["node-a".to_string()],
                },
                container_mount_path: "/data/rustfs0".to_string(),
                mount_path: "/data/rustfs0".to_string(),
            },
            table: "0 2048 flakey /dev/sda 0 1 1".to_string(),
            status: "0 2048 flakey 1 0".to_string(),
        }
    }

    fn recovery_request<'a>(
        config: &'a FaultTestConfig,
        collector: &'a ArtifactCollector,
        original_error: &'a anyhow::Error,
    ) -> FaultDeleteTimeoutRecoveryRequest<'a> {
        FaultDeleteTimeoutRecoveryRequest {
            config,
            collector,
            case_name: "case",
            run_id: "run-123",
            original_error,
            delete_started_at: Instant::now(),
        }
    }

    #[test]
    fn applied_fault_delegates_lifecycle_and_snapshot_to_its_owner() {
        let state = recording_state();
        let mut fault: AppliedFault = Box::new(RecordingFault::new("target", state.clone()));
        fault
            .wait_active(Duration::from_secs(7))
            .expect("wait active");
        fault.ensure_active("workload").expect("active");
        let snapshot = fault.snapshot("after-workload").expect("snapshot");
        assert_eq!(snapshot.resource_name.as_deref(), Some("target"));
        assert_eq!(snapshot.stage, "after-workload");
        fault.delete(Duration::from_secs(1)).expect("delete");
        assert_eq!(
            state.lock().expect("state").waits,
            vec![("target", Duration::from_secs(7))]
        );
        assert_eq!(
            state.lock().expect("state").deletes,
            vec![("target", Duration::from_secs(1))]
        );
    }

    #[test]
    fn applied_fault_routes_recovery_to_its_owner() {
        let state = recording_state();
        let mut fault: AppliedFault = Box::new(RecordingFault::new("target", state.clone()));
        let tempdir = tempfile::tempdir().expect("tempdir");
        let collector = ArtifactCollector::new(tempdir.path());
        let config = FaultTestConfig::for_test("context", "storage");
        let original_error = anyhow!("timeout");
        assert!(
            fault
                .recover_delete_timeout(&recovery_request(&config, &collector, &original_error))
                .expect("recover")
                .is_none()
        );
        assert_eq!(state.lock().expect("state").recoveries, vec!["target"]);
    }

    #[test]
    fn removal_failures_keep_their_backend_classification_through_context() {
        let plain = anyhow!("kubectl timed out");
        assert_eq!(
            super::removal_failure_classification(&plain),
            "environment_or_fault_backend"
        );
        let classified: anyhow::Error = super::ClassifiedFaultFailure {
            classification: "graceful_shutdown_failed",
            message: "Pod exited 137".to_string(),
        }
        .into();
        assert_eq!(
            super::removal_failure_classification(&classified),
            "graceful_shutdown_failed"
        );
        let wrapped = classified.context("removing applied faults");
        assert_eq!(
            super::removal_failure_classification(&wrapped),
            "graceful_shutdown_failed"
        );
        assert!(wrapped.to_string().contains("removing applied faults"));
    }

    #[test]
    fn applied_fault_preserves_backend_recovery_evidence() {
        let expected = recording_dm_snapshot("recovered", "helper");
        let fault: AppliedFault = Box::new(
            RecordingFault::new("target", recording_state())
                .with_recovery_dm_snapshot(expected.clone()),
        );
        assert_eq!(fault.recovery_dm_snapshot(), Some(expected));
        assert!(!fault.requires_recovery_boundary());
        assert!(fault.failure_artifacts().is_none());
    }
}
