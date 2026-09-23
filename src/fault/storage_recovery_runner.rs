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

//! Common execution lifecycle for explicitly qualified storage recovery.

use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, ensure};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{
    fault::{
        config::FaultTestConfig,
        plan::{ExecutionPlan, StorageRecoveryExecutionPlan},
        scenarios::FaultScenario,
        shutdown::RunDeadline,
        storage_recovery::StorageRecoveryCase,
    },
    framework::artifacts::ArtifactCollector,
};

pub(crate) const STORAGE_RECOVERY_WORKFLOW_ARTIFACT: &str = "storage-recovery-workflow.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum PhaseStatus {
    Succeeded,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PhaseReceipt {
    phase: String,
    status: PhaseStatus,
    started_at_ms: u64,
    ended_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StorageRecoveryWorkflowEvidence {
    schema_version: u8,
    scenario: String,
    case: StorageRecoveryCase,
    run_id: String,
    phases: Vec<PhaseReceipt>,
    cancel_attempted: bool,
    evidence_persisted_before_cleanup: bool,
    cleanup_succeeded: bool,
    completed: bool,
}

impl StorageRecoveryWorkflowEvidence {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1,
            "unsupported storage workflow schema"
        );
        ensure!(
            self.case.scenario() == self.scenario
                && !self.run_id.trim().is_empty()
                && !self.phases.is_empty(),
            "storage workflow lacks an exact scenario, case, or run identity"
        );
        ensure!(
            self.phases.iter().all(|phase| {
                !phase.phase.trim().is_empty()
                    && phase.started_at_ms > 0
                    && phase.started_at_ms <= phase.ended_at_ms
                    && (phase.status == PhaseStatus::Failed) == phase.error.is_some()
            }) && self
                .phases
                .windows(2)
                .all(|pair| pair[0].ended_at_ms <= pair[1].started_at_ms),
            "storage workflow phase receipts are invalid or unordered"
        );
        ensure!(
            self.evidence_persisted_before_cleanup,
            "storage workflow did not persist raw evidence before cleanup"
        );
        ensure!(
            self.phases
                .last()
                .is_some_and(|phase| phase.phase == "cleanup"),
            "storage workflow must end with cleanup"
        );
        ensure!(
            self.cleanup_succeeded
                == self
                    .phases
                    .last()
                    .is_some_and(|phase| phase.status == PhaseStatus::Succeeded),
            "storage workflow cleanup summary contradicts its receipt"
        );
        if self.completed {
            ensure!(
                self.phases
                    .iter()
                    .all(|phase| phase.status == PhaseStatus::Succeeded)
                    && !self.cancel_attempted
                    && self.cleanup_succeeded,
                "completed storage workflow contains a failed or canceled phase"
            );
        } else {
            ensure!(
                self.phases
                    .iter()
                    .any(|phase| phase.status == PhaseStatus::Failed),
                "incomplete storage workflow lacks a failed phase"
            );
        }
        Ok(())
    }

    pub(crate) fn validate_completed_attempt(
        &self,
        scenario: &str,
        run_id: &str,
        case: StorageRecoveryCase,
    ) -> Result<()> {
        self.validate()?;
        ensure!(
            self.completed
                && self.scenario == scenario
                && self.run_id == run_id
                && self.case == case,
            "storage workflow is incomplete or belongs to another exact attempt"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OwnedHealCancel {
    Canceled,
    NoOwnedHeal,
}

#[async_trait(?Send)]
pub(crate) trait StorageRecoveryCaseDriver: Send + Sync {
    async fn prepare_and_seal_dataset(&self) -> Result<()>;
    async fn capture_offline_mapping(&self) -> Result<()>;
    async fn replace_volume(&self) -> Result<()>;
    async fn start_heal(&self) -> Result<()>;
    async fn verify_replacement_baseline(&self) -> Result<()>;
    async fn wait_for_owned_heal(&self) -> Result<()>;
    async fn verify_recovery_and_post_write(&self) -> Result<()>;
    async fn persist_raw_evidence(&self) -> Result<()>;
    async fn persist_workflow_snapshot(
        &self,
        evidence: &StorageRecoveryWorkflowEvidence,
    ) -> Result<()>;
    async fn cancel_owned_heal(&self) -> Result<OwnedHealCancel>;
    async fn cleanup_or_quarantine(&self) -> Result<()>;
}

struct WorkflowResult {
    evidence: StorageRecoveryWorkflowEvidence,
    error: Option<anyhow::Error>,
}

async fn execute_storage_recovery_workflow<D: StorageRecoveryCaseDriver + ?Sized>(
    plan: &StorageRecoveryExecutionPlan,
    run_id: &str,
    driver: &D,
    deadline: RunDeadline,
    cleanup_timeout: Duration,
) -> WorkflowResult {
    let mut evidence = StorageRecoveryWorkflowEvidence {
        schema_version: 1,
        scenario: plan.scenario.clone(),
        case: plan.case,
        run_id: run_id.to_string(),
        phases: Vec::new(),
        cancel_attempted: false,
        evidence_persisted_before_cleanup: false,
        cleanup_succeeded: false,
        completed: false,
    };
    let operation_deadline = tokio::time::Instant::now()
        .checked_add(plan.operation_timeout)
        .filter(|_| !plan.operation_timeout.is_zero());
    let mut primary = None;

    macro_rules! phase {
        ($name:literal, $future:expr) => {
            if primary.is_none() {
                let started_at_ms = now_ms();
                let result = match operation_deadline {
                    Some(operation_deadline) => {
                        run_bounded(deadline, operation_deadline, $name, $future).await
                    }
                    None => Err(anyhow!(
                        "storage-recovery operation timeout must be positive"
                    )),
                };
                primary = record_phase(&mut evidence, $name, started_at_ms, result);
            }
        };
    }

    phase!(
        "prepare-and-seal-dataset",
        driver.prepare_and_seal_dataset()
    );
    phase!("capture-offline-mapping", driver.capture_offline_mapping());
    phase!("replace-volume", driver.replace_volume());
    phase!(
        "verify-replacement-baseline",
        driver.verify_replacement_baseline()
    );
    let owns_heal = if primary.is_none() {
        phase!("start-heal", driver.start_heal());
        primary.is_none()
    } else {
        false
    };
    phase!("wait-owned-heal", driver.wait_for_owned_heal());
    phase!(
        "verify-recovery-and-post-write",
        driver.verify_recovery_and_post_write()
    );

    if primary.is_some() && owns_heal {
        let started_at_ms = now_ms();
        let cancel = tokio::time::timeout(cleanup_timeout, driver.cancel_owned_heal())
            .await
            .map_err(|_| anyhow!("storage-recovery heal cancellation timed out"))
            .and_then(|result| result);
        evidence.cancel_attempted = matches!(cancel, Ok(OwnedHealCancel::Canceled));
        if let Some(cancel_error) = record_phase(
            &mut evidence,
            "cancel-heal",
            started_at_ms,
            cancel.map(|_| ()),
        ) {
            let original = primary.take().expect("cancel follows a primary failure");
            primary = Some(original.context(format!(
                "owned heal cancellation also failed: {cancel_error:#}"
            )));
        }
    }

    let persist_started_at_ms = now_ms();
    let persisted = tokio::time::timeout(cleanup_timeout, driver.persist_raw_evidence())
        .await
        .map_err(|_| anyhow!("storage-recovery evidence persistence timed out"))
        .and_then(|result| result);
    evidence.evidence_persisted_before_cleanup = persisted.is_ok();
    if let Some(persist_error) = record_phase(
        &mut evidence,
        "persist-raw-evidence",
        persist_started_at_ms,
        persisted,
    ) {
        primary = Some(match primary {
            Some(original) => original.context(format!(
                "raw evidence persistence also failed: {persist_error:#}"
            )),
            None => persist_error,
        });
    }

    let workflow_persist_started_at_ms = now_ms();
    let workflow_persisted =
        tokio::time::timeout(cleanup_timeout, driver.persist_workflow_snapshot(&evidence))
            .await
            .map_err(|_| anyhow!("storage-recovery workflow persistence timed out"))
            .and_then(|result| result);
    if let Some(persist_error) = record_phase(
        &mut evidence,
        "persist-workflow-evidence",
        workflow_persist_started_at_ms,
        workflow_persisted,
    ) {
        primary = Some(match primary {
            Some(original) => original.context(format!(
                "workflow evidence persistence also failed: {persist_error:#}"
            )),
            None => persist_error,
        });
    }

    let cleanup_started_at_ms = now_ms();
    let cleanup = tokio::time::timeout(cleanup_timeout, driver.cleanup_or_quarantine())
        .await
        .map_err(|_| anyhow!("storage-recovery cleanup timed out"))
        .and_then(|result| result);
    if let Some(cleanup_error) =
        record_phase(&mut evidence, "cleanup", cleanup_started_at_ms, cleanup)
    {
        primary = Some(match primary {
            Some(original) => original.context(format!(
                "cleanup or quarantine also failed: {cleanup_error:#}"
            )),
            None => cleanup_error,
        });
    } else {
        evidence.cleanup_succeeded = true;
    }
    evidence.completed = primary.is_none();
    WorkflowResult {
        evidence,
        error: primary,
    }
}

async fn run_bounded<T>(
    deadline: RunDeadline,
    operation_deadline: tokio::time::Instant,
    phase: &str,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    let operation = async {
        tokio::time::timeout_at(operation_deadline, future)
            .await
            .with_context(|| format!("storage-recovery phase {phase} exceeded operation timeout"))?
    };
    deadline.run(operation).await
}

fn record_phase(
    evidence: &mut StorageRecoveryWorkflowEvidence,
    phase: &str,
    started_at_ms: u64,
    result: Result<()>,
) -> Option<anyhow::Error> {
    let ended_at_ms = now_ms();
    let started_at_ms = evidence.phases.last().map_or(started_at_ms, |previous| {
        previous.ended_at_ms.max(started_at_ms)
    });
    match result {
        Ok(()) => {
            evidence.phases.push(PhaseReceipt {
                phase: phase.to_string(),
                status: PhaseStatus::Succeeded,
                started_at_ms,
                ended_at_ms,
                error: None,
            });
            None
        }
        Err(error) => {
            evidence.phases.push(PhaseReceipt {
                phase: phase.to_string(),
                status: PhaseStatus::Failed,
                started_at_ms,
                ended_at_ms,
                error: Some(format!("{error:#}")),
            });
            Some(error)
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
        .max(1)
}

pub(crate) async fn run_storage_recovery_case(
    config: &FaultTestConfig,
    collector: &ArtifactCollector,
    scenario: &FaultScenario,
    execution_plan: &ExecutionPlan,
    plan: &StorageRecoveryExecutionPlan,
    run_id: &str,
    deadline: RunDeadline,
) -> Result<()> {
    ensure!(
        (config.qualify_planned_storage
            || crate::fault::scenarios::scenario_spec(&scenario.name)?
                .status
                .is_executable())
            && config.storage_recovery_case == Some(plan.case)
            && config.destructive_enabled
            && execution_plan.storage_recovery() == Some(plan)
            && scenario.name == plan.scenario
            && scenario.case_name == plan.case_name,
        "storage-recovery runner requires one exact destructive storage case"
    );
    match plan.case {
        StorageRecoveryCase::OnDiskBitrotAutomaticScanner
        | StorageRecoveryCase::OnDiskBitrotAdminDeep => {
            return crate::fault::on_disk_bitrot::run_on_disk_bitrot_case(
                config,
                collector,
                scenario,
                execution_plan,
                plan,
                run_id,
                deadline,
            )
            .await;
        }
        StorageRecoveryCase::FreshVolumeReplacementAutomaticReplacement
        | StorageRecoveryCase::FreshVolumeReplacementAdminDeep => {}
        StorageRecoveryCase::StaleDiskReturn => {
            return crate::fault::stale_disk_runner::run_stale_disk_case(
                config,
                collector,
                scenario,
                execution_plan,
                plan,
                run_id,
                deadline,
            )
            .await;
        }
    }
    let driver = crate::fault::fresh_volume::FreshVolumeDriver::new(
        config, collector, scenario, plan, run_id, deadline,
    )?;
    let result =
        execute_storage_recovery_workflow(plan, run_id, &driver, deadline, config.cluster.timeout)
            .await;
    collector.write_text(
        scenario.case_name,
        STORAGE_RECOVERY_WORKFLOW_ARTIFACT,
        &serde_json::to_string_pretty(&result.evidence)?,
    )?;
    let validation = result.evidence.validate();
    match (result.error, validation) {
        (Some(error), Ok(())) => Err(error),
        (Some(error), Err(validation)) => Err(error.context(format!(
            "storage workflow artifact validation also failed: {validation:#}"
        ))),
        (None, Err(validation)) => Err(validation),
        (None, Ok(())) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::fault::plan::FaultWorkloadMode;

    struct FakeDriver {
        calls: Mutex<Vec<&'static str>>,
        fail: Option<&'static str>,
        cleanup_fails: bool,
    }

    impl FakeDriver {
        fn step(&self, name: &'static str) -> Result<()> {
            self.calls.lock().expect("calls").push(name);
            if self.fail == Some(name) || (name == "cleanup" && self.cleanup_fails) {
                anyhow::bail!("primary {name}")
            }
            Ok(())
        }
    }

    #[async_trait(?Send)]
    impl StorageRecoveryCaseDriver for FakeDriver {
        async fn prepare_and_seal_dataset(&self) -> Result<()> {
            self.step("prepare")
        }
        async fn capture_offline_mapping(&self) -> Result<()> {
            self.step("mapping")
        }
        async fn replace_volume(&self) -> Result<()> {
            self.step("replace")
        }
        async fn start_heal(&self) -> Result<()> {
            self.step("start")
        }
        async fn verify_replacement_baseline(&self) -> Result<()> {
            self.step("baseline")
        }
        async fn wait_for_owned_heal(&self) -> Result<()> {
            self.step("wait")
        }
        async fn verify_recovery_and_post_write(&self) -> Result<()> {
            self.step("verify")
        }
        async fn persist_raw_evidence(&self) -> Result<()> {
            self.step("persist")
        }
        async fn persist_workflow_snapshot(
            &self,
            _evidence: &StorageRecoveryWorkflowEvidence,
        ) -> Result<()> {
            self.step("workflow")
        }
        async fn cancel_owned_heal(&self) -> Result<OwnedHealCancel> {
            self.step("cancel")?;
            Ok(OwnedHealCancel::Canceled)
        }
        async fn cleanup_or_quarantine(&self) -> Result<()> {
            self.step("cleanup")
        }
    }

    fn plan() -> StorageRecoveryExecutionPlan {
        StorageRecoveryExecutionPlan {
            scenario: "fresh-volume-replacement".to_string(),
            case_name: "case",
            workload_mode: FaultWorkloadMode::S3Mixed,
            operation_timeout: Duration::from_secs(5),
            case: StorageRecoveryCase::FreshVolumeReplacementAdminDeep,
        }
    }

    #[tokio::test]
    async fn persists_before_cleanup_and_preserves_primary_error() {
        let driver = FakeDriver {
            calls: Mutex::new(Vec::new()),
            fail: Some("baseline"),
            cleanup_fails: false,
        };
        let result = execute_storage_recovery_workflow(
            &plan(),
            "run",
            &driver,
            RunDeadline::default(),
            Duration::from_secs(1),
        )
        .await;
        assert!(
            result
                .error
                .as_ref()
                .is_some_and(|error| error.to_string().contains("primary baseline"))
        );
        assert_eq!(
            *driver.calls.lock().expect("calls"),
            [
                "prepare", "mapping", "replace", "baseline", "persist", "workflow", "cleanup"
            ]
        );
        assert!(result.evidence.evidence_persisted_before_cleanup);
        result.evidence.validate().expect("valid failure evidence");
    }

    #[tokio::test]
    async fn start_failure_never_cancels_foreign_heal() {
        let driver = FakeDriver {
            calls: Mutex::new(Vec::new()),
            fail: Some("start"),
            cleanup_fails: false,
        };
        let result = execute_storage_recovery_workflow(
            &plan(),
            "run",
            &driver,
            RunDeadline::default(),
            Duration::from_secs(1),
        )
        .await;
        assert!(result.error.is_some());
        assert_eq!(
            *driver.calls.lock().expect("calls"),
            [
                "prepare", "mapping", "replace", "baseline", "start", "persist", "workflow",
                "cleanup"
            ]
        );
        assert!(!result.evidence.cancel_attempted);
    }

    #[tokio::test]
    async fn cleanup_failure_is_secondary_to_the_primary_workflow_error() {
        let driver = FakeDriver {
            calls: Mutex::new(Vec::new()),
            fail: Some("baseline"),
            cleanup_fails: true,
        };
        let result = execute_storage_recovery_workflow(
            &plan(),
            "run",
            &driver,
            RunDeadline::default(),
            Duration::from_secs(1),
        )
        .await;
        let error = format!("{:#}", result.error.expect("workflow failure"));
        assert!(error.contains("primary baseline"));
        assert!(error.contains("primary cleanup"));
        assert!(result.evidence.evidence_persisted_before_cleanup);
        assert!(!result.evidence.cleanup_succeeded);
        result.evidence.validate().expect("valid failure evidence");
    }
}
