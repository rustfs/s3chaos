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

use anyhow::{Context, Result};

use super::FaultRun;
use crate::fault::{
    events::RunEventStatus,
    history::{DurabilityCohort, Recorder},
    shutdown::SuiteDeadlineExceeded,
    workload::S3WorkloadClient,
    workload::execution::{
        POST_RECOVERY_WRITE_HISTORY_ARTIFACT, POST_RECOVERY_WRITE_REPORT_ARTIFACT,
        PostRecoveryWriteRequest, post_recovery_object_count, run_post_recovery_write_probe,
    },
};

/// Mixes the probe seed away from the workload seed so probe bodies never
/// collide with workload bodies even when indices overlap.
pub(crate) const POST_RECOVERY_SEED_SALT: u64 = 0x5052_4F42_4552_4543;

impl FaultRun<'_> {
    /// Prove the recovered cluster accepts fresh mutations. The probe records
    /// into its own history file: the workload history is authenticated as a
    /// strict prechecker/recommit/final-checker phase chain, and the ACK
    /// cases additionally require it to stay quiet after the trigger.
    ///
    /// Callers await this directly rather than under `RunDeadline::run`: a
    /// cancelled PUT, DELETE, or multipart request would leave a mutation
    /// RustFS may have applied without a finished history record. Instead
    /// every mutation is capped to the remaining suite budget and the probe
    /// checks the deadline between objects and phases.
    pub(super) async fn probe_post_recovery_writes(&self, s3: &S3WorkloadClient) -> Result<()> {
        let collector = self.collector;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let object_count = post_recovery_object_count(workload_plan.object_count);
        let s3 = match self.deadline.instant()? {
            Some(deadline) => s3.with_mutation_deadline(deadline),
            None => s3.clone(),
        };
        events.record(
            "post-recovery-write",
            RunEventStatus::Started,
            "writing, listing, and deleting fresh objects on the recovered cluster",
            Some(serde_json::json!({ "objects": object_count })),
        )?;
        let history_path = collector
            .case_dir(scenario.case_name)
            .join(POST_RECOVERY_WRITE_HISTORY_ARTIFACT);
        let history = Recorder::create(history_path, &scenario.name, run_id)
            .context("create post-recovery write probe history")?;
        history.set_durability_cohort(DurabilityCohort::PostRecovery);
        let report = match run_post_recovery_write_probe(&PostRecoveryWriteRequest {
            s3: &s3,
            history: &history,
            run_id,
            scope: crate::fault::workload::WriteProbeScope::PostRecovery,
            seed: workload_plan.seed ^ POST_RECOVERY_SEED_SALT,
            object_count,
            concurrency: workload_plan.concurrency,
            deadline: self.deadline,
        })
        .await
        {
            Ok(report) => report,
            Err(error) => {
                self.record_failure(
                    "post-recovery-write",
                    probe_error_classification(&error),
                    &error,
                    None,
                    None,
                )?;
                return Err(error);
            }
        };
        collector.write_text(
            scenario.case_name,
            POST_RECOVERY_WRITE_REPORT_ARTIFACT,
            &serde_json::to_string_pretty(&report)?,
        )?;
        if let Err(error) = report.require_success() {
            self.record_failure(
                "post-recovery-write",
                "post_recovery_write_failed",
                &error,
                Some(serde_json::json!({
                    "objects": report.objects,
                    "puts_verified": report.puts_verified,
                    "deletes_verified_absent": report.deletes_verified_absent,
                    "failures": report.failures,
                })),
                None,
            )?;
            return Err(error);
        }
        events.record(
            "post-recovery-write",
            RunEventStatus::Succeeded,
            "fresh writes, reads, listings, and deletes all succeeded after recovery",
            Some(serde_json::json!({
                "objects": report.objects,
                "multipart_completes_verified": report.multipart_completes_verified,
                "lists_verified": report.lists_verified,
            })),
        )?;
        Ok(())
    }
}

/// A probe cut short by the suite budget is the suite deadline, the verdict
/// the recommit and availability-endpoint paths give it too; anything else
/// that stops the probe before it can report is a harness execution error.
pub(super) fn probe_error_classification(error: &anyhow::Error) -> &'static str {
    if error.is::<SuiteDeadlineExceeded>() {
        "test_or_environment"
    } else {
        "workload_execution_error"
    }
}

#[cfg(test)]
mod tests {
    use super::probe_error_classification;
    use crate::fault::{
        history::Recorder,
        reporting::{FailureSummary, ResponsibilityDomain},
        shutdown::{RunDeadline, SuiteDeadlineExceeded},
        workload::{
            S3WorkloadClient,
            execution::{PostRecoveryWriteRequest, run_post_recovery_write_probe},
        },
    };

    #[tokio::test]
    async fn a_probe_cut_short_by_the_suite_budget_is_classified_as_the_deadline() {
        let client = S3WorkloadClient::new(
            "http://127.0.0.1:1",
            "bucket",
            "test-access",
            "test-secret",
            std::time::Duration::from_secs(1),
        )
        .await
        .expect("client");
        let dir = tempfile::tempdir().expect("tempdir");
        let history = Recorder::create(dir.path().join("history.jsonl"), "pod-failure", "run-1")
            .expect("recorder");

        let error = run_post_recovery_write_probe(&PostRecoveryWriteRequest {
            s3: &client,
            history: &history,
            run_id: "run-1",
            scope: crate::fault::workload::WriteProbeScope::PostRecovery,
            seed: 1,
            object_count: 8,
            concurrency: 4,
            deadline: RunDeadline::new(Some(0)).expect("deadline"),
        })
        .await
        .expect_err("an exhausted budget stops the probe before its first phase");

        assert!(error.is::<SuiteDeadlineExceeded>(), "{error:#}");
        assert!(history.records().is_empty(), "no request was started");
        let classification = probe_error_classification(&error);
        assert_eq!(classification, "test_or_environment");
        let summary = FailureSummary::new(
            "pod-failure",
            "post-recovery-write",
            classification,
            error.to_string(),
        )
        .expect("allowlisted classification");
        assert_ne!(
            summary.responsibility_domain(),
            Some(ResponsibilityDomain::Product)
        );

        assert_eq!(
            probe_error_classification(&anyhow::anyhow!("record PUT: disk full")),
            "workload_execution_error"
        );
    }
}
