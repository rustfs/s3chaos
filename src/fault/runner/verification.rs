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
    checker,
    events::RunEventStatus,
    reporting::{FailureSummary, FaultEvidence, write_checker_error},
    workload::S3WorkloadClient,
};
use anyhow::{Result, bail};

use super::FaultRun;
use crate::fault::workload::execution::{MixedWorkloadResult, recommit_unconfirmed_objects};

impl FaultRun<'_> {
    pub(super) async fn verify_recovered(&self, s3: &S3WorkloadClient) -> Result<()> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        events.record(
            "checker-pre-recommit",
            RunEventStatus::Started,
            "checking recovered object model before recommit",
            None,
        )?;
        let pre_recommit_record_start = history.records().len();
        let pre_recommit_report = match checker::check_s3_history(
            s3,
            history,
            true,
            workload_plan.concurrency,
            config.workload_versioning,
        )
        .await
        {
            Ok(report) => report,
            Err(error) => {
                let message = error.to_string();
                events
                    .record(
                        "checker-pre-recommit",
                        RunEventStatus::Failed,
                        message.clone(),
                        None,
                    )
                    .ok();
                write_checker_error(
                    collector,
                    scenario.case_name,
                    "checker-pre-recommit-error.txt",
                    &message,
                )?;
                let recovery_stability_report = checker::RecoveryStabilityReport::harness_error(
                    message.clone(),
                    config.recovery_stability_reread,
                )
                .with_identity(&scenario.name, run_id);
                collector.write_text(
                    scenario.case_name,
                    "recovery-stability-report.json",
                    &serde_json::to_string_pretty(&recovery_stability_report)?,
                )?;
                self.write_failure_summary(
                    FailureSummary::from_checker(
                        &scenario.name,
                        "checker-pre-recommit",
                        recovery_stability_report.classification,
                        message,
                    )
                    .with_recovered_within_seconds(
                        recovery_stability_report.recovered_within_seconds,
                    )
                    .with_evidence_classifications(
                        recovery_stability_report.evidence_classifications(),
                    ),
                )?;
                return Err(error);
            }
        };
        collector.write_text(
            scenario.case_name,
            "checker-pre-recommit-report.json",
            &serde_json::to_string_pretty(&pre_recommit_report)?,
        )?;
        if let Err(error) = pre_recommit_report.require_success() {
            events
                .record(
                    "checker-pre-recommit",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            let recovery_stability_report = self
                .reread_recovery_tail(s3, &pre_recommit_report, pre_recommit_record_start)
                .await;
            collector.write_text(
                scenario.case_name,
                "recovery-stability-report.json",
                &serde_json::to_string_pretty(&recovery_stability_report)?,
            )?;
            self.write_failure_summary(
                FailureSummary::from_checker(
                    &scenario.name,
                    "checker-pre-recommit-verdict",
                    recovery_stability_report.classification,
                    error.to_string(),
                )
                .with_recovered_within_seconds(recovery_stability_report.recovered_within_seconds)
                .with_evidence_classifications(recovery_stability_report.evidence_classifications())
                .with_list_warnings(
                    recovery_stability_report.final_list_warning_count,
                    recovery_stability_report.list_warnings.clone(),
                ),
            )?;
            return Err(error);
        }
        events.record(
            "checker-pre-recommit",
            RunEventStatus::Succeeded,
            "pre-recommit object model check passed",
            None,
        )?;
        Ok(())
    }
    pub(super) async fn recommit(
        &self,
        s3: &S3WorkloadClient,
        workload: &mut MixedWorkloadResult,
    ) -> Result<()> {
        let collector = self.collector;
        let scenario = self.scenario;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        events.record(
            "recommit-unconfirmed",
            RunEventStatus::Started,
            "recommitting previously unconfirmed writes after recovery",
            Some(serde_json::json!({ "attempted": workload.unconfirmed_puts.len() })),
        )?;
        let recommit_report = recommit_unconfirmed_objects(
            s3,
            history,
            &workload.unconfirmed_puts,
            workload_plan.concurrency,
        )
        .await;
        collector.write_text(
            scenario.case_name,
            "recommit-report.json",
            &serde_json::to_string_pretty(&recommit_report)?,
        )?;
        workload.summary.recommitted_after_recovery = recommit_report.committed;
        collector.write_text(
            scenario.case_name,
            "workload-summary.json",
            &serde_json::to_string_pretty(&workload.summary)?,
        )?;
        if recommit_report.has_failures() {
            let message = recommit_report.failure_message();
            events
                .record(
                    "recommit-unconfirmed",
                    RunEventStatus::Failed,
                    message.clone(),
                    Some(serde_json::json!({
                        "failed": recommit_report.failed,
                        "harness_errors": recommit_report.harness_errors,
                    })),
                )
                .ok();
            self.write_failure_summary(FailureSummary::new(
                &scenario.name,
                "recommit-unconfirmed",
                recommit_report.failure_classification(),
                message.clone(),
            )?)?;
            bail!("{message}");
        }
        events.record(
            "recommit-unconfirmed",
            RunEventStatus::Succeeded,
            "previously unconfirmed writes were recommitted",
            Some(serde_json::json!({ "committed": recommit_report.committed })),
        )?;
        Ok(())
    }
    pub(super) async fn verify_final(
        &self,
        s3: &S3WorkloadClient,
        workload: &MixedWorkloadResult,
        evidence: &mut FaultEvidence,
    ) -> Result<()> {
        self.verify_final_with_disruptions(s3, workload.summary.disrupted(), evidence)
            .await
    }

    pub(super) async fn verify_final_without_recommit(
        &self,
        s3: &S3WorkloadClient,
        evidence: &mut FaultEvidence,
    ) -> Result<()> {
        self.verify_final_with_disruptions(s3, 0, evidence).await
    }

    async fn verify_final_with_disruptions(
        &self,
        s3: &S3WorkloadClient,
        client_disruptions: usize,
        evidence: &mut FaultEvidence,
    ) -> Result<()> {
        let config = self.config;
        let collector = self.collector;
        let scenario = self.scenario;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        events.record(
            "checker-final",
            RunEventStatus::Started,
            "checking final recovered object model",
            None,
        )?;
        let report = match checker::check_s3_history(
            s3,
            history,
            true,
            workload_plan.concurrency,
            config.workload_versioning,
        )
        .await
        {
            Ok(report) => report,
            Err(error) => {
                let message = error.to_string();
                events
                    .record(
                        "checker-final",
                        RunEventStatus::Failed,
                        message.clone(),
                        None,
                    )
                    .ok();
                write_checker_error(
                    collector,
                    scenario.case_name,
                    "checker-final-error.txt",
                    &message,
                )?;
                self.write_failure_summary(FailureSummary::new(
                    &scenario.name,
                    "checker-final",
                    "checker_or_environment",
                    message,
                )?)?;
                return Err(error);
            }
        };
        collector.write_text(
            scenario.case_name,
            "checker-report.json",
            &serde_json::to_string_pretty(&report)?,
        )?;
        evidence.recovered = report.tenant_recovered;
        evidence.client_disruptions = client_disruptions;
        collector.write_text(
            scenario.case_name,
            "fault-evidence.json",
            &serde_json::to_string_pretty(&evidence)?,
        )?;
        if let Err(error) = report.require_success() {
            events
                .record(
                    "checker-final",
                    RunEventStatus::Failed,
                    error.to_string(),
                    None,
                )
                .ok();
            let classification = report.failure_classification();
            self.write_failure_summary(
                FailureSummary::from_checker(
                    &scenario.name,
                    "checker-verdict",
                    classification,
                    error.to_string(),
                )
                .with_list_warnings(
                    report.final_list_warning_count,
                    report.list_warnings.clone(),
                ),
            )?;
            return Err(error);
        }
        events.record(
            "checker-final",
            RunEventStatus::Succeeded,
            "final object model check passed",
            Some(serde_json::json!({
                "committed_puts": report.committed_puts,
                "verified_live_objects": report.verified_live_objects,
                "final_listed_objects": report.final_listed_objects,
            })),
        )?;
        Ok(())
    }
    async fn reread_recovery_tail(
        &self,
        s3: &S3WorkloadClient,
        pre_recommit_report: &checker::CheckerReport,
        pre_recommit_record_start: usize,
    ) -> checker::RecoveryStabilityReport {
        let config = self.config;
        let scenario = self.scenario;
        let run_id = &self.context.run_id;
        let workload_plan = &self.context.workload_plan;
        let events = &self.context.events;
        let history = &self.context.history;
        events
            .record(
                "recovery-stability-reread",
                RunEventStatus::Started,
                "bounded reread of recovery-tail committed GET failures",
                Some(serde_json::json!({
                    "max_recovery_seconds": config.recovery_stability_reread.as_secs()
                })),
            )
            .ok();

        match checker::recovery_stability_reread(
            s3,
            history,
            pre_recommit_report,
            pre_recommit_record_start,
            workload_plan.concurrency,
            config.recovery_stability_reread,
        )
        .await
        {
            Ok(report) => {
                events
                    .record(
                        "recovery-stability-reread",
                        RunEventStatus::Succeeded,
                        "bounded recovery stability reread completed",
                        Some(serde_json::json!({
                            "classification": report.classification.as_str(),
                            "attempted_keys": report.reread_attempted_keys.len(),
                            "recovered_keys": report.reread_recovered_keys.len(),
                            "still_unavailable_keys": report.still_unavailable_keys.len(),
                            "hash_mismatches": report.hash_mismatches.len()
                        })),
                    )
                    .ok();
                report
            }
            Err(reread_error) => {
                let message = format!("recovery stability reread failed: {reread_error}");
                events
                    .record(
                        "recovery-stability-reread",
                        RunEventStatus::Failed,
                        message.clone(),
                        None,
                    )
                    .ok();
                checker::RecoveryStabilityReport::harness_error(
                    message,
                    config.recovery_stability_reread,
                )
                .with_identity(&scenario.name, run_id)
            }
        }
    }
}
