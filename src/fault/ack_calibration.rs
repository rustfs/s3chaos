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

//! Offline comparison of two supervised ACK calibration attempts.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::fault::{
    acknowledged_mutation::{ACK_CALIBRATION_ARTIFACT, AckCalibrationEvidence, AckCalibrationMode},
    artifact_validation::{
        ArtifactValidationOptions, validate_expected_failure_artifacts,
        validate_fault_artifacts_for_planned_attempt_and_write_report,
    },
    recovery_health::RecoveryHealthReport,
    spec::FaultRunSpec,
    suite_plan::FaultSuitePlan,
};

#[derive(Serialize)]
pub struct AckCalibrationReport {
    pub scenario: String,
    pub strict_run_id: String,
    pub relaxed_run_id: String,
    pub image_digest: String,
    pub loss_classification: String,
    pub strict_suite_root: PathBuf,
    pub relaxed_suite_root: PathBuf,
    pub checked_scope: Vec<&'static str>,
    pub external_settings_not_attested: Vec<&'static str>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SuiteSummary {
    run_id: String,
    status: String,
    attempts: Vec<AttemptSummary>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttemptSummary {
    run_id: String,
    scenario: String,
    status: String,
    started_at_ms: u64,
    ended_at_ms: u64,
}

#[derive(Clone)]
struct Control {
    root: PathBuf,
    spec: FaultRunSpec,
    mode: AckCalibrationEvidence,
    health: RecoveryHealthReport,
    mount: serde_json::Value,
    loss: Option<String>,
}

fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&fs::read(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("parse {}", path.display()))
}

fn load_control(root: &Path, mode: AckCalibrationMode) -> Result<Control> {
    let root = fs::canonicalize(root)?;
    let plan: FaultSuitePlan = read(&root.join("suite-plan.json"))?;
    let summary: SuiteSummary = read(&root.join("suite-summary.json"))?;
    ensure!(
        plan.attempts.len() == 1 && summary.attempts.len() == 1,
        "calibration requires separate single-attempt supervised suites"
    );
    ensure!(
        summary.run_id == plan.run_id && summary.status == "succeeded",
        "calibration suite did not succeed"
    );
    let attempt = &plan.attempts[0];
    let observed = &summary.attempts[0];
    ensure!(
        attempt.run_id.as_deref() == Some(observed.run_id.as_str())
            && observed.scenario == attempt.scenario
            && observed.started_at_ms <= observed.ended_at_ms,
        "calibration attempt identity or time window differs from plan"
    );
    ensure!(
        observed.status
            == if mode == AckCalibrationMode::Strict {
                "succeeded"
            } else {
                "expected-failure"
            },
        "calibration control has the wrong outcome"
    );
    let relative_case = Path::new(&attempt.artifacts.case_dir)
        .strip_prefix(&plan.artifact_root)
        .context("calibration case is outside persisted suite root")?;
    ensure!(
        relative_case.components().count() == 2
            && relative_case.file_name().and_then(|name| name.to_str())
                == Some(attempt.case_name.as_str())
            && relative_case
                .components()
                .all(|component| matches!(component, std::path::Component::Normal(_))),
        "calibration case contains unsafe path components"
    );
    let case = fs::canonicalize(root.join(relative_case))?;
    ensure!(
        case.starts_with(&root),
        "calibration case escaped suite root"
    );
    let spec: FaultRunSpec = read(&case.join("run-spec.json"))?;
    ensure!(
        spec.metadata.run_id == observed.run_id
            && spec.scenario.name == attempt.scenario
            && spec.scenario.case_name == attempt.case_name
            && spec.scenario.ack_trigger == attempt.ack_trigger,
        "calibration run spec differs from suite plan"
    );
    ensure!(
        spec.scenario
            .ack_trigger
            .as_ref()
            .and_then(|trigger| trigger.calibration_mode)
            == Some(mode),
        "calibration run spec lacks requested mode"
    );
    ensure!(
        spec.workload.mode == attempt.workload.mode
            && spec.workload.object_count == attempt.workload.objects
            && spec.workload.concurrency == attempt.workload.concurrency
            && spec.workload.versioning == attempt.workload.versioning
            && spec.workload.seed == attempt.workload.seed
            && spec.workload.operation_mix == attempt.workload.operation_mix
            && spec.workload.prefill_concurrency == attempt.workload.prefill_concurrency
            && spec.workload.request_timeout_seconds == attempt.workload.request_timeout_seconds
            && spec.cluster.rustfs_image == plan.cluster.rustfs_image,
        "calibration workload or candidate image differs from suite plan"
    );
    let options = ArtifactValidationOptions {
        scenario: attempt.scenario.clone(),
        artifact_root: case
            .parent()
            .context("calibration case lacks attempt root")?
            .to_path_buf(),
        expected_workload_objects: spec.workload.object_count,
        expected_workload_concurrency: spec.workload.concurrency,
        expected_workload_versioning: spec.workload.versioning,
        expected_rustfs_pod_count: spec.recovery.expected_rustfs_pod_count,
        expected_stable_window_seconds: spec.recovery.stable_pod_window_seconds,
        expected_recovery_stability_reread_seconds: spec.recovery.recovery_stability_reread_seconds,
        expected_rustfs_volume_path: String::new(),
    };
    let validated =
        validate_fault_artifacts_for_planned_attempt_and_write_report(&options, &observed.run_id)?;
    ensure!(
        validated.run_succeeded == (mode == AckCalibrationMode::Strict),
        "calibration artifact verdict differs from control"
    );
    let loss = if mode == AckCalibrationMode::Relaxed {
        let expected = attempt
            .expected_failure
            .as_ref()
            .context("relaxed control lacks expectedFailure")?;
        let failure = validate_expected_failure_artifacts(
            &root,
            &case,
            &observed.run_id,
            &attempt.scenario,
            &attempt.case_name,
            observed.started_at_ms,
            observed.ended_at_ms,
        )?;
        expected.validate_observed(
            failure.summary.classification(),
            failure.summary.severity(),
            failure.summary.responsibility_domain(),
            failure.summary.primary_evidence_refs(),
        )?;
        let classification = failure.summary.classification();
        ensure!(
            matches!(
                classification,
                "committed_version_missing"
                    | "delete_marker_missing"
                    | "deleted_object_resurrected"
            ),
            "relaxed calibration requires observed ACK state loss, not availability or harness failure"
        );
        Some(classification.to_string())
    } else {
        ensure!(
            attempt.expected_failure.is_none(),
            "strict control must require PASS"
        );
        None
    };
    let mode = read(&case.join(ACK_CALIBRATION_ARTIFACT))?;
    let health = read(&case.join("recovery-health.json"))?;
    let crash: serde_json::Value = read(&case.join("dm-crash-boundary.json"))?;
    let mount = crash
        .get("mount_before")
        .context("calibration crash boundary lacks pre-crash mount")?
        .clone();
    Ok(Control {
        root,
        spec,
        mode,
        health,
        mount,
        loss,
    })
}

pub fn validate_ack_calibration_pair(
    strict_root: &Path,
    relaxed_root: &Path,
) -> Result<AckCalibrationReport> {
    let strict = load_control(strict_root, AckCalibrationMode::Strict)?;
    let relaxed = load_control(relaxed_root, AckCalibrationMode::Relaxed)?;
    compare_controls(strict, relaxed)
}

fn compare_controls(strict: Control, relaxed: Control) -> Result<AckCalibrationReport> {
    ensure!(
        strict.root != relaxed.root && strict.spec.metadata.run_id != relaxed.spec.metadata.run_id,
        "calibration controls must be independent runs"
    );
    ensure!(
        strict.spec.scenario.name == relaxed.spec.scenario.name
            && strict.spec.scenario.detector == relaxed.spec.scenario.detector
            && strict.spec.workload == relaxed.spec.workload
            && strict.spec.recovery == relaxed.spec.recovery,
        "calibration controls differ in detector, payload/seed, or recovery contract"
    );
    let strict_trigger = strict
        .spec
        .scenario
        .ack_trigger
        .as_ref()
        .context("strict ACK trigger missing")?;
    let relaxed_trigger = relaxed
        .spec
        .scenario
        .ack_trigger
        .as_ref()
        .context("relaxed ACK trigger missing")?;
    ensure!(
        strict_trigger.mutation == relaxed_trigger.mutation
            && strict_trigger.operation_timeout_ms == relaxed_trigger.operation_timeout_ms
            && strict_trigger.max_ack_to_fault_ms == relaxed_trigger.max_ack_to_fault_ms,
        "calibration controls use different ACK timing contracts"
    );
    ensure!(
        strict.spec.cluster.context == relaxed.spec.cluster.context
            && strict.spec.cluster.storage_class == relaxed.spec.cluster.storage_class
            && strict.spec.cluster.rustfs_image == relaxed.spec.cluster.rustfs_image,
        "calibration controls use different cluster or storage classes"
    );
    let left = &strict.health.baseline;
    let right = &relaxed.health.baseline;
    ensure!(
        left.standard_parity == right.standard_parity
            && left.total_sets == right.total_sets
            && left.drives_per_set == right.drives_per_set
            && left.server_endpoints.len() == right.server_endpoints.len(),
        "calibration controls use different EC geometry"
    );
    for key in ["filesystem", "options"] {
        let left = strict.mount[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("strict mount contract missing")?;
        let right = relaxed.mount[key]
            .as_str()
            .filter(|value| !value.is_empty())
            .context("relaxed mount contract missing")?;
        ensure!(
            left == right,
            "calibration controls use different filesystem or mount options"
        );
    }
    let digest = |control: &Control| -> Result<String> {
        control
            .mode
            .pods
            .first()
            .and_then(|pod| pod.image_id.rsplit_once("sha256:"))
            .map(|(_, digest)| digest.to_ascii_lowercase())
            .context("calibration image digest missing")
    };
    let image_digest = digest(&strict)?;
    ensure!(
        image_digest == digest(&relaxed)?,
        "calibration controls use different candidate image digests"
    );
    Ok(AckCalibrationReport {
        scenario: strict.spec.scenario.name,
        strict_run_id: strict.spec.metadata.run_id,
        relaxed_run_id: relaxed.spec.metadata.run_id,
        image_digest,
        loss_classification: relaxed.loss.context("relaxed loss missing")?,
        strict_suite_root: strict.root,
        relaxed_suite_root: relaxed.root,
        checked_scope: vec![
            "native-artifacts",
            "strict-pass",
            "relaxed-ack-state-loss",
            "image-digest",
            "detector",
            "workload-and-seed",
            "ack-timing",
            "recovery-policy",
            "ec-geometry",
            "cluster-storage-class-and-pinned-image",
            "filesystem-and-mount-options",
        ],
        external_settings_not_attested: vec![
            "host-kernel-writeback-settings",
            "image-source-provenance",
            "physical-power-loss",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{
        acknowledged_mutation::{AckBucketMode, AckCalibrationPod},
        config::FaultTestConfig,
        plan::FaultPlan,
        recovery_health::RecoveryHealthBaseline,
        scenarios::{FaultScenario, apply_catalog_defaults, scenario_spec},
        workload::WorkloadPlan,
    };

    fn control(mode: AckCalibrationMode) -> Control {
        let mut config = FaultTestConfig::for_test("lab", "dm-storage");
        config.scenario = "dm-drop-writes-after-ack-put".into();
        config.ack_calibration = Some(mode);
        config.cluster.rustfs_image = format!("rustfs/rustfs@sha256:{}", "a".repeat(64));
        apply_catalog_defaults(&mut config).unwrap();
        let scenario = FaultScenario::from_config(&config).unwrap();
        let catalog = scenario_spec(&scenario.name).unwrap();
        let plan = FaultPlan::from_scenario(&scenario, catalog).unwrap();
        let workload = WorkloadPlan::seeded(42, scenario.object_count, config.workload.concurrency);
        let spec = FaultRunSpec::resolved(
            &config,
            &scenario,
            catalog,
            &plan,
            &workload,
            mode.as_str(),
            "bucket",
        );
        Control {
            root: PathBuf::from(mode.as_str()),
            mode: AckCalibrationEvidence {
                scenario: scenario.name,
                run_id: mode.as_str().into(),
                mode,
                observed_at_ms: 1,
                bucket_response: AckBucketMode {
                    bucket: "bucket".into(),
                    mode: Some(mode.as_str().into()),
                },
                pods: vec![AckCalibrationPod {
                    name: "pod".into(),
                    uid: "uid".into(),
                    image: "candidate".into(),
                    image_id: format!("containerd://sha256:{}", "a".repeat(64)),
                    container_id: "containerd://process-1".into(),
                    process_mode: mode.as_str().into(),
                    new_bucket_mode: mode.as_str().into(),
                }],
            },
            health: RecoveryHealthReport {
                scenario: config.scenario,
                run_id: mode.as_str().into(),
                baseline: RecoveryHealthBaseline {
                    observed_at_ms: 1,
                    deployment_id: "deployment".into(),
                    standard_parity: 2,
                    total_sets: vec![1],
                    drives_per_set: vec![4],
                    server_endpoints: vec!["server".into()],
                    drive_uuids: vec![],
                },
                started_at_ms: 2,
                completed_at_ms: 3,
                timeout_seconds: 10,
                attempts: 1,
                first_healthy_at_ms: Some(3),
                observation: None,
                readiness: vec![],
                violations: vec![],
                passed: true,
            },
            spec,
            mount: serde_json::json!({"filesystem": "ext4", "options": "rw,relatime,data=ordered"}),
            loss: (mode == AckCalibrationMode::Relaxed).then(|| "committed_version_missing".into()),
        }
    }

    #[test]
    fn pair_requires_matching_image_workload_topology_and_crash_contract() {
        let strict = control(AckCalibrationMode::Strict);
        let relaxed = control(AckCalibrationMode::Relaxed);
        assert!(compare_controls(strict.clone(), relaxed.clone()).is_ok());
        let mutations: &[fn(&mut Control)] = &[
            |control| control.mode.pods[0].image_id = format!("sha256:{}", "b".repeat(64)),
            |control| control.spec.workload.plan.seed += 1,
            |control| control.health.baseline.standard_parity += 1,
            |control| control.mount["options"] = serde_json::json!("rw,data=writeback"),
            |control| {
                control
                    .spec
                    .scenario
                    .ack_trigger
                    .as_mut()
                    .unwrap()
                    .max_ack_to_fault_ms += 1
            },
            |control| control.spec.cluster.context = "another-lab".into(),
            |control| control.loss = None,
        ];
        for mutate in mutations {
            let mut mismatch = relaxed.clone();
            mutate(&mut mismatch);
            assert!(compare_controls(strict.clone(), mismatch).is_err());
        }
        let mut same_run = relaxed;
        same_run.spec.metadata.run_id = strict.spec.metadata.run_id.clone();
        assert!(compare_controls(strict, same_run).is_err());
    }

    fn write_control_header(base_dir: &Path, mode: AckCalibrationMode) -> PathBuf {
        use crate::fault::{suite::FaultSuite, suite_plan::build_fault_suite_plan_expansion};
        let yaml = if mode == AckCalibrationMode::Strict {
            include_str!("../../fault/examples/ack-put-strict.yaml")
        } else {
            include_str!("../../fault/examples/ack-put-relaxed.yaml")
        };
        let suite: FaultSuite = serde_yaml_ng::from_str(yaml).unwrap();
        let mut config = FaultTestConfig::for_test("lab", "dm-storage");
        config.cluster.artifacts_dir = base_dir.into();
        config.cluster.rustfs_image = format!("rustfs/rustfs@sha256:{}", "a".repeat(64));
        let expansion = build_fault_suite_plan_expansion(
            suite.resolve().unwrap(),
            config,
            format!("suite-{}", mode.as_str()),
        )
        .unwrap();
        let root = PathBuf::from(&expansion.plan.artifact_root);
        let attempt = &expansion.plan.attempts[0];
        let case = Path::new(&attempt.artifacts.case_dir);
        fs::create_dir_all(case).unwrap();
        fs::write(
            root.join("suite-plan.json"),
            serde_json::to_vec(&expansion.plan).unwrap(),
        )
        .unwrap();
        fs::write(root.join("suite-summary.json"), serde_json::to_vec(&serde_json::json!({
            "runId": expansion.plan.run_id, "status": "succeeded", "attempts": [{
                "runId": attempt.run_id, "scenario": attempt.scenario,
                "status": if mode == AckCalibrationMode::Strict { "succeeded" } else { "expected-failure" },
                "startedAtMs": 1, "endedAtMs": 100
            }]
        })).unwrap()).unwrap();
        let mut fixture = control(mode);
        fixture.spec.metadata.run_id = attempt.run_id.clone().unwrap();
        fixture.spec.scenario.ack_trigger = attempt.ack_trigger.clone();
        fixture.spec.workload.object_count = attempt.workload.objects;
        fixture.spec.workload.concurrency = attempt.workload.concurrency;
        fixture.spec.workload.seed = attempt.workload.seed;
        fixture.spec.workload.plan = WorkloadPlan::seeded(
            attempt.workload.seed,
            attempt.workload.objects,
            attempt.workload.concurrency,
        );
        fixture.spec.workload.prefill_concurrency = attempt.workload.prefill_concurrency;

        fs::write(
            case.join("run-spec.json"),
            serde_json::to_vec(&fixture.spec).unwrap(),
        )
        .unwrap();
        root
    }

    #[test]
    fn load_control_rejects_relaxed_pass_and_changed_mode_or_scenario() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_control_header(dir.path(), AckCalibrationMode::Relaxed);
        let summary_path = root.join("suite-summary.json");
        let summary: serde_json::Value = read(&summary_path).unwrap();
        let mut passed = summary.clone();
        passed["attempts"][0]["status"] = serde_json::json!("succeeded");
        fs::write(&summary_path, serde_json::to_vec(&passed).unwrap()).unwrap();
        assert!(
            load_control(&root, AckCalibrationMode::Relaxed)
                .err()
                .unwrap()
                .to_string()
                .contains("wrong outcome")
        );
        fs::write(&summary_path, serde_json::to_vec(&summary).unwrap()).unwrap();
        let plan: FaultSuitePlan = read(&root.join("suite-plan.json")).unwrap();
        let spec_path = Path::new(&plan.attempts[0].artifacts.case_dir).join("run-spec.json");
        let original: FaultRunSpec = read(&spec_path).unwrap();
        for mode in [Some(AckCalibrationMode::Strict), None] {
            let mut wrong = original.clone();
            wrong
                .scenario
                .ack_trigger
                .as_mut()
                .unwrap()
                .calibration_mode = mode;
            fs::write(&spec_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
            assert!(
                load_control(&root, AckCalibrationMode::Relaxed)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("differs from suite plan")
            );
        }
        let mut wrong = original.clone();
        wrong.scenario.name = "dm-drop-writes-after-ack-overwrite".into();
        fs::write(&spec_path, serde_json::to_vec(&wrong).unwrap()).unwrap();
        assert!(
            load_control(&root, AckCalibrationMode::Relaxed)
                .err()
                .unwrap()
                .to_string()
                .contains("differs from suite plan")
        );
        fs::write(&spec_path, serde_json::to_vec(&original).unwrap()).unwrap();
        assert!(
            load_control(&root, AckCalibrationMode::Relaxed).is_err(),
            "success labels cannot replace native evidence"
        );
    }

    #[test]
    fn missing_native_artifacts_never_qualify_a_pair() {
        let empty = tempfile::tempdir().unwrap();
        assert!(validate_ack_calibration_pair(empty.path(), empty.path()).is_err());
    }
}
