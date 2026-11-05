// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail, ensure};

use crate::fault::{
    suite::FaultSuite,
    suite_plan::{
        FAULT_SUITE_PLAN_API_VERSION, FAULT_SUITE_PLAN_KIND, FaultSuitePlan, suite_seed_for_attempt,
    },
};

/// Select the original scenario definition and preserve the selected workload seed.
pub fn select_attempt(original_root: &Path, selection: &str) -> Result<(FaultSuite, u64)> {
    let mut suite = FaultSuite::from_yaml_path(original_root.join("suite.yaml"))?;
    suite.resolve()?;
    let mut plans = Vec::new();
    find_plans(&original_root.join("artifacts"), 0, &mut plans)?;
    ensure!(
        plans.len() == 1,
        "expected one recorded fault suite plan, found {}",
        plans.len()
    );
    let plan: FaultSuitePlan =
        serde_json::from_slice(&fs::read(&plans[0])?).context("read original fault suite plan")?;
    ensure!(
        plan.api_version == FAULT_SUITE_PLAN_API_VERSION
            && plan.kind == FAULT_SUITE_PLAN_KIND
            && plan.suite == suite.metadata.name,
        "recorded suite plan does not match the saved suite"
    );
    let expected: Vec<_> = suite
        .scenarios
        .iter()
        .enumerate()
        .flat_map(|(scenario_index, scenario)| {
            (1..=scenario.repetitions)
                .map(move |repetition| (scenario_index, &scenario.name, repetition))
        })
        .collect();
    ensure!(
        expected.len() == plan.attempts.len(),
        "recorded attempts do not match the saved suite repetitions"
    );
    for (offset, (attempt, (_, scenario, repetition))) in
        plan.attempts.iter().zip(&expected).enumerate()
    {
        ensure!(
            attempt.index == offset + 1
                && &attempt.scenario == *scenario
                && attempt.repetition == *repetition,
            "recorded attempt {} does not match the saved suite order",
            attempt.index
        );
        ensure!(
            suite_seed_for_attempt(attempt.workload.seed, attempt.index, attempt.repetition)
                == plan.suite_seed,
            "recorded workload seed does not match the original suite seed for attempt {}",
            attempt.index
        );
    }
    let selected = if let Some(index) = selection.strip_prefix("attempt:") {
        let index: usize = index
            .parse()
            .context("attempt selection must be a positive index such as attempt:1")?;
        plan.attempts
            .iter()
            .position(|attempt| attempt.index == index)
            .with_context(|| format!("attempt:{index} is absent from the original suite"))?
    } else {
        let matches: Vec<_> = plan
            .attempts
            .iter()
            .enumerate()
            .filter(|(_, attempt)| attempt.scenario == selection || attempt.case_name == selection)
            .collect();
        match matches.as_slice() {
            [(offset, _)] => *offset,
            [] => bail!("case {selection:?} is absent from the original suite"),
            _ => bail!(
                "case {selection:?} has multiple attempts; select {}",
                matches
                    .iter()
                    .map(|(_, attempt)| format!("attempt:{}", attempt.index))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        }
    };
    let mut scenario = suite.scenarios[expected[selected].0].clone();
    scenario.repetitions = 1;
    suite.scenarios = vec![scenario];
    suite.resolve()?;
    Ok((
        suite,
        suite_seed_for_attempt(plan.attempts[selected].workload.seed, 1, 1),
    ))
}

fn find_plans(root: &Path, depth: usize, found: &mut Vec<PathBuf>) -> Result<()> {
    ensure!(
        depth <= 16,
        "fault artifact directory nesting exceeds the supported depth"
    );
    for entry in
        fs::read_dir(root).with_context(|| format!("read fault artifacts {}", root.display()))?
    {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            find_plans(&entry.path(), depth + 1, found)?;
        } else if kind.is_file() && entry.file_name() == "suite-plan.json" {
            found.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fault::{config::FaultTestConfig, suite_plan::build_fault_suite_plan_expansion};

    fn original() -> (tempfile::TempDir, FaultSuite, FaultSuitePlan) {
        let suite: FaultSuite = serde_yaml_ng::from_str(
            r#"
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: replay-seeds
budgets:
  maxDuration: 24h
  maxClientDisruptions: 1200
workloadProfiles:
  replay:
    objects: 600
    concurrency: 30
scenarios:
  - name: io-eio
    repetitions: 2
    faultDuration: 10s
    percent: 20
    workloadProfile: replay
    expectedFailure:
      classification: data_corruption
      severity: fail_correctness
      responsibilityDomain: product
      evidenceRefs:
        - checker-report.json
  - name: network-delay
    faultDuration: 20s
    workloadProfile: replay
    params:
      kind: networkDelay
      latency: 200ms
      jitter: 50ms
      correlationPercent: 25
"#,
        )
        .unwrap();
        let mut config = FaultTestConfig::for_test("replay-cluster", "dynamic");
        config.workload_seed = Some(12345);
        let plan =
            build_fault_suite_plan_expansion(suite.resolve().unwrap(), config, "original".into())
                .unwrap()
                .plan;
        let root = tempfile::tempdir().unwrap();
        let artifacts = root.path().join("artifacts/replay-seeds/original");
        fs::create_dir_all(&artifacts).unwrap();
        fs::write(
            root.path().join("suite.yaml"),
            serde_yaml_ng::to_string(&suite).unwrap(),
        )
        .unwrap();
        fs::write(
            artifacts.join("suite-plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
        (root, suite, plan)
    }

    #[test]
    fn selected_repetition_preserves_seed_profile_expected_failure_and_budgets() {
        let (root, original, plan) = original();
        let before = fs::read(root.path().join("suite.yaml")).unwrap();
        let (selected, seed) = select_attempt(root.path(), "attempt:2").unwrap();
        assert_eq!(selected.scenarios.len(), 1);
        let mut expected = original.scenarios[0].clone();
        expected.repetitions = 1;
        assert_eq!(selected.scenarios[0], expected);
        assert_eq!(selected.budgets, original.budgets);
        assert_eq!(selected.workload_profiles, original.workload_profiles);
        let mut config = FaultTestConfig::for_test("replay-cluster", "dynamic");
        config.workload_seed = Some(seed);
        let replay =
            build_fault_suite_plan_expansion(selected.resolve().unwrap(), config, "replay".into())
                .unwrap()
                .plan;
        assert_eq!(replay.attempts[0].workload, plan.attempts[1].workload);
        assert_eq!(
            replay.attempts[0].expected_failure,
            plan.attempts[1].expected_failure
        );
        assert_eq!(fs::read(root.path().join("suite.yaml")).unwrap(), before);
    }

    #[test]
    fn a_unique_name_preserves_fault_parameters() {
        let (root, original, _) = original();
        let (selected, _) = select_attempt(root.path(), "network-delay").unwrap();
        assert_eq!(selected.scenarios, vec![original.scenarios[1].clone()]);
    }

    #[test]
    fn duplicate_names_and_missing_attempts_require_an_exact_choice() {
        let (root, _, _) = original();
        let error = select_attempt(root.path(), "io-eio")
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("attempt:1") && error.contains("attempt:2"),
            "{error}"
        );
        for selection in ["attempt:0", "attempt:4", "attempt:invalid", "unknown"] {
            assert!(select_attempt(root.path(), selection).is_err());
        }
    }

    #[test]
    fn inconsistent_saved_plan_cannot_reproduce_a_different_attempt() {
        let (root, _, mut plan) = original();
        plan.attempts[1].workload.seed ^= 1;
        fs::write(
            root.path()
                .join("artifacts/replay-seeds/original/suite-plan.json"),
            serde_json::to_vec(&plan).unwrap(),
        )
        .unwrap();
        assert!(
            select_attempt(root.path(), "attempt:2")
                .unwrap_err()
                .to_string()
                .contains("workload seed")
        );
    }
}
