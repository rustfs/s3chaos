// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

use s3chaos::protocol::{
    suite::{ProtocolSuite, ProtocolSuiteSelector},
    suite_plan::{
        ProtocolMutatingProbeSummary, ProtocolSuitePlan, ProtocolSuitePlanPreflight,
        TargetFingerprint,
    },
    suite_runner::protocol_reproduction_suite,
};
use std::fs;

fn recorded_suite() -> (tempfile::TempDir, ProtocolSuitePlan) {
    let root = tempfile::tempdir().expect("run directory");
    let mut suite: ProtocolSuite =
        serde_yaml_ng::from_str(include_str!("../protocol/examples/smoke.yaml"))
            .expect("smoke suite");
    let plan = ProtocolSuitePlan::build(
        &suite.resolve().expect("resolved suite"),
        TargetFingerprint::new(
            "http://127.0.0.1:9000",
            "us-east-1",
            "original-deployment",
            None,
            None,
        )
        .expect("fingerprint"),
        ProtocolSuitePlanPreflight {
            endpoint_reachable: true,
            admin_api_reachable: true,
            external_identity: None,
            capability_matrix: Vec::new(),
            stale_buckets: Vec::new(),
            stale_identities: Vec::new(),
            stale_resource_policy: "fail".into(),
            mutating_permission_probe: ProtocolMutatingProbeSummary::not_run(),
        },
        root.path(),
        "original-run",
    )
    .expect("plan");
    // The source selection and ambient endpoint are not authoritative after a run.
    suite.selector = ProtocolSuiteSelector {
        tags: vec!["slow".into()],
        ..Default::default()
    };
    suite.target.endpoint = "${S3CHAOS_REPRODUCTION_UNRESOLVED_ENDPOINT}".into();
    suite.target.region = "changed-region".into();
    suite.execution.timeouts.case_seconds += 1;
    fs::write(
        root.path().join("protocol-suite.yaml"),
        serde_yaml_ng::to_string(&suite).expect("yaml"),
    )
    .expect("source");
    fs::write(
        root.path().join("protocol-suite-plan.json"),
        plan.to_json().expect("plan json"),
    )
    .expect("plan");
    (root, plan)
}

#[test]
fn reproduction_uses_recorded_selection_target_and_execution_parameters() {
    let (root, plan) = recorded_suite();
    let original = fs::read(root.path().join("protocol-suite.yaml")).expect("source");
    let (suite, fingerprint) =
        protocol_reproduction_suite(root.path(), None).expect("reproduction");
    assert_eq!(
        suite.selector.cases,
        plan.cases
            .iter()
            .map(|case| case.id.clone())
            .collect::<Vec<_>>()
    );
    assert!(suite.selector.tags.is_empty());
    assert_eq!(suite.execution.timeouts, plan.execution.timeouts);
    assert_eq!(suite.target.endpoint, plan.target.fingerprint.endpoint);
    assert_eq!(suite.target.region, plan.target.fingerprint.region);
    assert_eq!(fingerprint, plan.target.fingerprint);
    assert_eq!(
        fs::read(root.path().join("protocol-suite.yaml")).expect("source after replay"),
        original
    );
    assert_eq!(fs::read_dir(root.path()).expect("run entries").count(), 2);
    assert!(protocol_reproduction_suite(root.path(), Some("not-in-original-run")).is_err());
    let mut empty_plan = plan;
    empty_plan.cases.clear();
    fs::write(
        root.path().join("protocol-suite-plan.json"),
        empty_plan.to_json().expect("empty plan json"),
    )
    .expect("empty plan");
    assert!(protocol_reproduction_suite(root.path(), None).is_err());
}

#[cfg(unix)]
#[test]
fn reproduction_reads_a_read_only_original_directory() {
    use std::os::unix::fs::PermissionsExt;
    let (root, plan) = recorded_suite();
    for entry in fs::read_dir(root.path()).expect("run entries") {
        fs::set_permissions(
            entry.expect("entry").path(),
            fs::Permissions::from_mode(0o444),
        )
        .expect("read-only file");
    }
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o555))
        .expect("read-only directory");
    let result = protocol_reproduction_suite(root.path(), Some(&plan.cases[0].id));
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))
        .expect("restore directory permissions");
    let (suite, _) = result.expect("read-only reproduction");
    assert_eq!(suite.selector.cases, vec![plan.cases[0].id.clone()]);
    assert_eq!(fs::read_dir(root.path()).expect("run entries").count(), 2);
}
