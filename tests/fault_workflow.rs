// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

#![cfg(unix)]

use std::{fs, os::unix::fs::PermissionsExt, process::Command};

fn executable(path: &std::path::Path, script: &str) {
    fs::write(path, script).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[test]
fn installed_fault_runner_builds_without_a_manifest_or_cargo() {
    let directory = tempfile::tempdir().unwrap();
    let scripts = directory.path().join("scripts");
    fs::create_dir(&scripts).unwrap();
    let script = scripts.join("fault-test.sh");
    fs::copy(
        concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"),
        &script,
    )
    .unwrap();
    let binary = directory.path().join("installed-s3chaos");
    executable(&binary, "#!/bin/sh\nprintf '%s\\n' \"$*\"\n");
    let cargo = directory.path().join("cargo");
    executable(
        &cargo,
        "#!/bin/sh\necho 'unexpected Cargo invocation' >&2\nexit 91\n",
    );
    let artifacts = directory.path().join("artifacts");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
require_cli_runtime
build_fault_binary "$2" test
s3chaos_cli fault-catalog-json
"#,
            "installed-fault-test",
        ])
        .arg(&script)
        .arg(&artifacts)
        .env("S3CHAOS_BINARY", &binary)
        .env(
            "PATH",
            format!("{}:/usr/bin:/bin", directory.path().display()),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("fault-catalog-json"));
    assert!(!directory.path().join("Cargo.toml").exists());
    assert_eq!(
        fs::read_to_string(artifacts.join("fault-test-binary.path"))
            .unwrap()
            .trim(),
        binary.to_str().unwrap()
    );
}

#[test]
fn missing_fault_inputs_are_reported_together_before_build() {
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
build_fault_binary() { printf 'unexpected build\n' >&2; return 91; }
run_one io-eio
"#,
            "missing-fault-inputs",
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"),
        ])
        .env_remove("RUSTFS_FAULT_TEST_SERVER_IMAGE")
        .env_remove("RUSTFS_FAULT_TEST_STORAGE_CLASS")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("RUSTFS_FAULT_TEST_SERVER_IMAGE is required"));
    assert!(stderr.contains("RUSTFS_FAULT_TEST_STORAGE_CLASS is required"));
    assert!(!stderr.contains("unexpected build"));
}

#[test]
fn selected_context_does_not_read_or_change_current_context() {
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
kubectl() { printf 'unexpected kubectl call\n' >&2; return 91; }
resolve_fault_context
[[ "$FAULT_CONTEXT" == selected-cluster ]]
[[ "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" == selected-cluster ]]
"#,
            "selected-fault-context",
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"),
        ])
        .env("S3CHAOS_TARGET_CONTEXT", "selected-cluster")
        .env(
            "RUSTFS_FAULT_TEST_EXPECTED_CONTEXT",
            "unrelated-current-context",
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn legacy_cleanup_without_a_run_root_cannot_delete_resources() {
    let output = Command::new("bash")
        .args([
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"),
            "cleanup",
        ])
        .env_remove("S3CHAOS_RUN_ROOT")
        .env_remove("RUSTFS_FAULT_TEST_RUN_ROOT")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cleanup requires a recorded run"));
}

#[test]
fn invalid_qualification_inputs_keep_the_requested_plan() {
    let directory = tempfile::tempdir().unwrap();
    let output = Command::new("bash")
        .args([
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"),
            "qualify",
            "cluster-cold-restart",
        ])
        .env("S3CHAOS_RUN_ROOT", directory.path())
        .env_remove("RUSTFS_FAULT_TEST_SERVER_IMAGE")
        .env_remove("RUSTFS_FAULT_TEST_STORAGE_CLASS")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let plan: serde_json::Value = serde_json::from_slice(
        &fs::read(directory.path().join("qualification-plan.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(plan["resolution"], "requested");
    assert!(directory.path().join("qualification-result.json").exists());
}

#[test]
fn a_remaining_process_group_cannot_publish_success() {
    let directory = tempfile::tempdir().unwrap();
    fs::write(directory.path().join("fault-session.json"), "{}").unwrap();
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
WORKFLOW_SESSION_ROOT="$2"
WORKFLOW_PROCESS_GROUP="$(ps -o pgid= -p $$ | tr -d ' ')"
s3chaos_cli() { printf 'unexpected completion receipt\n' >&2; }
trap handle_exit EXIT
true
"#,
            "unfinished-fault-process-group",
            concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"),
        ])
        .arg(directory.path())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("supervised processes remain active"),
        "{stderr}"
    );
    assert!(!stderr.contains("unexpected completion receipt"));
    assert!(!directory.path().join("fault-workflow-result.json").exists());
}
