// Copyright 2026 RustFS Team
// SPDX-License-Identifier: Apache-2.0

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output, Stdio},
};

use serde_json::Value;

struct Sandbox {
    directory: tempfile::TempDir,
    binary: PathBuf,
}

impl Sandbox {
    fn new() -> Self {
        let directory = tempfile::tempdir().expect("temporary directory");
        fs::create_dir(directory.path().join("work")).expect("working directory");
        fs::create_dir(directory.path().join("empty-path")).expect("empty PATH directory");
        Self {
            directory,
            binary: PathBuf::from(env!("CARGO_BIN_EXE_s3chaos")),
        }
    }

    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .env_clear()
            .env("PATH", self.directory.path().join("empty-path"))
            .current_dir(self.directory.path().join("work"))
            .stdin(Stdio::null());
        command
    }

    fn local_command(&self, arguments: &[&str]) -> Command {
        let mut command = self.command();
        command
            .arg("--config")
            .arg(self.directory.path().join("missing-targets.json"))
            .arg("--data-dir")
            .arg(self.data())
            .args(arguments);
        command
    }

    fn local(&self, arguments: &[&str]) -> Output {
        self.local_command(arguments)
            .output()
            .expect("execute local command")
    }

    fn data(&self) -> PathBuf {
        self.directory.path().join("data")
    }
}

fn successful(output: Output) -> String {
    assert!(
        output.status.success(),
        "status: {}\nstdout: {}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("UTF-8 stdout")
}

fn json_output(output: Output) -> Value {
    let stdout = successful(output);
    serde_json::from_str(&stdout).unwrap_or_else(|error| panic!("JSON output: {error}\n{stdout}"))
}

#[test]
fn workflow_help_needs_no_environment_or_target_configuration() {
    let sandbox = Sandbox::new();
    let commands: &[&[&str]] = &[
        &[],
        &["--help"],
        &["init", "--help"],
        &["run", "--help"],
        &["run", "fault", "--help"],
        &["run", "protocol", "--help"],
        &["run", "mint", "--help"],
        &["runs", "--help"],
        &["report", "--help"],
        &["reproduce", "--help"],
        &["cleanup", "--help"],
        &["doctor", "--help"],
        &["validate", "--help"],
        &["console", "--help"],
        &["list", "--help"],
    ];
    for arguments in commands {
        let stdout = successful(
            sandbox
                .command()
                .args(*arguments)
                .output()
                .expect("command help"),
        );
        assert!(stdout.contains("Usage:"), "{arguments:?}: {stdout}");
    }
    assert!(!sandbox.data().exists());
}

#[test]
fn worker_help_returns_before_loading_targets_or_starting_workers() {
    let sandbox = Sandbox::new();
    for worker in [
        "fault-run",
        "fault-suite-run",
        "fault-console-serve",
        "fault-validate-artifacts",
        "protocol-suite-plan",
        "protocol-suite-run",
        "protocol-suite-reproduce",
        "protocol-cleanup",
        "protocol-mint-run",
        "protocol-mint-cleanup",
        "protocol-mint-verify-target",
        "workflow-mint-discover",
        "workflow-mint-reproduce",
        "fault-workflow-cleanup",
    ] {
        let stdout = successful(
            sandbox
                .command()
                .args([worker, "--help"])
                .output()
                .expect("worker help"),
        );
        assert!(stdout.contains("Commands:"), "{worker}: {stdout}");
    }
    assert!(!sandbox.data().exists());
}

#[test]
fn bundled_smoke_suites_validate_without_target_configuration() {
    let sandbox = Sandbox::new();
    for kind in ["fault", "protocol"] {
        let stdout = successful(sandbox.local(&["validate", kind, "smoke"]));
        assert!(stdout.contains(&format!("{kind} suite is valid")));
    }
    let invalid = sandbox.local(&["validate", "protocol", "missing-suite"]);
    assert!(!invalid.status.success(), "missing suite must be rejected");
    assert!(!sandbox.data().join("runs").exists());
}

#[test]
fn first_runs_query_reports_an_empty_history() {
    let sandbox = Sandbox::new();
    assert!(!sandbox.data().exists());
    let history = json_output(sandbox.local(&["runs", "--json"]));
    assert_eq!(history["total"], 0);
    assert_eq!(history["runs"], serde_json::json!([]));
    assert_eq!(history["warnings"], serde_json::json!([]));
    let stdout = successful(sandbox.local(&["runs"]));
    assert!(stdout.contains("0 of 0 runs"), "{stdout}");
}

#[test]
fn missing_configuration_produces_inspectable_failed_runs() {
    let sandbox = Sandbox::new();
    for kind in ["fault", "protocol", "mint"] {
        let output = sandbox.local(&["run", kind, "--target", "missing"]);
        assert!(!output.status.success(), "missing configuration must fail");
        let stdout = String::from_utf8(output.stdout).expect("run stdout");
        assert!(stdout.contains("Result: failed"), "{stdout}");

        let history = json_output(sandbox.local(&["runs", "--kind", kind, "--json"]));
        assert_eq!(history["total"], 1);
        let id = history["runs"][0]["id"].as_str().expect("run ID");
        let root = sandbox.data().join("runs").join(id);
        let bytes = fs::read(root.join("record.json")).expect("recorded failure");
        let record: Value = serde_json::from_slice(&bytes).expect("run record");
        assert_eq!(record["kind"], kind);
        assert_eq!(record["target"], "missing");
        assert_eq!(record["state"], "finished");
        assert_eq!(record["result"], "failed");
        assert_eq!(record["exitCode"], 1);
        assert!(record["finishedAt"].is_string());
        assert!(
            record["error"]
                .as_str()
                .expect("configuration error")
                .contains("missing-targets.json")
        );
        assert!(!root.join("artifacts").exists());

        for run in [id, root.to_str().expect("absolute run path")] {
            let report = json_output(sandbox.local(&["report", run, "--json"]));
            assert_eq!(report["kind"], kind);
            assert_eq!(report["result"], "failed");
        }
        assert_eq!(fs::read(root.join("record.json")).expect("record"), bytes);
    }
    let history = json_output(sandbox.local(&["runs", "--result", "failed", "--json"]));
    assert_eq!(history["total"], 3);
}

#[cfg(unix)]
#[test]
fn fault_worker_uses_saved_environment_and_requires_evidence_after_successful_exit() {
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt};

    let sandbox = Sandbox::new();
    successful(sandbox.local(&[
        "init",
        "--kind",
        "fault",
        "--target",
        "local-fixture",
        "--context",
        "saved-context",
        "--storage-class",
        "saved-storage",
        "--image",
        "example.invalid/rustfs:test",
        "--namespace",
        "saved-namespace",
        "--option",
        "RUSTFS_FAULT_TEST_SEED=1234",
    ]));
    let fake_bash = sandbox.directory.path().join("empty-path/bash");
    fs::write(
        &fake_bash,
        "#!/bin/sh\n/usr/bin/env > \"${S3CHAOS_RUN_ROOT%/*}/worker.env\"\nexit 0\n",
    )
    .expect("fake supervisor");
    fs::set_permissions(&fake_bash, fs::Permissions::from_mode(0o755))
        .expect("executable supervisor");
    let output = sandbox
        .local_command(&["run", "fault", "--target", "local-fixture"])
        .env("RUSTFS_FAULT_TEST_AMBIENT_SENTINEL", "test-only-value")
        .env("RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY", "test-only-secret")
        .env("S3CHAOS_AMBIENT_SENTINEL", "test-only-value")
        .env("S3CHAOS_KEEP_RESOURCES", "1")
        .env("RUSTFS_FAULT_TEST_EXPECTED_CONTEXT", "ambient-context")
        .env("RUSTFS_FAULT_TEST_NAMESPACE", "ambient-namespace")
        .env("RUSTFS_FAULT_TEST_SEED", "5678")
        .env("S3CHAOS_RUN_ROOT", "/unused-test-run")
        .output()
        .expect("run with fake supervisor");
    assert!(
        !output.status.success(),
        "a worker exit without test evidence must not pass"
    );
    let stdout = String::from_utf8(output.stdout).expect("run stdout");
    assert!(stdout.contains("Result: incomplete"), "{stdout}");
    let history = json_output(sandbox.local(&["runs", "--json"]));
    assert_eq!(history["total"], 1);
    assert_eq!(history["runs"][0]["result"], "incomplete");
    let id = history["runs"][0]["id"].as_str().expect("run ID");
    let root = sandbox.data().join("runs").join(id);
    let captured = fs::read_to_string(root.join("worker.env")).expect("worker environment");
    let environment = captured
        .lines()
        .map(|line| line.split_once('=').expect("environment entry"))
        .collect::<BTreeMap<_, _>>();
    for name in [
        "RUSTFS_FAULT_TEST_AMBIENT_SENTINEL",
        "RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY",
        "S3CHAOS_AMBIENT_SENTINEL",
        "S3CHAOS_KEEP_RESOURCES",
    ] {
        assert!(!environment.contains_key(name), "ambient setting {name}");
    }
    assert_eq!(environment["S3CHAOS_TARGET_CONTEXT"], "saved-context");
    assert_eq!(
        environment["RUSTFS_FAULT_TEST_EXPECTED_CONTEXT"],
        "saved-context"
    );
    assert_eq!(
        environment["RUSTFS_FAULT_TEST_NAMESPACE"],
        "saved-namespace"
    );
    assert_eq!(environment["RUSTFS_FAULT_TEST_SEED"], "1234");
    assert_eq!(environment["S3CHAOS_RUN_ID"], id);
    let expected_root = root.join("artifacts");
    assert_eq!(
        environment["S3CHAOS_RUN_ROOT"],
        expected_root.to_str().expect("artifact path")
    );
    assert_eq!(
        environment["RUSTFS_FAULT_TEST_RUN_ROOT"],
        environment["S3CHAOS_RUN_ROOT"]
    );
    let record: Value =
        serde_json::from_slice(&fs::read(root.join("record.json")).expect("run record"))
            .expect("record JSON");
    assert_eq!(record["exitCode"], 0);
    assert_eq!(record["state"], "finished");
    assert_eq!(record["result"], "incomplete");
    let report = json_output(sandbox.local(&["report", id, "--json"]));
    assert_eq!(report["result"], "incomplete");
}

#[cfg(target_os = "linux")]
#[test]
fn quorum_dm_runs_and_reproduces_with_run_scoped_state_files() {
    use std::os::unix::fs::PermissionsExt;

    let sandbox = Sandbox::new();
    let source = sandbox.directory.path().join("targets.json");
    let targets: Vec<_> = ["a", "b"]
        .iter()
        .map(|token| {
            serde_json::json!({
                "node": format!("node-{token}"), "mapperName": format!("dm-{token}"),
                "mountPath": format!("/data/{token}"), "persistentVolume": format!("pv-{token}"),
                "observerNamespace": "observers", "observerPod": format!("observer-{token}"),
                "stateFile": format!(".host-mutation-{token}.json"), "stateToken": token,
            })
        })
        .collect();
    let template = serde_json::json!({"targets": targets});
    fs::write(&source, serde_json::to_vec(&template).unwrap()).unwrap();
    let config = serde_json::json!({"schemaVersion": 1, "targets": {"lab": {"fault": {
        "context": "local-context", "storageClass": "static", "image": "rustfs:test",
        "options": {
            "RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS": source,
            "RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE": "1",
            "RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST": "node-a,node-b",
            "RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST": "/dev/mapper/dm-a,/dev/mapper/dm-b",
            "RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST": "pv-a,pv-b"
        }
    }}}});
    fs::write(
        sandbox.directory.path().join("missing-targets.json"),
        serde_json::to_vec(&config).unwrap(),
    )
    .unwrap();
    let script = sandbox.directory.path().join("empty-path/bash");
    fs::write(
        &script,
        r#"#!/bin/bash
source "$1"
kubectl() { printf 'unexpected kubectl invocation\n' >&2; exit 91; }
build_fault_binary() { :; }
require_dm_scenario() { :; }
preflight() { :; }
start_workflow_session() { :; }
run_scenario() { printf '%s' "$1" > "$2/scenario-started"; }
run_dm "$3"
"#,
    )
    .unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let path = format!(
        "{}:/usr/bin:/bin",
        sandbox.directory.path().join("empty-path").display()
    );
    let mut original_id = String::new();
    let mut original_evidence = None;
    for replay in [false, true] {
        let arguments = if replay {
            vec!["reproduce", original_id.as_str(), "--use-current-image"]
        } else {
            vec![
                "run",
                "fault",
                "--target",
                "lab",
                "--case",
                "quorum-p-dm-eio",
            ]
        };
        let output = sandbox
            .local_command(&arguments)
            .env("PATH", &path)
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "a simulated scenario has no final evidence"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Result: incomplete"),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let history = json_output(sandbox.local(&["runs", "--json"]));
        let id = history["runs"]
            .as_array()
            .unwrap()
            .iter()
            .find_map(|run| run["id"].as_str().filter(|id| *id != original_id))
            .unwrap();
        let root = sandbox.data().join("runs").join(id);
        assert_eq!(
            fs::read_to_string(root.join("artifacts/scenario-started")).unwrap(),
            "quorum-p-dm-eio"
        );
        let resolved: Value = serde_json::from_slice(
            &fs::read(root.join("quorum-dm-targets-resolved.json")).unwrap(),
        )
        .unwrap();
        for (index, token) in ["a", "b"].iter().enumerate() {
            assert_eq!(
                resolved["targets"][index]["stateFile"],
                root.join(format!("artifacts/.host-mutation-{token}.json"))
                    .display()
                    .to_string()
            );
        }
        if !replay {
            original_id = id.into();
            original_evidence =
                Some(fs::read(root.join("quorum-dm-targets-resolved.json")).unwrap());
            fs::remove_file(&source).unwrap();
        }
    }
    let original = sandbox.data().join("runs").join(original_id);
    assert_eq!(
        fs::read(original.join("quorum-dm-targets-resolved.json")).unwrap(),
        original_evidence.unwrap()
    );
    let saved: Value =
        serde_json::from_slice(&fs::read(original.join("quorum-dm-targets.json")).unwrap())
            .unwrap();
    assert_eq!(saved, template);
}

#[cfg(target_os = "linux")]
#[test]
fn cleanup_rejects_a_live_worker_after_its_parent_has_exited() {
    use s3chaos::workflow::{
        config::Target,
        runs::{ProcessIdentity, RunRecord},
    };

    let sandbox = Sandbox::new();
    let mut parent = Command::new("/bin/sh")
        .args(["-c", "read value"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("local parent process");
    let parent_identity = ProcessIdentity::for_pid(parent.id()).expect("parent identity");
    drop(parent.stdin.take());
    parent.wait().expect("parent exit");
    assert_eq!(parent_identity.is_running(), Some(false));
    let worker_identity = ProcessIdentity::current().expect("live worker identity");
    assert_eq!(worker_identity.is_running(), Some(true));
    let (mut record, root) = RunRecord::create(
        &sandbox.data(),
        "fault",
        "local-fixture",
        Target::default(),
        None,
    )
    .expect("unfinished run");
    record.process = Some(parent_identity);
    record.worker_process = Some(worker_identity);
    for state in ["running", "finished"] {
        record.state = state.into();
        record.result = if state == "running" {
            "running"
        } else {
            "passed"
        }
        .into();
        record.save(&root).expect("record live worker");
        let before = fs::read(root.join("record.json")).expect("record before cleanup");

        let output = sandbox.local(&["cleanup", &record.id]);
        assert!(!output.status.success(), "live worker must block cleanup");
        let stderr = String::from_utf8(output.stderr).expect("cleanup stderr");
        assert!(
            stderr.contains("the recorded worker is still active"),
            "{stderr}"
        );
        assert_eq!(
            fs::read(root.join("record.json")).expect("record after cleanup"),
            before
        );
        assert!(!root.join("artifacts").exists());
    }
}

#[test]
fn installed_binary_lists_and_validates_without_cargo_or_source_files() {
    let mut sandbox = Sandbox::new();
    let installed = sandbox.directory.path().join("installed-s3chaos");
    fs::hard_link(&sandbox.binary, &installed)
        .or_else(|_| fs::copy(&sandbox.binary, &installed).map(|_| ()))
        .expect("install binary");
    sandbox.binary = installed;
    assert_eq!(
        fs::read_dir(sandbox.directory.path().join("work"))
            .expect("working directory")
            .count(),
        0
    );
    let help = successful(
        sandbox
            .command()
            .arg("--help")
            .output()
            .expect("installed help"),
    );
    assert!(help.contains("Usage:"));
    let suites = successful(sandbox.local(&["list", "suites"]));
    assert!(suites.contains("fault\tsmoke"));
    assert!(suites.contains("protocol\tsmoke"));
    for row in suites.lines().skip(1) {
        let (kind, suite) = row.split_once('\t').expect("suite kind and runnable name");
        let stdout = successful(sandbox.local(&["validate", kind, suite]));
        assert!(stdout.contains(&format!("{kind} suite is valid")));
    }
    let cases = json_output(sandbox.local(&["list", "cases", "--kind", "protocol"]));
    assert!(!cases.as_array().expect("protocol case catalog").is_empty());
    for kind in ["fault", "protocol"] {
        let suites = successful(sandbox.local(&["list", "suites", "--kind", kind]));
        assert!(suites.contains(&format!("{kind}\tsmoke")));
        assert!(
            suites
                .lines()
                .skip(1)
                .all(|row| row.starts_with(&format!("{kind}\t")))
        );
    }
}

#[test]
fn mint_cleanup_reaches_the_recovery_worker_without_original_credentials() {
    use s3chaos::workflow::{
        config::{CredentialSource, MintTarget, Target},
        runs::RunRecord,
    };

    let sandbox = Sandbox::new();
    let target = Target {
        mint: Some(MintTarget {
            context: "local-context".into(),
            service: "rustfs".into(),
            port: Some(9000),
            endpoint: None,
            region: "us-east-1".into(),
            container: "rustfs".into(),
            credentials: CredentialSource {
                access_key_env: "LAB_KEY".into(),
                secret_key_env: "LAB_SECRET".into(),
                session_token_env: Some("LAB_TOKEN".into()),
            },
        }),
        ..Target::default()
    };
    let (mut record, root) =
        RunRecord::create(&sandbox.data(), "mint", "local-fixture", target, None)
            .expect("Mint run record");
    record.state = "finished".into();
    record.result = "failed".into();
    record.save(&root).expect("finished Mint run");
    let before = fs::read(root.join("record.json")).expect("record before cleanup");
    fs::create_dir(root.join("artifacts")).expect("empty artifacts");

    for partial_credentials in [false, true] {
        let mut command = sandbox.local_command(&["cleanup", &record.id]);
        if partial_credentials {
            command.env("LAB_KEY", "test-only-key");
        }
        let output = command.output().expect("Mint recovery command");
        assert!(
            !output.status.success(),
            "missing ownership evidence must block cleanup"
        );
        let stderr = String::from_utf8(output.stderr).expect("cleanup stderr");
        assert!(stderr.contains("mint-target-spec.json"), "{stderr}");
        assert!(
            !stderr.contains("missing credential environment variables"),
            "{stderr}"
        );
        assert!(!stderr.contains("test-only-key"), "{stderr}");
        assert_eq!(
            fs::read(root.join("record.json")).expect("record after cleanup"),
            before
        );
    }
}
