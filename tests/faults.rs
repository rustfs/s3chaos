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

use anyhow::Result;
#[cfg(unix)]
use std::process::{Command, Output};

#[cfg(unix)]
fn fault_supervision_output(host_storage_mutation_active: bool) -> Output {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
group_probe_count=0
observed_signals=""
sleep() { :; }
host_storage_mutation_active() { [[ "$2" == "active" ]]; }
kill() {
  case "$1" in
    -TERM|-KILL)
      observed_signals="${observed_signals}${1#-}:$2:$3 "
      return 0
      ;;
    -0)
      [[ "$2" == "--" && "$3" == "-4242" ]] || return 1
      group_probe_count=$((group_probe_count + 1))
      (( group_probe_count <= 3 ))
      ;;
    *)
      return 1
      ;;
  esac
}
terminate_process_group 4242 4242 "$2" token-a "" 0
printf '%s\n' "$observed_signals"
"#,
            "fault-process-supervision-test",
            script,
            if host_storage_mutation_active {
                "active"
            } else {
                "inactive"
            },
        ])
        .output()
        .expect("run fault process supervision shell test")
}

#[cfg(unix)]
#[test]
fn active_dm_termination_past_grace_never_escalates_to_sigkill() {
    let output = fault_supervision_output(true);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "TERM:--:-4242"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("refusing to send SIGKILL"));
    assert!(stderr.contains("waiting for the fault process to restore or quarantine"));
}

#[cfg(unix)]
#[test]
fn ordinary_fault_termination_escalates_when_group_outlives_leader() {
    let output = fault_supervision_output(false);

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "TERM:--:-4242 KILL:--:-4242"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("escalating to KILL"));
}

#[cfg(unix)]
#[test]
fn process_group_snapshot_omits_command_arguments() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let secret = "snapshot-secret-must-not-persist";
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
group="$(ps -o pgid= -p "$$" | tr -d '[:space:]')"
capture_process_group "$2" before-term "$$" "$group"
"#,
            "fault-process-snapshot-test",
            script,
            temporary.path().to_str().expect("temporary path"),
            secret,
        ])
        .output()
        .expect("capture process group snapshot");

    assert!(output.status.success());
    let snapshot = std::fs::read_to_string(temporary.path().join("process-group-before-term.txt"))
        .expect("process group snapshot");
    assert!(!snapshot.contains(secret));
    let processes = snapshot.lines().skip(1).collect::<Vec<_>>();
    assert!(!processes.is_empty());
    for process in processes {
        assert_eq!(process.split_whitespace().count(), 4, "{process}");
    }
}

#[cfg(unix)]
#[test]
fn host_mutation_marker_rejects_wrong_token_and_cross_process_owner() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let marker = temporary.path().join("marker.json");
    std::fs::write(&marker, "{}").expect("marker");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    for phase in ["activating", "active", "rollback"] {
        let output = Command::new("bash")
            .args([
                "-c",
                r#"
source "$1"
descends=yes
marker_phase="$3"
jq() {
  case "$2" in
    '.schemaVersion // empty') printf '1\n' ;;
    '.token // empty') printf 'token-a\n' ;;
    '.ownerPid // empty') printf '222\n' ;;
    '.phase // empty') printf '%s\n' "$marker_phase" ;;
    *) return 1 ;;
  esac
}
kill() { [[ "$1" == "-0" && "$2" == "222" ]]; }
process_descends_from() { [[ "$descends" == "yes" && "$1" == "222" && "$2" == "111" ]]; }
host_storage_mutation_active 111 "$2" token-a && printf 'valid\n'
host_storage_mutation_active 111 "$2" token-b || printf 'wrong-token-rejected\n'
descends=no
host_storage_mutation_active 111 "$2" token-a || printf 'cross-process-rejected\n'
"#,
                "fault-mutation-state-test",
                script,
                marker.to_str().expect("marker path"),
                phase,
            ])
            .output()
            .expect("validate host mutation marker");

        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "valid\nwrong-token-rejected\ncross-process-rejected\n"
        );
    }
}

#[cfg(unix)]
#[test]
fn wrapper_preserves_unresolved_host_state_after_process_exit() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let marker = temporary.path().join("marker.json");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    for phase in [
        "prepared",
        "activating",
        "active",
        "rollback",
        "recovery-required",
    ] {
        let content =
            format!(r#"{{"schemaVersion":1,"token":"token-a","ownerPid":4242,"phase":"{phase}"}}"#);
        std::fs::write(&marker, &content).unwrap();
        let output = Command::new("bash")
            .args([
                "-c",
                r#"
source "$1"
ACTIVE_HOST_MUTATION_STATE_FILE="$2"
ACTIVE_HOST_MUTATION_STATE_TOKEN=token-a
cleanup_host_mutation_state
[[ -z "$ACTIVE_HOST_MUTATION_STATE_FILE" && -z "$ACTIVE_HOST_MUTATION_STATE_TOKEN" ]]
"#,
                "unresolved-host-state-test",
                script,
                marker.to_str().unwrap(),
            ])
            .output()
            .expect("wrapper cleanup");
        assert!(output.status.success());
        assert_eq!(std::fs::read_to_string(&marker).unwrap(), content);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("preserving unresolved host mutation state")
        );
    }
}

#[cfg(unix)]
#[test]
fn failed_run_captures_evidence_before_managed_chaos_cleanup() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let case_dir = temporary.path().join("case");
    std::fs::create_dir(&case_dir).expect("case directory");
    std::fs::write(case_dir.join("diagnosis.txt"), "diagnosis\n").expect("diagnosis");
    std::fs::write(case_dir.join("failure-summary.json"), "{}\n").expect("failure summary");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
manifest_function="$(declare -f write_failure_evidence_manifest)"
eval "${manifest_function/write_failure_evidence_manifest/write_failure_evidence_manifest_real}"
summary_function="$(declare -f write_runner_failure_summary)"
eval "${summary_function/write_runner_failure_summary/write_runner_failure_summary_real}"
capture_cluster_snapshot() { printf 'snapshot:%s\n' "$2"; }
capture_fault_logs() { printf 'logs\n'; }
write_runner_failure_summary() {
  printf 'summary:%s:%s\n' "$1" "$3"
  write_runner_failure_summary_real "$@"
}
write_failure_evidence_manifest() {
  printf 'manifest:%s:%s\n' "$1" "$5"
  write_failure_evidence_manifest_real "$@"
}
cleanup_managed_chaos() { printf 'cleanup\n'; }
finalize_failed_run scenario io-eio "$2" 42 failed
"#,
            "fault-failure-finalization-test",
            script,
            temporary.path().to_str().expect("temporary path"),
        ])
        .output()
        .expect("run fault failure finalization shell test");

    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "snapshot:failed\nlogs\nsummary:io-eio:42\nmanifest:scenario:failed\ncleanup\n"
    );
    let manifest = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(temporary.path().join("failure-evidence.json"))
            .expect("failure evidence"),
    )
    .expect("failure evidence json");
    assert_eq!(manifest["status"], "captured-before-managed-chaos-cleanup");
    assert_eq!(manifest["scope"], "scenario");
    assert_eq!(manifest["name"], "io-eio");
    assert_eq!(manifest["exitCode"], 42);
    assert_eq!(manifest["snapshotStage"], "failed");
    assert_eq!(manifest["detailedRustDiagnosisFiles"], 1);
    assert_eq!(manifest["failureSummaryFiles"], 2);
    assert!(temporary.path().join("runner-diagnosis.txt").is_file());
    let summary = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(temporary.path().join("runner-failure-summary.json"))
            .expect("runner failure summary"),
    )
    .expect("runner failure summary json");
    assert_eq!(summary["rust_failure_summary_present"], true);
}

#[cfg(unix)]
#[test]
fn ordinary_chaos_suite_gate_rejects_static_and_warp_plans() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let valid = temporary.path().join("valid.json");
    let static_storage = temporary.path().join("static.json");
    let warp = temporary.path().join("warp.json");
    std::fs::write(
        &valid,
        r#"{"requiresChaosMesh":true,"requiresStaticStorage":false,"attempts":[{"scenario":"io-eio","requiresChaosMesh":true,"requiresStaticStorage":false,"expectedBackend":"chaos-mesh-io"}]}"#,
    )
    .expect("valid plan");
    std::fs::write(
        &static_storage,
        r#"{"requiresChaosMesh":false,"requiresStaticStorage":true,"attempts":[{"scenario":"dm-flakey","requiresChaosMesh":false,"requiresStaticStorage":true,"expectedBackend":"host-device-mapper"}]}"#,
    )
    .expect("static plan");
    std::fs::write(
        &warp,
        r#"{"requiresChaosMesh":true,"requiresStaticStorage":false,"attempts":[{"scenario":"warp-under-chaos","requiresChaosMesh":true,"requiresStaticStorage":false,"expectedBackend":"chaos-mesh-io"}]}"#,
    )
    .expect("warp plan");

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
is_ordinary_chaos_suite_plan "$2"
! is_ordinary_chaos_suite_plan "$3"
! is_ordinary_chaos_suite_plan "$4"
require_non_static_suite_plan "$2"
! (require_non_static_suite_plan "$3") 2>/dev/null
"#,
            "fault-chaos-suite-gate-test",
            script,
            valid.to_str().expect("valid path"),
            static_storage.to_str().expect("static path"),
            warp.to_str().expect("warp path"),
        ])
        .output()
        .expect("run ordinary Chaos suite gate shell test");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn planned_qualification_matrix_is_closed_and_typed() {
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
FAULT_TEST_BINARY="$2"
list_qualification_cases
! qualification_case_contract arbitrary-shell
"#,
            "fault-qualification-matrix-test",
            script,
            env!("CARGO_BIN_EXE_s3chaos"),
        ])
        .output()
        .expect("inspect qualification matrix");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        concat!(
            "qualification-case\tscenario\tkind\tstorage-recovery-case\n",
            "admin-decommission\tadmin-decommission\tadmin\t-\n",
            "admin-rebalance\tadmin-rebalance\tadmin\t-\n",
            "fresh-volume-replacement-automatic-replacement\tfresh-volume-replacement\tstorage\tfresh-volume-replacement-automatic-replacement\n",
            "fresh-volume-replacement-admin-deep\tfresh-volume-replacement\tstorage\tfresh-volume-replacement-admin-deep\n",
            "on-disk-bitrot-automatic-scanner\ton-disk-bitrot\tstorage\ton-disk-bitrot-automatic-scanner\n",
            "on-disk-bitrot-admin-deep\ton-disk-bitrot\tstorage\ton-disk-bitrot-admin-deep\n",
            "stale-disk-return\tstale-disk-return-detect\tstorage\tstale-disk-return\n",
        )
    );
}

#[cfg(unix)]
#[test]
fn qualification_wrapper_passes_only_the_selected_opt_in() {
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let fake_binary = temporary.path().join("fake-s3chaos");
    std::fs::write(&fake_binary, "#!/usr/bin/env bash\nenv\n").expect("fake binary");
    let mut permissions = std::fs::metadata(&fake_binary)
        .expect("fake binary metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&fake_binary, permissions).expect("fake binary permissions");

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
kubectl_cluster() { printf '{"items":[]}\n'; }
list_non_fault_tenants() { :; }
scenario_requires_chaos_mesh() { return 1; }
capture_cluster_snapshot() { :; }
capture_fault_logs() { :; }
validate_scenario_artifacts() { :; }
sleep() { :; }
FAULT_TEST_BINARY="$2"
WORKLOAD_OBJECTS=12
WORKLOAD_CONCURRENCY=1
RUSTFS_POD_COUNT=4
RUSTFS_VOLUME_PATH=/data/rustfs0
RUSTFS_POD_STABLE_WINDOW_SECONDS=1
HEALTH_GUARD_FAILURE_THRESHOLD=1

mkdir -p "$3/admin" "$3/storage" "$3/ordinary"
run_scenario admin-decommission "$3/admin" admin -
run_scenario fresh-volume-replacement "$3/storage" storage fresh-volume-replacement-admin-deep
RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=1
RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=1
RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=stale-disk-return
run_scenario io-eio "$3/ordinary"
"#,
            "fault-qualification-environment-test",
            script,
            fake_binary.to_str().expect("fake binary path"),
            temporary.path().to_str().expect("temporary path"),
        ])
        .output()
        .expect("run qualification environment test");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let read_log = |root: &str, scenario: &str| {
        std::fs::read_to_string(temporary.path().join(root).join(scenario).join("test.log"))
            .expect("qualification test log")
    };
    let admin = read_log("admin", "admin-decommission");
    assert!(admin.contains("RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=1\n"));
    assert!(admin.contains("RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=\n"));
    assert!(admin.contains("RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=\n"));

    let storage = read_log("storage", "fresh-volume-replacement");
    assert!(storage.contains("RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=\n"));
    assert!(storage.contains("RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=1\n"));
    assert!(
        storage.contains(
            "RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=fresh-volume-replacement-admin-deep\n"
        )
    );

    let ordinary = read_log("ordinary", "io-eio");
    assert!(ordinary.contains("RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=\n"));
    assert!(ordinary.contains("RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=\n"));
    assert!(ordinary.contains("RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=\n"));
}

#[cfg(unix)]
#[test]
fn bitrot_qualification_preflight_uses_its_storage_helper_not_the_dm_observer() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let target = temporary.path().join("target.json");
    std::fs::write(
        &target,
        r#"{"volume":{"namespace":"fault-ns"},"helperPodName":"storage-helper"}"#,
    )
    .expect("bitrot target config");

    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
TEST_ROOT="$3"
require_command() { :; }
validate_runtime_env_contract() { :; }
validate_qualification_env_contract() { :; }
resolve_fault_context() { :; }
require_storage_class() { :; }
require_namespace_ownership() { :; }
require_non_fault_tenants_ready() { :; }
scenario_requires_chaos_mesh() { return 0; }
scenario_crds() { printf 'iochaos.chaos-mesh.org\n'; }
require_chaos_ready() { :; }
scenario_required_tools() { :; }
scenario_requires_static_storage() { return 0; }
validate_dm_env_contract() { touch "$TEST_ROOT/dm-preflight-used"; }
kubectl_ns() { printf '%s\n' "$*" >>"$TEST_ROOT/kubectl-ns.log"; }
kubectl_cluster() {
  if [[ "$*" == "get nodes -o json" ]]; then
    printf '%s\n' '{"items":[{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"DiskPressure","status":"False"}]}},{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"DiskPressure","status":"False"}]}},{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"DiskPressure","status":"False"}]}},{"status":{"conditions":[{"type":"Ready","status":"True"},{"type":"DiskPressure","status":"False"}]}}]}'
  elif [[ "$*" == *"jsonpath="* ]]; then
    printf 'privileged'
  else
    printf '{}\n'
  fi
}
QUALIFICATION_SCENARIO=on-disk-bitrot
QUALIFICATION_KIND=storage
QUALIFICATION_STORAGE_CASE=on-disk-bitrot-admin-deep
ACTIVE_QUALIFICATION_CASE=on-disk-bitrot-admin-deep
FAULT_CONTEXT=real-cluster
FAULT_NAMESPACE=fault-ns
RUSTFS_FAULT_TEST_SERVER_IMAGE=rustfs:test
RUSTFS_FAULT_TEST_STORAGE_CLASS=local-static
RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG="$2"
preflight on-disk-bitrot qualification on-disk-bitrot-admin-deep
[[ ! -e "$TEST_ROOT/dm-preflight-used" ]]
grep -Fx 'fault-ns get pod storage-helper' "$TEST_ROOT/kubectl-ns.log"
"#,
            "fault-qualification-bitrot-preflight-test",
            script,
            target.to_str().expect("target path"),
            temporary.path().to_str().expect("temporary path"),
        ])
        .output()
        .expect("run bitrot qualification preflight test");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(unix)]
#[test]
fn qualification_metadata_is_bound_to_its_run_root() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
FAULT_TEST_BINARY="$3"
write_qualification_plan "$2" fresh-volume-replacement-admin-deep fresh-volume-replacement storage fresh-volume-replacement-admin-deep
write_qualification_result "$2" passed 0
analyze_qualification "$2" >"$2/qualification-analysis.json"
mkdir "$2/requested"
write_qualification_request_plan "$2/requested" unknown-safe-case
write_qualification_result "$2/requested" failed 1
analyze_qualification "$2/requested" >"$2/requested/qualification-analysis.json"
"#,
            "fault-qualification-metadata-test",
            script,
            temporary.path().to_str().expect("temporary path"),
            env!("CARGO_BIN_EXE_s3chaos"),
        ])
        .output()
        .expect("write qualification metadata");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let plan = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(temporary.path().join("qualification-plan.json"))
            .expect("qualification plan"),
    )
    .expect("qualification plan JSON");
    assert_eq!(plan["schemaVersion"], 1);
    assert_eq!(plan["resolution"], "resolved");
    assert_eq!(
        plan["qualificationCase"],
        "fresh-volume-replacement-admin-deep"
    );
    assert_eq!(plan["scenario"], "fresh-volume-replacement");
    assert_eq!(plan["kind"], "storage");
    assert_eq!(
        plan["storageRecoveryCase"],
        "fresh-volume-replacement-admin-deep"
    );
    assert_eq!(
        plan["runRoot"],
        temporary.path().to_str().expect("temporary path")
    );
    assert_eq!(
        plan["artifactRoot"],
        temporary
            .path()
            .join("fresh-volume-replacement")
            .to_str()
            .expect("artifact root")
    );

    let result = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(temporary.path().join("qualification-result.json"))
            .expect("qualification result"),
    )
    .expect("qualification result JSON");
    assert_eq!(result["schemaVersion"], 1);
    assert_eq!(result["outcome"], "passed");
    assert_eq!(result["exitCode"], 0);

    let analysis = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(temporary.path().join("qualification-analysis.json"))
            .expect("qualification analysis"),
    )
    .expect("qualification analysis JSON");
    assert_eq!(analysis["qualificationPlan"], plan);
    assert_eq!(analysis["qualificationResult"], result);
    assert_eq!(analysis["console"]["attempts"], serde_json::json!([]));
    assert_eq!(analysis["schemaVersion"], 1);

    let requested_analysis = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(
            temporary
                .path()
                .join("requested/qualification-analysis.json"),
        )
        .expect("requested qualification analysis"),
    )
    .expect("requested qualification analysis JSON");
    assert_eq!(
        requested_analysis["qualificationPlan"]["resolution"],
        "requested"
    );
    assert_eq!(
        requested_analysis["qualificationResult"]["outcome"],
        "failed"
    );

    let contradictory = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
jq '.scenario = "on-disk-bitrot"' "$2/qualification-plan.json" >"$2/contradictory-plan.json"
mv "$2/contradictory-plan.json" "$2/qualification-plan.json"
s3chaos_cli() { printf '{}\n'; }
! (analyze_qualification "$2")
"#,
            "fault-qualification-contradictory-metadata-test",
            script,
            temporary.path().to_str().expect("temporary path"),
        ])
        .output()
        .expect("reject contradictory qualification metadata");
    assert!(
        contradictory.status.success(),
        "{}",
        String::from_utf8_lossy(&contradictory.stderr)
    );
}

#[cfg(unix)]
#[test]
fn unknown_qualification_case_leaves_analyzable_requested_plan() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let run_root = temporary.path().join("unknown-case");
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh");
    let output = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
FAULT_TEST_BINARY="$3"
build_fault_binary() { :; }
trap handle_exit EXIT
RUSTFS_FAULT_TEST_RUN_ROOT="$2"
run_qualification unknown-safe-case
"#,
            "fault-qualification-unknown-case-test",
            script,
            run_root.to_str().expect("run root"),
            env!("CARGO_BIN_EXE_s3chaos"),
        ])
        .output()
        .expect("reject unknown qualification case");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("unsupported qualification case: unknown-safe-case")
    );

    let analysis = Command::new("bash")
        .args([
            "-c",
            r#"
source "$1"
FAULT_TEST_BINARY="$3"
analyze_qualification "$2"
"#,
            "fault-qualification-unknown-case-analysis-test",
            script,
            run_root.to_str().expect("run root"),
            env!("CARGO_BIN_EXE_s3chaos"),
        ])
        .output()
        .expect("analyze rejected qualification case");
    assert!(
        analysis.status.success(),
        "{}",
        String::from_utf8_lossy(&analysis.stderr)
    );
    let analysis = serde_json::from_slice::<serde_json::Value>(&analysis.stdout)
        .expect("qualification analysis JSON");
    assert_eq!(
        analysis["qualificationPlan"]["qualificationCase"],
        "unknown-safe-case"
    );
    assert_eq!(analysis["qualificationPlan"]["resolution"], "requested");
    assert_eq!(analysis["qualificationResult"]["outcome"], "failed");
}

#[tokio::test]
#[ignore = "destructive RustFS workload fault scenario; select with RUSTFS_FAULT_TEST_SCENARIO"]
async fn fault_selected_scenario() -> Result<()> {
    s3chaos::fault::runner::run_selected_scenario_from_env().await
}

#[cfg(unix)]
#[test]
fn quorum_dm_wrapper_validates_exact_targets_and_protects_both_markers() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let targets = root.join("targets.json");
    let values: Vec<_> = ["a", "b"].iter().map(|id| serde_json::json!({
        "node": format!("node-{id}"), "mapperName": format!("dm-{id}"), "mountPath": format!("/data/{id}"),
        "persistentVolume": format!("pv-{id}"), "observerNamespace": "observers", "observerPod": format!("observer-{id}"),
        "stateFile": root.join(format!(".host-mutation-{id}.json")), "stateToken": id,
    })).collect();
    std::fs::write(
        &targets,
        serde_json::to_vec(&serde_json::json!({"targets":values})).unwrap(),
    )
    .unwrap();
    let output = Command::new("bash").args(["-c", r#"
source "$1"
export RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS="$2/targets.json"
export RUSTFS_FAULT_TEST_RUN_ROOT="$2"
export RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1
export RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST=node-a,node-b
export RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST=/dev/mapper/dm-a,/dev/mapper/dm-b
export RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST=pv-a,pv-b
validate_dm_env_contract quorum-p-dm-eio
[[ "${#ACTIVE_QUORUM_DM_STATE_FILES[@]}" == 2 ]]
for index in 0 1; do
  file="${ACTIVE_QUORUM_DM_STATE_FILES[$index]}"
  token="${ACTIVE_QUORUM_DM_STATE_TOKENS[$index]}"
  jq -n --arg token "$token" '{schemaVersion:1,token:$token,ownerPid:222,phase:"active"}' >"$file"
  host_storage_mutation_active 111 "" "" || exit 21
  probes=0 signals=""
  process_group_alive() { probes=$((probes + 1)); (( probes <= 2 )); }
  capture_process_group() { :; }
  signal_process_group() { signals="$signals $3"; }
  sleep() { :; }
  terminate_process_group 111 111 "" "" "$2" 0
  [[ "$signals" == " TERM" ]] || exit 27
  printf '{' >"$file"
  host_storage_mutation_active 111 "" "" || exit 22
  jq -n '{schemaVersion:1,token:"foreign",ownerPid:222,phase:"rollback"}' >"$file"
  host_storage_mutation_active 111 "" "" || exit 23
  rm "$file"
done
host_storage_mutation_active 111 "" "" && exit 24
( RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST=node-a,node-b,node-c; validate_dm_env_contract quorum-p-dm-eio ) && exit 25
jq '.targets[1].stateToken="a"' "$2/targets.json" >"$2/duplicate.json"
( RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS="$2/duplicate.json"; validate_dm_env_contract quorum-p-dm-eio ) && exit 26
printf 'validated-and-protected\n'
"#, "qdm-wrapper-test", concat!(env!("CARGO_MANIFEST_DIR"), "/scripts/fault-test.sh"), root.to_str().unwrap()]).output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "validated-and-protected\n"
    );
}
