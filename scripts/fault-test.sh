#!/usr/bin/env bash
# Copyright 2025 RustFS Team
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PACKAGE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MANIFEST="$PACKAGE_DIR/Cargo.toml"
MANAGER="s3chaos"
MANAGER_SELECTOR="app.kubernetes.io/managed-by=$MANAGER"
WORKLOAD_OBJECTS="${RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS:-40000}"
WORKLOAD_CONCURRENCY="${RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY:-80}"
RUSTFS_POD_COUNT="${RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT:-4}"
RUSTFS_VOLUME_PATH="${RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH:-/data/rustfs0}"
RUSTFS_POD_STABLE_WINDOW_SECONDS="${RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS:-60}"
HEALTH_GUARD_FAILURE_THRESHOLD="${RUSTFS_FAULT_TEST_HEALTH_GUARD_FAILURE_THRESHOLD:-1}"
PROCESS_TERMINATION_GRACE_SECONDS="${RUSTFS_FAULT_TEST_PROCESS_TERMINATION_GRACE_SECONDS:-60}"
BUILD_JOBS="${RUSTFS_FAULT_TEST_BUILD_JOBS:-}"
CHAOS_MESH_VERSION="${RUSTFS_FAULT_TEST_CHAOS_MESH_VERSION:-2.8.3}"
CHAOS_DAEMON_RUNTIME="${RUSTFS_FAULT_TEST_CHAOS_DAEMON_RUNTIME:-containerd}"
CHAOS_DAEMON_SOCKET_PATH="${RUSTFS_FAULT_TEST_CHAOS_DAEMON_SOCKET_PATH:-/run/k3s/containerd/containerd.sock}"
CHAOS_DASHBOARD_PORT="${RUSTFS_FAULT_TEST_CHAOS_DASHBOARD_PORT:-2333}"

FAULT_CONTEXT="${RUSTFS_FAULT_TEST_EXPECTED_CONTEXT:-}"
FAULT_NAMESPACE="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
FAULT_TENANT="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
CHAOS_NAMESPACE="${RUSTFS_FAULT_TEST_CHAOS_NAMESPACE:-chaos-mesh}"
OPERATOR_NAMESPACE="${RUSTFS_FAULT_TEST_OPERATOR_NAMESPACE:-rustfs-system}"
OPERATOR_PAUSE_REPLICAS_ANNOTATION="s3chaos.rustfs.com/operator-paused-replicas"
OPERATOR_PAUSE_RUN_ANNOTATION="s3chaos.rustfs.com/operator-paused-run"
NAMESPACE_DELETE_TIMEOUT="${RUSTFS_FAULT_TEST_NAMESPACE_DELETE_TIMEOUT:-600s}"
ACTIVE_PID=""
ACTIVE_PROCESS_GROUP=""
ACTIVE_ARTIFACTS=""
ACTIVE_SCOPE=""
ACTIVE_NAME=""
ACTIVE_HOST_MUTATION_STATE_FILE=""
ACTIVE_HOST_MUTATION_STATE_TOKEN=""
ACTIVE_QUALIFICATION_ROOT=""
ACTIVE_QUALIFICATION_CASE=""
FAULT_TEST_BINARY=""
FAULT_CATALOG_JSON=""
FAULT_QUALIFICATION_CATALOG_JSON=""

usage() {
  cat <<'EOF'
Usage: fault-test.sh <command> [scenario]

Commands:
  preflight [scenario]  Validate the current real-cluster environment.
  run <scenario>        Run one non-DM scenario with health guards.
  chaos-plan <file>     Plan an ordinary Chaos Mesh-only suite.
  chaos-run <file>      Run an ordinary Chaos Mesh-only suite.
  dm-run <scenario>     Run exactly one supervised device-mapper scenario.
  list                  List catalog scenarios.
  qualify-list          List closed planned-qualification cases.
  qualify <case>        Run one supervised planned qualification.
  qualify-analyze <run-root>
                        Render machine-readable analysis for one qualification.
  suite-template        Print a YAML FaultSuite template.
  suite-validate <file> Validate a YAML FaultSuite contract.
  suite-plan <file>     Render the resolved destructive FaultSuite plan.
  suite-run <file>      Run a non-static YAML FaultSuite sequentially.
  dashboard-install     Install/upgrade Chaos Mesh with Dashboard enabled.
  dashboard-port-forward [port]
                        Port-forward the Chaos Mesh Dashboard locally.
  cleanup               Remove managed Chaos and the owned fault namespace.

RUSTFS_FAULT_TEST_EXPECTED_CONTEXT is optional for ordinary runs. Planned
qualification requires an explicit expected context, namespace, and Tenant.
RUSTFS_FAULT_TEST_PROCESS_TERMINATION_GRACE_SECONDS controls the graceful
shutdown window before non-storage runs are escalated to SIGKILL (default: 60).
EOF
}

die() {
  echo "fault-test: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

trim_value() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

require_nonempty_env() {
  local name="$1" value
  value="$(trim_value "${!name:-}")"
  [[ -n "$value" ]] || die "$name is required"
  export "$name=$value"
}

require_positive_integer() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || die "$name must be a positive integer"
}

require_unsigned_integer() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[0-9]+$ ]] || die "$name must be an unsigned integer"
}

require_optional_unsigned_integer() {
  local name="$1" value
  value="$(trim_value "${!name:-}")"
  [[ -z "$value" ]] && return 0
  require_unsigned_integer "$name" "$value"
  export "$name=$value"
}

require_optional_positive_integer() {
  local name="$1" value
  value="$(trim_value "${!name:-}")"
  [[ -z "$value" ]] && return 0
  require_positive_integer "$name" "$value"
  export "$name=$value"
}

require_optional_bool() {
  local name="$1" value
  value="$(trim_value "${!name:-}")"
  [[ -z "$value" ]] && return 0
  case "$value" in
    1|0|[Tt][Rr][Uu][Ee]|[Ff][Aa][Ll][Ss][Ee]|[Yy][Ee][Ss]|[Nn][Oo])
      export "$name=$value"
      ;;
    *)
      die "$name must be a boolean: 1/0, true/false, or yes/no"
      ;;
  esac
}

require_safe_node_name() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[A-Za-z0-9.-]+$ ]] || die "$name must be a valid node name"
}

require_safe_dm_name() {
  local name="$1" value="$2"
  [[ "$value" =~ ^[A-Za-z0-9._+-]+$ ]] || die "$name contains unsupported characters"
}

require_absolute_non_root_path() {
  local name="$1" value="$2"
  [[ "$value" == /* && "$value" != "/" ]] || die "$name must be an absolute non-root path"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || die "$name must not contain newlines"
  [[ "$value" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "$name must contain only ASCII letters, digits, '/', '.', '_', or '-'"
}

require_safe_image_ref() {
  local name="$1" value="$2"
  [[ -n "$value" ]] || die "$name must be a non-empty image reference"
  [[ "$value" != *[[:space:]]* ]] || die "$name must not contain whitespace"
}

kubectl_context() {
  kubectl config current-context
}

ensure_inherited_kubeconfig() {
  local default_config home_config
  [[ -n "${KUBECONFIG:-}" ]] && return 0
  home_config="${HOME:-}/.kube/config"
  [[ -r "$home_config" ]] && return 0
  for default_config in /etc/rancher/k3s/k3s.yaml; do
    if [[ -r "$default_config" ]]; then
      export KUBECONFIG="$default_config"
      return 0
    fi
  done
}

resolve_fault_context() {
  local current_context
  ensure_inherited_kubeconfig
  FAULT_CONTEXT="$(trim_value "$FAULT_CONTEXT")"
  current_context="$(kubectl_context)"
  if [[ -n "$FAULT_CONTEXT" ]]; then
    [[ "$current_context" == "$FAULT_CONTEXT" ]] || die "current context $current_context does not match RUSTFS_FAULT_TEST_EXPECTED_CONTEXT $FAULT_CONTEXT"
    export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT="$FAULT_CONTEXT"
  else
    FAULT_CONTEXT="$current_context"
    export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT="$FAULT_CONTEXT"
  fi
  [[ "$FAULT_CONTEXT" != kind-* ]] || die "fault tests require a real Kubernetes or K3s cluster, got $FAULT_CONTEXT"
}

kubectl_ns() {
  kubectl --context "$FAULT_CONTEXT" -n "$1" "${@:2}"
}

kubectl_cluster() {
  kubectl --context "$FAULT_CONTEXT" "$@"
}

fault_catalog_json() {
  require_command cargo
  require_command jq
  if [[ -z "$FAULT_CATALOG_JSON" ]]; then
    FAULT_CATALOG_JSON="$(s3chaos_cli fault-catalog-json)"
  fi
  printf '%s\n' "$FAULT_CATALOG_JSON"
}

s3chaos_cli() {
  if [[ -n "$FAULT_TEST_BINARY" && -x "$FAULT_TEST_BINARY" ]]; then
    "$FAULT_TEST_BINARY" "$@"
  elif [[ -n "$BUILD_JOBS" ]]; then
    CARGO_BUILD_JOBS="$BUILD_JOBS" cargo run --quiet --manifest-path "$MANIFEST" --bin s3chaos -- "$@"
  else
    cargo run --quiet --manifest-path "$MANIFEST" --bin s3chaos -- "$@"
  fi
}

catalog_scenario_query() {
  local scenario="$1"
  shift
  fault_catalog_json | jq -e --arg scenario "$scenario" "$@"
}

is_supported_scenario() {
  catalog_scenario_query "$1" 'any(.[]; .scenario == $scenario and .status == "executable")' >/dev/null
}

require_supported_scenario() {
  local scenario="$1"
  is_supported_scenario "$scenario" || die "unsupported scenario: $scenario"
}

is_planned_scenario() {
  catalog_scenario_query "$1" 'any(.[]; .scenario == $scenario and .status == "planned")' >/dev/null
}

qualification_catalog_json() {
  if [[ -z "$FAULT_QUALIFICATION_CATALOG_JSON" ]]; then
    FAULT_QUALIFICATION_CATALOG_JSON="$(s3chaos_cli fault-qualification-catalog-json)"
  fi
  printf '%s\n' "$FAULT_QUALIFICATION_CATALOG_JSON"
}

qualification_cases() {
  qualification_catalog_json | jq -r '.[].qualificationCase'
}

qualification_case_contract() {
  qualification_catalog_json | jq -er --arg qualification_case "$1" '
    .[]
    | select(.qualificationCase == $qualification_case)
    | [.scenario, .kind, (.storageRecoveryCase // "-")]
    | @tsv
  '
}

list_qualification_cases() {
  local qualification_case contract scenario kind storage_case
  printf 'qualification-case\tscenario\tkind\tstorage-recovery-case\n'
  while IFS= read -r qualification_case; do
    contract="$(qualification_case_contract "$qualification_case")"
    IFS=$'\t' read -r scenario kind storage_case <<<"$contract"
    printf '%s\t%s\t%s\t%s\n' "$qualification_case" "$scenario" "$kind" "$storage_case"
  done < <(qualification_cases)
}

resolve_qualification_case() {
  local qualification_case="$1" contract
  if ! contract="$(qualification_case_contract "$qualification_case")"; then
    die "unsupported qualification case: $qualification_case; run make fault-qualify-list"
  fi
  IFS=$'\t' read -r QUALIFICATION_SCENARIO QUALIFICATION_KIND QUALIFICATION_STORAGE_CASE <<<"$contract"
}

scenario_percent_supported() {
  catalog_scenario_query "$1" '.[] | select(.scenario == $scenario) | .percent_supported' >/dev/null
}

scenario_requires_static_storage() {
  catalog_scenario_query "$1" '.[] | select(.scenario == $scenario) | .isolation == "dedicated-linux-block-device"' >/dev/null
}

require_dm_scenario() {
  local scenario="$1"
  require_supported_scenario "$scenario"
  scenario_requires_static_storage "$scenario" \
    || die "$scenario is not a device-mapper scenario; use fault-chaos-run for ordinary Chaos Mesh or fault-suite-run for Warp"
}

require_non_dm_scenario() {
  local scenario="$1"
  require_supported_scenario "$scenario"
  ! scenario_requires_static_storage "$scenario" \
    || die "$scenario is a device-mapper scenario; run it in the foreground with make fault-dm-run SCENARIO=$scenario"
}

scenario_crds() {
  local scenario="$1"
  fault_catalog_json | jq -r --arg scenario "$scenario" '.[] | select(.scenario == $scenario) | .crds[]?'
}

# Chaos Mesh is only a requirement for scenarios that render one of its CRDs;
# kubectl-driven lifecycle scenarios and host device-mapper scenarios run
# without it.
scenario_requires_chaos_mesh() {
  catalog_scenario_query "$1" '.[] | select(.scenario == $scenario) | (.crds | length) > 0' >/dev/null
}

scenario_required_tools() {
  local scenario="$1"
  fault_catalog_json | jq -r --arg scenario "$scenario" '.[] | select(.scenario == $scenario) | .required_tools[]?'
}

validate_runtime_env_contract() {
  local scenario="$1" percent timeout_seconds

  WORKLOAD_OBJECTS="$(trim_value "$WORKLOAD_OBJECTS")"
  WORKLOAD_CONCURRENCY="$(trim_value "$WORKLOAD_CONCURRENCY")"
  RUSTFS_POD_COUNT="$(trim_value "$RUSTFS_POD_COUNT")"
  RUSTFS_VOLUME_PATH="$(trim_value "$RUSTFS_VOLUME_PATH")"
  RUSTFS_POD_STABLE_WINDOW_SECONDS="$(trim_value "$RUSTFS_POD_STABLE_WINDOW_SECONDS")"
  HEALTH_GUARD_FAILURE_THRESHOLD="$(trim_value "$HEALTH_GUARD_FAILURE_THRESHOLD")"
  PROCESS_TERMINATION_GRACE_SECONDS="$(trim_value "$PROCESS_TERMINATION_GRACE_SECONDS")"
  BUILD_JOBS="$(trim_value "$BUILD_JOBS")"

  require_positive_integer RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS "$WORKLOAD_OBJECTS"
  (( 10#$WORKLOAD_OBJECTS >= 12 )) || die "RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS must be at least 12"
  require_positive_integer RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY "$WORKLOAD_CONCURRENCY"
  (( 10#$WORKLOAD_CONCURRENCY <= 10#$WORKLOAD_OBJECTS )) || die "RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY must be <= RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS"
  require_positive_integer RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT "$RUSTFS_POD_COUNT"
  require_absolute_non_root_path RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH "$RUSTFS_VOLUME_PATH"
  require_positive_integer RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS "$RUSTFS_POD_STABLE_WINDOW_SECONDS"
  require_positive_integer RUSTFS_FAULT_TEST_HEALTH_GUARD_FAILURE_THRESHOLD "$HEALTH_GUARD_FAILURE_THRESHOLD"
  require_positive_integer RUSTFS_FAULT_TEST_PROCESS_TERMINATION_GRACE_SECONDS "$PROCESS_TERMINATION_GRACE_SECONDS"
  if [[ -n "$BUILD_JOBS" ]]; then
    require_positive_integer RUSTFS_FAULT_TEST_BUILD_JOBS "$BUILD_JOBS"
  fi
  timeout_seconds="$(trim_value "${RUSTFS_FAULT_TEST_TIMEOUT_SECONDS:-300}")"
  require_unsigned_integer RUSTFS_FAULT_TEST_TIMEOUT_SECONDS "$timeout_seconds"
  (( 10#$RUSTFS_POD_STABLE_WINDOW_SECONDS < 10#$timeout_seconds )) || die "RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS must be less than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS"
  export RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT="$RUSTFS_POD_COUNT"
  export RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH="$RUSTFS_VOLUME_PATH"
  export RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS="$RUSTFS_POD_STABLE_WINDOW_SECONDS"
  export RUSTFS_FAULT_TEST_HEALTH_GUARD_FAILURE_THRESHOLD="$HEALTH_GUARD_FAILURE_THRESHOLD"
  export RUSTFS_FAULT_TEST_PROCESS_TERMINATION_GRACE_SECONDS="$PROCESS_TERMINATION_GRACE_SECONDS"
  require_optional_positive_integer RUSTFS_FAULT_TEST_DURATION_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_REQUEST_TIMEOUT_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_TIMEOUT_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_WARP_DURATION_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_SEED
  require_optional_bool RUSTFS_FAULT_TEST_USE_CLUSTER_IP
  require_optional_bool RUSTFS_FAULT_TEST_REQUIRE_CLIENT_DISRUPTION
  require_optional_bool RUSTFS_FAULT_TEST_WORKLOAD_VERSIONING

  percent="$(trim_value "${RUSTFS_FAULT_TEST_PERCENT:-}")"
  if [[ -n "$percent" ]]; then
    require_positive_integer RUSTFS_FAULT_TEST_PERCENT "$percent"
    (( 10#$percent <= 100 )) || die "RUSTFS_FAULT_TEST_PERCENT must be in 1..=100"
    scenario_percent_supported "$scenario" || die "RUSTFS_FAULT_TEST_PERCENT does not apply to scenario $scenario"
    export RUSTFS_FAULT_TEST_PERCENT="$percent"
  fi
}

validate_qualification_env_contract() {
  local qualification_case="$1" scenario="$2" kind="$3" storage_case="$4"
  local expected_local_pvs target_config

  require_nonempty_env RUSTFS_FAULT_TEST_EXPECTED_CONTEXT
  require_nonempty_env RUSTFS_FAULT_TEST_NAMESPACE
  require_nonempty_env RUSTFS_FAULT_TEST_TENANT
  FAULT_CONTEXT="$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT"
  FAULT_NAMESPACE="$RUSTFS_FAULT_TEST_NAMESPACE"
  FAULT_TENANT="$RUSTFS_FAULT_TEST_TENANT"

  case "$kind" in
    admin)
      [[ "$storage_case" == "-" ]] || die "$qualification_case has an unexpected storage-recovery case"
      ;;
    storage)
      [[ "$storage_case" != "-" ]] || die "$qualification_case lacks its storage-recovery case"
      case "$scenario" in
        fresh-volume-replacement)
          require_nonempty_env RUSTFS_FAULT_TEST_STATIC_LOCAL_PVS_JSON
          require_nonempty_env RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE
          require_nonempty_env RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT
          require_nonempty_env RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST
          require_nonempty_env RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST
          require_safe_image_ref RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE "$RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE"
          require_safe_node_name RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT "$RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT"
          expected_local_pvs=$((10#$RUSTFS_POD_COUNT + 1))
          jq -e --argjson expected "$expected_local_pvs" \
            'type == "array" and length == $expected' \
            <<<"$RUSTFS_FAULT_TEST_STATIC_LOCAL_PVS_JSON" >/dev/null \
            || die "RUSTFS_FAULT_TEST_STATIC_LOCAL_PVS_JSON must contain exactly $expected_local_pvs Local PV entries"
          ;;
        on-disk-bitrot)
          require_nonempty_env RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG
          target_config="$RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG"
          require_absolute_non_root_path RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG "$target_config"
          [[ -f "$target_config" && ! -L "$target_config" ]] \
            || die "RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG must be a regular non-symlink file"
          ;;
        stale-disk-return-detect)
          ;;
        *)
          die "unsupported planned storage scenario: $scenario"
          ;;
      esac
      ;;
    *)
      die "unsupported qualification kind: $kind"
      ;;
  esac
}

validate_dm_env_contract() {
  local scenario="$1"
  local dm_opt_in
  require_nonempty_env RUSTFS_FAULT_TEST_DM_NAME
  require_nonempty_env RUSTFS_FAULT_TEST_DM_NODE
  require_nonempty_env RUSTFS_FAULT_TEST_DM_MOUNT_PATH
  require_nonempty_env RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE
  require_nonempty_env RUSTFS_FAULT_TEST_DM_OBSERVER_POD
  require_nonempty_env RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE
  require_nonempty_env RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST
  require_nonempty_env RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST
  require_nonempty_env RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST
  if [[ "$scenario" == "dm-flakey" ]]; then
    require_nonempty_env RUSTFS_FAULT_TEST_DM_FAULT_TABLE
  fi

  require_safe_dm_name RUSTFS_FAULT_TEST_DM_NAME "$RUSTFS_FAULT_TEST_DM_NAME"
  require_safe_node_name RUSTFS_FAULT_TEST_DM_NODE "$RUSTFS_FAULT_TEST_DM_NODE"
  require_safe_node_name RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE "$RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE"
  require_safe_node_name RUSTFS_FAULT_TEST_DM_OBSERVER_POD "$RUSTFS_FAULT_TEST_DM_OBSERVER_POD"
  require_absolute_non_root_path RUSTFS_FAULT_TEST_DM_MOUNT_PATH "$RUSTFS_FAULT_TEST_DM_MOUNT_PATH"
  require_absolute_non_root_path RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST "$RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST"
  require_safe_node_name RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST "$RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST"
  require_safe_image_ref RUSTFS_FAULT_TEST_DM_HELPER_IMAGE "${RUSTFS_FAULT_TEST_DM_HELPER_IMAGE:-rancher/mirrored-library-busybox:1.37.0}"

  dm_opt_in="$(printf '%s' "$RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE" | tr '[:upper:]' '[:lower:]')"
  [[ "$dm_opt_in" == "1" || "$dm_opt_in" == "true" || "$dm_opt_in" == "yes" ]] \
    || die "RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE must explicitly enable device-mapper mutation"
  [[ "$RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST" == "$RUSTFS_FAULT_TEST_DM_NODE" ]] \
    || die "RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST must exactly match RUSTFS_FAULT_TEST_DM_NODE"
  [[ "$RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST" == "/dev/mapper/$RUSTFS_FAULT_TEST_DM_NAME" ]] \
    || die "RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST must exactly match /dev/mapper/$RUSTFS_FAULT_TEST_DM_NAME"
  [[ "$RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE" != "$FAULT_NAMESPACE" ]] \
    || die "the read-only DM observer must be outside the disposable fault Tenant namespace"
}

require_namespace_ownership() {
  if ! kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1; then
    return 0
  fi

  local manager tenant
  manager="$(kubectl_cluster get namespace "$FAULT_NAMESPACE" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/managed-by}')"
  tenant="$(kubectl_cluster get namespace "$FAULT_NAMESPACE" -o jsonpath='{.metadata.annotations.rustfs\.com/fault-test-tenant}')"
  [[ "$manager" == "$MANAGER" ]] || die "namespace $FAULT_NAMESPACE is not managed by $MANAGER"
  [[ "$tenant" == "$FAULT_TENANT" ]] || die "namespace $FAULT_NAMESPACE is not owned by tenant $FAULT_TENANT"
}

list_non_fault_tenants() {
  kubectl_cluster get tenants -A -o json | jq -r --arg namespace "$FAULT_NAMESPACE" '
    .items[]
    | select(.metadata.namespace != $namespace)
    | [.metadata.namespace, .metadata.name]
    | @tsv
  '
}

tenant_current_state() {
  local namespace="$1" tenant="$2"
  kubectl_ns "$namespace" get tenant "$tenant" -o jsonpath='{.status.currentState}' 2>/dev/null || true
}

require_non_fault_tenants_ready() {
  local namespace tenant state
  while IFS=$'\t' read -r namespace tenant; do
    [[ -n "$namespace" ]] || continue
    state="$(tenant_current_state "$namespace" "$tenant")"
    [[ "$state" == "Ready" ]] || die "pre-existing Tenant $namespace/$tenant is not Ready: ${state:-missing}"
  done < <(list_non_fault_tenants)
}

non_fault_tenants_are_ready() {
  local baseline_tenants="$1"
  local namespace tenant state
  while IFS=$'\t' read -r namespace tenant; do
    [[ -n "$namespace" ]] || continue
    state="$(tenant_current_state "$namespace" "$tenant")"
    [[ "$state" == "Ready" ]] || return 1
  done <"$baseline_tenants"
  return 0
}

build_fault_binary() {
  local run_root="$1" label="$2"
  local build_messages="$run_root/fault-build.jsonl"
  local build_jobs_label="auto"
  local -a build_command=(
    cargo build --manifest-path "$MANIFEST" --bin s3chaos
    --message-format=json-render-diagnostics
  )

  BUILD_JOBS="$(trim_value "$BUILD_JOBS")"
  if [[ -n "$BUILD_JOBS" ]]; then
    require_positive_integer RUSTFS_FAULT_TEST_BUILD_JOBS "$BUILD_JOBS"
    build_jobs_label="$BUILD_JOBS"
    build_command=(env "CARGO_BUILD_JOBS=$BUILD_JOBS" "${build_command[@]}")
  fi
  mkdir -p "$run_root"
  echo "preparing s3chaos binary for $label with jobs=$build_jobs_label and lowest host priority"
  if command -v ionice >/dev/null 2>&1; then
    nice -n 19 ionice -c3 "${build_command[@]}" \
      >"$build_messages" 2>"$run_root/fault-build.log"
  else
    nice -n 19 "${build_command[@]}" \
      >"$build_messages" 2>"$run_root/fault-build.log"
  fi
  FAULT_TEST_BINARY="$(jq -r '
    select(
      .reason == "compiler-artifact"
      and .target.name == "s3chaos"
      and (.target.kind | index("bin"))
    )
    | .executable // empty
  ' "$build_messages" | tail -n 1)"
  [[ -x "$FAULT_TEST_BINARY" ]] || die "s3chaos fault-run binary was not produced; see $run_root/fault-build.log"
  printf '%s\n' "$FAULT_TEST_BINARY" >"$run_root/fault-test-binary.path"
}

chaos_deployment_ready() {
  kubectl_ns "$CHAOS_NAMESPACE" get deployment chaos-controller-manager -o json | jq -r '
    (.status.readyReplicas // 0) == (.spec.replicas // 0) and (.spec.replicas // 0) > 0
  '
}

chaos_daemon_ready() {
  kubectl_ns "$CHAOS_NAMESPACE" get daemonset chaos-daemon -o json | jq -r '
    (.status.numberReady // 0) == (.status.desiredNumberScheduled // 0) and (.status.desiredNumberScheduled // 0) > 0
  '
}

chaos_is_ready() {
  local deployment_ready daemon_ready
  deployment_ready="$(chaos_deployment_ready 2>/dev/null)" || return 1
  daemon_ready="$(chaos_daemon_ready 2>/dev/null)" || return 1
  [[ "$deployment_ready" == "true" && "$daemon_ready" == "true" ]]
}

require_chaos_ready() {
  local deployment_ready daemon_ready
  deployment_ready="$(chaos_deployment_ready)"
  daemon_ready="$(chaos_daemon_ready)"
  [[ "$deployment_ready" == "true" ]] || die "Chaos Mesh controller-manager is not fully Ready"
  [[ "$daemon_ready" == "true" ]] || die "Chaos Mesh chaos-daemon is not fully Ready"
}

install_chaos_dashboard() {
  require_command helm
  require_command kubectl
  resolve_fault_context

  helm repo add chaos-mesh https://charts.chaos-mesh.org >/dev/null 2>&1 \
    || helm repo add chaos-mesh https://charts.chaos-mesh.org --force-update >/dev/null
  helm repo update chaos-mesh >/dev/null
  helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh \
    -n "$CHAOS_NAMESPACE" --create-namespace --version "$CHAOS_MESH_VERSION" \
    --set "chaosDaemon.runtime=$CHAOS_DAEMON_RUNTIME" \
    --set "chaosDaemon.socketPath=$CHAOS_DAEMON_SOCKET_PATH" \
    --set dashboard.create=true \
    --set dashboard.securityMode=true \
    --set dashboard.service.type=ClusterIP \
    --wait --timeout 10m

  kubectl_ns "$CHAOS_NAMESPACE" rollout status deployment/chaos-dashboard --timeout=120s
  kubectl_ns "$CHAOS_NAMESPACE" get service chaos-dashboard
  echo "Chaos Mesh Dashboard is installed in namespace $CHAOS_NAMESPACE with securityMode=true"
  echo "Run: $0 dashboard-port-forward ${CHAOS_DASHBOARD_PORT}"
}

port_forward_chaos_dashboard() {
  local port="${1:-$CHAOS_DASHBOARD_PORT}"
  require_command kubectl
  require_positive_integer RUSTFS_FAULT_TEST_CHAOS_DASHBOARD_PORT "$port"
  resolve_fault_context
  kubectl_ns "$CHAOS_NAMESPACE" get service chaos-dashboard >/dev/null \
    || die "Chaos Mesh Dashboard service chaos-dashboard was not found in namespace $CHAOS_NAMESPACE"

  echo "Chaos Mesh Dashboard: http://127.0.0.1:$port"
  echo "Authentication remains controlled by Chaos Mesh Dashboard RBAC/securityMode."
  echo "Press Ctrl-C to stop the port-forward."
  kubectl_ns "$CHAOS_NAMESPACE" port-forward service/chaos-dashboard "$port:2333"
}

require_storage_class() {
  local scenario="$1" qualification_case="${2:-}"
  local storage_class provisioner pv_count
  require_nonempty_env RUSTFS_FAULT_TEST_STORAGE_CLASS
  storage_class="$RUSTFS_FAULT_TEST_STORAGE_CLASS"
  provisioner="$(kubectl_cluster get storageclass "$storage_class" -o json | jq -r '.provisioner // ""')"
  [[ -n "$provisioner" ]] || die "StorageClass $storage_class has no provisioner"

  if [[ "$qualification_case" == fresh-volume-replacement-* ]]; then
    [[ "$provisioner" == "kubernetes.io/no-provisioner" ]] || die "$qualification_case requires a no-provisioner StorageClass"
  elif scenario_requires_static_storage "$scenario"; then
    [[ "$provisioner" == "kubernetes.io/no-provisioner" ]] || die "$scenario requires a no-provisioner StorageClass"
    pv_count="$(kubectl_cluster get pv -o json | jq -r --arg storage_class "$storage_class" '
      [.items[]
        | select(.spec.storageClassName == $storage_class)
        | select(.status.phase == "Available" or .status.phase == "Bound")
        | select(.spec.capacity.storage == "100Gi")]
      | length
    ')"
    [[ "$pv_count" -eq 4 ]] || die "$scenario requires exactly four Available/Bound 100Gi PVs, found $pv_count"
  else
    [[ "$provisioner" != "kubernetes.io/no-provisioner" ]] || die "non-static scenarios require dynamic provisioning"
  fi
}

preflight() {
  local scenario="${1:-io-eio}"
  local mode="${2:-executable}" qualification_case="${3:-}"
  local ready_nodes crd tool target_config target_namespace target_helper_pod
  local disk_pressure_nodes
  if [[ "$mode" == "qualification" ]]; then
    [[ "$scenario" == "$QUALIFICATION_SCENARIO" && "$qualification_case" == "$ACTIVE_QUALIFICATION_CASE" ]] \
      || die "qualification preflight is not bound to the resolved case"
  else
    [[ "$mode" == "executable" && -z "$qualification_case" ]] || die "unsupported preflight mode: $mode"
    require_supported_scenario "$scenario"
  fi

  require_command cargo
  require_command jq
  require_command kubectl
  require_command nice
  require_command ps
  require_command awk
  require_command setsid
  validate_runtime_env_contract "$scenario"
  if [[ "$mode" == "qualification" ]]; then
    validate_qualification_env_contract \
      "$qualification_case" "$scenario" "$QUALIFICATION_KIND" "$QUALIFICATION_STORAGE_CASE"
  fi
  require_nonempty_env RUSTFS_FAULT_TEST_SERVER_IMAGE

  resolve_fault_context

  kubectl_cluster get crd tenants.rustfs.com >/dev/null
  ready_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[]
    | select(.spec.unschedulable != true)
    | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
  min_nodes="$(resolve_min_ready_nodes)"
  [[ "$min_nodes" =~ ^[0-9]+$ && "$min_nodes" -ge 1 ]] || die "RUSTFS_FAULT_TEST_MIN_NODES must be a positive integer, got $min_nodes"
  [[ "$ready_nodes" -ge "$min_nodes" ]] || die "at least $min_nodes schedulable Ready node(s) are required, found $ready_nodes"
  disk_pressure_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[]
    | select(any(.status.conditions[]; .type == "DiskPressure" and .status == "True"))
    | .metadata.name] | join(",")')"
  [[ -z "$disk_pressure_nodes" ]] || die "node DiskPressure present before fault test: $disk_pressure_nodes"

  require_storage_class "$scenario" "$qualification_case"
  require_namespace_ownership
  require_non_fault_tenants_ready

  if scenario_requires_chaos_mesh "$scenario"; then
    for crd in $(scenario_crds "$scenario"); do
      kubectl_cluster get crd "$crd" >/dev/null
    done
    require_chaos_ready
  fi
  for tool in $(scenario_required_tools "$scenario"); do
    require_command "$tool"
  done
  if [[ "$scenario" == "on-disk-bitrot" && "$mode" == "qualification" ]]; then
    target_config="$RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG"
    target_namespace="$(jq -er '.volume.namespace | strings | select(length > 0)' "$target_config")" \
      || die "bitrot target config lacks volume.namespace"
    target_helper_pod="$(jq -er '.helperPodName | strings | select(length > 0)' "$target_config")" \
      || die "bitrot target config lacks helperPodName"
    [[ "$target_namespace" == "$FAULT_NAMESPACE" ]] \
      || die "bitrot target config belongs to another namespace: $target_namespace"
    kubectl_ns "$target_namespace" get pod "$target_helper_pod" >/dev/null \
      || die "on-disk-bitrot requires its configured storage helper Pod"
    kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1 \
      || die "on-disk-bitrot requires a pre-created owned fault namespace with privileged Pod Security"
    [[ "$(kubectl_cluster get namespace "$FAULT_NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" == "privileged" ]] \
      || die "on-disk-bitrot requires pod-security.kubernetes.io/enforce=privileged on $FAULT_NAMESPACE"
  elif scenario_requires_static_storage "$scenario"; then
    validate_dm_env_contract "$scenario"
    kubectl_cluster -n "$RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE" \
      get pod "$RUSTFS_FAULT_TEST_DM_OBSERVER_POD" >/dev/null \
      || die "$scenario requires the configured pre-provisioned host observer Pod"
    kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1 || die "$scenario requires a pre-created owned fault namespace with privileged Pod Security"
    [[ "$(kubectl_cluster get namespace "$FAULT_NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" == "privileged" ]] || die "$scenario requires pod-security.kubernetes.io/enforce=privileged on $FAULT_NAMESPACE"
  elif [[ "$qualification_case" == fresh-volume-replacement-* ]]; then
    kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1 \
      || die "$qualification_case requires a pre-created owned fault namespace with privileged Pod Security"
    [[ "$(kubectl_cluster get namespace "$FAULT_NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" == "privileged" ]] \
      || die "$qualification_case requires pod-security.kubernetes.io/enforce=privileged on $FAULT_NAMESPACE"
  fi

  echo "preflight passed: context=$FAULT_CONTEXT scenario=$scenario nodes=$ready_nodes storageClass=${RUSTFS_FAULT_TEST_STORAGE_CLASS} objects=$WORKLOAD_OBJECTS concurrency=$WORKLOAD_CONCURRENCY pods=$RUSTFS_POD_COUNT volume=$RUSTFS_VOLUME_PATH"
}

preflight_cleanup() {
  require_command jq
  require_command kubectl
  resolve_fault_context
  require_namespace_ownership
}

# Four nodes when the tenant must spread. One node is enough when pods may
# colocate: a single-node k3s/OrbStack/kind cluster otherwise cannot run any
# scenario unless the operator sets RUSTFS_FAULT_TEST_MIN_NODES=1 by hand.
resolve_min_ready_nodes() {
  if [[ -n "${RUSTFS_FAULT_TEST_MIN_NODES:-}" ]]; then
    printf '%s\n' "$RUSTFS_FAULT_TEST_MIN_NODES"
    return 0
  fi
  local spread
  spread="$(printf '%s' "${RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS:-true}" | tr '[:upper:]' '[:lower:]')"
  case "$spread" in
    1|true|yes) printf '4\n' ;;
    0|false|no) printf '1\n' ;;
    *) die "RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS must be a boolean: 1/0, true/false, or yes/no" ;;
  esac
}

CHAOS_DELETE_WAIT_SECONDS="${RUSTFS_FAULT_TEST_CHAOS_DELETE_WAIT_SECONDS:-40}"

cleanup_managed_chaos() {
  local kind
  for kind in schedule iochaos podchaos networkchaos stresschaos; do
    kubectl_ns "$CHAOS_NAMESPACE" delete "$kind" -l "$MANAGER_SELECTOR" \
      --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
  done
  if [[ -n "${FAULT_NAMESPACE:-}" ]]; then
    kubectl_ns "$FAULT_NAMESPACE" delete podiochaos --all \
      --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
  fi
  local deadline=$((SECONDS + CHAOS_DELETE_WAIT_SECONDS))
  while (( SECONDS < deadline )); do
    if ! chaos_leftovers_remain; then
      return 0
    fi
    sleep 2
  done
  clear_stuck_chaos_finalizers
  for kind in schedule iochaos podchaos networkchaos stresschaos; do
    kubectl_ns "$CHAOS_NAMESPACE" delete "$kind" -l "$MANAGER_SELECTOR" \
      --ignore-not-found=true --timeout="${CHAOS_DELETE_WAIT_SECONDS}s" >/dev/null 2>&1 || true
  done
  if [[ -n "${FAULT_NAMESPACE:-}" ]]; then
    kubectl_ns "$FAULT_NAMESPACE" delete podiochaos --all \
      --ignore-not-found=true --timeout="${CHAOS_DELETE_WAIT_SECONDS}s" >/dev/null 2>&1 || true
  fi
}

chaos_leftovers_remain() {
  if kubectl_ns "$CHAOS_NAMESPACE" get schedule,iochaos,podchaos,networkchaos,stresschaos \
    -l "$MANAGER_SELECTOR" -o name 2>/dev/null | grep -q .; then
    return 0
  fi
  if [[ -n "${FAULT_NAMESPACE:-}" ]]; then
    kubectl_ns "$FAULT_NAMESPACE" get podiochaos -o name 2>/dev/null | grep -q .
    return
  fi
  return 1
}

clear_stuck_chaos_finalizers() {
  local kind names name
  for kind in schedule iochaos podchaos networkchaos stresschaos; do
    names="$(kubectl_ns "$CHAOS_NAMESPACE" get "$kind" -l "$MANAGER_SELECTOR" \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      echo "warning: clearing finalizers on stuck ${kind}/${name} in ${CHAOS_NAMESPACE}" >&2
      kubectl_ns "$CHAOS_NAMESPACE" patch "$kind" "$name" --type=merge \
        -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1 || true
    done <<<"$names"
  done
  if [[ -n "${FAULT_NAMESPACE:-}" ]]; then
    names="$(kubectl_ns "$FAULT_NAMESPACE" get podiochaos \
      -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' 2>/dev/null || true)"
    while IFS= read -r name; do
      [[ -n "$name" ]] || continue
      echo "warning: clearing finalizers on stuck podiochaos/${name} in ${FAULT_NAMESPACE}" >&2
      kubectl_ns "$FAULT_NAMESPACE" patch podiochaos "$name" --type=merge \
        -p '{"metadata":{"finalizers":[]}}' >/dev/null 2>&1 || true
    done <<<"$names"
  fi
}

capture_process_group() {
  local artifacts="$1" stage="$2" process="$3" group="$4"
  [[ -n "$artifacts" && -d "$artifacts" ]] || return 0
  {
    printf 'capturedAt=%s process=%s processGroup=%s stage=%s\n' \
      "$(date -u +%FT%TZ)" "$process" "$group" "$stage"
    ps -eo pid=,ppid=,pgid=,stat= \
      | awk -v group="$group" '$3 == group { print }'
  } >"$artifacts/process-group-$stage.txt" 2>&1 || true
}

process_group_alive() {
  local process="$1" group="$2"
  if [[ "$group" =~ ^[1-9][0-9]*$ ]]; then
    kill -0 -- "-$group" 2>/dev/null
    return
  fi
  kill -0 "$process" 2>/dev/null
}

signal_process_group() {
  local process="$1" group="$2" signal="$3"
  if [[ "$group" =~ ^[1-9][0-9]*$ ]]; then
    kill -"$signal" -- "-$group" 2>/dev/null && return 0
  fi
  kill -"$signal" "$process" 2>/dev/null || true
}

terminate_process_group() {
  local parent="$1" group="$2" state_file="$3" state_token="$4" artifacts="$5"
  local grace_seconds="${6:-$PROCESS_TERMINATION_GRACE_SECONDS}" deadline
  capture_process_group "$artifacts" before-term "$parent" "$group"
  signal_process_group "$parent" "$group" TERM
  deadline=$((SECONDS + grace_seconds))
  while process_group_alive "$parent" "$group" && (( SECONDS < deadline )); do
    sleep 1
  done
  if process_group_alive "$parent" "$group"; then
    if host_storage_mutation_active "$parent" "$state_file" "$state_token"; then
      echo "warning: device-mapper host-storage mutation may still be active after ${grace_seconds}s; refusing to send SIGKILL because it could interrupt rollback" >&2
      echo "warning: waiting for the fault process to restore or quarantine the target; preserve its proof artifacts for scoped manual recovery if it cannot finish" >&2
      while process_group_alive "$parent" "$group"; do
        if ! host_storage_mutation_active "$parent" "$state_file" "$state_token"; then
          echo "warning: host-storage mutation is no longer active but the fault process group is still running; escalating to KILL" >&2
          capture_process_group "$artifacts" before-kill "$parent" "$group"
          signal_process_group "$parent" "$group" KILL
          break
        fi
        sleep 1
      done
    else
      echo "warning: fault process did not finish graceful recovery within ${grace_seconds}s; escalating to KILL" >&2
      capture_process_group "$artifacts" before-kill "$parent" "$group"
      signal_process_group "$parent" "$group" KILL
    fi
  fi
  capture_process_group "$artifacts" after-termination "$parent" "$group"
}

process_descends_from() {
  local process="$1" ancestor="$2" parent
  [[ "$process" =~ ^[1-9][0-9]*$ && "$ancestor" =~ ^[1-9][0-9]*$ ]] || return 1
  while (( process > 1 )); do
    [[ "$process" == "$ancestor" ]] && return 0
    parent="$(ps -o ppid= -p "$process" 2>/dev/null | tr -d '[:space:]')"
    [[ "$parent" =~ ^[1-9][0-9]*$ && "$parent" != "$process" ]] || return 1
    process="$parent"
  done
  return 1
}

host_storage_mutation_active() {
  local parent="$1" state_file="$2" state_token="$3" owner phase token schema
  [[ -n "$state_file" && -n "$state_token" && -f "$state_file" ]] || return 1
  schema="$(jq -r '.schemaVersion // empty' "$state_file" 2>/dev/null)" || return 1
  token="$(jq -r '.token // empty' "$state_file" 2>/dev/null)" || return 1
  owner="$(jq -r '.ownerPid // empty' "$state_file" 2>/dev/null)" || return 1
  phase="$(jq -r '.phase // empty' "$state_file" 2>/dev/null)" || return 1
  [[ "$schema" == "1" && "$token" == "$state_token" ]] || return 1
  [[ "$phase" == "activating" || "$phase" == "active" || "$phase" == "rollback" ]] || return 1
  kill -0 "$owner" 2>/dev/null || return 1
  process_descends_from "$owner" "$parent"
}

prepare_host_mutation_state() {
  local root="$1"
  root="$(cd "$root" && pwd -P)"
  ACTIVE_HOST_MUTATION_STATE_TOKEN="fault-$$-${BASHPID}-${RANDOM}-$(date +%s)"
  ACTIVE_HOST_MUTATION_STATE_FILE="$root/.host-mutation-${ACTIVE_HOST_MUTATION_STATE_TOKEN}.json"
}

cleanup_host_mutation_state() {
  if [[ -n "$ACTIVE_HOST_MUTATION_STATE_FILE" && -e "$ACTIVE_HOST_MUTATION_STATE_FILE" ]]; then
    echo "warning: preserving unresolved host mutation state at $ACTIVE_HOST_MUTATION_STATE_FILE; verify device recovery before removing it" >&2
  fi
  ACTIVE_HOST_MUTATION_STATE_FILE=""
  ACTIVE_HOST_MUTATION_STATE_TOKEN=""
}

clear_active_run_state() {
  ACTIVE_PID=""
  ACTIVE_PROCESS_GROUP=""
  ACTIVE_ARTIFACTS=""
  ACTIVE_SCOPE=""
  ACTIVE_NAME=""
}

handle_signal() {
  trap '' INT TERM HUP
  if [[ -n "$ACTIVE_PID" ]]; then
    terminate_process_group "$ACTIVE_PID" "$ACTIVE_PROCESS_GROUP" "$ACTIVE_HOST_MUTATION_STATE_FILE" "$ACTIVE_HOST_MUTATION_STATE_TOKEN" "$ACTIVE_ARTIFACTS"
    wait "$ACTIVE_PID" 2>/dev/null || true
    ACTIVE_PID=""
    ACTIVE_PROCESS_GROUP=""
  fi
  if [[ -n "$ACTIVE_ARTIFACTS" ]]; then
    touch "$ACTIVE_ARTIFACTS/interrupted" \
      || warn_artifact_write_failed "interrupted marker" "$ACTIVE_ARTIFACTS/interrupted"
    if [[ "$ACTIVE_SCOPE" == "suite" ]]; then
      echo 130 >"$ACTIVE_ARTIFACTS/suite-exit-code" \
        || warn_artifact_write_failed "suite-exit-code" "$ACTIVE_ARTIFACTS/suite-exit-code"
    else
      echo 130 >"$ACTIVE_ARTIFACTS/exit-code" \
        || warn_artifact_write_failed "exit-code" "$ACTIVE_ARTIFACTS/exit-code"
    fi
    finalize_failed_run "${ACTIVE_SCOPE:-run}" "${ACTIVE_NAME:-unknown}" "$ACTIVE_ARTIFACTS" 130 interrupted
  else
    cleanup_managed_chaos
  fi
  if [[ -n "$ACTIVE_QUALIFICATION_ROOT" ]]; then
    write_qualification_result "$ACTIVE_QUALIFICATION_ROOT" interrupted 130 \
      || warn_artifact_write_failed \
        "qualification-result.json" "$ACTIVE_QUALIFICATION_ROOT/qualification-result.json"
  fi
  cleanup_host_mutation_state
  exit 130
}

handle_exit() {
  local rc=$? outcome=failed
  trap - EXIT
  if [[ -n "$ACTIVE_QUALIFICATION_ROOT" && ! -f "$ACTIVE_QUALIFICATION_ROOT/qualification-result.json" ]]; then
    [[ "$rc" -ne 130 ]] || outcome=interrupted
    write_qualification_result "$ACTIVE_QUALIFICATION_ROOT" "$outcome" "$rc" \
      || warn_artifact_write_failed \
        "qualification-result.json" "$ACTIVE_QUALIFICATION_ROOT/qualification-result.json"
    echo "qualification outcome: $outcome" >&2
    echo "qualification artifacts: $ACTIVE_QUALIFICATION_ROOT" >&2
    echo "analyze with: make fault-qualify-analyze RUN_ROOT=$ACTIVE_QUALIFICATION_ROOT" >&2
  fi
  return "$rc"
}

capture_cluster_snapshot() {
  local artifacts="$1" stage="$2"
  kubectl_cluster get nodes -o wide >"$artifacts/nodes-$stage.txt" 2>&1 || true
  kubectl_ns "$FAULT_NAMESPACE" get tenants -o wide >"$artifacts/tenants-$stage.txt" 2>&1 || true
  kubectl_ns "$FAULT_NAMESPACE" get pods -o wide >"$artifacts/pods-$stage.txt" 2>&1 || true
  kubectl_ns "$FAULT_NAMESPACE" get pvc -o wide >"$artifacts/pvcs-$stage.txt" 2>&1 || true
  kubectl_cluster get pv -o wide >"$artifacts/pvs-$stage.txt" 2>&1 || true
  kubectl_ns "$CHAOS_NAMESPACE" get iochaos,podchaos,networkchaos,stresschaos -o yaml >"$artifacts/chaos-$stage.yaml" 2>&1 || true
  kubectl_ns "$FAULT_NAMESPACE" get events --sort-by=.lastTimestamp >"$artifacts/events-$stage.txt" 2>&1 || true
}

capture_fault_logs() {
  local artifacts="$1" pod name
  for pod in $(kubectl_ns "$FAULT_NAMESPACE" get pods -l "rustfs.tenant=$FAULT_TENANT" -o name 2>/dev/null || true); do
    name="${pod#pod/}"
    kubectl_ns "$FAULT_NAMESPACE" logs "$pod" >"$artifacts/$name.log" 2>&1 || true
    kubectl_ns "$FAULT_NAMESPACE" logs "$pod" --previous >"$artifacts/$name-previous.log" 2>&1 || true
  done
}

health_status_json() {
  local baseline_ready_nodes="$1" baseline_tenants="$2" require_chaos="$3"
  local current_ready_nodes=0 disk_pressure_nodes="" disk_pressure_count=0
  local nodes_safe=false disk_pressure_safe=true tenants_safe=true chaos_safe=true chaos_required=false
  local safe=false reason="cluster_health_safe" message="cluster health is safe"

  if [[ "$require_chaos" == "true" ]]; then
    chaos_required=true
  fi

  current_ready_nodes="$(kubectl_cluster get nodes -o json 2>/dev/null \
    | jq -r '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length' 2>/dev/null \
    || echo 0)"
  if [[ "$current_ready_nodes" -ge "$baseline_ready_nodes" ]]; then
    nodes_safe=true
  else
    reason="ready_node_count_below_baseline"
    message="Ready node count is below baseline"
  fi

  disk_pressure_nodes="$(kubectl_cluster get nodes -o json 2>/dev/null \
    | jq -r '[.items[]
      | select(any(.status.conditions[]; .type == "DiskPressure" and .status == "True"))
      | .metadata.name] | join(",")' 2>/dev/null || true)"
  if [[ -n "$disk_pressure_nodes" ]]; then
    disk_pressure_safe=false
    disk_pressure_count="$(tr ',' '\n' <<<"$disk_pressure_nodes" | grep -c . || true)"
    if [[ "$reason" == "cluster_health_safe" ]]; then
      reason="node_disk_pressure"
      message="node DiskPressure detected"
    fi
  fi

  if ! non_fault_tenants_are_ready "$baseline_tenants"; then
    tenants_safe=false
    if [[ "$reason" == "cluster_health_safe" ]]; then
      reason="non_fault_tenant_not_ready"
      message="pre-existing non-fault Tenant is not Ready"
    fi
  fi

  if [[ "$chaos_required" == "true" ]] && ! chaos_is_ready; then
    chaos_safe=false
    if [[ "$reason" == "cluster_health_safe" ]]; then
      reason="chaos_mesh_not_ready"
      message="Chaos Mesh controller or daemon is not Ready"
    fi
  fi

  if [[ "$nodes_safe" == "true" && "$disk_pressure_safe" == "true" && "$tenants_safe" == "true" && "$chaos_safe" == "true" ]]; then
    safe=true
  fi

  jq -cn \
    --argjson safe "$safe" \
    --arg reason "$reason" \
    --arg message "$message" \
    --argjson baseline_ready_nodes "$baseline_ready_nodes" \
    --argjson current_ready_nodes "$current_ready_nodes" \
    --argjson nodes_safe "$nodes_safe" \
    --arg disk_pressure_nodes "$disk_pressure_nodes" \
    --argjson disk_pressure_count "$disk_pressure_count" \
    --argjson disk_pressure_safe "$disk_pressure_safe" \
    --argjson tenants_safe "$tenants_safe" \
    --argjson chaos_required "$chaos_required" \
    --argjson chaos_safe "$chaos_safe" \
    '{
      safe: $safe,
      reason: $reason,
      message: $message,
      subchecks: {
        readyNodes: {
          safe: $nodes_safe,
          current: $current_ready_nodes,
          baseline: $baseline_ready_nodes
        },
        nodeDiskPressure: {
          safe: $disk_pressure_safe,
          count: $disk_pressure_count,
          nodes: (if $disk_pressure_nodes == "" then [] else ($disk_pressure_nodes | split(",")) end)
        },
        nonFaultTenants: {
          safe: $tenants_safe
        },
        chaosMesh: {
          required: $chaos_required,
          safe: $chaos_safe
        }
      }
    }'
}

write_health_watch_event() {
  local jsonl="$1" at="$2" scope="$3" name="$4" safe="$5" health_checks="$6" message="$7" reason="$8" status_json="$9"
  local consecutive_failures="${10:-0}" failure_threshold="${11:-1}" will_abort="${12:-false}"
  jq -cn \
    --arg at "$at" \
    --arg scope "$scope" \
    --arg name "$name" \
    --argjson safe "$safe" \
    --argjson health_checks "$health_checks" \
    --arg message "$message" \
    --arg reason "$reason" \
    --argjson status "$status_json" \
    --argjson consecutive_failures "$consecutive_failures" \
    --argjson failure_threshold "$failure_threshold" \
    --argjson will_abort "$will_abort" \
    '{
      at: $at,
      scope: $scope,
      safe: $safe,
      health_checks: $health_checks,
      consecutive_failures: $consecutive_failures,
      failure_threshold: $failure_threshold,
      will_abort: $will_abort
    } + (if $scope == "scenario" then {scenario: $name} else {suite: $name} end) + {
      message: $message,
      reason: $reason,
      subchecks: ($status.subchecks // {})
    }' >>"$jsonl"
}

append_health_watch_log() {
  local path="$1" at="$2" safe="$3" health_checks="$4" reason="$5" message="$6" consecutive_failures="$7" failure_threshold="$8" will_abort="$9"
  printf '%s safe=%s checks=%s reason=%s consecutiveFailures=%s/%s willAbort=%s message=%s\n' \
    "$at" "$safe" "$health_checks" "$reason" "$consecutive_failures" "$failure_threshold" "$will_abort" "$message" >>"$path"
}

health_failure_is_immediate() {
  local reason="$1"
  [[ "$reason" == "node_disk_pressure" || "$reason" == "ready_node_count_below_baseline" ]]
}

validate_scenario_artifacts() {
  local scenario="$1" artifacts="$2" run_root="$3"
  local summary_row
  if ! summary_row="$(s3chaos_cli fault-validate-artifacts "$scenario" "$artifacts" --validation-summary-tsv)"; then
    echo "fault-test: $scenario artifacts did not pass Rust contract validation" >&2
    return 1
  fi
  printf '%s\n' "$summary_row" >>"$run_root/validation-summary.tsv"
}

write_runner_failure_summary() {
  local scenario="$1" artifacts="$2" rc="$3"
  local health_guard_failed=false artifact_validation_failed=false rust_failure_summary=false
  local health_watch_last="" rust_failure_summary_path=""
  [[ ! -f "$artifacts/health-guard-failed" ]] || health_guard_failed=true
  [[ ! -f "$artifacts/artifact-validation-failed" ]] || artifact_validation_failed=true
  rust_failure_summary_path="$(find "$artifacts" -type f -name failure-summary.json -print -quit 2>/dev/null || true)"
  [[ -z "$rust_failure_summary_path" ]] || rust_failure_summary=true
  [[ ! -f "$artifacts/health-watch.log" ]] || health_watch_last="$(tail -n 1 "$artifacts/health-watch.log" 2>/dev/null || true)"
  jq -n \
    --arg scenario "$scenario" \
    --argjson exit_code "$rc" \
    --argjson health_guard_failed "$health_guard_failed" \
    --argjson artifact_validation_failed "$artifact_validation_failed" \
    --argjson rust_failure_summary "$rust_failure_summary" \
    --arg test_log "$artifacts/test.log" \
    --arg health_watch_last "$health_watch_last" \
    '{
      scenario: $scenario,
      stage: "runner",
      exit_code: $exit_code,
      health_guard_failed: $health_guard_failed,
      artifact_validation_failed: $artifact_validation_failed,
      rust_failure_summary_present: $rust_failure_summary,
      test_log: $test_log,
      health_watch_last: (if $health_watch_last == "" then null else $health_watch_last end)
    }' >"$artifacts/runner-failure-summary.json"
}

write_suite_runner_failure_summary() {
  local suite="$1" run_root="$2" rc="$3"
  local health_guard_failed=false suite_budget_failed=false suite_summary_present=false
  local health_watch_last="" suite_summary_path=""
  [[ ! -f "$run_root/health-guard-failed" ]] || health_guard_failed=true
  [[ ! -f "$run_root/suite-budget-failed" ]] || suite_budget_failed=true
  suite_summary_path="$(find "$run_root" -type f -name suite-summary.json -print -quit 2>/dev/null || true)"
  [[ -z "$suite_summary_path" ]] || suite_summary_present=true
  [[ ! -f "$run_root/health-watch.log" ]] || health_watch_last="$(tail -n 1 "$run_root/health-watch.log" 2>/dev/null || true)"
  jq -n \
    --arg suite "$suite" \
    --argjson exit_code "$rc" \
    --argjson health_guard_failed "$health_guard_failed" \
    --argjson suite_budget_failed "$suite_budget_failed" \
    --argjson suite_summary_present "$suite_summary_present" \
    --arg suite_log "$run_root/suite.log" \
    --arg health_watch_last "$health_watch_last" \
    '{
      suite: $suite,
      stage: "runner",
      exit_code: $exit_code,
      health_guard_failed: $health_guard_failed,
      suite_budget_failed: $suite_budget_failed,
      suite_summary_present: $suite_summary_present,
      suite_log: $suite_log,
      health_watch_last: (if $health_watch_last == "" then null else $health_watch_last end)
    }' >"$run_root/runner-failure-summary.json"
}

write_failure_evidence_manifest() {
  local scope="$1" name="$2" artifacts="$3" rc="$4" snapshot_stage="$5"
  local diagnosis_count failure_summary_count captured_at
  diagnosis_count="$(find "$artifacts" -type f -name diagnosis.txt -print 2>/dev/null | wc -l | tr -d '[:space:]')"
  failure_summary_count="$(find "$artifacts" -type f \( -name failure-summary.json -o -name runner-failure-summary.json \) -print 2>/dev/null | wc -l | tr -d '[:space:]')"
  captured_at="$(date -u +%FT%TZ)"

  cat >"$artifacts/runner-diagnosis.txt" <<EOF
Failure evidence was captured before residual managed Chaos cleanup.
scope=$scope
name=$name
exitCode=$rc
detailedRustDiagnosisFiles=$diagnosis_count
failureSummaryFiles=$failure_summary_count

Inspect runner-failure-summary.json, the case-scoped failure-summary.json and diagnosis.txt files, the $snapshot_stage cluster snapshot, and the captured RustFS logs.
EOF

  jq -n \
    --arg captured_at "$captured_at" \
    --arg scope "$scope" \
    --arg name "$name" \
    --arg snapshot_stage "$snapshot_stage" \
    --argjson exit_code "$rc" \
    --argjson detailed_diagnosis_files "$diagnosis_count" \
    --argjson failure_summary_files "$failure_summary_count" \
    '{
      schemaVersion: 1,
      status: "captured-before-managed-chaos-cleanup",
      capturedAt: $captured_at,
      scope: $scope,
      name: $name,
      exitCode: $exit_code,
      snapshotStage: $snapshot_stage,
      detailedRustDiagnosisFiles: $detailed_diagnosis_files,
      failureSummaryFiles: $failure_summary_files,
      runnerDiagnosis: "runner-diagnosis.txt"
    }' >"$artifacts/failure-evidence.json"
}

finalize_failed_run() {
  local scope="$1" name="$2" artifacts="$3" rc="$4" snapshot_stage="${5:-failed}"
  capture_cluster_snapshot "$artifacts" "$snapshot_stage"
  capture_fault_logs "$artifacts"
  case "$scope" in
    scenario)
      write_runner_failure_summary "$name" "$artifacts" "$rc" \
        || warn_artifact_write_failed "runner-failure-summary.json" "$artifacts/runner-failure-summary.json"
      ;;
    suite)
      write_suite_runner_failure_summary "$name" "$artifacts" "$rc" \
        || warn_artifact_write_failed "runner-failure-summary.json" "$artifacts/runner-failure-summary.json"
      ;;
    *)
      jq -n --arg scope "$scope" --arg name "$name" --argjson exit_code "$rc" \
        '{scope: $scope, name: $name, stage: "runner", exit_code: $exit_code}' \
        >"$artifacts/runner-failure-summary.json" \
        || warn_artifact_write_failed "runner-failure-summary.json" "$artifacts/runner-failure-summary.json"
      ;;
  esac
  write_failure_evidence_manifest "$scope" "$name" "$artifacts" "$rc" "$snapshot_stage" \
    || warn_artifact_write_failed "failure-evidence.json" "$artifacts/failure-evidence.json"
  cleanup_managed_chaos
}

warn_artifact_write_failed() {
  local artifact="$1" path="$2"
  echo "warning: could not write $artifact: $path" >&2
}

run_scenario() {
  local scenario="$1" run_root="$2" qualification_kind="${3:-ordinary}" storage_case="${4:--}"
  local artifacts="$run_root/$scenario"
  local baseline_ready_nodes baseline_tenants test_pid rc current_time health_checks require_chaos
  local health_status health_safe health_message health_reason
  local consecutive_health_failures will_abort
  local -a qualification_env
  case "$qualification_kind" in
    ordinary)
      qualification_env=(
        RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=
        RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=
        RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=
      )
      ;;
    admin)
      [[ "$storage_case" == "-" ]] || die "admin qualification cannot select a storage-recovery case"
      qualification_env=(
        RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=1
        RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=
        RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=
      )
      ;;
    storage)
      [[ "$storage_case" != "-" ]] || die "storage qualification requires an exact storage-recovery case"
      qualification_env=(
        RUSTFS_FAULT_TEST_QUALIFY_PLANNED_ADMIN=
        RUSTFS_FAULT_TEST_QUALIFY_PLANNED_STORAGE=1
        "RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=$storage_case"
      )
      ;;
    *)
      die "unsupported qualification kind: $qualification_kind"
      ;;
  esac
  mkdir -p "$artifacts"
  baseline_ready_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
  baseline_tenants="$artifacts/baseline-non-fault-tenants.tsv"
  list_non_fault_tenants >"$baseline_tenants"
  if scenario_requires_chaos_mesh "$scenario"; then
    require_chaos=true
  else
    require_chaos=false
  fi
  capture_cluster_snapshot "$artifacts" before
  prepare_host_mutation_state "$artifacts"

  echo "starting scenario=$scenario artifacts=$artifacts"
  ACTIVE_ARTIFACTS="$artifacts"
  ACTIVE_SCOPE="scenario"
  ACTIVE_NAME="$scenario"
  # A runner can spawn helpers that reparent before cancellation. Giving the
  # run its own session makes its process group the cancellation boundary.
  setsid env "${qualification_env[@]}" \
    RUSTFS_FAULT_TEST_DESTRUCTIVE=1 \
    RUSTFS_FAULT_TEST_SCENARIO="$scenario" \
    RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS="$WORKLOAD_OBJECTS" \
    RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY="$WORKLOAD_CONCURRENCY" \
    RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT="$RUSTFS_POD_COUNT" \
    RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH="$RUSTFS_VOLUME_PATH" \
    RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS="$RUSTFS_POD_STABLE_WINDOW_SECONDS" \
    RUSTFS_FAULT_TEST_DURATION_SECONDS="${RUSTFS_FAULT_TEST_DURATION_SECONDS:-7200}" \
    RUSTFS_FAULT_TEST_ARTIFACTS="$artifacts" \
    RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_FILE="$ACTIVE_HOST_MUTATION_STATE_FILE" \
    RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_TOKEN="$ACTIVE_HOST_MUTATION_STATE_TOKEN" \
    "$FAULT_TEST_BINARY" fault-run \
      >"$artifacts/test.log" 2>&1 &
  test_pid=$!
  ACTIVE_PID="$test_pid" ACTIVE_PROCESS_GROUP="$test_pid"
  health_checks=0
  consecutive_health_failures=0

  while kill -0 "$test_pid" 2>/dev/null; do
    current_time="$(date -u +%FT%TZ)"
    health_checks=$((health_checks + 1))
    health_status="$(health_status_json "$baseline_ready_nodes" "$baseline_tenants" "$require_chaos")"
    health_safe="$(jq -r '.safe' <<<"$health_status")"
    health_message="$(jq -r '.message' <<<"$health_status")"
    health_reason="$(jq -r '.reason' <<<"$health_status")"
    if [[ "$health_safe" == "true" ]]; then
      consecutive_health_failures=0
      append_health_watch_log "$artifacts/health-watch.log" "$current_time" true "$health_checks" "$health_reason" "$health_message" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" false
      write_health_watch_event "$artifacts/health-watch.jsonl" "$current_time" scenario "$scenario" true "$health_checks" "$health_message" "$health_reason" "$health_status" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" false \
        || warn_artifact_write_failed "health-watch.jsonl" "$artifacts/health-watch.jsonl"
      if (( health_checks % 6 == 0 )); then
        echo "scenario=$scenario running safe=true time=$current_time"
      fi
    else
      consecutive_health_failures=$((consecutive_health_failures + 1))
      will_abort=false
      if health_failure_is_immediate "$health_reason" || (( consecutive_health_failures >= 10#$HEALTH_GUARD_FAILURE_THRESHOLD )); then
        will_abort=true
      fi
      append_health_watch_log "$artifacts/health-watch.log" "$current_time" false "$health_checks" "$health_reason" "$health_message" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" "$will_abort"
      write_health_watch_event "$artifacts/health-watch.jsonl" "$current_time" scenario "$scenario" false "$health_checks" "$health_message" "$health_reason" "$health_status" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" "$will_abort" \
        || warn_artifact_write_failed "health-watch.jsonl" "$artifacts/health-watch.jsonl"
      if [[ "$will_abort" == "true" ]]; then
        touch "$artifacts/health-guard-failed"
        terminate_process_group "$test_pid" "$ACTIVE_PROCESS_GROUP" "$ACTIVE_HOST_MUTATION_STATE_FILE" "$ACTIVE_HOST_MUTATION_STATE_TOKEN" "$artifacts"
        break
      fi
    fi
    sleep 10
  done

  rc=0
  wait "$test_pid" 2>/dev/null || rc=$?
  cleanup_host_mutation_state
  ACTIVE_PID=""
  ACTIVE_PROCESS_GROUP=""
  [[ ! -f "$artifacts/health-guard-failed" ]] || rc=90
  echo "$rc" >"$artifacts/exit-code"

  if [[ "$rc" -ne 0 ]]; then
    finalize_failed_run scenario "$scenario" "$artifacts" "$rc"
    clear_active_run_state
    echo "scenario failed: $scenario rc=$rc log=$artifacts/test.log" >&2
    return "$rc"
  fi
  if ! validate_scenario_artifacts "$scenario" "$artifacts" "$run_root"; then
    rc=1
    touch "$artifacts/artifact-validation-failed" \
      || warn_artifact_write_failed "artifact-validation-failed marker" "$artifacts/artifact-validation-failed"
    echo "$rc" >"$artifacts/exit-code" \
      || warn_artifact_write_failed "exit-code" "$artifacts/exit-code"
    finalize_failed_run scenario "$scenario" "$artifacts" "$rc"
    clear_active_run_state
    echo "scenario failed artifact validation: $scenario log=$artifacts/test.log" >&2
    return "$rc"
  fi
  capture_cluster_snapshot "$artifacts" after
  capture_fault_logs "$artifacts"
  clear_active_run_state
  echo "scenario passed: $scenario"
}

new_run_root() {
  if [[ -n "${RUSTFS_FAULT_TEST_RUN_ROOT:-}" ]]; then
    echo "$RUSTFS_FAULT_TEST_RUN_ROOT"
  else
    echo "$PACKAGE_DIR/target/fault-tests/$(date -u +%Y%m%dT%H%M%SZ)"
  fi
}

initialize_summary() {
  local run_root="$1"
  mkdir -p "$run_root"
  if [[ ! -f "$run_root/validation-summary.tsv" ]]; then
    printf 'scenario\tseed\texit\tdisruptions\trecommitted\tcommitted\tmissing\thash_mismatch\tcorrupt_read\tfinal_list_warning\trecovered\n' \
      >"$run_root/validation-summary.tsv"
  fi
}

run_one() {
  local scenario="$1" mode="${2:-ordinary}" run_root
  run_root="$(new_run_root)"
  initialize_summary "$run_root"
  run_root="$(cd "$run_root" && pwd -P)"
  build_fault_binary "$run_root" "scenario=$scenario"
  if [[ "$mode" == "dm" ]]; then
    require_dm_scenario "$scenario"
  else
    require_non_dm_scenario "$scenario"
  fi
  preflight "$scenario"
  echo "s3chaos fault-run binary ready"
  run_scenario "$scenario" "$run_root"
  echo "run artifacts: $run_root"
}

run_dm() {
  local scenario="$1"
  run_one "$scenario" dm
}

new_qualification_run_root() {
  local qualification_case="$1"
  if [[ -n "${RUSTFS_FAULT_TEST_RUN_ROOT:-}" ]]; then
    echo "$RUSTFS_FAULT_TEST_RUN_ROOT"
  else
    echo "$PACKAGE_DIR/target/fault-tests/qualifications/$(date -u +%Y%m%dT%H%M%SZ)-$qualification_case"
  fi
}

write_qualification_request_plan() {
  local run_root="$1" qualification_case="$2" target temporary
  target="$run_root/qualification-plan.json"
  temporary="$(mktemp "$run_root/.qualification-plan.XXXXXX")"
  if jq -n \
    --arg qualification_case "$qualification_case" \
    --arg run_root "$run_root" \
    --arg created_at "$(date -u +%FT%TZ)" \
    '{
      schemaVersion: 1,
      resolution: "requested",
      qualificationCase: $qualification_case,
      scenario: null,
      kind: null,
      storageRecoveryCase: null,
      runRoot: $run_root,
      artifactRoot: null,
      createdAt: $created_at
    }' >"$temporary"; then
    mv "$temporary" "$target"
  else
    local rc=$?
    rm -f "$temporary"
    return "$rc"
  fi
}

write_qualification_plan() {
  local run_root="$1" qualification_case="$2" scenario="$3" kind="$4" storage_case="$5"
  local storage_case_json=null target temporary
  target="$run_root/qualification-plan.json"
  temporary="$(mktemp "$run_root/.qualification-plan.XXXXXX")"
  if [[ "$storage_case" != "-" ]]; then
    storage_case_json="$(jq -Rn --arg value "$storage_case" '$value')"
  fi
  if jq -n \
    --arg qualification_case "$qualification_case" \
    --arg scenario "$scenario" \
    --arg kind "$kind" \
    --argjson storage_case "$storage_case_json" \
    --arg run_root "$run_root" \
    --arg artifact_root "$run_root/$scenario" \
    --arg created_at "$(date -u +%FT%TZ)" \
    '{
      schemaVersion: 1,
      resolution: "resolved",
      qualificationCase: $qualification_case,
      scenario: $scenario,
      kind: $kind,
      storageRecoveryCase: $storage_case,
      runRoot: $run_root,
      artifactRoot: $artifact_root,
      createdAt: $created_at
    }' >"$temporary"; then
    mv "$temporary" "$target"
  else
    local rc=$?
    rm -f "$temporary"
    return "$rc"
  fi
}

write_qualification_result() {
  local run_root="$1" outcome="$2" exit_code="$3" target temporary
  target="$run_root/qualification-result.json"
  temporary="$(mktemp "$run_root/.qualification-result.XXXXXX")"
  if jq -n \
    --arg outcome "$outcome" \
    --argjson exit_code "$exit_code" \
    --arg completed_at "$(date -u +%FT%TZ)" \
    '{
      schemaVersion: 1,
      outcome: $outcome,
      exitCode: $exit_code,
      completedAt: $completed_at
    }' >"$temporary"; then
    mv "$temporary" "$target"
  else
    local rc=$?
    rm -f "$temporary"
    return "$rc"
  fi
}

run_qualification() {
  local qualification_case="$1" run_root rc outcome
  [[ "$qualification_case" =~ ^[a-z0-9]+(-[a-z0-9]+)*$ && ${#qualification_case} -le 128 ]] \
    || die "qualification case must be a lowercase kebab-case token"
  ACTIVE_QUALIFICATION_CASE="$qualification_case"
  run_root="$(new_qualification_run_root "$qualification_case")"
  if [[ -d "$run_root" && -n "$(find "$run_root" -mindepth 1 -print -quit 2>/dev/null)" ]]; then
    die "qualification run root already exists and is not empty: $run_root"
  fi
  mkdir -p "$run_root"
  run_root="$(cd "$run_root" && pwd -P)"
  ACTIVE_QUALIFICATION_ROOT="$run_root"
  initialize_summary "$run_root"
  write_qualification_request_plan "$run_root" "$qualification_case"
  echo "qualification run root: $run_root"
  echo "live console: make fault-console-serve CONSOLE_ROOT=$run_root"
  build_fault_binary "$run_root" "qualification=$qualification_case"
  resolve_qualification_case "$qualification_case"
  write_qualification_plan \
    "$run_root" "$qualification_case" "$QUALIFICATION_SCENARIO" \
    "$QUALIFICATION_KIND" "$QUALIFICATION_STORAGE_CASE"
  is_planned_scenario "$QUALIFICATION_SCENARIO" \
    || die "qualification scenario is no longer Planned: $QUALIFICATION_SCENARIO"
  preflight "$QUALIFICATION_SCENARIO" qualification "$qualification_case"
  echo "s3chaos planned qualification binary ready: case=$qualification_case"

  rc=0
  if run_scenario \
    "$QUALIFICATION_SCENARIO" "$run_root" "$QUALIFICATION_KIND" \
    "$QUALIFICATION_STORAGE_CASE"; then
    outcome=passed
  else
    rc=$?
    outcome=failed
  fi
  write_qualification_result "$run_root" "$outcome" "$rc"
  ACTIVE_QUALIFICATION_ROOT=""
  ACTIVE_QUALIFICATION_CASE=""
  echo "qualification outcome: $outcome"
  echo "qualification artifacts: $run_root"
  echo "analyze with: make fault-qualify-analyze RUN_ROOT=$run_root"
  return "$rc"
}

analyze_qualification() {
  local run_root="$1" plan result resolution console_snapshot qualification_case contract scenario kind storage_case rc
  require_command cargo
  require_command jq
  require_command mktemp
  [[ -d "$run_root" ]] || die "qualification run root does not exist: $run_root"
  run_root="$(cd "$run_root" && pwd -P)"
  plan="$run_root/qualification-plan.json"
  [[ -f "$plan" ]] || die "qualification run lacks qualification-plan.json: $run_root"
  jq -e --arg run_root "$run_root" '
    .schemaVersion == 1
    and (.resolution == "requested" or .resolution == "resolved")
    and (.qualificationCase | type == "string" and length > 0)
    and .runRoot == $run_root
    and (
      if .resolution == "requested"
      then .scenario == null and .kind == null and .storageRecoveryCase == null and .artifactRoot == null
      else (.scenario | type == "string" and length > 0)
        and (.kind == "admin" or .kind == "storage")
        and .artifactRoot == ($run_root + "/" + .scenario)
      end
    )
  ' "$plan" >/dev/null || die "qualification-plan.json is invalid or belongs to another run root"
  resolution="$(jq -r '.resolution' "$plan")"
  qualification_case="$(jq -r '.qualificationCase' "$plan")"
  result="$run_root/qualification-result.json"
  if [[ -f "$result" ]]; then
    jq -e '
      .schemaVersion == 1
      and (.completedAt | type == "string" and length > 0)
      and (.exitCode | type == "number" and floor == . and . >= 0)
      and (
        (.outcome == "passed" and .exitCode == 0)
        or (.outcome == "failed" and .exitCode > 0)
        or (.outcome == "interrupted" and .exitCode == 130)
      )
    ' "$result" >/dev/null || die "qualification-result.json is invalid"
  fi
  if [[ "$resolution" == "requested" ]]; then
    [[ -f "$result" ]] \
      || die "unresolved qualification plan has no terminal result"
    jq -e '.outcome == "failed" or .outcome == "interrupted"' "$result" >/dev/null \
      || die "unresolved qualification plan cannot have a passing result"
  else
    if ! contract="$(qualification_case_contract "$qualification_case")"; then
      die "qualification-plan.json names an unsupported qualification case"
    fi
    IFS=$'\t' read -r scenario kind storage_case <<<"$contract"
    jq -e \
      --arg scenario "$scenario" \
      --arg kind "$kind" \
      --arg storage_case "$storage_case" '
        .scenario == $scenario
        and .kind == $kind
        and (
          if $storage_case == "-"
          then .storageRecoveryCase == null
          else .storageRecoveryCase == $storage_case
          end
        )
      ' "$plan" >/dev/null || die "qualification-plan.json contradicts the closed case contract"
  fi
  console_snapshot="$(mktemp /tmp/s3chaos-qualification-console.XXXXXX)"
  if ! s3chaos_cli fault-console-json "$run_root" >"$console_snapshot"; then
    rm -f "$console_snapshot"
    die "failed to build the qualification console snapshot"
  fi
  if [[ -f "$result" ]]; then
    if jq -n \
      --slurpfile qualification_plan "$plan" \
      --slurpfile qualification_result "$result" \
      --slurpfile console "$console_snapshot" \
      '{
        schemaVersion: 1,
        qualificationPlan: $qualification_plan[0],
        qualificationResult: $qualification_result[0],
        console: $console[0]
      }'; then
      rc=0
    else
      rc=$?
    fi
  else
    if jq -n \
      --slurpfile qualification_plan "$plan" \
      --slurpfile console "$console_snapshot" \
      '{
        schemaVersion: 1,
        qualificationPlan: $qualification_plan[0],
        qualificationResult: null,
        console: $console[0]
      }'; then
      rc=0
    else
      rc=$?
    fi
  fi
  rm -f "$console_snapshot"
  return "$rc"
}

preflight_suite() {
  local suite="$1" plan_path="$2" mode="${3:-general}" scenario crd tool
  ensure_inherited_kubeconfig
  s3chaos_cli fault-suite-plan "$suite" >"$plan_path"
  if [[ "$mode" == "chaos" ]]; then
    require_ordinary_chaos_suite_plan "$plan_path"
  else
    require_non_static_suite_plan "$plan_path"
  fi
  scenario="$(jq -r '.attempts[0].scenario // empty' "$plan_path")"
  [[ -n "$scenario" ]] || die "fault suite plan contains no attempts: $suite"
  preflight "$scenario"
  while IFS= read -r crd; do
    [[ -n "$crd" ]] || continue
    kubectl_cluster get crd "$crd" >/dev/null
  done < <(jq -r '.requiredCrds[]?' "$plan_path")
  while IFS= read -r tool; do
    [[ -n "$tool" ]] || continue
    require_command "$tool"
  done < <(jq -r '.requiredTools[]?' "$plan_path")
}

is_ordinary_chaos_suite_plan() {
  local plan_path="$1"
  jq -e '
    .requiresChaosMesh == true
    and .requiresStaticStorage == false
    and (.attempts | length > 0)
    and all(.attempts[];
      .scenario != "warp-under-chaos"
      and
      .requiresChaosMesh == true
      and .requiresStaticStorage == false
      and (.expectedBackend | startswith("chaos-mesh-")))
  ' "$plan_path" >/dev/null
}

require_non_static_suite_plan() {
  local plan_path="$1"
  jq -e '.requiresStaticStorage == false' "$plan_path" >/dev/null \
    || die "fault-suite-run does not execute device-mapper suites; run exactly one scenario in the foreground with make fault-dm-run SCENARIO=<name>"
}

require_ordinary_chaos_suite_plan() {
  local plan_path="$1"
  is_ordinary_chaos_suite_plan "$plan_path" \
    || die "fault-chaos-run accepts only ordinary Chaos Mesh scenarios; use fault-suite-run for Warp or fault-dm-run for one device-mapper scenario"
}

plan_chaos_suite() {
  local suite="$1" plan_path
  [[ -f "$suite" ]] || die "suite yaml file not found: $suite"
  ensure_inherited_kubeconfig
  plan_path="$(mktemp)"
  if ! s3chaos_cli fault-suite-plan "$suite" >"$plan_path"; then
    rm -f "$plan_path"
    die "failed to plan ordinary Chaos Mesh suite: $suite"
  fi
  if ! is_ordinary_chaos_suite_plan "$plan_path"; then
    rm -f "$plan_path"
    die "fault-chaos-plan accepts only ordinary Chaos Mesh scenarios; use fault-suite-plan for Warp or device-mapper plans"
  fi
  cat "$plan_path"
  rm -f "$plan_path"
}

suite_requires_chaos() {
  local plan_path="$1"
  jq -e '.requiresChaosMesh == true' "$plan_path" >/dev/null
}

run_suite() {
  local suite="$1" mode="${2:-general}" run_root rc suite_plan suite_name
  local baseline_ready_nodes baseline_tenants current_time health_checks require_chaos
  local health_status health_safe health_message health_reason
  local consecutive_health_failures will_abort
  [[ -f "$suite" ]] || die "suite yaml file not found: $suite"
  run_root="$(new_run_root)"
  mkdir -p "$run_root"
  run_root="$(cd "$run_root" && pwd -P)"
  suite_plan="$run_root/suite-plan-preview.json"
  build_fault_binary "$run_root" "fault-suite-run"
  preflight_suite "$suite" "$suite_plan" "$mode"
  suite_name="$(jq -r '.suite // empty' "$suite_plan")"
  [[ -n "$suite_name" ]] || suite_name="$suite"
  baseline_ready_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
  baseline_tenants="$run_root/baseline-non-fault-tenants.tsv"
  list_non_fault_tenants >"$baseline_tenants"
  if suite_requires_chaos "$suite_plan"; then
    require_chaos=true
  else
    require_chaos=false
  fi
  capture_cluster_snapshot "$run_root" before
  prepare_host_mutation_state "$run_root"

  echo "starting suite=$suite artifacts=$run_root"
  ACTIVE_ARTIFACTS="$run_root"
  ACTIVE_SCOPE="suite"
  ACTIVE_NAME="$suite_name"
  # Keep every suite helper inside a single process-group cancellation boundary.
  setsid env \
    RUSTFS_FAULT_TEST_DESTRUCTIVE=1 \
    RUSTFS_FAULT_TEST_ARTIFACTS="$run_root" \
    RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_FILE="$ACTIVE_HOST_MUTATION_STATE_FILE" \
    RUSTFS_FAULT_TEST_HOST_MUTATION_STATE_TOKEN="$ACTIVE_HOST_MUTATION_STATE_TOKEN" \
    "$FAULT_TEST_BINARY" fault-suite-run "$suite" \
      >"$run_root/suite.log" 2>&1 &
  ACTIVE_PID="$!" ACTIVE_PROCESS_GROUP="$!"
  health_checks=0
  consecutive_health_failures=0

  while kill -0 "$ACTIVE_PID" 2>/dev/null; do
    current_time="$(date -u +%FT%TZ)"
    health_checks=$((health_checks + 1))
    health_status="$(health_status_json "$baseline_ready_nodes" "$baseline_tenants" "$require_chaos")"
    health_safe="$(jq -r '.safe' <<<"$health_status")"
    health_message="$(jq -r '.message' <<<"$health_status")"
    health_reason="$(jq -r '.reason' <<<"$health_status")"
    if [[ "$health_safe" == "true" ]]; then
      consecutive_health_failures=0
      append_health_watch_log "$run_root/health-watch.log" "$current_time" true "$health_checks" "$health_reason" "$health_message" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" false
      write_health_watch_event "$run_root/health-watch.jsonl" "$current_time" suite "$suite_name" true "$health_checks" "$health_message" "$health_reason" "$health_status" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" false \
        || warn_artifact_write_failed "health-watch.jsonl" "$run_root/health-watch.jsonl"
      if (( health_checks % 6 == 0 )); then
        echo "suite=$suite running safe=true time=$current_time"
      fi
    else
      consecutive_health_failures=$((consecutive_health_failures + 1))
      will_abort=false
      if health_failure_is_immediate "$health_reason" || (( consecutive_health_failures >= 10#$HEALTH_GUARD_FAILURE_THRESHOLD )); then
        will_abort=true
      fi
      append_health_watch_log "$run_root/health-watch.log" "$current_time" false "$health_checks" "$health_reason" "$health_message" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" "$will_abort"
      write_health_watch_event "$run_root/health-watch.jsonl" "$current_time" suite "$suite_name" false "$health_checks" "$health_message" "$health_reason" "$health_status" "$consecutive_health_failures" "$HEALTH_GUARD_FAILURE_THRESHOLD" "$will_abort" \
        || warn_artifact_write_failed "health-watch.jsonl" "$run_root/health-watch.jsonl"
      if [[ "$will_abort" == "true" ]]; then
        touch "$run_root/health-guard-failed"
        terminate_process_group "$ACTIVE_PID" "$ACTIVE_PROCESS_GROUP" "$ACTIVE_HOST_MUTATION_STATE_FILE" "$ACTIVE_HOST_MUTATION_STATE_TOKEN" "$run_root"
        break
      fi
    fi
    sleep 10
  done

  rc=0
  wait "$ACTIVE_PID" 2>/dev/null || rc=$?
  cleanup_host_mutation_state
  ACTIVE_PID=""
  ACTIVE_PROCESS_GROUP=""
  [[ ! -f "$run_root/health-guard-failed" ]] || rc=90
  echo "$rc" >"$run_root/suite-exit-code"
  if [[ "$rc" -ne 0 ]]; then
    finalize_failed_run suite "$suite_name" "$run_root" "$rc"
    clear_active_run_state
    echo "suite failed: $suite rc=$rc log=$run_root/suite.log" >&2
    return "$rc"
  fi
  capture_cluster_snapshot "$run_root" after
  capture_fault_logs "$run_root"
  clear_active_run_state
  echo "suite passed: $suite"
  echo "run artifacts: $run_root"
}

list_scenarios() {
  fault_catalog_json | jq -r '.[] | select(.status == "executable") | .scenario'
}

# cluster-cold-restart records the operator pause as annotations on the
# operator Deployment before scaling it to zero. A run that died before its
# own restore leaves that record behind; undo it here. Returns non-zero when
# a restore was possible and did not complete, or when it cannot be told
# whether one is possible; only an explicit RBAC "no" (the profile the
# non-cold lifecycle scenarios run with) is skipped, loudly.
restore_paused_operators() {
  local can_list can_i_rc=0 can_i_stderr listing deployments name replicas
  can_i_stderr="$(mktemp)"
  can_list="$(kubectl_ns "$OPERATOR_NAMESPACE" auth can-i list deployments --request-timeout=30s 2>"$can_i_stderr")" || can_i_rc=$?
  if [[ "$can_list" == "yes" ]]; then
    rm -f "$can_i_stderr"
  elif [[ "$can_list" == no* ]]; then
    rm -f "$can_i_stderr"
    echo "warning: this context may not list Deployments in $OPERATOR_NAMESPACE; skipped the operator pause-record restore (run cleanup with a context that can, if a cluster-cold-restart run was killed)" >&2
    return 0
  else
    echo "error: cannot determine whether this context may list Deployments in $OPERATOR_NAMESPACE (kubectl auth can-i exit $can_i_rc): $(cat "$can_i_stderr")" >&2
    rm -f "$can_i_stderr"
    return 1
  fi
  # Listing a namespaced resource in a namespace that does not exist returns
  # an empty list, so any failure here is an API or transport error.
  if ! listing="$(kubectl_ns "$OPERATOR_NAMESPACE" get deployment -o json --request-timeout=30s)"; then
    echo "error: cannot list operator Deployments in $OPERATOR_NAMESPACE to look for pause records left by a previous run" >&2
    return 1
  fi
  if ! deployments="$(printf '%s' "$listing" \
    | jq -r --arg key "$OPERATOR_PAUSE_REPLICAS_ANNOTATION" '.items[] | select(.metadata.annotations[$key] != null) | "\(.metadata.name)\t\(.metadata.annotations[$key])"')"; then
    echo "error: cannot parse the operator Deployment listing for $OPERATOR_NAMESPACE" >&2
    return 1
  fi
  [[ -n "$deployments" ]] || return 0
  while IFS=$'\t' read -r name replicas; do
    [[ -n "$name" ]] || continue
    if [[ ! "$replicas" =~ ^[1-9][0-9]*$ ]]; then
      echo "error: operator Deployment $OPERATOR_NAMESPACE/$name carries an unreadable pause record ($OPERATOR_PAUSE_REPLICAS_ANNOTATION=$replicas); restore it manually and remove the annotation" >&2
      return 1
    fi
    echo "restoring operator Deployment $OPERATOR_NAMESPACE/$name left paused by a previous run to $replicas replica(s)"
    if ! kubectl_ns "$OPERATOR_NAMESPACE" scale deployment "$name" --replicas="$replicas" --request-timeout=30s \
      || ! kubectl_ns "$OPERATOR_NAMESPACE" rollout status deployment "$name" --timeout=300s \
      || ! kubectl_ns "$OPERATOR_NAMESPACE" annotate deployment "$name" "${OPERATOR_PAUSE_REPLICAS_ANNOTATION}-" "${OPERATOR_PAUSE_RUN_ANNOTATION}-" --request-timeout=30s; then
      echo "error: failed to restore operator Deployment $OPERATOR_NAMESPACE/$name to $replicas replica(s)" >&2
      return 1
    fi
  done <<<"$deployments"
}

# Fixture removal and the residual-Chaos check. Failures are returned rather
# than ending the script so cleanup can still report the operator restore.
cleanup_fixture() {
  if kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1; then
    require_namespace_ownership
    if ! kubectl_cluster delete namespace "$FAULT_NAMESPACE" --wait=true --timeout="$NAMESPACE_DELETE_TIMEOUT"; then
      echo "error: deleting namespace $FAULT_NAMESPACE did not complete within $NAMESPACE_DELETE_TIMEOUT" >&2
      return 1
    fi
  fi
  if kubectl_ns "$CHAOS_NAMESPACE" get iochaos,podchaos,networkchaos,stresschaos -l "$MANAGER_SELECTOR" -o name 2>/dev/null | grep -q .; then
    echo "error: managed Chaos resources remain after cleanup" >&2
    return 1
  fi
}

cleanup() {
  local fixture_status=0 restore_status=0
  cleanup_managed_chaos
  # The operator is restored first so a Tenant finalizer that needs it can
  # complete during the namespace deletion. Both parts always run: the
  # fixture steps run in a subshell so an ownership die cannot skip the
  # summary, and each part's status is kept.
  restore_paused_operators || restore_status=$?
  ( cleanup_fixture ) || fixture_status=$?
  if [[ "$fixture_status" -ne 0 || "$restore_status" -ne 0 ]]; then
    die "cleanup incomplete: fixture cleanup exit $fixture_status, operator restore exit $restore_status; see the errors above"
  fi
  echo "managed fault-test resources cleaned; external StorageClasses, PVs, and host devices were not changed"
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

trap handle_signal INT TERM HUP
trap handle_exit EXIT

case "${1:-help}" in
  help|-h|--help)
    usage
    ;;
  preflight)
    preflight "${2:-io-eio}"
    ;;
  run)
    [[ -n "${2:-}" ]] || die "scenario is required"
    [[ -z "${3:-}" ]] || die "run accepts exactly one scenario"
    run_one "$2"
    ;;
  chaos-plan)
    [[ -n "${2:-}" ]] || die "ordinary Chaos Mesh suite yaml path is required"
    [[ -z "${3:-}" ]] || die "chaos-plan accepts exactly one suite yaml path"
    plan_chaos_suite "$2"
    ;;
  chaos-run)
    [[ -n "${2:-}" ]] || die "ordinary Chaos Mesh suite yaml path is required"
    [[ -z "${3:-}" ]] || die "chaos-run accepts exactly one suite yaml path"
    run_suite "$2" chaos
    ;;
  dm-run)
    [[ -n "${2:-}" ]] || die "device-mapper scenario is required"
    [[ -z "${3:-}" ]] || die "dm-run accepts exactly one scenario"
    run_dm "$2"
    ;;
  list)
    [[ -z "${2:-}" ]] || die "list does not accept arguments; run a named scenario with: fault-test.sh run <scenario>"
    list_scenarios
    ;;
  qualify-list)
    [[ -z "${2:-}" ]] || die "qualify-list does not accept arguments"
    list_qualification_cases
    ;;
  qualify)
    [[ -n "${2:-}" ]] || die "qualification case is required"
    [[ -z "${3:-}" ]] || die "qualify accepts exactly one qualification case"
    run_qualification "$2"
    ;;
  qualify-analyze)
    [[ -n "${2:-}" ]] || die "qualification run root is required"
    [[ -z "${3:-}" ]] || die "qualify-analyze accepts exactly one run root"
    analyze_qualification "$2"
    ;;
  suite-template)
    [[ -z "${2:-}" ]] || die "suite-template does not accept arguments"
    s3chaos_cli fault-suite-template
    ;;
  suite-validate)
    [[ -n "${2:-}" ]] || die "suite yaml path is required"
    [[ -z "${3:-}" ]] || die "suite-validate accepts exactly one suite yaml path"
    s3chaos_cli fault-suite-validate "$2"
    ;;
  suite-plan)
    [[ -n "${2:-}" ]] || die "suite yaml path is required"
    [[ -z "${3:-}" ]] || die "suite-plan accepts exactly one suite yaml path"
    ensure_inherited_kubeconfig
    s3chaos_cli fault-suite-plan "$2"
    ;;
  suite-run)
    [[ -n "${2:-}" ]] || die "suite yaml path is required"
    [[ -z "${3:-}" ]] || die "suite-run accepts exactly one suite yaml path"
    run_suite "$2"
    ;;
  dashboard-install)
    [[ -z "${2:-}" ]] || die "dashboard-install does not accept arguments"
    install_chaos_dashboard
    ;;
  dashboard-port-forward)
    [[ -z "${3:-}" ]] || die "dashboard-port-forward accepts at most one local port"
    port_forward_chaos_dashboard "${2:-}"
    ;;
  cleanup)
    preflight_cleanup
    cleanup
    ;;
  *)
    usage >&2
    die "unknown command: $1"
    ;;
esac
