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
BUILD_JOBS="${RUSTFS_FAULT_TEST_BUILD_JOBS:-1}"
CHAOS_MESH_VERSION="${RUSTFS_FAULT_TEST_CHAOS_MESH_VERSION:-2.8.3}"
CHAOS_DAEMON_RUNTIME="${RUSTFS_FAULT_TEST_CHAOS_DAEMON_RUNTIME:-containerd}"
CHAOS_DAEMON_SOCKET_PATH="${RUSTFS_FAULT_TEST_CHAOS_DAEMON_SOCKET_PATH:-/run/k3s/containerd/containerd.sock}"
CHAOS_DASHBOARD_PORT="${RUSTFS_FAULT_TEST_CHAOS_DASHBOARD_PORT:-2333}"

FAULT_CONTEXT="${RUSTFS_FAULT_TEST_EXPECTED_CONTEXT:-}"
FAULT_NAMESPACE="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
FAULT_TENANT="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
CHAOS_NAMESPACE="${RUSTFS_FAULT_TEST_CHAOS_NAMESPACE:-chaos-mesh}"
ACTIVE_PID=""
ACTIVE_ARTIFACTS=""
FAULT_TEST_BINARY=""
FAULT_CATALOG_JSON=""

usage() {
  cat <<'EOF'
Usage: fault-test.sh <command> [scenario]

Commands:
  preflight [scenario]  Validate the current real-cluster environment.
  run <scenario>        Run one destructive scenario with health guards.
  list                  List catalog scenarios.
  suite-template        Print a YAML FaultSuite template.
  suite-validate <file> Validate a YAML FaultSuite contract.
  suite-plan <file>     Render the resolved destructive FaultSuite plan.
  suite-run <file>      Run a destructive YAML FaultSuite sequentially.
  dashboard-install     Install/upgrade Chaos Mesh with Dashboard enabled.
  dashboard-port-forward [port]
                        Port-forward the Chaos Mesh Dashboard locally.
  cleanup               Remove managed Chaos and the owned fault namespace.

RUSTFS_FAULT_TEST_EXPECTED_CONTEXT is optional. When unset, the current
non-Kind kubectl context is used and pinned for the run.
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
  else
    CARGO_BUILD_JOBS="$BUILD_JOBS" cargo run --quiet --manifest-path "$MANIFEST" --bin s3chaos -- "$@"
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

scenario_percent_supported() {
  catalog_scenario_query "$1" '.[] | select(.scenario == $scenario) | .percent_supported' >/dev/null
}

scenario_requires_static_storage() {
  catalog_scenario_query "$1" '.[] | select(.scenario == $scenario) | .isolation == "dedicated-linux-block-device"' >/dev/null
}

scenario_crds() {
  local scenario="$1"
  fault_catalog_json | jq -r --arg scenario "$scenario" '.[] | select(.scenario == $scenario) | .crds[]?'
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
  BUILD_JOBS="$(trim_value "$BUILD_JOBS")"

  require_positive_integer RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS "$WORKLOAD_OBJECTS"
  (( 10#$WORKLOAD_OBJECTS >= 12 )) || die "RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS must be at least 12"
  require_positive_integer RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY "$WORKLOAD_CONCURRENCY"
  (( 10#$WORKLOAD_CONCURRENCY <= 10#$WORKLOAD_OBJECTS )) || die "RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY must be <= RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS"
  require_positive_integer RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT "$RUSTFS_POD_COUNT"
  require_absolute_non_root_path RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH "$RUSTFS_VOLUME_PATH"
  require_positive_integer RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS "$RUSTFS_POD_STABLE_WINDOW_SECONDS"
  timeout_seconds="$(trim_value "${RUSTFS_FAULT_TEST_TIMEOUT_SECONDS:-300}")"
  require_unsigned_integer RUSTFS_FAULT_TEST_TIMEOUT_SECONDS "$timeout_seconds"
  (( 10#$RUSTFS_POD_STABLE_WINDOW_SECONDS < 10#$timeout_seconds )) || die "RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS must be less than RUSTFS_FAULT_TEST_TIMEOUT_SECONDS"
  export RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT="$RUSTFS_POD_COUNT"
  export RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH="$RUSTFS_VOLUME_PATH"
  export RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS="$RUSTFS_POD_STABLE_WINDOW_SECONDS"
  require_optional_positive_integer RUSTFS_FAULT_TEST_DURATION_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_REQUEST_TIMEOUT_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_TIMEOUT_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_WARP_DURATION_SECONDS
  require_optional_unsigned_integer RUSTFS_FAULT_TEST_SEED
  require_optional_bool RUSTFS_FAULT_TEST_USE_CLUSTER_IP
  require_optional_bool RUSTFS_FAULT_TEST_REQUIRE_CLIENT_DISRUPTION

  percent="$(trim_value "${RUSTFS_FAULT_TEST_PERCENT:-}")"
  if [[ -n "$percent" ]]; then
    require_positive_integer RUSTFS_FAULT_TEST_PERCENT "$percent"
    (( 10#$percent <= 100 )) || die "RUSTFS_FAULT_TEST_PERCENT must be in 1..=100"
    scenario_percent_supported "$scenario" || die "RUSTFS_FAULT_TEST_PERCENT does not apply to scenario $scenario"
    export RUSTFS_FAULT_TEST_PERCENT="$percent"
  fi
}

validate_dm_env_contract() {
  require_nonempty_env RUSTFS_FAULT_TEST_DM_NAME
  require_nonempty_env RUSTFS_FAULT_TEST_DM_NODE
  require_nonempty_env RUSTFS_FAULT_TEST_DM_MOUNT_PATH
  require_nonempty_env RUSTFS_FAULT_TEST_DM_FAULT_TABLE

  require_safe_dm_name RUSTFS_FAULT_TEST_DM_NAME "$RUSTFS_FAULT_TEST_DM_NAME"
  require_safe_node_name RUSTFS_FAULT_TEST_DM_NODE "$RUSTFS_FAULT_TEST_DM_NODE"
  require_absolute_non_root_path RUSTFS_FAULT_TEST_DM_MOUNT_PATH "$RUSTFS_FAULT_TEST_DM_MOUNT_PATH"
  require_safe_image_ref RUSTFS_FAULT_TEST_DM_HELPER_IMAGE "${RUSTFS_FAULT_TEST_DM_HELPER_IMAGE:-rancher/mirrored-library-busybox:1.37.0}"
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

prepare_fault_binary() {
  local scenario="$1" run_root="$2"
  preflight "$scenario"
  build_fault_binary "$run_root" "scenario=$scenario"
  preflight "$scenario"
  echo "s3chaos fault-run binary ready"
}

build_fault_binary() {
  local run_root="$1" label="$2"
  local build_messages="$run_root/fault-build.jsonl"
  local -a build_command=(
    cargo build --manifest-path "$MANIFEST" --bin s3chaos
    --message-format=json-render-diagnostics
  )

  BUILD_JOBS="$(trim_value "$BUILD_JOBS")"
  require_positive_integer RUSTFS_FAULT_TEST_BUILD_JOBS "$BUILD_JOBS"
  mkdir -p "$run_root"
  echo "preparing s3chaos binary for $label with jobs=$BUILD_JOBS and lowest host priority"
  if command -v ionice >/dev/null 2>&1; then
    CARGO_BUILD_JOBS="$BUILD_JOBS" nice -n 19 ionice -c3 "${build_command[@]}" \
      >"$build_messages" 2>"$run_root/fault-build.log"
  else
    CARGO_BUILD_JOBS="$BUILD_JOBS" nice -n 19 "${build_command[@]}" \
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
  local scenario="$1"
  local storage_class provisioner pv_count
  require_nonempty_env RUSTFS_FAULT_TEST_STORAGE_CLASS
  storage_class="$RUSTFS_FAULT_TEST_STORAGE_CLASS"
  provisioner="$(kubectl_cluster get storageclass "$storage_class" -o json | jq -r '.provisioner // ""')"
  [[ -n "$provisioner" ]] || die "StorageClass $storage_class has no provisioner"

  if [[ "$scenario" == "dm-flakey" ]]; then
    [[ "$provisioner" == "kubernetes.io/no-provisioner" ]] || die "dm-flakey requires a no-provisioner StorageClass"
    pv_count="$(kubectl_cluster get pv -o json | jq -r --arg storage_class "$storage_class" '
      [.items[]
        | select(.spec.storageClassName == $storage_class)
        | select(.status.phase == "Available" or .status.phase == "Bound")
        | select(.spec.capacity.storage == "100Gi")]
      | length
    ')"
    [[ "$pv_count" -eq 4 ]] || die "dm-flakey requires exactly four Available/Bound 100Gi PVs, found $pv_count"
  else
    [[ "$provisioner" != "kubernetes.io/no-provisioner" ]] || die "non-static scenarios require dynamic provisioning"
  fi
}

preflight() {
  local scenario="${1:-io-eio}"
  local ready_nodes crd tool
  require_supported_scenario "$scenario"

  require_command cargo
  require_command jq
  require_command kubectl
  require_command nice
  require_command pgrep
  validate_runtime_env_contract "$scenario"
  require_nonempty_env RUSTFS_FAULT_TEST_SERVER_IMAGE

  resolve_fault_context

  kubectl_cluster get crd tenants.rustfs.com >/dev/null
  ready_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[]
    | select(.spec.unschedulable != true)
    | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
  [[ "$ready_nodes" -ge 4 ]] || die "at least four schedulable Ready nodes are required, found $ready_nodes"

  require_storage_class "$scenario"
  require_namespace_ownership
  require_non_fault_tenants_ready

  if ! scenario_requires_static_storage "$scenario"; then
    for crd in $(scenario_crds "$scenario"); do
      kubectl_cluster get crd "$crd" >/dev/null
    done
    require_chaos_ready
  fi
  for tool in $(scenario_required_tools "$scenario"); do
    require_command "$tool"
  done
  if [[ "$scenario" == "dm-flakey" ]]; then
    validate_dm_env_contract
    kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1 || die "dm-flakey requires a pre-created owned fault namespace with privileged Pod Security"
    [[ "$(kubectl_cluster get namespace "$FAULT_NAMESPACE" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}')" == "privileged" ]] || die "dm-flakey requires pod-security.kubernetes.io/enforce=privileged on $FAULT_NAMESPACE"
  fi

  echo "preflight passed: context=$FAULT_CONTEXT scenario=$scenario nodes=$ready_nodes storageClass=${RUSTFS_FAULT_TEST_STORAGE_CLASS} objects=$WORKLOAD_OBJECTS concurrency=$WORKLOAD_CONCURRENCY pods=$RUSTFS_POD_COUNT volume=$RUSTFS_VOLUME_PATH"
}

preflight_cleanup() {
  require_command jq
  require_command kubectl
  resolve_fault_context
  require_namespace_ownership
}

cleanup_managed_chaos() {
  kubectl_ns "$CHAOS_NAMESPACE" delete iochaos,podchaos,networkchaos,stresschaos \
    -l "$MANAGER_SELECTOR" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
}

terminate_process_tree() {
  local parent="$1"
  local child
  for child in $(pgrep -P "$parent" 2>/dev/null || true); do
    terminate_process_tree "$child"
  done
  kill -TERM "$parent" 2>/dev/null || true
}

handle_signal() {
  cleanup_managed_chaos
  if [[ -n "$ACTIVE_PID" ]]; then
    terminate_process_tree "$ACTIVE_PID"
  fi
  if [[ -n "$ACTIVE_ARTIFACTS" ]]; then
    touch "$ACTIVE_ARTIFACTS/interrupted"
    echo 130 >"$ACTIVE_ARTIFACTS/exit-code"
    capture_cluster_snapshot "$ACTIVE_ARTIFACTS" interrupted
    capture_fault_logs "$ACTIVE_ARTIFACTS"
  fi
  exit 130
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

health_is_safe() {
  local baseline_ready_nodes="$1" baseline_tenants="$2" require_chaos="$3"
  local current_ready_nodes
  current_ready_nodes="$(kubectl_cluster get nodes -o json 2>/dev/null | jq -r '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length' 2>/dev/null || echo 0)"
  [[ "$current_ready_nodes" -ge "$baseline_ready_nodes" ]] || return 1
  non_fault_tenants_are_ready "$baseline_tenants" || return 1
  [[ "$require_chaos" != "true" ]] || chaos_is_ready || return 1
  return 0
}

validate_scenario_artifacts() {
  local scenario="$1" artifacts="$2" run_root="$3"
  local summary_row
  summary_row="$(s3chaos_cli fault-validate-artifacts "$scenario" "$artifacts" --validation-summary-tsv)" \
    || die "$scenario artifacts did not pass Rust contract validation"
  printf '%s\n' "$summary_row" >>"$run_root/validation-summary.tsv"
}

write_runner_failure_summary() {
  local scenario="$1" artifacts="$2" rc="$3"
  local health_guard_failed=false rust_failure_summary=false
  [[ ! -f "$artifacts/health-guard-failed" ]] || health_guard_failed=true
  [[ ! -f "$artifacts/failure-summary.json" ]] || rust_failure_summary=true
  jq -n \
    --arg scenario "$scenario" \
    --argjson exit_code "$rc" \
    --argjson health_guard_failed "$health_guard_failed" \
    --argjson rust_failure_summary "$rust_failure_summary" \
    --arg test_log "$artifacts/test.log" \
    '{
      scenario: $scenario,
      stage: "runner",
      exit_code: $exit_code,
      health_guard_failed: $health_guard_failed,
      rust_failure_summary_present: $rust_failure_summary,
      test_log: $test_log
    }' >"$artifacts/runner-failure-summary.json"
}

run_scenario() {
  local scenario="$1" run_root="$2"
  local artifacts="$run_root/$scenario"
  local baseline_ready_nodes baseline_tenants test_pid rc current_time health_checks require_chaos
  preflight "$scenario"
  mkdir -p "$artifacts"
  baseline_ready_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
  baseline_tenants="$artifacts/baseline-non-fault-tenants.tsv"
  list_non_fault_tenants >"$baseline_tenants"
  if [[ "$scenario" == "dm-flakey" ]]; then
    require_chaos=false
  else
    require_chaos=true
  fi
  capture_cluster_snapshot "$artifacts" before

  echo "starting scenario=$scenario artifacts=$artifacts"
  (
    set +e
    RUSTFS_FAULT_TEST_DESTRUCTIVE=1 \
    RUSTFS_FAULT_TEST_SCENARIO="$scenario" \
    RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS="$WORKLOAD_OBJECTS" \
    RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY="$WORKLOAD_CONCURRENCY" \
    RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT="$RUSTFS_POD_COUNT" \
    RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH="$RUSTFS_VOLUME_PATH" \
    RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS="$RUSTFS_POD_STABLE_WINDOW_SECONDS" \
    RUSTFS_FAULT_TEST_DURATION_SECONDS="${RUSTFS_FAULT_TEST_DURATION_SECONDS:-7200}" \
    RUSTFS_FAULT_TEST_ARTIFACTS="$artifacts" \
    "$FAULT_TEST_BINARY" fault-run \
      >"$artifacts/test.log" 2>&1
    echo "$?" >"$artifacts/test-exit-code.tmp"
  ) &
  test_pid=$!
  ACTIVE_PID="$test_pid"
  ACTIVE_ARTIFACTS="$artifacts"
  health_checks=0

  while kill -0 "$test_pid" 2>/dev/null; do
    current_time="$(date -u +%FT%TZ)"
    health_checks=$((health_checks + 1))
    if health_is_safe "$baseline_ready_nodes" "$baseline_tenants" "$require_chaos"; then
      echo "$current_time safe=true" >>"$artifacts/health-watch.log"
      if (( health_checks % 6 == 0 )); then
        echo "scenario=$scenario running safe=true time=$current_time"
      fi
    else
      echo "$current_time safe=false" >>"$artifacts/health-watch.log"
      touch "$artifacts/health-guard-failed"
      cleanup_managed_chaos
      terminate_process_tree "$test_pid"
      break
    fi
    sleep 10
  done

  wait "$test_pid" 2>/dev/null || true
  ACTIVE_PID=""
  ACTIVE_ARTIFACTS=""
  rc=125
  [[ -f "$artifacts/test-exit-code.tmp" ]] && rc="$(cat "$artifacts/test-exit-code.tmp")"
  [[ ! -f "$artifacts/health-guard-failed" ]] || rc=90
  echo "$rc" >"$artifacts/exit-code"
  capture_cluster_snapshot "$artifacts" after
  capture_fault_logs "$artifacts"

  if [[ "$rc" -ne 0 ]]; then
    write_runner_failure_summary "$scenario" "$artifacts" "$rc"
    cleanup_managed_chaos
    echo "scenario failed: $scenario rc=$rc log=$artifacts/test.log" >&2
    return "$rc"
  fi
  validate_scenario_artifacts "$scenario" "$artifacts" "$run_root"
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
  local scenario="$1" run_root
  require_supported_scenario "$scenario"
  run_root="$(new_run_root)"
  initialize_summary "$run_root"
  prepare_fault_binary "$scenario" "$run_root"
  run_scenario "$scenario" "$run_root"
  echo "run artifacts: $run_root"
}

preflight_suite() {
  local suite="$1" plan_path="$2" scenario
  s3chaos_cli fault-suite-validate "$suite"
  ensure_inherited_kubeconfig
  s3chaos_cli fault-suite-plan "$suite" >"$plan_path"
  while IFS= read -r scenario; do
    [[ -n "$scenario" ]] || continue
    preflight "$scenario"
  done < <(jq -r '.attempts[].scenario' "$plan_path" | sort -u)
}

suite_requires_chaos() {
  local plan_path="$1"
  jq -e '.requiresChaosMesh == true' "$plan_path" >/dev/null
}

suite_max_duration_seconds() {
  local plan_path="$1"
  jq -r '.budgets.maxDurationSeconds // empty' "$plan_path"
}

run_suite() {
  local suite="$1" run_root rc suite_plan
  local baseline_ready_nodes baseline_tenants current_time health_checks require_chaos
  local started_at now max_duration_seconds elapsed
  [[ -f "$suite" ]] || die "suite yaml file not found: $suite"
  run_root="$(new_run_root)"
  mkdir -p "$run_root"
  suite_plan="$run_root/suite-plan-preview.json"
  preflight_suite "$suite" "$suite_plan"
  build_fault_binary "$run_root" "fault-suite-run"
  preflight_suite "$suite" "$suite_plan"
  baseline_ready_nodes="$(kubectl_cluster get nodes -o json | jq -r '[.items[] | select(any(.status.conditions[]; .type == "Ready" and .status == "True"))] | length')"
  baseline_tenants="$run_root/baseline-non-fault-tenants.tsv"
  list_non_fault_tenants >"$baseline_tenants"
  if suite_requires_chaos "$suite_plan"; then
    require_chaos=true
  else
    require_chaos=false
  fi
  max_duration_seconds="$(suite_max_duration_seconds "$suite_plan")"
  capture_cluster_snapshot "$run_root" before

  echo "starting suite=$suite artifacts=$run_root"
  ACTIVE_ARTIFACTS="$run_root"
  (
    set +e
    RUSTFS_FAULT_TEST_DESTRUCTIVE=1 \
    RUSTFS_FAULT_TEST_ARTIFACTS="$run_root" \
    "$FAULT_TEST_BINARY" fault-suite-run "$suite" \
      >"$run_root/suite.log" 2>&1
    echo "$?" >"$run_root/suite-exit-code.tmp"
  ) &
  ACTIVE_PID="$!"
  started_at="$(date +%s)"
  health_checks=0

  while kill -0 "$ACTIVE_PID" 2>/dev/null; do
    current_time="$(date -u +%FT%TZ)"
    now="$(date +%s)"
    elapsed=$((now - started_at))
    if [[ -n "$max_duration_seconds" && "$elapsed" -ge "$max_duration_seconds" ]]; then
      echo "$current_time budget=false maxDurationSeconds=$max_duration_seconds elapsedSeconds=$elapsed" >>"$run_root/health-watch.log"
      touch "$run_root/suite-budget-failed"
      cleanup_managed_chaos
      terminate_process_tree "$ACTIVE_PID"
      break
    fi

    health_checks=$((health_checks + 1))
    if health_is_safe "$baseline_ready_nodes" "$baseline_tenants" "$require_chaos"; then
      echo "$current_time safe=true" >>"$run_root/health-watch.log"
      if (( health_checks % 6 == 0 )); then
        echo "suite=$suite running safe=true time=$current_time"
      fi
    else
      echo "$current_time safe=false" >>"$run_root/health-watch.log"
      touch "$run_root/health-guard-failed"
      cleanup_managed_chaos
      terminate_process_tree "$ACTIVE_PID"
      break
    fi
    sleep 10
  done

  wait "$ACTIVE_PID" 2>/dev/null || true
  ACTIVE_PID=""
  ACTIVE_ARTIFACTS=""
  rc=125
  [[ -f "$run_root/suite-exit-code.tmp" ]] && rc="$(cat "$run_root/suite-exit-code.tmp")"
  [[ ! -f "$run_root/health-guard-failed" ]] || rc=90
  [[ ! -f "$run_root/suite-budget-failed" ]] || rc=91
  echo "$rc" >"$run_root/suite-exit-code"
  capture_cluster_snapshot "$run_root" after
  capture_fault_logs "$run_root"
  if [[ "$rc" -ne 0 ]]; then
    cleanup_managed_chaos
    echo "suite failed: $suite rc=$rc log=$run_root/suite.log" >&2
    return "$rc"
  fi
  echo "suite passed: $suite"
  echo "run artifacts: $run_root"
}

list_scenarios() {
  fault_catalog_json | jq -r '.[] | .scenario'
}

cleanup() {
  cleanup_managed_chaos
  if kubectl_cluster get namespace "$FAULT_NAMESPACE" >/dev/null 2>&1; then
    require_namespace_ownership
    kubectl_cluster delete namespace "$FAULT_NAMESPACE" --wait=true
  fi
  if kubectl_ns "$CHAOS_NAMESPACE" get iochaos,podchaos,networkchaos,stresschaos -l "$MANAGER_SELECTOR" -o name 2>/dev/null | grep -q .; then
    die "managed Chaos resources remain after cleanup"
  fi
  echo "managed fault-test resources cleaned; external StorageClasses, PVs, and host devices were not changed"
}

trap handle_signal INT TERM HUP

case "${1:-help}" in
  help|-h|--help)
    usage
    ;;
  preflight)
    preflight "${2:-io-eio}"
    ;;
  run)
    [[ -n "${2:-}" ]] || die "scenario is required"
    run_one "$2"
    ;;
  list)
    [[ -z "${2:-}" ]] || die "list does not accept arguments; run a named scenario with: fault-test.sh run <scenario>"
    list_scenarios
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
