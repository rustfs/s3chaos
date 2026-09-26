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

# Producers for release-gate evidence files. Exit 1 is a failure.
# Missing tools and missing endpoints are failures, not skips.
set -euo pipefail

mode="${1:-}"
artifact_dir="${RELEASE_GATE_ARTIFACT_DIR:-target/release-gate/artifacts}"
namespace="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
tenant="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
chaos_namespace="${RUSTFS_FAULT_TEST_CHAOS_NAMESPACE:-chaos-mesh}"
endpoint="${RUSTFS_ENDPOINT:-}"
mc_bin="${MC_BIN:-mc}"
access_key="${AWS_ACCESS_KEY_ID:-rustfsadmin}"
secret_key="${AWS_SECRET_ACCESS_KEY:-rustfsadmin}"
mkdir -p "$artifact_dir"

require_mc() {
  if ! command -v "$mc_bin" >/dev/null 2>&1; then
    echo "mc is required to produce ${mode} evidence" >&2
    exit 1
  fi
  if [[ -z "$endpoint" ]]; then
    echo "RUSTFS_ENDPOINT is required to produce ${mode} evidence" >&2
    exit 1
  fi
}

health_code() {
  local url="$1" code
  code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$url" 2>/dev/null || true)"
  if [[ ! "$code" =~ ^[0-9]+$ ]]; then
    code=0
  fi
  printf '%s\n' "$code"
}

case "$mode" in
  fresh-install)
    if [[ -z "$endpoint" ]]; then
      echo "RUSTFS_ENDPOINT is required for fresh-install" >&2
      exit 1
    fi
    if ! command -v curl >/dev/null 2>&1; then
      echo "curl is required for fresh-install" >&2
      exit 1
    fi
    health="$(health_code "${endpoint%/}/health")"
    if [[ "$health" != "200" ]]; then
      health="$(health_code "${endpoint%/}/minio/health/live")"
    fi
    live="$(health_code "${endpoint%/}/health/live")"
    if [[ "$live" != "200" ]]; then
      live="$(health_code "${endpoint%/}/minio/health/live")"
    fi
    image_matches=true
    if [[ -n "${RUSTFS_IMAGE:-}" ]] && command -v kubectl >/dev/null 2>&1; then
      images="$(kubectl -n "$namespace" get pods -l "rustfs.tenant=${tenant}" -o jsonpath='{range .items[*]}{.spec.containers[0].image}{"\n"}{end}' 2>/dev/null || true)"
      if [[ -z "$images" ]] || grep -qv -x "${RUSTFS_IMAGE}" <<<"$images"; then
        image_matches=false
      fi
    elif [[ -n "${RUSTFS_IMAGE:-}" ]]; then
      image_matches=false
    fi
    cat >"$artifact_dir/fresh-install.json" <<EOF
{"health":${health},"live":${live},"image_matches":${image_matches}}
EOF
    [[ "$health" == "200" && "$live" == "200" && "$image_matches" == true ]]
    ;;

  large-object-get)
    require_mc
    alias_name="rg-large"
    "$mc_bin" alias set "$alias_name" "$endpoint" "$access_key" "$secret_key" >/dev/null
    "$mc_bin" mb --ignore-existing "$alias_name/rg-large" >/dev/null
    dd if=/dev/urandom of="$artifact_dir/large.bin" bs=1M count=8 status=none
    expected_len="$(wc -c <"$artifact_dir/large.bin" | tr -d ' ')"
    expected_sha="$(sha256sum "$artifact_dir/large.bin" | awk '{print $1}')"
    "$mc_bin" cp "$artifact_dir/large.bin" "$alias_name/rg-large/large.bin" >/dev/null
    "$mc_bin" cp "$alias_name/rg-large/large.bin" "$artifact_dir/large.got" >/dev/null
    actual_len="$(wc -c <"$artifact_dir/large.got" | tr -d ' ')"
    actual_sha="$(sha256sum "$artifact_dir/large.got" | awk '{print $1}')"
    cat >"$artifact_dir/large-object-get.json" <<EOF
{"expected_len":${expected_len},"actual_len":${actual_len},"expected_sha256":"${expected_sha}","actual_sha256":"${actual_sha}"}
EOF
    [[ "$expected_len" == "$actual_len" && "$expected_sha" == "$actual_sha" ]]
    ;;

  lifecycle)
    require_mc
    alias_name="rg-ilm"
    "$mc_bin" alias set "$alias_name" "$endpoint" "$access_key" "$secret_key" >/dev/null
    "$mc_bin" mb --ignore-existing "$alias_name/rg-ilm-gate" >/dev/null
    printf 'lifecycle-body' >"$artifact_dir/lifecycle-object.bin"
    "$mc_bin" cp "$artifact_dir/lifecycle-object.bin" "$alias_name/rg-ilm-gate/object.bin" >/dev/null
    cat >"$artifact_dir/lifecycle-import.json" <<'EOF'
{"Rules":[{"ID":"rg-expire","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":30}}]}
EOF
    rule_accepted=false
    if "$mc_bin" ilm import "$alias_name/rg-ilm-gate" <"$artifact_dir/lifecycle-import.json" >/dev/null; then
      rule_accepted=true
    fi
    listed_enabled=false
    if "$mc_bin" ilm ls "$alias_name/rg-ilm-gate" | grep -q rg-expire; then
      listed_enabled=true
    fi
    get_matches=false
    if "$mc_bin" cp "$alias_name/rg-ilm-gate/object.bin" "$artifact_dir/lifecycle-object.got" >/dev/null && \
      cmp -s "$artifact_dir/lifecycle-object.bin" "$artifact_dir/lifecycle-object.got"; then
      get_matches=true
    fi
    cat >"$artifact_dir/lifecycle-rule.json" <<EOF
{"rule_accepted":${rule_accepted},"listed_enabled":${listed_enabled},"get_matches":${get_matches}}
EOF
    [[ "$rule_accepted" == true && "$listed_enabled" == true && "$get_matches" == true ]]
    ;;

  quorum-edge)
    require_mc
    if ! command -v kubectl >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
      echo "kubectl and curl are required for the quorum-edge probe" >&2
      exit 1
    fi
    mapfile -t pods < <(kubectl -n "$namespace" get pods -l "rustfs.tenant=${tenant}" --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' | sort)
    if [[ "${#pods[@]}" -lt 4 ]]; then
      echo "quorum-edge needs 4 Running tenant pods, found ${#pods[@]}" >&2
      exit 1
    fi
    warm="${pods[0]}"
    cold="${pods[1]}"
    victim_a="${pods[2]}"
    victim_b="${pods[3]}"
    chaos_a="rg-qe-${victim_a}"
    chaos_b="rg-qe-${victim_b}"
    delete_chaos() {
      kubectl -n "$chaos_namespace" delete podchaos "$chaos_a" "$chaos_b" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    }
    trap delete_chaos EXIT
    warm_ip="$(kubectl -n "$namespace" get pod "$warm" -o jsonpath='{.status.podIP}')"
    "$mc_bin" alias set rg-warm "http://${warm_ip}:9000" "$access_key" "$secret_key" >/dev/null
    "$mc_bin" mb --ignore-existing rg-warm/rg-qe >/dev/null
    printf 'quorum-edge-object' >"$artifact_dir/qe-object.bin"
    "$mc_bin" cp "$artifact_dir/qe-object.bin" rg-warm/rg-qe/object.bin >/dev/null
    for victim in "$victim_a" "$victim_b"; do
      name="rg-qe-${victim}"
      kubectl -n "$chaos_namespace" apply -f - <<EOF
apiVersion: chaos-mesh.org/v1alpha1
kind: PodChaos
metadata:
  name: ${name}
  namespace: ${chaos_namespace}
spec:
  action: pod-failure
  mode: one
  selector:
    pods:
      ${namespace}:
        - ${victim}
  duration: "180s"
  gracePeriod: 0
EOF
    done
    sleep 5
    probe_pod() {
      local name="$1" cold_flag="$2" ip alias ok attempted wrong put_rejected put_attempted live ready
      ip="$(kubectl -n "$namespace" get pod "$name" -o jsonpath='{.status.podIP}')"
      alias="rg-probe-${name}"
      "$mc_bin" alias set "$alias" "http://${ip}:9000" "$access_key" "$secret_key" >/dev/null
      ok=0
      attempted=5
      wrong=0
      local i
      for i in 1 2 3 4 5; do
        if "$mc_bin" cp "$alias/rg-qe/object.bin" "$artifact_dir/qe-got.bin" >/dev/null 2>&1; then
          if cmp -s "$artifact_dir/qe-object.bin" "$artifact_dir/qe-got.bin"; then
            ok=$((ok + 1))
          else
            wrong=$((wrong + 1))
          fi
        fi
      done
      put_rejected=0
      put_attempted=3
      for i in 1 2 3; do
        if ! "$mc_bin" cp "$artifact_dir/qe-object.bin" "$alias/rg-qe/put-${name}-${i}" >/dev/null 2>&1; then
          put_rejected=$((put_rejected + 1))
        fi
      done
      live="$(health_code "http://${ip}:9000/health/live")"
      if [[ "$live" != "200" ]]; then
        live="$(health_code "http://${ip}:9000/minio/health/live")"
      fi
      ready="$(health_code "http://${ip}:9000/health/ready")"
      if [[ "$ready" == "000" || "$ready" == "0" ]]; then
        ready="$(health_code "http://${ip}:9000/minio/health/ready")"
      fi
      printf '{"name":"%s","cold_bucket":%s,"get_ok":%s,"get_attempted":%s,"wrong_sha256":%s,"put_rejected":%s,"put_attempted":%s,"health_live":%s,"health_ready":%s}' \
        "$name" "$cold_flag" "$ok" "$attempted" "$wrong" "$put_rejected" "$put_attempted" "$live" "$ready"
    }
    warm_json="$(probe_pod "$warm" false)"
    cold_json="$(probe_pod "$cold" true)"
    cat >"$artifact_dir/quorum-edge-cold-read.json" <<EOF
{"survivors":[${warm_json},${cold_json}]}
EOF
    delete_chaos
    trap - EXIT
    ;;

  dm-error)
    name="${RUSTFS_FAULT_TEST_DM_NAME:-}"
    node="${RUSTFS_FAULT_TEST_DM_NODE:-}"
    observer_ns="${RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE:-}"
    observer_pod="${RUSTFS_FAULT_TEST_DM_OBSERVER_POD:-}"
    if [[ -z "$name" || -z "$node" || -z "$observer_ns" || -z "$observer_pod" ]]; then
      echo "dm-error requires RUSTFS_FAULT_TEST_DM_NAME, DM_NODE, DM_OBSERVER_NAMESPACE, and DM_OBSERVER_POD" >&2
      exit 1
    fi
    if ! command -v kubectl >/dev/null 2>&1; then
      echo "kubectl is required for dm-error" >&2
      exit 1
    fi
    dm() {
      kubectl -n "$observer_ns" exec "$observer_pod" -- dmsetup "$@"
    }
    original="$(dm table "$name")"
    if [[ -z "$original" ]]; then
      echo "dmsetup table ${name} was empty" >&2
      exit 1
    fi
    sectors="$(awk '{print $2; exit}' <<<"$original")"
    restore_table() {
      printf '%s\n' "$original" | kubectl -n "$observer_ns" exec -i "$observer_pod" -- dmsetup load "$name" >/dev/null
      dm resume "$name" >/dev/null 2>&1 || true
    }
    trap restore_table EXIT
    dm suspend "$name"
    printf '0 %s error\n' "$sectors" | kubectl -n "$observer_ns" exec -i "$observer_pod" -- dmsetup load "$name"
    dm resume "$name"
    injected="$(dm table "$name")"
    table_has_error_target=false
    if [[ "$injected" == *"error"* ]]; then
      table_has_error_target=true
    fi
    restore_table
    trap - EXIT
    restored="$(dm table "$name")"
    recovered=false
    if [[ "$restored" == "$original" ]]; then
      recovered=true
    fi
    reads_survived=false
    if dm status "$name" >/dev/null 2>&1; then
      reads_survived=true
    fi
    mount_path="${RUSTFS_FAULT_TEST_DM_MOUNT_PATH:-}"
    if [[ -n "$mount_path" ]]; then
      reads_survived=false
      if kubectl -n "$observer_ns" exec "$observer_pod" -- dd if="$mount_path" of=/dev/null bs=4096 count=1 status=none >/dev/null 2>&1; then
        reads_survived=true
      fi
    fi
    cat >"$artifact_dir/dm-error.json" <<EOF
{"table_has_error_target":${table_has_error_target},"reads_survived":${reads_survived},"recovered":${recovered}}
EOF
    [[ "$table_has_error_target" == true && "$recovered" == true ]]
    ;;

  *)
    echo "unknown evidence mode: ${mode}" >&2
    exit 1
    ;;
esac
