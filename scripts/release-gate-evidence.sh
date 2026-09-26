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
    work="$(mktemp -d "${artifact_dir}/qe.XXXXXX")"
    delete_chaos() {
      kubectl -n "$chaos_namespace" delete podchaos "$chaos_a" "$chaos_b" --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
    }
    cleanup_probe() {
      delete_chaos
      "$mc_bin" alias rm rg-warm >/dev/null 2>&1 || true
      "$mc_bin" alias rm rg-cold >/dev/null 2>&1 || true
      rm -rf "$work"
    }
    trap cleanup_probe EXIT
    # Aliases are created and checked before PodChaos. A failure here is a
    # tool error: do not write probe JSON, and do not write objects into the
    # repository working directory.
    setup_alias() {
      local name="$1" alias="$2" ip
      ip="$(kubectl -n "$namespace" get pod "$name" -o jsonpath='{.status.podIP}')"
      if [[ -z "$ip" ]]; then
        echo "pod ${name} has no IP; refusing to probe" >&2
        exit 1
      fi
      if ! "$mc_bin" alias set "$alias" "http://${ip}:9000" "$access_key" "$secret_key" >&2; then
        echo "mc alias set ${alias} failed before the fault" >&2
        exit 1
      fi
      if ! "$mc_bin" ls "$alias" >/dev/null; then
        echo "alias ${alias} cannot list the pod endpoint before the fault" >&2
        exit 1
      fi
    }
    setup_alias "$warm" rg-warm
    setup_alias "$cold" rg-cold
    printf 'quorum-edge-object' >"$work/object.bin"
    if ! "$mc_bin" mb --ignore-existing rg-warm/rg-qe >/dev/null; then
      echo "mc mb rg-warm/rg-qe failed before the fault" >&2
      exit 1
    fi
    if ! "$mc_bin" pipe rg-warm/rg-qe/object.bin <"$work/object.bin" >/dev/null; then
      echo "mc pipe of the quorum object failed before the fault" >&2
      exit 1
    fi
    if ! "$mc_bin" stat rg-warm/rg-qe/object.bin >/dev/null; then
      echo "mc stat of the quorum object failed before the fault" >&2
      exit 1
    fi
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
    read_ready() {
      local name="$1" dest="$2" status
      if ! status="$(kubectl -n "$namespace" get pod "$name" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')"; then
        echo "cannot read Ready condition for ${name}" >&2
        exit 1
      fi
      printf -v "$dest" '%s' "$status"
    }
    deadline=$((SECONDS + 90))
    while (( SECONDS < deadline )); do
      read_ready "$victim_a" ready_a
      read_ready "$victim_b" ready_b
      if [[ "$ready_a" != "True" && "$ready_b" != "True" ]]; then
        break
      fi
      sleep 2
    done
    read_ready "$victim_a" ready_a
    read_ready "$victim_b" ready_b
    if [[ "$ready_a" == "True" || "$ready_b" == "True" ]]; then
      echo "quorum-edge victims stayed Ready; probe JSON was not written" >&2
      exit 1
    fi
    tool_error() {
      local err="$1"
      # Alias and client setup failures abort the probe. An S3 404 or 503
      # stays a counted request failure so the JSON still records R1.
      grep -Eq 'alias .* not found|not a valid alias|Unable to initialize|Invalid URL' "$err"
    }
    probe_pod() {
      local name="$1" cold_flag="$2" dest="$3" alias ok attempted wrong put_rejected put_attempted live ready ip
      if [[ "$name" == "$warm" ]]; then
        alias="rg-warm"
      else
        alias="rg-cold"
      fi
      if ! "$mc_bin" alias list | grep -Eq "^${alias}([[:space:]]|$)"; then
        echo "alias ${alias} disappeared; refusing to record a probe" >&2
        exit 1
      fi
      ip="$(kubectl -n "$namespace" get pod "$name" -o jsonpath='{.status.podIP}')"
      ok=0
      attempted=5
      wrong=0
      local i
      for i in 1 2 3 4 5; do
        if "$mc_bin" cat "${alias}/rg-qe/object.bin" >"$work/got.bin" 2>"$work/get.err"; then
          if cmp -s "$work/object.bin" "$work/got.bin"; then
            ok=$((ok + 1))
          else
            wrong=$((wrong + 1))
          fi
        elif tool_error "$work/get.err"; then
          echo "mc cat tool error for ${alias}; refusing to record a probe" >&2
          cat "$work/get.err" >&2
          exit 1
        fi
      done
      put_rejected=0
      put_attempted=3
      for i in 1 2 3; do
        if "$mc_bin" pipe "${alias}/rg-qe/put-${name}-${i}" <"$work/object.bin" >/dev/null 2>"$work/put.err"; then
          :
        elif tool_error "$work/put.err"; then
          echo "mc pipe tool error for ${alias}; refusing to record a probe" >&2
          cat "$work/put.err" >&2
          exit 1
        else
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
      printf '{"name":"%s","cold_bucket":%s,"get_ok":%s,"get_attempted":%s,"wrong_sha256":%s,"put_rejected":%s,"put_attempted":%s,"health_live":%s,"health_ready":%s}\n' \
        "$name" "$cold_flag" "$ok" "$attempted" "$wrong" "$put_rejected" "$put_attempted" "$live" "$ready" >"$dest"
    }
    probe_pod "$warm" false "$work/warm.json"
    probe_pod "$cold" true "$work/cold.json"
    cat >"$artifact_dir/quorum-edge-cold-read.json" <<EOF
{"survivors":[$(cat "$work/warm.json"),$(cat "$work/cold.json")]}
EOF
    cleanup_probe
    trap - EXIT
    ;;

  dm-error)
    name="${RUSTFS_FAULT_TEST_DM_NAME:-}"
    node="${RUSTFS_FAULT_TEST_DM_NODE:-}"
    observer_ns="${RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE:-}"
    observer_pod="${RUSTFS_FAULT_TEST_DM_OBSERVER_POD:-}"
    mount_path="${RUSTFS_FAULT_TEST_DM_MOUNT_PATH:-}"
    if [[ -z "$name" || -z "$node" || -z "$observer_ns" || -z "$observer_pod" || -z "$mount_path" ]]; then
      echo "dm-error requires RUSTFS_FAULT_TEST_DM_NAME, DM_NODE, DM_MOUNT_PATH, DM_OBSERVER_NAMESPACE, and DM_OBSERVER_POD" >&2
      exit 1
    fi
    if [[ ! "$mount_path" =~ ^/[A-Za-z0-9._/-]+$ || ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
      echo "refusing dm name ${name} or mount path ${mount_path}" >&2
      exit 1
    fi
    if ! command -v kubectl >/dev/null 2>&1; then
      echo "kubectl is required for dm-error" >&2
      exit 1
    fi
    bound=0
    while IFS=$'\t' read -r phase claim path; do
      if [[ "$phase" == "Bound" && "$claim" == "$namespace" && "$path" == "$mount_path" ]]; then
        bound=$((bound + 1))
      fi
    done < <(kubectl get pv -o jsonpath='{range .items[*]}{.status.phase}{"\t"}{.spec.claimRef.namespace}{"\t"}{.spec.local.path}{"\n"}{end}')
    if [[ "$bound" -lt 1 ]]; then
      echo "no Bound PV with local path ${mount_path} is claimed by namespace ${namespace}" >&2
      exit 1
    fi
    # The observer image is busybox and has no dmsetup. The host does.
    host_exec() {
      kubectl -n "$observer_ns" exec "$observer_pod" -- nsenter -t 1 -m -i -- "$@"
    }
    dmsetup_bin="/usr/sbin/dmsetup"
    if ! host_exec test -x "$dmsetup_bin"; then
      if host_exec test -x /sbin/dmsetup; then
        dmsetup_bin="/sbin/dmsetup"
      else
        echo "host nsenter cannot find dmsetup; the observer image does not provide it" >&2
        exit 1
      fi
    fi
    dm() {
      host_exec "$dmsetup_bin" "$@"
    }
    original="$(dm table "$name")"
    if [[ -z "$original" ]]; then
      echo "dmsetup table ${name} was empty" >&2
      exit 1
    fi
    sectors="$(awk '{print $2; exit}' <<<"$original")"
    marker="${mount_path}/rg-dm-error-marker"
    if ! host_exec sh -c "printf 'dm-error-marker\n' > '${marker}'"; then
      echo "failed to write ${marker} while the original table was active" >&2
      exit 1
    fi
    restore_table() {
      printf '%s\n' "$original" | kubectl -n "$observer_ns" exec -i "$observer_pod" -- nsenter -t 1 -m -i -- "$dmsetup_bin" load "$name" >/dev/null
      dm resume "$name" >/dev/null 2>&1 || true
    }
    cleanup_dm() {
      restore_table
      host_exec rm -f "$marker" >/dev/null 2>&1 || true
    }
    trap cleanup_dm EXIT
    dm suspend "$name"
    printf '0 %s error\n' "$sectors" | kubectl -n "$observer_ns" exec -i "$observer_pod" -- nsenter -t 1 -m -i -- "$dmsetup_bin" load "$name"
    dm resume "$name"
    injected="$(dm table "$name")"
    table_has_error_target=false
    if [[ "$injected" == *"error"* ]]; then
      table_has_error_target=true
    fi
    # Read the marker while the error target is still active. A successful
    # read here means the fault did not land.
    read_failed_during_fault=false
    if ! host_exec dd if="$marker" of=/dev/null bs=4096 count=1 status=none >/dev/null 2>&1; then
      read_failed_during_fault=true
    fi
    restore_table
    restored="$(dm table "$name")"
    got="$(host_exec cat "$marker" 2>/dev/null || true)"
    recovered=false
    if [[ "$restored" == "$original" && "$got" == "dm-error-marker" ]]; then
      recovered=true
    fi
    host_exec rm -f "$marker" >/dev/null 2>&1 || true
    trap - EXIT
    cat >"$artifact_dir/dm-error.json" <<EOF
{"table_has_error_target":${table_has_error_target},"read_failed_during_fault":${read_failed_during_fault},"recovered":${recovered}}
EOF
    [[ "$table_has_error_target" == true && "$read_failed_during_fault" == true && "$recovered" == true ]]
    ;;

  *)
    echo "unknown evidence mode: ${mode}" >&2
    exit 1
    ;;
esac
