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

# dm-error and the static-PV reset share one host path. The observer image
# has no dmsetup; absolute paths are resolved after nsenter, in the host
# mount namespace, so dd/e2fsck are the host binaries rather than busybox.
GATE_DM_PV="rg-dm-error-pv"
GATE_DM_PVC="rg-dm-error-claim"

rg_dm_safe_token() {
  [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]]
}

rg_dm_safe_path() {
  local path="$1"
  [[ "$path" =~ ^/[A-Za-z0-9._/-]+$ && "$path" != *..* && "$path" != *//* ]] || return 1
  local parts
  parts="$(awk -F/ '{print NF-1}' <<<"$path")"
  [[ "$parts" -ge 2 ]]
}

rg_dm_host_exec() {
  kubectl -n "$observer_ns" exec "$observer_pod" -- nsenter -t 1 -m -i -- "$@"
}

rg_dm_resolve() {
  local tool="$1" candidate
  for candidate in "/usr/sbin/$tool" "/sbin/$tool" "/usr/bin/$tool" "/bin/$tool"; do
    if rg_dm_host_exec test -x "$candidate"; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  echo "host nsenter cannot find ${tool}" >&2
  return 1
}

rg_dm_setup() {
  name="${RUSTFS_FAULT_TEST_DM_NAME:-}"
  node="${RUSTFS_FAULT_TEST_DM_NODE:-}"
  observer_ns="${RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE:-}"
  observer_pod="${RUSTFS_FAULT_TEST_DM_OBSERVER_POD:-}"
  mount_path="${RUSTFS_FAULT_TEST_DM_MOUNT_PATH:-}"
  dm_class="${RUSTFS_RELEASE_GATE_DM_STORAGE_CLASS:-}"
  if [[ -z "$name" || -z "$node" || -z "$observer_ns" || -z "$observer_pod" || -z "$mount_path" || -z "$dm_class" ]]; then
    echo "device-mapper evidence requires RUSTFS_FAULT_TEST_DM_NAME, DM_NODE, DM_MOUNT_PATH, DM_OBSERVER_NAMESPACE, DM_OBSERVER_POD, and RUSTFS_RELEASE_GATE_DM_STORAGE_CLASS" >&2
    return 1
  fi
  rg_dm_safe_token "$name" && rg_dm_safe_token "$node" && rg_dm_safe_token "$observer_ns" \
    && rg_dm_safe_token "$observer_pod" && rg_dm_safe_token "$dm_class" && rg_dm_safe_token "$namespace" \
    && rg_dm_safe_path "$mount_path" || {
    echo "refusing dm name, node, namespace, storage class, or mount path" >&2
    return 1
  }
  if [[ "${RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST:-}" != "/dev/mapper/${name}" ]]; then
    echo "RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST must be /dev/mapper/${name}" >&2
    return 1
  fi
  if ! command -v kubectl >/dev/null 2>&1 || ! command -v jq >/dev/null 2>&1; then
    echo "kubectl and jq are required for device-mapper evidence" >&2
    return 1
  fi
  dmsetup_bin="$(rg_dm_resolve dmsetup)"
  dd_bin="$(rg_dm_resolve dd)"
  sh_bin="$(rg_dm_resolve sh)"
  find_bin="$(rg_dm_resolve find)"
  dedicated_path="$(dirname "$mount_path")/rg-dm-error"
  if [[ "$dedicated_path" == "/rg-dm-error" ]] || ! rg_dm_safe_path "$dedicated_path"; then
    echo "refusing dedicated dm-error path ${dedicated_path}" >&2
    return 1
  fi
}

rg_dm_drop_caches() {
  if ! rg_dm_host_exec "$sh_bin" -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; then
    echo "drop_caches failed; reads still use O_DIRECT" >&2
  fi
}

# Suspend must use --nolockfs. A mounted filesystem whose device is already
# returning EIO makes the default lockfs freeze fail, and a resume error
# leaves the error target active.
rg_dm_transition() {
  local table="$1" err
  if ! err="$(rg_dm_host_exec "$dmsetup_bin" suspend --nolockfs "$name" 2>&1)"; then
    echo "dmsetup suspend --nolockfs ${name} failed: ${err}" >&2
    return 1
  fi
  if ! err="$(printf '%s\n' "$table" | kubectl -n "$observer_ns" exec -i "$observer_pod" -- nsenter -t 1 -m -i -- "$dmsetup_bin" load "$name" 2>&1)"; then
    echo "dmsetup load ${name} failed: ${err}" >&2
    return 1
  fi
  if ! err="$(rg_dm_host_exec "$dmsetup_bin" resume "$name" 2>&1)"; then
    echo "dmsetup resume ${name} failed: ${err}" >&2
    return 1
  fi
}

rg_dm_table_is() {
  local want="$1" got
  got="$(rg_dm_host_exec "$dmsetup_bin" table "$name")"
  [[ "$got" == "$want" ]]
}

rg_dm_remove_dedicated_dir() {
  local owners
  [[ -n "${dedicated_path:-}" ]] || return 0
  rg_dm_safe_path "$dedicated_path" || return 1
  [[ "$dedicated_path" == */rg-dm-error ]] || return 1
  owners="$(kubectl get pv -o json | jq -r --arg path "$dedicated_path" '
    [.items[] | select(.spec.local.path == $path)] | length
  ')"
  if [[ "$owners" != "0" ]]; then
    echo "refusing to remove ${dedicated_path}; a PersistentVolume still uses it" >&2
    return 1
  fi
  if rg_dm_host_exec test -d "$dedicated_path"; then
    rg_dm_host_exec rm -rf -- "$dedicated_path"
  fi
}

rg_dm_delete_gate_volume() {
  kubectl -n "$namespace" delete pvc "$GATE_DM_PVC" --ignore-not-found --wait=true
  kubectl delete pv "$GATE_DM_PV" --ignore-not-found --wait=true
  rg_dm_remove_dedicated_dir
}

# A Retain PV stays Released after the claim is gone. Clearing claimRef makes
# it Available again. Only 100Gi volumes of the DM class are touched, so the
# 1Gi gate PV cannot consume one of the four static volumes.
rg_dm_reset_released() {
  local rows pv path parts still
  kubectl -n "$namespace" delete pvc "$GATE_DM_PVC" --ignore-not-found --wait=true
  still=1
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    still="$(kubectl get pv -o json | jq -r --arg ns "$namespace" --arg claim "$GATE_DM_PVC" '
      [.items[]
        | select(.spec.claimRef.namespace == $ns and .spec.claimRef.name == $claim)
        | select(.status.phase == "Bound")
        | select(.metadata.name != "rg-dm-error-pv")]
      | length
    ')"
    [[ "$still" == "0" ]] && break
    sleep 1
  done
  if [[ "$still" != "0" ]]; then
    echo "PVC ${GATE_DM_PVC} is still bound to a static PV" >&2
    return 1
  fi
  kubectl delete pv "$GATE_DM_PV" --ignore-not-found --wait=true
  rows="$(kubectl get pv -o json | jq -r --arg class "$dm_class" '
    .items[]
    | select(.spec.storageClassName == $class)
    | select(.status.phase == "Released")
    | select(.spec.capacity.storage == "100Gi")
    | select(.metadata.name != "rg-dm-error-pv")
    | select(.spec.local.path | type == "string")
    | [.metadata.name, .spec.local.path]
    | @tsv
  ')"
  while IFS=$'\t' read -r pv path; do
    [[ -z "${pv:-}" ]] && continue
    rg_dm_safe_token "$pv" || {
      echo "refusing to reset PV ${pv}" >&2
      return 1
    }
    rg_dm_safe_path "$path" || {
      echo "refusing to empty ${path}" >&2
      return 1
    }
    parts="$(awk -F/ '{print NF-1}' <<<"$path")"
    if [[ "$parts" -lt 3 ]]; then
      echo "refusing to empty short path ${path}" >&2
      return 1
    fi
    if rg_dm_host_exec test -d "$path"; then
      rg_dm_host_exec "$find_bin" "$path" -mindepth 1 -xdev -delete
    fi
    kubectl patch pv "$pv" --type=json -p='[{"op":"remove","path":"/spec/claimRef"}]'
  done <<<"$rows"
  rg_dm_remove_dedicated_dir
}

rg_dm_create_gate_volume() {
  local collision
  collision="$(kubectl get pv -o json | jq -r --arg path "$dedicated_path" --arg pv "$GATE_DM_PV" '
    [.items[] | select(.spec.local.path == $path) | select(.metadata.name != $pv)] | length
  ')"
  if [[ "$collision" != "0" ]]; then
    echo "dedicated path ${dedicated_path} is already a PersistentVolume" >&2
    return 1
  fi
  rg_dm_host_exec mkdir -p -- "$dedicated_path"
  kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${GATE_DM_PV}
  labels:
    app.kubernetes.io/managed-by: s3chaos
    s3chaos.rustfs.com/release-gate: dm-error
spec:
  capacity:
    storage: 1Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ${dm_class}
  local:
    path: ${dedicated_path}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - ${node}
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${GATE_DM_PVC}
  namespace: ${namespace}
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: ${dm_class}
  volumeName: ${GATE_DM_PV}
  resources:
    requests:
      storage: 1Gi
EOF
  local phase=""
  for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    phase="$(kubectl -n "$namespace" get pvc "$GATE_DM_PVC" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "$phase" == "Bound" ]] && return 0
    sleep 1
  done
  echo "PVC ${namespace}/${GATE_DM_PVC} did not bind (phase ${phase:-missing})" >&2
  return 1
}

rg_dm_write_marker() {
  local marker="$1"
  rg_dm_host_exec "$dd_bin" if=/dev/zero of="$marker" bs=4096 count=1 conv=fsync status=none
  rg_dm_host_exec "$sh_bin" -c 'printf "dm-error-marker\n" | "$1" of="$2" conv=notrunc,fsync status=none' _ "$dd_bin" "$marker"
}

rg_dm_direct_header() {
  local marker="$1"
  rg_dm_drop_caches
  # Print only the 15-byte header on the host. A pipe to local head would
  # SIGPIPE dd under pipefail, and bash cannot store the NUL padding.
  rg_dm_host_exec "$sh_bin" -c '
    tmp="/tmp/rg-dm-error-read.$$"
    if ! "$1" if="$2" of="$tmp" bs=4096 count=1 iflag=direct status=none; then
      rm -f "$tmp"
      exit 1
    fi
    "$1" if="$tmp" bs=15 count=1 status=none
    rc=$?
    rm -f "$tmp"
    exit "$rc"
  ' _ "$dd_bin" "$marker"
}

rg_dm_repair_mount() {
  local dev="/dev/mapper/${name}" fstype e2fsck repair mount_bin umount_bin blkid findmnt rc
  umount_bin="$(rg_dm_resolve umount)" || return 1
  mount_bin="$(rg_dm_resolve mount)" || return 1
  blkid="$(rg_dm_resolve blkid)" || return 1
  findmnt="$(rg_dm_resolve findmnt)" || return 1
  if rg_dm_host_exec "$findmnt" -n --target "$mount_path" >/dev/null 2>&1; then
    rg_dm_host_exec "$umount_bin" "$mount_path" || return 1
  fi
  fs_unmounted=true
  fstype="$(rg_dm_host_exec "$blkid" -o value -s TYPE "$dev")"
  if [[ "$fstype" == ext2 || "$fstype" == ext3 || "$fstype" == ext4 ]]; then
    e2fsck="$(rg_dm_resolve e2fsck)" || return 1
    # e2fsck exits 1 when it corrected errors and 2 when a reboot is advised.
    rc=0
    rg_dm_host_exec "$e2fsck" -fy "$dev" || rc=$?
    if [[ "$rc" -gt 2 ]]; then
      echo "e2fsck ${dev} exited ${rc}" >&2
      return 1
    fi
  elif [[ "$fstype" == "xfs" ]]; then
    repair="$(rg_dm_resolve xfs_repair)" || return 1
    rg_dm_host_exec "$repair" "$dev" || return 1
  else
    echo "refusing to repair filesystem type ${fstype:-unknown} on ${dev}" >&2
    return 1
  fi
  rg_dm_host_exec "$mount_bin" "$dev" "$mount_path" || return 1
  fs_unmounted=false
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

  reset-dm-pvs)
    rg_dm_setup
    rg_dm_reset_released
    ;;

  dm-error)
    rg_dm_setup
    rg_dm_reset_released
    fs_unmounted=false
    marker="${mount_path}/rg-dm-error-marker"
    cleanup_dm() {
      local status=$?
      trap - EXIT
      set +e
      if [[ -n "${original:-}" ]]; then
        rg_dm_transition "$original"
        if rg_dm_table_is "$original"; then
      if [[ "$fs_unmounted" == true ]]; then
        rg_dm_repair_mount || status=1
      fi
          rg_dm_host_exec rm -f "$marker"
        else
          echo "cleanup left ${name} off the original table" >&2
          status=1
        fi
      fi
      rg_dm_delete_gate_volume
      exit "$status"
    }
    trap cleanup_dm EXIT
    rg_dm_create_gate_volume
    original="$(rg_dm_host_exec "$dmsetup_bin" table "$name")"
    if [[ -z "$original" ]]; then
      echo "dmsetup table ${name} was empty" >&2
      exit 1
    fi
    sectors="$(awk '{print $2; exit}' <<<"$original")"
    if [[ ! "$sectors" =~ ^[0-9]+$ ]]; then
      echo "dmsetup table ${name} has no sector count: ${original}" >&2
      exit 1
    fi
    if ! rg_dm_write_marker "$marker"; then
      echo "failed to write ${marker} while the original table was active" >&2
      exit 1
    fi
    if ! rg_dm_transition "0 ${sectors} error"; then
      echo "failed to install the error target on ${name}" >&2
      exit 1
    fi
    injected="$(rg_dm_host_exec "$dmsetup_bin" table "$name")"
    table_has_error_target=false
    if [[ "$injected" == "0 ${sectors} error" ]]; then
      table_has_error_target=true
    fi
    # O_DIRECT does not satisfy the read from the page cache. A cached read
    # of a marker that was just written succeeds even when the error target
    # is active.
    rg_dm_drop_caches
    read_failed_during_fault=false
    if ! rg_dm_host_exec "$dd_bin" if="$marker" of=/dev/null bs=4096 count=1 iflag=direct status=none; then
      read_failed_during_fault=true
    fi
    recovered=false
    if rg_dm_transition "$original" && rg_dm_table_is "$original"; then
      got="$(rg_dm_direct_header "$marker" || true)"
      if [[ "$got" != "dm-error-marker" ]]; then
        rg_dm_repair_mount
        got="$(rg_dm_direct_header "$marker" || true)"
      fi
      if [[ "$got" == "dm-error-marker" ]]; then
        recovered=true
        rg_dm_host_exec rm -f "$marker"
      fi
    else
      echo "dmsetup table ${name} was not restored to the original map" >&2
    fi
    rg_dm_delete_gate_volume
    if [[ "$table_has_error_target" == true && "$read_failed_during_fault" == true && "$recovered" == true ]]; then
      trap - EXIT
    fi
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
