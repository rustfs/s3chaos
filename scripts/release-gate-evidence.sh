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

rg_dm_resolve_optional() {
  local tool="$1" candidate
  for candidate in "/usr/sbin/$tool" "/sbin/$tool" "/usr/bin/$tool" "/bin/$tool"; do
    if rg_dm_host_exec test -x "$candidate" >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

rg_dm_resolve() {
  local path
  if path="$(rg_dm_resolve_optional "$1")"; then
    printf '%s\n' "$path"
    return 0
  fi
  echo "host nsenter cannot find ${1}" >&2
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

# sync here is only safe after the original table is back. Calling it while
# the error target is loaded writes dirty metadata into that target and
# aborts the ext4 journal.
rg_dm_drop_caches() {
  if ! rg_dm_host_exec "$sh_bin" -c 'sync; echo 3 > /proc/sys/vm/drop_caches'; then
    echo "drop_caches failed; reads still use O_DIRECT" >&2
  fi
}

rg_dm_drop_page_cache() {
  if ! rg_dm_host_exec "$sh_bin" -c 'echo 3 > /proc/sys/vm/drop_caches'; then
    echo "drop_caches failed; the direct read still uses O_DIRECT" >&2
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

# dmsetup table prints "0 <sectors> error " with a trailing space. Field 3 is
# the target type either way. Field 2 is the sector count.
rg_dm_table_field() {
  awk -v n="$2" '{print $n; exit}' <<<"$1"
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
  # A missing directory makes kubectl exec exit 1. That is not a failure.
  if rg_dm_host_exec test -d "$dedicated_path" >/dev/null 2>&1; then
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
  local failed=0
  while IFS=$'\t' read -r pv path; do
    [[ -z "${pv:-}" ]] && continue
    if ! rg_dm_safe_token "$pv"; then
      echo "refusing to reset PV ${pv}" >&2
      failed=1
      continue
    fi
    if ! rg_dm_safe_path "$path"; then
      echo "refusing to empty ${path}" >&2
      failed=1
      continue
    fi
    parts="$(awk -F/ '{print NF-1}' <<<"$path")"
    if [[ "$parts" -lt 3 ]]; then
      echo "refusing to empty short path ${path}" >&2
      failed=1
      continue
    fi
    # Keep lost+found. Deleting it makes the next e2fsck offer to create it.
    # One volume returning EIO must not skip the remaining PVs. Leave its
    # claimRef in place so a half-emptied device is not marked Available.
    if rg_dm_host_exec test -d "$path" >/dev/null 2>&1; then
      if ! rg_dm_host_exec "$find_bin" "$path" -mindepth 1 -xdev ! -name lost+found -delete; then
        echo "failed to empty ${path}" >&2
        failed=1
        continue
      fi
    fi
    if ! kubectl patch pv "$pv" --type=json -p='[{"op":"remove","path":"/spec/claimRef"}]'; then
      echo "failed to clear claimRef on ${pv}" >&2
      failed=1
    fi
  done <<<"$rows"
  if ! rg_dm_remove_dedicated_dir; then
    failed=1
  fi
  [[ "$failed" == 0 ]]
}

# A dm-run tenant that still holds the 100Gi static PVs must be removed before
# claimRef can be cleared. Only a tenant whose pool uses this storage class,
# and PVCs in the fault namespace, are deleted. The namespace itself stays.
rg_dm_release_bound() {
  local bound uses holders claim still
  rg_dm_safe_token "$tenant" || {
    echo "refusing tenant name" >&2
    return 1
  }
  bound="$(kubectl get pv -o json | jq -r --arg class "$dm_class" '
    [.items[]
      | select(.spec.storageClassName == $class)
      | select(.spec.capacity.storage == "100Gi")
      | select(.metadata.name != "rg-dm-error-pv")
      | select(.status.phase == "Bound")]
    | length
  ')"
  if [[ "$bound" == "0" ]]; then
    return 0
  fi
  uses="$(kubectl -n "$namespace" get tenant "$tenant" -o json 2>/dev/null | jq -r --arg class "$dm_class" '
    [.spec.pools[]?.persistence.volumeClaimTemplate.storageClassName] | any(. == $class)
  ' || true)"
  holders="$(kubectl -n "$namespace" get pvc -l "rustfs.tenant=${tenant}" -o json 2>/dev/null | jq -r --arg class "$dm_class" '
    [.items[] | select(.spec.storageClassName == $class)] | length
  ' || true)"
  if [[ "$uses" == "true" || ( "$holders" =~ ^[0-9]+$ && "$holders" -gt 0 ) ]]; then
    echo "deleting Tenant ${namespace}/${tenant}; it holds ${dm_class} volumes" >&2
    kubectl -n "$namespace" delete tenant "$tenant" --ignore-not-found --wait=false
    kubectl -n "$namespace" delete statefulset,pod,pvc,svc -l "rustfs.tenant=${tenant}" --ignore-not-found --wait=false
  fi
  for _ in $(seq 1 90); do
    still="$(kubectl get pv -o json | jq -r --arg class "$dm_class" '
      [.items[]
        | select(.spec.storageClassName == $class)
        | select(.spec.capacity.storage == "100Gi")
        | select(.metadata.name != "rg-dm-error-pv")
        | select(.status.phase == "Bound")]
      | length
    ')" || still=1
    [[ "$still" == "0" ]] && return 0
    # The operator can recreate a PVC until the Tenant is gone. Delete only
    # claims in the fault namespace, and give up if they are still Bound.
    while IFS= read -r claim; do
      [[ -z "${claim:-}" ]] && continue
      rg_dm_safe_token "$claim" || {
        echo "refusing to delete PVC ${claim}" >&2
        return 1
      }
      kubectl -n "$namespace" delete pvc "$claim" --ignore-not-found --wait=false
    done < <(kubectl get pv -o json | jq -r --arg class "$dm_class" --arg ns "$namespace" '
      .items[]
      | select(.spec.storageClassName == $class)
      | select(.spec.capacity.storage == "100Gi")
      | select(.metadata.name != "rg-dm-error-pv")
      | select(.status.phase == "Bound")
      | select(.spec.claimRef.namespace == $ns)
      | .spec.claimRef.name
    ')
    sleep 2
  done
  echo "DM storage class ${dm_class} still has Bound 100Gi volumes" >&2
  return 1
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

# --mountpoint is exact. --target walks up to the parent filesystem, so an
# already-unmounted lab path looks mounted and umount then fails with exit 32.
rg_dm_mounted_source() {
  local findmnt src
  findmnt="$(rg_dm_resolve findmnt)" || return 1
  src="$(rg_dm_host_exec "$findmnt" -n -o SOURCE --mountpoint "$mount_path" 2>/dev/null || true)"
  src="${src//[[:space:]]/}"
  printf '%s\n' "$src"
}

rg_dm_exact_mount() {
  [[ "$(rg_dm_mounted_source)" == "/dev/mapper/${name}" ]]
}

rg_dm_open_count() {
  local info
  info="$(rg_dm_host_exec "$dmsetup_bin" info -c -o open --noheadings "$name" 2>/dev/null || true)"
  info="${info//[[:space:]]/}"
  if [[ "$info" =~ ^[0-9]+$ ]]; then
    printf '%s\n' "$info"
    return 0
  fi
  echo "dmsetup info open count for ${name} was ${info:-empty}" >&2
  return 1
}

# Prints dev, mount point, shared id, and master id, separated by ASCII 0x1f.
# shared and master are empty when that optional field is absent.
# Returns 1 when the line is not a mountinfo record.
rg_dm_mountinfo_ids() {
  local line="$1"
  local -a tok
  local n i dev point shared="" master=""
  [[ -n "$line" ]] || return 1
  read -r -a tok <<<"$line"
  n=${#tok[@]}
  # id, parent, maj:min, root, mount point, options, then optional fields and '-'.
  [[ "$n" -ge 7 ]] || return 1
  dev="${tok[2]}"
  point="${tok[4]}"
  [[ "$dev" =~ ^[0-9]+:[0-9]+$ ]] || return 1
  for ((i = 6; i < n; i++)); do
    [[ "${tok[$i]}" == "-" ]] && break
    case "${tok[$i]}" in
      shared:[0-9]*)
        shared="${tok[$i]#shared:}"
        [[ "$shared" =~ ^[0-9]+$ ]] || shared=""
        ;;
      master:[0-9]*)
        master="${tok[$i]#master:}"
        [[ "$master" =~ ^[0-9]+$ ]] || master=""
        ;;
    esac
  done
  # Unit separator, not tab: a blank shared id must not swallow master.
  printf '%s\037%s\037%s\037%s\n' "$dev" "$point" "$shared" "$master"
}

# Returns 0 when some mount namespace other than PID 1 has this major:minor
# as a real holder. Returns 1 when the scan finishes without one.
# Returns 2 when the scan cannot be trusted.
# $3 is the host mount path. A slave whose master:N equals the host mount's
# shared:N, and whose mount point is that path or a directory under it,
# disappears when the host unmounts (systemd PrivateTmp/ProtectSystem copies).
# It is not a holder. A kubepods cgroup is a holder even for that slave shape,
# because a hostPath volume with HostToContainer propagation uses the same
# master id. Field 3 is the only major:minor; later fields are not.
rg_dm_proc_has_foreign_mount() {
  local majmin="$1" proc_root="$2" host_path="$3"
  local host_ns pid_dir pid ns host_shared="" found_host=false
  local line parsed dev point shared master saw slave_only
  [[ "$majmin" =~ ^[0-9]+:[0-9]+$ ]] || return 2
  [[ "$host_path" == /* && "$host_path" != *" "* && "$host_path" != *"/" ]] || return 2
  host_ns="$(readlink "${proc_root}/1/ns/mnt" 2>/dev/null || true)"
  [[ -n "$host_ns" ]] || return 2
  [[ -r "${proc_root}/1/mountinfo" ]] || return 2
  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    parsed="$(rg_dm_mountinfo_ids "$line" || true)"
    [[ -n "$parsed" ]] || continue
    IFS=$'\037' read -r dev point shared master <<<"$parsed"
    if [[ "$dev" == "$majmin" && "$point" == "$host_path" ]]; then
      found_host=true
      host_shared="$shared"
      break
    fi
  done <"${proc_root}/1/mountinfo"
  [[ "$found_host" == true ]] || return 2
  for pid_dir in "${proc_root}"/[0-9]*; do
    pid="${pid_dir##*/}"
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    [[ "$pid" == 1 ]] && continue
    ns="$(readlink "${pid_dir}/ns/mnt" 2>/dev/null || true)"
    [[ -n "$ns" && "$ns" != "$host_ns" ]] || continue
    [[ -r "${pid_dir}/mountinfo" ]] || continue
    saw=false
    slave_only=true
    while IFS= read -r line || [[ -n "${line:-}" ]]; do
      parsed="$(rg_dm_mountinfo_ids "$line" || true)"
      [[ -n "$parsed" ]] || continue
      IFS=$'\037' read -r dev point shared master <<<"$parsed"
      [[ "$dev" == "$majmin" ]] || continue
      saw=true
      if [[ -n "$host_shared" && "$master" == "$host_shared" && ( "$point" == "$host_path" || "$point" == "$host_path"/* ) ]]; then
        continue
      fi
      slave_only=false
      break
    done <"${pid_dir}/mountinfo"
    [[ "$saw" == true ]] || continue
    # Only propagated slaves remain. An unreadable cgroup cannot prove the
    # process is outside kubepods, so it stays a holder.
    if [[ "$slave_only" == false ]] || [[ ! -r "${pid_dir}/cgroup" ]] || grep -q kubepods "${pid_dir}/cgroup"; then
      echo "device ${majmin} is mounted in mount namespace ${ns} (pid ${pid})" >&2
      return 0
    fi
  done
  return 1
}

# Stdout is in-use, clear, or error. The exit status is always 0 so a clear
# scan is not reported as "command terminated with exit code 1".
rg_dm_foreign_scan_token() {
  local rc=0
  rg_dm_proc_has_foreign_mount "$@" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    printf '%s\n' in-use
  elif [[ "$rc" -eq 1 ]]; then
    printf '%s\n' clear
  else
    printf '%s\n' error
  fi
}

rg_dm_majmin() {
  local findmnt majmin
  findmnt="$(rg_dm_resolve findmnt)" || return 1
  majmin="$(rg_dm_host_exec "$findmnt" -n -o MAJ:MIN --mountpoint "$mount_path" 2>/dev/null || true)"
  majmin="${majmin//[[:space:]]/}"
  [[ "$majmin" =~ ^[0-9]+:[0-9]+$ ]] || return 1
  printf '%s\n' "$majmin"
}

# hostPath and other bind mounts live in a different mount namespace. They
# share the superblock, so the host open count stays 1 and findmnt -S on
# the host does not list them.
rg_dm_foreign_mount() {
  local majmin="$1" bash_bin body line rc=0
  bash_bin="$(rg_dm_resolve_optional bash)" || bash_bin="$(rg_dm_resolve_optional sh)" || return 2
  body="$(declare -f rg_dm_mountinfo_ids rg_dm_proc_has_foreign_mount rg_dm_foreign_scan_token)"
  # The host command exits 0. clear used to be exit 1, and kubectl then
  # printed "command terminated with exit code 1" twice per dm-error run.
  line="$(
    rg_dm_host_exec "$bash_bin" -c "${body}
rg_dm_foreign_scan_token \"\$1\" /proc \"\$2\"" _ "$majmin" "$mount_path"
  )" || rc=$?
  if [[ "$rc" != 0 ]]; then
    echo "mount namespace scan failed" >&2
    return 2
  fi
  case "$line" in
    in-use) return 0 ;;
    clear) return 1 ;;
    *)
      echo "mount namespace scan returned ${line:-empty}" >&2
      return 2
      ;;
  esac
}

# The host fixture mount accounts for one open. A pod mount, a foreign
# mount namespace, or a second holder means the volume is in use.
# Returns 0 when the caller must skip.
rg_dm_target_in_use() {
  local bound opens findmnt target extra=false majmin foreign
  bound="$(kubectl get pv -o json | jq -r --arg path "$mount_path" --arg class "$dm_class" '
    [.items[]
      | select(.spec.storageClassName == $class)
      | select(.spec.capacity.storage == "100Gi")
      | select(.spec.local.path == $path)
      | select(.status.phase == "Bound")]
    | length
  ')"
  if [[ "$bound" != "0" ]]; then
    echo "PersistentVolume for ${mount_path} is Bound" >&2
    return 0
  fi
  findmnt="$(rg_dm_resolve findmnt)" || return 0
  while IFS= read -r target; do
    [[ -z "${target:-}" ]] && continue
    if [[ "$target" != "$mount_path" ]]; then
      echo "device /dev/mapper/${name} is also mounted at ${target}" >&2
      extra=true
    fi
  done < <(rg_dm_host_exec "$findmnt" -n -o TARGET -S "/dev/mapper/${name}" 2>/dev/null || true)
  if [[ "$extra" == true ]]; then
    return 0
  fi
  opens="$(rg_dm_open_count)" || return 0
  if [[ "$opens" -gt 1 ]]; then
    echo "device-mapper ${name} open count is ${opens}" >&2
    return 0
  fi
  if ! majmin="$(rg_dm_majmin)"; then
    echo "cannot read major:minor for ${mount_path}" >&2
    return 0
  fi
  set +e
  rg_dm_foreign_mount "$majmin"
  foreign=$?
  set -e
  if [[ "$foreign" != 1 ]]; then
    return 0
  fi
  return 1
}

# Commit dirty metadata before the error target exists. A sync after that
# load writes the journal onto the error target and the filesystem goes
# read-only while the marker blocks can still be read.
rg_dm_flush_before_fault() {
  local dev="/dev/mapper/${name}" freeze blockdev err
  rg_dm_host_exec "$sh_bin" -c 'sync' || return 1
  if freeze="$(rg_dm_resolve_optional fsfreeze)"; then
    if ! err="$(rg_dm_host_exec "$freeze" --freeze "$mount_path" 2>&1)"; then
      echo "fsfreeze --freeze ${mount_path} failed: ${err}" >&2
      return 1
    fi
    fs_frozen=true
    if ! err="$(rg_dm_host_exec "$freeze" --unfreeze "$mount_path" 2>&1)"; then
      echo "fsfreeze --unfreeze ${mount_path} failed: ${err}" >&2
      if rg_dm_host_exec "$freeze" --unfreeze "$mount_path" >/dev/null 2>&1; then
        fs_frozen=false
      fi
      return 1
    fi
    fs_frozen=false
  fi
  if blockdev="$(rg_dm_resolve_optional blockdev)"; then
    if ! err="$(rg_dm_host_exec "$blockdev" --flushbufs "$dev" 2>&1)"; then
      echo "blockdev --flushbufs ${dev} failed: ${err}" >&2
      return 1
    fi
  elif [[ -z "${freeze:-}" ]]; then
    echo "neither fsfreeze nor blockdev is available to flush ${dev}" >&2
    return 1
  fi
  rg_dm_host_exec "$sh_bin" -c 'sync' || return 1
}

rg_dm_unfreeze() {
  local freeze err
  [[ "${fs_frozen:-false}" == true ]] || return 0
  freeze="$(rg_dm_resolve_optional fsfreeze)" || return 1
  if ! err="$(rg_dm_host_exec "$freeze" --unfreeze "$mount_path" 2>&1)"; then
    echo "fsfreeze --unfreeze ${mount_path} failed: ${err}" >&2
    return 1
  fi
  fs_frozen=false
}

# $1 is mount options. A bare "ro" token means read-only. errors=remount-ro
# does not. Columns from findmnt may be separated by spaces.
rg_dm_options_rw() {
  local opts="$1" tok rw=false ro=false
  [[ -n "$opts" ]] || return 1
  while IFS= read -r tok; do
    [[ -z "$tok" ]] && continue
    [[ "$tok" == rw ]] && rw=true
    [[ "$tok" == ro ]] && ro=true
  done < <(printf '%s\n' "$opts" | tr ', ' '\n')
  [[ "$rw" == true && "$ro" == false ]]
}

# dumpe2fs -h text from an unmounted filesystem after e2fsck.
rg_dm_ext_superblock_clean() {
  local text="$1" state features
  state="$(awk -F: '/^Filesystem state:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' <<<"$text")"
  features="$(awk -F: '/^Filesystem features:/ { sub(/^[[:space:]]+/, "", $2); print $2; exit }' <<<"$text")"
  [[ "$state" == "clean" ]] || return 1
  [[ "$features" != *needs_recovery* ]] || return 1
}

rg_dm_fsck_device() {
  local dev="$1" fstype e2fsck repair blkid rc dump text
  blkid="$(rg_dm_resolve blkid)" || return 1
  fstype="$(rg_dm_host_exec "$blkid" -o value -s TYPE "$dev" || true)"
  if [[ "$fstype" == ext2 || "$fstype" == ext3 || "$fstype" == ext4 ]]; then
    e2fsck="$(rg_dm_resolve e2fsck)" || return 1
    # e2fsck exits 1 when it corrected errors and 2 when a reboot is advised.
    rc=0
    rg_dm_host_exec "$e2fsck" -fy "$dev" || rc=$?
    if [[ "$rc" -gt 2 ]]; then
      echo "e2fsck ${dev} exited ${rc}" >&2
      return 1
    fi
    dump="$(rg_dm_resolve dumpe2fs)" || return 1
    text="$(rg_dm_host_exec "$dump" -h "$dev" 2>/dev/null || true)"
    if ! rg_dm_ext_superblock_clean "$text"; then
      echo "ext superblock on ${dev} is not clean after e2fsck" >&2
      printf '%s\n' "$text" >&2
      return 1
    fi
    superblock_clean=true
  elif [[ "$fstype" == "xfs" ]]; then
    repair="$(rg_dm_resolve xfs_repair)" || return 1
    rg_dm_host_exec "$repair" "$dev" || return 1
    superblock_clean=true
  else
    echo "refusing to repair filesystem type ${fstype:-unknown} on ${dev}" >&2
    return 1
  fi
}

rg_dm_mount_device() {
  local dev="/dev/mapper/${name}" mount_bin
  mount_bin="$(rg_dm_resolve mount)" || return 1
  rg_dm_host_exec "$mount_bin" "$dev" "$mount_path"
}

# Unmount only an exact mount of the dm device, check the filesystem only
# when nothing else holds it open, and mount it again before returning.
rg_dm_repair_mount() {
  local dev="/dev/mapper/${name}" umount_bin opens
  umount_bin="$(rg_dm_resolve umount)" || return 1
  if rg_dm_exact_mount; then
    if ! rg_dm_host_exec "$umount_bin" "$mount_path"; then
      echo "umount ${mount_path} failed" >&2
      return 1
    fi
  elif [[ -n "$(rg_dm_mounted_source)" ]]; then
    echo "refusing to unmount ${mount_path}; it is not ${dev}" >&2
    return 1
  fi
  opens="$(rg_dm_open_count || true)"
  if [[ "$opens" != "0" ]]; then
    echo "refusing to check ${dev}; open count is ${opens:-unknown}" >&2
    rg_dm_mount_device || true
    return 1
  fi
  if ! rg_dm_fsck_device "$dev"; then
    rg_dm_mount_device || true
    return 1
  fi
  if ! rg_dm_mount_device; then
    echo "mount ${dev} ${mount_path} failed" >&2
    return 1
  fi
}

rg_dm_restore_mount() {
  local dev="/dev/mapper/${name}" src opens
  if rg_dm_exact_mount; then
    return 0
  fi
  src="$(rg_dm_mounted_source)"
  if [[ -n "$src" && "$src" != "$dev" ]]; then
    echo "refusing to mount ${dev} over ${src} at ${mount_path}" >&2
    return 1
  fi
  opens="$(rg_dm_open_count || true)"
  if [[ "$opens" == "0" ]]; then
    rg_dm_fsck_device "$dev" || true
  else
    echo "not checking ${dev}; open count is ${opens:-unknown}" >&2
  fi
  if ! rg_dm_mount_device; then
    echo "mount ${dev} ${mount_path} failed" >&2
    return 1
  fi
}

# Open count 0 or 1 is the host mount (or an already-unmounted device).
# A foreign mount namespace still counts as a holder.
rg_dm_holders_absent() {
  local opens majmin foreign
  opens="$(rg_dm_open_count)" || return 1
  [[ "$opens" -le 1 ]] || return 1
  majmin="$(rg_dm_majmin)" || return 1
  set +e
  rg_dm_foreign_mount "$majmin"
  foreign=$?
  set -e
  [[ "$foreign" == 1 ]]
}

rg_dm_mount_options() {
  local findmnt
  findmnt="$(rg_dm_resolve findmnt)" || return 1
  rg_dm_host_exec "$findmnt" -n -o OPTIONS,FS-OPTIONS --mountpoint "$mount_path" 2>/dev/null || true
}

# A marker read is not enough: the journal can be aborted and the mount
# still serve those blocks. Require a read-write mount and a new file.
rg_dm_confirm_recovered() {
  local opts probe got
  if ! rg_dm_exact_mount; then
    echo "refusing recovery probe; ${mount_path} is not an exact mount of /dev/mapper/${name}" >&2
    return 1
  fi
  opts="$(rg_dm_mount_options)"
  if ! rg_dm_options_rw "$opts"; then
    echo "mount ${mount_path} is not read-write (${opts:-missing})" >&2
    return 1
  fi
  if [[ "${superblock_clean:-false}" != true ]]; then
    echo "filesystem superblock was not checked clean" >&2
    return 1
  fi
  probe="${mount_path}/rg-dm-error-probe"
  if ! rg_dm_write_marker "$probe"; then
    echo "recovery write failed on ${mount_path}" >&2
    rg_dm_host_exec rm -f "$probe" >/dev/null 2>&1 || true
    return 1
  fi
  probe_written=true
  got="$(rg_dm_direct_header "$probe" || true)"
  if ! rg_dm_host_exec rm -f "$probe"; then
    echo "failed to remove recovery probe ${probe}" >&2
    return 1
  fi
  probe_written=false
  [[ "$got" == "dm-error-marker" ]]
}

rg_dm_write_error_json() {
  if [[ -n "${skip_reason:-}" ]]; then
    jq -n --arg skip "$skip_reason" '{skip:$skip}' >"$artifact_dir/dm-error.json"
    return
  fi
  jq -n \
    --argjson table_has_error_target "$table_has_error_target" \
    --argjson read_failed_during_fault "$read_failed_during_fault" \
    --argjson recovered "$recovered" \
    '{table_has_error_target:$table_has_error_target,read_failed_during_fault:$read_failed_during_fault,recovered:$recovered}' \
    >"$artifact_dir/dm-error.json"
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

  dm-table-target)
    rg_dm_table_field "${2-}" 3
    ;;

  dm-mountinfo-foreign)
    set +e
    rg_dm_proc_has_foreign_mount "${2-}" "${3-}" "${4-}"
    rc=$?
    set -e
    if [[ "$rc" == 0 ]]; then
      printf 'in-use\n'
    elif [[ "$rc" == 1 ]]; then
      printf 'clear\n'
    else
      printf 'error\n'
      exit 1
    fi
    ;;

  dm-mountinfo-status)
    rg_dm_foreign_scan_token "${2-}" "${3-}" "${4-}"
    ;;

  dm-ext-state)
    text="$(cat)"
    if rg_dm_ext_superblock_clean "$text"; then
      printf 'clean\n'
    else
      printf 'dirty\n'
    fi
    ;;

  dm-mount-rw)
    if rg_dm_options_rw "${2-}"; then
      printf 'rw\n'
    else
      printf 'not-rw\n'
    fi
    ;;

  reset-dm-pvs)
    rg_dm_setup
    rg_dm_reset_released
    ;;

  release-dm-pvs)
    rg_dm_setup
    rg_dm_release_bound
    rg_dm_reset_released
    ;;

  dm-error)
    rg_dm_setup
    table_has_error_target=false
    read_failed_during_fault=false
    recovered=false
    skip_reason=""
    mount_was_exact=false
    marker_written=false
    probe_written=false
    fs_frozen=false
    superblock_clean=false
    original=""
    marker="${mount_path}/rg-dm-error-marker"
    cleanup_dm() {
      local status=$?
      trap - EXIT
      set +e
      if [[ -n "${original:-}" ]] && ! rg_dm_table_is "$original"; then
        # Keep going after a restore error so the mount and JSON are written.
        # rg_dm_transition already logged the failing dmsetup step.
        rg_dm_transition "$original" || true
        if ! rg_dm_table_is "$original"; then
          echo "cleanup left ${name} off the original table" >&2
          status=1
          recovered=false
          # Suspend can fail when the device is already suspended, which skips
          # resume inside rg_dm_transition. Resume once so the mount can return.
          if ! err="$(rg_dm_host_exec "$dmsetup_bin" resume "$name" 2>&1)"; then
            echo "dmsetup resume ${name} during cleanup failed: ${err}" >&2
          fi
        fi
      fi
      if ! rg_dm_unfreeze; then
        status=1
        recovered=false
      fi
      # Remount even when the table restore failed. An unmounted lab path
      # makes later writes land on the parent filesystem.
      if [[ "$mount_was_exact" == true ]] && ! rg_dm_exact_mount; then
        rg_dm_restore_mount || status=1
      fi
      if [[ "$marker_written" == true ]]; then
        if ! rg_dm_host_exec rm -f "$marker"; then
          echo "failed to delete ${marker}" >&2
          recovered=false
          status=1
        else
          marker_written=false
        fi
      fi
      if [[ "$probe_written" == true ]]; then
        if ! rg_dm_host_exec rm -f "${mount_path}/rg-dm-error-probe"; then
          echo "failed to delete recovery probe" >&2
          recovered=false
          status=1
        else
          probe_written=false
        fi
      fi
      if ! rg_dm_delete_gate_volume; then
        status=1
        if [[ -z "$skip_reason" ]]; then
          recovered=false
        fi
      fi
      rg_dm_write_error_json || status=1
      if [[ -n "$skip_reason" ]]; then
        exit "$status"
      fi
      if [[ "$table_has_error_target" != true || "$read_failed_during_fault" != true || "$recovered" != true ]]; then
        status=1
      fi
      exit "$status"
    }
    trap cleanup_dm EXIT
    if rg_dm_exact_mount; then
      mount_was_exact=true
    else
      echo "refusing dm-error; ${mount_path} is not an exact mount of /dev/mapper/${name}" >&2
      exit 1
    fi
    if rg_dm_target_in_use; then
      skip_reason="SKIP-dm-in-use: ${mount_path} has another mount, a foreign mount namespace, an open holder, or a Bound PersistentVolume"
      exit 0
    fi
    rg_dm_reset_released
    rg_dm_create_gate_volume
    original="$(rg_dm_host_exec "$dmsetup_bin" table "$name")"
    if [[ -z "$original" ]]; then
      echo "dmsetup table ${name} was empty" >&2
      exit 1
    fi
    sectors="$(rg_dm_table_field "$original" 2)"
    if [[ ! "$sectors" =~ ^[0-9]+$ ]]; then
      echo "dmsetup table ${name} has no sector count: ${original}" >&2
      exit 1
    fi
    if ! rg_dm_write_marker "$marker"; then
      echo "failed to write ${marker} while the original table was active" >&2
      exit 1
    fi
    marker_written=true
    if ! rg_dm_flush_before_fault; then
      echo "failed to flush ${mount_path} before the error target" >&2
      exit 1
    fi
    if ! rg_dm_transition "0 ${sectors} error"; then
      echo "failed to install the error target on ${name}" >&2
      exit 1
    fi
    injected="$(rg_dm_host_exec "$dmsetup_bin" table "$name")"
    table_has_error_target=false
    if [[ "$(rg_dm_table_field "$injected" 3)" == "error" && "$(rg_dm_table_field "$injected" 2)" == "$sectors" ]]; then
      table_has_error_target=true
    fi
    # O_DIRECT does not satisfy the read from the page cache. A cached read
    # of a marker that was just written succeeds even when the error target
    # is active. Do not sync here: that writeback hits the error target.
    rg_dm_drop_page_cache
    read_failed_during_fault=false
    if ! rg_dm_host_exec "$dd_bin" if="$marker" of=/dev/null bs=4096 count=1 iflag=direct status=none; then
      read_failed_during_fault=true
    fi
    recovered=false
    if rg_dm_transition "$original" && rg_dm_table_is "$original"; then
      if ! rg_dm_unfreeze; then
        echo "filesystem stayed frozen after restore" >&2
      elif rg_dm_holders_absent; then
        # The marker can still be read after the journal aborts. Check the
        # filesystem whenever nobody else holds the device.
        rg_dm_repair_mount || true
      else
        echo "not checking the filesystem; another holder is present" >&2
      fi
      got="$(rg_dm_direct_header "$marker" || true)"
      if [[ "$got" == "dm-error-marker" ]] && rg_dm_confirm_recovered; then
        if rg_dm_host_exec rm -f "$marker"; then
          marker_written=false
          recovered=true
        else
          echo "failed to delete ${marker}" >&2
        fi
      fi
    else
      echo "dmsetup table ${name} was not restored to the original map" >&2
    fi
    if [[ "$table_has_error_target" == true && "$read_failed_during_fault" == true && "$recovered" == true ]]; then
      exit 0
    fi
    exit 1
    ;;

  *)
    echo "unknown evidence mode: ${mode}" >&2
    exit 1
    ;;
esac
