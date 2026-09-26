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

# Non-IOChaos disk faults.
# fill refuses when the data volume shares the node root filesystem
# (local-path / hostPath). A dedicated filesystem is filled only up to its
# own free space, and the filler is removed on every exit.
# Exit 1: misconfiguration or the check failed.
# Exit 2: the container cannot remount (not coverage).
# Exit 3: the volume shares the node filesystem (SKIP-unsafe-shared-fs).
set -euo pipefail

mode="${1:-fill}"
artifact_dir="${RELEASE_GATE_ARTIFACT_DIR:-target/release-gate/artifacts}"
namespace="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
tenant="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
volume="${RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH:-/data/rustfs0}"
mkdir -p "$artifact_dir"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 1
fi
pod="$(kubectl -n "$namespace" get pod -l "rustfs.tenant=${tenant}" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "$pod" ]]; then
  echo "no Running tenant pod; refusing to guess a disk target" >&2
  exit 1
fi

marker="${volume}/release-gate-marker"
filler="${volume}/release-gate-fill"

cleanup_files() {
  kubectl -n "$namespace" exec "$pod" -- sh -c "rm -f '${filler}' '${marker}'" >/dev/null 2>&1 || true
  # A fill that still trips DiskPressure leaves chaos-daemon Evicted. Those
  # pods are phase Failed; drop them so the DaemonSet can replace them.
  kubectl -n "${RUSTFS_FAULT_TEST_CHAOS_NAMESPACE:-chaos-mesh}" delete pod \
    -l app.kubernetes.io/component=chaos-daemon \
    --field-selector=status.phase=Failed \
    --ignore-not-found=true --wait=false >/dev/null 2>&1 || true
}
trap cleanup_files EXIT

shared_filesystem() {
  local class claim
  claim="$(kubectl -n "$namespace" get pod "$pod" -o jsonpath='{range .spec.volumes[*]}{.persistentVolumeClaim.claimName}{"\n"}{end}' 2>/dev/null | head -n 1 || true)"
  if [[ -n "$claim" ]]; then
    class="$(kubectl -n "$namespace" get pvc "$claim" -o jsonpath='{.spec.storageClassName}' 2>/dev/null | tr '[:upper:]' '[:lower:]' || true)"
    case "$class" in
      local-path|local-path-*|*hostpath*|*host-path*) return 0 ;;
    esac
  fi
  if kubectl -n "$namespace" get pod "$pod" -o json 2>/dev/null | grep -q '"hostPath"'; then
    return 0
  fi
  local vol_dev root_dev
  vol_dev="$(kubectl -n "$namespace" exec "$pod" -- sh -c "stat -c %d '${volume}' 2>/dev/null || stat -f %d '${volume}'" 2>/dev/null || true)"
  root_dev="$(kubectl -n "$namespace" exec "$pod" -- sh -c "stat -c %d / 2>/dev/null || stat -f %d /" 2>/dev/null || true)"
  [[ -n "$vol_dev" && "$vol_dev" == "$root_dev" ]]
}

if [[ "$mode" == "fill" || "$mode" == "remount" ]]; then
  if shared_filesystem; then
    echo "volume ${volume} shares the node filesystem (storage class or device id); refusing to fill or remount it" >&2
    exit 3
  fi
fi

kubectl -n "$namespace" exec "$pod" -- sh -c "printf 'release-gate-marker\n' > '${marker}'"

if [[ "$mode" == "fill" ]]; then
  avail_kb="$(kubectl -n "$namespace" exec "$pod" -- sh -c "df -Pk '${volume}' | awk 'NR==2 {print \$4}'" 2>/dev/null || true)"
  if [[ ! "$avail_kb" =~ ^[0-9]+$ || "$avail_kb" -lt 1024 ]]; then
    echo "could not read a bounded free-space figure for ${volume}" >&2
    exit 1
  fi
  # One extra MiB past the reported free space so the last write hits ENOSPC
  # inside this filesystem and cannot spill onto another disk.
  count_mib=$((avail_kb / 1024 + 1))
  set +e
  output="$(kubectl -n "$namespace" exec "$pod" -- sh -c "dd if=/dev/zero of='${filler}' bs=1M count=${count_mib}" 2>&1)"
  set -e
  recovered=false
  if kubectl -n "$namespace" exec "$pod" -- sh -c "rm -f '${filler}'" >/dev/null 2>&1; then
    recovered=true
  fi
  got="$(kubectl -n "$namespace" exec "$pod" -- sh -c "cat '${marker}'" 2>/dev/null || true)"
  if [[ "$output" != *"No space left on device"* ]]; then
    echo "filling ${volume} did not report ENOSPC" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  reads_ok=false
  if [[ "$got" == "release-gate-marker" ]]; then
    reads_ok=true
  fi
  cat >"$artifact_dir/disk-full-fill.json" <<EOF
{"enospc_observed":true,"reads_ok":${reads_ok},"recovered":${recovered}}
EOF
  [[ "$reads_ok" == true && "$recovered" == true ]]
  exit 0
fi

if [[ "$mode" == "remount" ]]; then
  if ! kubectl -n "$namespace" exec "$pod" -- sh -c "mount -o remount,ro '${volume}'"; then
    echo "remount read-only failed; the container is not privileged and this is not coverage" >&2
    exit 2
  fi
  got="$(kubectl -n "$namespace" exec "$pod" -- sh -c "cat '${marker}'" 2>/dev/null || true)"
  reads_ok=false
  if [[ "$got" == "release-gate-marker" ]]; then
    reads_ok=true
  fi
  write_rejected=false
  if ! kubectl -n "$namespace" exec "$pod" -- sh -c "touch '${volume}/release-gate-ro-write'"; then
    write_rejected=true
  fi
  if ! kubectl -n "$namespace" exec "$pod" -- sh -c "mount -o remount,rw '${volume}'"; then
    echo "failed to restore a read-write mount on ${volume}" >&2
    exit 1
  fi
  cat >"$artifact_dir/volume-remount-ro.json" <<EOF
{"remounted_ro":true,"writes_rejected":${write_rejected},"reads_ok":${reads_ok},"restored":true}
EOF
  [[ "$write_rejected" == true && "$reads_ok" == true ]]
  exit 0
fi

echo "unknown host disk mode: $mode" >&2
exit 1
