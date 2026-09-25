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

# Non-IOChaos disk faults so arm64 hosts are not blocked on the toda binary.
# fill: write until ENOSPC on the data volume, then delete the filler.
# remount: remount the data volume read-only, reject a write, restore it.
# Exit 2 when the pod cannot perform the operation (SKIP-no-privileged).
set -euo pipefail

mode="${1:-fill}"
artifact_dir="${RELEASE_GATE_ARTIFACT_DIR:-target/release-gate/artifacts}"
namespace="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
tenant="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
volume="${RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH:-/data/rustfs0}"
mkdir -p "$artifact_dir"

if ! command -v kubectl >/dev/null 2>&1; then
  echo "kubectl is required" >&2
  exit 2
fi
pod="$(kubectl -n "$namespace" get pod -l "rustfs.tenant=${tenant}" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "$pod" ]]; then
  echo "no tenant pod to inject a host disk fault" >&2
  exit 2
fi

marker="${volume}/release-gate-marker"
kubectl -n "$namespace" exec "$pod" -- sh -c "printf 'release-gate-marker\n' > '${marker}'"

if [[ "$mode" == "fill" ]]; then
  set +e
  output="$(kubectl -n "$namespace" exec "$pod" -- sh -c "dd if=/dev/zero of='${volume}/release-gate-fill' bs=1M" 2>&1)"
  set -e
  recovered=false
  if kubectl -n "$namespace" exec "$pod" -- sh -c "rm -f '${volume}/release-gate-fill'" >/dev/null 2>&1; then
    recovered=true
  fi
  got="$(kubectl -n "$namespace" exec "$pod" -- sh -c "cat '${marker}'" 2>/dev/null || true)"
  kubectl -n "$namespace" exec "$pod" -- sh -c "rm -f '${marker}'" >/dev/null 2>&1 || true
  if [[ "$output" != *"No space left on device"* ]]; then
    echo "filling ${volume} did not report ENOSPC" >&2
    printf '%s\n' "$output" >&2
    exit 1
  fi
  reads_ok=false
  [[ "$got" == "release-gate-marker" ]] && reads_ok=true
  cat >"$artifact_dir/disk-full-fill.json" <<EOF
{"enospc_observed":true,"reads_ok":${reads_ok},"recovered":${recovered}}
EOF
  [[ "$reads_ok" == true ]]
  exit 0
fi

if [[ "$mode" == "remount" ]]; then
  if ! kubectl -n "$namespace" exec "$pod" -- sh -c "mount -o remount,ro '${volume}'"; then
    kubectl -n "$namespace" exec "$pod" -- sh -c "rm -f '${marker}'" >/dev/null 2>&1 || true
    echo "remount read-only failed; the container is not privileged" >&2
    exit 2
  fi
  got="$(kubectl -n "$namespace" exec "$pod" -- sh -c "cat '${marker}'" 2>/dev/null || true)"
  reads_ok=false
  [[ "$got" == "release-gate-marker" ]] && reads_ok=true
  write_rejected=false
  if ! kubectl -n "$namespace" exec "$pod" -- sh -c "touch '${volume}/release-gate-ro-write'"; then
    write_rejected=true
  fi
  kubectl -n "$namespace" exec "$pod" -- sh -c "mount -o remount,rw '${volume}'" || {
    echo "failed to restore a read-write mount on ${volume}" >&2
    exit 1
  }
  kubectl -n "$namespace" exec "$pod" -- sh -c "rm -f '${marker}'" >/dev/null 2>&1 || true
  cat >"$artifact_dir/volume-remount-ro.json" <<EOF
{"remounted_ro":true,"writes_rejected":${write_rejected},"reads_ok":${reads_ok},"restored":true}
EOF
  [[ "$write_rejected" == true && "$reads_ok" == true ]]
  exit 0
fi

echo "unknown host disk mode: $mode" >&2
exit 1
