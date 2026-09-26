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

# Rolling upgrade / rollback.
# Deploys the previous image first, writes the dataset there, then rolls
# forward. After the patch, wait until every non-deleted pod is Running,
# Ready, and on the target image. Exit 1 is a failure, including missing
# configuration. Exit 2 is only "mc or kubectl is not installed".
set -euo pipefail

mode="${1:-upgrade}"
artifact_dir="${RELEASE_GATE_ARTIFACT_DIR:-target/release-gate/artifacts}"
namespace="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
tenant="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
prev_image="${RUSTFS_PREV_IMAGE:-}"
new_image="${RUSTFS_IMAGE:-}"
prev_tag="${RUSTFS_PREV_VERSION:-}"
new_tag="${RUSTFS_VERSION:-}"
endpoint="${RUSTFS_ENDPOINT:-}"
mc_bin="${MC_BIN:-mc}"
rollout_error_threshold="${RUSTFS_UPGRADE_ROLLOUT_ERROR_THRESHOLD:-10}"
probe_pid=""

if ! command -v "$mc_bin" >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
  echo "mc and kubectl must be installed for the upgrade script" >&2
  exit 2
fi
if [[ -z "$endpoint" || -z "$new_image" || -z "$prev_image" ]]; then
  echo "RUSTFS_ENDPOINT, RUSTFS_IMAGE, and RUSTFS_PREV_IMAGE are required" >&2
  exit 1
fi
if [[ ! "$new_image" =~ ^[A-Za-z0-9._+:/@-]+$ || ! "$prev_image" =~ ^[A-Za-z0-9._+:/@-]+$ ]]; then
  echo "RUSTFS_IMAGE and RUSTFS_PREV_IMAGE must be image references" >&2
  exit 1
fi
if [[ ! "$rollout_error_threshold" =~ ^[0-9]+$ ]]; then
  echo "RUSTFS_UPGRADE_ROLLOUT_ERROR_THRESHOLD must be an integer" >&2
  exit 1
fi
mkdir -p "$artifact_dir"
rm -f "$artifact_dir/warp-baseline-ops.txt" "$artifact_dir/warp-current-ops.txt" \
  "$artifact_dir/warp-compare.json" "$artifact_dir/probe.fail"
alias_name="rg-upgrade"
"$mc_bin" alias set "$alias_name" "$endpoint" "${AWS_ACCESS_KEY_ID:-rustfsadmin}" "${AWS_SECRET_ACCESS_KEY:-rustfsadmin}" >/dev/null

stop_probe() {
  if [[ -n "$probe_pid" ]]; then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    probe_pid=""
  fi
}
trap stop_probe EXIT

write_dataset() {
  "$mc_bin" mb --ignore-existing "$alias_name/rg-data" >/dev/null
  "$mc_bin" mb --ignore-existing "$alias_name/rg-ver" >/dev/null
  "$mc_bin" mb --ignore-existing "$alias_name/rg-ilm" >/dev/null
  "$mc_bin" mb --ignore-existing "$alias_name/rg-pol" >/dev/null
  printf 'release-gate-object' >"$artifact_dir/object.bin"
  "$mc_bin" cp "$artifact_dir/object.bin" "$alias_name/rg-data/object.bin" >/dev/null
  dd if=/dev/zero of="$artifact_dir/multipart.bin" bs=1M count=17 status=none
  "$mc_bin" cp "$artifact_dir/multipart.bin" "$alias_name/rg-data/multipart.bin" >/dev/null
  "$mc_bin" version enable "$alias_name/rg-ver" >/dev/null
  printf 'v1' >"$artifact_dir/v1.bin"
  printf 'v2' >"$artifact_dir/v2.bin"
  "$mc_bin" cp "$artifact_dir/v1.bin" "$alias_name/rg-ver/key.bin" >/dev/null
  "$mc_bin" cp "$artifact_dir/v2.bin" "$alias_name/rg-ver/key.bin" >/dev/null
  cat >"$artifact_dir/lifecycle.json" <<'EOF'
{"Rules":[{"ID":"rg-expire","Status":"Enabled","Filter":{"Prefix":""},"Expiration":{"Days":1}}]}
EOF
  "$mc_bin" ilm import "$alias_name/rg-ilm" <"$artifact_dir/lifecycle.json" >/dev/null
  cat >"$artifact_dir/policy.json" <<'EOF'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":["s3:GetObject"],"Resource":["arn:aws:s3:::rg-pol/*"]}]}
EOF
  "$mc_bin" anonymous set-json "$artifact_dir/policy.json" "$alias_name/rg-pol" >/dev/null || \
    "$mc_bin" policy set-json "$artifact_dir/policy.json" "$alias_name/rg-pol" >/dev/null || true
}

checksum_ok() {
  "$mc_bin" cp "$alias_name/rg-data/object.bin" "$artifact_dir/object.got" >/dev/null
  cmp -s "$artifact_dir/object.bin" "$artifact_dir/object.got"
}

pods_match_image() {
  local image="$1" bad total
  bad="$(kubectl -n "$namespace" get pods -l "rustfs.tenant=${tenant}" -o json | jq -r --arg image "$image" '
    [.items[]
      | select(.metadata.deletionTimestamp | not)
      | select(
          .status.phase != "Running"
          or (.spec.containers[0].image != $image)
          or (.status.containerStatuses[0].ready != true)
        )] | length')"
  total="$(kubectl -n "$namespace" get pods -l "rustfs.tenant=${tenant}" -o json | jq -r '[.items[] | select(.metadata.deletionTimestamp | not)] | length')"
  [[ "$bad" == "0" && "$total" =~ ^[1-9][0-9]*$ ]]
}

tenant_blocked() {
  local status
  status="$(kubectl -n "$namespace" get tenant "$tenant" -o jsonpath='{range .status.conditions[?(@.type=="WorkloadSecurityIncompatible")]}{.status}{end}' 2>/dev/null || true)"
  [[ "$status" == "True" ]]
}

patch_image() {
  local image="$1" expect_tag="$2"
  local payload deadline version_output
  payload="$(printf '{"metadata":{"annotations":{"operator.rustfs.com/runtime-default-image-ack":"%s"}},"spec":{"image":"%s"}}' "$image" "$image")"
  kubectl -n "$namespace" patch tenant "$tenant" --type=merge -p "$payload"
  deadline=$((SECONDS + 600))
  while (( SECONDS < deadline )); do
    if tenant_blocked; then
      echo "tenant ${tenant} is WorkloadSecurityIncompatible for ${image}" >&2
      return 1
    fi
    if pods_match_image "$image"; then
      version_output="$(kubectl -n "$namespace" exec "$(first_pod)" -- rustfs --version 2>/dev/null || true)"
      if [[ -n "$expect_tag" && "$version_output" != *"$expect_tag"* ]]; then
        echo "pods run ${image} but --version does not contain ${expect_tag}" >&2
        printf '%s\n' "$version_output" >&2
        return 1
      fi
      return 0
    fi
    sleep 5
  done
  echo "timed out waiting for every pod to run ${image}" >&2
  kubectl -n "$namespace" get pods -l "rustfs.tenant=${tenant}" -o wide >&2 || true
  return 1
}

first_pod() {
  kubectl -n "$namespace" get pods -l "rustfs.tenant=${tenant}" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}'
}

start_probe() {
  : >"$artifact_dir/probe.fail"
  (
    while true; do
      "$mc_bin" stat "$alias_name/rg-data/object.bin" >/dev/null 2>&1 || echo x >>"$artifact_dir/probe.fail"
      sleep 1
    done
  ) &
  probe_pid=$!
}

probe_failures() {
  local count
  count="$(wc -l <"$artifact_dir/probe.fail" 2>/dev/null || echo 0)"
  count="${count//[[:space:]]/}"
  if [[ ! "$count" =~ ^[0-9]+$ ]]; then
    count=0
  fi
  printf '%s\n' "$count"
}

record_warp() {
  local label="$1" out="$2"
  local warp_bin="${WARP_BIN:-warp}"
  if ! command -v "$warp_bin" >/dev/null 2>&1; then
    return 0
  fi
  local log ops
  log="$artifact_dir/warp-${label}.log"
  "$warp_bin" mixed --host "$endpoint" \
    --access-key "${AWS_ACCESS_KEY_ID:-rustfsadmin}" \
    --secret-key "${AWS_SECRET_ACCESS_KEY:-rustfsadmin}" \
    --duration 20s --concurrent 4 --objects 64 --obj.size 64KiB \
    >"$log" 2>&1 || true
  ops="$(awk '{for (i = 1; i <= NF; i++) if ($i ~ /^obj\/s,?$/) {gsub(/,/, "", $(i-1)); print $(i-1); exit}}' "$log" || true)"
  if [[ "$ops" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
    printf '%s\n' "$ops" >"$out"
  fi
}

patch_image "$prev_image" "$prev_tag"
write_dataset
if ! checksum_ok; then
  echo "baseline object checksum failed on the previous image" >&2
  exit 1
fi
record_warp previous "$artifact_dir/warp-baseline-ops.txt"

start_probe
patch_image "$new_image" "$new_tag"
stop_probe
trap - EXIT
rollout_probe_failures="$(probe_failures)"
record_warp current "$artifact_dir/warp-current-ops.txt"

objects=false
if checksum_ok; then
  objects=true
fi
multipart=false
if "$mc_bin" cp "$alias_name/rg-data/multipart.bin" "$artifact_dir/multipart.got" >/dev/null && \
  cmp -s "$artifact_dir/multipart.bin" "$artifact_dir/multipart.got"; then
  multipart=true
fi
versions=false
version_lines="$("$mc_bin" ls --versions "$alias_name/rg-ver/key.bin" || true)"
version_count="$(printf '%s\n' "$version_lines" | grep -c . || true)"
if [[ "$version_count" -ge 2 ]]; then
  versions=true
fi
lifecycle=false
if "$mc_bin" ilm ls "$alias_name/rg-ilm" | grep -q rg-expire; then
  lifecycle=true
fi
policy=false
"$mc_bin" anonymous get-json "$alias_name/rg-pol" >"$artifact_dir/policy.got" 2>/dev/null || \
  "$mc_bin" policy get-json "$alias_name/rg-pol" >"$artifact_dir/policy.got" 2>/dev/null || true
if grep -q GetObject "$artifact_dir/policy.got" 2>/dev/null; then
  policy=true
fi
client_errors=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if ! checksum_ok; then
    client_errors=$((client_errors + 1))
  fi
done
rolled_back=false
if [[ "$mode" == "rollback" ]]; then
  trap stop_probe EXIT
  start_probe
  patch_image "$prev_image" "$prev_tag"
  stop_probe
  trap - EXIT
  rollback_probe="$(probe_failures)"
  rollout_probe_failures=$((rollout_probe_failures + rollback_probe))
  if checksum_ok; then
    rolled_back=true
  fi
  # Later cases must run against the release under test, not the rolled-back image.
  patch_image "$new_image" "$new_tag"
fi

if [[ -f "$artifact_dir/warp-baseline-ops.txt" && -f "$artifact_dir/warp-current-ops.txt" ]]; then
  cat >"$artifact_dir/warp-compare.json" <<EOF
{"current_ops":$(cat "$artifact_dir/warp-current-ops.txt"),"baseline_ops":$(cat "$artifact_dir/warp-baseline-ops.txt")}
EOF
fi

out="$artifact_dir/upgrade-stability.json"
if [[ "$mode" == "rollback" ]]; then
  out="$artifact_dir/upgrade-rollback.json"
fi
cat >"$out" <<EOF
{"objects_match":${objects},"multipart_match":${multipart},"versions_match":${versions},"lifecycle_match":${lifecycle},"policy_match":${policy},"client_errors":${client_errors},"error_threshold":0,"rollout_probe_failures":${rollout_probe_failures},"rollout_error_threshold":${rollout_error_threshold},"rolled_back":${rolled_back}}
EOF
if [[ "$objects" != true || "$multipart" != true || "$versions" != true || "$lifecycle" != true || "$policy" != true || "$client_errors" -gt 0 ]]; then
  exit 1
fi
if [[ "$rollout_probe_failures" -gt "$rollout_error_threshold" ]]; then
  exit 1
fi
if [[ "$mode" == "rollback" && "$rolled_back" != true ]]; then
  exit 1
fi
