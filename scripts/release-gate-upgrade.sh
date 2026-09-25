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

# Rolling upgrade / rollback evidence for the release gate.
# Exit 0 writes upgrade-stability.json or upgrade-rollback.json.
# Exit 2 means mc or the tenant is not available (SKIP-no-mc).
set -euo pipefail

mode="${1:-upgrade}"
artifact_dir="${RELEASE_GATE_ARTIFACT_DIR:-target/release-gate/artifacts}"
namespace="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
tenant="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"
prev_image="${RUSTFS_PREV_IMAGE:-}"
new_image="${RUSTFS_IMAGE:-}"
endpoint="${RUSTFS_ENDPOINT:-}"
mc_bin="${MC_BIN:-mc}"

if ! command -v "$mc_bin" >/dev/null 2>&1 || ! command -v kubectl >/dev/null 2>&1; then
  echo "mc and kubectl are required for the upgrade script" >&2
  exit 2
fi
if [[ -z "$endpoint" || -z "$new_image" || -z "$prev_image" ]]; then
  echo "RUSTFS_ENDPOINT, RUSTFS_IMAGE, and RUSTFS_PREV_IMAGE are required" >&2
  echo "RUSTFS_PREV_IMAGE must be the previous container image, not only the version tag" >&2
  exit 2
fi
if [[ ! "$new_image" =~ ^[A-Za-z0-9._+:/@-]+$ || ! "$prev_image" =~ ^[A-Za-z0-9._+:/@-]+$ ]]; then
  echo "RUSTFS_IMAGE and RUSTFS_PREV_IMAGE must be image references" >&2
  exit 2
fi

mkdir -p "$artifact_dir"
alias_name="rg-upgrade"
"$mc_bin" alias set "$alias_name" "$endpoint" "${AWS_ACCESS_KEY_ID:-rustfsadmin}" "${AWS_SECRET_ACCESS_KEY:-rustfsadmin}" >/dev/null

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

patch_image() {
  local image="$1"
  kubectl -n "$namespace" patch tenant "$tenant" --type=merge -p "{\"spec\":{\"image\":\"${image}\"}}"
  kubectl -n "$namespace" rollout status "statefulset" -l "rustfs.tenant=${tenant}" --timeout=600s
}

write_dataset
if ! checksum_ok; then
  echo "baseline object checksum failed before upgrade" >&2
  exit 1
fi

probe_pid=""
stop_probe() {
  if [[ -n "$probe_pid" ]]; then
    kill "$probe_pid" 2>/dev/null || true
    wait "$probe_pid" 2>/dev/null || true
    probe_pid=""
  fi
}
trap stop_probe EXIT
: >"$artifact_dir/probe.fail"
(
  while true; do
    "$mc_bin" stat "$alias_name/rg-data/object.bin" >/dev/null 2>&1 || echo x >>"$artifact_dir/probe.fail"
    sleep 1
  done
) &
probe_pid=$!
patch_image "$new_image"
stop_probe
trap - EXIT
objects=false
checksum_ok && objects=true
multipart=false
"$mc_bin" cp "$alias_name/rg-data/multipart.bin" "$artifact_dir/multipart.got" >/dev/null && \
  cmp -s "$artifact_dir/multipart.bin" "$artifact_dir/multipart.got" && multipart=true || true
versions=false
version_lines="$("$mc_bin" ls --versions "$alias_name/rg-ver/key.bin" || true)"
version_count="$(printf '%s\n' "$version_lines" | grep -c . || true)"
if [[ "$version_count" -ge 2 ]]; then
  versions=true
fi
lifecycle=false
"$mc_bin" ilm ls "$alias_name/rg-ilm" | grep -q rg-expire && lifecycle=true || true
policy=false
"$mc_bin" anonymous get-json "$alias_name/rg-pol" >"$artifact_dir/policy.got" 2>/dev/null || \
  "$mc_bin" policy get-json "$alias_name/rg-pol" >"$artifact_dir/policy.got" 2>/dev/null || true
grep -q GetObject "$artifact_dir/policy.got" 2>/dev/null && policy=true || true
client_errors=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
  if ! checksum_ok; then
    client_errors=$((client_errors + 1))
  fi
done
rolled_back=false
if [[ "$mode" == "rollback" ]]; then
  patch_image "$prev_image"
  if checksum_ok; then
    rolled_back=true
  fi
fi
out="$artifact_dir/upgrade-stability.json"
if [[ "$mode" == "rollback" ]]; then
  out="$artifact_dir/upgrade-rollback.json"
fi
cat >"$out" <<EOF
{"objects_match":${objects},"multipart_match":${multipart},"versions_match":${versions},"lifecycle_match":${lifecycle},"policy_match":${policy},"client_errors":${client_errors},"error_threshold":0,"rolled_back":${rolled_back}}
EOF
if [[ "$objects" != true || "$multipart" != true || "$versions" != true || "$lifecycle" != true || "$policy" != true || "$client_errors" -gt 0 ]]; then
  exit 1
fi
if [[ "$mode" == "rollback" && "$rolled_back" != true ]]; then
  exit 1
fi
