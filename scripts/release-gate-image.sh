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

# Build a local image from an extracted rustfs binary and, when k3s is
# installed, import it into the k8s.io containerd namespace. Prints the image
# reference on stdout. Exit 1 when the image cannot be built, smoked, or seen
# by kubelet.
#
# k3s containerd.sock is root-only. This script uses the current user's
# `k3s ctr` when the socket is writable, otherwise `sudo -n` (no password
# prompt). A password prompt or a missing sudoers rule is a hard failure.
set -euo pipefail

tag="${1:-}"
binary="${2:-}"
if [[ -z "$tag" || -z "$binary" || ! -f "$binary" ]]; then
  echo "usage: release-gate-image.sh <tag> <rustfs-binary>" >&2
  exit 1
fi
if [[ ! "$tag" =~ ^[A-Za-z0-9._+-]+$ ]]; then
  echo "refusing image tag ${tag}" >&2
  exit 1
fi

image_tag="${tag//+/-}"
image="${RUSTFS_RELEASE_GATE_IMAGE_REPO:-rustfs-release}:${image_tag}"
base="${RUSTFS_RELEASE_GATE_BASE_IMAGE:-debian:bookworm-slim}"
bin_path="${RUSTFS_RELEASE_GATE_BINARY_PATH:-/usr/bin/rustfs}"
if [[ ! "$image" =~ ^[A-Za-z0-9._+:/@-]+$ || ! "$base" =~ ^[A-Za-z0-9._+:/@-]+$ || ! "$bin_path" =~ ^/[A-Za-z0-9._+/-]+$ ]]; then
  echo "refusing image ${image}, base ${base}, or binary path ${bin_path}" >&2
  exit 1
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
cp "$binary" "$work/rustfs"
chmod 755 "$work/rustfs"
cat >"$work/Dockerfile" <<EOF
FROM ${base}
USER root
# debian:bookworm-slim has apt-get and an empty CA bundle. Internode TLS
# fails closed without ca-certificates. A custom base may already ship the
# bundle; otherwise it must provide apt-get.
RUN set -eu; \\
    if [ -s /etc/ssl/certs/ca-certificates.crt ]; then \\
      :; \\
    elif command -v apt-get >/dev/null 2>&1; then \\
      apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*; \\
    else \\
      echo "base image has neither /etc/ssl/certs/ca-certificates.crt nor apt-get" >&2; \\
      exit 1; \\
    fi
COPY rustfs ${bin_path}
ENTRYPOINT ["${bin_path}"]
EOF

# CTR is the k3s containerd client, empty when k3s is not installed.
CTR=()
if command -v k3s >/dev/null 2>&1; then
  if k3s ctr -n k8s.io images ls >/dev/null 2>&1; then
    CTR=(k3s ctr -n k8s.io)
  elif sudo -n k3s ctr -n k8s.io images ls >/dev/null 2>&1; then
    CTR=(sudo -n k3s ctr -n k8s.io)
  else
    echo "k3s is installed but this user cannot talk to containerd namespace k8s.io." >&2
    echo "The socket /run/k3s/containerd/containerd.sock is root-only." >&2
    echo "Grant that socket or allow passwordless 'sudo -n k3s ctr', then rerun." >&2
    exit 1
  fi
fi

import_tar() {
  local tar="$1"
  if [[ ${#CTR[@]} -eq 0 ]]; then
    return 0
  fi
  if ! "${CTR[@]}" images import "$tar" >&2; then
    echo "failed to import ${tar} into k3s containerd namespace k8s.io" >&2
    exit 1
  fi
}

normalize_ref() {
  local ref="$1"
  if [[ "$ref" == */* ]]; then
    printf '%s\n' "$ref"
  else
    printf 'docker.io/library/%s\n' "$ref"
  fi
}

k3s_image_names() {
  "${CTR[@]}" images ls | awk 'NR > 1 { print $1 }'
}

# containerd stores a short name as docker.io/library/<name>. Pin that ref.
pin_imported() {
  if [[ ${#CTR[@]} -eq 0 ]]; then
    return 0
  fi
  local full found
  full="$(normalize_ref "$image")"
  found="$(k3s_image_names | grep -Fx "$full" || true)"
  if [[ -z "$found" ]]; then
    found="$(k3s_image_names | grep -F "$image" | head -n 1 || true)"
    if [[ -n "$found" && "$found" != */* ]]; then
      found="$(normalize_ref "$found")"
    fi
  fi
  if [[ -z "$found" ]]; then
    echo "k3s containerd cannot see ${full}; kubelet will not run this image" >&2
    exit 1
  fi
  if ! "${CTR[@]}" images label "$found" io.cri-containerd.pinned=pinned >&2; then
    echo "failed to pin ${found} (io.cri-containerd.pinned=pinned)" >&2
    exit 1
  fi
}

# RUNNER invokes the engine that can `run` the image. BUILD_INTO_K3S means
# the build already wrote the k8s.io namespace, so import is unnecessary.
RUNNER=()
BUILT_INTO_K3S=false
K3S_SOCK="/run/k3s/containerd/containerd.sock"

smoke_runner() {
  if [[ ${#RUNNER[@]} -eq 0 ]]; then
    echo "no container runtime can smoke-test ${image}" >&2
    exit 1
  fi
  echo "smoke-testing ${image}" >&2
  "${RUNNER[@]}" run --rm --network none --entrypoint "$bin_path" "$image" --version >&2
  "${RUNNER[@]}" run --rm --network none --entrypoint sh "$image" -c 'test -s /etc/ssl/certs/ca-certificates.crt'
}

smoke_buildah() {
  local ctr_id
  ctr_id="$(buildah from "$image")"
  echo "smoke-testing ${image} via buildah" >&2
  buildah run "$ctr_id" -- "$bin_path" --version >&2
  buildah run "$ctr_id" -- sh -c 'test -s /etc/ssl/certs/ca-certificates.crt'
  buildah rm "$ctr_id" >/dev/null
}

if command -v docker >/dev/null 2>&1; then
  docker build -t "$image" "$work" >&2
  docker save -o "$work/image.tar" "$image"
  import_tar "$work/image.tar"
  RUNNER=(docker)
elif command -v nerdctl >/dev/null 2>&1; then
  if [[ -S "$K3S_SOCK" ]]; then
    if nerdctl --address "$K3S_SOCK" --namespace k8s.io build -t "$image" "$work" >&2; then
      BUILT_INTO_K3S=true
      RUNNER=(nerdctl --address "$K3S_SOCK" --namespace k8s.io)
    elif sudo -n nerdctl --address "$K3S_SOCK" --namespace k8s.io build -t "$image" "$work" >&2; then
      BUILT_INTO_K3S=true
      RUNNER=(sudo -n nerdctl --address "$K3S_SOCK" --namespace k8s.io)
    fi
  fi
  if [[ "$BUILT_INTO_K3S" != true ]]; then
    nerdctl build -t "$image" "$work" >&2
    nerdctl save -o "$work/image.tar" "$image"
    import_tar "$work/image.tar"
    RUNNER=(nerdctl)
  fi
elif command -v buildah >/dev/null 2>&1; then
  buildah bud -t "$image" "$work" >&2
  buildah push "$image" "oci-archive:$work/image.tar" >&2
  import_tar "$work/image.tar"
else
  echo "no docker, nerdctl, or buildah available to load ${image} from the release zip" >&2
  exit 1
fi

if [[ ${#RUNNER[@]} -gt 0 ]]; then
  smoke_runner
else
  smoke_buildah
fi
pin_imported
printf '%s\n' "$image"
