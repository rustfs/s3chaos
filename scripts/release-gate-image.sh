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

# Build and load a local image from an extracted rustfs binary.
# Prints the image reference on stdout. Exit 1 when no builder can load it.
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
COPY rustfs ${bin_path}
ENTRYPOINT ["${bin_path}"]
EOF

built=false
# Builder progress stays on stderr so stdout is only the image reference.
if command -v docker >/dev/null 2>&1; then
  docker build -t "$image" "$work" >&2
  built=true
  if command -v k3s >/dev/null 2>&1; then
    docker save "$image" | k3s ctr images import - >&2
  fi
elif command -v nerdctl >/dev/null 2>&1; then
  nerdctl build -t "$image" "$work" >&2
  built=true
elif command -v buildah >/dev/null 2>&1; then
  buildah bud -t "$image" "$work" >&2
  built=true
fi

if [[ "$built" != true ]]; then
  echo "no docker, nerdctl, or buildah available to load ${image} from the release zip" >&2
  exit 1
fi

if command -v k3s >/dev/null 2>&1; then
  k3s ctr images label "$image" io.cri-containerd.pinned=pinned >/dev/null 2>&1 || true
fi
printf '%s\n' "$image"
