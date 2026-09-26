# RustFS release gate

`make release-gate` is the entry point for one RustFS release tag. It records
the version, previous version, image, git SHA, and artifact checksums, then
runs a tier of cases and writes:

- `target/release-gate/<version>/<tier>/<run-id>/release-gate.json`
- `target/release-gate/<version>/<tier>/<run-id>/release-gate.junit.xml`
- `target/release-gate/<version>/<tier>/<run-id>/RELEASE_GATE.md`

Set `RELEASE_GATE_OUTPUT` to choose the directory. Set `RELEASE_GATE_RUN_ID`
to make the default directory stable. A live run deletes script-produced
evidence in that directory first, unless `RELEASE_GATE_REUSE_EVIDENCE=1`.

Each case is `PASS`, `FAIL`, or `SKIP`. A skip reason starts with a stable
code. Missing evidence and misconfiguration fail the gate. These skips do
not fail the gate:

| Code | When it is allowed |
| --- | --- |
| `SKIP-dry-run` | `RELEASE_GATE_DRY_RUN=1` |
| `SKIP-toda-arm64` | IOChaos or warp-under-chaos on an arch whose chaos-daemon toda binary cannot run (Apple Silicon) |
| `SKIP-no-dm` | device-mapper scenarios when `RUSTFS_RELEASE_GATE_HAS_DM` is unset |
| `SKIP-timechaos` | `clock-skew`; TimeChaos is still catalog-planned |
| `SKIP-planned` | catalog-planned admin and storage qualification, including expand, rebalance, and decommission until those scenarios are executable |
| `SKIP-dm-not-selected` | device-mapper scenarios other than `RELEASE_GATE_DM_SCENARIO` (default `dm-flakey`). One DM scenario per gate run |
| `DEFERRED-physical-power` | physical PSU cycle; `pod-kill-one` and `pod-graceful-restart-one` are the proxy |
| `SKIP-no-prev-version` | upgrade, rollback, or warp regression without `RUSTFS_PREV_VERSION` |
| `SKIP-no-artifact` | dry-run with `RELEASE_GATE_FETCH=0` only |
| `SKIP-no-cluster` | dry-run only; a live run treats this as a gate failure |

These statuses do not pass: `SKIP-no-mc`, `SKIP-no-privileged`,
`SKIP-unsafe-shared-fs`, `SKIP-no-dm-device`, `SKIP-no-unzip`,
`SKIP-no-otool`, `SKIP-aborted`, and any other code. A live run with fetch
enabled fails when checksum, `--version`, or `ldd`/`otool` input is missing.
`volume-remount-ro` checks capabilities before the shared-filesystem test
and is `SKIP-no-privileged` on operator pods that drop every capability,
including local-path; that row is not coverage. `disk-full-fill` still
refuses a shared filesystem first (`SKIP-unsafe-shared-fs`).

## Commands

```bash
# Plan every case and verify published artifacts. No cluster.
make release-gate \
  RUSTFS_VERSION=1.0.1-preview.11 \
  RUSTFS_PREV_VERSION=1.0.0 \
  RELEASE_GATE_TIER=full \
  RELEASE_GATE_DRY_RUN=1

# Live smoke on a prepared cluster. The image defaults to RUSTFS_IMAGE.
make release-gate \
  RUSTFS_VERSION=1.0.1-preview.11 \
  RUSTFS_IMAGE=rustfs/rustfs:1.0.1-preview.11 \
  RELEASE_GATE_TIER=smoke \
  RELEASE_GATE_DRY_RUN=0 \
  RUSTFS_RELEASE_GATE_HAS_CLUSTER=1

# Standard tier: smoke, plus network, restarts, quorum-edge, protocol
# regression, lifecycle, warp regression, and upgrade.
make release-gate RUSTFS_VERSION=1.0.1-preview.11 RUSTFS_PREV_VERSION=1.0.0 RELEASE_GATE_TIER=standard
```

`RELEASE_GATE_FETCH=1` (the Make default) downloads `SHA256SUMS` first, then
each host-architecture zip from `rustfs/rustfs`. Each download is retried
three times, must match the asset size when GitHub reports one, and must
match the SHA256SUMS digest. A mismatch deletes the file and retries. A
failed fetch or a failed image build aborts a live run before any case
touches the cluster: remaining cluster cases are `SKIP-aborted` and the
verdict is fail. Set `RELEASE_GATE_FETCH=0` to score files already in
`RUSTFS_ARTIFACT_DIR`.

The host zip set is every Linux zip for the architecture, not the first
directory entry. `ldd` is recorded per zip (`rustfs-ldd.txt` for gnu,
`rustfs-ldd-musl.txt` for musl). A static musl binary does not hide a
foreign library in the gnu binary. The container image is built from the gnu
zip when one exists; `rustfs-image-libc.txt` records `gnu` or `musl`.
`--version` is taken from that binary. On macOS, `otool -L` is taken from
the macOS zip (`rustfs-otool.txt`). Homebrew `liblzma` under
`/opt/homebrew` fails dynamic-deps. The git SHA comes from the `git commit`
line, or from the tag object when `target_commitish` is a branch name.

When `RUSTFS_IMAGE` or `RUSTFS_PREV_IMAGE` is unset on a live cluster, the
gate builds `rustfs-release:<tag>` from the gnu binary
(`scripts/release-gate-image.sh`). The default base is `debian:bookworm-slim`.
The Dockerfile installs `ca-certificates` when the bundle is empty, then
smoke-tests `--version` and a non-empty `/etc/ssl/certs/ca-certificates.crt`
before the image is used. `RUSTFS_RELEASE_GATE_BINARY_PATH` defaults to
`/usr/bin/rustfs`.

docker, nerdctl, and buildah can build the image. When `k3s` is installed
the image is imported into containerd namespace `k8s.io` and pinned as
`docker.io/library/<name>:<tag>` (`io.cri-containerd.pinned=pinned`). The
script does not ignore a failed pin. `k3s ctr` needs the containerd socket.
If the socket is root-only, the script uses `sudo -n` and fails with that
hint instead of prompting. A build that kubelet cannot see is a failure.
A missing builder or binary fails the gate.

`fresh-install` deploys `RUSTFS_IMAGE` (the same tenant annotation and pod
wait as the upgrade) before protocol smoke, the large GET, and lifecycle.
If that deploy fails, later cluster cases are `SKIP-aborted` so they do not
run against the previous image.

Protocol suites plan their target fingerprint at the start of each case and
set `RUSTFS_PROTOCOL_TEST_DEDICATED=1` plus
`RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT` for that plan. Also set
`RUSTFS_PROTOCOL_TEST_ENDPOINT` and the admin credential variables the
protocol harness already requires. The fingerprint is recomputed on every
gate run, including after `cluster-cold-restart` replaced the tenant.

Tiers:

- **smoke** — artifact identity, protocol smoke, large GET, fresh install,
  `pod-kill-one`, `pod-graceful-restart-one`, post-fault checksums.
- **standard** — smoke, plus network faults, restart storm, rolling and cold
  restart, quorum edge, the cold-bucket survivor probe, IOChaos when toda
  works, disk fill and remount without IOChaos, protocol regression,
  lifecycle, warp regression, upgrade, and rollback.
- **full** — standard, plus device-mapper, warp-under-chaos, the remaining
  IOChaos cases, planned admin/storage qualification, expand, and the
  deferred physical power row.

## Evidence files

Drop these JSON files in the artifact directory to score a case without
re-running it. They are the contract the Mac Mini campaign already produced.

- `quorum-edge-cold-read.json` — `survivors[]`. `cold_bucket` is a bool,
  true when that survivor never served the bucket (not a bucket name).
  Each survivor has `name`, `get_ok`, `get_attempted`, `wrong_sha256`,
  `put_rejected`, `put_attempted`, `health_live`, and `health_ready`.
  `quorum-edge-cold-read` requires at least two survivors, one cold, every
  GET succeeded, every PUT rejected, and `health_live` 200. It does not
  look at readiness. `quorum-edge-readiness` requires `health_ready` 200
  on every survivor. Preview.11 fails the cold-read case: the cold survivor
  GET is 0/N. Readiness 503 is its own failure.
- `large-object-get.json` — `expected_len`, `actual_len`, `expected_sha256`,
  `actual_sha256`. A short body fails.
- `warp-compare.json` — `current_ops`, `baseline_ops`. Default regression
  threshold is `RUSTFS_WARP_REGRESSION_PERCENT=20`.
- `upgrade-stability.json` and `upgrade-rollback.json` — object, multipart,
  version, lifecycle, and policy booleans, plus `client_errors`,
  `error_threshold`, `rollout_probe_failures`, and
  `rollout_error_threshold` (default 10, override with
  `RUSTFS_UPGRADE_ROLLOUT_ERROR_THRESHOLD`). Rollback also needs
  `rolled_back: true`. The script deploys `RUSTFS_PREV_IMAGE` first, writes
  the dataset, then rolls to `RUSTFS_IMAGE`. Both images need the operator
  annotation `operator.rustfs.com/runtime-default-image-ack`. The script
  waits until every pod runs the target image. `kubectl rollout status`
  alone is not the signal.
- `lifecycle-rule.json` — `rule_accepted`, `listed_enabled`, `get_matches`.
- `expand-status.json` — `pools_before`, `pools_after`, `integrity_ok`.
- `decommission-status.json` — `complete: true`.
- `rebalance-status.json` — `stopped`, `integrity_ok`.
  While those catalog scenarios are Planned, a missing file is
  `SKIP-planned`. A file that is present is scored.
- `disk-full-fill.json` — `enospc_observed`, `reads_ok`, `recovered`. The
  filler is bounded to that filesystem's free space and removed on exit.
  local-path, hostPath, or a volume whose device id matches `/` is
  `SKIP-unsafe-shared-fs` and is not a pass.
- `volume-remount-ro.json` — `remounted_ro`, `writes_rejected`, `reads_ok`,
  `restored`.
- `dm-error.json` — `table_has_error_target`, `read_failed_during_fault`,
  `recovered`. The producer uses `nsenter` to run host `dmsetup`, writes a
  regular file, reads it while the error target is active (that read must
  fail), then restores the table and reads again. A Bound PV whose
  `spec.local.path` is `RUSTFS_FAULT_TEST_DM_MOUNT_PATH` must already be
  claimed by the fault namespace. `SKIP-no-dm` when device-mapper is not
  selected. `SKIP-no-dm-device` (not a pass) when the selected scenario
  lacks the dm-run env or `RUSTFS_RELEASE_GATE_DM_STORAGE_CLASS`. That
  class is a `kubernetes.io/no-provisioner` class and is passed only to the
  one `dm-run`. The dynamic class used by every other scenario stays in
  `RUSTFS_FAULT_TEST_STORAGE_CLASS`. Other DM scenarios are
  `SKIP-dm-not-selected`. Do not run the eight DM scenarios back to back.
- `fresh-install.json` — `health` and `live` are 200. `image_matches`
  fails the case when it is present and false. On a live run this file is
  written after the release image is deployed.
- `rustfs-version.txt`, `rustfs-image-libc.txt`, `rustfs-ldd.txt`,
  `rustfs-ldd-musl.txt`, `rustfs-otool.txt`. An `ldd` line `lib => not found`
  fails dynamic-deps as `missing: lib`. Each ldd file is scored on its own.

`scripts/release-gate-evidence.sh` writes fresh-install, large-object,
lifecycle, quorum-edge, and dm-error JSON on a live cluster. The
quorum-edge probe creates and checks `mc` aliases before PodChaos, waits
until the victims are not Ready, and uses `mc cat` / `mc pipe` against
those aliases. Probe files live under the artifact directory and are
removed on exit. An alias or client error exits before any probe JSON is
written. An S3 503 is recorded, not treated as a tool failure.
`scripts/release-gate-upgrade.sh` writes the upgrade JSON. `deploy` only
rolls the tenant to `RUSTFS_IMAGE`. When `warp` is installed, `--host` is
the endpoint without a scheme (and `--tls` for https). A warp failure or a
missing obj/s number leaves `warp-compare.json` absent so the warp case
fails on its own; the upgrade JSON is still written.
`scripts/release-gate-host-disk.sh` fills a dedicated volume until ENOSPC
or remounts it read-only. Neither disk script uses IOChaos. Exit 1 is a
failed check or bad configuration. Exit 2 is `SKIP-no-privileged` and is
still a gate failure. Exit 3 is the shared-filesystem refusal.

## CI amd64

`.github/workflows/release-gate.yml` runs on `workflow_dispatch`, on
`repository_dispatch` type `rustfs-release`, and on a daily check of the
latest `rustfs/rustfs` release. The default job fetches the Linux asset and
plans the selected tier. `run_kind=true` boots kind, installs Chaos Mesh
2.8.3, and runs the tier live only when the RustFS Tenant CRD is already
installed. amd64 runners can run IOChaos; the arm64 chaos-daemon image cannot.

Dispatch payload:

```json
{"version":"1.0.1-preview.11","prev_version":"1.0.0","tier":"standard","dry_run":"false"}
```

## Mac Mini arm64

Full tier on the self-hosted Mini:

1. OrbStack or Lima Ubuntu, k3s, Chaos Mesh 2.8.3, RustFS operator, and a
   tenant image built from the release.
2. Single-node clusters must colocate pods:

```bash
export RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS=false
export RUSTFS_FAULT_TEST_TENANT_UNSAFE_BYPASS_DISK_CHECK=true
export RUSTFS_RELEASE_GATE_ARCH=aarch64
export RUSTFS_RELEASE_GATE_TODA=0
export RUSTFS_RELEASE_GATE_HAS_CLUSTER=1
export RUSTFS_RELEASE_GATE_HAS_DM=0
make release-gate \
  RUSTFS_VERSION=1.0.1-preview.11 \
  RUSTFS_PREV_VERSION=1.0.0 \
  RUSTFS_IMAGE=rustfs-local:1.0.1-preview.11 \
  RELEASE_GATE_TIER=full \
  RELEASE_GATE_DRY_RUN=0
```

`RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS=false` selects a minimum of one
Ready node. Set `RUSTFS_FAULT_TEST_MIN_NODES` only when that default is wrong.
Device-mapper rows stay `SKIP-no-dm` unless `RUSTFS_RELEASE_GATE_HAS_DM=1`.
With that set, a missing dm-run env is `SKIP-no-dm-device` and does not pass.
Direct `network-loss` uses 80% loss. The release gate also sets
`RUSTFS_RELEASE_GATE_NETWORK_LOSS_SCOPE=all` (Chaos Mesh `mode: all` on the
source selector) and `RUSTFS_FAULT_TEST_NETWORK_LOSS_MIN_PERCENT=10`. The
case passes only when the fault window has at least 30 attempts and an
error rate of at least that percent. A quiet sample fails. Unset, other
runs keep the old "any disrupted call" check, and suite YAML that sets
`lossPercent` keeps its own value. IOChaos and TimeChaos stay skipped on
Apple Silicon. Expect `quorum-edge-cold-read` to fail on 1.0.1-preview.11.
`quorum-edge-readiness` is a separate row.

`s3chaos` builds on macOS: `openat2` and `major`/`minor` are Linux-only and
the other targets fail closed. The artifact check (`--version`, `ldd`,
`otool -L`) is what the Mac runs. This does not make the storage-recovery
helper able to mutate a volume on macOS.

If `git pull` does not update a release-gate branch, the remote fetch
refspec may only include `main`. Fetch that branch explicitly, for example
`git fetch origin cursor/release-gate-2e6e`.

Before the first scenario, and after a failed IOChaos run, `make fault-cleanup`
clears stuck IOChaos and PodIOChaos finalizers so the next scenario does not
inherit the fault. The port-forward used for S3 is replaced if it dies while
the tenant is still starting, including after `pod-crash-versioned-hot` and
`rolling-restart-all`.
