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
| `DEFERRED-physical-power` | physical PSU cycle; `pod-kill-one` and `pod-graceful-restart-one` are the proxy |
| `SKIP-no-prev-version` | upgrade, rollback, or warp regression without `RUSTFS_PREV_VERSION` |
| `SKIP-no-artifact` | dry-run with `RELEASE_GATE_FETCH=0` only |
| `SKIP-no-cluster` | dry-run only; a live run treats this as a gate failure |

These statuses do not pass: `SKIP-no-mc`, `SKIP-no-privileged`,
`SKIP-unsafe-shared-fs`, `SKIP-no-dm-device`, `SKIP-no-unzip`,
`SKIP-no-otool`, and any other code. A live run with fetch enabled fails
when checksum, `--version`, or `ldd`/`otool` input is missing. `volume-remount-ro`
is `SKIP-no-privileged` on operator pods that drop every capability; that
row is not coverage.

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

`RELEASE_GATE_FETCH=1` (the Make default) downloads `SHA256SUMS` and the
host-architecture zip from `rustfs/rustfs`, checks the checksum, unzips the
binary, and records `rustfs --version` plus `ldd` or `otool -L`. The git SHA
comes from the `git commit` line, or from the tag object when
`target_commitish` is a branch name. Set `RELEASE_GATE_FETCH=0` to score
files already in `RUSTFS_ARTIFACT_DIR`.

When `RUSTFS_IMAGE` or `RUSTFS_PREV_IMAGE` is unset on a live cluster, the
gate builds `rustfs-release:<tag>` from the extracted binary
(`scripts/release-gate-image.sh`). `RUSTFS_RELEASE_GATE_BASE_IMAGE` defaults
to `debian:bookworm-slim` and `RUSTFS_RELEASE_GATE_BINARY_PATH` defaults to
`/usr/bin/rustfs`. A missing builder or binary fails the gate.

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
- `dm-error.json` — `table_has_error_target`, `reads_survived`, `recovered`.
  `SKIP-no-dm` when device-mapper is not selected. `SKIP-no-dm-device`
  (not a pass) when it is selected but the dm-run env is missing. With
  that env, catalog device-mapper scenarios use `fault-test.sh dm-run`.
- `fresh-install.json` — `health` and `live` are 200. `image_matches`
  fails the case when it is present and false.
- `rustfs-version.txt`, `rustfs-ldd.txt`, `rustfs-otool.txt`. An `ldd`
  line `lib => not found` fails dynamic-deps as `missing: lib`.

`scripts/release-gate-evidence.sh` writes fresh-install, large-object,
lifecycle, quorum-edge, and dm-error JSON on a live cluster.
`scripts/release-gate-upgrade.sh` writes the upgrade JSON and, when `warp`
is installed, `warp-compare.json`. `scripts/release-gate-host-disk.sh`
fills a dedicated volume until ENOSPC or remounts it read-only. Neither
disk script uses IOChaos. Exit 1 is a failed check or bad configuration.
Exit 2 means the tool or privilege is missing and is still a gate failure.
Exit 3 is the shared-filesystem refusal.

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
Direct `network-loss` uses 80% loss so the client-visible check is not a
coin flip; suite YAML that sets `lossPercent` keeps its own value. IOChaos
and TimeChaos stay skipped on Apple Silicon. Expect `quorum-edge-cold-read`
to fail on 1.0.1-preview.11. `quorum-edge-readiness` is a separate row.

Before the first scenario, and after a failed IOChaos run, `make fault-cleanup`
clears stuck IOChaos and PodIOChaos finalizers so the next scenario does not
inherit the fault. The port-forward used for S3 is replaced if it dies while
the tenant is still starting, including after `pod-crash-versioned-hot` and
`rolling-restart-all`.
