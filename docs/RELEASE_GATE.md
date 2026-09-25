# RustFS release gate

`make release-gate` is the entry point for one RustFS release tag. It records
the version, previous version, image, git SHA, and artifact checksums, then
runs a tier of cases and writes:

- `target/release-gate/<version>/release-gate.json`
- `target/release-gate/<version>/release-gate.junit.xml`
- `target/release-gate/<version>/RELEASE_GATE.md`

Each case is `PASS`, `FAIL`, or `SKIP`. A skip reason starts with a stable
code. A live run fails if a required case was skipped because no cluster was
available. These skips do not fail the gate:

| Code | When it is allowed |
| --- | --- |
| `SKIP-dry-run` | `RELEASE_GATE_DRY_RUN=1` |
| `SKIP-toda-arm64` | IOChaos or warp-under-chaos on an arch whose chaos-daemon toda binary cannot run (Apple Silicon) |
| `SKIP-no-dm` | device-mapper scenarios without a pre-provisioned Linux device |
| `SKIP-timechaos` | `clock-skew`; TimeChaos is still catalog-planned |
| `SKIP-planned` | catalog-planned admin and storage qualification, or a check that only has a scorer |
| `DEFERRED-physical-power` | physical PSU cycle; `pod-kill-one` and `pod-graceful-restart-one` are the proxy |
| `SKIP-no-prev-version` | upgrade, rollback, or warp regression without `RUSTFS_PREV_VERSION` |
| `SKIP-no-artifact` | checksum, `--version`, or `ldd`/`otool` input was not fetched |
| `SKIP-no-baseline` | warp regression without `warp-compare.json` |
| `SKIP-no-cluster` | dry-run only; a live run treats this as a gate failure |
| `SKIP-no-mc` | upgrade script has no `mc` or tenant |
| `SKIP-no-privileged` | volume remount or fill could not run inside the pod |

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

`RELEASE_GATE_FETCH=1` (the Make default) downloads `SHA256SUMS` and the Linux
assets from `rustfs/rustfs` and checks them. Set `RELEASE_GATE_FETCH=0` to
score files already in `RUSTFS_ARTIFACT_DIR`.

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

- `quorum-edge-cold-read.json` — `survivors[]` with `cold_bucket`, GET
  counts, `wrong_sha256`, rejected PUTs, `health_live`, `health_ready`.
  Preview.11 fails: the cold survivor returns 503 and every survivor's
  `/health/ready` is 503.
- `large-object-get.json` — `expected_len`, `actual_len`, `expected_sha256`,
  `actual_sha256`. A short body fails.
- `warp-compare.json` — `current_ops`, `baseline_ops`. Default regression
  threshold is `RUSTFS_WARP_REGRESSION_PERCENT=20`.
- `upgrade-stability.json` and `upgrade-rollback.json` — object, multipart,
  version, lifecycle, and policy booleans, plus `client_errors` and
  `error_threshold`. Rollback also needs `rolled_back: true`.
- `lifecycle-rule.json` — `rule_accepted`, `listed_enabled`, `get_matches`.
- `expand-status.json` — `pools_before`, `pools_after`, `integrity_ok`.
- `decommission-status.json` — `complete: true`.
- `rebalance-status.json` — `stopped`, `integrity_ok`.
  A live run that selected these cases fails when the file is missing.
  Dry-run records `SKIP-dry-run`. `dm-error.json` is `SKIP-no-dm` unless
  `RUSTFS_RELEASE_GATE_HAS_DM=1`.
- `disk-full-fill.json`, `volume-remount-ro.json`, `dm-error.json`.
- `fresh-install.json` — `health` and `live` are 200. A live run without
  this file fails; tenant preflight does not prove a fresh install.
- Upgrade needs `RUSTFS_PREV_IMAGE` (the previous container image).
  `client_errors` counts post-rollout object reads that fail; the threshold
  in the written JSON is 0. A background `mc stat` loop runs during rollout.
- `rustfs-version.txt`, `rustfs-ldd.txt`, `rustfs-otool.txt`.

`scripts/release-gate-upgrade.sh` writes the upgrade JSON when `mc` and
kubectl can see the tenant. `scripts/release-gate-host-disk.sh` fills a
volume until ENOSPC or remounts it read-only. Neither script uses IOChaos.

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
Device-mapper rows stay `SKIP-no-dm` unless a Lima privileged VM has the
device and `RUSTFS_RELEASE_GATE_HAS_DM=1`. IOChaos and TimeChaos stay skipped
on Apple Silicon. Expect `quorum-edge-cold-read` to fail on 1.0.1-preview.11.

Before the first scenario, and after a failed IOChaos run, `make fault-cleanup`
clears stuck IOChaos and PodIOChaos finalizers so the next scenario does not
inherit the fault. The port-forward used for S3 is replaced if it dies while
the tenant is still starting, including after `pod-crash-versioned-hot` and
`rolling-restart-all`.
