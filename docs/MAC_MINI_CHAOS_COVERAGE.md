# Mac Mini chaos catalog vs s3chaos

Mac Mini lab cases do not cover s3chaos. s3chaos is deeper on Kubernetes
erasure-set proofs, acknowledged-write device-mapper crashes, and admin
qualification. s3chaos also does not execute every Mac Mini family. This
matrix maps the local `C-*` ids onto the typed catalog in
`src/fault/scenarios.rs`. Statuses are taken from that catalog and the
backends that can actually apply them.

`Planned` entries are visible in `fault-catalog-json` and are rejected by
ordinary preflight. The six Mac Mini rows marked Planned below are not
qualification cases: `make fault-qualify-list` does not select them.
`Deferred` rows have no catalog scenario.

Peer A/B against Pigsty SILO or MinIO is an optional offline lab procedure.
CI does not download or run those binaries. Relative drop, error percent, and
time-to-baseline are what `warp-powerloss-metrics.json` records.

| Local ID | s3chaos scenario | Status | Runs on |
| --- | --- | --- | --- |
| C-NET-01 partition one | `network-partition-one` | Covered | CI amd64, Mac Mini arm64 |
| C-NET-02 intermittent flaky | `network-flaky` | Partial. Bursty correlated loss (`loss` 1..=40, `correlation` >= 75). One NetworkChaos action cannot also corrupt, and this is not a timed on/off gate. | CI amd64, Mac Mini arm64 |
| C-NET-03 delay | `network-delay` | Covered | CI amd64, Mac Mini arm64 |
| C-NET-04 steady loss | `network-loss` | Covered | CI amd64, Mac Mini arm64 |
| C-NET-05 one-way blackhole | `network-asymmetric-partition` | Covered. `direction: to`, `mode: one`. The write-quorum proof still requires `direction: both` and `mode: fixed`. | CI amd64, Mac Mini arm64 |
| C-NET-06 corrupt | `network-corrupt` | Covered | CI amd64, Mac Mini arm64 |
| C-NET-07 duplicate | `network-duplicate` | Covered | CI amd64, Mac Mini arm64 |
| C-PWR-01 SIGKILL | `pod-kill-one`, `pod-failure`, `node-crash-proxy` | Covered for process death. Not a PSU cycle. | CI amd64, Mac Mini arm64. `node-crash-proxy` is manual (device-mapper). |
| C-PWR-02 graceful stop | `pod-graceful-restart-one` | Covered | CI amd64, Mac Mini arm64 |
| C-PWR-03 VM / PSU hard stop | release-gate `physical-power` | Deferred. `DEFERRED-physical-power`. Kill -9 and graceful stop stay the proxy. | manual |
| C-DISK-01 detach | `io-eio` and other volume faults | Partial. IOChaos EIO is not a device detach. | CI amd64. Mac Mini arm64 is `SKIP-toda-arm64` until the chaos-daemon image ships an arm64 toda. |
| C-DISK-02 empty replace | `fresh-volume-replacement` | Planned qualification case | manual |
| C-DISK-03 bitrot | `on-disk-bitrot` | Planned qualification case. Object shards, not metadata. | manual |
| C-DISK-04 full | `disk-full` and release-gate `disk-full-fill` | IOChaos ENOSPC is CI amd64 only. `disk-full-fill` writes the volume until ENOSPC without toda. | CI amd64 for IOChaos. Mac Mini arm64 for `disk-full-fill`. |
| C-DISK-05 remount read-only | `io-read-only` and release-gate `volume-remount-ro` | IOChaos returns `EROFS` on `WRITE`. `volume-remount-ro` remounts the mount. | CI amd64 for IOChaos. Mac Mini arm64 for the remount when the pod is privileged. |
| C-DISK-06 slow disk | `io-latency` | Covered | CI amd64. Mac Mini arm64 is `SKIP-toda-arm64`. |
| C-DISK-07 two volumes, one Pod, one erasure set | `io-eio-same-pod-two-volumes` | Planned. `assess_same_pod_two_volume_geometry` fails closed. The runner still binds one volume per server. | manual |
| C-DISK-08 dm-flakey / dm-error / drop_writes | `dm-flakey`, `dm-drop-writes-after-ack-*`, release-gate `dm-error` | dm-flakey and drop-writes are executable with a pre-provisioned device. `dm-error` is scored from `dm-error.json` until it is a catalog scenario. | manual (`SKIP-no-dm` otherwise) |
| C-PROC-01 crash storm | `pod-restart-storm` | Covered. Schedule is preferred. If `status.time` is still empty after 30s, a controller loop SIGKILLs the same Pod every 15s. | CI amd64, Mac Mini arm64 |
| C-PROC-02 OOM | `stress-memory` | Partial. Memory pressure, not a cgroup `OOMKilled` proof. | CI amd64, Mac Mini arm64 |
| C-PROC-03 CPU | `stress-cpu` | Covered | CI amd64, Mac Mini arm64 |
| C-PROC-04 FD exhaustion | none | Deferred. No catalog entry. | manual |
| C-TIME-01 clock skew | `clock-skew` | Planned. TimeChaos is not wired. The release gate records `SKIP-timechaos`. | CI amd64 once TimeChaos is executable. Not arm64. |
| C-CERT-01 credential rotation mid-load | `credential-rotation-mid-load` | Planned. No rotation actuator. | manual |
| C-TOPO-01 split-brain dual partition | `network-split-brain` | Planned. Overlapping selectors isolate selected Pods from each other instead of leaving two live pairs. | manual |
| C-TOPO-02 rolling restart | `rolling-restart-all` | Covered | CI amd64, Mac Mini arm64 |
| C-TOPO-03 2/4 quorum loss | `pod-failure-quorum-edge`, `network-partition-write-quorum-loss` | Covered | CI amd64, Mac Mini arm64 |
| C-TOPO-04 cold restart | `cluster-cold-restart` | Covered | CI amd64, Mac Mini arm64 |
| C-TOPO-05 cold metadata on a survivor | release-gate `quorum-edge-cold-read` | Regression for 1.0.1-preview.11. Reads each survivor directly, including a bucket that survivor never loaded. Writes must be rejected. `/health/live` stays 200 and `/health/ready` must stay 200. | CI amd64, Mac Mini arm64 |
| C-META-01/02/03 metadata corruption | `metadata-shard-corruption` | Planned. Distinct from planned object-shard `on-disk-bitrot`. | manual |
| C-LOAD-01 Warp under power loss | `warp-under-chaos` | Partial. `warp-powerloss-metrics.json` records in-run baseline ops/s, degraded ops/s, drop percent, fault-window error percent, and time-to-baseline (REACHED or NOT_REACHED). Node ready lag is `NOT_APPLICABLE` because the campaign is IOChaos EIO, not a node stop. Peer compare is `not-in-ci`. `NOT_REACHED` does not fail the run. | CI amd64. Mac Mini arm64 is `SKIP-toda-arm64`. |
| C-LOAD-02 disk fault during multipart PUT | `io-eio-during-multipart` | Covered. Same single-volume EIO proof as `io-eio`, with the multipart-heavy workload profile. | CI amd64. Mac Mini arm64 is `SKIP-toda-arm64`. |
| C-LOAD-03 partition during heal | `network-partition-during-heal` | Planned. Heal progress is only recorded inside qualification workflows and is not composable with NetworkChaos. | manual |
| C-FUNC-01 S3 smoke | release-gate `protocol:protocol/examples/smoke.yaml` | Protocol smoke suite | CI amd64, Mac Mini arm64 |
| C-FUNC-02 versioning | release-gate `protocol:protocol/examples/full-regression.yaml` | Protocol regression includes versioning | CI amd64, Mac Mini arm64 |
| C-FUNC-03 lifecycle | release-gate `s3-lifecycle-rule` | ILM import, list, and GET. Score `lifecycle-rule.json` or the upgrade script. | CI amd64, Mac Mini arm64 |
| C-FUNC-04 large GET | release-gate `large-object-get-integrity` | Full body length plus sha256. Truncation fails the case. | CI amd64, Mac Mini arm64 |
| C-PERF-01 warp regression | release-gate `warp-regression-vs-previous` | PUT/GET/mixed ops/s versus the previous release. Default threshold is 20%. | CI amd64, Mac Mini arm64 |
| C-ADMIN-01 expand | release-gate `expand-pools` | Pools must increase and object integrity must hold. | manual |
| C-ADMIN-02 rebalance | `admin-rebalance`, release-gate `admin-rebalance-complete` | Planned qualification. The gate fails a status that is not terminal success. | manual |
| C-ADMIN-03 decommission | `admin-decommission`, release-gate `admin-decommission-complete` | Planned qualification. Pass requires `complete: true`. | manual |
| C-UPG-01 rolling upgrade | release-gate `upgrade-stability` | Previous release dataset, then rolling upgrade under the new image. | CI amd64, Mac Mini arm64 when `RUSTFS_PREV_VERSION` is set |
| C-UPG-02 rollback | release-gate `upgrade-rollback` | Downgrade after the upgrade and read the same dataset. | CI amd64, Mac Mini arm64 when `RUSTFS_PREV_VERSION` is set |
| C-UPG-03 fresh install | release-gate `fresh-install` | `/health` and `/health/live` are 200 on the new image. | CI amd64, Mac Mini arm64 |
| C-REL-01 release artifacts | `release-artifact-checksums`, `release-artifact-version`, `release-artifact-dynamic-deps` | SHA256SUMS, `--version` contains the tag, and `ldd` / `otool -L` show no non-system libraries (Homebrew `liblzma` fails). | CI amd64, Mac Mini arm64 |

`fault/examples/warp-powerloss.yaml` is the suite that runs `warp-under-chaos`
for the metrics artifact. `fault/examples/chaos-mesh.yaml` includes the
executable Chaos Mesh scenarios and still excludes Warp.

The release gate in `docs/RELEASE_GATE.md` is the single entry point that
selects these rows by tier. CI amd64 is `.github/workflows/release-gate.yml`.
Mac Mini arm64 is a self-hosted full tier: OrbStack or Lima, k3s, Chaos Mesh,
`RUSTFS_FAULT_TEST_TENANT_SPREAD_ACROSS_HOSTS=false` (one Ready node is then
enough). IOChaos and TimeChaos stay `SKIP-toda-arm64` / `SKIP-timechaos` on
that host because the arm64 chaos-daemon image's toda binary is amd64.
