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

| Local ID | s3chaos scenario | Status |
| --- | --- | --- |
| C-NET-01 partition one | `network-partition-one` | Covered |
| C-NET-02 intermittent flaky | `network-flaky` | Partial. Bursty correlated loss (`loss` 1..=40, `correlation` >= 75). One NetworkChaos action cannot also corrupt, and this is not a timed on/off gate. |
| C-NET-03 delay | `network-delay` | Covered |
| C-NET-04 steady loss | `network-loss` | Covered |
| C-NET-05 one-way blackhole | `network-asymmetric-partition` | Covered. `direction: to`, `mode: one`. The write-quorum proof still requires `direction: both` and `mode: fixed`. |
| C-PWR-01 SIGKILL | `pod-kill-one`, `pod-failure`, `node-crash-proxy` | Covered for process death. Not a PSU cycle. |
| C-PWR-02 graceful stop | `pod-graceful-restart-one` | Covered |
| C-PWR-03 VM / PSU hard stop | none | Deferred. `docs/DURABILITY_FAULT_TESTING_TODO.md` §13. |
| C-DISK-01 detach | `io-eio` and other volume faults | Partial. IOChaos EIO is not a device detach. |
| C-DISK-02 empty replace | `fresh-volume-replacement` | Planned qualification case |
| C-DISK-03 bitrot | `on-disk-bitrot` | Planned qualification case. Object shards, not metadata. |
| C-DISK-04 full | `disk-full` | Covered |
| C-DISK-05 remount read-only | `io-read-only` | Partial. IOChaos returns `EROFS` (errno 30) on `WRITE`. It does not remount the volume. |
| C-DISK-06 slow disk | `io-latency` | Covered |
| C-DISK-07 two volumes, one Pod, one erasure set | `io-eio-same-pod-two-volumes` | Planned. `assess_same_pod_two_volume_geometry` fails closed. The runner still binds one volume per server. |
| C-PROC-01 crash storm | `pod-restart-storm` | Covered. Chaos Mesh `Schedule` kills the highest-ordinal Pod every 15s. Activation is one kill plus the schedule staying armed. |
| C-PROC-02 OOM | `stress-memory` | Partial. Memory pressure, not a cgroup `OOMKilled` proof. |
| C-PROC-03 CPU | `stress-cpu` | Covered |
| C-PROC-04 FD exhaustion | none | Deferred. No catalog entry. |
| C-TIME-01 clock skew | `clock-skew` | Planned. TimeChaos is not wired. |
| C-CERT-01 credential rotation mid-load | `credential-rotation-mid-load` | Planned. No rotation actuator. |
| C-TOPO-01 split-brain dual partition | `network-split-brain` | Planned. Overlapping selectors isolate selected Pods from each other instead of leaving two live pairs. |
| C-TOPO-02 rolling restart | `rolling-restart-all` | Covered |
| C-TOPO-03 2/4 quorum loss | `pod-failure-quorum-edge`, `network-partition-write-quorum-loss` | Covered |
| C-TOPO-04 cold restart | `cluster-cold-restart` | Covered |
| C-META-01/02/03 metadata corruption | `metadata-shard-corruption` | Planned. Distinct from planned object-shard `on-disk-bitrot`. |
| C-LOAD-01 Warp under power loss | `warp-under-chaos` | Partial. `warp-powerloss-metrics.json` records in-run baseline ops/s, degraded ops/s, drop percent, fault-window error percent, and time-to-baseline (REACHED or NOT_REACHED). Node ready lag is `NOT_APPLICABLE` because the campaign is IOChaos EIO, not a node stop. Peer compare is `not-in-ci`. `NOT_REACHED` does not fail the run. |
| C-LOAD-02 disk fault during multipart PUT | `io-eio-during-multipart` | Covered. Same single-volume EIO proof as `io-eio`, with the multipart-heavy workload profile. |
| C-LOAD-03 partition during heal | `network-partition-during-heal` | Planned. Heal progress is only recorded inside qualification workflows and is not composable with NetworkChaos. |

`fault/examples/warp-powerloss.yaml` is the suite that runs `warp-under-chaos`
for the metrics artifact. `fault/examples/chaos-mesh.yaml` includes the new
executable Chaos Mesh scenarios and still excludes Warp.
