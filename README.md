# s3chaos

S3Chaos is a testing framework for RustFS, the S3-compatible object store.
It provides two complementary harnesses that run against RustFS deployments
on Kubernetes:

- **Fault injection** (`src/fault/`): injects real failures into a RustFS
  cluster — disk I/O errors, network partitions, pod kills, resource stress,
  quorum loss — drives mixed S3 workloads through the failure window, then
  verifies recovery and data integrity.
- **S3 protocol compatibility** (`src/protocol/`): exercises RustFS's S3 API
  surface with native test cases across authorization, IAM, STS, OIDC,
  bucket policy, and a bounded compatibility supplement alongside Mint.

## Architecture

```
src/
  bin/s3chaos.rs     CLI entry point ("s3chaos" binary); s3chaos/ holds its
                     console server module
  fault/             Fault-injection framework: scenario catalog, backends
                     (Chaos Mesh, host device-mapper), workload generation,
                     history capture, post-recovery checker, run lifecycle,
                     artifact validation, console
  protocol/          Protocol harness: native cases (cases/), capability
                     catalog (catalog/), S3/STS/admin/Keycloak clients,
                     fixture registry with ownership + durable cleanup,
                     preflight, runner, reporting
  framework/         Shared Kubernetes plumbing: kube client, kubectl wrapper,
                     port-forward, tenant factory, wait helpers
scripts/             Shell entry points invoked by Make targets
protocol/
  examples/          Ready-to-run suite YAMLs: smoke, full-regression,
                     slow-regression, oidc-keycloak
fault/
  examples/          Ready-to-run fault suites: canonical Chaos Mesh,
                     focused correctness suites, Warp performance
console/             Web console assets served by the run console
```

The `s3chaos` CLI exposes machine-readable commands (`fault-catalog-json`,
`fault-qualification-catalog-json`, `protocol-catalog-json`,
`*-suite-json`, ...) used by scripts, CI, and the console. There is no
installed binary on a fresh checkout; run commands via Cargo:

```bash
cargo run --quiet --bin s3chaos -- help
```

## Build and Static Checks

```bash
make check            # cargo fmt --check + clippy -D warnings + tests
make fault-check      # check + fault script/YAML validation
make protocol-check   # check + bash -n on protocol scripts
```

## Release gate

`make release-gate RUSTFS_VERSION=<tag>` plans or runs the smoke, standard,
or full tier for one RustFS release, including upgrade from
`RUSTFS_PREV_VERSION` and a JSON/JUnit/Markdown report. Tiers, skip codes,
and the Mac Mini arm64 limits are in `docs/RELEASE_GATE.md`.

## Fault-Injection Testing

The normal correctness workflow uses one foreground command for all ordinary
Chaos Mesh scenarios and one foreground command for exactly one device-mapper
scenario:

```bash
make fault-list                                      # executable scenario list
make fault-chaos-run                                 # canonical 20-attempt suite
make fault-dm-run SCENARIO=dm-flakey-versioned-hot  # one supervised DM run
make fault-dm-run SCENARIO=node-crash-proxy         # DM crash + node held down
make fault-console-serve                             # browse run artifacts

# Pin the context, namespace, and tenant recorded in the run's target proof.
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<run-context>'
export RUSTFS_FAULT_TEST_NAMESPACE='<run-namespace>'
export RUSTFS_FAULT_TEST_TENANT='<run-tenant>'
make fault-cleanup                                   # release cluster fixtures
```

Both live targets build once and run cluster preflight once. The Chaos wrapper
uses one pre-run plan pass. `make fault-preflight SCENARIO=...` is available for
standalone diagnostics, but it is not a required execution step.
Use `make fault-chaos-plan` only when reviewing the resolved plan without
starting the suite. Override the canonical suite with
`CHAOS_SUITE=/path/to/suite.yaml`; `fault-chaos-run` rejects static storage and
Warp plans. The generic `fault-suite-*` targets remain available for custom
non-static suites and the separate Warp campaign.

Runnable scenario families (35 executable entries): I/O faults (`io-eio`,
`io-eio-during-multipart`, `io-read-mistake`, `io-read-only`, `io-latency`,
`disk-full`, `dm-flakey*`, and the five typed `dm-drop-writes-after-ack-*`
cases), network faults (`network-partition-one`,
`network-asymmetric-partition`, `network-partition-write-quorum-loss`,
`network-delay/loss/flaky/corrupt/duplicate`), pod faults (`pod-kill-one`,
`pod-restart-storm`, `pod-failure`, `pod-crash-versioned-hot`),
kubectl-driven lifecycle restarts (`pod-graceful-restart-one`,
`rolling-restart-all`, `cluster-cold-restart`), stress (`stress-cpu`,
`stress-memory`), typed volume quorum (`quorum-p-io-fault`,
`quorum-p-plus-one-io-fault`), and the `warp-under-chaos` benchmark campaign.
Each typed volume quorum run captures bounded RustFS admin health samples before
its probes/workload and after the workload/controller recheck; both samples
require every non-target drive to be healthy and do not claim continuous health.
Five catalog entries remain qualification-only with status `Planned`
(`fresh-volume-replacement`, admin decommission and
rebalance, `on-disk-bitrot`, `stale-disk-return-detect`): they appear in
`cargo run --bin s3chaos -- fault-catalog-json` but are filtered out of
`make fault-list` and rejected by ordinary preflight and suite validation.
Their concrete drivers are reachable only through the closed local
qualification workflow described below.
Six further `Planned` entries record Mac Mini families that have no safe
actuator yet (`io-eio-same-pod-two-volumes`, `network-partition-during-heal`,
`clock-skew`, `credential-rotation-mid-load`, `network-split-brain`,
`metadata-shard-corruption`). They are catalog-only and are not qualification
cases. The coverage matrix is
[`docs/MAC_MINI_CHAOS_COVERAGE.md`](docs/MAC_MINI_CHAOS_COVERAGE.md).
Heal is a recovery mode of replacement and bitrot rather than a standalone
healthy-cluster scenario. Long-running campaigns remain suite orchestration,
not a fault backend or scenario family.
The ordered durability work queue and its safety prerequisites remain in
[`docs/DURABILITY_FAULT_TESTING_TODO.md`](docs/DURABILITY_FAULT_TESTING_TODO.md).
Volume-quorum runs require matching RustFS non-target drive-health observations
before and after the workload. These endpoint guards are not continuous health
monitoring; live qualification is still required before release gating.

### Planned reliability qualification

List the seven closed qualification cases, derived from the Rust typed catalog,
and run exactly one through the same health watcher, evidence capture, artifact
validation, and interruption-safe supervision used by executable fault
scenarios:

```bash
make fault-qualify-list

export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<exact-current-context>'
export RUSTFS_FAULT_TEST_NAMESPACE='<owned-fault-namespace>'
export RUSTFS_FAULT_TEST_TENANT='<owned-fault-tenant>'
export RUSTFS_FAULT_TEST_SERVER_IMAGE='<rustfs-image>'
export RUSTFS_FAULT_TEST_STORAGE_CLASS='<dedicated-storage-class>'
make fault-qualify QUALIFICATION_CASE=admin-rebalance
```

The command always enables the destructive gate itself, but it does not infer
or default the cluster identity. Admin qualification requires dynamic storage.
Fresh-volume qualification additionally requires a no-provisioner StorageClass,
one Local PV specification per server plus one held-back replacement,
`RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE`, the exact Operator Deployment, and
host/PV allowlists. Fresh-volume and bitrot require Chaos Mesh for their
exact-quorum IOChaos proof. Bitrot additionally requires an absolute,
operator-reviewed `RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG`, its
pre-created privileged storage helper, and a privileged owned namespace.
The bitrot inspector is not pinned to a RustFS release or tag. It explicitly
accepts the current XL2 1.3/header 3/meta 3 on-disk capability profile with
format version 1, erasure version 3, and SIPMOD+PARITY checksums, and fails
closed when an unknown profile is encountered.
Stale-disk cases require the existing supervised device-mapper environment.

Every invocation gets a case-qualified run root under
`target/fault-tests/qualifications/` unless `RUSTFS_FAULT_TEST_RUN_ROOT` is
explicitly set. The run root contains `qualification-plan.json`,
`qualification-result.json`, `validation-summary.tsv`, the case artifacts,
health observations, cluster snapshots, RustFS logs, and failure diagnostics.
Successful runs validate their artifacts before returning. Analyze either a
successful or failed run as machine-readable JSON, or open the local console:

```bash
make fault-qualify-analyze RUN_ROOT='<printed-run-root>'
make fault-console-serve CONSOLE_ROOT='<printed-run-root>'
```

Inspect and validate the captured run before setting its recorded context,
namespace, and Tenant for `make fault-cleanup`. Planned qualification remains a
single-run workflow and is intentionally unavailable through FaultSuite.

Ready-to-run suites under [`fault/examples/`](fault/examples/) keep different
execution environments and verdicts separate:

| Suite | Scope | Additional requirement |
| --- | --- | --- |
| `chaos-mesh.yaml` | Canonical 25-attempt correctness run: smoke, regression, four typed quorum checks, and the two-Pod quorum edge | Dedicated cluster with Chaos Mesh; reference four-server single-erasure-set topology for the write-quorum boundary. `pod-restart-storm` also needs the Chaos Mesh Schedule CRD |
| `smoke.yaml` | Six short correctness and recovery checks across I/O, pod, and network faults | Dedicated cluster with Chaos Mesh |
| `regression.yaml` | Remaining ordinary Chaos Mesh scenarios, including the write-quorum boundary, one-way partition, bursty loss, read-only IOChaos, multipart EIO, and the pod-kill schedule | Reference four-server single-erasure-set topology for `network-partition-write-quorum-loss` |
| `quorum-reliability.yaml` | Four payload/metadata checks at the P and P+1 volume boundaries, plus the two-Pod quorum edge | Reference four-server single-erasure-set topology |
| `restart.yaml` | Graceful single-Pod restart, ordered rolling restart, and held cold restart driven through kubectl (no Chaos Mesh, so run it with `make fault-suite-run`; `fault-chaos-run` rejects it) | StatefulSet-managed Tenant; `cluster-cold-restart` also needs `RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT` naming the RustFS operator Deployment it pauses |
| `warp-performance.yaml` | Performance-only Warp-under-chaos campaign; correctness still comes from the normal checker | `warp` on `PATH`; Warp defaults to 60 seconds. Writes `warp-powerloss-metrics.json` |
| `warp-powerloss.yaml` | Same Warp campaign, named for the power-loss metrics artifact | `warp` on `PATH`. Peer A/B is offline only; see `docs/MAC_MINI_CHAOS_COVERAGE.md` |

The Rust runner owns `budgets.maxDuration` for both `make fault-suite-run`
and direct `s3chaos fault-suite-run` invocations. Expiration fails the suite,
including its final attempt, and stops admitting workload operations. In-flight
multipart operations and cleanup are drained before returning; device recovery
and synchronous external commands may finish after the budget. The shell wrapper
continues to supervise cluster health independently.

Warp planning requires a positive `RUSTFS_FAULT_TEST_WARP_DURATION_SECONDS`
strictly below `faultDuration - RUSTFS_FAULT_TEST_TIMEOUT_SECONDS` to leave
headroom for post-Warp operations. With this suite's 15-minute fault window and
the default 300-second timeout, Warp must be shorter than 600 seconds. When
increasing Warp duration, increase `faultDuration` and the suite's `maxDuration`
as needed, then run `make fault-suite-plan SUITE=fault/examples/warp-performance.yaml`
with the intended environment. Static `fault-suite-validate` checks YAML only.
This headroom is not a runtime guarantee: Warp setup and the correctness workload
also take time, and the run fails if the fault expires before they finish.

Each suite runs its scenarios sequentially to keep their conflict domains from
overlapping. Device-mapper scenarios are excluded from multi-attempt suites and
must run one at a time under operator supervision. Do not run multiple fault
suites concurrently against the same fault-test namespace. CI validates these
YAML contracts only; it never starts a destructive suite.

All seven device-mapper scenarios need host preparation beyond the environment
variables below: a device-mapper table over a dedicated block device, a static
local PV/storage class, and scenario-specific variables
(`RUSTFS_FAULT_TEST_DM_NAME`, `RUSTFS_FAULT_TEST_DM_NODE`,
`RUSTFS_FAULT_TEST_DM_MOUNT_PATH`, a separate pre-provisioned read-only host
observer, backend-specific destructive opt-in, exact node/device/PV allowlists,
plus a fault table name for legacy `dm-flakey`). Follow
[`docs/DM_FLAKEY.md`](docs/DM_FLAKEY.md) for the complete host device, static
Local PV, observer, privileged namespace, run, and teardown process.
There is no Make target that provisions or removes the host devices.

Required environment for non-static scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
```

`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` (optional) pins the run to an expected
dedicated Kubernetes/K3s context and aborts if the current context differs.
Workload size and concurrency are tunable via `RUSTFS_FAULT_TEST_WORKLOAD_*`
variables; see `src/fault/config.rs`.

After a live scenario or suite starts, a runner, health guard, signal, or
artifact-check failure first preserves a failed cluster snapshot, current and
previous RustFS logs, `runner-failure-summary.json`, `runner-diagnosis.txt`, and
`failure-evidence.json`. The wrapper removes residual managed Chaos only after
those files are written. The run directory remains available for diagnosis;
verify it before the separate cluster-scoped `fault-cleanup` step.

Every scenario proves recovery beyond S3 readability. Before the fault the
runner captures the healthy RustFS layout from `/rustfs/admin/v3/info`; after
Tenant readiness and the stable Pod window it polls until every baseline
drive reports `ok`, the deployment identity and erasure geometry are
unchanged, and every RustFS Pod answers `/health/ready` through the API
server Pod proxy (`recovery-health.json`, failure classification
`recovery_health_degraded`). It then writes, reads back, lists, and deletes a
small set of fresh objects under a run-scoped prefix outside the workload
prefix (`post-recovery-write-report.json` plus its own
`post-recovery-write-history.jsonl`, classification
`post_recovery_write_failed`). The final checker also rejects listed keys that
no write explains or that GET cannot read back (`listed_key_unreadable`,
`unexpected_listed_object`). Scenarios whose fault stays inside RustFS
redundancy (`pod-kill-one`, `pod-failure`, `network-partition-one`) carry the
`availability-required` impact policy: every prefilled object must read back
with its committed hash while the fault is active and each mixed-workload
operation family must reach `RUSTFS_FAULT_TEST_MIN_AVAILABILITY_PERCENT`
non-disrupted operations (`availability-report.json`, classification
`availability_regression`). The catalog floor is 99; the variable may only
raise it. A floor below 100 tolerates one disrupted operation per family, and
a family with fewer than 20 operations under the fault is not evidence and
fails closed; plans that cannot reach it (240 objects with the default
operation mix) are rejected at planning and by `fault-suite-validate` rather
than after the fault window. Because a `kubectl port-forward` stays pinned to
one Pod, the runner re-pins the S3 endpoint to a surviving Pod that the Chaos
Mesh controller did not target once the fault is active, so the contract
measures a client attached to a healthy node; ClusterIP endpoints need no
pinning. These contracts are not yet calibrated on a live cluster; treat the
first live runs as calibration.
The lifecycle scenarios (`kubernetes-lifecycle` backend) restart RustFS
through kubectl instead of Chaos Mesh. The RustFS operator writes the Tenant
StatefulSet with server-side apply and owns `spec.replicas` and the Pod
template annotations, so a `kubectl scale` or `rollout restart` makes kubectl
a co-owner of those fields and the operator's next apply conflicts
(`StatefulSetApplyFailed`) instead of converging. The scenarios therefore
delete Pods with the default `terminationGracePeriodSeconds` and capture each
RustFS container's final `terminated` state from a streaming Pod watch
(`pod-lifecycle-watch.json`, kubectl stderr in
`pod-lifecycle-watch.stderr.log`); the SIGTERM reference is the graceful
delete's `deletionTimestamp - deletionGracePeriodSeconds`, never kubelet's
final grace-0 rewrite. A container that is SIGKILLed at grace expiry, dies to
SIGTERM's default action, or exits non-zero fails the run as
`graceful_shutdown_failed`; a replacement that never becomes Ready or restarts
before Ready fails as `product_or_environment`, and a StatefulSet whose UID
changes fails too (`pod-lifecycle-evidence.json`). `pod-graceful-restart-one`
and `rolling-restart-all` issue their first delete only after the first
fault-phase S3 request has started (checked against `history.jsonl`), so
SIGTERM lands under load; the StatefulSet must be converged on one revision,
every replacement must run it, and replacements are tracked past Ready and
re-read after the recovery gate; the rolling restart goes from
the highest ordinal down and, with a port-forward endpoint, pins all client
traffic to the smallest-name Pod and restarts that Pod only after the
workload. `cluster-cold-restart` runs on a fresh Tenant fixture (the scale
leaves `kubectl-scale` co-owning `spec.replicas`), requires
`podManagementPolicy: Parallel`, pauses the operator Deployment named by
`RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT` (in
`RUSTFS_FAULT_TEST_OPERATOR_NAMESPACE`; it must run an image containing
`RUSTFS_FAULT_TEST_OPERATOR_IMAGE_MATCH`, default `rustfs/operator`) by
recording the pause as annotations on that Deployment and scaling it to zero,
drains every Pod before the workload, samples `spec.replicas` and the Pod count every second while the outage is
held, requires every workload operation to fail, then
scales both back. The operator is restored when the run unwinds normally or
on a signal; if the harness is killed outright, the annotations remain and
the next `cluster-cold-restart` pre-cleanup or `make fault-cleanup` restores
the operator from them. `make fault-cleanup` restores any paused operator (so a Tenant finalizer that
needs it can complete), then removes the fixture namespace with a bounded wait
(`RUSTFS_FAULT_TEST_NAMESPACE_DELETE_TIMEOUT`, default 600s) and checks
residual Chaos resources; both parts always run and cleanup exits non-zero if
either failed. The restore is skipped with a warning only on an explicit RBAC
"no"; an unreadable record or an undeterminable permission fails. The other lifecycle scenarios warn at pre-cleanup
when they can read a leftover pause record.
These scenarios have not yet been calibrated on a live cluster.
`make fault-dashboard-install` mutates the current cluster (installs/upgrades
the Chaos Mesh release via Helm); treat it like a live run.
`make fault-cleanup` is scoped by the current Kubernetes context, namespace,
and tenant; it does not consume an artifact root. Verify those values against
the run and pin `RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` before cleanup.

## S3 Protocol Testing

Two complementary execution layers:

1. **Native cases** (`src/protocol/cases/`): Rust test cases over authz,
   IAM, STS, OIDC (Keycloak-backed `AssumeRoleWithWebIdentity`), bucket
   policy, and a bounded compatibility supplement, with fixture ownership and
   durable cleanup. Native case results do not claim coverage of an external
   conformance suite.
2. **Mint**: black-box SDK compatibility run via
   `make protocol-compatibility-mint`. The default audited profile pins the
   `aws-sdk-php` core suite, image digest, platform, exact function inventory,
   and known-failure baseline. It accepts only a leased, run-owned Kubernetes
   namespace, captures RustFS evidence, and deletes that namespace after every
   completed, failed, timed-out, or interrupted run. Its exit status requires
   both the structured Mint gate and verified teardown to pass.

A live protocol run requires more than the fault-side inputs:

```bash
export RUSTFS_PROTOCOL_COMPAT_SERVER_ENDPOINT=<host:port>       # or RUSTFS_PROTOCOL_TEST_ENDPOINT per suite
export RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=<key>
export RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=<secret>
export RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT=<verified 64-character SHA-256>
```

Destructive execution additionally demands two acknowledgements that the
target is a verified dedicated server:

- `RUSTFS_PROTOCOL_TEST_DEDICATED=1`.
- `RUSTFS_PROTOCOL_TEST_TARGET_FINGERPRINT=<sha256>` pinning the exact server
  identity. Run `make protocol-suite-plan SUITE=...` once: its JSON output
  contains `target.fingerprint.sha256` computed from the server-reported
  deployment id; copy that value into the variable. A changed server
  fingerprint aborts the run instead of testing the wrong target.

Mint has a stricter target boundary. Deploy RustFS into a new namespace on the
independent test server, label that namespace and every pod with the same run
id, then create a target file from
`protocol/mint/ephemeral-target.example.yaml`. The namespace must have:

```text
app.kubernetes.io/managed-by=s3chaos-mint
rustfs.com/mint-run-id=<run-id>
rustfs.com/mint-expires-at=<same RFC3339 value as target expiresAt>
```

The target file pins the exact kube context, namespace UID, lease, Service,
endpoint, region, RustFS container image digest, and server fingerprint. The
endpoint must be an address or DNS name advertised by that Service, whose
owned EndpointSlices must resolve only to the proved RustFS Pod UIDs. It is a
destructive hand-off: after ownership and readiness are proven, s3chaos owns
the whole namespace and will delete it with a Kubernetes UID precondition.
Do not point it at a shared or long-lived namespace.

```bash
export RUSTFS_PROTOCOL_TEST_DEDICATED=1
export RUSTFS_PROTOCOL_MINT_TARGET_SPEC=/path/to/ephemeral-target.yaml
export RUSTFS_PROTOCOL_TEST_ADMIN_ACCESS_KEY=<key>
export RUSTFS_PROTOCOL_TEST_ADMIN_SECRET_KEY=<secret>
make protocol-compatibility-mint
```

For the `oidc-keycloak` example profile you also need a prepared Keycloak
realm and matching RustFS OIDC configuration:

- Keycloak: dedicated realm, confidential client with direct access grants
  enabled, and an ID-token protocol mapper of type "user attribute" mapping
  the user attribute `policy` to an ID-token claim `policy` (multivalued
  enabled; a single string is also accepted). The Keycloak admin user needs
  permission to create and delete users in that realm.
- RustFS server: `RUSTFS_IDENTITY_OPENID_ENABLE=on`,
  `RUSTFS_IDENTITY_OPENID_CONFIG_URL=<issuer/discovery URL>`,
  `RUSTFS_IDENTITY_OPENID_CLIENT_ID/_CLIENT_SECRET`, and
  `RUSTFS_IDENTITY_OPENID_CLAIM_NAME=policy`.
- s3chaos client: `RUSTFS_PROTOCOL_OIDC_ISSUER`, `_ADMIN_URL`, `_REALM`,
  `_CLIENT_ID`, `_CLIENT_SECRET`, `_ADMIN_USERNAME`, `_ADMIN_PASSWORD`,
  `_ADMIN_REALM` (see constants in `src/protocol/clients/keycloak.rs`).

```bash
make protocol-list                                            # case catalog
make protocol-compatibility-mint                              # audited Mint run
make protocol-validate-mint-session ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>
make protocol-validate-mint-artifacts ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>/mint
make protocol-mint-cleanup ARTIFACT_ROOT=target/protocol-compatibility/mint/<run> # crash recovery only
make protocol-suite-template                                  # suite skeleton
make protocol-suite-validate SUITE=protocol/examples/smoke.yaml
make protocol-suite-plan SUITE=protocol/examples/smoke.yaml   # dry-run expansion
make protocol-suite-run SUITE=protocol/examples/smoke.yaml    # live run
make protocol-validate-artifacts ARTIFACT_ROOT=target/protocol-tests/<run>  # verify run artifacts first
make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/<run>             # then release fixtures
```

Suite YAML may carry a `contracts` block for RustFS behaviors that are not
settled yet; every key and value is validated and unknown ones fail
`protocol-suite-validate`. Today it holds
`forceDeleteHeaderSingleObject` (`ignore-header`, the default, or `reject`),
asserted by `delete-force-header-contract` for a non-owner single-object
DeleteObject that carries `X-Rustfs-Force-Delete: true`
(rustfs/rustfs#7649). The selected value is recorded in
`protocol-suite-plan.json`. `full-regression.yaml` pins `reject`, the
behavior RustFS main enforces today, so the release-candidate gate is not
permanently red; flip it to `ignore-header` once #7649 settles.

Validate before cleanup: for a failed or interrupted run the artifact root is
the only record of what happened on the server, and cleanup deletes registered
fixtures.

## CI

- `.github/workflows/ci.yml`: fmt/clippy/tests plus static validation of fault
  suites, protocol contracts, all example profiles, and shell lint. No cluster
  needed; fault suites are never executed by CI.
- `.github/workflows/protocol-live.yml`: live RustFS suites (smoke gate,
  native regression, expiration regression, external OIDC regression) on the
  shared `sm-standard-4` runner. It is intentionally not a pull-request gate:
  pull requests have no live-target credentials, and `.github/workflows/ci.yml`
  owns their static protocol validation. Full live execution runs on
  `workflow_dispatch` (inputs `rustfs_image_digest`, `rustfs_version`, and an
  optional `rustfs_endpoint` +
  `rustfs_target_fingerprint` pair that redirects the run to a
  per-candidate target) and on `repository_dispatch` with event type
  `rustfs-release-candidate`, which the rustfs repository sends for every
  release candidate with the same keys in `client_payload`, for example:
  `gh api repos/rustfs/s3chaos/dispatches -f event_type=rustfs-release-candidate -f 'client_payload[rustfs_version]=1.0.0-rc.6' -f 'client_payload[rustfs_image_digest]=sha256:...'`.
  A `validate-inputs` job gates every live job: dispatch values are
  character-restricted, and an endpoint override is honored only when its
  host is listed in the `PROTOCOL_LIVE_ENDPOINT_ALLOWLIST` repository
  variable (comma-separated hosts; unset refuses all overrides). Build
  provenance, the override host, and the allowlist decision are written to
  the run summary and to `target-provenance.env` inside every uploaded
  artifact; flake history under `.history/` is keyed by profile and target
  fingerprint so a redirected run never pollutes the shared target's
  signals. Mint is
  run by command on the independent Kubernetes test server; no Mint workflow
  or schedule is installed by this repository.

## Requirements

- Rust (see `Cargo.toml` edition/toolchain), `make`, `bash`, `jq` (the
  fault scripts pipe catalogs through it), and `kubectl`.
- Live runs additionally need Docker (the Mint layer), Helm (Chaos Mesh
  install), and for `dm-flakey*` scenarios hosts with prepared device-mapper
  flakey tables as described above.
- Live runs additionally need: a dedicated Kubernetes/K3s cluster, Chaos Mesh
  installed for chaos-backed scenarios (host device-mapper scenarios need
  `dm-flakey` capable hosts), `kubectl` access via a dedicated context, and
  the required environment variables above.
