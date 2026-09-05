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
  examples/          Ready-to-run fault suites: smoke, regression,
                     device-mapper lab, Warp performance
console/             Web console assets served by the run console
```

The `s3chaos` CLI exposes machine-readable commands (`fault-catalog-json`,
`protocol-catalog-json`, `*-suite-json`, ...) used by scripts, CI, and the
console. There is no
installed binary on a fresh checkout; run commands via Cargo:

```bash
cargo run --quiet --bin s3chaos -- help
```

## Build and Static Checks

```bash
make check            # cargo fmt --check + clippy -D warnings + tests
make fault-check      # check + bash -n on fault-test.sh
make protocol-check   # check + bash -n on protocol scripts
```

## Fault-Injection Testing

Workflow: discover scenarios → preflight → preflight-validate a suite → plan →
run → inspect artifacts/console → cleanup.

```bash
make fault-list                                   # scenario catalog
make fault-preflight SCENARIO=io-eio              # cluster readiness checks
make fault-suite-template > suite.yaml            # generate a suite skeleton
make fault-suite-validate SUITE=suite.yaml        # static suite validation
make fault-suite-plan SUITE=suite.yaml            # dry-run expansion
make fault-suite-run SUITE=suite.yaml             # live run (needs a cluster)
make fault-suite-run SUITE=fault/examples/smoke.yaml
make fault-console-serve                          # browse run artifacts

# Pin the context, namespace, and tenant recorded in the run's target proof.
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<run-context>'
export RUSTFS_FAULT_TEST_NAMESPACE='<run-namespace>'
export RUSTFS_FAULT_TEST_TENANT='<run-tenant>'
make fault-cleanup                                # release cluster fixtures
```

Runnable scenario families (20 executable entries): I/O faults (`io-eio`,
`io-read-mistake`, `io-latency`, `disk-full`, `dm-flakey*`), network faults
(`network-partition-one`, `network-partition-write-quorum-loss`,
`network-delay/loss/corrupt/duplicate`), pod faults (`pod-kill-one`,
`pod-failure`, `pod-crash-versioned-hot`), stress (`stress-cpu`,
`stress-memory`), typed volume quorum (`quorum-p-io-fault`,
`quorum-p-plus-one-io-fault`), and the `warp-under-chaos` benchmark campaign.
Each typed volume quorum run captures bounded RustFS admin health samples before
its probes/workload and after the workload/controller recheck; both samples
require every non-target drive to be healthy and do not claim continuous health.
A further five catalog entries are roadmap placeholders with status `Planned`
(`fresh-volume-replacement`, admin decommission and
rebalance, `on-disk-bitrot`, `stale-disk-return-detect`): they appear in
`cargo run --bin s3chaos -- fault-catalog-json` but are filtered out of
`make fault-list` and rejected by preflight and suite validation.
Heal is a recovery mode of replacement and bitrot rather than a standalone
healthy-cluster scenario. Long-running campaigns remain suite orchestration,
not a fault backend or scenario family.
The ordered durability work queue and its safety prerequisites remain in
[`docs/DURABILITY_FAULT_TESTING_TODO.md`](docs/DURABILITY_FAULT_TESTING_TODO.md).
Volume-quorum runs require matching RustFS non-target drive-health observations
before and after the workload. These endpoint guards are not continuous health
monitoring; live qualification is still required before release gating.

Ready-to-run suites under [`fault/examples/`](fault/examples/) keep different
execution environments and verdicts separate:

| Suite | Scope | Additional requirement |
| --- | --- | --- |
| `smoke.yaml` | Six short correctness and recovery checks across I/O, pod, and network faults | Dedicated cluster with Chaos Mesh |
| `regression.yaml` | Remaining ordinary Chaos Mesh scenarios, including the write-quorum boundary | Reference four-server single-erasure-set topology for `network-partition-write-quorum-loss` |
| `dm-lab.yaml` | `dm-flakey` and the versioned hot-key soft-power-loss proxy | Prepared dedicated block device and static local PV from `docs/DM_FLAKEY.md` |
| `warp-performance.yaml` | Performance-only Warp-under-chaos campaign; correctness still comes from the normal checker | `warp` on `PATH`; Warp defaults to 60 seconds |

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
overlapping. Do not run multiple fault suites concurrently against the same
fault-test namespace. CI validates these YAML contracts only; it never starts a
destructive suite.

The two `dm-flakey*` scenarios need host preparation beyond the environment
variables below: a device-mapper flakey table over a dedicated block device,
a static local PV/storage class, and scenario-specific variables
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

Validate before cleanup: for a failed or interrupted run the artifact root is
the only record of what happened on the server, and cleanup deletes registered
fixtures.

## CI

- `.github/workflows/ci.yml`: fmt/clippy/tests plus static validation of fault
  suites, protocol contracts, all example profiles, and shell lint. No cluster
  needed; fault suites are never executed by CI.
- `.github/workflows/protocol-live.yml`: live RustFS suites (smoke gate,
  native regression, expiration regression, external OIDC regression) on a
  self-hosted runner. Full live execution is manually dispatchable. Mint is
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
