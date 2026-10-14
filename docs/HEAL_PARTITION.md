# Network partition during replacement heal

`network-partition-during-heal` runs the typed
`network-partition-during-heal-admin-deep` storage-recovery case. It replaces one
dedicated Local PV with an empty generation, starts a run-owned recursive
AdminDeep heal, isolates the replacement Pod from its three peers, restores
connectivity, and verifies every committed object version. The repaired drive
also has to pass the existing causal exact-quorum read proof.

## Prepared target

Use four Linux containerd nodes, four one-volume RustFS Pods in one erasure set,
a no-provisioner StorageClass, a disposable owned namespace with privileged Pod
Security, and an explicitly approved destructive target. The RustFS image must
contain `curl` and `/usr/local/bin/s3chaos-quorum-probe`. Chaos Mesh must serve
both `iochaos.chaos-mesh.org` and `networkchaos.chaos-mesh.org`.

Build the architecture-matched derived image using
[QUORUM_CALIBRATION.md](QUORUM_CALIBRATION.md). The shared Dockerfile also installs
`/usr/local/bin/s3chaos-storage-helper`; that image can supply both
`RUSTFS_FAULT_TEST_SERVER_IMAGE` and `RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE`.
The builder and base image must use compatible Linux runtime libraries.

Prepare five dedicated filesystem/device mounts: four initial volumes on
distinct nodes and one empty replacement on an initial node. The harness creates
the run-owned Kubernetes PVs, so their names must not already exist. The host
paths must already exist and be backed by distinct approved devices/filesystems.
The final JSON entry is held back until replacement. Configure the exact
Operator Deployment that owns the Tenant; its namespace and image match use the
existing lifecycle settings described in the [README](../README.md).

Replace these placeholders with approved target identities:

```bash
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<exact-current-context>'
export RUSTFS_FAULT_TEST_NAMESPACE='<owned-privileged-namespace>'
export RUSTFS_FAULT_TEST_TENANT='<owned-tenant>'
export RUSTFS_FAULT_TEST_SERVER_IMAGE='<derived-rustfs-image@sha256:digest>'
export RUSTFS_FAULT_TEST_STORAGE_HELPER_IMAGE="$RUSTFS_FAULT_TEST_SERVER_IMAGE"
export RUSTFS_FAULT_TEST_STORAGE_CLASS='<dedicated-no-provisioner-class>'
export RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT='<rustfs-operator-deployment>'
export RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST=worker-a,worker-b,worker-c,worker-d
export RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST=heal-a,heal-b,heal-c,heal-d,heal-new
export RUSTFS_FAULT_TEST_STATIC_LOCAL_PVS_JSON='[
  {"name":"heal-a","node":"worker-a","localPath":"/mnt/approved/heal-a","capacity":"100Gi"},
  {"name":"heal-b","node":"worker-b","localPath":"/mnt/approved/heal-b","capacity":"100Gi"},
  {"name":"heal-c","node":"worker-c","localPath":"/mnt/approved/heal-c","capacity":"100Gi"},
  {"name":"heal-d","node":"worker-d","localPath":"/mnt/approved/heal-d","capacity":"100Gi"},
  {"name":"heal-new","node":"worker-a","localPath":"/mnt/approved/heal-new","capacity":"100Gi"}
]'
export RUSTFS_FAULT_TEST_DESTRUCTIVE=1
make -j2 fault-suite-validate SUITE=fault/examples/network-partition-during-heal.yaml
make -j2 fault-suite-run SUITE=fault/examples/network-partition-during-heal.yaml
```

The suite supplies the exact recovery case and a 2,000-object dataset. A direct
`make -j2 fault-run SCENARIO=network-partition-during-heal` selects the same unique
case automatically; workload size and deadlines retain the existing environment
settings. Prepare one fresh fixture per attempt.

## Evidence and verdict

Injection requires two increasing, nonterminal status responses for the exact
owned `clientToken`, with explicit `objectsScanned`, `objectsHealed`, and
`objectsFailed` counters. Idle, completed, failed, unsupported, or unrelated heal
responses fail qualification. A dataset that heals before this observation
window also fails qualification.

`heal-partition-proof.json` binds the replacement generation, complementary
selectors, NetworkChaos UID/controller records, and all directed Pod-to-Pod
connection receipts. Baseline and restored probes must connect to each exact Pod
IP. During injection, cross-group TCP connections must fail while peer-group
connections remain usable. The active interval spans at least ten seconds,
with nonterminal heal samples bracketing exact-version GETs; the NetworkChaos TTL
is sixty seconds. Successful GETs must return the committed bytes. Disappearance
or corrupt successful reads fail the run.

After confirmed NetworkChaos removal, the owned heal must finish successfully
with positive repair counters. Full version/history checking, repaired-drive
force reads, recovery health, and new-write/read/delete probes remain required.
The existing storage Lease, Operator restoration, helper journal and quarantine
rules cover failures and cancellation. Host volumes remain retained for inspection.

Validate the exact emitted scenario artifact root before cluster cleanup:

```bash
cargo run --quiet --bin s3chaos -- fault-validate-artifacts \
  network-partition-during-heal '<exact emitted scenario artifact root>'
```

Confirm the recorded context, namespace and Tenant, pin
`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT`, and then use the existing `make fault-cleanup`
procedure. This implementation still requires live qualification against the
prepared RustFS/Chaos Mesh image and storage layout.
