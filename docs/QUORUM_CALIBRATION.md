# Independent quorum calibration

The typed P/P+1 IOChaos cases require independent filesystem observations before
using S3 results as a quorum oracle. Each selected RustFS container receives a
run-owned fixture before injection. Three rounds, separated by at least one
second, each call READ, WRITE, FSYNC, RENAME and UNLINK against separately staged
files. Numeric `EIO` from every requested operation is required. Setup errors,
missing files, permission errors, transport failure and successful operations
never qualify. A second complete sample follows the mixed workload. This is
bounded sampling, not proof that every I/O throughout the interval failed.

The installed served IOChaos CRD must accept a string array of methods. An
advertised enum must include all five methods; upstream Chaos Mesh 2.8.0 uses
an [unrestricted string array](https://github.com/chaos-mesh/chaos-mesh/blob/v2.8.0/config/crd/bases/chaos-mesh.org_iochaos.yaml), so actual syscall receipts remain the deployed
version compatibility check. Before mutation, `quorum-runtime-provenance.json` records its schema and the deployed
controller/daemon resolved image identities, plus the exact RustFS container
identities and derived image digests. An unsupported schema or missing helper
fails before fault injection; unsupported runtime behavior remains unqualified. The native fixture binds helper protocol version 1,
helper SHA-256, directory/file inode and device, run ID and container generation.
Activation evidence now uses schema version 3; older one-shot artifacts cannot
satisfy the stronger success contract and must be regenerated.
IOChaos remounts through FUSE: [Toda preserves backing inodes](https://github.com/chaos-mesh/toda/blob/523c67dbd5bd3fb2758b7194679a3cab2e7be917/src/hookfs/utils.rs),
but the active mount has a different device number. Active probes bind the
staged inodes and require one consistent active device across files and both
sample windows; cleanup requires the original device and inode after removal.
During faults, fixture ownership uses metadata; reading the owner marker would
itself encounter injected READ errors. Cleanup checks the owner after restoration.

A successful DELETE response remains forbidden whenever typed metadata write
quorum is unavailable, including HTTP success without a delete-marker flag.
This implements independent syscall calibration instead of the S3 negative
warmup proposed in backlog #2550. Using repeated PUT/MPU/DELETE failures to
activate the gate would make RustFS behavior the evidence for the injection
and could hide a real quorum violation by calling it an inactive fault. The
existing typed S3 workload remains the product oracle for each unavailable
mutation class; syscall sampling does not prove a one-to-one mapping from
each product mutation to a particular persistence operation. Live evidence is
still required to establish that diagnostic relationship.

DELETE history now includes S3 request IDs when returned, enabling correlation
with RustFS logs. Calibration does not reinterpret a successful S3 mutation as
proof of a healthy fault backend. Failed calibration skips the typed oracle,
restores the fault, and retains failed evidence before returning a failed run.

## Dedicated helper image

Use a dedicated derived image for these qualification runs. Record the original
RustFS digest, this repository's helper commit, build platform and builder digest
alongside the resulting image digest. The candidate is the derived image; do not
label it as the unchanged upstream RustFS image.

```bash
# Set these to verified immutable images for the target architecture.
export RUSTFS_BASE='registry.example/rustfs@sha256:...'
export RUST_BUILDER='rust@sha256:...'
git rev-parse HEAD
docker build --platform linux/amd64 -f fault/images/quorum-probe.Dockerfile \
  --build-arg RUSTFS_IMAGE="$RUSTFS_BASE" \
  --build-arg BUILDER_IMAGE="$RUST_BUILDER" \
  -t registry.example/rustfs-quorum:qualification .
```

The builder and RustFS base must have compatible Linux runtime libraries. Build
for the cluster architecture; publish and deploy the resulting immutable digest
through `RUSTFS_FAULT_TEST_SERVER_IMAGE`. The helper path is
`/usr/local/bin/s3chaos-quorum-probe`; it accepts a closed JSON protocol on stdin.
It needs the same volume permissions as RustFS and no extra Linux capabilities.
Pre-staging verifies its executable availability and protocol before mutation.
Use the existing `quorum-reliability.yaml` suite for the four IOChaos boundaries;
run its static validation before any separately authorized live run.

## Continuous block EIO reference

`quorum-p-dm-eio` is a diagnostic reference for a fresh EC2+2 payload layout:
four servers, one volume each, one erasure set, exactly two selected devices on
two nodes. It requires dedicated pre-provisioned Linux device-mapper storage and
read-only observer Pods outside the disposable fault namespace. Metadata-class
and other layouts are rejected. It is not release-qualified by adding this code.

Set `RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS` to an absolute JSON file:

```json
{"targets":[
  {"node":"worker-a","mapperName":"rustfs-a","mountPath":"/data/dm-a","persistentVolume":"pv-a","observerNamespace":"storage-observers","observerPod":"observer-a","stateFile":"/absolute/run/.host-mutation-qdm-a.json","stateToken":"qdm-a"},
  {"node":"worker-b","mapperName":"rustfs-b","mountPath":"/data/dm-b","persistentVolume":"pv-b","observerNamespace":"storage-observers","observerPod":"observer-b","stateFile":"/absolute/run/.host-mutation-qdm-b.json","stateToken":"qdm-b"}
]}
```

These are placeholders, not cluster defaults. Pre-create an absolute run root
and use an absolute target-file path. Each absent state file must be directly
under that root (or its scenario artifact directory) and named
`.host-mutation-<stateToken>.json`, with a unique token. After replacing the JSON
identities with approved cluster targets, the corresponding environment is:

```bash
export RUSTFS_FAULT_TEST_RUN_ROOT=/absolute/run
mkdir -p "$RUSTFS_FAULT_TEST_RUN_ROOT"
export RUSTFS_FAULT_TEST_QUORUM_DM_TARGETS=/absolute/quorum-dm-targets.json
export RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST=worker-a,worker-b
export RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST=/dev/mapper/rustfs-a,/dev/mapper/rustfs-b
export RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST=pv-a,pv-b
export RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1
make -j2 fault-dm-run SCENARIO=quorum-p-dm-eio
```

The three allowlists must exactly match the two JSON members. All existing
context, namespace ownership, static storage and image prerequisites apply.
Device-mapper execution remains excluded from the ordinary multi-attempt suite
runner. The wrapper persists its validated target JSON into this run before
launching the fault process; cancellation checks the exact two recorded state
file/token pairs before considering a hard kill.

Before activation, both original healthy linear tables, mounted PV/device
identities, uncached successful reads and ownership proofs are persisted. Runtime
erasure membership is refreshed after preparation. Both activations must finish
within the bounded topology freshness window or roll back. Continuous flakey
`error_reads`/`error_writes` tables are independently checked around three direct
block reads per device, one second apart, before and after workload. Block-layer
EIO does not imply immediate errors for cached filesystem reads or metadata
syscalls; those operations are not used as this reference's activation predicate.

`quorum-dm-active.json`, `quorum-dm-after-workload.json` and
`quorum-dm-recovered.json` bind the same two targets to host proofs, direct-read
receipts, exact tables and run windows. Per-device artifacts live under
`quorum-dm-target-0/` and `quorum-dm-target-1/`. The offline validator requires
successful post-cleanup ownership/table/mount observations for both devices.
Failure of the second activation triggers reverse rollback of both attempted
targets; a rollback error cannot skip the other device. Cooperative cancellation
also attempts restoration. A hard kill can leave fsynced mutation markers:
preserve them and follow the exact scoped recovery commands in the host proofs;
repeat mutation is blocked until recovery. Do not assume automatic SIGKILL
recovery.

Neither finite canary sampling nor this executable reference supplies live
qualification evidence. Release gating still needs repeated authorized cluster
runs, authenticated artifacts and investigation of any successful mutation at an
unavailable boundary.
