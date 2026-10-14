# Same-Pod EIO and metadata corruption

Both scenarios use the existing fault runner, scoped cleanup, artifact validator,
health watcher, and final S3 checker. Run them only against a dedicated prepared
cluster. Set the exact context, owned namespace and Tenant, candidate image, and
dedicated StorageClass through the normal `RUSTFS_FAULT_TEST_*` environment.
The same-Pod suite uses 600 objects and concurrency 30. Metadata recovery uses
the existing bounded versioned-hot workload: 96 objects, concurrency 4, and
explicit operation weights, payload distribution and hot-key selection.

## Two volumes on one Pod

`io-eio-same-pod-two-volumes` creates a fresh four-server Tenant with two volumes
per server. Authenticated RustFS admin information must report a single erasure
set and drive paths matching `/data/rustfs0` and `/data/rustfs1` on the selected
Pod. The runtime geometry must retain both read and write quorum after two
volumes become unavailable. Each mount must resolve to a distinct drive UUID,
PVC and PV, on the same Pod UID and RustFS container generation.

The candidate image must contain `/usr/local/bin/s3chaos-quorum-probe`. Follow
[the dedicated helper image instructions](QUORUM_CALIBRATION.md#dedicated-helper-image)
to build and select the candidate image. The normal static suite checks require
no cluster mutation:

```bash
make -j2 fault-suite-validate SUITE=fault/examples/io-eio-same-pod-two-volumes.yaml
make -j2 fault-suite-plan SUITE=fault/examples/io-eio-same-pod-two-volumes.yaml
```

After the target is prepared and the live run is authorized:

```bash
make -j2 fault-suite-run SUITE=fault/examples/io-eio-same-pod-two-volumes.yaml
```

The suite selects the second mount through `params.secondVolumePath`; the primary
mount is `RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH`, defaulting to `/data/rustfs0`. The two
paths must be different normalized mounts. The fault duration is eight minutes
inside a thirty-minute total suite deadline.

Two IOChaos resources each select exactly the same Pod and one proved mount.
Each resource requests 100% EIO for READ, WRITE, FSYNC, RENAME and UNLINK.
Independently staged native fixtures require numeric EIO from all five operations
in three rounds before the S3 workload and in three rounds afterward. These
bounded samples authenticate both fault targets. The selected Pod/container generation,
IOChaos UID, mount, and controller record must remain unchanged between the two
windows. Active checks allow Readiness changes while requiring the RustFS
container to remain Running. Baseline and recovery require Ready Pods.
Unqualified probe results fail the run and retain diagnostic evidence.

The workload verifies committed-object reads and its required availability
floor. Recovery deletes both IOChaos resources, removes both owned fixtures,
checks healthy drives and fresh writes, and runs the final committed-object
checker. The artifact validator rechecks the two mount bindings, both resource
snapshots, independent activation and continuity receipts, cleanup, and the
same Pod/container identity.

## Selected XL2 metadata corruption

`metadata-shard-corruption` uses the explicit
`metadata-shard-corruption-admin-deep` storage-recovery case. It requires a
prepared one-volume-per-server Local PV/device-mapper deployment, the existing
privileged storage helper, exact host/PV allowlists, and an absolute,
operator-reviewed `RUSTFS_FAULT_TEST_STORAGE_RECOVERY_TARGET_CONFIG` JSON file.
The target file uses the existing `BitrotLiveTargetConfig` schema in
`src/fault/on_disk_bitrot.rs`; it records current Tenant, Pod, PVC, PV, node,
helper, filesystem, drive, device-mapper, and lock identities. Its dedicated
bucket must begin with `s3chaos-metadata-`, and `mutationByteOffset` must be zero.
Set `selectedPartNumber` to an existing external part for the baseline mapping
and unchanged-data proof. The exact unavailable Pod cohort must equal the
authenticated payload read tolerance and exclude the mutation target.

```bash
make -j2 fault-suite-validate SUITE=fault/examples/metadata-shard-corruption.yaml
make -j2 fault-suite-plan SUITE=fault/examples/metadata-shard-corruption.yaml
```

After the target is prepared and the live run is authorized:

```bash
make -j2 fault-suite-run SUITE=fault/examples/metadata-shard-corruption.yaml
```

The helper seals the selected version's XL2 mapping and both metadata and data
identities. `MutateMetadata` changes one byte at offset zero of that object's
`xl.meta`, journals the original byte, synchronizes the journal and file, and
verifies the resulting digest. The operation is restricted to the sealed
metadata path and exact file generation. The selected data part remains intact.

With the exact read-quorum cohort unavailable, the selected version must reject
corrupted metadata without returning incorrect bytes. Owned admin deep heal then
repairs that same version. Success requires a renewed XL2 mapping, the original
metadata digest, the unchanged selected data-part digest, successful S3 reads,
healthy recovery, fresh writes, and the final checker. `metadata-selection.json`,
`metadata-mutation.json`, `metadata-corruption-window.json`, `metadata-heal.json`,
`metadata-cleanup.json` and `metadata-workflow.json` carry the receipt-bound proof.

The total suite deadline is 90 minutes. Failure and cooperative interruption use
the existing journal recovery, helper-generation checks, Lease reconciliation,
IOChaos removal, and owned admin-heal cancellation. Preserve the printed artifact
root and validate it before any separately authorized cluster cleanup. Select
cleanup through the recorded context, namespace and Tenant, with
`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` set to that exact context.

Static verification demonstrates the implementation and artifact checks. Live
qualification requires captured evidence from the prepared candidate deployment.
