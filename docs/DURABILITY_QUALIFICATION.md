# Durability live qualification

A calibration result belongs to one detector, candidate image digest, workload,
and storage layout.

## ACK positive and negative controls

Prepare an explicitly authorized dedicated DM lab using [DM_FLAKEY.md](DM_FLAKEY.md).
Pin the context, namespace, Tenant, static PVs, node/device allowlist and candidate
image as `name@sha256:<digest>`; mutable tags are rejected for calibration.
Keep the same pinned image and observed runtime digest, EC geometry, filesystem, mount options and
host writeback/journal settings for both controls. Record the RustFS, Operator,
and S3Chaos commits and image digests with the lab report. Never run the pair in
a loop: static volumes require supervised inspection and a fresh fixture between
attempts.

Use the same explicit seed for both controls:

```bash
export RUSTFS_FAULT_TEST_SEED=424242
make fault-suite-validate SUITE=fault/examples/ack-put-strict.yaml
make fault-suite-validate SUITE=fault/examples/ack-put-relaxed.yaml
make fault-suite-run SUITE=fault/examples/ack-put-strict.yaml
```

`ackCalibration: strict` sets both `RUSTFS_DURABILITY_MODE=strict` and
`RUSTFS_NEW_BUCKET_DURABILITY_MODE=strict`. The latter matters: newer RustFS
builds seed newly created buckets with their own relaxed override by default.
Conflicting or duplicate ambient entries in `RUSTFS_FAULT_TEST_SERVER_ENV` are
rejected. The run records the actual Pod modes and resolved image identities,
and requires the signed bucket-durability GET to return an explicit matching
override before preparing the fault. An unsupported endpoint, inherited/null
mode, wrong bucket, changed Pod UID or mixed image digest stops calibration.
Only these two non-secret environment values are retained.

Inspect and validate the exact emitted artifacts before cleanup. Confirm the
recorded context, namespace and Tenant, pin
`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT`, and follow the DM recovery/cleanup runbook.
After preparing a fresh approved fixture with matching lab settings, run:

```bash
make fault-suite-run SUITE=fault/examples/ack-put-relaxed.yaml
```

The relaxed control must produce the declared product failure tied to the
acknowledged key/version. A timeout, backend failure, unrelated missing key,
invalid artifact, or successful relaxed checker is not a detector hit. A single
failed drive can be masked by EC redundancy; if both modes pass, this detector
is unqualified for the tested layout. Do not weaken the oracle or report that
pair as calibrated. Investigate the crash window and failure scope separately.

After both supervised runs, compare their exact emitted suite roots:

```bash
cargo run --quiet --bin s3chaos -- fault-ack-calibration-analyze \
  '<strict-suite-root>' '<relaxed-suite-root>'
```

The analyzer revalidates native artifacts rather than trusting prior validation
reports or suite status. It requires strict PASS and relaxed observed ACK state
loss, independent run identities, the same candidate digest, detector, payload
and seed, ACK timing, recovery policy, EC geometry, cluster/storage class, and
pre-crash filesystem/mount options. Host kernel writeback settings and image
provenance must additionally be preserved in the operator's lab report; the
analyzer does not attest those external settings. Its output is evidence for
this pair.

Repeat with individually reviewed single-attempt suites for overwrite,
delete-marker, zero-byte PUT and multipart completion. Choose the exact expected
loss classification before running the negative control. Do not change the
expectation after seeing an unrelated failure. No result for PUT qualifies the
other mutation types.

## Fresh-volume and bitrot variants

[PR #99](https://github.com/rustfs/s3chaos/pull/99) enables ordinary execution
of fresh-volume replacement and bitrot, including their four recovery variants.
It also provides the corresponding single-attempt suites under `fault/examples/`:
`fresh-volume-replacement-automatic.yaml`,
`fresh-volume-replacement-admin-deep.yaml`, `on-disk-bitrot.yaml`, and
`on-disk-bitrot-admin-deep.yaml`.

Prepare the exact target JSON, helper image, dedicated Local-PV configuration,
context, namespace and Tenant before running. Set
`RUSTFS_FAULT_TEST_DESTRUCTIVE=1` and select one explicit recovery case:

```bash
RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=fresh-volume-replacement-automatic-replacement \
  make fault-run SCENARIO=fresh-volume-replacement
RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=fresh-volume-replacement-admin-deep \
  make fault-run SCENARIO=fresh-volume-replacement
RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=on-disk-bitrot-automatic-scanner \
  make fault-run SCENARIO=on-disk-bitrot
RUSTFS_FAULT_TEST_STORAGE_RECOVERY_CASE=on-disk-bitrot-admin-deep \
  make fault-run SCENARIO=on-disk-bitrot
```

Run one command per prepared fixture. The existing
`make fault-qualify QUALIFICATION_CASE=<case>` entrypoint remains available for
each of these four case names; `make fault-qualify-list` describes its contract.

Validate an ordinary run using its exact emitted artifact root and scenario:

```bash
cargo run --quiet --bin s3chaos -- fault-validate-artifacts \
  '<scenario>' '<exact emitted artifact root>'
```

For a run started through `fault-qualify`, use its qualification run root:

```bash
make fault-qualify-analyze RUN_ROOT='<exact emitted qualification run root>'
```

Retain the plan/result, pinned images/topology, full native artifact validation,
old/new drive generation and emptiness evidence, matching heal operation and
terminal state, exact-version mapping, and force-read isolation/restore proof.
Bitrot also needs the actual mutation receipt and matching checksum detection
within the corruption window. Missing detection, background-repair races,
unsupported diagnostics and incomplete restore are unqualified or failed, never
PASS. Stop on an unexpected failure and preserve live evidence before cleanup.
