# Credential rotation during S3 load

`credential-rotation-mid-load` exercises a built-in IAM user's secret rotation
through `PUT /rustfs/admin/v3/set-user-secret-key`. The target is a freshly
created run-owned user with access limited to the run-owned versioned bucket.
The scenario generates both secrets in memory and keeps the Tenant's control
credentials available for administration and cleanup.

Use the normal prepared-cluster configuration from `README.md`:

```bash
make -j2 fault-run SCENARIO=credential-rotation-mid-load
make -j2 fault-suite-plan SUITE=fault/examples/credential-rotation.yaml
make -j2 fault-suite-run SUITE=fault/examples/credential-rotation.yaml
```

The suite runs 64 objects with eight concurrent requests. `faultDuration` bounds
the rotation request, the old-credential workload, credential propagation, and
the new-credential mutation probes. The existing cluster timeout bounds recovery.
IAM cleanup is bounded by the smaller of that timeout and 45 seconds.
Cluster mutation requires the normal explicit destructive
opt-in. A current RustFS build exposing the secret-rotation endpoint is required.

The scenario verifies prefilled bytes with the old secret, runs finite PUT
requests while rotating that secret, and proves request overlap using the
existing history recorder's timestamps and event sequence numbers. Each RustFS
Pod must reject the old secret and return matching prefilled bytes with the new
secret. Pod-specific port-forwards provide direct authentication checks even
when the normal workload uses a service port-forward.

The new secret must commit a PUT, return matching bytes through GET, commit an
overwrite with a distinct version, and commit a DELETE marker which hides the
current object. The existing checker reads every committed historical version,
validates bytes and version listings, and checks current delete visibility.
Recovery health must match the original RustFS deployment and Pod identities.

`credential-rotation.json` records credential fingerprints, the rotation
request interval, exact S3 history references, each Pod's authentication proof,
and IAM cleanup results. Cleanup queries each original Pod directly and records
its Pod UID, RustFS container ID, port-forward target, IAM inventory HTTP status,
request ID, response digest, and old/new credential rejection records. IAM names
are stored as SHA256 fingerprints. Pod metadata and runtime status bracket those
requests; the original UID and container ID must remain unchanged. Raw access keys
and secrets are omitted. S3 history
errors redact the in-memory generated and control credentials. The offline
`fault-validate-artifacts` command validates the same references and checker
audit; an empty workload, missing Pod, accepted old secret, unconfirmed version,
missing overlap, a stale peer's IAM cache, changed container generation, or
unfinished cleanup cannot pass. Every original Pod must report the user and
policy absent and reject both secrets before cleanup is marked complete.

IAM user and policy removal run after verification and after failed attempts.
Cancellation also runs bounded identity cleanup while the main port-forward
remains available. A separate read-only cleanup history preserves partial
coverage on timeout or cancellation and keeps the data checker's audited history
unchanged. Tenant resources and versioned objects remain available for
artifact validation followed by the normal explicit `fault-cleanup` workflow.

The implemented variant is built-in IAM user secret rotation. TLS certificate,
external identity, and STS/session rotation require their own target and
authentication evidence. Static tests cover this variant's evidence validation,
signed wire API, and cleanup behavior; a live qualification must exercise it on
a prepared RustFS deployment before claiming a product compatibility result.
