# s3chaos

S3Chaos is a fault-injection and recovery-verification framework for
S3-compatible object storage, starting with RustFS on Kubernetes.

It provides:

- A machine-readable fault scenario catalog.
- Kubernetes fixture ownership and cleanup guards.
- Chaos Mesh and host device-mapper fault backends.
- Mixed S3 workload generation, history capture, recommit, and post-recovery
  verification.
- Run contracts and event artifacts intended for future YAML orchestration and
  visualization.

## Commands

```bash
make fault-check
make fault-list
make fault-preflight SCENARIO=io-eio
make fault-run SCENARIO=io-eio
make fault-cleanup
```

Required runtime inputs for non-static scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT=<dedicated-k8s-or-k3s-context>
```

See [docs/FAULT_TESTING.md](docs/FAULT_TESTING.md) for cluster preparation,
scenario selection, dm-flakey setup, artifact contracts, and cleanup rules.
