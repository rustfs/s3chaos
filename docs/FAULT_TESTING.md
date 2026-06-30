<!--
Copyright 2025 RustFS Team

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# RustFS Fault-Test Operations

This guide is the operational entry point for running RustFS workload fault
tests from the standalone `s3chaos` repository.

## Scope

Fault tests run only on a dedicated real Kubernetes or K3s cluster. They are
not Kind tests and are not designed for shared application clusters. The runner
creates and deletes its own namespace, Tenant, PVCs, Pods, Services, StatefulSet,
and Chaos Mesh resources.

The fault-test runner owns only the resources it creates in the fault namespace.
Pre-existing non-fault Tenants are treated as health guardrails: preflight
requires them to be Ready, and each scenario stops if one becomes non-Ready. The
runner never modifies, restarts, scales, or cleans up those Tenants. Do not point
the fault namespace, Tenant, StorageClass, or device-mapper path at shared or
production resources.

Default owned resources:

```text
namespace: rustfs-fault-test
tenant:    fault-test-tenant
manager:   app.kubernetes.io/managed-by=s3chaos
```

## Commands

Run all commands from the repository root.

```bash
make fault-check
make fault-list
make fault-preflight SCENARIO=io-eio
make fault-run SCENARIO=io-eio
make fault-run-dm
make fault-suite-template
make fault-suite-validate SUITE=suite.yaml
make fault-suite-plan SUITE=suite.yaml
make fault-suite-run SUITE=suite.yaml
make fault-dashboard-install
make fault-dashboard-port-forward
make fault-cleanup
```

`fault-check` is local only. It runs Bash syntax, Rust fmt, tests, and clippy.

`fault-run` prebuilds the `s3chaos` CLI before the fault window, then runs
`s3chaos fault-run` directly. The runner reruns preflight before and after the
build. After a successful run, the shell runner delegates artifact contract
validation to `s3chaos fault-validate-artifacts`; Bash does not duplicate the
JSON artifact schema.

## Required Environment

Only these variables are required for non-static fault scenarios:

```bash
export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
```

`RUSTFS_FAULT_TEST_SERVER_IMAGE` must be explicit. Prefer a pinned digest so a
failed run can be reproduced.

`RUSTFS_FAULT_TEST_EXPECTED_CONTEXT` is optional. When set, both the shell
runner and Rust test entrypoint require the current context to match it exactly.
When unset, the current non-Kind context is used and pinned for the run.
When `KUBECONFIG` is unset on a K3s host, the runner inherits
`/etc/rancher/k3s/k3s.yaml` if it is readable so the Rust Kubernetes client uses
the same cluster as `kubectl`.

```bash
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT=<dedicated-k8s-or-k3s-context>
```

## Common Overrides

Defaults are centralized in `src/fault/config.rs`. The shell
runner passes the same values into the Rust test and validates artifacts against
the selected values. Shell preflight mirrors the Rust entrypoint for numeric
ranges, booleans, and scenario-specific percent overrides.

Fault-test orchestration lives under `src/fault/`: runtime configuration,
scenario catalog, plan expansion, fault backends, fixture ownership checks, S3
workload history, and the Rust runner. Shared Kubernetes wrappers, kubectl
command helpers, artifact collection, port-forwarding, and generic Tenant
resource cleanup remain under `src/framework/`.

| Variable | Default | Use |
| --- | --- | --- |
| `RUSTFS_FAULT_TEST_NAMESPACE` | `rustfs-fault-test` | Fault namespace. |
| `RUSTFS_FAULT_TEST_TENANT` | `fault-test-tenant` | Tenant name. |
| `RUSTFS_FAULT_TEST_CHAOS_NAMESPACE` | `chaos-mesh` | Chaos Mesh namespace. |
| `RUSTFS_FAULT_TEST_USE_CLUSTER_IP` | `false` | Set to `1` when the runner can reach Service ClusterIPs. |
| `RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS` | `40000` | Total object count; must be at least 12. |
| `RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY` | `80` | S3 workload concurrency; must be 1 through object count. |
| `RUSTFS_FAULT_TEST_PREFILL_CONCURRENCY` | `min(16, workload concurrency)` | Setup PUT+GET verification concurrency before fault injection. |
| `RUSTFS_FAULT_TEST_DURATION_SECONDS` | `7200` | Maximum fault TTL. Successful runs recover earlier. |
| `RUSTFS_FAULT_TEST_REQUEST_TIMEOUT_SECONDS` | `30` | Per S3 request timeout. |
| `RUSTFS_FAULT_TEST_TIMEOUT_SECONDS` | `300` | Kubernetes wait timeout. |
| `RUSTFS_FAULT_TEST_SEED` | generated | Reuse a workload plan. |
| `RUSTFS_FAULT_TEST_RUSTFS_POD_COUNT` | `4` | Expected RustFS server Pod count for stability gates. |
| `RUSTFS_FAULT_TEST_RUSTFS_VOLUME_PATH` | `/data/rustfs0` | RustFS data volume path targeted by volume faults; must be an absolute safe path using ASCII letters, digits, `/`, `.`, `_`, or `-`. |
| `RUSTFS_FAULT_TEST_RUSTFS_POD_STABLE_WINDOW_SECONDS` | `60` | Required no-restart Ready window before and after fault injection. |
| `RUSTFS_FAULT_TEST_REQUIRE_CLIENT_DISRUPTION` | `false` | Force at least one client-visible failed/timeout/unknown S3 operation even when the catalog marks disruption optional. |
| `RUSTFS_FAULT_TEST_BUILD_JOBS` | `1` | Cargo prebuild job count. |
| `RUSTFS_FAULT_TEST_RUN_ROOT` | timestamped target dir | Artifact root. |
| `RUSTFS_FAULT_TEST_CHAOS_MESH_VERSION` | `2.8.3` | Chaos Mesh Helm chart version for optional Dashboard installation. |
| `RUSTFS_FAULT_TEST_CHAOS_DAEMON_RUNTIME` | `containerd` | Chaos Daemon runtime value passed to Helm. |
| `RUSTFS_FAULT_TEST_CHAOS_DAEMON_SOCKET_PATH` | `/run/k3s/containerd/containerd.sock` | Runtime socket path passed to Helm. |
| `RUSTFS_FAULT_TEST_CHAOS_DASHBOARD_PORT` | `2333` | Local port for Dashboard port-forward. |

The prefill stage writes each setup object once and requires a matching GET
before fault injection. It retries transient GET timeouts or unknown read
failures a small bounded number of times; mismatched bytes and explicit S3
failures still fail the run immediately. Its concurrency is intentionally
separate from the fault-window workload so setup does not fail the scenario
before the selected fault is injected.

For a small rehearsal run:

```bash
export RUSTFS_FAULT_TEST_WORKLOAD_OBJECTS=64
export RUSTFS_FAULT_TEST_WORKLOAD_CONCURRENCY=8
make fault-run SCENARIO=io-eio
```

`RUSTFS_FAULT_TEST_PERCENT` applies only when the Rust scenario catalog marks
the scenario as percent-based. Fixed-target scenarios reject a percent override.
Run `make fault-list` or `cargo run --manifest-path Cargo.toml --bin s3chaos -- fault-catalog-json` to inspect the current catalog.

## Cluster Preparation

Check the current context first:

```bash
kubectl config current-context
kubectl get nodes
kubectl get crd tenants.rustfs.com
kubectl get storageclass
```

Requirements:

- The current context must be a real Kubernetes or K3s cluster, not `kind-*`.
- At least four schedulable Ready nodes are required for the current default
  Tenant shape.
- Non-static scenarios need a dedicated dynamic StorageClass.
- `dm-flakey` needs a dedicated static Local PV StorageClass and explicit
  device-mapper variables.
- Other Tenants in the cluster are health guardrails. They must remain Ready,
  but the runner does not modify them.

For K3s with local-path storage, verify the actual backing filesystem has
enough free space. PVC capacity alone may not enforce real disk quota.

```bash
kubectl -n kube-system get configmap local-path-config -o yaml
df -h <actual-provisioner-path>
```

Chaos Mesh is required for Chaos Mesh-backed scenarios. The validated version is v2.8.3:

```bash
helm repo add chaos-mesh https://charts.chaos-mesh.org
helm repo update
helm upgrade --install chaos-mesh chaos-mesh/chaos-mesh \
  -n chaos-mesh --create-namespace --version 2.8.3 \
  --set chaosDaemon.runtime=containerd \
  --set chaosDaemon.socketPath=/run/k3s/containerd/containerd.sock \
  --set dashboard.create=false \
  --wait --timeout 10m

kubectl -n chaos-mesh get deployment,daemonset
kubectl get crd iochaos.chaos-mesh.org podchaos.chaos-mesh.org networkchaos.chaos-mesh.org stresschaos.chaos-mesh.org
```

Use the actual runtime socket for non-K3s clusters.

The Dashboard is optional observability, not a pass/fail signal. To install or
upgrade Chaos Mesh with the Dashboard enabled and authentication still on:

```bash
make fault-dashboard-install
make fault-dashboard-port-forward
```

The port-forward prints a local `http://127.0.0.1:<port>` URL. Keep Dashboard
access local or otherwise protected; the runner verdict still comes from
artifacts and checker reports.

## Recommended Run Flow

1. Run the local gate:

   ```bash
   make fault-check
   ```

2. Export the required runtime values:

   ```bash
   export RUSTFS_FAULT_TEST_STORAGE_CLASS=<dedicated-dynamic-storage-class>
   export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
   export RUSTFS_FAULT_TEST_USE_CLUSTER_IP=1
   ```

3. Run preflight and the first P0 scenario:

   ```bash
   make fault-preflight SCENARIO=io-eio
   make fault-run SCENARIO=io-eio
   ```

4. List the catalog and run each selected scenario explicitly:

   ```bash
   make fault-list
   make fault-run SCENARIO=network-delay
   ```

5. Collect artifacts, then clean owned resources:

   ```bash
   make fault-cleanup
   ```

## Scenario Catalog

The Rust catalog in `src/fault/scenarios.rs` is the only maintained scenario
source of truth. The shell runner and this guide query that catalog instead of
duplicating scenario names, percent rules, CRDs, tools, or impact policy.

```bash
make fault-list
cargo run --manifest-path Cargo.toml --bin s3chaos -- fault-catalog-json
```

Each run names exactly one scenario with `SCENARIO=<name>`. SRE-owned scheduling
or automation should live outside this repository and call the same explicit
command for the desired scenario. Tool requirements, such as `warp` for
`warp-under-chaos`, are read from the Rust catalog during preflight.

## YAML Suite Contracts

Scenario definitions stay in Rust. YAML suites are a declarative composition
layer for selected scenarios, budgets, observability, and per-scenario
overrides. They compile against the Rust catalog and fail fast when a scenario
name, percent override, duration, or workload budget is invalid. If `workload`
is present for a scenario, set both `objects` and `concurrency`. Unknown YAML
fields are rejected so typos cannot silently drop suite budgets or workload
overrides.

Generate a starting point:

```bash
make fault-suite-template > suite.yaml
make fault-suite-validate SUITE=suite.yaml
cargo run --manifest-path Cargo.toml --bin s3chaos -- fault-suite-json suite.yaml
make fault-suite-plan SUITE=suite.yaml
```

Example:

```yaml
apiVersion: rustfs.com/s3chaos/v1alpha1
kind: FaultSuite
metadata:
  name: rustfs-smoke
budgets:
  maxDuration: 2h
  stopOnFirstFailure: true
  maxClientDisruptions: 20
  recoveryStableWindowSeconds: 60
observability:
  chaosDashboard: optional
artifacts:
  required: strict
scenarios:
  - name: io-eio
    duration: 10m
    percent: 20
    workload:
      objects: 40000
      concurrency: 80
  - name: network-delay
    duration: 8m
```

Render and review the exact destructive plan before running:

```bash
make fault-suite-plan SUITE=suite.yaml
```

The plan expands each attempt with scenario, repetition, resolved duration,
selected faults, targets, workload profile, expected backend, CRDs/tools,
artifact paths, and budget impact. Suite runs also write the execution plan to
`suite-plan.json` under the suite artifact root. Set `RUSTFS_FAULT_TEST_SEED`
before both planning and running when the preview and execution must use the
same workload seeds.

Run a suite sequentially:

```bash
make fault-suite-run SUITE=suite.yaml
```

The shell entrypoint validates the suite, asks Rust to render the suite plan,
preflights each referenced scenario, prebuilds the `s3chaos` binary, captures
cluster snapshots, watches baseline node/Tenant/Chaos Mesh health while the
suite is running, and terminates the suite if the guard fails or `maxDuration`
is reached. The Rust suite runner creates a suite artifact root under
`RUSTFS_FAULT_TEST_ARTIFACTS`, runs each planned scenario/repetition in order,
validates each successful scenario's artifacts with the Rust artifact contract,
refuses to start impossible plans whose minimum attempt duration plus recovery
timeout cannot fit within `maxDuration`, keeps enforcing the live remaining
`maxDuration` before every attempt, enforces `stopOnFirstFailure` and cumulative
`maxClientDisruptions`, and writes `suite-plan.json` and `suite-summary.json`.

The suite runner is intentionally sequential. It does not yet support parallel
execution, matrix expansion, per-scenario cluster/storage credentials,
`observability.chaosDashboard: required`, or `artifacts.required: default`.

## Artifacts And Pass Criteria

Artifacts are written under:

```text
${RUSTFS_FAULT_TEST_RUN_ROOT:-target/fault-tests/<timestamp>}/<scenario>/<case-name>/
```

For example, a single `io-eio` run writes the Rust artifacts under:

```text
target/fault-tests/<timestamp>/io-eio/fault_io_eio_preserves_committed_objects/
```

The shell runner also writes runner-level files such as `test.log`,
`health-watch.log`, `exit-code`, and cluster snapshots in the outer scenario
directory. Suite runs add the suite and attempt directories before the same
case-name layer:

```text
target/fault-tests/<timestamp>/<suite-name>/<suite-run-id>/<attempt>/<case-name>/
```

Suite-level artifacts include:

```text
suite-plan.json
suite-summary.json
```

Key files:

```text
run-spec.yaml
run-spec.json
run-events.jsonl
run-metadata.json
workload-plan.json
history.jsonl
workload-summary.json
recommit-report.json
checker-pre-recommit-report.json
checker-report.json
fault-evidence.json
chaos-manifest.yaml
fault-status-*.json
nodes-*.txt
pods-*.txt
pvcs-*.txt
pvs-*.txt
events-*.txt
*.log
```

A successful run must show:

- `run-spec.yaml` and `run-spec.json`: the resolved run contract, including the
  selected scenario, fault list, workload profile, recovery gates, topology
  assumptions, and required artifacts. This is the stable handoff surface for
  suite planning, audit, and UI rendering. The shell runner validates that the
  JSON and YAML artifacts decode to the same contract.
- `run-events.jsonl`: an ordered lifecycle event stream for visualization. A
  successful run includes `run started`, `checker-final succeeded`, and `run
  succeeded` events.
- `fault-evidence.json`: `injected`, `active_during_workload`, and `recovered`
  are `true`.
- `checker-pre-recommit-report.json` and `checker-report.json`: `passed` is
  `true`; expected live objects are GET+sha256 verified; missing objects, hash
  mismatches, unavailable committed-object reads, unknown committed-object read
  failures, successful corrupted reads, unexpected visible deleted objects, and
  final post-recovery LIST warnings are empty. `list_history_warnings` are
  retained as sampled workload-time diagnostics.
- `recommit-report.json`: every previously unconfirmed write was recommitted
  and GET verified after recovery.
- `workload-plan.json`: object count, concurrency, and payload distribution are
  internally consistent with the selected environment values.

If a scenario fails, inspect `failure-summary.json`,
`runner-failure-summary.json`, `test.log`, `fault-status-*.json`, and the
RustFS Pod logs first.

## Cleanup

`fault-cleanup` removes managed Chaos resources and the owned fault namespace.
It does not remove external StorageClasses, PVs, provisioners, host paths, loop
devices, or device-mapper devices.

```bash
make fault-cleanup
```

Manual checks:

```bash
kubectl -n "${RUSTFS_FAULT_TEST_CHAOS_NAMESPACE:-chaos-mesh}" \
  get iochaos,podchaos,networkchaos,stresschaos \
  -l app.kubernetes.io/managed-by=s3chaos

kubectl get namespace "${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
```

## dm-flakey

`dm-flakey` is an explicit scenario that needs a dedicated static Local PV setup
and privileged helper access on the fault namespace.

There is no Make target that installs this environment. Prepare the host storage
and Kubernetes Local PVs first, then use `fault-preflight` to verify them.

### dm-flakey Host Storage

Prefer real dedicated block devices. The loop-file commands below are for lab
clusters only. Run them on the Kubernetes nodes that will host the four static
Local PVs.

On the node that will receive the device-mapper fault:

```bash
export LAB=/data/rustfs/rustfs-fault-lab
export DM_NAME=rustfs-fault-dm

sudo mkdir -p "$LAB/volume"
sudo truncate -s 120G "$LAB/disk.img"
export BACKING="$(sudo losetup --find --show "$LAB/disk.img")"
export SECTORS="$(sudo blockdev --getsz "$BACKING")"
sudo dmsetup create "$DM_NAME" --table "0 $SECTORS linear $BACKING 0"
sudo mkfs.ext4 -F "/dev/mapper/$DM_NAME"
sudo mount "/dev/mapper/$DM_NAME" "$LAB/volume"
sudo chmod 0777 "$LAB/volume"

sudo dmsetup table "$DM_NAME"
findmnt -n -o SOURCE --target "$LAB/volume"
```

On each of the other three nodes:

```bash
export LAB=/data/rustfs/rustfs-fault-lab

sudo mkdir -p "$LAB/volume"
sudo truncate -s 120G "$LAB/disk.img"
export BACKING="$(sudo losetup --find --show "$LAB/disk.img")"
sudo mkfs.ext4 -F "$BACKING"
sudo mount "$BACKING" "$LAB/volume"
sudo chmod 0777 "$LAB/volume"
findmnt -n -o SOURCE --target "$LAB/volume"
```

### dm-flakey Kubernetes Storage

Create one `kubernetes.io/no-provisioner` StorageClass and exactly four `100Gi`
Local PVs for the fault StorageClass. Each PV must point at the host path created
above and must use node affinity for its real node name.

```bash
export DM_STORAGE_CLASS=rustfs-fault-dm
export DM_MOUNT_PATH=/data/rustfs/rustfs-fault-lab/volume

kubectl apply -f - <<EOF
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${DM_STORAGE_CLASS}
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: WaitForFirstConsumer
reclaimPolicy: Retain
EOF
```

Repeat this PV manifest for each of the four worker nodes, changing
`<pv-name>` and `<node-name>` each time:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: <pv-name>
  labels:
    app.kubernetes.io/managed-by: s3chaos
spec:
  capacity:
    storage: 100Gi
  volumeMode: Filesystem
  accessModes:
    - ReadWriteOnce
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ${DM_STORAGE_CLASS}
  local:
    path: ${DM_MOUNT_PATH}
  nodeAffinity:
    required:
      nodeSelectorTerms:
        - matchExpressions:
            - key: kubernetes.io/hostname
              operator: In
              values:
                - <node-name>
EOF
```

Pre-create or update the fault namespace so the helper pod can run privileged
and the runner can prove ownership:

```bash
export RUSTFS_FAULT_TEST_NAMESPACE="${RUSTFS_FAULT_TEST_NAMESPACE:-rustfs-fault-test}"
export RUSTFS_FAULT_TEST_TENANT="${RUSTFS_FAULT_TEST_TENANT:-fault-test-tenant}"

kubectl create namespace "$RUSTFS_FAULT_TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
kubectl label namespace "$RUSTFS_FAULT_TEST_NAMESPACE" \
  app.kubernetes.io/managed-by=s3chaos \
  pod-security.kubernetes.io/enforce=privileged \
  --overwrite
kubectl annotate namespace "$RUSTFS_FAULT_TEST_NAMESPACE" \
  "rustfs.com/fault-test-tenant=$RUSTFS_FAULT_TEST_TENANT" \
  --overwrite
```

Verify the storage setup before running the scenario:

```bash
kubectl get storageclass "$DM_STORAGE_CLASS"
kubectl get pv -o wide | grep "$DM_STORAGE_CLASS"
kubectl get namespace "$RUSTFS_FAULT_TEST_NAMESPACE" --show-labels
```

The `dm-flakey` preflight requires exactly four `Available` or `Bound` `100Gi`
PVs in the selected static StorageClass.

### dm-flakey Run

Required variables on the machine that runs the s3chaos command:

```bash
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
export RUSTFS_FAULT_TEST_STORAGE_CLASS=rustfs-fault-dm
export RUSTFS_FAULT_TEST_DM_NAME=rustfs-fault-dm
export RUSTFS_FAULT_TEST_DM_NODE=<dm-node-name>
export RUSTFS_FAULT_TEST_DM_MOUNT_PATH=/data/rustfs/rustfs-fault-lab/volume
export RUSTFS_FAULT_TEST_DM_FAULT_TABLE='0 <sectors> flakey <backing-device> 0 1 15'
```

Use the `SECTORS` and `BACKING` values from the DM node host-storage setup for
`<sectors>` and `<backing-device>`.

Optional:

```bash
export RUSTFS_FAULT_TEST_DM_RECOVERY_TABLE='<dmsetup recovery table>'
export RUSTFS_FAULT_TEST_DM_HELPER_IMAGE='rancher/mirrored-library-busybox:1.37.0'
```

Run:

```bash
make fault-preflight SCENARIO=dm-flakey
make fault-run-dm
```

The Rust test reads the original `dmsetup table` as the recovery table when
`RUSTFS_FAULT_TEST_DM_RECOVERY_TABLE` is unset. On normal failure paths it
restores that table, but operators must still verify host storage manually after
the run.

### dm-flakey Cleanup

`fault-cleanup` removes the owned Kubernetes namespace and managed Chaos
resources only. It does not remove the static StorageClass, PVs, loop devices,
mounts, or device-mapper device.

```bash
make fault-cleanup
kubectl delete pv -l app.kubernetes.io/managed-by=s3chaos
kubectl delete storageclass rustfs-fault-dm
```

On the DM node:

```bash
sudo umount /data/rustfs/rustfs-fault-lab/volume
sudo dmsetup remove rustfs-fault-dm
sudo losetup -j /data/rustfs/rustfs-fault-lab/disk.img
sudo losetup -d <loop-device>
sudo rm -rf /data/rustfs/rustfs-fault-lab
```

On the other three nodes:

```bash
sudo umount /data/rustfs/rustfs-fault-lab/volume
sudo losetup -j /data/rustfs/rustfs-fault-lab/disk.img
sudo losetup -d <loop-device>
sudo rm -rf /data/rustfs/rustfs-fault-lab
```
