# dm-flakey Operations

This runbook prepares and tears down the host device-mapper and Kubernetes
storage required by the `dm-flakey` and `dm-flakey-versioned-hot` scenarios.
Use only dedicated lab hosts and storage. Verify every node, device, mount,
PersistentVolume, and path before applying or removing resources.

`dm-flakey` and `dm-flakey-versioned-hot` are explicit scenarios that need a
dedicated static Local PV setup and privileged helper access on the fault
namespace.

There is no Make target that installs this environment. Prepare the host storage
and Kubernetes Local PVs first, then use `fault-preflight` to verify them.

## dm-flakey Host Storage

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

## dm-flakey Kubernetes Storage

Create one `kubernetes.io/no-provisioner` StorageClass and exactly four `100Gi`
Local PVs for the fault StorageClass. Each PV must point at the host path created
above and must use node affinity for its real node name.

```bash
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<dedicated-context>'
export DM_STORAGE_CLASS=rustfs-fault-dm
export DM_MOUNT_PATH=/data/rustfs/rustfs-fault-lab/volume

kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" apply -f - <<EOF
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
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" apply -f - <<EOF
apiVersion: v1
kind: PersistentVolume
metadata:
  name: <pv-name>
  labels:
    app.kubernetes.io/managed-by: s3chaos
    rustfs.com/fault-storage: dm-flakey
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

kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  create namespace "$RUSTFS_FAULT_TEST_NAMESPACE" --dry-run=client -o yaml | \
  kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" apply -f -
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  label namespace "$RUSTFS_FAULT_TEST_NAMESPACE" \
  app.kubernetes.io/managed-by=s3chaos \
  pod-security.kubernetes.io/enforce=privileged \
  --overwrite
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  annotate namespace "$RUSTFS_FAULT_TEST_NAMESPACE" \
  "rustfs.com/fault-test-tenant=$RUSTFS_FAULT_TEST_TENANT" \
  --overwrite
```

Verify the storage setup before running the scenario:

```bash
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  get storageclass "$DM_STORAGE_CLASS"
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  get pv -o wide | grep "$DM_STORAGE_CLASS"
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  get namespace "$RUSTFS_FAULT_TEST_NAMESPACE" --show-labels
```

The device-mapper scenario preflight requires exactly four `Available` or
`Bound` `100Gi` PVs in the selected static StorageClass.

Create a long-lived read-only host observer outside the disposable fault
Tenant namespace. Preflight only executes `findmnt`, `readlink`, and `dmsetup
table` through this Pod; it never creates a helper Pod or changes host/storage
state. Replace `<dm-node-name>` before applying:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: rustfs-fault-observers
---
apiVersion: v1
kind: Pod
metadata:
  name: dm-observer
  namespace: rustfs-fault-observers
  labels:
    app.kubernetes.io/managed-by: s3chaos
    rustfs.com/fault-host-observer: "true"
spec:
  nodeName: <dm-node-name>
  restartPolicy: Never
  containers:
    - name: host-tools
      image: rancher/mirrored-library-busybox:1.37.0
      command: ["sh", "-c", "trap : TERM INT; while :; do sleep 3600 & wait $!; done"]
      securityContext:
        privileged: true
      volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
  volumes:
    - name: host-root
      hostPath:
        path: /
        type: Directory
```

The observer is intentionally separate from the fault namespace because the
runner recreates that namespace for dedicated-storage scenarios. Its
privileged access is still security-sensitive; dedicate it to the lab and
remove it after testing.

## dm-flakey Run

Required variables on the machine that runs the s3chaos command:

```bash
export RUSTFS_FAULT_TEST_SERVER_IMAGE='docker.io/rustfs/rustfs@sha256:<digest>'
export RUSTFS_FAULT_TEST_STORAGE_CLASS=rustfs-fault-dm
export RUSTFS_FAULT_TEST_DM_NAME=rustfs-fault-dm
export RUSTFS_FAULT_TEST_DM_NODE='<dm-node-name>'
export RUSTFS_FAULT_TEST_DM_MOUNT_PATH=/data/rustfs/rustfs-fault-lab/volume
export RUSTFS_FAULT_TEST_DM_FAULT_TABLE='0 <sectors> flakey <backing-device> 0 1 15'
export RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE=rustfs-fault-observers
export RUSTFS_FAULT_TEST_DM_OBSERVER_POD=dm-observer
export RUSTFS_FAULT_TEST_DEVICE_MAPPER_DESTRUCTIVE=1
export RUSTFS_FAULT_TEST_HOST_NODE_ALLOWLIST='<dm-node-name>'
export RUSTFS_FAULT_TEST_HOST_DEVICE_ALLOWLIST=/dev/mapper/rustfs-fault-dm
export RUSTFS_FAULT_TEST_HOST_PV_ALLOWLIST='<exact-target-pv-name>'
```

Copy the length and backing-device fields from `sudo dmsetup table "$DM_NAME"`
on the DM node into `<sectors>` and `<backing-device>`. Preserve the reported
device identifier exactly (typically `major:minor`); an equivalent `/dev/loopN`
path does not satisfy the exact table contract. `RUSTFS_FAULT_TEST_DM_FAULT_TABLE` is
required only by the legacy `dm-flakey` EIO scenario. The
`dm-flakey-versioned-hot` crash proxy ignores it and derives a fail-closed
`drop_writes` table from the live, single-segment linear table.

Optional:

```bash
export RUSTFS_FAULT_TEST_DM_RECOVERY_TABLE='<dmsetup recovery table>'
export RUSTFS_FAULT_TEST_DM_HELPER_IMAGE='rancher/mirrored-library-busybox:1.37.0'
export RUSTFS_FAULT_TEST_ACK_OPERATION_TIMEOUT_MS=30000
export RUSTFS_FAULT_TEST_MAX_ACK_TO_FAULT_MS=1000
```

Run:

```bash
make fault-preflight SCENARIO=dm-flakey
make fault-run-dm
```

Run the soft-power-loss proxy with the same host/PV variables but without a
fault-table variable:

```bash
unset RUSTFS_FAULT_TEST_DM_FAULT_TABLE
make fault-preflight SCENARIO=dm-flakey-versioned-hot
make fault-run SCENARIO=dm-flakey-versioned-hot
```

Run one true ACK-then-activate detector by selecting its typed scenario:

```bash
make fault-run SCENARIO=dm-drop-writes-after-ack-put
make fault-run SCENARIO=dm-drop-writes-after-ack-overwrite
make fault-run SCENARIO=dm-drop-writes-after-ack-delete-marker
make fault-run SCENARIO=dm-drop-writes-after-ack-zero-byte-put
make fault-run SCENARIO=dm-drop-writes-after-ack-multipart-complete
```

These five cases share the same DeviceMapper actuator but remain independent
catalog entries and suite attempts. Each prepares only its required baseline,
proves the host-storage target, issues one typed mutation, and starts
`drop_writes` only after a definite 2xx response with a non-null version ID.
`ack-to-fault-evidence.json` records the operation ID, key, version ID, ACK
timestamp, fault activation timestamp, measured ACK-to-fault interval, and
`maxAckToFaultMs`. No S3 request is allowed between that ACK and the forced
crash boundary. A timeout, unknown result, missing version identity, late
activation, or extra request invalidates the run rather than producing PASS.
The gate contract rejects `maxAckToFaultMs` above 1000 ms. Both checker reports
must enumerate the exact history-derived `key@version` values, including the
trigger version or DELETE marker. Multipart staging is registered for normal
error cleanup and guarded for cancellation before the completion ACK.

Its recovery boundary is intentionally owned by the host backend:

1. Prove the Local PV, Pod, node, mount, mapper source, and active linear table.
2. Switch to `up=0`, `down=86400`, `drop_writes` using `--nolockfs`, so the
   switch does not synchronize filesystem dirty state.
3. Run the versioned workload and require at least one successful PUT, delete
   marker, or multipart completion with a version ID.
4. Add a run-owned `NoSchedule` taint, force-delete the owning Pod, and unmount
   the filesystem while `drop_writes` is still active. The unmount flush is
   acknowledged but discarded, then releases the page cache.
5. Restore the exact pre-injection linear table, remount with the captured
   filesystem type/options, remove the taint, and wait for the replacement Pod
   and Tenant to stabilize before lineage verification.

The adapter refuses multi-segment or non-linear recovery tables, refuses to
overwrite a pre-existing crash-containment taint, and keeps the node tainted if
storage cannot be remounted. A configured recovery-table override must exactly
match the table observed before crash injection. Immediately before mutation,
`host-storage-proof.json` binds the exact node, logical/canonical device, PV,
PVC, Pod UID, mounted filesystem, recovery-table hash, quarantine rule, and
post-cleanup requirements. Apply re-observes the same target and fails closed if
it changed. Successful recovery writes `host-storage-post-cleanup.json` only
after the recovery table, mapper-backed mount, and absent quarantine are
observed.

Activation, after-workload, and recovery snapshots bind the mapper name,
canonical device, suspension state, table, and observation time to that proof.
Missing snapshots or drift invalidate the run. If rollback fails, the adapter
attempts to suspend the mapper with `--noflush --nolockfs` and verifies that
I/O remains suspended. `NoSchedule` only prevents new scheduling; it does not
stop an existing Pod. The helper and unresolved mutation marker remain for
manual recovery even if the scheduling taint succeeds. The wrapper preserves
that marker after the process exits; only verified recovery clears it.

The Rust test reads the original `dmsetup table` as the recovery table when
`RUSTFS_FAULT_TEST_DM_RECOVERY_TABLE` is unset. On normal failure paths it
restores that table, but operators must still verify host storage manually after
the run.

## dm-flakey Cleanup

`fault-cleanup` removes the owned Kubernetes namespace and managed Chaos
resources only. It does not remove the static StorageClass, PVs, loop devices,
mounts, or device-mapper device.

Before removing host storage, confirm the active mount source, device-mapper
table, and loop-device path still match this runbook's dedicated lab paths.
Stop if any resolved target differs.

```bash
export RUSTFS_FAULT_TEST_EXPECTED_CONTEXT='<run-context>'
export RUSTFS_FAULT_TEST_NAMESPACE='<run-namespace>'
export RUSTFS_FAULT_TEST_TENANT='<run-tenant>'
make fault-cleanup
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  delete namespace "$RUSTFS_FAULT_TEST_DM_OBSERVER_NAMESPACE"
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  delete pv -l rustfs.com/fault-storage=dm-flakey
kubectl --context "$RUSTFS_FAULT_TEST_EXPECTED_CONTEXT" \
  delete storageclass rustfs-fault-dm
```

On the DM node:

```bash
sudo umount /data/rustfs/rustfs-fault-lab/volume
sudo dmsetup remove rustfs-fault-dm
sudo losetup -j /data/rustfs/rustfs-fault-lab/disk.img
export LOOP_DEVICE='<verified-loop-device-from-losetup-output>'
sudo losetup -d "$LOOP_DEVICE"
sudo rm -rf /data/rustfs/rustfs-fault-lab
```

On the other three nodes:

```bash
sudo umount /data/rustfs/rustfs-fault-lab/volume
sudo losetup -j /data/rustfs/rustfs-fault-lab/disk.img
export LOOP_DEVICE='<verified-loop-device-from-losetup-output>'
sudo losetup -d "$LOOP_DEVICE"
sudo rm -rf /data/rustfs/rustfs-fault-lab
```
