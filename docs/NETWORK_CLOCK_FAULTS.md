# Network partition and process-clock fault cases

Both cases use the standard injection runner, deterministic mixed S3 workload,
recovery health gate, post-recovery write probe, and full object-model checker.
They can run through the existing CLI, Make targets, and fault-suite console.

```bash
make -j2 fault-suite-validate SUITE=fault/examples/network-clock.yaml
make -j2 fault-suite-plan SUITE=fault/examples/network-clock.yaml
make -j2 fault-suite-run SUITE=fault/examples/network-clock.yaml
```

The live run uses the target configured by the normal fault-test environment.
Chaos Mesh must provide the NetworkChaos and TimeChaos CRDs and working
controller/daemon injection support. Keep the fault duration longer than the
bounded probes and workload. A resource that expires before the post-workload
observations fails validation. Each resource is explicitly deleted before
recovery, with the same run-scoped cleanup used by other Chaos Mesh cases.

## `network-split-brain`

Exactly four symmetric Ready RustFS servers must belong to one runtime-proven
erasure set. The first two names in sorted order form one side and the last
two form the other. Both sides must retain read quorum and lose write quorum
under the reported server/drive membership. Other geometry fails preflight.

NetworkChaos uses exact, disjoint Pod selectors with `direction: both`.
Before injection, during the fault, after the mixed workload, and after
deletion, the runner probes every ordered Pod pair from the RustFS container's
network namespace. Each container needs `curl`, as provided by the standard
RustFS runtime image. Missing tools and malformed receipts fail preflight.
Probes use the live PodIP and declared RustFS S3 TCP listener. Healthy paths
must return HTTP 200 from `/health/live`; cut paths must time out before TCP
connection establishment. An HTTP timeout after TCP connected cannot prove
the network cut.

One pinned endpoint on each side reads up to three pre-fault committed objects
and attempts one fresh PUT with retries disabled. Reads must match their
committed bytes. PUT must return HTTP 503 or reach its bounded timeout after
one transmission; an acknowledged PUT fails the case. The per-side history
is stored separately from the normal workload history, and its operation IDs,
hashes, run identity, and timing are checked against the evidence. Probe PUTs
use a separate run-owned prefix. Their timeout or HTTP 503 result leaves the
commit state unconfirmed. After the normal recovery health gate, LIST and GET
receipts accept each probe key as absent or containing its exact expected
bytes and hash, including a request completed after network restoration.
Foreign keys and wrong bytes fail verification. The normal workload checker
keeps its existing prefix and rules. A proved product failure is recorded while
normal recovery and object verification complete; the run then returns that
failure.

`network-split-brain.json` records identities, complementary groups,
controller snapshots around probes, raw curl receipts, and per-side operation
IDs. `network-split-brain-s3-history.jsonl` holds the S3 records,
and `network-split-brain-recovery-history.jsonl` records recovered probe state.
Every capture
checks Pod UID, containerID, node, PodIP, and listener port before and after
the observations.

## `clock-skew`

The highest sorted Pod name is the target; the first is an independent control.
The case needs at least two running RustFS Pods. TimeChaos selects exactly the
target's `rustfs` container and `CLOCK_REALTIME`; monotonic clocks keep their
normal behavior. The existing mixed workload connects directly to that same
Pod through a port-forward established before injection, with the original
UID/containerID recorded alongside Date evidence. The default offset is
120 seconds. Typed suite parameters
accept positive or negative offsets with an absolute value in 60..=600 seconds:

```yaml
params:
  kind: clockSkew
  offsetSeconds: -120
```

`clock-skew.json` captures two fresh HTTP Date responses from each pinned Pod
in every phase. The request interval, one-second Date resolution, and a
two-second clock tolerance bound the expected offset. Date must advance
between samples. The target must show the planned offset during the fault
and return to the healthy time range after deletion; the control must stay in
that range throughout. Missing Date, cached responses, an unchanged process
clock under injection, or replaced Pod/container identities fail the case.

TimeChaos affects PID 1 and its children in the container. A process started
through `kubectl exec` is outside that lineage, so its clock is unsuitable as
the running RustFS clock observation. The case observes the already-running
RustFS HTTP listener through a direct Pod port-forward. The actuator changes
only the selected process clock; it has no host-clock operation. See the
[Chaos Mesh TimeChaos documentation](https://chaos-mesh.org/docs/simulate-time-chaos-on-kubernetes/).
