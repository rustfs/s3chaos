# RustFS Durability Fault Testing TODO

This TODO is the source of truth for the RustFS durability fault-testing work.
It folds the earlier durability/crash-consistency design discussion and the
PR #15 review feedback into an implementation order. Future work should follow
this file in order unless a new blocker changes the risk ranking.

Status legend:

- DONE: implemented on the current branch or already on `origin/main`.
- PARTIAL: usable foundation exists, but it is not sufficient for the review
  requirement.
- TODO: not implemented.
- BLOCKED: must not be implemented until a prerequisite proof or policy exists.
- DEFERRED: intentionally outside the current roadmap.

## Current Implemented Baseline

- [x] DONE: Ordered TODO as the single roadmap.
  Meaning: this file is the implementation entry point for durability
  fault-testing work. The older `docs/todo.md` roadmap has been folded into this
  file and removed so future work has one source of truth.

- [x] DONE: Suite plan extraction.
  Meaning: `suite_plan.rs` owns the pure `fault-suite-plan` model and plan
  expansion; suite execution persists `suite-plan.json`.

- [x] DONE: Basic fault lifecycle port.
  Meaning: `fault_lifecycle.rs` owns `FaultLifecyclePort` and `AppliedFaults`
  for apply/wait/snapshot/delete orchestration.

- [ ] PARTIAL: Backend lifecycle extraction.
  Meaning: the lifecycle container exists, but stateful Chaos Mesh, PodKill, and
  dm-flakey handle wrappers still live in `runner.rs`. Move them only if more
  backend state makes runner ownership unclear.

- [x] DONE: Failure summary v2 contract stabilization.
  Meaning: new writers emit `schema_version`, `phase`,
  `s3_model_classification`, `run_failure_reason`, `responsibility_domain`,
  severity, correctness/availability, evidence classifications, and
  `primary_evidence_refs`. Additive v2 fields remain optional for readers,
  writer classifications are allowlisted, and primary evidence uses one
  root-relative contract. Dedicated final-checker classification precision is
  still tracked below.

### Failure Summary V2 Compatibility Contract

- Readers must accept v2 summaries that predate additive fields. In particular,
  `case_name`, `observed_at_ms`, `phase`, `s3_model_classification`,
  `run_failure_reason`, `responsibility_domain`, and `primary_evidence_refs`
  are optional through v2. When present, they are validated. A future v3 may
  make them required.
- New writers emit `observed_at_ms` and the projection fields. Their
  classifications come from a closed allowlist; unknown or misspelled values
  are writer errors instead of falling through to `needs_investigation`.
- S3-model classifications are `recovery_tail_read_latency`,
  `committed_object_unavailable`, `committed_version_missing`,
  `committed_version_unavailable`, `version_hash_mismatch`,
  `delete_marker_missing`, `deleted_object_resurrected`,
  `delete_marker_lineage_incomplete`,
  `version_id_missing_on_committed_write`,
  `multipart_upload_lineage_incomplete`, `list_unavailable_or_unknown`,
  `listed_key_unreadable`, `unexpected_listed_object`, `data_corruption`, and
  `ambiguous_write_materialized`.
- Current run-failure reasons are `harness_error`, `test_harness`,
  `workload_execution_error`, `artifact_validation_failed`,
  `checker_execution_error`, `preflight_failed`, `health_guard_failed`,
  `fault_backend_unavailable`, `fault_not_active`, `fault_not_recovered`,
  `recovery_health_degraded`, `post_recovery_write_failed`,
  `availability_regression`,
  `unknown`, `checker_or_environment`, `test_or_environment`,
  `environment_or_fault_backend`, `product_or_environment`,
  `environment_or_workload`, `workload_or_product`, and `no_signal`. Mixed
  reasons are current writer outputs with unknown responsibility, not merely
  legacy reader inputs.
- New `primary_evidence_refs` entries are relative to the suite run artifact
  root (or the configured artifact root for a standalone scenario), never
  absolute, escaping, missing, or self-referential. Readers continue to accept
  the original v2 case-directory-relative leaf form for existing artifacts.

- [x] DONE: `preflight-summary.json`, `target-proof.json`, and
  `artifact-validation-report.json` are part of the success artifact gate.
  Meaning: runner writes structured preflight/target proof artifacts, run specs
  require them, and artifact validation checks them for successful runs.

- [ ] PARTIAL: Target proof.
  Meaning: current proof resolves RustFS pods, PVCs, PVs, nodes, and
  device-or-path for selector/volume targets. It does not yet prove erasure-set
  identity, data/parity width, or same-set target coverage.

- [ ] PARTIAL: Durability cohorts and fault-window evidence.
  Meaning: history/checker can report `pre_fault`, `fault_active`,
  `post_recovery`, and fault-window relations. The typed ACK cases additionally
  bind the exact pre-fault trigger record to ACK, apply, activation, and crash
  timestamps. The qualification-only reliability families now have
  scenario-specific overlap, generation, mutation, heal, or stale-return
  contracts; their live timing and topology assumptions still need calibration.

- [x] DONE: LIST timeout/non-completion is separated from successful LIST
  content errors in checker classification.
  Meaning: a LIST request that does not complete is availability/unknown
  evidence, while a completed LIST with wrong content remains correctness
  evidence.

- [x] DONE: Versioned checker semantics.
  Meaning: committed version reads, delete marker checks, resurrection checks,
  ambiguous writes, recovery-tail classification, and dedicated final
  classifications are wired through failure-summary output.

- [x] DONE: Read-only artifact console exists.
  Meaning: `fault-console-json` and `fault-console-serve` inspect artifact
  roots.

## Retired Roadmap Guardrails

The old `docs/todo.md` roadmap is intentionally folded here. Keep these
guardrails when implementing the ordered TODO below.

### Bash And Rust Responsibility Boundary

- [x] DONE: Rust owns suite planning and persists `suite-plan.json`.
  Meaning: `s3chaos fault-suite-plan <suite.yaml>` is the destructive-plan
  review surface before execution.

- [ ] PARTIAL: Keep moving execution contract ownership into Rust.
  Meaning: Rust should own suite planning, artifact layout, budget decisions,
  and runtime validation. `scripts/fault-test.sh` should stay a thin operational
  wrapper for shell-specific setup, build preparation, process supervision, and
  cluster cleanup.

- [ ] PARTIAL: Keep the plan output operator-reviewable.
  Meaning: each attempt plan should include scenario, repetition, resolved fault
  duration, selected fault, target, workload profile, expected backend, required
  CRDs/tools, artifact paths, and budget impact before new YAML expressiveness is
  added.

### Suite YAML Contract Boundary

- [x] DONE: Typed scenario parameters and reusable workload profiles exist.
  Meaning: catalog-declared `params.kind` supports network delay/loss/corrupt/
  duplicate, IO latency, CPU stress, and memory stress. Suite-level
  `workloadProfiles` define reusable operation mix, payload distribution, and
  hotspot behavior, while a scenario selects one with `workloadProfile`.

- [x] DONE: Fault duration and suite budget have separate meanings.
  Meaning: scenario `faultDuration` is only the injection window. The suite
  `budgets.maxDuration` value is the protective attempt/suite budget.

- [ ] PARTIAL: Keep YAML intent-oriented, not a raw backend passthrough.
  Meaning: scenarios may declare safe parameter schemas such as network delay,
  packet loss, IO fault mode, target policy, or stress intensity, but Rust must
  continue to own supported fault semantics and reject unknown fields,
  unsupported params, unsafe values, and scenario/backend mismatches before
  destructive work starts.

### Fault Backend Port Boundary

- [x] DONE: Basic lifecycle orchestration is behind a fault-domain port.
  Meaning: apply, wait-active, snapshot, delete, and cleanup are modeled through
  lifecycle abstractions instead of being suite-parser behavior.

- [ ] PARTIAL: Keep backend-specific state out of suite parsing and planning.
  Meaning: Chaos Mesh, device-mapper, pod disruption, and future backends should
  remain adapters behind the fault-domain port. Backend-specific manifests,
  commands, status parsing, identity capture, and cleanup details must not define
  the user-facing suite contract.

- [ ] PARTIAL: Defer new backend families until the parameter model is stable.
  Meaning: adding more backends before scenario params are settled would let
  adapters leak semantics into YAML. New backend work should start from the
  catalog/spec boundary.

### RustFS Reliability Coverage Boundary

- [ ] PARTIAL: Versioned reliability workflows exist behind qualification.
  Meaning: current executable catalog scenarios still mostly cover
  inject-recover-verify faults. Fresh volume replacement, admin
  decommission/rebalance, on-disk bitrot, and stale disk with dangling cleanup
  now have closed qualification workflows but remain Planned pending live
  evidence. Long-run suite campaigns remain in the ordered TODO below.

- [ ] PARTIAL: Keep admin operations as scenario-owned product/recovery steps.
  Meaning: decommission/rebalance now have a fault-owned narrow port, typed
  RustFS signed-HTTP adapter, multi-pool Tenant model, and fail-closed evidence
  contracts. They remain scenario workflows rather than generic fault backend
  behavior. Heal is a recovery strategy for replacement/bitrot, not a
  standalone healthy-cluster scenario.

### Console And Reporting Boundary

- [x] DONE: Read-only artifact inspection exists.
  Meaning: the console can inspect artifact roots without becoming an execution
  control plane.

- [ ] PARTIAL: Keep shaping stable structured report JSON for the console.
  Meaning: suite summaries should link plans, live attempt status, artifact
  locations, health-guard decisions, final verdicts, run specs, event streams,
  checker reports, workload summaries, and fault evidence. `failures[]` is the
  ordered failure index, and `stopReason` points to the failure that stopped the
  suite early.

- [ ] TODO: Keep execution CLI-only until control-plane safety is explicit.
  Meaning: the console must remain read-only until authorization, audit,
  cancellation, and blast-radius controls are designed and implemented.

## Implementation Order

### 1. Keep This TODO And Current Code Aligned Before More Feature Work

- [x] DONE: Remove the stale long-form roadmap from this PR.
  Meaning: this TODO is now the only durability fault-testing work queue in
  `docs/`. Future status drift should be corrected here instead of maintaining a
  second roadmap.

- [x] DONE: Make failure-summary v2 additions explicitly optional until v3.
  Meaning: `schema_version=2` already exists. New fields that would invalidate
  existing v2 artifacts, especially `observed_at_ms`, must be optional until a
  future v3 contract.

- [x] DONE: Treat legacy mixed classifications as real run failure reasons while
  the writer still emits them.
  Meaning: keys such as `checker_or_environment`,
  `environment_or_workload`, `workload_or_product`, and
  `product_or_environment` should be documented and validated as current writer
  outputs, not only as legacy reader inputs, until they are replaced.

- [x] DONE: Fix the `primary_evidence_refs` contract.
  Meaning: the design says no self-reference and suite-root relative paths, but
  current writers include `failure-summary.json` and validation is same-dir. Pick
  one contract, update writer, validator, console, and docs together.

- [x] DONE: Add exhaustive classification allowlist tests for new writers.
  Meaning: unknown or misspelled classification strings must not silently
  degrade to `needs_investigation`/`unknown` when the writer intended a product
  verdict.

### 2. Add Detector Calibration Before New Destructive Scenarios

- [x] DONE: Add catalog metadata for detector calibration.
  Meaning: every catalog scenario declares typed `detects` bug families and is
  explicitly qualified as a `gate-candidate` or `diagnostic-only` detector.
  Catalog validation rejects empty or duplicate families. `gate-candidate`
  does not mean calibrated; the live calibration ladder remains required.

- [ ] TODO: Implement the durability-mode calibration ladder.
  Meaning: run each detector against RustFS modes/images where the expected
  result is known: `strict` must pass, `relaxed` must fail for metadata-loss
  families, and `none` or a pinned vulnerable image must fail more broadly. A
  scenario that cannot produce this PASS/FAIL pair is diagnostic-only.

- [ ] TODO: Make calibration evidence mandatory for Phase 4 acceptance.
  Meaning: successful calibration must include mode/image, workload shape,
  target proof, non-empty crash-window cohort, expected classification, actual
  classification, and artifact validation. Missing signal is `no_signal` or
  harness/backend failure, not PASS.

- [x] DONE: Add explicit expected-failure semantics for diagnostic suites.
  Meaning: a suite scenario may declare a typed product classification,
  severity, responsibility domain, and required evidence refs. The suite
  summary accepts the non-zero attempt only when its validated failure summary
  matches every field and all required evidence exists. Success, `no_signal`,
  missing summaries, infra/backend failures, and missing evidence remain suite
  failures.

### 3. Correct The Soft-Power-Loss Fault Model

- [x] DONE: Add a dm `drop_writes` actuator path.
  Meaning: EIO/flakey faults exercise error handling, not ACK-then-lost
  durability. `drop_writes` lets writes appear successful to the upper layer
  while the backend discards them, which can expose metadata/data loss after a
  committed ACK.

- [x] DONE: Add `dmsetup suspend --nolockfs` support for crash-like table
  switches.
  Meaning: default suspend freezes and syncs the filesystem, which can flush the
  exact dirty pages the test is trying to lose. Any crash-like dm path must avoid
  implicit flushes.

- [x] DONE: Implement true ack-triggered fault execution.
  Meaning: the runner must wait for an eligible committed operation, record
  `trigger_operation_id`, version id, ACK timestamp, and apply the fault within
  `maxAckToFaultMs`. Timeout/unknown/interrupted operations do not arm the
  trigger. Five typed cases cover create PUT, overwrite, DELETE marker,
  zero-byte PUT, and pre-staged MPU completion. The older
  `dm-flakey-versioned-hot` diagnostic deliberately retains its original
  fault-active hot-workload semantics.

- [ ] PARTIAL: Add a quiet single-write calibration workload.
  Meaning: hot workloads can self-defeat metadata-loss tests because later
  fdatasync/journal activity may persist earlier metadata. The first detector
  should use one committed operation, tight ack-to-fault timing, bounded retry,
  and recorded filesystem commit/writeback parameters. The ACK cases now
  create only the bucket and case-specific prerequisite version or multipart
  parts, prove the target, issue exactly one eligible commit, activate
  `drop_writes`, and send no further S3 request before the crash boundary.
  Runtime artifacts bind the typed mutation, operation/version identity, ACK
  and activation timestamps, `maxAckToFaultMs`, and the DM crash/recovery
  evidence. Recording host filesystem/journal writeback parameters for
  cross-run calibration remains TODO.

- [x] DONE: Assert a non-empty crash-window cohort.
  Meaning: if no committed operation actually fell inside the requested
  ACK-to-fault window, the run did not test the intended failure model and must
  not pass as a product verdict.

### 4. Add Per-Version-Type Quorum Math

- [x] DONE: Add a quorum table by version/object type.
  Meaning: the pure model separates payload and persisted metadata quorum
  geometry. The executable volume-quorum cases bind their typed payload or
  metadata parameter to that table before deriving P or P+1.

- [x] DONE: Record RustFS erasure-set shape in target proof.
  Meaning: network quorum binds Tenant geometry and Ready Pod identities to
  runtime set/parity and server/drive membership. Volume quorum additionally
  binds every Pod/container/mount/PVC/PV candidate to its sole drive UUID
  before apply, then records the actual selected and non-target partition from
  IOChaos controller evidence.

- [x] DONE: Keep volume-quorum scenarios fail-closed on exact same-erasure-set
  volume proof.
  Meaning: volume quorum accepts only a fresh single-pool, single-set Tenant
  with one volume per server. It maps the runtime admin drive UUIDs to complete
  Kubernetes volume proofs, then validates the actual IOChaos targets and their
  complement. Unsupported or ambiguous layouts do not inject a fault.

### 5. Implement Volume-Kind Fixed Targeting

- [x] DONE: Allow `FixedTargets(N)` for RustFS volume fault kinds.
  Meaning: the typed fault and backend layers accept bounded fixed target
  counts while existing percent-based scenarios retain their one-Pod selector
  and independent I/O sampling behavior. Executable quorum scenarios resolve a
  semantic P/P+1 selector to this mode only after runtime topology proof.
  Composite fault plans remain rejected.

- [x] DONE: Render and prove Chaos Mesh volume faults for `FixedTargets(N)`.
  Meaning: IOChaos renders `mode: fixed` with the declared count, injects all
  matching I/O on those selected volumes, and records the controller-selected
  container targets. Runtime proof binds the exact RustFS container mount path
  through Pod volume name, PVC, PV, storage source, and supported required Node
  label constraints; unsupported affinity forms fail closed. Every Pod in the
  tenant selector must pass preflight before a fixed count can be injected.
  Activation and workload evidence preserve the selected Pod names, UIDs, and
  running RustFS container IDs and reject controller record drift. Replacing a
  container invalidates its mount-namespace proof even when the Pod UID stays
  unchanged. The proof also validates action,
  methods, parameters, sampling, and duration. Quorum target proof also
  partitions the complete same-set drive membership into selected and
  non-target UUIDs. The host DeviceMapper backend remains deliberately
  single-target because its configuration names one mapper/device.

- [x] DONE: Keep quorum targeting separate from heterogeneous composition.
  Meaning: `FixedTargets(N)` changes only the selector of one typed volume
  injection. It does not introduce a generic multi-phase workflow abstraction,
  heterogeneous faults, or raw YAML backend steps. P/P+1 remain independent
  single-fault scenarios whose concrete count is derived at runtime.

### 6. Harden Target-Aware Safety Gates

- [ ] PARTIAL: Make the health guard target-aware.
  Meaning: volume quorum proves the exact selected IOChaos targets and complete
  non-target drive set at activation and after the workload. RustFS admin
  observations before the read probes/mutations and after the workload require
  all non-target drives to be healthy, with unchanged deployment, geometry,
  and drive identities. These are two endpoint guards, not proof of continuous
  health between samples. Continuous monitoring remains pending.

- [x] DONE: Post-recovery RustFS health gate for every scenario.
  Meaning: `recovery_health.rs` captures the healthy drive/server/geometry
  baseline before fault activation and, after the recovery gate, polls until
  RustFS reports exactly that drive set `ok` and every Pod answers readiness,
  writing `recovery-health.json` (rustfs/backlog#2443). A drive that stays
  `offline`/`unknown`/`faulty` after recovery fails as
  `recovery_health_degraded` even when every committed object reads back.

- [x] DONE: Post-recovery fresh-write probe and LIST ghost-key check.
  Meaning: after recovery the runner writes, reads, lists, and deletes fresh
  objects under a separate prefix with its own history file so the
  authenticated workload phase chain stays untouched
  (`post-recovery-write-report.json`, rustfs/backlog#2444). The final checker
  reports listed keys that GET cannot read (`listed_key_unreadable`) and
  readable listed keys no write explains (`unexpected_listed_object`);
  failed-but-materialized writes are tolerated only when GET returns the
  bytes one of the failed attempts sent.

- [x] DONE: Availability contract for in-redundancy faults.
  Meaning: `pod-kill-one`, `pod-failure`, and `network-partition-one` use the
  `availability-required` impact policy (rustfs/backlog#2445): a fault-active
  read probe over the prefilled cohort must verify every object and each
  workload family must meet `RUSTFS_FAULT_TEST_MIN_AVAILABILITY_PERCENT`
  (catalog floor 99, which the variable may only raise; floors below 100
  tolerate one disrupted operation per family; families under 20 operations
  fail closed as unexercised).
  The port-forward is re-pinned to a surviving Pod after activation because a
  Service forward stays attached to the Pod it started on. The 99% default is
  a pre-calibration margin; live runs must calibrate it before it gates a
  release.

- [x] DONE: Shutdown and restart coverage through a kubectl lifecycle backend.
  Meaning: `pod-graceful-restart-one`, `rolling-restart-all`, and
  `cluster-cold-restart` use `FaultBackend::KubernetesLifecycle`
  (rustfs/backlog#2446). Pods are deleted with their default grace period:
  the operator applies the StatefulSet server-side and owns `spec.replicas`
  and the template annotations, so `rollout restart` and bare scaling would
  make kubectl a field co-owner and turn every later operator apply into a
  conflict. The final container `terminated` state is captured from a Pod
  watch and classified by the documented grace-timeout rule
  (`graceful_shutdown_failed` is a product failure; a replacement that never
  becomes Ready is `product_or_environment`). Cold restart runs on a fresh
  Tenant (the scale leaves `kubectl-scale` co-owning `spec.replicas`), pauses
  the identity-checked operator Deployment named by
  `RUSTFS_FAULT_TEST_OPERATOR_DEPLOYMENT` with an annotation record that
  `fault-cleanup` can restore from, holds `spec.replicas` at zero, requires
  the workload to fail entirely, and restores both. All three reuse the
  recovery-health gate, the post-recovery write probe, and (for the first
  two) the availability contract. Live calibration is still pending.

- [x] DONE: Simultaneous multi-node failure and node-level crash proxy
  (rustfs/backlog#2447).
  Meaning: `pod-failure-quorum-edge` fails two RustFS Pods with one fixed-count
  PodChaos after the live runtime topology proof shows that removing their
  drives leaves read quorum but breaks write quorum; any other geometry fails
  closed. Every mutation during the outage must be rejected, and a
  read-survival probe (`quorum-edge-read-survival.json`) must verify the whole
  prefilled cohort through a forward re-pinned to a surviving Pod. The
  actual PodChaos targets are bound to the erasure-set membership at
  activation, after the workload, and again by offline artifact validation.
  `node-crash-proxy` runs the device-mapper `drop_writes` crash boundary under
  versioned load and then holds the node down: the `NoSchedule` quarantine
  taint and the node-local PV keep the replacement Pod unscheduled, so no
  second injection is needed. A composite PodChaos was rejected because it
  cannot inject into the Pending replacement and, applied before the boundary,
  would stop the writes `drop_writes` is meant to drop. The target Pod is
  sampled every five seconds with bounded `kubectl` calls; once the node has
  been down for 60 seconds the survivors must serve every prefilled object the
  workload never touched and a fresh write probe while it stays down
  (`node-down-hold.json`, `node-down-write-report.json`), and suite budgets
  reserve that hold; recovery then
  requires every drive `ok` again. Live calibration of both scenarios, including
  the hold length against RustFS drive-offline detection, is still pending.

- [x] DONE: Add host/storage mutation preflight.
  Meaning: executable device-mapper scenarios now require exact singleton
  node/device/PV allowlists, a separate device-mapper destructive opt-in, and a
  typed rollback/quarantine/post-cleanup contract. The proof persists canonical
  fault/recovery tables and executable rollback commands; apply re-observes the
  full Pod UID/PVC/PV/node/mount/table chain before loading the proven table.
  ACK-triggered cases finish that preparation before the mutation and use one
  host transaction after ACK to recheck the mapper, host mount, and table before
  activation. Observer and helper commands enter PID 1's mount namespace and
  preserve remote exit status separately from `kubectl` transport. Signal
  cancellation unwinds the guard. Activation and workload snapshots prove the
  same active mapper and fault table; `drop_writes` recovery also requires an
  offline read-only filesystem check before remount and writes
  `dm-filesystem-check.json`. Successful recovery binds its snapshot to
  `host-storage-post-cleanup.json`. Failed mapper rollback attempts suspension
  and retains the helper and mutation marker for manual recovery. A filesystem
  check failure instead leaves the recovered mapper active, the filesystem
  unmounted, and the node quarantined. PV replacement, bitrot, and stale-disk
  flows remain qualification-only Planned entries; their adapters now apply
  scenario-specific PV, device, mutation, inventory, and rollback proofs and
  still require live qualification.

- [x] DONE: Make host/storage mutation preflight side-effect free.
  Meaning: host preflight reads Kubernetes metadata and fixed read-only host
  commands through a pre-provisioned observer Pod, then writes only the proof
  artifact. It does not create the observer or mutate disks, PV/PVC objects,
  object data, or power state.

### 7. Wire Precise Final Checker Classifications

- [x] DONE: Project final checker evidence to product classifications.
  Meaning: final checker failures must map to S3-visible product classes such
  as `committed_version_missing`, `committed_object_unavailable`,
  `delete_marker_missing`, or `version_hash_mismatch`, not generic
  `product_or_environment`.

- [x] DONE: Split committed version/delete marker/MPU primary classifications.
  Meaning: checker already records many facts; reporting must expose the
  highest-signal one as the primary `s3_model_classification` so #4221-style
  ACK-then-loss is routed to product correctness/availability, not unknown.

- [x] DONE: Add durability checker goldens.
  Meaning: synthetic histories should cover PUT 200 loss, DELETE 204
  resurrection, committed MPU complete loss, missing version id, ambiguous
  materialization, LIST timeout, and completed LIST wrong content.

The checker owns classification precedence. Exact committed-version 404 or
complete-version-list omission is `committed_version_missing`; exact-version
timeouts remain `committed_version_unavailable`; version body mismatch is
`version_hash_mismatch`; missing committed delete markers and visible deleted
objects are `delete_marker_missing` and `deleted_object_resurrected`. A 2xx
write response without a version id is incomplete lineage, not proven loss;
DELETE uses `delete_marker_lineage_incomplete`, while MPU completion uses the
more specific `multipart_upload_lineage_incomplete`.
Reporting only projects this typed checker result into failure-summary fields.

### 8. Add The First Calibrated Destructive Smoke Scenarios

- [x] DONE: Add the typed `dm-drop-writes-after-ack-*` family.
  Meaning: five independent executable cases cover PUT create, overwrite,
  DELETE marker, zero-byte PUT, and pre-staged MPU completion. Each uses the
  ACK trigger, quiet single-write execution, `drop_writes`, target proof, a
  forced crash boundary, and precise final checker classification.

- [ ] TODO: Add strict/relaxed/none host writeback calibration controls.
  Meaning: the ACK detectors fail closed on late activation and record the
  measured window, but cross-host comparisons still need explicit filesystem
  and journal writeback parameter capture plus controlled calibration modes.

- [x] DONE: Add `dm-flakey-versioned-hot` as a diagnostic single-volume
  soft-power-loss proxy.
  Meaning: the backend now uses `drop_writes`, `--nolockfs`, forced Pod loss,
  unmount/remount cache release, ACK evidence, and fail-closed recovery proof.
  It remains a negative control rather than the first calibrated detector:
  one-volume loss is masked by EC and hot workloads can flush or mask signal.

- [x] DONE: Add `pod-crash-versioned-hot` as a process-crash proxy and negative
  control.
  Meaning: it proves versioned workload/checker behavior through process
  disruption, but it must not be described as physical power loss.

- [x] DONE: Add `quorum-p-io-fault` and `quorum-p-plus-one-io-fault`.
  Meaning: these target exactly P and P+1 volumes in one erasure set with
  same-set proof. Payload and metadata are explicit typed cases, producing four
  suite attempts. P verifies the complete stable typed read cohort remains
  readable with intact hashes. At both P and P+1, every mutation whose write
  quorum exceeds the remaining shard count must receive no success ACK.
  Payload P+1 permits DELETE success only when metadata write quorum remains;
  for EC2+2 it rejects PUT, DELETE, and multipart completion. EC6+2 payload P
  still permits writes, while metadata P and P+1 reject all three mutations.
  Both boundaries stage multipart uploads before injection so completion
  rejection is observed directly rather than inferred from failed staging.
  Bounded `/rustfs/admin/v3/info` samples before the probes/workload and after
  the workload/controller recheck bind the unchanged deployment, geometry,
  endpoints, Pods, and drive UUIDs and require every non-target drive to be
  healthy. These two endpoint samples are guards, not continuous-health proof.
  Live qualification evidence is still required before release gating.

### 9. Fix Heal-Family Oracle Blind Spots

- [ ] PARTIAL: Add force-read-through-repaired-volume support.
  Meaning: after replacing or corrupting one volume, normal GET can reconstruct
  from other shards and pass even if heal is broken. The scenario must force
  reads through the healed/repaired volume, for example by faulting the other P
  volumes, before declaring heal success. `ForceReadThroughProof` now rejects
  any artifact that does not leave exactly read quorum online or excludes the
  repaired shard. Fresh-volume and bitrot qualification drivers now execute
  that exact-quorum targeting; live-cluster calibration remains before either
  scenario can leave Planned status.

- [ ] PARTIAL: Add `fresh-volume-replacement-heal`.
  Meaning: replace one PVC/PV with an empty volume, record original and
  replacement generation, quarantine/restore path, heal progress, and then force
  proof that the new volume contains the committed versions. The typed
  generation, pre-adoption emptiness, heal, and forced-read evidence contracts
  are connected to the Local-PV replacement driver, including Operator pause,
  empty-volume proof, rollback, and cleanup. Live Operator and RustFS
  qualification remains outstanding.

- [ ] PARTIAL: Add `on-disk-bitrot-heal`.
  Meaning: mutate bytes in one shard on a dedicated host volume, prove exact
  object-to-shard mapping, byte offset, original/mutated hash, rollback path,
  and verify corrupt bytes are never returned as successful S3 data. The
  mutation proof accepts only an exact RustFS object-version mapping and refuses
  guessed private paths. The driver now obtains that mapping with a bounded,
  offline XL2 inspector plus the privileged storage helper; it accepts the
  current capability profile and fails closed on unknown formats. Live
  qualification remains outstanding.

- [ ] PARTIAL: Add heal observer artifacts.
  Meaning: `heal-summary.json` and `heal-progress.jsonl` should explain heal
  convergence/non-convergence, but checker/history remain the S3-visible verdict
  source. Typed summary/progress validation now requires monotonic counters and
  a matching successful terminal sample. Fresh-volume emits the generic heal
  artifacts, and bitrot emits case-specific scanner/admin heal evidence during
  execution; live convergence and timeout calibration remain outstanding.

### 10. Complete Admin Topology Workflows

- [x] DONE: Add typed multi-pool Tenant rendering and RustFS admin topology
  operations.
  Meaning: each pool owns its server, volume, storage, placement, and class
  configuration. The fault-owned adapter supports pool list plus decommission
  start/status/cancel/clear and rebalance start/status/stop without using an
  `rc` subprocess or putting scenario policy in the IAM-oriented protocol port.

- [ ] PARTIAL: Add fail-closed decommission/rebalance evidence contracts.
  Meaning: preflight binds named pools and the fresh Tenant UID's endpoint sets
  to exact runtime pool IDs/cmdlines without array-order inference; it checks
  health, mutual exclusion, and the decommission 130% capacity guard plus a
  bounded workload budget, including SDK retries and possible recovery
  recommits. Timestamped pool lists bound to the same attempt
  must repeat those checks immediately before the start request and prove the
  post-terminal health/topology observation.
  Operation/progress evidence is bound to the current run, case, Tenant UID,
  and attempt time window and requires a successful terminal state, monotonic
  scenario-specific state transitions, and before/after topology. Failed,
  canceled, stopped, mismatched, zero-movement, or incomplete evidence cannot
  pass. Terminal responses must also have no unresolved decommission entries
  or rebalance cleanup-warning entries, even if aggregate counters are clear.

- [ ] PARTIAL: Add the scenario-owned `admin-decommission` operation phase.
  Meaning: the decommission case now reaches the shared admin executor through
  the dedicated Planned-admin qualification flag. It stages an attempt-owned
  two-pool Tenant, runs the bounded versioned S3 workload, polls through the
  signed RustFS admin adapter, persists raw request/progress/overlap evidence,
  and performs identity-safe cancel/clear and Tenant cleanup on failure. The
  contract requires a real S3 operation and an exact-target status request
  interval to intersect, rejects zero movement and incomplete mutation
  families, and binds the version-aware final checker to complete history. The
  catalog remains Planned until the Operator/RustFS path is live-qualified.

- [ ] PARTIAL: Add the scenario-owned `admin-rebalance` operation phase.
  Meaning: the rebalance case now has a narrow staged-fixture port, bounded
  polling and stop-on-failure sequencing, raw request/progress capture, and an
  offline overlap contract. The contract requires a real S3 operation and a
  rebalance status request interval to intersect, rejects zero movement and
  incomplete mutation families, and binds the version-aware final checker to
  the complete history. The catalog remains Planned until the Operator/RustFS
  path is live-qualified.

- [ ] PARTIAL: Keep `admin-decommission` and `admin-rebalance` Planned until
  their production drivers are live-qualified.
  Meaning: typed admin dispatch and the shared phase executor no longer invent
  a generic `FaultInjection`; both cases have concrete drivers. They remain
  behind the exact Planned-admin qualification flag until staged Tenant
  identity, overlap, rollback, artifact, and final-checker receipts pass
  against live Operator and RustFS revisions.

### 11. Add Stale Disk, Dangling Cleanup, And Campaign Scenarios

- [x] DONE: Add disk generation evidence contracts.
  Meaning: stale-disk and fresh-volume flows need PV/PVC/node/device generation,
  mount identity, reattach event, and old/new generation comparison. The
  contracts reject generation reuse for fresh replacement and reject a
  different generation for stale return.

- [ ] PARTIAL: Add `stale-disk-return-detect`.
  Meaning: continue writes/deletes while one disk generation is absent, reattach
  the old generation, and prove latest version id, delete marker latest state,
  and object hash do not roll back. The qualification runner now performs the
  supervised detach/reattach sequence and records bounded absence/return
  samples; live device-mapper and RustFS qualification remains outstanding.

- [ ] PARTIAL: Cover dangling cleanup inside `stale-disk-return-detect`.
  Meaning: record shard inventory before/after dangling cleanup and prove the
  cleanup actor did not delete recoverable committed fragments. This is a
  recovery phase and oracle of stale-disk return rather than a separate fault
  family. The runner records inventory before and after cleanup and validates
  the cleanup proof; live calibration must still demonstrate that the bounded
  inventory and cleanup behavior match RustFS under workload.

- [ ] TODO: Add `long-run-durability-campaign`.
  Meaning: run repeated calibrated scenarios under continuous workload with
  periodic full verification and fd/RSS/artifact-size trend gates for release
  qualification. Implement this as suite orchestration after the component
  scenarios are executable, not as a planned fault backend.

### 12. Document Network Faults As A Separate Axis

- [ ] TODO: Mark network partitions as availability/consistency coverage, not
  static durability-loss coverage.
  Meaning: network scenarios are valuable and cheaper to execute, but they do
  not substitute for stale disk, data shard loss, or ACK-then-lost storage
  physics. `network-asymmetric-partition` now covers a one-way blackhole
  (`direction: to`, one source Pod). `network-flaky` covers bursty correlated
  loss only; it is not a timed on/off gate and it does not stack corruption.

### 13. Keep Physical Power Deferred

- [ ] DEFERRED: Real power-cycle backend and power scenarios.
  Meaning: `single-node-power-cycle-after-ack`,
  `delete-marker-hard-poweroff`, `multipart-complete-hard-poweroff`,
  `quorum-p-power-cycle`, and `quorum-p-plus-one-power-cycle` stay out of the
  implementation order until a lab controller can prove target allowlist,
  out-of-band artifact writing, independent recovery, credential scope, and
  network path outside the fault domain. Do not add a physical PSU catalog
  scenario. Mac Mini `C-PWR-03` stays Deferred; see
  `docs/MAC_MINI_CHAOS_COVERAGE.md`.

### 14. Mac Mini Catalog Gaps That Still Lack A Safe Actuator

These entries are catalogued as `Planned` and are not qualification cases.
`make fault-qualify-list` does not select them. Do not mark them executable
until the blocker in each item is gone.

- [ ] TODO: `io-eio-same-pod-two-volumes` (`C-DISK-07`).
  Meaning: `assess_same_pod_two_volume_geometry` fails closed unless
  `volumesPerServer >= 2`, the Pod has two data mounts, and those mounts are
  proven to share one erasure set. The volume binder and the single-fault
  IOChaos plan still assume one volume per server, so there is no executable
  runner.

- [ ] TODO: `network-partition-during-heal` (`C-LOAD-03`).
  Meaning: heal progress is captured only inside the planned fresh-volume and
  bitrot qualification workflows. It is not a composable signal that a
  NetworkChaos run can wait on.

- [ ] TODO: `clock-skew` (`C-TIME-01`).
  Meaning: Chaos Mesh TimeChaos is not wired, and shifting the clock of an
  already-running RustFS process is version-dependent. No host clock actuator.

- [ ] TODO: `credential-rotation-mid-load` (`C-CERT-01`).
  Meaning: no actuator rotates RustFS or Keycloak credentials while a workload
  is in flight without inventing a second harness.

- [ ] TODO: `network-split-brain` (`C-TOPO-01`).
  Meaning: the current NetworkChaos renderer uses overlapping source and target
  selectors, which isolates the selected Pods from each other instead of
  leaving two live pairs. Complement selectors are not implemented.

- [ ] TODO: `metadata-shard-corruption` (`C-META-01`/`C-META-02`/`C-META-03`).
  Meaning: `on-disk-bitrot` remains the planned object-shard case. It does not
  target metadata shards, and the binder is still one volume. No host mutation.

- [ ] DEFERRED: `C-PROC-04` file-descriptor exhaustion.
  Meaning: optional diagnostic pressure. No catalog entry until a cgroup or
  rlimit actuator can prove the target and clean it up.
