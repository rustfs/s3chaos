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
  `data_corruption`, and `ambiguous_write_materialized`.
- Current run-failure reasons are `harness_error`, `test_harness`,
  `workload_execution_error`, `artifact_validation_failed`,
  `checker_execution_error`, `preflight_failed`, `health_guard_failed`,
  `fault_backend_unavailable`, `fault_not_active`, `fault_not_recovered`,
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
  `post_recovery`, and fault-window relations. This is not the same as a true
  ack-triggered fault executor.

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

- [ ] PARTIAL: Versioned workload foundation exists, but the reliability plan is
  not implemented yet.
  Meaning: current executable catalog scenarios still mostly cover
  inject-recover-verify faults. The stateful RustFS reliability flows remain in
  the ordered TODO below: quorum P/P+1, fresh volume replacement, admin
  decommission/rebalance, on-disk bitrot, stale disk with dangling cleanup,
  and long-run suite campaigns.

- [ ] TODO: Keep admin operations as scenario-owned product/recovery steps.
  Meaning: RustFS admin APIs such as heal, decommission, and rebalance should be
  orchestrated by scenarios and observed through workload/history/checker
  verdicts. They are not generic fault backend behavior. Heal is a recovery
  strategy for replacement/bitrot, not a healthy-cluster scenario.
  Decommission needs a multi-pool Tenant shape first.

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

- [ ] TODO: Implement true ack-triggered fault execution.
  Meaning: the runner must wait for an eligible committed operation, record
  `trigger_operation_id`, version id, ACK timestamp, and apply the fault within
  `maxAckToFaultMs`. Timeout/unknown/interrupted operations must not arm the
  trigger. The hot DM proxy now records an acknowledged mutation before its
  forced crash boundary, but the drop-writes table is active before that ACK;
  the calibrated quiet single-write detector still needs the stricter
  ACK-then-activate timing contract.

- [ ] TODO: Add a quiet single-write calibration workload.
  Meaning: hot workloads can self-defeat metadata-loss tests because later
  fdatasync/journal activity may persist earlier metadata. The first detector
  should use one committed operation, tight ack-to-fault timing, bounded retry,
  and recorded filesystem commit/writeback parameters.

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
  health between samples. Continuous monitoring and post-recovery target-aware
  guards remain pending.

- [x] DONE: Add host/storage mutation preflight.
  Meaning: executable device-mapper scenarios now require exact singleton
  node/device/PV allowlists, a separate device-mapper destructive opt-in, and a
  typed rollback/quarantine/post-cleanup contract. The proof persists canonical
  fault/recovery tables and executable rollback commands; apply re-observes the
  full Pod UID/PVC/PV/node/mount/table chain before loading the proven table.
  Signal cancellation unwinds the guard. Activation and workload snapshots
  prove the same active mapper and fault table; successful recovery binds its
  snapshot to `host-storage-post-cleanup.json`. Failed rollback attempts to
  suspend the mapper and retains the helper and mutation marker for manual
  recovery; a scheduling taint alone cannot prove storage containment. PV
  replacement, bitrot, and stale-disk flows remain non-executable catalog
  entries and must use the same domain proof when their adapters are implemented.

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

- [ ] TODO: Add `dm-drop-writes-after-ack`.
  Meaning: this is the first executable soft-power-loss detector. It should use
  ack-trigger, quiet single-write calibration, `drop_writes`, strict/relaxed/none
  calibration, target proof, and precise final checker classification.

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
  repaired shard; runtime orchestration still depends on executable quorum
  targeting.

- [ ] PARTIAL: Add `fresh-volume-replacement-heal`.
  Meaning: replace one PVC/PV with an empty volume, record original and
  replacement generation, quarantine/restore path, heal progress, and then force
  proof that the new volume contains the committed versions. The typed
  generation, pre-adoption emptiness, heal, and forced-read evidence contracts
  exist; a safe Operator/PVC replacement adapter is still required.

- [ ] PARTIAL: Add `on-disk-bitrot-heal`.
  Meaning: mutate bytes in one shard on a dedicated host volume, prove exact
  object-to-shard mapping, byte offset, original/mutated hash, rollback path,
  and verify corrupt bytes are never returned as successful S3 data. The
  mutation proof accepts only a versioned RustFS diagnostic mapping and refuses
  guessed private paths; RustFS does not yet expose that stable hook to S3Chaos.

- [ ] PARTIAL: Add heal observer artifacts.
  Meaning: `heal-summary.json` and `heal-progress.jsonl` should explain heal
  convergence/non-convergence, but checker/history remain the S3-visible verdict
  source. Typed summary/progress validation now requires monotonic counters and
  a matching successful terminal sample; the admin/scanner adapters must emit
  the artifacts during execution.

### 10. Add Stale Disk, Dangling Cleanup, And Campaign Scenarios

- [x] DONE: Add disk generation evidence contracts.
  Meaning: stale-disk and fresh-volume flows need PV/PVC/node/device generation,
  mount identity, reattach event, and old/new generation comparison. The
  contracts reject generation reuse for fresh replacement and reject a
  different generation for stale return.

- [ ] PARTIAL: Add `stale-disk-return-detect`.
  Meaning: continue writes/deletes while one disk generation is absent, reattach
  the old generation, and prove latest version id, delete marker latest state,
  and object hash do not roll back. The catalog and evidence contracts exist;
  the detach/reattach runtime adapter remains intentionally blocked.

- [ ] PARTIAL: Cover dangling cleanup inside `stale-disk-return-detect`.
  Meaning: record shard inventory before/after dangling cleanup and prove the
  cleanup actor did not delete recoverable committed fragments. This is a
  recovery phase and oracle of stale-disk return rather than a separate fault
  family. The proof contract exists; the RustFS inventory/cleanup adapter is
  still required.

- [ ] TODO: Add `long-run-durability-campaign`.
  Meaning: run repeated calibrated scenarios under continuous workload with
  periodic full verification and fd/RSS/artifact-size trend gates for release
  qualification. Implement this as suite orchestration after the component
  scenarios are executable, not as a planned fault backend.

### 11. Document Network Faults As A Separate Axis

- [ ] TODO: Mark network partitions as availability/consistency coverage, not
  static durability-loss coverage.
  Meaning: network scenarios are valuable and cheaper to execute, but they do
  not substitute for stale disk, data shard loss, or ACK-then-lost storage
  physics. Multi-target/asymmetric partition can be tracked separately.

### 12. Keep Physical Power Deferred

- [ ] DEFERRED: Real power-cycle backend and power scenarios.
  Meaning: `single-node-power-cycle-after-ack`,
  `delete-marker-hard-poweroff`, `multipart-complete-hard-poweroff`,
  `quorum-p-power-cycle`, and `quorum-p-plus-one-power-cycle` stay out of the
  implementation order until a lab controller can prove target allowlist,
  out-of-band artifact writing, independent recovery, credential scope, and
  network path outside the fault domain.
