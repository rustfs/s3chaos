# Fault Suite Roadmap

This document tracks the next architecture steps for the fault-suite runner. The
current suite format is valid for selecting catalog scenarios, repetitions,
durations, percent overrides, workload object count, workload concurrency, and
suite budgets. It should not grow into a free-form Chaos Mesh passthrough before
the runner has an auditable plan and stronger safety boundaries.

## 1. Consolidate Bash And Rust Responsibilities

Status: first implementation pass added Rust-owned suite planning through
`s3chaos fault-suite-plan <suite.yaml>` and made suite runs persist the resolved
plan as `suite-plan.json`.

- Move more execution contract ownership into Rust: suite planning, artifact
  layout, budget decisions, and runtime validation.
- Keep `scripts/fault-test.sh` as a thin operational wrapper for shell-specific
  setup, build preparation, process supervision, and cluster cleanup.
- Add `s3chaos fault-suite-plan <suite.yaml>` to render the exact destructive
  plan before execution.
- Include each attempt's scenario, repetition, resolved duration, selected fault,
  target, workload profile, expected backend, required CRDs/tools, artifact
  paths, and budget impact in the plan output.
- Treat the plan output as the review surface for operators before expanding
  YAML expressiveness.

## 2. Extend The Suite YAML Contract

- Add typed scenario parameters instead of exposing raw backend manifests.
- Let supported scenarios declare safe parameter schemas, such as network delay,
  packet loss, IO fault mode, target selection policy, or stress intensity.
- Extend workload profiles beyond `objects` and `concurrency` with operation
  mix, payload distribution, multipart ratio, read/write/delete/list weights,
  hotspot behavior, and duration-based profiles.
- Keep validation strict: unknown fields, unsupported params, unsafe values, and
  scenario/backend mismatches must fail before any destructive work starts.
- Preserve catalog-backed behavior so YAML describes intent while Rust owns the
  supported fault semantics.

## 3. Abstract Fault Backend Ports

- Introduce a backend port owned by the fault domain for apply, wait-active,
  snapshot, ensure-active, delete, and cleanup operations.
- Keep Chaos Mesh, device-mapper, and future backends as adapters behind that
  port.
- Avoid adding a new backend until the scenario parameter model is stable enough
  that backend adapters do not define user-facing semantics.
- Keep backend-specific manifests, command invocations, status parsing, and
  cleanup details out of suite parsing and planning code.

## 4. Add Console And Reporting Surfaces

- Design a console-facing summary format for suite plans, live attempt status,
  artifact locations, health-guard decisions, and final verdicts.
- Link suite summaries to run specs, event streams, checker reports, workload
  summaries, and fault evidence.
- Keep the console surface read-only at first; execution should continue through
  the CLI until authorization, audit, cancellation, and blast-radius controls are
  explicit.
- Use the console requirements to shape stable report JSON instead of parsing
  human-oriented logs.
