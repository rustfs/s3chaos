SHELL := /bin/bash

SCENARIO ?=
SUITE ?=
QUALIFICATION_CASE ?=
RUN_ROOT ?=
CHAOS_SUITE ?= $(CURDIR)/fault/examples/chaos-mesh.yaml
CONSOLE_ROOT ?= $(CURDIR)/target/fault-tests
CONSOLE_ADDR ?= 127.0.0.1:0
CONSOLE_ALLOW_NON_LOOPBACK ?=
FAULT_SCRIPT := $(CURDIR)/scripts/fault-test.sh
PROTOCOL_SCRIPT := $(CURDIR)/scripts/protocol-test.sh
PROTOCOL_COMPAT_SCRIPT := $(CURDIR)/scripts/protocol-compatibility.sh

.PHONY: check fmt fmt-check clippy test fault-check fault-list fault-qualify-list fault-qualify fault-qualify-analyze fault-preflight fault-run fault-chaos-plan fault-chaos-run fault-dm-run fault-suite-template fault-suite-validate fault-suite-plan fault-suite-run fault-console-json fault-console-serve fault-dashboard-install fault-dashboard-port-forward fault-cleanup release-gate protocol-check protocol-list protocol-compatibility-mint protocol-mint-cleanup protocol-suite-template protocol-suite-validate protocol-suite-plan protocol-suite-run protocol-cleanup protocol-validate-artifacts protocol-validate-mint-artifacts protocol-validate-mint-session

RELEASE_GATE_TIER ?= standard
RELEASE_GATE_DRY_RUN ?= 0
RELEASE_GATE_FETCH ?= 1

check: fmt-check clippy test

fmt:
	+cargo fmt --all

fmt-check:
	+cargo fmt --all -- --check

clippy:
	+cargo clippy --all-targets -- -D warnings

test:
	+cargo test --all-targets

fault-check: check
	bash -n $(FAULT_SCRIPT)
	+@for suite in $(CURDIR)/fault/examples/*.yaml; do bash $(FAULT_SCRIPT) suite-validate "$$suite"; done

fault-list:
	+@bash $(FAULT_SCRIPT) list

fault-qualify-list:
	+@bash $(FAULT_SCRIPT) qualify-list

fault-qualify:
	@test -n "$(QUALIFICATION_CASE)" || (echo "QUALIFICATION_CASE is required; run make fault-qualify-list" >&2; exit 1)
	+bash $(FAULT_SCRIPT) qualify "$(QUALIFICATION_CASE)"

fault-qualify-analyze:
	@test -n "$(RUN_ROOT)" || (echo "RUN_ROOT is required, for example: make fault-qualify-analyze RUN_ROOT=target/fault-tests/qualifications/<run>" >&2; exit 1)
	+bash $(FAULT_SCRIPT) qualify-analyze "$(RUN_ROOT)"

fault-preflight:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-preflight SCENARIO=io-eio" >&2; exit 1)
	+bash $(FAULT_SCRIPT) preflight "$(SCENARIO)"

fault-run:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-run SCENARIO=io-eio" >&2; exit 1)
	+bash $(FAULT_SCRIPT) run "$(SCENARIO)"

fault-chaos-plan:
	+@bash $(FAULT_SCRIPT) chaos-plan "$(CHAOS_SUITE)"

fault-chaos-run:
	+bash $(FAULT_SCRIPT) chaos-run "$(CHAOS_SUITE)"

fault-dm-run:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-dm-run SCENARIO=dm-flakey" >&2; exit 1)
	+bash $(FAULT_SCRIPT) dm-run "$(SCENARIO)"

fault-suite-template:
	+@bash $(FAULT_SCRIPT) suite-template

fault-suite-validate:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-validate SUITE=suite.yaml" >&2; exit 1)
	+bash $(FAULT_SCRIPT) suite-validate "$(SUITE)"

fault-suite-plan:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-plan SUITE=suite.yaml" >&2; exit 1)
	+bash $(FAULT_SCRIPT) suite-plan "$(SUITE)"

fault-suite-run:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-run SUITE=suite.yaml" >&2; exit 1)
	+bash $(FAULT_SCRIPT) suite-run "$(SUITE)"

fault-console-json:
	+cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- fault-console-json "$(CONSOLE_ROOT)"

fault-console-serve:
	+cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- fault-console-serve "$(CONSOLE_ROOT)" --addr "$(CONSOLE_ADDR)" $(CONSOLE_ALLOW_NON_LOOPBACK)

fault-dashboard-install:
	+bash $(FAULT_SCRIPT) dashboard-install

fault-dashboard-port-forward:
	+bash $(FAULT_SCRIPT) dashboard-port-forward

fault-cleanup:
	+bash $(FAULT_SCRIPT) cleanup

# Full RustFS release gate. Example:
#   make release-gate RUSTFS_VERSION=1.0.1-preview.11 RUSTFS_PREV_VERSION=1.0.0 RELEASE_GATE_TIER=full
# Dry-run plans every case and still verifies artifacts when RELEASE_GATE_FETCH=1:
#   make release-gate RUSTFS_VERSION=1.0.1-preview.11 RELEASE_GATE_DRY_RUN=1 RELEASE_GATE_TIER=full
release-gate:
	@test -n "$(RUSTFS_VERSION)" || (echo "RUSTFS_VERSION is required, for example: make release-gate RUSTFS_VERSION=1.0.1-preview.11" >&2; exit 1)
	bash -n $(CURDIR)/scripts/release-gate-upgrade.sh
	bash -n $(CURDIR)/scripts/release-gate-host-disk.sh
	+RUSTFS_VERSION="$(RUSTFS_VERSION)" \
		RUSTFS_PREV_VERSION="$(RUSTFS_PREV_VERSION)" \
		RUSTFS_IMAGE="$(RUSTFS_IMAGE)" \
		RUSTFS_PREV_IMAGE="$(RUSTFS_PREV_IMAGE)" \
		RELEASE_GATE_TIER="$(RELEASE_GATE_TIER)" \
		RELEASE_GATE_DRY_RUN="$(RELEASE_GATE_DRY_RUN)" \
		RELEASE_GATE_FETCH="$(RELEASE_GATE_FETCH)" \
		cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- release-gate

protocol-check: check
	bash -n $(PROTOCOL_SCRIPT)
	bash -n $(PROTOCOL_COMPAT_SCRIPT)

protocol-list:
	+@bash $(PROTOCOL_SCRIPT) list

protocol-compatibility-mint:
	+bash $(PROTOCOL_COMPAT_SCRIPT) mint

protocol-validate-mint-artifacts:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-validate-mint-artifacts ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>/mint" >&2; exit 1)
	+cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- protocol-mint-validate-artifacts "$(ARTIFACT_ROOT)"

protocol-validate-mint-session:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-validate-mint-session ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>" >&2; exit 1)
	+cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- protocol-mint-validate-session "$(ARTIFACT_ROOT)"

protocol-mint-cleanup:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-mint-cleanup ARTIFACT_ROOT=target/protocol-compatibility/mint/<run>" >&2; exit 1)
	+cargo run --quiet --manifest-path Cargo.toml --bin s3chaos -- protocol-mint-cleanup "$(ARTIFACT_ROOT)"

protocol-suite-template:
	+@bash $(PROTOCOL_SCRIPT) suite-template

protocol-suite-validate:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make protocol-suite-validate SUITE=suite.yaml" >&2; exit 1)
	+bash $(PROTOCOL_SCRIPT) suite-validate "$(SUITE)"

protocol-suite-plan:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make protocol-suite-plan SUITE=suite.yaml" >&2; exit 1)
	+bash $(PROTOCOL_SCRIPT) suite-plan "$(SUITE)"

protocol-suite-run:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make protocol-suite-run SUITE=suite.yaml" >&2; exit 1)
	+bash $(PROTOCOL_SCRIPT) suite-run "$(SUITE)"

protocol-cleanup:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-cleanup ARTIFACT_ROOT=target/protocol-tests/..." >&2; exit 1)
	+bash $(PROTOCOL_SCRIPT) cleanup "$(ARTIFACT_ROOT)"

protocol-validate-artifacts:
	@test -n "$(ARTIFACT_ROOT)" || (echo "ARTIFACT_ROOT is required, for example: make protocol-validate-artifacts ARTIFACT_ROOT=target/protocol-tests/..." >&2; exit 1)
	+bash $(PROTOCOL_SCRIPT) validate-artifacts "$(ARTIFACT_ROOT)"
