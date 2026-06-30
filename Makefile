SHELL := /bin/bash

SCENARIO ?=
SUITE ?=
FAULT_SCRIPT := $(CURDIR)/scripts/fault-test.sh

.PHONY: check fmt fmt-check clippy test fault-check fault-list fault-preflight fault-run fault-run-dm fault-suite-template fault-suite-validate fault-suite-plan fault-suite-run fault-dashboard-install fault-dashboard-port-forward fault-cleanup

check: fmt-check clippy test

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

clippy:
	cargo clippy --all-targets -- -D warnings

test:
	cargo test --all-targets

fault-check: check
	bash -n $(FAULT_SCRIPT)

fault-list:
	@bash $(FAULT_SCRIPT) list

fault-preflight:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-preflight SCENARIO=io-eio" >&2; exit 1)
	bash $(FAULT_SCRIPT) preflight "$(SCENARIO)"

fault-run:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-run SCENARIO=io-eio" >&2; exit 1)
	bash $(FAULT_SCRIPT) run "$(SCENARIO)"

fault-run-dm:
	bash $(FAULT_SCRIPT) run dm-flakey

fault-suite-template:
	@bash $(FAULT_SCRIPT) suite-template

fault-suite-validate:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-validate SUITE=suite.yaml" >&2; exit 1)
	bash $(FAULT_SCRIPT) suite-validate "$(SUITE)"

fault-suite-plan:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-plan SUITE=suite.yaml" >&2; exit 1)
	bash $(FAULT_SCRIPT) suite-plan "$(SUITE)"

fault-suite-run:
	@test -n "$(SUITE)" || (echo "SUITE is required, for example: make fault-suite-run SUITE=suite.yaml" >&2; exit 1)
	bash $(FAULT_SCRIPT) suite-run "$(SUITE)"

fault-dashboard-install:
	bash $(FAULT_SCRIPT) dashboard-install

fault-dashboard-port-forward:
	bash $(FAULT_SCRIPT) dashboard-port-forward

fault-cleanup:
	bash $(FAULT_SCRIPT) cleanup
