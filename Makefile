SHELL := /bin/bash

SCENARIO ?=
FAULT_SCRIPT := $(CURDIR)/scripts/fault-test.sh

.PHONY: check fmt fmt-check clippy test fault-check fault-list fault-preflight fault-run fault-run-dm fault-cleanup

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
	$(FAULT_SCRIPT) list

fault-preflight:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-preflight SCENARIO=io-eio" >&2; exit 1)
	$(FAULT_SCRIPT) preflight "$(SCENARIO)"

fault-run:
	@test -n "$(SCENARIO)" || (echo "SCENARIO is required, for example: make fault-run SCENARIO=io-eio" >&2; exit 1)
	$(FAULT_SCRIPT) run "$(SCENARIO)"

fault-run-dm:
	$(FAULT_SCRIPT) run dm-flakey

fault-cleanup:
	$(FAULT_SCRIPT) cleanup
