# ios-backup-crypt — the one entrypoint. CI calls only these targets (no logic in YAML).
#
# The dev host is a PURE CONTAINER HOST: no Go toolchain is installed on it. The gate
# runs inside a pinned Go toolchain container built from deploy/Dockerfile, so dev and
# CI compile with identical toolchains. All version + image pins live in versions.env
# (the single source of truth). Mirrors quince's Makefile — Go-only, so far simpler:
# one toolchain, one gate, no Node/Python/Rust.
#
# Requirements on the box: `make` + a container runtime (nerdctl or docker) with buildkit.

include versions.env

ROOT       := $(abspath .)
RUNTIME    ?= $(shell command -v nerdctl 2>/dev/null || command -v docker 2>/dev/null)
IMAGE_TAG  ?= local

# Named cache volumes — persistent across runs, safe to lose (they live on disposable
# runtime storage). They are what keep the containerized gate fast.
GO_BUILD_VOL := ios-backup-crypt-go-build
GO_MOD_VOL   := ios-backup-crypt-go-mod

# Locally-built toolchain images (== the deploy/Dockerfile stages).
TC_GO := ios-backup-crypt-toolchain-go:$(IMAGE_TAG)
TC_PY := ios-backup-crypt-toolchain-py:$(IMAGE_TAG)

# Build-args threaded into the image build so the Dockerfile and the gate agree on pins.
BUILD_ARGS := \
	--build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION)

PY_BUILD_ARGS := \
	--build-arg PYTHON_IMAGE=$(PYTHON_IMAGE) \
	--build-arg IPHONE_BACKUP_DECRYPT_VERSION=$(IPHONE_BACKUP_DECRYPT_VERSION)

# `RUN`: repo bind-mounted at /src.
RUN := $(RUNTIME) run --rm -v $(ROOT):/src

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@echo "ios-backup-crypt gate (runs in a pinned Go toolchain container via $(RUNTIME)):"
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
	@echo "Runtime detected: $(RUNTIME)"

.PHONY: preflight
preflight:
	@test -n "$(RUNTIME)" || { echo "ERROR: no container runtime (nerdctl/docker) found. This box must be a container host."; exit 1; }

.PHONY: tc-go
tc-go: preflight ## Ensure the Go toolchain image exists (builds only if missing — see tc-go-force)
	@$(RUNTIME) image inspect $(TC_GO) >/dev/null 2>&1 || $(MAKE) --no-print-directory tc-go-force

.PHONY: tc-go-force
tc-go-force: preflight ## Rebuild the Go toolchain image (run after a versions.env / Dockerfile change)
	$(RUNTIME) build $(BUILD_ARGS) --target toolchain-go -t $(TC_GO) -f deploy/Dockerfile .

# EVERY MODULE IN THIS REPOSITORY, and the one list that says so.
#
# `./...` STOPS AT A MODULE BOUNDARY. `fixture/` is a separate module with its own `go.mod`, so
# a root-level `go test ./...` / `go vet ./...` / `go mod tidy` sees none of it — and reports
# success, because there is nothing wrong with what it did look at. `gofmt -l .` is the odd one
# out: it walks DIRECTORIES rather than modules, so it recurses the whole tree regardless. That
# asymmetry is what makes this easy to get wrong — one check keeps working while the others
# quietly narrow.
#
# A VARIABLE RATHER THAN THE LIST REPEATED IN EACH TARGET. It was written out once, in `gates`,
# and the two targets that did not have it were both wrong: `test` ran the root module only
# (#20), and `tidy` tidied the root `go.mod` only — which is how `fixture/go.mod` came to
# require a root version two releases behind its own code, the defect `#17` fixed and
# `fixture/v0.1.0` had already shipped once. Adding a third module should cost one edit here.
MODULES = . ./fixture

.PHONY: gates
gates: tc-go ## Run the gate: gofmt -l (empty) + go vet + golangci-lint + go test -race
# The module loop is MODULES, above — `./...` would see the root module only. `golangci-lint`
# is per-module too and is inside the loop for that reason.
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local $(TC_GO) sh -euc '\
	    unformatted=$$(gofmt -l .); \
	    if [ -n "$$unformatted" ]; then echo "gofmt needs to run on:"; echo "$$unformatted"; exit 1; fi; \
	    for mod in $(MODULES); do \
	      echo "=== module $$mod ==="; \
	      ( cd "$$mod" && go vet ./... && golangci-lint run && go test -race ./... ); \
	    done'

.PHONY: gates-all
gates-all: gates gates-diff ## The full ladder: the Go gate + the differential (rung 3)

.PHONY: tc-py
tc-py: preflight ## Ensure the Python oracle image exists (builds only if missing — see tc-py-force)
	@$(RUNTIME) image inspect $(TC_PY) >/dev/null 2>&1 || $(MAKE) --no-print-directory tc-py-force

.PHONY: tc-py-force
tc-py-force: preflight ## Rebuild the Python reference (differential oracle) image
	$(RUNTIME) build $(PY_BUILD_ARGS) --target toolchain-py -t $(TC_PY) -f deploy/Dockerfile .

.PHONY: gates-diff
gates-diff: tc-go tc-py ## Differential: Go and the Python reference decrypt one synthetic fixture, byte-compared (rung 3)
	# The fixture is written by container-root and includes 0700 dirs, so ALL .difftmp
	# creation/removal happens in-container — a non-root CI host can't rm root-owned files.
	# Clear any stale scratch from a previous failed run.
	$(RUN) $(TC_GO) rm -rf /src/.difftmp
	# 1) Go: build a synthetic backup, decrypt it, emit outputs + index into .difftmp.
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local -e DIFF_OUT=/src/.difftmp $(TC_GO) \
	  sh -euc 'go test -count=1 -run TestWriteDifferentialFixture ./'
	# 2) Python: decrypt the SAME fixture with the reference and byte-compare.
	$(RUN) -w /src $(TC_PY) python deploy/differential.py /src/.difftmp
	# 3) Clean up in-container (files are container-root-owned).
	$(RUN) $(TC_GO) rm -rf /src/.difftmp

# ---------------------------------------------------------------------------
# OPERATOR-LOCAL real-backup targets (testing-ladder rung 4). NEVER in CI: they read a
# real backup + password from the environment, and touch real personal data. Nothing
# here is committed — the harness is generic; the path, password, and decrypted output
# stay on the operator's machine. See CONTRIBUTING.md.
#
#   IOSBACKUP_REAL_DIR       host path to the backup directory (bind-mounted read-only)
#   IOSBACKUP_REAL_PASSWORD  the backup password (exported; forwarded, never on argv)
# ---------------------------------------------------------------------------
.PHONY: gates-real
gates-real: tc-go tc-py ## Real-backup differential vs the Python reference (operator-local; needs IOSBACKUP_REAL_DIR + exported IOSBACKUP_REAL_PASSWORD)
	@test -n "$(IOSBACKUP_REAL_DIR)" || { echo "set IOSBACKUP_REAL_DIR=<backup dir> and export IOSBACKUP_REAL_PASSWORD"; exit 1; }
	$(RUN) $(TC_GO) rm -rf /src/.realtmp
	# 1) Go: decrypt the real Manifest.db + a spread sample of files.
	$(RUN) -w /src -v "$(IOSBACKUP_REAL_DIR):/backup:ro" \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local -e REAL_BACKUP=/backup -e DIFF_OUT=/src/.realtmp -e IOSBACKUP_REAL_PASSWORD \
	  $(TC_GO) sh -euc 'go test -v -count=1 -timeout 600s -run TestRealBackupDifferential ./'
	# 2) Python reference: decrypt the SAME real backup and byte-compare (password from env).
	$(RUN) -w /src -v "$(IOSBACKUP_REAL_DIR):/backup:ro" -e IOSBACKUP_REAL_PASSWORD \
	  $(TC_PY) python deploy/differential.py /src/.realtmp --backup /backup --password-env IOSBACKUP_REAL_PASSWORD
	$(RUN) $(TC_GO) rm -rf /src/.realtmp

.PHONY: extract-real
extract-real: tc-go ## Decrypt a real backup to a logical <domain>/<path> tree at EXTRACT_OUT (operator-local; real personal data — keep it local)
	@test -n "$(IOSBACKUP_REAL_DIR)" || { echo "set IOSBACKUP_REAL_DIR=<backup dir> and export IOSBACKUP_REAL_PASSWORD"; exit 1; }
	@test -n "$(EXTRACT_OUT)" || { echo "set EXTRACT_OUT=<host dir for the decrypted tree> (needs room for the backup; use IOSBACKUP_EXTRACT_MAXBYTES to skip large media)"; exit 1; }
	$(RUN) -w /src -v "$(IOSBACKUP_REAL_DIR):/backup:ro" -v "$(EXTRACT_OUT):/out" \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local -e REAL_BACKUP=/backup -e IOSBACKUP_EXTRACT_OUT=/out \
	  -e IOSBACKUP_REAL_PASSWORD -e IOSBACKUP_EXTRACT_MAXBYTES \
	  $(TC_GO) sh -euc 'go test -v -count=1 -timeout 0 -run TestRealBackupExtractAll ./'

.PHONY: diagnose-real
diagnose-real: tc-go ## Explain why specific files are missing from an extract (operator-local)
	@test -n "$(IOSBACKUP_REAL_DIR)" || { echo "set IOSBACKUP_REAL_DIR=<backup dir> and export IOSBACKUP_REAL_PASSWORD"; exit 1; }
	$(RUN) -w /src -v "$(IOSBACKUP_REAL_DIR):/backup:ro" \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local -e REAL_BACKUP=/backup -e IOSBACKUP_DIAGNOSE=1 -e IOSBACKUP_REAL_PASSWORD \
	  $(TC_GO) sh -euc 'go test -v -count=1 -timeout 900s -run TestRealBackupDiagnose ./'

.PHONY: verify-real
verify-real: tc-go ## Decrypt every file to /dev/null — full decrypt + tally with NO disk writes (operator-local)
	@test -n "$(IOSBACKUP_REAL_DIR)" || { echo "set IOSBACKUP_REAL_DIR=<backup dir> and export IOSBACKUP_REAL_PASSWORD"; exit 1; }
	$(RUN) -w /src -v "$(IOSBACKUP_REAL_DIR):/backup:ro" \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local -e REAL_BACKUP=/backup -e IOSBACKUP_EXTRACT_OUT=/dev/null \
	  -e IOSBACKUP_REAL_PASSWORD -e IOSBACKUP_EXTRACT_MAXBYTES \
	  $(TC_GO) sh -euc 'go test -v -count=1 -timeout 0 -run TestRealBackupExtractAll ./'

.PHONY: test
test: tc-go ## Just the tests (go test -race) in EVERY module, no lint — for a fast inner loop
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local $(TC_GO) sh -euc '\
	    for mod in $(MODULES); do \
	      echo "=== module $$mod ==="; \
	      ( cd "$$mod" && go test -race ./... ); \
	    done'

.PHONY: tidy
tidy: tc-go ## Run `go mod tidy` in EVERY module, inside the toolchain container
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e GOTOOLCHAIN=local $(TC_GO) sh -euc '\
	    for mod in $(MODULES); do \
	      echo "=== module $$mod ==="; \
	      ( cd "$$mod" && go mod tidy ); \
	    done'

.PHONY: clean
clean: ## Drop cache volumes and the locally-built toolchain images
	-rm -rf $(ROOT)/.difftmp
	-$(RUNTIME) volume rm $(GO_BUILD_VOL) $(GO_MOD_VOL)
	-$(RUNTIME) rmi $(TC_GO) $(TC_PY)
