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
tc-go: preflight ## Build the pinned Go toolchain image from deploy/Dockerfile
	$(RUNTIME) build $(BUILD_ARGS) --target toolchain-go -t $(TC_GO) -f deploy/Dockerfile .

.PHONY: gates
gates: tc-go ## Run the gate: gofmt -l (empty) + go vet + golangci-lint + go test -race
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local $(TC_GO) sh -euc '\
	    unformatted=$$(gofmt -l .); \
	    if [ -n "$$unformatted" ]; then echo "gofmt needs to run on:"; echo "$$unformatted"; exit 1; fi; \
	    go vet ./...; \
	    golangci-lint run; \
	    go test -race ./...'

.PHONY: gates-all
gates-all: gates gates-diff ## The full ladder: the Go gate + the differential (rung 3)

.PHONY: tc-py
tc-py: preflight ## Build the Python reference (differential oracle) image
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

.PHONY: test
test: tc-go ## Just the tests (go test -race), no lint — for a fast inner loop
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e CGO_ENABLED=1 -e GOTOOLCHAIN=local $(TC_GO) sh -euc 'go test -race ./...'

.PHONY: tidy
tidy: tc-go ## Run `go mod tidy` inside the toolchain container
	$(RUN) -w /src \
	  -v $(GO_BUILD_VOL):/root/.cache/go-build -v $(GO_MOD_VOL):/go/pkg/mod \
	  -e GOTOOLCHAIN=local $(TC_GO) sh -euc 'go mod tidy'

.PHONY: clean
clean: ## Drop cache volumes and the locally-built toolchain images
	-rm -rf $(ROOT)/.difftmp
	-$(RUNTIME) volume rm $(GO_BUILD_VOL) $(GO_MOD_VOL)
	-$(RUNTIME) rmi $(TC_GO) $(TC_PY)
