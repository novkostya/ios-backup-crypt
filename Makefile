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

# Locally-built toolchain image (== the deploy/Dockerfile toolchain-go stage).
TC_GO := ios-backup-crypt-toolchain-go:$(IMAGE_TAG)

# Build-args threaded into the image build so the Dockerfile and the gate agree on pins.
BUILD_ARGS := \
	--build-arg GO_IMAGE=$(GO_IMAGE) \
	--build-arg GOLANGCI_LINT_VERSION=$(GOLANGCI_LINT_VERSION)

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
clean: ## Drop cache volumes and the locally-built toolchain image
	-$(RUNTIME) volume rm $(GO_BUILD_VOL) $(GO_MOD_VOL)
	-$(RUNTIME) rmi $(TC_GO)
