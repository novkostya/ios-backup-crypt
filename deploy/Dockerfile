# syntax=docker/dockerfile:1
#
# ios-backup-crypt is a pure Go library — no production image ships. This Dockerfile
# exists only to define the pinned Go toolchain container the gate runs inside, so dev
# and CI compile with identical toolchains (mirrors quince, Go-only). All pins arrive
# as build-args from the Makefile, defaulting to versions.env.

ARG GO_IMAGE=golang:1.26.5-alpine3.24
ARG PYTHON_IMAGE=python:3.13-slim

# --- toolchain-go: the main gate container (gofmt + vet + golangci-lint + go test -race) ---
FROM ${GO_IMAGE} AS toolchain-go
ARG GOLANGCI_LINT_VERSION
# git: module fetches. gcc + musl-dev: the race detector needs cgo (CGO_ENABLED=1).
RUN apk add --no-cache git make bash gcc musl-dev
# golangci-lint built WITH this exact Go, so no analyzer/toolchain skew. The v2 module
# path carries the /v2 suffix.
RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v${GOLANGCI_LINT_VERSION}
WORKDIR /src

# --- toolchain-py: the differential-test oracle (ladder rung 3) — the Python reference
#     implementation. Debian slim, so pycryptodome installs from a wheel (no compiler). ---
FROM ${PYTHON_IMAGE} AS toolchain-py
ARG IPHONE_BACKUP_DECRYPT_VERSION
RUN pip install --no-cache-dir "iphone_backup_decrypt==${IPHONE_BACKUP_DECRYPT_VERSION}"
WORKDIR /src
