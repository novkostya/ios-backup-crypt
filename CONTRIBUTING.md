# Contributing

Thanks for your interest. This is a small, focused library, so changes are easiest to
accept when they stay within scope (see the README): decrypting the encrypted iOS backup
format — nothing app-specific.

## Building and testing

The gates run inside pinned toolchain containers, so you need `make` and a container
runtime (nerdctl or docker) with buildkit, but **no local Go toolchain**:

```sh
make gates       # gofmt + go vet + golangci-lint + go test -race
make gates-diff  # differential vs the Python reference (pulls a Python image)
make gates-all   # both — the full ladder CI runs
```

Please make sure `make gates-all` is green before opening a pull request. New behaviour
should come with a test; any new cryptographic constant should be pinned by a
known-answer vector or exercised by the synthetic round-trip and the differential.

## Style

- Keep the public API small, and give every exported symbol a godoc comment.
- Match the surrounding code; `gofmt` is enforced by the gate.
- Avoid new dependencies without a clear reason — cgo-free and dependency-light are goals.

## Security

Please don't file public issues for vulnerabilities — see [`SECURITY.md`](SECURITY.md).
