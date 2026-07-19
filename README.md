# ios-backup-crypt

[![ci](https://github.com/novkostya/ios-backup-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/novkostya/ios-backup-crypt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/novkostya/ios-backup-crypt.svg)](https://pkg.go.dev/github.com/novkostya/ios-backup-crypt)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> A small, dependency-light **Go library for decrypting encrypted iOS local backups**
> (the `idevicebackup2` / Finder backup format, iOS 10.2+). Parses the keybag, derives
> the key from the backup password, decrypts `Manifest.db`, and streams individual files
> out by their original domain + path.

**Status: early implementation.** The keybag parser, two-stage PBKDF2 KDF, and RFC 3394
AES key unwrap are in place and proven against known-answer vectors (milestone 1); the
`Manifest.db` and per-file decrypt paths land next. The plan and full spec live in
[`CLAUDE.md`](CLAUDE.md).

## Build & test

The dev box is a pure container host — no Go toolchain is installed on it. The one gate
runs inside a pinned Go toolchain container (see [`versions.env`](versions.env) and
[`deploy/Dockerfile`](deploy/Dockerfile)):

```sh
make gates   # gofmt -l (empty) + go vet + golangci-lint + go test -race, in-container
```

Requires `make` and a container runtime (nerdctl or docker) with buildkit. CI runs the
same `make gates` from a fresh checkout.

## Why

It's the all-Go decryption engine behind [quince](https://github.com/novkostya/quince),
a self-hosted iPhone/iPad backup manager — replacing a Python dependency with a single,
cross-compilable, streaming library. Useful standalone to anyone who wants to read an
encrypted iOS backup from Go.

## Scope

- Keybag (TLV) parse; two-stage PBKDF2 key derivation; RFC 3394 AES key unwrap.
- `Manifest.db` decryption and `Files`-table reading.
- Per-file NSKeyedArchiver metadata decode + streaming AES-CBC decryption.
- A test-only backup *builder* for self-contained fixtures (no real backup needed to test).

Out of scope: app-domain schema parsing (Messages, Photos, …), any daemon/RPC layer,
unencrypted backups.

## Design notes

- **Streaming**, never buffer-a-whole-file — runs on small-RAM hardware.
- **cgo-free** (`modernc.org/sqlite`) — trivial cross-compilation.
- Correctness proven by known-answer vectors, synthetic round-trips, and differential
  testing against the well-worn Python reference
  ([`iphone_backup_decrypt`](https://github.com/jsharkey13/iphone_backup_decrypt)).

## License

MIT — see [LICENSE](LICENSE).
