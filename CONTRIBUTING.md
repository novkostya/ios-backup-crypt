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

### Real-backup differential (operator-local)

The final rung of the testing ladder byte-compares this library against the Python
reference on a **real** encrypted backup. It is **operator-local by design** — a real
backup is personal data, so it never runs in CI and nothing about it (path, password, or
decrypted output) is committed. The harness is generic and reads everything from the
environment; the backup directory is bind-mounted read-only.

```sh
export IOSBACKUP_REAL_PASSWORD='the-backup-password'   # exported, never on the command line
make gates-real IOSBACKUP_REAL_DIR=/path/to/backup/<UDID>
```

It decrypts the real `Manifest.db` and a spread sample of files with both this library
and the reference and asserts they are byte-identical. To decrypt a backup to a logical
`<domain>/<relativePath>` tree (e.g. as input for a downstream parser), use
`make extract-real` — mind the disk space, and set `IOSBACKUP_EXTRACT_MAXBYTES` to skip
large media:

```sh
make extract-real IOSBACKUP_REAL_DIR=/path/to/backup/<UDID> \
     EXTRACT_OUT=/somewhere/with/room IOSBACKUP_EXTRACT_MAXBYTES=52428800
```

To decrypt every file but write nothing — a full-backup decrypt check that reports the
tally (extracted / incomplete / errored) without touching the disk — use `make verify-real`:

```sh
make verify-real IOSBACKUP_REAL_DIR=/path/to/backup/<UDID>
```

## Style

- Keep the public API small, and give every exported symbol a godoc comment.
- Match the surrounding code; `gofmt` is enforced by the gate.
- Avoid new dependencies without a clear reason — cgo-free and dependency-light are goals.

## Security

Please don't file public issues for vulnerabilities — see [`SECURITY.md`](SECURITY.md).
