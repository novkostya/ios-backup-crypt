# ios-backup-crypt — implementer charter & entry point

A **pure Go library** that decrypts encrypted iOS local backups (the `idevicebackup2` /
Finder format). Standalone, public, MIT. This file is the whole spec — there is no
`docs/` yet; milestone 0 may add one if it earns its keep.

## Why this exists

It is the future decryption engine for **quince** (`github.com/novkostya/quince`), a
self-hosted iPhone/iPad backup manager. quince currently shells out to the Python
`iphone_backup_decrypt`; this library is its all-Go replacement. **The two projects are
decoupled by design** — quince consumes this only through its own vault RPC + conformance
suite, so nothing here needs to know quince exists. Build the best small crypto library
you can; quince adopts it when it passes quince's bar.

Reference implementation to study and match: **`github.com/jsharkey13/iphone_backup_decrypt`**
(Python, MIT, ~small, format-stable since iOS 10.2). It is the source of truth for exact
constants, tag names, and edge cases — **read it; do not trust this charter's crypto
details over the reference.**

## Scope

### Decrypt path (the library)

The algorithm, in order (verify every constant/tag against the reference source):

1. **`Manifest.plist`** (backup root, binary plist) → `IsEncrypted`, `BackupKeyBag`
   (keybag blob), `ManifestKey` (4-byte class + wrapped key).
2. **Keybag parse** — TLV format (4-char tag, 4-byte big-endian length, value):
   header (VERS/TYPE/UUID/HMCK/WRAP/SALT/ITER + double-protection DPWT/DPIC/DPSL) and
   per-class entries (UUID/CLAS/WRAP/WPKY/KTYP …).
3. **Key derivation** password → KEK (the two-stage KDF that makes this slow):
   PBKDF2-**SHA256**(password, DPSL, DPIC ≈ 10,000,000) → PBKDF2-**SHA1**(that, SALT,
   ITER ≈ 10,000).
4. **Unwrap class keys** — RFC 3394 AES key unwrap (AES-KW) of each WPKY with the KEK.
5. **ManifestKey** → unwrap with its class key → the Manifest.db AES key.
6. **Manifest.db** — AES-CBC decrypt the SQLite file; open it (read-only).
7. **`Files` table** — rows: `fileID` (SHA1 = on-disk name), `domain`, `relativePath`,
   `flags`, `file` (NSKeyedArchiver blob). On disk the blob lives at
   `<backup>/<fileID[:2]>/<fileID>`.
8. **Per-file** — decode the `file` NSKeyedArchiver blob → `EncryptionKey` (class +
   wrapped) + `Size` + protection class; unwrap the file key; AES-CBC decrypt the
   on-disk blob; **truncate to `Size`** (strip CBC block padding).

**API shape — make it map 1:1 onto quince's vault RPC** (so the eventual thin RPC binary
is trivial). Sketch, refine as you build:

```go
type Backup struct { /* ... */ }
func Open(backupDir string) (*Backup, error)      // reads Manifest.plist + keybag
func (b *Backup) Unlock(password string) error    // KDF + unwrap + decrypt Manifest.db
func (b *Backup) List(domain, prefix string) iter.Seq[FileEntry]   // lazy
func (b *Backup) Stat(fileID string) (FileEntry, error)
func (b *Backup) DecryptFile(fileID string, w io.Writer) error     // STREAMING, not buffered
func (b *Backup) DeviceInfo() (Info, error)       // name, iOS version, file count
```

**Streaming is mandatory** (`io.Writer`/`io.Reader`, block-at-a-time AES-CBC) — the
consumer runs on small-RAM NAS boxes and must never buffer a multi-GB file. Never
`ReadFile` a backup blob whole.

### Encrypt/builder path (test-only)

Behind a build tag or a `builder` subpackage: construct a **tiny synthetic encrypted
backup** with a known password (`test`) — a valid keybag, a Manifest.db with a handful of
Files rows, and a few encrypted blobs. This is the round-trip test oracle AND the
self-contained fixture generator both this repo and quince (its qn.8 rung) need. It never
ships in the library's public API surface.

### Out of scope

Domain parsing (Messages/Photos/sms.db schemas — that's quince's job), any network/RPC/
daemon code (quince wraps this), unencrypted backups (encryption is required upstream).

## Go primitives (look up current versions — do not hardcode from memory)

- **PBKDF2**: stdlib `crypto/pbkdf2` (Go 1.24+); else `golang.org/x/crypto/pbkdf2`.
- **AES-CBC / AES-ECB**: stdlib `crypto/aes` + `crypto/cipher`.
- **RFC 3394 AES key unwrap**: not in stdlib — implement (~40 lines) and prove it with
  the RFC 3394 §4 official test vectors before anything else depends on it.
- **Binary plist**: `howett.net/plist` (decode the plist tree; walk the NSKeyedArchiver
  `$objects`/`$top` graph yourself).
- **SQLite**: `modernc.org/sqlite` (cgo-free — matches quince; keeps this cross-compilable).

## Testing ladder (each rung gates in CI)

1. **Known-answer vectors** — RFC 3394 unwrap + PBKDF2 (SHA256/SHA1) against official
   test vectors. No backup needed; pure math correctness.
2. **Synthetic round-trip** — builder makes a backup, library decrypts it, assert
   byte-identity of every file and Manifest row. Fully self-contained; the CI backbone.
3. **Differential vs the Python reference** — same synthetic fixture through
   `iphone_backup_decrypt`; byte-compare decrypted Manifest.db + sample files. Catches
   any constant you got subtly wrong.
4. **Real-backup differential** — the same byte-compare against a *real* encrypted
   backup. **Operator-local only, NEVER in CI or committed** (a real backup is personal
   data). Gate it behind an env var pointing at a local path; document how to run it.

## House rules (inherited from quince)

- **Version pins are looked up, never remembered.** LLM training data is stale; query
  the live source (pkg.go.dev, releases, image tags) at pin time, prefer newest stable
  with support runway, comment any deviation. (quince pins Go 1.26.x, golangci-lint
  2.12.x, Alpine 3.24 — verify these are still current when you scaffold.)
- **Pure container host / containerized gates.** No Go toolchain installed on the dev
  box. `make gates` runs inside a pinned Go toolchain container via a nerdctl/docker
  autodetect wrapper (mirror quince's Makefile, Go-only — far simpler: one toolchain,
  no Node/Python/Rust). Runs fine in quince's existing `quince-dev` LXC.
- **Public + MIT** from commit one (LICENSE is in place). This is a library others may
  vendor — clean godoc, semver tags, no breaking churn after v0.1.
- **No personal/infra facts** ever (there should be none in a pure library anyway — keep
  it that way; the real-backup path stays env-driven and undocumented as to location).
- **Prove by running**, not by reading: a KDF is "correct" when its vector test passes,
  not when the code looks right.

## Milestones

0. **Scaffold**: `go.mod` (`github.com/novkostya/ios-backup-crypt`, package e.g.
   `iosbackup`), Makefile (containerized `gates`: `gofmt -l` empty + `go vet` +
   `golangci-lint` + `go test -race ./...`), `versions.env`, `.gitignore`, GitHub
   Actions CI running `make gates`, a stub README build badge. `git init`, first commit
   (commit when the Operator asks).
1. **Keybag + KDF + unwrap** green on RFC 3394 + PBKDF2 vectors (ladder rung 1).
2. **Manifest.db decrypts** on a synthetic backup; Files table reads.
3. **Full per-file decrypt + streaming**, synthetic round-trip green in CI (rung 2).
4. **Differential vs Python** green in CI on the synthetic fixture (rung 3); measure the
   10M-round unlock time and record it (must fit a ~30 s budget on modest hardware).
5. **Real-backup differential** passes locally (rung 4) → **tag v0.1**. Only then may
   quince begin its Go-vault flip.

## Kickoff

New session in this directory → *"Read CLAUDE.md. Do milestone 0 (scaffold), then
milestone 1."* One milestone per session; prove each with `make gates` + the rung's
vector/round-trip tests before moving on.
