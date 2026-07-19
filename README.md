# ios-backup-crypt

[![ci](https://github.com/novkostya/ios-backup-crypt/actions/workflows/ci.yml/badge.svg)](https://github.com/novkostya/ios-backup-crypt/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/novkostya/ios-backup-crypt.svg)](https://pkg.go.dev/github.com/novkostya/ios-backup-crypt)
[![Go version](https://img.shields.io/github/go-mod/go-version/novkostya/ios-backup-crypt)](go.mod)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> A small, dependency-light **Go library for decrypting encrypted iOS local backups**
> — the `idevicebackup2` / Finder (iTunes) backup format, stable since iOS 10.2.

It parses the backup keybag, derives the key from the backup password (the slow
two-stage PBKDF2), unwraps the per-class and per-file keys, decrypts `Manifest.db`, and
streams individual files out by their original domain and path. It is pure Go, cgo-free,
and streams every blob block-at-a-time, so it runs comfortably on small-RAM hardware such
as a NAS.

## Status

**Pre-1.0 — the API may change before the `v0.1` tag.** The full decrypt path is
implemented and works end to end. Correctness is established by:

- **known-answer vectors** — RFC 3394 key unwrap, RFC 6070 / SHA-256 PBKDF2, NIST
  SP 800-38A AES-CBC;
- a **self-contained synthetic round-trip** (a test-only builder writes an encrypted
  backup; the library decrypts it back byte-for-byte, run under `-race`);
- a **differential** against the well-worn Python reference
  [`iphone_backup_decrypt`](https://github.com/jsharkey13/iphone_backup_decrypt): both
  decrypt the same fixture to **byte-identical** output.

It has **not yet been validated against a real device backup** (that step is operator-local
by design, since a real backup is personal data) and has **not been independently
audited**. Use accordingly.

## Install

```sh
go get github.com/novkostya/ios-backup-crypt
```

Requires **Go 1.25+**. No cgo, no system libraries — `go build` cross-compiles cleanly.

## Usage

```go
package main

import (
	"fmt"
	"log"
	"os"

	iosbackup "github.com/novkostya/ios-backup-crypt"
)

func main() {
	// Point at an encrypted backup directory (the folder containing Manifest.plist).
	b, err := iosbackup.Open("/path/to/MobileSync/Backup/<UDID>")
	if err != nil {
		log.Fatal(err)
	}
	defer b.Close()

	// The slow part: derive keys from the backup password and decrypt the index.
	if err := b.Unlock("your-backup-password"); err != nil {
		log.Fatal(err)
	}

	info, err := b.DeviceInfo()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s — iOS %s — %d files\n", info.DeviceName, info.ProductVersion, info.FileCount)

	// Stream the decrypted SMS database straight to a local file.
	out, err := os.Create("sms.db")
	if err != nil {
		log.Fatal(err)
	}
	defer out.Close()

	for entry := range b.List("HomeDomain", "Library/SMS/sms.db") {
		if err := b.DecryptFile(entry.FileID, out); err != nil {
			log.Fatal(err)
		}
	}
	if err := b.Err(); err != nil { // surfaces any error from the List iteration
		log.Fatal(err)
	}
}
```

See the [package documentation](https://pkg.go.dev/github.com/novkostya/ios-backup-crypt)
for the full API (`Open`, `Unlock`, `List`, `Stat`, `DecryptFile`, `DeviceInfo`, `Close`).

**Where do backups live, and how do I make one encrypted?** In Finder (macOS) or iTunes
(Windows), select the device and tick **“Encrypt local backup.”** The backup folder is
`~/Library/Application Support/MobileSync/Backup/<UDID>/` on macOS and
`%APPDATA%\Apple\MobileSync\Backup\<UDID>\` (or `%APPDATA%\Apple Computer\…`) on Windows.
This library handles encrypted backups only.

## What it does

1. Reads `Manifest.plist` → `IsEncrypted`, `BackupKeyBag`, `ManifestKey`.
2. Parses the keybag (TLV) and derives the key-encryption key from the password:
   PBKDF2-SHA256(password, …) → PBKDF2-SHA1(…), then RFC 3394-unwraps the class keys.
3. Unwraps the `ManifestKey`, AES-CBC-decrypts `Manifest.db`, and reads its `Files` table.
4. For each file: decodes the NSKeyedArchiver metadata blob, unwraps the per-file key,
   and streams an AES-CBC decryption of the on-disk blob, truncated to the recorded size.

**Out of scope:** app-domain schema parsing (Messages, Photos, …), any daemon/RPC layer,
and unencrypted backups.

## Development

The gates run inside pinned toolchain containers, so dev and CI compile identically — no
Go toolchain needs to be installed on the host, only `make` and a container runtime
(nerdctl or docker) with buildkit. All version pins live in [`versions.env`](versions.env).

```sh
make gates       # gofmt + go vet + golangci-lint + go test -race   (the Go gate)
make gates-diff  # differential vs the Python reference on a synthetic fixture
make gates-all   # both — what CI runs
```

Correctness is layered as a testing ladder (see [`CLAUDE.md`](CLAUDE.md) for the full
design and algorithm): known-answer vectors → synthetic round-trip → differential vs the
Python reference → (operator-local) real-backup differential.

## Security

This library decrypts iOS backups, which contain highly personal data. It has not been
independently audited and is pre-1.0. See [`SECURITY.md`](SECURITY.md) for the security
model and how to report a vulnerability.

## Acknowledgements

- **[`iphone_backup_decrypt`](https://github.com/jsharkey13/iphone_backup_decrypt)** by
  jsharkey13 (MIT) — the reference implementation this library is modelled on and
  differentially tested against; the source of truth for exact constants and edge cases.
- **[`howett.net/plist`](https://github.com/DHowett/go-plist)** by Dustin L. Howett
  (BSD-2-Clause) — binary property-list decoding.
- **[`modernc.org/sqlite`](https://gitlab.com/cznic/sqlite)** (BSD-3-Clause) — the
  cgo-free SQLite driver that keeps this library cross-compilable.
- The standards it implements: RFC 3394 (AES Key Wrap), RFC 8018 / RFC 6070 (PBKDF2),
  and NIST SP 800-38A (AES-CBC).

Built as the all-Go decryption engine for
[quince](https://github.com/novkostya/quince), a self-hosted iPhone/iPad backup manager,
but useful standalone to anyone reading an encrypted iOS backup from Go.

## License

[MIT](LICENSE) © Konstantin Novikov
