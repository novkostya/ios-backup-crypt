// The fixture generator is its OWN MODULE, and that is the whole point of it being here
// rather than in the root one — Operator ruling, 2026-08-20 (quince#1349).
//
// Making it importable is what a consumer needs: a real encrypted backup is personal data
// that must never enter a CI run, so somebody testing their own code against real
// encrypted-backup structure has no other source. Making it a SEPARATE MODULE is what
// keeps that from costing anything: `github.com/novkostya/ios-backup-crypt` gains no
// exported identifier, so CONTRIBUTING's "keep the public API small" holds literally
// rather than by argument, and this module's stability promise is its own.
//
// It reaches the root module's internal/ packages, which is legal and was MEASURED rather
// than assumed: Go's internal rule is a path-prefix rule, not a module boundary — a
// package under `<root>/fixture` is inside the tree rooted at `<root>`. Verified with a
// control (a nonexistent internal import fails; this one type-checks under `go vet`).
module github.com/novkostya/ios-backup-crypt/fixture

go 1.25.0

require (
	github.com/novkostya/ios-backup-crypt v0.1.1
	howett.net/plist v1.0.1
	modernc.org/sqlite v1.54.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.46.0 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

// The two modules depend on each other by design and both directions are real: this one
// needs the root's AES-CBC and AES-KW helpers, and the root's tests need this one to build
// the backups they decrypt. Resolved locally by replace on both sides rather than by
// duplicating the crypto, which would let an encrypt path and a decrypt path drift apart —
// the one thing a round-trip test exists to prevent.
replace github.com/novkostya/ios-backup-crypt => ../
