// The fixture generator ships as its OWN MODULE — Operator ruling, 2026-08-20
// (quince#1349) — so that `github.com/novkostya/ios-backup-crypt` gains no exported
// identifier and CONTRIBUTING's "keep the public API small" holds literally rather than by
// argument. Importing this is opt-in, and this module's stability promise is its own.
//
// THE DEPENDENCY RUNS ONE WAY: this module needs the root's generator, and the root needs
// nothing from here. That asymmetry is why internal/builder stays where it is and this
// package only wraps it. Moving the generator here would make the root's own tests require
// this module back, and a `replace` covers that in the MAIN MODULE ONLY — a consumer would
// inherit a `require` on a version that does not exist.
//
// Measured rather than reasoned, in a scratch consumer of the root module:
//   go build ./...    → succeeds (graph pruning; it imports nothing from fixture)
//   go list -m all    → github.com/novkostya/ios-backup-crypt/fixture@v0.0.0:
//                       invalid version: unknown revision fixture/v0.0.0
// So the breakage hides from the command people run and appears in the ones tooling runs.
//
// It reaches the root's internal/ packages, which is legal and was also measured: Go's
// internal rule is a path-prefix rule, not a module boundary, so a package under
// <root>/fixture is inside the tree rooted at <root>. Verified with a control — a
// nonexistent internal import fails, this one type-checks under `go vet`.
module github.com/novkostya/ios-backup-crypt/fixture

go 1.25.0

require github.com/novkostya/ios-backup-crypt v0.1.1

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/sys v0.46.0 // indirect
	howett.net/plist v1.0.1 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.54.0 // indirect
)

replace github.com/novkostya/ios-backup-crypt => ../
