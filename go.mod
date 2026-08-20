module github.com/novkostya/ios-backup-crypt

// Minimum Go for consumers. 1.25 is the true floor: modernc.org/sqlite requires it, and
// this library only uses features available by 1.24 (crypto/pbkdf2, iter). The gates
// build with a newer pinned toolchain (see versions.env), but consumers need only 1.25+.
go 1.25.0

require (
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

// The fixture generator is a separate module in this repository (see fixture/go.mod). The
// root's own tests use it to build the backups they decrypt, so the dependency runs both
// ways and both directions are resolved by replace.
require github.com/novkostya/ios-backup-crypt/fixture v0.0.0

replace github.com/novkostya/ios-backup-crypt/fixture => ./fixture
