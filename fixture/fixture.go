// Package fixture builds a synthetic *encrypted* iOS backup on disk — a valid keybag, a
// wrapped Manifest key, an AES-CBC-encrypted Manifest.db and a binary Manifest.plist —
// so that code which reads encrypted backups can be tested without one.
//
// WHY IT EXISTS AS A PUBLIC THING AT ALL. A real encrypted backup is somebody's personal
// data and must never enter a CI run. This library already makes that argument for itself:
// its real-backup differential is operator-local by design. A consumer has the same problem
// and no way to solve it, because an encrypt path is the only thing that produces a backup
// a decrypt path can read.
//
// IT IS A SEPARATE MODULE, so `github.com/novkostya/ios-backup-crypt` gains no exported
// identifier and CONTRIBUTING's "keep the public API small" holds literally rather than by
// argument. Importing this is opt-in; a consumer that only decrypts never sees it.
//
// IT IS A WRAPPER, NOT THE IMPLEMENTATION, and that is load-bearing rather than tidy. The
// generator stays at internal/builder in the root module, so the dependency runs ONE WAY:
// fixture → root. Moving it here instead would force the root's own tests to require this
// module back, and a `replace` covers that only in the main module — a consumer would
// inherit a `require` on a version that does not exist. See internal/builder's doc for the
// measurement.
//
// IT IS TEST SUPPORT, NOT A BACKUP WRITER. It builds inputs for tests: small files, small
// KDF work factors, one protection class. It is not a tool for producing a backup anything
// should restore from, and its stability promise is its own rather than the decryption
// API's.
package fixture

import "github.com/novkostya/ios-backup-crypt/internal/builder"

// DefaultPassword is used when Spec.Password is empty.
const DefaultPassword = builder.DefaultPassword

// The exported surface is ALIASES rather than new types, so a value built here is the same
// value the implementation uses — no conversion, no shadow struct to keep in step, and a
// field added to the generator appears here without a second edit that could be forgotten.
//
// THAT HELD FOR THE FIELD AND NOT FOR ITS TYPE, WHICH IS THE EDIT THAT WAS FORGOTTEN (#18).
// v0.2.0 shipped Spec.Status and Spec.Info as fields whose types had no alias here, so a
// consumer could not construct either — and Spec.Info, being a pointer, could not even be
// allocated. Nothing in this repository noticed: the root module reaches internal/builder
// directly and this module builds under a `replace`, so the consumer view was compiled
// nowhere. TestEveryTypeSpecNeedsIsNameableByAConsumer is now that compile, and a new field
// of an unexported type fails there rather than in somebody else's repository.
type (
	// File is one row to place in the fixture's Files table.
	File = builder.File
	// Spec describes the synthetic backup to build.
	Spec = builder.Spec
	// WrittenFile records a row placed in the Files table, including its computed fileID.
	WrittenFile = builder.WrittenFile
	// StatusInfo describes the Status.plist to generate. Zero writes no file.
	StatusInfo = builder.StatusInfo
	// DeviceExtras describes the Info.plist to generate. Nil writes no file.
	DeviceExtras = builder.DeviceExtras
	// Result reports what Build wrote.
	Result = builder.Result
)

// Build writes Manifest.plist and a Manifest.db into dir, plus one on-disk blob per file
// with content. It returns the password the backup was built with and the rows it placed,
// each with the fileID that addresses it.
//
// Set Spec.Unencrypted for a backup with no encryption anywhere — plain SQLite index,
// plaintext blobs, IsEncrypted false, and an empty Result.Password because there is nothing
// to unlock. The file records are identical either way, which is what makes this the right
// place to build one: a consumer needing an unencrypted fixture would otherwise write
// NSKeyedArchiver MBFile records itself.
func Build(dir string, spec Spec) (*Result, error) { return builder.Build(dir, spec) }
