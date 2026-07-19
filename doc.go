// Package iosbackup decrypts encrypted iOS local backups — the idevicebackup2 / Finder
// (iTunes) backup format, stable since iOS 10.2.
//
// It parses the backup keybag, derives the key-encryption key from the backup password
// (a deliberately slow two-stage PBKDF2), unwraps the per-class and per-file keys,
// decrypts Manifest.db, and streams individual files out by their original domain and
// relative path. It is pure Go and cgo-free, and it decrypts block-at-a-time, so a
// multi-gigabyte file is never buffered whole — it runs on small-RAM hardware.
//
// The typical flow is Open, then Unlock, then read:
//
//	b, err := iosbackup.Open(dir)        // reads Manifest.plist + keybag
//	// ...
//	err = b.Unlock(password)             // KDF + unwrap + decrypt Manifest.db
//	for e := range b.List(domain, prefix) {
//		// ...
//	}
//	err = b.DecryptFile(fileID, w)       // streaming
//	b.Close()
//
// See the package Example for a complete program. This library handles encrypted backups
// only; app-domain schema parsing (Messages, Photos, …) is out of scope. A Backup value
// is not safe for concurrent use.
package iosbackup
