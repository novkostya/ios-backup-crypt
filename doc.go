// Package iosbackup decrypts encrypted iOS local backups — the idevicebackup2 /
// Finder backup format (stable since iOS 10.2).
//
// It is a pure-Go, dependency-light, streaming decryption engine: it parses the
// backup keybag, derives the key-encryption key from the backup password (the slow
// two-stage PBKDF2), unwraps the per-class and per-file keys, decrypts Manifest.db,
// and streams individual files out by their original domain and relative path.
//
// The eventual public API (built out across milestones) maps 1:1 onto a vault RPC:
//
//	func Open(backupDir string) (*Backup, error)   // reads Manifest.plist + keybag
//	func (b *Backup) Unlock(password string) error // KDF + unwrap + decrypt Manifest.db
//	func (b *Backup) List(domain, prefix string) iter.Seq[FileEntry]
//	func (b *Backup) Stat(fileID string) (FileEntry, error)
//	func (b *Backup) DecryptFile(fileID string, w io.Writer) error // streaming
//	func (b *Backup) DeviceInfo() (Info, error)
//
// Decryption is always streaming (block-at-a-time AES-CBC): a backup blob is never
// read whole into memory, so the library runs on small-RAM hardware.
//
// The cryptographic primitives live in internal packages, each proven against
// known-answer vectors before anything depends on it:
//
//   - internal/aeskw — RFC 3394 AES key wrap/unwrap (RFC 3394 §4 vectors).
//   - internal/aescbc — streaming AES-CBC (NIST SP 800-38A vector).
//   - internal/keybag — keybag TLV parse + two-stage PBKDF2 KDF (RFC 6070 + SHA-256
//     vectors) + class-key unwrap.
//
// This is the all-Go decryption engine behind quince
// (github.com/novkostya/quince); it is standalone and useful to anyone reading an
// encrypted iOS backup from Go.
package iosbackup
