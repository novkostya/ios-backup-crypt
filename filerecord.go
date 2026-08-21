package iosbackup

import (
	"fmt"
	"time"

	"howett.net/plist"
)

// fileRecord is the decrypt-relevant subset of a Files.file NSKeyedArchiver blob, plus the
// two metadata fields a caller needs to describe a file without decrypting it.
type fileRecord struct {
	size            int64
	mtime           time.Time // zero when the record carries no LastModified — see below
	protectionClass uint32
	encryptionKey   []byte // 40-byte wrapped key (class prefix stripped); nil if none
}

// decodeFileRecord walks the NSKeyedArchiver graph in a Files.file blob. The graph is a
// binary plist with a flat $objects array; $top.root is a UID indexing the root MBFile
// object. The MBFile carries Size and ProtectionClass as plain integers and
// EncryptionKey as a UID pointing at an NSMutableData object whose NS.data is the wrapped
// file key prefixed with a 4-byte protection class (which we strip, matching the
// reference).
func decodeFileRecord(blob []byte) (fileRecord, error) {
	var root map[string]any
	if _, err := plist.Unmarshal(blob, &root); err != nil {
		return fileRecord{}, fmt.Errorf("iosbackup: parse file record: %w", err)
	}

	objects, ok := root["$objects"].([]any)
	if !ok {
		return fileRecord{}, fmt.Errorf("iosbackup: file record missing $objects array")
	}
	top, ok := root["$top"].(map[string]any)
	if !ok {
		return fileRecord{}, fmt.Errorf("iosbackup: file record missing $top")
	}
	rootIdx, ok := asUID(top["root"])
	if !ok || rootIdx >= uint64(len(objects)) {
		return fileRecord{}, fmt.Errorf("iosbackup: file record has invalid root reference")
	}
	mb, ok := objects[rootIdx].(map[string]any)
	if !ok {
		return fileRecord{}, fmt.Errorf("iosbackup: file record root is not an object")
	}

	var rec fileRecord
	size, ok := asInt64(mb["Size"])
	if !ok {
		return fileRecord{}, fmt.Errorf("iosbackup: file record missing Size")
	}
	rec.size = size

	// LastModified is a Unix timestamp in seconds, and it is OPTIONAL. The reference
	// implementation reads it with a plain `.get()` and guards every use with
	// `if file_plist.mtime:` — so a record without one is ordinary, not corrupt, and a
	// missing timestamp must never fail a decode that is otherwise fine. Callers get the
	// zero Time and can tell the difference with IsZero.
	if ms, ok := asInt64(mb["LastModified"]); ok {
		rec.mtime = time.Unix(ms, 0).UTC()
	}
	if pc, ok := asInt64(mb["ProtectionClass"]); ok {
		rec.protectionClass = uint32(pc)
	}

	// EncryptionKey is absent for directories and symlinks.
	if ekRef, present := mb["EncryptionKey"]; present {
		ekIdx, ok := asUID(ekRef)
		if !ok || ekIdx >= uint64(len(objects)) {
			return fileRecord{}, fmt.Errorf("iosbackup: file record has invalid EncryptionKey reference")
		}
		ekObj, ok := objects[ekIdx].(map[string]any)
		if !ok {
			return fileRecord{}, fmt.Errorf("iosbackup: EncryptionKey object malformed")
		}
		nsData, ok := ekObj["NS.data"].([]byte)
		if !ok || len(nsData) <= 4 {
			return fileRecord{}, fmt.Errorf("iosbackup: EncryptionKey NS.data malformed")
		}
		rec.encryptionKey = nsData[4:] // strip the 4-byte protection-class prefix
	}
	return rec, nil
}

// asInt64 reads a plist integer regardless of the concrete type howett.net/plist chose.
func asInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case uint64:
		return int64(n), true
	case int:
		return int64(n), true
	default:
		return 0, false
	}
}

// asUID reads an NSKeyedArchiver object reference (CF$UID).
func asUID(v any) (uint64, bool) {
	switch u := v.(type) {
	case plist.UID:
		return uint64(u), true
	case uint64:
		return u, true
	default:
		return 0, false
	}
}

// FileRecord is what a Files.file blob says ABOUT a file, as distinct from the file's
// content: the two metadata fields a caller needs in order to describe an entry without
// decrypting anything.
//
// A struct rather than two return values because the record carries more than this — Flags,
// Mode, Birth, InodeNumber, UserID, GroupID, ExtendedAttributes and, for symlinks, Target —
// and a caller that later needs one of them should get a field rather than a fourth return.
type FileRecord struct {
	// Size is the recorded plaintext length in bytes. Directories and symlinks record 0.
	Size int64

	// MTime is the last-modified time, or the ZERO Time when the record carries none.
	// Absent is ordinary rather than corrupt — the field is optional in the format and the
	// reference implementation guards every use of it. Check IsZero; do not read a zero
	// value as 1970. (Identical to FileEntry.MTime, deliberately.)
	MTime time.Time
}

// DecodeFileRecord reads the metadata out of one Files.file blob.
//
// WHY A DECRYPTION LIBRARY EXPORTS THIS, since the charter says the scope is decrypting
// encrypted backups and this function decrypts nothing: the MBFile record is the FILE-RECORD
// FORMAT, not a decryption step. An unencrypted backup's Manifest.db is plain SQLite that any
// caller can open, but Size and MTime are not columns in it — they live inside this blob, in
// exactly the same NSKeyedArchiver shape, and decoding them is Apple-format parsing that is
// needed identically whether or not a key was ever involved.
//
// So the alternative to exporting it is a second copy of this decoder in every consumer, and
// two copies of a record decoder can disagree about a file's size — the encrypted path saying
// one number and the unencrypted path another for the identical record. That is the
// duplication argument this repository already accepted for the crypto in #4, applied to the
// one piece that is not crypto at all. The charter is untouched: this library still only
// decrypts, and a consumer reading a manifest nobody encrypted borrows the part that was
// never about encryption. (novkostya/ios-backup-crypt#8.)
//
// MEASURED, on a real unencrypted iPad backup, 2026-08-21, across all three record kinds
// (file, directory, symlink): the graph is identical to the encrypted case — bplist00,
// NSKeyedArchiver, $top.root into an MBFile carrying Size, LastModified, ProtectionClass,
// Flags, Mode, Birth, RelativePath, InodeNumber, UserID and GroupID. The ONLY difference is
// that EncryptionKey is absent, which this decoder already treats as ordinary because that
// is also the directory-and-symlink case. The issue proposing this export flagged "I have
// not checked whether the record format differs" as the thing that could make the answer
// bigger than an export; it does not differ, so it did not.
//
// It deliberately does NOT surface ProtectionClass or the wrapped EncryptionKey. Those ARE
// decryption details, and exporting them would widen the charter this function is careful
// not to touch.
func DecodeFileRecord(blob []byte) (FileRecord, error) {
	rec, err := decodeFileRecord(blob)
	if err != nil {
		return FileRecord{}, err
	}
	return FileRecord{Size: rec.size, MTime: rec.mtime}, nil
}
