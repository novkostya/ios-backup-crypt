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
