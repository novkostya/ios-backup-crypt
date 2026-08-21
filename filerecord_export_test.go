package iosbackup

import (
	"testing"
	"time"

	"howett.net/plist"
)

// recordBlob marshals one MBFile record in the shape a real Manifest.db carries, so each
// case below can vary exactly one thing: whether EncryptionKey is present (encrypted file
// vs. every entry of an unencrypted backup, and every directory or symlink of either) and
// whether the optional LastModified is.
//
// Built here rather than driven through internal/builder because builder.Build produces a
// whole encrypted backup, and the cases that matter are the ones with no encryption at all.
func recordBlob(t *testing.T, size int64, mtime time.Time, withKey bool) []byte {
	t.Helper()

	record := map[string]any{
		"Size":            size,
		"ProtectionClass": 3,
		"RelativePath":    "Library/Preferences/example.plist",
	}
	if !mtime.IsZero() {
		record["LastModified"] = mtime.Unix()
	}
	objects := []any{"$null", record}
	if withKey {
		// 4-byte protection-class prefix + a wrapped-key-shaped tail. The decoder strips the
		// prefix and never interprets the rest, so its contents are irrelevant here.
		objects = append(objects, map[string]any{"NS.data": make([]byte, 4+40)})
		record["EncryptionKey"] = plist.UID(len(objects) - 1)
	}

	blob, err := plist.Marshal(map[string]any{
		"$version":  100000,
		"$archiver": "NSKeyedArchiver",
		"$top":      map[string]any{"root": plist.UID(1)},
		"$objects":  objects,
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshaling the test record: %v", err)
	}
	return blob
}

// The exported decoder is what a consumer reading an UNENCRYPTED backup leans on, so the
// case that matters most is the record with NO EncryptionKey — which in an unencrypted
// backup is EVERY entry, ordinary files included, not just directories and symlinks.
func TestDecodeFileRecordReadsARecordWithNoEncryptionKey(t *testing.T) {
	mtime := time.Unix(1_600_000_000, 0).UTC()

	rec, err := DecodeFileRecord(recordBlob(t, 4242, mtime, false))
	if err != nil {
		t.Fatalf("DecodeFileRecord: %v", err)
	}
	if rec.Size != 4242 {
		t.Errorf("Size = %d, want 4242", rec.Size)
	}
	if !rec.MTime.Equal(mtime) {
		t.Errorf("MTime = %v, want %v", rec.MTime, mtime)
	}
}

// And a record WITH one decodes identically — the export must not become a
// no-encryption-key special case, because the encrypted path uses the same decoder.
func TestDecodeFileRecordIsIndifferentToAnEncryptionKey(t *testing.T) {
	mtime := time.Unix(1_700_000_000, 0).UTC()

	with, err := DecodeFileRecord(recordBlob(t, 99, mtime, true))
	if err != nil {
		t.Fatalf("DecodeFileRecord (with key): %v", err)
	}
	without, err := DecodeFileRecord(recordBlob(t, 99, mtime, false))
	if err != nil {
		t.Fatalf("DecodeFileRecord (no key): %v", err)
	}
	if with != without {
		t.Errorf("the same record decodes differently with and without an EncryptionKey: "+
			"%+v vs %+v", with, without)
	}
}

// ABSENT MUST STAY DISTINGUISHABLE FROM 1970. LastModified is optional in the format, and a
// consumer that renders a zero Time as an epoch date shows such files as 1 January 1970 —
// which is why the field is documented as IsZero-checkable rather than defaulted.
func TestDecodeFileRecordLeavesAnAbsentMTimeZero(t *testing.T) {
	rec, err := DecodeFileRecord(recordBlob(t, 0, time.Time{}, false))
	if err != nil {
		t.Fatalf("DecodeFileRecord: %v", err)
	}
	if !rec.MTime.IsZero() {
		t.Errorf("MTime = %v, want the zero Time: the record carries no LastModified", rec.MTime)
	}
}

// A blob that is not a plist is an error rather than a zero record, so a caller cannot
// mistake "could not read this" for "this file is 0 bytes with no mtime".
func TestDecodeFileRecordRefusesAMalformedBlob(t *testing.T) {
	if _, err := DecodeFileRecord([]byte("this is not an NSKeyedArchiver blob")); err == nil {
		t.Error("DecodeFileRecord accepted a non-plist blob; a caller would read the zero " +
			"FileRecord as a real 0-byte file")
	}
}

// The exported decoder and the library's own internal one must not drift: the export is a
// projection of decodeFileRecord, and this fails if it ever becomes a reimplementation.
func TestDecodeFileRecordAgreesWithTheInternalDecoder(t *testing.T) {
	mtime := time.Unix(1_650_000_000, 0).UTC()
	blob := recordBlob(t, 7, mtime, true)

	internal, err := decodeFileRecord(blob)
	if err != nil {
		t.Fatalf("decodeFileRecord: %v", err)
	}
	exported, err := DecodeFileRecord(blob)
	if err != nil {
		t.Fatalf("DecodeFileRecord: %v", err)
	}
	if exported.Size != internal.size || !exported.MTime.Equal(internal.mtime) {
		t.Errorf("exported %+v does not match internal size=%d mtime=%v",
			exported, internal.size, internal.mtime)
	}
}
