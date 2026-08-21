package iosbackup

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
	"howett.net/plist"

	_ "modernc.org/sqlite"
)

// The unencrypted fixture must be genuinely unencrypted, checked at each of the three places
// encryption would otherwise show: the index, the plist and the blobs. Asserted structurally
// rather than by "Open refused it", because a fixture that is subtly still encrypted would
// make a consumer's conformance run agree with a bug.
func TestUnencryptedFixtureHasNoEncryptionAnywhere(t *testing.T) {
	dir := t.TempDir()
	mtime := time.Unix(1_600_000_000, 0).UTC()
	content := []byte("plaintext on disk, no padding, no key")

	res, err := builder.Build(dir, builder.Spec{
		Unencrypted:    true,
		DeviceName:     "Test Device",
		ProductVersion: "17.0",
		Files: []builder.File{
			{Domain: "AppDomain-com.example", RelativePath: "Documents/note.txt", Flags: 1, Data: content, MTime: mtime},
			{Domain: "AppDomain-com.example", RelativePath: "Documents", Flags: 2},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Password != "" {
		t.Errorf("Result.Password = %q, want empty: there is nothing to unlock", res.Password)
	}

	// 1. The index is plain SQLite, not ciphertext.
	head, err := os.ReadFile(filepath.Join(dir, "Manifest.db"))
	if err != nil {
		t.Fatalf("reading Manifest.db: %v", err)
	}
	if !bytes.HasPrefix(head, []byte("SQLite format 3\x00")) {
		t.Errorf("Manifest.db does not start with the SQLite magic; it is still encrypted")
	}

	// 2. The plist declares it, and carries no key material at all.
	raw, err := os.ReadFile(filepath.Join(dir, "Manifest.plist"))
	if err != nil {
		t.Fatalf("reading Manifest.plist: %v", err)
	}
	var mp map[string]any
	if _, err := plist.Unmarshal(raw, &mp); err != nil {
		t.Fatalf("parsing Manifest.plist: %v", err)
	}
	if enc, _ := mp["IsEncrypted"].(bool); enc {
		t.Error("Manifest.plist says IsEncrypted true")
	}
	for _, k := range []string{"BackupKeyBag", "ManifestKey"} {
		if _, present := mp[k]; present {
			t.Errorf("Manifest.plist carries %s; an unencrypted backup has no key material", k)
		}
	}

	// 3. The blob is the plaintext, byte for byte and with no padding — which is what lets a
	// consumer check a recorded Size against the on-disk length at all.
	var fileRow string
	for _, w := range res.Files {
		if w.Flags == 1 {
			fileRow = w.FileID
		}
	}
	blob, err := os.ReadFile(filepath.Join(dir, fileRow[:2], fileRow))
	if err != nil {
		t.Fatalf("reading the blob: %v", err)
	}
	if !bytes.Equal(blob, content) {
		t.Errorf("on-disk blob is %d bytes and differs from the %d bytes written",
			len(blob), len(content))
	}
}

// The file records must be THE SAME RECORDS as the encrypted path writes, minus the
// EncryptionKey. That is the claim that justifies building this here rather than in a
// consumer, so it is asserted rather than assumed — and it is asserted through the exported
// decoder, which is what a consumer will actually use.
func TestUnencryptedFixtureRecordsDecodeThroughTheExportedDecoder(t *testing.T) {
	dir := t.TempDir()
	mtime := time.Unix(1_700_000_000, 0).UTC()
	content := bytes.Repeat([]byte{0x7A}, 1234)

	res, err := builder.Build(dir, builder.Spec{
		Unencrypted: true,
		Files: []builder.File{
			{Domain: "CameraRollDomain", RelativePath: "Media/IMG_0001.JPG", Flags: 1, Data: content, MTime: mtime},
			{Domain: "CameraRollDomain", RelativePath: "Media", Flags: 2},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "Manifest.db")+"?mode=ro")
	if err != nil {
		t.Fatalf("opening the index: %v", err)
	}
	defer func() { _ = db.Close() }()

	for _, w := range res.Files {
		var raw []byte
		if err := db.QueryRow(`select file from Files where fileID = ?`, w.FileID).Scan(&raw); err != nil {
			t.Fatalf("reading the record for %s: %v", w.RelativePath, err)
		}
		rec, err := DecodeFileRecord(raw)
		if err != nil {
			t.Fatalf("DecodeFileRecord(%s): %v", w.RelativePath, err)
		}
		switch w.Flags {
		case 1:
			if rec.Size != int64(len(content)) {
				t.Errorf("file Size = %d, want %d", rec.Size, len(content))
			}
			if !rec.MTime.Equal(mtime) {
				t.Errorf("file MTime = %v, want %v", rec.MTime, mtime)
			}
		case 2:
			if rec.Size != 0 {
				t.Errorf("directory Size = %d, want 0", rec.Size)
			}
			if !rec.MTime.IsZero() {
				t.Errorf("directory MTime = %v, want zero: no MTime was set", rec.MTime)
			}
		}
	}
}

// The encrypted path must be untouched by the branch added for the unencrypted one — the
// regression this change could plausibly cause.
func TestEncryptedFixtureIsStillEncrypted(t *testing.T) {
	dir := t.TempDir()
	if _, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{
			{Domain: "AppDomain-com.example", RelativePath: "Documents/note.txt", Flags: 1, Data: []byte("secret")},
		},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	head, err := os.ReadFile(filepath.Join(dir, "Manifest.db"))
	if err != nil {
		t.Fatalf("reading Manifest.db: %v", err)
	}
	if bytes.HasPrefix(head, []byte("SQLite format 3\x00")) {
		t.Error("the ENCRYPTED fixture's Manifest.db is plain SQLite; the unencrypted branch " +
			"has leaked into the default path")
	}
}
