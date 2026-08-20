package iosbackup

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
	"github.com/novkostya/ios-backup-crypt/internal/keybag"
)

// TestOpenUnlockRoundTrip is the milestone-2 proof: a synthetic encrypted backup is
// built, opened, unlocked (KDF → unwrap → Manifest.db AES-CBC decrypt), and its Files
// table is read back via List and Stat.
func TestOpenUnlockRoundTrip(t *testing.T) {
	dir := t.TempDir()
	spec := builder.Spec{
		Password:       "test",
		DeviceName:     "Test iPhone",
		ProductVersion: "17.5.1",
		Files: []builder.File{
			{Domain: "AppDomain-com.example.app", RelativePath: "Documents/a.txt", Flags: 1},
			{Domain: "AppDomain-com.example.app", RelativePath: "Documents/b.txt", Flags: 1},
			{Domain: "AppDomain-com.example.app", RelativePath: "Documents", Flags: 2},
			{Domain: "HomeDomain", RelativePath: "Library/SMS/sms.db", Flags: 1},
		},
	}
	res, err := builder.Build(dir, spec)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })

	// Locked: file operations fail before Unlock, but device metadata is available.
	if _, err := b.Stat(res.Files[0].FileID); !errors.Is(err, ErrLocked) {
		t.Fatalf("Stat before Unlock: got %v, want ErrLocked", err)
	}
	if info, _ := b.DeviceInfo(); info.DeviceName != "Test iPhone" || info.ProductVersion != "17.5.1" {
		t.Fatalf("DeviceInfo pre-unlock = %+v", info)
	}

	if err := b.Unlock("test"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Full listing returns every row (files and the directory).
	var all []FileEntry
	for e := range b.List("", "") {
		all = append(all, e)
	}
	if err := b.Err(); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != len(res.Files) {
		t.Fatalf("List returned %d rows, want %d", len(all), len(res.Files))
	}

	// Domain + relativePath-prefix filter (should match the two Documents/*.txt files,
	// not the "Documents" directory).
	var docs []FileEntry
	for e := range b.List("AppDomain-com.example.app", "Documents/") {
		docs = append(docs, e)
	}
	if len(docs) != 2 {
		t.Fatalf("prefixed List returned %d rows, want 2: %+v", len(docs), docs)
	}
	for _, e := range docs {
		if e.Domain != "AppDomain-com.example.app" {
			t.Errorf("unexpected domain %q", e.Domain)
		}
	}

	// Stat a known file by its computed fileID.
	want := res.Files[3] // HomeDomain / Library/SMS/sms.db
	e, err := b.Stat(want.FileID)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if e.Domain != want.Domain || e.RelativePath != want.RelativePath || e.Flags != want.Flags {
		t.Fatalf("Stat mismatch:\n got  %+v\n want %+v", e, want)
	}

	if _, err := b.Stat("0000000000000000000000000000000000000000"); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("Stat(unknown): got %v, want ErrFileNotFound", err)
	}

	// File count after unlock.
	info, err := b.DeviceInfo()
	if err != nil {
		t.Fatalf("DeviceInfo: %v", err)
	}
	if info.FileCount != int64(len(res.Files)) {
		t.Fatalf("FileCount = %d, want %d", info.FileCount, len(res.Files))
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	dir := t.TempDir()
	if _, err := builder.Build(dir, builder.Spec{
		Password: "correct-horse",
		Files:    []builder.File{{Domain: "HomeDomain", RelativePath: "x", Flags: 1}},
	}); err != nil {
		t.Fatalf("Build: %v", err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Unlock("wrong"); !errors.Is(err, keybag.ErrWrongPassword) {
		t.Fatalf("Unlock(wrong): got %v, want keybag.ErrWrongPassword", err)
	}
}

func TestOpenNotEncrypted(t *testing.T) {
	dir := t.TempDir()
	data, err := plist.Marshal(map[string]any{"IsEncrypted": false}, plist.XMLFormat)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Manifest.plist"), data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrNotEncrypted) {
		t.Fatalf("Open(unencrypted): got %v, want ErrNotEncrypted", err)
	}
}

func TestOpenMissingBackup(t *testing.T) {
	if _, err := Open(t.TempDir()); err == nil {
		t.Fatalf("Open(empty dir): got nil, want error")
	}
}
