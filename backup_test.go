package iosbackup

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
	// BOTH SENTINELS, AND THE PAIR IS THE POINT. `ErrBadPassword` is what a consumer outside
	// this module can match — the whole reason it exists — and `keybag.ErrWrongPassword` is
	// what the wrap must not have discarded. Asserting only the first would let a later
	// refactor replace the cause with a bare sentinel and stay green, taking the specific
	// sentence out of every consumer's logs.
	err = b.Unlock("wrong")
	if !errors.Is(err, ErrBadPassword) {
		t.Fatalf("Unlock(wrong): got %v, want ErrBadPassword — the sentinel a consumer outside "+
			"this module matches on, and the difference between telling a user to retype "+
			"their password and telling them the backup is broken", err)
	}
	if !errors.Is(err, keybag.ErrWrongPassword) {
		t.Errorf("Unlock(wrong) = %v: the underlying keybag error was replaced rather than "+
			"wrapped, so its sentence no longer reaches a caller's logs", err)
	}
	// A CORRECT PASSWORD MUST NOT MATCH IT — the control, without which the two assertions
	// above pass against a function that returns ErrBadPassword unconditionally.
	if err := b.Unlock("correct-horse"); err != nil {
		t.Fatalf("Unlock(correct): %v", err)
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

// WithScratchDir puts the decrypted index where the caller says, and Close removes it.
//
// THE CONTROL IS THE OTHER HALF: without the option the file must NOT appear there. A test
// that only checks the positive would pass against an implementation that wrote to both
// places, or to neither and left the assertion vacuous — the directory is empty at the end
// either way, because Close cleans up.
func TestWithScratchDirPutsTheDecryptedIndexWhereAsked(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("aaa")}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	scratch := t.TempDir()
	b, err := Open(dir, WithScratchDir(scratch))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := b.Unlock(res.Password); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatalf("reading the scratch dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("scratch holds %d entries, want exactly the decrypted index", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "iosbackup-manifest-") {
		t.Errorf("scratch holds %q, which is not the decrypted index", entries[0].Name())
	}

	// It is a real, readable database while the backup is unlocked — not merely a file with
	// the right name.
	if _, err := b.Stat(res.Files[0].FileID); err != nil {
		t.Errorf("the backup is not usable with a caller-chosen scratch dir: %v", err)
	}

	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	entries, err = os.ReadDir(scratch)
	if err != nil {
		t.Fatalf("re-reading the scratch dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("Close left %d entries in the scratch dir, want none", len(entries))
	}
}

// The control for the test above: with no option, nothing lands in that directory.
func TestWithoutTheOptionTheScratchDirStaysEmpty(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("aaa")}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	notScratch := t.TempDir()
	b, err := Open(dir) // no option — the default is the OS temp dir
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Unlock(res.Password); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	entries, err := os.ReadDir(notScratch)
	if err != nil {
		t.Fatalf("reading the directory: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("a directory nobody named holds %d entries; the option is not what decided the location", len(entries))
	}
}

// Open with no options keeps meaning what it meant — the variadic must not change the
// zero-option call.
func TestOpenWithoutOptionsIsUnchanged(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("aaa")}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Unlock(res.Password); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	if _, err := b.Stat(res.Files[0].FileID); err != nil {
		t.Errorf("Stat after a plain Open: %v", err)
	}
}

// A scratch directory that does not exist is a refusal with a reason, not a silent
// fallback to the OS temp dir — which would put plaintext somewhere the caller does not
// wipe while reporting success.
func TestAMissingScratchDirIsRefusedNotIgnored(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("aaa")}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	b, err := Open(dir, WithScratchDir(filepath.Join(t.TempDir(), "does-not-exist")))
	if err != nil {
		t.Fatalf("Open should not validate the directory: %v", err)
	}
	defer func() { _ = b.Close() }()

	if err := b.Unlock(res.Password); err == nil {
		t.Error("Unlock succeeded with a nonexistent scratch dir; it must refuse rather than fall back")
	}
}
