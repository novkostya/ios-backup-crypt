package iosbackup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
)

// TestDecryptFileRoundTrip is the milestone-3 proof: files written by the builder decrypt
// back byte-for-byte, across sizes that exercise padding and cross-chunk streaming.
func TestDecryptFileRoundTrip(t *testing.T) {
	small := []byte("hello, world")           // 12 bytes: not block-aligned
	aligned := bytes.Repeat([]byte{0x5A}, 64) // exact multiple of the block size
	big := make([]byte, 200000)               // larger than the 64 KiB streaming chunk
	for i := range big {
		big[i] = byte(i * 131 % 251)
	}
	empty := []byte{} // zero-length file (still gets a full padding block)

	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Password: "test",
		Files: []builder.File{
			{Domain: "HomeDomain", RelativePath: "small.txt", Flags: 1, Data: small},
			{Domain: "HomeDomain", RelativePath: "aligned.bin", Flags: 1, Data: aligned},
			{Domain: "HomeDomain", RelativePath: "big.bin", Flags: 1, Data: big},
			{Domain: "HomeDomain", RelativePath: "empty.dat", Flags: 1, Data: empty},
			{Domain: "HomeDomain", RelativePath: "Documents", Flags: 2}, // directory: no Data
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Unlock("test"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	for i, want := range [][]byte{small, aligned, big, empty} {
		id := res.Files[i].FileID
		var buf bytes.Buffer
		if err := b.DecryptFile(id, &buf); err != nil {
			t.Fatalf("DecryptFile(%s, %q): %v", id, res.Files[i].RelativePath, err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Fatalf("%q: decrypted %d bytes, want %d (mismatch)", res.Files[i].RelativePath, buf.Len(), len(want))
		}
	}

	// A directory has no encryption key.
	dirID := res.Files[4].FileID
	if err := b.DecryptFile(dirID, io.Discard); !errors.Is(err, ErrNotAFile) {
		t.Fatalf("DecryptFile(dir): got %v, want ErrNotAFile", err)
	}

	// Unknown fileID.
	if err := b.DecryptFile(strings.Repeat("a", 40), io.Discard); !errors.Is(err, ErrFileNotFound) {
		t.Fatalf("DecryptFile(unknown): got %v, want ErrFileNotFound", err)
	}
}

// TestDecryptFileIncomplete simulates the real-backup quirk where a file's on-disk data
// is shorter than its recorded size (a file still being written when the backup ran):
// DecryptFile must report ErrIncompleteFile rather than a generic error.
func TestDecryptFileIncomplete(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "live.db", Flags: 1, Data: bytes.Repeat([]byte{0x7}, 4096)}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	// Truncate the on-disk blob so it decrypts to fewer bytes than the recorded size.
	id := res.Files[0].FileID
	if err := os.Truncate(filepath.Join(dir, id[:2], id), 2048); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.Unlock("test"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	var buf bytes.Buffer
	if err := b.DecryptFile(id, &buf); !errors.Is(err, ErrIncompleteFile) {
		t.Fatalf("DecryptFile(truncated): got %v, want ErrIncompleteFile", err)
	}
	// The recovered content is the valid 2048-byte prefix — NOT false-stripped as if the
	// trailing 0x07 bytes were PKCS#7 padding (which would drop 7 real bytes).
	if want := bytes.Repeat([]byte{0x7}, 2048); !bytes.Equal(buf.Bytes(), want) {
		t.Fatalf("recovered %d bytes, want the 2048-byte prefix intact", buf.Len())
	}
}

func TestDecryptFileLocked(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("x")}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	if err := b.DecryptFile(res.Files[0].FileID, io.Discard); !errors.Is(err, ErrLocked) {
		t.Fatalf("DecryptFile before Unlock: got %v, want ErrLocked", err)
	}
}

// Size and MTime come off the per-row record, and MTime is OPTIONAL — a record without a
// LastModified is ordinary, not corrupt. That absent case is the one worth pinning: the
// reference reads the field with a plain .get() and guards every use of it, so anything
// that treats a missing timestamp as an error, or as 1970, is wrong in a way that only
// shows up on real data.
func TestListAndStatCarrySizeAndOptionalMTime(t *testing.T) {
	dir := t.TempDir()
	stamped := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{
			{Domain: "HomeDomain", RelativePath: "a-stamped", Flags: 1, Data: []byte("twelve bytes"), MTime: stamped},
			{Domain: "HomeDomain", RelativePath: "b-unstamped", Flags: 1, Data: []byte("five!")},
			{Domain: "HomeDomain", RelativePath: "c-dir", Flags: 2},
		},
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

	got := map[string]FileEntry{}
	for e := range b.List("", "") {
		got[e.RelativePath] = e
	}
	if err := b.Err(); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("listed %d entries, want 3", len(got))
	}

	if e := got["a-stamped"]; e.Size != 12 {
		t.Errorf("a-stamped Size = %d, want 12", e.Size)
	} else if !e.MTime.Equal(stamped) {
		t.Errorf("a-stamped MTime = %v, want %v", e.MTime, stamped)
	}

	// The case this test exists for.
	if e := got["b-unstamped"]; e.Size != 5 {
		t.Errorf("b-unstamped Size = %d, want 5", e.Size)
	} else if !e.MTime.IsZero() {
		t.Errorf("b-unstamped MTime = %v, want the zero Time for an absent LastModified", e.MTime)
	}

	if e := got["c-dir"]; e.Size != 0 {
		t.Errorf("directory Size = %d, want 0", e.Size)
	}

	// Stat agrees with List, or one of the two paths is decoding differently.
	for _, path := range []string{"a-stamped", "b-unstamped", "c-dir"} {
		want := got[path]
		st, err := b.Stat(want.FileID)
		if err != nil {
			t.Fatalf("Stat(%s): %v", path, err)
		}
		if st.Size != want.Size || !st.MTime.Equal(want.MTime) {
			t.Errorf("%s: Stat = (%d, %v), List = (%d, %v)", path, st.Size, st.MTime, want.Size, want.MTime)
		}
	}
}

// A record that will not decode costs its own entry its metadata and nothing else — the
// walk continues, and Err reports that the listing was imperfect. Stopping would let one
// unreadable row hide every file after it in a backup somebody is trying to browse.
func TestAnUndecodableRecordDoesNotTruncateTheWalk(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		Files: []builder.File{
			{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("aaa")},
			{Domain: "HomeDomain", RelativePath: "b", Flags: 1, BadRecord: true},
			{Domain: "HomeDomain", RelativePath: "c", Flags: 1, Data: []byte("ccc")},
		},
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

	var paths []string
	for e := range b.List("", "") {
		paths = append(paths, e.RelativePath)
	}

	if len(paths) != 3 {
		t.Errorf("walk yielded %v, want all three entries despite the bad record", paths)
	}
	if err := b.Err(); err == nil {
		t.Error("Err() is nil; an undecodable record must be reported, not swallowed")
	}

	// The entries around the bad one are intact — the failure is scoped to its own row.
	got := map[string]FileEntry{}
	for e := range b.List("", "") {
		got[e.RelativePath] = e
	}
	if got["a"].Size != 3 || got["c"].Size != 3 {
		t.Errorf("neighbors lost their metadata: a=%d c=%d, want 3 and 3", got["a"].Size, got["c"].Size)
	}
	if got["b"].RelativePath != "b" {
		t.Error("the bad row vanished; it should still be listed, just without metadata")
	}
	if got["b"].Size != 0 || !got["b"].MTime.IsZero() {
		t.Errorf("the bad row carries metadata it could not have: %+v", got["b"])
	}
}
