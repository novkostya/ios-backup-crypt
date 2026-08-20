package iosbackup

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/novkostya/ios-backup-crypt/fixture"
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
	res, err := fixture.Build(dir, fixture.Spec{
		Password: "test",
		Files: []fixture.File{
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
	res, err := fixture.Build(dir, fixture.Spec{
		Files: []fixture.File{{Domain: "HomeDomain", RelativePath: "live.db", Flags: 1, Data: bytes.Repeat([]byte{0x7}, 4096)}},
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
	res, err := fixture.Build(dir, fixture.Spec{
		Files: []fixture.File{{Domain: "HomeDomain", RelativePath: "a", Flags: 1, Data: []byte("x")}},
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
