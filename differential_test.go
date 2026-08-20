package iosbackup

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
)

// diffIndex is written to <DIFF_OUT>/index.json so the Python comparator
// (deploy/differential.py) knows which files to extract and compare. For the synthetic
// fixture it also carries the (throwaway) password; for a real backup the password is
// omitted here and passed to the comparator via the environment instead.
type diffIndex struct {
	Password string          `json:"password,omitempty"`
	Files    []diffIndexFile `json:"files"`
}

type diffIndexFile struct {
	FileID       string `json:"fileID"`
	Domain       string `json:"domain"`
	RelativePath string `json:"relativePath"`
}

// TestWriteDifferentialFixture is not an ordinary unit test: it only runs when DIFF_OUT
// is set (the `make gates-diff` gate). It builds a synthetic encrypted backup, decrypts
// it with THIS library, and emits the decrypted Manifest.db, each file's decrypted
// contents, and an index.json. deploy/differential.py then decrypts the SAME backup with
// the Python reference implementation and byte-compares — proving no constant was got
// subtly wrong (testing-ladder rung 3). Under the normal gate it skips immediately.
func TestWriteDifferentialFixture(t *testing.T) {
	out := os.Getenv("DIFF_OUT")
	if out == "" {
		t.Skip("DIFF_OUT not set; run via `make gates-diff`")
	}

	files := []builder.File{
		{Domain: "HomeDomain", RelativePath: "Library/SMS/sms.db", Flags: 1, Data: pattern(1500)},
		{Domain: "AppDomain-com.example.app", RelativePath: "Documents/notes.txt", Flags: 1, Data: []byte("the quick brown fox jumps over the lazy dog\n")},
		{Domain: "CameraRollDomain", RelativePath: "Media/DCIM/100APPLE/IMG_0001.JPG", Flags: 1, Data: pattern(200000)},
		{Domain: "HomeDomain", RelativePath: "Library/Preferences/empty.plist", Flags: 1, Data: []byte{}},
	}

	backupDir := filepath.Join(out, "backup")
	goDir := filepath.Join(out, "go")
	if err := os.MkdirAll(goDir, 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := builder.Build(backupDir, builder.Spec{
		Password:       "test",
		DeviceName:     "Differential iPhone",
		ProductVersion: "17.5.1",
		Files:          files,
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	b, err := Open(backupDir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Unlock("test"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// Copy out the library's decrypted Manifest.db for a raw byte-compare.
	if err := copyFile(b.dbPath, filepath.Join(goDir, "Manifest.db")); err != nil {
		t.Fatalf("copy Manifest.db: %v", err)
	}

	// Decrypt each file's contents, one output file per fileID.
	idx := diffIndex{Password: "test"}
	for _, wf := range res.Files {
		f, err := os.Create(filepath.Join(goDir, wf.FileID))
		if err != nil {
			t.Fatal(err)
		}
		derr := b.DecryptFile(wf.FileID, f)
		cerr := f.Close()
		if derr != nil {
			t.Fatalf("DecryptFile(%s): %v", wf.RelativePath, derr)
		}
		if cerr != nil {
			t.Fatal(cerr)
		}
		idx.Files = append(idx.Files, diffIndexFile{FileID: wf.FileID, Domain: wf.Domain, RelativePath: wf.RelativePath})
	}

	data, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "index.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("differential fixture written to %s (%d files)", out, len(idx.Files))
}

// pattern returns n deterministic bytes for reproducible fixture content.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*37 + 11)
	}
	return b
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
