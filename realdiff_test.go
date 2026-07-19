package iosbackup

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The real-backup harness (testing-ladder rung 4) is OPERATOR-LOCAL: it runs only when
// the environment points it at a real encrypted backup, so it never runs in CI and no
// real path, password, or decrypted byte is ever committed. Drive it via
// `make gates-real` and `make extract-real` (see CONTRIBUTING.md).
//
// Environment (set by those Make targets):
//   REAL_BACKUP               container path to the backup directory (bind-mounted RO)
//   IOSBACKUP_REAL_PASSWORD   the backup password
//   DIFF_OUT                  scratch dir for the differential's Go outputs + index
//   IOSBACKUP_EXTRACT_OUT     destination tree for a full decrypt (extract only)
//   IOSBACKUP_EXTRACT_MAXBYTES optional per-file size cap in bytes (0/unset = no cap)

// TestRealBackupDifferential decrypts the real backup's Manifest.db plus a spread sample
// of files with THIS library and writes them to DIFF_OUT for deploy/differential.py to
// byte-compare against the Python reference. Decrypting all files twice is unnecessary to
// prove correctness, so it samples across domains and skips very large blobs.
func TestRealBackupDifferential(t *testing.T) {
	dir := os.Getenv("REAL_BACKUP")
	out := os.Getenv("DIFF_OUT")
	if dir == "" || out == "" {
		t.Skip("REAL_BACKUP / DIFF_OUT not set; run via `make gates-real`")
	}

	goDir := filepath.Join(out, "go")
	if err := os.MkdirAll(goDir, 0o755); err != nil {
		t.Fatal(err)
	}

	b := openRealBackup(t, dir)
	defer func() { _ = b.Close() }()

	// Decrypted Manifest.db → byte-compare target.
	if err := copyFile(b.dbPath, filepath.Join(goDir, "Manifest.db")); err != nil {
		t.Fatalf("copy Manifest.db: %v", err)
	}

	// Collect regular files, then take an even stride across them (they are ordered by
	// domain, relativePath, so a stride spans domains).
	var files []FileEntry
	for e := range b.List("", "") {
		if e.Flags == 1 {
			files = append(files, e)
		}
	}
	if err := b.Err(); err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("regular files in backup: %d", len(files))

	const sampleTarget = 60
	const maxBytes = 25 << 20 // skip blobs larger than 25 MiB to keep the sample fast
	stride := len(files) / sampleTarget
	if stride < 1 {
		stride = 1
	}

	var sampled []diffIndexFile
	var nSkipped int
	for i := 0; i < len(files) && len(sampled) < sampleTarget; i += stride {
		e := files[i]
		blob := filepath.Join(dir, e.FileID[:2], e.FileID)
		st, err := os.Stat(blob)
		if err != nil || st.Size() > maxBytes {
			continue // missing on-disk blob, or too big for the sample
		}
		dst := filepath.Join(goDir, e.FileID)
		f, err := os.Create(dst)
		if err != nil {
			t.Fatal(err)
		}
		derr := b.DecryptFile(e.FileID, f)
		cerr := f.Close()
		if derr != nil {
			// Skip files this backup stored incompletely (or that otherwise fail to
			// decrypt) rather than aborting; the reference would reject them too.
			_ = os.Remove(dst)
			nSkipped++
			t.Logf("sample skip %s / %s: %v", e.Domain, e.RelativePath, derr)
			continue
		}
		if cerr != nil {
			t.Fatal(cerr)
		}
		sampled = append(sampled, diffIndexFile{FileID: e.FileID, Domain: e.Domain, RelativePath: e.RelativePath})
	}
	t.Logf("sampled %d files for the differential (%d candidates skipped)", len(sampled), nSkipped)

	// index.json deliberately carries no password (the comparator reads it from env).
	data, err := json.MarshalIndent(diffIndex{Files: sampled}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(out, "index.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestRealBackupExtractAll decrypts the real backup into a logical <domain>/<relativePath>
// tree under IOSBACKUP_EXTRACT_OUT — the fixture an ios-backup-parser implementer spikes
// on. It is operator-local; the tree is real personal data and must stay on the
// operator's infra. IOSBACKUP_EXTRACT_MAXBYTES optionally skips large media blobs so the
// databases-and-structure subset fits a smaller volume.
func TestRealBackupExtractAll(t *testing.T) {
	dir := os.Getenv("REAL_BACKUP")
	outRoot := os.Getenv("IOSBACKUP_EXTRACT_OUT")
	if dir == "" || outRoot == "" {
		t.Skip("REAL_BACKUP / IOSBACKUP_EXTRACT_OUT not set; run via `make extract-real`")
	}

	var maxBytes int64
	if v := os.Getenv("IOSBACKUP_EXTRACT_MAXBYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			t.Fatalf("IOSBACKUP_EXTRACT_MAXBYTES: %v", err)
		}
		maxBytes = n
	}

	b := openRealBackup(t, dir)
	defer func() { _ = b.Close() }()

	var nFiles, nCapped, nIncomplete, nErrors int
	var nBytes int64
	for e := range b.List("", "") {
		if e.Flags != 1 {
			continue // only regular files have content
		}
		blob := filepath.Join(dir, e.FileID[:2], e.FileID)
		st, err := os.Stat(blob)
		if err != nil {
			continue // no on-disk blob
		}
		if maxBytes > 0 && st.Size() > maxBytes {
			nCapped++
			continue
		}
		dst, ok := safeTreePath(outRoot, e.Domain, e.RelativePath)
		if !ok {
			t.Fatalf("refusing unsafe path: domain=%q relativePath=%q", e.Domain, e.RelativePath)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		f, err := os.Create(dst)
		if err != nil {
			t.Fatal(err)
		}
		derr := b.DecryptFile(e.FileID, f)
		cerr := f.Close()
		if derr != nil {
			// Real backups contain files stored incompletely; skip and drop the partial
			// rather than aborting the whole extraction.
			_ = os.Remove(dst)
			if errors.Is(derr, ErrIncompleteFile) {
				nIncomplete++
			} else {
				nErrors++
				t.Logf("skip %s / %s: %v", e.Domain, e.RelativePath, derr)
			}
			continue
		}
		if cerr != nil {
			t.Fatal(cerr)
		}
		nFiles++
		nBytes += st.Size()
	}
	if err := b.Err(); err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("extracted %d files (~%d MiB) to %s", nFiles, nBytes>>20, outRoot)
	t.Logf("skipped: %d over size cap, %d incomplete (stored shorter than recorded), %d other errors", nCapped, nIncomplete, nErrors)
}

// TestRealBackupOpen is a password-free smoke test: it parses a real Manifest.plist and
// keybag (no Unlock), so the parse path can be validated against a real device without
// handling the password. Gated on REAL_BACKUP; skips in CI.
func TestRealBackupOpen(t *testing.T) {
	dir := os.Getenv("REAL_BACKUP")
	if dir == "" {
		t.Skip("REAL_BACKUP not set")
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	defer func() { _ = b.Close() }()
	info, err := b.DeviceInfo()
	if err != nil {
		t.Fatalf("DeviceInfo: %v", err)
	}
	t.Logf("parsed OK (not unlocked): device=%q iOS=%s", info.DeviceName, info.ProductVersion)
}

func openRealBackup(t *testing.T, dir string) *Backup {
	t.Helper()
	b, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	if err := b.Unlock(os.Getenv("IOSBACKUP_REAL_PASSWORD")); err != nil {
		_ = b.Close()
		t.Fatalf("Unlock: %v (wrong IOSBACKUP_REAL_PASSWORD?)", err)
	}
	if info, err := b.DeviceInfo(); err == nil {
		t.Logf("device=%q iOS=%s files=%d", info.DeviceName, info.ProductVersion, info.FileCount)
	}
	return b
}

// safeTreePath joins root/domain/relativePath and confirms the result stays within root,
// so a hostile or malformed relativePath cannot escape the output tree.
func safeTreePath(root, domain, relativePath string) (string, bool) {
	dst := filepath.Join(root, domain, filepath.FromSlash(relativePath))
	rootClean := filepath.Clean(root) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(dst)+string(os.PathSeparator), rootClean) {
		return "", false
	}
	return dst, true
}
