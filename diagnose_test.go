package iosbackup

import (
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/novkostya/ios-backup-crypt/internal/keybag"
)

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// TestRealBackupDiagnose explains why specific files are or aren't in an extracted tree.
// Operator-local; gated on REAL_BACKUP + IOSBACKUP_DIAGNOSE. Run via `make diagnose-real`.
func TestRealBackupDiagnose(t *testing.T) {
	dir := os.Getenv("REAL_BACKUP")
	if dir == "" || os.Getenv("IOSBACKUP_DIAGNOSE") == "" {
		t.Skip("set REAL_BACKUP and IOSBACKUP_DIAGNOSE=1 (via `make diagnose-real`)")
	}
	b := openRealBackup(t, dir)
	defer func() { _ = b.Close() }()

	decClass := func(err error) string {
		switch {
		case err == nil:
			return "ok"
		case errors.Is(err, ErrIncompleteFile):
			return "INCOMPLETE"
		case errors.Is(err, keybag.ErrClassLocked):
			return "CLASS-LOCKED"
		case errors.Is(err, keybag.ErrClassNotFound):
			return "CLASS-NOT-FOUND"
		case errors.Is(err, ErrNotAFile):
			return "no-key"
		default:
			return err.Error()
		}
	}

	// Part 1 — named primary databases (the ones the parser needs), one row each.
	t.Log("=== named primary databases ===")
	primaries := []struct{ domain, rel string }{
		{"HomeDomain", "Library/AddressBook/AddressBookImages.sqlitedb"}, // control: present in tree
		{"HomeDomain", "Library/SMS/sms.db"},
		{"HomeDomain", "Library/AddressBook/AddressBook.sqlitedb"},
		{"HomeDomain", "Library/CallHistoryDB/CallHistory.storedata"},
		{"HomeDomain", "Library/Calendar/Calendar.sqlitedb"},
		{"HomeDomain", "Library/Notes/notes.sqlite"},
		{"CameraRollDomain", "Media/PhotoData/Photos.sqlite"},
	}
	for _, p := range primaries {
		sum := sha1.Sum([]byte(p.domain + "-" + p.rel))
		id := hex.EncodeToString(sum[:])

		var flags int64
		var blob []byte
		switch err := b.db.QueryRow("SELECT flags, file FROM Files WHERE fileID = ?", id).Scan(&flags, &blob); {
		case errors.Is(err, sql.ErrNoRows):
			t.Logf("%-46s NOT IN Files table", p.rel)
			continue
		case err != nil:
			t.Fatalf("query %s: %v", p.rel, err)
		}
		rec, derr := decodeFileRecord(blob)
		recSize, class, hasKey := int64(-1), uint32(0), false
		if derr == nil {
			recSize, class, hasKey = rec.size, rec.protectionClass, rec.encryptionKey != nil
		}
		blobSize := int64(-1)
		if st, e := os.Stat(filepath.Join(dir, id[:2], id)); e == nil {
			blobSize = st.Size()
		}
		cw := &countWriter{}
		res := decClass(b.DecryptFile(id, cw))
		t.Logf("%-46s flags=%d class=%d hasKey=%v recSize=%d blob=%d decrypt=%s recovered=%d",
			p.rel, flags, class, hasKey, recSize, blobSize, res, cw.n)
	}

	// Part 2 — census of every regular file's decrypt outcome, and the full list of the
	// incomplete ones (so we can see the true scope and whether the primary DBs are in it).
	t.Log("=== decrypt census over all regular files ===")
	var nOK, nIncomplete, nOther int
	var incomplete []string
	for e := range b.List("", "") {
		if e.Flags != 1 {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, e.FileID[:2], e.FileID)); err != nil {
			continue
		}
		cw := &countWriter{}
		switch err := b.DecryptFile(e.FileID, cw); {
		case err == nil:
			nOK++
		case errors.Is(err, ErrIncompleteFile):
			nIncomplete++
			incomplete = append(incomplete, e.Domain+" / "+e.RelativePath)
		default:
			nOther++
			t.Logf("OTHER-ERROR %s / %s: %v", e.Domain, e.RelativePath, err)
		}
	}
	if err := b.Err(); err != nil {
		t.Fatalf("List: %v", err)
	}
	t.Logf("ok=%d incomplete=%d other=%d", nOK, nIncomplete, nOther)
	t.Log("--- incomplete files ---")
	for _, f := range incomplete {
		t.Logf("  %s", f)
	}
}
