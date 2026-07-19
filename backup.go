package iosbackup

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"iter"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // register the cgo-free "sqlite" driver

	"github.com/novkostya/ios-backup-crypt/internal/aescbc"
	"github.com/novkostya/ios-backup-crypt/internal/keybag"
)

var (
	// ErrNotEncrypted reports a backup whose Manifest.plist IsEncrypted flag is false.
	// This library decrypts encrypted backups only.
	ErrNotEncrypted = errors.New("iosbackup: backup is not encrypted")
	// ErrLocked reports an operation that needs the backup unlocked first.
	ErrLocked = errors.New("iosbackup: backup is locked (call Unlock first)")
	// ErrFileNotFound reports a Stat/DecryptFile for a fileID absent from the Files
	// table.
	ErrFileNotFound = errors.New("iosbackup: file not found")
	// ErrNotAFile reports a DecryptFile for a record with no encryption key — a
	// directory or symlink, which has no decryptable content.
	ErrNotAFile = errors.New("iosbackup: entry has no encrypted content (directory or symlink)")
)

// FileEntry is one row of the backup's Files table.
type FileEntry struct {
	FileID       string // SHA-1 hex; the file's on-disk name under <backup>/<fileID[:2]>/
	Domain       string
	RelativePath string
	Flags        int64 // 1 = file, 2 = directory, 4 = symlink (iOS convention)
}

// Info summarizes the backed-up device.
type Info struct {
	DeviceName     string
	ProductVersion string // iOS version
	FileCount      int64  // rows in the Files table (0 until unlocked)
}

// Backup is an opened iOS backup directory. Open reads its Manifest.plist and keybag;
// Unlock derives the keys and decrypts Manifest.db. A Backup is not safe for concurrent
// use. Call Close when done to release the decrypted-index temp file.
type Backup struct {
	dir      string
	manifest *manifestPlist
	keybag   *keybag.Keybag

	db     *sql.DB
	dbPath string // temp decrypted Manifest.db, removed by Close
	err    error  // last List iteration error, surfaced via Err
}

// Open reads <backupDir>/Manifest.plist and parses the keybag. The returned Backup is
// locked; call Unlock with the backup password before reading files.
func Open(backupDir string) (*Backup, error) {
	mp, err := readManifestPlist(backupDir)
	if err != nil {
		return nil, err
	}
	if !mp.IsEncrypted {
		return nil, ErrNotEncrypted
	}
	if len(mp.BackupKeyBag) == 0 {
		return nil, errors.New("iosbackup: Manifest.plist has no BackupKeyBag")
	}
	kb, err := keybag.Parse(mp.BackupKeyBag)
	if err != nil {
		return nil, err
	}
	return &Backup{dir: backupDir, manifest: mp, keybag: kb}, nil
}

// Unlock derives the key-encryption key from the password, unwraps the class keys and
// the Manifest key, and decrypts Manifest.db into a temporary SQLite database opened
// read-only. It is idempotent: a second call on an unlocked backup is a no-op.
func (b *Backup) Unlock(password string) error {
	if b.db != nil {
		return nil
	}
	if err := b.keybag.Unlock(password); err != nil {
		return err
	}
	class, wrapped, err := splitManifestKey(b.manifest.ManifestKey)
	if err != nil {
		return err
	}
	manifestKey, err := b.keybag.UnwrapKeyForClass(class, wrapped)
	if err != nil {
		return fmt.Errorf("iosbackup: unwrap Manifest key: %w", err)
	}

	tmpPath, err := b.decryptManifestDB(manifestKey)
	if err != nil {
		return err
	}

	db, err := sql.Open("sqlite", "file:"+tmpPath+"?mode=ro&immutable=1")
	if err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("iosbackup: open decrypted Manifest.db: %w", err)
	}
	b.db = db
	b.dbPath = tmpPath
	return nil
}

// decryptManifestDB streams <dir>/Manifest.db through AES-CBC into a fresh temp file and
// returns its path.
func (b *Backup) decryptManifestDB(manifestKey []byte) (string, error) {
	tmp, err := os.CreateTemp("", "iosbackup-manifest-*.db")
	if err != nil {
		return "", err
	}
	tmpPath := tmp.Name()

	enc, err := os.Open(filepath.Join(b.dir, "Manifest.db"))
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return "", err
	}

	_, decErr := aescbc.DecryptStream(tmp, enc, manifestKey, make([]byte, 16))
	_ = enc.Close()
	if cerr := tmp.Close(); decErr == nil {
		decErr = cerr
	}
	if decErr != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("iosbackup: decrypt Manifest.db: %w", decErr)
	}
	return tmpPath, nil
}

// Close releases the decrypted-index database and removes its temp file.
func (b *Backup) Close() error {
	var err error
	if b.db != nil {
		err = b.db.Close()
		b.db = nil
	}
	if b.dbPath != "" {
		if rerr := os.Remove(b.dbPath); err == nil && rerr != nil && !os.IsNotExist(rerr) {
			err = rerr
		}
		b.dbPath = ""
	}
	return err
}

// List iterates the Files table lazily, filtered by exact domain (empty = any) and a
// relativePath prefix (empty = any), ordered by domain then relativePath. Iteration
// stops on the first error; call Err afterwards to retrieve it. The backup must be
// unlocked.
func (b *Backup) List(domain, prefix string) iter.Seq[FileEntry] {
	return func(yield func(FileEntry) bool) {
		b.err = nil
		if b.db == nil {
			b.err = ErrLocked
			return
		}

		q := "SELECT fileID, domain, relativePath, flags FROM Files"
		var conds []string
		var args []any
		if domain != "" {
			conds = append(conds, "domain = ?")
			args = append(args, domain)
		}
		if prefix != "" {
			conds = append(conds, `relativePath LIKE ? ESCAPE '\'`)
			args = append(args, escapeLike(prefix)+"%")
		}
		if len(conds) > 0 {
			q += " WHERE " + strings.Join(conds, " AND ")
		}
		q += " ORDER BY domain, relativePath"

		rows, err := b.db.Query(q, args...)
		if err != nil {
			b.err = err
			return
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var e FileEntry
			if err := rows.Scan(&e.FileID, &e.Domain, &e.RelativePath, &e.Flags); err != nil {
				b.err = err
				return
			}
			if !yield(e) {
				return
			}
		}
		if err := rows.Err(); err != nil {
			b.err = err
		}
	}
}

// Err returns the error, if any, from the most recent List iteration.
func (b *Backup) Err() error { return b.err }

// Stat returns the Files-table row for the given fileID. The backup must be unlocked.
func (b *Backup) Stat(fileID string) (FileEntry, error) {
	if b.db == nil {
		return FileEntry{}, ErrLocked
	}
	var e FileEntry
	err := b.db.
		QueryRow("SELECT fileID, domain, relativePath, flags FROM Files WHERE fileID = ? LIMIT 1", fileID).
		Scan(&e.FileID, &e.Domain, &e.RelativePath, &e.Flags)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return FileEntry{}, ErrFileNotFound
	case err != nil:
		return FileEntry{}, err
	}
	return e, nil
}

// DecryptFile streams the decrypted contents of the file with the given fileID into w.
// It reads the file's NSKeyedArchiver record from the Files table, unwraps the per-file
// key with the record's protection-class key, opens the on-disk blob at
// <backup>/<fileID[:2]>/<fileID>, and AES-CBC-decrypts it block-at-a-time, truncating to
// the record's stored size (which strips the CBC/PKCS#7 padding). The backup must be
// unlocked. It returns ErrNotAFile for directories/symlinks and ErrFileNotFound for an
// unknown fileID.
func (b *Backup) DecryptFile(fileID string, w io.Writer) error {
	if b.db == nil {
		return ErrLocked
	}
	if len(fileID) < 2 {
		return ErrFileNotFound
	}

	var blob []byte
	switch err := b.db.QueryRow("SELECT file FROM Files WHERE fileID = ? LIMIT 1", fileID).Scan(&blob); {
	case errors.Is(err, sql.ErrNoRows):
		return ErrFileNotFound
	case err != nil:
		return err
	}

	rec, err := decodeFileRecord(blob)
	if err != nil {
		return err
	}
	if rec.encryptionKey == nil {
		return fmt.Errorf("%w: %s", ErrNotAFile, fileID)
	}

	fileKey, err := b.keybag.UnwrapKeyForClass(rec.protectionClass, rec.encryptionKey)
	if err != nil {
		return fmt.Errorf("iosbackup: unwrap file key for %s: %w", fileID, err)
	}

	enc, err := os.Open(filepath.Join(b.dir, fileID[:2], fileID))
	if err != nil {
		return err
	}
	defer func() { _ = enc.Close() }()

	lw := &limitWriter{w: w, remaining: rec.size}
	if _, err := aescbc.DecryptStream(lw, enc, fileKey, make([]byte, 16)); err != nil {
		return fmt.Errorf("iosbackup: decrypt %s: %w", fileID, err)
	}
	if lw.remaining > 0 {
		return fmt.Errorf("iosbackup: %s is %d bytes short of its recorded size %d", fileID, lw.remaining, rec.size)
	}
	return nil
}

// DeviceInfo reports the device name and iOS version (from Manifest.plist, available
// before unlocking) and the Files-table row count (0 until unlocked).
func (b *Backup) DeviceInfo() (Info, error) {
	info := Info{
		DeviceName:     b.manifest.Lockdown.DeviceName,
		ProductVersion: b.manifest.Lockdown.ProductVersion,
	}
	if b.db != nil {
		if err := b.db.QueryRow("SELECT COUNT(*) FROM Files").Scan(&info.FileCount); err != nil {
			return info, err
		}
	}
	return info, nil
}

// escapeLike escapes the LIKE metacharacters in a user-supplied prefix so it matches
// literally (paired with ESCAPE '\' in the query).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// limitWriter forwards at most remaining bytes to w and silently drops the rest — used
// to truncate a CBC-decrypted blob to its recorded plaintext size, discarding the
// trailing block padding. It always reports the full input as consumed so the streaming
// decrypter processes every ciphertext block.
type limitWriter struct {
	w         io.Writer
	remaining int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if l.remaining <= 0 {
		return len(p), nil
	}
	take := int64(len(p))
	if take > l.remaining {
		take = l.remaining
	}
	if _, err := l.w.Write(p[:take]); err != nil {
		return 0, err
	}
	l.remaining -= take
	return len(p), nil
}
