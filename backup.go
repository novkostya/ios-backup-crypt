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
	"time"

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
	// ErrIncompleteFile reports that the recovered content is shorter than the size
	// recorded in the file's metadata. Real backups contain such files when a file was
	// still being written as the backup ran (e.g. a live database captured mid-write):
	// fewer bytes reached the backup than the manifest records. It is advisory —
	// DecryptFile has already written every recovered byte (a usable prefix of the file)
	// before returning it; callers extracting in bulk typically keep the partial and
	// flag it with errors.Is rather than discarding it.
	ErrIncompleteFile = errors.New("iosbackup: recovered content shorter than the recorded size")
)

// FileEntry is one row of the backup's Files table.
type FileEntry struct {
	FileID       string // SHA-1 hex; the file's on-disk name under <backup>/<fileID[:2]>/
	Domain       string
	RelativePath string
	Flags        int64 // 1 = file, 2 = directory, 4 = symlink (iOS convention)

	// Size is the file's recorded length in bytes — the plaintext length, which is what
	// DecryptFile truncates its output to. Directories and symlinks record 0.
	Size int64

	// MTime is the file's last-modified time, or the ZERO Time when the record carries
	// none. Absent is ordinary rather than corrupt: the field is optional in the format and
	// the reference implementation guards every use of it. Check IsZero; do not read a zero
	// value as 1970.
	MTime time.Time
}

// Info summarizes the backed-up device. Every field except FileCount comes from
// Manifest.plist and is available BEFORE Unlock; see DeviceInfo.
type Info struct {
	DeviceName     string
	ProductVersion string // iOS version, e.g. "17.5.1"

	// The rest of Manifest.plist's Lockdown dict. These cost nothing extra: the file is
	// already read and parsed to find the keybag, and these fields were being discarded at
	// the point of parse. A consumer that wants to tell two backups of one device apart —
	// or to say "iPad" rather than guessing from a name — needed a second reader for data
	// this library already had in hand.
	DeviceClass string // "iPhone", "iPad", …
	ProductType string // model identifier, e.g. "iPad13,4" — NOT a marketing name, and
	// this library ships no mapping table for one
	BuildVersion   string // iOS build, e.g. "21F90"
	SerialNumber   string
	UniqueDeviceID string

	// FileCount is the number of rows in the Files table.
	//
	// READ FileCountKnown BEFORE READING THIS. The Files table lives in the encrypted
	// Manifest.db, so the count is unavailable until Unlock — and a plain int64 reports
	// "locked" and "genuinely empty" with the same zero. That ambiguity cannot be resolved
	// by a caller, and a caller that renders it anyway says "0 files" about a perfectly good
	// backup.
	FileCount      int64
	FileCountKnown bool
}

// Backup is an opened iOS backup directory. Open reads its Manifest.plist and keybag;
// Unlock derives the keys and decrypts Manifest.db. A Backup is not safe for concurrent
// use. Call Close when done to release the decrypted-index temp file.
type Backup struct {
	dir      string
	manifest *manifestPlist
	keybag   *keybag.Keybag

	// scratchDir is where the decrypted Manifest.db is written. Empty means the OS
	// temporary directory, which is Go's os.CreateTemp default and this library's
	// historical behavior.
	scratchDir string

	db     *sql.DB
	dbPath string // temp decrypted Manifest.db, removed by Close
	err    error  // last List iteration error, surfaced via Err
}

// An Option configures a Backup at Open time.
type Option func(*Backup)

// WithScratchDir directs the decrypted Manifest.db to dir instead of the OS temporary
// directory. The directory must already exist; Open does not create it.
//
// WHY A CALLER WOULD WANT THIS, since the default works. Unlock decrypts Manifest.db to
// disk, and that file is the complete file index of somebody's phone in plaintext: every
// domain, every path. Close removes it, and Close runs on a clean exit — not on a SIGKILL,
// an OOM, or a panic in a caller's own goroutine.
//
// A caller that already owns a directory it wipes — one it clears on start as well as on
// teardown — can cover the crash case, which no amount of care inside this library can. It
// cannot do that for a path it does not choose. That is the whole of the feature: not
// "somewhere else", but "somewhere the caller has already promised to clean".
//
// It is an OPTION rather than a required argument because the default is correct for the
// ordinary case and this library's public surface is meant to stay small: Open(dir) keeps
// compiling and keeps meaning what it meant.
func WithScratchDir(dir string) Option {
	return func(b *Backup) { b.scratchDir = dir }
}

// Open reads <backupDir>/Manifest.plist and parses the keybag. The returned Backup is
// locked; call Unlock with the backup password before reading files.
func Open(backupDir string, opts ...Option) (*Backup, error) {
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
	b := &Backup{dir: backupDir, manifest: mp, keybag: kb}
	for _, opt := range opts {
		opt(b)
	}
	return b, nil
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
// returns its path. The file lands in the Backup's scratchDir, or the OS temporary
// directory when none was set — see WithScratchDir for why a caller might care.
func (b *Backup) decryptManifestDB(manifestKey []byte) (string, error) {
	tmp, err := os.CreateTemp(b.scratchDir, "iosbackup-manifest-*.db")
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
//
// IT DECODES ONE NSKeyedArchiver BLOB PER ROW, and that is the dominant cost of a walk.
// Size and MTime live only in the `file` column's plist — there is no cheaper source, and
// the reference implementation pays the same price per file. Callers walking a large
// manifest for names alone are paying for metadata they may not want; if that ever matters
// enough to measure, the answer is a second method, not a silently cheaper List.
//
// A ROW WHOSE RECORD WILL NOT DECODE IS STILL YIELDED, with Size 0 and a zero MTime, and
// the error is reported through Err. The alternative — stopping the walk — would make one
// unreadable record hide every file after it in a backup a user is trying to browse, which
// is a worse failure than an entry with missing metadata. Err is how a caller learns the
// listing was imperfect; it is not a reason to discard the part that worked.
func (b *Backup) List(domain, prefix string) iter.Seq[FileEntry] {
	return func(yield func(FileEntry) bool) {
		b.err = nil
		if b.db == nil {
			b.err = ErrLocked
			return
		}

		q := "SELECT fileID, domain, relativePath, flags, file FROM Files"
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
			var blob []byte
			if err := rows.Scan(&e.FileID, &e.Domain, &e.RelativePath, &e.Flags, &blob); err != nil {
				b.err = err
				return
			}
			// A record that will not decode costs this entry its metadata, not the walk.
			if rec, err := decodeFileRecord(blob); err != nil {
				b.err = fmt.Errorf("iosbackup: file record for %s: %w", e.FileID, err)
			} else {
				e.Size, e.MTime = rec.size, rec.mtime
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
// Like List, it decodes the row's NSKeyedArchiver record to fill Size and MTime — for one
// row that cost is negligible.
//
// Unlike List, a record that will not decode is an ERROR here rather than a partial entry:
// Stat is a question about one file, so answering it with silently-missing metadata would
// give the caller no way to tell "this file has no mtime" from "this record is broken".
func (b *Backup) Stat(fileID string) (FileEntry, error) {
	if b.db == nil {
		return FileEntry{}, ErrLocked
	}
	var e FileEntry
	var blob []byte
	err := b.db.
		QueryRow("SELECT fileID, domain, relativePath, flags, file FROM Files WHERE fileID = ? LIMIT 1", fileID).
		Scan(&e.FileID, &e.Domain, &e.RelativePath, &e.Flags, &blob)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return FileEntry{}, ErrFileNotFound
	case err != nil:
		return FileEntry{}, err
	}
	rec, err := decodeFileRecord(blob)
	if err != nil {
		return FileEntry{}, fmt.Errorf("iosbackup: file record for %s: %w", fileID, err)
	}
	e.Size, e.MTime = rec.size, rec.mtime
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
	fi, err := enc.Stat()
	if err != nil {
		return err
	}

	// A complete file's ciphertext is its plaintext size PKCS#7-padded up by a block, so
	// its final block is padding to strip. If the on-disk ciphertext is shorter than
	// that, the file was captured mid-write (e.g. a live database): its final block is
	// real data, not padding, so it is kept as-is. Either way we write the maximum
	// recoverable content, streaming, holding back only the final block.
	tw := &tailWriter{w: w, strip: fi.Size() >= paddedLen(rec.size)}
	if _, err := aescbc.DecryptStream(tw, enc, fileKey, make([]byte, 16)); err != nil {
		return fmt.Errorf("iosbackup: decrypt %s: %w", fileID, err)
	}
	recovered, err := tw.finish()
	if err != nil {
		return fmt.Errorf("iosbackup: decrypt %s: %w", fileID, err)
	}
	if recovered < rec.size {
		return fmt.Errorf("%w: %s (recovered %d of %d bytes)", ErrIncompleteFile, fileID, recovered, rec.size)
	}
	return nil
}

// DeviceInfo reports what is known about the backed-up device.
//
// Everything except the file count comes from Manifest.plist and is available BEFORE
// Unlock, because that file is not encrypted. The file count needs the decrypted index, so
// it is reported as unknown until then — check Info.FileCountKnown rather than testing
// FileCount against zero, which cannot distinguish "locked" from "empty".
func (b *Backup) DeviceInfo() (Info, error) {
	info := Info{
		DeviceName:     b.manifest.Lockdown.DeviceName,
		ProductVersion: b.manifest.Lockdown.ProductVersion,
		DeviceClass:    b.manifest.Lockdown.DeviceClass,
		ProductType:    b.manifest.Lockdown.ProductType,
		BuildVersion:   b.manifest.Lockdown.BuildVersion,
		SerialNumber:   b.manifest.Lockdown.SerialNumber,
		UniqueDeviceID: b.manifest.Lockdown.UniqueDeviceID,
	}
	if b.db != nil {
		if err := b.db.QueryRow("SELECT COUNT(*) FROM Files").Scan(&info.FileCount); err != nil {
			return info, err
		}
		// Set ONLY after the query succeeds: a failed count must not leave a zero looking
		// like an answer, which is the whole point of the flag.
		info.FileCountKnown = true
	}
	return info, nil
}

// escapeLike escapes the LIKE metacharacters in a user-supplied prefix so it matches
// literally (paired with ESCAPE '\' in the query).
func escapeLike(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

const aesBlockSize = 16

// paddedLen is the ciphertext length of a complete file whose plaintext is size bytes:
// PKCS#7 pads up to the next block boundary, adding a whole block when already aligned.
func paddedLen(size int64) int64 {
	return (size/aesBlockSize + 1) * aesBlockSize
}

// tailWriter forwards a CBC-decrypted stream to w while holding back the final block, so
// that at finish it can strip PKCS#7 padding from it (when strip is set and the padding
// is valid) without buffering the whole file. It reports the number of content bytes
// written. When strip is false — a truncated, mid-write file whose last block is real
// data — the final block is written unchanged.
type tailWriter struct {
	w     io.Writer
	strip bool
	buf   []byte
	n     int64
}

func (t *tailWriter) Write(p []byte) (int, error) {
	t.buf = append(t.buf, p...)
	if flush := len(t.buf) - aesBlockSize; flush > 0 {
		if _, err := t.w.Write(t.buf[:flush]); err != nil {
			return 0, err
		}
		t.n += int64(flush)
		t.buf = t.buf[:copy(t.buf, t.buf[flush:])] // retain only the final block
	}
	return len(p), nil
}

func (t *tailWriter) finish() (int64, error) {
	b := t.buf
	if t.strip {
		if k := pkcs7PadLen(b); k > 0 {
			b = b[:len(b)-k]
		}
	}
	if len(b) > 0 {
		if _, err := t.w.Write(b); err != nil {
			return 0, err
		}
		t.n += int64(len(b))
	}
	return t.n, nil
}

// pkcs7PadLen returns the length of valid PKCS#7 padding at the end of b, or 0 if the
// trailing bytes are not valid padding (so nothing is stripped from real data).
func pkcs7PadLen(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	n := int(b[len(b)-1])
	if n < 1 || n > aesBlockSize || n > len(b) {
		return 0
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return 0
		}
	}
	return n
}
