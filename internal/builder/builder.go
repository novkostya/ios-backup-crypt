// Package builder constructs a synthetic *encrypted* iOS backup on disk: a valid keybag, a
// wrapped Manifest key, an AES-CBC-encrypted Manifest.db (a real SQLite database with a
// Files table), and a binary Manifest.plist. The encrypt path here is the mirror image of
// the library's decrypt path, so a backup this package writes is exactly what the library
// must be able to read back.
//
// IT STAYS UNDER internal/ AND IS EXPORTED BY A WRAPPER — the `fixture` module, a separate
// module in this repository, re-exports it for consumers. That indirection buys the one
// thing a straight move cannot: the dependency runs ONE WAY.
//
// A move would put this package in the fixture module, and then the root module's own tests
// — which need it to build the backups they decrypt — would have to `require` that module
// back. A `replace` makes that work locally and ONLY locally: `replace` is honored in the
// main module alone, so a consumer inherits the `require` on a version that does not exist.
// Measured rather than reasoned: a scratch consumer of this root module gets
// `go list -m all` → "github.com/novkostya/ios-backup-crypt/fixture@v0.0.0: invalid
// version: unknown revision fixture/v0.0.0", while `go build` survives on graph pruning —
// so the breakage hides from the command people run and appears in the ones tooling runs.
//
// Left here, the root module requires nothing new, and `fixture` depends on the root. The
// arrow points one way and there is no placeholder version anywhere.
package builder

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // register the cgo-free "sqlite" driver

	"github.com/novkostya/ios-backup-crypt/internal/aescbc"
	"github.com/novkostya/ios-backup-crypt/internal/aeskw"
	"howett.net/plist"
)

// DefaultPassword is used when Spec.Password is empty.
const DefaultPassword = "test"

// protectionClass is the single protection class the fixture uses for both the Manifest
// key and file keys (NSFileProtectionCompleteUntilFirstUserAuthentication).
const protectionClass uint32 = 4

// wrapPassphrase marks a class key wrapped by the passphrase-derived KEK.
const wrapPassphrase = 2

// File is one row to place in the fixture's Files table. When Data is non-nil the
// builder writes an encrypted on-disk blob and a full file record with an EncryptionKey;
// when Data is nil (a directory) it writes a keyless record with size 0.
type File struct {
	Domain       string
	RelativePath string
	Flags        int64 // 1 = file, 2 = directory (iOS convention)
	Data         []byte

	// MTime, when non-zero, is written as the record's LastModified. Left zero, the record
	// carries NO LastModified at all — which is the case a consumer most needs to be able to
	// build, because the field is optional in the real format and "absent" is the state that
	// gets mishandled. A fixture that could only produce records WITH a timestamp could not
	// test the branch that matters.
	MTime time.Time

	// BadRecord writes an UNDECODABLE `file` blob for this row instead of a valid
	// NSKeyedArchiver record. The row still appears in the Files table with its domain,
	// path and flags; only its metadata is unreadable.
	//
	// A fixture generator exists to build inputs for tests, and the inputs hardest to come
	// by are the broken ones — a real backup with a corrupt record is not something anybody
	// can produce on demand, and the handling of one is exactly the behavior nobody
	// exercises until it happens. Data is ignored when this is set: there is no key to
	// encrypt with once the record is gone.
	BadRecord bool
}

// Spec describes the synthetic backup to build.
type Spec struct {
	Password       string // defaults to DefaultPassword
	DeviceName     string // → Manifest.plist Lockdown.DeviceName
	ProductVersion string // → Manifest.plist Lockdown.ProductVersion (iOS version)

	// The rest of Manifest.plist's Lockdown dict. Left zero, each is simply absent from the
	// generated plist, which is the state a consumer most needs to be able to build: these
	// fields are optional in the real format and a fixture that could only produce them
	// PRESENT could not test the branch that reads one that is missing.
	DeviceClass    string // → Lockdown.DeviceClass ("iPhone", "iPad", …)
	ProductType    string // → Lockdown.ProductType (model identifier)
	BuildVersion   string // → Lockdown.BuildVersion
	SerialNumber   string // → Lockdown.SerialNumber
	UniqueDeviceID string // → Lockdown.UniqueDeviceID

	// Status and Info generate the OTHER TWO plists a real backup carries. Both are nil or
	// zero by default, so an existing caller keeps getting exactly the two files it always
	// got — a backup with neither is itself a state a reader must handle.
	Status StatusInfo
	Info   *DeviceExtras
	Files  []File
	// KDF work factors — kept small so tests are fast (real backups use DPIC ≈ 1e7).
	// Zero values default to DPIC=4096, ITER=4096. Ignored when Unencrypted.
	DPIC, ITER uint32

	// Unencrypted builds a backup with NO encryption anywhere: a plain SQLite Manifest.db,
	// a Manifest.plist with IsEncrypted false and neither BackupKeyBag nor ManifestKey, and
	// plaintext on-disk blobs. Password, DPIC and ITER are ignored.
	//
	// IT IS THE SAME FILE RECORDS, and that is the point of building it here rather than in
	// a consumer. Measured on a real unencrypted iPad backup: the `Files` schema is
	// identical and each `file` blob is the same NSKeyedArchiver MBFile graph, carrying
	// Size, LastModified, ProtectionClass, Flags, Mode, Birth, RelativePath, InodeNumber,
	// UserID and GroupID — the ONLY difference is that EncryptionKey is absent, which is
	// already how this builder writes a directory. A consumer that needed an unencrypted
	// fixture would otherwise have to write MBFile records itself, which is a second WRITER
	// of the format to sit beside the second READER that #8 exists to prevent. A fixture
	// that builds records slightly wrong makes a conformance suite agree with a bug.
	Unencrypted bool
}

// WrittenFile records a row placed in the Files table, including its computed fileID.
type WrittenFile struct {
	FileID       string
	Domain       string
	RelativePath string
	Flags        int64
}

// Result reports what Build wrote.
type Result struct {
	Password string
	Files    []WrittenFile
}

// Build writes Manifest.plist and a Manifest.db into dir — encrypted, or plaintext when
// Spec.Unencrypted is set.
func Build(dir string, spec Spec) (*Result, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if spec.Unencrypted {
		return buildUnencrypted(dir, spec)
	}
	if spec.Password == "" {
		spec.Password = DefaultPassword
	}
	if spec.DPIC == 0 {
		spec.DPIC = 4096
	}
	if spec.ITER == 0 {
		spec.ITER = 4096
	}

	// Random salts + keys.
	dpsl, err := randBytes(20)
	if err != nil {
		return nil, err
	}
	salt, err := randBytes(20)
	if err != nil {
		return nil, err
	}
	classKey, err := randBytes(32)
	if err != nil {
		return nil, err
	}
	manifestKey, err := randBytes(32)
	if err != nil {
		return nil, err
	}

	// Keybag: wrap the class key under the password-derived KEK.
	kek, err := deriveKEK(spec.Password, dpsl, spec.DPIC, salt, spec.ITER)
	if err != nil {
		return nil, err
	}
	keybagBlob, err := buildKeybag(kek, dpsl, salt, spec.DPIC, spec.ITER, classKey)
	if err != nil {
		return nil, err
	}

	// ManifestKey: wrap the Manifest AES key under the class key, prefixed with the
	// little-endian protection class (the on-disk Manifest.plist layout).
	wrappedManifest, err := aeskw.Wrap(classKey, manifestKey)
	if err != nil {
		return nil, err
	}
	manifestKeyField := make([]byte, 4+len(wrappedManifest))
	binary.LittleEndian.PutUint32(manifestKeyField[:4], protectionClass)
	copy(manifestKeyField[4:], wrappedManifest)

	// Manifest.db: a real SQLite Files table (with per-file records and on-disk
	// encrypted blobs), AES-CBC-encrypted under the Manifest key.
	written, dbBytes, err := buildManifestDB(dir, classKey, spec.Files)
	if err != nil {
		return nil, err
	}
	if len(dbBytes)%16 != 0 {
		return nil, fmt.Errorf("builder: SQLite file size %d is not block-aligned", len(dbBytes))
	}
	var enc bytes.Buffer
	if _, err := aescbc.EncryptStream(&enc, bytes.NewReader(dbBytes), manifestKey, make([]byte, 16)); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "Manifest.db"), enc.Bytes(), 0o600); err != nil {
		return nil, err
	}

	// Manifest.plist (binary).
	mp := map[string]any{
		"IsEncrypted":  true,
		"BackupKeyBag": keybagBlob,
		"ManifestKey":  manifestKeyField,
		"Version":      "10.0",
		"Lockdown":     lockdownDict(spec),
	}
	plistBytes, err := plist.Marshal(mp, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "Manifest.plist"), plistBytes, 0o600); err != nil {
		return nil, err
	}
	if err := writeStatusPlist(dir, spec.Status); err != nil {
		return nil, err
	}
	if err := writeInfoPlist(dir, spec); err != nil {
		return nil, err
	}

	return &Result{Password: spec.Password, Files: written}, nil
}

// buildKeybag assembles the header + one passphrase-wrapped class-key block.
func buildKeybag(kek, dpsl, salt []byte, dpic, iter uint32, classKey []byte) ([]byte, error) {
	wpky, err := aeskw.Wrap(kek, classKey)
	if err != nil {
		return nil, err
	}
	uuid1, err := randBytes(16)
	if err != nil {
		return nil, err
	}
	uuid2, err := randBytes(16)
	if err != nil {
		return nil, err
	}
	hmck, err := randBytes(40)
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	b.Write(tlvU32("VERS", 4))
	b.Write(tlvU32("TYPE", 1)) // backup keybag
	b.Write(tlv("UUID", uuid1))
	b.Write(tlv("HMCK", hmck))
	b.Write(tlvU32("WRAP", 0))
	b.Write(tlv("SALT", salt))
	b.Write(tlvU32("ITER", iter))
	b.Write(tlvU32("DPWT", 1))
	b.Write(tlvU32("DPIC", dpic))
	b.Write(tlv("DPSL", dpsl))
	// Class-key block (the second UUID opens it).
	b.Write(tlv("UUID", uuid2))
	b.Write(tlvU32("CLAS", protectionClass))
	b.Write(tlvU32("WRAP", wrapPassphrase))
	b.Write(tlvU32("KTYP", 0))
	b.Write(tlv("WPKY", wpky))
	return b.Bytes(), nil
}

// buildManifestDB creates a SQLite database with a Files table, inserts a row (with its
// NSKeyedArchiver file record) per entry, writes each file's encrypted on-disk blob into
// dir, and returns the recorded rows plus the raw database bytes.
func buildManifestDB(dir string, classKey []byte, files []File) ([]WrittenFile, []byte, error) {
	tmp, err := os.CreateTemp("", "iosbackup-build-*.db")
	if err != nil {
		return nil, nil, err
	}
	path := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(path) }()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, nil, err
	}
	if _, err := db.Exec(`CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)`); err != nil {
		_ = db.Close()
		return nil, nil, err
	}

	// ONE TRANSACTION FOR THE WHOLE LOOP, and it is a usability property rather than a
	// micro-optimisation. SQLite gives every statement its own implicit transaction, so a
	// per-row Exec pays a durability barrier per row: measured at 9.88 ms/row against
	// 0.013 ms/row here — 776x — which is 15m20s versus ~1.3s for the 100,000-row fixture a
	// consumer needs to test anything at real-backup scale (novkostya/quince#1444). A
	// generator that cannot build a realistic fixture in CI pushes consumers toward
	// committing a large binary or skipping the gate, which is what this package exists to
	// prevent.
	//
	// It changes no durability guarantee for the artifact: the file is read whole and
	// re-encrypted afterwards, so nothing observes an intermediate state.
	tx, err := db.Begin()
	if err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	insert, err := tx.Prepare(`INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, nil, err
	}

	written := make([]WrittenFile, 0, len(files))
	for _, f := range files {
		id := fileID(f.Domain, f.RelativePath)
		record, err := buildFileRecord(dir, id, classKey, f)
		if err != nil {
			_ = insert.Close()
			_ = tx.Rollback()
			_ = db.Close()
			return nil, nil, err
		}
		if _, err := insert.Exec(id, f.Domain, f.RelativePath, f.Flags, record); err != nil {
			_ = insert.Close()
			_ = tx.Rollback()
			_ = db.Close()
			return nil, nil, err
		}
		written = append(written, WrittenFile{FileID: id, Domain: f.Domain, RelativePath: f.RelativePath, Flags: f.Flags})
	}
	if err := insert.Close(); err != nil {
		_ = tx.Rollback()
		_ = db.Close()
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		_ = db.Close()
		return nil, nil, err
	}
	if err := db.Close(); err != nil {
		return nil, nil, err
	}

	dbBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	return written, dbBytes, nil
}

// buildFileRecord builds the NSKeyedArchiver blob for one Files row. For a file (Data
// non-nil) it also generates a per-file key, wraps it under the class key into the
// EncryptionKey object, and writes the AES-CBC-encrypted (PKCS#7-padded) content to
// <dir>/<id[:2]>/<id>. Directories get a keyless, size-0 record.
func buildFileRecord(dir, id string, classKey []byte, f File) ([]byte, error) {
	if f.BadRecord {
		// Deliberately not a plist. The row is otherwise ordinary, which is the point:
		// everything but the metadata is still readable.
		return []byte("this is not an NSKeyedArchiver blob"), nil
	}
	record := map[string]any{
		"Size":            len(f.Data),
		"ProtectionClass": int(protectionClass),
		"RelativePath":    f.RelativePath,
	}
	// Written ONLY when set, so that a zero MTime produces a record with no LastModified
	// key at all — the optional-field case a consumer needs to be able to construct.
	if !f.MTime.IsZero() {
		record["LastModified"] = f.MTime.Unix()
	}
	objects := []any{"$null", record}

	if f.Data != nil {
		if classKey == nil {
			// UNENCRYPTED: the blob goes down as plaintext and the record carries NO
			// EncryptionKey — which is exactly the keyless shape this function already
			// writes for a directory, and exactly what a real unencrypted backup holds for
			// every entry including ordinary files.
			if err := writePlainBlob(dir, id, f.Data); err != nil {
				return nil, err
			}
		} else {
			fileKey, err := randBytes(32)
			if err != nil {
				return nil, err
			}
			wrapped, err := aeskw.Wrap(classKey, fileKey)
			if err != nil {
				return nil, err
			}
			encKeyData := make([]byte, 4+len(wrapped))
			binary.LittleEndian.PutUint32(encKeyData[:4], protectionClass)
			copy(encKeyData[4:], wrapped)

			objects = append(objects, map[string]any{"NS.data": encKeyData})
			record["EncryptionKey"] = plist.UID(len(objects) - 1)

			if err := writeEncryptedBlob(dir, id, fileKey, f.Data); err != nil {
				return nil, err
			}
		}
	}

	archive := map[string]any{
		"$version":  100000,
		"$archiver": "NSKeyedArchiver",
		"$top":      map[string]any{"root": plist.UID(1)},
		"$objects":  objects,
	}
	return plist.Marshal(archive, plist.BinaryFormat)
}

// writeEncryptedBlob PKCS#7-pads data to the AES block size, AES-CBC-encrypts it under
// fileKey (zero IV), and writes it to <dir>/<id[:2]>/<id>.
func writeEncryptedBlob(dir, id string, fileKey, data []byte) error {
	var enc bytes.Buffer
	if _, err := aescbc.EncryptStream(&enc, bytes.NewReader(pkcs7Pad(data, 16)), fileKey, make([]byte, 16)); err != nil {
		return err
	}
	sub := filepath.Join(dir, id[:2])
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sub, id), enc.Bytes(), 0o600)
}

// pkcs7Pad appends PKCS#7 padding (always 1..block bytes, matching iOS's per-file
// encryption) so the result is a whole number of blocks.
func pkcs7Pad(data []byte, block int) []byte {
	n := block - len(data)%block
	out := make([]byte, len(data)+n)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(n)
	}
	return out
}

// fileID mirrors iOS's on-disk naming: SHA-1 of "domain-relativePath", hex-encoded.
func fileID(domain, relativePath string) string {
	sum := sha1.Sum([]byte(domain + "-" + relativePath))
	return hex.EncodeToString(sum[:])
}

// deriveKEK is the two-stage PBKDF2 KDF, written independently of the library's own so
// the round-trip genuinely cross-checks it.
func deriveKEK(password string, dpsl []byte, dpic uint32, salt []byte, iter uint32) ([]byte, error) {
	r1, err := pbkdf2.Key(sha256.New, password, dpsl, int(dpic), 32)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha1.New, string(r1), salt, int(iter), 32)
}

func tlv(tag string, val []byte) []byte {
	b := make([]byte, 8+len(val))
	copy(b[:4], tag)
	binary.BigEndian.PutUint32(b[4:8], uint32(len(val)))
	copy(b[8:], val)
	return b
}

func tlvU32(tag string, v uint32) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return tlv(tag, b[:])
}

func randBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// buildUnencrypted writes a backup with no encryption anywhere: a plain SQLite Manifest.db,
// plaintext on-disk blobs, and a Manifest.plist declaring IsEncrypted false with neither a
// keybag nor a ManifestKey.
//
// It shares buildManifestDB and buildFileRecord with the encrypted path rather than
// duplicating them — a nil classKey is the whole of the difference — so the two kinds of
// fixture cannot drift in the one thing a consumer reads from both: the file record.
func buildUnencrypted(dir string, spec Spec) (*Result, error) {
	written, dbBytes, err := buildManifestDB(dir, nil, spec.Files)
	if err != nil {
		return nil, err
	}
	// Written as-is: no cipher, so no block alignment to satisfy and no padding. That is
	// also why a consumer can check a recorded Size against the on-disk length here and
	// cannot on an encrypted backup, where the blob is padded.
	if err := os.WriteFile(filepath.Join(dir, "Manifest.db"), dbBytes, 0o600); err != nil {
		return nil, err
	}

	mp := map[string]any{
		"IsEncrypted": false,
		"Version":     "10.0",
		"Lockdown":    lockdownDict(spec),
	}
	plistBytes, err := plist.Marshal(mp, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "Manifest.plist"), plistBytes, 0o600); err != nil {
		return nil, err
	}
	if err := writeStatusPlist(dir, spec.Status); err != nil {
		return nil, err
	}
	if err := writeInfoPlist(dir, spec); err != nil {
		return nil, err
	}

	// Password is empty rather than DefaultPassword: there is nothing to unlock, and
	// returning a password for a backup that takes none is the "field that silently
	// validates nothing" the seam refuses to have.
	return &Result{Files: written}, nil
}

// writePlainBlob writes data verbatim to <dir>/<id[:2]>/<id> — the unencrypted backup's
// on-disk form, where the stored length IS the plaintext length.
func writePlainBlob(dir, id string, data []byte) error {
	sub := filepath.Join(dir, id[:2])
	if err := os.MkdirAll(sub, 0o700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(sub, id), data, 0o600)
}

// lockdownDict builds Manifest.plist's Lockdown dict, omitting every field left zero.
//
// ONE HELPER FOR BOTH WRITERS. The encrypted and unencrypted paths each write their own
// Manifest.plist, and a field added to one and forgotten in the other is a fixture that
// silently tests less than it appears to on whichever path the author was not looking at.
//
// Omission is deliberate rather than incidental: these keys are optional in the real
// format, so a zero value writing an EMPTY STRING would make "absent" unbuildable, and
// absent is the case a reader is most likely to get wrong.
func lockdownDict(spec Spec) map[string]any {
	d := map[string]any{
		"DeviceName":     spec.DeviceName,
		"ProductVersion": spec.ProductVersion,
	}
	for k, v := range map[string]string{
		"DeviceClass":    spec.DeviceClass,
		"ProductType":    spec.ProductType,
		"BuildVersion":   spec.BuildVersion,
		"SerialNumber":   spec.SerialNumber,
		"UniqueDeviceID": spec.UniqueDeviceID,
	} {
		if v != "" {
			d[k] = v
		}
	}
	return d
}

// Info.plist and Status.plist are the OTHER TWO plists a real backup carries, and until now
// this generator wrote neither. Both are unencrypted, so a consumer can read them without a
// password — which is exactly why a fixture needs to be able to produce them: the code paths
// that read them are reachable on a LOCKED backup, and a generator that cannot build one
// leaves that whole tier untestable.
//
// THE ON-DISK FORMATS ARE NOT THE SAME, and the fixture matches what iOS actually writes
// rather than picking one for convenience: measured on two real backups (an iPad and an
// iPhone), Info.plist is XML and Status.plist is binary, while Manifest.plist is binary.
// A reader that only ever met this generator's output would otherwise never meet an XML
// plist at all, and would pass its tests while failing on every real backup.

// StatusInfo is Status.plist — six keys, 189 bytes on both real backups measured. Left
// zero, Build writes no Status.plist at all, because "the file is missing" is a state a
// reader has to handle and a fixture must be able to build.
type StatusInfo struct {
	BackupState   string // e.g. "new"
	Date          time.Time
	IsFullBackup  bool   // full vs incremental — a fact quince cannot show today
	SnapshotState string // e.g. "finished"
	UUID          string
	Version       string // the backup FORMAT version, e.g. "3.3" — not the iOS version
}

// DeviceExtras is the part of Info.plist that is not already in Spec's Lockdown fields.
//
// IMEI, ICCID and PhoneNumber are present on a phone and absent on an iPad — measured — so
// they are optional here for the same reason the Lockdown extras are: absent is a real state
// and a fixture that could not build it would leave the branch untested.
type DeviceExtras struct {
	DisplayName           string
	GUID                  string
	TargetIdentifier      string
	TargetType            string // e.g. "Device"
	ITunesVersion         string
	LastBackupDate        time.Time
	InstalledApplications []string // bundle ids, the USER-INSTALLED list

	IMEI        string
	ICCID       string
	PhoneNumber string
}

// writeStatusPlist writes Status.plist (binary, as iOS does). A zero StatusInfo writes
// nothing — see StatusInfo.
func writeStatusPlist(dir string, s StatusInfo) error {
	if s.IsZero() {
		return nil
	}
	m := map[string]any{
		"BackupState":   s.BackupState,
		"IsFullBackup":  s.IsFullBackup,
		"SnapshotState": s.SnapshotState,
		"UUID":          s.UUID,
		"Version":       s.Version,
	}
	if !s.Date.IsZero() {
		m["Date"] = s.Date
	}
	b, err := plist.Marshal(m, plist.BinaryFormat)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "Status.plist"), b, 0o600)
}

// writeInfoPlist writes Info.plist (XML, as iOS does). Nothing is written when the spec
// asks for none, so "no Info.plist" stays buildable.
//
// The device fields are taken from Spec rather than duplicated in DeviceExtras: a real
// Info.plist and a real Manifest.plist agree about the device, and a fixture that let them
// disagree would invite a reader to prefer one arbitrarily and never notice.
func writeInfoPlist(dir string, spec Spec) error {
	e := spec.Info
	if e == nil {
		return nil
	}
	m := map[string]any{
		"Device Name":     spec.DeviceName,
		"Product Version": spec.ProductVersion,
		"Target Type":     e.TargetType,
	}
	for k, v := range map[string]string{
		"Display Name":      e.DisplayName,
		"GUID":              e.GUID,
		"Target Identifier": e.TargetIdentifier,
		"iTunes Version":    e.ITunesVersion,
		"Build Version":     spec.BuildVersion,
		"Product Type":      spec.ProductType,
		"Serial Number":     spec.SerialNumber,
		"Unique Identifier": spec.UniqueDeviceID,
		"IMEI":              e.IMEI,
		"ICCID":             e.ICCID,
		"Phone Number":      e.PhoneNumber,
	} {
		if v != "" {
			m[k] = v
		}
	}
	if !e.LastBackupDate.IsZero() {
		m["Last Backup Date"] = e.LastBackupDate
	}
	if len(e.InstalledApplications) > 0 {
		apps := make([]any, 0, len(e.InstalledApplications))
		// Applications mirrors Installed Applications on a real backup — one entry per
		// installed bundle id. The per-app value is metadata this library does not model,
		// so it is written as an empty dict rather than invented.
		perApp := map[string]any{}
		for _, id := range e.InstalledApplications {
			apps = append(apps, id)
			perApp[id] = map[string]any{}
		}
		m["Installed Applications"] = apps
		m["Applications"] = perApp
	}
	b, err := plist.Marshal(m, plist.XMLFormat)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "Info.plist"), b, 0o600)
}

// IsZero reports that nothing was set, so Build writes no Status.plist.
//
// Field by field rather than `s == StatusInfo{}`: struct equality on a time.Time compares
// the monotonic reading too, which is not what "unset" means and is not a comparison the
// time package wants anyone making.
func (s StatusInfo) IsZero() bool {
	return s.BackupState == "" &&
		s.SnapshotState == "" &&
		s.UUID == "" &&
		s.Version == "" &&
		!s.IsFullBackup &&
		s.Date.IsZero()
}
