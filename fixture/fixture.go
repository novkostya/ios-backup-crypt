// Package fixture constructs a synthetic *encrypted* iOS backup on disk: a valid keybag,
// a wrapped Manifest key, an AES-CBC-encrypted Manifest.db (a real SQLite database with a
// Files table), and a binary Manifest.plist. The encrypt path here is the mirror image of
// the library's decrypt path, so a backup this package writes is exactly what the library
// must be able to read back.
//
// IT IS PUBLIC, AND THAT IS A DECISION RATHER THAN AN OVERSIGHT. It lived under internal/
// with a comment saying it would never ship, on the ordinary and good reasoning that test
// scaffolding is not API. The case that overturned it: a real encrypted backup is somebody's
// personal data and must never enter a CI run, so a *consumer* of this library that wants
// to test its own code against real encrypted-backup structure has no other way to get one.
// This library already makes exactly that argument for its own operator-local differential;
// the same argument holds one layer up, and nothing else can satisfy it — an encrypt path is
// the only thing that produces a backup a decrypt path can read.
//
// IT IS A SEPARATE MODULE SO THE DECRYPTION API STAYS EXACTLY AS SMALL AS IT WAS — see
// fixture/go.mod. Importing this is opt-in, and `github.com/novkostya/ios-backup-crypt`
// gains no exported identifier at all, so CONTRIBUTING's "keep the public API small" holds
// literally rather than by argument.
//
// IT IS TEST SUPPORT, NOT A BACKUP WRITER, and the distinction bounds what it promises. It
// builds inputs for tests: small files, small KDF work factors, one protection class. It is
// not a tool for producing a backup anything should restore from, and its stability promise
// is the weaker one that goes with that — the decryption API is what this module's version
// number is about.
package fixture

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
}

// Spec describes the synthetic backup to build.
type Spec struct {
	Password       string // defaults to DefaultPassword
	DeviceName     string // → Manifest.plist Lockdown.DeviceName
	ProductVersion string // → Manifest.plist Lockdown.ProductVersion (iOS version)
	Files          []File
	// KDF work factors — kept small so tests are fast (real backups use DPIC ≈ 1e7).
	// Zero values default to DPIC=4096, ITER=4096.
	DPIC, ITER uint32
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

// Build writes Manifest.plist and an encrypted Manifest.db into dir.
func Build(dir string, spec Spec) (*Result, error) {
	if spec.Password == "" {
		spec.Password = DefaultPassword
	}
	if spec.DPIC == 0 {
		spec.DPIC = 4096
	}
	if spec.ITER == 0 {
		spec.ITER = 4096
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
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
		"Lockdown": map[string]any{
			"DeviceName":     spec.DeviceName,
			"ProductVersion": spec.ProductVersion,
		},
	}
	plistBytes, err := plist.Marshal(mp, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "Manifest.plist"), plistBytes, 0o600); err != nil {
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

	written := make([]WrittenFile, 0, len(files))
	for _, f := range files {
		id := fileID(f.Domain, f.RelativePath)
		record, err := buildFileRecord(dir, id, classKey, f)
		if err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		if _, err := db.Exec(
			`INSERT INTO Files (fileID, domain, relativePath, flags, file) VALUES (?,?,?,?,?)`,
			id, f.Domain, f.RelativePath, f.Flags, record,
		); err != nil {
			_ = db.Close()
			return nil, nil, err
		}
		written = append(written, WrittenFile{FileID: id, Domain: f.Domain, RelativePath: f.RelativePath, Flags: f.Flags})
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
	record := map[string]any{
		"Size":            len(f.Data),
		"ProtectionClass": int(protectionClass),
		"RelativePath":    f.RelativePath,
	}
	objects := []any{"$null", record}

	if f.Data != nil {
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
