package keybag

import (
	"bytes"
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/novkostya/ios-backup-crypt/internal/aeskw"
)

// --- keybag blob construction helpers (also the seed of the test-only builder) ---

func tlv(tag string, val []byte) []byte {
	if len(tag) != 4 {
		panic("tag must be 4 bytes")
	}
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

// inlineKEK derives the KEK straight from the primitives, in the known-correct order,
// independent of deriveKEK — so a keybag built with it is a genuine oracle.
func inlineKEK(t *testing.T, pw string, dpsl []byte, dpic uint32, salt []byte, iter uint32) []byte {
	t.Helper()
	r1, err := pbkdf2.Key(sha256.New, pw, dpsl, int(dpic), kekLen)
	if err != nil {
		t.Fatal(err)
	}
	kek, err := pbkdf2.Key(sha1.New, string(r1), salt, int(iter), kekLen)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

// kdf params kept tiny so the test is fast; real backups use DPIC ≈ 10,000,000.
var (
	testDPSL         = []byte("double-protection-salt!!")
	testSALT         = []byte("keybag-header-salt-16b")
	testDPIC  uint32 = 1000
	testITER  uint32 = 1000
	testClass uint32 = 4 // NSFileProtectionCompleteUntilFirstUserAuthentication
)

// buildTestKeybag assembles a minimal but well-formed encrypted-backup keybag: a header
// with double-protection KDF params, and one passphrase-wrapped class key.
func buildTestKeybag(t *testing.T, password string, classKeyPlain []byte) []byte {
	t.Helper()
	kek := inlineKEK(t, password, testDPSL, testDPIC, testSALT, testITER)
	wpky, err := aeskw.Wrap(kek, classKeyPlain)
	if err != nil {
		t.Fatalf("wrap class key: %v", err)
	}

	var b bytes.Buffer
	// Header.
	b.Write(tlvU32("VERS", 4))
	b.Write(tlvU32("TYPE", 1)) // backup keybag
	b.Write(tlv("UUID", bytes.Repeat([]byte{0xA1}, 16)))
	b.Write(tlv("HMCK", bytes.Repeat([]byte{0xB2}, 40)))
	b.Write(tlvU32("WRAP", 0))
	b.Write(tlv("SALT", testSALT))
	b.Write(tlvU32("ITER", testITER))
	b.Write(tlvU32("DPWT", 1))
	b.Write(tlvU32("DPIC", testDPIC))
	b.Write(tlv("DPSL", testDPSL))
	// One class-key block (second UUID opens it).
	b.Write(tlv("UUID", bytes.Repeat([]byte{0xC3}, 16)))
	b.Write(tlvU32("CLAS", testClass))
	b.Write(tlvU32("WRAP", wrapPassphrase))
	b.Write(tlvU32("KTYP", 0))
	b.Write(tlv("WPKY", wpky))
	return b.Bytes()
}

func TestParseHeaderAndClass(t *testing.T) {
	classKeyPlain := bytes.Repeat([]byte{0x11}, 32)
	kb, err := Parse(buildTestKeybag(t, "test", classKeyPlain))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if kb.Type != 1 {
		t.Errorf("Type = %d, want 1", kb.Type)
	}
	if !bytes.Equal(kb.UUID, bytes.Repeat([]byte{0xA1}, 16)) {
		t.Errorf("UUID = %X, want the header UUID", kb.UUID)
	}
	if kb.attrUint32("DPIC") != testDPIC || kb.attrUint32("ITER") != testITER {
		t.Errorf("DPIC=%d ITER=%d, want %d/%d", kb.attrUint32("DPIC"), kb.attrUint32("ITER"), testDPIC, testITER)
	}
	if !bytes.Equal(kb.attrs["DPSL"], testDPSL) {
		t.Errorf("DPSL mismatch")
	}
	if len(kb.classKeys) != 1 {
		t.Fatalf("classKeys = %d, want 1", len(kb.classKeys))
	}
	ck := kb.classKeys[testClass]
	if ck == nil {
		t.Fatalf("class %d not parsed", testClass)
	}
	if ck.wrap&wrapPassphrase == 0 {
		t.Errorf("class WRAP = %d, want passphrase bit set", ck.wrap)
	}
	if len(ck.wpky) != 40 { // 32-byte key wrapped -> 40 bytes
		t.Errorf("WPKY len = %d, want 40", len(ck.wpky))
	}
}

// TestUnlockRoundTrip is the milestone-1 integration proof: TLV parse -> two-stage KDF
// -> RFC 3394 unwrap, then a file-key unwrap with the recovered class key.
func TestUnlockRoundTrip(t *testing.T) {
	classKeyPlain := bytes.Repeat([]byte{0x11}, 32)
	blob := buildTestKeybag(t, "test", classKeyPlain)

	kb, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := kb.Unlock("test"); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	// The class key must come back byte-identical.
	if got := kb.classKeys[testClass].key; !bytes.Equal(got, classKeyPlain) {
		t.Fatalf("recovered class key mismatch:\n got  %X\n want %X", got, classKeyPlain)
	}

	// A per-file key wrapped under the class key must unwrap via UnwrapKeyForClass.
	fileKeyPlain := bytes.Repeat([]byte{0x22}, 32)
	wrappedFileKey, err := aeskw.Wrap(classKeyPlain, fileKeyPlain)
	if err != nil {
		t.Fatalf("wrap file key: %v", err)
	}
	if len(wrappedFileKey) != wrappedKeyLen {
		t.Fatalf("wrapped file key len = %d, want %d", len(wrappedFileKey), wrappedKeyLen)
	}
	got, err := kb.UnwrapKeyForClass(testClass, wrappedFileKey)
	if err != nil {
		t.Fatalf("UnwrapKeyForClass: %v", err)
	}
	if !bytes.Equal(got, fileKeyPlain) {
		t.Fatalf("file key mismatch:\n got  %X\n want %X", got, fileKeyPlain)
	}
}

func TestUnlockWrongPassword(t *testing.T) {
	blob := buildTestKeybag(t, "test", bytes.Repeat([]byte{0x11}, 32))
	kb, err := Parse(blob)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := kb.Unlock("wrong"); err != ErrWrongPassword {
		t.Fatalf("Unlock(wrong): got %v, want ErrWrongPassword", err)
	}
}

func TestUnlockMissingKDFParams(t *testing.T) {
	// A keybag with a class key but no double-protection KDF fields.
	var b bytes.Buffer
	b.Write(tlvU32("TYPE", 1))
	b.Write(tlv("UUID", bytes.Repeat([]byte{0xA1}, 16)))
	b.Write(tlvU32("WRAP", 0))
	b.Write(tlv("UUID", bytes.Repeat([]byte{0xC3}, 16)))
	b.Write(tlvU32("CLAS", testClass))
	b.Write(tlvU32("WRAP", wrapPassphrase))
	b.Write(tlv("WPKY", bytes.Repeat([]byte{0x00}, 40)))

	kb, err := Parse(b.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := kb.Unlock("test"); err != ErrMissingKDFParams {
		t.Fatalf("Unlock: got %v, want ErrMissingKDFParams", err)
	}
}

func TestUnwrapBeforeUnlock(t *testing.T) {
	kb, err := Parse(buildTestKeybag(t, "test", bytes.Repeat([]byte{0x11}, 32)))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, err := kb.UnwrapKeyForClass(testClass, bytes.Repeat([]byte{0}, wrappedKeyLen)); err != ErrClassLocked {
		t.Fatalf("UnwrapKeyForClass before Unlock: got %v, want ErrClassLocked", err)
	}
	if _, err := kb.UnwrapKeyForClass(999, bytes.Repeat([]byte{0}, wrappedKeyLen)); err != ErrClassNotFound {
		t.Fatalf("UnwrapKeyForClass(unknown): got %v, want ErrClassNotFound", err)
	}
}

func TestParseErrors(t *testing.T) {
	// Length field overruns the blob.
	bad := tlv("WPKY", bytes.Repeat([]byte{0}, 40))
	binary.BigEndian.PutUint32(bad[4:8], 1000) // claim 1000 bytes; only 40 present
	if _, err := Parse(bad); err == nil {
		t.Errorf("Parse(overrun): got nil, want error")
	}
	// No class keys at all.
	if _, err := Parse(tlvU32("TYPE", 1)); err == nil {
		t.Errorf("Parse(no classes): got nil, want error")
	}
}
