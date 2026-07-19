// Package keybag parses an iOS backup keybag and recovers its protection-class keys.
//
// A keybag is the flat TLV blob stored under Manifest.plist's BackupKeyBag key: a
// header (VERS/TYPE/UUID/HMCK/WRAP/SALT/ITER plus the double-protection DPWT/DPIC/DPSL)
// followed by one block per protection class (UUID/CLAS/WRAP/WPKY/KTYP/…). Unlock runs
// the two-stage PBKDF2 KDF over the backup password to derive the key-encryption key,
// then RFC 3394-unwraps each passphrase-protected class key. UnwrapKeyForClass unwraps
// individual Manifest / per-file keys with the recovered class key.
package keybag

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/novkostya/ios-backup-crypt/internal/aeskw"
)

// wrapPassphrase is the WRAP-flag bit marking a class key wrapped by the
// passphrase-derived KEK (as opposed to the hardware device key). Only class keys with
// this bit set can be recovered from the backup password alone.
const wrapPassphrase = 2

// wrappedKeyLen is the length of a wrapped per-file / Manifest key: a 32-byte key
// becomes 40 bytes under RFC 3394 (five 64-bit semiblocks).
const wrappedKeyLen = 0x28

var (
	// ErrInvalidKeybag reports a structurally malformed keybag blob.
	ErrInvalidKeybag = errors.New("keybag: malformed blob")
	// ErrMissingKDFParams reports a keybag lacking the double-protection KDF fields
	// (DPSL/DPIC/SALT/ITER) needed to derive the KEK from a password.
	ErrMissingKDFParams = errors.New("keybag: missing KDF parameters (DPSL/DPIC/SALT/ITER)")
	// ErrWrongPassword reports that no passphrase-wrapped class key could be unwrapped
	// with the derived KEK — almost always a wrong backup password.
	ErrWrongPassword = errors.New("keybag: wrong password (no class keys unwrapped)")
	// ErrClassNotFound reports a request for a protection class absent from the keybag.
	ErrClassNotFound = errors.New("keybag: protection class not found")
	// ErrClassLocked reports a class key not unwrapped by Unlock (wrong password, or a
	// class that is not passphrase-wrapped).
	ErrClassLocked = errors.New("keybag: class key is locked (call Unlock first)")
	// ErrKeyLen reports a wrapped key of unexpected length.
	ErrKeyLen = errors.New("keybag: wrapped key has invalid length")
)

// classKey is one per-protection-class entry. Only the fields the decrypt path needs
// are retained; other class tags (UUID/KTYP/PBKY) are recognized but discarded.
type classKey struct {
	clas uint32
	wrap uint32
	wpky []byte // wrapped class key (empty if this class is not wrapped)
	key  []byte // unwrapped class key, populated by Unlock
}

// Keybag is a parsed iOS backup keybag: header attributes plus the per-class wrapped
// keys.
type Keybag struct {
	Type uint32 // keybag TYPE (backup keybags are type 1)
	UUID []byte // keybag UUID
	Wrap uint32 // header-level WRAP policy

	attrs     map[string][]byte    // header TLV values (SALT/ITER/DPSL/DPIC/HMCK/…)
	classKeys map[uint32]*classKey // keyed by protection class (CLAS)
}

// Parse decodes a keybag TLV blob (the Manifest.plist BackupKeyBag value). The format
// is a flat sequence of records — a 4-byte tag, a 4-byte big-endian length, then the
// value. Header fields come first; the second and later UUID tags each begin a new
// protection-class block.
func Parse(blob []byte) (*Keybag, error) {
	kb := &Keybag{
		attrs:     make(map[string][]byte),
		classKeys: make(map[uint32]*classKey),
	}

	var cur *classKey
	commit := func() {
		if cur != nil {
			kb.classKeys[cur.clas] = cur
			cur = nil
		}
	}

	i := 0
	for i+8 <= len(blob) {
		tag := string(blob[i : i+4])
		length := int(binary.BigEndian.Uint32(blob[i+4 : i+8]))
		i += 8
		if i+length > len(blob) {
			return nil, fmt.Errorf("%w: tag %q length %d overruns blob", ErrInvalidKeybag, tag, length)
		}
		val := blob[i : i+length]
		i += length

		switch {
		case tag == "TYPE" && cur == nil:
			kb.Type = be32(val)
		case tag == "UUID" && kb.UUID == nil:
			// First UUID is the keybag's own; once past it, cur != nil so this
			// branch is never taken again.
			kb.UUID = bytes.Clone(val)
		case tag == "WRAP" && cur == nil:
			kb.Wrap = be32(val)
		case tag == "UUID":
			// A UUID past the header opens a new class-key block.
			commit()
			cur = &classKey{}
		case tag == "CLAS" && cur != nil:
			cur.clas = be32(val)
		case tag == "WRAP" && cur != nil:
			cur.wrap = be32(val)
		case tag == "WPKY" && cur != nil:
			cur.wpky = bytes.Clone(val)
		case (tag == "KTYP" || tag == "PBKY") && cur != nil:
			// Class-scoped but unused by the decrypt path; recognize so they do not
			// leak into the header attributes.
		default:
			kb.attrs[tag] = bytes.Clone(val)
		}
	}
	commit()

	if len(kb.classKeys) == 0 {
		return nil, fmt.Errorf("%w: no protection-class keys", ErrInvalidKeybag)
	}
	return kb, nil
}

// Unlock derives the key-encryption key from the backup password (the slow two-stage
// PBKDF2) and RFC 3394-unwraps every passphrase-wrapped class key. It returns
// ErrWrongPassword if no class key unwraps, and ErrMissingKDFParams if the keybag lacks
// the double-protection KDF fields. Unlock is idempotent.
func (kb *Keybag) Unlock(password string) error {
	dpsl := kb.attrs["DPSL"]
	dpic := kb.attrUint32("DPIC")
	salt := kb.attrs["SALT"]
	iter := kb.attrUint32("ITER")
	if len(dpsl) == 0 || dpic == 0 || len(salt) == 0 || iter == 0 {
		return ErrMissingKDFParams
	}

	kek, err := deriveKEK(password, dpsl, dpic, salt, iter)
	if err != nil {
		return err
	}

	unwrapped := 0
	for _, ck := range kb.classKeys {
		if len(ck.wpky) == 0 || ck.wrap&wrapPassphrase == 0 {
			continue
		}
		key, err := aeskw.Unwrap(kek, ck.wpky)
		if err != nil {
			// The KEK failed a passphrase-wrapped key's integrity check: the
			// password is wrong (a correct password unwraps every such key).
			return ErrWrongPassword
		}
		ck.key = key
		unwrapped++
	}
	if unwrapped == 0 {
		return ErrWrongPassword
	}
	return nil
}

// UnwrapKeyForClass unwraps a wrapped per-file or Manifest key with the (already
// unlocked) class key for the given protection class. wrappedKey is the wrapped key
// bytes — e.g. the Manifest.plist ManifestKey minus its 4-byte class prefix, or a
// file's EncryptionKey. Call Unlock first.
func (kb *Keybag) UnwrapKeyForClass(class uint32, wrappedKey []byte) ([]byte, error) {
	ck, ok := kb.classKeys[class]
	if !ok {
		return nil, ErrClassNotFound
	}
	if len(ck.key) == 0 {
		return nil, ErrClassLocked
	}
	if len(wrappedKey) != wrappedKeyLen {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrKeyLen, len(wrappedKey), wrappedKeyLen)
	}
	return aeskw.Unwrap(ck.key, wrappedKey)
}

// attrUint32 reads a header attribute as a big-endian uint32 (0 if absent).
func (kb *Keybag) attrUint32(tag string) uint32 { return be32(kb.attrs[tag]) }

// be32 reads a big-endian unsigned integer from a keybag value. Integer fields are
// always 4 bytes in practice; shorter/longer values are folded big-endian rather than
// panicking.
func be32(b []byte) uint32 {
	if len(b) == 4 {
		return binary.BigEndian.Uint32(b)
	}
	var v uint32
	for _, c := range b {
		v = v<<8 | uint32(c)
	}
	return v
}
