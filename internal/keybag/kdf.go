package keybag

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
)

// kekLen is the byte length of the derived key-encryption key (AES-256).
const kekLen = 32

// deriveKEK reproduces the iOS backup key-derivation function: the two-stage PBKDF2
// that makes unlocking deliberately slow.
//
//	stage 1: PBKDF2-HMAC-SHA256(password, DPSL, DPIC)  // DPIC ≈ 10,000,000 on-device
//	stage 2: PBKDF2-HMAC-SHA1(stage1, SALT, ITER)      // ITER ≈ 10,000
//
// Both stages emit 32 bytes; the stage-2 output is the KEK that unwraps the keybag's
// passphrase-protected class keys. The order and hash choice matter — they are pinned
// by the PBKDF2 known-answer vectors and the synthetic keybag round-trip.
func deriveKEK(password string, dpsl []byte, dpic uint32, salt []byte, iter uint32) ([]byte, error) {
	round1, err := pbkdf2.Key(sha256.New, password, dpsl, int(dpic), kekLen)
	if err != nil {
		return nil, fmt.Errorf("keybag: stage-1 PBKDF2-SHA256: %w", err)
	}
	kek, err := pbkdf2.Key(sha1.New, string(round1), salt, int(iter), kekLen)
	if err != nil {
		return nil, fmt.Errorf("keybag: stage-2 PBKDF2-SHA1: %w", err)
	}
	return kek, nil
}
