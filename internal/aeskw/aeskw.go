// Package aeskw implements the RFC 3394 AES Key Wrap algorithm and its inverse — the
// key-unwrap primitive iOS backups use to protect class keys and per-file keys.
//
// It is deliberately tiny and depends only on crypto/aes. Correctness is proven
// against the official RFC 3394 §4 test vectors (see aeskw_test.go) before anything
// else in this module relies on it.
package aeskw

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
)

// defaultIV is the RFC 3394 §2.2.3.1 default initial value. After unwrapping, the
// integrity-check register A must equal this constant, or the data is rejected.
const defaultIV uint64 = 0xA6A6A6A6A6A6A6A6

var (
	// ErrKeyLen reports a wrapped/plaintext input whose length is not a multiple of
	// the 64-bit semiblock, or is too short for the algorithm.
	ErrKeyLen = errors.New("aeskw: input length must be a multiple of 8 bytes and long enough")
	// ErrIntegrity reports a failed RFC 3394 integrity check after unwrapping —
	// the wrong key-encryption key, or corrupted ciphertext.
	ErrIntegrity = errors.New("aeskw: integrity check failed (wrong key or corrupt data)")
)

// Wrap wraps the plaintext key data with the key-encryption key kek per RFC 3394.
// The KEK selects AES-128/192/256 by its length (16/24/32 bytes). plaintext must be a
// positive multiple of 8 bytes and at least 16 bytes (two 64-bit semiblocks). The
// result is 8 bytes longer than plaintext.
func Wrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, ErrKeyLen
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(plaintext) / 8
	// r[1..n] hold the semiblocks; index 0 is unused so the math mirrors the RFC.
	r := make([]byte, len(plaintext))
	copy(r, plaintext)
	a := defaultIV

	var buf [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			binary.BigEndian.PutUint64(buf[:8], a)
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Encrypt(buf[:], buf[:])
			a = binary.BigEndian.Uint64(buf[:8]) ^ uint64(n*j+i)
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}

	out := make([]byte, len(plaintext)+8)
	binary.BigEndian.PutUint64(out[:8], a)
	copy(out[8:], r)
	return out, nil
}

// Unwrap reverses Wrap: it unwraps wrapped with the key-encryption key kek and
// verifies the RFC 3394 integrity check. wrapped must be a multiple of 8 bytes and at
// least 24 bytes (the IV semiblock plus two data semiblocks). It returns ErrIntegrity
// if the check register does not match the default IV — signaling a wrong KEK or
// tampered ciphertext. The result is 8 bytes shorter than wrapped.
func Unwrap(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) < 24 || len(wrapped)%8 != 0 {
		return nil, ErrKeyLen
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	n := len(wrapped)/8 - 1
	a := binary.BigEndian.Uint64(wrapped[:8])
	r := make([]byte, len(wrapped)-8)
	copy(r, wrapped[8:])

	var buf [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			binary.BigEndian.PutUint64(buf[:8], a^uint64(n*j+i))
			copy(buf[8:], r[(i-1)*8:i*8])
			block.Decrypt(buf[:], buf[:])
			a = binary.BigEndian.Uint64(buf[:8])
			copy(r[(i-1)*8:i*8], buf[8:])
		}
	}

	if a != defaultIV {
		return nil, ErrIntegrity
	}
	return r, nil
}
