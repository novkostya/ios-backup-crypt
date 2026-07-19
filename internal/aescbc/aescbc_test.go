package aescbc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex: %v", err)
	}
	return b
}

// NIST SP 800-38A §F.2.5/F.2.6 — AES-256-CBC known-answer vector (the four-block
// example). Ciphertext independently reproduced with `openssl enc -aes-256-cbc -nopad`
// before being pinned here.
var (
	nistKey = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
	nistIV  = "000102030405060708090a0b0c0d0e0f"
	nistPT  = "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
	nistCT = "f58c4c04d6e5f1ba779eabfb5f7bfbd6" +
		"9cfc4e967edb808d679f777bc6702c7d" +
		"39f23369a9d9bacfa530e26304231461" +
		"b2eb05e2c39be9fcda6c19078c6a9d1b"
)

func TestDecryptStreamNIST(t *testing.T) {
	var out bytes.Buffer
	n, err := DecryptStream(&out, bytes.NewReader(mustHex(t, nistCT)), mustHex(t, nistKey), mustHex(t, nistIV))
	if err != nil {
		t.Fatalf("DecryptStream: %v", err)
	}
	if n != 64 {
		t.Errorf("wrote %d bytes, want 64", n)
	}
	if got := hex.EncodeToString(out.Bytes()); got != nistPT {
		t.Fatalf("plaintext mismatch:\n got  %s\n want %s", got, nistPT)
	}
}

func TestEncryptStreamNIST(t *testing.T) {
	var out bytes.Buffer
	if _, err := EncryptStream(&out, bytes.NewReader(mustHex(t, nistPT)), mustHex(t, nistKey), mustHex(t, nistIV)); err != nil {
		t.Fatalf("EncryptStream: %v", err)
	}
	if got := hex.EncodeToString(out.Bytes()); got != nistCT {
		t.Fatalf("ciphertext mismatch:\n got  %s\n want %s", got, nistCT)
	}
}

// TestRoundTripAcrossChunks proves the CBC chaining state is carried across the 64 KiB
// streaming buffer: encrypt-then-decrypt must reproduce inputs both smaller and larger
// than one chunk, under a zero IV (as iOS uses).
func TestRoundTripAcrossChunks(t *testing.T) {
	key := mustHex(t, nistKey)
	iv := make([]byte, 16) // iOS zero IV
	for _, size := range []int{16, 64, 4096, chunk, chunk + 16, 3*chunk + 32} {
		plain := make([]byte, size)
		for i := range plain {
			plain[i] = byte(i*31 + 7)
		}
		var enc bytes.Buffer
		if _, err := EncryptStream(&enc, bytes.NewReader(plain), key, iv); err != nil {
			t.Fatalf("EncryptStream(%d): %v", size, err)
		}
		if enc.Len() != size {
			t.Fatalf("EncryptStream(%d): got %d bytes", size, enc.Len())
		}
		var dec bytes.Buffer
		if _, err := DecryptStream(&dec, bytes.NewReader(enc.Bytes()), key, iv); err != nil {
			t.Fatalf("DecryptStream(%d): %v", size, err)
		}
		if !bytes.Equal(dec.Bytes(), plain) {
			t.Fatalf("round-trip(%d) mismatch", size)
		}
	}
}

func TestNotBlockAligned(t *testing.T) {
	key := mustHex(t, nistKey)
	iv := make([]byte, 16)
	var out bytes.Buffer
	if _, err := DecryptStream(&out, bytes.NewReader(make([]byte, 20)), key, iv); err != ErrNotBlockAligned {
		t.Fatalf("got %v, want ErrNotBlockAligned", err)
	}
}
