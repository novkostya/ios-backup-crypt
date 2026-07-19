package aeskw

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// The six official RFC 3394 §4 test vectors. Each proves both directions: Wrap(kek,
// key) must produce ciphertext, and Unwrap(kek, ciphertext) must recover key.
// Values transcribed from RFC 3394 (verified against rfc-editor.org, 2026-07-19).
var rfc3394Vectors = []struct {
	name       string
	kek        string
	key        string
	ciphertext string
}{
	{
		"4.1 128-bit data, 128-bit KEK",
		"000102030405060708090A0B0C0D0E0F",
		"00112233445566778899AABBCCDDEEFF",
		"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
	},
	{
		"4.2 128-bit data, 192-bit KEK",
		"000102030405060708090A0B0C0D0E0F1011121314151617",
		"00112233445566778899AABBCCDDEEFF",
		"96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
	},
	{
		"4.3 128-bit data, 256-bit KEK",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"00112233445566778899AABBCCDDEEFF",
		"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
	},
	{
		"4.4 192-bit data, 192-bit KEK",
		"000102030405060708090A0B0C0D0E0F1011121314151617",
		"00112233445566778899AABBCCDDEEFF0001020304050607",
		"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
	},
	{
		"4.5 192-bit data, 256-bit KEK",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"00112233445566778899AABBCCDDEEFF0001020304050607",
		"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
	},
	{
		"4.6 256-bit data, 256-bit KEK",
		"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
		"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
		"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
	},
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestWrapRFC3394(t *testing.T) {
	for _, v := range rfc3394Vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := Wrap(mustHex(t, v.kek), mustHex(t, v.key))
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if want := mustHex(t, v.ciphertext); !bytes.Equal(got, want) {
				t.Fatalf("Wrap mismatch:\n got  %X\n want %X", got, want)
			}
		})
	}
}

func TestUnwrapRFC3394(t *testing.T) {
	for _, v := range rfc3394Vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := Unwrap(mustHex(t, v.kek), mustHex(t, v.ciphertext))
			if err != nil {
				t.Fatalf("Unwrap: %v", err)
			}
			if want := mustHex(t, v.key); !bytes.Equal(got, want) {
				t.Fatalf("Unwrap mismatch:\n got  %X\n want %X", got, want)
			}
		})
	}
}

func TestWrapUnwrapRoundTrip(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F")
	// A few sizes: 2, 4, and 5 semiblocks (5 == the 40-byte wrapped-key shape iOS uses).
	for _, n := range []int{16, 32, 40} {
		key := make([]byte, n)
		for i := range key {
			key[i] = byte(i * 7)
		}
		wrapped, err := Wrap(kek, key)
		if err != nil {
			t.Fatalf("Wrap(%d): %v", n, err)
		}
		if len(wrapped) != n+8 {
			t.Fatalf("Wrap(%d): got %d bytes, want %d", n, len(wrapped), n+8)
		}
		got, err := Unwrap(kek, wrapped)
		if err != nil {
			t.Fatalf("Unwrap(%d): %v", n, err)
		}
		if !bytes.Equal(got, key) {
			t.Fatalf("round-trip(%d) mismatch:\n got  %X\n want %X", n, got, key)
		}
	}
}

func TestUnwrapWrongKEK(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	wrong := mustHex(t, "0102030405060708090A0B0C0D0E0F00")
	wrapped, err := Wrap(kek, mustHex(t, "00112233445566778899AABBCCDDEEFF"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if _, err := Unwrap(wrong, wrapped); err != ErrIntegrity {
		t.Fatalf("Unwrap with wrong KEK: got err=%v, want ErrIntegrity", err)
	}
}

func TestLengthErrors(t *testing.T) {
	kek := mustHex(t, "000102030405060708090A0B0C0D0E0F")
	// Wrap: not a multiple of 8, and too short.
	if _, err := Wrap(kek, make([]byte, 15)); err != ErrKeyLen {
		t.Errorf("Wrap(15): got %v, want ErrKeyLen", err)
	}
	if _, err := Wrap(kek, make([]byte, 8)); err != ErrKeyLen {
		t.Errorf("Wrap(8): got %v, want ErrKeyLen", err)
	}
	// Unwrap: not a multiple of 8, and too short (needs IV + 2 semiblocks = 24).
	if _, err := Unwrap(kek, make([]byte, 20)); err != ErrKeyLen {
		t.Errorf("Unwrap(20): got %v, want ErrKeyLen", err)
	}
	if _, err := Unwrap(kek, make([]byte, 16)); err != ErrKeyLen {
		t.Errorf("Unwrap(16): got %v, want ErrKeyLen", err)
	}
}
