package keybag

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"testing"
)

type pbkdf2Vector struct {
	password string
	salt     string
	iter     int
	keyLen   int
	want     string
}

// PBKDF2-HMAC-SHA1 — the canonical RFC 6070 vectors (the c=16,777,216 case is omitted;
// it is correct but far too slow for CI). These anchor the KDF to the official spec.
var sha1Vectors = []pbkdf2Vector{
	{"password", "salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"},
	{"password", "salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"},
	{"password", "salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"},
	{
		"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25,
		"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038",
	},
	{"pass\x00word", "sa\x00lt", 4096, 16, "56fa6aa75548099dcc37d7f03425e0c3"},
}

// PBKDF2-HMAC-SHA256 — cross-checked against an independent implementation (Python
// hashlib.pbkdf2_hmac); the (P="password", S="salt") set matches the widely used
// community vectors. Proving stage-1 (SHA-256) usage as well as stage-2 (SHA-1).
var sha256Vectors = []pbkdf2Vector{
	{"password", "salt", 1, 32, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
	{"password", "salt", 2, 32, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
	{"password", "salt", 4096, 32, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	{
		"passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 40,
		"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9",
	},
	{"pass\x00word", "sa\x00lt", 4096, 16, "89b69d0516f829893c696226650a8687"},
}

func runPBKDF2Vectors(t *testing.T, h func() hash.Hash, vectors []pbkdf2Vector) {
	t.Helper()
	for _, v := range vectors {
		got, err := pbkdf2.Key(h, v.password, []byte(v.salt), v.iter, v.keyLen)
		if err != nil {
			t.Fatalf("pbkdf2(%q,%q,c=%d): %v", v.password, v.salt, v.iter, err)
		}
		if hex.EncodeToString(got) != v.want {
			t.Errorf("pbkdf2(%q,%q,c=%d,len=%d):\n got  %x\n want %s",
				v.password, v.salt, v.iter, v.keyLen, got, v.want)
		}
	}
}

func TestPBKDF2_SHA1_RFC6070(t *testing.T) { runPBKDF2Vectors(t, sha1.New, sha1Vectors) }
func TestPBKDF2_SHA256(t *testing.T)       { runPBKDF2Vectors(t, sha256.New, sha256Vectors) }

// TestDeriveKEKStageOrder pins the two-stage composition: SHA-256 first (DPSL/DPIC),
// SHA-1 second (SALT/ITER). It rebuilds the KEK inline from the raw primitives and
// requires deriveKEK to match — so a swapped hash or swapped salt would be caught.
func TestDeriveKEKStageOrder(t *testing.T) {
	pw := "test"
	dpsl := []byte("double-protection-salt")
	salt := []byte("keybag-salt-value")
	var dpic, iter uint32 = 1000, 2000

	round1, err := pbkdf2.Key(sha256.New, pw, dpsl, int(dpic), kekLen)
	if err != nil {
		t.Fatal(err)
	}
	wantKEK, err := pbkdf2.Key(sha1.New, string(round1), salt, int(iter), kekLen)
	if err != nil {
		t.Fatal(err)
	}

	got, err := deriveKEK(pw, dpsl, dpic, salt, iter)
	if err != nil {
		t.Fatalf("deriveKEK: %v", err)
	}
	if hex.EncodeToString(got) != hex.EncodeToString(wantKEK) {
		t.Fatalf("deriveKEK mismatch:\n got  %x\n want %x", got, wantKEK)
	}
	if len(got) != kekLen {
		t.Fatalf("KEK length %d, want %d", len(got), kekLen)
	}
}

// BenchmarkDeriveKEKRealistic measures the unlock KDF at production work factors
// (DPIC = 10,000,000 SHA-256 rounds, then ITER = 10,000 SHA-1 rounds) — the deliberately
// slow key derivation a real backup password goes through. It is not part of the gate
// (benchmarks do not run under `go test`); measure a single unlock with:
//
//	go test -run '^$' -bench BenchmarkDeriveKEKRealistic -benchtime=1x ./internal/keybag
//
// Recorded measurement (milestone 4): ~1.45 s per unlock on an Intel Core Ultra 7 155H
// (which has the SHA-NI extension Go's crypto/sha256 uses). That leaves a wide margin
// under the ~30 s budget: even hardware ~15x slower with no SHA acceleration stays inside
// it, and modern arm64 NAS SoCs (ARMv8 SHA2 extensions) land in the low seconds.
func BenchmarkDeriveKEKRealistic(b *testing.B) {
	dpsl := []byte("differential-salt-dpsl-16b")
	salt := []byte("keybag-header-salt-value")
	const dpic, iter = 10_000_000, 10_000
	for b.Loop() {
		if _, err := deriveKEK("correct horse battery staple", dpsl, dpic, salt, iter); err != nil {
			b.Fatal(err)
		}
	}
}
