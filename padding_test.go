package iosbackup

import (
	"bytes"
	"testing"
)

func TestPaddedLen(t *testing.T) {
	// PKCS#7 rounds up to the next block, adding a full block when already aligned.
	cases := map[int64]int64{0: 16, 1: 16, 15: 16, 16: 32, 17: 32, 4096: 4112, 200000: 200016}
	for size, want := range cases {
		if got := paddedLen(size); got != want {
			t.Errorf("paddedLen(%d) = %d, want %d", size, got, want)
		}
	}
}

func TestPKCS7PadLen(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want int
	}{
		{"valid 3", []byte{1, 2, 3, 3, 3}, 3},
		{"full block", bytes.Repeat([]byte{16}, 16), 16},
		{"single 01", []byte{9, 1}, 1},
		{"not all equal", []byte{1, 2, 3, 2, 3}, 0},
		{"len exceeds data", []byte{7, 7}, 0}, // last byte 7 > len 2
		{"zero byte", []byte{0}, 0},
		{"empty", nil, 0},
	}
	for _, c := range cases {
		if got := pkcs7PadLen(c.in); got != c.want {
			t.Errorf("%s: pkcs7PadLen(%v) = %d, want %d", c.name, c.in, got, c.want)
		}
	}
}

func TestTailWriter(t *testing.T) {
	// 32 bytes ending in a valid 2-byte PKCS#7 pad.
	data := append(bytes.Repeat([]byte{0xAA}, 30), 2, 2)
	for _, tc := range []struct {
		strip bool
		wantN int64
	}{
		{strip: true, wantN: 30},  // strips the 2-byte padding
		{strip: false, wantN: 32}, // keeps the final block intact (truncated-file case)
	} {
		var out bytes.Buffer
		tw := &tailWriter{w: &out, strip: tc.strip}
		for i := 0; i < len(data); i += 7 { // odd chunks exercise the hold-back
			end := min(i+7, len(data))
			if _, err := tw.Write(data[i:end]); err != nil {
				t.Fatal(err)
			}
		}
		n, err := tw.finish()
		if err != nil {
			t.Fatal(err)
		}
		if n != tc.wantN || int64(out.Len()) != tc.wantN {
			t.Fatalf("strip=%v: finish=%d out=%d, want %d", tc.strip, n, out.Len(), tc.wantN)
		}
		if !bytes.Equal(out.Bytes(), data[:tc.wantN]) {
			t.Fatalf("strip=%v: content mismatch", tc.strip)
		}
	}
}
