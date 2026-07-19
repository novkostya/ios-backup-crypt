// Package aescbc provides streaming AES-CBC decryption (and encryption, for the test
// builder) — block-at-a-time so a multi-gigabyte backup blob is never buffered whole.
//
// iOS backups encrypt Manifest.db and every per-file blob with AES-CBC under a zero IV.
// The functions here take the IV as a parameter so they can also be exercised against
// the NIST SP 800-38A known-answer vectors, which use a non-zero IV.
package aescbc

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
)

// chunk is the streaming buffer size — a multiple of the AES block size.
const chunk = 1 << 16 // 64 KiB

// ErrNotBlockAligned reports input whose length is not a multiple of the AES block size
// (16 bytes). CBC ciphertext is always block-aligned; iOS pads plaintext to a block.
var ErrNotBlockAligned = errors.New("aescbc: input not a multiple of the 16-byte block size")

// DecryptStream decrypts src (AES-CBC under key and iv) into dst, one buffer at a time,
// and returns the number of bytes written. It does not remove padding — callers strip
// PKCS#7 padding (per-file blobs) or truncate to a known size (Manifest.db is already
// SQLite-page-aligned) themselves. The total input length must be a multiple of 16.
func DecryptStream(dst io.Writer, src io.Reader, key, iv []byte) (int64, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	if len(iv) != block.BlockSize() {
		return 0, errors.New("aescbc: iv length must equal the block size")
	}
	return stream(dst, src, cipher.NewCBCDecrypter(block, iv), block.BlockSize())
}

// EncryptStream is the inverse of DecryptStream (used by the synthetic-backup builder
// and round-trip tests). The input length must be a multiple of 16.
func EncryptStream(dst io.Writer, src io.Reader, key, iv []byte) (int64, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, err
	}
	if len(iv) != block.BlockSize() {
		return 0, errors.New("aescbc: iv length must equal the block size")
	}
	return stream(dst, src, cipher.NewCBCEncrypter(block, iv), block.BlockSize())
}

// stream runs mode over src → dst in block-aligned chunks. cipher.BlockMode carries the
// CBC chaining state across CryptBlocks calls, so processing in chunks is equivalent to
// processing the whole input at once.
func stream(dst io.Writer, src io.Reader, mode cipher.BlockMode, blockSize int) (int64, error) {
	buf := make([]byte, chunk)
	var total int64
	for {
		n, err := io.ReadFull(src, buf)
		if n > 0 {
			if n%blockSize != 0 {
				return total, ErrNotBlockAligned
			}
			mode.CryptBlocks(buf[:n], buf[:n])
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}
