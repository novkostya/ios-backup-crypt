package iosbackup

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"howett.net/plist"
)

// manifestPlist is the subset of Manifest.plist the decrypt path needs.
type manifestPlist struct {
	IsEncrypted  bool     `plist:"IsEncrypted"`
	BackupKeyBag []byte   `plist:"BackupKeyBag"`
	ManifestKey  []byte   `plist:"ManifestKey"`
	Lockdown     lockdown `plist:"Lockdown"`
}

// lockdown holds the device-identifying fields from Manifest.plist's Lockdown dict.
type lockdown struct {
	DeviceName     string `plist:"DeviceName"`
	ProductVersion string `plist:"ProductVersion"`
}

// readManifestPlist reads and decodes <dir>/Manifest.plist. The file is small metadata,
// so it is read whole (unlike backup blobs, which stream).
func readManifestPlist(dir string) (*manifestPlist, error) {
	data, err := os.ReadFile(filepath.Join(dir, "Manifest.plist"))
	if err != nil {
		return nil, err
	}
	var mp manifestPlist
	if _, err := plist.Unmarshal(data, &mp); err != nil {
		return nil, fmt.Errorf("iosbackup: parse Manifest.plist: %w", err)
	}
	return &mp, nil
}

// splitManifestKey separates the ManifestKey into its little-endian protection class and
// the wrapped Manifest AES key (bytes 0–3 are the class; the rest is the wrapped key).
func splitManifestKey(mk []byte) (class uint32, wrapped []byte, err error) {
	if len(mk) <= 4 {
		return 0, nil, fmt.Errorf("iosbackup: ManifestKey too short (%d bytes)", len(mk))
	}
	class = binary.LittleEndian.Uint32(mk[:4])
	wrapped = mk[4:]
	return class, wrapped, nil
}
