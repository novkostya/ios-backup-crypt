package iosbackup

import (
	"os"
	"path/filepath"
	"testing"

	"howett.net/plist"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
)

// The whole Lockdown dict is readable before Unlock, because Manifest.plist is not
// encrypted. Asserted on an ENCRYPTED backup with no password supplied: if any of this
// needed a key, the test could not pass.
func TestDeviceInfoBeforeUnlock(t *testing.T) {
	dir := t.TempDir()
	spec := builder.Spec{
		DeviceName:     "Test iPad",
		ProductVersion: "17.5.1",
		DeviceClass:    "iPad",
		ProductType:    "iPad13,4",
		BuildVersion:   "21F90",
		SerialNumber:   "XXXXXXXXXXXX",
		UniqueDeviceID: "00000000-000000000000000A",
		Files:          []builder.File{{Domain: "HomeDomain", RelativePath: "a.txt", Flags: 1, Data: []byte("x")}},
	}
	if _, err := builder.Build(dir, spec); err != nil {
		t.Fatal(err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()

	info, err := b.DeviceInfo()
	if err != nil {
		t.Fatalf("DeviceInfo before unlock: %v", err)
	}
	for _, c := range []struct{ name, got, want string }{
		{"DeviceName", info.DeviceName, spec.DeviceName},
		{"ProductVersion", info.ProductVersion, spec.ProductVersion},
		{"DeviceClass", info.DeviceClass, spec.DeviceClass},
		{"ProductType", info.ProductType, spec.ProductType},
		{"BuildVersion", info.BuildVersion, spec.BuildVersion},
		{"SerialNumber", info.SerialNumber, spec.SerialNumber},
		{"UniqueDeviceID", info.UniqueDeviceID, spec.UniqueDeviceID},
	} {
		if c.got != c.want {
			t.Errorf("%s before unlock = %q, want %q", c.name, c.got, c.want)
		}
	}

	// The count is the ONE field that needs the key, and it must say so rather than
	// reporting a zero a caller cannot interpret.
	if info.FileCountKnown {
		t.Error("FileCountKnown = true before unlock; a locked backup cannot know its file count")
	}
	if info.FileCount != 0 {
		t.Errorf("FileCount = %d before unlock, want 0", info.FileCount)
	}
}

// After Unlock the count is known, and the flag is what distinguishes it from the locked
// zero above.
func TestFileCountKnownAfterUnlock(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{
		DeviceName: "Test iPad",
		Files: []builder.File{
			{Domain: "HomeDomain", RelativePath: "a.txt", Flags: 1, Data: []byte("x")},
			{Domain: "HomeDomain", RelativePath: "b.txt", Flags: 1, Data: []byte("yy")},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Unlock(res.Password); err != nil {
		t.Fatal(err)
	}
	info, err := b.DeviceInfo()
	if err != nil {
		t.Fatal(err)
	}
	if !info.FileCountKnown {
		t.Fatal("FileCountKnown = false after unlock")
	}
	if info.FileCount != int64(len(res.Files)) {
		t.Errorf("FileCount = %d, want %d", info.FileCount, len(res.Files))
	}
}

// An EMPTY unlocked backup reports zero as a KNOWN zero. This is the case the flag exists
// for: without it this state and the locked state above are the same value.
func TestEmptyUnlockedBackupReportsKnownZero(t *testing.T) {
	dir := t.TempDir()
	res, err := builder.Build(dir, builder.Spec{DeviceName: "Test iPad"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	if err := b.Unlock(res.Password); err != nil {
		t.Fatal(err)
	}
	info, err := b.DeviceInfo()
	if err != nil {
		t.Fatal(err)
	}
	if info.FileCount != 0 {
		t.Fatalf("FileCount = %d, want 0", info.FileCount)
	}
	if !info.FileCountKnown {
		t.Error("FileCountKnown = false for an EMPTY unlocked backup — indistinguishable from locked")
	}
}

// A field left unset is ABSENT from the plist, not an empty string, and reads back empty.
// The builder's omit behavior exists so this branch is buildable at all.
func TestAbsentLockdownFieldsReadEmpty(t *testing.T) {
	dir := t.TempDir()
	if _, err := builder.Build(dir, builder.Spec{
		DeviceName:     "Test iPad",
		ProductVersion: "17.5.1",
		Files:          []builder.File{{Domain: "HomeDomain", RelativePath: "a.txt", Flags: 1, Data: []byte("x")}},
	}); err != nil {
		t.Fatal(err)
	}
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	info, err := b.DeviceInfo()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, got string }{
		{"DeviceClass", info.DeviceClass},
		{"ProductType", info.ProductType},
		{"BuildVersion", info.BuildVersion},
		{"SerialNumber", info.SerialNumber},
		{"UniqueDeviceID", info.UniqueDeviceID},
	} {
		if c.got != "" {
			t.Errorf("%s = %q for a spec that did not set it, want empty", c.name, c.got)
		}
	}
	// AND THE KEY IS GENUINELY ABSENT, not present-and-empty. Reading back "" cannot tell
	// those apart — an empty string decodes to "" either way — so the assertion that this
	// test is actually about has to be made against the plist itself.
	raw, err := os.ReadFile(filepath.Join(dir, "Manifest.plist"))
	if err != nil {
		t.Fatal(err)
	}
	var mp struct {
		Lockdown map[string]any `plist:"Lockdown"`
	}
	if _, err := plist.Unmarshal(raw, &mp); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"DeviceClass", "ProductType", "BuildVersion", "SerialNumber", "UniqueDeviceID"} {
		if _, present := mp.Lockdown[k]; present {
			t.Errorf("Lockdown[%q] is present in the plist; an unset spec field must be OMITTED, "+
				"or the fixture cannot build the absent case at all", k)
		}
	}
	// Control: a field that WAS set must be present, so the loop above is not vacuously
	// passing against an empty or misparsed dict.
	if _, present := mp.Lockdown["DeviceName"]; !present {
		t.Fatal("Lockdown[\"DeviceName\"] absent — the plist did not parse as expected, so the " +
			"absence assertions above prove nothing")
	}
}
