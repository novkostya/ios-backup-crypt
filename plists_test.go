package iosbackup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"howett.net/plist"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
)

// fullSpec is a fixture carrying every plist a real backup has. Identifiers are INVENTED:
// a real serial or IMEI in a test file is device content in public git forever.
func fullSpec() builder.Spec {
	return builder.Spec{
		DeviceName:     "Test iPad",
		ProductVersion: "17.5.1",
		DeviceClass:    "iPad",
		ProductType:    "iPad13,4",
		BuildVersion:   "21F90",
		SerialNumber:   "XXXXXXXXXXXX",
		UniqueDeviceID: "00000000-000000000000000A",
		Status: builder.StatusInfo{
			BackupState:   "new",
			Date:          time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC),
			IsFullBackup:  true,
			SnapshotState: "finished",
			UUID:          "00000000-0000-4000-8000-000000000000",
			Version:       "3.3",
		},
		Info: &builder.DeviceExtras{
			DisplayName:           "Test iPad",
			GUID:                  "0123456789abcdef0123456789abcdef",
			TargetIdentifier:      "00000000-000000000000000A",
			TargetType:            "Device",
			ITunesVersion:         "12.12.10.1",
			LastBackupDate:        time.Date(2026, 8, 22, 1, 0, 0, 0, time.UTC),
			InstalledApplications: []string{"com.example.one", "com.example.two"},
		},
		Files: []builder.File{{Domain: "HomeDomain", RelativePath: "a.txt", Flags: 1, Data: []byte("x")}},
	}
}

func readPlist(t *testing.T, path string) (map[string]any, []byte) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", filepath.Base(path), err)
	}
	var m map[string]any
	if _, err := plist.Unmarshal(raw, &m); err != nil {
		t.Fatalf("parse %s: %v", filepath.Base(path), err)
	}
	return m, raw
}

// Both new plists are written, parse, and carry what the spec asked for.
func TestBuildWritesInfoAndStatusPlists(t *testing.T) {
	dir := t.TempDir()
	spec := fullSpec()
	if _, err := builder.Build(dir, spec); err != nil {
		t.Fatal(err)
	}

	status, statusRaw := readPlist(t, filepath.Join(dir, "Status.plist"))
	for k, want := range map[string]any{
		"BackupState":   "new",
		"SnapshotState": "finished",
		"Version":       "3.3",
		"IsFullBackup":  true,
	} {
		if got := status[k]; got != want {
			t.Errorf("Status.plist[%q] = %v, want %v", k, got, want)
		}
	}
	if _, ok := status["Date"].(time.Time); !ok {
		t.Errorf("Status.plist[\"Date\"] = %T, want time.Time", status["Date"])
	}

	info, infoRaw := readPlist(t, filepath.Join(dir, "Info.plist"))
	for k, want := range map[string]any{
		"Device Name":       "Test iPad",
		"Product Version":   "17.5.1",
		"Product Type":      "iPad13,4",
		"Build Version":     "21F90",
		"Serial Number":     "XXXXXXXXXXXX",
		"Unique Identifier": "00000000-000000000000000A",
		"Target Type":       "Device",
	} {
		if got := info[k]; got != want {
			t.Errorf("Info.plist[%q] = %v, want %v", k, got, want)
		}
	}
	apps, ok := info["Installed Applications"].([]any)
	if !ok || len(apps) != 2 {
		t.Fatalf("Installed Applications = %v (%T), want 2 entries", info["Installed Applications"], info["Installed Applications"])
	}
	if perApp, ok := info["Applications"].(map[string]any); !ok || len(perApp) != 2 {
		t.Errorf("Applications = %v, want a dict of 2 — it mirrors Installed Applications on a real backup", info["Applications"])
	}

	// THE FORMATS DIFFER, AND THAT IS THE POINT. Measured on two real backups: Info.plist
	// is XML, Status.plist and Manifest.plist are binary. A reader tested only against a
	// generator that wrote everything binary would never meet an XML plist and would pass
	// while failing on every real backup.
	if got := string(infoRaw[:6]); got != "<?xml " {
		t.Errorf("Info.plist starts %q, want XML — iOS writes this one as XML", got)
	}
	if got := string(statusRaw[:8]); got != "bplist00" {
		t.Errorf("Status.plist starts %q, want binary", got)
	}
	_, manifestRaw := readPlist(t, filepath.Join(dir, "Manifest.plist"))
	if got := string(manifestRaw[:8]); got != "bplist00" {
		t.Errorf("Manifest.plist starts %q, want binary", got)
	}
}

// A spec that asks for neither writes neither — the state of every fixture built before
// this change, and a state a reader must handle.
func TestBuildWithoutInfoOrStatusWritesNeither(t *testing.T) {
	dir := t.TempDir()
	if _, err := builder.Build(dir, builder.Spec{
		DeviceName: "Test iPad",
		Files:      []builder.File{{Domain: "HomeDomain", RelativePath: "a.txt", Flags: 1, Data: []byte("x")}},
	}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Info.plist", "Status.plist"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s exists for a spec that asked for none (err=%v)", name, err)
		}
	}
	// Control: the two that are always written still are, so the absence checks above are
	// not passing against an empty directory.
	for _, name := range []string{"Manifest.plist", "Manifest.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s missing: %v — the absence assertions above prove nothing", name, err)
		}
	}
}

// The phone-only fields are omitted when unset, so "this backup is an iPad" is buildable.
func TestPhoneOnlyFieldsOmittedWhenUnset(t *testing.T) {
	dir := t.TempDir()
	if _, err := builder.Build(dir, fullSpec()); err != nil {
		t.Fatal(err)
	}
	info, _ := readPlist(t, filepath.Join(dir, "Info.plist"))
	for _, k := range []string{"IMEI", "ICCID", "Phone Number"} {
		if _, present := info[k]; present {
			t.Errorf("Info.plist[%q] present on an iPad spec that did not set it", k)
		}
	}

	// And present when they ARE set, which is what makes the absence above meaningful.
	dir2 := t.TempDir()
	spec := fullSpec()
	spec.DeviceClass = "iPhone"
	spec.Info.IMEI = "000000000000000"
	spec.Info.ICCID = "0000000000000000000"
	spec.Info.PhoneNumber = "+10000000000"
	if _, err := builder.Build(dir2, spec); err != nil {
		t.Fatal(err)
	}
	info2, _ := readPlist(t, filepath.Join(dir2, "Info.plist"))
	for _, k := range []string{"IMEI", "ICCID", "Phone Number"} {
		if _, present := info2[k]; !present {
			t.Errorf("Info.plist[%q] absent on a phone spec that set it", k)
		}
	}
}

// Both plists are written on the unencrypted path too — it shares the writers, and a field
// added to one path and forgotten in the other is the defect lockdownDict already fixed.
func TestUnencryptedBuildAlsoWritesBothPlists(t *testing.T) {
	dir := t.TempDir()
	spec := fullSpec()
	spec.Unencrypted = true
	if _, err := builder.Build(dir, spec); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"Info.plist", "Status.plist"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s missing on the unencrypted path: %v", name, err)
		}
	}
}
