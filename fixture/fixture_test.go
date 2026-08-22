// package fixture_test, deliberately EXTERNAL. The point of this package becoming public
// is that somebody outside this module can build a backup to test their own code against,
// so the test that matters is one written the way such a consumer would write it: only
// exported identifiers, no access to the package's internals. An in-package test would
// still pass if half the surface a consumer needs were unexported.
package fixture_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/novkostya/ios-backup-crypt/fixture"
)

// A consumer can build a backup using nothing but the exported API, and gets back enough
// to address every file it asked for.
func TestBuildIsUsableFromOutsideThePackage(t *testing.T) {
	dir := t.TempDir()

	res, err := fixture.Build(dir, fixture.Spec{
		DeviceName:     "test-device",
		ProductVersion: "26.0",
		Files: []fixture.File{
			{Domain: "HomeDomain", RelativePath: "Library/Prefs/a.plist", Flags: 1, Data: []byte("alpha")},
			{Domain: "HomeDomain", RelativePath: "Library/Prefs", Flags: 2},
			{Domain: "CameraRollDomain", RelativePath: "Media/DCIM/IMG_0001.HEIC", Flags: 1, Data: []byte("beta")},
		},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if res.Password != fixture.DefaultPassword {
		t.Errorf("Password = %q, want the documented default %q", res.Password, fixture.DefaultPassword)
	}
	if len(res.Files) != 3 {
		t.Fatalf("Result reported %d files, want 3", len(res.Files))
	}

	// Every row carries a file id, because that is what a consumer addresses a file by —
	// the caller supplies a path and gets back the SHA-1 the format actually uses.
	seen := map[string]bool{}
	for _, f := range res.Files {
		if f.FileID == "" {
			t.Errorf("%s/%s has no FileID", f.Domain, f.RelativePath)
		}
		if seen[f.FileID] {
			t.Errorf("duplicate FileID %s", f.FileID)
		}
		seen[f.FileID] = true
	}

	// The two artifacts a decrypt path opens first.
	for _, name := range []string{"Manifest.plist", "Manifest.db"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("Build did not write %s: %v", name, err)
		}
	}
}

// The password is the caller's when they supply one — a consumer testing a wrong-password
// path needs to know which password is the right one.
func TestBuildHonorsASuppliedPassword(t *testing.T) {
	res, err := fixture.Build(t.TempDir(), fixture.Spec{
		Password: "not-the-default",
		Files:    []fixture.File{{Domain: "HomeDomain", RelativePath: "x", Flags: 1, Data: []byte("x")}},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if res.Password != "not-the-default" {
		t.Errorf("Password = %q, want the one that was supplied", res.Password)
	}
}

// EVERY TYPE Spec REFERS TO MUST BE NAMEABLE FROM OUT HERE, and this test exists to fail
// when one is not (#18).
//
// `Spec.Status` and `Spec.Info` shipped in fixture/v0.2.0 as fields whose TYPES had no
// alias, so a consumer could not construct either — and `Spec.Info`, being a pointer, could
// not even be allocated. Nothing in this repository caught it: the root module's tests reach
// `internal/builder` directly, and this module's own build runs under a `replace`, so the
// consumer's view was compiled nowhere.
//
// The file's alias block claims "a field added to the generator appears here without a
// second edit that could be forgotten." That is true of the FIELD and false of the TYPE it
// is made of, which is the edit that was forgotten. This test is what makes the claim hold:
// it names every type by its `fixture.`-qualified alias, so a field of an unexported type
// fails to compile HERE rather than in somebody else's repository.
//
// EVERY EXPORTED FIELD IS SET, including the ones whose types are builtins and could not
// possibly fail. That is deliberate: this is a SNAPSHOT of the whole surface, so a reader
// adding a field can see at a glance whether it is covered, and the diff that adds one to
// Spec without touching this test is visibly incomplete.
//
// WHAT IT DOES NOT DO, stated so nobody trusts it further than it goes: a NEW field of a new
// unexported type does not break this test until somebody sets it here. Go has no
// exhaustiveness check for struct literals, and reflection cannot help — an alias does not
// change type identity, so `reflect` reports `internal/builder` as the package for the
// aliased types and the correct ones are indistinguishable from the broken ones. If that
// gap is worth closing mechanically, `exhaustruct` on this file is the tool.
func TestEveryTypeSpecNeedsIsNameableByAConsumer(t *testing.T) {
	dir := t.TempDir()

	// Composite literals throughout, with no `unsafe`, no reflection and no type-inference
	// tricks — if any of these names is missing, this file does not build.
	spec := fixture.Spec{
		Password:       "test",
		DeviceName:     "Study Tablet",
		ProductVersion: "17.5.1",
		DeviceClass:    "iPad",
		ProductType:    "iPadT9,9",
		BuildVersion:   "21F9000",
		SerialNumber:   "SERIALINVENTED1",
		UniqueDeviceID: "00009999-000A9999A99A999A",
		DPIC:           4096,
		ITER:           4096,
		Status: fixture.StatusInfo{
			BackupState:   "new",
			Date:          time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
			IsFullBackup:  true,
			SnapshotState: "finished",
			UUID:          "UUIDINVENTED0001",
			Version:       "3.3",
		},
		Info: &fixture.DeviceExtras{
			DisplayName:           "Study Tablet",
			GUID:                  "GUIDINVENTED0001",
			TargetIdentifier:      "00009999-000A9999A99A999A",
			TargetType:            "Device",
			ITunesVersion:         "12.12.9",
			LastBackupDate:        time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
			InstalledApplications: []string{"com.example.notes", "com.example.reader"},
			IMEI:                  "990000000000001",
			ICCID:                 "89000000000000000001",
			PhoneNumber:           "+15550000001",
		},
		Files: []fixture.File{{
			Domain:       "HomeDomain",
			RelativePath: "Library/note.txt",
			Flags:        1,
			Data:         []byte("x"),
			MTime:        time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC),
			BadRecord:    false,
		}},
	}

	res, err := fixture.Build(dir, spec)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	// Result and WrittenFile are the other half of the surface — named here so the same
	// compile covers what Build HANDS BACK as well as what it takes.
	var written fixture.WrittenFile
	if len(res.Files) > 0 {
		written = res.Files[0]
	}
	if written.FileID == "" || written.Domain != "HomeDomain" || written.RelativePath == "" {
		t.Errorf("WrittenFile = %+v, want the row that was placed", written)
	}
	if written.Flags != 1 {
		t.Errorf("WrittenFile.Flags = %d, want 1", written.Flags)
	}

	// AND THE PLISTS ARE ACTUALLY WRITTEN. Naming the types is the compile-time half; this
	// is the half that says the fields did something, so the test cannot pass on a Spec
	// whose two newest fields are accepted and silently ignored.
	for _, name := range []string{"Status.plist", "Info.plist", "Manifest.plist"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Errorf("%s was not written: %v", name, err)
		}
	}
}
