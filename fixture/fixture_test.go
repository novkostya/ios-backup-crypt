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
