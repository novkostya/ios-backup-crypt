package iosbackup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/novkostya/ios-backup-crypt/internal/builder"
)

// Both readers work on a LOCKED backup. Asserted on an ENCRYPTED fixture with no password
// supplied anywhere: if either needed a key, this could not pass.
func TestReadPlistsBeforeUnlock(t *testing.T) {
	dir := t.TempDir()
	spec := fullSpec()
	if _, err := builder.Build(dir, spec); err != nil {
		t.Fatal(err)
	}

	// Opened, so the control below can assert this fixture really is encrypted and
	// really is locked — otherwise "works before Unlock" proves nothing.
	b, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()

	st, err := ReadStatus(dir)
	if err != nil {
		t.Fatalf("BackupStatus before unlock: %v", err)
	}
	if !st.Present {
		t.Fatal("Status.Present = false for a backup that has a Status.plist")
	}
	if st.BackupState != "new" || st.SnapshotState != "finished" || st.Version != "3.3" {
		t.Errorf("Status = %+v", st)
	}
	if !st.IsFullBackup {
		t.Error("IsFullBackup = false, want true")
	}
	if st.Date.IsZero() {
		t.Error("Date is zero")
	}

	e, err := ReadDeviceExtras(dir)
	if err != nil {
		t.Fatalf("DeviceExtras before unlock: %v", err)
	}
	if !e.Present {
		t.Fatal("DeviceExtras.Present = false for a backup that has an Info.plist")
	}
	if e.DisplayName != "Test iPad" || e.TargetType != "Device" || e.ITunesVersion != "12.12.10.1" {
		t.Errorf("DeviceExtras = %+v", e)
	}
	if len(e.InstalledApplications) != 2 {
		t.Errorf("InstalledApplications = %v, want 2", e.InstalledApplications)
	}
	if e.LastBackupDate.IsZero() {
		t.Error("LastBackupDate is zero")
	}
	// Control: the backup really is encrypted and really is locked, so "works before
	// Unlock" is a claim about this state rather than about a fixture that needed no key.
	if !b.manifest.IsEncrypted {
		t.Fatal("fixture is not encrypted — the before-unlock claim proves nothing")
	}
	if b.db != nil {
		t.Fatal("index is open — the backup is not locked")
	}
}

// An ABSENT file is a state, not a failure, and the two readers say so rather than erroring.
func TestAbsentPlistsReportNotPresent(t *testing.T) {
	dir := t.TempDir()
	if _, err := builder.Build(dir, builder.Spec{
		DeviceName: "Test iPad",
		Files:      []builder.File{{Domain: "HomeDomain", RelativePath: "a.txt", Flags: 1, Data: []byte("x")}},
	}); err != nil {
		t.Fatal(err)
	}

	st, err := ReadStatus(dir)
	if err != nil {
		t.Fatalf("BackupStatus with no Status.plist returned an error: %v — absence is a state", err)
	}
	if st.Present {
		t.Error("Status.Present = true when the file does not exist")
	}
	e, err := ReadDeviceExtras(dir)
	if err != nil {
		t.Fatalf("DeviceExtras with no Info.plist returned an error: %v — absence is a state", err)
	}
	if e.Present {
		t.Error("DeviceExtras.Present = true when the file does not exist")
	}
}

// A file that EXISTS and will not parse IS an error — a broken backup, not an old one. This
// is the distinction Present exists to keep: without it both arrive as a zero value.
func TestUnparseablePlistIsAnError(t *testing.T) {
	for _, name := range []string{"Status.plist", "Info.plist"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if _, err := builder.Build(dir, fullSpec()); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte("not a plist at all"), 0o600); err != nil {
				t.Fatal(err)
			}

			var readErr error
			if name == "Status.plist" {
				_, readErr = ReadStatus(dir)
			} else {
				_, readErr = ReadDeviceExtras(dir)
			}
			if readErr == nil {
				t.Fatalf("%s full of garbage read without error — a corrupt file must not "+
					"be reported the same way as a missing one", name)
			}
		})
	}
}

// The cellular fields are empty on a tablet and populated on a phone. Both directions,
// because an all-empty result would pass the first check on its own.
func TestCellularFieldsFollowTheDevice(t *testing.T) {
	tablet := t.TempDir()
	if _, err := builder.Build(tablet, fullSpec()); err != nil {
		t.Fatal(err)
	}
	et, err := ReadDeviceExtras(tablet)
	if err != nil {
		t.Fatal(err)
	}
	if et.IMEI != "" || et.ICCID != "" || et.PhoneNumber != "" {
		t.Errorf("cellular fields set on a tablet fixture: %+v", et)
	}

	phone := t.TempDir()
	spec := fullSpec()
	spec.DeviceClass = "iPhone"
	spec.Info.IMEI = "000000000000000"
	spec.Info.ICCID = "0000000000000000000"
	spec.Info.PhoneNumber = "+10000000000"
	if _, err := builder.Build(phone, spec); err != nil {
		t.Fatal(err)
	}
	ep, err := ReadDeviceExtras(phone)
	if err != nil {
		t.Fatal(err)
	}
	if ep.IMEI == "" || ep.ICCID == "" || ep.PhoneNumber == "" {
		t.Errorf("cellular fields empty on a phone fixture that set them: %+v", ep)
	}
}

// Both readers work on the unencrypted backend too — the files are plain either way.
func TestReadersWorkOnUnencryptedBackup(t *testing.T) {
	dir := t.TempDir()
	spec := fullSpec()
	spec.Unencrypted = true
	if _, err := builder.Build(dir, spec); err != nil {
		t.Fatal(err)
	}
	st, err := ReadStatus(dir)
	if err != nil || !st.Present {
		t.Fatalf("BackupStatus on unencrypted = %+v, %v", st, err)
	}
	e, err := ReadDeviceExtras(dir)
	if err != nil || !e.Present {
		t.Fatalf("DeviceExtras on unencrypted = %+v, %v", e, err)
	}
}
