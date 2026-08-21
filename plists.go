package iosbackup

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"howett.net/plist"
)

// This file reads the two plists that are NOT part of the decrypt path: Status.plist and
// Info.plist. Both are unencrypted, so everything here works on a LOCKED backup — Open is
// enough, Unlock is not required and is not consulted.
//
// THEY ARE SEPARATE CALLS FROM DeviceInfo, AND DELIBERATELY SO. The three files cost three
// very different amounts, measured on two real backups:
//
//	Manifest.plist   268 KB / 429 KB   binary   0.8 / 1.6 ms   (already read by Open)
//	Status.plist     189 B  / 189 B    binary   11 / 39 µs
//	Info.plist       904 KB / 9.5 MB   XML      10.5 / 99.3 ms
//
// Folding Info.plist's fields into DeviceInfo would put a 99 ms parse behind a call that is
// currently free, on a struct callers fetch to read a device name. Keeping them apart makes
// the cost visible at the call site and lets a caller pay only for what it shows.
//
// EACH RESULT REPORTS ITS OWN PRESENCE. A backup may legitimately lack either file, and
// "absent" is not a failure — it is a state a caller has to render differently from "read
// it, and the field was empty". Same discipline as Info.FileCountKnown.

// Status is Status.plist: what the backup session itself recorded.
type Status struct {
	// Present is false when the backup has no Status.plist. Every other field is then zero.
	// Check this before reading them — an absent file and a file full of empty strings are
	// different facts about a backup, and only one of them is odd.
	Present bool

	BackupState   string // e.g. "new"
	Date          time.Time
	IsFullBackup  bool   // whether this was a full backup rather than an incremental one
	SnapshotState string // e.g. "finished"
	UUID          string
	Version       string // the backup FORMAT version, e.g. "3.3" — NOT the iOS version
}

// DeviceExtras is the part of Info.plist not already covered by DeviceInfo.
//
// IMEI, ICCID and PhoneNumber are cellular-device fields: present on an iPhone, absent on an
// iPad. Empty means the key was not in the file.
type DeviceExtras struct {
	// Present is false when the backup has no Info.plist. See Status.Present.
	Present bool

	DisplayName      string
	GUID             string
	TargetIdentifier string
	TargetType       string
	ITunesVersion    string
	LastBackupDate   time.Time

	// InstalledApplications is the user-installed bundle-id list.
	//
	// IT IS NOT THE ONLY APP COUNT A BACKUP CONTAINS, and the difference is large enough to
	// mislead: measured on one real iPad, this list holds 21 entries while Manifest.plist's
	// Applications dict holds 1203 — the second counts every bundle with a container,
	// including Apple system services. They answer different questions and a caller should
	// say which one it is showing.
	InstalledApplications []string

	IMEI        string
	ICCID       string
	PhoneNumber string
}

// ReadStatus reads <dir>/Status.plist. It needs no password and works before Unlock.
//
// A missing file is NOT an error: the result reports Present false. Anything else — a file
// that exists and will not parse — is an error, because that is a broken backup rather than
// an old one.
func ReadStatus(dir string) (Status, error) {
	m, present, err := readPlistFile(dir, "Status.plist")
	if err != nil || !present {
		return Status{}, err
	}
	s := Status{
		Present:       true,
		BackupState:   plistString(m, "BackupState"),
		SnapshotState: plistString(m, "SnapshotState"),
		UUID:          plistString(m, "UUID"),
		Version:       plistString(m, "Version"),
	}
	if v, ok := m["IsFullBackup"].(bool); ok {
		s.IsFullBackup = v
	}
	if v, ok := m["Date"].(time.Time); ok {
		s.Date = v
	}
	return s, nil
}

// ReadDeviceExtras reads <dir>/Info.plist. It needs no password and works before Unlock.
//
// THIS IS THE EXPENSIVE ONE — 10 ms on an iPad and 99 ms on a phone, scaling with the app
// count, because the file is XML and carries per-app metadata blobs. Call it once per backup
// and keep the result; it is not a cheap accessor despite looking like one.
//
// A missing file reports Present false rather than erroring; see ReadStatus.
func ReadDeviceExtras(dir string) (DeviceExtras, error) {
	m, present, err := readPlistFile(dir, "Info.plist")
	if err != nil || !present {
		return DeviceExtras{}, err
	}
	e := DeviceExtras{
		Present:          true,
		DisplayName:      plistString(m, "Display Name"),
		GUID:             plistString(m, "GUID"),
		TargetIdentifier: plistString(m, "Target Identifier"),
		TargetType:       plistString(m, "Target Type"),
		ITunesVersion:    plistString(m, "iTunes Version"),
		IMEI:             plistString(m, "IMEI"),
		ICCID:            plistString(m, "ICCID"),
		PhoneNumber:      plistString(m, "Phone Number"),
	}
	if v, ok := m["Last Backup Date"].(time.Time); ok {
		e.LastBackupDate = v
	}
	if raw, ok := m["Installed Applications"].([]any); ok {
		e.InstalledApplications = make([]string, 0, len(raw))
		for _, v := range raw {
			if s, ok := v.(string); ok {
				e.InstalledApplications = append(e.InstalledApplications, s)
			}
		}
	}
	return e, nil
}

// readPlistFile reads and decodes one plist from the backup directory. It reports absence
// separately from failure, because os.IsNotExist is the one error here that is not a fault.
//
// The format is not specified: howett.net/plist detects binary vs XML from the header, and
// a real backup uses both — Info.plist is XML where the other two are binary.
func readPlistFile(dir, name string) (map[string]any, bool, error) {
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	var m map[string]any
	if _, err := plist.Unmarshal(raw, &m); err != nil {
		return nil, false, fmt.Errorf("iosbackup: parse %s: %w", name, err)
	}
	return m, true, nil
}

// plistString reads a string key, yielding "" when the key is absent or is not a string.
// These keys are optional in the real format and a wrong type is not worth failing a whole
// read over — a caller that needs to tell absent from empty has the raw file.
func plistString(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// THESE TAKE A DIRECTORY RATHER THAN A *Backup, AND THAT IS FORCED RATHER THAN STYLISTIC.
//
// Open refuses an unencrypted backup with ErrNotEncrypted, so a *Backup cannot exist for
// one — and these two files are plain on EVERY backup, encrypted or not. As methods they
// would have been unreachable on precisely the backups that need no password at all, which
// is the opposite of useful for a pre-unlock surface. A caller always has the directory: it
// is what it would pass to Open.
//
// Found by a test asserting they worked on an unencrypted fixture. They did not, and could
// not have.
