package iosbackup_test

import (
	"fmt"
	"log"
	"os"

	iosbackup "github.com/novkostya/ios-backup-crypt"
)

// Example opens an encrypted iOS backup, unlocks it with the backup password, prints the
// device summary, and streams a decrypted file out. It is illustrative and is not
// executed (it needs a real backup on disk), but it is compiled with the package so the
// documented API stays correct.
func Example() {
	// The backup directory is the folder that contains Manifest.plist.
	b, err := iosbackup.Open("/path/to/MobileSync/Backup/00000000-000000000000000E")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = b.Close() }()

	// The slow step: derive keys from the password and decrypt the index.
	if err := b.Unlock("your-backup-password"); err != nil {
		log.Fatal(err)
	}

	info, err := b.DeviceInfo()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("%s — iOS %s — %d files\n", info.DeviceName, info.ProductVersion, info.FileCount)

	// Stream the decrypted SMS database to a local file.
	out, err := os.Create("sms.db")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = out.Close() }()

	for entry := range b.List("HomeDomain", "Library/SMS/sms.db") {
		if err := b.DecryptFile(entry.FileID, out); err != nil {
			log.Fatal(err)
		}
	}
	if err := b.Err(); err != nil { // surfaces any error from the List iteration
		log.Fatal(err)
	}
}
