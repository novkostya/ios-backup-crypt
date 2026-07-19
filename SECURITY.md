# Security Policy

## Status

`ios-backup-crypt` is a **pre-1.0 cryptographic library and has not undergone an
independent security audit.** Review it before relying on it in a sensitive context.

## Handling sensitive data

This library decrypts iOS backups, which contain highly personal data — messages,
photos, health and location history, keychain items, and more. Treat both the **backup
password** and any **decrypted output** as sensitive.

What the library does with your data:

- It never logs the password, derived keys, or file contents.
- It **streams** file decryption (`DecryptFile`) block-at-a-time rather than buffering
  whole files, so plaintext is not held in memory in bulk.
- While a backup is unlocked it writes a **decrypted copy of the backup index**
  (`Manifest.db`) to a temporary file (created with `0600` permissions). That file is
  removed when you call `Close`. On a shared machine, be aware of your temp directory's
  visibility, and always `Close` the backup when done.

The library only reads from the backup directory; it never writes into it, and never
performs any network I/O.

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** — do not open a public issue.

Use GitHub's private vulnerability reporting: on this repository, open the **Security**
tab and choose **“Report a vulnerability.”** This creates a private advisory visible only
to the maintainers.

Please include a description, affected version or commit, and a reproduction if you have
one. We aim to acknowledge reports within a few days.
