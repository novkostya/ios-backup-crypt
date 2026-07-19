#!/usr/bin/env python3
"""Differential check against the Python reference implementation.

Decrypt a backup with iphone_backup_decrypt and byte-compare against this library's Go
output. Used two ways:

  * synthetic fixture (testing-ladder rung 3, `make gates-diff`):
        python differential.py <WORKDIR>
    where <WORKDIR> holds backup/ (the fixture), go/ (Go output), index.json (with the
    throwaway password).

  * real backup (rung 4, operator-local, `make gates-real`):
        python differential.py <WORKDIR> --backup <DIR> --password-env <VAR>
    where <DIR> is the real backup (bind-mounted read-only) and the password is read from
    the named environment variable — never from a file or the command line.

A mismatch means a constant, tag, or offset was got subtly wrong in the Go decrypt path.
"""

import argparse
import json
import os
import sys

from iphone_backup_decrypt import EncryptedBackup


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("workdir")
    ap.add_argument("--backup", default=None, help="backup dir (default: <workdir>/backup)")
    ap.add_argument("--password-env", default=None, help="env var holding the password (default: index.json)")
    args = ap.parse_args()

    with open(os.path.join(args.workdir, "index.json"), "r", encoding="utf-8") as fh:
        index = json.load(fh)

    backup_dir = args.backup or os.path.join(args.workdir, "backup")
    if args.password_env:
        password = os.environ[args.password_env]
    else:
        password = index["password"]

    go_dir = os.path.join(args.workdir, "go")
    py_dir = os.path.join(args.workdir, "py")
    os.makedirs(py_dir, exist_ok=True)

    backup = EncryptedBackup(backup_directory=backup_dir, passphrase=password)

    failures = 0

    # 1) The decrypted Manifest.db must be byte-identical.
    py_manifest = os.path.join(py_dir, "Manifest.db")
    backup.save_manifest_file(py_manifest)
    go_bytes = _read(os.path.join(go_dir, "Manifest.db"))
    py_bytes = _read(py_manifest)
    if go_bytes == py_bytes:
        print("OK   Manifest.db ({} bytes)".format(len(go_bytes)))
    else:
        print("FAIL Manifest.db (go {} vs py {} bytes)".format(len(go_bytes), len(py_bytes)))
        failures += 1

    # 2) Each sampled file's decrypted contents must be byte-identical.
    for entry in index["files"]:
        go_data = _read(os.path.join(go_dir, entry["fileID"]))
        py_data = backup.extract_file_as_bytes(entry["relativePath"], domain_like=entry["domain"])
        label = "{} / {}".format(entry["domain"], entry["relativePath"])
        if py_data is not None and py_data == go_data:
            print("OK   {} ({} bytes)".format(label, len(go_data)))
        else:
            py_len = len(py_data) if py_data is not None else -1
            print("FAIL {} (go {} vs py {} bytes)".format(label, len(go_data), py_len))
            failures += 1

    n = len(index["files"])
    if failures:
        print("\n{} differential mismatch(es) across Manifest.db + {} files.".format(failures, n))
        return 1
    print("\nAll differential checks passed (Go output == Python reference): Manifest.db + {} files.".format(n))
    return 0


if __name__ == "__main__":
    sys.exit(main())
