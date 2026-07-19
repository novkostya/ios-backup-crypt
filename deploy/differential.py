#!/usr/bin/env python3
"""Differential check (testing-ladder rung 3).

Decrypt the synthetic fixture with the Python reference implementation
(iphone_backup_decrypt) and byte-compare against this library's Go output. A mismatch
means a constant, tag, or offset was got subtly wrong somewhere in the Go decrypt path.

Usage: python differential.py <DIFF_OUT>

<DIFF_OUT> is produced by `go test -run TestWriteDifferentialFixture` and contains:
    backup/       the synthetic encrypted backup (Manifest.plist + Manifest.db + blobs)
    go/           Go-decrypted outputs: Manifest.db and one file per fileID
    index.json    {"password": ..., "files": [{fileID, domain, relativePath}, ...]}
"""

import json
import os
import sys

from iphone_backup_decrypt import EncryptedBackup


def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def main(work_dir):
    with open(os.path.join(work_dir, "index.json"), "r", encoding="utf-8") as fh:
        index = json.load(fh)

    backup_dir = os.path.join(work_dir, "backup")
    go_dir = os.path.join(work_dir, "go")
    py_dir = os.path.join(work_dir, "py")
    os.makedirs(py_dir, exist_ok=True)

    backup = EncryptedBackup(backup_directory=backup_dir, passphrase=index["password"])

    failures = 0

    # 1) The decrypted Manifest.db must be byte-identical.
    py_manifest = os.path.join(py_dir, "Manifest.db")
    backup.save_manifest_file(py_manifest)
    go_manifest_bytes = _read(os.path.join(go_dir, "Manifest.db"))
    py_manifest_bytes = _read(py_manifest)
    if go_manifest_bytes == py_manifest_bytes:
        print("OK   Manifest.db ({} bytes)".format(len(go_manifest_bytes)))
    else:
        print("FAIL Manifest.db (go {} vs py {} bytes)".format(len(go_manifest_bytes), len(py_manifest_bytes)))
        failures += 1

    # 2) Each file's decrypted contents must be byte-identical.
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

    if failures:
        print("\n{} differential mismatch(es).".format(failures))
        return 1
    print("\nAll differential checks passed (Go output == Python reference).")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: differential.py <DIFF_OUT>", file=sys.stderr)
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
