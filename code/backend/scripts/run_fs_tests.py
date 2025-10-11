#!/usr/bin/env python3
"""Run quick in-process tests for the file-security CLI handlers.

This calls the functions in `stegocrypt_cli.py` directly so generated keys
remain in memory across calls (unlike separate CLI invocations).
"""
import os
import sys
import json
import base64
import tempfile
from types import SimpleNamespace

# Ensure backend folder is on path (script is under code/backend/scripts)
BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import stegocrypt_cli as cli


def run_tests():
    print("Running file-security in-process tests...")

    # Initialize backend
    try:
        _ = cli.get_file_security_manager()
    except Exception as e:
        print("Failed to initialize file security manager:", e)
        return

    # 1) generate-keypair
    args = SimpleNamespace(fs_command='generate-keypair')
    res = cli.process_file_security_command(args)
    print("\n== generate-keypair result ==")
    print(json.dumps(res, indent=2))

    public_b64 = res.get('publicKey')
    private_id = res.get('privateKeyId')
    fingerprint = res.get('fingerprint')

    # 2) view-key-info
    args = SimpleNamespace(fs_command='view-key-info')
    res = cli.process_file_security_command(args)
    print("\n== view-key-info result ==")
    print(json.dumps(res, indent=2))

    # 3) export-public-key -> write to temp file
    tmpdir = tempfile.gettempdir()
    out_path = os.path.join(tmpdir, f"stegocrypt_test_{fingerprint or 'key'}.pub")
    args = SimpleNamespace(fs_command='export-public-key', file_path=out_path)
    res = cli.process_file_security_command(args)
    print("\n== export-public-key result ==")
    print(json.dumps(res, indent=2))

    if os.path.exists(out_path):
        size = os.path.getsize(out_path)
        print(f"\nExported public key file: {out_path} ({size} bytes)")
    else:
        print(f"\nExpected exported public key at {out_path} but file not found")


if __name__ == '__main__':
    run_tests()
