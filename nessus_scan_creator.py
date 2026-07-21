#!/usr/bin/env python3
"""Launcher for separate-per-IP and multi-IP single-scan Nessus creators."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def main() -> int:
    base = Path(__file__).resolve().parent
    options = {
        "1": base / "nessus_master_scan_bulk_creator.py",
        "2": base / "nessus_multi_ip_single_scan_creator.py",
    }

    print("Nessus Scan Creator")
    print("  1) Create a separate scan for each IP")
    print("  2) Create one scan containing multiple IPs")

    while True:
        choice = input("Choose mode [1/2]: ").strip()
        if choice in options:
            break
        print("Please enter 1 or 2.")

    selected = options[choice]
    if not selected.is_file():
        print(f"Required script is missing: {selected}", file=sys.stderr)
        return 1

    command = [sys.executable, str(selected), *sys.argv[1:]]
    return subprocess.run(command, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
