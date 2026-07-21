#!/usr/bin/env python3
"""
NESSUS MULTI-IP SINGLE SCAN CREATOR

Creates one copied Nessus scan containing multiple individual IP addresses.
Supports:
  1. Unauthenticated scan for all targets.
  2. Authenticated scan using one shared SSH username/password for all targets.

The script uses Nessus API access/secret keys and never launches the scan.
"""

from __future__ import annotations

import csv
import getpass
import ipaddress
import json
import os
import ssl
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

NESSUS_URL = os.getenv("NESSUS_URL", "https://127.0.0.1:8834")
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", os.getenv("ACCESS_KEY", "your_nessus_access_key"))
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", os.getenv("SECRET_KEY", "your_nessus_secret_key"))
REQUEST_TIMEOUT = int(os.getenv("NESSUS_TIMEOUT", "90"))
VERIFY_SSL = os.getenv("NESSUS_VERIFY_SSL", "no").strip().lower() in {"1", "true", "yes", "y"}
ROLLBACK_ON_UPDATE_FAILURE = os.getenv("ROLLBACK_ON_UPDATE_FAILURE", "yes").strip().lower() in {"1", "true", "yes", "y"}
REPORT_FILE = f"multi_ip_single_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"


class C:
    if sys.stdout.isatty():
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        CYAN = "\033[36m"
        BOLD = "\033[1m"
        NC = "\033[0m"
    else:
        RED = GREEN = YELLOW = BLUE = CYAN = BOLD = NC = ""


def info(message: str) -> None:
    print(f"{C.CYAN}[*] {message}{C.NC}")


def success(message: str) -> None:
    print(f"{C.GREEN}[+] {message}{C.NC}")


def warning(message: str) -> None:
    print(f"{C.YELLOW}[WARNING] {message}{C.NC}")


def fatal(message: str) -> None:
    print(f"{C.RED}[ERROR] {message}{C.NC}")
    raise SystemExit(1)


def extract_error(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("error", "message", "detail"):
            if data.get(key):
                return str(data[key])
        return json.dumps(data, ensure_ascii=False)
    return str(data)


def walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def has_nonempty(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, dict):
        return any(has_nonempty(item) for item in value.values())
    if isinstance(value, list):
        return any(has_nonempty(item) for item in value)
    return True


def safe_name(value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in value.strip())
    return cleaned.strip("_") or "MULTI_IP_SCAN"


def ask_choice(prompt: str, allowed: List[str]) -> str:
    normalized = {item.lower() for item in allowed}
    while True:
        value = input(prompt).strip().lower()
        if value in normalized:
            return value
        warning(f"Allowed choices: {', '.join(allowed)}")


@dataclass
class Folder:
    id: str
    name: str
    folder_type: str
    selectable: bool


@dataclass
class Scan:
    id: str
    name: str
    folder_id: str
    status: str
    uuid: str
    policy_id: str


class NessusClient:
    def __init__(self, base_url: str, access_key: str, secret_key: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.ssl_context = ssl.create_default_context() if VERIFY_SSL else ssl._create_unverified_context()

        if not access_key or access_key in {"your_nessus_access_key", "PUT_YOUR_ACCESS_KEY_HERE"}:
            fatal("Set NESSUS_ACCESS_KEY before running the script.")
        if not secret_key or secret_key in {"your_nessus_secret_key", "PUT_YOUR_SECRET_KEY_HERE"}:
            fatal("Set NESSUS_SECRET_KEY before running the script.")

    @property
    def auth_header(self) -> str:
        return f"accessKey={self.access_key}; secretKey={self.secret_key}"

    def request(self, method: str, endpoint: str, payload: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        headers = {"X-ApiKeys": self.auth_header, "Accept": "application/json"}
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"{self.base_url}{endpoint}",
            data=body,
            method=method.upper(),
            headers=headers,
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT,
                context=self.ssl_context,
            ) as response:
                raw = response.read().decode("utf-8", errors="replace")
                return response.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            try:
                return exc.code, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return exc.code, raw
        except urllib.error.URLError as exc:
            fatal(f"Unable to connect to {self.base_url}: {exc}")
        except TimeoutError:
            fatal(f"Nessus request timed out after {REQUEST_TIMEOUT} seconds.")
        return 0, {}

    def get_ok(self, endpoint: str) -> Any:
        status, data = self.request("GET", endpoint)
        if status != 200:
            fatal(f"GET {endpoint} failed. HTTP {status}: {extract_error(data)}")
        return data

    def test_connection(self) -> None:
        info("Testing Nessus API connection with access key and secret key...")
        status, data = self.request("GET", "/server/status")
        if status != 200:
            fatal(f"Nessus connection failed. HTTP {status}: {extract_error(data)}")
        success("Connected to Nessus API successfully.")

    def load_folders(self) -> List[Folder]:
        data = self.get_ok("/folders")
        folders: List[Folder] = []
        for item in data.get("folders", []):
            folder_id = str(item.get("id", ""))
            name = str(item.get("name", "Unnamed Folder")).replace("\n", " ").replace("\t", " ")
            folder_type = str(item.get("type", "unknown"))
            normalized_name = name.strip().lower()
            selectable = normalized_name not in {"trash", "all scans"} and folder_type.strip().lower() != "trash"
            if folder_id:
                folders.append(Folder(folder_id, name, folder_type, selectable))
        if not folders:
            fatal("No Nessus folders were returned.")
        return folders

    def load_scans(self) -> List[Scan]:
        data = self.get_ok("/scans")
        scans: List[Scan] = []
        for item in data.get("scans", []):
            scan_id = str(item.get("id", ""))
            if not scan_id:
                continue
            scans.append(
                Scan(
                    id=scan_id,
                    name=str(item.get("name", "Unnamed Scan")).replace("\n", " ").replace("\t", " "),
                    folder_id=str(item.get("folder_id", "")),
                    status=str(item.get("status", "unknown")),
                    uuid=str(item.get("uuid") or ""),
                    policy_id=str(item.get("policy_id", "")),
                )
            )
        if not scans:
            fatal("No Nessus scan configurations were returned.")
        return scans

    def resolve_editor_uuid(self, scan_id: str) -> str:
        status, data = self.request("GET", f"/editor/scan/{scan_id}")
        if status == 200 and isinstance(data, dict):
            candidates = [data.get("uuid"), data.get("template_uuid")]
            for key in ("scan", "policy", "template"):
                child = data.get(key)
                if isinstance(child, dict):
                    candidates.extend([child.get("uuid"), child.get("template_uuid")])
            for candidate in candidates:
                if candidate:
                    return str(candidate)

        status, data = self.request("GET", f"/scans/{scan_id}")
        if status == 200 and isinstance(data, dict):
            for child in (data.get("scan"), data.get("info"), data):
                if isinstance(child, dict) and child.get("uuid"):
                    return str(child["uuid"])
        fatal("Unable to determine the master scan editor UUID.")
        return ""

    def ensure_master_has_no_credentials(self, scan_id: str) -> None:
        info("Checking the master scan for existing credentials...")
        status, data = self.request("GET", f"/editor/scan/{scan_id}")
        if status != 200:
            warning("Could not inspect master credentials. Verify manually before continuing.")
            return
        for item in walk(data):
            credentials = item.get("credentials")
            if isinstance(credentials, dict):
                current = credentials.get("current")
                if isinstance(current, dict) and has_nonempty(current):
                    fatal("The master scan already contains credentials. Remove them before copying it.")
        success("No existing credentials were detected in the master scan.")

    def detect_ssh_password_method(self) -> str:
        status, data = self.request("GET", "/credentials/types")
        if status != 200:
            warning("Unable to read SSH credential schema; using auth_method=password.")
            return "password"
        for item in walk(data):
            if str(item.get("id") or item.get("name") or "").lower() != "ssh":
                continue
            for child in walk(item):
                if str(child.get("id") or "").lower() != "auth_method":
                    continue
                for option in child.get("options", []) if isinstance(child.get("options"), list) else []:
                    if not isinstance(option, dict):
                        continue
                    option_id = str(option.get("id") or "")
                    option_name = str(option.get("name") or "")
                    if option_id.lower() == "password" or option_name.lower() == "password":
                        return option_id or "password"
        return "password"

    def copy_scan(self, master_scan_id: str, folder_id: str, scan_name: str) -> str:
        status, data = self.request(
            "POST",
            f"/scans/{master_scan_id}/copy",
            {"folder_id": int(folder_id), "name": scan_name},
        )
        if status not in (200, 201):
            raise RuntimeError(f"Copy failed. HTTP {status}: {extract_error(data)}")
        if isinstance(data, dict):
            candidates = [data]
            for key in ("scan", "copy", "configuration"):
                if isinstance(data.get(key), dict):
                    candidates.insert(0, data[key])
            for item in candidates:
                if item.get("id") is not None:
                    return str(item["id"])
        raise RuntimeError("Copy succeeded, but the copied scan ID was not returned.")

    def update_scan(
        self,
        copied_scan_id: str,
        editor_uuid: str,
        destination_folder_id: str,
        scan_name: str,
        master_scan_name: str,
        targets: List[str],
        credential: Optional[Dict[str, str]],
        ssh_auth_method: str,
    ) -> None:
        target_text = "\n".join(targets)
        authenticated = credential is not None
        description = (
            f"Copied from '{master_scan_name}'. Contains {len(targets)} targets and uses one shared SSH credential across all targets."
            if authenticated
            else f"Copied from '{master_scan_name}'. Contains {len(targets)} unauthenticated targets."
        )
        payload: Dict[str, Any] = {
            "uuid": editor_uuid,
            "settings": {
                "name": scan_name,
                "description": description,
                "folder_id": int(destination_folder_id),
                "text_targets": target_text,
                "enabled": False,
            },
        }
        if credential:
            payload["credentials"] = {
                "add": {
                    "Host": {
                        "SSH": [
                            {
                                "auth_method": ssh_auth_method,
                                "username": credential["username"],
                                "password": credential["password"],
                            }
                        ]
                    }
                }
            }
        status, data = self.request("PUT", f"/scans/{copied_scan_id}", payload)
        if status not in (200, 201):
            raise RuntimeError(f"Update failed. HTTP {status}: {extract_error(data)}")

    def delete_scan_best_effort(self, scan_id: str) -> None:
        if not ROLLBACK_ON_UPDATE_FAILURE:
            return
        status, data = self.request("DELETE", f"/scans/{scan_id}")
        if status in (200, 202, 204):
            warning(f"Removed incomplete copied scan ID {scan_id}.")
        else:
            warning(f"Could not remove incomplete scan ID {scan_id}. HTTP {status}: {extract_error(data)}")


def load_targets(path: Path) -> List[str]:
    targets: List[str] = []
    invalid: List[str] = []
    seen = set()
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    for raw in text.replace(",", "\n").splitlines():
        candidate = raw.strip()
        if not candidate or candidate.startswith("#"):
            continue
        try:
            ip = str(ipaddress.ip_address(candidate))
        except ValueError:
            invalid.append(candidate)
            continue
        if ip not in seen:
            targets.append(ip)
            seen.add(ip)
    if invalid:
        warning("Invalid entries skipped: " + ", ".join(invalid))
    if not targets:
        fatal(f"No valid individual IP addresses were found in {path}")
    success(f"Loaded {len(targets)} unique IP address(es).")
    return targets


def select_folder(folders: List[Folder], title: str) -> Folder:
    print(f"\n{C.BLUE}{C.BOLD}{title}{C.NC}")
    for index, folder in enumerate(folders, start=1):
        marker = "" if folder.selectable else " [not selectable]"
        print(f" {index:3d}) {folder.name} [ID: {folder.id} | Type: {folder.folder_type}]{marker}")
    while True:
        value = input("Select folder number (or q to quit): ").strip().lower()
        if value == "q":
            raise SystemExit(0)
        if value.isdigit() and 1 <= int(value) <= len(folders):
            selected = folders[int(value) - 1]
            if selected.selectable:
                return selected
            warning("That folder cannot be selected.")
        else:
            warning("Enter a valid folder number.")


def select_master_scan(scans: List[Scan], folder: Folder) -> Scan:
    candidates = [scan for scan in scans if scan.folder_id == folder.id]
    if not candidates:
        fatal(f"No scans were found in folder '{folder.name}'.")
    print(f"\n{C.BLUE}{C.BOLD}Select Master Scan from {folder.name}{C.NC}")
    for index, scan in enumerate(candidates, start=1):
        print(f" {index:3d}) {scan.name} [ID: {scan.id} | Status: {scan.status}]")
    while True:
        value = input("Select master scan number (or q to quit): ").strip().lower()
        if value == "q":
            raise SystemExit(0)
        if value.isdigit() and 1 <= int(value) <= len(candidates):
            selected = candidates[int(value) - 1]
            if selected.policy_id and selected.policy_id not in {"0", "null", "None"}:
                warning(f"Selected scan reports policy_id={selected.policy_id}. An independent Advanced Scan master is recommended.")
            return selected
        warning("Enter a valid scan number.")


def prompt_ip_file(default_path: str = "") -> Path:
    while True:
        suffix = f" [{default_path}]" if default_path else ""
        raw = input(f"Enter IP file path{suffix}: ").strip().strip('"').strip("'")
        if not raw and default_path:
            raw = default_path
        path = Path(os.path.expanduser(raw))
        if path.is_file() and os.access(path, os.R_OK):
            return path
        warning(f"File is missing or unreadable: {path}")


def prompt_shared_credential() -> Dict[str, str]:
    print(f"\n{C.YELLOW}{C.BOLD}Shared credential warning{C.NC}")
    warning("This one SSH credential may be attempted against every IP in the scan.")
    warning("Use this only when all targets are approved to use the same account and lockout risk is controlled.")
    if ask_choice("Continue with one shared SSH credential? [y/N]: ", ["y", "n", ""]) != "y":
        raise SystemExit(0)
    while True:
        username = input("Shared SSH username: ").strip()
        if username:
            break
        warning("Username cannot be empty.")
    while True:
        password = getpass.getpass("Shared SSH password: ")
        confirm = getpass.getpass("Confirm shared SSH password: ")
        if not password:
            warning("Password cannot be empty.")
        elif password != confirm:
            warning("Passwords do not match.")
        else:
            return {"username": username, "password": password}


def write_report(targets: List[str], scan_name: str, scan_id: str, mode: str, status: str) -> None:
    with open(REPORT_FILE, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["IP", "Scan Name", "Scan ID", "Mode", "Status"])
        for target in targets:
            writer.writerow([target, scan_name, scan_id, mode, status])


def print_banner() -> None:
    print(f"{C.CYAN}{C.BOLD}===============================================================================")
    print("                    NESSUS MULTI-IP SINGLE SCAN CREATOR")
    print(f"==============================================================================={C.NC}")
    print("Creates one copied Nessus scan containing all IPs from one file.")
    print("The created scan remains disabled and is never launched automatically.\n")


def main() -> None:
    print_banner()
    default_ip_file = sys.argv[1] if len(sys.argv) > 1 else ""

    print("  1) Unauthenticated: multiple IPs in one scan")
    print("  2) Authenticated: multiple IPs with one shared SSH credential")
    mode_choice = ask_choice("Choose mode [1/2]: ", ["1", "2"])
    mode = "Authenticated - shared SSH credential" if mode_choice == "2" else "Unauthenticated"

    client = NessusClient(NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY)
    client.test_connection()
    folders = client.load_folders()
    scans = client.load_scans()

    master_folder = select_folder(folders, "Select Folder Containing the Master Scan")
    master_scan = select_master_scan(scans, master_folder)
    destination_folder = select_folder(folders, "Select Destination Folder")

    client.ensure_master_has_no_credentials(master_scan.id)
    editor_uuid = client.resolve_editor_uuid(master_scan.id)

    ip_file = prompt_ip_file(default_ip_file)
    targets = load_targets(ip_file)

    default_name = safe_name(f"{destination_folder.name}_MULTI_{len(targets)}_HOSTS")
    entered_name = input(f"New scan name [{default_name}]: ").strip()
    scan_name = safe_name(entered_name or default_name)

    existing_names = {scan.name for scan in scans}
    if scan_name in existing_names:
        fatal(f"A scan named '{scan_name}' already exists. Choose a different name.")

    credential: Optional[Dict[str, str]] = None
    ssh_auth_method = "password"
    if mode_choice == "2":
        credential = prompt_shared_credential()
        ssh_auth_method = client.detect_ssh_password_method()

    print(f"\n{C.BLUE}{C.BOLD}Review{C.NC}")
    print(f"Master scan       : {master_scan.name} (ID: {master_scan.id})")
    print(f"Destination folder: {destination_folder.name} (ID: {destination_folder.id})")
    print(f"New scan name     : {scan_name}")
    print(f"Mode              : {mode}")
    print(f"Target count      : {len(targets)}")
    print("Automatic launch  : Disabled")
    if ask_choice("Create this one scan now? [y/N]: ", ["y", "n", ""]) != "y":
        warning("Cancelled. No scan was created.")
        raise SystemExit(0)

    copied_id = ""
    try:
        copied_id = client.copy_scan(master_scan.id, destination_folder.id, scan_name)
        success(f"Master scan copied. New scan ID: {copied_id}")
        client.update_scan(
            copied_scan_id=copied_id,
            editor_uuid=editor_uuid,
            destination_folder_id=destination_folder.id,
            scan_name=scan_name,
            master_scan_name=master_scan.name,
            targets=targets,
            credential=credential,
            ssh_auth_method=ssh_auth_method,
        )
        success(f"Updated one scan with {len(targets)} targets.")
        write_report(targets, scan_name, copied_id, mode, "Created and updated")
    except Exception as exc:
        if copied_id:
            client.delete_scan_best_effort(copied_id)
        write_report(targets, scan_name, copied_id, mode, f"Failed: {exc}")
        fatal(str(exc))

    print(f"\n{C.GREEN}{C.BOLD}Completed successfully.{C.NC}")
    print(f"Scan ID           : {copied_id}")
    print(f"Targets           : {len(targets)}")
    print(f"Report            : {REPORT_FILE}")
    print("Automatic launch  : Disabled")
    if credential:
        warning("Before launch, confirm Credentials > Host > SSH and verify the shared account is valid for every target.")
    else:
        warning("Review the target list in Nessus before launching the scan manually.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warning("Interrupted by user. Any scan already created may remain in Nessus.")
        raise SystemExit(130)
