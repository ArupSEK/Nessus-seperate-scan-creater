#!/usr/bin/env python3
"""
NESSUS MASTER SCAN BULK CREATOR - PYTHON VERSION
Author  : Sleeping Bhudda
Purpose :
  1. Create separate Nessus scan copies from one credential-free master scan.
  2. Support authenticated and unauthenticated scan creation.
  3. Keep Back option before IP/credential entry.
  4. In Manual Secure Entry mode, create each scan immediately after that IP credential is entered.
  5. Store manual credentials in a local protected file for future reuse.
  6. Never launch scans automatically.

Security note:
  The local credential file is protected with OS file permissions only:
      ~/.nessus_bulk_creator/manual_credentials.json
  Permission is set to 600 and parent folder to 700.
  For stronger security, use full disk encryption or replace this store with GPG/secret-manager storage.
"""

from __future__ import annotations

import csv
import getpass
import ipaddress
import json
import os
import ssl
import stat
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# EDIT THESE VALUES OR USE ENVIRONMENT VARIABLES BEFORE RUNNING
# =============================================================================
NESSUS_URL = os.getenv("NESSUS_URL", "https://127.0.0.1:8834")
NESSUS_ACCESS_KEY = os.getenv("NESSUS_ACCESS_KEY", os.getenv("ACCESS_KEY", "your_nessus_access_key"))
NESSUS_SECRET_KEY = os.getenv("NESSUS_SECRET_KEY", os.getenv("SECRET_KEY", "your_nessus_secret_key"))

# =============================================================================
# OPTIONAL BEHAVIOUR
# =============================================================================
CURL_TIMEOUT = int(os.getenv("CURL_TIMEOUT", "90"))
SKIP_EXISTING_NAMES = os.getenv("SKIP_EXISTING_NAMES", "yes").lower() == "yes"
ROLLBACK_ON_UPDATE_FAILURE = os.getenv("ROLLBACK_ON_UPDATE_FAILURE", "yes").lower() == "yes"
VERIFY_FIRST_AUTH_CREDENTIAL = os.getenv("VERIFY_FIRST_AUTH_CREDENTIAL", "yes").lower() == "yes"

# Local persistent storage for manually entered credentials
LOCAL_STORE_DIR = Path(os.getenv("NESSUS_BULK_CREATOR_HOME", str(Path.home() / ".nessus_bulk_creator")))
LOCAL_CREDENTIAL_STORE = LOCAL_STORE_DIR / "manual_credentials.json"

REPORT_FILE = f"master_scan_copies_python_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"


# =============================================================================
# COLORS
# =============================================================================
class C:
    if sys.stdout.isatty():
        RED = "\033[31m"
        GREEN = "\033[32m"
        YELLOW = "\033[33m"
        BLUE = "\033[34m"
        MAGENTA = "\033[35m"
        CYAN = "\033[36m"
        BOLD = "\033[1m"
        NC = "\033[0m"
    else:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = BOLD = NC = ""


def info(message: str) -> None:
    print(f"{C.CYAN}[*] {message}{C.NC}")


def success(message: str) -> None:
    print(f"{C.GREEN}[+] {message}{C.NC}")


def warning(message: str) -> None:
    print(f"{C.YELLOW}[WARNING] {message}{C.NC}")


def error(message: str) -> None:
    print(f"{C.RED}[ERROR] {message}{C.NC}")


def fatal(message: str) -> None:
    error(message)
    raise SystemExit(1)


# =============================================================================
# DATA STRUCTURES
# =============================================================================
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
    scan_type: str


@dataclass
class Selection:
    scan_mode: str = ""
    scan_mode_label: str = ""
    auth_input_mode: str = ""
    auth_input_label: str = ""
    master_folder_id: str = ""
    master_folder_name: str = ""
    master_scan_id: str = ""
    master_scan_name: str = ""
    master_scan_status: str = ""
    master_scan_uuid: str = ""
    master_policy_id: str = ""
    master_scan_type: str = ""
    destination_folder_id: str = ""
    destination_folder_name: str = ""
    ssh_auth_method: str = "password"


# =============================================================================
# UTILITY
# =============================================================================
def print_banner() -> None:
    os.system("clear 2>/dev/null")
    print(f"{C.CYAN}{C.BOLD}==============================================================================={C.NC}")
    print(f"{C.GREEN}{C.BOLD}                NESSUS MASTER SCAN BULK CREATOR - PYTHON{C.NC}")
    print(f"{C.MAGENTA}{C.BOLD}                         Author: Sleeping Bhudda{C.NC}")
    print(f"{C.CYAN}{C.BOLD}==============================================================================={C.NC}")
    print(f"{C.YELLOW}{C.BOLD}Updated Manual Flow:{C.NC}")
    print("  1. Choose scan type")
    print("  2. Connect to Nessus and select folders/master scan FIRST")
    print("  3. Review selection and use Back if folder/master/destination is wrong")
    print("  4. In manual mode, type credential for one IP")
    print("  5. That IP scan is created immediately")
    print("  6. Credential is stored locally for future reuse")
    print("  7. Scans are never launched automatically")
    print(f"{C.CYAN}{C.BOLD}==============================================================================={C.NC}\n")


def sanitize_name_part(value: str) -> str:
    return value.replace("/", "_").replace(":", "_").replace(" ", "_")


def prompt_choice(prompt: str, allowed: List[str]) -> str:
    allowed_lower = [x.lower() for x in allowed]
    while True:
        value = input(prompt).strip()
        if value.lower() in allowed_lower:
            return value.lower()
        warning(f"Allowed choices: {', '.join(allowed)}")


def normalize_path(raw_path: str) -> Path:
    raw_path = raw_path.strip().strip('"').strip("'")
    return Path(os.path.expanduser(raw_path))


def prompt_file(title: str, instructions: str, prompt_text: str, default_path: str = "") -> Path:
    print(f"\n{C.BLUE}{C.BOLD}{title}{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")
    print(instructions)

    while True:
        display_prompt = prompt_text
        if default_path:
            display_prompt = f"{prompt_text}[{default_path}] "
        raw = input(display_prompt).strip()
        if not raw and default_path:
            raw = default_path

        path = normalize_path(raw)
        if not raw:
            warning("File path cannot be empty.")
            continue
        if not path.exists():
            warning(f"Path does not exist: {path}")
            default_path = str(path)
            continue
        if not path.is_file():
            warning(f"This is not a regular file: {path}")
            default_path = str(path)
            continue
        if not os.access(path, os.R_OK):
            warning(f"File is not readable: {path}")
            default_path = str(path)
            continue
        return path


def recursive_walk(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from recursive_walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from recursive_walk(child)


def has_nonempty(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, dict):
        return any(has_nonempty(v) for v in value.values())
    if isinstance(value, list):
        return any(has_nonempty(v) for v in value)
    return True


def extract_error_message(data: Any) -> str:
    if isinstance(data, dict):
        for key in ("error", "message", "detail"):
            if data.get(key):
                return str(data[key])
        return json.dumps(data, ensure_ascii=False)
    return str(data)


# =============================================================================
# LOCAL CREDENTIAL STORE
# =============================================================================
def ensure_local_store() -> None:
    LOCAL_STORE_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(LOCAL_STORE_DIR, 0o700)

    if not LOCAL_CREDENTIAL_STORE.exists():
        payload = {
            "warning": "Passwords are protected by local OS file permissions only, not encrypted.",
            "created_by": "Nessus Master Scan Bulk Creator Python",
            "credentials": {},
        }
        LOCAL_CREDENTIAL_STORE.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.chmod(LOCAL_CREDENTIAL_STORE, 0o600)


def load_local_credentials() -> Dict[str, Dict[str, str]]:
    ensure_local_store()
    try:
        data = json.loads(LOCAL_CREDENTIAL_STORE.read_text(encoding="utf-8"))
        credentials = data.get("credentials", {})
        if isinstance(credentials, dict):
            return credentials
    except Exception:
        warning("Could not read local credential store. A new one will be used.")
    return {}


def save_local_credential(ip: str, username: str, password: str) -> None:
    ensure_local_store()
    try:
        data = json.loads(LOCAL_CREDENTIAL_STORE.read_text(encoding="utf-8"))
    except Exception:
        data = {
            "warning": "Passwords are protected by local OS file permissions only, not encrypted.",
            "created_by": "Nessus Master Scan Bulk Creator Python",
            "credentials": {},
        }

    if not isinstance(data.get("credentials"), dict):
        data["credentials"] = {}

    data["credentials"][ip] = {
        "username": username,
        "password": password,
        "updated_at": datetime.now().isoformat(timespec="seconds"),
    }

    temp_path = LOCAL_CREDENTIAL_STORE.with_suffix(".json.tmp")
    temp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.chmod(temp_path, 0o600)
    temp_path.replace(LOCAL_CREDENTIAL_STORE)
    os.chmod(LOCAL_CREDENTIAL_STORE, 0o600)


def get_manual_credential_for_ip(ip: str) -> Dict[str, str]:
    local_credentials = load_local_credentials()
    existing = local_credentials.get(ip)

    if existing and existing.get("username") and existing.get("password"):
        print(f"\n{C.CYAN}Target: {ip}{C.NC}")
        print(f"Stored credential found for this IP. Username: {existing.get('username')}")
        choice = prompt_choice("Use stored credential? [y=use / n=re-enter / q=quit]: ", ["y", "n", "q"])
        if choice == "q":
            warning("Operation cancelled.")
            raise SystemExit(0)
        if choice == "y":
            return {"username": existing["username"], "password": existing["password"]}

    print(f"\n{C.CYAN}Target: {ip}{C.NC}")
    while True:
        username = input("SSH username: ").strip()
        if username:
            break
        warning("Username cannot be empty.")

    while True:
        password = getpass.getpass("SSH password: ")
        confirm_password = getpass.getpass("Confirm SSH password: ")
        if not password:
            warning("Password cannot be empty.")
            continue
        if password != confirm_password:
            warning("Passwords do not match.")
            continue
        break

    save_local_credential(ip, username, password)
    success(f"Credential saved locally with chmod 600: {LOCAL_CREDENTIAL_STORE}")
    return {"username": username, "password": password}


# =============================================================================
# NESSUS API CLIENT
# =============================================================================
class NessusClient:
    def __init__(self, base_url: str, access_key: str, secret_key: str):
        self.base_url = base_url.rstrip("/")
        self.access_key = access_key
        self.secret_key = secret_key
        self.ssl_context = ssl._create_unverified_context()

        if not access_key or access_key in {"your_nessus_access_key", "PUT_YOUR_ACCESS_KEY_HERE"}:
            fatal("Add your Nessus access key in the script or export NESSUS_ACCESS_KEY.")
        if not secret_key or secret_key in {"your_nessus_secret_key", "PUT_YOUR_SECRET_KEY_HERE"}:
            fatal("Add your Nessus secret key in the script or export NESSUS_SECRET_KEY.")

    @property
    def auth_header(self) -> str:
        return f"accessKey={self.access_key}; secretKey={self.secret_key}"

    def request(self, method: str, endpoint: str, payload: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        url = f"{self.base_url}{endpoint}"
        data = None
        headers = {
            "X-ApiKeys": self.auth_header,
            "Accept": "application/json",
        }

        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, method=method.upper(), headers=headers)

        try:
            with urllib.request.urlopen(req, timeout=CURL_TIMEOUT, context=self.ssl_context) as response:
                raw = response.read().decode("utf-8", errors="replace")
                return response.status, self._parse_json(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            return exc.code, self._parse_json(raw)
        except urllib.error.URLError as exc:
            fatal(f"Unable to connect to {self.base_url}: {exc}")
        except TimeoutError:
            fatal(f"Connection timed out after {CURL_TIMEOUT} seconds.")
        return 0, {}

    @staticmethod
    def _parse_json(raw: str) -> Any:
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except Exception:
            return raw

    def get_ok(self, endpoint: str) -> Any:
        status, data = self.request("GET", endpoint)
        if status != 200:
            fatal(f"GET {endpoint} failed. HTTP {status}: {extract_error_message(data)}")
        return data

    def test_connection(self) -> None:
        info("Testing Nessus API connection...")
        status, data = self.request("GET", "/server/status")
        if status != 200:
            fatal(f"Nessus connection failed. HTTP {status}: {extract_error_message(data)}")
        success("Connected to Nessus successfully.")

    def load_folders(self) -> List[Folder]:
        info("Retrieving folders from Nessus...")
        data = self.get_ok("/folders")
        folders = []

        for folder in data.get("folders", []):
            folder_id = str(folder.get("id", ""))
            name = str(folder.get("name", "Unnamed Folder")).replace("\t", " ").replace("\n", " ")
            folder_type = str(folder.get("type", "unknown")).replace("\t", " ").replace("\n", " ")
            normalized_name = name.strip().lower()
            normalized_type = folder_type.strip().lower()
            selectable = normalized_name not in {"trash", "all scans"} and normalized_type != "trash"
            if folder_id:
                folders.append(Folder(folder_id, name, folder_type, selectable))

        if not folders:
            fatal("No folders were returned by Nessus.")
        return folders

    def load_scans(self) -> List[Scan]:
        info("Retrieving existing scan configurations from Nessus...")
        data = self.get_ok("/scans")
        scans = []

        for scan in data.get("scans", []):
            scan_id = str(scan.get("id", ""))
            if not scan_id:
                continue
            scans.append(
                Scan(
                    id=scan_id,
                    name=str(scan.get("name", "Unnamed Scan")).replace("\t", " ").replace("\n", " "),
                    folder_id=str(scan.get("folder_id", "")),
                    status=str(scan.get("status", "unknown")),
                    uuid=str(scan.get("uuid") or ""),
                    policy_id=str(scan.get("policy_id", "")),
                    scan_type=str(scan.get("type", "")),
                )
            )

        if not scans:
            fatal("No scan configurations were returned by Nessus.")
        return scans

    def resolve_master_uuid(self, selection: Selection) -> str:
        info("Retrieving the Master Scan editor UUID required for updates...")
        status, data = self.request("GET", f"/editor/scan/{selection.master_scan_id}")

        if status == 200 and isinstance(data, dict):
            candidates = [data.get("uuid"), data.get("template_uuid")]
            for key in ("scan", "policy", "template"):
                value = data.get(key)
                if isinstance(value, dict):
                    candidates.extend([value.get("uuid"), value.get("template_uuid")])
            for candidate in candidates:
                if candidate:
                    success("Master editor UUID loaded successfully.")
                    return str(candidate)

        warning("The editor endpoint did not expose a UUID; trying scan details fallback.")
        status, details = self.request("GET", f"/scans/{selection.master_scan_id}")
        if status == 200 and isinstance(details, dict):
            for obj in (details.get("scan"), details.get("info"), details):
                if isinstance(obj, dict) and obj.get("uuid"):
                    warning("Using fallback scan UUID because editor UUID was unavailable.")
                    return str(obj["uuid"])

        fatal("Unable to determine the Master Scan UUID required for PUT /scans/{id}.")
        return ""

    def check_master_credentials(self, selection: Selection) -> None:
        info("Checking whether the selected Master Scan already contains credentials...")
        status, data = self.request("GET", f"/editor/scan/{selection.master_scan_id}")
        if status != 200:
            warning("Could not inspect Master Scan credentials. Confirm manually that the master contains no credentials.")
            return

        detected = "no"
        for obj in recursive_walk(data):
            credentials = obj.get("credentials")
            if isinstance(credentials, dict):
                current = credentials.get("current")
                if isinstance(current, dict) and has_nonempty(current):
                    detected = "yes"
                    break

        if detected == "yes":
            fatal("The selected Master Scan contains existing credentials. Remove them before copying to avoid account lockout.")
        success("No existing credentials were detected in the Master Scan.")

    def detect_ssh_password_auth_method(self) -> str:
        info("Determining the exact SSH password authentication method ID...")
        status, data = self.request("GET", "/credentials/types")
        if status != 200:
            warning("Could not read the SSH schema; using auth_method=password")
            return "password"

        for obj in recursive_walk(data):
            type_id = str(obj.get("id") or obj.get("name") or "").lower()
            if type_id != "ssh":
                continue

            for child in recursive_walk(obj):
                if str(child.get("id") or "").lower() != "auth_method":
                    continue
                options = child.get("options")
                if not isinstance(options, list):
                    continue
                for option in options:
                    if not isinstance(option, dict):
                        continue
                    option_id = str(option.get("id") or "")
                    option_name = str(option.get("name") or "")
                    if option_id.lower() == "password" or option_name.lower() == "password":
                        success(f"SSH auth_method: {option_id or 'password'}")
                        return option_id or "password"

        warning("Could not detect exact SSH password method; using auth_method=password")
        return "password"

    def copy_master_scan(self, master_scan_id: str, folder_id: str, scan_name: str) -> str:
        payload = {"folder_id": int(folder_id), "name": scan_name}
        status, data = self.request("POST", f"/scans/{master_scan_id}/copy", payload)
        if status not in (200, 201):
            raise RuntimeError(f"Copy failed HTTP {status}: {extract_error_message(data)}")

        candidates = []
        if isinstance(data, dict):
            for key in ("scan", "copy", "configuration"):
                value = data.get(key)
                if isinstance(value, dict):
                    candidates.append(value)
            candidates.append(data)

        for obj in candidates:
            if isinstance(obj, dict) and obj.get("id") is not None:
                return str(obj["id"])

        raise RuntimeError("Copy succeeded but new Scan ID could not be parsed.")

    def update_copied_scan(
        self,
        copied_scan_id: str,
        selection: Selection,
        target: str,
        scan_name: str,
        credential: Optional[Dict[str, str]],
    ) -> None:
        authenticated = credential is not None
        description = (
            f"Copied from Master Scan '{selection.master_scan_name}'. Authenticated SSH scan for {target}; one credential is mapped only to this IP."
            if authenticated
            else f"Copied from Master Scan '{selection.master_scan_name}'. Unauthenticated scan for {target}."
        )

        payload: Dict[str, Any] = {
            "uuid": selection.master_scan_uuid,
            "settings": {
                "name": scan_name,
                "description": description,
                "folder_id": int(selection.destination_folder_id),
                "text_targets": target,
                "enabled": False,
            },
        }

        if authenticated:
            payload["credentials"] = {
                "add": {
                    "Host": {
                        "SSH": [
                            {
                                "auth_method": selection.ssh_auth_method,
                                "username": credential["username"],
                                "password": credential["password"],
                            }
                        ]
                    }
                }
            }

        status, data = self.request("PUT", f"/scans/{copied_scan_id}", payload)
        if status not in (200, 201):
            raise RuntimeError(f"Update failed HTTP {status}: {extract_error_message(data)}")

    def delete_scan_best_effort(self, scan_id: str) -> None:
        if not ROLLBACK_ON_UPDATE_FAILURE:
            return

        status, data = self.request("DELETE", f"/scans/{scan_id}")
        if status in (200, 202, 204):
            warning(f"Removed incomplete copied scan ID {scan_id}.")
        else:
            warning(f"Could not remove incomplete scan ID {scan_id}. HTTP {status}: {extract_error_message(data)}")

    def verify_auth_credential_best_effort(self, scan_id: str, username: str) -> None:
        if not VERIFY_FIRST_AUTH_CREDENTIAL:
            return

        status, data = self.request("GET", f"/editor/scan/{scan_id}")
        if status != 200:
            warning("Could not verify credential in editor response. Confirm manually before launch.")
            return

        verified = False
        for obj in recursive_walk(data):
            credentials = obj.get("credentials")
            if isinstance(credentials, dict):
                current = credentials.get("current")
                if isinstance(current, dict):
                    host = current.get("Host")
                    if isinstance(host, dict) and host.get("SSH"):
                        verified = True
                        break

        if not verified:
            for obj in recursive_walk(data):
                if str(obj.get("username") or "") == username:
                    verified = True
                    break

        if verified:
            success("Best-effort check found the SSH credential on the first copied scan.")
        else:
            warning("The update API accepted the credential, but the editor response did not confirm it.")
            warning("Open the first copied scan in Nessus and confirm Credentials > Host > SSH before launching.")


# =============================================================================
# INPUT LOADERS
# =============================================================================
def load_targets_from_ip_file(ip_file: Path) -> List[str]:
    targets: List[str] = []
    invalid: List[str] = []
    seen = set()

    for line in ip_file.read_text(encoding="utf-8-sig", errors="replace").splitlines():
        target = line.replace("\r", "").strip()
        if not target or target.startswith("#"):
            continue

        try:
            ip = str(ipaddress.ip_address(target))
        except ValueError:
            invalid.append(target)
            continue

        if ip not in seen:
            targets.append(ip)
            seen.add(ip)

    if not targets:
        fatal(f"No valid individual IP addresses were found in {ip_file}")

    if invalid:
        warning("The following non-IP entries will be skipped:")
        for item in invalid:
            print(f"  {item}")

    success(f"Loaded {len(targets)} unique IP address(es).")
    return targets


def load_credentials_from_csv(csv_file: Path) -> Tuple[List[str], Dict[str, Dict[str, str]]]:
    info("Validating credential CSV and mapping each credential to one IP...")

    ip_aliases = {"ip", "ip address", "ip_address", "host", "target"}
    user_aliases = {"username", "user", "login"}
    pass_aliases = {"password", "pass"}

    credentials: Dict[str, Dict[str, str]] = {}
    targets: List[str] = []
    errors: List[str] = []

    with csv_file.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            fatal("CSV is empty or has no header row.")

        fields = {str(name or "").strip().lower(): name for name in reader.fieldnames if name is not None}

        def find_column(aliases: set, label: str) -> str:
            for alias in aliases:
                if alias in fields:
                    return fields[alias]
            fatal(f"Missing {label} column. Required header: IP,Username,Password")
            return ""

        ip_col = find_column(ip_aliases, "IP")
        user_col = find_column(user_aliases, "Username")
        pass_col = find_column(pass_aliases, "Password")

        for line_number, row in enumerate(reader, start=2):
            raw_ip = str(row.get(ip_col) or "").strip()
            username = str(row.get(user_col) or "").strip()
            password = str(row.get(pass_col) or "")

            if not raw_ip and not username and not password:
                continue
            if raw_ip.startswith("#"):
                continue

            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                errors.append(f"Line {line_number}: invalid individual IP address: {raw_ip!r}")
                continue

            if not username:
                errors.append(f"Line {line_number}: username is empty for {ip}")
                continue
            if not password:
                errors.append(f"Line {line_number}: password is empty for {ip}")
                continue
            if ip in credentials:
                errors.append(f"Line {line_number}: duplicate IP address: {ip}")
                continue

            credentials[ip] = {"username": username, "password": password}
            targets.append(ip)

    if errors:
        fatal("Credential CSV validation failed:\n" + "\n".join(errors))
    if not targets:
        fatal("No valid credential rows were found.")

    success(f"Loaded {len(targets)} unique IP-to-credential mapping(s).")
    success("Passwords will not be printed or written to the report.")
    return targets, credentials


# =============================================================================
# SELECTION FLOW
# =============================================================================
def select_scan_mode(selection: Selection) -> None:
    print(f"\n{C.BLUE}{C.BOLD}FIRST STEP: Select Scan Type{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")
    print(f"  1) {C.GREEN}{C.BOLD}Authenticated Scan{C.NC}")
    print("     One copied scan per IP with one matching SSH credential.")
    print(f"  2) {C.YELLOW}{C.BOLD}Unauthenticated Scan{C.NC}")
    print("     One copied scan per IP without host credentials.")

    choice = prompt_choice("\nChoose scan type [1=Auth, 2=Unauth]: ", ["1", "2"])
    if choice == "1":
        selection.scan_mode = "authenticated"
        selection.scan_mode_label = "Authenticated Scan"
    else:
        selection.scan_mode = "unauthenticated"
        selection.scan_mode_label = "Unauthenticated Scan"

    success(f"Selected scan type: {selection.scan_mode_label}")


def select_auth_input_mode(selection: Selection) -> None:
    if selection.scan_mode != "authenticated":
        return

    print(f"\n{C.BLUE}{C.BOLD}Select Credential Input Method{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")
    print(f"  1) {C.GREEN}{C.BOLD}Manual secure entry - immediate scan creation{C.NC}")
    print("     After entering credential for one IP, that IP scan is created immediately.")
    print(f"  2) {C.CYAN}{C.BOLD}Credential CSV file{C.NC}")
    print("     Required columns: IP,Username,Password.")

    choice = prompt_choice("\nChoose credential method [1=Manual, 2=CSV]: ", ["1", "2"])
    if choice == "1":
        selection.auth_input_mode = "manual"
        selection.auth_input_label = "Manual secure entry"
    else:
        selection.auth_input_mode = "csv"
        selection.auth_input_label = "Credential CSV file"

    success(f"Selected credential method: {selection.auth_input_label}")


def select_folder_from_menu(folders: List[Folder], purpose: str, allow_back: bool = False) -> Tuple[str, Optional[Folder]]:
    print(f"\n{C.BLUE}{C.BOLD}{purpose}{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")

    for index, folder in enumerate(folders, start=1):
        marker = "" if folder.selectable else " [not selectable]"
        print(f" {index:3d}) {folder.name:38s} [ID: {folder.id} | Type: {folder.folder_type}]{marker}")

    print()
    if allow_back:
        print("   b) Back to previous step")
    print("   q) Quit without creating scans")

    while True:
        choice = input("\nSelect folder number: ").strip().lower()
        if choice == "q":
            warning("Operation cancelled. No scans were created.")
            raise SystemExit(0)
        if choice == "b" and allow_back:
            return "back", None

        if choice.isdigit():
            number = int(choice)
            if 1 <= number <= len(folders):
                folder = folders[number - 1]
                if not folder.selectable:
                    warning(f"'{folder.name}' cannot be selected.")
                    continue
                return "selected", folder

        warning(f"Enter a number from 1 to {len(folders)}, or b/q where available.")


def select_master_folder_step(selection: Selection, folders: List[Folder], scans: List[Scan]) -> None:
    while True:
        _, folder = select_folder_from_menu(folders, "Select the Folder Containing the Master Scan", False)
        assert folder is not None
        folder_scan_count = sum(1 for scan in scans if scan.folder_id == folder.id)
        if folder_scan_count == 0:
            warning(f"No scan configurations were found in '{folder.name}'. Select another folder.")
            continue

        selection.master_folder_id = folder.id
        selection.master_folder_name = folder.name
        return


def select_master_scan_step(selection: Selection, scans: List[Scan]) -> str:
    candidates = [scan for scan in scans if scan.folder_id == selection.master_folder_id]
    if not candidates:
        return "back"

    print(f"\n{C.BLUE}{C.BOLD}Select Master Scan from: {selection.master_folder_name}{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")

    for index, scan in enumerate(candidates, start=1):
        print(f" {index:3d}) {scan.name:48s} [ID: {scan.id} | Status: {scan.status}]")

    print("\n   b) Back to master folder selection")
    print("   q) Quit without creating scans")

    while True:
        choice = input("\nSelect Master Scan number: ").strip().lower()
        if choice == "b":
            return "back"
        if choice == "q":
            warning("Operation cancelled. No scans were created.")
            raise SystemExit(0)

        if choice.isdigit():
            number = int(choice)
            if 1 <= number <= len(candidates):
                scan = candidates[number - 1]
                selection.master_scan_id = scan.id
                selection.master_scan_name = scan.name
                selection.master_scan_status = scan.status
                selection.master_scan_uuid = scan.uuid
                selection.master_policy_id = scan.policy_id
                selection.master_scan_type = scan.scan_type
                success(f"Selected Master Scan: {scan.name} (ID: {scan.id})")

                if scan.policy_id and scan.policy_id not in {"0", "null", "None"}:
                    warning(f"This scan reports policy_id={scan.policy_id} and may be policy-based.")
                    warning("For independently editable copies, use a Master Scan created directly from Advanced Scan.")
                    answer = prompt_choice("Continue with this Master Scan anyway? [y/N/b]: ", ["y", "n", "b", ""])
                    if answer == "b":
                        return "back"
                    if answer != "y":
                        fatal("Select an independent Advanced Scan master.")

                if scan.status and scan.status not in {"empty", "never"}:
                    warning(f"Master status is '{scan.status}'. A master should normally never be launched.")
                return "selected"

        warning(f"Enter a number from 1 to {len(candidates)}, or b/q.")


def select_destination_folder_step(selection: Selection, folders: List[Folder]) -> str:
    action, folder = select_folder_from_menu(folders, "Select Destination Folder for the New Scan Copies", True)
    if action == "back":
        return "back"
    assert folder is not None

    selection.destination_folder_id = folder.id
    selection.destination_folder_name = folder.name
    success(f"Selected destination folder: {folder.name} (ID: {folder.id})")

    if selection.destination_folder_id == selection.master_folder_id:
        warning("The Master Scan folder and destination folder are the same.")
        answer = prompt_choice("Continue using the same folder? [y/N/b]: ", ["y", "n", "b", ""])
        if answer == "y":
            return "selected"
        if answer == "b":
            return "back"
        warning("Select a different destination folder.")
        return "retry"

    return "selected"


def selection_wizard(selection: Selection, folders: List[Folder], scans: List[Scan]) -> None:
    step = 1
    while True:
        if step == 1:
            select_master_folder_step(selection, folders, scans)
            step = 2
        elif step == 2:
            action = select_master_scan_step(selection, scans)
            step = 1 if action == "back" else 3
        elif step == 3:
            action = select_destination_folder_step(selection, folders)
            if action == "selected":
                return
            if action == "back":
                step = 2
            else:
                step = 3


def pause_before_credentials(selection: Selection) -> bool:
    print(f"\n{C.BLUE}{C.BOLD}Selection Review Before IP/Credential Entry{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")
    print(f"Scan type    : {selection.scan_mode_label}")
    print(f"Master folder: {selection.master_folder_name}")
    print(f"Master scan  : {selection.master_scan_name} (ID: {selection.master_scan_id})")
    print(f"Destination  : {selection.destination_folder_name} (ID: {selection.destination_folder_id})")
    if selection.scan_mode == "authenticated":
        print(f"Credential   : {selection.auth_input_label}")

    print("\n  y) Continue to IP/credential input")
    print("  b) Go back and correct folder/master/destination selection")
    print("  q) Quit without creating scans")

    choice = prompt_choice("Choose [y/b/q]: ", ["y", "b", "q"])
    if choice == "q":
        warning("Operation cancelled. No scans were created.")
        raise SystemExit(0)
    return choice == "y"


# =============================================================================
# CREATION
# =============================================================================
def write_report_header(report_path: str) -> None:
    with open(report_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["IP", "Scan Name", "Scan ID", "Scan Type", "Credential Method", "Master Scan", "Destination Folder", "Status"])


def append_report(report_path: str, row: List[str]) -> None:
    with open(report_path, "a", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(row)


def create_single_scan_for_ip(
    client: NessusClient,
    selection: Selection,
    existing_names: set,
    target: str,
    credential: Optional[Dict[str, str]],
    report_path: str,
) -> Tuple[str, str]:
    scan_name = f"{selection.destination_folder_name}_{sanitize_name_part(target)}"
    credential_method = selection.auth_input_label if credential else "N/A"

    if SKIP_EXISTING_NAMES and scan_name in existing_names:
        warning(f"A scan named '{scan_name}' already exists. Skipping.")
        append_report(
            report_path,
            [
                target,
                scan_name,
                "",
                selection.scan_mode_label,
                credential_method,
                selection.master_scan_name,
                selection.destination_folder_name,
                "Skipped: name already exists",
            ],
        )
        return "skipped", ""

    copied_id = ""
    try:
        copied_id = client.copy_master_scan(selection.master_scan_id, selection.destination_folder_id, scan_name)
        success(f"Master copied. New Scan ID: {copied_id}")

        client.update_copied_scan(copied_id, selection, target, scan_name, credential)
        success(f"Target updated to: {target}")
        if credential:
            success("One SSH credential request was accepted for this scan.")

        existing_names.add(scan_name)
        append_report(
            report_path,
            [
                target,
                scan_name,
                copied_id,
                selection.scan_mode_label,
                credential_method,
                selection.master_scan_name,
                selection.destination_folder_name,
                "Created and updated",
            ],
        )
        return "created", copied_id

    except Exception as exc:
        error(str(exc))
        if copied_id:
            client.delete_scan_best_effort(copied_id)
        append_report(
            report_path,
            [
                target,
                scan_name,
                copied_id,
                selection.scan_mode_label,
                credential_method,
                selection.master_scan_name,
                selection.destination_folder_name,
                f"Failed: {exc}",
            ],
        )
        return "failed", copied_id


def create_scans_batch(
    client: NessusClient,
    selection: Selection,
    scans: List[Scan],
    targets: List[str],
    credentials: Optional[Dict[str, Dict[str, str]]] = None,
) -> None:
    existing_names = {scan.name for scan in scans}
    write_report_header(REPORT_FILE)

    total = len(targets)
    created = skipped = failed = 0
    verified_once = False

    print(f"\n{C.CYAN}{C.BOLD}[*] Copying and updating Master Scan configurations...{C.NC}")

    for index, target in enumerate(targets, start=1):
        scan_name = f"{selection.destination_folder_name}_{sanitize_name_part(target)}"
        print(f"\n{C.CYAN}[{index}/{total}] Processing: {scan_name}{C.NC}")
        print(f"    Target: {target}")

        credential = None
        if selection.scan_mode == "authenticated":
            if not credentials or target not in credentials:
                error(f"No credential mapping found for {target}")
                failed += 1
                continue
            credential = credentials[target]

        status, copied_id = create_single_scan_for_ip(
            client=client,
            selection=selection,
            existing_names=existing_names,
            target=target,
            credential=credential,
            report_path=REPORT_FILE,
        )

        if status == "created":
            created += 1
            if credential and not verified_once:
                client.verify_auth_credential_best_effort(copied_id, credential.get("username", ""))
                verified_once = True
        elif status == "skipped":
            skipped += 1
        else:
            failed += 1

        time.sleep(1)

    print_final_summary(total, created, skipped, failed, selection)


def create_scans_manual_immediate(client: NessusClient, selection: Selection, scans: List[Scan], targets: List[str]) -> None:
    existing_names = {scan.name for scan in scans}
    write_report_header(REPORT_FILE)

    total = len(targets)
    created = skipped = failed = 0
    verified_once = False

    print(f"\n{C.CYAN}{C.BOLD}[*] Manual immediate mode started.{C.NC}")
    print("For each IP, you will enter SSH credential, then that IP scan will be created immediately.")
    print(f"Local credential file: {LOCAL_CREDENTIAL_STORE}")
    warning("Local credential file uses chmod 600. It is not encrypted by this script.")

    for index, target in enumerate(targets, start=1):
        scan_name = f"{selection.destination_folder_name}_{sanitize_name_part(target)}"
        print(f"\n{C.CYAN}[{index}/{total}] Processing: {scan_name}{C.NC}")
        print(f"    Target: {target}")

        if SKIP_EXISTING_NAMES and scan_name in existing_names:
            warning(f"A scan named '{scan_name}' already exists. Skipping credential prompt.")
            append_report(
                REPORT_FILE,
                [
                    target,
                    scan_name,
                    "",
                    selection.scan_mode_label,
                    selection.auth_input_label,
                    selection.master_scan_name,
                    selection.destination_folder_name,
                    "Skipped: name already exists",
                ],
            )
            skipped += 1
            continue

        credential = get_manual_credential_for_ip(target)

        status, copied_id = create_single_scan_for_ip(
            client=client,
            selection=selection,
            existing_names=existing_names,
            target=target,
            credential=credential,
            report_path=REPORT_FILE,
        )

        if status == "created":
            created += 1
            if not verified_once:
                client.verify_auth_credential_best_effort(copied_id, credential.get("username", ""))
                verified_once = True
        elif status == "skipped":
            skipped += 1
        else:
            failed += 1

        time.sleep(1)

    print_final_summary(total, created, skipped, failed, selection)


def print_final_summary(total: int, created: int, skipped: int, failed: int, selection: Selection) -> None:
    print(f"\n{C.BLUE}{C.BOLD}Final Summary{C.NC}")
    print(f"{C.BLUE}--------------------------------------------------------------{C.NC}")
    print(f"Targets processed   : {total}")
    print(f"Created successfully: {C.GREEN}{created}{C.NC}")
    print(f"Skipped             : {C.YELLOW}{skipped}{C.NC}")
    print(f"Failed              : {C.RED}{failed}{C.NC}")
    print(f"Report              : {REPORT_FILE}")
    print("Automatic launch    : Disabled")

    if selection.scan_mode == "authenticated" and created > 0:
        print(f"\n{C.YELLOW}{C.BOLD}Before launching:{C.NC} Open the first created scan and confirm Credentials > Host > SSH.")


# =============================================================================
# MAIN
# =============================================================================
def main() -> None:
    default_ip_file = sys.argv[1] if len(sys.argv) > 1 else ""
    default_credential_file = sys.argv[2] if len(sys.argv) > 2 else ""

    print_banner()

    selection = Selection()
    select_scan_mode(selection)
    select_auth_input_mode(selection)

    client = NessusClient(NESSUS_URL, NESSUS_ACCESS_KEY, NESSUS_SECRET_KEY)
    client.test_connection()

    folders = client.load_folders()
    scans = client.load_scans()

    while True:
        selection_wizard(selection, folders, scans)
        selection.master_scan_uuid = client.resolve_master_uuid(selection)
        client.check_master_credentials(selection)
        if selection.scan_mode == "authenticated":
            selection.ssh_auth_method = client.detect_ssh_password_auth_method()

        if pause_before_credentials(selection):
            break

    if selection.scan_mode == "authenticated" and selection.auth_input_mode == "csv":
        credential_file = prompt_file(
            "Select Credential CSV File",
            "Required header: IP,Username,Password.",
            "Enter credential CSV path: ",
            default_credential_file,
        )
        try:
            permissions = stat.S_IMODE(os.stat(credential_file).st_mode)
            if permissions not in (0o600, 0o400):
                warning(f"Credential CSV permissions are {oct(permissions)}. Recommended: chmod 600 \"{credential_file}\"")
        except Exception:
            pass

        targets, credentials = load_credentials_from_csv(credential_file)
        create_scans_batch(client, selection, scans, targets, credentials)

    elif selection.scan_mode == "authenticated" and selection.auth_input_mode == "manual":
        ip_file = prompt_file(
            "Select IP Address File",
            "The file must contain one individual IP address per line.",
            "Enter IP file path: ",
            default_ip_file,
        )
        targets = load_targets_from_ip_file(ip_file)
        create_scans_manual_immediate(client, selection, scans, targets)

    else:
        ip_file = prompt_file(
            "Select IP Address File",
            "The file must contain one individual IP address per line.",
            "Enter IP file path: ",
            default_ip_file,
        )
        targets = load_targets_from_ip_file(ip_file)
        create_scans_batch(client, selection, scans, targets, credentials=None)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print()
        warning("Interrupted by user.")
        warning("Any scan already created before interruption will remain in Nessus.")
        warning(f"Manual credentials already saved remain in: {LOCAL_CREDENTIAL_STORE}")
        raise SystemExit(130)
