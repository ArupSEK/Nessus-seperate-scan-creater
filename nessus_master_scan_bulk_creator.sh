#!/usr/bin/env bash

#===============================================================================
# NESSUS MASTER SCAN BULK CREATOR
# Author  : Sleeping Bhudda
# Purpose :
#   1. Ask first: Authenticated Scan or Unauthenticated Scan
#   2. For Authenticated mode, accept secure manual credentials or CSV input
#   3. Allow Tab completion while selecting input files
#   4. Retrieve Nessus folders and let the user select the master-scan folder
#   5. Retrieve existing scans and let the user select an independent master scan
#   6. Let the user select the destination folder
#   7. Copy the master once for every individual IP address
#   8. Rename each copy as: <Destination Folder Name>_<IP Address>
#   9. Replace the copied target with exactly one IP address
#  10. For Authenticated mode, add one matching SSH username/password per scan
#  11. Never launch scans automatically
#===============================================================================

set -uo pipefail

#-------------------------------------------------------------------------------
# EDIT THESE VALUES BEFORE RUNNING
#-------------------------------------------------------------------------------
NESSUS_URL="https://127.0.0.1:8834"
NESSUS_ACCESS_KEY="your_nessus_access_key"
NESSUS_SECRET_KEY="your_nessus_secret_key"

#-------------------------------------------------------------------------------
# OPTIONAL BEHAVIOUR
#-------------------------------------------------------------------------------
CURL_TIMEOUT="${CURL_TIMEOUT:-90}"
SKIP_EXISTING_NAMES="${SKIP_EXISTING_NAMES:-yes}"
ROLLBACK_ON_UPDATE_FAILURE="${ROLLBACK_ON_UPDATE_FAILURE:-yes}"
VERIFY_FIRST_AUTH_CREDENTIAL="${VERIFY_FIRST_AUTH_CREDENTIAL:-yes}"

DEFAULT_IP_FILE="${1:-}"
DEFAULT_CREDENTIAL_FILE="${2:-}"

#-------------------------------------------------------------------------------
# RUNTIME VARIABLES
#-------------------------------------------------------------------------------
AUTH_HEADER=""
SCAN_MODE=""
SCAN_MODE_LABEL=""
AUTH_INPUT_MODE=""
AUTH_INPUT_LABEL=""
IP_FILE=""
CREDENTIAL_FILE=""
SSH_AUTH_METHOD="password"
REPORT_FILE="master_scan_copies_$(date +%Y%m%d_%H%M%S).csv"

TMP_DIR="$(mktemp -d)"
CREDENTIALS_JSON="$TMP_DIR/credentials.json"
trap 'rm -rf "$TMP_DIR"' EXIT

TARGETS=()
INVALID_TARGETS=()
FOLDER_IDS=()
FOLDER_NAMES=()
FOLDER_TYPES=()
FOLDER_SELECTABLE=()
SCAN_IDS=()
SCAN_NAMES=()
SCAN_FOLDER_IDS=()
SCAN_STATUSES=()
SCAN_UUIDS=()
SCAN_POLICY_IDS=()
SCAN_TYPES=()
declare -A EXISTING_SCAN_NAMES=()

#-------------------------------------------------------------------------------
# COLOURS
#-------------------------------------------------------------------------------
if [[ -t 1 ]]; then
    RED="$(tput setaf 1 2>/dev/null || true)"
    GREEN="$(tput setaf 2 2>/dev/null || true)"
    YELLOW="$(tput setaf 3 2>/dev/null || true)"
    BLUE="$(tput setaf 4 2>/dev/null || true)"
    MAGENTA="$(tput setaf 5 2>/dev/null || true)"
    CYAN="$(tput setaf 6 2>/dev/null || true)"
    WHITE="$(tput setaf 7 2>/dev/null || true)"
    BOLD="$(tput bold 2>/dev/null || true)"
    NC="$(tput sgr0 2>/dev/null || true)"
else
    RED=""; GREEN=""; YELLOW=""; BLUE=""; MAGENTA=""; CYAN=""; WHITE=""; BOLD=""; NC=""
fi

#-------------------------------------------------------------------------------
# DISPLAY HELPERS
#-------------------------------------------------------------------------------
print_banner() {
    clear 2>/dev/null || true
    printf '%s\n' "${CYAN}${BOLD}===============================================================================${NC}"
    printf '%s\n' "${GREEN}${BOLD}                     NESSUS MASTER SCAN BULK CREATOR${NC}"
    printf '%s\n' "${MAGENTA}${BOLD}                         Author: Sleeping Bhudda${NC}"
    printf '%s\n' "${CYAN}${BOLD}===============================================================================${NC}"
    printf '\n'
    printf '%s\n' "${YELLOW}${BOLD}Purpose:${NC}"
    printf '%s\n' "  1. Choose Authenticated or Unauthenticated scanning"
    printf '%s\n' "  2. Select a credential-free Master Scan already saved in Nessus"
    printf '%s\n' "  3. Copy the Master Scan once for every individual IP"
    printf '%s\n' "  4. Preserve the Master's plugin and assessment configuration"
    printf '%s\n' "  5. Replace the target and optionally add one SSH credential per copy"
    printf '%s\n' "  6. Never launch scans automatically"
    printf '\n%s\n\n' "${CYAN}${BOLD}===============================================================================${NC}"
}

fatal() { printf '%s\n' "${RED}[ERROR] $*${NC}" >&2; exit 1; }
warning() { printf '%s\n' "${YELLOW}[WARNING] $*${NC}"; }
info() { printf '%s\n' "${CYAN}[*] $*${NC}"; }
success() { printf '%s\n' "${GREEN}[+] $*${NC}"; }

require_command() { command -v "$1" >/dev/null 2>&1 || fatal "Required command not found: $1"; }

csv_escape() {
    local value="${1:-}"
    value="${value//"/""}"
    printf '"%s"' "$value"
}

normalise_entered_path() {
    local entered_path="$1"
    entered_path="${entered_path#"${entered_path%%[![:space:]]*}"}"
    entered_path="${entered_path%"${entered_path##*[![:space:]]}"}"

    if [[ "$entered_path" == \"*\" && "$entered_path" == *\" ]]; then
        entered_path="${entered_path:1:${#entered_path}-2}"
    elif [[ "$entered_path" == \'*\' && "$entered_path" == *\' ]]; then
        entered_path="${entered_path:1:${#entered_path}-2}"
    fi

    # Readline can insert backslashes while completing paths containing spaces.
    entered_path="${entered_path//\\ / }"
    entered_path="${entered_path//\\(/(}"
    entered_path="${entered_path//\\)/)}"
    entered_path="${entered_path//\\[/[}"
    entered_path="${entered_path//\\]/]}"
    entered_path="${entered_path//\\&/&}"

    if [[ "$entered_path" == "~" ]]; then
        entered_path="$HOME"
    elif [[ "$entered_path" == "~/"* ]]; then
        entered_path="$HOME/${entered_path#\~/}"
    fi

    printf '%s' "$entered_path"
}

prompt_for_file() {
    local title="$1"
    local instructions="$2"
    local prompt_text="$3"
    local default_path="$4"
    local entered_path=""

    printf '\n%s\n' "${BLUE}${BOLD}${title}${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    printf '%s\n' "$instructions"

    while true; do
        [[ -t 0 ]] || fatal "Interactive terminal input is required."
        if [[ -n "$default_path" ]]; then
            read -e -r -i "$default_path" -p "$prompt_text" entered_path
        else
            read -e -r -p "$prompt_text" entered_path
        fi
        entered_path="$(normalise_entered_path "$entered_path")"

        [[ -n "$entered_path" ]] || { warning "File path cannot be empty."; continue; }
        [[ -e "$entered_path" ]] || { warning "Path does not exist: $entered_path"; default_path="$entered_path"; continue; }
        [[ -f "$entered_path" ]] || { warning "This is not a regular file: $entered_path"; default_path="$entered_path"; continue; }
        [[ -r "$entered_path" ]] || { warning "File is not readable: $entered_path"; default_path="$entered_path"; continue; }

        PROMPTED_FILE_PATH="$entered_path"
        return 0
    done
}

#-------------------------------------------------------------------------------
# USER SELECTION
#-------------------------------------------------------------------------------
select_scan_mode() {
    local choice
    printf '\n%s\n' "${BLUE}${BOLD}FIRST STEP: Select Scan Type${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    printf '  1) %sAuthenticated Scan%s\n' "${GREEN}${BOLD}" "$NC"
    printf '     One copied scan per IP with one matching SSH credential.\n'
    printf '  2) %sUnauthenticated Scan%s\n' "${YELLOW}${BOLD}" "$NC"
    printf '     One copied scan per IP without host credentials.\n'

    while true; do
        printf '\n'
        read -r -p "Choose scan type [1=Auth, 2=Unauth]: " choice
        case "$choice" in
            1) SCAN_MODE="authenticated"; SCAN_MODE_LABEL="Authenticated Scan"; break ;;
            2) SCAN_MODE="unauthenticated"; SCAN_MODE_LABEL="Unauthenticated Scan"; break ;;
            *) warning "Enter 1 for Authenticated or 2 for Unauthenticated." ;;
        esac
    done
    success "Selected scan type: $SCAN_MODE_LABEL"
}

select_auth_input_mode() {
    local choice
    [[ "$SCAN_MODE" == "authenticated" ]] || return 0

    printf '\n%s\n' "${BLUE}${BOLD}Select Credential Input Method${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    printf '  1) %sManual secure entry%s\n' "${GREEN}${BOLD}" "$NC"
    printf '     Select an IP file, then type username and hidden password per IP.\n'
    printf '  2) %sCredential CSV file%s\n' "${CYAN}${BOLD}" "$NC"
    printf '     Required columns: IP,Username,Password\n'

    while true; do
        printf '\n'
        read -r -p "Choose credential method [1=Manual, 2=CSV]: " choice
        case "$choice" in
            1) AUTH_INPUT_MODE="manual"; AUTH_INPUT_LABEL="Manual secure entry"; break ;;
            2) AUTH_INPUT_MODE="csv"; AUTH_INPUT_LABEL="Credential CSV file"; break ;;
            *) warning "Enter 1 for Manual or 2 for CSV." ;;
        esac
    done
    success "Selected credential method: $AUTH_INPUT_LABEL"
}

prompt_input_files() {
    if [[ "$SCAN_MODE" == "authenticated" && "$AUTH_INPUT_MODE" == "csv" ]]; then
        prompt_for_file "Select Credential CSV File" "Required header: IP,Username,Password. Press Tab to complete the path." "Enter credential CSV path: " "$DEFAULT_CREDENTIAL_FILE"
        CREDENTIAL_FILE="$PROMPTED_FILE_PATH"
        success "Selected credential CSV: $CREDENTIAL_FILE"
        local permissions=""
        permissions=$(stat -c '%a' "$CREDENTIAL_FILE" 2>/dev/null || true)
        if [[ -n "$permissions" && "$permissions" != "600" && "$permissions" != "400" ]]; then
            warning "Credential CSV permissions are $permissions. Recommended: chmod 600 \"$CREDENTIAL_FILE\""
        fi
    else
        prompt_for_file "Select IP Address File" "The file must contain one individual IP address per line. Press Tab to complete the path." "Enter IP file path: " "$DEFAULT_IP_FILE"
        IP_FILE="$PROMPTED_FILE_PATH"
        success "Selected IP file: $IP_FILE"
    fi
}

#-------------------------------------------------------------------------------
# API HELPERS
#-------------------------------------------------------------------------------
set_api_header() {
    local access_key secret_key
    access_key="${NESSUS_ACCESS_KEY:-${ACCESS_KEY:-}}"
    secret_key="${NESSUS_SECRET_KEY:-${SECRET_KEY:-}}"

    [[ -n "$access_key" && "$access_key" != "your_nessus_access_key" && "$access_key" != "PUT_YOUR_ACCESS_KEY_HERE" ]] || fatal "Add your Nessus access key at the top of the script."
    [[ -n "$secret_key" && "$secret_key" != "your_nessus_secret_key" && "$secret_key" != "PUT_YOUR_SECRET_KEY_HERE" ]] || fatal "Add your Nessus secret key at the top of the script."

    AUTH_HEADER="X-ApiKeys: accessKey=${access_key}; secretKey=${secret_key}"
}

api_call() {
    local method="$1"
    local endpoint="$2"
    local output_file="$3"
    local data_file="${4:-}"
    local status
    local -a command

    command=(
        curl -skS
        --connect-timeout 15
        --max-time "$CURL_TIMEOUT"
        -o "$output_file"
        -w '%{http_code}'
        -X "$method"
        -H "$AUTH_HEADER"
        -H 'Accept: application/json'
    )

    if [[ -n "$data_file" ]]; then
        command+=(-H 'Content-Type: application/json' --data-binary "@$data_file")
    fi

    command+=("${NESSUS_URL}${endpoint}")
    status="$("${command[@]}")" || return 1
    printf '%s' "$status"
}

api_get() {
    local endpoint="$1"
    local output_file="$2"
    local status
    status="$(api_call GET "$endpoint" "$output_file")" || return 1
    [[ "$status" == "200" ]]
}

test_connection() {
    local response_file="$TMP_DIR/server_status.json"
    local status
    info "Testing Nessus API connection..."
    status="$(api_call GET '/server/status' "$response_file")" || fatal "Unable to connect to $NESSUS_URL"
    if [[ "$status" != "200" ]]; then
        printf '%s\n' "Server response:"
        cat "$response_file" 2>/dev/null || true
        fatal "Nessus connection failed. HTTP $status"
    fi
    success "Connected to Nessus successfully."
}

extract_error_message() {
    local response_file="$1"
    python3 - "$response_file" <<'PY'
import json
import sys
path = sys.argv[1]
try:
    raw = open(path, "r", encoding="utf-8").read()
    data = json.loads(raw)
except Exception:
    print(raw.strip() if 'raw' in locals() else "Unknown API error")
    raise SystemExit(0)
for key in ("error", "message", "detail"):
    if isinstance(data, dict) and data.get(key):
        print(data[key])
        break
else:
    print(json.dumps(data, ensure_ascii=False))
PY
}

#-------------------------------------------------------------------------------
# TARGET AND CREDENTIAL INPUT
#-------------------------------------------------------------------------------
load_targets_from_ip_file() {
    TARGETS=()
    INVALID_TARGETS=()
    declare -A seen_targets=()
    local target

    while IFS= read -r target || [[ -n "$target" ]]; do
        target="${target//$'\r'/}"
        target="${target#"${target%%[![:space:]]*}"}"
        target="${target%"${target##*[![:space:]]}"}"
        [[ -n "$target" ]] || continue
        [[ "$target" == \#* ]] && continue

        if python3 - "$target" >/dev/null 2>&1 <<'PY'
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PY
        then
            if [[ -z "${seen_targets[$target]+x}" ]]; then
                TARGETS+=("$target")
                seen_targets["$target"]=1
            fi
        else
            INVALID_TARGETS+=("$target")
        fi
    done < "$IP_FILE"

    ((${#TARGETS[@]} > 0)) || fatal "No valid individual IP addresses were found in $IP_FILE"
    if ((${#INVALID_TARGETS[@]} > 0)); then
        warning "The following non-IP entries will be skipped:"
        printf '  %s\n' "${INVALID_TARGETS[@]}"
    fi
    success "Loaded ${#TARGETS[@]} unique IP address(es)."
}

load_credentials_from_csv() {
    local targets_file="$TMP_DIR/credential_targets.txt"
    local error_file="$TMP_DIR/credential_csv_error.txt"
    info "Validating credential CSV and mapping each credential to one IP..."

    if ! python3 - "$CREDENTIAL_FILE" "$CREDENTIALS_JSON" "$targets_file" 2>"$error_file" <<'PY'
import csv
import ipaddress
import json
import os
import sys
csv_path, json_path, targets_path = sys.argv[1:4]
IP_ALIASES = {"ip", "ip address", "ip_address", "host", "target"}
USER_ALIASES = {"username", "user", "login"}
PASS_ALIASES = {"password", "pass"}

def norm(value):
    return str(value or "").strip().lower()

with open(csv_path, "r", encoding="utf-8-sig", newline="") as handle:
    reader = csv.DictReader(handle)
    if not reader.fieldnames:
        raise SystemExit("CSV is empty or has no header row.")
    fields = {norm(name): name for name in reader.fieldnames if name is not None}

    def find_col(aliases, label):
        for alias in aliases:
            if alias in fields:
                return fields[alias]
        raise SystemExit(f"Missing {label} column. Required header: IP,Username,Password")

    ip_col = find_col(IP_ALIASES, "IP")
    user_col = find_col(USER_ALIASES, "Username")
    pass_col = find_col(PASS_ALIASES, "Password")
    credentials = {}
    targets = []
    errors = []

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
    raise SystemExit("\n".join(errors))
if not targets:
    raise SystemExit("No valid credential rows were found.")

with open(json_path, "w", encoding="utf-8") as handle:
    json.dump(credentials, handle, ensure_ascii=False)
os.chmod(json_path, 0o600)
with open(targets_path, "w", encoding="utf-8", newline="\n") as handle:
    for target in targets:
        handle.write(target + "\n")
PY
    then
        printf '%s\n' "${RED}[ERROR] Credential CSV validation failed:${NC}"
        cat "$error_file" >&2
        exit 1
    fi

    TARGETS=()
    local target
    while IFS= read -r target || [[ -n "$target" ]]; do
        [[ -n "$target" ]] && TARGETS+=("$target")
    done < "$targets_file"

    ((${#TARGETS[@]} > 0)) || fatal "No targets were loaded from the credential CSV."
    success "Loaded ${#TARGETS[@]} unique IP-to-credential mapping(s)."
    success "Passwords will not be printed or written to the report."
}

collect_manual_credentials() {
    local target username password confirm_password entry_file
    printf '\n%s\n' "${BLUE}${BOLD}Enter SSH Credentials Securely${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    printf '%s\n' "Password input is hidden and must be entered twice."
    printf '{}\n' > "$CREDENTIALS_JSON"
    chmod 600 "$CREDENTIALS_JSON"

    for target in "${TARGETS[@]}"; do
        printf '\n%s\n' "${CYAN}Target: ${target}${NC}"
        while true; do
            read -r -p "SSH username: " username
            username="${username#"${username%%[![:space:]]*}"}"
            username="${username%"${username##*[![:space:]]}"}"
            [[ -n "$username" ]] && break
            warning "Username cannot be empty."
        done

        while true; do
            read -s -r -p "SSH password: " password
            printf '\n'
            read -s -r -p "Confirm SSH password: " confirm_password
            printf '\n'
            [[ -n "$password" ]] || { warning "Password cannot be empty."; continue; }
            [[ "$password" == "$confirm_password" ]] || { warning "Passwords do not match."; continue; }
            break
        done

        entry_file="$(mktemp "$TMP_DIR/manual_credential.XXXXXX")"
        chmod 600 "$entry_file"
        printf '%s\0%s\0%s\0' "$target" "$username" "$password" > "$entry_file"

        python3 - "$CREDENTIALS_JSON" "$entry_file" <<'PY'
import json
import os
import sys
json_path, entry_path = sys.argv[1:3]
raw = open(entry_path, "rb").read().split(b"\0")
if len(raw) < 4:
    raise SystemExit("Unable to read credential input.")
ip, username, password = (part.decode("utf-8") for part in raw[:3])
try:
    data = json.load(open(json_path, "r", encoding="utf-8"))
except Exception:
    data = {}
data[ip] = {"username": username, "password": password}
with open(json_path, "w", encoding="utf-8") as handle:
    json.dump(data, handle, ensure_ascii=False)
os.chmod(json_path, 0o600)
PY
        rm -f "$entry_file"
        unset password confirm_password username entry_file
        success "Credential stored temporarily for $target."
    done
}

prepare_targets_and_credentials() {
    if [[ "$SCAN_MODE" == "authenticated" && "$AUTH_INPUT_MODE" == "csv" ]]; then
        load_credentials_from_csv
    else
        load_targets_from_ip_file
        if [[ "$SCAN_MODE" == "authenticated" ]]; then
            collect_manual_credentials
        fi
    fi
}

#-------------------------------------------------------------------------------
# NESSUS FOLDERS AND SCANS
#-------------------------------------------------------------------------------
load_folders() {
    local response_file="$TMP_DIR/folders.json"
    local parsed_file="$TMP_DIR/folders.tsv"
    info "Retrieving folders from Nessus..."
    api_get '/folders' "$response_file" || { cat "$response_file" 2>/dev/null || true; fatal "Unable to retrieve Nessus folders."; }

    python3 - "$response_file" > "$parsed_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for folder in data.get("folders", []):
    folder_id = folder.get("id", "")
    name = str(folder.get("name", "Unnamed Folder"))
    folder_type = str(folder.get("type", "unknown"))
    name = name.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    folder_type = folder_type.replace("\t", " ").replace("\r", " ").replace("\n", " ")
    normalized_name = name.strip().lower()
    normalized_type = folder_type.strip().lower()
    selectable = "yes"
    if normalized_name in {"trash", "all scans"} or normalized_type == "trash":
        selectable = "no"
    print("\x1f".join(map(str, [folder_id, name, folder_type, selectable])))
PY

    [[ -s "$parsed_file" ]] || fatal "No folders were returned by Nessus."
    while IFS=$'\x1f' read -r folder_id folder_name folder_type selectable; do
        [[ -n "$folder_id" ]] || continue
        FOLDER_IDS+=("$folder_id")
        FOLDER_NAMES+=("$folder_name")
        FOLDER_TYPES+=("$folder_type")
        FOLDER_SELECTABLE+=("$selectable")
    done < "$parsed_file"
    ((${#FOLDER_IDS[@]} > 0)) || fatal "No usable folders were found."
}

load_scans() {
    local response_file="$TMP_DIR/scans.json"
    local parsed_file="$TMP_DIR/scans.tsv"
    info "Retrieving existing scan configurations from Nessus..."
    api_get '/scans' "$response_file" || { cat "$response_file" 2>/dev/null || true; fatal "Unable to retrieve Nessus scans."; }

    python3 - "$response_file" > "$parsed_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for scan in data.get("scans", []):
    def safe(value):
        return str(value).replace("\t", " ").replace("\r", " ").replace("\n", " ")
    print("\x1f".join(map(safe, [
        scan.get("id", ""),
        scan.get("name", "Unnamed Scan"),
        scan.get("folder_id", ""),
        scan.get("status", "unknown"),
        scan.get("uuid") or "",
        scan.get("policy_id", ""),
        scan.get("type", ""),
    ])))
PY

    [[ -s "$parsed_file" ]] || fatal "No scan configurations were returned by Nessus."
    local scan_id scan_name folder_id status uuid policy_id scan_type
    while IFS=$'\x1f' read -r scan_id scan_name folder_id status uuid policy_id scan_type; do
        [[ -n "$scan_id" ]] || continue
        SCAN_IDS+=("$scan_id")
        SCAN_NAMES+=("$scan_name")
        SCAN_FOLDER_IDS+=("$folder_id")
        SCAN_STATUSES+=("$status")
        SCAN_UUIDS+=("$uuid")
        SCAN_POLICY_IDS+=("$policy_id")
        SCAN_TYPES+=("$scan_type")
        EXISTING_SCAN_NAMES["$scan_name"]=1
    done < "$parsed_file"
    ((${#SCAN_IDS[@]} > 0)) || fatal "No usable scan configurations were found."
}

select_folder_from_menu() {
    local purpose="$1"
    local choice index marker
    printf '\n%s\n' "${BLUE}${BOLD}${purpose}${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    for index in "${!FOLDER_IDS[@]}"; do
        marker=""
        [[ "${FOLDER_SELECTABLE[$index]}" != "yes" ]] && marker=" [not selectable]"
        printf ' %3d) %-38s [ID: %s | Type: %s]%s\n' "$((index + 1))" "${FOLDER_NAMES[$index]}" "${FOLDER_IDS[$index]}" "${FOLDER_TYPES[$index]}" "$marker"
    done

    while true; do
        printf '\n'
        read -r -p "Select folder number: " choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= ${#FOLDER_IDS[@]})); then
            index=$((choice - 1))
            if [[ "${FOLDER_SELECTABLE[$index]}" != "yes" ]]; then
                warning "'${FOLDER_NAMES[$index]}' cannot be selected."
                continue
            fi
            SELECTED_MENU_FOLDER_ID="${FOLDER_IDS[$index]}"
            SELECTED_MENU_FOLDER_NAME="${FOLDER_NAMES[$index]}"
            return 0
        fi
        warning "Enter a number from 1 to ${#FOLDER_IDS[@]}."
    done
}

select_master_scan() {
    local choice display_index array_index folder_scan_count
    local -a candidate_indexes
    while true; do
        select_folder_from_menu "Select the Folder Containing the Master Scan"
        MASTER_FOLDER_ID="$SELECTED_MENU_FOLDER_ID"
        MASTER_FOLDER_NAME="$SELECTED_MENU_FOLDER_NAME"
        candidate_indexes=()
        for array_index in "${!SCAN_IDS[@]}"; do
            [[ "${SCAN_FOLDER_IDS[$array_index]}" == "$MASTER_FOLDER_ID" ]] && candidate_indexes+=("$array_index")
        done
        folder_scan_count=${#candidate_indexes[@]}
        ((folder_scan_count > 0)) || { warning "No scan configurations were found in '$MASTER_FOLDER_NAME'. Select another folder."; continue; }

        printf '\n%s\n' "${BLUE}${BOLD}Select Master Scan from: ${MASTER_FOLDER_NAME}${NC}"
        printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
        for display_index in "${!candidate_indexes[@]}"; do
            array_index="${candidate_indexes[$display_index]}"
            printf ' %3d) %-48s [ID: %s | Status: %s]\n' "$((display_index + 1))" "${SCAN_NAMES[$array_index]}" "${SCAN_IDS[$array_index]}" "${SCAN_STATUSES[$array_index]}"
        done

        while true; do
            printf '\n'
            read -r -p "Select Master Scan number: " choice
            if [[ "$choice" =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= folder_scan_count)); then
                array_index="${candidate_indexes[$((choice - 1))]}"
                SELECTED_MASTER_SCAN_ID="${SCAN_IDS[$array_index]}"
                SELECTED_MASTER_SCAN_NAME="${SCAN_NAMES[$array_index]}"
                SELECTED_MASTER_SCAN_STATUS="${SCAN_STATUSES[$array_index]}"
                SELECTED_MASTER_SCAN_UUID="${SCAN_UUIDS[$array_index]}"
                SELECTED_MASTER_POLICY_ID="${SCAN_POLICY_IDS[$array_index]}"
                SELECTED_MASTER_SCAN_TYPE="${SCAN_TYPES[$array_index]}"
                break 2
            fi
            warning "Enter a number from 1 to $folder_scan_count."
        done
    done

    success "Selected Master Scan: $SELECTED_MASTER_SCAN_NAME (ID: $SELECTED_MASTER_SCAN_ID)"
    if [[ -n "$SELECTED_MASTER_POLICY_ID" && "$SELECTED_MASTER_POLICY_ID" != "0" && "$SELECTED_MASTER_POLICY_ID" != "null" ]]; then
        warning "This scan reports policy_id=$SELECTED_MASTER_POLICY_ID and may be policy-based."
        warning "For independently editable copies, use a Master Scan created directly from Advanced Scan."
        local answer
        read -r -p "Continue with this Master Scan anyway? [y/N]: " answer
        [[ "$answer" =~ ^[Yy]$ ]] || fatal "Select an independent Advanced Scan master."
    fi
    if [[ -n "$SELECTED_MASTER_SCAN_STATUS" && "$SELECTED_MASTER_SCAN_STATUS" != "empty" && "$SELECTED_MASTER_SCAN_STATUS" != "never" ]]; then
        warning "Master status is '$SELECTED_MASTER_SCAN_STATUS'. A master should normally never be launched."
    fi
}

select_destination_folder() {
    select_folder_from_menu "Select Destination Folder for the New Scan Copies"
    SELECTED_FOLDER_ID="$SELECTED_MENU_FOLDER_ID"
    SELECTED_FOLDER_NAME="$SELECTED_MENU_FOLDER_NAME"
    success "Selected destination folder: $SELECTED_FOLDER_NAME (ID: $SELECTED_FOLDER_ID)"
    if [[ "$SELECTED_FOLDER_ID" == "$MASTER_FOLDER_ID" ]]; then
        warning "The Master Scan folder and destination folder are the same."
        local answer
        read -r -p "Continue using the same folder? [y/N]: " answer
        [[ "$answer" =~ ^[Yy]$ ]] || fatal "Select a different destination folder."
    fi
}

resolve_master_uuid() {
    local editor_file="$TMP_DIR/master_editor.json"
    local results_file="$TMP_DIR/master_results.json"
    local editor_uuid=""
    info "Retrieving the Master Scan editor UUID required for updates..."

    if api_get "/editor/scan/${SELECTED_MASTER_SCAN_ID}" "$editor_file"; then
        editor_uuid="$(python3 - "$editor_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
candidates = []
if isinstance(data, dict):
    candidates.extend([data.get("uuid"), data.get("template_uuid")])
    for key in ("scan", "policy", "template"):
        value = data.get(key)
        if isinstance(value, dict):
            candidates.extend([value.get("uuid"), value.get("template_uuid")])
for value in candidates:
    if value:
        print(value)
        break
PY
)"
    fi

    if [[ -n "$editor_uuid" ]]; then
        SELECTED_MASTER_SCAN_UUID="$editor_uuid"
        success "Master editor UUID loaded successfully."
        return 0
    fi

    warning "The editor endpoint did not expose a UUID; trying scan details and scan-list fallbacks."
    if api_get "/scans/${SELECTED_MASTER_SCAN_ID}" "$results_file"; then
        SELECTED_MASTER_SCAN_UUID="$(python3 - "$results_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
for obj in (data.get("scan"), data.get("info"), data):
    if isinstance(obj, dict) and obj.get("uuid"):
        print(obj["uuid"])
        break
PY
)"
    fi
    [[ -n "$SELECTED_MASTER_SCAN_UUID" ]] || fatal "Unable to determine the Master Scan UUID required for PUT /scans/{id}."
    warning "Using a fallback scan UUID because the editor UUID was unavailable."
}

check_master_credentials() {
    local editor_file="$TMP_DIR/master_credential_check.json"
    local detected="unknown"
    info "Checking whether the selected Master Scan already contains credentials..."
    if ! api_get "/editor/scan/${SELECTED_MASTER_SCAN_ID}" "$editor_file"; then
        warning "Could not inspect Master Scan credentials. Confirm manually that the master contains no credentials."
        return 0
    fi
    detected="$(python3 - "$editor_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
def has_nonempty(value):
    if value is None or value == "" or value == [] or value == {}:
        return False
    if isinstance(value, dict):
        return any(has_nonempty(v) for v in value.values())
    if isinstance(value, list):
        return any(has_nonempty(v) for v in value)
    return True
def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)
for obj in walk(data):
    credentials = obj.get("credentials")
    if isinstance(credentials, dict):
        current = credentials.get("current")
        if isinstance(current, dict) and has_nonempty(current):
            print("yes")
            raise SystemExit(0)
print("no")
PY
)"
    [[ "$detected" == "yes" ]] && fatal "The selected Master Scan contains existing credentials. Remove them before copying to avoid account lockout."
    success "No existing credentials were detected in the Master Scan."
}

detect_ssh_password_auth_method() {
    local response_file="$TMP_DIR/credential_types.json"
    local detected=""
    [[ "$SCAN_MODE" == "authenticated" ]] || return 0
    info "Determining the exact SSH password authentication method ID..."
    if api_get '/credentials/types' "$response_file"; then
        detected="$(python3 - "$response_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)
def find_password_option(value):
    for obj in walk(value):
        if str(obj.get("id") or "").lower() != "auth_method":
            continue
        options = obj.get("options")
        if not isinstance(options, list):
            continue
        for option in options:
            if not isinstance(option, dict):
                continue
            option_id = str(option.get("id") or "")
            option_name = str(option.get("name") or "")
            if option_id.lower() == "password" or option_name.lower() == "password":
                return option_id or "password"
    return ""
for obj in walk(data):
    type_id = str(obj.get("id") or obj.get("name") or "").lower()
    if type_id != "ssh":
        continue
    result = find_password_option(obj)
    if result:
        print(result)
        raise SystemExit(0)
raise SystemExit(1)
PY
)" || true
    fi
    if [[ -n "$detected" ]]; then
        SSH_AUTH_METHOD="$detected"
        success "SSH auth_method: $SSH_AUTH_METHOD"
    else
        SSH_AUTH_METHOD="password"
        warning "Could not read the SSH schema; using auth_method=$SSH_AUTH_METHOD"
    fi
}

#-------------------------------------------------------------------------------
# CONFIRMATION
#-------------------------------------------------------------------------------
confirm_creation() {
    local answer
    printf '\n%s\n' "${BLUE}${BOLD}Creation Summary${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    printf 'Scan type       : %s\n' "$SCAN_MODE_LABEL"
    printf 'Master folder   : %s\n' "$MASTER_FOLDER_NAME"
    printf 'Master scan     : %s (ID: %s)\n' "$SELECTED_MASTER_SCAN_NAME" "$SELECTED_MASTER_SCAN_ID"
    printf 'Destination     : %s (ID: %s)\n' "$SELECTED_FOLDER_NAME" "$SELECTED_FOLDER_ID"
    printf 'Valid IPs       : %s\n' "${#TARGETS[@]}"
    printf 'New scan names  : %s_<IP address>\n' "$SELECTED_FOLDER_NAME"
    printf 'Automatic launch: Disabled\n'
    printf 'Existing names  : %s\n' "$SKIP_EXISTING_NAMES"
    if [[ "$SCAN_MODE" == "authenticated" ]]; then
        printf 'Credential input: %s\n' "$AUTH_INPUT_LABEL"
        printf 'Credential rule : Exactly one SSH credential per copied scan\n'
    else
        printf 'Credentials     : None\n'
    fi
    printf '\n%s\n' "${YELLOW}${BOLD}IMPORTANT:${NC} The selected Master Scan must remain credential-free."
    printf '\n'
    read -r -p "Create these Master Scan copies? [y/N]: " answer
    [[ "$answer" =~ ^[Yy]$ ]] || { warning "Operation cancelled. No scans were created."; exit 0; }
}

#-------------------------------------------------------------------------------
# COPY, UPDATE, VERIFY, ROLLBACK
#-------------------------------------------------------------------------------
parse_copy_response() {
    local response_file="$1"
    python3 - "$response_file" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
candidates = []
if isinstance(data, dict):
    for key in ("scan", "copy", "configuration"):
        value = data.get(key)
        if isinstance(value, dict):
            candidates.append(value)
    candidates.append(data)
scan_id = ""
uuid = ""
for obj in candidates:
    if not scan_id and obj.get("id") is not None:
        scan_id = str(obj.get("id"))
    if not uuid and obj.get("uuid"):
        uuid = str(obj.get("uuid"))
print(f"{scan_id}\x1f{uuid}")
PY
}

rollback_copy() {
    local scan_id="$1"
    local response_file="$TMP_DIR/delete_${scan_id}.json"
    local status
    [[ "$ROLLBACK_ON_UPDATE_FAILURE" == "yes" ]] || return 0
    status="$(api_call DELETE "/scans/${scan_id}" "$response_file")" || true
    if [[ "$status" == "200" || "$status" == "202" || "$status" == "204" ]]; then
        warning "Removed incomplete copied scan ID $scan_id."
    else
        warning "Could not remove incomplete scan ID $scan_id (HTTP ${status:-unknown})."
    fi
}

verify_auth_credential_best_effort() {
    local scan_id="$1"
    local username="$2"
    local editor_file="$TMP_DIR/verify_auth_${scan_id}.json"
    local verified="no"
    [[ "$VERIFY_FIRST_AUTH_CREDENTIAL" == "yes" ]] || return 0
    if api_get "/editor/scan/${scan_id}" "$editor_file"; then
        verified="$(python3 - "$editor_file" "$username" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
username = sys.argv[2]
def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)
for obj in walk(data):
    credentials = obj.get("credentials")
    if isinstance(credentials, dict):
        current = credentials.get("current")
        if isinstance(current, dict):
            host = current.get("Host")
            if isinstance(host, dict) and host.get("SSH"):
                print("yes")
                raise SystemExit(0)
for obj in walk(data):
    if str(obj.get("username") or "") == username:
        print("yes")
        raise SystemExit(0)
print("no")
PY
)"
    fi
    if [[ "$verified" == "yes" ]]; then
        success "Best-effort check found the SSH credential on the first copied scan."
    else
        warning "The update API accepted the credential, but the editor response did not confirm it."
        warning "Open the first copied scan in Nessus and confirm Credentials > Host > SSH before launching."
    fi
}

create_master_copies() {
    local total created failed skipped target safe_target scan_name
    local copy_payload copy_response copy_status copied_id copied_uuid
    local update_payload update_response update_status update_error
    local username="" credential_method="N/A" verified_once="no"

    total=${#TARGETS[@]}
    created=0
    failed=0
    skipped=0
    printf '%s\n' '"IP","Scan Name","Scan ID","Scan Type","Credential Method","Master Scan","Destination Folder","Status"' > "$REPORT_FILE"
    printf '\n%s\n' "${CYAN}${BOLD}[*] Copying and updating Master Scan configurations...${NC}"

    local index=0
    for target in "${TARGETS[@]}"; do
        ((index += 1))
        safe_target="$(printf '%s' "$target" | tr '/: ' '___')"
        scan_name="${SELECTED_FOLDER_NAME}_${safe_target}"
        printf '\n%s\n' "${CYAN}[${index}/${total}] Processing: ${scan_name}${NC}"
        printf '    Target: %s\n' "$target"

        if [[ "$SKIP_EXISTING_NAMES" == "yes" && -n "${EXISTING_SCAN_NAMES[$scan_name]+x}" ]]; then
            warning "A scan named '$scan_name' already exists. Skipping."
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_escape "$target")" "$(csv_escape "$scan_name")" '""' "$(csv_escape "$SCAN_MODE_LABEL")" "$(csv_escape "${AUTH_INPUT_LABEL:-N/A}")" "$(csv_escape "$SELECTED_MASTER_SCAN_NAME")" "$(csv_escape "$SELECTED_FOLDER_NAME")" '"Skipped: name already exists"' >> "$REPORT_FILE"
            ((skipped += 1))
            continue
        fi

        copy_payload="$TMP_DIR/copy_${index}.json"
        copy_response="$TMP_DIR/copy_response_${index}.json"
        python3 - "$SELECTED_FOLDER_ID" "$scan_name" "$copy_payload" <<'PY'
import json
import os
import sys
folder_id, name, path = sys.argv[1:4]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({"folder_id": int(folder_id), "name": name}, handle)
os.chmod(path, 0o600)
PY
        copy_status="$(api_call POST "/scans/${SELECTED_MASTER_SCAN_ID}/copy" "$copy_response" "$copy_payload")" || copy_status=""
        if [[ "$copy_status" != "200" && "$copy_status" != "201" ]]; then
            update_error="$(extract_error_message "$copy_response")"
            printf '%s\n' "${RED}    [ERROR] Master copy failed. HTTP ${copy_status:-unknown}: ${update_error}${NC}"
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_escape "$target")" "$(csv_escape "$scan_name")" '""' "$(csv_escape "$SCAN_MODE_LABEL")" "$(csv_escape "${AUTH_INPUT_LABEL:-N/A}")" "$(csv_escape "$SELECTED_MASTER_SCAN_NAME")" "$(csv_escape "$SELECTED_FOLDER_NAME")" "$(csv_escape "Copy failed HTTP ${copy_status:-unknown}")" >> "$REPORT_FILE"
            ((failed += 1))
            continue
        fi

        IFS=$'\x1f' read -r copied_id copied_uuid < <(parse_copy_response "$copy_response")
        if [[ -z "$copied_id" ]]; then
            printf '%s\n' "${RED}    [ERROR] Copy succeeded but the new Scan ID could not be parsed.${NC}"
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_escape "$target")" "$(csv_escape "$scan_name")" '""' "$(csv_escape "$SCAN_MODE_LABEL")" "$(csv_escape "${AUTH_INPUT_LABEL:-N/A}")" "$(csv_escape "$SELECTED_MASTER_SCAN_NAME")" "$(csv_escape "$SELECTED_FOLDER_NAME")" '"Copy response missing Scan ID"' >> "$REPORT_FILE"
            ((failed += 1))
            continue
        fi

        copied_uuid="$SELECTED_MASTER_SCAN_UUID"
        printf '%s\n' "${GREEN}    [+] Master copied. New Scan ID: ${copied_id}${NC}"
        update_payload="$TMP_DIR/update_${copied_id}.json"
        update_response="$TMP_DIR/update_response_${copied_id}.json"

        if [[ "$SCAN_MODE" == "authenticated" ]]; then
            username="$(python3 - "$CREDENTIALS_JSON" "$target" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1], "r", encoding="utf-8"))
credential = data.get(sys.argv[2]) or {}
print(credential.get("username", ""))
PY
)"
            credential_method="$AUTH_INPUT_LABEL"
        else
            username=""
            credential_method="N/A"
        fi

        python3 - "$copied_uuid" "$scan_name" "$target" "$SELECTED_FOLDER_ID" "$SCAN_MODE" "$CREDENTIALS_JSON" "$SSH_AUTH_METHOD" "$SELECTED_MASTER_SCAN_NAME" "$update_payload" <<'PY'
import json
import os
import sys
scan_uuid, scan_name, target, folder_id, scan_mode, credentials_path, auth_method, master_name, output_path = sys.argv[1:10]
authenticated = scan_mode == "authenticated"
description = (
    f"Copied from Master Scan '{master_name}'. Authenticated SSH scan for {target}; one credential is mapped only to this IP."
    if authenticated
    else f"Copied from Master Scan '{master_name}'. Unauthenticated scan for {target}."
)
payload = {
    "uuid": scan_uuid,
    "settings": {
        "name": scan_name,
        "description": description,
        "folder_id": int(folder_id),
        "text_targets": target,
        "enabled": False,
    },
}
if authenticated:
    credentials = json.load(open(credentials_path, "r", encoding="utf-8"))
    credential = credentials.get(target)
    if not credential:
        raise SystemExit(f"No credential mapping found for {target}")
    payload["credentials"] = {
        "add": {
            "Host": {
                "SSH": [
                    {
                        "auth_method": auth_method,
                        "username": credential["username"],
                        "password": credential["password"],
                    }
                ]
            }
        }
    }
with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(payload, handle, ensure_ascii=False)
os.chmod(output_path, 0o600)
PY
        if [[ $? -ne 0 ]]; then
            printf '%s\n' "${RED}    [ERROR] Could not build the update payload.${NC}"
            rollback_copy "$copied_id"
            ((failed += 1))
            continue
        fi

        update_status="$(api_call PUT "/scans/${copied_id}" "$update_response" "$update_payload")" || update_status=""
        if [[ "$update_status" == "200" || "$update_status" == "201" ]]; then
            printf '%s\n' "${GREEN}    [+] Target updated to: ${target}${NC}"
            if [[ "$SCAN_MODE" == "authenticated" ]]; then
                printf '%s\n' "${GREEN}    [+] One SSH credential request was accepted for this scan.${NC}"
                if [[ "$verified_once" == "no" ]]; then
                    verify_auth_credential_best_effort "$copied_id" "$username"
                    verified_once="yes"
                fi
            fi
            EXISTING_SCAN_NAMES["$scan_name"]=1
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_escape "$target")" "$(csv_escape "$scan_name")" "$(csv_escape "$copied_id")" "$(csv_escape "$SCAN_MODE_LABEL")" "$(csv_escape "$credential_method")" "$(csv_escape "$SELECTED_MASTER_SCAN_NAME")" "$(csv_escape "$SELECTED_FOLDER_NAME")" '"Created and updated"' >> "$REPORT_FILE"
            ((created += 1))
        else
            update_error="$(extract_error_message "$update_response")"
            printf '%s\n' "${RED}    [ERROR] Copied scan update failed. HTTP ${update_status:-unknown}: ${update_error}${NC}"
            rollback_copy "$copied_id"
            printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(csv_escape "$target")" "$(csv_escape "$scan_name")" "$(csv_escape "$copied_id")" "$(csv_escape "$SCAN_MODE_LABEL")" "$(csv_escape "$credential_method")" "$(csv_escape "$SELECTED_MASTER_SCAN_NAME")" "$(csv_escape "$SELECTED_FOLDER_NAME")" "$(csv_escape "Update failed HTTP ${update_status:-unknown}")" >> "$REPORT_FILE"
            ((failed += 1))
        fi
        sleep 1
    done

    printf '\n%s\n' "${BLUE}${BOLD}Final Summary${NC}"
    printf '%s\n' "${BLUE}--------------------------------------------------------------${NC}"
    printf 'Targets processed   : %s\n' "$total"
    printf 'Created successfully: %s%s%s\n' "$GREEN" "$created" "$NC"
    printf 'Skipped             : %s%s%s\n' "$YELLOW" "$skipped" "$NC"
    printf 'Failed              : %s%s%s\n' "$RED" "$failed" "$NC"
    printf 'Report              : %s\n' "$REPORT_FILE"
    printf 'Automatic launch    : Disabled\n'
    if [[ "$SCAN_MODE" == "authenticated" && "$created" -gt 0 ]]; then
        printf '\n%s\n' "${YELLOW}${BOLD}Before launching:${NC} Open the first created scan and confirm Credentials > Host > SSH."
    fi
}

#-------------------------------------------------------------------------------
# MAIN
#-------------------------------------------------------------------------------
main() {
    print_banner
    require_command curl
    require_command python3
    require_command stat

    select_scan_mode
    select_auth_input_mode
    prompt_input_files

    set_api_header
    test_connection
    prepare_targets_and_credentials
    load_folders
    load_scans
    select_master_scan
    select_destination_folder
    resolve_master_uuid
    check_master_credentials
    detect_ssh_password_auth_method
    confirm_creation
    create_master_copies
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
