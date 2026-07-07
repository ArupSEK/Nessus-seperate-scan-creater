# 🛡️ Nessus Master Scan Bulk Creator

A Bash/Python-based Nessus automation tool by **Sleeping Bhudda** to create separate scan copies from one master scan.

## What it does

This tool helps you create one Nessus scan per IP address without manually duplicating scans in the Nessus UI.

It can create:

- **Authenticated scans** with one SSH username/password mapped to each IP
- **Unauthenticated scans** with only one target IP per copied scan

The script **never launches scans automatically**. It only creates and updates scan configurations.

## Available scripts

```text
nessus_master_scan_bulk_creator.sh
nessus_master_scan_bulk_creator.py
```

## Python version - immediate manual mode

The Python version supports a safer manual flow:

```text
Choose scan type
   ↓
Authenticated or Unauthenticated
   ↓
Connect to Nessus API
   ↓
Load folders and scans from Nessus
   ↓
Select master scan folder
   ↓
Select master scan
   ↓
Select destination folder
   ↓
Review selection
   ↓
Use y to continue OR b to go back
   ↓
Select IP file
   ↓
For each IP:
   Enter username/password
   Save credential locally
   Immediately create that IP scan
   Update target to exactly one IP
   Add SSH credential
   Write report row
```

In **Manual secure entry** mode, the Python script does **not** wait for all credentials to be entered first. It creates each scan immediately after the credential for that IP is entered.

If the script is interrupted, scans already created remain in Nessus. Manual credentials already entered remain in the local protected file.

Local credential file:

```text
~/.nessus_bulk_creator/manual_credentials.json
```

Permissions used:

```text
Folder: 700
File  : 600
```

Security note: this local credential file is protected by OS permissions only. It is not encrypted by the script. Use full-disk encryption or replace the store with GPG/secret-manager storage if stronger protection is required.

## Bash version - original flow

The Bash version first completes all Nessus-side selections, then asks for the IP file or credentials.

This avoids the old issue where you typed many usernames/passwords first, then later made a mistake in folder/master scan selection and had to start again.

## Main workflow

```text
Choose scan type
   ↓
For authenticated mode, choose manual entry or credential CSV
   ↓
Connect to Nessus API
   ↓
Load Nessus folders and scans
   ↓
Select master scan folder
   ↓
Select credential-free master scan
   ↓
Select destination folder
   ↓
Review all Nessus selections
   ↓
Use y to continue OR b to go back and correct selection
   ↓
Select IP file or credential CSV
   ↓
For manual authenticated Bash mode, enter username/password per IP
   ↓
Final creation confirmation
   ↓
Copy master scan once per IP
   ↓
Rename each scan as <Destination Folder Name>_<IP>
   ↓
Update target to exactly one IP
   ↓
Add SSH credential if authenticated mode is selected
   ↓
Generate CSV report
```

## 🔙 Back feature

The scripts support correction before credentials are entered.

You can go back from:

- Master scan selection → back to master folder selection
- Destination folder selection → back to master scan selection
- Selection review screen → back to folder/master/destination selection

This means manual credentials are requested **only after** you confirm:

```text
Master Folder
Master Scan
Destination Folder
Scan Type
Credential Method
```

## Before running

Edit these values at the top of the script or use environment variables:

```bash
export NESSUS_URL="https://127.0.0.1:8834"
export NESSUS_ACCESS_KEY="your_nessus_access_key"
export NESSUS_SECRET_KEY="your_nessus_secret_key"
```

## Requirements

```bash
sudo apt update
sudo apt install -y curl python3
```

The Python version uses only Python standard libraries. No pip package is required.

## Run Bash version

```bash
git clone https://github.com/ArupSEK/Nessus-seperate-scan-creater.git
cd Nessus-seperate-scan-creater
chmod +x nessus_master_scan_bulk_creator.sh
./nessus_master_scan_bulk_creator.sh
```

## Run Python version

```bash
git clone https://github.com/ArupSEK/Nessus-seperate-scan-creater.git
cd Nessus-seperate-scan-creater
chmod +x nessus_master_scan_bulk_creator.py
python3 nessus_master_scan_bulk_creator.py
```

You can also pre-fill input paths:

```bash
python3 nessus_master_scan_bulk_creator.py ips.txt credentials.csv
```

## IP file format

For unauthenticated mode or manual credential mode:

```text
192.168.1.10
192.168.1.11
10.10.10.25
```

Rules:

- One individual IP per line
- CIDR/ranges are not accepted
- Blank lines are skipped
- Lines starting with `#` are skipped

## Credential CSV format

For authenticated CSV mode:

```csv
IP,Username,Password
192.168.1.10,root,Password@123
192.168.1.11,admin,Password@456
```

Recommended file permission:

```bash
chmod 600 credentials.csv
```

## Safety rules

- The selected master scan should be credential-free.
- The tool checks for existing master credentials before copying.
- Manual credentials are requested only after folder/master/destination selection is reviewed.
- Each copied scan receives exactly one target IP.
- Each authenticated copied scan receives only the matching SSH credential.
- Existing scan names are skipped by default.
- If scan update fails, the copied scan is removed by default.
- Scans are not launched automatically.

## Output report

After execution, the tool creates a CSV report like:

```text
master_scan_copies_YYYYMMDD_HHMMSS.csv
master_scan_copies_python_YYYYMMDD_HHMMSS.csv
```

Report columns:

```text
IP, Scan Name, Scan ID, Scan Type, Credential Method, Master Scan, Destination Folder, Status
```

## Important note

After creating authenticated scans, open the first copied scan in Nessus and verify:

```text
Credentials > Host > SSH
```

Then launch scans manually only after confirmation.
