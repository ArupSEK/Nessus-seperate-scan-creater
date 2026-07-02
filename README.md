# 🛡️ Nessus Master Scan Bulk Creator

A Bash-based Nessus automation tool by **Sleeping Bhudda** to create separate scan copies from one master scan.

## What it does

This tool helps you create one Nessus scan per IP address without manually duplicating scans in the Nessus UI.

It can create:

- **Authenticated scans** with one SSH username/password mapped to each IP
- **Unauthenticated scans** with only one target IP per copied scan

The script **never launches scans automatically**. It only creates and updates scan configurations.

## Main workflow

```text
Choose scan type
   ↓
Select IP file or credential CSV
   ↓
Connect to Nessus API
   ↓
Load Nessus folders
   ↓
Select master scan folder
   ↓
Select credential-free master scan
   ↓
Select destination folder
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

## Script file

```text
nessus_master_scan_bulk_creator.sh
```

## Before running

Edit these values at the top of the script:

```bash
NESSUS_URL="https://127.0.0.1:8834"
NESSUS_ACCESS_KEY="your_nessus_access_key"
NESSUS_SECRET_KEY="your_nessus_secret_key"
```

## Requirements

```bash
sudo apt update
sudo apt install -y curl python3
```

## Run

```bash
git clone https://github.com/ArupSEK/Nessus-seperate-scan-creater.git
cd Nessus-seperate-scan-creater
chmod +x nessus_master_scan_bulk_creator.sh
./nessus_master_scan_bulk_creator.sh
```

You can also pre-fill input paths:

```bash
./nessus_master_scan_bulk_creator.sh ips.txt credentials.csv
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
- Each copied scan receives exactly one target IP.
- Each authenticated copied scan receives only the matching SSH credential.
- Existing scan names are skipped by default.
- If scan update fails, the copied scan is removed by default.
- Scans are not launched automatically.

## Output report

After execution, the tool creates a CSV report like:

```text
master_scan_copies_YYYYMMDD_HHMMSS.csv
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
