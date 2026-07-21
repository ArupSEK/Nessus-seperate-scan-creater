# Multiple IPs in One Nessus Scan

The repository now includes an additional mode for creating **one Nessus scan containing multiple IP addresses**.

## Files

```text
nessus_scan_creator.py
nessus_multi_ip_single_scan_creator.py
```

Use the launcher to choose between the existing separate-scan mode and the new single-scan mode:

```bash
python3 nessus_scan_creator.py
```

Menu:

```text
1) Create a separate scan for each IP
2) Create one scan containing multiple IPs
```

You can also run the new mode directly:

```bash
python3 nessus_multi_ip_single_scan_creator.py ips.txt
```

## API authentication

Yes. The scripts connect to Nessus using the Nessus API access key and secret key.

```bash
export NESSUS_URL="https://127.0.0.1:8834"
export NESSUS_ACCESS_KEY="your_nessus_access_key"
export NESSUS_SECRET_KEY="your_nessus_secret_key"
```

The request header is:

```text
X-ApiKeys: accessKey=<ACCESS_KEY>; secretKey=<SECRET_KEY>
```

Do not commit real keys to GitHub. Use environment variables.

## Input file

Use one individual IP per line. Comma-separated IPs are also accepted.

```text
192.168.1.10
192.168.1.11
10.10.10.25
```

Blank lines, comments beginning with `#`, invalid entries, and duplicate IPs are handled safely.

## Modes

### Unauthenticated

One copied scan is created and all IPs are placed in the target field. No host credential is added.

### Authenticated with one shared SSH credential

One copied scan is created and one SSH username/password is added for the entire target list.

**Important:** Nessus may try this shared credential against every target. Use this mode only when the same account is approved and valid across all listed systems. Confirm lockout controls before launching.

Per-IP credential mapping remains available only in the existing **separate scan per IP** workflow. This prevents different host passwords from being reused across unrelated targets in one scan.

## Safety behavior

- The master scan must not contain existing credentials.
- The script copies the master only once.
- All validated IPs are written to `text_targets` in the copied scan.
- The created scan remains disabled.
- The script never launches scans automatically.
- If the update fails, the incomplete copied scan is removed by default.
- A CSV report is generated locally.

## Recommended validation

Before manually launching the created scan:

1. Open the new scan in Nessus.
2. Confirm the full target list.
3. For authenticated mode, confirm **Credentials > Host > SSH**.
4. Verify the shared account is permitted on every target.
5. Start with a small approved target group before using a large list.
