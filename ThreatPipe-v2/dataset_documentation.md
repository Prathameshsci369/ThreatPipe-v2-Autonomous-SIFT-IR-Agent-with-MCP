
# Dataset Documentation

## Overview
The ThreatPipe v2 test dataset is a synthetically generated, multi-format security log file designed to simulate a realistic, multi-stage intrusion on a web server. 

Unlike standard log datasets, this dataset is tightly coupled with a physical filesystem layout (created by `setup_test_evidence.py`). When the LangGraph agent executes SIFT tools (`strings`, `file`, `grep`), it is analyzing **real malicious files** on disk, allowing the pipeline to demonstrate true forensic accuracy and the self-correction loop.

## Data Source
Synthetically generated via `generate_test_logs.py`. 
The default output file is `realistic_attack.log`.

## Log Formats Included
The dataset contains 6 distinct log formats to test the `trigger_parser.py` regex capabilities:
1. **Apache/Nginx Combined Web Logs:** Standard GET/POST requests with status codes and sizes.
2. **SSH Auth Logs:** `sshd` format logs for brute-force and successful login events.
3. **FTP Logs (ProFTPD):** `STOR` (upload) and `RETR` (download) events.
4. **Memory Anomaly Logs:** Volatility-style `malfind` output indicating injected processes.
5. **Windows Registry Logs:** Run key persistence events.
6. **MFT Timeline Logs:** `mactime`/`fls` style body file entries with MACB timestamps.

---

## Attack Campaigns & Ground Truth

The dataset simulates 4 distinct attacker IPs performing different phases of the MITRE ATT&CK kill chain.

### Campaign 1: Full APT Kill Chain (IP: 192.168.1.55)
This IP executes a complete, sophisticated attack sequence.
- **RECON:** Probes for `.env` and `.git/config`.
- **EXPLOIT (SQLi):** Uses `UNION SELECT INTO OUTFILE` to drop a web shell (`sqli_dump.php`).
- **UPLOAD:** Uses legitimate upload endpoint (`upload.php`).
- **BACKDOOR:** Executes commands via `shell.php?cmd=`, accesses obfuscated shell (`cache.php` using `base64_decode`), and triggers a polyglot payload (`evil.png` containing PHP).
- **PERSIST:** Downloads a cron-based reverse shell script (`cron_setup.sh`).
- **EXFIL:** Uses FTP `RETR` to steal the database backup.

**Artifact Mapping:** Logs map to real files in `/tmp/threatpipe_evidence/www/uploads/` and `/images/`.

### Campaign 2: Brute Force & Valid Accounts (IP: 10.0.0.42)
- **SCAN:** Nikto-style directory brute forcing (returning 404s).
- **SCAN:** SSH brute force against multiple users (Failed password).
- **EXPLOIT:** Successful SSH login (Accepted password), demonstrating the transition from scanning to valid account takeover.

**Artifact Mapping:** Simulates remote access; triggers the SSH regex parser.

### Campaign 3: Reconnaissance Scanner (IP: 192.168.1.80)
- **RECON:** Probing sensitive paths (`/wp-config.php`, `/phpinfo.php`, `/adminer.php`).

**Artifact Mapping:** Logs map to files in `/tmp/threatpipe_evidence/www/` (e.g., `wp-config.php`).

### Campaign 4: Exploitation Attempts (IPs: 203.0.113.77, 198.51.100.23)
- **EXPLOIT (SQLi):** Standard SQL injection payloads (`OR 1=1`, `DROP TABLE`, `SLEEP`).
- **EXPLOIT (LFI/RFI):** Local/Remote File Inclusion (`../../etc/passwd`, `php://filter`).

**Artifact Mapping:** Tests the agent's ability to flag active exploitation even if the file doesn't exist on the local disk.

---

## Forensic Format Ground Truth

The dataset includes specialized log formats designed to trigger specific SIFT tool workflows:

| Log Format | Example Line | Expected Agent Behavior |
|---|---|---|
| **Memory Anomaly** | `[MEMORY] PID=1337 process=svchost.exe malfind=YES...` | `trigger_parser` identifies `memory_anomaly` type. Agent runs `strings` on the mock `.dmp` file, finding shellcode and C2 IPs. |
| **Registry Persistence** | `[REGISTRY] HKLM\Software\Microsoft\Windows\CurrentVersion\Run...` | `trigger_parser` identifies `registry_event`. Agent runs `strings` on the mock `.hive` file, finding the Run key. |
| **MFT Timeline** | `2026-04-16T03:14:25Z m... /var/www/html/uploads/shell.php` | `trigger_parser` identifies `mft_entry`. Agent can correlate file creation time with trigger event. |

---

## Benign Traffic Baseline
To test the Stage 1 LLM classification accuracy, the dataset injects realistic noise:
- **Default Size (`--size medium`):** ~150 benign requests from 50+ internal IPs (`10.1.x.x`) requesting standard resources (HTML, CSS, API endpoints) with `200 OK` responses.

---

## Regenerating / Customizing the Dataset
The dataset is fully reproducible via command-line flags, allowing judges to test the LLM sliding window under different data volumes:

```bash
# Small dataset (Fast test)
python generate_test_logs.py --size small

# Large dataset (Tests LLM context window chunking)
python generate_test_logs.py --size large

# Targeted test (Only Web Shells and SQLi)
python generate_test_logs.py --attacks webshell,sqli --output sqli_test.log
```

---

## Statistical Summary (Default `medium` run)
- **Total Lines:** ~200
- **Attack Lines:** ~45
- **Benign Lines:** ~155
- **Expected Stage 1 Output:** ~20-25 suspicious lines classified by the LLM.
- **Expected Verdicts:** 
  - `MALICIOUS`: Web shell execution, Obfuscated PHP access, Polyglot image execution.
  - `SUSPICIOUS`: Sensitive file probing (`/.env`), SSH brute force, SQL injection attempts.
  - `BENIGN`: Normal site navigation.



