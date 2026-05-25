"""
ThreatPipe v2 — Stage Classifier
==================================
Agent forensic result + raw log → attack stage + attack vector.

No LLM. Pure deterministic mapping.
Feeds HackerMindsetGraph with structured stage data.

Input:
  - StructuredTrigger (parsed log)
  - CrossReferenceResult (agent forensic verdict)
  - raw_log string

Output:
  - stage: "RECON" / "SCAN" / "EXPLOIT" / "UPLOAD" / "BACKDOOR" / "PERSIST" / "EXFIL" / "LATERAL"
  - attack_vector: specific technique string
  - evidence: dict for graph node
"""

import re
from typing import Optional, Tuple

from logger import get_logger
from hacker_mindset_graph import ATTACK_VECTOR_MAP, STAGE_PROGRESSION

log = get_logger("stage_classifier")

# ─── Classification rules ─────────────────────────────────────────────────────
# Each rule: (check_fn, stage, attack_vector, priority)
# Higher priority = checked first

# Sensitive paths → RECON
_RECON_PATHS = [
    ".env", ".git", "robots.txt", "wp-config", "phpinfo",
    "/.well-known", "sitemap.xml", "crossdomain.xml",
    "server-status", "server-info", "elmah.axd",
    "/backup", "/bak", "/.htaccess", "web.config",
    "adminer", "phpmyadmin", "cpanel", "webmail",
]

# Scan/probe patterns
_SCAN_PATTERNS = [
    r"nikto", r"nmap", r"masscan", r"sqlmap", r"dirbuster",
    r"gobuster", r"wfuzz", r"burpsuite", r"acunetix",
    r"nessus", r"openvas", r"w3af", r"skipfish",
]

# SQL injection patterns
_SQLI_PATTERNS = [
    r"union.{0,10}select", r"or.{0,5}1.{0,3}=.{0,3}1",
    r"drop.{0,5}table", r"insert.{0,5}into",
    r"sleep\s*\(", r"benchmark\s*\(", r"load_file\s*\(",
    r"into\s+outfile", r";\s*--", r"'--",
    r"xp_cmdshell", r"exec\s*\(", r"waitfor\s+delay",
]

# Command injection in URL + PHP obfuscation + bytecode
_CMDINJECT_PATTERNS = [
    r"cmd=", r"exec=", r"shell=", r"command=", r"run=",
    r"passthru=", r"system=", r"eval=",
    r"whoami", r"`id`", r"uname",
    r"cat.{0,10}/etc/passwd", r"cat.{0,10}/etc/shadow",
    r"/bin/sh", r"/bin/bash", r"nc\s+-e",
    # PHP obfuscation indicators
    r"base64_decode", r"gzinflate", r"gzuncompress", r"str_rot13",
    r"eval\s*\(", r"assert\s*\(", r"preg_replace.*\/e",
    r"chr\s*\(\d",     r"\\x[0-9a-f]{2}",
    # React/Node.js RCE
    r"__proto__", r"constructor\[", r"require\(",
    r"child_process", r"execSync", r"spawnSync",
    # Java deserialization
    r"aced0005", r"rO0AB", r"java\.lang\.Runtime",
]

# PHP bytecode / obfuscation specific patterns
_PHP_OBFUSCATION_PATTERNS = [
    r"eval\s*\(", r"base64_decode\s*\(", r"gzinflate\s*\(",
    r"gzuncompress\s*\(", r"str_rot13\s*\(", r"assert\s*\(",
    r"preg_replace.*\/e", r"call_user_func", r"array_map.*eval",
    r"create_function", r"ReflectionFunction",
   
    r"\$\{.*\}\s*\(", r"\$\$",   r"\\x[0-9a-f]{2}",
]

# React/Modern web app vuln patterns  
_REACT_VULN_PATTERNS = [
    r"__proto__\[", r"constructor\[", r"prototype\[",
    r"dangerouslySetInnerHTML", r"eval\s*\(.*\$",
    r"innerHTML\s*=", r"document\.write\s*\(",
    r"setTimeout\s*\(.*\+", r"setInterval\s*\(.*\+",
]

# File upload indicators
_UPLOAD_PATTERNS = [
    r"POST.*upload", r"POST.*file", r"multipart/form-data",
    r"\.php.*POST.*200", r"\.phtml.*POST",
    r"STOR\s+.*\.(php|phtml|php3|asp|jsp|sh|py|pl)",
]

# Exfiltration indicators
_EXFIL_PATHS = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "id_rsa", "id_dsa", ".ssh/authorized_keys",
    "db.sql", "database.sql", "dump.sql",
    "backup.tar", "backup.zip", ".bash_history",
    "credentials", "passwords.txt", "secret",
]

# Persistence indicators
_PERSIST_PATHS = [
    "cron", "crontab", "rc.local", "init.d",
    "authorized_keys", ".profile", ".bashrc",
    "currentversion", "winlogon", "services.exe", "svchost",
    "startup",
]


def _check_patterns(text: str, patterns: list) -> bool:
    """Check if any pattern matches in text (case-insensitive)."""
    text_lower = text.lower()
    for p in patterns:
        if re.search(p, text_lower, re.IGNORECASE):
            return True
    return False


def classify_stage(
    raw_log: str,
    trigger=None,         # StructuredTrigger (optional)
    analysis=None,        # CrossReferenceResult (optional)
) -> Tuple[str, str, dict]:
    """
    Main entry point.

    Returns (stage, attack_vector, evidence_dict).

    Priority order:
      1. If forensic verdict = MALICIOUS → check what TYPE of malicious
      2. If http_method = POST + php upload → UPLOAD
      3. If cmd= in query → BACKDOOR (webshell execution)
      4. If SQLi pattern → EXPLOIT
      5. If sensitive path probe → RECON
      6. If repeated 401/403 → SCAN (brute force)
      7. If scanner user-agent → SCAN
      8. Default → RECON (safe assumption for unknown)
    """
    raw_lower = raw_log.lower()

    # Collect all available context
    entity      = trigger.entity      if trigger else raw_log[:80]
    artifact    = trigger.artifact_path if trigger else ""
    http_method = (trigger.http_method or "").upper() if trigger else ""
    http_status = trigger.http_status if trigger else None
    verdict     = analysis.verdict    if analysis else None
    explanation = (analysis.explanation or "").lower() if analysis else ""
    src_ip      = trigger.src_ip      if trigger else None

    evidence = {
        "raw_log":    raw_log[:200],
        "entity":     entity,
        "artifact":   artifact,
        "method":     http_method,
        "status":     http_status,
        "verdict":    verdict,
    }
    # Tool output hint from explanation (for obfuscation detection)
    tool_output_hint = explanation + " " + entity + " " + artifact

    log.debug(f"classify_stage: entity={entity} method={http_method} verdict={verdict}")

    # ── Priority 0: PHP obfuscation / bytecode detected ─────────────────────
    if artifact and artifact.endswith((".php", ".phtml", ".php3", ".php5")):
        if _check_patterns(tool_output_hint, _PHP_OBFUSCATION_PATTERNS if "_PHP_OBFUSCATION_PATTERNS" in dir() else []):
            log.info(f"  → UPLOAD (php_file_upload) obfuscated PHP detected")
            return "UPLOAD", "php_file_upload", evidence

    # ── Priority 1: BACKDOOR — webshell execution (cmd= in query) ────────────
    if _check_patterns(raw_log, _CMDINJECT_PATTERNS):
        # Further check: if verdict is MALICIOUS with system()/exec()
        if verdict == "MALICIOUS" and any(
            k in explanation for k in ["system(", "exec(", "shell", "command"]
        ):
            log.info(f"  → BACKDOOR (webshell_execution) verdict=MALICIOUS")
            return "BACKDOOR", "webshell_execution", evidence
        log.info(f"  → BACKDOOR (command_injection)")
        return "BACKDOOR", "command_injection", evidence

    # ── Priority 2: UPLOAD — file upload via POST ─────────────────────────────
    if http_method in ("POST", "PUT", "STOR"):
        if any(ext in entity.lower() for ext in [
            ".php", ".phtml", ".php3", ".asp", ".jsp",
            ".sh", ".py", ".pl", ".rb", ".exe", ".dll"
        ]):
            log.info(f"  → UPLOAD (php_file_upload)")
            return "UPLOAD", "php_file_upload", evidence
        if "upload" in entity.lower() or "file" in entity.lower():
            log.info(f"  → UPLOAD (binary_upload)")
            return "UPLOAD", "binary_upload", evidence
        # FTP STOR
        if http_method == "STOR":
            log.info(f"  → UPLOAD (ftp_stor)")
            return "UPLOAD", "ftp_stor", evidence

    # ── Priority 3: MALICIOUS verdict → BACKDOOR if webshell confirmed ────────
    if verdict == "MALICIOUS":
        if any(k in explanation for k in ["web shell", "system(", "exec(", "passthru", "base64"]):
            log.info(f"  → BACKDOOR (webshell_execution) confirmed by forensics")
            return "BACKDOOR", "webshell_execution", evidence
        if any(k in explanation for k in ["c2", "beacon", "reverse shell", "inject"]):
            log.info(f"  → BACKDOOR (c2_beacon) confirmed by forensics")
            return "BACKDOOR", "c2_beacon", evidence
        if any(k in explanation for k in ["polyglot", "image", "png", "jpg"]):
            log.info(f"  → UPLOAD (php_file_upload) polyglot confirmed")
            return "UPLOAD", "php_file_upload", evidence

    # ── Priority 4: EXFIL — sensitive data access ─────────────────────────────
    if _check_patterns(entity + artifact, _EXFIL_PATHS):
        log.info(f"  → EXFIL (credential_file_access)")
        return "EXFIL", "credential_file_access", evidence

    # ── Priority 5: PERSIST — persistence paths ───────────────────────────────
    if _check_patterns(entity + artifact, _PERSIST_PATHS):
        log.info(f"  → PERSIST (registry_run_key)")
        return "PERSIST", "registry_run_key", evidence

    # ── Priority 6: EXPLOIT — SQL injection ──────────────────────────────────
    if _check_patterns(raw_log, _SQLI_PATTERNS):
        log.info(f"  → EXPLOIT (sql_injection)")
        return "EXPLOIT", "sql_injection", evidence

    # ── Priority 7: SCAN — brute force (repeated 401/403) ─────────────────────
    if http_status in (401, 403):
        log.info(f"  → SCAN (login_bruteforce) status={http_status}")
        return "SCAN", "login_bruteforce", evidence

    # ── Priority 8: SCAN — scanner user-agent ────────────────────────────────
    if _check_patterns(raw_log, _SCAN_PATTERNS):
        log.info(f"  → SCAN (directory_bruteforce)")
        return "SCAN", "directory_bruteforce", evidence

    # ── Priority 9: RECON — sensitive file probe (HTTP 200) ──────────────────
    if _check_patterns(entity + artifact, _RECON_PATHS):
        log.info(f"  → RECON (sensitive_file_probe)")
        return "RECON", "sensitive_file_probe", evidence

    # ── Priority 10: RECON — directory listing / 403 on upload dir ───────────
    if http_status == 403 and any(k in entity.lower() for k in ["upload", "admin", "backup"]):
        log.info(f"  → RECON (directory_listing)")
        return "RECON", "directory_listing", evidence

    # ── Default: RECON ────────────────────────────────────────────────────────
    log.debug(f"  → RECON (default — no specific vector matched)")
    return "RECON", "version_probe", evidence


def classify_ip_threat(ip_history: list) -> str:
    """
    Given a list of stages this IP has gone through,
    return a threat assessment string.
    """
    if not ip_history:
        return "No activity"

    stage_set = set(ip_history)
    max_idx   = max(
        STAGE_PROGRESSION.index(s)
        for s in ip_history
        if s in STAGE_PROGRESSION
    )
    max_stage = STAGE_PROGRESSION[max_idx]

    if "BACKDOOR" in stage_set or "PERSIST" in stage_set:
        return f"COMPROMISED — attacker has persistent access (reached {max_stage})"
    elif "EXFIL" in stage_set:
        return f"DATA BREACH — exfiltration attempted (reached {max_stage})"
    elif "UPLOAD" in stage_set:
        return f"ACTIVE ATTACK — malicious upload detected (reached {max_stage})"
    elif "EXPLOIT" in stage_set:
        return f"EXPLOITATION — active exploit attempts (reached {max_stage})"
    elif "SCAN" in stage_set:
        return f"SCANNING — vulnerability probing active (reached {max_stage})"
    else:
        return f"RECONNAISSANCE — information gathering (reached {max_stage})"