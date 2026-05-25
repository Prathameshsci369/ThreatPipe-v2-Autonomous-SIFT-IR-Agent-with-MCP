"""
ThreatPipe v2 — Trigger Parser
================================
Raw log string → StructuredTrigger.
NO LLM. Pure regex + rule-based parsing.
Fast, deterministic, zero API cost.

Supported log formats:
  1. Apache / Nginx combined web log
     192.168.1.1 - - [16/Apr/2026:03:14:25 +0000] "POST /upload.php HTTP/1.1" 200 432
  2. Apache / Nginx short (no timezone offset)
     192.168.1.1 - - [16/Apr/2026:03:14:25] "GET /shell.php?cmd=id HTTP/1.1" 200
  3. MFT timeline entry  (log2timeline / mactime output)
     2026-04-16T03:14:25Z  MACB  /var/www/html/shell.php
  4. Registry event (Windows-style)
     [REGISTRY] HKLM\Software\Microsoft\Windows\CurrentVersion\Run  shell  REG_SZ  C:\shell.exe
  5. Memory anomaly (volatility-style)
     [MEMORY] PID=1337 process=svchost.exe malfind=YES injected_region=0x7ff00000
  6. Zeek/Bro FTP log (tab-separated)
     1331903558.95  CotBpL  192.168.202.96  40138  192.168.28.101  21  ftp  -  RETR  svchost.exe
  7. ProFTPD / vsftpd syslog
     May 17 08:59:01 server proftpd[1234]: 192.168.1.55 - STOR /uploads/shell.php
  8. SSH brute force (auth.log style)
     May 17 03:14:22 server sshd[1234]: Failed password for root from 192.168.1.55 port 4444 ssh2
  9. SQL injection (app log style)
     [SQLI] 192.168.1.55 GET /search?q=1'+OR+'1'='1 HTTP/1.1 500

Artifact type mapping:
  .php, .phtml, .php3  → php_file
  .py, .sh, .pl, .rb   → script
  .jpg, .jpeg, .png,
  .gif, .bmp, .webp    → image
  .exe, .dll, .so,
  .elf, .bin           → binary
  HKLM\..., HKCU\...  → registry_key
  PID=...              → memory_region
  .log                 → log_file
  anything else        → unknown
"""

import re
from datetime import datetime, timezone
from typing import Optional

from logger import get_logger, log_trigger, log_exception
from schemas import StructuredTrigger

log = get_logger(__name__)

# ─── Regex patterns ───────────────────────────────────────────────────────────

# Apache/Nginx combined log
_RE_WEBLOG = re.compile(
    r'(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'   # source IP
    r'\s+-\s+-\s+'
    r'\[(?P<ts>[^\]]+)\]'                      # [timestamp]
    r'\s+"(?P<method>[A-Z]+)'                  # "METHOD
    r'\s+(?P<path>[^\s"]+)'                    # /path/to/file?qs
    r'\s+HTTP/[\d.]+"'                         # HTTP/1.1"
    r'\s+(?P<status>\d{3})',                   # status code
    re.IGNORECASE,
)

# MFT / mactime / log2timeline line
_RE_MFT = re.compile(
    r'(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:\d{2})?)'
    r'.*?(?P<path>/[^\s]+)',
    re.IGNORECASE,
)

# Windows registry event
_RE_REGISTRY = re.compile(
    r'\[REGISTRY\]\s+'
    r'(?P<key>HK[A-Z_]+\\[^\s]+)'
    r'(?:\s+(?P<name>[^\s]+))?'
    r'(?:\s+REG_[A-Z]+\s+(?P<value>.+))?',
    re.IGNORECASE,
)

# Volatility memory anomaly
_RE_MEMORY = re.compile(
    r'\[MEMORY\]\s+'
    r'PID=(?P<pid>\d+)'
    r'\s+process=(?P<process>[^\s]+)'
    r'(?:\s+malfind=(?P<malfind>[A-Z]+))?'
    r'(?:\s+injected_region=(?P<region>0x[0-9a-fA-F]+))?'
    r'(?:\s+dump=(?P<dump>[^\s]+))?',
    re.IGNORECASE,
)

# ─── Zeek/Bro FTP log (tab-separated TSV) ───────────────────────────────────
# Format: ts  uid  src_ip  src_port  dst_ip  dst_port  proto  username  command  arg  ...
_RE_ZEEK_FTP = re.compile(
    r'^(?P<ts>\d+\.\d+)'                         # unix timestamp
    r'	(?P<uid>[^	]+)'                          # connection uid
    r'	(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'    # src IP
    r'	(?P<src_port>\d+)'                        # src port
    r'	(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})'    # dst IP
    r'	(?P<dst_port>\d+)'                        # dst port (21=FTP)
    r'(?:	[^	]*){0,2}'                          # skip 0-2 optional fields
    r'	(?P<command>[A-Z]+)'                      # FTP command: RETR STOR DELE PORT etc
    r'	(?P<arg>[^	]*)',                          # argument (filename, path, etc.)
    re.IGNORECASE,
)

# ProFTPD / vsftpd syslog format
# May 17 08:59:01 server proftpd[1234]: 192.168.1.55 - STOR /uploads/shell.php
_RE_PROFTPD = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
    r'\s+\S+\s+(?:proftpd|vsftpd)\[\d+\]:\s+'
    r'(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+-\s+(?P<command>[A-Z]+)'
    r'\s+(?P<arg>\S+)',
    re.IGNORECASE,
)

# SSH brute force — auth.log / secure log
# Failed password for root from 192.168.1.55 port 4444 ssh2
# Accepted password for user from 192.168.1.55 port 4444 ssh2
_RE_SSH = re.compile(
    r'(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)'
    r'\s+\S+\s+sshd\[\d+\]:\s+'
    r'(?P<result>Failed|Accepted|Invalid)\s+\w+\s+for\s+(?P<user>\S+)'
    r'\s+from\s+(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'\s+port\s+(?P<port>\d+)',
    re.IGNORECASE,
)

# SQL injection attempt — app log or WAF log
# Works with URL-encoded, space-encoded (+), and quoted payloads
_RE_SQLI = re.compile(
    r'(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})'
    r'.*?(?P<payload>'
    r'(?:union[\s+]select'
    r'|or[\s+]1[\s]*=[\s]*1'
    r'|and[\s+]1[\s]*=[\s]*1'
    r'|drop[\s+]table'
    r'|insert[\s+]into'
    r'|sleep[\s]*\('
    r'|benchmark[\s]*\('
    r'|load_file[\s]*\('
    r'|into[\s+]outfile'
    r"|'[\s]*or[\s]*'"
    r'|;[\s]*--'
    r'|--[\s]*$))',
    re.IGNORECASE,
)

# Web timestamp formats
_TS_FORMATS = [
    "%d/%b/%Y:%H:%M:%S %z",    # 16/Apr/2026:03:14:25 +0000
    "%d/%b/%Y:%H:%M:%S",       # 16/Apr/2026:03:14:25
    "%Y-%m-%dT%H:%M:%SZ",      # 2026-04-16T03:14:25Z
    "%Y-%m-%dT%H:%M:%S%z",     # 2026-04-16T03:14:25+00:00
]

# ─── Artifact type detector ───────────────────────────────────────────────────

_EXT_MAP = {
    ".php": "php_file", ".phtml": "php_file", ".php3": "php_file",
    ".php4": "php_file", ".php5": "php_file", ".php7": "php_file",
    ".py": "script", ".sh": "script", ".pl": "script",
    ".rb": "script", ".js": "script", ".ts": "script",
    ".ps1": "script", ".bat": "script", ".cmd": "script",
    ".jpg": "image", ".jpeg": "image", ".png": "image",
    ".gif": "image", ".bmp": "image", ".webp": "image",
    ".svg": "image", ".ico": "image",
    ".exe": "binary", ".dll": "binary", ".so": "binary",
    ".elf": "binary", ".bin": "binary", ".msi": "binary",
    ".log": "log_file", ".txt": "log_file",
}


def _detect_artifact_type(path: str) -> str:
    """Return artifact type string from file path / URI."""
    clean = path.split("?")[0].split("#")[0].lower().rstrip("/")
    dot = clean.rfind(".")
    if dot != -1:
        ext = clean[dot:]
        if ext in _EXT_MAP:
            log.debug(f"  artifact_type by extension: '{ext}' → '{_EXT_MAP[ext]}'")
            return _EXT_MAP[ext]
    log.debug(f"  artifact_type: unknown  (no matching ext for '{clean}')")
    return "unknown"


def _parse_timestamp(ts_raw: str) -> Optional[datetime]:
    """Try multiple timestamp formats, return UTC datetime or None."""
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(ts_raw.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    log.warning(f"  Could not parse timestamp: '{ts_raw}'")
    return None


def _build_artifact_path(uri_path: str, web_root: str = None) -> str:
    """Map a web URI like /uploads/shell.php to a filesystem path."""
    from config import get_web_root
    root = web_root or get_web_root()
    clean_uri = uri_path.split("?")[0].split("#")[0]
    fs_path = root.rstrip("/") + "/" + clean_uri.lstrip("/")
    log.debug(f"  artifact_path: URI='{clean_uri}' → FS='{fs_path}'")
    return fs_path


# ─── Per-format parsers ───────────────────────────────────────────────────────

def _parse_web_log(raw: str) -> Optional[StructuredTrigger]:
    m = _RE_WEBLOG.search(raw)
    if not m:
        return None

    src_ip    = m.group("src_ip")
    ts_raw    = m.group("ts")
    method    = m.group("method").upper()
    full_path = m.group("path")
    status    = int(m.group("status"))
    uri_path  = full_path.split("?")[0]
    query     = full_path[len(uri_path):]

    ts_dt     = _parse_timestamp(ts_raw)
    art_type  = _detect_artifact_type(uri_path)
    art_path  = _build_artifact_path(uri_path)

    ts_str = ts_dt.strftime("%H:%M:%S UTC") if ts_dt else ts_raw
    claim = (
        f"File '{uri_path}' was accessed via {method} "
        f"from {src_ip} at {ts_str} "
        f"(HTTP {status})"
    )
    if query:
        claim += f" with query '{query}'"

    log.debug(f"  [web_log] method={method} uri={uri_path} "
              f"status={status} src_ip={src_ip} ts={ts_raw}")

    return StructuredTrigger(
        trigger_type  = "web_log",
        entity        = uri_path,
        src_ip        = src_ip,
        timestamp_raw = ts_raw,
        timestamp_dt  = ts_dt,
        http_method   = method,
        http_status   = status,
        claim         = claim,
        artifact_path = art_path,
        artifact_type = art_type,
        raw_log       = raw,
    )


def _parse_mft(raw: str) -> Optional[StructuredTrigger]:
    m = _RE_MFT.search(raw)
    if not m:
        return None

    ts_raw   = m.group("ts")
    fs_path  = m.group("path")
    ts_dt    = _parse_timestamp(ts_raw)
    art_type = _detect_artifact_type(fs_path)
    ts_str   = ts_dt.strftime("%H:%M:%S UTC") if ts_dt else ts_raw

    claim = f"Filesystem activity on '{fs_path}' recorded at {ts_str} in MFT timeline"

    log.debug(f"  [mft] path={fs_path} ts={ts_raw}")

    return StructuredTrigger(
        trigger_type  = "mft_entry",
        entity        = fs_path,
        timestamp_raw = ts_raw,
        timestamp_dt  = ts_dt,
        claim         = claim,
        artifact_path = fs_path,
        artifact_type = art_type,
        raw_log       = raw,
    )


def _parse_registry(raw: str) -> Optional[StructuredTrigger]:
    m = _RE_REGISTRY.search(raw)
    if not m:
        return None

    key   = m.group("key")
    name  = m.group("name") or ""
    value = m.group("value") or ""

    claim = f"Registry key '{key}' was written"
    if name:
        claim += f" (value name: '{name}')"
    if value:
        claim += f" → '{value.strip()}'"

    log.debug(f"  [registry] key={key} name={name}")

    return StructuredTrigger(
        trigger_type  = "registry_event",
        entity        = key,
        claim         = claim,
        artifact_path = key,
        artifact_type = "registry_key",
        raw_log       = raw,
    )


def _parse_memory(raw: str) -> Optional[StructuredTrigger]:
    m = _RE_MEMORY.search(raw)
    if not m:
        return None

    pid     = m.group("pid")
    process = m.group("process")
    malfind = m.group("malfind") or "UNKNOWN"
    region  = m.group("region") or "unknown"

    dump   = m.group("dump") or ""
    entity = f"PID:{pid}:{process}"
    claim  = (
        f"Process '{process}' (PID {pid}) flagged by malfind={malfind} "
        f"at memory region {region}"
    )
    # If a dump file path is provided, use it as artifact_path so
    # strings/file tools can run on it directly (vol.py not required)
    artifact_path = dump if dump else f"PID:{pid}"

    log.debug(f"  [memory] pid={pid} process={process} malfind={malfind} dump={dump or 'none'}")

    return StructuredTrigger(
        trigger_type  = "memory_anomaly",
        entity        = entity,
        claim         = claim,
        artifact_path = artifact_path,
        artifact_type = "memory_region",
        raw_log       = raw,
    )


def _parse_zeek_ftp(raw: str) -> Optional[StructuredTrigger]:
    """Parse Zeek/Bro FTP log line (tab-separated)."""
    if '	' not in raw:
        return None
    m = _RE_ZEEK_FTP.search(raw)
    if not m:
        return None

    src_ip  = m.group("src_ip")
    command = m.group("command").upper()
    arg     = m.group("arg").strip() or ""
    ts_raw  = m.group("ts")

    # Convert unix timestamp to datetime
    try:
        ts_dt = datetime.fromtimestamp(float(ts_raw), tz=timezone.utc)
        ts_str = ts_dt.strftime("%H:%M:%S UTC")
    except Exception:
        ts_dt, ts_str = None, ts_raw

    art_type = _detect_artifact_type(arg) if arg else "unknown"

    # Suspicious FTP commands
    suspicious_cmds = {"STOR", "RETR", "DELE", "RNTO", "SITE", "PORT", "EPRT"}
    severity = "HIGH" if command in suspicious_cmds else "LOW"

    claim = (
        f"FTP {command} from {src_ip} at {ts_str}"
        + (f" — file: '{arg}'" if arg else "")
    )

    log.debug(f"  [zeek_ftp] cmd={command} src={src_ip} arg={arg} sev={severity}")

    return StructuredTrigger(
        trigger_type  = "web_log",    # reuse web_log — agent handles it same way
        entity        = arg or f"FTP:{command}",
        src_ip        = src_ip,
        timestamp_raw = ts_raw,
        timestamp_dt  = ts_dt,
        http_method   = command,      # reuse http_method field for FTP command
        http_status   = None,
        claim         = claim,
        #artifact_path = arg,
        artifact_path = _build_artifact_path(arg),
        artifact_type = art_type,
        raw_log       = raw,
    )


def _parse_proftpd(raw: str) -> Optional[StructuredTrigger]:
    """Parse ProFTPD / vsftpd syslog format."""
    m = _RE_PROFTPD.search(raw)
    if not m:
        return None

    src_ip  = m.group("src_ip")
    command = m.group("command").upper()
    arg     = m.group("arg").strip()
    ts_raw  = f"{m.group('month')} {m.group('day')} {m.group('time')}"
    art_type = _detect_artifact_type(arg)

    claim = f"FTP {command} from {src_ip} at {ts_raw} — file: '{arg}'"
    log.debug(f"  [proftpd] cmd={command} src={src_ip} arg={arg}")

    return StructuredTrigger(
        trigger_type  = "web_log",
        entity        = arg or f"FTP:{command}",
        src_ip        = src_ip,
        timestamp_raw = ts_raw,
        http_method   = command,
        claim         = claim,
        #artifact_path = arg,
        artifact_path = _build_artifact_path(arg),
        artifact_type = art_type,
        raw_log       = raw,
    )


def _parse_ssh(raw: str) -> Optional[StructuredTrigger]:
    """Parse SSH auth.log brute force / login events."""
    m = _RE_SSH.search(raw)
    if not m:
        return None

    result  = m.group("result").upper()   # FAILED / ACCEPTED / INVALID
    user    = m.group("user")
    src_ip  = m.group("src_ip")
    port    = m.group("port")
    ts_raw  = f"{m.group('month')} {m.group('day')} {m.group('time')}"

    claim = (
        f"SSH {result} login for user '{user}' "
        f"from {src_ip}:{port} at {ts_raw}"
    )

    # ACCEPTED = successful login (higher severity)
    art_type = "unknown"
    log.debug(f"  [ssh] result={result} user={user} src={src_ip}")

    return StructuredTrigger(
        trigger_type  = "web_log",
        entity        = f"SSH:{user}@{src_ip}",
        src_ip        = src_ip,
        timestamp_raw = ts_raw,
        http_method   = f"SSH_{result}",
        http_status   = 200 if result == "ACCEPTED" else 401,
        claim         = claim,
        artifact_path = f"/home/{user}/.ssh",
        artifact_type = art_type,
        raw_log       = raw,
    )


def _parse_sqli(raw: str) -> Optional[StructuredTrigger]:
    """Parse SQL injection attempt from app/WAF logs."""
    m = _RE_SQLI.search(raw)
    if not m:
        return None

    src_ip  = m.group("src_ip")
    payload = m.group("payload")

    # Try to extract URI from the line
    uri_match = re.search(r'"(?:GET|POST|PUT)\s+(/[^\s"]*)', raw, re.IGNORECASE)
    uri = uri_match.group(1) if uri_match else "/unknown"
    art_type = _detect_artifact_type(uri)

    # Status code
    status_match = re.search(r'\s(\d{3})\s*$', raw)
    status = int(status_match.group(1)) if status_match else None

    claim = (
        f"SQL injection attempt from {src_ip} "
        f"on '{uri}' — payload: '{payload[:60]}'"
    )
    log.debug(f"  [sqli] src={src_ip} uri={uri} payload={payload[:40]}")

    return StructuredTrigger(
        trigger_type  = "web_log",
        entity        = uri,
        src_ip        = src_ip,
        http_status   = status,
        claim         = claim,
        artifact_path = _build_artifact_path(uri),
        artifact_type = art_type,
        raw_log       = raw,
    )


# ─── Public API ───────────────────────────────────────────────────────────────

def parse_trigger(raw_log: str) -> StructuredTrigger:
    """
    Main entry point.
    Tries each parser in priority order.
    Falls back to 'unknown' trigger if nothing matches.
    Logs everything.
    """
    log.info(f"PARSING trigger: '{raw_log[:120]}{'...' if len(raw_log) > 120 else ''}'")

    raw_log = raw_log.strip()

    parsers = [
        ("web_log",  _parse_web_log),
        ("mft",      _parse_mft),
        ("registry", _parse_registry),
        ("memory",   _parse_memory),
        ("zeek_ftp", _parse_zeek_ftp),   # Zeek/Bro TSV FTP logs
        ("proftpd",  _parse_proftpd),    # ProFTPD / vsftpd syslog
        ("ssh",      _parse_ssh),        # SSH auth.log brute force
        ("sqli",     _parse_sqli),       # SQL injection WAF/app logs
    ]

    for name, parser_fn in parsers:
        log.debug(f"  trying parser: {name}")
        try:
            result = parser_fn(raw_log)
            if result is not None:
                log.info(f"  ✓ matched parser: {name}")
                log_trigger(log, raw_log, {
                    "trigger_type":  result.trigger_type,
                    "entity":        result.entity,
                    "src_ip":        result.src_ip,
                    "timestamp_raw": result.timestamp_raw,
                    "timestamp_dt":  str(result.timestamp_dt),
                    "http_method":   result.http_method,
                    "http_status":   result.http_status,
                    "artifact_path": result.artifact_path,
                    "artifact_type": result.artifact_type,
                    "claim":         result.claim,
                })
                return result
        except Exception as exc:
            log_exception(log, f"trigger_parser.{name}", exc)
            continue

    # Nothing matched
    log.warning(f"  ✗ no parser matched — returning unknown trigger")
    fallback = StructuredTrigger(
        trigger_type  = "unknown",
        entity        = raw_log[:80],
        claim         = f"Unknown event: '{raw_log[:80]}'",
        artifact_path = "",
        artifact_type = "unknown",
        raw_log       = raw_log,
    )
    log_trigger(log, raw_log, {"trigger_type": "unknown", "entity": raw_log[:80]})
    return fallback