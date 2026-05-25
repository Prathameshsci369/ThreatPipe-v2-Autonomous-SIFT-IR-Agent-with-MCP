"""
ThreatPipe v2 — Tool Selector
================================
artifact_type + trigger_type → which SIFT tool to run + exact arguments.
NO LLM. Pure deterministic rule map.

Each artifact type has:
  - primary_tool   : first choice (cycle=0)
  - fallback_tools : if primary fails or returns empty (cycle=1,2)
  - args_template  : argument list with {artifact_path} placeholder

Tool selection priority:
  1. artifact_type (most specific)
  2. trigger_type  (broad category fallback)
  3. hardcoded default → "strings" (always available on SIFT)

Supported mappings:
  php_file      → strings, file, md5sum
  image         → file, strings, md5sum
  binary        → file, strings, sha256sum
  script        → strings, file
  log_file      → grep (pattern search), strings
  registry_key  → strings (on exported hive dump)
  memory_region → volatility malfind (special case)
  unknown       → strings, file
"""

from dataclasses import dataclass, field
from typing import List

from logger import get_logger
from config import get_tool_path
from schemas import StructuredTrigger

log = get_logger(__name__)


# ─── Tool plan dataclass ──────────────────────────────────────────────────────

@dataclass
class ToolSelection:
    """Returned by select_tool(). agent.py uses this to build subprocess call."""
    tool_name:  str
    tool_path:  str
    args:       List[str]
    rationale:  str
    hypothesis: str
    category:   str = "generic"
    fallbacks:  List["ToolSelection"] = field(default_factory=list)


# ─── Rule table ───────────────────────────────────────────────────────────────

_RULES = {

    "php_file": [
        {
            "tool":      "strings",
            "args":      ["-n", "6", "{artifact_path}"],
            "rationale": "Dump printable strings — reveals system(), exec(), base64_decode(), eval(), preg_replace /e modifier",
            "hypothesis":"PHP web shell — expect execution functions, base64 blobs, or obfuscated payloads",
            "category":  "static_analysis",
        },
        {
            "tool":      "grep",
            "args":      ["-aiE",
                          "eval\(|base64_decode\(|system\(|exec\(|shell_exec\(|passthru\(|popen\(|assert\(|str_rot13|gzinflate|gzuncompress|_REQUEST|_COOKIE|chr\(",
                          "{artifact_path}"],
            "rationale": "Grep for PHP obfuscation: eval/base64/rot13/gzip encoding, superglobal abuse",
            "hypothesis":"Obfuscated PHP shell — encoded payload, eval-based execution chain",
            "category":  "php_obfuscation",
        },
        {
            "tool":      "file",
            "args":      ["{artifact_path}"],
            "rationale": "Verify MIME type — image masquerading as PHP shows wrong magic bytes",
            "hypothesis":"Verify file is actually PHP/ASCII text, not a disguised binary",
            "category":  "file_identification",
        },
        {
            "tool":      "sha256sum",
            "args":      ["{artifact_path}"],
            "rationale": "SHA256 for VirusTotal/MISP IOC correlation",
            "hypothesis":"Unique hash for external threat intel lookup",
            "category":  "hashing",
        },
    ],

    "image": [
        {
            "tool":      "file",
            "args":      ["{artifact_path}"],
            "rationale": "Check magic bytes — PHP hidden in image will not show image/jpeg",
            "hypothesis":"Valid image magic bytes expected — mismatch = suspicious",
            "category":  "file_identification",
        },
        {
            "tool":      "strings",
            "args":      ["-n", "6", "{artifact_path}"],
            "rationale": "Strings on image — <?php or JS in image binary = polyglot attack",
            "hypothesis":"Image should have no executable strings — presence = MALICIOUS",
            "category":  "static_analysis",
        },
        {
            "tool":      "md5sum",
            "args":      ["{artifact_path}"],
            "rationale": "Hash for IOC correlation",
            "hypothesis":"Unique hash for threat intel lookup",
            "category":  "hashing",
        },
    ],

    "binary": [
        {
            "tool":      "file",
            "args":      ["{artifact_path}"],
            "rationale": "Identify ELF/PE/Mach-O type, packed or not",
            "hypothesis":"Legitimate binary vs packed malware",
            "category":  "file_identification",
        },
        {
            "tool":      "strings",
            "args":      ["-n", "8", "{artifact_path}"],
            "rationale": "Extract long strings — C2 domains, IPs, suspicious API names",
            "hypothesis":"Malware strings: /bin/sh, wget, curl, base64 encoded payloads",
            "category":  "static_analysis",
        },
        {
            "tool":      "sha256sum",
            "args":      ["{artifact_path}"],
            "rationale": "SHA256 for VirusTotal / MISP correlation",
            "hypothesis":"Hash for external threat intel",
            "category":  "hashing",
        },
    ],

    "script": [
        {
            "tool":      "strings",
            "args":      ["-n", "6", "{artifact_path}"],
            "rationale": "Scripts are text — strings reveals full readable content",
            "hypothesis":"Reverse shell, cron persistence, or data exfil commands",
            "category":  "static_analysis",
        },
        {
            "tool":      "file",
            "args":      ["{artifact_path}"],
            "rationale": "Confirm interpreter line (python3, bash, perl)",
            "hypothesis":"Confirm actual script type matches extension",
            "category":  "file_identification",
        },
    ],

    "log_file": [
        {
            "tool":      "grep",
            "args":      ["-iE",
                          "error|fail|denied|unauthorized|inject|union|select|exec|cmd=|wget|curl",
                          "{artifact_path}"],
            "rationale": "Grep for attack keywords in log file",
            "hypothesis":"Log file contains evidence of SQLi, RCE, or recon activity",
            "category":  "log_analysis",
        },
        {
            "tool":      "strings",
            "args":      ["-n", "6", "{artifact_path}"],
            "rationale": "Fallback: full string dump of log",
            "hypothesis":"Any printable content from the log file",
            "category":  "static_analysis",
        },
    ],

    "registry_key": [
        {
            "tool":      "strings",
            "args":      ["-n", "6", "{artifact_path}"],
            "rationale": "Strings on exported registry hive dump",
            "hypothesis":"Persistence mechanism — autorun executable path",
            "category":  "static_analysis",
        },
    ],

    "memory_region": [
        {
            "tool":      "strings",
            "args":      ["-n", "8", "{artifact_path}"],
            "rationale": "Strings on memory dump region",
            "hypothesis":"Injected shellcode, C2 strings, or PE headers",
            "category":  "memory_analysis",
        },
    ],

    "unknown": [
        {
            "tool":      "strings",
            "args":      ["-n", "6", "{artifact_path}"],
            "rationale": "Default safe fallback — strings works on any file type",
            "hypothesis":"Unknown artifact — look for any suspicious printable strings",
            "category":  "static_analysis",
        },
        {
            "tool":      "file",
            "args":      ["{artifact_path}"],
            "rationale": "Identify file type by magic bytes",
            "hypothesis":"Determine actual file type for better tool selection",
            "category":  "file_identification",
        },
    ],

    # ── Filesystem artifacts — SIFT fls/icat/mactime ──────────────────────────
    "disk_image": [
        {
            "tool":      "mmls",
            "args":      ["{artifact_path}"],
            "rationale": "List partition table — identify filesystem layout for targeted icat extraction",
            "hypothesis":"Disk image contains hidden/deleted partitions or evidence of wiping",
            "category":  "disk_forensics",
        },
        {
            "tool":      "fsstat",
            "args":      ["-o", "2048", "{artifact_path}"],
            "rationale": "Filesystem stats — last mount time, volume label, deleted file count",
            "hypothesis":"Filesystem metadata reveals timeline of attacker activity",
            "category":  "disk_forensics",
        },
        {
            "tool":      "fls",
            "args":      ["-r", "-d", "-o", "2048", "{artifact_path}"],
            "rationale": "fls -r -d lists deleted files recursively — attacker cleanup artifacts",
            "hypothesis":"Deleted web shells, scripts, or logs left in filesystem",
            "category":  "disk_forensics",
        },
    ],

    "timeline": [
        {
            "tool":      "mactime",
            "args":      ["-b", "{artifact_path}", "-d"],
            "rationale": "mactime converts fls bodyfile to human-readable MAC timeline",
            "hypothesis":"Timeline reveals attacker activity windows — file creation/modification spikes",
            "category":  "timeline_analysis",
        },
        {
            "tool":      "grep",
            "args":      ["-iE", "\.php|\.sh|\.py|\.jsp|\.asp", "{artifact_path}"],
            "rationale": "Filter timeline for script file events only",
            "hypothesis":"Script files created/modified during attack window",
            "category":  "timeline_analysis",
        },
    ],

    # ── Network capture artifacts ─────────────────────────────────────────────
    "pcap": [
        {
            "tool":      "strings",
            "args":      ["-n", "8", "{artifact_path}"],
            "rationale": "Extract readable strings from PCAP — HTTP payloads, C2 URIs, credentials",
            "hypothesis":"Network capture contains attack payloads or C2 communication",
            "category":  "network_forensics",
        },
        {
            "tool":      "grep",
            "args":      ["-aiE",
                          "cmd=|exec=|shell=|passwd|shadow|\.php|\.exe|wget |curl |/bin/sh|/bin/bash",
                          "{artifact_path}"],
            "rationale": "Grep for HTTP attack patterns in PCAP strings output",
            "hypothesis":"Attack traffic embedded in PCAP — web shell commands, file downloads",
            "category":  "network_forensics",
        },
    ],
}


# ─── Builder ──────────────────────────────────────────────────────────────────

def _build_selection(rule: dict, artifact_path: str) -> ToolSelection:
    """Resolve {artifact_path} placeholder and return ToolSelection."""
    tool_name = rule["tool"]
    tool_path = get_tool_path(tool_name)
    resolved_args = [
        a.replace("{artifact_path}", artifact_path)
        for a in rule["args"]
    ]
    log.debug(
        f"  built: {tool_name} {' '.join(resolved_args)}  [{rule['category']}]"
    )
    return ToolSelection(
        tool_name  = tool_name,
        tool_path  = tool_path,
        args       = resolved_args,
        rationale  = rule["rationale"],
        hypothesis = rule["hypothesis"],
        category   = rule["category"],
    )


def _build_volatility_selection(trigger: StructuredTrigger) -> ToolSelection:
    """Special case: memory_anomaly → volatility malfind."""
    pid = "unknown"
    if trigger.artifact_path.startswith("PID:"):
        parts = trigger.artifact_path.split(":")
        pid = parts[1] if len(parts) > 1 else "unknown"

    tool_name = get_tool_path("volatility")
    args = ["malfind", f"--pid={pid}", "--dump-dir=/tmp/vol_dump"]

    log.info(f"  special case: volatility malfind  pid={pid}")
    return ToolSelection(
        tool_name  = tool_name,
        tool_path  = tool_name,
        args       = args,
        rationale  = f"Volatility malfind on PID {pid} — dump injected memory regions",
        hypothesis = "Process has injected code — expect PE headers or shellcode in dump",
        category   = "memory_analysis",
    )


# ─── Public API ───────────────────────────────────────────────────────────────

def select_tool(trigger: StructuredTrigger, cycle: int = 0) -> ToolSelection:
    """
    Main entry point.

    cycle=0  → primary tool for this artifact type
    cycle=1  → first fallback
    cycle=2+ → last available rule

    Logs every decision with full rationale.
    """
    art_type  = trigger.artifact_type
    art_path  = trigger.artifact_path
    trig_type = trigger.trigger_type

    log.info(
        f"TOOL SELECTION  artifact_type={art_type}  "
        f"trigger_type={trig_type}  cycle={cycle}"
    )
    log.debug(f"  artifact_path : {art_path}")

    # Special case — memory anomaly → volatility
    if trig_type == "memory_anomaly":
        sel = _build_volatility_selection(trigger)
        log.info(f"  → {sel.tool_name}  [{sel.category}]")
        log.info(f"    rationale : {sel.rationale}")
        return sel

    # Lookup rule table
    rules = _RULES.get(art_type)
    if not rules:
        log.warning(
            f"  no rules for artifact_type='{art_type}' — "
            f"falling back to 'unknown' ruleset"
        )
        rules = _RULES["unknown"]

    # Pick by cycle
    idx = min(cycle, len(rules) - 1)
    if cycle >= len(rules):
        log.warning(
            f"  cycle={cycle} exceeds rule count ({len(rules)}) "
            f"— clamping to idx={idx}"
        )

    chosen = rules[idx]
    primary = _build_selection(chosen, art_path)

    # Build fallbacks = all other rules except chosen
    fallbacks = []
    for i, r in enumerate(rules):
        if i != idx:
            fallbacks.append(_build_selection(r, art_path))
    primary.fallbacks = fallbacks

    log.info(f"  → {primary.tool_name}  [{primary.category}]")
    log.info(f"    rationale : {primary.rationale}")
    log.info(f"    hypothesis: {primary.hypothesis}")
    log.debug(f"    fallbacks : {[f.tool_name for f in fallbacks]}")

    return primary


def select_all_tools(trigger: StructuredTrigger) -> List[ToolSelection]:
    """Return ALL tool selections for this artifact type (full chain)."""
    art_type = trigger.artifact_type
    rules    = _RULES.get(art_type, _RULES["unknown"])
    selections = [_build_selection(r, trigger.artifact_path) for r in rules]
    log.info(
        f"ALL TOOLS for artifact_type={art_type}: "
        f"{[s.tool_name for s in selections]}"
    )
    return selections