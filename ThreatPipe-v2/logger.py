"""
ThreatPipe v2 — Logger
======================
Har ek step, tool call, LLM output, error, network info — sab kuch
log file madhe save hota. Console la color-coded short version disto,
file la full raw dump hota.

Log file location : ./logs/threatpipe_<timestamp>.log
Log level         : DEBUG (everything)
Format (file)     : timestamp | level | module | line | message
Format (console)  : level | module | message  (color coded)
"""

import logging
import os
import sys
import json
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any

# ─── Directories ──────────────────────────────────────────────────────────────
LOG_DIR = Path("./logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

# One log file per run — timestamp in filename so old runs don't overwrite
_RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
LOG_FILE = LOG_DIR / f"threatpipe_{_RUN_TIMESTAMP}.log"

# ─── ANSI colors for console ──────────────────────────────────────────────────
class _Colors:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    DIM     = "\033[2m"
    BLUE    = "\033[94m"

# ─── Custom formatters ────────────────────────────────────────────────────────
class _FileFormatter(logging.Formatter):
    """Full detail formatter for log file — nothing is hidden."""

    FMT = (
        "%(asctime)s.%(msecs)03d"
        " | %(levelname)-8s"
        " | %(name)-25s"
        " | L%(lineno)-4d"
        " | %(message)s"
    )

    def __init__(self):
        super().__init__(fmt=self.FMT, datefmt="%Y-%m-%d %H:%M:%S")

    def formatException(self, exc_info):
        # Full traceback in file
        return "".join(traceback.format_exception(*exc_info))


class _ConsoleFormatter(logging.Formatter):
    """Color-coded short formatter for terminal."""

    LEVEL_COLORS = {
        logging.DEBUG:    _Colors.DIM    + "DBG",
        logging.INFO:     _Colors.CYAN   + "INF",
        logging.WARNING:  _Colors.YELLOW + "WRN",
        logging.ERROR:    _Colors.RED    + "ERR",
        logging.CRITICAL: _Colors.RED    + _Colors.BOLD + "CRT",
    }

    FMT = "{color} | {name:<20} | {msg}{reset}"

    def format(self, record: logging.LogRecord) -> str:
        color_prefix = self.LEVEL_COLORS.get(record.levelno, "???")
        name = record.name.split(".")[-1]  # show only leaf module name
        msg  = record.getMessage()
        line = self.FMT.format(
            color=color_prefix,
            name=name,
            msg=msg,
            reset=_Colors.RESET,
        )
        if record.exc_info:
            # Short one-liner on console, full detail in file
            exc_type = record.exc_info[0]
            exc_val  = record.exc_info[1]
            line += f"\n  {_Colors.RED}↳ {exc_type.__name__}: {exc_val}{_Colors.RESET}"
        return line


# ─── Root logger setup ────────────────────────────────────────────────────────
def _setup_root_logger() -> logging.Logger:
    root = logging.getLogger("threatpipe")
    root.setLevel(logging.DEBUG)   # capture EVERYTHING

    # Prevent duplicate handlers if module is re-imported
    if root.handlers:
        return root

    # ── File handler — DEBUG and above, full detail ──
    fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(_FileFormatter())
    root.addHandler(fh)

    # ── Console handler — INFO and above, color coded ──
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(_ConsoleFormatter())
    root.addHandler(ch)

    # Write a clear separator at the start of each run
    root.info("=" * 70)
    root.info(f"ThreatPipe v2 — Session started  [{_RUN_TIMESTAMP}]")
    root.info(f"Log file → {LOG_FILE.resolve()}")
    root.info("=" * 70)

    return root


_root_logger = _setup_root_logger()


# ─── Public API ───────────────────────────────────────────────────────────────
def get_logger(name: str) -> logging.Logger:
    """
    Call this in every module:

        from logger import get_logger
        log = get_logger(__name__)
    """
    return logging.getLogger(f"threatpipe.{name}")


# ─── Structured event loggers ─────────────────────────────────────────────────
# These write nicely formatted blocks so you can grep specific event types.

_SECTION = "─" * 60

def log_stage(logger: logging.Logger, stage_num: int, stage_name: str, details: dict = None):
    """Log a pipeline stage transition — always visible in file."""
    logger.info(_SECTION)
    logger.info(f"STAGE {stage_num} ▶  {stage_name.upper()}")
    if details:
        for k, v in details.items():
            logger.info(f"  {k:<20} : {v}")
    logger.info(_SECTION)


def log_trigger(logger: logging.Logger, raw_log: str, parsed: dict):
    """Log the raw HTTP/MFT/registry trigger and the parsed struct."""
    logger.debug("── TRIGGER RAW ──────────────────────────────────────────")
    logger.debug(f"  raw   : {raw_log}")
    logger.debug("── TRIGGER PARSED ───────────────────────────────────────")
    for k, v in parsed.items():
        logger.debug(f"  {k:<20} : {v}")
    logger.debug("─────────────────────────────────────────────────────────")


def log_tool_call(logger: logging.Logger, tool: str, args: list, cwd: str = None):
    """Log every subprocess call before it runs."""
    cmd_str = " ".join([tool] + args)
    logger.info(f"TOOL EXEC  ▶  {cmd_str}")
    logger.debug(f"  tool      : {tool}")
    logger.debug(f"  args      : {args}")
    logger.debug(f"  cwd       : {cwd or os.getcwd()}")


def log_tool_result(logger: logging.Logger, tool: str, returncode: int,
                    stdout: str, stderr: str, elapsed_ms: float):
    """Log the full stdout/stderr of every tool — messy is fine."""
    status = "OK" if returncode == 0 else f"EXIT {returncode}"
    logger.info(f"TOOL RESULT ◀  {tool}  [{status}]  {elapsed_ms:.1f}ms")

    # stdout — always to file, truncated on console
    if stdout:
        logger.debug("── STDOUT ───────────────────────────────────────────────")
        for line in stdout.splitlines():
            logger.debug(f"  {line}")
        logger.debug("────────────────────────────────────────────────────────")

    # stderr — always logged; may contain useful diagnostics
    if stderr:
        level = logging.WARNING if returncode != 0 else logging.DEBUG
        logger.log(level, "── STDERR ───────────────────────────────────────────────")
        for line in stderr.splitlines():
            logger.log(level, f"  {line}")
        logger.log(level, "────────────────────────────────────────────────────────")

    if not stdout and not stderr:
        logger.debug(f"  (no output from {tool})")


def log_llm_request(logger: logging.Logger, model: str, prompt_preview: str,
                    token_estimate: int = 0):
    """Log what we're sending to the LLM."""
    logger.debug("── LLM REQUEST ──────────────────────────────────────────")
    logger.debug(f"  model         : {model}")
    logger.debug(f"  token_estimate: {token_estimate}")
    logger.debug(f"  prompt_preview: {prompt_preview[:300]}{'...' if len(prompt_preview) > 300 else ''}")
    logger.debug("────────────────────────────────────────────────────────")


def log_llm_response(logger: logging.Logger, model: str, response_text: str,
                     input_tokens: int = 0, output_tokens: int = 0,
                     cost_usd: float = 0.0):
    """Log every LLM response — full text to file."""
    logger.info(
        f"LLM RESPONSE ◀  {model} "
        f"[in:{input_tokens} out:{output_tokens} cost:${cost_usd:.6f}]"
    )
    logger.debug("── LLM OUTPUT ───────────────────────────────────────────")
    for line in response_text.splitlines():
        logger.debug(f"  {line}")
    logger.debug("────────────────────────────────────────────────────────")


def log_graph_op(logger: logging.Logger, operation: str, node_id: str = None,
                 edge: tuple = None, attrs: dict = None):
    """Log every evidence graph read/write operation."""
    if node_id:
        logger.debug(f"GRAPH {operation:<8} node={node_id}  attrs={attrs or {}}")
    elif edge:
        src, dst = edge
        logger.debug(f"GRAPH {operation:<8} edge={src}→{dst}  attrs={attrs or {}}")
    else:
        logger.debug(f"GRAPH {operation}")


def log_cross_ref(logger: logging.Logger, trigger_claim: str, tool_output_summary: str,
                  result: str, confidence: float, explanation: str):
    """Log the cross-reference decision in a clear block."""
    logger.info("── CROSS-REFERENCE ──────────────────────────────────────")
    logger.info(f"  trigger claim : {trigger_claim}")
    logger.info(f"  tool output   : {tool_output_summary[:200]}")
    logger.info(f"  result        : {result}  (confidence {confidence:.2f})")
    logger.info(f"  explanation   : {explanation}")
    logger.info("────────────────────────────────────────────────────────")


def log_verdict(logger: logging.Logger, verdict: str, confidence: float,
                explanation: str, cycle: int):
    """Final verdict log — always INFO so it's visible on console."""
    color = {
        "MALICIOUS":  _Colors.RED    + _Colors.BOLD,
        "SUSPICIOUS": _Colors.YELLOW,
        "BENIGN":     _Colors.GREEN,
    }.get(verdict, _Colors.WHITE)

    logger.info("══ VERDICT ══════════════════════════════════════════════")
    logger.info(f"  verdict     : {verdict}")
    logger.info(f"  confidence  : {confidence:.2f}")
    logger.info(f"  cycle       : {cycle}")
    logger.info(f"  explanation : {explanation}")
    logger.info("═════════════════════════════════════════════════════════")


def log_json(logger: logging.Logger, label: str, obj: Any, level: int = logging.DEBUG):
    """Dump any dict/pydantic object as indented JSON to the log file."""
    try:
        if hasattr(obj, "model_dump"):
            obj = obj.model_dump()
        text = json.dumps(obj, indent=2, default=str)
    except Exception:
        text = repr(obj)

    logger.log(level, f"── JSON DUMP: {label} ─────────────────────────────────")
    for line in text.splitlines():
        logger.log(level, f"  {line}")
    logger.log(level, "────────────────────────────────────────────────────────")


def log_exception(logger: logging.Logger, context: str, exc: Exception):
    """Log an exception with full traceback to file, short to console."""
    logger.error(f"EXCEPTION in {context}: {type(exc).__name__}: {exc}", exc_info=exc)


def log_session_end(logger: logging.Logger, total_cycles: int, verdict: str,
                    total_cost: float):
    """Write a clean session summary at the end."""
    logger.info("═" * 60)
    logger.info("SESSION COMPLETE")
    logger.info(f"  total cycles : {total_cycles}")
    logger.info(f"  final verdict: {verdict}")
    logger.info(f"  total cost   : ${total_cost:.6f}")
    logger.info(f"  log saved to : {LOG_FILE.resolve()}")
    logger.info("═" * 60)