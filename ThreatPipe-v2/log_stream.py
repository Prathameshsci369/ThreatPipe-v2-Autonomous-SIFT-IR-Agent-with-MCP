"""
ThreatPipe v2 — Log Stream Classifier (Phase 5)
=================================================
Raw log file → sliding window → LLM Stage 1 classification
→ suspicious_logs.txt

NO regex. NO heuristics. Direct LLM classification on 2K token windows.

Stage 1 LLM job:
  - Read a batch of raw log lines
  - Identify which lines look suspicious
  - Return line numbers + one-line reason each
  - Fast, cheap — small output, big input

Stage 2 (agent.py) handles the actual investigation.

Usage:
    from log_stream import stream_classify
    stream_classify("access.log", "suspicious_logs.txt")

    # or CLI
    python log_stream.py access.log
    python log_stream.py access.log --output suspicious.txt --window 80
"""

import os
import sys
import json
import time
import argparse
from pathlib import Path
from typing import Iterator, List, Tuple
from datetime import datetime, timezone

from langchain_core.prompts import ChatPromptTemplate
from langchain_mistralai import ChatMistralAI
from pydantic import BaseModel, Field

from logger import get_logger, log_stage, log_llm_request, log_llm_response, log_exception
from config import CONFIG, token_manager

log = get_logger("log_stream")

# ─── Constants ────────────────────────────────────────────────────────────────

# Approx chars per token (conservative — keeps us well under 2K tokens)
CHARS_PER_TOKEN   = 4
# Target input token budget for log lines per window (leave room for prompt)
LOG_TOKEN_BUDGET  = 1600   # ~1600 tokens of logs, ~400 tokens for prompt = 2K total
MAX_WINDOW_LINES  = 200    # hard cap — never send more than 200 lines at once


# ─── LLM Stage 1 — classifier output schema ───────────────────────────────────

class SuspiciousLine(BaseModel):
    line_number: int   = Field(..., description="1-indexed line number in this batch")
    #reason:      str   = Field(..., description="One sentence — why this line is suspicious")
    reason:      str   = Field(..., description="VERY brief reason (max 20 words)")
    severity:    str   = Field(..., description="HIGH / MEDIUM / LOW")


class ClassifierResult(BaseModel):
    suspicious: List[SuspiciousLine] = Field(
        default_factory=list,
        description="List of suspicious lines. Empty list if nothing suspicious."
    )
    window_summary: str = Field(
        default="",
        description="One sentence summary of this log window (e.g. '3 suspicious POST requests from 192.168.1.55')"
    )


# ─── Stage 1 LLM setup ────────────────────────────────────────────────────────

_CLASSIFIER_SYSTEM = """
You are a SOC analyst reviewing raw server logs.
Your job: quickly triage a batch of log lines and identify suspicious ones.

SUSPICIOUS indicators (examples — not exhaustive):
- Web shells: ?cmd=, ?exec=, ?shell=, passthru, system(, base64_decode
- Unusual HTTP methods to sensitive paths: POST to /admin/, /uploads/, /backup/
- Path traversal: ../, ../../, %2e%2e
- SQL injection: UNION SELECT, OR 1=1, DROP TABLE
- Scanner patterns: nikto, sqlmap, nmap, masscan in user-agent
- Unusual file access: .php in upload directories, double extensions (.php.jpg)
- Rapid repeated requests from same IP (possible brute force or automation)
- Large response sizes to normally small endpoints
- Access to sensitive files: /etc/passwd, /wp-config.php, /.env, /.git/
- Command injection in query strings: ;whoami, |id, `cat /etc/passwd`
- Memory/process anomalies: malfind, injected, hollowing
- Registry persistence paths: CurrentVersion\\Run, Winlogon

BENIGN (do NOT flag):
- Normal GET requests for static assets (images, CSS, JS)
- Standard API calls with expected parameters
- Normal status codes (200) for expected resources
- Health checks, monitoring pings
OUTPUT FORMAT:
Return ONLY the JSON — no explanation, no markdown, no preamble.
IMPORTANT: Return AT MOST the top 15 most suspicious lines per batch. Keep reasons VERY brief (under 20 words).
If nothing is suspicious, return: {{"suspicious": [], "window_summary": "No suspicious activity detected."}}
"""

_CLASSIFIER_HUMAN = """
Batch {batch_num} of {total_batches} — lines {start_line} to {end_line}:

{log_lines}

Identify suspicious lines. Return JSON only.
"""

import time 
def _get_classifier_llm() -> ChatMistralAI:
    """Separate LLM instance for Stage 1 — lower max_tokens since output is small."""
    api_key = os.getenv("MISTRAL_API_KEY")
    if not api_key:
        raise ValueError("MISTRAL_API_KEY not set")
    print("Request delay added 20 seconds so waith 20s")

    
    return ChatMistralAI(
        model       = CONFIG.get("llm", {}).get("model", "mistral-small-lates"),
        api_key     = api_key,
        temperature = 0.0,
        max_tokens  = 2000,   # Stage 1 output is small — list of line numbers
        callbacks   = [token_manager],
    )


# ─── Sliding window generator ─────────────────────────────────────────────────

def _sliding_windows(
    lines: List[str],
    token_budget: int = LOG_TOKEN_BUDGET,
    max_lines: int    = MAX_WINDOW_LINES,
) -> Iterator[Tuple[int, int, List[str]]]:
    """
    Yield (start_idx, end_idx, window_lines) chunks.
    Each chunk fits within token_budget.
    start_idx and end_idx are 0-based indices into `lines`.
    """
    i = 0
    total = len(lines)

    while i < total:
        window       = []
        token_count  = 0
        j            = i

        while j < total and len(window) < max_lines:
            line        = lines[j]
            line_tokens = len(line) // CHARS_PER_TOKEN + 1

            if token_count + line_tokens > token_budget and window:
                break   # window full — yield what we have

            window.append(line)
            token_count += line_tokens
            j += 1

        if window:
            log.debug(
                f"Window [{i}:{j}]  lines={len(window)}  "
                f"~{token_count} tokens"
            )
            yield i, j - 1, window

        i = j


# ─── Stage 1 classification ───────────────────────────────────────────────────

def _classify_window(
    llm_structured,
    window_lines:   List[str],
    start_line_num: int,   # 1-based line number of first line in window
    batch_num:      int,
    total_batches:  int,
) -> ClassifierResult:
    """
    Send one window to LLM Stage 1.
    Returns ClassifierResult with suspicious line numbers (relative to window).
    """
    # Format lines with numbers for LLM reference
    numbered = "\n".join(
        f"[{start_line_num + i}] {line.rstrip()}"
        for i, line in enumerate(window_lines)
    )

    end_line_num = start_line_num + len(window_lines) - 1

    log_llm_request(
        log,
        model          = "mistral-small-latest (Stage 1)",
        prompt_preview = f"batch={batch_num}  lines={start_line_num}-{end_line_num}  chars={len(numbered)}",
        token_estimate = len(numbered) // CHARS_PER_TOKEN,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", _CLASSIFIER_SYSTEM),
        ("human",  _CLASSIFIER_HUMAN),
    ])
    chain = prompt | llm_structured

    t0 = time.monotonic()
    try:
        result: ClassifierResult = chain.invoke({
            "batch_num":     batch_num,
            "total_batches": total_batches,
            "start_line":    start_line_num,
            "end_line":      end_line_num,
            "log_lines":     numbered,
        })
        elapsed = (time.monotonic() - t0) * 1000

        log.info(
            f"Stage1 batch={batch_num}  "
            f"suspicious={len(result.suspicious)}  "
            f"elapsed={elapsed:.0f}ms"
        )
        log.info(f"  summary: {result.window_summary}")

        for s in result.suspicious:
            log.info(
                f"  [{s.severity}] line {s.line_number}: {s.reason[:80]}"
            )

        return result

    except Exception as exc:
        log_exception(log, f"_classify_window batch={batch_num}", exc)
        # On failure — return empty (don't crash the pipeline)
        return ClassifierResult(
            suspicious      = [],
            window_summary  = f"Classification failed: {exc}",
        )


# ─── Main public API ──────────────────────────────────────────────────────────

def stream_classify(
    input_path:  str,
    output_path: str = "suspicious_logs.txt",
    window_size: int = LOG_TOKEN_BUDGET,
) -> List[str]:
    """
    Main entry point.

    Reads input_path line by line, slides windows through it,
    classifies each window with Stage 1 LLM, writes suspicious
    log lines to output_path.

    Returns list of suspicious log lines (for direct use in pipeline).
    """
    input_file  = Path(input_path)
    output_file = Path(output_path)

    if not input_file.exists():
        log.error(f"Input file not found: {input_path}")
        raise FileNotFoundError(f"{input_path} not found")

    log.info(f"stream_classify START  input={input_path}  output={output_path}")
    log_stage(log, 0, "Log Stream Classification", {
        "input":       input_path,
        "output":      output_path,
        "window_budget": f"~{window_size} tokens",
    })

    # ── Read all lines ──
    with open(input_file, "r", encoding="utf-8", errors="replace") as f:
        all_lines = f.readlines()

    total_lines = len(all_lines)
    log.info(f"Loaded {total_lines} log lines from {input_path}")

    if total_lines == 0:
        log.warning("Input file is empty — nothing to classify")
        return []

    # ── Build windows ──
    windows = list(_sliding_windows(all_lines, token_budget=window_size))
    total_batches = len(windows)
    log.info(f"Created {total_batches} sliding windows")

    # ── Stage 1 LLM ──
    llm = _get_classifier_llm()
    structured_llm = llm.with_structured_output(ClassifierResult)

    suspicious_lines: List[str]  = []
    suspicious_meta:  List[dict] = []   # for output file header

    for batch_num, (start_idx, end_idx, window_lines) in enumerate(windows, start=1):
        start_line_num = start_idx + 1  # 1-based

        result = _classify_window(
            structured_llm,
            window_lines,
            start_line_num,
            batch_num,
            total_batches,
        )

        # Collect suspicious lines
        for s in result.suspicious:
            # s.line_number is 1-based absolute line number
            abs_idx = s.line_number - 1
            if 0 <= abs_idx < total_lines:
                raw_line = all_lines[abs_idx].rstrip()
                suspicious_lines.append(raw_line)
                suspicious_meta.append({
                    "line_number": s.line_number,
                    "severity":    s.severity,
                    "reason":      s.reason,
                    "raw":         raw_line,
                })
            else:
                log.warning(
                    f"LLM returned out-of-range line_number={s.line_number} "
                    f"(total={total_lines}) — skipping"
                )

    # ── Write output file ──
    ts = datetime.now(timezone.utc).isoformat()
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(f"# ThreatPipe v2 — Stage 1 Classification Output\n")
        f.write(f"# Generated : {ts}\n")
        f.write(f"# Input     : {input_path}\n")
        f.write(f"# Total logs: {total_lines}\n")
        f.write(f"# Suspicious: {len(suspicious_lines)}\n")
        f.write(f"# Batches   : {total_batches}\n")
        f.write(f"# LLM cost  : ${token_manager.total_cost:.6f}\n")
        f.write(f"#\n")
        f.write(f"# Format: SEVERITY | REASON | RAW_LOG_LINE\n")
        f.write(f"# {'─'*70}\n\n")

        for meta in suspicious_meta:
            f.write(
                f"# [{meta['severity']}] Line {meta['line_number']}: {meta['reason']}\n"
                f"{meta['raw']}\n\n"
            )

    log.info(
        f"stream_classify DONE  "
        f"total={total_lines}  suspicious={len(suspicious_lines)}  "
        f"written={output_file}  cost=${token_manager.total_cost:.6f}"
    )

    return suspicious_lines


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ThreatPipe Stage 1 — Log stream classifier"
    )
    parser.add_argument("input",          help="Input log file path")
    parser.add_argument("--output", "-o", default="suspicious_logs.txt",
                        help="Output file for suspicious logs (default: suspicious_logs.txt)")
    parser.add_argument("--window", "-w", type=int, default=LOG_TOKEN_BUDGET,
                        help=f"Token budget per window (default: {LOG_TOKEN_BUDGET})")
    args = parser.parse_args()

    try:
        suspicious = stream_classify(args.input, args.output, args.window)
        print(f"\nDone. {len(suspicious)} suspicious lines → {args.output}")
    except Exception as exc:
        log.exception(f"stream_classify failed: {exc}")
        sys.exit(1)