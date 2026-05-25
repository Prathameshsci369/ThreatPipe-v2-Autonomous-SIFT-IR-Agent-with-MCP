"""
ThreatPipe v2 — Stream Run (Phase 5)
======================================
Full pipeline orchestrator:

  Step 1: log_stream.py  → Stage 1 LLM classifies raw logs → suspicious_logs.txt
  Step 2: agent.py       → Stage 2 investigates each suspicious log
                           (4-lens, SIFT tools, self-correction, evidence graph)

Usage:
    # Full pipeline — raw log file input
    python stream_run.py access.log

    # Skip Stage 1 — use existing suspicious_logs.txt directly
    python stream_run.py --skip-classify suspicious_logs.txt

    # Custom output path
    python stream_run.py access.log --suspicious-out my_suspicious.txt

    # Generate sample log file for testing
    python stream_run.py --generate-sample
"""

import sys
import time
import argparse
from pathlib import Path
from datetime import datetime, timezone

from logger import get_logger, log_stage, log_session_end
from log_stream import stream_classify
from agent import app as agent_app
from config import token_manager
from hacker_mindset_graph import HackerMindsetGraph
from stage_classifier import classify_stage, classify_ip_threat
from mindset_analyzer import analyze as mindset_analyze

log = get_logger("stream_run")

# ─── ANSI colors ──────────────────────────────────────────────────────────────
RED    = "\033[91m"; GREEN  = "\033[92m"; YELLOW = "\033[93m"
CYAN   = "\033[96m"; BOLD   = "\033[1m";  DIM    = "\033[2m"; RESET  = "\033[0m"

VERDICT_COLOR = {"MALICIOUS": RED + BOLD, "SUSPICIOUS": YELLOW, "BENIGN": GREEN}


# ─── Sample log file generator ────────────────────────────────────────────────

SAMPLE_LOGS = """
192.168.1.10 - - [16/Apr/2026:02:00:01] "GET /index.html HTTP/1.1" 200 1234
192.168.1.10 - - [16/Apr/2026:02:00:02] "GET /style.css HTTP/1.1" 200 5678
192.168.1.10 - - [16/Apr/2026:02:00:03] "GET /logo.png HTTP/1.1" 200 9012
192.168.1.11 - - [16/Apr/2026:02:01:00] "GET /about.html HTTP/1.1" 200 3456
192.168.1.11 - - [16/Apr/2026:02:01:01] "GET /contact.html HTTP/1.1" 200 2345
192.168.1.11 - - [16/Apr/2026:02:01:02] "GET /favicon.ico HTTP/1.1" 200 1234
192.168.1.12 - - [16/Apr/2026:02:02:00] "GET /products.html HTTP/1.1" 200 8901
192.168.1.12 - - [16/Apr/2026:02:02:01] "GET /images/product1.jpg HTTP/1.1" 200 45678
192.168.1.12 - - [16/Apr/2026:02:02:02] "GET /images/product2.jpg HTTP/1.1" 200 34567
192.168.1.12 - - [16/Apr/2026:02:02:03] "GET /images/product3.jpg HTTP/1.1" 200 23456
192.168.1.13 - - [16/Apr/2026:02:03:00] "GET /blog/post1.html HTTP/1.1" 200 6789
192.168.1.13 - - [16/Apr/2026:02:03:01] "GET /blog/post2.html HTTP/1.1" 200 5678
192.168.1.13 - - [16/Apr/2026:02:03:02] "GET /blog/post3.html HTTP/1.1" 200 4567
192.168.1.14 - - [16/Apr/2026:02:04:00] "GET /api/products HTTP/1.1" 200 2345
192.168.1.14 - - [16/Apr/2026:02:04:01] "GET /api/categories HTTP/1.1" 200 1234
192.168.1.14 - - [16/Apr/2026:02:04:02] "GET /api/health HTTP/1.1" 200 15
192.168.1.15 - - [16/Apr/2026:02:05:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.15 - - [16/Apr/2026:02:05:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.15 - - [16/Apr/2026:02:05:02] "GET /main.js HTTP/1.1" 200 9012
192.168.1.16 - - [16/Apr/2026:02:06:00] "GET /search?q=laptop HTTP/1.1" 200 3456
192.168.1.16 - - [16/Apr/2026:02:06:01] "GET /search?q=phone HTTP/1.1" 200 3456
192.168.1.16 - - [16/Apr/2026:02:06:02] "GET /search?q=tablet HTTP/1.1" 200 3456
192.168.1.17 - - [16/Apr/2026:02:07:00] "POST /api/login HTTP/1.1" 200 456
192.168.1.17 - - [16/Apr/2026:02:07:01] "GET /dashboard HTTP/1.1" 200 7890
192.168.1.17 - - [16/Apr/2026:02:07:02] "GET /api/user/profile HTTP/1.1" 200 234
192.168.1.18 - - [16/Apr/2026:02:08:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.18 - - [16/Apr/2026:02:08:01] "GET /about.html HTTP/1.1" 200 2345
192.168.1.18 - - [16/Apr/2026:02:08:02] "GET /contact.html HTTP/1.1" 200 1234
192.168.1.19 - - [16/Apr/2026:02:09:00] "GET /products.html HTTP/1.1" 200 8901
192.168.1.19 - - [16/Apr/2026:02:09:01] "GET /cart HTTP/1.1" 200 2345
192.168.1.19 - - [16/Apr/2026:02:09:02] "POST /checkout HTTP/1.1" 200 1234
192.168.1.20 - - [16/Apr/2026:02:10:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.20 - - [16/Apr/2026:02:10:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.20 - - [16/Apr/2026:02:10:02] "GET /images/hero.jpg HTTP/1.1" 200 56789
192.168.1.21 - - [16/Apr/2026:02:11:00] "GET /blog/post1.html HTTP/1.1" 200 6789
192.168.1.21 - - [16/Apr/2026:02:11:01] "GET /blog/post4.html HTTP/1.1" 200 5678
192.168.1.21 - - [16/Apr/2026:02:11:02] "GET /blog/post5.html HTTP/1.1" 200 4567
192.168.1.22 - - [16/Apr/2026:02:12:00] "GET /api/health HTTP/1.1" 200 15
192.168.1.22 - - [16/Apr/2026:02:12:05] "GET /api/health HTTP/1.1" 200 15
192.168.1.22 - - [16/Apr/2026:02:12:10] "GET /api/health HTTP/1.1" 200 15
192.168.1.23 - - [16/Apr/2026:02:13:00] "GET /products.html HTTP/1.1" 200 8901
192.168.1.23 - - [16/Apr/2026:02:13:01] "GET /images/product4.jpg HTTP/1.1" 200 23456
192.168.1.23 - - [16/Apr/2026:02:13:02] "GET /images/product5.jpg HTTP/1.1" 200 34567
192.168.1.24 - - [16/Apr/2026:02:14:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.24 - - [16/Apr/2026:02:14:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.24 - - [16/Apr/2026:02:14:02] "GET /main.js HTTP/1.1" 200 9012
192.168.1.55 - - [16/Apr/2026:03:14:18] "GET /index.html HTTP/1.1" 200 1234
192.168.1.55 - - [16/Apr/2026:03:14:19] "GET /robots.txt HTTP/1.1" 200 45
192.168.1.55 - - [16/Apr/2026:03:14:20] "GET /uploads/ HTTP/1.1" 403 234
192.168.1.55 - - [16/Apr/2026:03:14:21] "GET /uploads/ HTTP/1.1" 403 234
192.168.1.55 - - [16/Apr/2026:03:14:22] "POST /uploads/upload.php HTTP/1.1" 200 432
192.168.1.55 - - [16/Apr/2026:03:14:23] "GET /uploads/shell.php HTTP/1.1" 200 31
192.168.1.55 - - [16/Apr/2026:03:14:25] "GET /uploads/shell.php?cmd=whoami HTTP/1.1" 200 15
192.168.1.55 - - [16/Apr/2026:03:14:27] "GET /uploads/shell.php?cmd=id HTTP/1.1" 200 23
192.168.1.55 - - [16/Apr/2026:03:14:29] "GET /uploads/shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1847
192.168.1.55 - - [16/Apr/2026:03:14:31] "GET /uploads/shell.php?cmd=ls+-la+/ HTTP/1.1" 200 456
192.168.1.55 - - [16/Apr/2026:03:14:33] "GET /uploads/shell.php?cmd=uname+-a HTTP/1.1" 200 89
192.168.1.55 - - [16/Apr/2026:03:14:35] "GET /uploads/shell.php?cmd=ps+aux HTTP/1.1" 200 2341
192.168.1.30 - - [16/Apr/2026:03:15:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.30 - - [16/Apr/2026:03:15:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.30 - - [16/Apr/2026:03:15:02] "GET /main.js HTTP/1.1" 200 9012
192.168.1.31 - - [16/Apr/2026:03:16:00] "GET /products.html HTTP/1.1" 200 8901
192.168.1.31 - - [16/Apr/2026:03:16:01] "GET /cart HTTP/1.1" 200 2345
192.168.1.31 - - [16/Apr/2026:03:16:02] "POST /checkout HTTP/1.1" 200 1234
192.168.1.32 - - [16/Apr/2026:03:17:00] "GET /blog/post1.html HTTP/1.1" 200 6789
192.168.1.32 - - [16/Apr/2026:03:17:01] "GET /blog/post2.html HTTP/1.1" 200 5678
192.168.1.33 - - [16/Apr/2026:03:18:00] "GET /api/health HTTP/1.1" 200 15
192.168.1.33 - - [16/Apr/2026:03:18:05] "GET /api/health HTTP/1.1" 200 15
192.168.1.60 - - [16/Apr/2026:03:45:00] "GET /images/logo.png HTTP/1.1" 200 120
192.168.1.60 - - [16/Apr/2026:03:45:01] "GET /images/banner.jpg HTTP/1.1" 200 45678
192.168.1.60 - - [16/Apr/2026:03:45:02] "GET /images/evil.png HTTP/1.1" 200 101
192.168.1.60 - - [16/Apr/2026:03:45:03] "GET /images/product1.jpg HTTP/1.1" 200 34567
192.168.1.34 - - [16/Apr/2026:03:50:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.34 - - [16/Apr/2026:03:50:01] "GET /about.html HTTP/1.1" 200 2345
192.168.1.35 - - [16/Apr/2026:03:51:00] "GET /search?q=shoes HTTP/1.1" 200 3456
192.168.1.35 - - [16/Apr/2026:03:51:01] "GET /search?q=bags HTTP/1.1" 200 3456
192.168.1.80 - - [16/Apr/2026:04:15:00] "GET /.env HTTP/1.1" 200 456
192.168.1.80 - - [16/Apr/2026:04:15:01] "GET /.git/config HTTP/1.1" 200 234
192.168.1.80 - - [16/Apr/2026:04:15:02] "GET /wp-config.php HTTP/1.1" 200 567
192.168.1.80 - - [16/Apr/2026:04:15:03] "GET /config.php HTTP/1.1" 404 234
192.168.1.80 - - [16/Apr/2026:04:15:04] "GET /admin/config.php HTTP/1.1" 404 234
192.168.1.36 - - [16/Apr/2026:04:20:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.36 - - [16/Apr/2026:04:20:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.36 - - [16/Apr/2026:04:20:02] "GET /main.js HTTP/1.1" 200 9012
192.168.1.37 - - [16/Apr/2026:04:21:00] "GET /products.html HTTP/1.1" 200 8901
192.168.1.37 - - [16/Apr/2026:04:21:01] "GET /images/product1.jpg HTTP/1.1" 200 45678
192.168.1.37 - - [16/Apr/2026:04:21:02] "GET /images/product2.jpg HTTP/1.1" 200 34567
192.168.1.38 - - [16/Apr/2026:04:22:00] "GET /blog/post1.html HTTP/1.1" 200 6789
192.168.1.38 - - [16/Apr/2026:04:22:01] "GET /blog/post2.html HTTP/1.1" 200 5678
192.168.1.38 - - [16/Apr/2026:04:22:02] "GET /blog/post3.html HTTP/1.1" 200 4567
192.168.1.39 - - [16/Apr/2026:04:23:00] "GET /api/health HTTP/1.1" 200 15
192.168.1.39 - - [16/Apr/2026:04:23:05] "GET /api/health HTTP/1.1" 200 15
192.168.1.40 - - [16/Apr/2026:04:24:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.40 - - [16/Apr/2026:04:24:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.40 - - [16/Apr/2026:04:24:02] "GET /contact.html HTTP/1.1" 200 1234
192.168.1.41 - - [16/Apr/2026:04:25:00] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:01] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:02] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:03] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:04] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:05] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:06] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:07] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:08] "POST /api/login HTTP/1.1" 401 123
192.168.1.41 - - [16/Apr/2026:04:25:09] "POST /api/login HTTP/1.1" 401 123
192.168.1.42 - - [16/Apr/2026:04:26:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.42 - - [16/Apr/2026:04:26:01] "GET /about.html HTTP/1.1" 200 2345
192.168.1.42 - - [16/Apr/2026:04:26:02] "GET /products.html HTTP/1.1" 200 8901
192.168.1.43 - - [16/Apr/2026:04:27:00] "GET /search?q=laptop HTTP/1.1" 200 3456
192.168.1.43 - - [16/Apr/2026:04:27:01] "GET /search?q=headphones HTTP/1.1" 200 3456
192.168.1.44 - - [16/Apr/2026:04:28:00] "GET /blog/post1.html HTTP/1.1" 200 6789
192.168.1.44 - - [16/Apr/2026:04:28:01] "GET /blog/post6.html HTTP/1.1" 200 5678
192.168.1.45 - - [16/Apr/2026:04:29:00] "GET /api/health HTTP/1.1" 200 15
192.168.1.45 - - [16/Apr/2026:04:29:05] "GET /api/health HTTP/1.1" 200 15
192.168.1.46 - - [16/Apr/2026:04:30:00] "GET /index.html HTTP/1.1" 200 1234
192.168.1.46 - - [16/Apr/2026:04:30:01] "GET /style.css HTTP/1.1" 200 5678
192.168.1.46 - - [16/Apr/2026:04:30:02] "GET /main.js HTTP/1.1" 200 9012
"""


def generate_sample(path: str = "sample_access.log"):
    """Write a sample log file for testing."""
    Path(path).write_text(SAMPLE_LOGS)
    log.info(f"Sample log file written: {path}  ({len(SAMPLE_LOGS.splitlines())} lines)")
    print(f"Sample log file created: {path}")
    return path


# ─── Suspicious log reader ────────────────────────────────────────────────────

def _read_suspicious_file(path: str) -> list[str]:
    """
    Read suspicious_logs.txt produced by log_stream.py.
    Skips comment lines (starting with #) and blank lines.
    Returns list of raw log line strings.
    """
    lines = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            stripped = line.strip()
            if stripped and not stripped.startswith("#"):
                lines.append(stripped)
    log.info(f"Read {len(lines)} suspicious log lines from {path}")
    return lines


# ─── Agent pipeline runner ────────────────────────────────────────────────────

def _run_agent(log_line: str, case_num: int) -> dict:
    """Run single log line through the full agent pipeline."""
    session_id = (
        f"stream_{case_num}_"
        f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
    )

    inputs = {
        "trigger_event":       log_line,
        "current_cycle":       0,
        "max_cycles":          3,
        "session_id":          session_id,
        "structured_trigger":  None,
        "plan":                None,
        "tool_output":         None,
        "analysis":            None,
        "final_report":        None,
        "trigger_node_id":     None,
        "artifact_node_id":    None,
        "tool_exec_node_id":   None,
        "_last_tool":          None,
        "_last_hypothesis":    None,
        "_prev_result_summary":None,
        "_tool_executions":    None,
    }

    return agent_app.invoke(inputs)


def _print_result(case_num: int, log_line: str, result: dict, elapsed_ms: float):
    """
    Print full investigation result to console.
    Shows: log line → trigger parse → tool selected → command → output → verdict
    """
    analysis = result.get("analysis")
    trigger  = result.get("structured_trigger")
    cycle    = result.get("current_cycle", 0)

    if not analysis:
        print(f"  [{case_num}] ERROR — no analysis returned")
        return

    color   = VERDICT_COLOR.get(analysis.verdict, "")
    sep     = "─" * 62

    print(f"\n{sep}")
    print(f"  {BOLD}[{case_num}] LOG:{RESET} {log_line[:90]}")
    print(f"{sep}")

    # Trigger parse result
    if trigger:
        print(f"  {CYAN}PARSE{RESET}    type={trigger.trigger_type}  "
              f"entity={trigger.entity}  artifact_type={trigger.artifact_type}")
        if trigger.src_ip:
            print(f"           src_ip={trigger.src_ip}  "
                  f"method={trigger.http_method}  status={trigger.http_status}")
        print(f"           claim: {trigger.claim[:90]}")

    # Tool execution details — from state extras stored by agent
    tool_executions = result.get("_tool_executions", [])
    if tool_executions:
        for te in tool_executions:
            status_str = "OK" if te.get("returncode", -1) == 0 else f"EXIT {te.get('returncode')}"
            print(f"\n  {CYAN}TOOL{RESET}     {BOLD}{te['tool']}{RESET}  "
                  f"[{status_str}]  {te.get('elapsed_ms', 0):.1f}ms  "
                  f"cycle={te.get('cycle', 0)}")
            print(f"  CMD      {te['tool']} {' '.join(te.get('args', []))}")
            print(f"  REASON   {te.get('rationale', '')[:80]}")
            print(f"  EXPECT   {te.get('hypothesis', '')[:80]}")
            # Output
            out = te.get("stdout", "").strip() or te.get("stderr", "").strip()
            if out:
                lines = out.splitlines()
                print(f"  OUTPUT   ┌{'─'*52}")
                for line in lines[:8]:
                    print(f"           │ {line[:70]}")
                if len(lines) > 8:
                    print(f"           │ ... ({len(lines)-8} more lines)")
                print(f"           └{'─'*52}")
            else:
                print(f"  OUTPUT   (empty)")
    else:
        # Fallback: show from analysis state if _tool_executions not available
        last_tool = result.get("_last_tool", "?")
        tool_out  = result.get("tool_output", "")
        if last_tool != "?":
            print(f"\n  {CYAN}TOOL{RESET}     {BOLD}{last_tool}{RESET}  cycle={cycle}")
            if tool_out:
                lines = tool_out.strip().splitlines()
                print(f"  OUTPUT   ┌{'─'*52}")
                for line in lines[:8]:
                    print(f"           │ {line[:70]}")
                if len(lines) > 8:
                    print(f"           │ ... ({len(lines)-8} more lines)")
                print(f"           └{'─'*52}")

    # Verdict
    print(f"\n  {color}▶ VERDICT: {analysis.verdict} "
          f"(confidence={analysis.confidence:.2f})  "
          f"cycles={cycle+1}  {elapsed_ms:.0f}ms{RESET}")
    print(f"  EXPLAIN  {analysis.explanation[:110]}")
    print(f"  STATUS   {analysis.status}")


# ─── Main orchestrator ────────────────────────────────────────────────────────

def run_pipeline(
    input_path:     str,
    suspicious_out: str  = "suspicious_logs.txt",
    skip_classify:  bool = False,
    mindset_db:     str  = "./hacker_mindset.db",
    run_mindset:    bool = True,
) -> dict:
    """
    Full pipeline:
      Stage 1 — LLM classifies raw logs → suspicious_logs.txt
      Stage 2 — Agent investigates each suspicious log (SIFT tools + 4-lens)
      Stage 3 — Mindset Graph records IP behavior + stage classification
      Stage 4 — Mindset Analyzer predicts next attack + generates alerts

    Returns summary dict.
    """
    cost_start = token_manager.total_cost
    ts_start   = time.monotonic()

    # ── Open Mindset Graph (persistent across runs) ────────────────────────
    mindset_graph = HackerMindsetGraph(db_path=mindset_db)

    # ──────────────────────────────────────────────────────────────────────
    # STAGE 1 — Log stream classification
    # ──────────────────────────────────────────────────────────────────────
    if skip_classify:
        log_stage(log, 1, "Stage 1 SKIPPED — reading existing suspicious file", {
            "file": input_path,
        })
        suspicious_lines = _read_suspicious_file(input_path)
    else:
        log_stage(log, 1, "Stage 1 — LLM Log Classification", {
            "input":  input_path,
            "output": suspicious_out,
        })
        suspicious_lines = stream_classify(input_path, suspicious_out)

    total_suspicious = len(suspicious_lines)

    if total_suspicious == 0:
        log.info("No suspicious logs found — pipeline complete")
        print(f"\n{GREEN}No suspicious logs detected.{RESET}")
        mindset_graph.close()
        return {"suspicious": 0, "investigated": 0}

    print(f"\n{BOLD}Stage 1 complete:{RESET} {total_suspicious} suspicious lines found")
    print(f"{'─'*60}")

    # ──────────────────────────────────────────────────────────────────────
    # STAGE 2 — Agent investigation
    # ──────────────────────────────────────────────────────────────────────
    log_stage(log, 2, "Stage 2 — Agent Investigation", {
        "suspicious_count": total_suspicious,
    })
    print(f"\n{BOLD}Stage 2 — Investigating {total_suspicious} suspicious logs:{RESET}")

    results    = []
    malicious  = 0
    suspicious = 0
    benign     = 0
    forensic_for_mindset = []   # collected for Stage 4 LLM

    for i, log_line in enumerate(suspicious_lines, start=1):
        t0     = time.monotonic()
        result = _run_agent(log_line, i)
        elapsed= (time.monotonic() - t0) * 1000

        results.append(result)
        _print_result(i, log_line, result, elapsed)

        analysis = result.get("analysis")
        trigger  = result.get("structured_trigger")

        if analysis:
            if analysis.verdict == "MALICIOUS":   malicious  += 1
            elif analysis.verdict == "SUSPICIOUS": suspicious += 1
            else:                                  benign     += 1

        # ── STAGE 3 — Mindset Graph update ──────────────────────────────
        if trigger and trigger.src_ip:
            session_id = result.get("session_id", f"stream_{i}")

            # Classify attack stage from forensic result + log
            stage, vector, evidence = classify_stage(
                raw_log  = log_line,
                trigger  = trigger,
                analysis = analysis,
            )

            # Record in persistent mindset graph
            profile = mindset_graph.record_activity(
                src_ip           = trigger.src_ip,
                stage            = stage,
                attack_vector    = vector,
                evidence         = evidence,
                session_id       = session_id,
                forensic_verdict     = analysis.verdict     if analysis else None,
                forensic_confidence  = analysis.confidence  if analysis else None,
            )

            # Log mindset update
            threat_color = (
                RED + BOLD if profile.get("threat_level") in ("CRITICAL", "HIGH")
                else YELLOW
            )
            log.info(
                f"MINDSET  ip={trigger.src_ip}  "
                f"stage={stage}  vector={vector}  "
                f"risk={profile.get('risk_score', 0):.2f}  "
                f"threat={profile.get('threat_level','?')}  "
                f"red_zone={profile.get('is_red_zone', False)}"
            )
            print(
                f"       mindset: {stage:<10}  "
                f"risk={profile.get('risk_score',0):.2f}  "
                f"{threat_color}{profile.get('threat_level','?')}{RESET}"
                + (f"  {RED+BOLD}🔴 RED ZONE{RESET}" if profile.get("is_red_zone") else "")
            )

            # Collect for Stage 4
            forensic_for_mindset.append({
                "src_ip":      trigger.src_ip,
                "entity":      trigger.entity,
                "verdict":     analysis.verdict     if analysis else "?",
                "confidence":  analysis.confidence  if analysis else 0.0,
                "explanation": analysis.explanation if analysis else "",
                "stage":       stage,
                "vector":      vector,
            })

    # ──────────────────────────────────────────────────────────────────────
    # STAGE 4 — Mindset Analyzer — LLM prediction + alerts
    # ──────────────────────────────────────────────────────────────────────
    if run_mindset:
        log_stage(log, 3, "Stage 3 — Mindset Analysis + Alert Generation", {
            "ips_tracked": len(set(
                f["src_ip"] for f in forensic_for_mindset
            )),
        })
        mindset_graph.dump_mindset_graph()
        mindset_analyze(
            graph            = mindset_graph,
            forensic_results = forensic_for_mindset,
            write_report     = True,
            report_path      = "mindset_report.txt",
        )

    # ──────────────────────────────────────────────────────────────────────
    # FINAL SUMMARY
    # ──────────────────────────────────────────────────────────────────────
    total_elapsed = (time.monotonic() - ts_start)
    total_cost    = token_manager.total_cost - cost_start

    print(f"\n{'═'*60}")
    print(f"  {BOLD}PIPELINE COMPLETE{RESET}")
    print(f"{'─'*60}")
    print(f"  Logs processed : {total_suspicious}")
    print(f"  {RED+BOLD}MALICIOUS {RESET}       : {malicious}")
    print(f"  {YELLOW}SUSPICIOUS{RESET}       : {suspicious}")
    print(f"  {GREEN}BENIGN    {RESET}       : {benign}")
    print(f"  Total time     : {total_elapsed:.1f}s")
    print(f"  LLM cost       : ${total_cost:.6f}")
    print(f"  Suspicious file: {suspicious_out}")
    print(f"  Mindset DB     : {mindset_db}")
    print(f"  Mindset report : mindset_report.txt")
    print(f"{'═'*60}\n")

    log_session_end(
        log,
        total_cycles = sum(r.get("current_cycle", 0) + 1 for r in results),
        verdict      = f"MALICIOUS:{malicious} SUSPICIOUS:{suspicious} BENIGN:{benign}",
        total_cost   = total_cost,
    )

    mindset_graph.close()

    return {
        "suspicious_found": total_suspicious,
        "investigated":     len(results),
        "malicious":        malicious,
        "suspicious":       suspicious,
        "benign":           benign,
        "total_cost_usd":   total_cost,
        "elapsed_sec":      total_elapsed,
    }


# ─── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="ThreatPipe v2 — Full streaming pipeline"
    )
    parser.add_argument(
        "input", nargs="?",
        help="Input log file (raw logs) or suspicious_logs.txt (with --skip-classify)"
    )
    parser.add_argument(
        "--suspicious-out", "-o",
        default="suspicious_logs.txt",
        help="Output path for Stage 1 suspicious logs (default: suspicious_logs.txt)"
    )
    parser.add_argument(
        "--skip-classify", "-s",
        action="store_true",
        help="Skip Stage 1 — use input file as already-classified suspicious logs"
    )
    parser.add_argument(
        "--generate-sample", "-g",
        action="store_true",
        help="Generate a sample log file and exit"
    )
    parser.add_argument(
        "--no-mindset",
        action="store_true",
        help="Skip Stage 3/4 mindset graph + alert generation"
    )

    args = parser.parse_args()

    if args.generate_sample:
        generate_sample()
        sys.exit(0)

    if not args.input:
        parser.print_help()
        sys.exit(1)

    if not Path(args.input).exists():
        print(f"Error: File not found: {args.input}")
        sys.exit(1)

    run_pipeline(
        input_path     = args.input,
        suspicious_out = args.suspicious_out,
        skip_classify  = args.skip_classify,
        run_mindset    = not args.no_mindset,
    )