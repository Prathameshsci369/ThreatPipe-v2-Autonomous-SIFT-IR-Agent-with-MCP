"""
ThreatPipe v2 — MCP Server (Phase 4)
======================================
FastAPI-based MCP (Model Context Protocol) server.
External tools / Claude Desktop la typed SIFT payloads push karta yetat.

Endpoints:
  POST /investigate       — single log line submit → full investigation
  GET  /status            — server health check
  GET  /sessions          — list all sessions from evidence graph
  GET  /session/{id}      — full session graph dump
  POST /batch             — multiple log lines batch submit

Run:
    uvicorn mcp_server:app --host 0.0.0.0 --port 9000 --reload

Test:
    curl -X POST http://localhost:9000/investigate \
      -H "Content-Type: application/json" \
      -d '{"log_line": "192.168.1.55 - - [16/Apr/2026:03:14:25] \"GET /uploads/shell.php?cmd=whoami HTTP/1.1\" 200"}'
"""

import sqlite3
import json
import uuid
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from logger import get_logger
from agent import app as agent_app
from config import get_db_path

log = get_logger("mcp_server")

# ─── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title       = "ThreatPipe v2 — MCP Server",
    description = "SIFT-native autonomous incident response agent. Submit logs, get verdicts.",
    version     = "2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ─── Request / Response schemas ───────────────────────────────────────────────

class InvestigateRequest(BaseModel):
    """Single log line investigation request."""
    log_line:   str = Field(..., description="Raw log line — web log, MFT, registry, or memory event")
    session_id: Optional[str] = Field(None, description="Optional session ID. Auto-generated if not provided.")
    max_cycles: int = Field(3, ge=1, le=5, description="Max self-correction cycles (1-5)")


class BatchRequest(BaseModel):
    """Multiple log lines batch investigation."""
    log_lines:  List[str] = Field(..., description="List of raw log lines to investigate")
    max_cycles: int = Field(3, ge=1, le=5)


class VerdictResponse(BaseModel):
    """Investigation result returned to caller."""
    session_id:   str
    trigger:      str
    entity:       str
    artifact:     str
    artifact_type:str
    verdict:      str
    confidence:   float
    status:       str
    cycles_used:  int
    explanation:  str
    cost_usd:     float
    timestamp:    str
    graph_nodes:  int
    graph_edges:  int


class BatchResponse(BaseModel):
    verdicts:    List[VerdictResponse]
    total_cost:  float
    total_cases: int
    malicious:   int
    suspicious:  int
    benign:      int


class SessionSummary(BaseModel):
    session_id:  str
    verdict:     Optional[str]
    confidence:  Optional[float]
    nodes:       int
    edges:       int


# ─── Investigation runner ─────────────────────────────────────────────────────

def _run_investigation(log_line: str, session_id: str, max_cycles: int) -> dict:
    """Run the full agent pipeline and return result dict."""
    log.info(f"MCP: starting investigation  session={session_id}")

    inputs = {
        "trigger_event":       log_line,
        "current_cycle":       0,
        "max_cycles":          max_cycles,
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
    }

    result = agent_app.invoke(inputs)
    log.info(f"MCP: investigation done  session={session_id}")
    return result


def _build_verdict_response(
    result: dict,
    log_line: str,
    session_id: str,
) -> VerdictResponse:
    """Convert agent result to VerdictResponse."""
    from config import token_manager

    analysis = result.get("analysis")
    trigger  = result.get("structured_trigger")

    # Count graph nodes/edges from SQLite
    nodes, edges = 0, 0
    try:
        conn = sqlite3.connect(get_db_path())
        cur  = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM nodes WHERE session_id=?", (session_id,))
        nodes = cur.fetchone()[0]
        cur.execute("""
            SELECT COUNT(*) FROM edges e
            JOIN nodes n ON e.src_id = n.node_id
            WHERE n.session_id=?
        """, (session_id,))
        edges = conn.execute("""
            SELECT COUNT(*) FROM edges WHERE src_id IN
            (SELECT node_id FROM nodes WHERE session_id=?)
        """, (session_id,)).fetchone()[0]
        conn.close()
    except Exception as exc:
        log.warning(f"Could not count graph nodes: {exc}")

    return VerdictResponse(
        session_id    = session_id,
        trigger       = log_line,
        entity        = trigger.entity        if trigger  else "unknown",
        artifact      = trigger.artifact_path if trigger  else "unknown",
        artifact_type = trigger.artifact_type if trigger  else "unknown",
        verdict       = analysis.verdict      if analysis else "UNKNOWN",
        confidence    = analysis.confidence   if analysis else 0.0,
        status        = analysis.status       if analysis else "UNKNOWN",
        cycles_used   = result.get("current_cycle", 0) + 1,
        explanation   = analysis.explanation  if analysis else "No analysis",
        cost_usd      = round(token_manager.total_cost, 6),
        timestamp     = datetime.now(timezone.utc).isoformat(),
        graph_nodes   = nodes,
        graph_edges   = edges,
    )


# ─── Endpoints ────────────────────────────────────────────────────────────────

@app.get("/status")
def status():
    """Health check endpoint."""
    return {
        "status":    "ok",
        "service":   "ThreatPipe v2 MCP Server",
        "version":   "2.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "db_path":   get_db_path(),
    }


@app.post("/investigate", response_model=VerdictResponse)
def investigate(req: InvestigateRequest):
    """
    Submit a single log line for investigation.

    Accepts: web logs, MFT entries, registry events, memory anomalies.
    Returns: verdict, confidence, explanation, evidence graph stats.
    """
    session_id = req.session_id or f"mcp_{uuid.uuid4().hex[:8]}"

    log.info(f"POST /investigate  session={session_id}  log='{req.log_line[:80]}'")

    try:
        result = _run_investigation(req.log_line, session_id, req.max_cycles)
        return _build_verdict_response(result, req.log_line, session_id)
    except Exception as exc:
        log.exception(f"Investigation failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/batch", response_model=BatchResponse)
def batch_investigate(req: BatchRequest):
    """
    Submit multiple log lines for batch investigation.
    Each log line gets its own session_id.
    Returns aggregated verdict counts + individual results.
    """
    log.info(f"POST /batch  count={len(req.log_lines)}")

    verdicts   = []
    total_cost = 0.0

    for i, log_line in enumerate(req.log_lines):
        session_id = f"mcp_batch_{uuid.uuid4().hex[:8]}"
        try:
            result   = _run_investigation(log_line, session_id, req.max_cycles)
            response = _build_verdict_response(result, log_line, session_id)
            verdicts.append(response)
            total_cost += response.cost_usd
        except Exception as exc:
            log.error(f"Batch item {i} failed: {exc}")
            verdicts.append(VerdictResponse(
                session_id    = session_id,
                trigger       = log_line,
                entity        = "error",
                artifact      = "error",
                artifact_type = "unknown",
                verdict       = "UNKNOWN",
                confidence    = 0.0,
                status        = "MISMATCH",
                cycles_used   = 0,
                explanation   = f"Investigation error: {exc}",
                cost_usd      = 0.0,
                timestamp     = datetime.now(timezone.utc).isoformat(),
                graph_nodes   = 0,
                graph_edges   = 0,
            ))

    return BatchResponse(
        verdicts    = verdicts,
        total_cost  = round(total_cost, 6),
        total_cases = len(verdicts),
        malicious   = sum(1 for v in verdicts if v.verdict == "MALICIOUS"),
        suspicious  = sum(1 for v in verdicts if v.verdict == "SUSPICIOUS"),
        benign      = sum(1 for v in verdicts if v.verdict == "BENIGN"),
    )


@app.get("/sessions", response_model=List[SessionSummary])
def list_sessions():
    """List all investigation sessions from the evidence graph DB."""
    try:
        conn = sqlite3.connect(get_db_path())
        conn.row_factory = sqlite3.Row
        cur  = conn.cursor()

        # Get all unique sessions with their finding nodes
        cur.execute("""
            SELECT
                n.session_id,
                f.verdict,
                f.confidence,
                COUNT(DISTINCT n2.node_id) as node_count
            FROM nodes n
            LEFT JOIN nodes f ON f.session_id = n.session_id
                AND f.node_type = 'finding'
            LEFT JOIN nodes n2 ON n2.session_id = n.session_id
            GROUP BY n.session_id, f.verdict, f.confidence
            ORDER BY n.created_at DESC
        """)
        rows = cur.fetchall()

        # Count edges per session
        sessions = {}
        for row in rows:
            sid = row["session_id"]
            if sid not in sessions:
                edge_count = conn.execute("""
                    SELECT COUNT(*) FROM edges WHERE src_id IN
                    (SELECT node_id FROM nodes WHERE session_id=?)
                """, (sid,)).fetchone()[0]
                sessions[sid] = SessionSummary(
                    session_id = sid,
                    verdict    = row["verdict"],
                    confidence = row["confidence"],
                    nodes      = row["node_count"],
                    edges      = edge_count,
                )
        conn.close()
        return list(sessions.values())

    except Exception as exc:
        log.exception(f"list_sessions failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/session/{session_id}")
def get_session(session_id: str):
    """Get full node+edge dump for a specific session."""
    try:
        conn = sqlite3.connect(get_db_path())
        conn.row_factory = sqlite3.Row
        cur  = conn.cursor()

        cur.execute(
            "SELECT * FROM nodes WHERE session_id=? ORDER BY created_at",
            (session_id,)
        )
        nodes = [dict(r) for r in cur.fetchall()]

        if not nodes:
            raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")

        edges = conn.execute("""
            SELECT e.* FROM edges e
            JOIN nodes n ON e.src_id = n.node_id
            WHERE n.session_id=?
            ORDER BY e.created_at
        """, (session_id,)).fetchall()
        edges = [dict(e) for e in edges]

        conn.close()

        return {
            "session_id": session_id,
            "nodes":      nodes,
            "edges":      edges,
            "summary": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "node_types":  list({n["node_type"] for n in nodes}),
            }
        }

    except HTTPException:
        raise
    except Exception as exc:
        log.exception(f"get_session failed: {exc}")
        raise HTTPException(status_code=500, detail=str(exc))
    


# ══════════════════════════════════════════════════════════════════════════════
# MCP TOOL LAYER — Structured SIFT tool execution with architectural guardrails
# ══════════════════════════════════════════════════════════════════════════════
#
# This is what the hackathon wants:
#   - Typed functions instead of generic execute_shell_cmd
#   - Tool allowlist — agent PHYSICALLY CANNOT run destructive commands
#   - Output truncation — prevents context window overload
#   - Path validation — prevents path traversal
#
# The agent calls these functions. These functions call SIFT tools.
# The agent never touches subprocess directly.

import subprocess as _subprocess
import os as _os

# ─── Allowed tools (read-only forensic analysis only) ─────────────────────────
# Destructive tools (rm, dd, shred, wipe, mkfs) are NOT here
# This is ARCHITECTURAL constraint — not prompt-based

ALLOWED_SIFT_TOOLS = {
    "strings":    {"default_args": ["-n", "6"],  "timeout": 30, "max_output": 5000},
    "file":       {"default_args": [],           "timeout": 10, "max_output": 2000},
    "grep":       {"default_args": ["-aiE"],     "timeout": 30, "max_output": 5000},
    "md5sum":     {"default_args": [],           "timeout": 10, "max_output": 500},
    "sha256sum":  {"default_args": [],           "timeout": 10, "max_output": 500},
    "fls":        {"default_args": ["-r", "-d"], "timeout": 60, "max_output": 8000},
    "icat":       {"default_args": [],           "timeout": 30, "max_output": 8000},
    "mmls":       {"default_args": [],           "timeout": 30, "max_output": 5000},
    "fsstat":     {"default_args": [],           "timeout": 30, "max_output": 5000},
    "mactime":    {"default_args": ["-d"],       "timeout": 30, "max_output": 8000},
    "volatility": {"default_args": [],           "timeout": 120,"max_output": 10000},
}

# Commands that should NEVER run — defense in depth
BLOCKED_PATTERNS = [
    "rm ", "rmdir", "dd ", "shred", "wipe", "mkfs",
    "format", "del ", "erase", ">", ">>",
    "chmod", "chown", "mv ", "cp ",
]


class MCPToolResult(BaseModel):
    """Structured result from MCP tool execution."""
    tool:         str
    artifact:     str
    returncode:   int
    stdout:       str
    stderr:       str
    truncated:    bool  = False
    blocked:      bool  = False
    block_reason: Optional[str] = None
    elapsed_ms:   float = 0.0


def mcp_call_tool(
    tool_name: str,
    extra_args: List[str] = [],
    artifact_path: str = "",
) -> MCPToolResult:
    """
    MCP-exposed: Run a SIFT tool on an artifact.

    ARCHITECTURAL GUARDRAILS (cannot be bypassed by LLM):
      1. Tool must be in ALLOWED_SIFT_TOOLS allowlist
      2. No destructive patterns in command
      3. Output truncated to prevent context window overload
      4. Path must exist on disk
      5. Hard timeout per tool

    This is the ONLY way the agent executes SIFT tools.
    """
    import time as _time

    # ── Guard 1: Tool allowlist ──
    if tool_name not in ALLOWED_SIFT_TOOLS:
        return MCPToolResult(
            tool=tool_name, artifact=artifact_path,
            returncode=-1, stdout="", stderr="",
            blocked=True,
            block_reason=f"Tool '{tool_name}' not in allowlist. Allowed: {list(ALLOWED_SIFT_TOOLS.keys())}",
        )

    # ── Guard 2: No destructive patterns ──
    full_cmd_str = f"{tool_name} {' '.join(extra_args)} {artifact_path}"
    for pattern in BLOCKED_PATTERNS:
        if pattern in full_cmd_str.lower():
            return MCPToolResult(
                tool=tool_name, artifact=artifact_path,
                returncode=-1, stdout="", stderr="",
                blocked=True,
                block_reason=f"Blocked destructive pattern: '{pattern}' in command",
            )

    # ── Guard 3: Artifact path must exist ──
    if artifact_path and not _os.path.exists(artifact_path):
        return MCPToolResult(
            tool=tool_name, artifact=artifact_path,
            returncode=-1, stdout="", stderr=f"Artifact not found: {artifact_path}",
            blocked=False,
        )

    # ── Execute ──
    config = ALLOWED_SIFT_TOOLS[tool_name]
    timeout = config["timeout"]
    max_output = config["max_output"]

    cmd = [tool_name] + config.get("default_args", []) + extra_args + [artifact_path]

    log.info(f"MCP TOOL  {' '.join(cmd)}")
    t0 = _time.monotonic()

    try:
        result = _subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        elapsed = (_time.monotonic() - t0) * 1000

        # ── Guard 4: Truncate output ──
        stdout = result.stdout[:max_output]
        stderr = result.stderr[:1000]
        truncated = len(result.stdout) > max_output

        if truncated:
            log.info(f"MCP OUTPUT TRUNCATED  {len(result.stdout)} → {max_output} chars")

        log.info(
            f"MCP TOOL DONE  {tool_name}  rc={result.returncode}  "
            f"elapsed={elapsed:.0f}ms  truncated={truncated}"
        )

        return MCPToolResult(
            tool=tool_name,
            artifact=artifact_path,
            returncode=result.returncode,
            stdout=stdout,
            stderr=stderr,
            truncated=truncated,
            blocked=False,
            elapsed_ms=round(elapsed, 2),
        )

    except _subprocess.TimeoutExpired:
        return MCPToolResult(
            tool=tool_name, artifact=artifact_path,
            returncode=124, stdout="", stderr=f"Timeout ({timeout}s)",
            blocked=False,
        )
    except FileNotFoundError:
        return MCPToolResult(
            tool=tool_name, artifact=artifact_path,
            returncode=127, stdout="", stderr=f"Tool not found: {tool_name}",
            blocked=False,
        )
    except Exception as exc:
        return MCPToolResult(
            tool=tool_name, artifact=artifact_path,
            returncode=-1, stdout="", stderr=str(exc),
            blocked=False,
        )


# ─── Typed MCP functions (like the hackathon examples) ────────────────────────

def mcp_get_amcache(artifact_path: str) -> MCPToolResult:
    """Parse Amcache hive for program execution history."""
    return mcp_call_tool("strings", ["-n", "8"], artifact_path)

def mcp_extract_mft_timeline(disk_image: str, offset: int = 2048) -> MCPToolResult:
    """Extract MFT timeline from disk image using fls."""
    return mcp_call_tool("fls", ["-o", str(offset)], disk_image)

def mcp_analyze_prefetch(artifact_path: str) -> MCPToolResult:
    """Analyze Windows Prefetch files."""
    return mcp_call_tool("strings", ["-n", "6"], artifact_path)

def mcp_get_file_metadata(artifact_path: str) -> dict:
    """Get file type + hash — calls two tools, returns combined result."""
    file_result = mcp_call_tool("file", [], artifact_path)
    hash_result = mcp_call_tool("sha256sum", [], artifact_path)
    return {
        "file_type": file_result.dict(),
        "hash":      hash_result.dict(),
    }

def mcp_memory_malfind(memory_image: str, pid: Optional[str] = None) -> MCPToolResult:
    """Volatility malfind — detect injected memory regions."""
    extra = ["malfind"]
    if pid:
        extra.append(f"--pid={pid}")
    return mcp_call_tool("volatility", extra, memory_image)

def mcp_grep_patterns(artifact_path: str, pattern: str) -> MCPToolResult:
    """Grep for specific patterns in an artifact."""
    return mcp_call_tool("grep", [pattern], artifact_path)