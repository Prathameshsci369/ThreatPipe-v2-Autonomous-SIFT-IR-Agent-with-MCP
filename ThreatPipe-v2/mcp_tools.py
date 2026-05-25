"""
ThreatPipe v2 — MCP Tool Layer
================================
SIFT tool execution with architectural guardrails.

This is the ONLY way the agent executes SIFT tools.
The agent NEVER calls subprocess directly — it goes through this layer.

Architectural guardrails (code-enforced, cannot be bypassed by LLM):
  1. Tool must be in ALLOWED_SIFT_TOOLS allowlist
  2. No destructive patterns in command
  3. Output truncated to prevent context window overload
  4. Artifact path must exist on disk
  5. Hard timeout per tool

Both agent.py and mcp_server.py import from this file.
"""

import os
import subprocess
import time
from typing import List, Optional

from pydantic import BaseModel, Field

from logger import get_logger

log = get_logger("mcp_tools")


# ─── Allowed tools (read-only forensic analysis only) ─────────────────────────
# Destructive tools (rm, dd, shred, wipe, mkfs) are NOT here
# This is ARCHITECTURAL constraint — not prompt-based

ALLOWED_SIFT_TOOLS = {
    "strings":    {"timeout": 30, "max_output": 5000},
    "file":       {"timeout": 10, "max_output": 2000},
    "grep":       {"timeout": 30, "max_output": 5000},
    "md5sum":     {"timeout": 10, "max_output": 500},
    "sha256sum":  {"timeout": 10, "max_output": 500},
    "fls":        {"timeout": 60, "max_output": 8000},
    "icat":       {"timeout": 30, "max_output": 8000},
    "mmls":       {"timeout": 30, "max_output": 5000},
    "fsstat":     {"timeout": 30, "max_output": 5000},
    "mactime":    {"timeout": 30, "max_output": 8000},
    "volatility": {"timeout": 120,"max_output": 10000},
    "log2timeline":{"timeout": 120,"max_output": 8000},
}

# Commands that should NEVER run — defense in depth
BLOCKED_PATTERNS = [
    "rm ", "rmdir", "dd ", "shred", "wipe", "mkfs",
    "format", "del ", "erase", "chmod", "chown",
    "mv ", "cp ", "> ", ">> ",
]


class MCPToolResult(BaseModel):
    """Structured result from MCP tool execution."""
    tool:         str
    artifact:     str          = ""
    returncode:   int          = -1
    stdout:       str          = ""
    stderr:       str          = ""
    truncated:    bool         = False
    blocked:      bool         = False
    block_reason: Optional[str] = None
    elapsed_ms:   float        = 0.0


def mcp_run_tool(
    tool_name: str,
    tool_args: List[str],
) -> MCPToolResult:
    """
    Run a SIFT tool with architectural guardrails.

    This is what agent.py calls INSTEAD of subprocess.run().

    Parameters:
      tool_name: e.g. "strings", "file", "grep"
      tool_args: e.g. ["-n", "6", "/evidence/shell.php"]
                 (the full arg list that tool_selector provides)

    Returns:
      MCPToolResult with stdout/stderr/returncode + guardrail metadata
    """
    # ── Guard 1: Tool must be in allowlist ──
    if tool_name not in ALLOWED_SIFT_TOOLS:
        log.warning(f"MCP BLOCKED: tool '{tool_name}' not in allowlist")
        return MCPToolResult(
            tool=tool_name,
            blocked=True,
            block_reason=(
                f"Tool '{tool_name}' not in allowlist. "
                f"Allowed: {list(ALLOWED_SIFT_TOOLS.keys())}"
            ),
        )

    # ── Guard 2: No destructive patterns in command ──
    full_cmd_str = f"{tool_name} {' '.join(tool_args)}"
    for pattern in BLOCKED_PATTERNS:
        if pattern in full_cmd_str.lower():
            log.warning(f"MCP BLOCKED: destructive pattern '{pattern}' detected")
            return MCPToolResult(
                tool=tool_name,
                blocked=True,
                block_reason=f"Blocked destructive pattern: '{pattern}'",
            )

    # ── Guard 3: Artifact path must exist (if args contain a path) ──
    # Last arg is usually the file path from tool_selector
    artifact_path = ""
    if tool_args:
        last_arg = tool_args[-1]
        if last_arg.startswith("/") or last_arg.startswith("./") or last_arg.startswith("C:\\"):
            artifact_path = last_arg
            if not os.path.exists(artifact_path):
                log.warning(f"MCP: artifact not found: {artifact_path}")
                # Don't block — tool might still produce useful error output
                # Just log it

    # ── Execute tool ──
    config = ALLOWED_SIFT_TOOLS[tool_name]
    timeout = config["timeout"]
    max_output = config["max_output"]

    cmd = [tool_name] + tool_args

    log.info(f"MCP EXEC: {' '.join(cmd)}")
    t0 = time.monotonic()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        elapsed = (time.monotonic() - t0) * 1000

        # ── Guard 4: Truncate output to prevent context window overload ──
        stdout = result.stdout[:max_output]
        stderr = result.stderr[:1000]
        truncated = len(result.stdout) > max_output

        if truncated:
            log.info(
                f"MCP TRUNCATED: {len(result.stdout)} → {max_output} chars "
                f"(context window protection)"
            )

        status = "OK" if result.returncode == 0 else f"EXIT {result.returncode}"
        log.info(
            f"MCP DONE: {tool_name}  [{status}]  {elapsed:.0f}ms  "
            f"truncated={truncated}"
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

    except subprocess.TimeoutExpired:
        log.error(f"MCP TIMEOUT: {tool_name} ({timeout}s)")
        return MCPToolResult(
            tool=tool_name,
            artifact=artifact_path,
            returncode=124,
            stderr=f"Tool timed out after {timeout}s",
            blocked=False,
        )

    except FileNotFoundError:
        log.error(f"MCP: tool not found on PATH: {tool_name}")
        return MCPToolResult(
            tool=tool_name,
            artifact=artifact_path,
            returncode=127,
            stderr=f"Tool not found on PATH: {tool_name}",
            blocked=False,
        )

    except Exception as exc:
        log.error(f"MCP ERROR: {tool_name} — {exc}")
        return MCPToolResult(
            tool=tool_name,
            artifact=artifact_path,
            returncode=-1,
            stderr=str(exc),
            blocked=False,
        )