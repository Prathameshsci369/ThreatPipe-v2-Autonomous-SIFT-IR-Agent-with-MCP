"""
ThreatPipe v2 — Agent (Phase 3)
=================================
5-node LangGraph pipeline + self-correction loop.

Pipeline:
  [1] parse_trigger_node     → raw log → StructuredTrigger (no LLM)
  [2] locate_artifact_node   → confirm artifact exists on disk (no LLM)
  [3] execute_tool_node      → run SIFT tool via subprocess (no LLM)
  [4] cross_reference_node   → 4-lens LLM reasoning → MATCH/MISMATCH/AMBIGUOUS
  [5] confirm_verdict_node   → write final finding node to graph

Phase 3 additions:
  - should_retry() conditional edge:
      MATCH + confidence >= threshold   → confirm_verdict (done)
      MISMATCH / AMBIGUOUS              → execute_tool (cycle+1, alternate tool)
      cycle >= max_cycles               → confirm_verdict (forced stop)
  - 4-lens LLM prompts:
      Lens 1 — Hacker   : what would attacker do with this file?
      Lens 2 — Temporal : does file timestamp align with trigger?
      Lens 3 — Kill Chain: where does this fit in ATT&CK kill chain?
      Lens 4 — Analyst  : cross-ref all evidence, final verdict
  - re_investigated edge written to graph on every retry cycle
  - Cycle counter incremented in state before re-route
"""

import os
import re
import subprocess
import time
from datetime import datetime, timezone
from typing import Literal

from langchain_core.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END

from logger import (
    get_logger, log_stage, log_tool_call, log_tool_result,
    log_llm_request, log_cross_ref, log_verdict, log_graph_op,
    log_exception, log_session_end,
)
from schemas import (
    AgentState, StructuredTrigger, CrossReferenceResult,
    EvidenceNode, InvestigationEdge,
)
from config import (
    get_llm, get_db_path, get_max_cycles,
    get_confidence_threshold, token_manager,
)
from trigger_parser import parse_trigger
from tool_selector import select_tool, ToolSelection
from evidence_graph import EvidenceGraph

log = get_logger(__name__)

# ─── LLM setup ────────────────────────────────────────────────────────────────
llm            = get_llm()
structured_llm = llm.with_structured_output(CrossReferenceResult)

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _get_graph(state: AgentState) -> EvidenceGraph:
    return EvidenceGraph(db_path=get_db_path(), session_id=state["session_id"])


def _slug(text: str, max_len: int = 30) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_\-]", "_", text)
    return slug[:max_len].strip("_").lower()


# ══════════════════════════════════════════════════════════════════════════════
# NODE 1 — parse_trigger_node
# ══════════════════════════════════════════════════════════════════════════════

def parse_trigger_node(state: AgentState) -> dict:
    log_stage(log, 1, "Trigger Parse", {"raw_log": state["trigger_event"][:100]})

    trigger: StructuredTrigger = parse_trigger(state["trigger_event"])

    log.info(
        f"Parsed trigger: type={trigger.trigger_type}  "
        f"entity={trigger.entity}  artifact_type={trigger.artifact_type}"
    )
    log.debug(f"  claim         : {trigger.claim}")
    log.debug(f"  artifact_path : {trigger.artifact_path}")
    log.debug(f"  src_ip        : {trigger.src_ip}")
    log.debug(f"  http_method   : {trigger.http_method}  status={trigger.http_status}")

    node_id = f"trigger:{_slug(trigger.entity)}_{state['session_id'][-6:]}"

    with _get_graph(state) as g:
        g.add_node(EvidenceNode(
            node_id    = node_id,
            node_type  = "trigger",
            label      = trigger.entity,
            data       = {
                "raw_log":       trigger.raw_log,
                "trigger_type":  trigger.trigger_type,
                "src_ip":        trigger.src_ip,
                "timestamp_raw": trigger.timestamp_raw,
                "http_method":   trigger.http_method,
                "http_status":   trigger.http_status,
                "claim":         trigger.claim,
                "artifact_type": trigger.artifact_type,
                "artifact_path": trigger.artifact_path,
            },
            session_id = state["session_id"],
        ))
        log_graph_op(log, "WRITE", node_id=node_id, attrs={"stage": "parse_trigger"})

    return {
        "structured_trigger": trigger,
        "trigger_node_id":    node_id,
    }


# ══════════════════════════════════════════════════════════════════════════════
# NODE 2 — locate_artifact_node
# ══════════════════════════════════════════════════════════════════════════════

def locate_artifact_node(state: AgentState) -> dict:
    log_stage(log, 2, "Artifact Locate")

    trigger: StructuredTrigger = state["structured_trigger"]
    art_path = trigger.artifact_path

    log.info(f"Locating artifact: {art_path}")

    skip_disk_check = trigger.trigger_type in ("registry_event", "memory_anomaly")
    exists, size_bytes, permissions, missing_reason = False, 0, "", ""

    if skip_disk_check:
        log.info(f"  skipping disk check — trigger_type={trigger.trigger_type}")
        exists = True
    else:
        exists = os.path.exists(art_path)
        if exists:
            try:
                stat        = os.stat(art_path)
                size_bytes  = stat.st_size
                permissions = oct(stat.st_mode)
                log.info(f"  ✓ found  size={size_bytes}B  perms={permissions}")
            except Exception as exc:
                log_exception(log, "locate_artifact stat", exc)
        else:
            missing_reason = f"File not found on disk: {art_path}"
            log.warning(f"  ✗ {missing_reason}")

    node_id = f"artifact:{_slug(trigger.entity)}_{state['session_id'][-6:]}"

    with _get_graph(state) as g:
        g.add_node(EvidenceNode(
            node_id    = node_id,
            node_type  = "artifact",
            label      = os.path.basename(art_path) or trigger.entity,
            data       = {
                "artifact_path":  art_path,
                "artifact_type":  trigger.artifact_type,
                "exists_on_disk": exists,
                "size_bytes":     size_bytes,
                "permissions":    permissions,
                "missing_reason": missing_reason,
            },
            session_id = state["session_id"],
        ))
        if state.get("trigger_node_id"):
            g.add_edge(InvestigationEdge(
                src_id   = node_id,
                dst_id   = state["trigger_node_id"],
                relation = "triggered_by",
            ))
        log_graph_op(log, "WRITE", node_id=node_id, attrs={"exists": exists})

    return {"artifact_node_id": node_id}


# ══════════════════════════════════════════════════════════════════════════════
# NODE 3 — execute_tool_node
# ══════════════════════════════════════════════════════════════════════════════

def execute_tool_node(state: AgentState) -> dict:
    cycle = state["current_cycle"]
    log_stage(log, 3, "Tool Execution", {"cycle": cycle})

    trigger: StructuredTrigger = state["structured_trigger"]
    selection: ToolSelection   = select_tool(trigger, cycle=cycle)

    # ── Print full tool selection detail — visible on console ──────────────
    log.info("── TOOL SELECTED ────────────────────────────────────────────")
    log.info(f"  tool      : {selection.tool_name}")
    log.info(f"  args      : {' '.join(selection.args)}")
    log.info(f"  category  : {selection.category}")
    log.info(f"  rationale : {selection.rationale}")
    log.info(f"  hypothesis: {selection.hypothesis}")
    log.info(f"  fallbacks : {[f.tool_name for f in selection.fallbacks]}")
    log.info("────────────────────────────────────────────────────────────")
    log_tool_call(log, selection.tool_name, selection.args)

    t0 = time.monotonic()
    stdout, stderr, returncode = "", "", -1

        # ── Route through MCP tool layer for architectural guardrails ──
    from mcp_tools import mcp_run_tool

    mcp_result = mcp_run_tool(
        tool_name = selection.tool_name,
        tool_args = selection.args,
    )

    if mcp_result.blocked:
        log.warning(f"  ✗ MCP BLOCKED: {mcp_result.block_reason}")
        stderr     = mcp_result.block_reason
        returncode = -1
        stdout     = ""
    else:
        stdout     = mcp_result.stdout
        stderr     = mcp_result.stderr
        returncode = mcp_result.returncode
        if mcp_result.truncated:
            log.info(f"  ⚠ output truncated by MCP (context window protection)")

    elapsed_ms  = (time.monotonic() - t0) * 1000
    tool_output = stdout if stdout.strip() else stderr

    log_tool_result(log, selection.tool_name, returncode, stdout, stderr, elapsed_ms)

    # ── node_id includes cycle number so each retry gets its own node ──
    node_id = (
        f"tool_exec:{selection.tool_name}_"
        f"c{cycle}_{state['session_id'][-6:]}"
    )

    with _get_graph(state) as g:
        g.add_node(EvidenceNode(
            node_id    = node_id,
            node_type  = "tool_execution",
            label      = f"{selection.tool_name} (cycle {cycle})",
            data       = {
                "tool_name":   selection.tool_name,
                "tool_path":   selection.tool_path,
                "args":        selection.args,
                "category":    selection.category,
                "rationale":   selection.rationale,
                "hypothesis":  selection.hypothesis,
                "returncode":  returncode,
                "stdout":      stdout,
                "stderr":      stderr,
                "elapsed_ms":  round(elapsed_ms, 2),
                "output_bytes": len(tool_output),
                "cycle":       cycle,
            },
            session_id = state["session_id"],
        ))

        # artifact → analyzed_by → tool_exec
        if state.get("artifact_node_id"):
            g.add_edge(InvestigationEdge(
                src_id   = state["artifact_node_id"],
                dst_id   = node_id,
                relation = "analyzed_by",
                meta     = {"cycle": cycle, "tool": selection.tool_name},
            ))

        # Phase 3: if this is a retry, link previous tool_exec → re_investigated → this
        if cycle > 0 and state.get("tool_exec_node_id"):
            prev_node_id = state["tool_exec_node_id"]
            g.add_edge(InvestigationEdge(
                src_id   = prev_node_id,
                dst_id   = node_id,
                relation = "re_investigated",
                meta     = {"reason": "MISMATCH_or_AMBIGUOUS", "cycle": cycle},
            ))
            log.info(
                f"  RETRY EDGE: {prev_node_id} ──[re_investigated]──▶ {node_id}"
            )

        log_graph_op(log, "WRITE", node_id=node_id,
                     attrs={"returncode": returncode, "cycle": cycle})

    # Accumulate tool executions for _print_result display
    prev_executions = state.get("_tool_executions") or []
    this_execution  = {
        "tool":        selection.tool_name,
        "args":        selection.args,
        "category":    selection.category,
        "rationale":   selection.rationale,
        "hypothesis":  selection.hypothesis,
        "returncode":  returncode,
        "stdout":      stdout,
        "stderr":      stderr,
        "elapsed_ms":  round(elapsed_ms, 2),
        "cycle":       cycle,
    }

    return {
        "tool_output":       tool_output,
        "tool_exec_node_id": node_id,
        "_last_hypothesis":  selection.hypothesis,
        "_last_tool":        selection.tool_name,
        "_tool_executions":  prev_executions + [this_execution],
    }


# ══════════════════════════════════════════════════════════════════════════════
# NODE 4 — cross_reference_node  (Phase 3: 4-lens reasoning)
# ══════════════════════════════════════════════════════════════════════════════

# ── Lens prompts ──────────────────────────────────────────────────────────────

_LENS_HACKER = """
LENS 1 — HACKER PERSPECTIVE:
From an attacker's viewpoint, how would this file/artifact be weaponized?
Does the tool output show signs of: web shells, reverse shells, C2 beacons,
persistence mechanisms, data exfiltration, lateral movement?
Be specific about what strings/functions indicate attacker intent.
"""

_LENS_TEMPORAL = """
LENS 2 — TEMPORAL PERSPECTIVE:
Does the file timestamp align with the trigger event time?
Is the file size anomalous (too small for claimed type, too large)?
Do the file permissions suggest it was placed deliberately?
If timestamp or size info is missing, state that explicitly.
"""

_LENS_KILLCHAIN = """
LENS 3 — KILL CHAIN / ATT&CK:
Which MITRE ATT&CK technique does this artifact most likely represent?
Options: T1505.003 (Web Shell), T1059 (Command Execution), T1055 (Process Injection),
T1547 (Boot Persistence), T1041 (Exfiltration), T1027 (Obfuscation), other.
State the technique ID and name. One sentence rationale.
"""

_LENS_ANALYST = """
LENS 4 — ANALYST SYNTHESIS:
Combining all lenses above and the tool output:
1. Status: MATCH / MISMATCH / AMBIGUOUS
2. Verdict: BENIGN / SUSPICIOUS / MALICIOUS
3. Confidence: 0.0 to 1.0
4. One sentence explanation.

Important rules:
- MALICIOUS if any of: system(), exec(), passthru(), popen(), base64_decode()
  found in PHP; PHP code found inside image binary; C2 URLs or shellcode in memory dump.
- SUSPICIOUS if: PHP file with no execution functions; anomalous permissions; 
  file type mismatch without clear payload.
- BENIGN if: file matches expected type with no attack strings.
- AMBIGUOUS if: tool output incomplete — request another tool on next cycle.
- If tool returned error/not found: MISMATCH, BENIGN, confidence=0.3.
"""

_CROSS_REF_SYSTEM = f"""
You are a SIFT forensic analyst performing incident response.
You apply four analytical lenses before giving a verdict.

{_LENS_HACKER}
{_LENS_TEMPORAL}
{_LENS_KILLCHAIN}
{_LENS_ANALYST}
"""

_CROSS_REF_HUMAN = """
Trigger claim : {claim}
Trigger type  : {trigger_type}
Artifact type : {artifact_type}
Artifact path : {artifact_path}
Cycle         : {cycle} of {max_cycles}
Tool used     : {tool_name}
Hypothesis    : {hypothesis}

Tool output:
{tool_output}

Previous cycle result (if any): {prev_result}
"""


# ─── Sensitive path detection helpers ────────────────────────────────────────
# File disk var nahi + HTTP 200 + sensitive path = attacker ne access keli hoti
# Recon indicator: T1083 (File Discovery) / T1552 (Credentials in Files)

_SENSITIVE_PATHS = [
    ".env", ".git", "wp-config", "config.php",
    "/etc/passwd", "/etc/shadow", "id_rsa", ".ssh",
    ".htaccess", "database.yml", "secrets", "credentials",
    "backup", ".bak", "dump.sql", "db.sql",
    "phpinfo", "phpmyadmin", "adminer",
]

def _is_sensitive_path(entity: str) -> bool:
    """Check if accessed path is a known sensitive/recon target."""
    e = entity.lower()
    return any(s in e for s in _SENSITIVE_PATHS)

def _tool_returned_not_found(tool_output: str) -> bool:
    """Check if tool output indicates file was not found on disk."""
    indicators = [
        "no such file",
        "cannot open",
        "no such file or directory",
        "not found",
        "does not exist",
    ]
    out_lower = tool_output.lower()
    return any(i in out_lower for i in indicators)


def cross_reference_node(state: AgentState) -> dict:
    """
    Stage 4: 4-lens LLM reasoning + sensitive path fast-path.

    Fast-path logic:
      file not on disk  +  sensitive path  +  HTTP 200
      → SUSPICIOUS immediately (no LLM, no wasted cycles)
      Reason: attacker accessed it (200 = success), file later deleted/moved.

    Normal path:
      4-lens LLM: Hacker / Temporal / Kill Chain / Analyst
    """
    cycle = state["current_cycle"]
    log_stage(log, 4, "Cross Reference (4-lens)", {"cycle": cycle})

    trigger: StructuredTrigger = state["structured_trigger"]
    tool_output = state.get("tool_output", "")
    tool_name   = state.get("_last_tool", "unknown")
    hypothesis  = state.get("_last_hypothesis", "unknown")
    prev_result = state.get("_prev_result_summary", "none — first cycle")
    max_cycles  = state.get("max_cycles", get_max_cycles())

    # ── Fast-path: sensitive path + file not found + HTTP 200 ────────────────
    if (
        _tool_returned_not_found(tool_output)
        and _is_sensitive_path(trigger.entity)
        and trigger.http_status == 200
    ):
        explanation = (
            f"Sensitive path '{trigger.entity}' returned HTTP 200 but file not "
            f"present on disk — possible exfiltration, cleanup, or served from "
            f"different location. Recon indicator: T1083 / T1552."
        )
        log.info(f"FAST-PATH  sensitive={trigger.entity}  http={trigger.http_status}  → SUSPICIOUS")
        log.info(f"  {explanation}")

        analysis = CrossReferenceResult(
            status      = "MATCH",
            explanation = explanation,
            verdict     = "SUSPICIOUS",
            confidence  = 0.80,
        )
        log_cross_ref(
            log,
            trigger_claim       = trigger.claim,
            tool_output_summary = tool_output[:200],
            result              = analysis.status,
            confidence          = analysis.confidence,
            explanation         = analysis.explanation,
        )
        prev_summary = (
            f"Cycle {cycle}: tool={tool_name} status=MATCH "
            f"verdict=SUSPICIOUS conf=0.80 — {explanation}"
        )
        return {"analysis": analysis, "_prev_result_summary": prev_summary}

    # ── Normal path: 4-lens LLM ───────────────────────────────────────────────
    output_for_llm = tool_output[:2000]
    if len(tool_output) > 2000:
        log.debug(f"  tool_output truncated: {len(tool_output)} → 2000 chars")

    log.info(
        f"4-lens analysis  tool={tool_name}  cycle={cycle}  "
        f"prev_result={prev_result[:60] if prev_result else 'none'}"
    )
    log.debug(f"  hypothesis    : {hypothesis}")
    log.debug(f"  trigger.claim : {trigger.claim}")

    log_llm_request(
        log,
        model          = "mistral-small-latest",
        prompt_preview = (
            f"claim={trigger.claim[:100]} | "
            f"tool={tool_name} | "
            f"output={output_for_llm[:200]}"
        ),
        token_estimate = (len(_CROSS_REF_SYSTEM) + len(output_for_llm)) // 4,
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", _CROSS_REF_SYSTEM),
        ("human",  _CROSS_REF_HUMAN),
    ])
    chain = prompt | structured_llm

    try:
        analysis: CrossReferenceResult = chain.invoke({
            "claim":         trigger.claim,
            "trigger_type":  trigger.trigger_type,
            "artifact_type": trigger.artifact_type,
            "artifact_path": trigger.artifact_path,
            "cycle":         cycle,
            "max_cycles":    max_cycles,
            "tool_name":     tool_name,
            "hypothesis":    hypothesis,
            "tool_output":   output_for_llm,
            "prev_result":   prev_result,
        })
        log.info(
            f"LLM cross-ref: status={analysis.status}  "
            f"verdict={analysis.verdict}  "
            f"confidence={analysis.confidence:.2f}"
        )
        log.debug(f"  explanation: {analysis.explanation}")

    except Exception as exc:
        log_exception(log, "cross_reference_node LLM", exc)
        analysis = CrossReferenceResult(
            status      = "AMBIGUOUS",
            explanation = f"LLM call failed: {exc}",
            verdict     = "SUSPICIOUS",
            confidence  = 0.3,
        )

    log_cross_ref(
        log,
        trigger_claim       = trigger.claim,
        tool_output_summary = tool_output[:200],
        result              = analysis.status,
        confidence          = analysis.confidence,
        explanation         = analysis.explanation,
    )

    prev_summary = (
        f"Cycle {cycle}: tool={tool_name} status={analysis.status} "
        f"verdict={analysis.verdict} conf={analysis.confidence:.2f} "
        f"— {analysis.explanation}"
    )
    return {
        "analysis":             analysis,
        "_prev_result_summary": prev_summary,
    }


# ══════════════════════════════════════════════════════════════════════════════
# CONDITIONAL EDGE — should_retry
# ══════════════════════════════════════════════════════════════════════════════

def should_retry(state: AgentState) -> Literal["retry", "done"]:
    """
    Phase 3 routing logic — called after cross_reference_node.

    retry → execute_tool_node (cycle+1, alternate tool)
    done  → confirm_verdict_node

    Retry conditions:
      - status is MISMATCH or AMBIGUOUS
      - AND current_cycle < max_cycles - 1
      - AND confidence < threshold (high confidence MISMATCH still retries
        — e.g. file not found, try alternate path)

    Force done conditions:
      - status is MATCH
      - OR cycle limit reached
      - OR verdict is MALICIOUS with confidence >= threshold (no need to retry)
    """
    analysis   = state.get("analysis")
    cycle      = state["current_cycle"]
    max_cycles = state.get("max_cycles", get_max_cycles())
    threshold  = get_confidence_threshold()

    if analysis is None:
        log.warning("should_retry: no analysis found — forcing done")
        return "done"

    status     = analysis.status
    verdict    = analysis.verdict
    confidence = analysis.confidence

    log.info(
        f"ROUTING CHECK  status={status}  verdict={verdict}  "
        f"conf={confidence:.2f}  cycle={cycle}/{max_cycles-1}"
    )

    # Always stop if cycle limit hit
    if cycle >= max_cycles - 1:
        log.info(f"  → done (cycle limit reached: {cycle}/{max_cycles-1})")
        return "done"

    # MALICIOUS with high confidence — no need to retry
    if verdict == "MALICIOUS" and confidence >= threshold:
        log.info(f"  → done (MALICIOUS with high confidence {confidence:.2f})")
        return "done"

    # MATCH with decent confidence — done
    if status == "MATCH" and confidence >= threshold:
        log.info(f"  → done (MATCH confidence={confidence:.2f} >= {threshold})")
        return "done"

    # MISMATCH or AMBIGUOUS — retry with next tool
    if status in ("MISMATCH", "AMBIGUOUS"):
        log.info(
            f"  → RETRY  (status={status}  confidence={confidence:.2f} < {threshold}  "
            f"cycle {cycle} → {cycle+1})"
        )
        return "retry"

    # MATCH but low confidence — retry
    if status == "MATCH" and confidence < threshold:
        log.info(
            f"  → RETRY  (MATCH but low confidence={confidence:.2f} < {threshold})"
        )
        return "retry"

    log.info(f"  → done (default)")
    return "done"


def increment_cycle_node(state: AgentState) -> dict:
    """
    Thin node between should_retry and execute_tool.
    Increments current_cycle before re-running execute_tool_node.
    Also logs the retry decision to evidence graph.
    """
    new_cycle = state["current_cycle"] + 1
    log.info(
        f"SELF-CORRECTION  cycle {state['current_cycle']} → {new_cycle}  "
        f"reason: {state.get('analysis').status if state.get('analysis') else 'unknown'}"
    )

    # Log re_investigation event to graph
    with _get_graph(state) as g:
        retry_node_id = (
            f"retry:c{new_cycle}_{state['session_id'][-6:]}"
        )
        g.add_node(EvidenceNode(
            node_id    = retry_node_id,
            node_type  = "tool_execution",
            label      = f"Self-correction cycle {new_cycle}",
            data       = {
                "event":       "self_correction",
                "prev_cycle":  state["current_cycle"],
                "new_cycle":   new_cycle,
                "prev_status": state.get("analysis").status if state.get("analysis") else "?",
                "prev_verdict":state.get("analysis").verdict if state.get("analysis") else "?",
                "reason":      "MISMATCH_or_AMBIGUOUS — trying alternate tool",
            },
            session_id = state["session_id"],
        ))
        log_graph_op(log, "WRITE", node_id=retry_node_id,
                     attrs={"event": "self_correction", "new_cycle": new_cycle})

    return {"current_cycle": new_cycle}


# ══════════════════════════════════════════════════════════════════════════════
# NODE 5 — confirm_verdict_node
# ══════════════════════════════════════════════════════════════════════════════

def confirm_verdict_node(state: AgentState) -> dict:
    log_stage(log, 5, "Confirm Verdict")

    trigger:  StructuredTrigger    = state["structured_trigger"]
    analysis: CrossReferenceResult = state["analysis"]
    cycle = state["current_cycle"]

    log_verdict(
        log,
        verdict     = analysis.verdict,
        confidence  = analysis.confidence,
        explanation = analysis.explanation,
        cycle       = cycle,
    )

    node_id = f"finding:{_slug(trigger.entity)}_{state['session_id'][-6:]}"

    with _get_graph(state) as g:
        g.add_node(EvidenceNode(
            node_id     = node_id,
            node_type   = "finding",
            label       = f"{analysis.verdict}: {trigger.entity}",
            data        = {
                "trigger_claim":     trigger.claim,
                "tool_output_bytes": len(state.get("tool_output", "")),
                "cross_ref_status":  analysis.status,
                "cycles_taken":      cycle + 1,
                "prev_cycle_summary": state.get("_prev_result_summary", ""),
            },
            verdict     = analysis.verdict,
            confidence  = analysis.confidence,
            explanation = analysis.explanation,
            session_id  = state["session_id"],
        ))

        if state.get("tool_exec_node_id"):
            g.add_edge(InvestigationEdge(
                src_id   = state["tool_exec_node_id"],
                dst_id   = node_id,
                relation = "produced",
            ))
        if state.get("trigger_node_id"):
            g.add_edge(InvestigationEdge(
                src_id   = node_id,
                dst_id   = state["trigger_node_id"],
                relation = "cross_references",
            ))

        log_graph_op(log, "WRITE", node_id=node_id,
                     attrs={"verdict": analysis.verdict, "cycles": cycle + 1})

        g.dump_graph()
        summary = g.get_session_summary()
        log.info(f"Session summary: {summary}")

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    report = (
        f"ThreatPipe v2 — Investigation Report\n"
        f"{'='*52}\n"
        f"Timestamp   : {ts}\n"
        f"Session     : {state['session_id']}\n"
        f"Trigger     : {state['trigger_event']}\n"
        f"Entity      : {trigger.entity}\n"
        f"Artifact    : {trigger.artifact_path}\n"
        f"Type        : {trigger.artifact_type}\n"
        f"Claim       : {trigger.claim}\n"
        f"{'─'*52}\n"
        f"Verdict     : {analysis.verdict}\n"
        f"Confidence  : {analysis.confidence:.2f}\n"
        f"Status      : {analysis.status}\n"
        f"Cycles used : {cycle + 1} / {state.get('max_cycles', get_max_cycles())}\n"
        f"Explanation : {analysis.explanation}\n"
    )

    if cycle > 0:
        report += f"Retry history: {state.get('_prev_result_summary', '')}\n"

    report += (
        f"{'─'*52}\n"
        f"Token cost  : ${token_manager.total_cost:.6f}\n"
        f"{'='*52}\n"
    )

    log_session_end(
        log,
        total_cycles = cycle + 1,
        verdict      = analysis.verdict,
        total_cost   = token_manager.total_cost,
    )

    return {"final_report": report}


# ══════════════════════════════════════════════════════════════════════════════
# GRAPH ASSEMBLY — Phase 3
# ══════════════════════════════════════════════════════════════════════════════

workflow = StateGraph(AgentState)

workflow.add_node("parse_trigger",    parse_trigger_node)
workflow.add_node("locate_artifact",  locate_artifact_node)
workflow.add_node("execute_tool",     execute_tool_node)
workflow.add_node("cross_reference",  cross_reference_node)
workflow.add_node("increment_cycle",  increment_cycle_node)   # Phase 3 new
workflow.add_node("confirm_verdict",  confirm_verdict_node)

workflow.set_entry_point("parse_trigger")

workflow.add_edge("parse_trigger",   "locate_artifact")
workflow.add_edge("locate_artifact", "execute_tool")
workflow.add_edge("execute_tool",    "cross_reference")

# Phase 3 conditional edge — MISMATCH/AMBIGUOUS → retry, MATCH → done
workflow.add_conditional_edges(
    "cross_reference",
    should_retry,
    {
        "retry": "increment_cycle",
        "done":  "confirm_verdict",
    },
)

# After cycle increment → back to execute_tool with new cycle number
workflow.add_edge("increment_cycle", "execute_tool")
workflow.add_edge("confirm_verdict", END)

app = workflow.compile()

log.info("LangGraph pipeline compiled — Phase 3 (self-correction loop active)")