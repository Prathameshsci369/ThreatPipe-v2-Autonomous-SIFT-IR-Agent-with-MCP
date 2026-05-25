"""
ThreatPipe v2 — Schemas
========================
Sablya Pydantic models ika jaagi. LangGraph state, tool plans,
evidence graph nodes/edges, aani cross-reference results.

Phase 1 : EvidenceNode, InvestigationEdge
Phase 2 : StructuredTrigger, AgentState (core fields)
Phase 3 : AgentState extended — _last_tool, _last_hypothesis,
           _prev_result_summary for self-correction loop
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Literal, Optional
from typing import TypedDict

from pydantic import BaseModel, Field


# ─── Existing schemas ──────────────────────────────────────────────────────────

class ToolPlan(BaseModel):
    """LLM decision: which SIFT tool to run and why."""
    tool_name:  str = Field(..., description="Exact system command name")
    arguments:  str = Field(..., description="All arguments as a single string")
    rationale:  str = Field(..., description="Why this tool proves/disproves the hypothesis")
    hypothesis: str = Field(..., description="What type of artifact is expected")


class CrossReferenceResult(BaseModel):
    """Trigger claim vs tool output comparison result."""
    status:      Literal["MATCH", "MISMATCH", "AMBIGUOUS"]
    explanation: str
    verdict:     Literal["BENIGN", "SUSPICIOUS", "MALICIOUS"] = "BENIGN"
    confidence:  float = Field(ge=0.0, le=1.0)


# ─── Evidence Graph schemas ────────────────────────────────────────────────────

class EvidenceNode(BaseModel):
    node_id:    str
    node_type:  Literal["trigger", "artifact", "tool_execution", "finding"]
    label:      str
    data:       Dict[str, Any] = Field(default_factory=dict)
    created_at: str            = Field(default_factory=lambda: datetime.now().isoformat())
    
    session_id: str            = "default"
    verdict:     Optional[Literal["BENIGN", "SUSPICIOUS", "MALICIOUS"]] = None
    confidence:  Optional[float]                                         = None
    explanation: Optional[str]                                           = None


class InvestigationEdge(BaseModel):
    src_id:     str
    dst_id:     str
    relation:   Literal[
        "triggered_by",
        "analyzed_by",
        "produced",
        "cross_references",
        "re_investigated",
    ]
    created_at: str = Field(default_factory=lambda: datetime.now().isoformat())
    
    meta:       Dict[str, Any] = Field(default_factory=dict)


# ─── Structured Trigger ────────────────────────────────────────────────────────

class StructuredTrigger(BaseModel):
    trigger_type:  Literal["web_log", "mft_entry", "registry_event", "memory_anomaly", "unknown"]
    entity:        str
    src_ip:        Optional[str]      = None
    timestamp_raw: Optional[str]      = None
    timestamp_dt:  Optional[datetime] = None
    http_method:   Optional[str]      = None
    http_status:   Optional[int]      = None
    claim:         str                = ""
    artifact_path: str                = ""
    artifact_type: Literal[
        "php_file", "image", "binary", "script",
        "log_file", "registry_key", "memory_region", "unknown"
    ] = "unknown"
    raw_log:       str = ""


# ─── LangGraph State — Phase 3 ────────────────────────────────────────────────

class AgentState(TypedDict):
    """
    Full state passed between every LangGraph node.

    Phase 3 additions:
      _last_tool            : tool name used in last execute_tool_node run
      _last_hypothesis      : hypothesis string from tool_selector
      _prev_result_summary  : one-line summary of previous cycle result
                              (passed to LLM for context in retry cycles)
    """
    # ── Input ──
    trigger_event:    str

    # ── Pipeline control ──
    current_cycle:    int
    max_cycles:       int
    session_id:       str

    # ── Stage outputs (None until that stage runs) ──
    structured_trigger:    Optional[StructuredTrigger]
    plan:                  Optional[ToolPlan]
    tool_output:           Optional[str]
    analysis:              Optional[CrossReferenceResult]
    final_report:          Optional[str]

    # ── Evidence graph node tracking ──
    trigger_node_id:       Optional[str]
    artifact_node_id:      Optional[str]
    tool_exec_node_id:     Optional[str]

    # ── Phase 3: self-correction context ──
    _last_tool:            Optional[str]   # e.g. "strings", "file"
    _last_hypothesis:      Optional[str]   # passed to cross_reference LLM
    _prev_result_summary:  Optional[str]   # "Cycle 0: MISMATCH BENIGN conf=0.30 — ..."
    _tool_executions:      Optional[list]  # list of tool execution dicts per cycle