"""
ThreatPipe v2 — Mindset Analyzer
==================================
LLM uses the Hacker Mindset Graph state to:
  1. Predict next likely attack stage per IP
  2. Generate actionable alerts for the SOC team
  3. Summarize overall attack campaign across all IPs

Called after every investigation batch completes.

Input:  HackerMindsetGraph state
Output: AlertReport (console + log file)
"""

import os
from datetime import datetime, timezone
from typing import List, Optional

from langchain_core.prompts import ChatPromptTemplate
from langchain_mistralai import ChatMistralAI
from pydantic import BaseModel, Field

from logger import get_logger, log_llm_request, log_exception
from config import CONFIG, token_manager
from hacker_mindset_graph import HackerMindsetGraph, STAGE_RISK, STAGE_PROGRESSION

log = get_logger("mindset_analyzer")

# ─── ANSI colors ──────────────────────────────────────────────────────────────
RED    = "\033[91m"; YELLOW = "\033[93m"; GREEN  = "\033[92m"
CYAN   = "\033[96m"; BOLD   = "\033[1m";  DIM    = "\033[2m"; RESET  = "\033[0m"


# ─── LLM output schema ────────────────────────────────────────────────────────

class IPAlert(BaseModel):
    src_ip:          str   = Field(..., description="Source IP address")
    current_stage:   str   = Field(..., description="Current attack stage")
    predicted_next:  str   = Field(..., description="Predicted next stage")
    threat_level:    str   = Field(..., description="CRITICAL/HIGH/MEDIUM/LOW")
    mitre_technique: str   = Field(..., description="Most likely MITRE ATT&CK technique ID and name")
    recommended_action: str = Field(..., description="Specific action for SOC team — one sentence")
    is_red_zone:     bool  = Field(..., description="True if IP should be blocked immediately")


class CampaignAnalysis(BaseModel):
    """Overall campaign analysis across all active IPs."""
    campaign_type:    str        = Field(..., description="Type of campaign: targeted/opportunistic/apt/botnet")
    active_ips:       int        = Field(..., description="Number of active attacker IPs")
    highest_stage:    str        = Field(..., description="Highest attack stage reached across all IPs")
    primary_vector:   str        = Field(..., description="Primary attack vector being used")
    kill_chain_stage: str        = Field(..., description="Overall kill chain position of the campaign")
    summary:          str        = Field(..., description="2-3 sentence campaign summary for SOC team")
    ip_alerts:        List[IPAlert] = Field(default_factory=list)
    immediate_actions: List[str] = Field(default_factory=list, description="Top 3 immediate actions for SOC team")


# ─── LLM prompts ──────────────────────────────────────────────────────────────

_ANALYZER_SYSTEM = """
You are a senior SOC analyst and threat intelligence expert performing
real-time attacker behavior analysis.

You receive a structured summary of the Hacker Mindset Graph — showing
which IPs are at which attack stages, what they have done, and forensic
verdicts from SIFT tool analysis.

Your job:
1. For each active IP: predict next attack stage and recommend action
2. Analyze the overall campaign: type, severity, kill chain position
3. Generate immediate actionable alerts — specific, not generic

MITRE ATT&CK reference:
  RECON    → T1592 (Gather Victim Host Info), T1589, T1598
  SCAN     → T1595 (Active Scanning), T1190 (Exploit Public-Facing App)
  EXPLOIT  → T1190, T1059 (Command Execution), T1055 (Process Injection)
  UPLOAD   → T1505.003 (Web Shell), T1027 (Obfuscated Files)
  BACKDOOR → T1505.003 (Web Shell), T1059.004 (Unix Shell)
  PERSIST  → T1547 (Boot Autostart), T1053 (Scheduled Task), T1098 (Account Manipulation)
  EXFIL    → T1041 (Exfiltration Over C2), T1083 (File Discovery), T1552 (Credentials)
  LATERAL  → T1021 (Remote Services), T1534 (Internal Spearphishing)

Rules:
- Be specific about recommended actions (block IP, check file X, monitor port Y)
- Mark IPs as red_zone=true if they are at BACKDOOR/PERSIST/EXFIL/LATERAL
- Campaign type: "targeted" if few IPs deep in kill chain, "opportunistic" if many IPs at RECON/SCAN
- Keep recommended_action to ONE clear sentence per IP
"""

_ANALYZER_HUMAN = """
HACKER MINDSET GRAPH STATE
===========================
Total active IPs: {total_ips}
Graph transitions recorded: {total_transitions}
Investigation timestamp: {timestamp}

STAGE OVERVIEW:
{stage_overview}

ACTIVE IP PROFILES:
{ip_profiles}

RED ZONE IPs (immediate threat):
{red_zone_ips}

FORENSIC VERDICTS FROM SIFT ANALYSIS:
{forensic_summary}

Analyze this attack campaign and generate alerts.
"""


# ─── Main analyzer ────────────────────────────────────────────────────────────

def _get_llm() -> ChatMistralAI:
    api_key = os.getenv("MISTRAL_API_KEY")
    if not api_key:
        raise ValueError("MISTRAL_API_KEY not set")
    return ChatMistralAI(
        model       = CONFIG.get("llm", {}).get("model", "mistral-small-latest"),
        api_key     = api_key,
        temperature = 0.1,
        max_tokens  = 2000,
        callbacks   = [token_manager],
    )


def _format_stage_overview(graph: HackerMindsetGraph) -> str:
    """Format stage summary for LLM prompt."""
    summary = graph.get_stage_summary()
    lines   = []
    for stage in STAGE_PROGRESSION:
        info = summary.get(stage, {})
        hits = info.get("total_hits", 0)
        ips  = info.get("active_ips", [])
        risk = STAGE_RISK.get(stage, "?")
        if hits > 0:
            lines.append(
                f"  {stage:<10} [{risk:<8}]  hits={hits}  "
                f"IPs: {', '.join(ips[:5])}"
                + ("..." if len(ips) > 5 else "")
            )
    return "\n".join(lines) if lines else "  No activity recorded yet"


def _format_ip_profiles(graph: HackerMindsetGraph) -> str:
    """Format top 10 highest-risk IP profiles for LLM."""
    rows = graph._conn.execute("""
        SELECT * FROM ip_profiles
        ORDER BY risk_score DESC
        LIMIT 10
    """).fetchall()

    if not rows:
        return "  No IP profiles recorded yet"

    import json
    lines = []
    for row in rows:
        history = json.loads(row["stage_history"])
        lines.append(
            f"  IP: {row['src_ip']:<18} "
            f"stage={row['current_stage']:<10} "
            f"risk={row['risk_score']:.2f}  "
            f"threat={row['threat_level']:<8} "
            f"path={' → '.join(history)}"
        )
    return "\n".join(lines)


def _format_red_zone(graph: HackerMindsetGraph) -> str:
    """Format red zone IPs."""
    red = graph.get_red_zone_ips()
    if not red:
        return "  None currently"
    lines = []
    for ip in red[:5]:
        lines.append(
            f"  🔴 {ip['src_ip']:<18} "
            f"stage={ip['current_stage']:<10} "
            f"reason={ip['red_zone_reason']}"
        )
    return "\n".join(lines)


def _format_forensic_summary(forensic_results: List[dict]) -> str:
    """Format recent forensic results from agent pipeline."""
    if not forensic_results:
        return "  No forensic results provided"
    lines = []
    for r in forensic_results[-10:]:  # last 10
        lines.append(
            f"  {r.get('src_ip','?'):<18} "
            f"entity={r.get('entity','?'):<25} "
            f"verdict={r.get('verdict','?'):<10} "
            f"conf={r.get('confidence',0):.2f}"
        )
    return "\n".join(lines)


def _print_alert_report(analysis: CampaignAnalysis):
    """Print formatted alert report to console."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    print(f"\n{'═'*65}")
    print(f"  {BOLD}{RED}⚠  THREATPIPE MINDSET ALERT REPORT{RESET}")
    print(f"  {ts}")
    print(f"{'═'*65}")

    # Campaign summary
    risk_color = RED if analysis.highest_stage in ("BACKDOOR","PERSIST","EXFIL","LATERAL") else YELLOW
    print(f"\n  {BOLD}Campaign:{RESET} {analysis.campaign_type.upper()}")
    print(f"  {BOLD}Active IPs:{RESET} {analysis.active_ips}")
    print(f"  {BOLD}Kill Chain:{RESET} {risk_color}{analysis.kill_chain_stage}{RESET}")
    print(f"  {BOLD}Primary Vector:{RESET} {analysis.primary_vector}")
    print(f"\n  {DIM}{analysis.summary}{RESET}")

    # Immediate actions
    if analysis.immediate_actions:
        print(f"\n  {BOLD}IMMEDIATE ACTIONS:{RESET}")
        for i, action in enumerate(analysis.immediate_actions, 1):
            print(f"  {RED}{i}.{RESET} {action}")

    # Per-IP alerts
    if analysis.ip_alerts:
        print(f"\n  {BOLD}IP ALERTS:{RESET}")
        for alert in analysis.ip_alerts:
            color = RED + BOLD if alert.is_red_zone else YELLOW
            zone  = "🔴 RED ZONE" if alert.is_red_zone else "⚠️  ACTIVE"
            print(f"\n  {color}{zone}{RESET}  {alert.src_ip}")
            print(f"    Stage    : {alert.current_stage} → {CYAN}{alert.predicted_next}{RESET}")
            print(f"    Threat   : {color}{alert.threat_level}{RESET}")
            print(f"    MITRE    : {alert.mitre_technique}")
            print(f"    Action   : {alert.recommended_action}")

    print(f"\n{'═'*65}\n")


def analyze(
    graph: HackerMindsetGraph,
    forensic_results: Optional[List[dict]] = None,
    write_report: bool = True,
    report_path: str   = "mindset_report.txt",
) -> Optional[CampaignAnalysis]:
    """
    Main entry point.

    Reads graph state → sends to LLM → returns CampaignAnalysis.
    Prints alert to console + writes to report file.

    forensic_results: list of dicts from agent pipeline
      each: {src_ip, entity, verdict, confidence, explanation}
    """
    log.info("MINDSET ANALYSIS starting")

    # ── Build prompt context ──────────────────────────────────────────────────
    total_ips = graph._conn.execute(
        "SELECT COUNT(DISTINCT src_ip) FROM ip_stage_events"
    ).fetchone()[0]
    total_transitions = graph.graph.number_of_edges()

    if total_ips == 0:
        log.info("No IPs recorded yet — skipping analysis")
        return None

    stage_overview   = _format_stage_overview(graph)
    ip_profiles_txt  = _format_ip_profiles(graph)
    red_zone_txt     = _format_red_zone(graph)
    forensic_txt     = _format_forensic_summary(forensic_results or [])
    ts               = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    prompt_human = _ANALYZER_HUMAN.format(
        total_ips         = total_ips,
        total_transitions = total_transitions,
        timestamp         = ts,
        stage_overview    = stage_overview,
        ip_profiles       = ip_profiles_txt,
        red_zone_ips      = red_zone_txt,
        forensic_summary  = forensic_txt,
    )

    log_llm_request(
        log,
        model          = "mistral-small-latest (mindset)",
        prompt_preview = prompt_human[:300],
        token_estimate = len(prompt_human) // 4,
    )

    # ── LLM call ──────────────────────────────────────────────────────────────
    llm = _get_llm()
    structured = llm.with_structured_output(CampaignAnalysis)
    prompt = ChatPromptTemplate.from_messages([
        ("system", _ANALYZER_SYSTEM),
        ("human",  "{input}"),
    ])
    chain = prompt | structured

    try:
        analysis: CampaignAnalysis = chain.invoke({"input": prompt_human})
        log.info(
            f"Mindset analysis done — "
            f"campaign={analysis.campaign_type}  "
            f"highest={analysis.highest_stage}  "
            f"red_zone_alerts={sum(1 for a in analysis.ip_alerts if a.is_red_zone)}"
        )
    except Exception as exc:
        log_exception(log, "mindset_analyzer LLM", exc)
        return None

    # ── Print to console ──────────────────────────────────────────────────────
    _print_alert_report(analysis)

    # ── Write report file ──────────────────────────────────────────────────────
    if write_report:
        try:
            with open(report_path, "w") as f:
                f.write(f"ThreatPipe v2 — Mindset Alert Report\n")
                f.write(f"Generated: {ts}\n")
                f.write(f"{'='*60}\n\n")
                f.write(f"Campaign Type  : {analysis.campaign_type}\n")
                f.write(f"Active IPs     : {analysis.active_ips}\n")
                f.write(f"Highest Stage  : {analysis.highest_stage}\n")
                f.write(f"Primary Vector : {analysis.primary_vector}\n")
                f.write(f"Kill Chain     : {analysis.kill_chain_stage}\n\n")
                f.write(f"Summary:\n{analysis.summary}\n\n")
                f.write(f"Immediate Actions:\n")
                for i, a in enumerate(analysis.immediate_actions, 1):
                    f.write(f"  {i}. {a}\n")
                f.write(f"\nIP Alerts:\n{'─'*60}\n")
                for alert in analysis.ip_alerts:
                    zone = "RED ZONE" if alert.is_red_zone else "ACTIVE"
                    f.write(f"\n[{zone}] {alert.src_ip}\n")
                    f.write(f"  Stage      : {alert.current_stage} → {alert.predicted_next}\n")
                    f.write(f"  Threat     : {alert.threat_level}\n")
                    f.write(f"  MITRE      : {alert.mitre_technique}\n")
                    f.write(f"  Action     : {alert.recommended_action}\n")
                f.write(f"\n{'─'*60}\n")
                f.write(f"Graph dump:\n")
                f.write(graph.dump_mindset_graph())

            log.info(f"Mindset report written: {report_path}")
        except Exception as exc:
            log_exception(log, "mindset_analyzer write_report", exc)

    return analysis