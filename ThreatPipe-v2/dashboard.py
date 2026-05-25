"""
ThreatPipe v2 — SOC Dashboard
================================
Streamlit-based defensive security dashboard.

Features:
  - Log file upload (any format)
  - Stage 1: LLM classification with live progress
  - Stage 2: Agent investigation per suspicious log
  - Results table with verdict, confidence, stage
  - Attack timeline chart
  - Hacker Mindset Graph visualization (NetworkX → Plotly)
  - Mindset alert report display
  - Collapsible log detail dropdowns

Run:
    streamlit run dashboard.py
"""

import os
import sys
import json
import time
import tempfile
import sqlite3
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Optional

import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import networkx as nx
import logging

# ─── Streamlit logging fix ────────────────────────────────────────────────────
# Streamlit captures stdout but not file handlers — fix by adding file handler
def _setup_streamlit_logging():
    """Ensure all threatpipe logs go to file even when running under Streamlit."""
    from pathlib import Path
    Path("./logs").mkdir(exist_ok=True)
    ts  = __import__("datetime").datetime.now().strftime("%Y%m%d_%H%M%S")
    log_path = f"./logs/dashboard_{ts}.log"

    root = logging.getLogger("threatpipe")
    # Remove existing handlers that may be stdout-only
    root.handlers = [h for h in root.handlers if isinstance(h, logging.FileHandler)]

    if not any(isinstance(h, logging.FileHandler) for h in root.handlers):
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(
            "%(asctime)s.%(msecs)03d | %(levelname)-8s | %(name)-25s | L%(lineno)-4d | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        ))
        root.addHandler(fh)
        root.setLevel(logging.DEBUG)
    return log_path

_dashboard_log_path = _setup_streamlit_logging()

# ─── Page config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title  = "ThreatPipe v2 — SOC Dashboard",
    page_icon   = "🔍",
    layout      = "wide",
    initial_sidebar_state = "expanded",
)

# ─── Styling ──────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@400;600;700&display=swap');

  html, body, [class*="css"] {
      font-family: 'Inter', sans-serif;
  }
  code, pre, .stCode {
      font-family: 'JetBrains Mono', monospace !important;
  }
  .verdict-MALICIOUS {
      background: #ff000022; border-left: 4px solid #ff4444;
      padding: 8px 12px; border-radius: 4px; color: #ff4444; font-weight: 700;
  }
  .verdict-SUSPICIOUS {
      background: #ffa50022; border-left: 4px solid #ffa500;
      padding: 8px 12px; border-radius: 4px; color: #ffa500; font-weight: 700;
  }
  .verdict-BENIGN {
      background: #00ff0022; border-left: 4px solid #00cc44;
      padding: 8px 12px; border-radius: 4px; color: #00cc44; font-weight: 700;
  }
  .red-zone-badge {
      background: #ff000033; border: 1px solid #ff4444;
      padding: 2px 8px; border-radius: 12px; color: #ff4444;
      font-size: 12px; font-weight: 700;
  }
  .metric-card {
      background: #1a1a2e; border: 1px solid #333;
      border-radius: 8px; padding: 16px; text-align: center;
  }
  .stage-badge {
      display: inline-block;
      padding: 2px 8px; border-radius: 4px;
      font-size: 11px; font-weight: 700; font-family: monospace;
  }
  div[data-testid="stExpander"] {
      border: 1px solid #333 !important;
      border-radius: 6px !important;
  }
</style>
""", unsafe_allow_html=True)

# ─── Stage colors ─────────────────────────────────────────────────────────────
STAGE_COLORS = {
    "RECON":    "#3498db",
    "SCAN":     "#f39c12",
    "EXPLOIT":  "#e74c3c",
    "UPLOAD":   "#e67e22",
    "BACKDOOR": "#c0392b",
    "PERSIST":  "#8e44ad",
    "EXFIL":    "#2c3e50",
    "LATERAL":  "#1abc9c",
}

VERDICT_COLORS = {
    "MALICIOUS":  "#ff4444",
    "SUSPICIOUS": "#ffa500",
    "BENIGN":     "#00cc44",
    "UNKNOWN":    "#888888",
}

STAGE_PROGRESSION = [
    "RECON", "SCAN", "EXPLOIT", "UPLOAD",
    "BACKDOOR", "PERSIST", "EXFIL", "LATERAL"
]

# ─── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🔍 ThreatPipe v2")
    st.markdown("**SIFT-native IR Agent**")
    st.markdown("---")

    api_key = st.text_input(
        "Mistral API Key",
        type="password",
        value=os.getenv("MISTRAL_API_KEY", ""),
        help="Required for LLM analysis"
    )
    if api_key:
        os.environ["MISTRAL_API_KEY"] = api_key

    st.markdown("---")
    st.markdown("**Settings**")
    max_cycles = st.slider("Max self-correction cycles", 1, 5, 3)
    window_budget = st.slider("Token window budget", 800, 2000, 1600, step=100)
    run_mindset = st.checkbox("Run mindset analysis", value=True)

    st.markdown("---")
    st.markdown("**Files**")
    mindset_db = st.text_input("Mindset DB path", value="./hacker_mindset.db")
    st.caption("Persistent across sessions")

    st.markdown("---")
    st.caption("FIND EVIL! 2026 — SANS Hackathon")

# ─── Header ───────────────────────────────────────────────────────────────────
st.markdown("# 🛡️ ThreatPipe v2 — SOC Dashboard")
st.markdown("**Autonomous SIFT-native incident response | Upload logs → Get verdicts → Visualize attack patterns**")
st.markdown("---")

# ─── Tab layout ───────────────────────────────────────────────────────────────
tab_analyze, tab_results, tab_mindset, tab_evidence = st.tabs([
    "📁 Analyze Logs",
    "📊 Results",
    "🧠 Mindset Graph",
    "🔬 Evidence Graph"
])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — Analyze Logs
# ══════════════════════════════════════════════════════════════════════════════

with tab_analyze:
    st.markdown("### Upload Log File")
    st.markdown("Supports: Apache/Nginx web logs, FTP logs, SSH auth.log, memory anomalies, MFT entries")

    uploaded = st.file_uploader(
        "Drop your log file here",
        type=["log", "txt", "csv", "tsv"],
        help="Any security log format — Stage 1 LLM will classify suspicious lines"
    )

    # ─── In dashboard.py — REPLACE the entire upload + run section ───

    col1, col2 = st.columns([3, 1])
    with col1:
        if uploaded:
            # Read ONCE and store in session_state
            raw_bytes = uploaded.read()
            content = raw_bytes.decode("utf-8", errors="replace")
            st.session_state["uploaded_content"] = content
            lines = content.splitlines()
            st.success(f"✓ Loaded: **{uploaded.name}** — {len(lines)} lines")

            with st.expander(f"Preview first 20 lines", expanded=False):
                st.code("\n".join(lines[:20]), language="text")

    with col2:
        use_sample = st.button("Use sample logs", use_container_width=True)

    if not api_key:
        st.warning("⚠️ Enter your Mistral API Key in the sidebar to run analysis")

    run_btn = st.button(
        "🚀 Run Analysis",
        type="primary",
        disabled=(not api_key or (uploaded is None and not use_sample)),
        use_container_width=True,
    )

    if run_btn or use_sample:
        if not api_key:
            st.error("API key required")
            st.stop()

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".log", delete=False, encoding="utf-8"
        ) as tmp:
            if use_sample:
                from stream_run import generate_sample, SAMPLE_LOGS
                tmp.write("\n".join(SAMPLE_LOGS.strip().split("\n")))
                tmp_path = tmp.name
                st.info("Using built-in sample logs")
            else:
                # ── FIX: use stored content, NOT uploaded.read() again ──
                content = st.session_state.get("uploaded_content", "")
                if not content:
                    st.error("File content lost — please re-upload the file")
                    st.stop()
                tmp.write(content)
                tmp_path = tmp.name

        suspicious_out = tempfile.mktemp(suffix="_suspicious.txt")

        # ── Progress UI ──
        st.markdown("---")
        progress_bar   = st.progress(0)
        status_text    = st.empty()
        stage1_expander = st.expander("Stage 1 — Log Classification", expanded=True)
        stage2_expander = st.expander("Stage 2 — Agent Investigation", expanded=True)

        results_store  = []
        suspicious_lines = []

        # Stage 1
        status_text.markdown("**Stage 1:** Classifying logs...")
        progress_bar.progress(10)

        with stage1_expander:
            s1_status = st.empty()
            s1_status.info("Running LLM classifier on log windows...")

        try:
            from log_stream import stream_classify
            suspicious_lines = stream_classify(tmp_path, suspicious_out, window_budget)
            with stage1_expander:
                # ── FIX: use stored content for line count too ──
                total_line_count = len(
                    st.session_state.get("uploaded_content", "").splitlines()
                ) if not use_sample else len(SAMPLE_LOGS.splitlines())
                s1_status.success(
                    f"✓ Found **{len(suspicious_lines)}** suspicious lines "
                    f"from {total_line_count} total"
                )
                if suspicious_lines:
                    with st.expander("Suspicious lines detected", expanded=False):
                        for i, sl in enumerate(suspicious_lines, 1):
                            st.code(f"[{i}] {sl}", language="text")
        except Exception as e:
            with stage1_expander:
                s1_status.error(f"Stage 1 error: {e}")
            suspicious_lines = []

    # ... rest of the Stage 2 code stays EXACTLY the same ...

        progress_bar.progress(30)

        # Stage 2
        if suspicious_lines:
            status_text.markdown(f"**Stage 2:** Investigating {len(suspicious_lines)} suspicious logs...")

            from agent import app as agent_app
            from config import token_manager
            from hacker_mindset_graph import HackerMindsetGraph
            from stage_classifier import classify_stage
            from mindset_analyzer import analyze as mindset_analyze

            mindset_graph = HackerMindsetGraph(db_path=mindset_db)
            forensic_for_mindset = []

            with stage2_expander:
                result_placeholder = st.empty()
                result_rows = []

            for i, log_line in enumerate(suspicious_lines):
                session_id = f"dash_{i}_{datetime.now(timezone.utc).strftime('%H%M%S')}"
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
                    "_tool_executions":    None,
                }

                t0 = time.monotonic()
                result = agent_app.invoke(inputs)
                elapsed = (time.monotonic() - t0) * 1000

                analysis = result.get("analysis")
                trigger  = result.get("structured_trigger")
                cycle    = result.get("current_cycle", 0)
                tools    = result.get("_tool_executions", [])

                # Stage classification + mindset graph
                stage, vector, evidence = "RECON", "unknown", {}
                if trigger and trigger.src_ip:
                    stage, vector, evidence = classify_stage(
                        raw_log  = log_line,
                        trigger  = trigger,
                        analysis = analysis,
                    )
                    mindset_graph.record_activity(
                        src_ip               = trigger.src_ip,
                        stage                = stage,
                        attack_vector        = vector,
                        evidence             = evidence,
                        session_id           = session_id,
                        forensic_verdict     = analysis.verdict if analysis else None,
                        forensic_confidence  = analysis.confidence if analysis else None,
                    )
                    forensic_for_mindset.append({
                        "src_ip":      trigger.src_ip,
                        "entity":      trigger.entity,
                        "verdict":     analysis.verdict if analysis else "?",
                        "confidence":  analysis.confidence if analysis else 0.0,
                        "explanation": analysis.explanation if analysis else "",
                        "stage":       stage,
                        "vector":      vector,
                    })

                row = {
                    "case":        i + 1,
                    "log":         log_line[:100],
                    "entity":      trigger.entity if trigger else "?",
                    "src_ip":      trigger.src_ip if trigger else "?",
                    "art_type":    trigger.artifact_type if trigger else "?",
                    "verdict":     analysis.verdict if analysis else "UNKNOWN",
                    "confidence":  analysis.confidence if analysis else 0.0,
                    "status":      analysis.status if analysis else "?",
                    "cycles":      cycle + 1,
                    "stage":       stage,
                    "vector":      vector,
                    "elapsed_ms":  elapsed,
                    "explanation": analysis.explanation if analysis else "",
                    "tools":       tools,
                    "session_id":  session_id,
                }
                results_store.append(row)
                result_rows.append({
                    "#":          row["case"],
                    "Entity":     row["entity"][:40],
                    "Verdict":    row["verdict"],
                    "Conf":       f"{row['confidence']:.2f}",
                    "Stage":      row["stage"],
                    "Cycles":     row["cycles"],
                })

                with stage2_expander:
                    result_placeholder.dataframe(
                        pd.DataFrame(result_rows),
                        use_container_width=True,
                        hide_index=True,
                    )

                pct = 30 + int(60 * (i + 1) / len(suspicious_lines))
                progress_bar.progress(pct)
                status_text.markdown(
                    f"**Stage 2:** {i+1}/{len(suspicious_lines)} investigated — "
                    f"Malicious: {sum(1 for r in results_store if r['verdict']=='MALICIOUS')} | "
                    f"Suspicious: {sum(1 for r in results_store if r['verdict']=='SUSPICIOUS')}"
                )

            # Stage 3 — Mindset
            progress_bar.progress(95)
            status_text.markdown("**Stage 3:** Running mindset analysis...")

            mindset_analysis = None
            if run_mindset and forensic_for_mindset:
                try:
                    mindset_analysis = mindset_analyze(
                        graph            = mindset_graph,
                        forensic_results = forensic_for_mindset,
                        write_report     = True,
                    )
                except Exception as e:
                    st.warning(f"Mindset analysis error: {e}")

            mindset_graph.close()

            progress_bar.progress(100)
            status_text.markdown("✅ **Analysis complete!**")

            # Store in session state
            st.session_state["results"]          = results_store
            st.session_state["mindset_db"]       = mindset_db
            st.session_state["mindset_analysis"] = mindset_analysis
            st.session_state["total_cost"]       = token_manager.total_cost

            st.success(
                f"Done! **{len(results_store)}** logs investigated — "
                f"Malicious: {sum(1 for r in results_store if r['verdict']=='MALICIOUS')} | "
                f"Suspicious: {sum(1 for r in results_store if r['verdict']=='SUSPICIOUS')} | "
                f"Cost: ${token_manager.total_cost:.5f}"
            )
            st.balloons()


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — Results
# ══════════════════════════════════════════════════════════════════════════════

with tab_results:
    results = st.session_state.get("results", [])

    if not results:
        st.info("Run an analysis in the 'Analyze Logs' tab first.")
    else:
        # ── Metrics row ──
        total     = len(results)
        malicious = sum(1 for r in results if r["verdict"] == "MALICIOUS")
        suspicious= sum(1 for r in results if r["verdict"] == "SUSPICIOUS")
        benign    = sum(1 for r in results if r["verdict"] == "BENIGN")
        cost      = st.session_state.get("total_cost", 0.0)

        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Investigated", total)
        c2.metric("🔴 Malicious",  malicious)
        c3.metric("🟡 Suspicious", suspicious)
        c4.metric("🟢 Benign",     benign)
        c5.metric("💰 LLM Cost",   f"${cost:.5f}")

        st.markdown("---")

        # ── Verdict distribution chart ──
        col_chart, col_stage = st.columns(2)

        with col_chart:
            st.markdown("#### Verdict Distribution")
            fig = go.Figure(go.Pie(
                labels = ["Malicious", "Suspicious", "Benign"],
                values = [malicious, suspicious, benign],
                marker_colors = ["#ff4444", "#ffa500", "#00cc44"],
                hole   = 0.4,
                textinfo = "label+percent",
            ))
            fig.update_layout(
                showlegend=False, height=280,
                margin=dict(t=0, b=0, l=0, r=0),
                paper_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"),
            )
            st.plotly_chart(fig, use_container_width=True)

        with col_stage:
            st.markdown("#### Attack Stage Distribution")
            stage_counts = {}
            for r in results:
                s = r.get("stage", "RECON")
                stage_counts[s] = stage_counts.get(s, 0) + 1

            stages  = list(stage_counts.keys())
            counts  = [stage_counts[s] for s in stages]
            colors  = [STAGE_COLORS.get(s, "#888") for s in stages]

            fig2 = go.Figure(go.Bar(
                x=stages, y=counts,
                marker_color=colors,
                text=counts, textposition="auto",
            ))
            fig2.update_layout(
                height=280, showlegend=False,
                margin=dict(t=0, b=0, l=0, r=0),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="white"),
                xaxis=dict(gridcolor="#333"),
                yaxis=dict(gridcolor="#333"),
            )
            st.plotly_chart(fig2, use_container_width=True)

        # ── Timeline ──
        st.markdown("#### Investigation Timeline")
        timeline_data = []
        for r in results:
            timeline_data.append({
                "Case":      r["case"],
                "Entity":    r["entity"][:40],
                "Verdict":   r["verdict"],
                "Stage":     r["stage"],
                "Time (ms)": r["elapsed_ms"],
                "Confidence":r["confidence"],
            })
        df = pd.DataFrame(timeline_data)
        fig3 = px.scatter(
            df, x="Case", y="Confidence",
            color="Verdict",
            color_discrete_map=VERDICT_COLORS,
            size="Time (ms)",
            hover_data=["Entity", "Stage", "Time (ms)"],
            symbol="Stage",
        )
        fig3.update_layout(
            height=300,
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="white"),
            xaxis=dict(gridcolor="#333", title="Case #"),
            yaxis=dict(gridcolor="#333", title="Confidence"),
        )
        st.plotly_chart(fig3, use_container_width=True)

        # ── Results table with expanders ──
        st.markdown("#### Detailed Results")
        st.caption("Click each case to see tool execution details")

        for r in results:
            verdict = r["verdict"]
            icon    = "🔴" if verdict == "MALICIOUS" else "🟡" if verdict == "SUSPICIOUS" else "🟢"
            label   = (
                f"{icon} [{r['case']}] {r['entity'][:50]}  |  "
                f"{verdict} ({r['confidence']:.2f})  |  "
                f"Stage: {r['stage']}  |  "
                f"Cycles: {r['cycles']}  |  "
                f"{r['elapsed_ms']:.0f}ms"
            )

            with st.expander(label, expanded=False):
                c1, c2, c3 = st.columns(3)
                c1.markdown(f"**Source IP:** `{r['src_ip']}`")
                c2.markdown(f"**Artifact type:** `{r['art_type']}`")
                c3.markdown(f"**Vector:** `{r['vector']}`")

                st.markdown(f"**Log:** `{r['log']}`")
                st.markdown(f"**Explanation:** {r['explanation']}")

                # Tool executions
                tools = r.get("tools", [])
                if tools:
                    st.markdown("**Tool Executions:**")
                    for te in tools:
                        status = "✓" if te.get("returncode", -1) == 0 else "✗"
                        st.markdown(
                            f"**Cycle {te.get('cycle',0)}** — "
                            f"`{te['tool']} {' '.join(te.get('args',[]))}` "
                            f"[{status} {te.get('elapsed_ms',0):.1f}ms]"
                        )
                        out = te.get("stdout","").strip() or te.get("stderr","").strip()
                        if out:
                            st.code(out[:500], language="text")


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — Mindset Graph
# ══════════════════════════════════════════════════════════════════════════════

with tab_mindset:
    if not st.session_state.get("results"):
        st.info("Run an analysis first.")
    else:
        st.markdown("### 🧠 Hacker Mindset Graph")
        st.markdown("Persistent attacker behavior graph — stages shared across all IPs")

        # Load from DB
        try:
            conn = sqlite3.connect(mindset_db)
            conn.row_factory = sqlite3.Row

            # IP profiles
            ip_rows = conn.execute(
                "SELECT * FROM ip_profiles ORDER BY risk_score DESC"
            ).fetchall()

            if ip_rows:
                # ── IP Risk table ──
                st.markdown("#### IP Risk Profiles")
                import json as json_mod
                ip_data = []
                for row in ip_rows:
                    history = json_mod.loads(row["stage_history"])
                    ip_data.append({
                        "IP":           row["src_ip"],
                        "Stage":        row["current_stage"],
                        "Risk":         f"{row['risk_score']:.2f}",
                        "Threat":       row["threat_level"],
                        "Path":         " → ".join(history),
                        "Events":       row["total_events"],
                        "Red Zone":     "🔴 YES" if row["is_red_zone"] else "No",
                    })
                df_ip = pd.DataFrame(ip_data)
                st.dataframe(df_ip, use_container_width=True, hide_index=True)

                # ── Stage overview ──
                st.markdown("#### Stage Activity")
                stage_rows = conn.execute("SELECT * FROM stage_nodes ORDER BY rowid").fetchall()
                stage_data = []
                for row in stage_rows:
                    stage_data.append({
                        "Stage":       row["stage"],
                        "Risk Level":  row["risk_level"],
                        "Total Hits":  row["total_hits"],
                    })
                df_stages = pd.DataFrame(stage_data)

                # Stage bar chart
                fig_stages = go.Figure()
                for _, row in df_stages.iterrows():
                    fig_stages.add_trace(go.Bar(
                        x=[row["Stage"]], y=[row["Total Hits"]],
                        name=row["Stage"],
                        marker_color=STAGE_COLORS.get(row["Stage"], "#888"),
                        showlegend=False,
                        text=[row["Total Hits"]],
                        textposition="auto",
                    ))
                fig_stages.update_layout(
                    height=250, barmode="stack",
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="white"),
                    xaxis=dict(gridcolor="#222"),
                    yaxis=dict(gridcolor="#222", title="Hits"),
                    margin=dict(t=10, b=10),
                )
                st.plotly_chart(fig_stages, use_container_width=True)

                # ── NetworkX → Plotly graph ──
                st.markdown("#### Attack Transition Graph")
                st.caption("Nodes = attack stages (shared) | Edges = observed transitions | Width = frequency")

                transition_rows = conn.execute(
                    "SELECT * FROM stage_transitions"
                ).fetchall()

                G = nx.DiGraph()
                for stage in STAGE_PROGRESSION:
                    G.add_node(stage)
                for row in transition_rows:
                    G.add_edge(
                        row["src_stage"], row["dst_stage"],
                        count=row["count"],
                        vector=row["attack_vector"],
                    )

                # Layout
                pos = {}
                for i, stage in enumerate(STAGE_PROGRESSION):
                    angle = i * (360 / len(STAGE_PROGRESSION))
                    import math
                    pos[stage] = (
                        math.cos(math.radians(angle)) * 2,
                        math.sin(math.radians(angle)) * 2,
                    )

                # Node sizes — by hit count
                hit_map = {row["stage"]: row["total_hits"] for row in stage_rows}

                # Draw edges
                edge_traces = []
                for src, dst, data in G.edges(data=True):
                    x0, y0 = pos[src]
                    x1, y1 = pos[dst]
                    width   = max(1, min(8, data.get("count", 1)))
                    edge_traces.append(go.Scatter(
                        x=[x0, x1, None], y=[y0, y1, None],
                        mode="lines",
                        line=dict(width=width, color="#666"),
                        hoverinfo="none",
                        showlegend=False,
                    ))

                # Draw nodes
                node_x, node_y, node_text, node_color, node_size = [], [], [], [], []
                for stage in STAGE_PROGRESSION:
                    x, y = pos[stage]
                    hits  = hit_map.get(stage, 0)
                    node_x.append(x)
                    node_y.append(y)
                    node_text.append(f"{stage}<br>hits={hits}")
                    node_color.append(STAGE_COLORS.get(stage, "#888"))
                    node_size.append(max(30, min(80, 20 + hits * 3)))

                node_trace = go.Scatter(
                    x=node_x, y=node_y,
                    mode="markers+text",
                    text=STAGE_PROGRESSION,
                    textposition="top center",
                    hovertext=node_text,
                    hoverinfo="text",
                    marker=dict(
                        size=node_size,
                        color=node_color,
                        line=dict(width=2, color="white"),
                    ),
                    showlegend=False,
                )

                fig_graph = go.Figure(
                    data=edge_traces + [node_trace],
                    layout=go.Layout(
                        height=500,
                        paper_bgcolor="rgba(0,0,0,0)",
                        plot_bgcolor="#0d1117",
                        font=dict(color="white"),
                        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                        margin=dict(t=20, b=20, l=20, r=20),
                        hovermode="closest",
                    )
                )
                st.plotly_chart(fig_graph, use_container_width=True)

                # ── Alert report ──
                analysis_obj = st.session_state.get("mindset_analysis")
                if analysis_obj:
                    st.markdown("---")
                    st.markdown("#### 🚨 Mindset Alert Report")

                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Campaign Type",  analysis_obj.campaign_type.upper())
                    col_b.metric("Highest Stage",  analysis_obj.highest_stage)
                    col_c.metric("Primary Vector", analysis_obj.primary_vector[:25])

                    st.info(analysis_obj.summary)

                    if analysis_obj.immediate_actions:
                        st.markdown("**Immediate Actions:**")
                        for i, action in enumerate(analysis_obj.immediate_actions, 1):
                            st.markdown(f"**{i}.** {action}")

                    st.markdown("**IP Alerts:**")
                    for alert in analysis_obj.ip_alerts:
                        if alert.is_red_zone:
                            st.error(
                                f"🔴 **RED ZONE — {alert.src_ip}**  \n"
                                f"Stage: `{alert.current_stage}` → `{alert.predicted_next}`  \n"
                                f"Threat: **{alert.threat_level}** | MITRE: {alert.mitre_technique}  \n"
                                f"**Action:** {alert.recommended_action}"
                            )
                        else:
                            st.warning(
                                f"⚠️ **{alert.src_ip}**  \n"
                                f"Stage: `{alert.current_stage}` → `{alert.predicted_next}`  \n"
                                f"Threat: **{alert.threat_level}** | MITRE: {alert.mitre_technique}  \n"
                                f"**Action:** {alert.recommended_action}"
                            )

            conn.close()

        except Exception as e:
            st.error(f"Error loading mindset graph: {e}")
            import traceback
            st.code(traceback.format_exc())


# ══════════════════════════════════════════════════════════════════════════════
# TAB 4 — Evidence Graph
# ══════════════════════════════════════════════════════════════════════════════

with tab_evidence:
    if not st.session_state.get("results"):
        st.info("Run an analysis first.")
    else:
        st.markdown("### 🔬 Evidence Graph")
        st.markdown("Per-session forensic investigation graph")

        results = st.session_state.get("results", [])
        session_ids = [r["session_id"] for r in results]

        selected = st.selectbox(
            "Select investigation session",
            options=session_ids,
            format_func=lambda sid: (
                f"{sid} — "
                + next((
                    f"{r['verdict']} | {r['entity'][:40]}"
                    for r in results if r["session_id"] == sid
                ), "")
            )
        )

        if selected:
            try:
                conn = sqlite3.connect("./threatpipe_evidence.db")
                conn.row_factory = sqlite3.Row

                nodes = conn.execute(
                    "SELECT * FROM nodes WHERE session_id=? ORDER BY created_at",
                    (selected,)
                ).fetchall()

                edges = conn.execute("""
                    SELECT e.* FROM edges e
                    JOIN nodes n ON e.src_id = n.node_id
                    WHERE n.session_id=?
                """, (selected,)).fetchall()

                conn.close()

                if not nodes:
                    st.warning("No graph data for this session")
                else:
                    # Summary
                    row = next(
                        (r for r in results if r["session_id"] == selected), {}
                    )
                    verdict = row.get("verdict", "?")
                    v_color = VERDICT_COLORS.get(verdict, "#888")

                    st.markdown(
                        f"**Verdict:** "
                        f"<span style='color:{v_color};font-weight:700'>{verdict}</span> "
                        f"({row.get('confidence', 0):.2f}) | "
                        f"**Cycles:** {row.get('cycles', 1)} | "
                        f"**Nodes:** {len(nodes)} | **Edges:** {len(edges)}",
                        unsafe_allow_html=True
                    )

                    # Graph visualization
                    G = nx.DiGraph()
                    node_map = {}
                    for node in nodes:
                        G.add_node(node["node_id"], **dict(node))
                        node_map[node["node_id"]] = dict(node)
                    for edge in edges:
                        G.add_edge(
                            edge["src_id"], edge["dst_id"],
                            relation=edge["relation"]
                        )

                    pos = nx.spring_layout(G, seed=42, k=2)

                    NODE_TYPE_COLORS = {
                        "trigger":        "#3498db",
                        "artifact":       "#f39c12",
                        "tool_execution": "#9b59b6",
                        "finding":        "#e74c3c",
                    }

                    # Edges
                    ev_traces = []
                    for src, dst, data in G.edges(data=True):
                        x0, y0 = pos[src]
                        x1, y1 = pos[dst]
                        ev_traces.append(go.Scatter(
                            x=[x0, x1, None], y=[y0, y1, None],
                            mode="lines",
                            line=dict(width=2, color="#555"),
                            hoverinfo="none",
                            showlegend=False,
                        ))
                        # Edge label
                        mx, my = (x0+x1)/2, (y0+y1)/2
                        ev_traces.append(go.Scatter(
                            x=[mx], y=[my],
                            mode="text",
                            text=[data.get("relation", "")],
                            textfont=dict(size=9, color="#aaa"),
                            hoverinfo="none",
                            showlegend=False,
                        ))

                    # Nodes
                    nv_x, nv_y, nv_text, nv_color, nv_size, nv_hover = [], [], [], [], [], []
                    for nid in G.nodes():
                        x, y = pos[nid]
                        attrs = node_map.get(nid, {})
                        ntype = attrs.get("node_type", "trigger")
                        label = attrs.get("label", nid)[:30]
                        nv_x.append(x)
                        nv_y.append(y)
                        nv_text.append(label)
                        nv_color.append(NODE_TYPE_COLORS.get(ntype, "#888"))
                        nv_size.append(30 if ntype == "finding" else 20)
                        verdict_str = (
                            f"<br>verdict: {attrs.get('verdict')}"
                            if attrs.get("verdict") else ""
                        )
                        nv_hover.append(
                            f"<b>{ntype.upper()}</b><br>{label}{verdict_str}"
                        )

                    nv_trace = go.Scatter(
                        x=nv_x, y=nv_y,
                        mode="markers+text",
                        text=nv_text,
                        textposition="top center",
                        hovertext=nv_hover,
                        hoverinfo="text",
                        marker=dict(
                            size=nv_size, color=nv_color,
                            line=dict(width=2, color="white"),
                        ),
                        showlegend=False,
                    )

                    fig_ev = go.Figure(
                        data=ev_traces + [nv_trace],
                        layout=go.Layout(
                            height=450,
                            paper_bgcolor="rgba(0,0,0,0)",
                            plot_bgcolor="#0d1117",
                            font=dict(color="white"),
                            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                            margin=dict(t=10, b=10, l=10, r=10),
                        )
                    )
                    st.plotly_chart(fig_ev, use_container_width=True)

                    # Legend
                    leg_cols = st.columns(4)
                    for i, (ntype, color) in enumerate(NODE_TYPE_COLORS.items()):
                        leg_cols[i].markdown(
                            f"<span style='color:{color}'>■</span> {ntype}",
                            unsafe_allow_html=True
                        )

                    # Raw node table
                    with st.expander("Raw node data", expanded=False):
                        node_table = []
                        for node in nodes:
                            node_table.append({
                                "Type":    node["node_type"],
                                "Label":   node["label"][:50],
                                "Verdict": node["verdict"] or "—",
                                "Conf":    f"{node['confidence']:.2f}" if node["confidence"] else "—",
                            })
                        st.dataframe(
                            pd.DataFrame(node_table),
                            use_container_width=True,
                            hide_index=True,
                        )

            except Exception as e:
                st.error(f"Error loading evidence graph: {e}")
                import traceback
                st.code(traceback.format_exc())