"""
ThreatPipe v2 — Hacker Mindset Graph
======================================
Persistent, IP-tracked, stage-based attacker behavior graph.

Architecture:
  - Stage nodes are SHARED across all IPs doing the same thing
  - IP addresses are tracked per stage (not separate graphs per IP)
  - Attack vectors diverge into separate paths when methods differ
  - Graph is PERSISTENT — survives reboots, new attackers, old attackers leaving
  - Long-term: accumulates all attack sessions over time

Stages (based on real pentest/attack methodology):
  RECON       → Target discovery: .env, .git, robots.txt, port scan
  SCAN        → Vulnerability probe: dirbusting, version detection
  EXPLOIT     → Active exploitation: SQLi, LFI, auth bypass
  UPLOAD      → File upload: web shell, malicious file placement
  BACKDOOR    → Persistent access: web shell execution, FTP STOR
  PERSIST     → Long-term access: cron, SSH key, registry run key
  EXFIL       → Data theft: /etc/passwd, db dumps, credential files
  LATERAL     → Moving inside network: internal scans, pivot

Graph DB: hacker_mindset.db (separate from evidence_graph)
NetworkX: DiGraph with stage nodes + IP tracking

Usage:
    from hacker_mindset_graph import HackerMindsetGraph
    g = HackerMindsetGraph()
    g.record_activity(
        src_ip      = "192.168.1.55",
        stage       = "RECON",
        attack_vector = "sensitive_file_probe",
        evidence    = {"entity": "/.env", "http_status": 200},
        session_id  = "stream_1_20260517",
    )
    prediction = g.predict_next_stage("192.168.1.55")
"""

import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import networkx as nx

from logger import get_logger, log_exception

log = get_logger("hacker_mindset_graph")

# ─── Stage definitions ────────────────────────────────────────────────────────

STAGES = {
    "RECON":    "Target discovery and information gathering",
    "SCAN":     "Vulnerability scanning and service probing",
    "EXPLOIT":  "Active exploitation attempt",
    "UPLOAD":   "Malicious file upload",
    "BACKDOOR": "Backdoor installation and execution",
    "PERSIST":  "Persistence mechanism creation",
    "EXFIL":    "Data exfiltration attempt",
    "LATERAL":  "Lateral movement inside network",
}

# Attack vectors per stage — what actions map to what stage
ATTACK_VECTOR_MAP = {
    # RECON indicators
    "sensitive_file_probe":   "RECON",   # .env, .git, wp-config
    "robots_txt_probe":       "RECON",
    "directory_listing":      "RECON",
    "ftp_banner_grab":        "RECON",
    "ssh_banner_grab":        "RECON",
    "version_probe":          "RECON",

    # SCAN indicators
    "directory_bruteforce":   "SCAN",
    "port_scan":              "SCAN",
    "login_bruteforce":       "SCAN",    # repeated failed logins
    "ssh_bruteforce":         "SCAN",
    "ftp_bruteforce":         "SCAN",
    "parameter_fuzz":         "SCAN",

    # EXPLOIT indicators
    "sql_injection":          "EXPLOIT",
    "lfi_attempt":            "EXPLOIT",  # local file inclusion
    "rfi_attempt":            "EXPLOIT",  # remote file inclusion
    "command_injection":      "EXPLOIT",  # ?cmd=, ?exec=
    "auth_bypass":            "EXPLOIT",
    "xxe_attempt":            "EXPLOIT",

    # UPLOAD indicators
    "php_file_upload":        "UPLOAD",
    "script_upload":          "UPLOAD",
    "binary_upload":          "UPLOAD",
    "ftp_stor":               "UPLOAD",   # FTP STOR command

    # BACKDOOR indicators
    "webshell_execution":     "BACKDOOR",
    "ftp_retr_suspicious":    "BACKDOOR", # FTP RETR of svchost.exe etc
    "reverse_shell":          "BACKDOOR",
    "c2_beacon":              "BACKDOOR",

    # PERSIST indicators
    "registry_run_key":       "PERSIST",
    "cron_modification":      "PERSIST",
    "ssh_key_placement":      "PERSIST",  # STOR to /.ssh/
    "startup_modification":   "PERSIST",

    # EXFIL indicators
    "credential_file_access": "EXFIL",   # /etc/passwd, /etc/shadow
    "db_dump_access":         "EXFIL",
    "ftp_data_transfer":      "EXFIL",
    "large_response":         "EXFIL",

    # LATERAL indicators
    "internal_scan":          "LATERAL",
    "pivot_attempt":          "LATERAL",
    "lateral_ftp":            "LATERAL",
}

# Expected stage progression (kill chain)
STAGE_PROGRESSION = [
    "RECON", "SCAN", "EXPLOIT", "UPLOAD",
    "BACKDOOR", "PERSIST", "EXFIL", "LATERAL"
]

# What stage typically follows what
NEXT_STAGE_PREDICTION = {
    "RECON":    ["SCAN", "EXPLOIT"],
    "SCAN":     ["EXPLOIT", "UPLOAD"],
    "EXPLOIT":  ["UPLOAD", "BACKDOOR"],
    "UPLOAD":   ["BACKDOOR", "PERSIST"],
    "BACKDOOR": ["PERSIST", "EXFIL"],
    "PERSIST":  ["EXFIL", "LATERAL"],
    "EXFIL":    ["LATERAL", "PERSIST"],
    "LATERAL":  ["EXFIL", "PERSIST"],
}

# Risk levels per stage
STAGE_RISK = {
    "RECON":    "LOW",
    "SCAN":     "MEDIUM",
    "EXPLOIT":  "HIGH",
    "UPLOAD":   "HIGH",
    "BACKDOOR": "CRITICAL",
    "PERSIST":  "CRITICAL",
    "EXFIL":    "CRITICAL",
    "LATERAL":  "CRITICAL",
}


# ─── SQLite DDL ───────────────────────────────────────────────────────────────

_DDL = """
CREATE TABLE IF NOT EXISTS stage_nodes (
    stage           TEXT PRIMARY KEY,
    description     TEXT NOT NULL,
    risk_level      TEXT NOT NULL,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    total_hits      INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS ip_stage_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    src_ip          TEXT NOT NULL,
    stage           TEXT NOT NULL,
    attack_vector   TEXT NOT NULL,
    evidence_json   TEXT NOT NULL DEFAULT '{}',
    session_id      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    forensic_verdict TEXT,
    forensic_confidence REAL
);

CREATE TABLE IF NOT EXISTS stage_transitions (
    src_stage       TEXT NOT NULL,
    dst_stage       TEXT NOT NULL,
    attack_vector   TEXT NOT NULL,
    count           INTEGER DEFAULT 1,
    PRIMARY KEY (src_stage, dst_stage, attack_vector)
);

CREATE TABLE IF NOT EXISTS ip_profiles (
    src_ip          TEXT PRIMARY KEY,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    current_stage   TEXT,
    highest_stage   TEXT,
    stage_history   TEXT NOT NULL DEFAULT '[]',
    total_events    INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0.0,
    threat_level    TEXT DEFAULT 'LOW',
    is_red_zone     INTEGER DEFAULT 0,
    red_zone_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_ip    ON ip_stage_events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_stage ON ip_stage_events(stage);
CREATE INDEX IF NOT EXISTS idx_events_ts    ON ip_stage_events(timestamp);
"""


class HackerMindsetGraph:
    """
    Persistent attacker behavior graph.

    Stage nodes are shared — all IPs doing RECON share one RECON node.
    IP profiles track individual attacker progression.
    Stage transitions accumulate over time — graph grows with each attack.
    """

    def __init__(self, db_path: str = "./hacker_mindset.db"):
        self.db_path = Path(db_path)
        self.graph   = nx.DiGraph()
        self._conn: Optional[sqlite3.Connection] = None

        log.info(f"HackerMindsetGraph init — db={self.db_path}")
        self._connect()
        self._create_tables()
        self._init_stage_nodes()
        self._load_graph()

    # ─── Setup ───────────────────────────────────────────────────────────────

    def _connect(self):
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False
        )
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        log.debug(f"SQLite connected: {self.db_path}")

    def _create_tables(self):
        self._conn.executescript(_DDL)
        self._conn.commit()
        log.debug("Mindset graph tables ready")

    def _init_stage_nodes(self):
        """Ensure all stage nodes exist in DB and NetworkX graph."""
        ts_now = datetime.now(timezone.utc).isoformat()
        for stage, desc in STAGES.items():
            self._conn.execute("""
                INSERT OR IGNORE INTO stage_nodes
                    (stage, description, risk_level, first_seen, last_seen, total_hits)
                VALUES (?, ?, ?, ?, ?, 0)
            """, (stage, desc, STAGE_RISK[stage], ts_now, ts_now))

            # Add to NetworkX
            if not self.graph.has_node(stage):
                self.graph.add_node(
                    stage,
                    description = desc,
                    risk_level  = STAGE_RISK[stage],
                    ips         = set(),
                    total_hits  = 0,
                )
        self._conn.commit()
        log.debug("Stage nodes initialized")

    def _load_graph(self):
        """Load existing transitions + IP data into NetworkX."""
        # Load stage node stats
        for row in self._conn.execute("SELECT * FROM stage_nodes"):
            if self.graph.has_node(row["stage"]):
                self.graph.nodes[row["stage"]]["total_hits"] = row["total_hits"]

        # Load existing transitions as edges
        for row in self._conn.execute("SELECT * FROM stage_transitions"):
            if not self.graph.has_edge(row["src_stage"], row["dst_stage"]):
                self.graph.add_edge(
                    row["src_stage"], row["dst_stage"],
                    count         = row["count"],
                    attack_vectors = [row["attack_vector"]],
                )
            else:
                self.graph.edges[row["src_stage"], row["dst_stage"]]["count"] += row["count"]

        # Load IP data into stage nodes
        for row in self._conn.execute(
            "SELECT DISTINCT src_ip, stage FROM ip_stage_events"
        ):
            if self.graph.has_node(row["stage"]):
                self.graph.nodes[row["stage"]]["ips"].add(row["src_ip"])

        n_ips = self._conn.execute(
            "SELECT COUNT(DISTINCT src_ip) FROM ip_stage_events"
        ).fetchone()[0]
        log.info(
            f"Mindset graph loaded — "
            f"stages={self.graph.number_of_nodes()}  "
            f"transitions={self.graph.number_of_edges()}  "
            f"known_ips={n_ips}"
        )

    # ─── Core API ─────────────────────────────────────────────────────────────

    def record_activity(
        self,
        src_ip:          str,
        stage:           str,
        attack_vector:   str,
        evidence:        dict,
        session_id:      str,
        forensic_verdict:    Optional[str]   = None,
        forensic_confidence: Optional[float] = None,
    ) -> dict:
        """
        Record one attacker activity event.

        - Updates stage node hit count
        - Tracks IP in stage
        - Records stage transition from previous stage
        - Updates IP profile (risk score, threat level, red zone)
        - Returns updated IP profile dict
        """
        ts_now = datetime.now(timezone.utc).isoformat()
        stage  = stage.upper()

        if stage not in STAGES:
            log.warning(f"Unknown stage: {stage} — skipping")
            return {}

        log.info(
            f"MINDSET RECORD  ip={src_ip}  stage={stage}  "
            f"vector={attack_vector}  verdict={forensic_verdict}"
        )

        # ── 1. Insert event ──────────────────────────────────────────────────
        self._conn.execute("""
            INSERT INTO ip_stage_events
                (src_ip, stage, attack_vector, evidence_json,
                 session_id, timestamp, forensic_verdict, forensic_confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            src_ip, stage, attack_vector,
            json.dumps(evidence, default=str),
            session_id, ts_now,
            forensic_verdict, forensic_confidence,
        ))

        # ── 2. Update stage node hit count ───────────────────────────────────
        self._conn.execute("""
            UPDATE stage_nodes
            SET total_hits = total_hits + 1, last_seen = ?
            WHERE stage = ?
        """, (ts_now, stage))

        if self.graph.has_node(stage):
            self.graph.nodes[stage]["total_hits"] = (
                self.graph.nodes[stage].get("total_hits", 0) + 1
            )
            self.graph.nodes[stage]["ips"].add(src_ip)

        # ── 3. Get previous stage for this IP ────────────────────────────────
        prev = self._conn.execute("""
            SELECT stage FROM ip_stage_events
            WHERE src_ip = ? AND stage != ?
            ORDER BY timestamp DESC LIMIT 1
        """, (src_ip, stage)).fetchone()

        prev_stage = prev["stage"] if prev else None

        # ── 4. Record stage transition ───────────────────────────────────────
        if prev_stage and prev_stage != stage:
            self._conn.execute("""
                INSERT INTO stage_transitions (src_stage, dst_stage, attack_vector, count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(src_stage, dst_stage, attack_vector)
                DO UPDATE SET count = count + 1
            """, (prev_stage, stage, attack_vector))

            # Add/update edge in NetworkX
            if not self.graph.has_edge(prev_stage, stage):
                self.graph.add_edge(
                    prev_stage, stage,
                    count=1,
                    attack_vectors=[attack_vector],
                )
                log.info(f"  NEW TRANSITION: {prev_stage} ──[{attack_vector}]──▶ {stage}")
            else:
                self.graph.edges[prev_stage, stage]["count"] += 1
                log.debug(f"  TRANSITION ++: {prev_stage} → {stage}")

        # ── 5. Update IP profile ─────────────────────────────────────────────
        profile = self._update_ip_profile(src_ip, stage, attack_vector, ts_now)

        self._conn.commit()
        return profile

    def _update_ip_profile(
        self, src_ip: str, stage: str, vector: str, ts_now: str
    ) -> dict:
        """Update or create IP profile with risk scoring."""
        existing = self._conn.execute(
            "SELECT * FROM ip_profiles WHERE src_ip = ?", (src_ip,)
        ).fetchone()

        stage_idx = STAGE_PROGRESSION.index(stage) if stage in STAGE_PROGRESSION else 0

        if existing:
            history = json.loads(existing["stage_history"])
            if stage not in history:
                history.append(stage)

            # Risk score: higher stage = higher risk
            # BACKDOOR/PERSIST/EXFIL = critical
            risk_score = min(1.0, (stage_idx + 1) / len(STAGE_PROGRESSION))

            # Escalate if MALICIOUS forensic verdict exists
            mal_count = self._conn.execute("""
                SELECT COUNT(*) FROM ip_stage_events
                WHERE src_ip = ? AND forensic_verdict = 'MALICIOUS'
            """, (src_ip,)).fetchone()[0]
            if mal_count > 0:
                risk_score = min(1.0, risk_score + 0.3)

            # Threat level
            threat_level = (
                "CRITICAL" if risk_score >= 0.8 else
                "HIGH"     if risk_score >= 0.6 else
                "MEDIUM"   if risk_score >= 0.4 else
                "LOW"
            )

            # Red zone: BACKDOOR/PERSIST/EXFIL or MALICIOUS verdict
            is_red = (
                stage in ("BACKDOOR", "PERSIST", "EXFIL", "LATERAL")
                or mal_count > 0
            )
            red_reason = (
                f"Stage={stage}, MALICIOUS verdicts={mal_count}"
                if is_red else ""
            )

            # Highest stage reached
            current_idx = STAGE_PROGRESSION.index(existing["highest_stage"]) \
                if existing["highest_stage"] in STAGE_PROGRESSION else -1
            highest = stage if stage_idx > current_idx else existing["highest_stage"]

            self._conn.execute("""
                UPDATE ip_profiles
                SET last_seen=?, current_stage=?, highest_stage=?,
                    stage_history=?, total_events=total_events+1,
                    risk_score=?, threat_level=?,
                    is_red_zone=?, red_zone_reason=?
                WHERE src_ip=?
            """, (
                ts_now, stage, highest,
                json.dumps(history), risk_score, threat_level,
                1 if is_red else 0, red_reason,
                src_ip,
            ))

            return {
                "src_ip": src_ip, "current_stage": stage,
                "highest_stage": highest, "stage_history": history,
                "risk_score": round(risk_score, 2),
                "threat_level": threat_level,
                "is_red_zone": is_red, "red_zone_reason": red_reason,
            }

        else:
            # New IP
            risk_score = (stage_idx + 1) / len(STAGE_PROGRESSION)
            threat_level = (
                "CRITICAL" if risk_score >= 0.8 else
                "HIGH"     if risk_score >= 0.6 else
                "MEDIUM"   if risk_score >= 0.4 else
                "LOW"
            )
            is_red = stage in ("BACKDOOR", "PERSIST", "EXFIL", "LATERAL")
            red_reason = f"Stage={stage}" if is_red else ""

            self._conn.execute("""
                INSERT INTO ip_profiles
                    (src_ip, first_seen, last_seen, current_stage, highest_stage,
                     stage_history, total_events, risk_score, threat_level,
                     is_red_zone, red_zone_reason)
                VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
            """, (
                src_ip, ts_now, ts_now, stage, stage,
                json.dumps([stage]),
                round(risk_score, 2), threat_level,
                1 if is_red else 0, red_reason,
            ))

            log.info(f"  NEW IP PROFILE: {src_ip}  stage={stage}  risk={risk_score:.2f}")
            return {
                "src_ip": src_ip, "current_stage": stage,
                "highest_stage": stage, "stage_history": [stage],
                "risk_score": round(risk_score, 2),
                "threat_level": threat_level,
                "is_red_zone": is_red, "red_zone_reason": red_reason,
            }

    # ─── Query API ────────────────────────────────────────────────────────────

    def get_ip_profile(self, src_ip: str) -> Optional[dict]:
        """Return full profile for an IP address."""
        row = self._conn.execute(
            "SELECT * FROM ip_profiles WHERE src_ip = ?", (src_ip,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["stage_history"] = json.loads(d["stage_history"])
        return d

    def get_red_zone_ips(self) -> List[dict]:
        """Return all IPs in the red zone — highest threat."""
        rows = self._conn.execute("""
            SELECT * FROM ip_profiles
            WHERE is_red_zone = 1
            ORDER BY risk_score DESC
        """).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["stage_history"] = json.loads(d["stage_history"])
            result.append(d)
        log.info(f"Red zone IPs: {len(result)}")
        return result

    def predict_next_stage(self, src_ip: str) -> dict:
        """
        Given an IP's current stage, predict the next likely attack stage
        based on historical transitions in the graph.
        """
        profile = self.get_ip_profile(src_ip)
        if not profile:
            return {"src_ip": src_ip, "prediction": "UNKNOWN", "reason": "IP not seen before"}

        current = profile["current_stage"]
        history = profile["stage_history"]

        # Get transitions from current stage
        if self.graph.has_node(current):
            successors = list(self.graph.successors(current))
            if successors:
                # Pick most common transition
                best = max(
                    successors,
                    key=lambda s: self.graph.edges[current, s].get("count", 0)
                )
                count = self.graph.edges[current, best].get("count", 0)
                prediction = best
                reason = f"Most common transition from {current} (seen {count}x)"
            else:
                # Fall back to kill chain knowledge
                next_stages = NEXT_STAGE_PREDICTION.get(current, [])
                prediction = next_stages[0] if next_stages else "UNKNOWN"
                reason = f"Kill chain prediction after {current}"
        else:
            prediction = "UNKNOWN"
            reason = "Current stage not in graph"

        result = {
            "src_ip":          src_ip,
            "current_stage":   current,
            "stage_history":   history,
            "predicted_next":  prediction,
            "reason":          reason,
            "risk_score":      profile["risk_score"],
            "threat_level":    profile["threat_level"],
            "is_red_zone":     profile["is_red_zone"],
            "alert":           f"ALERT: {src_ip} likely moving to {prediction} — {reason}",
        }
        log.info(
            f"PREDICTION  ip={src_ip}  current={current}  "
            f"next={prediction}  risk={profile['risk_score']}"
        )
        return result

    def get_stage_summary(self) -> dict:
        """Return full graph summary — all stages, IPs, transitions."""
        summary = {}
        for stage in STAGES:
            row = self._conn.execute(
                "SELECT * FROM stage_nodes WHERE stage = ?", (stage,)
            ).fetchone()
            ips = self._conn.execute(
                "SELECT DISTINCT src_ip FROM ip_stage_events WHERE stage = ?",
                (stage,)
            ).fetchall()
            summary[stage] = {
                "description":  STAGES[stage],
                "risk_level":   STAGE_RISK[stage],
                "total_hits":   row["total_hits"] if row else 0,
                "active_ips":   [r["src_ip"] for r in ips],
                "ip_count":     len(ips),
            }
        return summary

    def dump_mindset_graph(self) -> str:
        """ASCII dump of the mindset graph — for logs and reports."""
        lines = [
            "═" * 65,
            "HACKER MINDSET GRAPH",
            f"stages={self.graph.number_of_nodes()}  "
            f"transitions={self.graph.number_of_edges()}",
            "─" * 65,
        ]

        red_ips = self.get_red_zone_ips()

        for stage in STAGE_PROGRESSION:
            if not self.graph.has_node(stage):
                continue
            attrs = self.graph.nodes[stage]
            ips   = list(attrs.get("ips", set()))
            hits  = attrs.get("total_hits", 0)
            risk  = STAGE_RISK.get(stage, "?")
            lines.append(
                f"  [{risk:<8}] {stage:<10}  hits={hits:<4}  "
                f"ips={len(ips)}  {ips[:3]}"
            )

        lines.append("─" * 65)
        for src, dst, data in self.graph.edges(data=True):
            lines.append(
                f"  {src:<10} ──[{data.get('count',0)}x]──▶  {dst}"
            )

        lines.append("─" * 65)
        if red_ips:
            lines.append(f"  RED ZONE IPs ({len(red_ips)}):")
            for ip in red_ips[:10]:
                lines.append(
                    f"    🔴 {ip['src_ip']:<18}  "
                    f"stage={ip['current_stage']:<10}  "
                    f"risk={ip['risk_score']:.2f}  "
                    f"threat={ip['threat_level']}"
                )
        lines.append("═" * 65)

        text = "\n".join(lines)
        log.info("\n" + text)
        return text

    # ─── Context manager ─────────────────────────────────────────────────────

    def close(self):
        if self._conn:
            self._conn.commit()
            self._conn.close()
            log.debug("HackerMindsetGraph closed")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()