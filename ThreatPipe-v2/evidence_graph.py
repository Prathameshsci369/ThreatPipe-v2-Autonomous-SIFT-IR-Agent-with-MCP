"""
ThreatPipe v2 — Evidence Graph
================================
SQLite + NetworkX based investigation graph.
Neo4j nahi — SIFT workstation la pip install networkx enough aahe.

What this does:
  - EvidenceNode aani InvestigationEdge SQLite madhe persist karto
  - NetworkX DiGraph in-memory fast queries la vaparla jaato
  - Har operation logger la jaato (add node, add edge, query, save, load)
  - Session-based — ek run = ek session_id = ek subgraph

Tables:
  nodes  (node_id, node_type, label, data_json, created_at, session_id,
           verdict, confidence, explanation)
  edges  (src_id, dst_id, relation, created_at, meta_json)

Usage:
    from evidence_graph import EvidenceGraph
    g = EvidenceGraph(db_path="./threatpipe_evidence.db", session_id="run_001")
    g.add_node(EvidenceNode(...))
    g.add_edge(InvestigationEdge(...))
    g.save()
    # query
    nodes = g.get_nodes_by_type("trigger")
    neighbors = g.get_neighbors("trigger:shell_php")
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

import networkx as nx

from logger import get_logger, log_graph_op, log_exception
from schemas import EvidenceNode, InvestigationEdge

log = get_logger(__name__)

# ─── DDL ──────────────────────────────────────────────────────────────────────
_CREATE_NODES = """
CREATE TABLE IF NOT EXISTS nodes (
    node_id     TEXT PRIMARY KEY,
    node_type   TEXT NOT NULL,
    label       TEXT NOT NULL,
    data_json   TEXT NOT NULL DEFAULT '{}',
    created_at  TEXT NOT NULL,
    session_id  TEXT NOT NULL DEFAULT 'default',
    verdict     TEXT,
    confidence  REAL,
    explanation TEXT
);
"""

_CREATE_EDGES = """
CREATE TABLE IF NOT EXISTS edges (
    src_id      TEXT NOT NULL,
    dst_id      TEXT NOT NULL,
    relation    TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    meta_json   TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (src_id, dst_id, relation)
);
"""

_CREATE_IDX_SESSION = "CREATE INDEX IF NOT EXISTS idx_nodes_session ON nodes(session_id);"
_CREATE_IDX_TYPE    = "CREATE INDEX IF NOT EXISTS idx_nodes_type    ON nodes(node_type);"


class EvidenceGraph:
    """
    In-memory NetworkX graph + SQLite persistence.

    Call  .save()  to flush to disk.
    Call  .load()  to restore a previous session (or resume current).
    """

    def __init__(self, db_path: str = "./threatpipe_evidence.db",
                 session_id: str = "default"):
        self.db_path    = Path(db_path)
        self.session_id = session_id
        self.graph      = nx.DiGraph()      # in-memory graph
        self._conn: Optional[sqlite3.Connection] = None

        log.info(f"EvidenceGraph init — db={self.db_path}  session={self.session_id}")
        self._connect()
        self._create_tables()
        # Load existing nodes/edges for this session so graph is warm on resume
        self._load_session()

    # ─── Connection ──────────────────────────────────────────────────────────

    def _connect(self):
        t0 = time.monotonic()
        try:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row          # dict-like rows
            self._conn.execute("PRAGMA journal_mode=WAL") # safe concurrent reads
            self._conn.execute("PRAGMA foreign_keys=ON")
            elapsed = (time.monotonic() - t0) * 1000
            log.debug(f"SQLite connected  path={self.db_path}  elapsed={elapsed:.1f}ms")
        except Exception as exc:
            log_exception(log, "EvidenceGraph._connect", exc)
            raise

    def _create_tables(self):
        try:
            cur = self._conn.cursor()
            cur.executescript(
                _CREATE_NODES + _CREATE_EDGES +
                _CREATE_IDX_SESSION + _CREATE_IDX_TYPE
            )
            self._conn.commit()
            log.debug("SQLite tables OK (nodes, edges)")
        except Exception as exc:
            log_exception(log, "EvidenceGraph._create_tables", exc)
            raise

    # ─── Load existing session data into NetworkX ─────────────────────────────

    def _load_session(self):
        """Pull all nodes + edges for this session into the in-memory graph."""
        t0 = time.monotonic()
        node_count = 0
        edge_count = 0

        try:
            cur = self._conn.cursor()

            # Nodes
            cur.execute("SELECT * FROM nodes WHERE session_id = ?", (self.session_id,))
            for row in cur.fetchall():
                data = json.loads(row["data_json"])
                self.graph.add_node(
                    row["node_id"],
                    node_type   = row["node_type"],
                    label       = row["label"],
                    data        = data,
                    created_at  = row["created_at"],
                    session_id  = row["session_id"],
                    verdict     = row["verdict"],
                    confidence  = row["confidence"],
                    explanation = row["explanation"],
                )
                node_count += 1

            # Edges
            cur.execute("""
                SELECT e.* FROM edges e
                JOIN nodes n ON e.src_id = n.node_id
                WHERE n.session_id = ?
            """, (self.session_id,))
            for row in cur.fetchall():
                meta = json.loads(row["meta_json"])
                self.graph.add_edge(
                    row["src_id"], row["dst_id"],
                    relation   = row["relation"],
                    created_at = row["created_at"],
                    meta       = meta,
                )
                edge_count += 1

            elapsed = (time.monotonic() - t0) * 1000
            log.info(
                f"Graph session loaded — "
                f"nodes={node_count}  edges={edge_count}  "
                f"session={self.session_id}  elapsed={elapsed:.1f}ms"
            )

        except Exception as exc:
            log_exception(log, "EvidenceGraph._load_session", exc)
            raise

    # ─── Write operations ─────────────────────────────────────────────────────

    def add_node(self, node: EvidenceNode) -> bool:
        """
        Add or update a node.
        Returns True on success, False if it already exists (no overwrite).
        Logs full node data at DEBUG level.
        """
        t0 = time.monotonic()

        # Force session_id to match this graph instance
        node.session_id = self.session_id

        log.debug(f"ADD NODE  id={node.node_id}  type={node.node_type}  label={node.label}")
        log.debug(f"  data keys : {list(node.data.keys())}")
        if node.verdict:
            log.debug(f"  verdict   : {node.verdict}  confidence={node.confidence}")

        # ── Check for duplicate ──
        if self.graph.has_node(node.node_id):
            log.warning(f"  ⚠ node already exists, skipping — id={node.node_id}")
            return False

        # ── Add to NetworkX ──
        self.graph.add_node(
            node.node_id,
            node_type   = node.node_type,
            label       = node.label,
            data        = node.data,
            created_at  = node.created_at,
            session_id  = node.session_id,
            verdict     = node.verdict,
            confidence  = node.confidence,
            explanation = node.explanation,
        )

        # ── Persist to SQLite ──
        try:
            self._conn.execute("""
                INSERT OR IGNORE INTO nodes
                    (node_id, node_type, label, data_json, created_at,
                     session_id, verdict, confidence, explanation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                node.node_id,
                node.node_type,
                node.label,
                json.dumps(node.data, default=str),
                node.created_at,
                node.session_id,
                node.verdict,
                node.confidence,
                node.explanation,
            ))
            self._conn.commit()

            elapsed = (time.monotonic() - t0) * 1000
            log_graph_op(log, "ADD", node_id=node.node_id,
                         attrs={"type": node.node_type, "elapsed_ms": f"{elapsed:.1f}"})
            return True

        except Exception as exc:
            log_exception(log, f"EvidenceGraph.add_node [{node.node_id}]", exc)
            return False

    def add_edge(self, edge: InvestigationEdge) -> bool:
        """
        Add a directed edge between two existing nodes.
        Logs the edge at DEBUG level.
        """
        t0 = time.monotonic()

        log.debug(
            f"ADD EDGE  {edge.src_id} ──[{edge.relation}]──▶ {edge.dst_id}"
        )

        # ── Warn if nodes don't exist yet (may be added later — still insert) ──
        missing = []
        for nid in (edge.src_id, edge.dst_id):
            if not self.graph.has_node(nid):
                missing.append(nid)
        if missing:
            log.warning(f"  ⚠ edge references nodes not yet in graph: {missing}")

        # ── Add to NetworkX ──
        self.graph.add_edge(
            edge.src_id, edge.dst_id,
            relation   = edge.relation,
            created_at = edge.created_at,
            meta       = edge.meta,
        )

        # ── Persist to SQLite ──
        try:
            self._conn.execute("""
                INSERT OR REPLACE INTO edges
                    (src_id, dst_id, relation, created_at, meta_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                edge.src_id,
                edge.dst_id,
                edge.relation,
                edge.created_at,
                json.dumps(edge.meta, default=str),
            ))
            self._conn.commit()

            elapsed = (time.monotonic() - t0) * 1000
            log_graph_op(log, "ADD", edge=(edge.src_id, edge.dst_id),
                         attrs={"relation": edge.relation, "elapsed_ms": f"{elapsed:.1f}"})
            return True

        except Exception as exc:
            log_exception(log, f"EvidenceGraph.add_edge [{edge.src_id}→{edge.dst_id}]", exc)
            return False

    def update_node_verdict(self, node_id: str, verdict: str,
                             confidence: float, explanation: str) -> bool:
        """Update verdict fields on an existing finding node."""
        log.info(f"UPDATE VERDICT  node={node_id}  verdict={verdict}  conf={confidence:.2f}")

        if not self.graph.has_node(node_id):
            log.error(f"  ✗ node not found in graph — id={node_id}")
            return False

        # Update NetworkX
        self.graph.nodes[node_id].update({
            "verdict":     verdict,
            "confidence":  confidence,
            "explanation": explanation,
        })

        # Update SQLite
        try:
            self._conn.execute("""
                UPDATE nodes
                SET verdict=?, confidence=?, explanation=?
                WHERE node_id=?
            """, (verdict, confidence, explanation, node_id))
            self._conn.commit()
            log.debug(f"  ✓ verdict updated in DB  node={node_id}")
            return True
        except Exception as exc:
            log_exception(log, f"EvidenceGraph.update_node_verdict [{node_id}]", exc)
            return False

    # ─── Read operations ──────────────────────────────────────────────────────

    def get_node(self, node_id: str) -> Optional[dict]:
        """Return node attribute dict or None."""
        if not self.graph.has_node(node_id):
            log.debug(f"GET NODE  id={node_id}  → not found")
            return None
        attrs = dict(self.graph.nodes[node_id])
        log_graph_op(log, "GET", node_id=node_id)
        return attrs

    def get_nodes_by_type(self, node_type: str) -> List[dict]:
        """Return all nodes of a specific type in this session."""
        result = []
        for nid, attrs in self.graph.nodes(data=True):
            if (attrs.get("node_type") == node_type and
                    attrs.get("session_id") == self.session_id):
                result.append({"node_id": nid, **attrs})

        log.debug(f"GET BY TYPE  type={node_type}  found={len(result)}")
        return result

    def get_neighbors(self, node_id: str) -> List[dict]:
        """Return all nodes directly connected to node_id (in both directions)."""
        if not self.graph.has_node(node_id):
            log.warning(f"GET NEIGHBORS  id={node_id}  → node not found")
            return []

        result = []
        for nbr in nx.all_neighbors(self.graph, node_id):
            result.append({
                "node_id": nbr,
                **self.graph.nodes[nbr],
                "edges_in":  [
                    d for u, v, d in self.graph.in_edges(nbr, data=True)
                ],
                "edges_out": [
                    d for u, v, d in self.graph.out_edges(nbr, data=True)
                ],
            })

        log.debug(f"GET NEIGHBORS  id={node_id}  found={len(result)}")
        return result

    def get_session_summary(self) -> dict:
        """Counts for this session — useful for final report."""
        session_nodes = [
            n for n, d in self.graph.nodes(data=True)
            if d.get("session_id") == self.session_id
        ]
        findings = [
            n for n in session_nodes
            if self.graph.nodes[n].get("node_type") == "finding"
        ]
        verdicts = {
            v: sum(1 for n in findings
                   if self.graph.nodes[n].get("verdict") == v)
            for v in ("MALICIOUS", "SUSPICIOUS", "BENIGN")
        }

        summary = {
            "session_id":    self.session_id,
            "total_nodes":   len(session_nodes),
            "total_edges":   self.graph.number_of_edges(),
            "findings":      len(findings),
            "verdicts":      verdicts,
        }
        log.info(f"SESSION SUMMARY  {summary}")
        return summary

    # ─── Persistence ──────────────────────────────────────────────────────────

    def save(self):
        """
        Flush any pending writes and log a checkpoint.
        SQLite commits are already per-operation (add_node, add_edge),
        so this is mostly a log checkpoint + WAL checkpoint.
        """
        try:
            self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")
            self._conn.commit()
            n = self.graph.number_of_nodes()
            e = self.graph.number_of_edges()
            log.info(f"GRAPH SAVED  nodes={n}  edges={e}  db={self.db_path}")
        except Exception as exc:
            log_exception(log, "EvidenceGraph.save", exc)

    def close(self):
        """Save and close the SQLite connection."""
        self.save()
        if self._conn:
            self._conn.close()
            log.debug(f"SQLite connection closed  db={self.db_path}")

    # ─── Debug dump ───────────────────────────────────────────────────────────

    def dump_graph(self) -> str:
        """
        Return a human-readable ASCII representation of the current graph.
        Useful at end of run — gets written to log file.
        """
        lines = [
            "═" * 60,
            f"EVIDENCE GRAPH DUMP — session={self.session_id}",
            f"nodes={self.graph.number_of_nodes()}  edges={self.graph.number_of_edges()}",
            "─" * 60,
        ]

        for nid, attrs in self.graph.nodes(data=True):
            if attrs.get("session_id") != self.session_id:
                continue
            verdict_str = (
                f"  [{attrs.get('verdict')} {attrs.get('confidence', 0):.2f}]"
                if attrs.get("verdict") else ""
            )
            lines.append(
                f"  [{attrs.get('node_type', '?'):<16}]  "
                f"{nid:<45}{verdict_str}"
            )

        lines.append("─" * 60)
        for src, dst, edata in self.graph.edges(data=True):
            lines.append(f"  {src}  ──[{edata.get('relation','?')}]──▶  {dst}")

        lines.append("═" * 60)
        text = "\n".join(lines)
        log.info("\n" + text)
        return text

    # ─── Context manager support ──────────────────────────────────────────────

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()