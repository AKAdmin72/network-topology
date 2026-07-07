import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

DB_PATH = Path(os.getenv("DATA_DIR", "/data")) / "topology.db"


def init():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT NOT NULL,
            type       TEXT NOT NULL,
            node_id    TEXT NOT NULL,
            node_label TEXT,
            detail     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

        CREATE TABLE IF NOT EXISTS link_traffic (
            switch_ip TEXT NOT NULL,
            port_num  TEXT NOT NULL,
            ts        TEXT NOT NULL,
            in_bps    REAL,
            out_bps   REAL,
            in_err_s  REAL,
            out_err_s REAL,
            PRIMARY KEY (switch_ip, port_num, ts)
        );
        CREATE INDEX IF NOT EXISTS idx_lt_key_ts ON link_traffic(switch_ip, port_num, ts);

        CREATE TABLE IF NOT EXISTS port_counters (
            switch_ip  TEXT NOT NULL,
            port_num   TEXT NOT NULL,
            ts         TEXT NOT NULL,
            in_octets  INTEGER,
            out_octets INTEGER,
            in_errors  INTEGER,
            out_errors INTEGER,
            PRIMARY KEY (switch_ip, port_num)
        );

        CREATE TABLE IF NOT EXISTS mac_table (
            mac        TEXT NOT NULL,
            switch_ip  TEXT NOT NULL,
            port_num   TEXT NOT NULL,
            vlan_id    INTEGER,
            is_edge    INTEGER DEFAULT 0,
            ts         TEXT NOT NULL,
            PRIMARY KEY (mac, switch_ip, port_num)
        );
        CREATE INDEX IF NOT EXISTS idx_mac_mac ON mac_table(mac);
        CREATE INDEX IF NOT EXISTS idx_mac_sw  ON mac_table(switch_ip, is_edge);

        CREATE TABLE IF NOT EXISTS node_overrides (
            node_id    TEXT PRIMARY KEY,
            node_type  TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)


def log_event(event_type: str, node_id: str, label: str = None, detail: dict = None):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO events (ts, type, node_id, node_label, detail) VALUES (?,?,?,?,?)",
            (ts, event_type, node_id, label, json.dumps(detail) if detail else None),
        )


def get_events(limit: int = 100) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT ts, type, node_id, node_label, detail FROM events ORDER BY ts DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_counters() -> dict:
    """Returns {(switch_ip, port_num): {ts, in_octets, out_octets, in_errors, out_errors}}"""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM port_counters").fetchall()
    return {(r["switch_ip"], r["port_num"]): dict(r) for r in rows}


def save_link_traffic(entries: list[dict]):
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            """INSERT OR IGNORE INTO link_traffic
               (switch_ip, port_num, ts, in_bps, out_bps, in_err_s, out_err_s)
               VALUES (?,?,?,?,?,?,?)""",
            [(e["switch_ip"], e["port_num"], e["ts"],
              e.get("in_bps"), e.get("out_bps"),
              e.get("in_err_s"), e.get("out_err_s")) for e in entries],
        )


def get_link_traffic(switch_ip: str, port_num: str, hours: int = 24) -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT ts, in_bps, out_bps, in_err_s, out_err_s
               FROM link_traffic WHERE switch_ip=? AND port_num=? AND ts>=?
               ORDER BY ts ASC""",
            (switch_ip, port_num, cutoff),
        ).fetchall()
    return [dict(r) for r in rows]


def get_top_ports(hours: int, limit: int) -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT switch_ip, port_num,
                      AVG(COALESCE(in_bps,  0)) AS avg_in,
                      AVG(COALESCE(out_bps, 0)) AS avg_out,
                      MAX(COALESCE(in_bps,  0)) AS max_in,
                      MAX(COALESCE(out_bps, 0)) AS max_out
               FROM link_traffic
               WHERE ts >= ?
               GROUP BY switch_ip, port_num
               ORDER BY MAX(COALESCE(in_bps, 0) + COALESCE(out_bps, 0)) DESC
               LIMIT ?""",
            (cutoff, limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_switch_traffic(hours: int) -> list[dict]:
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT switch_ip,
                      AVG(COALESCE(in_bps,  0)) AS avg_in,
                      AVG(COALESCE(out_bps, 0)) AS avg_out,
                      MAX(COALESCE(in_bps,  0)) AS max_in,
                      MAX(COALESCE(out_bps, 0)) AS max_out,
                      COUNT(DISTINCT port_num)   AS active_ports
               FROM link_traffic
               WHERE ts >= ?
               GROUP BY switch_ip
               ORDER BY (AVG(COALESCE(in_bps, 0)) + AVG(COALESCE(out_bps, 0))) DESC""",
            (cutoff,),
        ).fetchall()
    return [dict(r) for r in rows]


def purge_old_traffic(days: int):
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM link_traffic WHERE ts < ?", (cutoff,))


def save_mac_entries(entries: list[dict]):
    if not entries:
        return
    with sqlite3.connect(DB_PATH) as conn:
        conn.executemany(
            """INSERT OR REPLACE INTO mac_table
               (mac, switch_ip, port_num, vlan_id, is_edge, ts)
               VALUES (?,?,?,?,?,?)""",
            [(e["mac"], e["switch_ip"], e["port_num"],
              e.get("vlan_id"), e.get("is_edge", 0), e["ts"]) for e in entries],
        )


def search_macs(q: str, limit: int = 20) -> list[dict]:
    """Search MACs by prefix (colon-separated). Returns is_edge=1 entries first."""
    q = q.lower().strip()
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT mac, switch_ip, port_num, vlan_id, is_edge, ts
               FROM mac_table WHERE mac LIKE ?
               ORDER BY is_edge DESC, ts DESC LIMIT ?""",
            (q + "%", limit),
        ).fetchall()
    return [dict(r) for r in rows]


def get_mac_entries(mac: str) -> list[dict]:
    """All entries for an exact MAC address."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT mac, switch_ip, port_num, vlan_id, is_edge, ts
               FROM mac_table WHERE mac = ? ORDER BY is_edge DESC, ts DESC""",
            (mac,),
        ).fetchall()
    return [dict(r) for r in rows]


def purge_old_macs(minutes: int):
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=minutes)).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM mac_table WHERE ts < ?", (cutoff,))


def get_node_type_overrides() -> dict[str, str]:
    """Returns {node_id: node_type} for all manual overrides."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT node_id, node_type FROM node_overrides").fetchall()
    return {r["node_id"]: r["node_type"] for r in rows}


def get_switch_macs(switch_ip: str) -> list[dict]:
    """Returns edge MAC entries for a switch ordered by port_num, mac."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT mac, port_num, vlan_id, ts
               FROM mac_table WHERE switch_ip=? AND is_edge=1
               ORDER BY port_num, mac""",
            (switch_ip,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_mac_counts() -> dict:
    """Returns {switch_ip: {total, edge}} MAC counts from current mac_table."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT switch_ip, COUNT(*) AS total, SUM(is_edge) AS edge
               FROM mac_table GROUP BY switch_ip"""
        ).fetchall()
    return {r["switch_ip"]: {"total": r["total"], "edge": r["edge"] or 0} for r in rows}


def set_node_type_override(node_id: str, node_type: str):
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO node_overrides (node_id, node_type, updated_at) VALUES (?,?,?)",
            (node_id, node_type, ts),
        )


def save_counters(entries: dict):
    """entries: {(switch_ip, port_num): {ts, in_octets, out_octets, in_errors, out_errors}}"""
    with sqlite3.connect(DB_PATH) as conn:
        for (switch_ip, port_num), d in entries.items():
            conn.execute(
                """INSERT OR REPLACE INTO port_counters
                   (switch_ip, port_num, ts, in_octets, out_octets, in_errors, out_errors)
                   VALUES (?,?,?,?,?,?,?)""",
                (switch_ip, port_num, d["ts"],
                 d.get("in_octets"), d.get("out_octets"),
                 d.get("in_errors"), d.get("out_errors")),
            )


def get_known_hostnames() -> dict[str, str]:
    """Return {ip: hostname} from the latest switch_appeared events where hostname != ip."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("""
            SELECT node_id, json_extract(detail, '$.ip') AS ip
            FROM events
            WHERE type = 'switch_appeared'
              AND detail IS NOT NULL
              AND node_id != json_extract(detail, '$.ip')
            GROUP BY json_extract(detail, '$.ip')
            HAVING ts = MAX(ts)
        """).fetchall()
    return {
        ip: name for name, ip in rows
        if ip and "no such" not in name.lower() and "not available" not in name.lower()
    }
