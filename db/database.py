"""
Database module — SQLite persistence layer for NIDS.
Handles all CRUD operations for devices, whitelist, alerts, and blocked IPs.
"""

import os
import sqlite3
import threading
from datetime import datetime
from typing import Dict, List

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "nids.db")


class Database:
    """Thread-safe SQLite database wrapper."""

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = os.path.abspath(db_path)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        """Create tables if they don't exist."""
        ddl = """
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL UNIQUE,
            mac         TEXT NOT NULL,
            status      TEXT DEFAULT 'Unknown',   -- Whitelisted | Unknown | Blocked
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS whitelist (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            ip      TEXT NOT NULL UNIQUE,
            mac     TEXT NOT NULL,
            label   TEXT DEFAULT '',
            added   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip      TEXT NOT NULL,
            mac         TEXT DEFAULT 'unknown',
            attack_type TEXT NOT NULL,
            confidence  REAL NOT NULL,
            action      TEXT DEFAULT 'Pending',  -- Blocked | Ignored | Whitelisted | Pending
            timestamp   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS blocked_ips (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ip         TEXT NOT NULL UNIQUE,
            mac        TEXT DEFAULT 'unknown',
            reason     TEXT DEFAULT '',
            blocked_at TEXT NOT NULL
        );
        """
        with self._lock:
            conn = self._connect()
            conn.executescript(ddl)
            conn.commit()
            conn.close()

    def upsert_device(self, ip: str, mac: str, status: str = None):
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._lock:
            conn = self._connect()
            existing = conn.execute(
                "SELECT status FROM devices WHERE ip=?", (ip,)
            ).fetchone()
            if existing:
                new_status = status if status else existing["status"]
                conn.execute(
                    "UPDATE devices SET mac=?, status=?, last_seen=? WHERE ip=?",
                    (mac, new_status, now, ip),
                )
            else:
                new_status = status if status else "Unknown"
                conn.execute(
                    "INSERT INTO devices (ip, mac, status, first_seen, last_seen) VALUES (?,?,?,?,?)",
                    (ip, mac, new_status, now, now),
                )
            conn.commit()
            conn.close()

    def get_all_devices(self) -> List[Dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT ip, mac, status, last_seen FROM devices ORDER BY last_seen DESC"
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def set_device_status(self, ip: str, status: str):
        with self._lock:
            conn = self._connect()
            conn.execute("UPDATE devices SET status=? WHERE ip=?", (status, ip))
            conn.commit()
            conn.close()

    def add_to_whitelist(self, ip: str, mac: str, label: str = ""):
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO whitelist (ip, mac, label, added) VALUES (?,?,?,?)",
                (ip, mac, label, now),
            )
            conn.execute("UPDATE devices SET status='Whitelisted' WHERE ip=?", (ip,))
            conn.commit()
            conn.close()

    def remove_from_whitelist(self, ip: str):
        with self._lock:
            conn = self._connect()
            conn.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
            conn.execute("UPDATE devices SET status='Unknown' WHERE ip=?", (ip,))
            conn.commit()
            conn.close()

    def get_whitelist(self) -> List[Dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT ip, mac, label, added FROM whitelist ORDER BY added DESC"
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def is_whitelisted(self, ip: str) -> bool:
        with self._lock:
            conn = self._connect()
            row = conn.execute("SELECT id FROM whitelist WHERE ip=?", (ip,)).fetchone()
            conn.close()
        return row is not None

    def add_alert(
        self,
        src_ip: str,
        mac: str,
        attack_type: str,
        confidence: float,
        action: str = "Pending",
    ) -> int:
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "INSERT INTO alerts (src_ip, mac, attack_type, confidence, action, timestamp) VALUES (?,?,?,?,?,?)",
                (src_ip, mac, attack_type, confidence, action, now),
            )
            alert_id = cur.lastrowid
            conn.commit()
            conn.close()
        return alert_id

    def update_alert_action(self, alert_id: int, action: str):
        with self._lock:
            conn = self._connect()
            conn.execute("UPDATE alerts SET action=? WHERE id=?", (action, alert_id))
            conn.commit()
            conn.close()

    def get_alerts(self, limit: int = 200) -> List[Dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT id, src_ip, mac, attack_type, confidence, action, timestamp "
                "FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def get_alert_counts(self) -> Dict:
        with self._lock:
            conn = self._connect()
            total = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            pending = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE action='Pending'"
            ).fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE action='Blocked'"
            ).fetchone()[0]
            conn.close()
        return {"total": total, "pending": pending, "blocked": blocked}

    def add_blocked_ip(self, ip: str, mac: str = "unknown", reason: str = ""):
        now = datetime.now().isoformat(sep=" ", timespec="seconds")
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR REPLACE INTO blocked_ips (ip, mac, reason, blocked_at) VALUES (?,?,?,?)",
                (ip, mac, reason, now),
            )
            conn.execute("UPDATE devices SET status='Blocked' WHERE ip=?", (ip,))
            conn.commit()
            conn.close()

    def remove_blocked_ip(self, ip: str):
        with self._lock:
            conn = self._connect()
            conn.execute("DELETE FROM blocked_ips WHERE ip=?", (ip,))
            wl = conn.execute("SELECT id FROM whitelist WHERE ip=?", (ip,)).fetchone()
            new_status = "Whitelisted" if wl else "Unknown"
            conn.execute("UPDATE devices SET status=? WHERE ip=?", (new_status, ip))
            conn.commit()
            conn.close()

    def get_blocked_ips(self) -> List[Dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT ip, mac, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC"
            ).fetchall()
            conn.close()
        return [dict(r) for r in rows]

    def is_blocked(self, ip: str) -> bool:
        with self._lock:
            conn = self._connect()
            row = conn.execute(
                "SELECT id FROM blocked_ips WHERE ip=?", (ip,)
            ).fetchone()
            conn.close()
        return row is not None

    def get_stats(self) -> Dict:
        with self._lock:
            conn = self._connect()
            devices = conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0]
            whitelisted = conn.execute("SELECT COUNT(*) FROM whitelist").fetchone()[0]
            alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
            blocked = conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0]
            conn.close()
        return {
            "devices": devices,
            "whitelisted": whitelisted,
            "alerts": alerts,
            "blocked": blocked,
        }
