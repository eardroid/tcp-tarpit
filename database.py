import sqlite3
import threading
from pathlib import Path


class Database:
    def __init__(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.make_tables()

    def make_tables(self):
        with self.lock:
            self.connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    destination_port INTEGER NOT NULL,
                    source_port INTEGER NOT NULL,
                    ttl INTEGER NOT NULL,
                    window_size INTEGER NOT NULL,
                    spoofed_os TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    status TEXT NOT NULL,
                    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    released_at TEXT
                );
                CREATE TABLE IF NOT EXISTS stats (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    total_connections INTEGER NOT NULL DEFAULT 0,
                    scanner_connections INTEGER NOT NULL DEFAULT 0,
                    normal_connections INTEGER NOT NULL DEFAULT 0
                );
                INSERT OR IGNORE INTO stats (id) VALUES (1);
                """
            )
            self.connection.commit()

    def add_connection(self, source_ip, destination_port, source_port, ttl, window_size,
                       spoofed_os, classification, status):
        with self.lock:
            cursor = self.connection.execute(
                """
                INSERT INTO connections
                    (source_ip, destination_port, source_port, ttl, window_size,
                     spoofed_os, classification, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (source_ip, destination_port, source_port, ttl, window_size,
                 spoofed_os, classification, status),
            )
            if classification == "scanner":
                self.connection.execute(
                    "UPDATE stats SET total_connections = total_connections + 1, "
                    "scanner_connections = scanner_connections + 1 WHERE id = 1"
                )
            else:
                self.connection.execute(
                    "UPDATE stats SET total_connections = total_connections + 1, "
                    "normal_connections = normal_connections + 1 WHERE id = 1"
                )
            self.connection.commit()
            return cursor.lastrowid

    def set_status(self, connection_id, status):
        with self.lock:
            self.connection.execute(
                "UPDATE connections SET status = ?, released_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, connection_id),
            )
            self.connection.commit()

    def get_stats(self):
        with self.lock:
            row = self.connection.execute("SELECT * FROM stats WHERE id = 1").fetchone()
            return dict(row)

    def get_recent_connections(self, count=15):
        with self.lock:
            rows = self.connection.execute(
                "SELECT * FROM connections ORDER BY id DESC LIMIT ?", (count,)
            ).fetchall()
            return [dict(row) for row in rows]

    def close(self):
        with self.lock:
            self.connection.close()
