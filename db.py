import os
import sqlite3
import threading

class Database:
    """One object that holds the connection to the database.
    app.py creates it once: db = Database(path)
    """

    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self.create_tables()

    def create_tables(self):
        with self.lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS students (
                    IDs INTEGER PRIMARY KEY,
                    FN TEXT NOT NULL,
                    LN TEXT NOT NULL,
                    DMajor TEXT NOT NULL,
                    Level TEXT NOT NULL,
                    Email TEXT NOT NULL,
                    Password TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS reports (
                    IDr INTEGER PRIMARY KEY,
                    IDs INTEGER NOT NULL,
                    Title TEXT NOT NULL,
                    Type TEXT NOT NULL,
                    K1 TEXT NOT NULL,
                    K2 TEXT NOT NULL,
                    K3 TEXT NOT NULL,
                    File TEXT NOT NULL,
                    FileName TEXT NOT NULL,
                    Date TEXT NOT NULL,
                    FOREIGN KEY (IDs) REFERENCES students(IDs) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS access_requests (
                    IDq INTEGER PRIMARY KEY AUTOINCREMENT,
                    IDr INTEGER NOT NULL,
                    Requester INTEGER NOT NULL,
                    Owner INTEGER NOT NULL,
                    Status TEXT NOT NULL DEFAULT 'pending',
                    FOREIGN KEY (IDr) REFERENCES reports(IDr) ON DELETE CASCADE,
                    FOREIGN KEY (Requester) REFERENCES students(IDs) ON DELETE CASCADE,
                    FOREIGN KEY (Owner) REFERENCES students(IDs) ON DELETE CASCADE
                );
            """)
            self.conn.commit()

    def execute(self, sql, params=()):
        """Execute a query with optional parameters and return the cursor."""
        with self.lock:
            cursor = self.conn.execute(sql, params)
            self.conn.commit()
            return cursor

    def one(self, sql, params=()):
        with self.lock:
            row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None

    def all(self, sql, params=()):
        with self.lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]