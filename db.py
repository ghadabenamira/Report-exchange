import os
import sqlite3
import threading
 
 
class Database:
    """One object that holds the connection to the database.
    app.py creates it once: db = Database(path)
    """
 
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()          # Flask can run several requests at once
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row   # rows behave like dicts
        self.conn.execute("PRAGMA foreign_keys = ON")   # enforce the relationships
        self.create_tables()
 
    def create_tables(self):
        with self.lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS students (
                IDs      INTEGER PRIMARY KEY,          -- 8 digits, given by the student
                FN       TEXT NOT NULL,
                LN       TEXT NOT NULL,
                DMajor   TEXT NOT NULL,
                Level    TEXT NOT NULL,
                Email    TEXT NOT NULL,
                Password TEXT NOT NULL
            );
 
            -- ONE student  ->  MANY reports  (foreign key reports.IDs -> students.IDs)
            CREATE TABLE IF NOT EXISTS reports (
                IDr      INTEGER PRIMARY KEY AUTOINCREMENT,
                IDs      INTEGER NOT NULL,
                Title    TEXT NOT NULL,
                Type     TEXT NOT NULL,
                K1       TEXT NOT NULL,
                K2       TEXT NOT NULL,
                K3       TEXT NOT NULL,
                File     TEXT NOT NULL,
                FileName TEXT NOT NULL,
                Date     TEXT NOT NULL,
                FOREIGN KEY (IDs) REFERENCES students(IDs) ON DELETE CASCADE
            );
 
            CREATE TABLE IF NOT EXISTS access_requests (
                IDq       INTEGER PRIMARY KEY AUTOINCREMENT,
                IDr       INTEGER NOT NULL,
                Requester INTEGER NOT NULL,
                Owner     INTEGER NOT NULL,
                Status    TEXT NOT NULL DEFAULT 'pending',
                FOREIGN KEY (IDr)       REFERENCES reports(IDr)    ON DELETE CASCADE,
                FOREIGN KEY (Requester) REFERENCES students(IDs)  ON DELETE CASCADE,
                FOREIGN KEY (Owner)     REFERENCES students(IDs)  ON DELETE CASCADE
            );
            """)
            self.conn.commit()
 
    # ---- small helpers used by app.py ----
    def execute(self, sql, params=()):
        """INSERT / UPDATE / DELETE. Returns the cursor (cursor.lastrowid = new id)."""
        with self.lock:
            cur = self.conn.execute(sql, params)
            self.conn.commit()
            return cur
 
    def one(self, sql, params=()):
        with self.lock:
            row = self.conn.execute(sql, params).fetchone()
        return dict(row) if row else None
 
    def all(self, sql, params=()):
        with self.lock:
            rows = self.conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
 