#!/usr/bin/env python3
"""
VexTunnel - User & Account Management Engine (Hardened v1.3)
Author: VoxelVoid-0
License: MIT

Features:
- Salted PBKDF2-SHA256 cryptographic credential hashing
- SQLite WAL mode with 5000ms busy timeout & foreign keys
- Strict username/password sanitization (anti-injection)
- Linux user integration (/bin/false restricted shells)
- Automated expiration & quota tracking
"""

import sqlite3
import os
import sys
import subprocess
import datetime
import re
import secrets
import hashlib
from contextlib import contextmanager
from typing import List, Dict, Optional

def hash_password(password: str) -> str:
    """Generate salted PBKDF2-SHA256 password hash (200,000 iterations)."""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
    return f"pbkdf2_sha256${salt}${digest.hex()}"

def verify_password(password: str, stored_hash: str) -> bool:
    """Constant-time verification of password against stored PBKDF2-SHA256 hash."""
    if not stored_hash or not stored_hash.startswith("pbkdf2_sha256$"):
        return False
    try:
        parts = stored_hash.split("$")
        if len(parts) != 3:
            return False
        _, salt, digest_hex = parts
        calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 200_000)
        return secrets.compare_digest(calc.hex(), digest_hex)
    except Exception:
        return False

def get_default_db_path() -> str:
    if os.name == 'nt':
        return "vextunnel.db"
    if os.path.exists("/etc/vextunnel/vextunnel.db"):
        return "/etc/vextunnel/vextunnel.db"
    return "/etc/vextunnel/vextunnel.db"

DEFAULT_DB_PATH = get_default_db_path()

class UserManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
                os.chmod(db_dir, 0o700)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        """Concurrency-safe connection with WAL mode and 5000ms busy timeout."""
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
        conn.execute("PRAGMA foreign_keys=ON;")
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            # 1. Authoritative Schema for Users
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'ssh-ws',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    max_logins INTEGER DEFAULT 2,
                    quota_bytes INTEGER DEFAULT 0,
                    used_bytes INTEGER DEFAULT 0,
                    last_counter_bytes INTEGER DEFAULT 0,
                    last_quota_alert_pct INTEGER DEFAULT 0,
                    quota_status TEXT DEFAULT 'active',
                    last_quota_sync TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            """)

            # 2. Authoritative Active Sessions Tracking Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    connected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'active'
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_active_sessions_user ON active_sessions(username, status);")
            conn.commit()

            # 3. Hard Migration: Drop legacy 'password' plaintext column if present (Fail-Hard, No Silent Fallback)
            cols = [col[1] for col in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "password" in cols:
                has_hash_col = "password_hash" in cols
                sel_query = "SELECT id, password" + (", password_hash" if has_hash_col else "") + " FROM users"
                rows = conn.execute(sel_query).fetchall()
                migrated_hashes = {}
                for r in rows:
                    p_plain = r["password"]
                    p_hash = r["password_hash"] if has_hash_col else ""
                    if p_hash and p_hash.startswith("pbkdf2_sha256$"):
                        migrated_hashes[r["id"]] = p_hash
                    elif p_plain and p_plain != "[PROTECTED]":
                        migrated_hashes[r["id"]] = hash_password(p_plain)

                conn.execute("ALTER TABLE users RENAME TO users_legacy;")
                conn.execute("""
                    CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        protocol TEXT NOT NULL DEFAULT 'ssh-ws',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        expires_at TIMESTAMP NOT NULL,
                        max_logins INTEGER DEFAULT 2,
                        quota_bytes INTEGER DEFAULT 0,
                        used_bytes INTEGER DEFAULT 0,
                        quota_status TEXT DEFAULT 'active',
                        last_quota_sync TIMESTAMP,
                        status TEXT DEFAULT 'active'
                    )
                """)
                legacy_rows = conn.execute("SELECT * FROM users_legacy").fetchall()
                for lr in legacy_rows:
                    row_id = lr["id"]
                    final_hash = migrated_hashes.get(row_id)
                    if not final_hash:
                        # Transaction rollback: Restore original state and abort without silent fallbacks
                        conn.execute("DROP TABLE users;")
                        conn.execute("ALTER TABLE users_legacy RENAME TO users;")
                        conn.commit()
                        raise RuntimeError(
                            f"Database migration aborted: Cannot derive password hash for legacy user '{lr['username']}' (ID: {row_id}). "
                            f"Transaction rolled back safely. Manual administrative reset required."
                        )
                    conn.execute("""
                        INSERT INTO users (id, username, password_hash, protocol, created_at, expires_at, max_logins, quota_bytes, used_bytes, quota_status, last_quota_sync, status)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        row_id,
                        lr["username"],
                        final_hash,
                        lr["protocol"] if "protocol" in lr.keys() else "ssh-ws",
                        lr["created_at"] if "created_at" in lr.keys() else datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        lr["expires_at"],
                        lr["max_logins"] if "max_logins" in lr.keys() else 2,
                        lr["quota_bytes"] if "quota_bytes" in lr.keys() else 0,
                        lr["used_bytes"] if "used_bytes" in lr.keys() else 0,
                        lr["quota_status"] if "quota_status" in lr.keys() else "active",
                        lr["last_quota_sync"] if "last_quota_sync" in lr.keys() else None,
                        lr["status"] if "status" in lr.keys() else "active"
                    ))
                conn.execute("DROP TABLE users_legacy;")
                conn.commit()

            # Ensure new columns exist in case table was created with an intermediate schema
            cols_after = [col[1] for col in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "quota_bytes" not in cols_after:
                conn.execute("ALTER TABLE users ADD COLUMN quota_bytes INTEGER DEFAULT 0")
            if "used_bytes" not in cols_after:
                conn.execute("ALTER TABLE users ADD COLUMN used_bytes INTEGER DEFAULT 0")
            if "last_counter_bytes" not in cols_after:
                conn.execute("ALTER TABLE users ADD COLUMN last_counter_bytes INTEGER DEFAULT 0")
            if "last_quota_alert_pct" not in cols_after:
                conn.execute("ALTER TABLE users ADD COLUMN last_quota_alert_pct INTEGER DEFAULT 0")
            if "quota_status" not in cols_after:
                conn.execute("ALTER TABLE users ADD COLUMN quota_status TEXT DEFAULT 'active'")
            if "last_quota_sync" not in cols_after:
                conn.execute("ALTER TABLE users ADD COLUMN last_quota_sync TIMESTAMP")
            conn.commit()

        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            if os.path.exists(self.db_path):
                try:
                    os.chmod(self.db_path, 0o600)
                except OSError:
                    pass

    def add_user(self, username: str, password: str, days: int, protocol: str = "ssh-ws", max_logins: int = 2, quota_bytes: int = 0) -> Dict:
        """Create a new VPN/SSH user with cryptographic password hashing and strict validation."""
        username = username.strip().lower()
        if not re.fullmatch(r"^[a-zA-Z0-9_-]{2,32}$", username):
            raise ValueError("Username must be 2-32 characters (alphanumeric, underscores, hyphens only).")

        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if any(ch in password for ch in ("\n", "\r", "\x00")):
            raise ValueError("Password cannot contain newlines or null control characters.")

        expires_at = datetime.datetime.now() + datetime.timedelta(days=days)
        exp_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
        exp_date_chage = expires_at.strftime("%Y-%m-%d")
        pwd_hash = hash_password(password)

        # System user creation if on Linux as root
        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            check = subprocess.run(["id", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode == 0:
                raise ValueError(f"System user '{username}' already exists.")

            cmd_add = ["useradd", "-M", "-s", "/bin/false", "-e", exp_date_chage, username]
            res = subprocess.run(cmd_add, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Failed to create system user: {res.stderr}")

            cmd_pass = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _, err = cmd_pass.communicate(input=f"{username}:{password}")
            if cmd_pass.returncode != 0:
                subprocess.run(["userdel", "-f", username])
                raise RuntimeError(f"Failed to set user password: {err}")

        # Record in SQLite with hashed password (no plaintext column)
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO users (username, password_hash, protocol, expires_at, max_logins, quota_bytes, used_bytes, quota_status, status)
                VALUES (?, ?, ?, ?, ?, ?, 0, 'active', 'active')
            """, (username, pwd_hash, protocol, exp_str, max_logins, quota_bytes))
            conn.commit()

        return {
            "username": username,
            "password_hash": pwd_hash,
            "expires_at": exp_str,
            "days": days,
            "max_logins": max_logins,
            "quota_bytes": quota_bytes,
            "quota_status": "active",
            "status": "active"
        }

    def authenticate_user(self, username: str, password: str) -> bool:
        """Authoritatively authenticate user against PBKDF2-SHA256 hash and verify active account status."""
        username = username.strip().lower()
        now = datetime.datetime.now()
        with self._get_connection() as conn:
            row = conn.execute("SELECT password_hash, status, quota_status, expires_at FROM users WHERE username = ?", (username,)).fetchone()
            if not row:
                return False
            # Authoritative Expiry Check: Reject immediately and commit expired status to DB
            try:
                exp = datetime.datetime.strptime(row["expires_at"], "%Y-%m-%d %H:%M:%S")
                if now >= exp:
                    if row["status"] != "expired":
                        conn.execute("UPDATE users SET status = 'expired' WHERE username = ?", (username,))
                        conn.commit()
                    return False
            except Exception:
                pass
            if row["status"] != "active":
                return False
            if "quota_status" in row.keys() and row["quota_status"] == "quota_exceeded":
                return False
            return verify_password(password, row["password_hash"])

    def change_password(self, username: str, new_password: str) -> bool:
        """Update user password on Linux system and SQLite database."""
        username = username.strip().lower()
        if len(new_password) < 8:
            raise ValueError("Password must be at least 8 characters long.")
        if any(ch in new_password for ch in ("\n", "\r", "\x00")):
            raise ValueError("Password cannot contain newlines or null control characters.")

        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            cmd_pass = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _, err = cmd_pass.communicate(input=f"{username}:{new_password}")
            if cmd_pass.returncode != 0:
                raise RuntimeError(f"Failed to update Linux system password: {err}")

        pwd_hash = hash_password(new_password)
        with self._get_connection() as conn:
            cur = conn.execute("UPDATE users SET password_hash = ? WHERE username = ?", (pwd_hash, username))
            conn.commit()
            return cur.rowcount > 0

    def delete_user(self, username: str) -> bool:
        """Delete user from Linux system and SQLite database."""
        username = username.strip().lower()
        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            subprocess.run(["userdel", "-f", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        with self._get_connection() as conn:
            cur = conn.execute("DELETE FROM users WHERE username = ?", (username,))
            conn.commit()
            return cur.rowcount > 0

    def renew_user(self, username: str, days: int) -> Optional[Dict]:
        """Renew user subscription by adding days to current expiry date."""
        username = username.strip().lower()
        with self._get_connection() as conn:
            user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            if not user:
                return None

            current_exp = datetime.datetime.strptime(user["expires_at"], "%Y-%m-%d %H:%M:%S")
            now = datetime.datetime.now()
            base_date = max(now, current_exp)
            new_exp = base_date + datetime.timedelta(days=days)
            new_exp_str = new_exp.strftime("%Y-%m-%d %H:%M:%S")
            exp_date_chage = new_exp.strftime("%Y-%m-%d")

            if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
                subprocess.run(["chage", "-E", exp_date_chage, username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["passwd", "-u", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            conn.execute("UPDATE users SET expires_at = ?, status = 'active' WHERE username = ?", (new_exp_str, username))
            conn.commit()

            return {
                "username": username,
                "new_expires_at": new_exp_str,
                "extended_days": days
            }

    def lock_user(self, username: str) -> bool:
        """Lock user account without deleting records."""
        username = username.strip().lower()
        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            subprocess.run(["passwd", "-l", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self._get_connection() as conn:
            cur = conn.execute("UPDATE users SET status = 'locked' WHERE username = ?", (username,))
            conn.commit()
            return cur.rowcount > 0

    def unlock_user(self, username: str) -> bool:
        """Unlock user account."""
        username = username.strip().lower()
        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            subprocess.run(["passwd", "-u", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with self._get_connection() as conn:
            cur = conn.execute("UPDATE users SET status = 'active' WHERE username = ?", (username,))
            conn.commit()
            return cur.rowcount > 0

    def list_users(self) -> List[Dict]:
        """List all users with remaining days, quotas, and status, and synchronize expired statuses."""
        users = []
        now = datetime.datetime.now()
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY expires_at ASC").fetchall()
            expired_to_sync = []
            for r in rows:
                exp = datetime.datetime.strptime(r["expires_at"], "%Y-%m-%d %H:%M:%S")
                diff = exp - now
                remaining_days = max(0, diff.days)
                is_expired = diff.total_seconds() <= 0
                status = "expired" if is_expired else r["status"]
                cols = r.keys()

                if is_expired and r["status"] == "active":
                    expired_to_sync.append((r["id"], r["username"]))

                users.append({
                    "id": r["id"],
                    "username": r["username"],
                    "password_hash": r["password_hash"],
                    "protocol": r["protocol"],
                    "expires_at": r["expires_at"],
                    "remaining_days": remaining_days,
                    "max_logins": r["max_logins"],
                    "quota_bytes": r["quota_bytes"],
                    "used_bytes": r["used_bytes"],
                    "last_counter_bytes": r["last_counter_bytes"] if "last_counter_bytes" in cols else 0,
                    "last_quota_alert_pct": r["last_quota_alert_pct"] if "last_quota_alert_pct" in cols else 0,
                    "quota_status": r["quota_status"] if "quota_status" in cols else "active",
                    "last_quota_sync": r["last_quota_sync"] if "last_quota_sync" in cols else None,
                    "status": status
                })

            # Authoritatively commit expired accounts to DB and lock system user
            for uid_row, uname in expired_to_sync:
                conn.execute("UPDATE users SET status = 'expired' WHERE id = ?", (uid_row,))
                if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
                    subprocess.run(["passwd", "-l", uname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if expired_to_sync:
                conn.commit()

        return users

    def cleanup_expired(self) -> int:
        """Lock expired accounts safely and dispatch Telegram alert if configured."""
        count = 0
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            expired_users = conn.execute("SELECT username, expires_at FROM users WHERE expires_at <= ? AND status = 'active'", (now,)).fetchall()
            for row in expired_users:
                uname = row["username"]
                exp_at = row["expires_at"]
                if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
                    subprocess.run(["passwd", "-l", uname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                conn.execute("UPDATE users SET status = 'expired' WHERE username = ?", (uname,))
                count += 1
                try:
                    from core.telegram_notifier import alert_account_expired
                    alert_account_expired(uname, exp_at)
                except Exception:
                    pass
            conn.commit()
        return count

if __name__ == "__main__":
    mgr = UserManager()
    if len(sys.argv) > 1:
        cmd = sys.argv[1].lower()
        if cmd == "cleanup":
            cleaned = mgr.cleanup_expired()
            print(f"Cleaned up {cleaned} expired users.")
        elif cmd == "add" and len(sys.argv) >= 5:
            username = sys.argv[2]
            password = sys.argv[3]
            days = int(sys.argv[4])
            res = mgr.add_user(username, password, days)
            print(f"SUCCESS: Created user {res['username']} (expires {res['expires_at']})")
        elif cmd == "list":
            users = mgr.list_users()
            print(f"{'USERNAME':<16} {'STATUS':<10} {'DAYS LEFT':<10} {'EXPIRES AT'}")
            print("-" * 55)
            for u in users:
                print(f"{u['username']:<16} {u['status']:<10} {u['remaining_days']:<10} {u['expires_at']}")
        elif cmd == "delete" and len(sys.argv) >= 3:
            username = sys.argv[2]
            if mgr.delete_user(username):
                print(f"SUCCESS: Deleted user {username}")
            else:
                print(f"FAILED: User {username} not found")
        else:
            print("Usage: user_manager.py [add <user> <pass> <days> | list | delete <user> | cleanup]")
    else:
        print("VexTunnel UserManager initialized. Total registered users:", len(mgr.list_users()))
