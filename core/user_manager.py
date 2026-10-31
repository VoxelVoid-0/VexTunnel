#!/usr/bin/env python3
"""
VexTunnel - User & Account Management Engine
Author: VexElvn
License: MIT

Features:
- SQLite-backed local account tracking
- Linux user integration (useradd with /bin/false restricted shell)
- Expiration date calculations & automated cleanup
- Zero data leaks, zero external telemetry
"""

import sqlite3
import os
import sys
import subprocess
import datetime
from contextlib import contextmanager
from typing import List, Dict, Optional

def get_default_db_path() -> str:
    if os.name == 'nt':
        return "vextunnel.db"
    if os.path.exists("/etc/vextunnel/vextunnel.db"):
        return "/etc/vextunnel/vextunnel.db"
    if os.path.exists("/etc/securetunnel/securetunnel.db"):
        return "/etc/securetunnel/securetunnel.db"
    return "/etc/vextunnel/vextunnel.db"

DEFAULT_DB_PATH = get_default_db_path()

class UserManager:
    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
        self._init_db()

    @contextmanager
    def _get_connection(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    protocol TEXT NOT NULL DEFAULT 'ssh-ws',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    max_logins INTEGER DEFAULT 2,
                    status TEXT DEFAULT 'active'
                )
            """)
            conn.commit()

    def add_user(self, username: str, password: str, days: int, protocol: str = "ssh-ws", max_logins: int = 2) -> Dict:
        """Create a new VPN/SSH user."""
        username = username.strip().lower()
        if not username.isalnum():
            raise ValueError("Username must be alphanumeric with no spaces.")

        expires_at = datetime.datetime.now() + datetime.timedelta(days=days)
        exp_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
        exp_date_chage = expires_at.strftime("%Y-%m-%d")

        # System user creation if on Linux
        if os.name != 'nt':
            # Check if user already exists in Linux
            check = subprocess.run(["id", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check.returncode == 0:
                raise ValueError(f"System user '{username}' already exists.")

            # Create user with restricted shell (/bin/false)
            cmd_add = ["useradd", "-M", "-s", "/bin/false", "-e", exp_date_chage, username]
            res = subprocess.run(cmd_add, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f"Failed to create system user: {res.stderr}")

            # Set password
            cmd_pass = subprocess.Popen(["chpasswd"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            _, err = cmd_pass.communicate(input=f"{username}:{password}")
            if cmd_pass.returncode != 0:
                # Rollback system user
                subprocess.run(["userdel", "-f", username])
                raise RuntimeError(f"Failed to set user password: {err}")

        # Record in SQLite
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO users (username, password, protocol, expires_at, max_logins, status)
                VALUES (?, ?, ?, ?, ?, 'active')
            """, (username, password, protocol, exp_str, max_logins))
            conn.commit()

        return {
            "username": username,
            "password": password,
            "protocol": protocol,
            "expires_at": exp_str,
            "days": days,
            "max_logins": max_logins
        }

    def delete_user(self, username: str) -> bool:
        """Delete user from system and database."""
        username = username.strip().lower()
        if os.name != 'nt':
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
            # If already expired, extend from now; else extend from current_exp
            base_date = max(now, current_exp)
            new_exp = base_date + datetime.timedelta(days=days)
            new_exp_str = new_exp.strftime("%Y-%m-%d %H:%M:%S")
            exp_date_chage = new_exp.strftime("%Y-%m-%d")

            if os.name != 'nt':
                # Update expiry in Linux shadow and unlock account
                subprocess.run(["chage", "-E", exp_date_chage, username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["passwd", "-u", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            conn.execute("UPDATE users SET expires_at = ?, status = 'active' WHERE username = ?", (new_exp_str, username))
            conn.commit()

            return {
                "username": username,
                "new_expires_at": new_exp_str,
                "extended_days": days
            }

    def list_users(self) -> List[Dict]:
        """List all users with remaining days and status."""
        users = []
        now = datetime.datetime.now()
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY expires_at ASC").fetchall()
            for r in rows:
                exp = datetime.datetime.strptime(r["expires_at"], "%Y-%m-%d %H:%M:%S")
                diff = exp - now
                remaining_days = max(0, diff.days)
                is_expired = diff.total_seconds() <= 0
                status = "expired" if is_expired else r["status"]

                users.append({
                    "id": r["id"],
                    "username": r["username"],
                    "password": r["password"],
                    "protocol": r["protocol"],
                    "expires_at": r["expires_at"],
                    "remaining_days": remaining_days,
                    "max_logins": r["max_logins"],
                    "status": status
                })
        return users

    def cleanup_expired(self) -> int:
        """Lock or remove expired accounts safely."""
        count = 0
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self._get_connection() as conn:
            expired_users = conn.execute("SELECT username FROM users WHERE expires_at <= ? AND status = 'active'", (now,)).fetchall()
            for row in expired_users:
                uname = row["username"]
                if os.name != 'nt':
                    # Lock user password instead of destructive deletion
                    subprocess.run(["passwd", "-l", uname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                conn.execute("UPDATE users SET status = 'expired' WHERE username = ?", (uname,))
                count += 1
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
        elif cmd == "renew" and len(sys.argv) >= 4:
            username = sys.argv[2]
            days = int(sys.argv[3])
            res = mgr.renew_user(username, days)
            if res:
                print(f"SUCCESS: Renewed user {username} until {res['new_expires_at']}")
            else:
                print(f"FAILED: User {username} not found")
        else:
            print("Usage: user_manager.py [add <user> <pass> <days> | list | delete <user> | renew <user> <days> | cleanup]")
    else:
        print("SecureTunnel UserManager initialized. Total registered users:", len(mgr.list_users()))
