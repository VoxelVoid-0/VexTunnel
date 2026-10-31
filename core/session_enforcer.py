#!/usr/bin/env python3
"""
VexTunnel - Session Concurrency & Login Limit Enforcer
Author: VoxelVoid-0
License: MIT

Enforces max_logins per user account in real-time by inspecting
active Dropbear/SSH user sessions and terminating unauthorized concurrent logins.
"""

import os
import sys
import time
import subprocess
import signal
import sqlite3
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [Enforcer] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("SessionEnforcer")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.user_manager import UserManager, DEFAULT_DB_PATH

LOG_FILE = "/var/log/vextunnel/session.log"

def get_active_dropbear_sessions() -> dict:
    """Return dictionary of {username: [pid1, pid2, ...]} for active Dropbear sessions."""
    if os.name == 'nt':
        return {}

    user_pids = {}
    try:
        res = subprocess.run(["ps", "-eo", "user,pid,args"], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            # Dropbear authenticated session runs under the client's username
            if "dropbear" in line and "-p" not in line and "grep" not in line:
                parts = line.split()
                if len(parts) >= 2:
                    uname = parts[0]
                    try:
                        pid = int(parts[1])
                    except ValueError:
                        continue

                    # Filter out system service accounts
                    if uname not in ("root", "dropbear", "daemon", "nobody"):
                        if uname not in user_pids:
                            user_pids[uname] = []
                        user_pids[uname].append(pid)
    except Exception as e:
        logger.debug(f"Error querying process table: {e}")

    return user_pids

def enforce_concurrency_limits(db_path: str = DEFAULT_DB_PATH) -> int:
    """Scan and terminate sessions exceeding max_logins. Return count of killed PIDs."""
    if os.name == 'nt':
        return 0

    killed_count = 0
    active_processes = get_active_dropbear_sessions()
    if not active_processes:
        return 0

    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT username, max_logins, status FROM users").fetchall()
        user_limits = {u["username"]: {"max": u["max_logins"], "status": u["status"]} for u in users}
        conn.close()
    except Exception as e:
        logger.debug(f"DB read error: {e}")
        return 0

    for username, pids in active_processes.items():
        user_info = user_limits.get(username)
        # If user is expired, locked, or not in DB, terminate all sessions
        if not user_info or user_info["status"] != "active":
            logger.warning(f"Unauthorized/Expired user '{username}' has {len(pids)} active sessions. Terminating all.")
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_count += 1
                except ProcessLookupError:
                    pass
            continue

        max_allowed = user_info["max"]
        if len(pids) > max_allowed:
            # Sort PIDs to keep older sessions and kill newest rogue connections
            pids.sort()
            excess_pids = pids[max_allowed:]
            logger.warning(f"User '{username}' exceeded max_logins ({len(pids)}/{max_allowed}). Terminating {len(excess_pids)} excess sessions.")
            for pid in excess_pids:
                try:
                    os.kill(pid, signal.SIGTERM)
                    time.sleep(0.1)
                    # Force kill if still lingering
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    killed_count += 1
                    logger.info(f"Killed excess session PID {pid} for user '{username}'")
                except ProcessLookupError:
                    pass

    return killed_count

def run_daemon(interval_sec: int = 10, db_path: str = DEFAULT_DB_PATH):
    """Run persistent background session enforcer daemon."""
    logger.info(f"VexTunnel Session Enforcer Daemon started (polling every {interval_sec}s)...")
    while True:
        try:
            enforce_concurrency_limits(db_path)
        except Exception as e:
            logger.error(f"Enforcer loop exception: {e}")
        time.sleep(interval_sec)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--once":
        killed = enforce_concurrency_limits()
        print(f"Enforcement check complete. Killed {killed} rogue sessions.")
    else:
        run_daemon()
