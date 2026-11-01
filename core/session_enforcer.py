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
from core.quota_manager import sync_all_quotas

LOG_FILE = "/var/log/vextunnel/session.log"

SYSTEM_USERS = {
    "root", "ubuntu", "debian", "centos", "admin", "ec2-user", "fedora",
    "rocky", "alma", "opc", "dropbear", "sshd", "daemon", "nobody",
    "systemd-network", "systemd-resolve", "messagebus", "syslog", "_apt", "sync"
}

def is_system_or_admin_user(username: str) -> bool:
    """Return True if username is an OS administrative or non-tunnel system account."""
    if not username or username in SYSTEM_USERS:
        return True
    if os.name != 'nt':
        try:
            import pwd
            entry = pwd.getpwnam(username)
            if entry.pw_uid < 1000:
                return True
            # Non-restricted interactive shells indicate legitimate system administrators
            restricted_shells = {"/bin/false", "/usr/sbin/nologin", "/bin/nologin"}
            if entry.pw_shell not in restricted_shells:
                return True
            # Check groups for administrative roles
            import grp
            admin_groups = {"sudo", "wheel", "admin", "adm"}
            for g in grp.getgrall():
                if g.gr_name in admin_groups and username in g.gr_mem:
                    return True
        except (KeyError, ImportError, Exception):
            pass
    return False

def get_active_user_sessions() -> dict:
    """
    Return dictionary of {username: [pid1, pid2, ...]} for active Dropbear and OpenSSH user sessions.
    Inspects process table for non-system accounts running Dropbear or OpenSSH child sessions.
    """
    if os.name == 'nt':
        return {}

    user_pids = {}

    try:
        res = subprocess.run(["ps", "-eo", "user,pid,comm,args"], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                uname = parts[0]
                if uname in SYSTEM_USERS or is_system_or_admin_user(uname) or "grep" in line:
                    continue
                try:
                    pid = int(parts[1])
                except ValueError:
                    continue

                comm = parts[2].lower()
                args_str = " ".join(parts[3:]).lower() if len(parts) > 3 else ""

                # Match Dropbear sessions or OpenSSH sessions (sshd, sshd-session, etc.)
                is_dropbear = "dropbear" in comm or "dropbear" in args_str
                is_openssh = "sshd" in comm or "sshd-session" in comm or "sshd" in args_str or "sshd-session" in args_str

                if (is_dropbear or is_openssh) and "-p" not in line and "-d" not in line:
                    if uname not in user_pids:
                        user_pids[uname] = []
                    if pid not in user_pids[uname]:
                        user_pids[uname].append(pid)
    except Exception as e:
        logger.debug(f"Error querying process table: {e}")

    return user_pids

def get_active_dropbear_sessions() -> dict:
    """Backwards-compatible alias for get_active_user_sessions."""
    return get_active_user_sessions()

def enforce_concurrency_limits(db_path: str = DEFAULT_DB_PATH) -> int:
    """
    Synchronize active Dropbear and OpenSSH processes with SQLite active_sessions table,
    enforce real-time bandwidth quotas, and terminate sessions exceeding max_logins.
    Return count of killed PIDs.
    """
    if os.name == 'nt':
        return 0

    killed_count = 0

    # 1. Synchronize kernel bandwidth quotas
    try:
        sync_all_quotas(db_path)
    except Exception as e:
        logger.debug(f"Quota sync error: {e}")

    active_processes = get_active_user_sessions()

    try:
        conn = sqlite3.connect(db_path, timeout=5.0)
        conn.row_factory = sqlite3.Row

        # 2. Synchronize active_sessions table in SQLite
        db_sessions = conn.execute("SELECT id, username, pid FROM active_sessions WHERE status = 'active'").fetchall()
        all_live_pids = set()
        for pids in active_processes.values():
            all_live_pids.update(pids)

        # Close sessions in DB whose processes have exited
        for ds in db_sessions:
            if ds["pid"] not in all_live_pids:
                conn.execute("UPDATE active_sessions SET status = 'closed' WHERE id = ?", (ds["id"],))

        # Register newly spawned processes in DB
        db_active_pids = {ds["pid"] for ds in db_sessions}
        for uname, pids in active_processes.items():
            for pid in pids:
                if pid not in db_active_pids:
                    conn.execute("INSERT INTO active_sessions (username, pid, status) VALUES (?, ?, 'active')", (uname, pid))
        conn.commit()

        # 3. Load user policies
        users = conn.execute("SELECT username, max_logins, status FROM users").fetchall()
        user_limits = {u["username"]: {"max": u["max_logins"], "status": u["status"]} for u in users}

        for username, pids in active_processes.items():
            user_info = user_limits.get(username)
            # Never terminate accounts not managed by VexTunnel (e.g. system administrators, cloud users)
            if not user_info:
                continue

            # If registered user is expired, locked, or quota exceeded, terminate all sessions
            if user_info["status"] != "active":
                reason = user_info["status"]
                logger.warning(f"VexTunnel user '{username}' is [{reason}]. Terminating all {len(pids)} active sessions.")
                for pid in pids:
                    try:
                        os.kill(pid, signal.SIGTERM)
                        killed_count += 1
                        conn.execute("UPDATE active_sessions SET status = 'closed' WHERE pid = ?", (pid,))
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
                        conn.execute("UPDATE active_sessions SET status = 'closed' WHERE pid = ?", (pid,))
                        logger.info(f"Killed excess session PID {pid} for user '{username}'")
                    except ProcessLookupError:
                        pass

        conn.commit()
        conn.close()
    except Exception as e:
        logger.debug(f"DB or session enforcement error: {e}")

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

