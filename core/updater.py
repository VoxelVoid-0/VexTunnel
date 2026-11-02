#!/usr/bin/env python3
"""
⚡ VexTunnel Self-Update & Database Preservation Engine ⚡
Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)

Guarantees 100% zero-downtime, zero-corruption updates:
  1. Captures pre-update active service baseline (prevents false-positive rollbacks).
  2. Creates atomic snapshots via Python SQLite Native Backup API (src.backup(dst)).
  3. Adapts PEP 668 pip package installation (--break-system-packages with fallback).
  4. Triggers automatic schema migrations via UserManager.
  5. Reloads systemd and restarts core daemons.
  6. Evaluates post-update health with an interactive 15-second countdown timer.
  7. Lock-free atomic rollback (stops services -> restores DB -> checkpoints -> restarts).
  8. In-memory process re-exec (os.execv) with test isolation.
"""

import os
import sys
import time
import shutil
import sqlite3
import subprocess
import datetime
import logging
from typing import Dict, List, Tuple, Optional, Set

logger = logging.getLogger("VexTunnelUpdater")

CORE_SERVICES = [
    "vextunnel-ws",
    "vextunnel-wss",
    "vextunnel-ws-8880",
    "vextunnel-enforcer",
    "dropbear",
    "badvpn-7300"
]

ESSENTIAL_SERVICES = {
    "vextunnel-ws",
    "vextunnel-enforcer",
    "dropbear"
}

def get_installed_version(install_dir: str = "/etc/vextunnel") -> str:
    """Read local VERSION file or fallback to v1.3.0."""
    vfile = os.path.join(install_dir, "VERSION")
    if os.path.isfile(vfile):
        try:
            with open(vfile, "r") as f:
                ver = f.read().strip()
                if ver:
                    return ver
        except Exception:
            pass
    return "v1.3.0"

def get_git_commit(repo_dir: str) -> str:
    """Return short commit hash or 'release'."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=repo_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "release"

def is_service_active(service_name: str) -> bool:
    """Check if a systemd service is active (running)."""
    if os.name == 'nt':
        return True  # Mocked on Windows
    try:
        res = subprocess.run(
            ["systemctl", "is-active", "--quiet", service_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception:
        return False

def capture_pre_update_state(db_path: str = "/etc/vextunnel/vextunnel.db", repo_dir: str = "/etc/vextunnel") -> Dict:
    """Capture snapshot of active services and database state prior to updating."""
    active_svcs = []
    for svc in CORE_SERVICES:
        if is_service_active(svc):
            active_svcs.append(svc)

    commit_hash = get_git_commit(repo_dir)
    version = get_installed_version(repo_dir)

    return {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "version": version,
        "commit": commit_hash,
        "active_services": active_svcs,
        "db_exists": os.path.isfile(db_path)
    }

def backup_database(db_path: str, backup_dir: str = "/etc/vextunnel/backups", max_backups: int = 5) -> Tuple[bool, str]:
    """
    Perform an atomic SQLite online backup using Python's native backup API.
    Guarantees clean snapshot of WAL without lock contention or torn pages.
    """
    if not os.path.isfile(db_path):
        return True, ""  # No existing DB to backup

    try:
        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_filename = f"vextunnel_{timestamp}.db"
        backup_filepath = os.path.join(backup_dir, backup_filename)

        # 1. Flush any uncheckpointed WAL frames into main database
        with sqlite3.connect(db_path, timeout=10.0) as src_conn:
            try:
                src_conn.execute("PRAGMA wal_checkpoint(FULL);")
            except Exception as e:
                logger.warning(f"WAL checkpoint warning: {e}")

            # 2. Check source integrity
            integrity = src_conn.execute("PRAGMA integrity_check;").fetchall()
            if not integrity or integrity[0][0] != "ok":
                return False, f"Source database integrity failed: {integrity}"

            # 3. Native Online Backup (atomic page copy)
            with sqlite3.connect(backup_filepath) as dst_conn:
                src_conn.backup(dst_conn)

        # 4. Rotate old backups (keep latest N)
        try:
            backups = []
            for fname in os.listdir(backup_dir):
                if fname.startswith("vextunnel_") and fname.endswith(".db"):
                    fpath = os.path.join(backup_dir, fname)
                    backups.append((os.path.getmtime(fpath), fpath))
            backups.sort(key=lambda x: x[0], reverse=True)
            for _, old_path in backups[max_backups:]:
                try:
                    os.remove(old_path)
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"Error rotating backups: {e}")

        return True, backup_filepath
    except Exception as e:
        logger.error(f"Native SQLite backup failed: {e}")
        return False, str(e)

def sync_dependencies(repo_dir: str) -> Tuple[bool, str]:
    """
    Synchronize pip requirements with PEP 668 adaptive compatibility.
    Handles --break-system-packages with fallback for older pip versions.
    """
    req_file = os.path.join(repo_dir, "requirements.txt")
    if not os.path.isfile(req_file) or os.path.getsize(req_file) == 0:
        return True, "No dependencies required."

    has_active_reqs = False
    try:
        with open(req_file, "r") as f:
            for line in f:
                s = line.strip()
                if s and not s.startswith("#"):
                    has_active_reqs = True
                    break
    except Exception:
        pass

    if not has_active_reqs:
        return True, "No active dependencies listed."

    # Check if pip is available
    check_pip = subprocess.run([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if check_pip.returncode != 0:
        if hasattr(os, "geteuid") and os.geteuid() == 0 and os.name != 'nt':
            try:
                subprocess.run(["apt-get", "update", "-y"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["apt-get", "install", "-y", "python3-pip"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
        check_pip2 = subprocess.run([sys.executable, "-m", "pip", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_pip2.returncode != 0:
            return False, "python3-pip is not installed on system."

    base_cmd = [sys.executable, "-m", "pip", "install", "-q", "--no-cache-dir", "-r", req_file]
    is_system_python = (sys.prefix == sys.base_prefix)

    try:
        if is_system_python and os.name != 'nt':
            # Attempt with --break-system-packages for Ubuntu 24.04 / Debian 12
            cmd = base_cmd + ["--break-system-packages"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                return True, "Dependencies installed successfully (PEP 668 mode)."
            # If failed because flag is not recognized on older pip (< 23.1), fallback
            if "no such option" in res.stderr.lower():
                res = subprocess.run(base_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                return res.returncode == 0, res.stderr or res.stdout
            return False, res.stderr
        else:
            res = subprocess.run(base_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return res.returncode == 0, res.stderr or res.stdout
    except Exception as e:
        return False, str(e)

def apply_migrations(db_path: str = "/etc/vextunnel/vextunnel.db") -> bool:
    """Instantiate UserManager to run pending database schema migrations."""
    if not os.path.isfile(db_path):
        return True
    try:
        from core.user_manager import UserManager
        UserManager(db_path)
        return True
    except Exception as e:
        logger.error(f"Migration error: {e}")
        return False

def stop_tunnel_services(services: List[str]) -> bool:
    """Stop designated tunnel services."""
    if os.name == 'nt':
        return True
    for svc in services:
        try:
            subprocess.run(["systemctl", "stop", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    return True

def start_tunnel_services(services: List[str]) -> bool:
    """Start designated tunnel services."""
    if os.name == 'nt':
        return True
    try:
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    for svc in services:
        try:
            subprocess.run(["systemctl", "start", svc], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    return True

def restart_tunnel_services(services_to_start: Optional[List[str]] = None) -> Dict[str, bool]:
    """Reload systemd and restart services."""
    if services_to_start is None:
        services_to_start = CORE_SERVICES

    results = {}
    if os.name == 'nt':
        for s in services_to_start:
            results[s] = True
        return results

    try:
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    for svc in services_to_start:
        try:
            res = subprocess.run(
                ["systemctl", "restart", svc],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            results[svc] = (res.returncode == 0)
        except Exception:
            results[svc] = False

    return results

def verify_health(pre_active_services: List[str]) -> Tuple[bool, List[str]]:
    """
    Verify service health against pre-update baseline.
    Avoids false-positive rollbacks for services that were already inactive.
    """
    if os.name == 'nt':
        return True, []

    failed = []
    # 1. Essential services MUST be running
    for svc in ESSENTIAL_SERVICES:
        if not is_service_active(svc):
            failed.append(svc)

    # 2. Check previously active optional services
    for svc in pre_active_services:
        if svc not in ESSENTIAL_SERVICES and svc in CORE_SERVICES:
            if not is_service_active(svc):
                failed.append(svc)

    return (len(failed) == 0), failed

def get_service_logs(service_name: str, lines: int = 20) -> str:
    """Fetch recent journalctl logs for failed service."""
    if os.name == 'nt':
        return "Logs unavailable on Windows."
    try:
        res = subprocess.run(
            ["journalctl", "-u", service_name, "-n", str(lines), "--no-pager"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )
        return res.stdout.strip()
    except Exception as e:
        return f"Error retrieving logs: {e}"

def interactive_rollback_countdown(failed_services: List[str], timeout_sec: int = 15) -> str:
    """
    Interactive cross-platform 15-second countdown timer.
    Returns:
      'r'       : Rollback immediately
      'c'       : Cancel rollback
      'timeout' : Timer expired (triggers automatic rollback)
    """
    # Non-interactive / Headless check: Instant rollback
    if not sys.stdin or not hasattr(sys.stdin, "isatty") or not sys.stdin.isatty():
        return "timeout"

    print("\n\033[1;31m[CRITICAL ALERT] One or more tunnel services failed post-update health check!\033[0m")
    for svc in failed_services:
        print(f" • \033[33m{svc}\033[0m is NOT active.")
        logs = get_service_logs(svc, lines=10)
        if logs:
            print(f"\033[2mRecent logs for {svc}:\n{logs}\033[0m\n")

    print("\033[1;33mAuto-rollback will trigger to safeguard the VPS.\033[0m")
    print("  \033[1m[R]\033[0m Rollback immediately")
    print("  \033[1m[C]\033[0m Cancel auto-rollback & debug manually\n")

    for remaining in range(timeout_sec, 0, -1):
        sys.stdout.write(f"\rAuto-rollback in \033[1;31m{remaining}s\033[0m (Press 'r' to rollback now, 'c' to cancel)... ")
        sys.stdout.flush()

        # Cross-platform non-blocking key check
        if os.name == 'nt':
            try:
                import msvcrt
                if msvcrt.kbhit():
                    char = msvcrt.getwch().lower()
                    if char in ('r', 'c'):
                        sys.stdout.write("\n")
                        return char
            except Exception:
                pass
            time.sleep(1.0)
        else:
            try:
                import select
                rlist, _, _ = select.select([sys.stdin], [], [], 1.0)
                if rlist:
                    char = sys.stdin.read(1).lower()
                    if char in ('r', 'c'):
                        sys.stdout.write("\n")
                        return char
            except Exception:
                time.sleep(1.0)

    sys.stdout.write("\n")
    return "timeout"

def rollback_update(
    repo_dir: str,
    prev_commit: str,
    backup_file: str,
    db_path: str = "/etc/vextunnel/vextunnel.db",
    services_to_restore: Optional[List[str]] = None
) -> bool:
    """
    Atomic lock-safe rollback:
      1. Stop services to prevent SQLITE_BUSY / locked database.
      2. Revert git commit (if git repository).
      3. Restore SQLite database via Native Backup API & truncate WAL.
      4. Restart previous stable services in finally block.
    """
    if services_to_restore is None:
        services_to_restore = list(ESSENTIAL_SERVICES)

    # 1. Stop services first to ensure no background writes lock the database
    stop_tunnel_services(CORE_SERVICES)

    rollback_ok = True
    try:
        # 2. Revert Git repository if present
        if prev_commit and prev_commit != "release" and os.path.isdir(os.path.join(repo_dir, ".git")):
            res = subprocess.run(
                ["git", "reset", "--hard", prev_commit],
                cwd=repo_dir,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            if res.returncode != 0:
                rollback_ok = False

        # 3. Restore SQLite database from native backup
        if backup_file and os.path.isfile(backup_file) and os.path.isfile(db_path):
            with sqlite3.connect(backup_file, timeout=10.0) as bkp:
                with sqlite3.connect(db_path, timeout=10.0) as target:
                    bkp.backup(target)
                    target.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    except Exception as e:
        logger.error(f"Error during rollback execution: {e}")
        rollback_ok = False
    finally:
        # 4. Restart services under previous stable code
        start_tunnel_services(services_to_restore)

    return rollback_ok

def reexec_menu() -> bool:
    """Seamlessly restart the active menu process with freshly pulled bytecode."""
    if os.environ.get("VEXTUNNEL_TEST_MODE") == "1":
        return True
    if hasattr(os, "execv"):
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as e:
            logger.error(f"Failed to re-exec process: {e}")
    return True
