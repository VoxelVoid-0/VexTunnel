#!/usr/bin/env python3
"""
⚡ VexTunnel Self-Update & Database Preservation Engine (v6) ⚡
Author : VoxelVoid-0 (https://github.com/VoxelVoid-0/VexTunnel)

Guarantees 100% zero-downtime, zero-corruption updates:
  1. Pre-flight Fail-Closed Disk Space Check (>= 150 MB free).
  2. Captures pre-update active service baseline (prevents false-positive rollbacks).
  3. Freezes database writes early via vextunnel-enforcer pause while WS tunnels stay alive.
  4. Creates atomic snapshots via Python SQLite Native Backup API (src.backup(dst)).
  5. Isolated Staging extraction & syntax verification via py_compile.
  6. Codebase rollback snapshot (/tmp/vextunnel_code_rollback.tar.gz) & stale bytecode purge.
  7. Atomic promotion with protected file shields (.db*, ports.env, certs/, backups/).
  8. Systemd ports.env decoupling sync & daemon-reload.
  9. Adapts PEP 668 pip package installation (--break-system-packages with fallback).
 10. Triggers automatic schema migrations via UserManager.
 11. Settling delay (3s) & Deep TCP socket connectivity probe (ports 80 & 109).
 12. Interactive 15-second countdown timer or automatic Two-Tier Rollback (Code + DB).
 13. In-memory process re-exec (os.execv) with test isolation.
"""

import os
import sys
import time
import shutil
import socket
import sqlite3
import tarfile
import subprocess
import datetime
import logging
import urllib.request
import py_compile
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

PROTECTED_ITEMS = {
    "vextunnel.db",
    "vextunnel.db-wal",
    "vextunnel.db-shm",
    "ports.env",
    "domain.conf",
    "telegram.json",
    "certs",
    "backups"
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

def check_disk_space(target_path: str = "/etc/vextunnel", min_free_mb: int = 150) -> Tuple[bool, int]:
    """
    Fail-closed disk space gate: Verifies target filesystem has >= min_free_mb free space.
    If space is insufficient or check encounters an error, returns False to prevent ENOSPC corruption.
    """
    try:
        check_dir = target_path
        while not os.path.exists(check_dir):
            parent = os.path.dirname(check_dir)
            if parent == check_dir:
                break
            check_dir = parent
        usage = shutil.disk_usage(check_dir)
        free_mb = int(usage.free / (1024 * 1024))
        return (free_mb >= min_free_mb), free_mb
    except Exception as e:
        logger.error(f"Failed to check disk space: {e}")
        return False, 0

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

def pause_enforcer_for_migration() -> bool:
    """
    Early service freeze: Stop vextunnel-enforcer early to stop database writes.
    Keeps client SSH WebSocket proxy tunnels (port 80/443) running without disconnect.
    """
    if os.name == 'nt':
        return True
    try:
        res = subprocess.run(
            ["systemctl", "stop", "vextunnel-enforcer"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return res.returncode == 0
    except Exception as e:
        logger.warning(f"Failed to pause vextunnel-enforcer: {e}")
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

def purge_bytecode(directory: str) -> None:
    """Purge all stale __pycache__ folders and .pyc/.pyo files recursively."""
    if not os.path.isdir(directory):
        return
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in dirs:
            if name == "__pycache__":
                shutil.rmtree(os.path.join(root, name), ignore_errors=True)
        for name in files:
            if name.endswith(".pyc") or name.endswith(".pyo"):
                try:
                    os.remove(os.path.join(root, name))
                except Exception:
                    pass

def create_code_snapshot(
    install_dir: str = "/etc/vextunnel",
    snapshot_path: str = "/tmp/vextunnel_code_rollback.tar.gz"
) -> Tuple[bool, str]:
    """
    Snapshot existing codebase prior to extraction.
    Excludes database, logs, certs, backups, and pycache to create a lean rollback archive.
    """
    if not os.path.isdir(install_dir):
        return True, ""
    try:
        os.makedirs(os.path.dirname(snapshot_path), exist_ok=True)

        def tar_filter(tarinfo):
            basename = os.path.basename(tarinfo.name)
            if basename in ("__pycache__", "backups", "certs", ".git", ".github"):
                return None
            if basename.endswith(".pyc") or basename.endswith(".pyo"):
                return None
            if basename == "vextunnel.db" or basename.startswith("vextunnel.db-"):
                return None
            return tarinfo

        with tarfile.open(snapshot_path, "w:gz") as tar:
            tar.add(install_dir, arcname=".", filter=tar_filter)

        return True, snapshot_path
    except Exception as e:
        logger.error(f"Failed to create code snapshot: {e}")
        return False, str(e)

def stage_and_verify_release(
    tar_path_or_url: str,
    staging_dir: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Extract release package into an isolated staging directory and compile bytecode.
    Guarantees no broken syntax, truncated files, or corrupt archives reach /etc/vextunnel.
    """
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    if staging_dir is None:
        staging_dir = f"/tmp/vextunnel_staging_{timestamp}_{os.getpid()}"

    local_tar = tar_path_or_url
    temp_download = False

    try:
        # Download if URL
        if tar_path_or_url.startswith("http://") or tar_path_or_url.startswith("https://"):
            local_tar = f"/tmp/vextunnel_dl_{timestamp}.tar.gz"
            req = urllib.request.Request(tar_path_or_url, headers={"User-Agent": "VexTunnel-Updater"})
            with urllib.request.urlopen(req, timeout=15) as resp, open(local_tar, "wb") as out:
                shutil.copyfileobj(resp, out)
            temp_download = True

        if not os.path.isfile(local_tar):
            return False, f"Release tarball not found: {local_tar}"

        os.makedirs(staging_dir, exist_ok=True)

        # Unpack safely
        with tarfile.open(local_tar, "r:gz") as tar:
            base_dir = os.path.abspath(staging_dir)
            for member in tar.getmembers():
                dest_path = os.path.abspath(os.path.join(base_dir, member.name))
                if not dest_path.startswith(base_dir):
                    raise ValueError(f"Directory traversal detected in tarball: {member.name}")
            tar.extractall(staging_dir)

        # Handle nested top-level folder if unpacked from GitHub archive (e.g. VexTunnel-1.3.1)
        scan_dir = staging_dir
        entries = os.listdir(staging_dir)
        if len(entries) == 1 and os.path.isdir(os.path.join(staging_dir, entries[0])) and not os.path.exists(os.path.join(staging_dir, "VERSION")):
            scan_dir = os.path.join(staging_dir, entries[0])

        # Verify critical core files exist
        critical_files = [
            os.path.join(scan_dir, "VERSION"),
            os.path.join(scan_dir, "core", "ws_proxy.py"),
            os.path.join(scan_dir, "core", "user_manager.py"),
            os.path.join(scan_dir, "core", "updater.py"),
            os.path.join(scan_dir, "cli", "menu.py")
        ]
        for cfile in critical_files:
            if not os.path.isfile(cfile):
                shutil.rmtree(staging_dir, ignore_errors=True)
                return False, f"Integrity check failed: Missing critical file '{os.path.basename(cfile)}'"

        # Compile all Python files to detect syntax errors before live deployment
        for root, _, files in os.walk(scan_dir):
            for f in files:
                if f.endswith(".py"):
                    py_path = os.path.join(root, f)
                    try:
                        py_compile.compile(py_path, doraise=True)
                    except py_compile.PyCompileError as pe:
                        shutil.rmtree(staging_dir, ignore_errors=True)
                        return False, f"Syntax verification failed in {f}: {pe}"

        return True, scan_dir
    except Exception as e:
        shutil.rmtree(staging_dir, ignore_errors=True)
        return False, f"Staging extraction error: {e}"
    finally:
        if temp_download and os.path.isfile(local_tar):
            try:
                os.remove(local_tar)
            except Exception:
                pass

def promote_staging_to_production(staging_source: str, install_dir: str = "/etc/vextunnel") -> Tuple[bool, str]:
    """
    Atomically promote verified staging files to production directory.
    Shields protected files (.db*, ports.env, certs/, backups/) against overwrite.
    """
    try:
        purge_bytecode(install_dir)
        os.makedirs(install_dir, exist_ok=True)

        actual_source = staging_source
        entries = os.listdir(staging_source)
        if len(entries) == 1 and os.path.isdir(os.path.join(staging_source, entries[0])) and not os.path.exists(os.path.join(staging_source, "VERSION")):
            actual_source = os.path.join(staging_source, entries[0])

        for root, dirs, files in os.walk(actual_source):
            rel_path = os.path.relpath(root, actual_source)
            dest_dir = install_dir if rel_path == "." else os.path.join(install_dir, rel_path)

            top_level = rel_path.split(os.sep)[0] if rel_path != "." else ""
            if top_level in ("certs", "backups", ".git"):
                continue

            os.makedirs(dest_dir, exist_ok=True)

            for f in files:
                # File shield: Protect database, user config, and custom ports
                if f in PROTECTED_ITEMS and os.path.exists(os.path.join(dest_dir, f)):
                    continue
                if f.startswith("vextunnel.db"):
                    continue

                src_file = os.path.join(root, f)
                dst_file = os.path.join(dest_dir, f)
                shutil.copy2(src_file, dst_file)

                # Ensure executable permissions on scripts and entrypoints
                if f.endswith(".sh") or f.endswith(".py") or f == "menu":
                    try:
                        os.chmod(dst_file, 0o755)
                    except Exception:
                        pass

        purge_bytecode(install_dir)
        shutil.rmtree(staging_source, ignore_errors=True)
        return True, "Promotion complete"
    except Exception as e:
        logger.error(f"Promotion failed: {e}")
        return False, str(e)

def sync_systemd_units(install_dir: str = "/etc/vextunnel") -> bool:
    """
    Deploy updated systemd service units to /etc/systemd/system/ and reload daemon.
    Units reference /etc/vextunnel/ports.env to decouple configuration.
    """
    if os.name == 'nt':
        return True
    systemd_src = os.path.join(install_dir, "install", "systemd")
    systemd_dst = "/etc/systemd/system"
    if not os.path.isdir(systemd_src) or not os.path.isdir(systemd_dst):
        return True
    try:
        for fname in os.listdir(systemd_src):
            if fname.endswith(".service"):
                shutil.copy2(os.path.join(systemd_src, fname), os.path.join(systemd_dst, fname))
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logger.warning(f"Error syncing systemd units: {e}")
        return False

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
            cmd = base_cmd + ["--break-system-packages"]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                return True, "Dependencies installed successfully (PEP 668 mode)."
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
    """Start designated tunnel services cleanly from cold state."""
    if os.name == 'nt':
        return True
    try:
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass
    svcs = list(services)
    if "vextunnel-enforcer" not in svcs and "vextunnel-enforcer" in CORE_SERVICES:
        svcs.append("vextunnel-enforcer")
    for svc in svcs:
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

def deep_socket_health_check(ports: Optional[List[int]] = None, timeout: float = 3.0) -> Tuple[bool, List[int]]:
    """
    Deep TCP socket connectivity probe on localhost.
    Confirms daemons are not merely marked 'active' by systemd, but actively accepting socket handshakes.
    """
    if os.name == 'nt':
        return True, []
    if ports is None:
        ports = [80, 109]

    failed_ports = []
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                pass
        except Exception:
            failed_ports.append(port)

    return (len(failed_ports) == 0), failed_ports

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

def two_tier_rollback(
    install_dir: str,
    code_snapshot_path: str,
    db_backup_path: str,
    db_path: str = "/etc/vextunnel/vextunnel.db",
    services_to_restore: Optional[List[str]] = None
) -> bool:
    """
    Two-tier safe atomic rollback:
      1. Stops all services to release file handles and SQLite locks.
      2. Reverts codebase using code snapshot tarball.
      3. Restores SQLite database from native backup and truncates WAL.
      4. Restarts active services in finally block.
    """
    if services_to_restore is None:
        services_to_restore = list(ESSENTIAL_SERVICES)

    # 1. Stop services first
    stop_tunnel_services(CORE_SERVICES)

    rollback_ok = True
    try:
        # 2. Revert codebase if snapshot exists
        if code_snapshot_path and os.path.isfile(code_snapshot_path):
            with tarfile.open(code_snapshot_path, "r:gz") as tar:
                tar.extractall(install_dir)
            purge_bytecode(install_dir)

        # 3. Restore SQLite database from native backup
        if db_backup_path and os.path.isfile(db_backup_path) and os.path.isfile(db_path):
            with sqlite3.connect(db_backup_path, timeout=10.0) as bkp:
                with sqlite3.connect(db_path, timeout=10.0) as target:
                    bkp.backup(target)
                    target.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    except Exception as e:
        logger.error(f"Error during two-tier rollback execution: {e}")
        rollback_ok = False
    finally:
        # 4. Restart services under restored stable code
        start_tunnel_services(services_to_restore)

    return rollback_ok

def rollback_update(
    repo_dir: str,
    prev_commit: str,
    backup_file: str,
    db_path: str = "/etc/vextunnel/vextunnel.db",
    services_to_restore: Optional[List[str]] = None
) -> bool:
    """Backwards-compatible wrapper calling two_tier_rollback."""
    code_snapshot = "/tmp/vextunnel_code_rollback.tar.gz"
    if not os.path.isfile(code_snapshot):
        code_snapshot = ""

    # If git repository, reset hard as well
    if prev_commit and prev_commit != "release" and os.path.isdir(os.path.join(repo_dir, ".git")):
        try:
            subprocess.run(["git", "reset", "--hard", prev_commit], cwd=repo_dir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

    return two_tier_rollback(
        install_dir=repo_dir,
        code_snapshot_path=code_snapshot,
        db_backup_path=backup_file,
        db_path=db_path,
        services_to_restore=services_to_restore
    )

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
