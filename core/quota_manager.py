#!/usr/bin/env python3
"""
VexTunnel - Hardware & Kernel-Level UID Byte Quota Manager
Author: VoxelVoid-0
License: MIT

Features:
- Linux kernel UID-based packet and byte accounting via iptables
- Real-time synchronization of bandwidth consumption into SQLite database
- Automatic enforcement: drops socket I/O and terminates sessions when quotas are exceeded
- Safe quota reset and network unblock lifecycle
"""

import os
import sys
import re
import datetime
import subprocess
import signal
import sqlite3
import logging
from typing import Optional, Dict

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [QuotaManager] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("QuotaManager")

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.user_manager import DEFAULT_DB_PATH
from core.telegram_notifier import alert_quota_threshold, alert_quota_exceeded

def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable string (KB, MB, GB, TB)."""
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num_bytes)
    i = 0
    while n >= 1024.0 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"

def parse_bytes(text: str) -> int:
    """Parse string representation (e.g. '50G', '50GB', '500M') into integer bytes."""
    text = text.strip().upper()
    if not text or text == "0":
        return 0
    match = re.match(r"^(\d+(?:\.\d+)?)\s*([KMGTP]?B?)$", text)
    if not match:
        raise ValueError(f"Invalid bandwidth quota format: '{text}' (use e.g. 50G, 500M, 10G)")
    val, unit = match.groups()
    val = float(val)
    multiplier = {
        "": 1, "B": 1,
        "K": 1024, "KB": 1024,
        "M": 1024**2, "MB": 1024**2,
        "G": 1024**3, "GB": 1024**3,
        "T": 1024**4, "TB": 1024**4,
        "P": 1024**5, "PB": 1024**5
    }.get(unit, 1)
    return int(val * multiplier)

def get_user_uid(username: str) -> Optional[int]:
    """Retrieve Linux system UID for a given username."""
    if os.name == 'nt':
        return None
    try:
        res = subprocess.run(["id", "-u", username], capture_output=True, text=True, timeout=3)
        if res.returncode == 0:
            return int(res.stdout.strip())
    except Exception:
        pass
    return None

def init_firewall_chains() -> bool:
    """Initialize dedicated VEXTUNNEL_BLOCK and VEXTUNNEL_QUOTA chains in iptables."""
    if os.name == 'nt' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return False
    try:
        # 1. Dedicated Block Chain (Evaluated at the very top of OUTPUT)
        subprocess.run(["iptables", "-N", "VEXTUNNEL_BLOCK"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check_block = subprocess.run(["iptables", "-C", "OUTPUT", "-j", "VEXTUNNEL_BLOCK"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_block.returncode != 0:
            subprocess.run(["iptables", "-I", "OUTPUT", "1", "-j", "VEXTUNNEL_BLOCK"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # 2. Dedicated Quota Accounting Chain
        subprocess.run(["iptables", "-N", "VEXTUNNEL_QUOTA"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check_quota = subprocess.run(["iptables", "-C", "OUTPUT", "-j", "VEXTUNNEL_QUOTA"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_quota.returncode != 0:
            subprocess.run(["iptables", "-A", "OUTPUT", "-j", "VEXTUNNEL_QUOTA"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception as e:
        logger.debug(f"Failed to initialize dedicated firewall chains: {e}")
        return False

def setup_anti_abuse_firewall(ports: list = None, rate_per_min: int = 60, burst: int = 40) -> bool:
    """
    Configure kernel-level connection rate limiting on tunnel ports using iptables hashlimit.
    Protects against SYN flooding and brute-force connection exhaustion without affecting ongoing streams.
    """
    if os.name == 'nt' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return False
    if ports is None:
        ports = [80, 443, 109, 22]
    try:
        check_mod = subprocess.run(["iptables", "-m", "hashlimit", "--help"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_mod.returncode != 0:
            return False

        subprocess.run(["iptables", "-N", "VEXTUNNEL_LIMIT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        check_limit = subprocess.run(["iptables", "-C", "INPUT", "-j", "VEXTUNNEL_LIMIT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if check_limit.returncode != 0:
            subprocess.run(["iptables", "-I", "INPUT", "1", "-j", "VEXTUNNEL_LIMIT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        for p in ports:
            rule_check = subprocess.run(
                ["iptables", "-C", "VEXTUNNEL_LIMIT", "-p", "tcp", "--dport", str(p), "-m", "conntrack", "--ctstate", "NEW",
                 "-m", "hashlimit", "--hashlimit-above", f"{rate_per_min}/min", "--hashlimit-burst", str(burst),
                 "--hashlimit-mode", "srcip", "--hashlimit-name", f"vex_limit_{p}", "-j", "DROP"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if rule_check.returncode != 0:
                subprocess.run(
                    ["iptables", "-A", "VEXTUNNEL_LIMIT", "-p", "tcp", "--dport", str(p), "-m", "conntrack", "--ctstate", "NEW",
                     "-m", "hashlimit", "--hashlimit-above", f"{rate_per_min}/min", "--hashlimit-burst", str(burst),
                     "--hashlimit-mode", "srcip", "--hashlimit-name", f"vex_limit_{p}", "-j", "DROP"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )
        logger.info(f"Firewall: Initialized VEXTUNNEL_LIMIT anti-abuse rate protection on ports {ports}")
        return True
    except Exception as e:
        logger.debug(f"Failed to setup anti-abuse firewall: {e}")
        return False

def setup_accounting_rule(uid: int) -> bool:
    """Ensure iptables VEXTUNNEL_QUOTA rule exists for this UID to count outgoing traffic."""
    if os.name == 'nt' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return False
    try:
        init_firewall_chains()
        check = subprocess.run(
            ["iptables", "-C", "VEXTUNNEL_QUOTA", "-m", "owner", "--uid-owner", str(uid), "-j", "ACCEPT"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-A", "VEXTUNNEL_QUOTA", "-m", "owner", "--uid-owner", str(uid), "-j", "ACCEPT"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logger.info(f"Initialized iptables accounting rule for UID {uid} in VEXTUNNEL_QUOTA")
        return True
    except Exception as e:
        logger.debug(f"Failed to setup accounting rule for UID {uid}: {e}")
        return False

def read_uid_bytes(uid: int) -> int:
    """Parse exact byte count for UID from isolated VEXTUNNEL_QUOTA chain."""
    if os.name == 'nt':
        return 0
    try:
        res = subprocess.run(
            ["iptables", "-L", "VEXTUNNEL_QUOTA", "-v", "-n", "-x"],
            capture_output=True, text=True, timeout=5
        )
        total_bytes = 0
        target_uid_str = f"owner UID match {uid}"
        target_uid_alt = f"--uid-owner {uid}"

        for line in res.stdout.splitlines():
            if target_uid_str in line or target_uid_alt in line:
                parts = line.split()
                if len(parts) >= 2:
                    try:
                        bytes_val = int(parts[1])
                        total_bytes += bytes_val
                    except ValueError:
                        pass
        return total_bytes
    except Exception as e:
        logger.debug(f"Failed to read iptables bytes for UID {uid}: {e}")
        return 0

def block_user_network(uid: int) -> bool:
    """Insert iptables DROP rule in VEXTUNNEL_BLOCK to cleanly block network egress."""
    if os.name == 'nt' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return False
    try:
        init_firewall_chains()
        check = subprocess.run(
            ["iptables", "-C", "VEXTUNNEL_BLOCK", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        if check.returncode != 0:
            subprocess.run(
                ["iptables", "-A", "VEXTUNNEL_BLOCK", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            logger.warning(f"Firewall: Inserted network DROP rule for UID {uid} in VEXTUNNEL_BLOCK")
        return True
    except Exception as e:
        logger.error(f"Error blocking network for UID {uid}: {e}")
        return False

def unblock_user_network(uid: int) -> bool:
    """Remove all iptables DROP rules for UID from VEXTUNNEL_BLOCK."""
    if os.name == 'nt' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return False
    try:
        while True:
            res = subprocess.run(
                ["iptables", "-D", "VEXTUNNEL_BLOCK", "-m", "owner", "--uid-owner", str(uid), "-j", "DROP"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            if res.returncode != 0:
                break
        logger.info(f"Firewall: Cleared network DROP rules for UID {uid} from VEXTUNNEL_BLOCK")
        return True
    except Exception as e:
        logger.error(f"Error unblocking network for UID {uid}: {e}")
        return False

def kill_user_sessions(username: str):
    """Terminate all active Dropbear and OpenSSH processes for the given username."""
    if os.name == 'nt':
        return
    try:
        import time
        # Graceful SIGTERM
        subprocess.run(["pkill", "-u", username], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.1)
        # Authoritative SIGKILL loop for lingering Dropbear/OpenSSH/tunnel processes
        res = subprocess.run(["ps", "-eo", "user,pid,comm"], capture_output=True, text=True, timeout=5)
        for line in res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == username:
                try:
                    pid = int(parts[1])
                    os.kill(pid, signal.SIGKILL)
                except (ValueError, ProcessLookupError):
                    pass
    except Exception as e:
        logger.debug(f"Error terminating user sessions for {username}: {e}")

def sync_all_quotas(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Dict]:
    """
    Synchronize Linux kernel byte counters with SQLite database and enforce cutoffs.
    Returns status map per user.
    """
    summary = {}
    init_firewall_chains()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        cols = [c[1] for c in conn.execute("PRAGMA table_info(users)").fetchall()]
        has_quota_status = "quota_status" in cols

        users = conn.execute("SELECT * FROM users").fetchall()

        for u in users:
            uname = u["username"]
            quota = u["quota_bytes"] if "quota_bytes" in cols else 0
            current_used = u["used_bytes"] if "used_bytes" in cols else 0
            status = u["status"]
            quota_status = u["quota_status"] if has_quota_status else "active"

            uid = get_user_uid(uname)
            if uid is not None and uid > 0:
                setup_accounting_rule(uid)
                iptables_bytes = read_uid_bytes(uid)
                last_counter = u["last_counter_bytes"] if "last_counter_bytes" in cols and u["last_counter_bytes"] is not None else 0

                # Delta computation with reboot / reset watermark tolerance
                if iptables_bytes >= last_counter:
                    delta = iptables_bytes - last_counter
                else:
                    # Counter reset detected (server rebooted or iptables flushed)
                    delta = iptables_bytes

                new_used = current_used + delta
                new_last_counter = iptables_bytes

            last_alert = u["last_quota_alert_pct"] if "last_quota_alert_pct" in cols and u["last_quota_alert_pct"] is not None else 0
            has_last_alert = "last_quota_alert_pct" in cols
            pct = int((new_used / quota) * 100) if quota > 0 else 0

            # Quota Exceeded Enforcement
            if quota > 0 and new_used >= quota:
                quota_status = "quota_exceeded"
                status = "quota_exceeded"
                if "last_counter_bytes" in cols and has_quota_status:
                    if has_last_alert:
                        conn.execute("""
                            UPDATE users SET used_bytes = ?, last_counter_bytes = ?, last_quota_alert_pct = 100, quota_status = 'quota_exceeded', status = 'quota_exceeded', last_quota_sync = ?
                            WHERE username = ?
                        """, (new_used, new_last_counter, now_str, uname))
                    else:
                        conn.execute("""
                            UPDATE users SET used_bytes = ?, last_counter_bytes = ?, quota_status = 'quota_exceeded', status = 'quota_exceeded', last_quota_sync = ?
                            WHERE username = ?
                        """, (new_used, new_last_counter, now_str, uname))
                elif has_quota_status:
                    conn.execute("""
                        UPDATE users SET used_bytes = ?, quota_status = 'quota_exceeded', status = 'quota_exceeded', last_quota_sync = ?
                        WHERE username = ?
                    """, (new_used, now_str, uname))
                else:
                    conn.execute("UPDATE users SET used_bytes = ?, status = 'quota_exceeded' WHERE username = ?", (new_used, uname))
                block_user_network(uid)
                kill_user_sessions(uname)

                if last_alert < 100:
                    try:
                        alert_quota_exceeded(uname, new_used, quota)
                    except Exception:
                        pass
            else:
                new_alert_val = last_alert
                if quota > 0 and pct >= 90 and last_alert < 90:
                    try:
                        alert_quota_threshold(uname, new_used, quota, 90)
                    except Exception:
                        pass
                    new_alert_val = 90
                elif quota > 0 and pct >= 80 and last_alert < 80:
                    try:
                        alert_quota_threshold(uname, new_used, quota, 80)
                    except Exception:
                        pass
                    new_alert_val = 80

                if delta > 0 or new_last_counter != last_counter or new_alert_val != last_alert:
                    if "last_counter_bytes" in cols and has_quota_status:
                        if has_last_alert:
                            conn.execute("""
                                UPDATE users SET used_bytes = ?, last_counter_bytes = ?, last_quota_alert_pct = ?, last_quota_sync = ?
                                WHERE username = ?
                            """, (new_used, new_last_counter, new_alert_val, now_str, uname))
                        else:
                            conn.execute("""
                                UPDATE users SET used_bytes = ?, last_counter_bytes = ?, last_quota_sync = ?
                                WHERE username = ?
                            """, (new_used, new_last_counter, now_str, uname))
                    elif has_quota_status:
                        conn.execute("""
                            UPDATE users SET used_bytes = ?, last_quota_sync = ?
                            WHERE username = ?
                        """, (new_used, now_str, uname))
                    else:
                        conn.execute("UPDATE users SET used_bytes = ? WHERE username = ?", (new_used, uname))
                current_used = new_used

            summary[uname] = {
                "quota_bytes": quota,
                "used_bytes": current_used,
                "quota_status": quota_status,
                "status": status
            }

        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error during quota synchronization: {e}")

    return summary

def reset_user_quota(username: str, db_path: str = DEFAULT_DB_PATH) -> bool:
    """Reset bandwidth counters and re-enable active network access for user."""
    username = username.strip().lower()
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        cols = [c[1] for c in conn.execute("PRAGMA table_info(users)").fetchall()]
        has_last_counter = "last_counter_bytes" in cols
        has_last_alert = "last_quota_alert_pct" in cols
        has_quota_status = "quota_status" in cols

        if has_last_counter and has_quota_status:
            if has_last_alert:
                cur = conn.execute("""
                    UPDATE users SET used_bytes = 0, last_counter_bytes = 0, last_quota_alert_pct = 0, quota_status = 'active', status = 'active', last_quota_sync = ?
                    WHERE username = ?
                """, (now_str, username))
            else:
                cur = conn.execute("""
                    UPDATE users SET used_bytes = 0, last_counter_bytes = 0, quota_status = 'active', status = 'active', last_quota_sync = ?
                    WHERE username = ?
                """, (now_str, username))
        elif has_quota_status:
            cur = conn.execute("""
                UPDATE users SET used_bytes = 0, quota_status = 'active', status = 'active', last_quota_sync = ?
                WHERE username = ?
            """, (now_str, username))
        else:
            cur = conn.execute("UPDATE users SET used_bytes = 0, status = 'active' WHERE username = ?", (username,))
        conn.commit()
        conn.close()

        uid = get_user_uid(username)
        if uid is not None and uid > 0:
            unblock_user_network(uid)
            # Reset iptables counter for VEXTUNNEL_QUOTA chain
            if hasattr(os, 'geteuid') and os.geteuid() == 0:
                subprocess.run(
                    ["iptables", "-Z", "VEXTUNNEL_QUOTA"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
                )

        logger.info(f"Bandwidth quota successfully reset to 0 B for user '{username}'")
        return cur.rowcount > 0
    except Exception as e:
        logger.error(f"Failed to reset quota for {username}: {e}")
        return False

def reset_all_quotas(db_path: str = DEFAULT_DB_PATH) -> int:
    """
    Automated scheduled/monthly quota reset:
    Zeroes bandwidth counters and unblocks network access for all users.
    Returns count of reset users.
    """
    count = 0
    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        users = conn.execute("SELECT username FROM users").fetchall()
        conn.close()
        for u in users:
            uname = u["username"]
            if reset_user_quota(uname, db_path):
                count += 1
        logger.info(f"Automated scheduled reset completed for {count} users.")
        if count > 0:
            try:
                from core.telegram_notifier import alert_all_quotas_reset
                alert_all_quotas_reset(count)
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Error in reset_all_quotas: {e}")
    return count

RESET_SERVICE_PATH = "/etc/systemd/system/vextunnel-quota-reset.service"
RESET_TIMER_PATH = "/etc/systemd/system/vextunnel-quota-reset.timer"

def is_monthly_quota_reset_enabled() -> bool:
    """Check if monthly quota reset systemd timer is active and enabled."""
    if os.name == 'nt':
        return False
    if not os.path.exists(RESET_TIMER_PATH):
        return False
    try:
        res = subprocess.run(["systemctl", "is-enabled", "vextunnel-quota-reset.timer"], capture_output=True, text=True, check=False)
        return res.returncode == 0
    except Exception:
        return False

def setup_monthly_quota_reset_timer(enable: bool = True) -> bool:
    """Enable or disable automated systemd timer for monthly quota reset."""
    if os.name == 'nt':
        logger.warning("Systemd timers are not supported on Windows.")
        return False

    if not enable:
        try:
            subprocess.run(["systemctl", "disable", "--now", "vextunnel-quota-reset.timer"], capture_output=True, check=False)
            if os.path.exists(RESET_TIMER_PATH):
                os.remove(RESET_TIMER_PATH)
            if os.path.exists(RESET_SERVICE_PATH):
                os.remove(RESET_SERVICE_PATH)
            subprocess.run(["systemctl", "daemon-reload"], capture_output=True, check=False)
            logger.info("Automated monthly quota reset timer disabled.")
            return True
        except Exception as e:
            logger.error(f"Failed to disable monthly reset timer: {e}")
            return False

    service_content = """[Unit]
Description=VexTunnel Monthly Bandwidth Quota Reset
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /etc/vextunnel/core/quota_manager.py reset-all
"""

    timer_content = """[Unit]
Description=Monthly Timer for VexTunnel Bandwidth Quota Reset

[Timer]
OnCalendar=*-*-01 00:00:00
Persistent=true

[Install]
WantedBy=timers.target
"""
    try:
        with open(RESET_SERVICE_PATH, "w") as f:
            f.write(service_content)
        with open(RESET_TIMER_PATH, "w") as f:
            f.write(timer_content)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, check=False)
        subprocess.run(["systemctl", "enable", "--now", "vextunnel-quota-reset.timer"], capture_output=True, check=False)
        logger.info("Automated monthly quota reset timer enabled successfully.")
        return True
    except Exception as e:
        logger.error(f"Failed to enable monthly reset timer: {e}")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "reset-all":
        res = reset_all_quotas()
        print(f"SUCCESS: Reset bandwidth quotas for {res} users.")
    else:
        sync = sync_all_quotas()
        print("VexTunnel Quota Sync Summary:")
        for u, inf in sync.items():
            print(f" {u:<16}: Used {format_bytes(inf['used_bytes'])} / {format_bytes(inf['quota_bytes'])} [{inf['quota_status'].upper()}]")

