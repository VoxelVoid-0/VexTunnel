#!/usr/bin/env python3
"""
VexTunnel - System & Service Monitor
Author: VexElvn
License: MIT
"""

import os
import subprocess
import shutil
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.session_enforcer import SYSTEM_USERS, is_system_or_admin_user

def get_uptime() -> str:
    """Get system uptime string."""
    if os.name == 'nt':
        return "1 day, 2:30 (Dev)"
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
            days = int(uptime_seconds // (24 * 3600))
            hours = int((uptime_seconds % (24 * 3600)) // 3600)
            minutes = int((uptime_seconds % 3600) // 60)
            if days > 0:
                return f"{days}d {hours}h {minutes}m"
            return f"{hours}h {minutes}m"
    except Exception:
        return "N/A"

def get_online_users(db_path: str = None) -> list:
    """Retrieve list of currently connected VexTunnel VPN tunnel users."""
    if os.name == 'nt':
        return [{"user": "dev_user", "ip": "127.0.0.1", "service": "Dropbear", "time": "00:00"}]

    online = []
    seen = set()

    # Load registered tunnel users from DB if available so we strictly display VexTunnel accounts
    registered_users = set()
    try:
        from core.user_manager import DEFAULT_DB_PATH
        actual_db = db_path or DEFAULT_DB_PATH
        if os.path.exists(actual_db):
            import sqlite3
            conn = sqlite3.connect(actual_db, timeout=2.0)
            rows = conn.execute("SELECT username FROM users").fetchall()
            registered_users = {r[0] for r in rows}
            conn.close()
    except Exception:
        pass

    # Parse process table for active Dropbear and OpenSSH VPN tunnels
    try:
        ps_res = subprocess.run(["ps", "-eo", "user,pid,comm,args"], capture_output=True, text=True, timeout=3)
        for line in ps_res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3:
                user = parts[0]
                # Filter out system daemons, administrative accounts, and grep processes
                if user in SYSTEM_USERS or is_system_or_admin_user(user) or "grep" in line:
                    continue
                # If registered_users is available, strictly filter to VexTunnel managed accounts
                if registered_users and user not in registered_users:
                    continue

                comm = parts[2].lower()
                args_str = " ".join(parts[3:]).lower() if len(parts) > 3 else ""

                if "dropbear" in comm or "dropbear" in args_str:
                    if user not in seen:
                        online.append({"user": user, "ip": "via WebSocket / Port 80/443", "service": "Dropbear WS", "time": "Active"})
                        seen.add(user)
                elif ("sshd" in comm or "sshd-session" in comm) and user not in seen:
                    online.append({"user": user, "ip": "via SSH Tunnel", "service": "OpenSSH Tunnel", "time": "Active"})
                    seen.add(user)
    except Exception:
        pass

    return online

def get_system_stats(db_path: str = None):
    stats = {
        "os": "Linux" if os.name != 'nt' else "Windows",
        "cpu": "N/A",
        "uptime": get_uptime(),
        "ram_used_mb": 0,
        "ram_total_mb": 0,
        "ram_percent": 0.0,
        "disk_percent": 0.0,
        "online_users_count": len(get_online_users(db_path))
    }

    # Disk usage
    total, used, free = shutil.disk_usage("/")
    stats["disk_percent"] = round((used / total) * 100, 1)

    # Linux stats
    if os.name != 'nt':
        try:
            with open("/proc/meminfo", "r") as f:
                lines = f.readlines()
            mem_total = 0
            mem_available = 0
            for line in lines:
                if line.startswith("MemTotal:"):
                    mem_total = int(line.split()[1]) // 1024
                elif line.startswith("MemAvailable:"):
                    mem_available = int(line.split()[1]) // 1024
            mem_used = mem_total - mem_available
            stats["ram_total_mb"] = mem_total
            stats["ram_used_mb"] = mem_used
            stats["ram_percent"] = round((mem_used / mem_total) * 100, 1) if mem_total else 0.0
        except Exception:
            pass

        try:
            loadavg = os.getloadavg()
            stats["cpu"] = f"{loadavg[0]} (1m), {loadavg[1]} (5m)"
        except Exception:
            pass

    return stats

def check_service_status(service_name: str) -> str:
    """Check systemd service active status."""
    if os.name == 'nt':
        return "UNKNOWN (Windows Dev)"

    try:
        res = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        status = res.stdout.strip()
        if status == "active":
            return "\033[92m● RUNNING\033[0m"
        elif status == "inactive":
            return "\033[93m○ STOPPED\033[0m"
        elif status == "failed":
            return "\033[91m✕ FAILED\033[0m"
        else:
            return f"\033[90m{status}\033[0m"
    except Exception:
        return "\033[91m✕ ERROR\033[0m"

def get_all_services_status():
    ws_80_status = check_service_status("vextunnel-ws")
    if "RUNNING" not in ws_80_status:
        ws_80_status = check_service_status("securetunnel-ws")

    ws_443_status = check_service_status("vextunnel-wss")

    ws_8880_status = check_service_status("vextunnel-ws-8880")
    if "RUNNING" not in ws_8880_status:
        ws_8880_status = check_service_status("securetunnel-ws-8880")

    services = {
        "OpenSSH Server (22/2222)": check_service_status("ssh"),
        "Dropbear SSH (109/143)": check_service_status("dropbear"),
        "WebSocket Proxy (Port 80 HTTP)": ws_80_status,
        "WebSocket Proxy (Port 443 WSS)": ws_443_status,
        "WebSocket Proxy (Port 8880)": ws_8880_status,
        "Session Concurrency Enforcer": check_service_status("vextunnel-enforcer"),
        "BadVPN UDPGW (Port 7100)": check_service_status("badvpn-7100"),
        "BadVPN UDPGW (Port 7200)": check_service_status("badvpn-7200"),
        "BadVPN UDPGW (Port 7300)": check_service_status("badvpn-7300")
    }
    return services

if __name__ == "__main__":
    stats = get_system_stats()
    print("--- System Stats ---")
    print(f"OS: {stats['os']}")
    print(f"RAM: {stats['ram_used_mb']} MB / {stats['ram_total_mb']} MB ({stats['ram_percent']}%)")
    print(f"Disk: {stats['disk_percent']}% used")
    print("\n--- Services Status ---")
    for s, st in get_all_services_status().items():
        print(f"{s:<30}: {st}")
