#!/usr/bin/env python3
"""
VexTunnel - System & Service Monitor
Author: VexElvn
License: MIT
"""

import os
import subprocess
import shutil

def get_system_stats():
    stats = {
        "os": "Linux" if os.name != 'nt' else "Windows",
        "cpu": "N/A",
        "ram_used_mb": 0,
        "ram_total_mb": 0,
        "ram_percent": 0.0,
        "disk_percent": 0.0
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

    ws_8880_status = check_service_status("vextunnel-ws-8880")
    if "RUNNING" not in ws_8880_status:
        ws_8880_status = check_service_status("securetunnel-ws-8880")

    services = {
        "OpenSSH Server (22/2222)": check_service_status("ssh"),
        "Dropbear SSH (109/143)": check_service_status("dropbear"),
        "WebSocket Proxy (Port 80)": ws_80_status,
        "WebSocket Proxy (Port 8880)": ws_8880_status,
        "3X-UI / Xray Panel": check_service_status("x-ui"),
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
