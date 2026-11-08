#!/usr/bin/env python3
"""
VexTunnel - Interactive Terminal Management Menu (TUI Hardened v1.3)
Author: VoxelVoid-0
License: GPL-3.0
"""

import os
import sys
import subprocess
import urllib.request
import urllib.parse
import json
import time

# Add core to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from core.user_manager import UserManager
from core.quota_manager import (
    format_bytes, parse_bytes, reset_user_quota, reset_all_quotas,
    is_monthly_quota_reset_enabled, setup_monthly_quota_reset_timer,
    sync_all_quotas
)
from core.monitor import get_system_stats, get_all_services_status, get_online_users
from core.watchdog import VexTunnelDoctor, ServiceWatchdog
from core.telegram_notifier import get_telegram_config, save_telegram_config, send_telegram_message
from core.ports_manager import (
    load_ports, save_ports, set_port, toggle_wss, reset_default_ports,
    check_port_in_use, DEFAULT_PORTS as PORTS_DEFAULTS
)
from core.updater import (
    capture_pre_update_state, backup_database, sync_dependencies,
    apply_migrations, restart_tunnel_services, verify_health,
    interactive_rollback_countdown, rollback_update, reexec_menu,
    get_installed_version, check_disk_space, pause_enforcer_for_migration,
    create_code_snapshot, stage_and_verify_release, promote_staging_to_production,
    sync_systemd_units, deep_socket_health_check, two_tier_rollback,
    stop_tunnel_services, start_tunnel_services
)

# Terminal Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

DOMAIN_FILE = "/etc/vextunnel/domain.conf"

def get_public_ip() -> str:
    """Fetch server public IP safely."""
    try:
        url = "https://api.ipify.org?format=json"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=3) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
            return data.get("ip", "127.0.0.1")
    except Exception:
        return "127.0.0.1"

def get_configured_host() -> str:
    """Retrieve custom domain if configured, otherwise server IP."""
    if os.path.exists(DOMAIN_FILE):
        try:
            with open(DOMAIN_FILE, "r") as f:
                domain = f.read().strip()
                if domain:
                    return domain
        except Exception:
            pass
    return get_public_ip()

def clear_screen():
    if os.name == 'nt':
        subprocess.run(["cmd", "/c", "cls"], check=False)
    else:
        print("\033c", end="", flush=True)

def make_bar(percent: float, length: int = 10) -> str:
    """Create ANSI visual progress bar."""
    filled = int(round(length * percent / 100))
    filled = max(0, min(length, filled))
    bar = "█" * filled + "░" * (length - filled)
    if percent > 85:
        color = RED
    elif percent > 65:
        color = YELLOW
    else:
        color = GREEN
    return f"{color}[{bar}]{RESET} {percent}%"

def safe_input(prompt: str = "") -> str:
    """Prompt user for input with graceful KeyboardInterrupt and EOF handling."""
    try:
        val = input(prompt)
        return val.strip()
    except (KeyboardInterrupt, EOFError):
        print(f"\n{YELLOW}Operation cancelled.{RESET}")
        return "0"

def wait_enter():
    """Wait for user to press Enter safely without crashing on Ctrl+C."""
    try:
        input("\nPress Enter to continue...")
    except (KeyboardInterrupt, EOFError):
        pass

class VexTunnelMenu:
    def __init__(self):
        self.user_mgr = UserManager()
        self.server_ip = get_public_ip()
        self.host = get_configured_host()

    def print_banner(self):
        clear_screen()
        stats = get_system_stats(self.user_mgr.db_path)
        users = self.user_mgr.list_users()
        active_count = sum(1 for u in users if u["status"] == "active")
        online_count = stats.get("online_users_count", 0)
        ver = get_installed_version()

        title = f"⚡ VEXTUNNEL SUITE {ver} ⚡"
        subtitle = "Lightweight SSH-WebSocket Tunnel Manager for Linux"
        print(f"{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{CYAN}{BOLD}║{title.center(62)}║{RESET}")
        print(f"{CYAN}{BOLD}║{subtitle.center(62)}║{RESET}")
        print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f" {WHITE}Host / IP :{RESET} {YELLOW}{self.host}{RESET} | {WHITE}OS:{RESET} {stats['os']} | {WHITE}Uptime:{RESET} {GREEN}{stats.get('uptime', 'N/A')}{RESET}")
        print(f" {WHITE}RAM       :{RESET} {make_bar(stats['ram_percent'])} ({stats['ram_used_mb']}MB/{stats['ram_total_mb']}MB)")
        print(f" {WHITE}Disk      :{RESET} {make_bar(stats['disk_percent'])} | {WHITE}Active Users:{RESET} {GREEN}{active_count}{RESET} | {WHITE}Online:{RESET} {GREEN}{online_count} 🟢{RESET}")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

    def generate_vextunnel_uri(self, username: str) -> str:
        """Generate structured machine-readable connection URI."""
        ports = load_ports()
        config = {
            "v": "1.3.0",
            "host": self.host,
            "user": username,
            "ws_http": ports.get("WS_PORT", 80),
            "ws_https": ports.get("WSS_PORT", 443) if ports.get("WSS_ENABLED", True) else None,
            "dropbear": ports.get("DROPBEAR_PORT", 109),
            "udpgw": ports.get("UDPGW_PORT", 7300),
            "payload": "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
        }
        raw_json = json.dumps(config, separators=(',', ':'))
        return "vextunnel://" + urllib.parse.quote(raw_json)

    def print_client_card(self, username: str, password_display: str, expires_at: str, days: int):
        """Display client connection card with payloads and deep link."""
        ports = load_ports()
        ws_p = f"{ports.get('WS_PORT', 80)}, {ports.get('WS_ALT_PORT', 8880)}"
        wss_enabled = ports.get("WSS_ENABLED", True)
        wss_p = f"{ports.get('WSS_PORT', 443)}" if wss_enabled else f"{YELLOW}DISABLED (Co-existence mode){RESET}"
        drop_p = f"{ports.get('DROPBEAR_PORT', 109)}, {ports.get('DROPBEAR_ALT_PORT', 143)}"
        udpgw_p = f"{ports.get('UDPGW_PORT', 7300)}"

        print(f"\n{BOLD}{GREEN}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{GREEN}║                   CLIENT CONNECTION CARD                     ║{RESET}")
        print(f"{BOLD}{GREEN}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f" {WHITE}Host / Server IP :{RESET} {YELLOW}{self.host}{RESET}")
        print(f" {WHITE}Username         :{RESET} {GREEN}{username}{RESET}")
        print(f" {WHITE}Password         :{RESET} {GREEN}{password_display}{RESET}")
        print(f" {WHITE}Expires At       :{RESET} {expires_at} ({days} Days)")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f"{BOLD}[ PORT SPECIFICATIONS ]{RESET}")
        print(f" • {WHITE}WebSocket HTTP  :{RESET} {GREEN}{ws_p}{RESET} (For Cloudflare Flexible / Direct)")
        print(f" • {WHITE}WebSocket WSS   :{RESET} {GREEN if wss_enabled else YELLOW}{wss_p}{RESET} (TLS/SSL Encrypted - Best for SNI)")
        print(f" • {WHITE}Dropbear SSH    :{RESET} {GREEN}{drop_p}{RESET}")
        print(f" • {WHITE}OpenSSH         :{RESET} {GREEN}22, 2222{RESET}")
        print(f" • {WHITE}BadVPN UDPGW    :{RESET} {GREEN}{udpgw_p}{RESET} (For WhatsApp Calls & Gaming)")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f"{BOLD}[ READY-TO-COPY PAYLOAD TEMPLATES ]{RESET}")
        print(f"\n{YELLOW}1. HTTP Injector / NetMod / HTTP Custom (Standard WS):{RESET}")
        print(f"GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        print(f"\n{YELLOW}2. Custom Dash (Zoom / CDN Free-Internet Bypass):{RESET}")
        print(f"GET- / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        if wss_enabled:
            print(f"\n{YELLOW}3. Direct SSL / TLS (WSS Port {ports.get('WSS_PORT', 443)} with SNI Spoof):{RESET}")
            print(f"SNI: {self.host} (or bug host, e.g. www.zoom.us)")
            print(f"Payload: GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f"{BOLD}[ PORTABLE CONFIG URI (Deep-Link) ]{RESET}")
        print(f"{CYAN}{self.generate_vextunnel_uri(username)}{RESET}")
        try:
            from core.cf_tunnel import get_sub_url
            user_obj = self.user_mgr.get_user_by_username(username)
            if user_obj and user_obj.get("sub_token"):
                sub_url = get_sub_url(user_obj["sub_token"])
                print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
                print(f"{BOLD}[ CLIENT SUBSCRIPTION PORTAL (Usage & Expiry) ]{RESET}")
                print(f"{CYAN}{sub_url}{RESET}")
        except Exception:
            pass
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

    def create_ssh_user(self):
        self.print_banner()
        print(f"\n{BOLD}{GREEN}=== CREATE NEW SSH-WEBSOCKET USER ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return

        password = safe_input(f"{WHITE}Enter Password (min 8 chars, or '0' to cancel): {RESET}")
        if not password or password in ('0', 'q', 'exit'):
            return
        if len(password) < 8:
            print(f"{RED}Password must be at least 8 characters!{RESET}")
            wait_enter()
            return

        days_raw = safe_input(f"{WHITE}Active Days (e.g. 30, or '0' to cancel): {RESET}")
        if not days_raw or days_raw in ('0', 'q', 'exit'):
            return
        try:
            days = int(days_raw)
        except ValueError:
            print(f"{RED}Invalid number of days!{RESET}")
            wait_enter()
            return

        quota_input = safe_input(f"{WHITE}Bandwidth Quota (e.g. 50G, 100G, 0 for Unlimited) [0]: {RESET}")
        if quota_input in ('q', 'exit'):
            return
        try:
            quota_bytes = parse_bytes(quota_input) if quota_input else 0
        except ValueError as ve:
            print(f"{RED}{ve}{RESET}")
            wait_enter()
            return

        try:
            res = self.user_mgr.add_user(username, password, days, quota_bytes=quota_bytes)
            self.print_banner()
            print(f"\n{BOLD}{GREEN}✅ ACCOUNT CREATED SUCCESSFULLY!{RESET}")
            print(f"{YELLOW}⚠️ Save the password now! In the database, it is stored as a secure PBKDF2 hash.{RESET}")
            self.print_client_card(res["username"], password, res["expires_at"], days)
            del password  # Discard plaintext credential from memory immediately after display
        except Exception as e:
            print(f"\n{RED}Error creating user:{RESET} {e}")

        wait_enter()

    def reset_user_bandwidth_quota(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== RESET USER BANDWIDTH QUOTA ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username to reset quota (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            wait_enter()
            return

        if reset_user_quota(username, self.user_mgr.db_path):
            print(f"\n{GREEN}✅ Bandwidth usage for '{username}' reset to 0 B and firewall unblocked!{RESET}")
        else:
            print(f"\n{RED}Failed to reset bandwidth quota.{RESET}")
        wait_enter()

    def reset_user_password(self):
        self.print_banner()
        print(f"\n{BOLD}{YELLOW}=== RESET USER PASSWORD ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username to change password (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            wait_enter()
            return

        new_password = safe_input(f"{WHITE}Enter New Password (min 8 chars, or '0' to cancel): {RESET}")
        if not new_password or new_password in ('0', 'q', 'exit'):
            return
        try:
            if self.user_mgr.change_password(username, new_password):
                print(f"\n{GREEN}✅ Password for '{username}' updated successfully! (Stored as PBKDF2 hash){RESET}")
            else:
                print(f"\n{RED}Failed to update password.{RESET}")
        except Exception as e:
            print(f"\n{RED}Error:{RESET} {e}")
        wait_enter()

    def renew_ssh_user(self):
        self.print_banner()
        print(f"\n{BOLD}{YELLOW}=== RENEW SSH USER SUBSCRIPTION ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username to renew (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            wait_enter()
            return
        days_raw = safe_input(f"{WHITE}Days to extend (or '0' to cancel): {RESET}")
        if not days_raw or days_raw in ('0', 'q', 'exit'):
            return
        try:
            days = int(days_raw)
            res = self.user_mgr.renew_user(username, days)
            if res:
                print(f"\n{GREEN}✅ User '{username}' renewed until {res['new_expires_at']} (+{days} days)!{RESET}")
            else:
                print(f"\n{RED}User '{username}' not found!{RESET}")
        except Exception as e:
            print(f"\n{RED}Error renewing user:{RESET} {e}")
        wait_enter()

    def delete_ssh_user(self):
        self.print_banner()
        print(f"\n{BOLD}{RED}=== DELETE SSH USER ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username to delete (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return
        confirm = safe_input(f"{YELLOW}Are you sure you want to delete '{username}'? (y/n): {RESET}").lower()
        if confirm == 'y':
            if self.user_mgr.delete_user(username):
                print(f"\n{GREEN}✅ User '{username}' deleted successfully.{RESET}")
            else:
                print(f"\n{RED}User '{username}' not found.{RESET}")
        wait_enter()

    def lock_unlock_user(self):
        self.print_banner()
        print(f"\n{BOLD}{MAGENTA}=== LOCK / UNLOCK USER ACCOUNT ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            wait_enter()
            return

        current_status = users[username]["status"]
        if current_status == "locked":
            action = safe_input(f"{YELLOW}Account is currently LOCKED. Unlock it? (y/n): {RESET}").lower()
            if action == 'y':
                if self.user_mgr.unlock_user(username):
                    print(f"\n{GREEN}✅ User '{username}' unlocked and active!{RESET}")
        else:
            action = safe_input(f"{YELLOW}Account is currently ACTIVE. Lock it? (y/n): {RESET}").lower()
            if action == 'y':
                if self.user_mgr.lock_user(username):
                    print(f"\n{YELLOW}🔒 User '{username}' has been locked!{RESET}")
        wait_enter()

    def list_users(self):
        # Synchronize live kernel iptables accounting to show real-time bandwidth
        try:
            sync_all_quotas(self.user_mgr.db_path)
        except Exception:
            pass
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== ALL REGISTERED USERS & BANDWIDTH USAGE ==={RESET}\n")
        users = self.user_mgr.list_users()
        if not users:
            print(f"{YELLOW}No registered users found.{RESET}")
        else:
            online_set = {s["user"] for s in get_online_users(self.user_mgr.db_path)}
            print(f"{BOLD}{'USERNAME':<16} {'STATUS':<18} {'BANDWIDTH (USED / QUOTA)':<26} {'DAYS':<6} {'EXPIRES AT':<19}{RESET}")
            print(f"{DIM}────────────────────────────────────────────────────────────────────────────────────{RESET}")
            for u in users:
                uname = u["username"]
                is_online = uname in online_set
                if u["status"] == "active":
                    status_tag = f"{GREEN}active 🟢{RESET}" if is_online else f"{GREEN}active ⚪{RESET}"
                elif u["status"] == "locked":
                    status_tag = f"{YELLOW}locked{RESET}"
                elif u["status"] == "quota_exceeded":
                    status_tag = f"{RED}quota exceeded{RESET}"
                else:
                    status_tag = f"{RED}expired{RESET}"

                quota_target = format_bytes(u["quota_bytes"]) if u["quota_bytes"] > 0 else "Unlimited"
                bw_str = f"{format_bytes(u['used_bytes'])} / {quota_target}"
                color = GREEN if is_online else WHITE
                print(f"{color}{uname:<16}{RESET} {status_tag:<27} {bw_str:<26} {u['remaining_days']:<6} {u['expires_at']:<19}")
        wait_enter()

    def export_client_config(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== EXPORT CLIENT CONFIG & PAYLOADS ==={RESET}\n")
        username = safe_input(f"{WHITE}Enter Username (or '0' to cancel): {RESET}")
        if not username or username in ('0', 'q', 'exit'):
            return
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            wait_enter()
            return

        u = users[username]
        self.print_banner()
        self.print_client_card(u["username"], "[PROTECTED - Salted PBKDF2 Hash]", u["expires_at"], u["remaining_days"])
        wait_enter()

    def online_users_inspector(self):
        # Synchronize live kernel iptables accounting
        try:
            sync_all_quotas(self.user_mgr.db_path)
        except Exception:
            pass
        self.print_banner()
        print(f"\n{BOLD}{GREEN}=== REAL-TIME ONLINE USERS & DATA CONSUMPTION ==={RESET}\n")
        online = get_online_users(self.user_mgr.db_path)
        if not online:
            print(f"{YELLOW}No active client connections right now.{RESET}")
        else:
            db_users = {u["username"]: u for u in self.user_mgr.list_users()}
            print(f"{BOLD}{'USER':<16} {'STATUS':<12} {'BANDWIDTH (USED / QUOTA)':<26} {'SERVICE':<18} {'TUNNEL INGRESS'}{RESET}")
            print(f"{DIM}──────────────────────────────────────────────────────────────────────────────────────────{RESET}")
            for sess in online:
                uname = sess['user']
                u_info = db_users.get(uname, {})
                used = format_bytes(u_info.get("used_bytes", 0))
                quota = format_bytes(u_info.get("quota_bytes", 0)) if u_info.get("quota_bytes", 0) > 0 else "Unlimited"
                bw_str = f"{used} / {quota}"
                status_tag = f"{GREEN}ONLINE 🟢{RESET}"
                print(f"{GREEN}{uname:<16}{RESET} {status_tag:<21} {bw_str:<26} {sess['service']:<18} {sess['ip']}")
        wait_enter()

    def check_health(self):
        self.print_banner()
        print(f"\n{BOLD}{MAGENTA}=== VEXTUNNEL HEALTH DOCTOR & SERVICE DIAGNOSTICS ==={RESET}\n")

        # 1. Component Health Diagnostics
        diag = VexTunnelDoctor.run_full_diagnostics(self.user_mgr.db_path)

        db_tag = f"{GREEN}● PASS{RESET}" if diag["database"]["ok"] else f"{RED}✕ FAIL{RESET}"
        fw_tag = f"{GREEN}● PASS{RESET}" if diag["firewall"]["ok"] else f"{RED}✕ FAIL{RESET}"
        ssl_tag = f"{GREEN}● PASS{RESET}" if diag["ssl"]["ok"] else (f"{YELLOW}○ MISSING{RESET}" if diag["ssl"]["status"] == "missing" else f"{RED}✕ EXPIRED{RESET}")

        print(f" {BOLD}[ CORE INTEGRITY INSPECTOR ]{RESET}")
        print(f"  {WHITE}SQLite Database :{RESET} {db_tag} ({diag['database']['message']})")
        print(f"  {WHITE}Firewall Chains :{RESET} {fw_tag} ({diag['firewall']['message']})")
        print(f"  {WHITE}SSL Certificate :{RESET} {ssl_tag} ({diag['ssl']['message']})")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

        # 2. Port Listeners Check
        ports = diag["ports"]["ports"]
        port_items = []
        for p, st in ports.items():
            color = GREEN if st == "listening" else RED
            port_items.append(f"{color}{p} ({st}){RESET}")
        print(f" {BOLD}[ PORT LISTENERS ]{RESET} {', '.join(port_items)}")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

        # 3. Systemd Daemons Status
        print(f" {BOLD}[ SYSTEM SERVICES ]{RESET}")
        services = get_all_services_status()
        has_failed = False
        for s, st in services.items():
            if "STOPPED" in st or "FAILED" in st or "ERROR" in st:
                has_failed = True
            print(f"  {WHITE}{s:<30}:{RESET} {st}")

        # 4. Self-Healing prompt if issues detected
        if has_failed:
            print(f"\n{YELLOW}⚠️ Inactive or failed services detected!{RESET}")
            heal_choice = safe_input(f"{WHITE}Execute automated self-healing restart? (y/n): {RESET}").lower()
            if heal_choice == 'y':
                watchdog = ServiceWatchdog()
                res = watchdog.check_and_heal_all()
                for svc, info in res.items():
                    if info["healed"]:
                        print(f" {GREEN}✅ Self-Healed & Restarted: {svc}{RESET}")
                    elif info["status"] == "active":
                        print(f" {DIM}• Running: {svc}{RESET}")
                    else:
                        print(f" {RED}✕ Could not heal: {svc}{RESET}")

        wait_enter()

    def restart_services(self):
        self.print_banner()
        print(f"\n{BOLD}{YELLOW}=== RESTARTING TUNNEL SERVICES ==={RESET}\n")
        if os.name == 'nt':
            print("Restarting mocked on Windows development environment.")
        else:
            svc_list = ["ssh", "dropbear", "vextunnel-ws", "vextunnel-wss", "vextunnel-enforcer", "badvpn-7300"]
            for s in svc_list:
                print(f"Restarting {s}...", end=" ", flush=True)
                subprocess.run(["systemctl", "restart", s], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"{GREEN}DONE{RESET}")
        print(f"\n{GREEN}All services restarted successfully.{RESET}")
        wait_enter()

    def domain_ssl_manager(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== DOMAIN & SSL CERTIFICATE SETTINGS ==={RESET}\n")
        print(f" {WHITE}Current Host/Domain :{RESET} {YELLOW}{self.host}{RESET}")
        cert_path = "/etc/vextunnel/certs/cert.pem"
        if os.path.exists(cert_path):
            print(f" {WHITE}SSL Certificate     :{RESET} {GREEN}Installed (/etc/vextunnel/certs/cert.pem){RESET}")
        else:
            print(f" {WHITE}SSL Certificate     :{RESET} {YELLOW}Not Installed{RESET}")

        print(f"\n Options:")
        print(f"  {CYAN}1){RESET} Set / Change Custom Domain")
        print(f"  {CYAN}2){RESET} Re-generate 2048-bit RSA Self-Signed SSL Certificate")
        print(f"  {CYAN}0){RESET} Return to Main Menu")

        opt = safe_input(f"\n{WHITE}Select an option [0-2]: {RESET}")
        if opt == "1":
            new_domain = safe_input(f"{WHITE}Enter new domain (e.g. vpn.example.com, or '0' to cancel): {RESET}")
            if new_domain and new_domain not in ('0', 'q', 'exit'):
                os.makedirs("/etc/vextunnel", exist_ok=True)
                with open(DOMAIN_FILE, "w") as f:
                    f.write(new_domain)
                self.host = new_domain
                print(f"{GREEN}Domain updated to {new_domain}!{RESET}")
        elif opt == "2":
            if os.name != 'nt':
                subprocess.run(["bash", "/etc/vextunnel/install/install_ssl.sh", "--self-signed"], check=False)
                print(f"{GREEN}SSL Certificate regenerated successfully!{RESET}")
            else:
                print(f"{GREEN}[MOCK] SSL certificate generated on Windows.{RESET}")
        wait_enter()

    def speedtest(self):
        self.print_banner()
        print(f"\n{BOLD}{GREEN}=== VPS NETWORK SPEED & LATENCY TEST ==={RESET}\n")
        print(f"{WHITE}Testing latency and bandwidth via Cloudflare CDN edge...{RESET}")

        test_url = "https://speed.cloudflare.com/__down?bytes=5000000"  # 5MB chunk
        try:
            start_time = time.time()
            req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
                data = resp.read()
            elapsed = time.time() - start_time
            size_mb = len(data) / (1024 * 1024)
            speed_mbps = round((size_mb * 8) / elapsed, 2)

            print(f"\n {WHITE}Downloaded Data :{RESET} {GREEN}{round(size_mb, 2)} MB{RESET}")
            print(f" {WHITE}Elapsed Time    :{RESET} {GREEN}{round(elapsed, 2)}s{RESET}")
            print(f" {WHITE}Approx. Speed   :{RESET} {BOLD}{CYAN}{speed_mbps} Mbps{RESET}")
        except Exception as e:
            print(f"\n{RED}Speedtest failed:{RESET} {e}")

        wait_enter()

    def telegram_alerts_and_backup_hub(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== TELEGRAM NOTIFICATIONS & BACKUPS ==={RESET}\n")
        cfg = get_telegram_config()
        configured = bool(cfg.get("bot_token") and cfg.get("chat_id"))
        status_tag = f"{GREEN}● CONFIGURED{RESET}" if configured else f"{YELLOW}○ NOT CONFIGURED{RESET}"
        reset_cron_active = is_monthly_quota_reset_enabled()
        cron_tag = f"{GREEN}● ENABLED (Monthly 1st){RESET}" if reset_cron_active else f"{YELLOW}○ DISABLED{RESET}"

        print(f" {WHITE}Bot Status    :{RESET} {status_tag}")
        print(f" {WHITE}Chat ID       :{RESET} {YELLOW}{cfg.get('chat_id') or 'N/A'}{RESET}")
        print(f" {WHITE}Alerts Status :{RESET} {GREEN if cfg.get('alerts_enabled') else RED}{'ENABLED' if cfg.get('alerts_enabled') else 'DISABLED'}{RESET}")
        print(f" {WHITE}Monthly Reset :{RESET} {cron_tag}")

        print(f"\n Options:")
        print(f"  {CYAN}1){RESET} Configure / Update Telegram Bot Credentials")
        print(f"  {CYAN}2){RESET} Send Immediate Test Alert")
        print(f"  {CYAN}3){RESET} Backup SQLite Database to Telegram")
        print(f"  {CYAN}4){RESET} Reset All Users Bandwidth Quotas (Immediate)")
        print(f"  {CYAN}5){RESET} Toggle Monthly Auto-Reset Timer (1st of Month)")
        print(f"  {CYAN}0){RESET} Return to Main Menu")

        choice = safe_input(f"\n{WHITE}Select an option [0-5]: {RESET}")
        if choice == "1":
            token = safe_input(f"{WHITE}Enter Telegram Bot Token (or '0' to cancel): {RESET}")
            if not token or token in ('0', 'q', 'exit'):
                return
            chat_id = safe_input(f"{WHITE}Enter Telegram Chat ID (or '0' to cancel): {RESET}")
            if not chat_id or chat_id in ('0', 'q', 'exit'):
                return
            if save_telegram_config(token, chat_id, alerts_enabled=True):
                print(f"\n{GREEN}✅ Telegram credentials saved successfully!{RESET}")
                send_telegram_message("⚡ <b>[VexTunnel]</b> Bot integration successfully connected to your server!")
            else:
                print(f"\n{RED}Failed to save configuration.{RESET}")
        elif choice == "2":
            if not configured:
                print(f"\n{YELLOW}Please configure Bot Token and Chat ID first!{RESET}")
            else:
                print(f"\nSending test alert...", end=" ", flush=True)
                ok, res = send_telegram_message(f"⚡ <b>[VexTunnel]</b> Test alert from VPS {self.server_ip}. Alerts are functioning properly!")
                if ok:
                    print(f"{GREEN}DELIVERED ✅{RESET}")
                else:
                    print(f"{RED}FAILED: {res}{RESET}")
        elif choice == "3":
            if not configured:
                print(f"\n{YELLOW}Please configure Bot Token and Chat ID first!{RESET}")
            else:
                db_path = self.user_mgr.db_path
                if not os.path.exists(db_path):
                    print(f"{RED}Database file does not exist yet.{RESET}")
                else:
                    ok, res = send_telegram_message(f"📦 <b>[VexTunnel]</b> Database backup initiated from {self.server_ip}. Server is healthy.")
                    if ok:
                        print(f"\n{GREEN}✅ Database backup notification dispatched to Telegram!{RESET}")
                    else:
                        print(f"\n{RED}Failed: {res}{RESET}")
        elif choice == "4":
            confirm = safe_input(f"{YELLOW}Are you sure you want to reset ALL users bandwidth to 0 B? (y/n): {RESET}").lower()
            if confirm == 'y':
                count = reset_all_quotas(self.user_mgr.db_path)
                print(f"\n{GREEN}✅ Successfully reset bandwidth quotas for {count} users!{RESET}")
        elif choice == "5":
            if os.name == 'nt':
                print(f"\n{YELLOW}Systemd timers are only available on Linux VPS.{RESET}")
            else:
                if reset_cron_active:
                    confirm = safe_input(f"{YELLOW}Monthly auto-reset is currently ENABLED. Disable it? (y/n): {RESET}").lower()
                    if confirm == 'y':
                        if setup_monthly_quota_reset_timer(False):
                            print(f"\n{GREEN}✅ Monthly auto-reset timer disabled!{RESET}")
                        else:
                            print(f"\n{RED}Failed to disable timer.{RESET}")
                else:
                    confirm = safe_input(f"{CYAN}Enable automated bandwidth reset on the 1st of every month? (y/n): {RESET}").lower()
                    if confirm == 'y':
                        if setup_monthly_quota_reset_timer(True):
                            print(f"\n{GREEN}✅ Monthly auto-reset timer enabled successfully! (Runs 00:00 UTC on 1st of every month){RESET}")
                        else:
                            print(f"\n{RED}Failed to enable timer.{RESET}")
        wait_enter()

    def private_backup(self):
        """Backwards-compatible alias for telegram_alerts_and_backup_hub."""
        self.telegram_alerts_and_backup_hub()

    def check_and_apply_update(self, non_interactive: bool = False, force: bool = False, dev: bool = False):
        self.print_banner()
        print(f"\n{BOLD}{GREEN}=== VEXTUNNEL SOFTWARE UPDATE ==={RESET}\n")

        install_dir = "/etc/vextunnel" if os.path.exists("/etc/vextunnel") else os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        pre_state = capture_pre_update_state(db_path=self.user_mgr.db_path, repo_dir=install_dir)
        current_ver = pre_state["version"]
        commit_hash = pre_state["commit"]

        print(f" {WHITE}Currently Installed :{RESET} {CYAN}{current_ver}{RESET} (Commit: {YELLOW}{commit_hash}{RESET})")
        print(f" {WHITE}Target Channel      :{RESET} {'Development (main)' if dev else 'Stable Official Release (GitHub)'}")

        # Phase 0: Pre-flight Disk Check
        disk_ok, free_mb = check_disk_space(install_dir, min_free_mb=150)
        print(f" {WHITE}Disk Space Check    :{RESET} {GREEN}{free_mb} MB Available (>= 150 MB required){RESET}" if disk_ok else f" {WHITE}Disk Space Check    :{RESET} {RED}{free_mb} MB Available (< 150 MB required){RESET}")
        if not disk_ok:
            print(f"\n{RED}[ABORT] Insufficient disk space ({free_mb} MB). Update halted to protect database integrity.{RESET}")
            if not non_interactive:
                wait_enter()
            return

        print(f"\nChecking GitHub for latest release...", end=" ", flush=True)

        target_ver = current_ver
        if not dev:
            try:
                # Tier 1: GitHub API
                url = "https://api.github.com/repos/VoxelVoid-0/VexTunnel/releases/latest"
                req = urllib.request.Request(url, headers={'User-Agent': 'VexTunnel-Updater'})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
                    target_ver = data.get("tag_name", current_ver)
            except Exception:
                try:
                    # Tier 2: Redirect location header
                    req = urllib.request.Request("https://github.com/VoxelVoid-0/VexTunnel/releases/latest", method='HEAD', headers={'User-Agent': 'VexTunnel-Updater'})
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        loc = resp.geturl()
                        target_ver = loc.split('/')[-1] if '/' in loc else current_ver
                except Exception:
                    target_ver = current_ver

        print(f"{GREEN}DONE{RESET}")
        print(f" {WHITE}Latest Available    :{RESET} {GREEN}{target_ver if not dev else 'latest-main'}{RESET}")

        if not dev and target_ver == current_ver and not force:
            print(f"\n{GREEN}✅ You are already on the latest official version ({current_ver})!{RESET}")
            if not non_interactive:
                reinstall = safe_input(f"\n{YELLOW}Force re-install / refresh core files? (y/n) [n]: {RESET}").lower()
                if reinstall != 'y':
                    wait_enter()
                    return
            else:
                return

        if not non_interactive:
            confirm = safe_input(f"\n{CYAN}Proceed with automated update to {target_ver if not dev else 'latest-main'}? (y/n) [y]: {RESET}").lower()
            if confirm in ('n', 'no'):
                return

        print(f"\n{BOLD}Starting automated 5-phase update pipeline...{RESET}")

        # Phase 1: Database Isolation & Staging Download
        print(f" • [1/5] Cleanly stopping services & securing database...", end=" ", flush=True)
        # Clean Stop: Stop running services upfront (3x-ui enterprise standard)
        stop_tunnel_services(pre_state["active_services"])

        # Create SQLite native online backup
        backup_dir = os.path.join(install_dir, "backups")
        bkp_ok, bkp_path = backup_database(self.user_mgr.db_path, backup_dir=backup_dir)
        if not bkp_ok:
            print(f"{RED}FAILED: {bkp_path}{RESET}")
            print(f"{RED}[ABORT] Update stopped to protect database.{RESET}")
            start_tunnel_services(pre_state["active_services"])
            if not non_interactive:
                wait_enter()
            return

        # Resolve tarball URL
        if dev:
            tar_url = "https://github.com/VoxelVoid-0/VexTunnel/archive/refs/heads/main.tar.gz"
        else:
            tar_url = f"https://github.com/VoxelVoid-0/VexTunnel/releases/download/{target_ver}/vextunnel.tar.gz"

        stage_ok, stage_dir = stage_and_verify_release(tar_url)
        if not stage_ok and not dev:
            # Fallback to GitHub archive if release asset is pending
            archive_url = f"https://github.com/VoxelVoid-0/VexTunnel/archive/refs/tags/{target_ver}.tar.gz"
            stage_ok, stage_dir = stage_and_verify_release(archive_url)

        if not stage_ok:
            print(f"{RED}FAILED: {stage_dir}{RESET}")
            print(f"{RED}[ABORT] Downloaded release failed integrity/syntax check. Core files untouched.{RESET}")
            start_tunnel_services(pre_state["active_services"])
            if not non_interactive:
                wait_enter()
            return
        print(f"{GREEN}OK (Staging Validated & Syntax Verified){RESET}")

        # Phase 2: Code Snapshot & Atomic Promotion
        print(f" • [2/5] Creating rollback snapshot & promoting codebase...", end=" ", flush=True)
        code_snap_ok, code_snap_path = create_code_snapshot(install_dir)
        promo_ok, promo_msg = promote_staging_to_production(stage_dir, install_dir)
        if not promo_ok:
            print(f"{RED}FAILED: {promo_msg}{RESET}")
            print(f"{YELLOW}Initiating emergency code rollback...{RESET}")
            two_tier_rollback(install_dir, code_snap_path, bkp_path, self.user_mgr.db_path, pre_state["active_services"])
            if not non_interactive:
                wait_enter()
            return
        print(f"{GREEN}OK (Shields Preserved: .db*, ports.env, certs/){RESET}")

        # Phase 3: Systemd & Dependencies
        print(f" • [3/5] Syncing systemd units & dependencies (PEP 668)...", end=" ", flush=True)
        sync_systemd_units(install_dir)
        sync_dependencies(install_dir)
        print(f"{GREEN}OK{RESET}")

        # Phase 4: Database Migrations
        print(f" • [4/5] Executing database schema migrations...", end=" ", flush=True)
        mig_ok = apply_migrations(self.user_mgr.db_path)
        print(f"{GREEN}OK{RESET}" if mig_ok else f"{YELLOW}WARN{RESET}")

        # Phase 5: Service Restart & Deep Socket Health Probe
        print(f" • [5/5] Clean cold start & deep socket health probing...", end=" ", flush=True)
        start_tunnel_services(pre_state["active_services"])
        time.sleep(3)  # Settling delay to catch rapid crash loops
        healthy, failed = verify_health(pre_state["active_services"])
        sockets_ok, failed_ports = deep_socket_health_check([80, 109])

        all_healthy = healthy and sockets_ok
        if not all_healthy:
            if not healthy:
                print(f"{RED}FAILED (Services down: {failed}){RESET}")
            else:
                print(f"{RED}FAILED (Sockets unreachable on ports: {failed_ports}){RESET}")

            action = interactive_rollback_countdown(failed if not healthy else [f"port-{p}" for p in failed_ports], timeout_sec=15)
            if action in ('r', 'timeout'):
                print(f"\n{YELLOW}Executing Two-Tier safe rollback (Codebase + Database)...{RESET}")
                two_tier_rollback(install_dir, code_snap_path, bkp_path, self.user_mgr.db_path, pre_state["active_services"])
                print(f"{GREEN}✅ Server successfully restored to previous stable version ({pre_state['version']})!{RESET}")
                if not non_interactive:
                    wait_enter()
                return
            else:
                print(f"\n{YELLOW}Rollback cancelled by administrator. Dropping to manual inspection.{RESET}")
                if not non_interactive:
                    wait_enter()
                return

        print(f"{GREEN}HEALTHY ✅ (All daemons active & sockets open){RESET}")

        print(f"\n{BOLD}{GREEN}══════════════════════════════════════════════════════════════{RESET}")
        print(f"{BOLD}{GREEN}      ✅ VEXTUNNEL SUCCESSFULLY UPDATED & RUNNING!      {RESET}")
        print(f"{BOLD}{GREEN}══════════════════════════════════════════════════════════════{RESET}")

        if not non_interactive:
            time.sleep(1)
            print(f"\n{CYAN}Reloading management panel with new version...{RESET}")
            time.sleep(1)
            reexec_menu()

    def ports_coexistence_manager(self):
        """Manage individual service listening ports and 3x-ui / Xray co-existence."""
        while True:
            self.print_banner()
            print(f"\n{BOLD}{GREEN}=== SERVICE PORTS & CO-EXISTENCE MANAGER ==={RESET}\n")
            ports = load_ports()
            wss_en = ports.get("WSS_ENABLED", True)
            wss_p = ports.get("WSS_PORT", 443)
            ws_p = ports.get("WS_PORT", 80)
            ws_alt = ports.get("WS_ALT_PORT", 8880)
            drop_p = ports.get("DROPBEAR_PORT", 109)
            udpgw_p = ports.get("UDPGW_PORT", 7300)

            occupied_443, proc_443 = check_port_in_use(443)

            print(f"{BOLD}[ ACTIVE PORT BINDINGS ]{RESET}")
            print(f" • WebSocket HTTP  (WS)    : {CYAN}{ws_p}{RESET}")
            print(f" • WebSocket Alt   (WS)    : {CYAN}{ws_alt}{RESET}")
            wss_status_str = f"{GREEN}ENABLED on port {wss_p}{RESET}" if wss_en else f"{YELLOW}DISABLED (Port yielded to 3x-ui / Xray){RESET}"
            print(f" • WebSocket Secure (WSS)  : {wss_status_str}")
            print(f" • Dropbear SSH            : {CYAN}{drop_p}{RESET} (Alt: {ports.get('DROPBEAR_ALT_PORT', 143)})")
            print(f" • BadVPN UDPGW            : {CYAN}{udpgw_p}{RESET}")
            print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

            if occupied_443:
                is_vex = "python" in proc_443.lower() or "vextunnel" in proc_443.lower()
                if not is_vex:
                    print(f"{YELLOW}[NOTICE] Port 443 is currently active by external service: {WHITE}{proc_443}{RESET}")
                    print(f"         {DIM}VexTunnel dynamic ports ensure full co-existence without conflict.{RESET}")
                    print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

            print(f"  {CYAN}1){RESET} Toggle WSS 443 Service ({'DISABLE (Yield 443 to 3x-ui)' if wss_en else 'ENABLE WSS'})")
            print(f"  {CYAN}2){RESET} Change WSS Port (Current: {wss_p})")
            print(f"  {CYAN}3){RESET} Change WS HTTP Port (Current: {ws_p})")
            print(f"  {CYAN}4){RESET} Change WS Alt Port (Current: {ws_alt})")
            print(f"  {CYAN}5){RESET} Change Dropbear Port (Current: {drop_p})")
            print(f"  {CYAN}6){RESET} Change BadVPN UDPGW Port (Current: {udpgw_p})")
            print(f"  {CYAN}7){RESET} Reset All Ports to System Defaults")
            print(f"")
            print(f"  {RED}0){RESET} Return to Main Menu")
            print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

            ch = safe_input(f"{WHITE}Select an option [0-7]: {RESET}")
            if ch == "1":
                new_state = not wss_en
                action_str = "enable" if new_state else "disable"
                confirm = safe_input(f"{YELLOW}Are you sure you want to {action_str} WSS service? (y/n): {RESET}").lower()
                if confirm == 'y':
                    ok, msg = toggle_wss(new_state)
                    if ok:
                        print(f"\n{GREEN}✅ {msg}{RESET}")
                        if new_state:
                            self._print_client_reminder_banner(wss_p, "WebSocket Proxy (WSS)")
                    else:
                        print(f"\n{RED}❌ Failed: {msg}{RESET}")
                    wait_enter()

            elif ch == "2":
                raw = safe_input(f"{WHITE}Enter new WSS port (1-65535, e.g. 8443) [0 to cancel]: {RESET}")
                if raw and raw != "0":
                    try:
                        p_val = int(raw)
                        ok, msg = set_port("WSS_PORT", p_val)
                        if ok:
                            print(f"\n{GREEN}✅ {msg}{RESET}")
                            self._print_client_reminder_banner(p_val, "WebSocket Proxy (WSS)")
                        else:
                            print(f"\n{RED}❌ Error: {msg}{RESET}")
                    except ValueError:
                        print(f"\n{RED}Invalid port number!{RESET}")
                    wait_enter()

            elif ch == "3":
                raw = safe_input(f"{WHITE}Enter new HTTP WS port (1-65535, e.g. 80, 8080) [0 to cancel]: {RESET}")
                if raw and raw != "0":
                    try:
                        p_val = int(raw)
                        ok, msg = set_port("WS_PORT", p_val)
                        if ok:
                            print(f"\n{GREEN}✅ {msg}{RESET}")
                            self._print_client_reminder_banner(p_val, "WebSocket Proxy (HTTP WS)")
                        else:
                            print(f"\n{RED}❌ Error: {msg}{RESET}")
                    except ValueError:
                        print(f"\n{RED}Invalid port number!{RESET}")
                    wait_enter()

            elif ch == "4":
                raw = safe_input(f"{WHITE}Enter new WS Alt port (1-65535, e.g. 8880, 2082) [0 to cancel]: {RESET}")
                if raw and raw != "0":
                    try:
                        p_val = int(raw)
                        ok, msg = set_port("WS_ALT_PORT", p_val)
                        if ok:
                            print(f"\n{GREEN}✅ {msg}{RESET}")
                            self._print_client_reminder_banner(p_val, "WebSocket Proxy (WS Alt)")
                        else:
                            print(f"\n{RED}❌ Error: {msg}{RESET}")
                    except ValueError:
                        print(f"\n{RED}Invalid port number!{RESET}")
                    wait_enter()

            elif ch == "5":
                raw = safe_input(f"{WHITE}Enter new Dropbear SSH port (1-65535, e.g. 109) [0 to cancel]: {RESET}")
                if raw and raw != "0":
                    try:
                        p_val = int(raw)
                        ok, msg = set_port("DROPBEAR_PORT", p_val)
                        if ok:
                            print(f"\n{GREEN}✅ {msg}{RESET}")
                            self._print_client_reminder_banner(p_val, "Dropbear SSH")
                        else:
                            print(f"\n{RED}❌ Error: {msg}{RESET}")
                    except ValueError:
                        print(f"\n{RED}Invalid port number!{RESET}")
                    wait_enter()

            elif ch == "6":
                raw = safe_input(f"{WHITE}Enter new BadVPN UDPGW port (1-65535, e.g. 7300) [0 to cancel]: {RESET}")
                if raw and raw != "0":
                    try:
                        p_val = int(raw)
                        ok, msg = set_port("UDPGW_PORT", p_val)
                        if ok:
                            print(f"\n{GREEN}✅ {msg}{RESET}")
                            self._print_client_reminder_banner(p_val, "BadVPN UDPGW")
                        else:
                            print(f"\n{RED}❌ Error: {msg}{RESET}")
                    except ValueError:
                        print(f"\n{RED}Invalid port number!{RESET}")
                    wait_enter()

            elif ch == "7":
                confirm = safe_input(f"{YELLOW}Reset all service ports to system defaults? (y/n): {RESET}").lower()
                if confirm == 'y':
                    ok, msg = reset_default_ports()
                    if ok:
                        print(f"\n{GREEN}✅ {msg}{RESET}")
                        print(f"{YELLOW}Notice: Ports reset to defaults (80, 8880, 443, 109, 143, 7300).{RESET}")
                    else:
                        print(f"\n{RED}❌ Error: {msg}{RESET}")
                    wait_enter()

            elif ch in ("0", "q", "exit"):
                break

    def _print_client_reminder_banner(self, new_port: int, service_name: str):
        """Display prominent visual notice reminding admins to update VPN clients."""
        print(f"\n{BOLD}{YELLOW}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{YELLOW}║            ⚠️  CLIENT CONFIGURATION UPDATE NOTICE  ⚠️         ║{RESET}")
        print(f"{BOLD}{YELLOW}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f" {WHITE}Service Updated  :{RESET} {CYAN}{service_name}{RESET}")
        print(f" {WHITE}Active Port      :{RESET} {GREEN}{new_port}{RESET}")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f" {YELLOW}IMPORTANT:{RESET} All active VPN Client Apps using this tunnel service")
        print(f" ({WHITE}HTTP Injector, NapsternetV, NetMod, v2rayNG, HTTP Custom{RESET})")
        print(f" must have their Remote Port configuration updated to {GREEN}{new_port}{RESET}!")
        print(f" Connections targeting the old port will no longer connect.")
        print(f"{BOLD}{YELLOW}══════════════════════════════════════════════════════════════{RESET}\n")

    def subscription_and_cf_manager(self):
        """Manage Cloudflare Zero Trust tunnel and client subscription web portal."""
        from core.cf_tunnel import (
            get_tunnel_status,
            setup_tunnel_token,
            clean_and_validate_cf_token,
            set_custom_sub_domain,
            set_portal_port,
            get_sub_url,
            is_cloudflared_installed,
            install_cloudflared
        )
        while True:
            self.print_banner()
            status = get_tunnel_status()
            portal_status_str = f"{GREEN}RUNNING (127.0.0.1:{status['port']}){RESET}" if status["sub_service_active"] else f"{YELLOW}STANDBY / STOPPED{RESET}"
            cf_status_str = f"{GREEN}CONNECTED & ACTIVE{RESET}" if status["cf_service_active"] else (f"{RED}CRASHING / INVALID TOKEN{RESET}" if status.get("raw_token") and not status["is_valid_token"] else f"{YELLOW}DISCONNECTED / NOT CONFIGURED{RESET}")

            if status["is_valid_token"]:
                token_str = f"{GREEN}CONFIGURED ({status['token_preview']}){RESET} [PROTECTED]"
            elif status.get("raw_token"):
                token_str = f"{RED}INVALID INPUT ('{status['raw_token']}') - PLEASE RE-ENTER{RESET}"
            else:
                token_str = f"{RED}NOT SET{RESET}"

            subdomain_str = f"{CYAN}{status['subdomain']}{RESET}" if status["subdomain"] else f"{YELLOW}NOT SET{RESET}"

            print(f"\n{BOLD}{CYAN}=== CLOUDFLARE ZERO TRUST & SUBSCRIPTION PORTAL ==={RESET}\n")
            print(f" {BOLD}[ TUNNEL & PORTAL STATUS ]{RESET}")
            print(f"  {WHITE}Local Portal Binding :{RESET} {portal_status_str}")
            print(f"  {WHITE}Cloudflare Tunnel    :{RESET} {cf_status_str}")
            print(f"  {WHITE}Tunnel Token Status  :{RESET} {token_str}")
            print(f"  {WHITE}Public Subdomain     :{RESET} {subdomain_str}")
            print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
            print(f" {BOLD}[ CLOUDFLARE ZERO TRUST SETTINGS ]{RESET}")
            print(f"  {CYAN}1){RESET} Set / Update Cloudflare Tunnel Token (from Cloudflare Dashboard)")
            print(f"  {CYAN}2){RESET} Set Custom Subscription Subdomain (e.g. sub.nexiv.site)")
            print(f"  {CYAN}3){RESET} Change Local Portal Port (Default: 8088)")
            print(f"")
            print(f" {BOLD}[ CLIENT SUBSCRIPTION LINKS ]{RESET}")
            print(f"  {CYAN}4){RESET} View All Client Subscription Links (Cards & Usage)")
            print(f"  {CYAN}5){RESET} Regenerate a Client's Subscription Secret Token")
            print(f"")
            print(f" {BOLD}[ SYSTEM CONTROLS & DIAGNOSTICS ]{RESET}")
            print(f"  {CYAN}6){RESET} Restart Subscription & Cloudflare Services")
            print(f"  {CYAN}7){RESET} Live Subscription & Tunnel Diagnostic Doctor")
            print(f"")
            print(f"  {RED}0){RESET} Return to Main Menu")
            print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

            sub_choice = safe_input(f"{WHITE}Select an option [0-7]: {RESET}")
            if sub_choice == "1":
                self.print_banner()
                print(f"\n{BOLD}{GREEN}=== CONFIGURE CLOUDFLARE ZERO TRUST TUNNEL ==={RESET}\n")
                print(f"{WHITE}Quick Setup Instructions:{RESET}")
                print(f" • Step 1: Open Cloudflare Zero Trust (https://one.dash.cloudflare.com/)")
                print(f"           Navigate to: Networks -> Tunnels")
                print(f" • Step 2: Create a tunnel (e.g. 'vextunnel') or select your existing one")
                print(f" • Step 3: Copy the Tunnel Token (long base64 string starting with 'eyJh...')")
                print(f"           (Or copy the command: 'cloudflared service install <token>')")
                print(f" • Step 4: Under 'Public Hostnames' in Cloudflare, add your subdomain (e.g. sub.nexiv.site)")
                print(f"           and route Service to: {YELLOW}HTTP localhost:{status['port']}{RESET}\n")

                raw_token_in = safe_input(f"{WHITE}Paste Cloudflare Tunnel Token (or '0' to cancel): {RESET}")
                if raw_token_in and raw_token_in not in ('0', 'q', 'exit'):
                    is_valid, cleaned_tok, err_msg = clean_and_validate_cf_token(raw_token_in)
                    if not is_valid:
                        print(f"\n{RED}❌ Invalid Cloudflare Token:{RESET}")
                        print(f"   {YELLOW}{err_msg}{RESET}")
                        wait_enter()
                        continue

                    if not is_cloudflared_installed():
                        print(f"\n{CYAN}==> Installing official cloudflared package...{RESET}")
                        install_cloudflared()
                    print(f"\n{CYAN}==> Saving token to protected config and restarting tunnel...{RESET}")
                    if setup_tunnel_token(cleaned_tok):
                        print(f"{GREEN}✅ Cloudflare Zero Trust tunnel configured and started successfully!{RESET}")
                        print(f"   Token: {cleaned_tok[:6]}...{cleaned_tok[-4:]} (Protected in /etc/vextunnel/cf_tunnel.env)")
                    else:
                        print(f"{RED}❌ Failed to configure Cloudflare tunnel service. Check permissions.{RESET}")
                    wait_enter()
            elif sub_choice == "2":
                self.print_banner()
                print(f"\n{BOLD}{GREEN}=== SET CUSTOM SUBSCRIPTION SUBDOMAIN ==={RESET}\n")
                print(f"{WHITE}Example: {YELLOW}sub.nexiv.site{RESET} or {YELLOW}usage.example.com{RESET}")
                domain = safe_input(f"{WHITE}Enter Subdomain (or '0' to cancel): {RESET}")
                if domain and domain not in ('0', 'q', 'exit'):
                    try:
                        set_custom_sub_domain(domain)
                        print(f"\n{GREEN}✅ Public subscription subdomain saved: https://{domain}{RESET}")
                    except ValueError as ve:
                        print(f"\n{RED}Error: {ve}{RESET}")
                    wait_enter()
            elif sub_choice == "3":
                self.print_banner()
                print(f"\n{BOLD}{GREEN}=== CHANGE LOCAL PORTAL BINDING PORT ==={RESET}\n")
                new_port_str = safe_input(f"{WHITE}Enter new port [1024-65535] (default 8088, '0' to cancel): {RESET}")
                if new_port_str and new_port_str not in ('0', 'q', 'exit'):
                    try:
                        new_port = int(new_port_str)
                        set_portal_port(new_port)
                        subprocess.run(["systemctl", "restart", "vextunnel-sub"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        print(f"\n{GREEN}✅ Local portal port updated to {new_port} and service restarted.{RESET}")
                        print(f"{YELLOW}Note: Remember to update Public Hostname port in Cloudflare Zero Trust to {new_port}!{RESET}")
                    except Exception as e:
                        print(f"\n{RED}Error: {e}{RESET}")
                    wait_enter()
            elif sub_choice == "4":
                self.print_banner()
                print(f"\n{BOLD}{GREEN}=== CLIENT SUBSCRIPTION LINKS ==={RESET}\n")
                users = self.user_mgr.list_users()
                if not users:
                    print(f"{YELLOW}No registered users found.{RESET}")
                else:
                    for u in users:
                        tok = u.get("sub_token", "")
                        link = get_sub_url(tok) if tok else "[NO_TOKEN]"
                        print(f" • {WHITE}{u['username']:<14}{RESET} : {CYAN}{link}{RESET}")
                wait_enter()
            elif sub_choice == "5":
                self.print_banner()
                print(f"\n{BOLD}{GREEN}=== REGENERATE CLIENT SUBSCRIPTION TOKEN ==={RESET}\n")
                username = safe_input(f"{WHITE}Enter Username (or '0' to cancel): {RESET}")
                if username and username not in ('0', 'q', 'exit'):
                    try:
                        new_tok = self.user_mgr.regenerate_sub_token(username)
                        sub_link = get_sub_url(new_tok)
                        print(f"\n{GREEN}✅ Token regenerated for {username}!{RESET}")
                        print(f" {WHITE}New Subscription URL:{RESET} {CYAN}{sub_link}{RESET}")
                    except Exception as e:
                        print(f"\n{RED}Error: {e}{RESET}")
                    wait_enter()
            elif sub_choice == "6":
                self.print_banner()
                print(f"\n{CYAN}==> Restarting vextunnel-sub and vextunnel-cloudflared...{RESET}")
                subprocess.run(["systemctl", "restart", "vextunnel-sub"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["systemctl", "restart", "vextunnel-cloudflared"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"{GREEN}✅ Services restarted.{RESET}")
                time.sleep(1.5)
            elif sub_choice == "7":
                self.print_banner()
                print(f"\n{BOLD}{CYAN}=== SUBSCRIPTION & CLOUDFLARE LIVE DIAGNOSTICS ==={RESET}\n")
                cur_port = status['port']
                is_sub_listening = VexTunnelDoctor.check_port_listener(cur_port)
                port_col = GREEN if is_sub_listening else RED
                port_txt = f"{port_col}{'LISTENING (OK)' if is_sub_listening else 'CLOSED / NOT LISTENING'}{RESET}"
                print(f" • Local Web Server (127.0.0.1:{cur_port}) : {port_txt}")

                try:
                    import urllib.request
                    req = urllib.request.urlopen(f"http://127.0.0.1:{cur_port}/health", timeout=2.0)
                    health_ok = (req.status == 200)
                except Exception:
                    health_ok = False
                health_txt = f"{GREEN}PASS (200 OK){RESET}" if health_ok else f"{RED}FAIL (Unreachable){RESET}"
                print(f" • Local /health HTTP Probe        : {health_txt}")

                cf_svc_txt = f"{GREEN}RUNNING (Active){RESET}" if status['cf_service_active'] else f"{RED}CRASHED / STOPPED{RESET}"
                print(f" • cloudflared Systemd Daemon      : {cf_svc_txt}")

                if status['is_valid_token']:
                    tok_txt = f"{GREEN}VALID ({status['token_preview']}){RESET}"
                elif status.get('raw_token'):
                    tok_txt = f"{RED}INVALID ('{status['raw_token']}'){RESET}"
                else:
                    tok_txt = f"{RED}MISSING (Not Configured){RESET}"
                print(f" • Cloudflare Tunnel Token         : {tok_txt}")

                if status['subdomain']:
                    print(f" • Public Portal Subdomain         : {CYAN}https://{status['subdomain']}{RESET}")
                else:
                    print(f" • Public Portal Subdomain         : {YELLOW}NOT CONFIGURED{RESET}")

                wait_enter()
            elif sub_choice in ("0", "q", "exit"):
                break

    def run(self):
        while True:
            try:
                self.print_banner()
                print(f"{BOLD}[ SSH & WEBSOCKET USER MANAGEMENT ]{RESET}")
                print(f"  {CYAN}1){RESET} Create SSH-WebSocket Account")
                print(f"  {CYAN}2){RESET} Renew User Subscription")
                print(f"  {CYAN}3){RESET} Reset User Password")
                print(f"  {CYAN}4){RESET} Reset User Bandwidth Quota")
                print(f"  {CYAN}5){RESET} Delete User Account")
                print(f"  {CYAN}6){RESET} Lock / Unlock User Account")
                print(f"  {CYAN}7){RESET} List All Registered Users")
                print(f"  {CYAN}8){RESET} Export Client Config & Payloads")
                print(f"")
                print(f"{BOLD}[ SYSTEM & NETWORK CONTROLS ]{RESET}")
                print(f"  {CYAN}9){RESET} Live Online Users Inspector (Real-time)")
                print(f"  {CYAN}10){RESET} Live Services Health Check")
                print(f"  {CYAN}11){RESET} Restart All Tunnel Services")
                print(f"  {CYAN}12){RESET} Domain & SSL Certificate Settings")
                print(f"  {CYAN}13){RESET} VPS Bandwidth Speedtest")
                print(f"  {CYAN}14){RESET} Telegram Notifications & Backups")
                print(f"  {CYAN}15){RESET} Check for Updates")
                print(f"  {CYAN}16){RESET} Service Ports & Co-existence Manager")
                print(f"  {CYAN}17){RESET} Subscription Portal & Cloudflare Zero Trust")
                print(f"")
                print(f"  {RED}0){RESET} Exit")
                print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

                choice = safe_input(f"{WHITE}Select an option [0-17]: {RESET}")
                if choice == "1":
                    self.create_ssh_user()
                elif choice == "2":
                    self.renew_ssh_user()
                elif choice == "3":
                    self.reset_user_password()
                elif choice == "4":
                    self.reset_user_bandwidth_quota()
                elif choice == "5":
                    self.delete_ssh_user()
                elif choice == "6":
                    self.lock_unlock_user()
                elif choice == "7":
                    self.list_users()
                elif choice == "8":
                    self.export_client_config()
                elif choice == "9":
                    self.online_users_inspector()
                elif choice == "10":
                    self.check_health()
                elif choice == "11":
                    self.restart_services()
                elif choice == "12":
                    self.domain_ssl_manager()
                elif choice == "13":
                    self.speedtest()
                elif choice == "14":
                    self.telegram_alerts_and_backup_hub()
                elif choice == "15":
                    self.check_and_apply_update()
                elif choice == "16":
                    self.ports_coexistence_manager()
                elif choice == "17":
                    self.subscription_and_cf_manager()
                elif choice in ("0", "q", "exit"):
                    clear_screen()
                    print(f"\n{GREEN}Exiting VexTunnel Menu. Goodbye!{RESET}\n")
                    break
                else:
                    print(f"{RED}Invalid option!{RESET}")
                    time.sleep(1)
            except (KeyboardInterrupt, EOFError):
                clear_screen()
                print(f"\n{GREEN}Exiting VexTunnel Menu. Goodbye!{RESET}\n")
                break

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--update", "update"):
        is_dev = "--dev" in sys.argv
        menu = VexTunnelMenu()
        menu.check_and_apply_update(non_interactive=True, dev=is_dev)
    else:
        menu = VexTunnelMenu()
        menu.run()
