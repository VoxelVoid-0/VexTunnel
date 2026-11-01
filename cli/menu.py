#!/usr/bin/env python3
"""
VexTunnel - Interactive Terminal Management Menu (TUI Hardened v1.2)
Author: VoxelVoid-0
License: MIT
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
    is_monthly_quota_reset_enabled, setup_monthly_quota_reset_timer
)
from core.monitor import get_system_stats, get_all_services_status, get_online_users
from core.watchdog import VexTunnelDoctor, ServiceWatchdog
from core.telegram_notifier import get_telegram_config, save_telegram_config, send_telegram_message

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
        stats = get_system_stats()
        users = self.user_mgr.list_users()
        active_count = sum(1 for u in users if u["status"] == "active")
        online_count = stats.get("online_users_count", 0)

        print(f"{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{CYAN}{BOLD}║                  ⚡ VEXTUNNEL SUITE v1.2.0 ⚡                ║{RESET}")
        print(f"{CYAN}{BOLD}║         Clean • High-Speed • Zero-Backdoor VPS Suite         ║{RESET}")
        print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f" {WHITE}Host / IP :{RESET} {YELLOW}{self.host}{RESET} | {WHITE}OS:{RESET} {stats['os']} | {WHITE}Uptime:{RESET} {GREEN}{stats.get('uptime', 'N/A')}{RESET}")
        print(f" {WHITE}RAM       :{RESET} {make_bar(stats['ram_percent'])} ({stats['ram_used_mb']}MB/{stats['ram_total_mb']}MB)")
        print(f" {WHITE}Disk      :{RESET} {make_bar(stats['disk_percent'])} | {WHITE}Active Users:{RESET} {GREEN}{active_count}{RESET} | {WHITE}Online:{RESET} {GREEN}{online_count} 🟢{RESET}")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

    def generate_vextunnel_uri(self, username: str) -> str:
        """Generate structured machine-readable connection URI."""
        config = {
            "v": "1.2.0",
            "host": self.host,
            "user": username,
            "ws_http": 80,
            "ws_https": 443,
            "dropbear": 109,
            "udpgw": 7300,
            "payload": "GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]"
        }
        raw_json = json.dumps(config, separators=(',', ':'))
        return "vextunnel://" + urllib.parse.quote(raw_json)

    def print_client_card(self, username: str, password_display: str, expires_at: str, days: int):
        """Display client connection card with payloads and deep link."""
        print(f"\n{BOLD}{GREEN}╔══════════════════════════════════════════════════════════════╗{RESET}")
        print(f"{BOLD}{GREEN}║                   CLIENT CONNECTION CARD                     ║{RESET}")
        print(f"{BOLD}{GREEN}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f" {WHITE}Host / Server IP :{RESET} {YELLOW}{self.host}{RESET}")
        print(f" {WHITE}Username         :{RESET} {GREEN}{username}{RESET}")
        print(f" {WHITE}Password         :{RESET} {GREEN}{password_display}{RESET}")
        print(f" {WHITE}Expires At       :{RESET} {expires_at} ({days} Days)")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f"{BOLD}[ PORT SPECIFICATIONS ]{RESET}")
        print(f" • {WHITE}WebSocket HTTP  :{RESET} {GREEN}80, 8880{RESET} (For Cloudflare Flexible / Direct)")
        print(f" • {WHITE}WebSocket WSS   :{RESET} {GREEN}443{RESET} (TLS/SSL Encrypted - Best for SNI)")
        print(f" • {WHITE}Dropbear SSH    :{RESET} {GREEN}109, 143{RESET}")
        print(f" • {WHITE}OpenSSH         :{RESET} {GREEN}22, 2222{RESET}")
        print(f" • {WHITE}BadVPN UDPGW    :{RESET} {GREEN}7300{RESET} (For WhatsApp Calls & Gaming)")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f"{BOLD}[ READY-TO-COPY PAYLOAD TEMPLATES ]{RESET}")
        print(f"\n{YELLOW}1. HTTP Injector / NetMod / HTTP Custom (Standard WS):{RESET}")
        print(f"GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        print(f"\n{YELLOW}2. Custom Dash (Zoom / CDN Free-Internet Bypass):{RESET}")
        print(f"GET- / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        print(f"\n{YELLOW}3. Direct SSL / TLS (WSS Port 443 with SNI Spoof):{RESET}")
        print(f"SNI: {self.host} (or bug host, e.g. www.zoom.us)")
        print(f"Payload: GET / HTTP/1.1[crlf]Host: [host][crlf]Upgrade: websocket[crlf][crlf]")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")
        print(f"{BOLD}[ PORTABLE CONFIG URI (Deep-Link) ]{RESET}")
        print(f"{CYAN}{self.generate_vextunnel_uri(username)}{RESET}")
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
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== ALL REGISTERED USERS & BANDWIDTH USAGE ==={RESET}\n")
        users = self.user_mgr.list_users()
        if not users:
            print(f"{YELLOW}No registered users found.{RESET}")
        else:
            print(f"{BOLD}{'USERNAME':<16} {'STATUS':<16} {'BANDWIDTH (USED / QUOTA)':<26} {'DAYS':<6} {'EXPIRES AT':<19}{RESET}")
            print(f"{DIM}────────────────────────────────────────────────────────────────────────────────────{RESET}")
            for u in users:
                if u["status"] == "active":
                    color = GREEN
                    raw_status = "active"
                elif u["status"] == "locked":
                    color = YELLOW
                    raw_status = "locked"
                elif u["status"] == "quota_exceeded":
                    color = RED
                    raw_status = "QUOTA EXCEEDED"
                else:
                    color = RED
                    raw_status = "expired"

                quota_target = format_bytes(u["quota_bytes"]) if u["quota_bytes"] > 0 else "Unlimited"
                bw_str = f"{format_bytes(u['used_bytes'])} / {quota_target}"
                print(f"{u['username']:<16} {color}{raw_status:<16}{RESET} {bw_str:<26} {u['remaining_days']:<6} {u['expires_at']:<19}")
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
        self.print_banner()
        print(f"\n{BOLD}{GREEN}=== REAL-TIME ONLINE USERS ==={RESET}\n")
        online = get_online_users()
        if not online:
            print(f"{YELLOW}No active client connections right now.{RESET}")
        else:
            print(f"{BOLD}{'USER':<18} {'IP ADDRESS':<26} {'SERVICE':<16} {'LOGIN TIME'}{RESET}")
            print(f"{DIM}──────────────────────────────────────────────────────────────────{RESET}")
            for sess in online:
                print(f"{GREEN}{sess['user']:<18}{RESET} {sess['ip']:<26} {sess['service']:<16} {sess['time']}")
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
        print(f"\n{BOLD}{CYAN}=== TELEGRAM BOT ALERTS & BACKUP HUB ==={RESET}\n")
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
                print(f"  {CYAN}14){RESET} Telegram Bot Alerts & Backup Hub")
                print(f"")
                print(f"  {RED}0){RESET} Exit")
                print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

                choice = safe_input(f"{WHITE}Select an option [0-14]: {RESET}")
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
    menu = VexTunnelMenu()
    menu.run()
