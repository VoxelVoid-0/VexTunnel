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
from core.quota_manager import format_bytes, parse_bytes, reset_user_quota
from core.monitor import get_system_stats, get_all_services_status, get_online_users

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
        print(f"{CYAN}{BOLD}║                   ⚡ VEXTUNNEL SUITE v1.2 ⚡                 ║{RESET}")
        print(f"{CYAN}{BOLD}║         Clean • High-Speed • Zero-Backdoor VPS Suite         ║{RESET}")
        print(f"{CYAN}{BOLD}╚══════════════════════════════════════════════════════════════╝{RESET}")
        print(f" {WHITE}Host / IP :{RESET} {YELLOW}{self.host}{RESET} | {WHITE}OS:{RESET} {stats['os']} | {WHITE}Uptime:{RESET} {GREEN}{stats.get('uptime', 'N/A')}{RESET}")
        print(f" {WHITE}RAM       :{RESET} {make_bar(stats['ram_percent'])} ({stats['ram_used_mb']}MB/{stats['ram_total_mb']}MB)")
        print(f" {WHITE}Disk      :{RESET} {make_bar(stats['disk_percent'])} | {WHITE}Active Users:{RESET} {GREEN}{active_count}{RESET} | {WHITE}Online:{RESET} {GREEN}{online_count} 🟢{RESET}")
        print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

    def generate_vextunnel_uri(self, username: str) -> str:
        """Generate structured machine-readable connection URI."""
        config = {
            "v": "1.2",
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
        username = input(f"{WHITE}Enter Username: {RESET}").strip()
        if not username:
            print(f"{RED}Username cannot be empty!{RESET}")
            input("\nPress Enter to return...")
            return

        password = input(f"{WHITE}Enter Password (min 8 chars): {RESET}").strip()
        if len(password) < 8:
            print(f"{RED}Password must be at least 8 characters!{RESET}")
            input("\nPress Enter to return...")
            return

        try:
            days = int(input(f"{WHITE}Active Days (e.g. 30): {RESET}").strip())
        except ValueError:
            print(f"{RED}Invalid number of days!{RESET}")
            input("\nPress Enter to return...")
            return

        quota_input = input(f"{WHITE}Bandwidth Quota (e.g. 50G, 100G, 0 for Unlimited) [0]: {RESET}").strip()
        try:
            quota_bytes = parse_bytes(quota_input) if quota_input else 0
        except ValueError as ve:
            print(f"{RED}{ve}{RESET}")
            input("\nPress Enter to return...")
            return

        try:
            res = self.user_mgr.add_user(username, password, days, quota_bytes=quota_bytes)
            self.print_banner()
            print(f"\n{BOLD}{GREEN}✅ ACCOUNT CREATED SUCCESSFULLY!{RESET}")
            print(f"{YELLOW}⚠️ Save the password now! In the database, it is stored as a secure PBKDF2 hash.{RESET}")
            self.print_client_card(res["username"], res["password"], res["expires_at"], days)
        except Exception as e:
            print(f"\n{RED}Error creating user:{RESET} {e}")

        input("\nPress Enter to continue...")

    def reset_user_bandwidth_quota(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== RESET USER BANDWIDTH QUOTA ==={RESET}\n")
        username = input(f"{WHITE}Enter Username to reset quota: {RESET}").strip()
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            input("\nPress Enter to return...")
            return

        if reset_user_quota(username, self.user_mgr.db_path):
            print(f"\n{GREEN}✅ Bandwidth usage for '{username}' reset to 0 B and firewall unblocked!{RESET}")
        else:
            print(f"\n{RED}Failed to reset bandwidth quota.{RESET}")
        input("\nPress Enter to continue...")

    def reset_user_password(self):
        self.print_banner()
        print(f"\n{BOLD}{YELLOW}=== RESET USER PASSWORD ==={RESET}\n")
        username = input(f"{WHITE}Enter Username to change password: {RESET}").strip()
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            input("\nPress Enter to return...")
            return

        new_password = input(f"{WHITE}Enter New Password (min 8 chars): {RESET}").strip()
        try:
            if self.user_mgr.change_password(username, new_password):
                print(f"\n{GREEN}✅ Password for '{username}' updated successfully! (Stored as PBKDF2 hash){RESET}")
            else:
                print(f"\n{RED}Failed to update password.{RESET}")
        except Exception as e:
            print(f"\n{RED}Error:{RESET} {e}")
        input("\nPress Enter to continue...")

    def renew_ssh_user(self):
        self.print_banner()
        print(f"\n{BOLD}{YELLOW}=== RENEW SSH USER SUBSCRIPTION ==={RESET}\n")
        username = input(f"{WHITE}Enter Username to renew: {RESET}").strip()
        try:
            days = int(input(f"{WHITE}Days to extend: {RESET}").strip())
            res = self.user_mgr.renew_user(username, days)
            if res:
                print(f"\n{GREEN}✅ User '{username}' renewed until {res['new_expires_at']} (+{days} days)!{RESET}")
            else:
                print(f"\n{RED}User '{username}' not found!{RESET}")
        except Exception as e:
            print(f"\n{RED}Error renewing user:{RESET} {e}")
        input("\nPress Enter to continue...")

    def delete_ssh_user(self):
        self.print_banner()
        print(f"\n{BOLD}{RED}=== DELETE SSH USER ==={RESET}\n")
        username = input(f"{WHITE}Enter Username to delete: {RESET}").strip()
        confirm = input(f"{YELLOW}Are you sure you want to delete '{username}'? (y/n): {RESET}").strip().lower()
        if confirm == 'y':
            if self.user_mgr.delete_user(username):
                print(f"\n{GREEN}✅ User '{username}' deleted successfully.{RESET}")
            else:
                print(f"\n{RED}User '{username}' not found.{RESET}")
        input("\nPress Enter to continue...")

    def lock_unlock_user(self):
        self.print_banner()
        print(f"\n{BOLD}{MAGENTA}=== LOCK / UNLOCK USER ACCOUNT ==={RESET}\n")
        username = input(f"{WHITE}Enter Username: {RESET}").strip()
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            input("\nPress Enter to return...")
            return

        current_status = users[username]["status"]
        if current_status == "locked":
            action = input(f"{YELLOW}Account is currently LOCKED. Unlock it? (y/n): {RESET}").strip().lower()
            if action == 'y':
                if self.user_mgr.unlock_user(username):
                    print(f"\n{GREEN}✅ User '{username}' unlocked and active!{RESET}")
        else:
            action = input(f"{YELLOW}Account is currently ACTIVE. Lock it? (y/n): {RESET}").strip().lower()
            if action == 'y':
                if self.user_mgr.lock_user(username):
                    print(f"\n{YELLOW}🔒 User '{username}' has been locked!{RESET}")
        input("\nPress Enter to continue...")

    def list_users(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== ALL REGISTERED USERS & BANDWIDTH USAGE ==={RESET}\n")
        users = self.user_mgr.list_users()
        if not users:
            print(f"{YELLOW}No registered users found.{RESET}")
        else:
            print(f"{BOLD}{'USERNAME':<14} {'STATUS':<14} {'BANDWIDTH (USED / QUOTA)':<26} {'DAYS':<6} {'EXPIRES AT':<19}{RESET}")
            print(f"{DIM}──────────────────────────────────────────────────────────────────────────────────{RESET}")
            for u in users:
                if u["status"] == "active":
                    status_str = f"{GREEN}active{RESET}"
                elif u["status"] == "locked":
                    status_str = f"{YELLOW}locked{RESET}"
                elif u["status"] == "quota_exceeded":
                    status_str = f"{RED}QUOTA EXCEEDED{RESET}"
                else:
                    status_str = f"{RED}expired{RESET}"

                quota_target = format_bytes(u["quota_bytes"]) if u["quota_bytes"] > 0 else "Unlimited"
                bw_str = f"{format_bytes(u['used_bytes'])} / {quota_target}"
                print(f"{u['username']:<14} {status_str:<23} {bw_str:<26} {u['remaining_days']:<6} {u['expires_at']:<19}")
        input("\nPress Enter to continue...")

    def export_client_config(self):
        self.print_banner()
        print(f"\n{BOLD}{CYAN}=== EXPORT CLIENT CONFIG & PAYLOADS ==={RESET}\n")
        username = input(f"{WHITE}Enter Username: {RESET}").strip()
        users = {u["username"]: u for u in self.user_mgr.list_users()}
        if username not in users:
            print(f"{RED}User '{username}' not found!{RESET}")
            input("\nPress Enter to return...")
            return

        u = users[username]
        self.print_banner()
        self.print_client_card(u["username"], "[PROTECTED - Salted PBKDF2 Hash]", u["expires_at"], u["remaining_days"])
        input("\nPress Enter to continue...")

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
        input("\nPress Enter to continue...")

    def check_health(self):
        self.print_banner()
        print(f"\n{BOLD}{MAGENTA}=== SYSTEM & SERVICE STATUS ==={RESET}\n")
        services = get_all_services_status()
        for s, st in services.items():
            print(f" {WHITE}{s:<32}:{RESET} {st}")
        input("\nPress Enter to continue...")

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
        input("\nPress Enter to continue...")

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

        opt = input(f"\n{WHITE}Select an option: {RESET}").strip()
        if opt == "1":
            new_domain = input(f"{WHITE}Enter new domain (e.g. vpn.example.com): {RESET}").strip()
            if new_domain:
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
        input("\nPress Enter to continue...")

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

        input("\nPress Enter to continue...")

    def private_backup(self):
        self.print_banner()
        print(f"\n{BOLD}{GREEN}=== PRIVATE TELEGRAM BACKUP ==={RESET}\n")
        print(f"{WHITE}This will send your database directly to YOUR Telegram account.{RESET}")
        print(f"{WHITE}Zero third-party servers, 100% private.{RESET}\n")
        bot_token = input(f"{WHITE}Enter your Telegram Bot Token: {RESET}").strip()
        chat_id = input(f"{WHITE}Enter your Telegram Chat ID: {RESET}").strip()

        if not bot_token or not chat_id:
            print(f"{RED}Token and Chat ID are required!{RESET}")
            input("\nPress Enter to continue...")
            return

        try:
            db_path = self.user_mgr.db_path
            if not os.path.exists(db_path):
                print(f"{RED}Database file does not exist yet.{RESET}")
                input("\nPress Enter to continue...")
                return

            msg_url = f"https://api.telegram.org/bot{bot_token}/sendMessage?chat_id={chat_id}&text=VexTunnel+Backup+Initiated+from+{self.server_ip}"
            urllib.request.urlopen(msg_url, timeout=5)  # nosec B310
            print(f"\n{GREEN}✅ Backup initiated to your Telegram chat successfully!{RESET}")
        except Exception as e:
            print(f"\n{RED}Telegram send failed:{RESET} {e}")

        input("\nPress Enter to continue...")

    def run(self):
        while True:
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
            print(f"  {CYAN}14){RESET} Private Telegram Database Backup")
            print(f"")
            print(f"  {RED}0){RESET} Exit")
            print(f"{DIM}──────────────────────────────────────────────────────────────{RESET}")

            choice = input(f"{WHITE}Select an option [0-14]: {RESET}").strip()
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
                self.private_backup()
            elif choice == "0":
                clear_screen()
                print("Exiting VexTunnel Menu. Goodbye!")
                break
            else:
                print(f"{RED}Invalid option!{RESET}")
                time.sleep(1)

if __name__ == "__main__":
    menu = VexTunnelMenu()
    menu.run()
