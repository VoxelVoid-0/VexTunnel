#!/usr/bin/env python3
"""
VexTunnel - Cloudflare Zero Trust Tunnel Manager (Hardened v1.3.11)
Author: VoxelVoid-0
License: GPL-3.0

Features:
- Official cloudflared package installation & updates (APT keyring & binary fallback)
- Tunnel token storage in chmod 600 environment file (/etc/vextunnel/cf_tunnel.env)
- Hides token from 'ps aux' via systemd EnvironmentFile
- Zero inbound open ports: Traffic routes via Cloudflare Edge to 127.0.0.1:8088
- Manages custom public subdomain for client subscription URLs
"""

import os
import sys
import shutil
import subprocess
import re
from typing import Dict, Optional

CF_ENV_PATH = "/etc/vextunnel/cf_tunnel.env" if os.name != 'nt' else "cf_tunnel.env"
CF_SERVICE_NAME = "vextunnel-cloudflared"
DEFAULT_SUB_PORT = 8088

def load_cf_config() -> Dict[str, str]:
    """Load Cloudflare tunnel environment configuration."""
    config = {
        "TUNNEL_TOKEN": "",
        "SUB_DOMAIN": "",
        "SUB_PORT": str(DEFAULT_SUB_PORT)
    }
    if os.path.exists(CF_ENV_PATH):
        try:
            with open(CF_ENV_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        config[k.strip()] = v.strip()
        except Exception:
            pass
    return config

def save_cf_config(config: Dict[str, str]) -> bool:
    """Save Cloudflare tunnel configuration with strict 0600 permissions."""
    cf_dir = os.path.dirname(CF_ENV_PATH)
    if cf_dir and not os.path.exists(cf_dir):
        os.makedirs(cf_dir, exist_ok=True)
        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            os.chmod(cf_dir, 0o700)

    lines = [
        "# VexTunnel Cloudflare Zero Trust Tunnel Configuration",
        "# Authoritative & Protected. Do not share this token.",
        f"TUNNEL_TOKEN={config.get('TUNNEL_TOKEN', '').strip()}",
        f"SUB_DOMAIN={config.get('SUB_DOMAIN', '').strip()}",
        f"SUB_PORT={config.get('SUB_PORT', str(DEFAULT_SUB_PORT)).strip()}",
    ]
    try:
        with open(CF_ENV_PATH, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
            os.chmod(CF_ENV_PATH, 0o600)
        return True
    except Exception:
        return False

def is_cloudflared_installed() -> bool:
    """Check if cloudflared binary is installed and executable."""
    if shutil.which("cloudflared"):
        return True
    for path in ("/usr/bin/cloudflared", "/usr/local/bin/cloudflared"):
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return True
    return False

def install_cloudflared() -> bool:
    """Install official cloudflared package via APT keyring or standalone binary fallback."""
    if is_cloudflared_installed():
        return True

    if os.name == 'nt' or not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return False

    # Attempt 1: Official Cloudflare APT repository
    try:
        subprocess.run(["mkdir", "-p", "--mode=0755", "/usr/share/keyrings"], check=True)
        gpg_cmd = "curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null"
        subprocess.run(gpg_cmd, shell=True, check=True)
        repo_cmd = "echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main' | tee /etc/apt/sources.list.d/cloudflared.list"
        subprocess.run(repo_cmd, shell=True, check=True)
        subprocess.run(["apt-get", "update", "-qq"], check=True)
        res = subprocess.run(["apt-get", "install", "-y", "-qq", "cloudflared"], capture_output=True, text=True)
        if res.returncode == 0 and is_cloudflared_installed():
            return True
    except Exception:
        pass

    # Attempt 2: Direct official binary download fallback
    try:
        import platform
        arch = platform.machine().lower()
        cf_arch = "arm64" if ("aarch64" in arch or "arm64" in arch) else "amd64"
        download_url = f"https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-{cf_arch}"
        dest_bin = "/usr/local/bin/cloudflared"
        curl_cmd = ["curl", "-fsSL", download_url, "-o", dest_bin]
        res = subprocess.run(curl_cmd, capture_output=True, text=True)
        if res.returncode == 0 and os.path.exists(dest_bin):
            os.chmod(dest_bin, 0o755)
            # Create symlink in /usr/bin if needed
            if not os.path.exists("/usr/bin/cloudflared"):
                try:
                    os.symlink(dest_bin, "/usr/bin/cloudflared")
                except OSError:
                    pass
            return True
    except Exception:
        pass

    return False

def setup_tunnel_token(token: str) -> bool:
    """Store Cloudflare Zero Trust tunnel token and restart tunnel service."""
    token = token.strip()
    if not token:
        return False

    config = load_cf_config()
    config["TUNNEL_TOKEN"] = token
    if not save_cf_config(config):
        return False

    # Ensure cloudflared is installed
    if not is_cloudflared_installed():
        install_cloudflared()

    # Restart systemd service if running on Linux as root
    if os.name != 'nt' and hasattr(os, 'geteuid') and os.geteuid() == 0:
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["systemctl", "enable", CF_SERVICE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        res = subprocess.run(["systemctl", "restart", CF_SERVICE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    return True

def set_custom_sub_domain(domain: str) -> bool:
    """Save custom public subscription subdomain (e.g. usage.example.com)."""
    domain = domain.strip().lower()
    # Basic domain sanitization (stripping https:// or trailing slashes)
    domain = re.sub(r"^https?://", "", domain).rstrip("/")
    if not domain or not re.fullmatch(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$", domain):
        raise ValueError("Invalid domain format. Example: usage.example.com or sub.domain.com")

    config = load_cf_config()
    config["SUB_DOMAIN"] = domain
    return save_cf_config(config)

def get_custom_sub_domain() -> str:
    """Get the currently configured public subscription subdomain."""
    config = load_cf_config()
    return config.get("SUB_DOMAIN", "")

def set_portal_port(port: int) -> bool:
    """Update localhost binding port for vextunnel-sub."""
    if not (1024 <= port <= 65535):
        raise ValueError("Port must be between 1024 and 65535.")
    config = load_cf_config()
    config["SUB_PORT"] = str(port)
    return save_cf_config(config)

def get_portal_port() -> int:
    """Get the configured localhost binding port for vextunnel-sub."""
    config = load_cf_config()
    try:
        return int(config.get("SUB_PORT", DEFAULT_SUB_PORT))
    except ValueError:
        return DEFAULT_SUB_PORT

def get_sub_url(token: str) -> str:
    """Build full HTTPS subscription link for client using configured Cloudflare subdomain."""
    subdomain = get_custom_sub_domain()
    if subdomain:
        return f"https://{subdomain}/sub/{token}"
    return f"[CONFIGURE_SUBDOMAIN_IN_MENU_17]/sub/{token}"

def get_tunnel_status() -> Dict:
    """Return dictionary with comprehensive tunnel and portal runtime status."""
    config = load_cf_config()
    installed = is_cloudflared_installed()
    has_token = bool(config.get("TUNNEL_TOKEN", ""))
    subdomain = config.get("SUB_DOMAIN", "")
    port = get_portal_port()

    cf_service_active = False
    sub_service_active = False

    if os.name != 'nt':
        res_cf = subprocess.run(["systemctl", "is-active", "--quiet", CF_SERVICE_NAME], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cf_service_active = (res_cf.returncode == 0)
        res_sub = subprocess.run(["systemctl", "is-active", "--quiet", "vextunnel-sub"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sub_service_active = (res_sub.returncode == 0)

    return {
        "installed": installed,
        "has_token": has_token,
        "subdomain": subdomain,
        "port": port,
        "cf_service_active": cf_service_active,
        "sub_service_active": sub_service_active
    }
