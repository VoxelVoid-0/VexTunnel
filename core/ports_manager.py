#!/usr/bin/env python3
"""
VexTunnel - Dynamic Port & Co-existence Manager
Handles non-destructive port reconfiguration, service binding,
dual-stack IPv4/IPv6 conflict detection, and surgical firewall lifecycle.

Author: VoxelVoid-0
License: GNU General Public License v3.0 (GPL-3.0)
"""

import os
import sys
import re
import socket
import subprocess
import shutil
import logging
from typing import Dict, Any, Tuple, Optional, List

logger = logging.getLogger("PortsManager")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

DEFAULT_PORTS_FILE = "/etc/vextunnel/ports.env"

DEFAULT_CONFIG: Dict[str, Any] = {
    "WS_PORT": 80,
    "WSS_PORT": 443,
    "WS_ALT_PORT": 8880,
    "DROPBEAR_PORT": 109,
    "DROPBEAR_ALT_PORT": 143,
    "BADVPN_PORT": 7300,
    "UDPGW_PORT": 7300,
    "OPENSSH_PORT": 22,
    "OPENSSH_ALT_PORT": 2222,
    "WSS_ENABLED": True
}
DEFAULT_PORTS = DEFAULT_CONFIG

SERVICE_MAP: Dict[str, str] = {
    "WS_PORT": "vextunnel-ws",
    "WSS_PORT": "vextunnel-wss",
    "WS_ALT_PORT": "vextunnel-ws-8880",
    "DROPBEAR_PORT": "dropbear",
    "BADVPN_PORT": "badvpn-7300",
    "UDPGW_PORT": "badvpn-7300"
}


def load_ports(path: str = DEFAULT_PORTS_FILE) -> Dict[str, Any]:
    """
    Parse ports.env key-value pairs with fallback defaults.
    Ensures integer conversion and boolean flag normalization.
    """
    config = dict(DEFAULT_CONFIG)
    if not os.path.exists(path):
        return config

    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")

                if k in ("WS_PORT", "WSS_PORT", "WS_ALT_PORT", "DROPBEAR_PORT", "DROPBEAR_ALT_PORT", "BADVPN_PORT", "UDPGW_PORT", "OPENSSH_PORT", "OPENSSH_ALT_PORT"):
                    try:
                        val = int(v)
                        config[k] = val
                        if k == "BADVPN_PORT":
                            config["UDPGW_PORT"] = val
                        elif k == "UDPGW_PORT":
                            config["BADVPN_PORT"] = val
                    except ValueError:
                        pass
                elif k == "WSS_ENABLED":
                    config[k] = v.lower() in ("true", "1", "yes", "on")
    except Exception as e:
        logger.warning(f"Error reading {path}: {e}")

    return config


def save_ports(ports: Dict[str, Any], path: str = DEFAULT_PORTS_FILE) -> bool:
    """
    Atomically write port configurations to ports.env preserving Unix permissions.
    """
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp_path = f"{path}.tmp.{os.getpid()}"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write("# VexTunnel Service Port Configurations\n")
            f.write("# Dynamically managed by VexTunnel Ports Manager\n\n")
            f.write(f"WS_PORT={int(ports.get('WS_PORT', 80))}\n")
            f.write(f"WSS_PORT={int(ports.get('WSS_PORT', 443))}\n")
            f.write(f"WS_ALT_PORT={int(ports.get('WS_ALT_PORT', 8880))}\n")
            f.write(f"DROPBEAR_PORT={int(ports.get('DROPBEAR_PORT', 109))}\n")
            f.write(f"BADVPN_PORT={int(ports.get('BADVPN_PORT', 7300))}\n")
            wss_en = "true" if ports.get("WSS_ENABLED", True) else "false"
            f.write(f"WSS_ENABLED={wss_en}\n")

        os.replace(tmp_path, path)
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass
        return True
    except Exception as e:
        logger.error(f"Failed to write ports config to {path}: {e}")
        return False


def check_port_in_use(port: int) -> Tuple[bool, Optional[str]]:
    """
    Detect if a port is actively bound across dual-stack IPv4 and IPv6.
    Returns (is_in_use, process_name_or_none).
    """
    # 1. Quick local socket test binding (IPv4 and IPv6)
    in_use = False
    for family, host in [(socket.AF_INET, "0.0.0.0"), (socket.AF_INET6, "::")]:
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((host, port))
            s.close()
        except OSError:
            in_use = True
            break
        except Exception:
            pass

    # 2. Process inspection via ss -tulpn or lsof
    proc_name = None
    if in_use and os.name != 'nt':
        try:
            # Match :<port>\s or ]:<port>\s to capture IPv4 (0.0.0.0:443) and IPv6 ([::]:443 / :::443)
            res = subprocess.run(["ss", "-tulpn"], capture_output=True, text=True, timeout=3)
            pattern = re.compile(rf'[:\]]{port}\s')
            for line in res.stdout.splitlines():
                if pattern.search(line) and "LISTEN" in line:
                    match_user = re.search(r'users:\(\("([^"]+)"', line)
                    if match_user:
                        proc_name = match_user.group(1)
                        break
        except Exception:
            pass

        if not proc_name:
            try:
                res_lsof = subprocess.run(["lsof", "-i", f":{port}", "-sTCP:LISTEN"], capture_output=True, text=True, timeout=3)
                lines = res_lsof.stdout.strip().splitlines()
                if len(lines) > 1:
                    parts = lines[1].split()
                    if parts:
                        proc_name = parts[0]
            except Exception:
                pass

    return in_use, proc_name


def is_ufw_active() -> bool:
    """Return True if UFW is installed and in an 'active' state."""
    if shutil.which("ufw") is None:
        return False
    try:
        res = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=3)
        return res.returncode == 0 and "Status: active" in res.stdout
    except Exception:
        return False


def update_firewall_rules(old_port: Optional[int] = None, new_port: Optional[int] = None, proto: str = "tcp", **kwargs) -> bool:
    """
    Surgically update firewall rules for newly assigned ports.
    - If UFW is active: Allows new port. Deletes old port IF not actively used by another daemon.
    - If raw IPTables: Surgically inserts rule at top of INPUT. Deletes old port rule.
    - CRITICAL: Never issues blanket flushes ('iptables -F') to protect Oracle Cloud iSCSI and cloud metadata.
    """
    proto = kwargs.get("protocol", proto)
    if new_port is None:
        new_port = kwargs.get("new_port")
    if old_port is None and "old_port" in kwargs:
        old_port = kwargs.get("old_port")

    # In development / non-root environment, allow test mock execution or return True
    is_root = hasattr(os, 'geteuid') and os.geteuid() == 0
    is_test_env = "unittest" in sys.modules or os.environ.get("VEXTUNNEL_TEST") == "1"
    if not is_root and not is_test_env:
        return True

    success = True

    # Check if old port is still actively in use by a co-existing daemon (e.g. 3x-ui on 443)
    old_port_still_needed = False
    if old_port and old_port != new_port:
        in_use, proc = check_port_in_use(old_port)
        if in_use and proc and "vextunnel" not in proc.lower():
            old_port_still_needed = True
            logger.info(f"Firewall: Preserving port {old_port} for active co-existing daemon '{proc}'.")

    # 1. UFW Management Path
    if is_ufw_active():
        try:
            # Allow new port
            if new_port:
                subprocess.run(["ufw", "allow", f"{new_port}/{proto}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                logger.info(f"Firewall (UFW): Allowed {new_port}/{proto}")

            # Delete old port if not needed by another service
            if old_port and old_port != new_port and not old_port_still_needed:
                subprocess.run(["ufw", "delete", "allow", f"{old_port}/{proto}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(["ufw", "delete", "allow", str(old_port)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"Firewall (UFW): Cleaned up inactive port {old_port}/{proto}")
        except Exception as e:
            logger.warning(f"Error updating UFW rules: {e}")
            success = False

    # 2. Raw IPTables Surgical Management Path
    # Ensures accessibility regardless of whether UFW front-end is installed/active
    try:
        if new_port:
            # Check if new port already has an ACCEPT rule in INPUT
            check_new = subprocess.run(["iptables", "-C", "INPUT", "-p", proto, "--dport", str(new_port), "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if check_new.returncode != 0:
                subprocess.run(["iptables", "-I", "INPUT", "1", "-p", proto, "--dport", str(new_port), "-j", "ACCEPT"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info(f"Firewall (iptables): Surgically injected ACCEPT rule for {new_port}/{proto}")

        # Delete old port rule if inactive and not needed by other daemons
        if old_port and old_port != new_port and not old_port_still_needed:
            subprocess.run(["iptables", "-D", "INPUT", "-p", proto, "--dport", str(old_port), "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info(f"Firewall (iptables): Surgically removed rule for {old_port}/{proto}")

        # Synchronize ip6tables if binary exists and IPv6 is active
        try:
            if shutil.which("ip6tables"):
                if new_port:
                    check_ip6 = subprocess.run(["ip6tables", "-C", "INPUT", "-p", proto, "--dport", str(new_port), "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    if check_ip6.returncode != 0:
                        subprocess.run(["ip6tables", "-I", "INPUT", "1", "-p", proto, "--dport", str(new_port), "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if old_port and old_port != new_port and not old_port_still_needed:
                    subprocess.run(["ip6tables", "-D", "INPUT", "-p", proto, "--dport", str(old_port), "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
    except Exception as e:
        logger.warning(f"Error updating iptables rules: {e}")
        success = False

    return success


def restart_service_safely(service_name: str) -> bool:
    """Safely reload and restart systemd service unit."""
    if os.name == 'nt':
        return True
    try:
        subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        res = subprocess.run(["systemctl", "restart", service_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        return res.returncode == 0
    except Exception as e:
        logger.error(f"Failed to restart service {service_name}: {e}")
        return False


def set_port(service_key: str, new_port: int, ports_file: str = DEFAULT_PORTS_FILE, **kwargs) -> Tuple[bool, str]:
    """
    Validate, configure, and rebind a VexTunnel service port.
    Returns (success: bool, message: str).
    """
    ports_file = kwargs.get("env_file", ports_file)
    if not (1 <= new_port <= 65535):
        return False, f"Invalid port number: {new_port}. Must be between 1 and 65535."

    if service_key == "UDPGW_PORT":
        service_key = "BADVPN_PORT"

    if service_key not in DEFAULT_CONFIG or service_key == "WSS_ENABLED":
        return False, f"Unknown service key: {service_key}"

    current_ports = load_ports(ports_file)
    old_port = current_ports.get(service_key)

    if old_port == new_port:
        return True, f"{service_key} is already configured to port {new_port}."

    # Prevent internal collisions with other VexTunnel ports
    ignored_keys = {"WSS_ENABLED", service_key}
    if service_key == "BADVPN_PORT":
        ignored_keys.add("UDPGW_PORT")
    for k, v in current_ports.items():
        if k not in ignored_keys and v == new_port:
            return False, f"Port {new_port} is already in use by {k} in VexTunnel."

    # Check for external process binding conflicts
    in_use, proc = check_port_in_use(new_port)
    if in_use:
        proc_str = f" by '{proc}'" if proc else ""
        return False, f"Port {new_port} is currently in use{proc_str}. Please choose an open port or stop the conflicting service."

    # Update config
    current_ports[service_key] = new_port
    if service_key == "BADVPN_PORT":
        current_ports["UDPGW_PORT"] = new_port
    if not save_ports(current_ports, ports_file):
        return False, "Failed to write changes to ports.env."

    # Update Firewall
    proto = "udp" if service_key == "BADVPN_PORT" else "tcp"
    update_firewall_rules(old_port=old_port, new_port=new_port, proto=proto)

    # Restart matching service
    service_name = SERVICE_MAP.get(service_key)
    if service_name:
        # If modifying WSS and WSS is currently disabled, do not attempt to start service
        if service_key == "WSS_PORT" and not current_ports.get("WSS_ENABLED", True):
            return True, f"Updated {service_key} to {new_port} (Service is currently DISABLED)."

        if restart_service_safely(service_name):
            logger.info(f"Successfully rebound {service_key} from {old_port} to {new_port} ({service_name} restarted)")
            return True, f"Successfully rebound {service_key} to port {new_port}."
        else:
            return False, f"Port saved to config, but service '{service_name}' failed to restart on port {new_port}."

    return True, f"Port updated to {new_port}."


def toggle_wss(enable: Optional[bool] = None, ports_file: str = DEFAULT_PORTS_FILE, **kwargs) -> Tuple[bool, str]:
    """
    Toggle VexTunnel WSS (Port 443 / Encrypted WebSocket Proxy) service state.
    Allows 1-click clean co-existence with 3x-ui on port 443.
    """
    ports_file = kwargs.get("env_file", ports_file)
    current_ports = load_ports(ports_file)
    current_state = current_ports.get("WSS_ENABLED", True)

    target_state = not current_state if enable is None else enable
    if current_state == target_state:
        status_str = "ENABLED" if current_state else "DISABLED"
        return True, f"WSS service is already {status_str}."

    wss_port = current_ports.get("WSS_PORT", 443)

    if target_state:
        # Enabling WSS: check if port is currently free
        in_use, proc = check_port_in_use(wss_port)
        if in_use and proc and "vextunnel" not in proc.lower():
            return False, f"Cannot enable WSS: Port {wss_port} is occupied by '{proc}'. Please assign an alternate port first."

        current_ports["WSS_ENABLED"] = True
        save_ports(current_ports, ports_file)
        update_firewall_rules(old_port=None, new_port=wss_port, proto="tcp")

        if os.name != 'nt':
            subprocess.run(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "enable", "vextunnel-wss"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "restart", "vextunnel-wss"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        logger.info(f"VexTunnel WSS service ENABLED on port {wss_port}")
        return True, f"VexTunnel WSS service successfully ENABLED on port {wss_port}."
    else:
        # Disabling WSS: stop and disable service
        current_ports["WSS_ENABLED"] = False
        save_ports(current_ports, ports_file)

        if os.name != 'nt':
            subprocess.run(["systemctl", "stop", "vextunnel-wss"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["systemctl", "disable", "vextunnel-wss"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        logger.info(f"VexTunnel WSS service DISABLED on port {wss_port}")
        return True, f"VexTunnel WSS service successfully DISABLED. Port {wss_port} is released for 3x-ui or other services."


def reset_default_ports(ports_file: str = DEFAULT_PORTS_FILE, **kwargs) -> Tuple[bool, str]:
    """Reset all VexTunnel ports back to default factory settings."""
    ports_file = kwargs.get("env_file", ports_file)
    defaults = dict(DEFAULT_CONFIG)
    if not save_ports(defaults, ports_file):
        return False, "Failed to reset ports.env."

    for s_name in SERVICE_MAP.values():
        restart_service_safely(s_name)

    return True, "All VexTunnel ports successfully restored to factory defaults."
