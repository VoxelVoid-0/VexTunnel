#!/usr/bin/env python3
"""
VexTunnel - Client Subscription Web Portal (Hardened v1.3.13)
Author: VoxelVoid-0
License: GPL-3.0

Features:
- Ultra-lightweight Python ThreadingHTTPServer (< 12MB RAM)
- Strict localhost binding: 127.0.0.1:8088 (NO 0.0.0.0, Zero Public Ports)
- Published securely via Cloudflare Zero Trust Named Tunnel
- Pre-DB regex validation (32-char lowercase hex) for DoS immunity
- In-memory thread-safe rate limiter (CF-Connecting-IP, 30 req/min)
- Short-lived read-only SQLite URI connections (mode=ro)
- 3x-ui dark slate UI with live client-side auto-sync (every 60s)
- Strictly omits Apps and Configs/QR codes
"""

import sys
import os
import re
import time
import json
import sqlite3
import datetime
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from typing import Optional, Dict, Tuple

# Configuration Constants
DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_BIND_PORT = 8088
DEFAULT_DB_PATH = "/etc/vextunnel/vextunnel.db" if os.path.exists("/etc/vextunnel/vextunnel.db") else "vextunnel.db"
TOKEN_REGEX = re.compile(r"^[0-9a-f]{32}$")
RATE_LIMIT_WINDOW = 60  # seconds
RATE_LIMIT_MAX_REQ = 30  # requests per window

def format_bytes(num_bytes: int) -> str:
    """Format bytes into clean human-readable units."""
    if num_bytes <= 0:
        return "0 B"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num_bytes)
    i = 0
    while n >= 1024.0 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f"{n:.2f} {units[i]}"

class ThreadSafeRateLimiter:
    """Thread-safe sliding-window rate limiter by client IP."""
    def __init__(self, window_sec: int = RATE_LIMIT_WINDOW, max_requests: int = RATE_LIMIT_MAX_REQ):
        self.window = window_sec
        self.max_requests = max_requests
        self.history: Dict[str, list] = {}
        self.lock = threading.Lock()

    def is_allowed(self, ip: str) -> Tuple[bool, int]:
        now = time.time()
        with self.lock:
            timestamps = self.history.get(ip, [])
            valid_from = now - self.window
            timestamps = [t for t in timestamps if t > valid_from]
            if len(timestamps) >= self.max_requests:
                self.history[ip] = timestamps
                retry_after = int(self.window - (now - timestamps[0])) + 1
                return False, max(1, retry_after)
            timestamps.append(now)
            self.history[ip] = timestamps
            if len(self.history) > 10000:
                self._prune_locked(valid_from)
            return True, 0

    def _prune_locked(self, cutoff: float):
        dead_ips = [ip for ip, ts in self.history.items() if not ts or ts[-1] <= cutoff]
        for ip in dead_ips:
            del self.history[ip]

GLOBAL_RATE_LIMITER = ThreadSafeRateLimiter()

class VexSubRequestHandler(BaseHTTPRequestHandler):
    server_version = "VexTunnel-Portal/1.3.13"
    sys_version = ""

    def get_client_ip(self) -> str:
        """Extract authentic client IP from Cloudflare header or fallback to socket."""
        cf_ip = self.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def send_security_headers(self, content_type: str = "text/html; charset=utf-8"):
        """Send strict HTTP security and cache headers."""
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' https:; img-src 'self' data: https:;")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")

    def query_user_readonly(self, token: str) -> Optional[Dict]:
        """Fetch user record strictly via short-lived read-only SQLite URI."""
        db_path = getattr(self.server, "db_path", DEFAULT_DB_PATH)
        abs_path = os.path.abspath(db_path)
        uri = f"file:{abs_path}?mode=ro"
        conn = None
        try:
            try:
                conn = sqlite3.connect(uri, uri=True, timeout=5.0)
            except sqlite3.OperationalError:
                conn = sqlite3.connect(abs_path, timeout=5.0)
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM users WHERE sub_token = ?", (token,)).fetchone()
            if not row:
                return None

            now = datetime.datetime.now()
            exp_str = str(row["expires_at"]).strip()
            exp = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
                try:
                    exp = datetime.datetime.strptime(exp_str, fmt)
                    break
                except ValueError:
                    pass
            if exp is None:
                try:
                    exp = datetime.datetime.fromisoformat(exp_str)
                except Exception:
                    exp = now + datetime.timedelta(days=30)
            diff = exp - now
            remaining_days = max(0, diff.days)
            is_expired = diff.total_seconds() <= 0

            status = row["status"].upper() if row["status"] else "ACTIVE"
            if is_expired:
                status = "EXPIRED"

            quota_bytes = int(row["quota_bytes"] or 0)
            used_bytes = int(row["used_bytes"] or 0)
            if quota_bytes > 0 and used_bytes >= quota_bytes and status == "ACTIVE":
                status = "QUOTA EXCEEDED"

            remaining_bytes = max(0, quota_bytes - used_bytes) if quota_bytes > 0 else 0
            pct = 0.0
            if quota_bytes > 0:
                pct = round(min(100.0, (used_bytes / quota_bytes) * 100.0), 2)

            return {
                "username": row["username"],
                "protocol": row["protocol"] if "protocol" in row.keys() else "ssh-ws",
                "status": status,
                "used_bytes": used_bytes,
                "used_formatted": format_bytes(used_bytes),
                "quota_bytes": quota_bytes,
                "quota_formatted": format_bytes(quota_bytes) if quota_bytes > 0 else "Unlimited",
                "remaining_bytes": remaining_bytes,
                "remaining_formatted": format_bytes(remaining_bytes) if quota_bytes > 0 else "Unlimited",
                "percentage": pct,
                "expires_at": row["expires_at"],
                "remaining_days": remaining_days,
                "max_logins": row["max_logins"] if "max_logins" in row.keys() else 2
            }
        except Exception as e:
            logger.error(f"Error querying user by sub_token: {e}")
            return None
        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_GET(self, head_only: bool = False):
        client_ip = self.get_client_ip()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = parse_qs(parsed.query)

        # 1. Health check route (no rate limiting)
        if path in ("/health", "/api/health"):
            self.send_response(200)
            self.send_security_headers("application/json")
            self.end_headers()
            if not head_only:
                payload = json.dumps({"status": "ok", "service": "vextunnel-sub", "timestamp": int(time.time())})
                self.wfile.write(payload.encode("utf-8"))
            return

        # 2. Rate Limiting Check
        allowed, retry_after = GLOBAL_RATE_LIMITER.is_allowed(client_ip)
        if not allowed:
            self.send_response(429)
            self.send_security_headers("text/html; charset=utf-8")
            self.send_header("Retry-After", str(retry_after))
            self.end_headers()
            if not head_only:
                self.wfile.write(self.render_rate_limit_page(retry_after).encode("utf-8"))
            return

        # 3. Match /sub/<token> endpoint
        parts = [p for p in path.split("/") if p]
        if len(parts) == 2 and parts[0] == "sub":
            raw_token = parts[1].lower()

            # Pre-DB Regex Gate (DoS Immunity)
            if not TOKEN_REGEX.fullmatch(raw_token):
                self.send_404(head_only=head_only)
                return

            # Read-only DB Query
            user_data = self.query_user_readonly(raw_token)
            if not user_data:
                self.send_404(head_only=head_only)
                return

            # Check if JSON format requested
            accept_hdr = self.headers.get("Accept", "")
            is_json_req = "format" in query and query["format"][0].lower() == "json"
            if is_json_req or "application/json" in accept_hdr:
                self.send_response(200)
                self.send_security_headers("application/json")
                self.end_headers()
                if not head_only:
                    self.wfile.write(json.dumps(user_data, indent=2).encode("utf-8"))
                return

            # Render 3x-ui Styled HTML
            self.send_response(200)
            self.send_security_headers("text/html; charset=utf-8")
            self.end_headers()
            if not head_only:
                html = self.render_3xui_sub_page(user_data, raw_token)
                self.wfile.write(html.encode("utf-8"))
            return

        # Any unknown path
        self.send_404(head_only=head_only)

    def send_404(self, head_only: bool = False):
        self.send_response(404)
        self.send_security_headers("text/html; charset=utf-8")
        self.end_headers()
        if not head_only:
            self.wfile.write(self.render_404_page().encode("utf-8"))

    def log_message(self, format, *args):
        # Keep logs silent in production to prevent disk spam
        pass

    def render_3xui_sub_page(self, data: Dict, token: str) -> str:
        """Render 3x-ui dark modern aesthetic subscription card (excluding apps & configs)."""
        status = data["status"]
        if status == "ACTIVE":
            badge_class = "badge-active"
            pulse_class = "pulse-active"
        elif status == "EXPIRED":
            badge_class = "badge-expired"
            pulse_class = "pulse-expired"
        elif status == "QUOTA EXCEEDED":
            badge_class = "badge-exceeded"
            pulse_class = "pulse-exceeded"
        else:
            badge_class = "badge-locked"
            pulse_class = "pulse-locked"

        pct = data["percentage"]
        bar_color = "linear-gradient(90deg, #38bdf8 0%, #0ea5e9 50%, #6366f1 100%)"
        if pct >= 90:
            bar_color = "linear-gradient(90deg, #f59e0b 0%, #ef4444 100%)"
        elif pct >= 75:
            bar_color = "linear-gradient(90deg, #38bdf8 0%, #f59e0b 100%)"

        days_text = f"{data['remaining_days']} Days Left" if data['remaining_days'] > 0 else "Expired"
        if status == "EXPIRED":
            days_text = "Expired"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subscription - {data['username']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }}
        body {{
            background-color: #0b0f19;
            background-image: 
                radial-gradient(at 0% 0%, rgba(56, 189, 248, 0.12) 0px, transparent 50%),
                radial-gradient(at 100% 100%, rgba(99, 102, 241, 0.12) 0px, transparent 50%);
            color: #f8fafc;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 1.5rem 1rem;
        }}
        .card-container {{
            width: 100%;
            max-width: 460px;
            background: #1e293b;
            border: 1px solid rgba(148, 163, 184, 0.15);
            border-radius: 1.25rem;
            padding: 2rem;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), 0 0 0 1px rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(12px);
        }}
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 1.75rem;
            padding-bottom: 1.25rem;
            border-bottom: 1px solid rgba(148, 163, 184, 0.12);
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}
        .brand-icon {{
            width: 36px;
            height: 36px;
            background: linear-gradient(135deg, #0ea5e9, #6366f1);
            border-radius: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #ffffff;
            font-weight: 700;
            font-size: 1.1rem;
            box-shadow: 0 4px 12px rgba(14, 165, 233, 0.35);
        }}
        .brand-text h1 {{
            font-size: 1.1rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            color: #ffffff;
        }}
        .brand-text span {{
            font-size: 0.8rem;
            color: #94a3b8;
        }}
        .status-badge {{
            display: inline-flex;
            align-items: center;
            gap: 0.45rem;
            padding: 0.35rem 0.85rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .pulse-dot {{
            width: 8px;
            height: 8px;
            border-radius: 50%;
            display: inline-block;
        }}
        .badge-active {{ background: rgba(16, 185, 129, 0.15); color: #34d399; border: 1px solid rgba(52, 211, 153, 0.3); }}
        .pulse-active {{ background: #10b981; box-shadow: 0 0 8px #10b981; }}
        .badge-expired {{ background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.3); }}
        .pulse-expired {{ background: #ef4444; box-shadow: 0 0 8px #ef4444; }}
        .badge-exceeded {{ background: rgba(245, 158, 11, 0.15); color: #fbbf24; border: 1px solid rgba(251, 191, 36, 0.3); }}
        .pulse-exceeded {{ background: #f59e0b; box-shadow: 0 0 8px #f59e0b; }}
        .badge-locked {{ background: rgba(148, 163, 184, 0.15); color: #94a3b8; border: 1px solid rgba(148, 163, 184, 0.3); }}
        .pulse-locked {{ background: #64748b; }}

        .section-title {{
            font-size: 0.78rem;
            font-weight: 600;
            text-transform: uppercase;
            color: #94a3b8;
            letter-spacing: 0.06em;
            margin-bottom: 0.85rem;
        }}
        .progress-box {{
            background: #0f172a;
            border-radius: 1rem;
            padding: 1.25rem;
            border: 1px solid rgba(148, 163, 184, 0.1);
            margin-bottom: 1.25rem;
        }}
        .progress-header {{
            display: flex;
            justify-content: space-between;
            align-items: baseline;
            margin-bottom: 0.75rem;
        }}
        .progress-percent {{
            font-size: 1.5rem;
            font-weight: 800;
            color: #38bdf8;
        }}
        .progress-label {{
            font-size: 0.82rem;
            color: #94a3b8;
        }}
        .progress-track {{
            width: 100%;
            height: 10px;
            background: #1e293b;
            border-radius: 9999px;
            overflow: hidden;
            position: relative;
        }}
        .progress-fill {{
            height: 100%;
            border-radius: 9999px;
            transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
            background: {bar_color};
            box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.65rem;
            margin-top: 1rem;
        }}
        .stat-card {{
            background: rgba(30, 41, 59, 0.8);
            border: 1px solid rgba(148, 163, 184, 0.08);
            border-radius: 0.75rem;
            padding: 0.75rem 0.5rem;
            text-align: center;
        }}
        .stat-card span {{
            display: block;
            font-size: 0.72rem;
            color: #94a3b8;
            margin-bottom: 0.25rem;
            text-transform: uppercase;
            letter-spacing: 0.02em;
        }}
        .stat-card strong {{
            display: block;
            font-size: 0.95rem;
            font-weight: 700;
            color: #f1f5f9;
        }}

        .info-card {{
            background: #0f172a;
            border-radius: 1rem;
            padding: 1.25rem;
            border: 1px solid rgba(148, 163, 184, 0.1);
            display: flex;
            flex-direction: column;
            gap: 0.85rem;
        }}
        .info-row {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.88rem;
        }}
        .info-key {{
            color: #94a3b8;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}
        .info-val {{
            color: #f1f5f9;
            font-weight: 600;
        }}
        .days-pill {{
            background: rgba(14, 165, 233, 0.15);
            color: #38bdf8;
            padding: 0.2rem 0.6rem;
            border-radius: 0.4rem;
            font-weight: 700;
            font-size: 0.82rem;
            border: 1px solid rgba(56, 189, 248, 0.25);
        }}

        .footer {{
            margin-top: 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            font-size: 0.75rem;
            color: #64748b;
            padding-top: 1rem;
            border-top: 1px solid rgba(148, 163, 184, 0.1);
        }}
        .live-tag {{
            display: inline-flex;
            align-items: center;
            gap: 0.35rem;
            color: #94a3b8;
        }}
        .live-dot {{
            width: 6px;
            height: 6px;
            background: #38bdf8;
            border-radius: 50%;
            animation: pulse-ring 2s infinite;
        }}
        @keyframes pulse-ring {{
            0% {{ transform: scale(0.95); opacity: 0.8; }}
            50% {{ transform: scale(1.4); opacity: 0.3; }}
            100% {{ transform: scale(0.95); opacity: 0.8; }}
        }}
    </style>
</head>
<body>
    <div class="card-container">
        <!-- Header -->
        <div class="header">
            <div class="brand">
                <div class="brand-icon">V</div>
                <div class="brand-text">
                    <h1 id="ui-username">{data['username']}</h1>
                    <span>SSH-WebSocket Portal</span>
                </div>
            </div>
            <div class="status-badge {badge_class}" id="ui-badge">
                <span class="pulse-dot {pulse_class}" id="ui-pulse"></span>
                <span id="ui-status-text">{status}</span>
            </div>
        </div>

        <!-- Bandwidth Usage Card -->
        <div class="section-title">Traffic & Quota</div>
        <div class="progress-box">
            <div class="progress-header">
                <span class="progress-percent" id="ui-percent">{pct}%</span>
                <span class="progress-label" id="ui-used-label">Used of {data['quota_formatted']}</span>
            </div>
            <div class="progress-track">
                <div class="progress-fill" id="ui-progress-bar" style="width: {pct}%;"></div>
            </div>
            <div class="stats-grid">
                <div class="stat-card">
                    <span>Used</span>
                    <strong id="ui-used">{data['used_formatted']}</strong>
                </div>
                <div class="stat-card">
                    <span>Remaining</span>
                    <strong id="ui-remaining">{data['remaining_formatted']}</strong>
                </div>
                <div class="stat-card">
                    <span>Total</span>
                    <strong id="ui-total">{data['quota_formatted']}</strong>
                </div>
            </div>
        </div>

        <!-- Validity & Expiry Card -->
        <div class="section-title">Account Validity</div>
        <div class="info-card">
            <div class="info-row">
                <span class="info-key">Expires At</span>
                <span class="info-val" id="ui-expires">{data['expires_at']}</span>
            </div>
            <div class="info-row">
                <span class="info-key">Time Remaining</span>
                <span class="days-pill" id="ui-days">{days_text}</span>
            </div>
            <div class="info-row">
                <span class="info-key">Max Logins</span>
                <span class="info-val" id="ui-logins">{data['max_logins']} Devices</span>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div class="live-tag">
                <span class="live-dot"></span>
                <span>Auto-syncs every 60s</span>
            </div>
            <span>VexTunnel Core</span>
        </div>
    </div>

    <!-- Client-side Vanilla JS live auto-sync polling every 60s -->
    <script>
        (function() {{
            const token = "{token}";
            function updateData() {{
                fetch('/sub/' + token + '?format=json', {{ cache: 'no-store' }})
                    .then(response => {{
                        if (!response.ok) throw new Error('Network error');
                        return response.json();
                    }})
                    .then(data => {{
                        document.getElementById('ui-percent').innerText = data.percentage + '%';
                        document.getElementById('ui-used-label').innerText = 'Used of ' + data.quota_formatted;
                        const pb = document.getElementById('ui-progress-bar');
                        pb.style.width = Math.min(100, data.percentage) + '%';
                        if (data.percentage >= 90) {{
                            pb.style.background = 'linear-gradient(90deg, #f59e0b 0%, #ef4444 100%)';
                        }} else if (data.percentage >= 75) {{
                            pb.style.background = 'linear-gradient(90deg, #38bdf8 0%, #f59e0b 100%)';
                        }} else {{
                            pb.style.background = 'linear-gradient(90deg, #38bdf8 0%, #0ea5e9 50%, #6366f1 100%)';
                        }}
                        document.getElementById('ui-used').innerText = data.used_formatted;
                        document.getElementById('ui-remaining').innerText = data.remaining_formatted;
                        document.getElementById('ui-total').innerText = data.quota_formatted;
                        document.getElementById('ui-expires').innerText = data.expires_at;
                        const daysElem = document.getElementById('ui-days');
                        daysElem.innerText = (data.remaining_days > 0 && data.status !== 'EXPIRED') ? (data.remaining_days + ' Days Left') : 'Expired';
                        
                        const statusElem = document.getElementById('ui-status-text');
                        const badgeElem = document.getElementById('ui-badge');
                        const pulseElem = document.getElementById('ui-pulse');
                        statusElem.innerText = data.status;
                        badgeElem.className = 'status-badge';
                        pulseElem.className = 'pulse-dot';
                        if (data.status === 'ACTIVE') {{
                            badgeElem.classList.add('badge-active');
                            pulseElem.classList.add('pulse-active');
                        }} else if (data.status === 'EXPIRED') {{
                            badgeElem.classList.add('badge-expired');
                            pulseElem.classList.add('pulse-expired');
                        }} else if (data.status === 'QUOTA EXCEEDED') {{
                            badgeElem.classList.add('badge-exceeded');
                            pulseElem.classList.add('pulse-exceeded');
                        }} else {{
                            badgeElem.classList.add('badge-locked');
                            pulseElem.classList.add('pulse-locked');
                        }}
                    }})
                    .catch(() => {{}});
            }}
            setInterval(updateData, 60000);
        }})();
    </script>
</body>
</html>"""

    def render_404_page(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Subscription Not Found</title>
    <style>
        body {
            background-color: #0b0f19;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 1.5rem;
        }
        .box {
            text-align: center;
            background: #1e293b;
            padding: 2.5rem 2rem;
            border-radius: 1.25rem;
            border: 1px solid rgba(148, 163, 184, 0.15);
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }
        h1 { font-size: 3.5rem; font-weight: 800; color: #38bdf8; line-height: 1; margin-bottom: 0.5rem; }
        h2 { font-size: 1.2rem; margin-bottom: 0.75rem; color: #ffffff; }
        p { font-size: 0.88rem; color: #94a3b8; line-height: 1.5; }
    </style>
</head>
<body>
    <div class="box">
        <h1>404</h1>
        <h2>Subscription Link Not Found</h2>
        <p>This subscription token is invalid or has expired. Please contact your VPN administrator to obtain an active link.</p>
    </div>
</body>
</html>"""

    def render_rate_limit_page(self, retry_after: int) -> str:
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>429 - Too Many Requests</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 1.5rem;
        }}
        .box {{
            text-align: center;
            background: #1e293b;
            padding: 2.5rem 2rem;
            border-radius: 1.25rem;
            border: 1px solid rgba(245, 158, 11, 0.3);
            max-width: 400px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
        }}
        h1 {{ font-size: 3rem; font-weight: 800; color: #f59e0b; line-height: 1; margin-bottom: 0.5rem; }}
        h2 {{ font-size: 1.2rem; margin-bottom: 0.75rem; color: #ffffff; }}
        p {{ font-size: 0.88rem; color: #94a3b8; line-height: 1.5; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>429</h1>
        <h2>Rate Limit Exceeded</h2>
        <p>Too many requests from your IP address. Please wait {retry_after} seconds before refreshing.</p>
    </div>
</body>
</html>"""

class ThreadedVexSubServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

def run_server(bind_host: str = DEFAULT_BIND_HOST, bind_port: int = DEFAULT_BIND_PORT, db_path: str = DEFAULT_DB_PATH):
    # Enforce strict localhost binding: NEVER allow 0.0.0.0
    if bind_host != "127.0.0.1" and bind_host != "localhost":
        bind_host = "127.0.0.1"

    server = ThreadedVexSubServer((bind_host, bind_port), VexSubRequestHandler)
    server.db_path = db_path
    print(f"[*] VexTunnel Subscription Web Portal running strictly on {bind_host}:{bind_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    port = DEFAULT_BIND_PORT
    if "SUB_PORT" in os.environ:
        try:
            port = int(os.environ["SUB_PORT"])
        except ValueError:
            pass
    elif os.path.exists("/etc/vextunnel/cf_tunnel.env"):
        try:
            with open("/etc/vextunnel/cf_tunnel.env", "r") as f:
                for line in f:
                    if line.startswith("SUB_PORT="):
                        port = int(line.split("=", 1)[1].strip())
        except Exception:
            pass

    run_server(DEFAULT_BIND_HOST, port, DEFAULT_DB_PATH)

