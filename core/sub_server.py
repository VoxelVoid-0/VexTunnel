#!/usr/bin/env python3
"""
VexTunnel - Client Subscription Web Portal (Hardened v1.3.15)
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
    server_version = "VexTunnel-Portal/1.3.15"
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

        # 3. Static asset serving for 404 page (CSS / JS)
        parts = [p for p in path.split("/") if p]
        if (len(parts) == 1 and parts[0] in ("style.css", "script.js")) or (len(parts) == 2 and parts[0] == "sub" and parts[1] in ("style.css", "script.js")):
            static_name = parts[-1]
            for cand_dir in (
                os.path.join(os.path.dirname(__file__), "..", "web", "404"),
                "/etc/vextunnel/web/404"
            ):
                file_path = os.path.join(cand_dir, static_name)
                if os.path.isfile(file_path):
                    content_type = "text/css; charset=utf-8" if static_name.endswith(".css") else "application/javascript; charset=utf-8"
                    self.send_response(200)
                    self.send_security_headers(content_type)
                    self.end_headers()
                    if not head_only:
                        try:
                            with open(file_path, "rb") as f:
                                self.wfile.write(f.read())
                        except Exception:
                            pass
                    return

        # 4. Match /sub/<token> endpoint
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
        # Check if local standalone template exists in web/404
        for cand in (
            os.path.join(os.path.dirname(__file__), "..", "web", "404", "index.html"),
            "/etc/vextunnel/web/404/index.html"
        ):
            if os.path.isfile(cand):
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        return f.read()
                except Exception:
                    pass
        return self._render_embedded_404()

    def _render_embedded_404(self) -> str:
        return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>404 - Page Not Found | VexTunnel</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/meyer-reset/2.0/reset.min.css">
  <style>
@import url("https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,900");
body, html {
  margin: 0;
  padding: 0;
  font-size: 16px;
  -webkit-font-smoothing: antialiased;
  background-color: #09334f;
  position: relative;
}

#yetiSVG {
  width: 600px;
  height: 470px;
  position: absolute;
  top: 0;
  left: 0;
  overflow: hidden;
}

#lightSVG {
  width: 600px;
  height: 470px;
  position: absolute;
  top: 0;
  left: 0;
  overflow: visible;
}

.content {
  padding: 5rem 3rem 0 25rem;
  position: relative;
  z-index: 10;
  font-family: "Source Sans Pro", sans-serif;
  color: #FFF;
}
.content h3 {
  margin: 0 0 0.8rem;
  font-size: 2.625rem;
  font-weight: 900;
  line-height: 120%;
}
.content p {
  font-size: 1.25rem;
  font-weight: normal;
  line-height: 150%;
  color: #d1e2ed;
}
.content p span {
  text-decoration: line-through;
}
.content .sub-note {
  margin-top: 1rem;
  font-size: 0.95rem;
  color: #94a3b8;
}
  </style>
</head>
<body>
<svg id="yetiSVG" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 600 470">
	<linearGradient id="flashlightGrad" x1="126.5842" x2="90.5842" y1="176.5625" y2="213.5625" gradientUnits="userSpaceOnUse">
		<stop offset="0" stop-color="#333"/>
		<stop offset=".076" stop-color="#414141"/>
		<stop offset=".2213" stop-color="#555"/>
		<stop offset=".3651" stop-color="#626262"/>
		<stop offset=".5043" stop-color="#666"/>
		<stop offset=".6323" stop-color="#606060"/>
		<stop offset=".8063" stop-color="#4e4e4e"/>
		<stop offset="1" stop-color="#333"/>
	</linearGradient>
	<path fill="#24658F" d="M0 0h600v470H0z"/>
	<g id="pillow">
		<path fill="#09334F" d="M241.3 124.6c-52.9 28.6-112.6 48-181.8 54.4-40.9 6.8-64.6-82.3-31.9-106.6C84 43.8 144.8 26.2 209.4 18c32.8 13 48.5 75.3 31.9 106.6z"/>
		<path fill="none" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M52.8 91.3c10 7.4 25.4 50.7 16.1 65.8M241.3 124.6c-52.9 28.6-112.6 48-181.8 54.4-40.9 6.8-64.6-82.3-31.9-106.6C84 43.8 144.8 26.2 209.4 18c32.8 13 48.5 75.3 31.9 106.6z"/>
		<path fill="#09334F" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M201.9 21.9c4.9-8 14.1-11.3 20.6-7.3s7.7 13.7 2.8 21.7"/>
		<path fill="#09334F" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M242.1 103.1c1.8.3 3.6.9 5.3 1.8 8.4 4.1 12.6 13 9.3 19.8s-12.9 9-21.3 4.9c-1.9-.9-3.6-2.1-5-3.4"/>
		<path fill="#09334F" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M70.3 172c.2 1.4.2 2.8.1 4.3-.8 9.4-8.3 16.4-16.7 15.6S39.2 183 40 173.7c.1-1.6.5-3.1 1-4.5"/>
		<path fill="#09334F" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M20.9 85.1c-4.1-5-5.1-11.6-2.1-16.9 4.1-7.2 14-9.2 22.1-4.6 3.7 2.1 6.4 5.2 7.9 8.6"/>
	</g>
	<g id="yeti">
		<path id="bodyBG" fill="#67B1E0" d="M80.9 291.4l-17.1-72.8c-6.3-27 10.4-54 37.4-60.3l93.1-29.6c26.5-8.1 54.6 6.8 62.7 33.3l21.9 71.5"/>
		<path class="hlFur" id="hlBody" fill="#FFF" d="M67.1 232.7c15.6-8.7 27.7-23.7 38-38.7 5.5-8 10.9-16.4 18.3-22.7 13.1-11.2 31.3-14.8 48.6-15 4.9 0 9.9.1 14.5-1.7 3.6-1.5 6.5-4.1 9.3-6.9 6.5-6.5 12-14 18-21-6.4-.6-12.9 0-19.4 2l-93.1 29.6c-27 6.3-43.7 33.4-37.4 60.3l3.2 14.1z"/>
		<path id="bodyOutline" fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M80.9 291.4l-17.1-72.8c-6.3-27 10.4-54 37.4-60.3l93.1-29.6c26.5-8.1 54.6 6.8 62.7 33.3l21.9 71.5"/>
		<path fill="#67B1E0" d="M197.5 132.4l-11.2-47.9c-6.3-26.7-32.7-44.1-59.5-38.2-27.4 6-44.5 33.1-38.1 60.3l13.6 56.2"/>
		<path class="hlFur" id="hlHead" fill="#FFF" d="M100.4 132.3l7.4 29.8 89.7-28.8-11.4-48.9c-1.6-6.8-4.5-12.9-8.4-18.3-9.6-7.9-28.5-12.9-46.9-8.5-24.9 5.9-34.5 23.6-38.1 37.9-.8.8-3.8 3-5.1 5.4.2 1.9.5 3.7 1 5.6l7 28.8 4.8-3z"/>
		<path fill="#67B1E0" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M182.1 71.6c3.8 3.6 7 7.7 9.5 12-1.8.4-3.6.9-5.3 1.6 3.2 2.9 5.7 6.3 7.6 9.9-1.1.3-2.2.7-3.3 1.1 2.5 3.5 4.3 7.4 5.4 11.5-.8-.5-2.2-.8-3.3-1"/>
		<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M197.5 132.4l-11.2-47.9c-6.3-26.7-32.7-44.1-59.5-38.2-27.4 6-44.5 33.1-38.1 60.3l13.6 56.2"/>
		<g>
			<ellipse cx="85.8" cy="120.4" fill="#88C9F2" rx="11.5" ry="11.5" transform="rotate(-66.265 85.7992 120.4318)"/>
			<path class="hlSkin" id="hlEar" fill="#DDF1FA" d="M80.4 122.2c-1.3-5.5 1.6-11.1 6.6-13.2-1.3-.1-2.6-.1-3.9.3-6.2 1.5-10 7.7-8.5 13.9s7.7 10 13.9 8.5c.7-.2 1.3-.4 1.9-.6-4.7-.6-8.9-4-10-8.9z"/>
			<path fill="#88C9F2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M84.2 116.6c-2.2.5-3.6 2.8-3 5 .5 2.2 2.8 3.6 5 3"/>
			<ellipse cx="85.8" cy="120.4" fill="none" stroke="#265D85" stroke-width="2.5" rx="11.5" ry="11.5" transform="rotate(-66.265 85.7992 120.4318)"/>
			<path class="hlFur" fill="#FFF" d="M106 130.3l-12 3.6 1.2-11.4-6.3-.1 6-12h-5.4l9.6-8.4z"/>
			<path class="hlFur" fill="#FFF" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M92.1 96.4c-5.1 5.9-8.4 11.7-10 17 4.2-1.2 8.5-2.2 12.8-3-4.2 4.8-6.7 9.5-7.6 13.8 2.7-.7 5.4-1.3 8-1.7-2.3 4.8-2.8 9.2-1.7 13.3 1.4-1 4-2.4 6.1-3.4"/>
		</g>
		<path class="hlSkin" id="face" fill="#DDF1FA" d="M169.1 70.4l7.3 23.4c9.4 26.8-1.8 45-20 50.7s-37.8-5.1-45.8-30.1L103.3 91"/>
		<path id="chin" fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M152.4 147.5c3.8 1 8 1.4 12.3 1.1-.5-1.4-1-2.9-1.6-4.3 3.8.6 7.9.7 12.1.1l-3.3-4.8c3.1-.6 6.3-1.6 9.5-3.1-1.4-1.6-2.8-3.1-4.2-4.6"/>
		<path class="hlFur" id="eyebrow" fill="#FFF" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M100.9 89.8c7.6 3.5 15.9 6.1 24.7 7.7 1.1-3.3 2.1-6.6 3-9.9 5.5 2.3 11.3 4.1 17.5 5.4.2-3.3.4-6.5.4-9.7 4.5.7 9.2 1.1 14 1.1-.5-3.4-1.1-6.7-1.7-10 4.5-1.9 9-4.2 13.3-6.9"/>
		<g id="eyeL">
			<circle cx="135.9" cy="105.3" r="3.5" fill="#265D85"/>
			<circle cx="133.7" cy="103.5" r="1" fill="#FFF"/>
		</g>
		<g id="eyeR">
			<circle cx="163.2" cy="96.3" r="3.5" fill="#265D85"/>
			<circle cx="160.9" cy="94.5" r="1" fill="#FFF"/>
		</g>
		<path id="nose" fill="#265D85" d="M149.3 101.2l4.4-1.6c1.8-.6 3.6 1 3.1 2.9l-1.1 3.9c-.4 1.6-2.3 2.2-3.6 1.3l-3.3-2.3c-1.7-1.1-1.3-3.5.5-4.2z"/>
		<path fill="#67B1E0" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M112.4 55.9c.9-4.3 3.8-9.2 8.8-13.7 1.4 2.3 2.8 4.7 4.1 7.1 2.3-4.8 6.9-9.8 13.8-14.1-.1 3.4-.3 6.8-.6 10.1 4.4-3 10.2-5.7 17.3-7.6-1.7 3.6-3.7 7.2-5.9 10.8"/>
		<g id="mouth">
			<path id="mouthBG" fill="#265D85" d="M149 115.7c-4.6 3.7-6.6 9.8-5 15.6.1.5.3 1.1.5 1.6.6 1.5 2.4 2.3 3.9 1.7l11.2-4.4 11.2-4.4c1.5-.6 2.3-2.4 1.7-3.9-.2-.5-.4-1-.7-1.5-2.8-5.2-8.4-8.3-14.1-7.9-3.7.2-5.9 1.1-8.7 3.2z"/>
			<g>
				<defs>
					<path id="mouthPath" d="M149 115.7c-4.6 3.7-6.6 9.8-5 15.6.1.5.3 1.1.5 1.6.6 1.5 2.4 2.3 3.9 1.7l11.2-4.4 11.2-4.4c1.5-.6 2.3-2.4 1.7-3.9-.2-.5-.4-1-.7-1.5-2.8-5.2-8.4-8.3-14.1-7.9-3.7.2-5.9 1.1-8.7 3.2z"/>
				</defs>
				<clipPath id="mouthClipPath">
					<use overflow="visible" xlink:href="#mouthPath"/>
				</clipPath>
				<g clip-path="url(#mouthClipPath)">
					<ellipse cx="160.8" cy="133.2" fill="#CC4A6C" rx="13" ry="8" transform="rotate(-21.685 160.775 133.1613)"/>
					<ellipse cx="158.4" cy="127.1" fill="#FFF" opacity=".1" rx="5" ry="1.5" transform="rotate(-21.685 158.3808 127.126)"/>
					<path id="tooth1" fill="#FFF" d="M161.5 116.1l-3.7 1.5c-1 .4-2.2-.1-2.6-1.1l-1.5-3.7 7.4-3 1.5 3.7c.5 1 0 2.2-1.1 2.6z"/>
					<path id="tooth2" fill="#FFF" d="M151.8 128.9l-1.9.7c-1 .4-1.5 1.6-1.1 2.6l1.1 2.8 5.6-2.2-1.1-2.8c-.5-1-1.6-1.5-2.6-1.1z"/>
					<path id="tooth3" fill="#FFF" d="M158.3 126.3l-1.9.7c-1 .4-1.5 1.6-1.1 2.6l1.1 2.8 5.6-2.2-1.1-2.8c-.5-1-1.6-1.5-2.6-1.1z"/>
				</g>
			</g>
			<path id="mouthOutline" fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M149 115.7c-4.6 3.7-6.6 9.8-5 15.6.1.5.3 1.1.5 1.6.6 1.5 2.4 2.3 3.9 1.7l11.2-4.4 11.2-4.4c1.5-.6 2.3-2.4 1.7-3.9-.2-.5-.4-1-.7-1.5-2.8-5.2-8.4-8.3-14.1-7.9-3.7.2-5.9 1.1-8.7 3.2z"/>
		</g>
		<g id="armR">
			<path class="hlSkin" fill="#DDF1FA" d="M158.4 116.9l-.7.3c-3.7 1.5-5.5 5.7-4.1 9.4l1.2 2.9c1.7 4.4 6.7 6.5 11.1 4.8l1.4-.5"/>
			<path fill="#A9DDF3" d="M154.8 129.1l.7 1.8c1 2.5 5.4 3.1 5.4 3.1l-2-5.1c-.3-.7-1.1-1.1-1.8-.8l-2.3 1z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M158.4 116.9l-.7.3c-3.7 1.5-5.5 5.7-4.1 9.4l1.2 2.9c1.7 4.4 6.7 6.5 11.1 4.8l1.4-.5"/>
			<path class="hlSkin" fill="#DDF1FA" stroke="#265D85" stroke-width="2.5" d="M167.7 113.2l-.7.3c-3.7 1.5-5.5 5.7-4.1 9.4l1.2 2.9c1.7 4.4 6.7 6.5 11.1 4.8l1.4-.5"/>
			<path class="hlSkin" fill="#DDF1FA" stroke="#265D85" stroke-width="2.5" d="M177 109.4l-.7.3c-3.7 1.5-5.5 5.7-4.1 9.4l1.2 2.9c1.7 4.4 6.7 6.5 11.1 4.8l1.4-.5"/>
			<path fill="#88C9F2" d="M162.3 128.6l18.6 46.7 37.2-14.8-17.9-44.8"/>
			<path class="hlSkin" fill="#DDF1FA" d="M206.5 130.7l-5.9-15.1-37.9 13 6.4 17.4c10 1.6 34.6-6.3 37.4-15.3z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M162.3 128.6l18.6 46.7 37.2-14.8-15.3-38.3"/>
			<path class="hlSkin" fill="#DDF1FA" d="M190.8 119l-1.5-3.7c-2-5.1-7.9-7.6-13-5.6l5.2 12.9"/>
			<path class="hlSkin" fill="#DDF1FA" d="M203.5 123.8l-1.5-3.7c-2-5.1-7.9-7.6-13-5.6l5.2 12.9"/>
			<path fill="#A9DDF3" d="M200.4 119.4l-.7-1.8c-1-2.5-5.4-3.1-5.4-3.1l1.9 4.8c.3.8 1.3 1.3 2.1.9l2.1-.8z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M203.5 123.8l-1.5-3.7c-2-5.1-7.9-7.6-13-5.6"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M193.7 126.4l-4.4-11.1c-2-5.1-7.9-7.6-13-5.6"/>
			<path fill="#67B1E0" d="M219.6 160.1c-1.5-6.2-3.2-13.2-5.1-21.1-2.8 2.1-5.6 4.5-8.3 7.4-2-1.8-4.1-3.7-6.2-5.7-2.4 3.6-4.6 7.7-6.7 12.1-3-1.9-6-3.9-9.2-6-1.4 2.9-2.7 6-4 9.2-4.7-.6-9.4-1.1-14.2-1.7 5.4 8 10.3 15.2 14.7 21.5"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M219.6 160.1c-1.5-6.2-3.2-13.2-5.1-21.1-2.8 2.1-5.6 4.5-8.3 7.4-2-1.8-4.1-3.7-6.2-5.7-2.4 3.6-4.6 7.7-6.7 12.1-3-1.9-6-3.9-9.2-6-1.4 2.9-2.7 6-4 9.2-4.7-.6-9.4-1.1-14.2-1.7 5.4 8 10.3 15.2 14.7 21.5"/>
			<path fill="none" stroke="#3A5E77" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M160.9 125l2 5.1"/>
			<path class="hlSkin" fill="#DDF1FA" d="M172.2 126.4l-1.5-3.7c-2-5.1-7.9-7.6-13-5.6l5.2 12.9"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M160.5 124l2.4 6.1"/>
			<path class="hlSkin" fill="#DDF1FA" d="M181.5 122.7L180 119c-2-5.1-7.9-7.6-13-5.6l5.2 12.9"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M181.5 122.7L180 119c-2-5.1-7.9-7.6-13-5.6"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M172.2 126.4l-1.5-3.7c-2-5.1-7.9-7.6-13-5.6"/>
		</g>
		<g id="armL">
			<path fill="#67B1E0" d="M50.9 156.7c-12 35.8-7.8 69.6 8.3 101.9 12.1 22.7 37 14.1 39.5-11.8v-65l-47.8-25.1z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M50.9 156.7c-12 35.8-7.8 69.6 8.3 101.9 10 22.3 37.3 15.1 39.5-11.8v-65l-47.8-25.1z"/>
			<path fill="none" stroke="#262626" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="20" d="M59.3 143.8l34.3 33.9"/>
			<path fill="#4D4D4D" d="M58.4 133.9l15.9 15.9-.9.9-16.5-16.5c.5-.2 1-.3 1.5-.3z"/>
			<path fill="#1A1A1A" d="M71.2 169.6l-20.1-20c-2.4-3.7-2.5-8.1.1-11.7l23.1 22.2"/>
			<path fill="#4D4D4D" d="M80.5 156.4l16 15.9-.9.9-16.5-16.5c.5-.1 1-.2 1.4-.3z"/>
			<path fill="#1A1A1A" d="M74.2 160.1L86 171.4l-2 11-10.2-10.1c-2.4-4.4-2.5-8.5.4-12.2z"/>
			<path fill="#88C9F2" d="M65.9 164.8c-1.9-5.5.8-11.8 6.1-14.1 4.9-2.2 10.4-.6 13.5 3.4 1.3 1.6 3.5 2.1 5.4 1.4 3-1.2 3.9-4.9 1.9-7.4-5.8-7.2-16.1-9.9-25-5.7-9.4 4.4-14.1 15.3-10.9 25.2"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M67.9 168.3c-1.1-1.2-2-3.6-2-3.6-1.9-5.5.8-11.8 6.1-14.1 4.9-2.2 10.4-.6 13.5 3.4 1.3 1.6 3.5 2.1 5.4 1.4 3-1.2 3.9-4.9 1.9-7.4-5.8-7.2-16.1-9.9-25-5.7-9.4 4.4-14.1 15.3-10.9 25.2"/>
			<path fill="#88C9F2" d="M69.9 168.7c-1.9-5.5.8-11.8 6.1-14.1 4.9-2.2 10.4-.6 13.5 3.4 1.3 1.6 3.5 2.1 5.4 1.4 3-1.2 3.9-4.9 1.9-7.4-5.8-7.2-16.1-9.9-25-5.7-9.4 4.4-14.1 15.3-10.9 25.2"/>
			<path fill="#67B1E0" d="M49.9 155l2.7 12.7.2 11.8 5 8.6 9.5-1.8 2-8.7-6.9.6 1.7-11.7-6.6 2.8 1-13.8-4.6 2.9z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M71.9 172.3c-1.1-1.2-2-3.6-2-3.6-1.9-5.5.8-11.8 6.1-14.1 4.9-2.2 10.4-.6 13.5 3.4 1.3 1.6 3.5 2.1 5.4 1.4 3-1.2 3.9-4.9 1.9-7.4-5.8-7.2-16.1-9.9-25-5.7"/>
			<path class="hlSkin" id="hlHandL" fill="#DDF1FA" d="M101.7 156.9c-5.8-7.2-16.1-9.9-25-5.7-5.9 2.8-9.9 8.1-11.3 14.1l-1-.9-6.2 4.2c5.5 18.1 19.3 25.4 30.4 21l1.2-9.1c-6 2.4-12.7-.7-14.9-6.8-1.9-5.5.8-11.8 6.1-14.1 4.9-2.2 10.4-.6 13.5 3.4 1.3 1.6 3.5 2.1 5.4 1.4 2.9-1.3 3.8-5 1.8-7.5z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M89.7 180.5c-6 2.4-12.7-.7-14.9-6.8"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M76.9 177.3c-1.1-1.2-2-3.6-2-3.6-1.9-5.5.8-11.8 6.1-14.1 4.9-2.2 10.4-.6 13.5 3.4 1.3 1.6 3.5 2.1 5.4 1.4 3-1.2 3.9-4.9 1.9-7.4-5.8-7.2-16.1-9.9-25-5.7"/>
			<path class="hlFur" id="hlArmL" fill="#FFF" d="M98.8 202.8l-1.4-8.7-5.2.7-7.2-11.5-6.8 9-3.9-9.3-7.5 4.8 3.5-11.4-7.1 1.9 2.7-13.5-7.8 4.9c-11.7 26.5-3.6 52.5 1.7 66.6 15.5-6.4 30.3-21.9 39-33.5z"/>
			<path fill="#A9DDF3" d="M101 161.2l-2.4-2.2c.2-1.6-.2-2.7-.8-3.9l2.6 2.5c.8.8 1 2.2.6 3.6z"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M66.9 187.8l3.5-11.4-7.2 1.9 2.6-13.9-7.5 4.5 1.2-15.5-5.5 4.2"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M54 157.6l-5.6-5.6 2.7 14.7"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M67.1 188l7.3-5 3.8 9.3"/>
			<path fill="none" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M78.2 192.3l6.8-9 7.1 11.5"/>
		</g>
	</g>
	<g id="fingersBackL" style="visibility: hidden;" fill="#88C9F2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5">
		<path d="M149.2 177.5l-5.6-23.3c-.6-2.7 1-5.4 3.7-6 2.7-.6 5.4 1 6 3.7l4.4 18.4c.6 2.7-1 5.4-3.7 6l-4.8 1.2M139.4 179.8l-5.6-23.3c-.6-2.7 1-5.4 3.7-6 2.7-.6 5.4 1 6 3.7l5.6 23.3-9.7 2.3z"/>
		<path d="M128.6 177.3l-4.4-18.4c-.6-2.7 1-5.4 3.7-6 2.7-.6 5.4 1 6 3.7l5.6 23.3-4.9 1.2c-2.7.5-5.4-1.2-6-3.8z"/>
	</g>
	<g id="fingersBackR" style="visibility: hidden;" fill="#88c9f2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5">
		<path d="M215.5 152l-15.9-17.9c-1.8-2.1-1.6-5.2.4-7.1 2.1-1.8 5.2-1.6 7.1.4l12.6 14.2c1.8 2.1 1.6 5.2-.4 7l-3.8 3.4"/>
		<path d="M208 158.6l-15.9-17.9c-1.8-2.1-1.6-5.2.4-7.1 2.1-1.8 5.2-1.6 7.1.4l15.9 17.9-7.5 6.7z"/>
		<path d="M197.2 161.5l-12.6-14.2c-1.8-2.1-1.6-5.2.4-7.1 2.1-1.8 5.2-1.6 7.1.4l15.9 17.9-3.7 3.3c-2.1 2-5.2 1.8-7.1-.3z"/>
	</g>
	<g id="blanket">
		<path d="M1.2 271.4C6.6 262 13 253.1 22.4 248c10.3-5.5 22.5-5.5 33.7-8.8 21.8-6.5 37.5-25.2 50.3-43.9 5.5-8 10.9-16.4 18.3-22.7 13.1-11.2 31.3-14.8 48.6-15 4.9 0 9.9.1 14.5-1.7 3.6-1.5 6.5-4.1 9.3-6.9 10.1-10.2 17.9-22.8 29-32 7.9-6.6 18.7-14.7 29.5-13.7 13.9 1.2 25 5.8 38.5-1.5 28.1-15.2 27.8-60.6 56.2-75.1 16.2-8.3 36.9-3.6 52.6-12.7 5.4-3.2 9.8-7.7 13.9-12.5h128.5l-350.8 209L1.3 363l-.1-91.6z" opacity=".1"/>
		<path fill="#09334F" d="M0 281.6c5.3-9.2 11.5-17.9 20.7-22.8 10.3-5.5 22.5-5.5 33.7-8.8 21.8-6.5 37.5-25.2 50.3-43.9 5.5-8 10.9-16.4 18.3-22.7 13.1-11.2 31.3-14.8 48.6-15 4.9 0 9.9.1 14.5-1.7 3.6-1.5 6.5-4.1 9.3-6.9 10.1-10.2 17.9-22.8 29-32 7.9-6.6 18.7-14.7 29.5-13.7 13.9 1.2 25 5.8 38.5-1.5 28.1-15.2 27.8-60.6 56.2-75.1 16.2-8.3 36.9-3.6 52.6-12.7C411 19.1 417.1 8.4 424.9.3H700v570H0V281.6z"/>
		<path fill="#072A40" d="M0 281.6c5.3-9.2 11.6-17.9 20.8-22.8 10.3-5.5 22.5-5.5 33.7-8.8 21.8-6.5 37.5-25.2 50.3-43.9 5.5-8 10.9-16.4 18.3-22.7 13.1-11.2 31.3-14.8 48.6-15 4.9 0 9.9.1 14.5-1.7 3.6-1.5 6.5-4.1 9.3-6.9 10.1-10.2 17.9-22.8 29-32 7.9-6.6 18.7-14.7 29.5-13.7 13.9 1.2 25 5.8 38.5-1.5 28.1-15.2 27.8-60.6 56.2-75.1 16.2-8.3 36.9-3.6 52.6-12.7 9.8-5.7 15.9-16.4 23.7-24.6h100.4c-3.5 2.8-7.3 5.3-11.4 7.2-11.6 5.4-23 6.6-34.9 1.9-10.5-4.2-22.3 2.4-30.1 10.6-7.8 8.2-14 18.3-23.7 24-15.7 9.1-36.4 4.4-52.6 12.7-28.4 14.6-28.2 60-56.2 75.1-13.5 7.3-24.6 2.8-38.5 1.5-10.8-1-21.5 7.1-29.5 13.7-11.2 9.2-18.9 21.8-29 32-2.7 2.7-5.7 5.4-9.3 6.9-4.5 1.9-9.6 1.7-14.5 1.7-17.3.2-35.4 3.8-48.6 15-7.4 6.3-12.8 14.7-18.3 22.7-12.9 18.7-28.6 37.4-50.3 43.9-11.2 3.4-23.4 3.3-33.7 8.8-11.9 6.4-18.9 19-25.2 31-8.2 15.3-11.6 30-19.6 44.7v-72z"/>
		<path fill="none" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M1.2 283c5.3-9.3 11.8-18 21.1-23 10.3-5.5 22.5-5.5 33.7-8.8 21.8-6.5 37.5-25.2 50.3-43.9 5.5-8 10.9-16.4 18.3-22.7 13.1-11.2 31.3-14.8 48.6-15 4.9 0 9.9.1 14.5-1.7 3.6-1.5 6.5-4.1 9.3-6.9 10.1-10.2 17.9-22.8 29-32 7.9-6.6 18.7-14.7 29.5-13.7 13.9 1.2 25 5.8 38.5-1.5 28.1-15.2 27.8-60.6 56.2-75.1 16.2-8.3 36.9-3.6 52.6-12.7 9.8-5.7 15.9-16.4 23.7-24.5"/>
		<path fill="none" stroke="#001726" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M1.2 355c8-14.7 11.7-29.4 19.9-44.9 6.3-11.9 13.3-24.6 25.2-31 10.3-5.5 22.5-5.5 33.7-8.8 21.8-6.5 37.5-25.2 50.3-43.9 5.5-8 10.9-16.4 18.3-22.7 13.1-11.2 31.3-14.8 48.6-15 4.9 0 9.9.1 14.5-1.7 3.6-1.5 6.5-4.1 9.3-6.9 10.1-10.2 17.9-22.8 29-32 7.9-6.6 18.7-14.7 29.5-13.7 13.9 1.2 25 5.8 38.5-1.5 28.1-15.2 27.8-60.6 56.2-75.1 16.2-8.3 36.9-3.6 52.6-12.7 9.8-5.7 15.9-15.8 23.7-24s19.6-14.8 30.1-10.6c11.9 4.8 23.2 3.5 34.9-1.9 4-1.9 7.7-4.4 11.2-7.1"/>
		<path d="M111.2 197.2s50.7 23.9 90.8 43.1c14.2 6.8 18 25.4 7.5 37.2-7.6 8.5-20.2 10.4-30 4.5l-89.9-54.7 21.6-30.1z" opacity=".03"/>
		<path d="M12.1 266s53.5 64.8 94.7 114c11.7 13.9 1.8 35.1-16.4 35.1-7.1 0-13.8-3.6-17.8-9.5L0 296.5v-13.2L12.1 266z" opacity=".03"/>
		<path d="M155.7 170.1s111.4 46.9 171.1 69c3.5 1.3 7.4 0 9.4-3.2 2.7-4.2.9-9.9-3.8-11.7-33.5-12.8-147.3-56-147.3-56l-29.4 1.9z" opacity=".03"/>
		<path d="M255.9 114.7S349 145.6 412 176c2.1 1 4.6.6 6.2-1 2.8-2.7 1.9-7.5-1.7-9-23.3-9.6-94.3-38.6-131.1-50.4-.1.1-10.2 1.9-29.5-.9z" opacity=".03"/>
		<path d="M356.6 34.9l152.1 49.3c2.2.7 4.5.6 6.7-.2 8.7-3.4 8.2-15.9-.7-18.6l-121-36.8-37.1 6.3z" opacity=".03"/>
	</g>
	<g id="fingersFrontL" style="visibility: hidden;">
		<path fill="#88C9F2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M146.2 165.1l2.8 11.6c.6 2.7 3.3 4.3 6 3.7 2.7-.6 4.3-3.3 3.7-6l-1.6-6.8c-.6-2.7-3.3-4.3-6-3.7l-4.9 1.2"/>
		<path fill="#A9DDF3" d="M151.4 173.8l.5 2.2c.3 1.1 1.3 1.7 2.4 1.5 1.1-.3 1.7-1.3 1.5-2.4l-.5-2.2-3.9.9z"/>
		<path fill="#88C9F2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M136.5 167.4l2.8 11.6c.6 2.7 3.3 4.3 6 3.7 2.7-.6 4.3-3.3 3.7-6l-2.8-11.6-9.7 2.3z"/>
		<path fill="#A9DDF3" d="M141.7 176.2l.5 2.2c.3 1.1 1.3 1.7 2.4 1.5 1.1-.3 1.7-1.3 1.5-2.4l-.5-2.2-3.9.9z"/>
		<path fill="#88C9F2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M127.9 174.6l1.6 6.8c.6 2.7 3.3 4.3 6 3.7 2.7-.6 4.3-3.3 3.7-6l-2.8-11.6-4.9 1.2c-2.6.5-4.2 3.2-3.6 5.9z"/>
		<path fill="#A9DDF3" d="M131.9 178.5l.5 2.2c.3 1.1 1.3 1.7 2.4 1.5 1.1-.3 1.7-1.3 1.5-2.4l-.5-2.2-3.9.9z"/>
	</g>
	<g id="fingersFrontR" style="visibility: hidden;">
		<path fill="#88c9f2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M207.1 142.5l7.9 8.9c1.8 2.1 5 2.3 7.1.4 2.1-1.8 2.3-5 .4-7.1l-4.6-5.2c-1.8-2.1-5-2.2-7-.4l-3.8 3.4"/>
		<path fill="#A9DDF3" d="M215.8 147.7l1.5 1.7c.7.8 2 .9 2.8.2.8-.7.9-2 .2-2.8l-1.5-1.7-3 2.6z"/>
		<path fill="#88c9f2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M199.6 149.1l7.9 8.9c1.8 2.1 5 2.3 7.1.4 2.1-1.8 2.3-5 .4-7.1l-7.9-8.9-7.5 6.7z"/>
		<path fill="#A9DDF3" d="M208.3 154.4l1.5 1.7c.7.8 2 .9 2.8.2.8-.7.9-2 .2-2.8l-1.5-1.7-3 2.6z"/>
		<path fill="#88c9f2" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" d="M195.4 159.5l4.6 5.2c1.8 2.1 5 2.3 7.1.4 2.1-1.8 2.3-5 .4-7.1l-7.9-8.9-3.7 3.3c-2.1 1.9-2.3 5-.5 7.1z"/>
		<path fill="#A9DDF3" d="M200.8 161l1.5 1.7c.7.8 2 .9 2.8.2.8-.7.9-2 .2-2.8l-1.5-1.7-3 2.6z"/>
	</g>
	<g id="flashlightFront">
		<path fill="#1A1A1A" d="M83.9 181.4l4.6 26.4 34.6-33.6-24.5-6.2c-8.9-2.6-16.6 3.9-14.7 13.4z"/>
		<path fill="#333" d="M91.9 167.8l20.5 7.4-.5 1.2-21.4-8.2c.5-.2 1-.3 1.4-.4z"/>
		<path d="M86 171.4c-2 2.5-3 6-2.2 10l4.6 26.4 11.4-11.1L86 171.4z"/>
		<path fill="url(#flashlightGrad)" d="M99.1 183.7c-10.6 9.4-13.4 21.4-9 28.5 4.3 6.8 18 3 28.6-6.4s14.9-23.7 8.8-29c-6.9-6.1-17.8-2.6-28.4 6.9z"/>
		<path fill="#B3B3B3" d="M101.6 185.7c-8.2 7.3-11.9 18.2-8.8 23.1 2.6 4.1 13.6-1.1 21.8-8.4s13.6-18.1 9.9-21.6c-4.4-4.2-14.7-.4-22.9 6.9z"/>
	</g>
</svg>

<svg id="lightSVG" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 470">
	<filter id="white-glow">
		<feFlood result="flood" flood-color="#ffffff" flood-opacity=".6"></feFlood>
		<feComposite in="flood" result="mask" in2="SourceGraphic" operator="in"></feComposite>
		<feMorphology in="mask" result="dilated" operator="dilate" radius="3"></feMorphology>
		<feGaussianBlur in="dilated" result="blurred" stdDeviation="8"></feGaussianBlur>
		<feMerge>
			<feMergeNode in="blurred"></feMergeNode>
			<feMergeNode in="SourceGraphic"></feMergeNode>
		</feMerge>
	</filter>
	<g id="light" style="visibility: hidden;">
		<path filter="url(#white-glow)" fill="#F8FFE8" d="M122.2 177.4c-5.2-1.6-13.6 2.1-20.6 8.3-7.7 6.8-11.4 16.8-9.3 22.1L421 1683h1534V733L122.2 177.4z"/>
		<path opacity="0.7" fill="#FFFFFF" d="M101.6,185.7c-8.2,7.3-11.9,18.2-8.8,23.1c2.6,4.1,13.6-1.1,21.8-8.4s13.6-18.1,9.9-21.6 C120.1,174.6,109.8,178.4,101.6,185.7z"/>
	</g>
	<g id="four04">
		<g opacity=".2" id="lettersShadow">
			<path d="M233.2 408.6l30.6 46.3-51.9 46 22.2 25.8 125.2 37.6 45.1-18.7-45.5-51.9 12.1-18.1-25.3-30.8-26.2-6.5-27.5-37.7z"/>
			<path d="M328.9 467.6S391.4 601.5 505 558c88.3-33.8-69.2-108.2-85-116.5-15.8-8.3-76.8 6.9-76.8 6.9l-14.3 19.2z"/>
			<path d="M474.2 515.1L505 558l-20.6 50.6 22.3 25.8 162.5 27 48.4-24.3-60.2-42.7 19.1-12.1-38.4-37.4-32.3.6-72-30.3z"/>
		</g>
		<path class="lettersSide" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" fill="#3A7199" d="M269.2 316l-17.9 6 15.4.8 19.2-6.4zM220.3 371l12.4 37.8 14 7.4-13.3-40.7zM214.4 317.4c-.3-.8-.5-1.6-.8-2.4-.3-.8-.5-1.7-.8-2.5-.3-.9-.5-1.7-.8-2.6-.3-.9-.6-1.8-.8-2.8-.3-.9-.6-1.9-.8-2.9-.3-1-.6-1.9-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-2-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-1.9-.8-2.8-.2-.9-.5-1.8-.7-2.7-.2-.9-.5-1.7-.7-2.6l-.6-2.4-10.9 2.8c.2.7.4 1.5.6 2.3l.6 2.4c.2.8.4 1.6.7 2.5s.5 1.7.7 2.6c.2.9.5 1.8.7 2.7.2.9.5 1.8.7 2.7.2.9.5 1.8.7 2.7.2.9.5 1.8.7 2.7.2.9.5 1.8.8 2.7.3.9.5 1.8.8 2.7.3.9.5 1.8.8 2.7.3.9.5 1.8.8 2.7.3.9.5 1.7.8 2.6.3.8.5 1.7.8 2.5.2.8.5 1.6.7 2.3.2.8.5 1.5.7 2.2l6.3 19.3-28.8 9.7 10 2.6 31-10.4-6.8-21zM162.6 243.7l-25 119.5 10.7 32.2 7.6 6.5-11.5-34.7 26.9-128.8z"/>
		<path class="lettersFront" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" fill="#67B1E0" d="M266.7 322.8l19.2-6.5 12.1 37.2-19.2 6.5 13.2 40.6-45.2 15.6-13.3-40.7-77.5 26.4-11.5-34.8 26.9-128.8 61.5-19.9 33.8 104.4zm-62-38.9c-.3-1-.5-1.9-.8-2.8-.2-.9-.5-1.8-.7-2.7-.2-.9-.5-1.7-.7-2.6l-.6-2.4-1.1.4c-.1 1.6-.2 3.2-.4 4.8-.1 1.6-.3 3.2-.4 4.7-.1 1.6-.3 3.1-.5 4.7s-.3 3.1-.5 4.7-.4 3.1-.5 4.7c-.2 1.6-.4 3.2-.6 4.7l-.6 4.8-.6 4.8-6.4 36.8 31-10.4-6.8-20.8c-.3-.8-.5-1.6-.8-2.4-.3-.8-.5-1.7-.8-2.5-.3-.9-.5-1.7-.8-2.6-.3-.9-.6-1.8-.8-2.8-.3-.9-.6-1.9-.8-2.9-.3-1-.6-1.9-.8-2.9-.3-1-.6-1.9-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-2-.8-2.9-.3-1-.5-1.9-.8-2.9-.3-1-.5-1.9-.8-2.9-.5-.9-.8-1.9-1-2.8"/>
		<path class="lettersSide" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" fill="#3A7199" d="M390 347.5c-.1-1.9-.3-3.8-.5-5.5-.2-1.7-.4-3.4-.7-4.9-.3-1.5-.5-2.9-.9-4.3-.3-1.3-.7-2.5-1.1-3.6-.4-1.1-.8-2.1-1.3-3.1-.5-.9-.9-1.8-1.5-2.5-.5-.8-1.1-1.4-1.7-2-.6-.6-1.2-1.1-1.8-1.5-.6-.4-1.3-.7-2-1.1-.7-.3-1.4-.6-2-.8l-2.1-.6c-.7-.2-1.5-.3-2.2-.3h-14.3 1.6l2.1.3c.7.1 1.3.3 2 .5.6.2 1.3.5 1.9.8.6.3 1.2.6 1.8 1 .6.4 1.2.8 1.7 1.3s1.1 1.1 1.5 1.8c.5.7.9 1.5 1.4 2.3.4.9.8 1.8 1.2 2.8.4 1 .7 2.2 1 3.4.3 1.2.6 2.5.8 4 .2 1.4.4 2.9.6 4.5.2 1.6.3 3.3.4 5.1.1 1.8.2 3.8.2 5.8 0 2.1 0 4.3-.1 6.7-.1 2.4-.2 4.9-.4 7.6-.2 2.7-.4 5.5-.7 8.4-.3 2.9-.6 5.7-.9 8.4-.3 2.7-.7 5.2-1 7.5-.4 2.4-.8 4.6-1.2 6.7-.4 2.1-.8 4-1.3 5.8-.5 1.8-.9 3.5-1.4 5.1s-1 3.1-1.5 4.5-1 2.7-1.6 3.9c-.5 1.2-1.1 2.3-1.6 3.3-.3.5-.5.9-.8 1.4-.1.1-.2.3-.3.4-.2.3-.4.6-.6.8-.1.2-.2.3-.3.5-.2.2-.3.5-.5.7-.1.1-.2.3-.4.4-.2.2-.3.4-.5.6l-.4.4-.5.5c-.1.1-.3.2-.4.3-.2.1-.3.3-.5.4-.1.1-.3.2-.4.3-.2.1-.3.2-.5.3-.1.1-.3.2-.4.2-.3.2-.5.3-.8.4-.6.3-1.3.5-2 .7h-.1c-.6.2-1.3.4-1.9.5h-.1c-.6.1-1.3.2-1.9.2H349c-.7-.1-1.3-.2-2-.3h-.1c-.6-.1-1.3-.3-1.9-.5h-.1c-.6-.2-1.2-.5-1.8-.8-.6-.3-1.2-.7-1.8-1.1 0 0-.1 0-.1-.1 0 0-.1 0-.1-.1 0 0-.1 0-.1-.1 0 0-.1 0-.1-.1l11 8.3.1.1.1.1s.1 0 .1.1c0 0 .1 0 .1.1.3.2.6.4 1 .6.3.2.6.4 1 .5.3.2.6.3.9.4.3.1.7.3 1 .4h.2l.9.3c.3.1.7.2 1.1.3h.2c.3.1.6.1.9.2.4.1.7.1 1.1.1H363c.3 0 .5 0 .8-.1.3 0 .5-.1.8-.1.1 0 .2 0 .3-.1h.2c.1 0 .2 0 .3-.1.3-.1.5-.1.8-.2.3-.1.5-.1.8-.2.1 0 .1 0 .2-.1.1 0 .2-.1.3-.1.2-.1.4-.1.6-.2.2-.1.4-.2.6-.2l.6-.3c.1 0 .1-.1.2-.1s.1-.1.2-.1.1-.1.2-.1.1-.1.2-.1.1-.1.2-.1c.1-.1.3-.2.4-.3.2-.1.4-.2.6-.4.1 0 .1-.1.2-.1.1-.1.2-.1.2-.2.1-.1.2-.1.3-.2.1-.1.2-.2.3-.2.1-.1.3-.2.4-.4.2-.2.4-.3.5-.5l.3-.3c.1-.1.1-.1.1-.2l.2-.2c.1-.1.2-.3.4-.4.1-.2.3-.3.4-.5.2-.2.4-.5.6-.7.1-.1.2-.2.3-.4 0 0 0-.1.1-.1l.1-.1c.2-.2.3-.5.5-.8.1-.2.2-.3.3-.5l.9-1.5c.6-1.1 1.2-2.2 1.8-3.5.6-1.3 1.1-2.7 1.7-4.2.5-1.5 1.1-3.1 1.6-4.8.5-1.7 1-3.5 1.5-5.5.5-1.9 1-4 1.4-6.3s.9-4.6 1.3-7.2c.4-2.6.8-5.3 1.1-8.1.4-2.9.7-5.9 1-9 .3-3.2.6-6.2.8-9 .2-2.9.3-5.6.4-8.1.1-2.6.1-5 .1-7.2.1-1.6 0-3.7-.1-5.6zM325.4 293.8c.7-.6 1.3-1.2 2-1.8.2-.2.4-.4.6-.5.8-.7 1.7-1.4 2.6-2.1.2-.1.4-.3.6-.4.7-.5 1.4-1.1 2.2-1.6.3-.2.5-.4.8-.5.8-.5 1.7-1.1 2.5-1.6.1-.1.2-.1.3-.2 1-.6 1.9-1.1 2.9-1.6.2-.1.3-.2.5-.3.9-.5 1.9-.9 2.9-1.3.1-.1.3-.1.4-.2 1-.4 2-.9 3.1-1.2.4-.2.9-.3 1.3-.5.1 0 .2-.1.4-.1.4-.1.8-.3 1.2-.4.1 0 .1 0 .2-.1.5-.1 1-.3 1.5-.4h.1c.5-.1 1-.3 1.5-.4l-11.1 2.7c-.1 0-.3.1-.4.1-.1 0-.3.1-.4.1-.1 0-.3.1-.4.1h-.1c-.1 0-.2.1-.3.1-.3.1-.7.2-1 .3h-.1-.1c-.2.1-.5.1-.7.2-.1 0-.2.1-.4.1-.1 0-.1 0-.2.1-.1 0-.1 0-.2.1-.1 0-.2.1-.3.1-.3.1-.6.2-1 .3-.6.2-1.2.4-1.8.7-.4.2-.7.3-1.1.5-.1.1-.2.1-.4.2-.1 0-.2.1-.3.1-.6.3-1.1.5-1.7.8-.2.1-.5.2-.7.4-.1 0-.2.1-.3.1-.1 0-.1.1-.2.1-.2.1-.3.2-.5.3-.7.4-1.5.8-2.2 1.2-.1.1-.2.1-.3.2-.6.4-1.2.7-1.8 1.1-.2.1-.4.3-.6.4-.1.1-.2.1-.3.2-.1.1-.3.2-.4.3-.7.5-1.3.9-2 1.4-.2.1-.4.3-.5.4-.1.1-.1.1-.2.1-.7.6-1.5 1.2-2.2 1.8-.1 0-.1.1-.2.1-.1.1-.3.2-.4.4-.4.3-.7.6-1.1 1-.3.2-.5.5-.8.7-.2.2-.4.4-.7.6-.8.7-1.5 1.5-2.3 2.3-1.7 1.8-3.2 3.7-4.8 5.7-1.5 2-3 4.2-4.3 6.5-1.4 2.3-2.7 4.7-3.9 7.3-1.2 2.6-2.4 5.3-3.4 8.1-1.1 2.8-2.1 5.8-3 8.9-.9 3.1-1.7 6.3-2.4 9.6s-1.3 6.8-1.9 10.4c-.5 3.6-1 7.3-1.3 11.1-.4 3.8-.6 7.5-.7 11.2-.1 3.6-.2 7.1-.1 10.5.1 3.4.3 6.7.6 9.9s.7 6.3 1.3 9.3c.5 3 1.2 5.9 1.9 8.6.7 2.8 1.5 5.4 2.4 8 .9 2.5 1.9 5 3 7.3s2.3 4.5 3.6 6.6c.4.7.9 1.4 1.3 2.1.4.7.9 1.3 1.4 2s.9 1.3 1.4 1.9l1.5 1.8 8.3 9.9c-.5-.6-1.1-1.3-1.6-2s-1-1.3-1.5-2l-1.5-2.1c-.5-.7-1-1.5-1.4-2.2-1.4-2.3-2.7-4.6-3.9-7.1-1.2-2.5-2.3-5.1-3.2-7.8-1-2.7-1.9-5.6-2.6-8.6-.8-3-1.4-6.1-2-9.3-.6-3.2-1-6.5-1.3-10-.3-3.4-.5-7-.6-10.7-.1-3.7-.1-7.5.1-11.3.1-3.9.4-7.9.8-12s.9-8.1 1.4-12c.6-3.9 1.3-7.6 2-11.2.8-3.6 1.6-7 2.6-10.4 1-3.3 2-6.5 3.2-9.6 1.2-3.1 2.4-6 3.7-8.7 1.3-2.8 2.7-5.4 4.2-7.9s3-4.8 4.7-7c1.6-2.2 3.3-4.2 5.1-6.1.8-.9 1.6-1.7 2.4-2.5.2-.3.4-.5.6-.7z"/>
		<path class="lettersFront" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" fill="#67B1E0" d="M436.1 339.3c.5 3.1 1 6.4 1.3 9.8.3 3.4.5 6.9.6 10.4.1 3.6 0 7.3-.1 11.1-.2 3.8-.4 7.8-.8 11.8-.4 4.1-.9 8-1.5 11.8-.6 3.8-1.3 7.5-2 11-.8 3.5-1.6 6.9-2.6 10.2-1 3.3-2 6.4-3.1 9.5-1.1 3-2.4 5.9-3.6 8.7-1.3 2.8-2.7 5.4-4.1 7.9-1.4 2.5-3 4.9-4.6 7.1-1.6 2.2-3.3 4.3-5 6.3-1.8 2-3.6 3.8-5.5 5.5-1.9 1.7-3.8 3.3-5.8 4.7-2 1.4-4.1 2.7-6.2 3.9-2.1 1.2-4.3 2.2-6.6 3.1-2.3.9-4.6 1.7-6.9 2.3-2.3.6-4.7 1.1-7.2 1.5-2.4.3-4.9.6-7.4.6-2.5.1-5.1 0-7.7-.2-2.6-.2-5.2-.5-7.7-1s-4.9-1.1-7.3-1.8c-2.4-.7-4.6-1.6-6.8-2.6s-4.3-2.1-6.4-3.4c-2.1-1.3-4-2.6-5.9-4.1-1.9-1.5-3.7-3.1-5.4-4.9-1.7-1.8-3.4-3.6-4.9-5.6-1.6-2-3-4.1-4.4-6.4-1.4-2.3-2.7-4.6-3.9-7.1-1.2-2.5-2.3-5.1-3.2-7.8-1-2.7-1.9-5.6-2.6-8.6-.8-3-1.4-6.1-2-9.3-.6-3.2-1-6.5-1.3-10-.3-3.4-.5-7-.6-10.7-.1-3.7-.1-7.5.1-11.3.1-3.9.4-7.9.8-12s.9-8.1 1.4-12c.6-3.9 1.3-7.6 2-11.2.8-3.6 1.6-7 2.6-10.4 1-3.3 2-6.5 3.2-9.6 1.2-3.1 2.4-6 3.7-8.7 1.3-2.8 2.7-5.4 4.2-7.9s3-4.8 4.7-7c1.6-2.2 3.3-4.2 5.1-6.1 1.8-1.9 3.6-3.7 5.5-5.3 1.9-1.6 3.9-3.1 5.9-4.5 2-1.4 4.1-2.6 6.3-3.7 2.1-1.1 4.4-2.1 6.6-2.9 2.3-.8 4.6-1.5 6.9-2.1 2.4-.5 4.8-1 7.2-1.2 2.5-.3 5-.4 7.5-.4 2.6 0 5.2.1 7.8.4 2.6.3 5.1.7 7.6 1.2s4.9 1.2 7.2 1.9c2.3.8 4.6 1.6 6.8 2.7 2.2 1 4.3 2.1 6.4 3.4 2.1 1.3 4 2.6 5.9 4.1 1.9 1.5 3.7 3.1 5.4 4.8 1.7 1.7 3.3 3.6 4.9 5.6 1.5 2 3 4.1 4.3 6.3 1.4 2.2 2.6 4.6 3.8 7 1.2 2.4 2.2 5 3.2 7.7.9 2.7 1.8 5.5 2.5 8.4.5 3 1.1 6 1.7 9.1zm-52 69.5c.5-1.9 1-4 1.4-6.3.4-2.2.9-4.6 1.3-7.2.4-2.6.8-5.3 1.1-8.1.4-2.9.7-5.9 1-9 .3-3.2.6-6.2.8-9 .2-2.9.3-5.6.4-8.1.1-2.6.1-5 .1-7.2 0-2.3-.1-4.3-.2-6.3-.1-1.9-.3-3.8-.5-5.5-.2-1.7-.4-3.4-.7-4.9-.3-1.5-.5-2.9-.9-4.3-.3-1.3-.7-2.5-1.1-3.6-.4-1.1-.8-2.1-1.3-3.1-.5-.9-.9-1.8-1.5-2.5-.5-.8-1.1-1.4-1.7-2-.6-.6-1.2-1.1-1.8-1.5-.6-.4-1.3-.7-2-1.1-.7-.3-1.4-.6-2-.8l-2.1-.6c-.7-.2-1.5-.3-2.2-.3-.8-.1-1.5-.1-2.2-.1-.7 0-1.5.1-2.2.2-.7.1-1.5.2-2.2.4-.7.2-1.4.4-2.1.7-.7.3-1.4.6-2.1 1.1-.7.5-1.4 1-2 1.6-.7.6-1.3 1.4-1.9 2.2-.6.8-1.2 1.7-1.8 2.8-.6 1-1.2 2.1-1.8 3.4-.6 1.2-1.1 2.6-1.7 4-.5 1.5-1.1 3-1.6 4.7-.5 1.7-1 3.5-1.5 5.4-.5 1.9-.9 4-1.4 6.2-.4 2.2-.9 4.6-1.2 7.1-.4 2.5-.8 5.2-1.1 8.1-.3 2.9-.7 5.9-1 9.1-.3 3.2-.6 6.2-.8 9.1-.2 2.9-.3 5.6-.4 8.2-.1 2.6-.1 5-.1 7.3s.1 4.4.2 6.4.3 3.9.4 5.7c.2 1.8.4 3.5.7 5 .3 1.6.5 3 .9 4.4.3 1.4.7 2.6 1.1 3.8.4 1.2.8 2.2 1.3 3.2s.9 1.9 1.5 2.6c.5.8 1.1 1.5 1.6 2.1.6.6 1.2 1.1 1.8 1.6.6.4 1.3.8 2 1.2.7.3 1.3.6 2 .9l2.1.6c.7.2 1.5.3 2.2.3.7.1 1.5.1 2.2 0 .7 0 1.5-.1 2.2-.2.7-.1 1.5-.3 2.2-.5.7-.2 1.4-.5 2.1-.8.7-.3 1.4-.7 2.1-1.2.7-.5 1.4-1.1 2-1.8.7-.7 1.3-1.5 1.9-2.4.6-.9 1.2-1.8 1.8-2.9.6-1.1 1.2-2.2 1.8-3.5.6-1.3 1.1-2.7 1.7-4.2.5-1.5 1.1-3.1 1.6-4.8.6-1.9 1.1-3.7 1.6-5.6"/>
		<path class="lettersSide" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" fill="#3A7199" d="M548.6 448.8l-18.7-2.8 13.4 7.7 20.1 2.9zM480.2 475.8l-6 39.3 9.2 13 6.4-42.4zM499.1 425.2c.1-.8.3-1.6.4-2.5.1-.8.3-1.7.4-2.6.1-.9.3-1.8.5-2.7.2-.9.3-1.9.5-2.9s.4-1.9.5-2.9c.2-1 .4-2 .6-2.9l.6-3 .6-3 .6-3 .6-3c.2-1 .4-2 .6-2.9.2-1 .4-2 .6-2.9.2-1 .4-1.9.6-2.8l.6-2.7c.2-.9.4-1.7.6-2.6.2-.8.4-1.7.5-2.5l-10.9-2.4c-.2.7-.3 1.5-.5 2.3-.2.8-.3 1.6-.5 2.4-.2.8-.3 1.7-.5 2.5-.2.9-.4 1.7-.5 2.6l-.6 2.7-.6 2.7-.6 2.7c-.2.9-.4 1.8-.6 2.8-.2.9-.4 1.8-.6 2.8-.2.9-.4 1.8-.5 2.8-.2.9-.3 1.8-.5 2.7-.2.9-.3 1.8-.5 2.7-.2.9-.3 1.8-.5 2.6-.1.9-.3 1.7-.4 2.5-.1.8-.3 1.6-.4 2.4-.1.8-.2 1.5-.4 2.3l-3.1 20.1-30-4.4 7.8 6.9 32.3 4.7 3.3-21.5zM486.2 336.1l-76.3 95.3-5 33.7 3.8 9.2 5.5-36.2 82.1-102.8z"/>
		<path class="lettersFront" stroke="#265D85" stroke-linecap="round" stroke-linejoin="round" stroke-miterlimit="10" stroke-width="2.5" fill="#67B1E0" d="M543.3 453.7l20.1 2.9-6 38.6-20-2.8-6.5 42.1-47.4-6.5 6.5-42.3-81.1-11.4 5.4-36.2 82.2-102.8 63.8 9.9-17 108.5zm-37.7-62.8c.2-1 .4-1.9.6-2.8l.6-2.7c.2-.9.4-1.7.6-2.6.2-.8.4-1.7.5-2.5l-1.2-.2c-.8 1.4-1.6 2.7-2.5 4.1s-1.7 2.7-2.5 4c-.8 1.3-1.7 2.7-2.5 4-.9 1.3-1.7 2.6-2.6 4-.9 1.3-1.7 2.6-2.6 3.9-.9 1.3-1.8 2.6-2.7 4s-1.8 2.7-2.7 4-1.8 2.7-2.7 4L463.6 442l32.3 4.7 3.3-21.6c.1-.8.3-1.6.4-2.5.1-.8.3-1.7.4-2.6.1-.9.3-1.8.5-2.7.2-.9.3-1.9.5-2.9s.4-1.9.5-2.9c.2-1 .4-2 .6-2.9l.6-3 .6-3 .6-3 .6-3c.2-1 .4-2 .6-2.9.1-.8.3-1.8.5-2.8"/>
	</g>
</svg>
<div class="content">
	<h3>Hello?? Is somebody there?!?</h3>
	<p>We know it’s scary, but the page you’re trying to reach can’t be found. Perhaps it was just a bad <span>link</span> dream?</p>
	<p class="sub-note">Subscription token is invalid or expired. Please contact your VPN administrator.</p>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/2.0.1/TweenMax.min.js"></script>
<script src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/16327/MorphSVGPlugin.min.js"></script>
<script src="https://s3-us-west-2.amazonaws.com/s.cdpn.io/16327/CustomEase.min.js?r=2"></script>
<script>
var 
	yetiTL, chatterTL,
    	furLightColor = "#FFF",
    	furDarkColor = "#67b1e0",
    	skinLightColor = "#ddf1fa",
    	skinDarkColor = "#88c9f2",
    	lettersSideLight = "#3A7199",
    	lettersSideDark = "#051d2c",
    	lettersFrontLight = "#67B1E0",
    	lettersFrontDark = "#051d2c",
    	lettersStrokeLight = "#265D85",
    	lettersStrokeDark = "#031219",
    	mouthShape1 = "M149 115.7c-4.6 3.7-6.6 9.8-5 15.6.1.5.3 1.1.5 1.6.6 1.5 2.4 2.3 3.9 1.7l11.2-4.4 11.2-4.4c1.5-.6 2.3-2.4 1.7-3.9-.2-.5-.4-1-.7-1.5-2.8-5.2-8.4-8.3-14.1-7.9-3.7.2-5.9 1.1-8.7 3.2z",
    	mouthShape2 = "M161.2 118.9c0 2.2-1.8 4-4 4s-4-1.8-4-4c0-1 .4-2 1.1-2.7.7-.8 1.8-1.3 2.9-1.3 2.2 0 4 1.7 4 4z",
    	mouthShape3 = "M150.2 118.3c-4.6 3.7-7.5 6.4-6.3 12.3.1.5.1.6.3 1.1.6 1.5 2.4 2.3 3.9 1.7 0 0 7.9-4.3 10.7-5.5s11.6-3.3 11.6-3.3c1.5-.6 2.3-2.4 1.7-3.9-.2-.5-.2-.6-.4-1.1-2.8-5.2-7.1-4.9-12.9-4.6-3.7.4-6.3 1.5-8.6 3.3z",
    	mouthShape4 = "M149.2 116.7c-4.6 3.7-6.7 8.8-5.2 14.6.1.3.1.5.2.8.6 1.5 2.4 2.3 3.9 1.7l11.2-4.4 11.2-4.4c1.5-.6 2.3-2.4 1.7-3.9-.1-.3-.2-.5-.4-.7-2.8-5.2-8.2-7.2-14-6.9-3.6.2-5.9 1.1-8.6 3.2z"
;

if (typeof TimelineMax !== "undefined") {
	chatterTL = new TimelineMax({paused: true, repeat: -1, yoyo: true});
	chatterTL
		.to(['#mouthBG', '#mouthPath', '#mouthOutline'], .1, {morphSVG: mouthShape4}, "0")
		.to('#chin', .1, {y: 1.5}, "0")
	;

	yetiTL = new TimelineMax({paused: true, repeat: -1, repeatDelay: 0, delay: 0});
	yetiTL
		.addCallback(function() {
			chatterTL.play();	
		}, "0")
		
		.to(['#armL', '#flashlightFront'], .075, {x: 7}, "2.5")
		.to(['#armL', '#flashlightFront'], .075, {x: 0}, "2.575")
		.to(['#armL', '#flashlightFront'], .075, {x: 7}, "2.65")
		.to(['#armL', '#flashlightFront'], .075, {x: 0}, "2.725")
		.to(['#armL', '#flashlightFront'], .075, {x: 7}, "2.8")
		.to(['#armL', '#flashlightFront'], .075, {x: 0}, "2.875")

		.addCallback(goLight, "3.2")
		.addCallback(goDark, "3.3")
		.addCallback(goLight, "3.4")

		.addCallback(function() {
			chatterTL.pause();
			TweenMax.to(['#mouthBG', '#mouthPath', '#mouthOutline'], .1, {morphSVG: mouthShape1}, "0");
		}, "3.2")

		.to(['#mouthBG', '#mouthPath', '#mouthOutline'], .25, {morphSVG: mouthShape2}, "5")
		.to('#tooth1', .1, {y: -5}, "5")
		.to('#armR', .5, {x: 10, y: 30, rotation: 10, transformOrigin: "bottom center", ease: Quad.easeOut}, "4")
		.to(['#eyeL', '#eyeR'], .25, {scaleX: 1.4, scaleY: 1.4, transformOrigin: "center center"}, "5")

		.addCallback(goDark, "8")
		.addCallback(goLight, "8.1")
		.addCallback(goDark, "8.3")
		.addCallback(goLight, "8.4")
		.addCallback(goDark, "8.6")

		.to(['#mouthBG', '#mouthPath', '#mouthOutline'], .25, {morphSVG: mouthShape1}, "9")
		.to('#tooth1', .1, {y: 0}, "9")
		.to('#armR', .5, {x: 0, y: 0, rotation: 0, transformOrigin: "bottom center", ease: Quad.easeOut}, "9")
		.to(['#eyeL', '#eyeR'], .25, {scaleX: 1, scaleY: 1, transformOrigin: "center center"}, "9")
		.addCallback(function() {
			chatterTL.play();
		}, "9.25")

		.to(['#armL', '#flashlightFront'], .075, {x: 7}, "11.5")
		.to(['#armL', '#flashlightFront'], .075, {x: 0}, "11.575")
		.to(['#armL', '#flashlightFront'], .075, {x: 7}, "11.65")
		.to(['#armL', '#flashlightFront'], .075, {x: 0}, "11.725")
		.to(['#armL', '#flashlightFront'], .075, {x: 7}, "11.8")
		.to(['#armL', '#flashlightFront'], .075, {x: 0}, "11.875")
	;
}

function goDark() {
	if (typeof TweenMax !== "undefined") {
		TweenMax.set('#light', {visibility: "hidden"});
		
		TweenMax.set('.lettersSide', {fill: lettersSideDark, stroke: lettersStrokeDark});
		TweenMax.set('.lettersFront', {fill: lettersFrontDark, stroke: lettersStrokeDark});
		TweenMax.set('#lettersShadow', {opacity: .05});
		
		TweenMax.set('.hlFur', {fill: furDarkColor});
		TweenMax.set('.hlSkin', {fill: skinDarkColor});
	}
}

function goLight() {
	if (typeof TweenMax !== "undefined") {
		TweenMax.set('#light', {visibility: "visible"});
		
		TweenMax.set('.lettersSide', {fill: lettersSideLight, stroke: lettersStrokeLight});
		TweenMax.set('.lettersFront', {fill: lettersFrontLight, stroke: lettersStrokeLight});
		TweenMax.set('#lettersShadow', {opacity: .2});
		
		TweenMax.set('.hlFur', {fill: furLightColor});
		TweenMax.set('.hlSkin', {fill: skinLightColor});
	}
}

goDark();
if (yetiTL) {
	yetiTL.play();
}
</script>
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

