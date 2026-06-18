#!/usr/bin/env python3
import http.server, json, os, re
from datetime import datetime
from urllib.parse import urlparse

BASE = os.path.dirname(os.path.abspath(__file__))


#------─ log parsers ──────────────────────────────────────────────────────────────

def extract_time(line):
    m = re.search(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}', line)
    if m: return m.group()
    m = re.search(r'\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}', line)
    if m: return m.group()
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def read_log(filename, alert_type, technique, severity):
    path = os.path.join(BASE, "logs", filename)
    alerts = []
    if not os.path.exists(path):
        return alerts
    with open(path, errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append({
                    "time":      extract_time(line),
                    "type":      alert_type,
                    "technique": technique,
                    "severity":  severity,
                    "detail":    line
                })
    return alerts

def get_alerts():
    a  = read_log("bruteforce_logs.txt",    "Brute Force",          "T1110", "HIGH")
    a += read_log("sudo_logs.txt",           "Privilege Escalation", "T1078", "CRITICAL")
    a += read_log("user_creation_logs.txt",  "Account Creation",     "T1136", "MEDIUM")
    a.sort(key=lambda x: x["time"], reverse=True)
    return a

def get_stats():
    alerts = get_alerts()
    return {
        "total":      len(alerts),
        "bruteforce": len([a for a in alerts if a["technique"] == "T1110"]),
        "escalation": len([a for a in alerts if a["technique"] == "T1078"]),
        "account":    len([a for a in alerts if a["technique"] == "T1136"]),
        "critical":   len([a for a in alerts if a["severity"]  == "CRITICAL"]),
        "high":       len([a for a in alerts if a["severity"]  == "HIGH"]),
        "medium":     len([a for a in alerts if a["severity"]  == "MEDIUM"]),
    }

def get_fp_stats():

    try:
        with open("alerts/alerts.json", "r") as f:
            alerts = json.load(f)
    except:
        alerts = []

    total = len(alerts)

    tp = sum(
        1 for a in alerts
        if a.get("review_status") == "TP"
    )

    fp = sum(
        1 for a in alerts
        if a.get("review_status") == "FP"
    )

    pending = sum(
        1 for a in alerts
        if a.get("review_status") == "Pending"
    )

    reviewed = tp + fp

    fp_rate = round(
        (fp / reviewed) * 100,
        2
    ) if reviewed > 0 else 0

    return {
        "total": total,
        "tp": tp,
        "fp": fp,
        "pending": pending,
        "fp_rate": fp_rate
    }

def get_iocs():
    path = os.path.join(BASE, "iocs", "iocs.json")
    if not os.path.exists(path): return []
    with open(path, errors="ignore") as f:
        try: return json.load(f)
        except: return []

# ── HTTP handler ─────────────────────────────────────────────────────────────

class Handler(http.server.SimpleHTTPRequestHandler):

    def do_GET(self):
        path = urlparse(self.path).path

        # API routes
        if path == "/api/alerts":
            self.send_json(get_alerts())
        elif path == "/api/stats":
            self.send_json(get_stats())
        elif path == "/api/iocs":
            self.send_json(get_iocs())
        elif path == "/api/fp_stats":
            self.send_json(get_fp_stats())
        # Serve dashboard HTML
        elif path == "/" or path == "/dashboard":
            self.serve_file(os.path.join(BASE, "dashboard", "index.html"), "text/html")

        # Static files fallback
        else:
            filepath = os.path.join(BASE, "dashboard", path.lstrip("/"))
            if os.path.exists(filepath):
                self.serve_file(filepath, "text/plain")
            else:
                self.send_error(404)

    def send_json(self, data):
        body = json.dumps(data, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type",  "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def serve_file(self, path, ctype):
        with open(path, "rb") as f:
            body = f.read()
        self.send_response(200)
        self.send_header("Content-Type",   ctype)
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass  # terminal clean rakhne ke liye

# ── start ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = 8000
    server = http.server.HTTPServer(("", port), Handler)
    print(f"\n  SOC Dashboard running → http://localhost:{port}\n")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n  Server stopped.")
