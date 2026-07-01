"""
VulnScan - Web Application Vulnerability Scanner
Main Flask Application
"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for
from flask_cors import CORS
import threading
import uuid
import json
import os
from datetime import datetime

from crawler import Crawler
from scanner import Scanner
from security_headers import SecurityHeaderScanner
from cookies import CookieScanner
from report_generator import ReportGenerator

app = Flask(__name__)
CORS(app)
app.secret_key = os.urandom(24)

# ── In-memory scan store (swap for Redis/SQLite in production) ──
scans = {}


# ─────────────────────────── ROUTES ───────────────────────────

@app.route("/")
def index():
    return render_template("index.html", scans=list(scans.values()))


@app.route("/report/<scan_id>")
def report_page(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return "Scan not found", 404
    return render_template("report.html", scan=scan, summary=_summary(scan["findings"]))


# ─────────────────────────── API ──────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
def start_scan():
    data = request.json or {}
    url    = data.get("url", "").strip()
    checks = data.get("checks", ["xss", "sqli", "csrf", "headers", "cookies", "openredirect"])
    depth  = int(data.get("depth", 2))
    timeout = int(data.get("timeout", 10))
    headers = data.get("headers", {})

    if not url:
        return jsonify({"error": "Target URL is required"}), 400

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "id":           scan_id,
        "url":          url,
        "status":       "running",
        "progress":     0,
        "phase":        "init",
        "logs":         [],
        "findings":     [],
        "started_at":   datetime.now().isoformat(),
        "completed_at": None,
        "error":        None,
    }

    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, url, checks, depth, timeout, headers),
        daemon=True,
    )
    thread.start()
    return jsonify({"scan_id": scan_id})


@app.route("/api/scan/<scan_id>/status")
def scan_status(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan)


@app.route("/api/scan/<scan_id>/findings")
def scan_findings(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(scan["findings"])


@app.route("/api/scan/<scan_id>/report/json")
def report_json(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify({
        "scan_id":      scan_id,
        "target":       scan["url"],
        "started_at":   scan["started_at"],
        "completed_at": scan["completed_at"],
        "findings":     scan["findings"],
        "summary":      _summary(scan["findings"]),
    })


@app.route("/api/scan/<scan_id>/report/html")
def report_html(scan_id):
    scan = scans.get(scan_id)
    if not scan:
        return "Scan not found", 404
    gen  = ReportGenerator(scan)
    path = gen.generate_html()
    return send_file(path, as_attachment=True, download_name="vulnscan-report.html")


@app.route("/api/scans")
def list_scans():
    result = [
        {
            "id":            s["id"],
            "url":           s["url"],
            "status":        s["status"],
            "started_at":    s["started_at"],
            "completed_at":  s["completed_at"],
            "finding_count": len(s["findings"]),
            "summary":       _summary(s["findings"]),
        }
        for s in scans.values()
    ]
    result.sort(key=lambda x: x["started_at"], reverse=True)
    return jsonify(result)


@app.route("/api/scan/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    if scan_id in scans:
        del scans[scan_id]
        return jsonify({"deleted": True})
    return jsonify({"error": "Not found"}), 404


# ─────────────────────────── HELPERS ──────────────────────────

def _summary(findings):
    s = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s[f.get("severity", "INFO")] = s.get(f.get("severity", "INFO"), 0) + 1
    return s


def _log(scan_id, msg, level="info"):
    if scan_id in scans:
        scans[scan_id]["logs"].append({
            "time":    datetime.now().strftime("%H:%M:%S"),
            "message": msg,
            "level":   level,
        })


def _add_finding(scan_id, finding):
    if scan_id in scans:
        finding.setdefault("id",            str(uuid.uuid4()))
        finding.setdefault("discovered_at", datetime.now().isoformat())
        scans[scan_id]["findings"].append(finding)


# ─────────────────────────── SCAN RUNNER ──────────────────────

def _run_scan(scan_id, url, checks, depth, timeout, custom_headers):
    try:
        scan = scans[scan_id]

        # ── Phase 1 · Crawl ──────────────────────────────────
        scan["phase"]    = "crawl"
        scan["progress"] = 5
        _log(scan_id, f"Starting scan on: {url}")
        _log(scan_id, f"Checks enabled: {', '.join(checks)}")

        crawler = Crawler(url, depth=depth, timeout=timeout, headers=custom_headers)
        _log(scan_id, "Crawling target for URLs and forms …")
        urls, forms = crawler.crawl()
        scan["progress"] = 20
        _log(scan_id, f"Discovered {len(urls)} URL(s) and {len(forms)} form(s)", "ok")

        # ── Phase 2 · Injection tests ─────────────────────────
        scan["phase"] = "inject"
        scanner = Scanner(timeout=timeout, headers=custom_headers)

        if "xss" in checks:
            scan["progress"] = 30
            _log(scan_id, "Testing for Cross-Site Scripting (XSS) …")
            for v in scanner.scan_xss(urls, forms):
                _add_finding(scan_id, v)
                _log(scan_id, f"[XSS] {v['url']} param={v['param']}", "warn")
            scan["progress"] = 45

        if "sqli" in checks:
            _log(scan_id, "Testing for SQL Injection …")
            for v in scanner.scan_sqli(urls, forms):
                _add_finding(scan_id, v)
                _log(scan_id, f"[SQLi] {v['url']} param={v['param']}", "error")
            scan["progress"] = 60

        if "openredirect" in checks:
            _log(scan_id, "Testing for Open Redirects …")
            for v in scanner.scan_open_redirect(urls):
                _add_finding(scan_id, v)
                _log(scan_id, f"[Redirect] {v['url']}", "warn")

        if "cmdinjection" in checks:
            _log(scan_id, "Testing for Command Injection …")
            for v in scanner.scan_command_injection(forms):
                _add_finding(scan_id, v)
                _log(scan_id, f"[CMDi] {v['url']} param={v['param']}", "error")

        if "pathtraversal" in checks:
            _log(scan_id, "Testing for Path Traversal …")
            for v in scanner.scan_path_traversal(urls):
                _add_finding(scan_id, v)
                _log(scan_id, f"[PathTraversal] {v['url']}", "warn")

        if "csrf" in checks:
            _log(scan_id, "Checking for CSRF vulnerabilities …")
            for v in scanner.scan_csrf(forms):
                _add_finding(scan_id, v)
                _log(scan_id, f"[CSRF] {v['url']}", "warn")

        scan["progress"] = 70

        # ── Phase 3 · Passive header / cookie checks ──────────
        scan["phase"] = "passive"

        if "headers" in checks:
            _log(scan_id, "Checking security headers …")
            hdr_scanner = SecurityHeaderScanner(timeout=timeout, headers=custom_headers)
            for v in hdr_scanner.scan(url):
                _add_finding(scan_id, v)
                _log(scan_id, f"[Header] Missing: {v['param']}", "warn")
            scan["progress"] = 85

        if "cookies" in checks:
            _log(scan_id, "Checking cookie security attributes …")
            ck_scanner = CookieScanner(timeout=timeout, headers=custom_headers)
            for v in ck_scanner.scan(url):
                _add_finding(scan_id, v)
                _log(scan_id, f"[Cookie] {v['name']}", "warn")

        # ── Phase 4 · Done ────────────────────────────────────
        scan["phase"]        = "complete"
        scan["progress"]     = 100
        scan["status"]       = "completed"
        scan["completed_at"] = datetime.now().isoformat()
        _log(scan_id, f"Scan complete — {len(scan['findings'])} finding(s) total.", "ok")

    except Exception as exc:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"]  = str(exc)
        _log(scan_id, f"Scan error: {exc}", "error")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
