#!/usr/bin/env python3
"""
Interactive Testing Web Server & Static File Server for AFFERENT.
Listens on port 8089.
Serves:
1. GET / or /live_tester.html -> Interactive Web Testing Portal for Laptop Browser
2. POST /api/scan -> Live ML Scan API (BiLSTM + Stacker XGBoost + VT Pool)
3. Static Files -> All files in /home/flyingsundaman/Human_Firewall/reports (live_dashboard.html, CSV, logs)
"""

import sys
import json
import time
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
from run_url_scan_test import scan_single_url

HTML_PORTAL = """<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AFFERENT · Live URL Scanner Testing Portal</title>
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --border: #1f2937;
      --accent: #3b82f6;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --green: #10b981;
      --red: #ef4444;
      --yellow: #f59e0b;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      padding: 30px 20px;
      display: flex;
      justify-content: center;
      min-height: 100vh;
    }
    .container {
      width: 100%;
      max-width: 880px;
    }
    .header {
      margin-bottom: 25px;
      border-bottom: 1px solid var(--border);
      padding-bottom: 20px;
    }
    .header h1 {
      font-size: 24px;
      font-weight: 700;
      color: #fff;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .header p {
      color: var(--text-muted);
      font-size: 14px;
      margin-top: 6px;
    }
    .nav-links {
      margin-top: 12px;
      display: flex;
      gap: 15px;
      font-size: 13px;
    }
    .nav-links a {
      color: var(--accent);
      text-decoration: none;
    }
    .nav-links a:hover { text-decoration: underline; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 24px;
      margin-bottom: 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.4);
    }
    .input-group {
      display: flex;
      gap: 10px;
      margin-bottom: 15px;
    }
    input[type="text"] {
      flex: 1;
      background: #030712;
      border: 1px solid #374151;
      border-radius: 8px;
      padding: 14px 16px;
      color: #fff;
      font-size: 15px;
      outline: none;
      transition: border 0.2s;
    }
    input[type="text"]:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2);
    }
    button.btn-scan {
      background: var(--accent);
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 0 24px;
      font-weight: 600;
      font-size: 15px;
      cursor: pointer;
      display: flex;
      align-items: center;
      gap: 8px;
      transition: background 0.2s;
    }
    button.btn-scan:hover { background: #2563eb; }
    button.btn-scan:disabled { opacity: 0.6; cursor: not-allowed; }
    .quick-samples {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
      font-size: 13px;
      color: var(--text-muted);
    }
    .sample-pill {
      background: #1f2937;
      color: #d1d5db;
      padding: 5px 12px;
      border-radius: 16px;
      cursor: pointer;
      transition: all 0.2s;
      border: 1px solid transparent;
    }
    .sample-pill:hover {
      background: #374151;
      color: #fff;
      border-color: var(--accent);
    }
    .sample-pill.threat { color: #fca5a5; }
    .sample-pill.benign { color: #86efac; }
    
    /* Result Section */
    #result-box { display: none; }
    .verdict-banner {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 18px 20px;
      border-radius: 10px;
      margin-bottom: 20px;
    }
    .verdict-banner.BLOCK { background: rgba(239, 68, 68, 0.15); border: 1px solid var(--red); color: #fca5a5; }
    .verdict-banner.ALLOW { background: rgba(16, 185, 129, 0.15); border: 1px solid var(--green); color: #86efac; }
    .verdict-banner.REVIEW { background: rgba(245, 158, 11, 0.15); border: 1px solid var(--yellow); color: #fde68a; }
    
    .verdict-title { font-size: 20px; font-weight: 800; display: flex; align-items: center; gap: 8px; }
    .verdict-sub { font-size: 13px; color: var(--text-muted); margin-top: 4px; }
    .latency-badge {
      font-size: 12px;
      background: rgba(0,0,0,0.4);
      padding: 4px 10px;
      border-radius: 20px;
      font-family: monospace;
    }
    
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 15px;
      margin-bottom: 20px;
    }
    .metric-card {
      background: #0b1120;
      border: 1px solid #1e293b;
      border-radius: 8px;
      padding: 16px;
    }
    .metric-card .title { font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; color: var(--text-muted); margin-bottom: 6px; }
    .metric-card .val { font-size: 18px; font-weight: 700; color: #fff; }
    .metric-card .detail { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
    
    .loader {
      display: none;
      text-align: center;
      padding: 30px;
      color: var(--text-muted);
      font-size: 14px;
    }
    .spinner {
      width: 32px;
      height: 32px;
      border: 3px solid rgba(255,255,255,0.1);
      border-radius: 50%;
      border-top-color: var(--accent);
      animation: spin 0.8s linear infinite;
      margin: 0 auto 12px;
    }
    @keyframes spin { to { transform: rotate(360deg); } }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>🛡️ AFFERENT URL Scanner · Testing Portal</h1>
      <p>Uji langsung model ML (Char-BiLSTM DL v5 + Stacker XGBoost Meta-Learner) & Multi-Key VirusTotal Pool</p>
      <div class="nav-links">
        <a href="/continuous_scan/live_dashboard.html" target="_blank">📊 Live 24H Dashboard</a>
        <a href="/continuous_scan/evaluation_metrics_master.csv" target="_blank">📥 Master Dataset CSV (11.342 URLs)</a>
        <a href="/benchmark_verdict_200_report.html" target="_blank">📑 200 URL Benchmark</a>
      </div>
    </div>

    <div class="card">
      <div class="input-group">
        <input type="text" id="target-url" placeholder="Ketik atau tempel URL (misal: https://klikbca-login-verifikasi.xyz)..." />
        <button class="btn-scan" id="scan-btn" onclick="executeScan()">⚡ Scan URL</button>
      </div>

      <div class="quick-samples">
        <span>Contoh Uji Cepat:</span>
        <span class="sample-pill benign" onclick="fillAndScan('https://www.bca.co.id')">BCA Resmi</span>
        <span class="sample-pill benign" onclick="fillAndScan('https://ugm.ac.id')">UGM Edu</span>
        <span class="sample-pill benign" onclick="fillAndScan('https://apispada.kemdiktisaintek.go.id')">Kemdikti Gov</span>
        <span class="sample-pill threat" onclick="fillAndScan('https://klikbca-login-verifikasi.xyz')">BCA Phishing (.xyz)</span>
        <span class="sample-pill threat" onclick="fillAndScan('https://livin-mandiri-update-tarif.online')">Mandiri Scam (.online)</span>
        <span class="sample-pill threat" onclick="fillAndScan('https://signincorrect.framer.website')">Framer SaaS Phish</span>
        <span class="sample-pill threat" onclick="fillAndScan('https://www.roblox.com.ss/users/8795648614/profile')">Roblox ccTLD Spoof (.ss)</span>
        <span class="sample-pill threat" onclick="fillAndScan('http://slot88-gacor-maxwin.xyz')">Slot88 Judi</span>
        <span class="sample-pill threat" onclick="fillAndScan('http://103.145.22.10/payload.exe')">Raw IP Malware</span>
      </div>
    </div>

    <div class="loader" id="loader">
      <div class="spinner"></div>
      <p>Menganalisis string URL & query arbitrase threat intelligence...</p>
    </div>

    <div class="card" id="result-box">
      <div id="verdict-banner" class="verdict-banner">
        <div>
          <div id="verdict-title" class="verdict-title">ALLOW</div>
          <div id="verdict-rationale" class="verdict-sub">High-confidence benign domain</div>
        </div>
        <div id="latency-badge" class="latency-badge">14.2ms</div>
      </div>

      <div class="metrics-grid">
        <div class="metric-card">
          <div class="title">1. Char-BiLSTM Deep Learning</div>
          <div id="bilstm-val" class="val">ALLOW (87%)</div>
          <div id="bilstm-type" class="detail">Tipe: Benign · Sequential Chars</div>
        </div>

        <div class="metric-card">
          <div class="title">2. Stacker XGBoost Meta-Learner</div>
          <div id="stacker-val" class="val">0.0003 (SAFE)</div>
          <div id="stacker-detail" class="detail">Tranco Verified · 11 Fitur Domain</div>
        </div>

        <div class="metric-card">
          <div class="title">3. Multi-Key VirusTotal Pool</div>
          <div id="vt-val" class="val">BYPASSED</div>
          <div id="vt-detail" class="detail">Keyakinan lokal mencukupi</div>
        </div>
      </div>
      
      <div style="font-size: 12px; color: var(--text-muted); font-family: monospace;" id="url-scanned-display"></div>
    </div>
  </div>

  <script>
    function fillAndScan(url) {
      document.getElementById('target-url').value = url;
      executeScan();
    }

    async function executeScan() {
      const input = document.getElementById('target-url');
      const url = input.value.trim();
      if (!url) return;

      const btn = document.getElementById('scan-btn');
      const loader = document.getElementById('loader');
      const box = document.getElementById('result-box');

      btn.disabled = true;
      loader.style.display = 'block';
      box.style.display = 'none';

      try {
        const resp = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: url })
        });
        const data = await resp.json();

        // Render Verdict
        const banner = document.getElementById('verdict-banner');
        banner.className = 'verdict-banner ' + data.final_decision;
        
        let sym = data.final_decision === 'ALLOW' ? '🛡️' : (data.final_decision === 'BLOCK' ? '🚨' : '⚠️');
        document.getElementById('verdict-title').innerHTML = `${sym} ${data.final_decision}`;
        document.getElementById('verdict-rationale').innerText = data.rationale;
        document.getElementById('latency-badge').innerText = `${data.latency_total_ms} ms (local: ${data.latency_local_ms}ms)`;

        // BiLSTM
        document.getElementById('bilstm-val').innerText = `${data.bilstm.action} (${data.bilstm.confidence}%)`;
        document.getElementById('bilstm-type').innerText = `Tipe Prediksi: ${data.bilstm.threat_type} · P_mal: ${data.bilstm.p_malicious}`;

        // Stacker
        document.getElementById('stacker-val').innerText = `${data.stacker.prob_malicious.toFixed(5)} (${data.stacker.verdict.toUpperCase()})`;
        document.getElementById('stacker-detail').innerText = `Tranco Top: ${data.stacker.tranco_top ? 'Ya (Trusted)' : 'Tidak (Untrusted)'}`;

        // VT
        if (data.virustotal.triggered) {
          document.getElementById('vt-val').innerText = `${data.virustotal.detections} / ${data.virustotal.total} Vendor`;
          document.getElementById('vt-detail').innerText = data.virustotal.detections >= 3 ? 'Konsensus Malicious' : 'Konsensus Clean / Low-Risk';
        } else {
          document.getElementById('vt-val').innerText = 'BYPASSED';
          document.getElementById('vt-detail').innerText = 'Hemat Kuota · Model Lokal Sangat Yakin';
        }

        document.getElementById('url-scanned-display').innerText = `Scanned Indicator: ${data.url}`;
        box.style.display = 'block';
      } catch (err) {
        alert('Gagal memproses scan: ' + err);
      } finally {
        btn.disabled = false;
        loader.style.display = 'none';
      }
    }

    document.getElementById('target-url').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executeScan();
    });
  </script>
</body>
</html>
"""

class TestServerHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(REPORTS_DIR), **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ["/", "/index.html", "/tester", "/test"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(HTML_PORTAL.encode("utf-8"))
            return
        # Otherwise serve static files from reports/
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/scan":
            length = int(self.headers.get("Content-Length", 0))
            body_raw = self.rfile.read(length).decode("utf-8")
            try:
                body = json.loads(body_raw)
                url = body.get("url", "").strip()
                if not url:
                    self._send_json({"error": "Field 'url' is required"}, 400)
                    return
                enable_vt = body.get("enable_vt", True)
                res = scan_single_url(url, enable_vt_fallback=enable_vt)
                self._send_json(res, 200)
            except Exception as e:
                self._send_json({"error": str(e)}, 500)
            return

        self._send_json({"error": "Endpoint not found"}, 404)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def _send_json(self, data: dict, status: int = 200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

def run():
    port = 8089
    server = HTTPServer(("0.0.0.0", port), TestServerHandler)
    print(f"[*] AFFERENT Interactive Testing Server running on http://0.0.0.0:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()

if __name__ == "__main__":
    run()
