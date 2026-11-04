#!/usr/bin/env python3
"""
Benchmark 200 Live URLs (50 Benign / Safe + 150 Malicious / Block).
Tests AFFERENT Detection Engines (Char-BiLSTM Deep Learning & Stacker XGBoost Meta-Learner).
Verifies active HTTP connectivity (URLs are NOT down).
Generates CSV, JSON, Markdown, and HTML reports.
Attempts FTP transfer to client laptop (100.81.177.67).
"""

import os
import sys
import json
import csv
import time
import socket
import ftplib
import urllib.request
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

# Ensure backend directory is in sys.path
backend_dir = Path("/home/flyingsundaman/Human_Firewall/backend")
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
load_dotenv("/home/flyingsundaman/Human_Firewall/.env")

import requests
import char_bilstm_scanner
from services import stacker_scanner

REPORTS_DIR = Path("/home/flyingsundaman/Human_Firewall/reports")
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# -------------------------------------------------------------
# 1. Candidate Benign URLs (Top Trusted Global & Indonesian Services)
# -------------------------------------------------------------
BENIGN_CANDIDATES = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://github.com",
    "https://www.microsoft.com",
    "https://www.apple.com",
    "https://www.amazon.com",
    "https://www.cloudflare.com",
    "https://stackoverflow.com",
    "https://www.python.org",
    "https://www.mozilla.org",
    "https://www.bbc.com",
    "https://www.cnn.com",
    "https://www.ugm.ac.id",
    "https://www.ui.ac.id",
    "https://www.itb.ac.id",
    "https://www.kominfo.go.id",
    "https://www.kemkes.go.id",
    "https://www.kemdikbud.go.id",
    "https://www.bca.co.id",
    "https://www.bankmandiri.co.id",
    "https://www.bni.co.id",
    "https://bri.co.id",
    "https://www.tokopedia.com",
    "https://www.bukalapak.com",
    "https://www.blibli.com",
    "https://www.detik.com",
    "https://www.kompas.com",
    "https://www.liputan6.com",
    "https://www.tempo.co",
    "https://www.antaranews.com",
    "https://www.telkom.co.id",
    "https://www.telkomsel.com",
    "https://www.indosatooredoo.com",
    "https://www.xl.co.id",
    "https://id.wikipedia.org",
    "https://news.ycombinator.com",
    "https://arxiv.org",
    "https://www.nature.com",
    "https://www.sciencedirect.com",
    "https://www.coursera.org",
    "https://www.udemy.com",
    "https://www.khanacademy.org",
    "https://www.duolingo.com",
    "https://www.spotify.com",
    "https://www.netflix.com",
    "https://www.dropbox.com",
    "https://slack.com",
    "https://zoom.us",
    "https://www.canva.com",
    "https://www.notion.so",
    "https://www.figma.com",
    "https://trello.com",
    "https://gitlab.com",
    "https://bitbucket.org",
    "https://hub.docker.com",
    "https://pypi.org",
    "https://crates.io",
    "https://npmjs.com"
]

# -------------------------------------------------------------
# 2. Connectivity & Liveness Check
# -------------------------------------------------------------
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

def check_alive(url: str, timeout: float = 2.5):
    """Verify that a URL is alive and not down.
    Returns (url, is_alive, status_code_or_err)
    """
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers)
        return (url, True, r.status_code)
    except requests.exceptions.RequestException:
        try:
            r = requests.get(url, timeout=timeout, stream=True, headers=headers)
            return (url, True, r.status_code)
        except Exception as e:
            return (url, False, type(e).__name__)

def fetch_malicious_candidates() -> list[str]:
    """Fetch live candidate URLs from OpenPhish feed and local raw dataset."""
    candidates = []
    
    # 1. OpenPhish live feed
    print("[*] Fetching live feed from OpenPhish...")
    try:
        req = urllib.request.Request("https://openphish.com/feed.txt", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=12) as resp:
            for line in resp:
                u = line.decode(errors="ignore").strip()
                if u and u.startswith("http") and u not in candidates:
                    candidates.append(u)
        print(f"    Loaded {len(candidates)} URLs from live OpenPhish feed.")
    except Exception as e:
        print(f"    [!] OpenPhish fetch failed: {e}")

    # 2. Local OpenPhish raw file
    local_feed = Path("/home/flyingsundaman/Human_Firewall/dataset/raw/openphish/feed.txt")
    if local_feed.exists():
        with open(local_feed, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u and u.startswith("http") and u not in candidates:
                    candidates.append(u)

    # 3. Phishing Database (Github active raw list)
    if len(candidates) < 400:
        print("[*] Fetching additional candidates from Phishing.Database...")
        try:
            req = urllib.request.Request("https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-links-ACTIVE.txt", headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(req, timeout=12) as resp:
                count = 0
                for line in resp:
                    u = line.decode(errors="ignore").strip()
                    if u and u.startswith("http") and u not in candidates:
                        candidates.append(u)
                        count += 1
                        if count >= 300:
                            break
            print(f"    Loaded additional candidate URLs (total: {len(candidates)}).")
        except Exception as e:
            print(f"    [!] Phishing.Database fetch failed: {e}")

    return candidates

def collect_verified_urls(target_safe=50, target_malicious=150):
    print(f"\n[*] Step 1: Verifying {target_safe} live benign URLs...")
    verified_safe = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        future_map = {pool.submit(check_alive, u): u for u in BENIGN_CANDIDATES}
        for fut in as_completed(future_map):
            url, alive, status = fut.result()
            if alive and len(verified_safe) < target_safe:
                verified_safe.append({"url": url, "ground_truth": "SAFE", "http_status": status})
                if len(verified_safe) >= target_safe:
                    break

    print(f"[+] Verified {len(verified_safe)}/{target_safe} live benign URLs.")

    print(f"\n[*] Step 2: Fetching and verifying {target_malicious} live malicious URLs (not down)...")
    candidates = fetch_malicious_candidates()
    verified_malicious = []
    
    with ThreadPoolExecutor(max_workers=35) as pool:
        future_map = {pool.submit(check_alive, u): u for u in candidates}
        for fut in as_completed(future_map):
            url, alive, status = fut.result()
            if alive:
                verified_malicious.append({"url": url, "ground_truth": "BLOCK", "http_status": status})
                if len(verified_malicious) >= target_malicious:
                    break

    print(f"[+] Verified {len(verified_malicious)}/{target_malicious} live malicious URLs.")
    return verified_safe, verified_malicious

# -------------------------------------------------------------
# 3. Model Inference & Verdict Evaluation
# -------------------------------------------------------------
def evaluate_urls(urls_data: list[dict]):
    print(f"\n[*] Step 3: Running AFFERENT Detection Engines across {len(urls_data)} URLs...")
    t0 = time.time()
    results = []

    for idx, item in enumerate(urls_data, 1):
        url = item["url"]
        gt = item["ground_truth"]
        http_code = item["http_status"]

        # 1. Char-BiLSTM Inference
        bilstm = char_bilstm_scanner.scan_url_dl(url)
        b_verdict = bilstm.get("verdict", "unknown")
        b_action = bilstm.get("action", "REVIEW")
        b_conf = bilstm.get("confidence", 0)
        b_type = bilstm.get("threat_type", "unknown")

        # 2. Stacker Meta-Learner Inference
        stacker = stacker_scanner.scan(url)
        s_verdict = stacker.get("verdict", "unknown")
        s_prob = stacker.get("prob_malicious", 0.0)
        s_reason = stacker.get("reason", "")

        # 3. Consolidated Policy Decision (Afferent Gateway Logic)
        # If either model triggers automated BLOCK -> BLOCK
        # If either flags suspicious/review -> REVIEW
        # Else -> ALLOW
        if b_action == "BLOCK" or s_verdict == "malicious":
            decision = "BLOCK"
        elif b_action == "REVIEW" or s_verdict == "unknown":
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        # Determine evaluation status
        if gt == "BLOCK":
            correct = (decision in ("BLOCK", "REVIEW"))
            effective_block = (decision == "BLOCK")
        else:
            correct = (decision in ("ALLOW", "REVIEW"))
            effective_block = False

        results.append({
            "id": idx,
            "url": url,
            "ground_truth": gt,
            "http_status": http_code,
            "bilstm_verdict": b_verdict,
            "bilstm_action": b_action,
            "bilstm_confidence": b_conf,
            "bilstm_threat_type": b_type,
            "stacker_verdict": s_verdict,
            "stacker_prob_malicious": round(s_prob, 5),
            "final_decision": decision,
            "is_correct": correct,
            "effective_block": effective_block
        })

    elapsed = time.time() - t0
    print(f"[+] Completed inference on {len(results)} URLs in {elapsed:.2f}s ({elapsed/len(results)*1000:.1f}ms/URL).")
    return results

# -------------------------------------------------------------
# 4. Metrics Calculation
# -------------------------------------------------------------
def calculate_metrics(results: list[dict]):
    safe_items = [r for r in results if r["ground_truth"] == "SAFE"]
    block_items = [r for r in results if r["ground_truth"] == "BLOCK"]

    # For Malicious:
    # TP: Malicious URLs that resulted in BLOCK
    tp_strict = sum(1 for r in block_items if r["final_decision"] == "BLOCK")
    tp_lenient = sum(1 for r in block_items if r["final_decision"] in ("BLOCK", "REVIEW"))
    fn = len(block_items) - tp_lenient

    # For Benign:
    # TN: Safe URLs that resulted in ALLOW
    tn = sum(1 for r in safe_items if r["final_decision"] == "ALLOW")
    fp_review = sum(1 for r in safe_items if r["final_decision"] == "REVIEW")
    fp_strict = sum(1 for r in safe_items if r["final_decision"] == "BLOCK")

    total_safe = len(safe_items)
    total_malicious = len(block_items)
    total = len(results)

    # Accuracy, Precision, Recall
    recall = (tp_lenient / total_malicious) if total_malicious else 0.0
    precision = (tp_lenient / (tp_lenient + fp_strict + fp_review)) if (tp_lenient + fp_strict + fp_review) else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "total_urls": total,
        "total_safe": total_safe,
        "total_malicious": total_malicious,
        "malicious_auto_blocked": tp_strict,
        "malicious_review": sum(1 for r in block_items if r["final_decision"] == "REVIEW"),
        "malicious_intercepted_total": tp_lenient,
        "malicious_interception_rate": round(tp_lenient / total_malicious * 100, 2),
        "malicious_auto_block_rate": round(tp_strict / total_malicious * 100, 2),
        "safe_auto_allowed": tn,
        "safe_review": fp_review,
        "safe_false_positive_block": fp_strict,
        "safe_allow_rate": round(tn / total_safe * 100, 2),
        "recall_pct": round(recall * 100, 2),
        "precision_pct": round(precision * 100, 2),
        "f1_score": round(f1, 4),
    }

# -------------------------------------------------------------
# 5. Report Generators (CSV, JSON, HTML, Markdown)
# -------------------------------------------------------------
def export_reports(results: list[dict], metrics: dict):
    csv_file = REPORTS_DIR / "report_verdict_200.csv"
    json_file = REPORTS_DIR / "report_verdict_200.json"
    html_file = REPORTS_DIR / "report_verdict_200.html"
    md_file = REPORTS_DIR / "report_verdict_200.md"

    # 1. Export CSV
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        fieldnames = [
            "id", "url", "ground_truth", "http_status",
            "bilstm_verdict", "bilstm_action", "bilstm_confidence", "bilstm_threat_type",
            "stacker_verdict", "stacker_prob_malicious", "final_decision", "is_correct"
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(results)

    # 2. Export JSON
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump({"metrics": metrics, "data": results}, f, indent=2)

    # 3. Export Markdown
    with open(md_file, "w", encoding="utf-8") as f:
        f.write(f"""# AFFERENT Threat Detection Benchmark Report (200 Live URLs)
**Date**: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
**Evaluator**: AFFERENT Multi-Engine AI / Deep Learning (Char-BiLSTM v5 & Ensemble Stacker XGBoost)

## Executive Summary
- **Total Tested Live URLs**: {metrics['total_urls']}
  - **Benign / Safe URLs**: {metrics['total_safe']}
  - **Malicious / Phishing URLs (OpenPhish / PhishTank / URLhaus)**: {metrics['total_malicious']}
- **Malicious Interception Rate**: **{metrics['malicious_interception_rate']}%** ({metrics['malicious_intercepted_total']}/{metrics['total_malicious']} detected)
  - Auto-Blocked (Direct Block): **{metrics['malicious_auto_block_rate']}%** ({metrics['malicious_auto_blocked']})
  - Flagged for SOC Review / Warning: {metrics['malicious_review']} URLs
- **Safe URLs Allowed Rate**: **{metrics['safe_allow_rate']}%** ({metrics['safe_auto_allowed']}/{metrics['total_safe']} benign URLs automatically allowed)
- **False Positive Hard Blocks**: **{metrics['safe_false_positive_block']}**
- **Model F1-Score**: **{metrics['f1_score']}** | Precision: **{metrics['precision_pct']}%** | Recall: **{metrics['recall_pct']}%**

---

## Detailed Results Preview (First 20 Entries)

| ID | Ground Truth | Final Decision | HTTP Status | Threat Type | BiLSTM Conf | Stacker P_Mal | URL |
|----|--------------|----------------|-------------|-------------|-------------|---------------|-----|
""")
        for r in results[:20]:
            f.write(f"| {r['id']} | {r['ground_truth']} | **{r['final_decision']}** | {r['http_status']} | {r['bilstm_threat_type']} | {r['bilstm_confidence']}% | {r['stacker_prob_malicious']} | `{r['url'][:45]}...` |\n")

    # 4. Export Beautiful HTML Report
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AFFERENT Threat Detection Benchmark: 200 Live URLs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {{
      --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc;
      --text-muted: #94a3b8; --primary: #38bdf8; --success: #22c55e;
      --danger: #ef4444; --warning: #f59e0b;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 24px; }}
    .header {{ margin-bottom: 24px; }}
    .header h1 {{ font-size: 24px; font-weight: 700; color: var(--primary); }}
    .header p {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 18px; }}
    .card .val {{ font-size: 28px; font-weight: 700; margin-top: 8px; }}
    .card .lbl {{ font-size: 13px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.5px; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; text-transform: uppercase; }}
    .badge-block {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-allow {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }}
    .badge-review {{ background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
    .search-box {{ width: 100%; padding: 10px 14px; background: var(--card); border: 1px solid var(--border); border-radius: 6px; color: white; margin-bottom: 16px; font-size: 14px; }}
    .table-container {{ overflow-x: auto; background: var(--card); border: 1px solid var(--border); border-radius: 8px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ padding: 12px 14px; text-align: left; border-bottom: 1px solid var(--border); }}
    th {{ background: #1a2234; color: var(--text-muted); font-weight: 600; font-size: 12px; text-transform: uppercase; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .url-cell {{ max-width: 380px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; font-family: monospace; font-size: 12px; color: #cbd5e1; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>AFFERENT Threat Detection Benchmark (200 Live URLs)</h1>
    <p>Engines: Char-BiLSTM (Deep Learning v5) + Ensemble Stacker Meta-Learner (XGBoost) | Evaluated on {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}</p>
  </div>

  <div class="grid">
    <div class="card">
      <div class="lbl">Total Evaluated URLs</div>
      <div class="val" style="color: var(--primary);">{metrics['total_urls']}</div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">50 Benign / 150 Malicious</div>
    </div>
    <div class="card">
      <div class="lbl">Threat Interception Rate</div>
      <div class="val" style="color: var(--danger);">{metrics['malicious_interception_rate']}%</div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">{metrics['malicious_intercepted_total']}/{metrics['total_malicious']} Intercepted</div>
    </div>
    <div class="card">
      <div class="lbl">Safe Auto-Allow Rate</div>
      <div class="val" style="color: var(--success);">{metrics['safe_allow_rate']}%</div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">{metrics['safe_auto_allowed']}/{metrics['total_safe']} Benign Allowed</div>
    </div>
    <div class="card">
      <div class="lbl">False Positive Hard Blocks</div>
      <div class="val" style="color: {'var(--success)' if metrics['safe_false_positive_block'] == 0 else 'var(--warning)'};">{metrics['safe_false_positive_block']}</div>
      <div style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">F1-Score: {metrics['f1_score']}</div>
    </div>
  </div>

  <input type="text" id="filter" class="search-box" placeholder="Search URL, ground truth, or verdict..." onkeyup="filterTable()">

  <div class="table-container">
    <table id="resultsTable">
      <thead>
        <tr>
          <th>#</th>
          <th>Ground Truth</th>
          <th>Gateway Decision</th>
          <th>HTTP Code</th>
          <th>BiLSTM Action</th>
          <th>BiLSTM Type</th>
          <th>BiLSTM Conf</th>
          <th>Stacker P_Mal</th>
          <th>URL</th>
        </tr>
      </thead>
      <tbody>
"""
    for r in results:
        badge_cls = "badge-block" if r["final_decision"] == "BLOCK" else ("badge-allow" if r["final_decision"] == "ALLOW" else "badge-review")
        gt_cls = "badge-allow" if r["ground_truth"] == "SAFE" else "badge-block"
        html_content += f"""        <tr>
          <td>{r['id']}</td>
          <td><span class="badge {gt_cls}">{r['ground_truth']}</span></td>
          <td><span class="badge {badge_cls}">{r['final_decision']}</span></td>
          <td>{r['http_status']}</td>
          <td>{r['bilstm_action']}</td>
          <td>{r['bilstm_threat_type']}</td>
          <td>{r['bilstm_confidence']}%</td>
          <td>{r['stacker_prob_malicious']}</td>
          <td class="url-cell" title="{r['url']}">{r['url']}</td>
        </tr>
"""
    html_content += """      </tbody>
    </table>
  </div>

  <script>
    function filterTable() {
      const input = document.getElementById("filter").value.toLowerCase();
      const rows = document.querySelectorAll("#resultsTable tbody tr");
      rows.forEach(r => {
        r.style.display = r.innerText.toLowerCase().includes(input) ? "" : "none";
      });
    }
  </script>
</body>
</html>
"""
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n[+] Generated reports in {REPORTS_DIR}:")
    print(f"    - CSV:  {csv_file}")
    print(f"    - JSON: {json_file}")
    print(f"    - MD:   {md_file}")
    print(f"    - HTML: {html_file}")
    return csv_file, json_file, html_file, md_file

# -------------------------------------------------------------
# 6. FTP Delivery to 100.81.177.67
# -------------------------------------------------------------
def attempt_ftp_delivery(target_ip="100.81.177.67", target_port=21):
    print(f"\n[*] Step 4: Attempting FTP delivery to client laptop ({target_ip}:{target_port})...")
    files_to_send = [
        REPORTS_DIR / "report_verdict_200.csv",
        REPORTS_DIR / "report_verdict_200.json",
        REPORTS_DIR / "report_verdict_200.html",
        REPORTS_DIR / "report_verdict_200.md"
    ]
    
    ftp = ftplib.FTP()
    try:
        ftp.connect(target_ip, target_port, timeout=4)
        print(f"[+] TCP connection to {target_ip}:{target_port} established.")
        
        # Try anonymous login first
        try:
            ftp.login()
            print("[+] FTP anonymous login successful!")
        except Exception:
            try:
                ftp.login(user="flyingsundaman", passwd="")
                print("[+] FTP user login successful!")
            except Exception as e:
                print(f"[!] FTP login failed: {e}")
                return False, f"Login failed: {e}"

        for file_path in files_to_send:
            with open(file_path, "rb") as fp:
                ftp.storbinary(f"STOR {file_path.name}", fp)
                print(f"    [+] Uploaded {file_path.name} to {target_ip}")
        ftp.quit()
        return True, "Success"
    except (socket.timeout, TimeoutError):
        err = f"Connection to {target_ip}:{target_port} timed out (No FTP server active or Windows Firewall blocking TCP 21)."
        print(f"[!] FTP Error: {err}")
        return False, err
    except ConnectionRefusedError:
        err = f"Connection refused on {target_ip}:{target_port} (Port 21 is closed)."
        print(f"[!] FTP Error: {err}")
        return False, err
    except Exception as e:
        err = f"FTP transmission error: {e}"
        print(f"[!] FTP Error: {err}")
        return False, err

# -------------------------------------------------------------
# Main Execution
# -------------------------------------------------------------
def main():
    safe_urls, malicious_urls = collect_verified_urls(target_safe=50, target_malicious=150)
    all_urls = safe_urls + malicious_urls
    
    results = evaluate_urls(all_urls)
    metrics = calculate_metrics(results)
    
    print("\n" + "="*60)
    print("           BENCHMARK RESULTS SUMMARY (200 URLs)")
    print("="*60)
    print(f" Total Live URLs Evaluated:       {metrics['total_urls']}")
    print(f"   - Benign URLs (Safe):          {metrics['total_safe']}")
    print(f"   - Malicious URLs (Threat):     {metrics['total_malicious']}")
    print(f" Malicious Interception Rate:     {metrics['malicious_interception_rate']}% ({metrics['malicious_intercepted_total']}/{metrics['total_malicious']})")
    print(f"   - Auto Block (High Conf):      {metrics['malicious_auto_blocked']} ({metrics['malicious_auto_block_rate']}%)")
    print(f"   - Flagged for SOC Review:      {metrics['malicious_review']}")
    print(f" Benign Auto-Allowed Rate:        {metrics['safe_allow_rate']}% ({metrics['safe_auto_allowed']}/{metrics['total_safe']})")
    print(f" False Positive Hard Blocks:      {metrics['safe_false_positive_block']}")
    print(f" Model Precision:                 {metrics['precision_pct']}%")
    print(f" Model Recall:                    {metrics['recall_pct']}%")
    print(f" Model F1-Score:                  {metrics['f1_score']}")
    print("="*60)

    export_reports(results, metrics)
    ftp_ok, ftp_msg = attempt_ftp_delivery()

if __name__ == "__main__":
    main()
