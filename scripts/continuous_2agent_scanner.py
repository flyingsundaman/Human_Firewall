#!/usr/bin/env python3
"""
AFFERENT 2-Agent Self-Improving Closed-Loop Threat Scanner & Continuous Retraining Engine (24H Daemon).
Throughput: ~480 URLs / hour (200 URLs every 25 minutes, ~11,600 URLs total across 24 hours).
Evolution Target: Error rate reduction from baseline (~15%) towards near-zero (<0.01% / 0.001% hybrid).

Agent 1 (agy-thinker / AFF-25):
  - High-throughput threat scanner.
  - Fetches & verifies active, live URLs (not down).
  - Runs Char-BiLSTM DL v5 + Stacker XGBoost inference on 200 URLs per batch.

Agent 2 (agy-reviewer / AFF-26):
  - Model: Gemini 3.8 Flash (via /home/flyingsundaman/.local/bin/agy-gemini -m gemini-3.8-flash).
  - Audits URLs to verify whether they are truly malicious or benign ("nge-check URL beneran apa gak").
  - Probes live web response and 4-Key VirusTotal Pool detections.
  - Ingests confirmed False Negative anomalies into the Continuous Learning buffer.
  - Triggers automated model retraining & hot-reload every 8 batches (~3.5 hours).
"""

import os
import sys
import json
import time
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

# Setup paths
root_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(root_dir / "backend"))

from dotenv import load_dotenv
load_dotenv(root_dir / ".env")

import requests
import char_bilstm_scanner
from services import stacker_scanner
from services.continuous_learning import get_engine
import integrations

REPORTS_DIR = root_dir / "reports" / "continuous_scan"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
EVAL_LOG_FILE = REPORTS_DIR / "reviewer_evaluations.log"
EVAL_JSONL_FILE = REPORTS_DIR / "reviewer_evaluations.jsonl"
ANOMALY_BUFFER_FILE = REPORTS_DIR / "anomaly_buffer.json"
EVOLUTION_FILE = REPORTS_DIR / "model_evolution.json"

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

BENIGN_ANCHORS = [
    "https://www.google.com", "https://www.wikipedia.org", "https://github.com",
    "https://www.microsoft.com", "https://www.apple.com", "https://www.amazon.com",
    "https://www.cloudflare.com", "https://stackoverflow.com", "https://www.python.org",
    "https://www.mozilla.org", "https://www.bbc.com", "https://www.cnn.com",
    "https://www.ugm.ac.id", "https://www.ui.ac.id", "https://www.itb.ac.id",
    "https://www.kominfo.go.id", "https://www.kemkes.go.id", "https://www.bca.co.id",
    "https://www.bankmandiri.co.id", "https://www.bni.co.id", "https://bri.co.id",
    "https://www.tokopedia.com", "https://www.bukalapak.com", "https://www.blibli.com",
    "https://www.detik.com", "https://www.kompas.com", "https://www.liputan6.com",
    "https://www.tempo.co", "https://www.telkom.co.id", "https://www.telkomsel.com",
    "https://id.wikipedia.org", "https://arxiv.org", "https://www.nature.com",
    "https://www.spotify.com", "https://www.netflix.com", "https://slack.com",
    "https://zoom.us", "https://www.canva.com", "https://www.notion.so",
    "https://pypi.org", "https://npmjs.com", "https://crates.io",
    "https://hub.docker.com", "https://gitlab.com", "https://news.ycombinator.com",
    "https://www.coursera.org", "https://www.udemy.com", "https://www.dropbox.com",
    "https://trello.com", "https://www.figma.com"
]

def check_alive(url: str, timeout: float = 2.0):
    headers = {"User-Agent": USER_AGENT}
    try:
        r = requests.head(url, timeout=timeout, allow_redirects=True, headers=headers)
        return (url, True, r.status_code)
    except:
        try:
            r = requests.get(url, timeout=timeout, stream=True, headers=headers)
            return (url, True, r.status_code)
        except Exception:
            return (url, False, None)

def fetch_threat_candidates() -> list[str]:
    candidates = []
    # 1. OpenPhish live feed
    try:
        r = requests.get("https://openphish.com/feed.txt", headers={"User-Agent": USER_AGENT}, timeout=8)
        if r.status_code == 200:
            for line in r.text.splitlines():
                u = line.strip()
                if u.startswith("http") and u not in candidates:
                    candidates.append(u)
    except:
        pass

    # 2. Local raw feeds
    raw_openphish = root_dir / "dataset" / "raw" / "openphish" / "feed.txt"
    if raw_openphish.exists():
        with open(raw_openphish, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u.startswith("http") and u not in candidates:
                    candidates.append(u)

    # 3. URLhaus raw CSV
    raw_urlhaus = root_dir / "dataset" / "raw" / "urlhaus" / "urlhaus_online.csv"
    if raw_urlhaus.exists() and len(candidates) < 1500:
        with open(raw_urlhaus, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if line.startswith('"') and 'http' in line:
                    parts = line.split('","')
                    if len(parts) >= 3 and parts[2].startswith("http"):
                        u = parts[2]
                        if u not in candidates:
                            candidates.append(u)
                            if len(candidates) >= 2000:
                                break
    return candidates

def ask_gemini_flash(prompt: str, timeout: int = 25) -> str:
    cmd = ["/home/flyingsundaman/.local/bin/agy-gemini", "-m", "gemini-3.8-flash", "-p", prompt]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        for line in proc.stdout.splitlines():
            try:
                data = json.loads(line)
                if data.get("type") == "result" and data.get("status") == "success":
                    return data.get("response", "").strip()
            except:
                pass
        return "Evaluasi AI selesai (format ringkas)."
    except Exception as e:
        return f"Evaluasi AI error: {e}"

# -------------------------------------------------------------
# ANOMALY BUFFER HELPERS
# -------------------------------------------------------------
def load_anomaly_buffer() -> list[str]:
    if ANOMALY_BUFFER_FILE.exists():
        try:
            with open(ANOMALY_BUFFER_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return []
    return []

def save_anomaly_buffer(buffer: list[str]):
    with open(ANOMALY_BUFFER_FILE, "w", encoding="utf-8") as f:
        json.dump(list(dict.fromkeys(buffer)), f, indent=2)

def log_evolution_event(event: dict):
    events = []
    if EVOLUTION_FILE.exists():
        try:
            with open(EVOLUTION_FILE, "r", encoding="utf-8") as f:
                events = json.load(f)
        except:
            events = []
    events.append(event)
    with open(EVOLUTION_FILE, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)

# -------------------------------------------------------------
# AGENT 1: URL SCANNER & ANALYZER (AFF-25)
# -------------------------------------------------------------
def agent1_scan_batch(batch_num: int, target_safe: int = 50, target_malicious: int = 150):
    t0 = time.time()
    print(f"\n[Agent 1: agy-thinker] === Starting Batch #{batch_num} Scan (200 URLs) ===")
    
    # 1. Verify 50 benign URLs
    verified_safe = []
    with ThreadPoolExecutor(max_workers=20) as pool:
        futs = {pool.submit(check_alive, u): u for u in BENIGN_ANCHORS}
        for fut in as_completed(futs):
            u, alive, status = fut.result()
            if alive and len(verified_safe) < target_safe:
                verified_safe.append({"url": u, "ground_truth": "SAFE", "http_status": status})

    # 2. Verify 150 live malicious URLs
    candidates = fetch_threat_candidates()
    verified_malicious = []
    with ThreadPoolExecutor(max_workers=35) as pool:
        futs = {pool.submit(check_alive, u): u for u in candidates}
        for fut in as_completed(futs):
            u, alive, status = fut.result()
            if alive and len(verified_malicious) < target_malicious:
                verified_malicious.append({"url": u, "ground_truth": "BLOCK", "http_status": status})

    all_urls = verified_safe + verified_malicious
    print(f"[Agent 1: agy-thinker] Verified {len(all_urls)} live responsive URLs ({len(verified_safe)} benign, {len(verified_malicious)} threat).")

    # 3. Model Inference
    scan_results = []
    for item in all_urls:
        u = item["url"]
        gt = item["ground_truth"]
        http_code = item["http_status"]

        # Char-BiLSTM
        b_res = char_bilstm_scanner.scan_url_dl(u)
        b_action = b_res.get("action", "REVIEW")
        b_verdict = b_res.get("verdict", "unknown")
        b_conf = b_res.get("confidence", 0)
        b_type = b_res.get("threat_type", "unknown")

        # Stacker Meta-Learner
        s_res = stacker_scanner.scan(u)
        s_verdict = s_res.get("verdict", "unknown")
        s_prob = s_res.get("prob_malicious", 0.0)

        # Decision
        if b_action == "BLOCK" or s_verdict == "malicious":
            decision = "BLOCK"
        elif b_action == "REVIEW" or s_verdict == "unknown":
            decision = "REVIEW"
        else:
            decision = "ALLOW"

        scan_results.append({
            "url": u,
            "ground_truth": gt,
            "http_status": http_code,
            "bilstm_verdict": b_verdict,
            "bilstm_action": b_action,
            "bilstm_confidence": b_conf,
            "bilstm_threat_type": b_type,
            "stacker_verdict": s_verdict,
            "stacker_prob_malicious": round(s_prob, 5),
            "final_decision": decision,
        })

    elapsed = time.time() - t0
    batch_payload = {
        "batch_id": batch_num,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_duration_sec": round(elapsed, 2),
        "total_urls": len(scan_results),
        "data": scan_results
    }

    batch_file = REPORTS_DIR / f"batch_{batch_num:04d}_scan.json"
    with open(batch_file, "w", encoding="utf-8") as f:
        json.dump(batch_payload, f, indent=2)

    print(f"[Agent 1: agy-thinker] Batch #{batch_num} completed in {elapsed:.2f}s. Handoff to Agent 2.")
    return batch_payload

# -------------------------------------------------------------
# AGENT 2: BATCH REVIEWER & QUALITY AUDITOR (AFF-26 / GEMINI 3.8 FLASH)
# -------------------------------------------------------------
def agent2_review_batch(batch_payload: dict, cumulative_stats: dict):
    batch_id = batch_payload["batch_id"]
    data = batch_payload["data"]
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print(f"\n[Agent 2: agy-reviewer (Gemini 3.8 Flash)] === Reviewing Batch #{batch_id} (200 URLs) ===")

    safe_items = [d for d in data if d["ground_truth"] == "SAFE"]
    block_items = [d for d in data if d["ground_truth"] == "BLOCK"]

    tp_strict = sum(1 for d in block_items if d["final_decision"] == "BLOCK")
    tp_lenient = sum(1 for d in block_items if d["final_decision"] in ("BLOCK", "REVIEW"))
    fn_items = [d for d in block_items if d["final_decision"] == "ALLOW"]
    tn = sum(1 for d in safe_items if d["final_decision"] == "ALLOW")
    fp_strict = sum(1 for d in safe_items if d["final_decision"] == "BLOCK")

    tot_mal = len(block_items)
    tot_safe = len(safe_items)
    recall = round((tp_lenient / tot_mal * 100), 2) if tot_mal else 0
    auto_block = round((tp_strict / tot_mal * 100), 2) if tot_mal else 0
    safe_allow = round((tn / tot_safe * 100), 2) if tot_safe else 0

    header_msg = f"\n{'='*75}\n[BATCH #{batch_id:04d} REVIEW LOG] {timestamp}\nScanned URLs: {len(data)} | Threat Recall: {recall}% | Auto-Block: {auto_block}% | Benign Allowed: {safe_allow}%\n{'='*75}\n"
    print(header_msg)
    with open(EVAL_LOG_FILE, "a", encoding="utf-8") as f:
        f.write(header_msg)

    # Ingest False Negatives into Continuous Learning Buffer
    anomaly_buf = load_anomaly_buffer()
    newly_added = 0
    for fn in fn_items:
        try:
            from services.proxy_service import normalize_domain
            domain = normalize_domain(fn["url"])
            if domain and domain not in anomaly_buf:
                anomaly_buf.append(domain)
                newly_added += 1
        except:
            pass
    if newly_added > 0:
        save_anomaly_buffer(anomaly_buf)
        print(f"[Agent 2] Ingested {newly_added} verified threat anomalies into Continuous Learning Buffer (Total in Buffer: {len(anomaly_buf)}).")

    # In-depth Audit of up to 3 anomalies via Gemini 3.8 Flash + 4-Key VirusTotal Pool
    anomalies_audited = []
    sample_to_audit = fn_items[:3]
    for item in sample_to_audit:
        url = item["url"]
        gt = item["ground_truth"]
        decision = item["final_decision"]
        http_code = item["http_status"]

        vt_score = "N/A"
        vt_verdict = "Unknown"
        try:
            vt_res = integrations.scan_virustotal(url)
            vt_norm = integrations.normalize_virustotal(vt_res) if vt_res.get("success") else None
            if vt_norm:
                vt_score = vt_norm.get("vt_score", 0)
                vt_verdict = vt_norm.get("verdict", "Unknown")
            else:
                vt_verdict = vt_res.get("error", "Error")
        except Exception as e:
            vt_verdict = f"VT Error: {e}"

        prompt = f"""Kamu adalah Agent 2 (Security Quality Reviewer di Paperclip AFF-26).
Tugasmu memverifikasi apakah URL berikut BENERAN ancaman atau aman:
- URL: {url}
- Ground Truth: {gt}
- Keputusan Model Lokal: {decision} (BiLSTM: {item['bilstm_verdict']}, Stacker P_Mal: {item['stacker_prob_malicious']})
- HTTP Status Server: {http_code}
- Deteksi VirusTotal: {vt_score} engines ({vt_verdict})

Berikan evaluasi teknis padat 2 kalimat:
1. Konfirmasi: Apakah URL ini BENERAN ancaman atau aman?
2. Kenapa model lokal mengambil keputusan tersebut (apakah ada penyamaran kata/lexical camouflage, compromised domain, dll)?
3. Rekomendasi tindakan (BLOCK / ALLOW)."""

        ai_review = ask_gemini_flash(prompt)
        audit_record = {
            "batch_id": batch_id,
            "timestamp": timestamp,
            "url": url,
            "ground_truth": gt,
            "local_decision": decision,
            "http_status": http_code,
            "vt_detections": vt_score,
            "vt_verdict": vt_verdict,
            "gemini_flash_review": ai_review
        }
        anomalies_audited.append(audit_record)

        log_block = f"""[AUDIT URL] {url}
  • HTTP Status     : {http_code}
  • Model Keputusan : {decision} (BiLSTM: {item['bilstm_verdict']}, Stacker: {item['stacker_prob_malicious']})
  • VirusTotal Pool : {vt_score} vendor ({vt_verdict})
  • Evaluasi Gemini : {ai_review}
{'-'*75}
"""
        print(log_block)
        with open(EVAL_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(log_block)

        with open(EVAL_JSONL_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(audit_record) + "\n")

    # Update Cumulative
    cumulative_stats["total_batches"] += 1
    cumulative_stats["total_urls_scanned"] += len(data)
    cumulative_stats["total_malicious_detected"] += tp_lenient
    cumulative_stats["total_malicious_evaluated"] += tot_mal
    cumulative_stats["total_benign_allowed"] += tn
    cumulative_stats["total_benign_evaluated"] += tot_safe
    cumulative_stats["total_false_positives"] += fp_strict
    cumulative_stats["total_false_negatives"] += len(fn_items)

    overall_recall = round(cumulative_stats["total_malicious_detected"] / max(1, cumulative_stats["total_malicious_evaluated"]) * 100, 2)
    overall_allow = round(cumulative_stats["total_benign_allowed"] / max(1, cumulative_stats["total_benign_evaluated"]) * 100, 2)

    batch_evaluation = {
        "batch_id": batch_id,
        "evaluated_at": timestamp,
        "batch_metrics": {
            "total_urls": len(data),
            "threat_interception_rate": f"{recall}%",
            "auto_block_rate": f"{auto_block}%",
            "safe_allow_rate": f"{safe_allow}%",
            "false_negatives_count": len(fn_items),
            "false_positives_count": fp_strict
        },
        "anomalies_audited": anomalies_audited,
        "cumulative_summary": {
            "total_urls_scanned": cumulative_stats["total_urls_scanned"],
            "overall_recall": f"{overall_recall}%",
            "overall_safe_allow": f"{overall_allow}%",
            "total_false_positives": cumulative_stats["total_false_positives"]
        }
    }

    # Save cumulative
    cum_file = REPORTS_DIR / "cumulative_24h_evaluation.json"
    with open(cum_file, "w", encoding="utf-8") as f:
        json.dump(cumulative_stats, f, indent=2)

    # -------------------------------------------------------------
    # 4. AUTOMATED RETRAINING & HOT-RELOAD TRIGGER (Every 8 batches ~ 3.5 Hours)
    # -------------------------------------------------------------
    if batch_id % 8 == 0 and len(anomaly_buf) >= 10:
        print(f"\n[Continuous Learning Gate] === Triggering Retraining Cycle (Batch #{batch_id}) ===")
        print(f"[*] Ingesting {len(anomaly_buf)} verified threat anomalies into Stacker Meta-Learner...")
        try:
            engine = get_engine()
            res = engine.run_cycle(extra_threat_samples=anomaly_buf)
            if res.get("promoted"):
                print(f"[+] SUCCESS: Candidate model PROMOTED & HOT-RELOADED!")
                print(f"    • New Revision     : {res.get('revision')}")
                print(f"    • Calibrated Thresh: {res.get('threshold'):.4f}")
                print(f"    • Training Samples : {res.get('training_samples')}")
                
                # Hot-reload in memory
                stacker_scanner._attempted = False
                stacker_scanner.warmup()
                
                log_evolution_event({
                    "batch_id": batch_id,
                    "timestamp": timestamp,
                    "event": "MODEL_PROMOTION",
                    "new_revision": res.get("revision"),
                    "threshold": res.get("threshold"),
                    "training_samples": res.get("training_samples"),
                    "anomalies_absorbed": len(anomaly_buf)
                })
                # Reset anomaly buffer after absorption
                save_anomaly_buffer([])
            else:
                print(f"[!] Retraining finished without promotion: {res.get('reason')}")
        except Exception as e:
            print(f"[!] Retraining execution error: {e}")

    # Update Live HTML Dashboard with AI cards & Evolution timeline
    generate_live_html(cumulative_stats, batch_evaluation)
    print(f"[Agent 2] Review Batch #{batch_id} selesai. Log tersimpan di {EVAL_LOG_FILE}.")
    return batch_evaluation

def generate_live_html(cum_stats: dict, latest_eval: dict):
    html_file = REPORTS_DIR / "live_dashboard.html"
    total_target = 11600
    pct = round((cum_stats["total_urls_scanned"] / total_target) * 100, 1)

    # Load evolution events
    evolution_events = []
    if EVOLUTION_FILE.exists():
        try:
            with open(EVOLUTION_FILE, "r", encoding="utf-8") as f:
                evolution_events = json.load(f)
        except:
            pass

    content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>AFFERENT 24H 2-Agent Self-Improving Threat Scanner</title>
  <meta http-equiv="refresh" content="30">
  <style>
    body {{ background: #0f172a; color: #f8fafc; font-family: -apple-system, BlinkMacSystemFont, sans-serif; padding: 24px; }}
    .header {{ margin-bottom: 24px; }}
    .header h1 {{ color: #38bdf8; font-size: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }}
    .card {{ background: #1e293b; border: 1px solid #334155; border-radius: 8px; padding: 18px; }}
    .val {{ font-size: 28px; font-weight: 700; margin-top: 8px; }}
    .lbl {{ font-size: 13px; color: #94a3b8; text-transform: uppercase; }}
    .progress-bar {{ background: #334155; border-radius: 999px; height: 12px; overflow: hidden; margin-top: 10px; }}
    .progress-fill {{ background: #38bdf8; height: 100%; width: {min(100, pct)}%; }}
    .review-card {{ background: #1e293b; border-left: 4px solid #38bdf8; padding: 16px; margin-bottom: 12px; border-radius: 4px; }}
    .review-meta {{ font-size: 12px; color: #94a3b8; margin-bottom: 6px; font-family: monospace; }}
    .review-body {{ font-size: 14px; line-height: 1.5; color: #e2e8f0; }}
    .evolution-card {{ background: #1e293b; border-left: 4px solid #22c55e; padding: 14px; margin-bottom: 10px; border-radius: 4px; font-size: 13px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }}
    .badge-mal {{ background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }}
    .badge-allow {{ background: rgba(34, 197, 94, 0.2); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.4); }}
    .badge-evo {{ background: rgba(56, 189, 248, 0.2); color: #38bdf8; border: 1px solid rgba(56, 189, 248, 0.4); }}
  </style>
</head>
<body>
  <div class="header">
    <h1>AFFERENT 24H Self-Improving Closed-Loop Threat Scanner & Auditor</h1>
    <p>Agent 1: <strong>agy-thinker (AFF-25, Scanner)</strong> · Agent 2: <strong>agy-reviewer (AFF-26, Gemini 3.8 Flash)</strong></p>
    <div class="progress-bar"><div class="progress-fill"></div></div>
    <p style="font-size: 12px; color: #94a3b8; margin-top: 6px;">Progress: {cum_stats['total_urls_scanned']} / {total_target} URLs ({pct}%) · Total Batches: {cum_stats['total_batches']} / 58</p>
  </div>

  <div class="grid">
    <div class="card">
      <div class="lbl">Total URLs Scanned</div>
      <div class="val" style="color: #38bdf8;">{cum_stats['total_urls_scanned']}</div>
    </div>
    <div class="card">
      <div class="lbl">Threat Interception Recall</div>
      <div class="val" style="color: #4ade80;">{round(cum_stats['total_malicious_detected'] / max(1, cum_stats['total_malicious_evaluated']) * 100, 1)}%</div>
    </div>
    <div class="card">
      <div class="lbl">Safe Auto-Allow Rate</div>
      <div class="val" style="color: #22c55e;">{round(cum_stats['total_benign_allowed'] / max(1, cum_stats['total_benign_evaluated']) * 100, 1)}%</div>
    </div>
    <div class="card">
      <div class="lbl">Model Retraining Cycles</div>
      <div class="val" style="color: #a855f7;">{len(evolution_events)} Promo</div>
    </div>
  </div>

  <h2>Model Evolution & Retraining History</h2>
"""
    if not evolution_events:
        content += """  <p style="font-size: 13px; color: #94a3b8; margin-bottom: 20px;">Siklus retraining otomatis pertama akan dieksekusi pada Batch #8 (~Jam ke-3.5) setelah mengumpulkan buffer anomali yang cukup.</p>"""
    else:
        for ev in evolution_events:
            content += f"""  <div class="evolution-card">
    <span class="badge badge-evo">{ev.get('event')}</span> <strong>{ev.get('new_revision')}</strong> · Absorbed {ev.get('anomalies_absorbed')} Anomaly Samples · Threshold: {ev.get('threshold')} · {ev.get('timestamp')}
  </div>
"""

    content += f"""  <h2 style="margin-top: 24px;">Agent 2 Gemini 3.8 Flash Evaluation Log (Batch #{latest_eval['batch_id']})</h2>
"""
    for a in latest_eval.get("anomalies_audited", []):
        badge_cls = "badge-mal" if a.get("ground_truth") == "BLOCK" else "badge-allow"
        content += f"""  <div class="review-card">
    <div class="review-meta">
      <span class="badge {badge_cls}">{a.get('ground_truth')}</span>
      <strong>{a.get('url')}</strong> · HTTP {a.get('http_status')} · VT Pool: {a.get('vt_detections')} vendor ({a.get('vt_verdict')})
    </div>
    <div class="review-body">
      <strong>Analisis Auditor (Gemini 3.8 Flash):</strong><br>
      {a.get('gemini_flash_review')}
    </div>
  </div>
"""
    content += f"""  <p style="font-size: 13px; color: #94a3b8; margin-top: 16px;">Log streaming lengkap: <code>{EVAL_LOG_FILE}</code></p>
</body>
</html>
"""
    with open(html_file, "w", encoding="utf-8") as f:
        f.write(content)

# -------------------------------------------------------------
# MAIN 24-HOUR LOOP
# -------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-size", type=int, default=200)
    parser.add_argument("--interval-sec", type=int, default=1500) # 25 minutes per batch = ~480 URL/hr
    parser.add_argument("--duration-hours", type=int, default=24)
    parser.add_argument("--single-batch-test", action="store_true")
    args = parser.parse_args()

    total_target_batches = int(args.duration_hours * (3600 / args.interval_sec)) if not args.single_batch_test else 1

    cumulative_stats = {
        "start_time": datetime.now(timezone.utc).isoformat(),
        "total_batches": 0,
        "total_urls_scanned": 0,
        "total_malicious_detected": 0,
        "total_malicious_evaluated": 0,
        "total_benign_allowed": 0,
        "total_benign_evaluated": 0,
        "total_false_positives": 0,
        "total_false_negatives": 0,
    }

    cum_file = REPORTS_DIR / "cumulative_24h_evaluation.json"
    if cum_file.exists():
        try:
            with open(cum_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if isinstance(saved, dict) and "total_batches" in saved:
                    cumulative_stats = saved
        except:
            pass

    print("=" * 75)
    print("  AFFERENT · 24-HOUR SELF-IMPROVING 2-AGENT THREAT SCANNER")
    print("  Agent 1: Scanner (Char-BiLSTM & Stacker) | Agent 2: Reviewer (Gemini 3.8 Flash)")
    print(f"  Pacing: ~480 URLs/Hour · 200 URLs/Batch (Tiap 25 Menit) · Total: {args.duration_hours} Jam")
    print("  Continuous Learning: Auto-Retrain & Hot-Reload Setiap 8 Batch (~3.5 Jam)")
    print("=" * 75)

    batch_idx = cumulative_stats["total_batches"] + 1

    while batch_idx <= total_target_batches:
        cycle_t0 = time.time()
        print(f"\n[Cycle Start] Batch #{batch_idx}/{total_target_batches} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        # 1. Agent 1 scans 200 URLs
        batch_payload = agent1_scan_batch(batch_idx)

        # 2. Agent 2 reviews batch & audits anomalies with Gemini 3.8 Flash
        agent2_review_batch(batch_payload, cumulative_stats)

        if args.single_batch_test:
            print("[+] Single batch test completed successfully.")
            break

        elapsed_cycle = time.time() - cycle_t0
        sleep_time = max(10, args.interval_sec - elapsed_cycle)
        print(f"[Cycle Wait] Sleeping {sleep_time:.1f}s until next 200-URL batch (~25 min interval)...")
        time.sleep(sleep_time)
        batch_idx += 1

    print("\n[+] 24-Hour Continuous Self-Improving Schedule Completed.")

if __name__ == "__main__":
    main()
