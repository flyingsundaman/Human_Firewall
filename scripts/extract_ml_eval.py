#!/home/flyingsundaman/Human_Firewall/venv/bin/python
"""
AFFERENT SOC ML Evaluation & Telemetry Extractor CLI
Extracts proxy traffic, SOC alerts, and evaluates live/recorded ML model predictions.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# Set up paths
_repo_dir = Path(__file__).resolve().parent.parent
_backend_dir = _repo_dir / "backend"
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))

from dotenv import load_dotenv
load_dotenv(_repo_dir / ".env")

try:
    from services import proxy_store, stacker_scanner
except ImportError as exc:
    print(f"Error importing AFFERENT backend modules: {exc}", file=sys.stderr)
    sys.exit(1)


def _format_prob(val: Optional[float]) -> str:
    if val is None:
        return "N/A"
    return f"{val:.4f}"


def get_traffic_records(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Retrieve raw traffic records from PostgreSQL proxy_traffic_events."""
    query = """
        SELECT 
            domain,
            action,
            decision_source,
            reason,
            occurred_at,
            event_id
        FROM proxy_traffic_events
        ORDER BY id DESC
    """
    if limit:
        query += f" LIMIT {int(limit)}"
    with proxy_store.connection() as conn:
        rows = conn.execute(query).fetchall()
        return [dict(r) for r in rows]


def get_alerts_records() -> Dict[str, Dict[str, Any]]:
    """Retrieve alerts indexed by domain."""
    query = """
        SELECT 
            domain,
            urgency,
            status,
            verdict,
            reason,
            confidence,
            source,
            created_at
        FROM proxy_alerts
        ORDER BY sequence DESC
    """
    alerts_by_domain: Dict[str, Dict[str, Any]] = {}
    with proxy_store.connection() as conn:
        for r in conn.execute(query).fetchall():
            d = dict(r)
            dom = d["domain"]
            if dom not in alerts_by_domain:
                alerts_by_domain[dom] = d
    return alerts_by_domain


def extract_and_evaluate(limit: Optional[int] = None, rescan: bool = True) -> List[Dict[str, Any]]:
    """Aggregate unique domains from proxy traffic and evaluate them with ML."""
    raw_traffic = get_traffic_records(limit)
    alerts = get_alerts_records()

    # Aggregate by domain
    aggregated: Dict[str, Dict[str, Any]] = {}
    for ev in raw_traffic:
        dom = ev["domain"]
        occurred = ev.get("occurred_at")
        if dom not in aggregated:
            aggregated[dom] = {
                "domain": dom,
                "count": 1,
                "first_seen": occurred,
                "last_seen": occurred,
                "latest_action": ev["action"],
                "decision_source": ev["decision_source"],
                "latest_reason": ev.get("reason", ""),
            }
        else:
            aggregated[dom]["count"] += 1
            if occurred and (not aggregated[dom]["first_seen"] or occurred < aggregated[dom]["first_seen"]):
                aggregated[dom]["first_seen"] = occurred
            if occurred and (not aggregated[dom]["last_seen"] or occurred > aggregated[dom]["last_seen"]):
                aggregated[dom]["last_seen"] = occurred
                aggregated[dom]["latest_action"] = ev["action"]
                aggregated[dom]["decision_source"] = ev["decision_source"]
                aggregated[dom]["latest_reason"] = ev.get("reason", "")

    # Run ML scan on each unique domain
    results: List[Dict[str, Any]] = []
    for dom, data in aggregated.items():
        ml_res = stacker_scanner.scan(dom) if rescan else {}
        alert_info = alerts.get(dom, {})

        results.append({
            "domain": dom,
            "requests": data["count"],
            "first_seen": str(data["first_seen"]),
            "last_seen": str(data["last_seen"]),
            "proxy_action": data["latest_action"],
            "decision_source": data["decision_source"],
            "recorded_reason": data["latest_reason"],
            # Live Model Output
            "ml_verdict": ml_res.get("verdict", "unknown"),
            "prob_malicious": ml_res.get("prob_malicious"),
            "confidence": ml_res.get("confidence"),
            "is_tranco_top": ml_res.get("tranco_top", False),
            "entropy": ml_res.get("entropy"),
            "ml_reason": ml_res.get("reason", ""),
            "model_version": ml_res.get("modelVersion", ""),
            # Alert Info
            "has_alert": dom in alerts,
            "alert_urgency": alert_info.get("urgency", ""),
            "alert_status": alert_info.get("status", ""),
        })

    return results


def print_summary(data: List[Dict[str, Any]]):
    """Print high-level summary and evaluation metrics in high-density table."""
    total_domains = len(data)
    total_requests = sum(d["requests"] for d in data)
    
    # Verdict counts
    verdicts = {"safe": 0, "malicious": 0, "unknown": 0}
    actions = {"allow": 0, "block": 0}
    alerts_count = sum(1 for d in data if d["has_alert"])
    
    for d in data:
        v = d["ml_verdict"]
        verdicts[v] = verdicts.get(v, 0) + 1
        act = d["proxy_action"]
        actions[act] = actions.get(act, 0) + 1

    model_st = stacker_scanner.status()

    print("\n" + "=" * 78)
    print("  AFFERENT SOC · ML MODEL EVALUATION & TELEMETRY SUMMARY")
    print("=" * 78)
    print(f" Model Version   : {model_st.get('modelVersion', 'Unknown')}")
    print(f" Model Engine    : {model_st.get('policyRevision', 'XGBoost Stacker')}")
    print(f" Total Requests  : {total_requests:,}")
    print(f" Unique Domains  : {total_domains:,}")
    print(f" Triggered Alerts: {alerts_count:,}")
    print("-" * 78)
    print(" DISTRIBUTION:")
    print(f"  • Safe        : {verdicts.get('safe', 0):>5} ({verdicts.get('safe', 0)/max(total_domains,1)*100:5.1f}%)")
    print(f"  • Malicious   : {verdicts.get('malicious', 0):>5} ({verdicts.get('malicious', 0)/max(total_domains,1)*100:5.1f}%)")
    print(f"  • Review/Unk  : {verdicts.get('unknown', 0):>5} ({verdicts.get('unknown', 0)/max(total_domains,1)*100:5.1f}%)")
    print(f"  • Proxy Allow : {actions.get('allow', 0):>5} ({actions.get('allow', 0)/max(total_domains,1)*100:5.1f}%)")
    print(f"  • Proxy Block : {actions.get('block', 0):>5} ({actions.get('block', 0)/max(total_domains,1)*100:5.1f}%)")
    print("-" * 78)

    # Top 10 High-Risk Domains (sorted by P_mal desc)
    sorted_by_pmal = sorted(
        [d for d in data if d.get("prob_malicious") is not None],
        key=lambda x: x["prob_malicious"],
        reverse=True,
    )

    print("\n TOP 10 HIGHEST RISK DOMAINS (P_mal >= threshold):")
    print(f" {'Domain':<36} {'Reqs':<6} {'P_mal':<8} {'Verdict':<10} {'Proxy':<7} {'Alert':<6}")
    print("-" * 78)
    for d in sorted_by_pmal[:10]:
        dom = d["domain"][:34]
        reqs = str(d["requests"])
        pmal = _format_prob(d["prob_malicious"])
        verd = d["ml_verdict"]
        act = d["proxy_action"]
        alt = "YES" if d["has_alert"] else "-"
        print(f" {dom:<36} {reqs:<6} {pmal:<8} {verd:<10} {act:<7} {alt:<6}")

    # Top 10 Review / Unknown Zone
    unknowns = [d for d in data if d["ml_verdict"] == "unknown"]
    unknowns_sorted = sorted(
        unknowns,
        key=lambda x: x.get("prob_malicious") or 0.0,
        reverse=True,
    )
    if unknowns_sorted:
        print("\n TOP UNKNOWN / REVIEW ZONE DOMAINS (Deferred to SOC):")
        print(f" {'Domain':<36} {'Reqs':<6} {'P_mal':<8} {'Entropy':<8} {'Tranco':<7}")
        print("-" * 78)
        for d in unknowns_sorted[:10]:
            dom = d["domain"][:34]
            reqs = str(d["requests"])
            pmal = _format_prob(d["prob_malicious"])
            ent = f"{d['entropy']:.2f}" if d.get("entropy") is not None else "-"
            tranco = "Top1M" if d["is_tranco_top"] else "No"
            print(f" {dom:<36} {reqs:<6} {pmal:<8} {ent:<8} {tranco:<7}")

    print("\n" + "=" * 78 + "\n")


def export_csv(data: List[Dict[str, Any]], filepath: str):
    """Export evaluated records to CSV."""
    if not data:
        print("No records to export.")
        return
    fieldnames = [
        "domain",
        "requests",
        "first_seen",
        "last_seen",
        "proxy_action",
        "decision_source",
        "ml_verdict",
        "prob_malicious",
        "confidence",
        "is_tranco_top",
        "entropy",
        "recorded_reason",
        "ml_reason",
        "model_version",
        "has_alert",
        "alert_urgency",
        "alert_status",
    ]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    print(f"✓ Berhasil mengekspor {len(data):,} domain ke file CSV: {filepath}")


def export_json(data: List[Dict[str, Any]], filepath: str):
    """Export evaluated records to JSON."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"✓ Berhasil mengekspor {len(data):,} domain ke file JSON: {filepath}")


def scan_single_domain(domain: str):
    """Deep inspect a single domain."""
    print(f"\nEvaluating domain: {domain}")
    print("=" * 60)
    res = stacker_scanner.scan(domain)
    for k, v in res.items():
        print(f" {k:<18}: {v}")
    
    # Check if domain was recorded in traffic
    with proxy_store.connection() as conn:
        history = conn.execute(
            """
            SELECT action, decision_source, reason, occurred_at 
            FROM proxy_traffic_events 
            WHERE domain = %s 
            ORDER BY id DESC LIMIT 5
            """,
            (domain,),
        ).fetchall()
        print("\n Recent Proxy Traffic History:")
        if not history:
            print("  (No traffic recorded for this domain yet)")
        for h in history:
            print(f"  • [{h['occurred_at']}] Action: {h['action']}, Source: {h['decision_source']}, Reason: {h['reason']}")
    print("=" * 60 + "\n")


def watch_mode(interval: int = 5):
    """Continuously monitor and display incoming SOC telemetry."""
    print(f"Watching SOC ML traffic events (refreshing every {interval}s, press Ctrl+C to stop)...")
    try:
        while True:
            data = extract_and_evaluate(limit=500)
            os.system("clear")
            print_summary(data)
            print(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Interval: {interval}s")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped watching.")


def main():
    parser = argparse.ArgumentParser(
        description="AFFERENT SOC ML Evaluation & Telemetry Extractor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contoh Penggunaan:
  afferent-eval                       # Tampilkan ringkasan evaluasi ML dari proxy SOC
  afferent-eval --csv hasil_ml.csv    # Ekspor semua hasil evaluasi ke CSV
  afferent-eval --json hasil_ml.json  # Ekspor ke JSON
  afferent-eval --scan google.com     # Evaluasi langsung domain spesifik
  afferent-eval --limit 100           # Evaluasi 100 event traffic terbaru
  afferent-eval --watch               # Pantau live incoming traffic & model score
        """
    )
    parser.add_argument("--limit", type=int, default=None, help="Batasi jumlah event traffic yang diambil")
    parser.add_argument("--csv", type=str, default=None, help="Nama file tujuan ekspor CSV (misal: eval.csv)")
    parser.add_argument("--json", type=str, default=None, help="Nama file tujuan ekspor JSON (misal: eval.json)")
    parser.add_argument("--scan", type=str, default=None, help="Pindai dan bedah fitur satu domain spesifik")
    parser.add_argument("--watch", action="store_true", help="Mode live watch (refresh berkala)")
    parser.add_argument("--interval", type=int, default=5, help="Interval refresh pada mode watch (default: 5 detik)")

    args = parser.parse_args()

    if args.scan:
        scan_single_domain(args.scan)
        return

    if args.watch:
        watch_mode(args.interval)
        return

    data = extract_and_evaluate(limit=args.limit)

    if args.csv:
        export_csv(data, args.csv)

    if args.json:
        export_json(data, args.json)

    if not args.csv and not args.json:
        print_summary(data)


if __name__ == "__main__":
    main()
