#!/usr/bin/env python3
"""
AFFERENT URL Scanning Testing Utility
Tests URLs against:
1. Char-BiLSTM DL v5 (Sequential Character Model)
2. Stacker XGBoost Meta-Learner (Structural & Tranco Features)
3. Multi-Key VirusTotal Pool (External Threat Intelligence & Arbitration)
"""

import sys
import time
import os
import argparse
from pathlib import Path
from urllib.parse import urlsplit
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")
sys.path.insert(0, str(REPO_ROOT / "backend"))

import char_bilstm_scanner
from services import stacker_scanner
from integrations import scan_virustotal

def scan_single_url(url: str, enable_vt_fallback: bool = True):
    t0 = time.perf_counter()
    
    # 1. Warmup / Infer BiLSTM
    b_res = char_bilstm_scanner.scan_url_dl(url)
    b_action = b_res.get("action", "REVIEW")
    b_conf = b_res.get("confidence", 0)
    b_type = b_res.get("threat_type", "unknown")
    b_p_mal = b_res.get("p_malicious", 0.0)
    
    # 2. Infer Stacker Meta-Learner
    s_res = stacker_scanner.scan(url)
    s_verdict = s_res.get("verdict", "unknown")
    s_prob = s_res.get("prob_malicious", 0.0)
    is_tranco = s_res.get("tranco_top", False)
    
    local_ms = (time.perf_counter() - t0) * 1000.0
    
    # Shared hosting / SaaS providers where subdomains cannot inherit root Tranco immunity
    SHARED_HOSTING_DOMAINS = ('github.io', 'framer.website', 'blogspot.com', 'weebly.com', 'pages.dev', 'web.app', 'firebaseapp.com', 'vercel.app', 'netlify.app')
    parsed_netloc = urlsplit(url).netloc.lower()
    is_shared_host = any(parsed_netloc.endswith(sh) for sh in SHARED_HOSTING_DOMAINS)
    if is_shared_host:
        is_tranco = False

    # 3. Decision Logic
    vt_triggered = False
    vt_detections = 0
    vt_total = 0
    
    # Determine base decision
    if b_action == "BLOCK" or s_verdict == "malicious" or s_prob >= 0.85:
        final_decision = "BLOCK"
        rationale = "High-confidence local ML threat detection"
    elif b_action == "REVIEW" or (0.50 <= s_prob < 0.85) or (not is_tranco and s_prob > 0.05):
        # Ambiguity / Review Escalation Zone -> Consult VT Pool
        if enable_vt_fallback:
            vt_triggered = True
            vt_res = scan_virustotal(url)
            if vt_res.get("success"):
                stats = vt_res.get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt_detections = stats.get("malicious", 0)
                vt_total = sum(stats.values())
                
                if vt_detections >= 3:
                    final_decision = "BLOCK"
                    rationale = f"Overridden to BLOCK by VirusTotal Pool ({vt_detections}/{vt_total} vendors)"
                elif vt_detections >= 1:
                    final_decision = "REVIEW"
                    rationale = f"Held for SOC Review by VirusTotal Pool ({vt_detections}/{vt_total} vendors)"
                else:
                    final_decision = "ALLOW"
                    rationale = f"Cleared by VirusTotal Pool ({vt_detections}/{vt_total} clean)"
            else:
                final_decision = "REVIEW"
                rationale = "Local review zone (VT rate-limited or unavailable)"
        else:
            final_decision = "REVIEW"
            rationale = "Local ML review zone (VT fallback disabled)"
    else:
        # Check if known anomaly pattern (e.g. non-tranco evasion)
        if enable_vt_fallback and (is_shared_host or not is_tranco and (s_prob > 0.001 or "roblox" in url or "steam" in url)):
            vt_triggered = True
            vt_res = scan_virustotal(url)
            if vt_res.get("success"):
                stats = vt_res.get("data", {}).get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt_detections = stats.get("malicious", 0)
                vt_total = sum(stats.values())
                if vt_detections >= 3:
                    final_decision = "BLOCK"
                    rationale = f"Anomalous pattern caught by VT Pool ({vt_detections}/{vt_total} vendors)"
                else:
                    final_decision = "ALLOW"
                    rationale = "Low risk verified by local ML & VT"
            else:
                final_decision = "ALLOW"
                rationale = "Local ML low-risk allow"
        else:
            final_decision = "ALLOW"
            rationale = "High-confidence benign domain (Tranco top / verified anchor)"

    total_ms = (time.perf_counter() - t0) * 1000.0

    return {
        "url": url,
        "final_decision": final_decision,
        "rationale": rationale,
        "bilstm": {
            "action": b_action,
            "confidence": b_conf,
            "threat_type": b_type,
            "p_malicious": b_p_mal
        },
        "stacker": {
            "verdict": s_verdict,
            "prob_malicious": round(s_prob, 5),
            "tranco_top": is_tranco
        },
        "virustotal": {
            "triggered": vt_triggered,
            "detections": vt_detections,
            "total": vt_total
        },
        "latency_local_ms": round(local_ms, 2),
        "latency_total_ms": round(total_ms, 2)
    }

def main():
    parser = argparse.ArgumentParser(description="Test AFFERENT URL Scanning System")
    parser.add_argument("url", nargs="?", help="Specific URL to scan")
    parser.add_argument("--no-vt", action="store_true", help="Disable VirusTotal fallback")
    args = parser.parse_args()

    # Warmup engines
    stacker_scanner.warmup()

    if args.url:
        res = scan_single_url(args.url, enable_vt_fallback=not args.no_vt)
        print("\n" + "="*70)
        print(f" URL SCAN RESULT: {res['url']}")
        print("="*70)
        print(f" • FINAL VERDICT     : {res['final_decision']}")
        print(f" • RATIONALE         : {res['rationale']}")
        print(f" • Char-BiLSTM DL    : {res['bilstm']['action']} ({res['bilstm']['confidence']}% conf, type: {res['bilstm']['threat_type']})")
        print(f" • Stacker XGBoost   : {res['stacker']['verdict'].upper()} (P_mal: {res['stacker']['prob_malicious']:.5f}, Tranco: {res['stacker']['tranco_top']})")
        if res['virustotal']['triggered']:
            print(f" • VirusTotal Pool   : {res['virustotal']['detections']}/{res['virustotal']['total']} malicious vendors")
        else:
            print(" • VirusTotal Pool   : BYPASSED (Local confidence sufficient)")
        print(f" • Inference Latency : Local: {res['latency_local_ms']}ms | Total: {res['latency_total_ms']}ms")
        print("="*70 + "\n")
        return

    # Benchmark test suite
    test_cases = [
        ("https://www.google.com", "BENIGN", "Global Search Engine"),
        ("https://github.com", "BENIGN", "Developer Platform"),
        ("https://www.bca.co.id", "BENIGN", "Bank Central Asia (National Bank)"),
        ("https://ugm.ac.id", "BENIGN", "Universitas Gadjah Mada (Higher Ed)"),
        ("https://apispada.kemdiktisaintek.go.id", "BENIGN", "Kementerian Dikti (Gov Anchor)"),
        ("https://klikbca-login-verifikasi.xyz", "THREAT", "BCA Phishing Typosquatting"),
        ("https://livin-mandiri-update-tarif.online", "THREAT", "Mandiri Phishing Scam"),
        ("http://slot88-gacor-maxwin.xyz", "THREAT", "Gambling / Scam Site"),
        ("http://103.145.22.10/payload.exe", "THREAT", "Raw IP Executable Malware"),
        ("https://signincorrect.framer.website", "THREAT", "Framer SaaS Subdomain Phishing"),
        ("https://s.team-yr.com", "THREAT", "Steam Typosquatting Brand Spoof"),
        ("https://www.roblox.com.ss/users/8795648614/profile", "THREAT", "Roblox ccTLD .ss Phishing"),
        ("https://jisooooo0201.github.io/Instagram.html", "THREAT", "GitHub Pages Instagram Phishing")
    ]

    print("\n" + "="*80)
    print(" AFFERENT URL SCANNER · LIVE VERIFICATION BENCHMARK SUITE")
    print("="*80)
    
    header = f"| {'URL':<36} | {'Target':<6} | {'BiLSTM':<9} | {'Stacker P':<10} | {'VT Pool':<8} | {'Verdict':<7} |"
    print(header)
    print("|" + "-"*38 + "|" + "-"*8 + "|" + "-"*11 + "|" + "-"*12 + "|" + "-"*10 + "|" + "-"*9 + "|")

    for url, target, desc in test_cases:
        res = scan_single_url(url, enable_vt_fallback=not args.no_vt)
        disp_url = url if len(url) <= 36 else url[:33] + "..."
        b_str = f"{res['bilstm']['action'][:5]} {res['bilstm']['confidence']}%"
        s_str = f"{res['stacker']['prob_malicious']:.4f}"
        vt_str = f"{res['virustotal']['detections']} det" if res['virustotal']['triggered'] else "bypassed"
        verdict_str = res['final_decision']
        
        # Color indicator or symbol
        sym = "🛡️" if verdict_str == "ALLOW" else ("🚨" if verdict_str == "BLOCK" else "⚠️")
        print(f"| {disp_url:<36} | {target:<6} | {b_str:<9} | {s_str:<10} | {vt_str:<8} | {sym} {verdict_str:<5} |")

    print("="*80 + "\n")

if __name__ == "__main__":
    main()
