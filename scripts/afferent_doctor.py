#!/usr/bin/env python3
"""
AFFERENT Setup & Doctor CLI (`scripts/afferent_doctor.py`)
Stdlib-only interactive .env configurator and installation troubleshooter.

Usage:
  python scripts/afferent_doctor.py                 # Run full system doctor diagnostics
  python scripts/afferent_doctor.py doctor --fix    # Run doctor and auto-fix permissions/missing keys/checksums
  python scripts/afferent_doctor.py setup           # Interactive guided .env & .env.proxy.local setup
  python scripts/afferent_doctor.py setup --host 100.99.128.37 --mode standalone
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent

SECRET_KEYS = (
    "SECRET_KEY",
    "SERVICE_API_KEY",
    "OTP_PEPPER",
    "AUTH_AUDIT_PEPPER",
    "PROXY_DB_PASSWORD",
    "REDIS_PASSWORD",
    "PROXY_IDENTITY_PEPPER",
    "ML_WEBHOOK_SECRET",
)


def detect_ips() -> dict[str, str]:
    """Detect local LAN IPv4 and Tailscale CGNAT IPv4 (100.64.0.0/10) using stdlib."""
    ips: dict[str, str] = {"loopback": "127.0.0.1"}
    try:
        out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"], text=True, stderr=subprocess.DEVNULL)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[1]
                ip_str = parts[3].split("/")[0]
                addr = ipaddress.ip_address(ip_str)
                if addr.is_loopback:
                    continue
                if ipaddress.ip_network("100.64.0.0/10").overlaps(ipaddress.ip_network(f"{ip_str}/32")):
                    ips["tailscale"] = ip_str
                elif addr.is_private and "lan" not in ips and not iface.startswith(("docker", "br-", "veth")):
                    ips["lan"] = ip_str
    except Exception:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                ips["lan"] = s.getsockname()[0]
        except Exception:
            pass
    return ips


def parse_env_file(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    env: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def write_or_update_env(
    directory: Path,
    host: str,
    mode: str = "standalone",
    vt_keys: str = "",
    force_update: bool = False,
) -> tuple[Path, Path, bool]:
    """Create or safely update .env and .env.proxy.local without wiping existing secrets."""
    from setup_lab import validate_host

    host = validate_host(host)
    env_path = directory / ".env"
    proxy_path = directory / ".env.proxy.local"
    template_path = directory / ".env.example"
    if not template_path.is_file():
        raise FileNotFoundError(f"Template not found: {template_path}")

    existing = parse_env_file(env_path)
    if existing and not force_update:
        raise ValueError("Existing .env found. Pass --update to patch/sync without losing secrets.")

    values: dict[str, str] = {}
    for key in SECRET_KEYS:
        old_val = existing.get(key, "")
        if old_val and not old_val.startswith("replace-with-"):
            values[key] = old_val
        else:
            values[key] = secrets.token_urlsafe(48)

    old_admin = existing.get("ADMIN_PASSWORD", "")
    values["ADMIN_PASSWORD"] = (
        old_admin if (old_admin and not old_admin.startswith("replace-with-")) else "Af!" + secrets.token_urlsafe(24)
    )

    origins = list(
        dict.fromkeys(
            [
                f"http://{host}:3000",
                "http://localhost:3000",
                "http://127.0.0.1:3000",
            ]
        )
    )
    values.update(
        APP_ENV=existing.get("APP_ENV", "development"),
        WEB_BIND_IP="0.0.0.0" if host != "127.0.0.1" else "127.0.0.1",
        PROXY_BIND_IP="0.0.0.0" if host != "127.0.0.1" else "127.0.0.1",
        NEXT_PUBLIC_BASE_URL=f"http://{host}:3000",
        NEXT_PUBLIC_API_URL=f"http://{host}:5000",
        SERVER_BASE_URL=f"http://{host}:5000",
        SIMULATION_BASE_URL=f"http://{host}:8080",
        GOPHISH_PHISH_PUBLIC_URL=f"http://{host}:8080",
        PUBLIC_PROXY_URL=f"http://{host}:3128",
        ALLOWED_ORIGINS=",".join(origins),
    )

    if mode == "standalone":
        values.update(
            API_URL="http://127.0.0.1:5000",
            SMTP_HOST="127.0.0.1",
            PROXY_ENFORCEMENT_API_URL="http://127.0.0.1:5000/api/proxy/enforcement/check",
            ML_DOMAIN_MODEL_DIR=str(directory / "backend/models/domain_v3"),
            ML_STACKER_MODEL_DIR=str(directory / "backend/models/stacker_v1"),
            TRANCO_CSV_PATH=str(directory / "dataset/raw/tranco/tranco_Y8YYG.csv"),
            DB_PATH=str(directory / "backend/instance/human_firewall.db"),
        )

    if vt_keys:
        clean_keys = [k.strip() for k in re.split(r"[,\s;]+", vt_keys) if len(k.strip()) >= 16]
        if clean_keys:
            values["VT_API_KEY"] = clean_keys[0]
            values["VT_API_KEYS"] = ",".join(clean_keys)
            values["VT_REQUESTS_PER_MINUTE"] = str(4 * len(clean_keys))
    else:
        for k in ("VT_API_KEY", "VT_API_KEYS", "VT_REQUESTS_PER_MINUTE", "GEMINI_API_KEY", "GOPHISH_API_KEY"):
            if k in existing and existing[k] and not existing[k].startswith("replace-with-"):
                values[k] = existing[k]

    template_text = template_path.read_text(encoding="utf-8")
    merged_keys = {**existing, **values}

    def replace_line(match: re.Match) -> str:
        key = match.group(1)
        if key in merged_keys:
            return f"{key}={merged_keys[key]}"
        return match.group(0)

    content = re.sub(r"^([A-Z0-9_]+)=.*$", replace_line, template_text, flags=re.M)
    # Preserve any extra custom keys from existing .env not in .env.example
    template_keys = set(re.findall(r"^([A-Z0-9_]+)=", content, flags=re.M))
    extra_lines = [f"{k}={v}" for k, v in merged_keys.items() if k not in template_keys]
    if extra_lines:
        content = content.rstrip("\n") + "\n\n# Custom/Extra Environment Keys\n" + "\n".join(extra_lines) + "\n"

    env_path.write_text(content, encoding="utf-8")
    env_path.chmod(0o600)

    proxy_values = {
        "POSTGRES_DB": merged_keys.get("PROXY_DB_NAME", "afferent_proxy"),
        "POSTGRES_USER": merged_keys.get("PROXY_DB_USER", "afferent_proxy_app"),
        "POSTGRES_PASSWORD": values["PROXY_DB_PASSWORD"],
        "PROXY_DB_PASSWORD": values["PROXY_DB_PASSWORD"],
        "REDIS_PASSWORD": values["REDIS_PASSWORD"],
        "PROXY_IDENTITY_PEPPER": values["PROXY_IDENTITY_PEPPER"],
        "ML_WEBHOOK_SECRET": values["ML_WEBHOOK_SECRET"],
    }
    proxy_path.write_text("\n".join(f"{k}={v}" for k, v in proxy_values.items()) + "\n", encoding="utf-8")
    proxy_path.chmod(0o600)

    return env_path, proxy_path, bool(existing)


def check_tcp_port(host: str, port: int, timeout: float = 0.8) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def check_http_health(url: str, timeout: float = 1.5) -> tuple[bool, int]:
    try:
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return (200 <= resp.status < 400), resp.status
    except urllib.error.HTTPError as e:
        return False, e.code
    except Exception:
        return False, 0


def run_doctor(directory: Path = ROOT, auto_fix: bool = False) -> int:
    print("=" * 74)
    print("  AFFERENT · INSTALLATION & RUNTIME DOCTOR")
    print("=" * 74)

    passes = 0
    warns = 0
    fails = 0
    fixes_applied: list[str] = []
    remediations: list[str] = []

    def record(status: str, section: str, msg: str, fix_hint: str = ""):
        nonlocal passes, warns, fails
        icon = {"PASS": "[OK]  ", "WARN": "[WARN]", "FAIL": "[FAIL]"}[status]
        if status == "PASS":
            passes += 1
        elif status == "WARN":
            warns += 1
        else:
            fails += 1
        print(f"  {icon} {section:<24} {msg}")
        if fix_hint and status in ("WARN", "FAIL"):
            remediations.append(f"• {section}: {fix_hint}")

    # -------------------------------------------------------------------------
    # 1. Python & System Prerequisites
    # -------------------------------------------------------------------------
    print("\n[1/5] Python & System Dependencies")
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    if sys.version_info >= (3, 10):
        record("PASS", "Python Version", f"Python {py_ver} ({sys.executable})")
    else:
        record("FAIL", "Python Version", f"Python {py_ver} (< 3.10)", "Install Python 3.10+")

    in_venv = sys.prefix != sys.base_prefix or (directory / "venv").is_dir()
    if in_venv:
        record("PASS", "Virtualenv", f"Detected ({directory / 'venv'})")
    else:
        record("WARN", "Virtualenv", "No venv detected", "Run: python3 -m venv venv && source venv/bin/activate")

    required_mods = ("flask", "requests", "joblib", "sklearn", "xgboost", "torch", "psycopg", "redis")
    missing_mods = [m for m in required_mods if importlib.util.find_spec(m) is None]
    if not missing_mods:
        record("PASS", "Python ML/Web Packages", "All core packages installed (flask, torch, xgboost, sklearn, psycopg, redis)")
    else:
        record(
            "WARN" if "venv" not in sys.executable and (directory / "venv/bin/python").exists() else "FAIL",
            "Python ML/Web Packages",
            f"Missing in current interpreter ({sys.executable}): {', '.join(missing_mods)}",
            f"{directory / 'venv/bin/pip'} install -r backend/requirements.txt -r backend/requirements-ml.txt",
        )

    for bin_name, label in (("node", "Node.js"), ("npm", "npm"), ("docker", "Docker CLI"), ("squid", "Squid Proxy")):
        path = shutil.which(bin_name)
        if path:
            record("PASS", f"Binary: {label}", path)
        else:
            record("WARN", f"Binary: {label}", "Not found in PATH", f"Install {label} if running {bin_name} locally")

    # -------------------------------------------------------------------------
    # 2. Environment Configuration (.env & .env.proxy.local)
    # -------------------------------------------------------------------------
    print("\n[2/5] Environment & Secret Hygiene (.env)")
    env_path = directory / ".env"
    proxy_env_path = directory / ".env.proxy.local"
    example_path = directory / ".env.example"

    if not env_path.is_file():
        if auto_fix and example_path.is_file():
            ips = detect_ips()
            host = ips.get("tailscale") or ips.get("lan") or "127.0.0.1"
            write_or_update_env(directory, host=host, mode="standalone", force_update=True)
            fixes_applied.append(f"Generated .env and .env.proxy.local for host {host}")
            record("PASS", ".env File", f"Auto-created for host {host}")
        else:
            record("FAIL", ".env File", "Missing .env file", "Run: python scripts/afferent_doctor.py setup")
    else:
        mode_oct = oct(env_path.stat().st_mode & 0o777)
        if (env_path.stat().st_mode & 0o077) != 0:
            if auto_fix:
                env_path.chmod(0o600)
                fixes_applied.append("Restricted .env file permissions to 0600")
                record("PASS", ".env Permissions", "Fixed to 0600")
            else:
                record("WARN", ".env Permissions", f"Permissions are {mode_oct} (recommended 0600)", "Run: chmod 600 .env")
        else:
            record("PASS", ".env Permissions", "0600 (owner-only)")

        env_vars = parse_env_file(env_path)
        example_vars = parse_env_file(example_path)
        missing_env_keys = [k for k in example_vars if k not in env_vars]
        if missing_env_keys and auto_fix:
            with env_path.open("a", encoding="utf-8") as f:
                f.write("\n# Auto-synced missing keys from .env.example\n")
                for k in missing_env_keys:
                    val = secrets.token_urlsafe(48) if k in SECRET_KEYS else example_vars[k]
                    f.write(f"{k}={val}\n")
                    env_vars[k] = val
            fixes_applied.append(f"Added {len(missing_env_keys)} missing keys to .env: {', '.join(missing_env_keys)}")
            missing_env_keys = []

        if not missing_env_keys:
            record("PASS", ".env Schema Sync", "All template keys present")
        else:
            record(
                "WARN",
                ".env Schema Sync",
                f"Missing {len(missing_env_keys)} keys ({', '.join(missing_env_keys[:4])}...)",
                "Run: python scripts/afferent_doctor.py doctor --fix",
            )

        bad_secrets = [
            k for k in ("SECRET_KEY", "ADMIN_PASSWORD", "SERVICE_API_KEY", "OTP_PEPPER", "AUTH_AUDIT_PEPPER")
            if not env_vars.get(k) or env_vars.get(k, "").startswith("replace-with-")
        ]
        if bad_secrets and auto_fix:
            raw_content = env_path.read_text(encoding="utf-8")
            for k in bad_secrets:
                new_val = ("Af!" + secrets.token_urlsafe(24)) if k == "ADMIN_PASSWORD" else secrets.token_urlsafe(48)
                if re.search(rf"^{k}=.*$", raw_content, flags=re.M):
                    raw_content = re.sub(rf"^{k}=.*$", f"{k}={new_val}", raw_content, flags=re.M)
                else:
                    raw_content = raw_content.rstrip("\n") + f"\n{k}={new_val}\n"
                env_vars[k] = new_val
            env_path.write_text(raw_content, encoding="utf-8")
            fixes_applied.append(f"Generated secure random values for placeholder secrets: {', '.join(bad_secrets)}")
            bad_secrets = []

        if not bad_secrets:
            record("PASS", "Bootstrap Secrets", "All mandatory secrets configured & non-placeholder")
        else:
            record(
                "FAIL",
                "Bootstrap Secrets",
                f"Placeholder/empty secrets: {', '.join(bad_secrets)}",
                "Run: python scripts/afferent_doctor.py doctor --fix",
            )

        # Check VT multi-key pool
        raw_vt = env_vars.get("VT_API_KEYS") or env_vars.get("VT_API_KEY") or ""
        vt_keys = [k.strip() for k in re.split(r"[,\s;]+", raw_vt) if len(k.strip()) >= 16]
        if vt_keys:
            record("PASS", "VirusTotal Key Pool", f"{len(vt_keys)} active key(s) ({len(vt_keys) * 4} req/min budget)")
        else:
            record("WARN", "VirusTotal Key Pool", "No VT_API_KEY / VT_API_KEYS configured (fallback will return Unknown)", "Set VT_API_KEYS in .env")

    if proxy_env_path.is_file():
        record("PASS", ".env.proxy.local", "Present for PostgreSQL/Redis proxy containers")
    else:
        if auto_fix and env_path.is_file():
            env_vars = parse_env_file(env_path)
            proxy_vals = {
                "POSTGRES_DB": env_vars.get("PROXY_DB_NAME", "afferent_proxy"),
                "POSTGRES_USER": env_vars.get("PROXY_DB_USER", "afferent_proxy_app"),
                "POSTGRES_PASSWORD": env_vars.get("PROXY_DB_PASSWORD") or secrets.token_urlsafe(48),
                "PROXY_DB_PASSWORD": env_vars.get("PROXY_DB_PASSWORD") or secrets.token_urlsafe(48),
                "REDIS_PASSWORD": env_vars.get("REDIS_PASSWORD") or secrets.token_urlsafe(48),
                "PROXY_IDENTITY_PEPPER": env_vars.get("PROXY_IDENTITY_PEPPER") or secrets.token_urlsafe(48),
                "ML_WEBHOOK_SECRET": env_vars.get("ML_WEBHOOK_SECRET") or secrets.token_urlsafe(48),
            }
            proxy_env_path.write_text("\n".join(f"{k}={v}" for k, v in proxy_vals.items()) + "\n", encoding="utf-8")
            proxy_env_path.chmod(0o600)
            fixes_applied.append("Created missing .env.proxy.local")
            record("PASS", ".env.proxy.local", "Auto-created from .env")
        else:
            record("WARN", ".env.proxy.local", "Missing .env.proxy.local", "Run: python scripts/afferent_doctor.py doctor --fix")

    # -------------------------------------------------------------------------
    # 3. ML Models & Datasets Integrity
    # -------------------------------------------------------------------------
    print("\n[3/5] Machine Learning Models & Datasets")
    domain_v3_dir = directory / "backend/models/domain_v3"
    domain_clf = domain_v3_dir / "classifier.joblib"
    domain_man = domain_v3_dir / "manifest.json"
    if domain_clf.is_file() and domain_man.is_file():
        man_data = json.loads(domain_man.read_text(encoding="utf-8"))
        actual_sha = hashlib.sha256(domain_clf.read_bytes()).hexdigest()
        expected_sha = man_data.get("artifact_sha256")
        if actual_sha == expected_sha:
            record("PASS", "Model: Domain v3", f"Ready (SHA-256 verified: {actual_sha[:12]}...)")
        elif auto_fix:
            man_data["artifact_sha256"] = actual_sha
            domain_man.write_text(json.dumps(man_data, indent=2) + "\n", encoding="utf-8")
            fixes_applied.append("Synced Domain v3 manifest.json artifact_sha256 checksum")
            record("PASS", "Model: Domain v3", f"Auto-fixed SHA-256 checksum ({actual_sha[:12]}...)")
        else:
            record(
                "FAIL",
                "Model: Domain v3",
                "SHA-256 mismatch between classifier.joblib and manifest.json",
                "Run: python scripts/afferent_doctor.py doctor --fix",
            )
    else:
        record("FAIL", "Model: Domain v3", "Missing backend/models/domain_v3 artifacts")

    stacker_dir = directory / "backend/models/stacker_v1"
    stacker_clf = stacker_dir / "stacker.joblib"
    stacker_man = stacker_dir / "manifest.json"
    if stacker_clf.is_file() and stacker_man.is_file():
        s_man = json.loads(stacker_man.read_text(encoding="utf-8"))
        rev = s_man.get("model_revision") or s_man.get("model_version", "v1")
        thresh = s_man.get("block_threshold", 0.85)
        record("PASS", "Model: Stacker XGBoost", f"Ready (rev: {rev}, threshold: {thresh})")
    else:
        record("WARN", "Model: Stacker XGBoost", "Missing stacker_v1 artifact", "Run: python scripts/auto_retrain.py --now")

    tranco_csv = directory / "dataset/raw/tranco/tranco_Y8YYG.csv"
    if tranco_csv.is_file():
        size_kb = tranco_csv.stat().st_size // 1024
        record("PASS", "Dataset: Tranco Top-1M", f"Present ({size_kb} KB)")
    else:
        record("WARN", "Dataset: Tranco Top-1M", f"Not found at {tranco_csv}", "Restore dataset/raw/tranco/tranco_Y8YYG.csv")

    # -------------------------------------------------------------------------
    # 4. Databases & Certificates
    # -------------------------------------------------------------------------
    print("\n[4/5] Storage & PKI Certificates")
    instance_dir = directory / "backend/instance"
    if not instance_dir.is_dir():
        if auto_fix:
            instance_dir.mkdir(parents=True, exist_ok=True)
            fixes_applied.append("Created backend/instance directory")
    sqlite_db = instance_dir / "human_firewall.db"
    if sqlite_db.is_file():
        record("PASS", "SQLite Database", f"Ready ({sqlite_db.stat().st_size // 1024} KB)")
    else:
        record("WARN", "SQLite Database", "Will be initialized on first backend boot")

    ca_candidates = [
        directory / "proxy/ssl_cert/afferent-proxy-ca.crt",
        directory / "proxy/ssl/afferent-proxy-ca.crt",
        directory / "afferent-proxy-ca.crt",
    ]
    found_ca = next((p for p in ca_candidates if p.is_file()), None)
    if found_ca:
        record("PASS", "Proxy SSL CA Cert", f"Found ({found_ca.relative_to(directory)})")
    else:
        record(
            "WARN",
            "Proxy SSL CA Cert",
            "No proxy CA certificate found",
            "Run: python scripts/setup_lab.py --certificates --server-host <IP>",
        )

    # -------------------------------------------------------------------------
    # 5. Live Service & Port Health
    # -------------------------------------------------------------------------
    print("\n[5/5] Active Network Services & Ports")
    ok_api, code_api = check_http_health("http://127.0.0.1:5000/health")
    if ok_api:
        record("PASS", "Flask Backend (:5000)", f"Healthy (HTTP {code_api})")
    else:
        record("WARN", "Flask Backend (:5000)", "Not responding on :5000", "Run: systemctl --user restart afferent-backend.service")

    ok_ui, code_ui = check_http_health("http://127.0.0.1:3000")
    if ok_ui or check_tcp_port("127.0.0.1", 3000):
        record("PASS", "Next.js UI (:3000)", "Listening on :3000")
    else:
        record("WARN", "Next.js UI (:3000)", "Not listening on :3000", "Run: systemctl --user restart afferent-dashboard.service")

    if check_tcp_port("127.0.0.1", 3128):
        record("PASS", "Squid Proxy (:3128)", "Listening on :3128")
    else:
        record("WARN", "Squid Proxy (:3128)", "Not listening on :3128", "Check Squid service or docker compose ps")

    if check_tcp_port("127.0.0.1", 5432):
        record("PASS", "PostgreSQL (:5432)", "Listening on :5432")
    else:
        record("WARN", "PostgreSQL (:5432)", "Not listening on :5432", "Run: docker compose up -d proxy_postgres")

    if check_tcp_port("127.0.0.1", 6380) or check_tcp_port("127.0.0.1", 6379):
        port_r = 6380 if check_tcp_port("127.0.0.1", 6380) else 6379
        record("PASS", f"Redis (:{port_r})", f"Listening on :{port_r}")
    else:
        record("WARN", "Redis (:6379/:6380)", "Not listening", "Run: docker compose up -d proxy_redis")

    if check_tcp_port("127.0.0.1", 8089):
        record("PASS", "Testing Portal (:8089)", "Listening on :8089")
    else:
        record("WARN", "Testing Portal (:8089)", "Not listening on :8089", "Run: systemctl --user restart afferent-reports-server.service")

    # -------------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------------
    print("\n" + "=" * 74)
    print(f"  SUMMARY: {passes} PASSED | {warns} WARNINGS | {fails} FAILED")
    print("=" * 74)
    if fixes_applied:
        print("\n[+] Auto-Fixes Applied:")
        for fix in fixes_applied:
            print(f"  ✓ {fix}")
    if remediations:
        print("\n[!] Recommended Actions:")
        for rem in remediations:
            print(f"  {rem}")
    print()
    return 1 if fails > 0 else 0


def interactive_setup(directory: Path = ROOT, args: argparse.Namespace | None = None) -> int:
    print("=" * 74)
    print("  AFFERENT · INTERACTIVE ENVIRONMENT CONFIGURATOR (.env)")
    print("=" * 74)
    ips = detect_ips()
    default_host = (args and args.host) or ips.get("tailscale") or ips.get("lan") or "127.0.0.1"
    print(f"  Detected Network IPs: {', '.join(f'{k}={v}' for k, v in ips.items())}")

    if args and not sys.stdin.isatty():
        host = default_host
        mode = getattr(args, "mode", "standalone") or "standalone"
        vt_keys = getattr(args, "vt_keys", "") or ""
        force_update = getattr(args, "update", False)
    elif args and (args.host or args.vt_keys or args.update) and not getattr(args, "interactive", False):
        host = default_host
        mode = getattr(args, "mode", "standalone") or "standalone"
        vt_keys = getattr(args, "vt_keys", "") or ""
        force_update = getattr(args, "update", False)
    else:
        raw_host = input(f"\n1. Server IPv4 / Hostname [{default_host}]: ").strip()
        host = raw_host or default_host
        raw_mode = input("2. Deployment Mode (standalone / docker) [standalone]: ").strip().lower()
        mode = raw_mode if raw_mode in ("standalone", "docker") else "standalone"
        vt_keys = input("3. VirusTotal API Key(s) (comma-separated, or Enter to keep/skip): ").strip()
        force_update = True

    try:
        env_path, proxy_path, updated = write_or_update_env(
            directory,
            host=host,
            mode=mode,
            vt_keys=vt_keys,
            force_update=force_update or not (directory / ".env").exists(),
        )
        action = "Updated" if updated else "Created"
        print(f"\n[+] {action} configuration files:")
        print(f"    • {env_path} (chmod 0600)")
        print(f"    • {proxy_path} (chmod 0600)")
        print(f"    • Dashboard URL : http://{host}:3000")
        print(f"    • Backend API   : http://{host}:5000")
        print(f"    • Proxy Gateway : http://{host}:3128")
        print("\nNext: Run `python scripts/afferent_doctor.py` to verify your installation.")
        return 0
    except Exception as exc:
        print(f"\n[!] Setup error: {exc}", file=sys.stderr)
        return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="AFFERENT .env Configurator & Installation Doctor")
    sub = parser.add_subparsers(dest="command")

    doc_p = sub.add_parser("doctor", help="Run installation & runtime health diagnostics")
    doc_p.add_argument("--fix", action="store_true", help="Automatically fix permissions, missing keys, and model checksums")

    set_p = sub.add_parser("setup", help="Create or update .env and .env.proxy.local")
    set_p.add_argument("--host", help="Server IPv4 or DNS hostname (auto-detected if omitted)")
    set_p.add_argument("--mode", choices=("standalone", "docker"), default="standalone", help="Path layout mode")
    set_p.add_argument("--vt-keys", default="", help="Comma-separated VirusTotal API keys")
    set_p.add_argument("--update", action="store_true", help="Safely patch existing .env without losing secrets")
    set_p.add_argument("--interactive", "-i", action="store_true", help="Interactive prompt mode")

    parser.add_argument("--fix", action="store_true", help="Run doctor with auto-fix enabled")
    args = parser.parse_args()

    if args.command == "setup":
        return interactive_setup(ROOT, args)
    return run_doctor(ROOT, auto_fix=getattr(args, "fix", False))


if __name__ == "__main__":
    raise SystemExit(main())
