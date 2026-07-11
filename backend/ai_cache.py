"""
ai_cache.py — Caching layer untuk hasil analisis AI.

Tujuan:
- Hemat API quota Gemini (free tier: 1500 req/hari)
- Response lebih cepat untuk request berulang
- Simpan hasil ke SQLite (tabel ai_cache) agar persist antar restart

TTL default 1 jam — cukup fresh untuk demo, tapi tidak spam API.
"""

import sqlite3
import json
import os
from datetime import datetime, timedelta

DB_PATH = os.path.join('instance', 'human_firewall.db')

# TTL (Time-To-Live) cache dalam detik
CACHE_TTL_SECONDS = 3600  # 1 jam


def _get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_cache_table():
    """Buat tabel ai_cache jika belum ada. Dipanggil sekali saat startup."""
    os.makedirs('instance', exist_ok=True)
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ai_cache (
            cache_key   TEXT PRIMARY KEY,
            result_json TEXT NOT NULL,
            created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at  TIMESTAMP NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def get_cached(cache_key: str) -> dict | None:
    """
    Ambil hasil dari cache. Return None jika tidak ada atau sudah expired.
    """
    conn = _get_conn()
    row = conn.execute(
        "SELECT result_json, expires_at FROM ai_cache WHERE cache_key = ?",
        (cache_key,)
    ).fetchone()
    conn.close()

    if row is None:
        return None

    # Cek apakah masih berlaku
    expires_at = datetime.fromisoformat(row["expires_at"])
    if datetime.utcnow() > expires_at:
        # Cache expired, hapus
        invalidate(cache_key)
        return None

    try:
        return json.loads(row["result_json"])
    except (json.JSONDecodeError, TypeError):
        return None


def set_cache(cache_key: str, result: dict, ttl_seconds: int = CACHE_TTL_SECONDS):
    """
    Simpan hasil analisis ke cache dengan TTL tertentu.
    Upsert: kalau key sudah ada, timpa dengan data baru.
    """
    expires_at = (datetime.utcnow() + timedelta(seconds=ttl_seconds)).isoformat()
    result_json = json.dumps(result, ensure_ascii=False)

    conn = _get_conn()
    conn.execute("""
        INSERT OR REPLACE INTO ai_cache (cache_key, result_json, created_at, expires_at)
        VALUES (?, ?, CURRENT_TIMESTAMP, ?)
    """, (cache_key, result_json, expires_at))
    conn.commit()
    conn.close()


def invalidate(cache_key: str):
    """Hapus satu entri cache (misal setelah data user berubah)."""
    conn = _get_conn()
    conn.execute("DELETE FROM ai_cache WHERE cache_key = ?", (cache_key,))
    conn.commit()
    conn.close()


def invalidate_all():
    """
    Hapus semua cache AI. Berguna saat seed data diulang atau
    admin minta refresh manual dari dashboard.
    """
    conn = _get_conn()
    conn.execute("DELETE FROM ai_cache")
    conn.commit()
    conn.close()


def cleanup_expired():
    """Bersihkan entri yang sudah expired. Opsional, bisa dijadwal berkala."""
    conn = _get_conn()
    conn.execute("DELETE FROM ai_cache WHERE expires_at < ?", (datetime.utcnow().isoformat(),))
    conn.commit()
    conn.close()


def get_cache_stats() -> dict:
    """Kembalikan statistik cache untuk debugging/monitoring."""
    conn = _get_conn()
    total = conn.execute("SELECT COUNT(*) FROM ai_cache").fetchone()[0]
    valid = conn.execute(
        "SELECT COUNT(*) FROM ai_cache WHERE expires_at > ?",
        (datetime.utcnow().isoformat(),)
    ).fetchone()[0]
    conn.close()
    return {"total_entries": total, "valid_entries": valid, "expired": total - valid}
