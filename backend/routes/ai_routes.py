"""
routes/ai_routes.py — Flask Blueprint untuk semua endpoint AI Behavioral Analysis.

Endpoints:
  GET  /api/ai/classify-all        → Klasifikasi batch semua user
  GET  /api/ai/user/<email>         → Analisis mendalam satu user
  GET  /api/ai/report?days=<n>      → Generate laporan naratif organisasi
  POST /api/ai/cache/invalidate     → Force-invalidate cache (admin only)
  GET  /api/ai/cache/stats          → Status cache (untuk debugging)

Semua endpoint protected oleh middleware auth di app.py (Bearer token / session).
"""

from flask import Blueprint, request, jsonify
import os
import json
import logging
import ai_analysis
import ai_prompts
import ai_cache
from datetime import datetime

logger = logging.getLogger(__name__)
ai_bp = Blueprint('ai', __name__)

# ─── Gemini Client Setup ────────────────────────────────────────────────────

def _get_openrouter_client():
    """Lazy-load OpenRouter client via OpenAI SDK. Raise RuntimeError kalau API key belum diset."""
    try:
        import openai
    except ImportError:
        raise RuntimeError(
            "openai belum terinstall. "
            "Jalankan: pip install openai"
        )

    api_key = os.environ.get("OPENROUTER_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Environment variable 'OPENROUTER_API_KEY' belum diset. "
            "Dapatkan key gratis di: https://openrouter.ai"
        )

    # Inisialisasi client OpenAI yang diarahkan ke OpenRouter
    client = openai.OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
    )
    return client


def _call_openrouter(system_prompt: str, user_prompt: str, expect_json: bool = True) -> dict | str:
    """
    Wrapper untuk memanggil OpenRouter API.
    - expect_json=True: parse response sebagai JSON, return dict
    - expect_json=False: return raw text (untuk laporan naratif)
    """
    client = _get_openrouter_client()
    model_name = os.environ.get("OPENROUTER_MODEL", "google/gemini-2.0-pro-exp-02-05:free")

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ],
        temperature=0.3,
    )
    
    raw_text = response.choices[0].message.content or ""

    if not expect_json:
        return raw_text

    # Bersihkan markdown code block kalau ada (model kadang masih nambahin)
    raw_text = raw_text.strip()
    if raw_text.startswith("```json"):
        raw_text = raw_text[7:]
    elif raw_text.startswith("```"):
        raw_text = raw_text[3:]
    if raw_text.endswith("```"):
        raw_text = raw_text[:-3]

    try:
        return json.loads(raw_text)
    except json.JSONDecodeError as e:
        logger.error(f"Gemini JSON parse error: {e}\nRaw: {raw_text[:500]}")
        raise ValueError(f"Gemini mengembalikan format yang tidak valid: {str(e)}")


# ─── Endpoint 1: Klasifikasi Semua User (Batch) ─────────────────────────────

@ai_bp.route('/api/ai/classify-all', methods=['GET'])
def classify_all_users():
    """
    Klasifikasi risk level semua user sekaligus.
    Cocok untuk SOC overview dashboard.
    Cache TTL: 1 jam.
    """
    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    cache_key = "ai:classify_all"

    if not force_refresh:
        cached = ai_cache.get_cached(cache_key)
        if cached:
            cached["_from_cache"] = True
            return jsonify(cached), 200

    try:
        users = ai_analysis.get_all_users_summary()
        if not users:
            return jsonify({"error": "Tidak ada data user di database"}), 404

        prompt = ai_prompts.build_batch_classification_prompt(users)
        result = _call_openrouter(
            system_prompt=ai_prompts.USER_ANALYSIS_SYSTEM,
            user_prompt=prompt,
            expect_json=True
        )

        result["_generated_at"] = datetime.utcnow().isoformat()
        result["_from_cache"] = False
        result["_total_users"] = len(users)

        ai_cache.set_cache(cache_key, result)
        return jsonify(result), 200

    except RuntimeError as e:
        return jsonify({"error": "Konfigurasi AI Error", "detail": str(e)}), 503
    except ValueError as e:
        return jsonify({"error": "AI response tidak valid", "detail": str(e)}), 502
    except Exception as e:
        logger.exception("classify_all_users error")
        return jsonify({"error": "Internal error", "detail": str(e)}), 500


# ─── Endpoint 2: Analisis Mendalam Per User ─────────────────────────────────

@ai_bp.route('/api/ai/user/<path:email>', methods=['GET'])
def analyze_user(email: str):
    """
    Analisis mendalam satu user: klasifikasi + edukasi personal + rekomendasi.
    Cache TTL: 1 jam per user.
    """
    days = int(request.args.get('days', 30))
    if days not in (1, 7, 14, 30):
        days = 30

    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    cache_key = f"ai:user:{email}:days{days}"

    if not force_refresh:
        cached = ai_cache.get_cached(cache_key)
        if cached:
            cached["_from_cache"] = True
            return jsonify(cached), 200

    try:
        user_ctx = ai_analysis.build_user_context(email, days)
        if user_ctx is None:
            return jsonify({"error": f"User '{email}' tidak ditemukan di database"}), 404

        prompt = ai_prompts.build_user_analysis_prompt(user_ctx)
        result = _call_openrouter(
            system_prompt=ai_prompts.USER_ANALYSIS_SYSTEM,
            user_prompt=prompt,
            expect_json=True
        )

        # Tambahkan konteks asli ke response agar frontend bisa pakai
        result["_raw_context"] = {
            "divisi": user_ctx["divisi"],
            "period_days": days,
            "summary": user_ctx["summary"],
            "trend": user_ctx["trend"],
        }
        result["_generated_at"] = datetime.utcnow().isoformat()
        result["_from_cache"] = False

        ai_cache.set_cache(cache_key, result)
        return jsonify(result), 200

    except RuntimeError as e:
        return jsonify({"error": "Konfigurasi AI Error", "detail": str(e)}), 503
    except ValueError as e:
        return jsonify({"error": "AI response tidak valid", "detail": str(e)}), 502
    except Exception as e:
        logger.exception(f"analyze_user error for {email}")
        return jsonify({"error": "Internal error", "detail": str(e)}), 500


# ─── Endpoint 3: Laporan Organisasi ─────────────────────────────────────────

@ai_bp.route('/api/ai/report', methods=['GET'])
def generate_org_report():
    """
    Generate laporan naratif analisis perilaku keamanan organisasi.
    Parameter: days = 1 | 7 | 14 | 30 (default: 7)
    Cache TTL: 1 jam.
    """
    days = int(request.args.get('days', 7))
    if days not in (1, 7, 14, 30):
        days = 7

    force_refresh = request.args.get('refresh', 'false').lower() == 'true'
    cache_key = f"ai:report:days{days}"

    if not force_refresh:
        cached = ai_cache.get_cached(cache_key)
        if cached:
            cached["_from_cache"] = True
            return jsonify(cached), 200

    try:
        org_ctx = ai_analysis.build_org_context(days)
        prompt = ai_prompts.build_org_report_prompt(org_ctx, days)

        result = _call_openrouter(
            system_prompt=ai_prompts.ORG_REPORT_SYSTEM,
            user_prompt=prompt,
            expect_json=True
        )

        result["_generated_at"] = datetime.utcnow().isoformat()
        result["_from_cache"] = False
        result["_org_context_snapshot"] = {
            "total_employees": org_ctx["total_employees"],
            "risk_distribution": org_ctx["risk_distribution"],
            "period_days": days,
        }

        ai_cache.set_cache(cache_key, result)
        return jsonify(result), 200

    except RuntimeError as e:
        return jsonify({"error": "Konfigurasi AI Error", "detail": str(e)}), 503
    except ValueError as e:
        return jsonify({"error": "AI response tidak valid", "detail": str(e)}), 502
    except Exception as e:
        logger.exception("generate_org_report error")
        return jsonify({"error": "Internal error", "detail": str(e)}), 500


# ─── Endpoint 4: Cache Management ───────────────────────────────────────────

@ai_bp.route('/api/ai/cache/invalidate', methods=['POST'])
def invalidate_ai_cache():
    """Force-invalidate semua cache AI. Berguna setelah seed ulang database."""
    try:
        ai_cache.invalidate_all()
        return jsonify({"message": "Semua cache AI berhasil dihapus"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@ai_bp.route('/api/ai/cache/stats', methods=['GET'])
def cache_stats():
    """Return statistik cache untuk debugging."""
    try:
        stats = ai_cache.get_cache_stats()
        return jsonify(stats), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500
