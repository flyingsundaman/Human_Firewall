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
    # max_retries=0 — matikan retry internal SDK agar fallback loop kita yang handle
    # timeout=25   — batas waktu 25 detik per request, tidak nunggu 30+ detik
    client = openai.OpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=api_key,
        max_retries=0,
        timeout=25.0,
    )
    return client


def _call_openrouter(system_prompt: str, user_prompt: str, expect_json: bool = True) -> dict | str:
    """
    Wrapper untuk memanggil OpenRouter API.
    - expect_json=True: parse response sebagai JSON, return dict
    - expect_json=False: return raw text (untuk laporan naratif)
    """
    client = _get_openrouter_client()
    
    # ── Fallback Model List ───────────────────────────────────────────────
    # Prioritas dari atas ke bawah. Jika satu gagal (404/429/400),
    # sistem otomatis lanjut ke model berikutnya.
    # Model di sini diambil dari konfigurasi OpenRouter yang terkonfirmasi aktif.
    FALLBACK_MODELS = [
        os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free"),
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen3-coder:free",
        "deepseek/deepseek-v4-flash:free",
        "nvidia/nemotron-3-super-120b-a12b:free",
        "qwen/qwen3-next-80b-a3b-instruct:free",
        "google/gemma-4-31b-it:free",
        "google/gemma-4-26b-a4b-it:free",
        "openai/gpt-oss-20b:free",
    ]
    
    # Hapus duplikat, pertahankan urutan
    unique_models = list(dict.fromkeys(FALLBACK_MODELS))

    response = None
    last_error = None
    
    for model_name in unique_models:
        try:
            response = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
            )
            logger.info(f"[Model] Berhasil menggunakan: {model_name}")
            break  # Jika berhasil, keluar dari loop fallback
        except Exception as e:
            logger.warning(f"[Fallback] Model '{model_name}' gagal ({type(e).__name__}). Mencoba selanjutnya...")
            last_error = e
            continue
            
    if not response:
        raise ValueError(f"Semua model fallback gagal. Error terakhir: {last_error}")

    
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


# ─── Endpoint 5: Agentic Investigate ────────────────────────────────────────

# ─── Tool Definitions untuk Agentic AI ──────────────────────────────────────
# Agent dapat memanggil tool-tool ini secara otonom selama proses investigasi.
# Setiap tool merepresentasikan sebuah "kemampuan" untuk mengambil data konteks.

AGENTIC_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "get_user_behavior_history",
            "description": "Ambil histori perilaku user: click_count phishing, training yang ditonton/diskip, poin gamifikasi, badge, dan timestamp terakhir klik. Gunakan ini pertama kali untuk memahami profil user.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Alamat email user yang ingin diinvestigasi."
                    }
                },
                "required": ["email"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_division_risk_ranking",
            "description": "Ambil ranking risiko semua divisi berdasarkan poin rata-rata. Gunakan ini untuk membandingkan user dengan rata-rata divisinya.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_open_incidents_by_division",
            "description": "Ambil daftar insiden keamanan yang masih 'open' di divisi tertentu. Gunakan ini untuk melihat apakah ada ancaman aktif di lingkungan kerja user.",
            "parameters": {
                "type": "object",
                "properties": {
                    "divisi": {
                        "type": "string",
                        "description": "Nama divisi yang ingin dicek insidennya."
                    }
                },
                "required": ["divisi"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_user_recent_events",
            "description": "Ambil 10 event terbaru user (klik, training, dll). Gunakan ini untuk melihat pola aktivitas paling baru.",
            "parameters": {
                "type": "object",
                "properties": {
                    "email": {
                        "type": "string",
                        "description": "Alamat email user."
                    }
                },
                "required": ["email"]
            }
        }
    }
]


def _execute_tool(tool_name: str, tool_args: dict) -> str:
    """Eksekusi tool yang dipanggil Agent dan kembalikan hasilnya sebagai string JSON."""
    import database

    if tool_name == "get_user_behavior_history":
        result = database.get_user_history(tool_args["email"])
        return json.dumps(result, default=str)

    elif tool_name == "get_division_risk_ranking":
        lb = database.get_leaderboard()
        return json.dumps(lb.get("by_divisi", []), default=str)

    elif tool_name == "get_open_incidents_by_division":
        incidents = database.list_incidents(status="open")
        divisi = tool_args.get("divisi", "").lower()
        filtered = [i for i in incidents if (i.get("divisi") or "").lower() == divisi]
        return json.dumps(filtered, default=str)

    elif tool_name == "get_user_recent_events":
        conn = database.get_connection()
        try:
            rows = conn.execute(
                "SELECT event_type, divisi, created_at, campaign_id FROM events WHERE email = ? ORDER BY created_at DESC LIMIT 10",
                (tool_args["email"],)
            ).fetchall()
            return json.dumps([dict(r) for r in rows], default=str)
        finally:
            conn.close()

    return json.dumps({"error": f"Tool '{tool_name}' tidak dikenal."})


@ai_bp.route('/api/ai/agentic/investigate', methods=['POST'])
def agentic_investigate():
    """
    ─── AGENTIC AI INVESTIGATOR ───────────────────────────────────────────────
    Endpoint ini menjalankan multi-step agentic reasoning.

    Agent bertindak sebagai "Security Analyst" virtual yang secara otonom:
    1. Menerima target investigasi (email user atau free-text query).
    2. Memutuskan sendiri tool mana yang perlu dipanggil untuk mengumpulkan data.
    3. Melakukan iterasi (max 5 langkah) sampai agent puas dengan konteksnya.
    4. Menghasilkan laporan investigasi final + rekomendasi tindakan.

    Request body (JSON):
        {
            "email": "rina.kusuma@netengineering-dummy.local",  // target user
            "query": "Apakah user ini berisiko tinggi?"         // optional, free text
        }

    Response:
        {
            "email": "...",
            "investigation_steps": [...],   // jejak langkah agent
            "final_report": {...},          // laporan final terstruktur
            "_steps_taken": 3,
            "_generated_at": "..."
        }
    """
    data = request.get_json(silent=True) or {}
    email = data.get("email", "").strip()
    query = data.get("query", f"Lakukan investigasi mendalam pada user dengan email {email} dan berikan rekomendasi tindakan.")

    if not email:
        return jsonify({"error": "Field 'email' wajib diisi."}), 400

    try:
        client = _get_openrouter_client()
        # Fallback list dipindahkan ke dalam loop agentic
    except RuntimeError as e:
        return jsonify({"error": "Konfigurasi AI Error", "detail": str(e)}), 503

    AGENTIC_SYSTEM_PROMPT = """Kamu adalah AI Security Analyst dari sistem Human Firewall.
Tugasmu adalah melakukan investigasi mendalam terhadap perilaku keamanan seorang karyawan.

Cara kerja:
1. Gunakan tool yang tersedia untuk mengumpulkan semua informasi yang relevan.
2. Analisis data secara holistik: bandingkan dengan rata-rata divisi, cek insiden aktif, lihat tren terbaru.
3. Setelah kamu merasa informasi cukup, buat laporan final dalam format JSON berikut:
{
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "risk_score": <0-100>,
  "summary": "<ringkasan singkat situasi user>",
  "key_findings": ["<temuan 1>", "<temuan 2>", ...],
  "recommended_actions": ["<aksi 1>", "<aksi 2>", ...],
  "narrative": "<penjelasan lengkap untuk SOC analyst>"
}

Gunakan Bahasa Indonesia. Jadilah spesifik dan gunakan data aktual yang kamu temukan."""

    messages = [
        {"role": "system", "content": AGENTIC_SYSTEM_PROMPT},
        {"role": "user", "content": f"Target investigasi: {email}\n\nQuery: {query}"}
    ]

    # ── Fallback Model List (sama dengan _call_openrouter) ──────────────
    FALLBACK_MODELS = [
        os.environ.get("OPENROUTER_MODEL", "meta-llama/llama-3.3-70b-instruct:free"),
        "meta-llama/llama-3.3-70b-instruct:free",
        "qwen/qwen3-coder:free",
        "deepseek/deepseek-v4-flash:free",
        "nvidia/nemotron-3-super-120b-a12b:free",
        "qwen/qwen3-next-80b-a3b-instruct:free",
        "google/gemma-4-31b-it:free",
        "google/gemma-4-26b-a4b-it:free",
        "openai/gpt-oss-20b:free",
    ]
    unique_models = list(dict.fromkeys(FALLBACK_MODELS))

    investigation_steps = []
    MAX_ITERATIONS = 5

    # ── Agentic Loop ──────────────────────────────────────────────────────────
    for iteration in range(MAX_ITERATIONS):
        response = None
        last_error = None
        
        # Coba model satu per satu
        for model_name in unique_models:
            try:
                response = client.chat.completions.create(
                    model=model_name,
                    messages=messages,
                    tools=AGENTIC_TOOLS,
                    tool_choice="auto",
                    temperature=0.2,
                )
                break # Berhasil!
            except Exception as e:
                logger.warning(f"[Agentic Fallback] Model {model_name} gagal: {e}. Mencoba model selanjutnya...")
                last_error = e
                continue
                
        if not response:
            return jsonify({"error": "Semua model fallback gagal merespons", "detail": str(last_error)}), 503

        choice = response.choices[0]
        msg = choice.message

        # Tambahkan response agent ke history
        messages.append({"role": "assistant", "content": msg.content, "tool_calls": [
            {
                "id": tc.id,
                "type": "function",
                "function": {"name": tc.function.name, "arguments": tc.function.arguments}
            } for tc in (msg.tool_calls or [])
        ]})

        # Jika agent tidak memanggil tool lagi — selesai
        if not msg.tool_calls:
            final_text = msg.content or ""
            # Coba parse sebagai JSON
            final_text = final_text.strip()
            if final_text.startswith("```"):
                final_text = final_text.split("```", 2)[-1] if "```" in final_text[3:] else final_text[3:]
                if final_text.startswith("json"):
                    final_text = final_text[4:]
                final_text = final_text.rsplit("```", 1)[0].strip()

            try:
                final_report = json.loads(final_text)
            except json.JSONDecodeError:
                final_report = {"narrative": final_text, "risk_level": "UNKNOWN"}

            return jsonify({
                "email": email,
                "investigation_steps": investigation_steps,
                "final_report": final_report,
                "_steps_taken": iteration + 1,
                "_generated_at": datetime.utcnow().isoformat(),
                "_model_used": model_name,
            }), 200

        # Eksekusi setiap tool yang dipanggil agent
        for tool_call in msg.tool_calls:
            tool_name = tool_call.function.name
            try:
                tool_args = json.loads(tool_call.function.arguments)
            except json.JSONDecodeError:
                tool_args = {}

            tool_result = _execute_tool(tool_name, tool_args)

            step_log = {
                "step": iteration + 1,
                "tool_called": tool_name,
                "args": tool_args,
                "result_preview": tool_result[:300] + "..." if len(tool_result) > 300 else tool_result
            }
            investigation_steps.append(step_log)
            logger.info(f"[Agentic] Step {iteration+1}: Called {tool_name}({tool_args})")

            # Kembalikan hasil tool ke agent
            messages.append({
                "role": "tool",
                "tool_call_id": tool_call.id,
                "content": tool_result
            })

    # Jika sudah max iterasi, minta kesimpulan paksa
    messages.append({
        "role": "user",
        "content": "Kamu telah mencapai batas investigasi. Berikan laporan final sekarang dalam format JSON yang sudah ditentukan."
    })
    final_response = client.chat.completions.create(
        model=model_name, messages=messages, temperature=0.2
    )
    final_text = (final_response.choices[0].message.content or "").strip()
    if final_text.startswith("```"):
        final_text = final_text[7:] if final_text.startswith("```json") else final_text[3:]
        final_text = final_text.rsplit("```", 1)[0].strip()
    try:
        final_report = json.loads(final_text)
    except json.JSONDecodeError:
        final_report = {"narrative": final_text, "risk_level": "UNKNOWN"}

    return jsonify({
        "email": email,
        "investigation_steps": investigation_steps,
        "final_report": final_report,
        "_steps_taken": MAX_ITERATIONS,
        "_generated_at": datetime.utcnow().isoformat(),
        "_model_used": model_name,
        "_warning": "Batas iterasi maksimum tercapai."
    }), 200
