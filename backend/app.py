"""
app.py — Flask API untuk Human Firewall Lite.
"""

from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
import database
import os

# =============================================================================
# DEV_BYPASS_AUTH — Development Mode untuk AI Behavioral Testing
# =============================================================================
# Set DEV_BYPASS_AUTH=true di file .env untuk menonaktifkan autentikasi.
# Ini memungkinkan testing endpoint AI (/api/ai/*) tanpa perlu login.
#
# ⚠️  WARNING: JANGAN set ke 'true' di environment production!
#     Selalu set kembali ke 'false' sebelum deploy.
# =============================================================================
DEV_BYPASS_AUTH = os.environ.get('DEV_BYPASS_AUTH', 'false').lower() == 'true'

if DEV_BYPASS_AUTH:
    # Dev mode: pakai nilai dummy agar Flask bisa start tanpa .env lengkap
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'dev-bypass-password')
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-bypass-secret-key-not-for-production')
    import warnings
    warnings.warn(
        "\n" + "="*60 +
        "\n⚠️  DEV_BYPASS_AUTH=true — AUTH DINONAKTIFKAN!" +
        "\n   Mode ini hanya untuk development AI Behavioral." +
        "\n   JANGAN gunakan di production." +
        "\n" + "="*60,
        stacklevel=1
    )
else:
    # Production mode: env vars wajib ada
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD')
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not ADMIN_PASSWORD:
        raise RuntimeError("CRITICAL ERROR: Environment variable 'ADMIN_PASSWORD' is not set! Flask application refuses to start.")
    if not SECRET_KEY:
        raise RuntimeError("CRITICAL ERROR: Environment variable 'SECRET_KEY' is not set! Flask application refuses to start.")

app = Flask(__name__)
app.secret_key = SECRET_KEY

# CORS Whitelist configuration
CORS(app, origins=os.environ.get('ALLOWED_ORIGINS', 'http://localhost:3000').split(','))

# Initialize database on startup
database.init_db()

# Initialize AI cache table (tabel ai_cache di SQLite)
import ai_cache
ai_cache.init_cache_table()

# Register blueprints
from routes.auth import auth_bp
from routes.events import events_bp
from routes.incidents import incidents_bp
from routes.admin_api import admin_api_bp
from routes.ai_routes import ai_bp  # AI Behavioral Engine

app.register_blueprint(auth_bp)
app.register_blueprint(events_bp)
app.register_blueprint(incidents_bp)
app.register_blueprint(admin_api_bp)
app.register_blueprint(ai_bp)  # Daftarkan AI Blueprint

# Public endpoints whitelisting (matching blueprint endpoint paths)
# /api/telegram/user is deliberately excluded to prevent sensitive data exposure
PUBLIC_ROUTES = {
    'events.redirect_handler', 'events.fake_login_submit', 'events.save_event',
    'events.get_user_history', 'events.user_profile', 'events.create_otp', 'events.verify_otp',
    'events.register_telegram', 'events.list_emails', 'auth.admin_login', 'health',
    'static', 'auth.api_auth_admin', 'events.api_user_eligibility', 'events.api_user_activity'
}

# Jika DEV_BYPASS_AUTH aktif, tambahkan semua endpoint AI ke public routes
# agar bisa diakses langsung tanpa Bearer token / session cookie.
if DEV_BYPASS_AUTH:
    PUBLIC_ROUTES.update({
        'ai.classify_all_users',
        'ai.analyze_user',
        'ai.generate_org_report',
        'ai.invalidate_ai_cache',
        'ai.cache_stats',
        'ai.agentic_investigate',  # endpoint baru
    })

@app.before_request
def require_admin_for_protected_routes():
    """Guard: redirect ke login page atau return 401 kalau belum autentikasi.
    Hanya berlaku untuk route yang TIDAK ada di PUBLIC_ROUTES.

    NOTE (DEV): Jika DEV_BYPASS_AUTH=true di .env, seluruh guard ini dilompati.
    Endpoint AI (/api/ai/*) juga otomatis ditambahkan ke PUBLIC_ROUTES.
    Lihat konfigurasi DEV_BYPASS_AUTH di bagian atas file ini.
    """
    # DEV MODE: Bypass seluruh auth check
    if DEV_BYPASS_AUTH:
        return

    if request.endpoint and request.endpoint not in PUBLIC_ROUTES:
        auth_header = request.headers.get('Authorization')
        
        # 1. Cek shared secret header untuk server-to-server (Next.js / n8n)
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            if token == SECRET_KEY:
                return

        # 2. Cek session cookie for legacy admin dashboard
        if session.get('is_admin'):
            return

        # 3. Return 401 JSON untuk endpoint API, atau 302 redirect untuk page biasa
        if request.path.startswith('/api/'):
            return jsonify({"error": "Unauthorized"}), 401
        return redirect(url_for('auth.admin_login'))

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/health')
def health():
    return jsonify({"status": "ok"}), 200

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    app.run(host='0.0.0.0', port=5000, debug=debug_mode)