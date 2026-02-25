"""
app.py — QR-Secure Flask Application
Main web server connecting database, security, and QR modules.
Routes:
    /               → Reception registration form
    /register       → POST: encrypt data, save to DB, generate QR
    /admin          → Admin scanning dashboard
    /scan           → POST: webcam scan trigger (AJAX)
    /verify/<id>    → GET:  decrypt & display visitor info
    /checkout/<id>  → POST: mark visitor as checked out
    /qr/<filename>  → Serve generated QR images
"""

import os
import re
import secrets
from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, jsonify, send_from_directory, session,
)

from database import init_db, add_visitor, get_visitor, get_all_visitors, update_status, set_verified_by
from security import encrypt_data, decrypt_data
from qr_handler import generate_qr, scan_qr_from_webcam, QR_DIR

# ── App Setup ──────────────────────────────────────────────────
app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FLASK_SECRET_FILE = os.path.join(BASE_DIR, ".flask_secret.key")


def _load_flask_secret_key() -> str:
    """
    Load Flask session key from environment or local file.
    Creates a stable key on first run if none exists.
    """
    env_key = os.getenv("FLASK_SECRET_KEY", "").strip()
    if env_key:
        return env_key

    if os.path.exists(FLASK_SECRET_FILE):
        with open(FLASK_SECRET_FILE, "r", encoding="utf-8") as f:
            stored_key = f.read().strip()
        if stored_key:
            return stored_key

    new_key = secrets.token_hex(32)
    with open(FLASK_SECRET_FILE, "w", encoding="utf-8") as f:
        f.write(new_key)
    return new_key


app.secret_key = _load_flask_secret_key()

# Admin credentials (change these for production)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# Initialise the database on first launch
init_db()


def _require_admin_redirect():
    """Redirect unauthenticated users to login."""
    if not session.get("admin_logged_in"):
        flash("Please log in first.", "error")
        return redirect(url_for("login"))
    return None


def _build_scan_response(visitor: dict, verified_by: str | None = None) -> dict:
    """Build a uniform JSON payload for scanned/verified visitor responses."""
    return {
        "success":     True,
        "id":          visitor["id"],
        "name":        visitor["name"],
        "phone":       decrypt_data(visitor["encrypted_phone"]),
        "purpose":     decrypt_data(visitor["encrypted_purpose"]),
        "timestamp":   visitor["timestamp"],
        "status":      visitor["status"],
        "verified_by": verified_by or visitor.get("verified_by") or "-",
    }


# ── Auth Routes ────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    """Admin login page with animated UI."""
    if session.get("admin_logged_in"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            session["username"] = username
            flash(f"Welcome, {username}!", "success")
            return redirect(url_for("admin"))
        else:
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    """Clear admin session."""
    session.pop("admin_logged_in", None)
    session.pop("username", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


# ── Public Routes ──────────────────────────────────────────────

@app.route("/")
def index():
    """Landing page with glassmorphism hero."""
    return render_template("index.html")


@app.route("/reception")
def reception():
    """Reception registration form (dark theme)."""
    return render_template("reception.html")


@app.route("/about")
def about():
    """About page — project overview for university examiners."""
    return render_template("about.html")


@app.route("/register", methods=["POST"])
def register():
    """
    Handle new visitor registration:
        1. Validate form inputs.
        2. Encrypt phone & purpose with AES-256.
        3. Store record in SQLite.
        4. Generate QR pass.
        5. Redirect to success page.
    """
    name    = request.form.get("name", "").strip()
    phone   = request.form.get("phone", "").strip()
    purpose = request.form.get("purpose", "").strip()

    # Basic validation
    if not all([name, phone, purpose]):
        flash("All fields are required.", "error")
        return redirect(url_for("reception"))

    if not re.fullmatch(r"\d{10}", phone):
        flash("Phone number must be exactly 10 digits.", "error")
        return redirect(url_for("reception"))

    try:
        # Encrypt sensitive fields
        enc_phone   = encrypt_data(phone)
        enc_purpose = encrypt_data(purpose)

        # Save to database
        visitor_id = add_visitor(name, enc_phone, enc_purpose)
        if visitor_id == -1:
            flash("Database error. Please try again.", "error")
            return redirect(url_for("reception"))

        # Generate QR pass
        generate_qr(visitor_id, enc_phone, enc_purpose)

        flash(f"Visitor registered successfully! ID: {visitor_id}", "success")
        return render_template(
            "success.html",
            visitor_id=visitor_id,
            name=name,
            qr_filename=f"visitor_{visitor_id}.png",
        )

    except Exception as e:
        flash(f"Registration failed: {e}", "error")
        return redirect(url_for("reception"))


@app.route("/admin")
def admin():
    """Admin dashboard — shows all visitors and scanning controls."""
    auth_redirect = _require_admin_redirect()
    if auth_redirect:
        return auth_redirect

    visitors = get_all_visitors()
    # Decrypt fields for display
    decrypted_visitors = []
    for v in visitors:
        try:
            decrypted_visitors.append({
                "id":          v["id"],
                "name":        v["name"],
                "phone":       decrypt_data(v["encrypted_phone"]),
                "purpose":     decrypt_data(v["encrypted_purpose"]),
                "timestamp":   v["timestamp"],
                "status":      v["status"],
                "verified_by": v.get("verified_by") or "-",
            })
        except Exception:
            decrypted_visitors.append({
                "id":          v["id"],
                "name":        v["name"],
                "phone":       "[decryption error]",
                "purpose":     "[decryption error]",
                "timestamp":   v["timestamp"],
                "status":      v["status"],
                "verified_by": v.get("verified_by") or "-",
            })
    return render_template("admin.html", visitors=decrypted_visitors)


@app.route("/scan", methods=["POST"])
def scan():
    """
    Trigger the webcam scanner. Returns JSON with decrypted visitor
    data or an error message. Called via AJAX from the admin page.
    """
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "message": "Authentication required. Please log in."}), 401

    try:
        result = scan_qr_from_webcam(timeout_seconds=30)
        if result is None:
            return jsonify({"success": False, "message": "No QR code detected. Try again."})

        visitor_id = result.get("id") if isinstance(result, dict) else None
        if visitor_id is None:
            return jsonify({"success": False, "message": "Invalid QR payload: missing visitor id."})

        try:
            visitor_id = int(visitor_id)
        except (TypeError, ValueError):
            return jsonify({"success": False, "message": "Invalid QR payload: visitor id is not a number."})

        visitor = get_visitor(visitor_id)
        if not visitor:
            return jsonify({"success": False, "message": f"Visitor ID {visitor_id} not found in database."})

        # ── Audit Trail: record which admin scanned this pass ──
        admin_user = session.get("username", "unknown")
        set_verified_by(visitor_id, admin_user)

        return jsonify(_build_scan_response(visitor, verified_by=admin_user))
    except RuntimeError as e:
        return jsonify({"success": False, "message": str(e)}), 503
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route("/api/verify-scan", methods=["POST"])
def verify_scan_api():
    """
    Verify a scanned visitor by ID.
    Used by browser-side mobile QR scanning from admin dashboard.
    """
    if not session.get("admin_logged_in"):
        return jsonify({"success": False, "message": "Authentication required. Please log in."}), 401

    payload = request.get_json(silent=True) or {}
    visitor_id = payload.get("visitor_id")
    if visitor_id is None:
        return jsonify({"success": False, "message": "Missing visitor_id in request body."}), 400

    try:
        visitor_id = int(visitor_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "visitor_id must be a number."}), 400

    visitor = get_visitor(visitor_id)
    if not visitor:
        return jsonify({"success": False, "message": f"Visitor ID {visitor_id} not found."}), 404

    admin_user = session.get("username", "unknown")
    set_verified_by(visitor_id, admin_user)

    try:
        return jsonify(_build_scan_response(visitor, verified_by=admin_user))
    except Exception:
        return jsonify({"success": False, "message": "Visitor found, but decrypt failed."}), 500


@app.route("/verify/<int:visitor_id>")
def verify(visitor_id):
    """Display decrypted visitor details (for manual lookup)."""
    auth_redirect = _require_admin_redirect()
    if auth_redirect:
        return auth_redirect

    visitor = get_visitor(visitor_id)
    if not visitor:
        flash("Visitor not found.", "error")
        return redirect(url_for("admin"))

    try:
        decrypted = {
            "id":        visitor["id"],
            "name":      visitor["name"],
            "phone":     decrypt_data(visitor["encrypted_phone"]),
            "purpose":   decrypt_data(visitor["encrypted_purpose"]),
            "timestamp": visitor["timestamp"],
            "status":    visitor["status"],
        }
    except Exception:
        flash("Failed to decrypt visitor data.", "error")
        return redirect(url_for("admin"))

    return render_template("verify.html", visitor=decrypted)


@app.route("/checkout/<int:visitor_id>", methods=["POST"])
def checkout(visitor_id):
    """Mark a visitor as checked out."""
    auth_redirect = _require_admin_redirect()
    if auth_redirect:
        return auth_redirect

    if update_status(visitor_id, "checked_out"):
        flash(f"Visitor {visitor_id} checked out.", "success")
    else:
        flash("Could not update status.", "error")
    return redirect(url_for("admin"))


@app.route("/qr/<filename>")
def serve_qr(filename):
    """Serve QR code images from the qr_codes/ directory."""
    return send_from_directory(QR_DIR, filename)


# ── Run ────────────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
