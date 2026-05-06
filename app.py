from flask import Flask, render_template, request, jsonify, redirect, url_for, session, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from zapv2 import ZAPv2
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.units import inch
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.legends import Legend
from email.message import EmailMessage
from collections import Counter
import psycopg2
import psycopg2.extras
import smtplib
import ssl
import time
import threading
import uuid
import json
import secrets
import io
import os
import logging
import re
import html

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ---------------- APP / ENV CONFIG ----------------
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_a_random_secret_key")
DATABASE_URL = os.environ.get("DATABASE_URL")
BASE_URL = os.environ.get("BASE_URL", "http://127.0.0.1:5000").rstrip("/")

# ---------------- ADMIN ACCOUNT ----------------
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "websecurityscanner@gmail.com")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "DeeneshAdmin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@@123!")

# ---------------- EMAIL CONFIGURATION ----------------
MAIL_SENDER = os.environ.get("MAIL_USERNAME")
MAIL_APP_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "True").lower() == "true"

# ---------------- ZAP CONFIGURATION ----------------
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://zap-service-q0cp:8080")

scan_tasks = {}

SCAN_MODES = {
    "quick": {"spider_timeout": 10, "ascan_timeout": 20, "label": "Quick Scan"},
    "full": {"spider_timeout": 15, "ascan_timeout": 35, "label": "Full Scan"}
}


# ---------------- DATABASE ----------------
def get_db_connection():
    if not DATABASE_URL:
        raise ValueError("DATABASE_URL is not set in Render environment variables.")
    return psycopg2.connect(DATABASE_URL, sslmode="require")


def get_cursor(conn):
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    conn = get_db_connection()
    cursor = get_cursor(conn)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            is_verified INTEGER NOT NULL DEFAULT 0,
            verify_token TEXT,
            reset_token TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id SERIAL PRIMARY KEY,
            scan_id TEXT UNIQUE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            target TEXT,
            scan_mode TEXT,
            status TEXT,
            total_findings INTEGER,
            vulnerabilities TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def seed_admin():
    conn = get_db_connection()
    cursor = get_cursor(conn)

    cursor.execute("SELECT * FROM users WHERE email = %s", (ADMIN_EMAIL,))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_verified)
            VALUES (%s, %s, %s, 'admin', 1)
        """, (ADMIN_USERNAME, ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD)))
        conn.commit()

    conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_email(email):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_verify_token(token):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM users WHERE verify_token = %s", (token,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_reset_token(token):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("SELECT * FROM users WHERE reset_token = %s", (token,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_all_users():
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("SELECT id, username, email, role, is_verified FROM users ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_history():
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("""
        SELECT sh.*, u.username, u.email
        FROM scan_history sh
        JOIN users u ON sh.user_id = u.id
        ORDER BY sh.id DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_user_history(user_id):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("""
        SELECT sh.*, u.username, u.email
        FROM scan_history sh
        JOIN users u ON sh.user_id = u.id
        WHERE sh.user_id = %s
        ORDER BY sh.id DESC
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_history_by_scan_id(scan_id):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("""
        SELECT sh.*, u.username, u.email
        FROM scan_history sh
        JOIN users u ON sh.user_id = u.id
        WHERE sh.scan_id = %s
    """, (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def save_scan_history(scan_id):
    task = scan_tasks.get(scan_id)
    if not task:
        return

    conn = get_db_connection()
    cursor = get_cursor(conn)

    cursor.execute("""
        INSERT INTO scan_history
        (scan_id, user_id, target, scan_mode, status, total_findings, vulnerabilities, created_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (scan_id) DO UPDATE SET
            user_id = EXCLUDED.user_id,
            target = EXCLUDED.target,
            scan_mode = EXCLUDED.scan_mode,
            status = EXCLUDED.status,
            total_findings = EXCLUDED.total_findings,
            vulnerabilities = EXCLUDED.vulnerabilities,
            created_at = EXCLUDED.created_at
    """, (
        scan_id,
        task["user_id"],
        task["target"],
        task["scan_mode"],
        task["status"] if not task["error"] else f"Error: {task['error']}",
        len(task["vulnerabilities"]),
        json.dumps(task["vulnerabilities"]),
        task.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S"))
    ))

    conn.commit()
    conn.close()


def delete_scan_by_id(scan_id):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("DELETE FROM scan_history WHERE scan_id = %s", (scan_id,))
    conn.commit()
    conn.close()


def delete_user_and_scans(user_id):
    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("DELETE FROM scan_history WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    conn.commit()
    conn.close()


# ---------------- DASHBOARD HELPERS ----------------
def calculate_risk_totals(history_rows):
    high = medium = low = info = 0

    for row in history_rows:
        vulns = json.loads(row["vulnerabilities"]) if row["vulnerabilities"] else []
        for vuln in vulns:
            risk = str(vuln.get("risk", "")).strip().lower()
            if risk == "high":
                high += 1
            elif risk == "medium":
                medium += 1
            elif risk == "low":
                low += 1
            else:
                info += 1

    return {"high": high, "medium": medium, "low": low, "info": info}


def apply_history_filters(rows, search_query="", mode_filter=""):
    filtered = []
    search_query = search_query.strip().lower()
    mode_filter = mode_filter.strip().lower()

    for row in rows:
        combined_text = " ".join([
            str(row.get("target", "")),
            str(row.get("status", "")),
            str(row.get("scan_mode", "")),
            str(row.get("username", "")),
            str(row.get("email", ""))
        ]).lower()

        mode_match = True if not mode_filter else mode_filter in str(row.get("scan_mode", "")).lower()
        search_match = True if not search_query else search_query in combined_text

        if mode_match and search_match:
            filtered.append(row)

    return filtered


def get_user_dashboard_stats(user_id):
    history_rows = get_user_history(user_id)
    totals = calculate_risk_totals(history_rows)
    return {
        "total_scans": len(history_rows),
        "total_findings": totals["high"] + totals["medium"] + totals["low"] + totals["info"],
        "high": totals["high"],
        "medium": totals["medium"],
        "low": totals["low"],
        "info": totals["info"]
    }


def risk_order_value(risk):
    risk = str(risk).strip().lower()
    order = {"high": 0, "medium": 1, "low": 2, "informational": 3, "info": 3}
    return order.get(risk, 4)


def sort_vulnerabilities(vulnerabilities):
    return sorted(
        vulnerabilities,
        key=lambda v: (risk_order_value(v.get("risk", "")), str(v.get("type", "")).lower())
    )


# ---------------- EMAIL ----------------
def send_email_message(to_email, subject, body):
    if not MAIL_SENDER or not MAIL_APP_PASSWORD:
        raise ValueError("MAIL_USERNAME or MAIL_PASSWORD is not set in environment variables.")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_SENDER
    msg["To"] = to_email
    msg.set_content(body)

    timeout_seconds = 10
    app_password = MAIL_APP_PASSWORD.replace(" ", "")

    try:
        if MAIL_USE_TLS and MAIL_PORT == 587:
            context = ssl.create_default_context()
            with smtplib.SMTP(MAIL_SERVER, MAIL_PORT, timeout=timeout_seconds) as server:
                server.starttls(context=context)
                server.login(MAIL_SENDER, app_password)
                server.send_message(msg)
        else:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, context=context, timeout=timeout_seconds) as server:
                server.login(MAIL_SENDER, app_password)
                server.send_message(msg)
    except Exception as e:
        app.logger.error(f"EMAIL ERROR: {e}")
        raise


# ---------------- AUTH HELPERS ----------------
def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return get_user_by_id(user_id)


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user or user["role"] != "admin":
            return "Access denied", 403
        return f(*args, **kwargs)
    return wrapper


# ---------------- AUTH ROUTES ----------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not username or not email or not password:
            return render_template("register.html", error="All fields are required.")

        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>_\-+=/\\\[\];\'`~]).{8,}$'
        if not re.match(password_pattern, password):
            return render_template(
                "register.html",
                error="Password must be at least 8 characters and include uppercase letter, lowercase letter, number, and symbol."
            )

        if get_user_by_email(email):
            return render_template("register.html", error="Email already registered.")

        verify_token = secrets.token_urlsafe(32)

        conn = get_db_connection()
        cursor = get_cursor(conn)
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, is_verified, verify_token)
                VALUES (%s, %s, %s, 'user', 0, %s)
            """, (username, email, generate_password_hash(password), verify_token))
            conn.commit()
        except psycopg2.IntegrityError:
            conn.rollback()
            conn.close()
            return render_template("register.html", error="Username or email already exists.")
        conn.close()

        verify_link = f"{BASE_URL}/verify/{verify_token}"

        subject = "Verify Your Web Security Scanner Account"
        body = f"""
Hello {username},

Thank you for registering.

Please verify your account by clicking the link below:
{verify_link}

If you did not create this account, please ignore this email.
"""

        try:
            send_email_message(email, subject, body)
            return render_template("verify_notice.html", title="Verification Email Sent", link=None)
        except Exception as e:
            return render_template(
                "verify_notice.html",
                title="Email Send Failed - Use This Link",
                link=verify_link,
                error=str(e)
            )

    return render_template("register.html")


@app.route('/verify/<token>')
def verify_email(token):
    user = get_user_by_verify_token(token)
    if not user:
        return "Invalid or expired verification link.", 400

    conn = get_db_connection()
    cursor = get_cursor(conn)
    cursor.execute("UPDATE users SET is_verified = 1, verify_token = NULL WHERE id = %s", (user["id"],))
    conn.commit()
    conn.close()

    return redirect(url_for("login"))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        user = get_user_by_email(email)

        if not user or not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Invalid email or password.")

        if user["is_verified"] == 0:
            return render_template("login.html", error="Please verify your account first.")

        session["user_id"] = user["id"]
        session["role"] = user["role"]
        session["username"] = user["username"]

        return redirect(url_for("index"))

    return render_template("login.html")


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get("email", "").strip().lower()
        user = get_user_by_email(email)

        if not user:
            return render_template("forgot_password.html", error="Email not found.")

        reset_token = secrets.token_urlsafe(32)

        conn = get_db_connection()
        cursor = get_cursor(conn)
        cursor.execute("UPDATE users SET reset_token = %s WHERE id = %s", (reset_token, user["id"]))
        conn.commit()
        conn.close()

        reset_link = f"{BASE_URL}/reset_password/{reset_token}"

        subject = "Reset Your Web Security Scanner Password"
        body = f"""
Hello {user['username']},

You requested to reset your password.

Please use the link below:
{reset_link}

If you did not request this, please ignore this email.
"""

        try:
            send_email_message(email, subject, body)
            return render_template("verify_notice.html", title="Password Reset Email Sent", link=None)
        except Exception as e:
            return render_template(
                "verify_notice.html",
                title="Email Send Failed - Use This Link",
                link=reset_link,
                error=str(e)
            )

    return render_template("forgot_password.html")


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = get_user_by_reset_token(token)
    if not user:
        return "Invalid or expired reset link.", 400

    if request.method == 'POST':
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not password or not confirm_password:
            return render_template("reset_password.html", token=token, error="All fields are required.")

        if password != confirm_password:
            return render_template("reset_password.html", token=token, error="Passwords do not match.")

        password_pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>_\-+=/\\\[\];\'`~]).{8,}$'
        if not re.match(password_pattern, password):
            return render_template(
                "reset_password.html",
                token=token,
                error="Password must be at least 8 characters and include uppercase letter, lowercase letter, number, and symbol."
            )

        conn = get_db_connection()
        cursor = get_cursor(conn)
        cursor.execute("""
            UPDATE users
            SET password_hash = %s, reset_token = NULL
            WHERE id = %s
        """, (generate_password_hash(password), user["id"]))
        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# ---------------- CVE / CVSS HELPERS ----------------
def get_cvss_score_from_risk(risk):
    risk = str(risk).strip().lower()

    if risk == "high":
        return "8.8"
    elif risk == "medium":
        return "6.5"
    elif risk == "low":
        return "3.1"
    elif risk in ["informational", "info"]:
        return "0.0"
    else:
        return "N/A"


def get_cve_from_alert(alert):
    possible_text = " ".join([
        str(alert.get("alert", "")),
        str(alert.get("description", "")),
        str(alert.get("reference", "")),
        str(alert.get("solution", ""))
    ])

    cve_matches = re.findall(r"CVE-\d{4}-\d{4,7}", possible_text, re.IGNORECASE)

    if cve_matches:
        return ", ".join(sorted(set(cve_matches)))

    return "N/A"


# ---------------- SCAN LOGIC ----------------
def safe_zap_progress(value):
    try:
        return int(value)
    except (ValueError, TypeError):
        return -1


def get_zap_client(max_retries=10, delay_seconds=5):
    proxies = {"http": ZAP_PROXY, "https": ZAP_PROXY}
    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            app.logger.info(f"Checking ZAP connection attempt {attempt}/{max_retries} using proxy: {ZAP_PROXY}")
            zap = ZAPv2(apikey=ZAP_API_KEY, proxies=proxies)
            app.logger.info(f"Connected to ZAP version: {zap.core.version}")
            return zap
        except Exception as e:
            last_error = e
            app.logger.warning(f"ZAP not ready yet. Retry {attempt}/{max_retries}. Error: {e}")
            time.sleep(delay_seconds)

    raise Exception(f"ZAP is not reachable after {max_retries} attempts. Last error: {last_error}")


def run_scan(scan_id, target, scan_mode, user_id):
    mode_config = SCAN_MODES.get(scan_mode, SCAN_MODES["quick"])
    spider_timeout = mode_config["spider_timeout"]
    ascan_timeout = mode_config["ascan_timeout"]
    mode_label = mode_config["label"]

    user = get_user_by_id(user_id)
    username = user["username"] if user else "Unknown"
    created_at = time.strftime("%Y-%m-%d %H:%M:%S")

    scan_tasks[scan_id] = {
        "user_id": user_id,
        "target": target,
        "scan_mode": mode_label,
        "status": "Starting scan...",
        "progress": 0,
        "completed": False,
        "vulnerabilities": [],
        "error": None,
        "username": username,
        "created_at": created_at
    }

    try:
        scan_tasks[scan_id]["status"] = "Connecting to OWASP ZAP..."
        zap = get_zap_client()

        scan_tasks[scan_id]["status"] = f"{mode_label}: Opening target..."
        zap.urlopen(target)
        time.sleep(2)

        scan_tasks[scan_id]["status"] = f"{mode_label}: Spider scanning..."
        spider_id = zap.spider.scan(target)
        spider_start = time.time()

        while True:
            spider_status = zap.spider.status(spider_id)
            spider_progress = safe_zap_progress(spider_status)

            if spider_progress == -1:
                scan_tasks[scan_id]["status"] = "Spider scan session expired or was lost. Moving to active scan..."
                break

            elapsed = time.time() - spider_start
            scan_tasks[scan_id]["progress"] = min(50, int(spider_progress * 0.5))

            if spider_progress >= 100:
                break
            if elapsed > spider_timeout:
                scan_tasks[scan_id]["status"] = f"{mode_label}: Spider timeout reached. Moving to active scan..."
                break
            time.sleep(2)

        scan_tasks[scan_id]["progress"] = 50
        time.sleep(2)

        scan_tasks[scan_id]["status"] = f"{mode_label}: Active scanning..."
        ascan_id = zap.ascan.scan(target)
        ascan_start = time.time()

        while True:
            active_status = zap.ascan.status(ascan_id)
            active_progress = safe_zap_progress(active_status)

            if active_progress == -1:
                scan_tasks[scan_id]["status"] = "Active scan session expired or was lost. Collecting available results..."
                break

            elapsed = time.time() - ascan_start
            scan_tasks[scan_id]["progress"] = min(100, 50 + int(active_progress * 0.5))

            if active_progress >= 100:
                break
            if elapsed > ascan_timeout:
                scan_tasks[scan_id]["status"] = f"{mode_label}: Active scan timeout reached. Collecting partial results..."
                break
            time.sleep(3)

        scan_tasks[scan_id]["progress"] = 100
        scan_tasks[scan_id]["status"] = f"{mode_label}: Collecting results..."
        time.sleep(2)

        alerts = zap.core.alerts(baseurl=target)
        vulnerabilities = []
        seen = set()

        for alert in alerts:
            vuln_type = alert.get("alert", "Unknown")
            risk = alert.get("risk", "Unknown")
            url = alert.get("url", "N/A")
            description = alert.get("description", "No description available.")
            solution = alert.get("solution", "No mitigation recommendation available.")

            unique_key = (vuln_type, risk, url)
            if unique_key not in seen:
                seen.add(unique_key)
                vulnerabilities.append({
                    "type": vuln_type,
                    "risk": risk,
                    "confidence": alert.get("confidence", "N/A"),
                    "cvss_score": get_cvss_score_from_risk(risk),
                    "cve_id": get_cve_from_alert(alert),
                    "cwe_id": alert.get("cweid", "N/A"),
                    "wasc_id": alert.get("wascid", "N/A"),
                    "plugin_id": alert.get("pluginId", "N/A"),
                    "url": url,
                    "description": description,
                    "solution": solution,
                    "reference": alert.get("reference", "N/A"),
                    "method": alert.get("method", "N/A"),
                    "param": alert.get("param", "N/A"),
                    "attack": alert.get("attack", "N/A"),
                    "evidence": alert.get("evidence", "N/A")
                })

        scan_tasks[scan_id]["vulnerabilities"] = sort_vulnerabilities(vulnerabilities)
        scan_tasks[scan_id]["status"] = f"{mode_label}: Scan Completed"
        scan_tasks[scan_id]["completed"] = True

    except Exception as e:
        app.logger.exception("ZAP scan failed")
        scan_tasks[scan_id]["status"] = f"{mode_label}: Scan Failed"
        scan_tasks[scan_id]["error"] = str(e)
        scan_tasks[scan_id]["completed"] = True

    save_scan_history(scan_id)


# ---------------- PDF REPORT HELPERS ----------------
def clean_pdf_text(value):
    if value is None:
        return "N/A"
    text = str(value)
    if not text.strip():
        return "N/A"
    text = re.sub(r"<[^>]+>", " ", text)
    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    return text if text else "N/A"


def pdf_safe(value):
    return html.escape(clean_pdf_text(value))


def normalize_risk(risk):
    risk = str(risk).strip().lower()
    if risk == "high":
        return "High"
    elif risk == "medium":
        return "Medium"
    elif risk == "low":
        return "Low"
    elif risk in ["informational", "info"]:
        return "Informational"
    return "Informational"


def risk_color(risk):
    risk = normalize_risk(risk)
    if risk == "High":
        return colors.HexColor("#dc2626")
    elif risk == "Medium":
        return colors.HexColor("#f97316")
    elif risk == "Low":
        return colors.HexColor("#eab308")
    return colors.HexColor("#2563eb")


def risk_light_color(risk):
    risk = normalize_risk(risk)
    if risk == "High":
        return colors.HexColor("#fee2e2")
    elif risk == "Medium":
        return colors.HexColor("#ffedd5")
    elif risk == "Low":
        return colors.HexColor("#fef9c3")
    return colors.HexColor("#dbeafe")


def get_risk_counts(vulnerabilities):
    counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for vuln in vulnerabilities:
        counts[normalize_risk(vuln.get("risk", "Informational"))] += 1
    return counts


def add_page_footer(canvas_obj, doc):
    canvas_obj.saveState()
    width, height = A4
    canvas_obj.setFont("Helvetica", 8)
    canvas_obj.setFillColor(colors.HexColor("#64748b"))
    canvas_obj.drawCentredString(width / 2, 25, f"Web Security Scanner Report | Page {doc.page}")
    canvas_obj.setStrokeColor(colors.HexColor("#cbd5e1"))
    canvas_obj.line(40, 40, width - 40, 40)
    canvas_obj.restoreState()


def build_risk_pie_chart(vulnerabilities):
    counts = get_risk_counts(vulnerabilities)
    labels = ["High", "Medium", "Low", "Informational"]
    values = [counts["High"], counts["Medium"], counts["Low"], counts["Informational"]]

    drawing = Drawing(420, 220)

    pie = Pie()
    pie.x = 70
    pie.y = 25
    pie.width = 170
    pie.height = 170
    pie.data = values if sum(values) > 0 else [1]
    pie.labels = None
    pie.slices.strokeWidth = 0.5
    pie.slices[0].fillColor = colors.HexColor("#dc2626")
    pie.slices[1].fillColor = colors.HexColor("#f97316")
    pie.slices[2].fillColor = colors.HexColor("#eab308")
    pie.slices[3].fillColor = colors.HexColor("#2563eb")

    legend = Legend()
    legend.x = 270
    legend.y = 80
    legend.boxAnchor = "w"
    legend.fontName = "Helvetica"
    legend.fontSize = 8
    legend.dx = 8
    legend.dy = 8
    legend.columnMaximum = 4
    legend.strokeWidth = 0
    legend.colorNamePairs = [
        (colors.HexColor("#dc2626"), f"High ({counts['High']})"),
        (colors.HexColor("#f97316"), f"Medium ({counts['Medium']})"),
        (colors.HexColor("#eab308"), f"Low ({counts['Low']})"),
        (colors.HexColor("#2563eb"), f"Informational ({counts['Informational']})"),
    ]

    drawing.add(pie)
    drawing.add(legend)
    return drawing


def build_summary_table(vulnerabilities, styles):
    counts = get_risk_counts(vulnerabilities)

    data = [
        [Paragraph("<b>Risk Level</b>", styles["TableHeader"]), Paragraph("<b>Total Findings</b>", styles["TableHeader"]), Paragraph("<b>Description</b>", styles["TableHeader"])],
        [Paragraph("High", styles["NormalText"]), Paragraph(str(counts["High"]), styles["NormalText"]), Paragraph("Critical attention required", styles["NormalText"])],
        [Paragraph("Medium", styles["NormalText"]), Paragraph(str(counts["Medium"]), styles["NormalText"]), Paragraph("Important remediation needed", styles["NormalText"])],
        [Paragraph("Low", styles["NormalText"]), Paragraph(str(counts["Low"]), styles["NormalText"]), Paragraph("Lower priority improvement", styles["NormalText"])],
        [Paragraph("Informational", styles["NormalText"]), Paragraph(str(counts["Informational"]), styles["NormalText"]), Paragraph("Useful security information", styles["NormalText"])],
    ]

    table = Table(data, colWidths=[1.5 * inch, 1.4 * inch, 3.8 * inch], repeatRows=1)
    table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, 1), colors.HexColor("#fee2e2")),
        ("BACKGROUND", (0, 2), (-1, 2), colors.HexColor("#ffedd5")),
        ("BACKGROUND", (0, 3), (-1, 3), colors.HexColor("#fef9c3")),
        ("BACKGROUND", (0, 4), (-1, 4), colors.HexColor("#dbeafe")),
    ]))
    return table


def build_alert_type_table(vulnerabilities, styles):
    counter = Counter()
    for vuln in vulnerabilities:
        alert_type = clean_pdf_text(vuln.get("type", "Unknown"))
        risk = normalize_risk(vuln.get("risk", "Informational"))
        counter[(alert_type, risk)] += 1

    data = [[Paragraph("<b>Alert Type</b>", styles["TableHeader"]), Paragraph("<b>Risk</b>", styles["TableHeader"]), Paragraph("<b>Count</b>", styles["TableHeader"])] ]

    sorted_items = sorted(counter.items(), key=lambda item: (risk_order_value(item[0][1]), item[0][0].lower()))
    for (alert_type, risk), count in sorted_items:
        data.append([Paragraph(pdf_safe(alert_type), styles["SmallText"]), Paragraph(pdf_safe(risk), styles["SmallText"]), Paragraph(str(count), styles["SmallText"])])

    table = Table(data, colWidths=[4.1 * inch, 1.4 * inch, 1.1 * inch], repeatRows=1)
    table_style = [
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]

    for row_index in range(1, len(data)):
        risk_text = data[row_index][1].getPlainText()
        table_style.append(("BACKGROUND", (1, row_index), (1, row_index), risk_light_color(risk_text)))

    table.setStyle(TableStyle(table_style))
    return table


def shorten_pdf_text(value, max_chars=900):
    text = clean_pdf_text(value)

    if text == "N/A":
        return "N/A"

    if len(text) > max_chars:
        return text[:max_chars] + "..."

    return text


def build_vulnerability_details(vuln, index, styles):
    story_items = []

    risk = normalize_risk(vuln.get("risk", "Informational"))
    header_color = risk_color(risk)
    light_color = risk_light_color(risk)
    title = clean_pdf_text(vuln.get("type", "Unknown Vulnerability"))

    header_table = Table(
        [[
            Paragraph(f"<b>Finding #{index}: {pdf_safe(title)}</b>", styles["WhiteHeader"]),
            Paragraph(f"<b>{pdf_safe(risk)}</b>", styles["WhiteHeaderRight"])
        ]],
        colWidths=[5.2 * inch, 1.3 * inch]
    )

    header_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), header_color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("BOX", (0, 0), (-1, -1), 0.8, header_color),
        ("LEFTPADDING", (0, 0), (-1, -1), 9),
        ("RIGHTPADDING", (0, 0), (-1, -1), 9),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))

    story_items.append(header_table)
    story_items.append(Spacer(1, 8))

    meta_data = [
        [
            Paragraph("<b>CVE ID</b>", styles["SmallText"]),
            Paragraph("<b>CVSS Score</b>", styles["SmallText"]),
            Paragraph("<b>CWE ID</b>", styles["SmallText"]),
            Paragraph("<b>WASC ID</b>", styles["SmallText"]),
            Paragraph("<b>Plugin ID</b>", styles["SmallText"]),
        ],
        [
            Paragraph(pdf_safe(vuln.get("cve_id", "N/A")), styles["SmallText"]),
            Paragraph(pdf_safe(vuln.get("cvss_score", "N/A")), styles["SmallText"]),
            Paragraph(pdf_safe(vuln.get("cwe_id", "N/A")), styles["SmallText"]),
            Paragraph(pdf_safe(vuln.get("wasc_id", "N/A")), styles["SmallText"]),
            Paragraph(pdf_safe(vuln.get("plugin_id", "N/A")), styles["SmallText"]),
        ],
        [
            Paragraph("<b>Confidence</b>", styles["SmallText"]),
            Paragraph("<b>Method</b>", styles["SmallText"]),
            Paragraph("<b>Parameter</b>", styles["SmallText"]),
            Paragraph("<b>Source</b>", styles["SmallText"]),
            Paragraph("<b>Status</b>", styles["SmallText"]),
        ],
        [
            Paragraph(pdf_safe(shorten_pdf_text(vuln.get("confidence", "N/A"), 80)), styles["SmallText"]),
            Paragraph(pdf_safe(shorten_pdf_text(vuln.get("method", "N/A"), 80)), styles["SmallText"]),
            Paragraph(pdf_safe(shorten_pdf_text(vuln.get("param", "N/A"), 80)), styles["SmallText"]),
            Paragraph("Scanner Alert", styles["SmallText"]),
            Paragraph("Detected", styles["SmallText"]),
        ],
    ]

    meta_table = Table(meta_data, colWidths=[1.3 * inch] * 5)

    meta_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (-1, 0), light_color),
        ("BACKGROUND", (0, 2), (-1, 2), light_color),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))

    story_items.append(meta_table)
    story_items.append(Spacer(1, 8))

    story_items.append(Paragraph("<b>Affected URL</b>", styles["SectionSmall"]))
    story_items.append(Paragraph(pdf_safe(vuln.get("url", "N/A")), styles["URLText"]))
    story_items.append(Spacer(1, 8))

    story_items.append(Paragraph("<b>Description</b>", styles["SectionSmall"]))
    story_items.append(Paragraph(pdf_safe(shorten_pdf_text(vuln.get("description", "No description available."), 1800)), styles["NormalText"]))
    story_items.append(Spacer(1, 8))

    story_items.append(Paragraph("<b>Recommended Mitigation</b>", styles["SectionSmall"]))
    story_items.append(Paragraph(pdf_safe(shorten_pdf_text(vuln.get("solution", "No mitigation recommendation available."), 1800)), styles["NormalText"]))
    story_items.append(Spacer(1, 8))

    attack = clean_pdf_text(vuln.get("attack", "N/A"))
    if attack != "N/A":
        story_items.append(Paragraph("<b>Attack Payload</b>", styles["SectionSmall"]))
        story_items.append(Paragraph(pdf_safe(shorten_pdf_text(attack, 700)), styles["SmallText"]))
        story_items.append(Spacer(1, 8))

    evidence = clean_pdf_text(vuln.get("evidence", "N/A"))
    if evidence != "N/A":
        story_items.append(Paragraph("<b>Evidence</b>", styles["SectionSmall"]))
        story_items.append(Paragraph(pdf_safe(shorten_pdf_text(evidence, 700)), styles["SmallText"]))
        story_items.append(Spacer(1, 8))

    reference = clean_pdf_text(vuln.get("reference", "N/A"))
    if reference != "N/A":
        story_items.append(Paragraph("<b>Reference</b>", styles["SectionSmall"]))
        story_items.append(Paragraph(pdf_safe(shorten_pdf_text(reference, 900)), styles["SmallText"]))
        story_items.append(Spacer(1, 8))

    story_items.append(Spacer(1, 16))
    return story_items


# ---------------- MAIN ROUTES ----------------
@app.route('/')
@login_required
def index():
    user = current_user()
    stats = get_user_dashboard_stats(user["id"])

    return render_template(
        "index.html",
        user=user,
        total_scans=stats["total_scans"],
        total_findings=stats["total_findings"],
        total_high=stats["high"],
        total_medium=stats["medium"],
        total_low=stats["low"],
        total_info=stats["info"]
    )


@app.route('/start_scan', methods=['POST'])
@login_required
def start_scan():
    target = request.form.get('url', '').strip()
    scan_mode = request.form.get('scan_mode', 'quick')
    user = current_user()

    if not target:
        return "No URL provided.", 400

    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target

    scan_id = str(uuid.uuid4())
    scan_tasks[scan_id] = {
        "user_id": user["id"],
        "target": target,
        "scan_mode": SCAN_MODES.get(scan_mode, SCAN_MODES["quick"])["label"],
        "status": "Queued scan...",
        "progress": 0,
        "completed": False,
        "vulnerabilities": [],
        "error": None,
        "username": user["username"],
        "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    thread = threading.Thread(target=run_scan, args=(scan_id, target, scan_mode, user["id"]), daemon=True)
    thread.start()

    return redirect(url_for('progress_page', scan_id=scan_id))


@app.route('/progress/<scan_id>')
@login_required
def progress_page(scan_id):
    return render_template('progress.html', scan_id=scan_id)


@app.route('/scan_status/<scan_id>')
@login_required
def scan_status(scan_id):
    task = scan_tasks.get(scan_id)

    if not task:
        row = get_history_by_scan_id(scan_id)
        if row:
            return jsonify({
                "target": row["target"],
                "scan_mode": row["scan_mode"],
                "status": row["status"],
                "progress": 100,
                "completed": True,
                "error": None if not str(row["status"]).startswith("Error:") else row["status"]
            })
        return jsonify({"error": "Invalid scan ID"}), 404

    user = current_user()
    if user["role"] != "admin" and task["user_id"] != user["id"]:
        return jsonify({"error": "Access denied"}), 403

    return jsonify({
        "target": task["target"],
        "scan_mode": task["scan_mode"],
        "status": task["status"],
        "progress": task["progress"],
        "completed": task["completed"],
        "error": task["error"]
    })


@app.route('/result/<scan_id>')
@login_required
def result(scan_id):
    user = current_user()
    task = scan_tasks.get(scan_id)

    if task:
        if user["role"] != "admin" and task["user_id"] != user["id"]:
            return "Access denied", 403

        result_data = {
            "scan_id": scan_id,
            "url": task["target"],
            "scan_mode": task["scan_mode"],
            "status": task["status"] if not task["error"] else f"Error: {task['error']}",
            "vulnerabilities": sort_vulnerabilities(task["vulnerabilities"]),
            "username": task["username"],
            "created_at": task["created_at"]
        }
        return render_template('result.html', result=result_data)

    row = get_history_by_scan_id(scan_id)
    if row:
        if user["role"] != "admin" and row["user_id"] != user["id"]:
            return "Access denied", 403

        parsed_vulns = json.loads(row["vulnerabilities"]) if row["vulnerabilities"] else []
        result_data = {
            "scan_id": row["scan_id"],
            "url": row["target"],
            "scan_mode": row["scan_mode"],
            "status": row["status"],
            "vulnerabilities": sort_vulnerabilities(parsed_vulns),
            "username": row["username"],
            "created_at": row["created_at"]
        }
        return render_template('result.html', result=result_data)

    return "Invalid scan ID", 404


@app.route('/history')
@login_required
def history():
    user = current_user()
    search_query = request.args.get("q", "").strip()
    mode_filter = request.args.get("mode", "").strip()

    history_rows = get_all_history() if user["role"] == "admin" else get_user_history(user["id"])
    filtered_history = apply_history_filters(history_rows, search_query, mode_filter)

    return render_template(
        'history.html',
        history=filtered_history,
        user=user,
        search_query=search_query,
        mode_filter=mode_filter
    )


@app.route('/admin')
@admin_required
def admin_panel():
    users = get_all_users()
    history_rows = get_all_history()
    risk_totals = calculate_risk_totals(history_rows)

    return render_template(
        "admin.html",
        users=users,
        history=history_rows,
        total_users=len(users),
        total_scans=len(history_rows),
        total_high=risk_totals["high"],
        total_medium=risk_totals["medium"],
        total_low=risk_totals["low"],
        total_info=risk_totals["info"]
    )


@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    user = get_user_by_id(user_id)
    current = current_user()

    if not user:
        return redirect(url_for("admin_panel"))

    if user["email"] == ADMIN_EMAIL or user["id"] == current["id"]:
        return redirect(url_for("admin_panel"))

    delete_user_and_scans(user_id)
    return redirect(url_for("admin_panel"))


@app.route('/admin/delete_scan/<scan_id>', methods=['POST'])
@admin_required
def admin_delete_scan(scan_id):
    delete_scan_by_id(scan_id)
    return redirect(url_for("admin_panel"))


@app.route('/export_report_pdf/<scan_id>')
@login_required
def export_report_pdf(scan_id):
    user = current_user()
    task = scan_tasks.get(scan_id)

    if task:
        if user["role"] != "admin" and task["user_id"] != user["id"]:
            return "Access denied", 403

        target = task["target"]
        scan_mode = task["scan_mode"]
        status = task["status"] if not task["error"] else f"Error: {task['error']}"
        vulnerabilities = sort_vulnerabilities(task["vulnerabilities"])
        username = task["username"]
        created_at = task["created_at"]
    else:
        row = get_history_by_scan_id(scan_id)
        if not row:
            return "Invalid scan ID", 404
        if user["role"] != "admin" and row["user_id"] != user["id"]:
            return "Access denied", 403

        target = row["target"]
        scan_mode = row["scan_mode"]
        status = row["status"]
        vulnerabilities = sort_vulnerabilities(json.loads(row["vulnerabilities"]) if row["vulnerabilities"] else [])
        username = row["username"]
        created_at = row["created_at"]

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=40,
        leftMargin=40,
        topMargin=50,
        bottomMargin=55
    )

    base_styles = getSampleStyleSheet()
    styles = {
        "Title": ParagraphStyle("Title", parent=base_styles["Title"], fontName="Helvetica-Bold", fontSize=22, leading=28, alignment=TA_CENTER, textColor=colors.HexColor("#0f172a"), spaceAfter=12),
        "Subtitle": ParagraphStyle("Subtitle", parent=base_styles["Normal"], fontSize=10, leading=14, alignment=TA_CENTER, textColor=colors.HexColor("#475569"), spaceAfter=18),
        "Heading": ParagraphStyle("Heading", parent=base_styles["Heading2"], fontName="Helvetica-Bold", fontSize=14, leading=18, textColor=colors.HexColor("#0f172a"), spaceBefore=12, spaceAfter=8),
        "SectionSmall": ParagraphStyle("SectionSmall", parent=base_styles["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=14, textColor=colors.HexColor("#0f172a"), spaceAfter=4),
        "NormalText": ParagraphStyle("NormalText", parent=base_styles["Normal"], fontSize=9, leading=13, textColor=colors.HexColor("#0f172a")),
        "SmallText": ParagraphStyle("SmallText", parent=base_styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#0f172a")),
        "TableHeader": ParagraphStyle("TableHeader", parent=base_styles["Normal"], fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=colors.white),
        "WhiteHeader": ParagraphStyle("WhiteHeader", parent=base_styles["Normal"], fontName="Helvetica-Bold", fontSize=11, leading=14, textColor=colors.white),
        "WhiteHeaderRight": ParagraphStyle("WhiteHeaderRight", parent=base_styles["Normal"], fontName="Helvetica-Bold", fontSize=10, leading=14, textColor=colors.white, alignment=TA_CENTER),
        "URLText": ParagraphStyle("URLText", parent=base_styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#1d4ed8"), backColor=colors.HexColor("#eff6ff"), borderColor=colors.HexColor("#bfdbfe"), borderWidth=0.5, borderPadding=6, spaceAfter=4)
    }

    story = []
    story.append(Paragraph("Web Application Security Assessment Report", styles["Title"]))
    story.append(Paragraph("Generated by Web Security Scanner", styles["Subtitle"]))

    story.append(Paragraph("1. Report Parameters", styles["Heading"]))
    parameter_data = [
        [Paragraph("<b>Scan ID</b>", styles["SmallText"]), Paragraph(pdf_safe(scan_id), styles["SmallText"])],
        [Paragraph("<b>Target URL</b>", styles["SmallText"]), Paragraph(pdf_safe(target), styles["SmallText"])],
        [Paragraph("<b>User</b>", styles["SmallText"]), Paragraph(pdf_safe(username), styles["SmallText"])],
        [Paragraph("<b>Scan Date & Time</b>", styles["SmallText"]), Paragraph(pdf_safe(created_at), styles["SmallText"])],
        [Paragraph("<b>Scan Mode</b>", styles["SmallText"]), Paragraph(pdf_safe(scan_mode), styles["SmallText"])],
        [Paragraph("<b>Status</b>", styles["SmallText"]), Paragraph(pdf_safe(status), styles["SmallText"])],
        [Paragraph("<b>Total Findings</b>", styles["SmallText"]), Paragraph(str(len(vulnerabilities)), styles["SmallText"])],
    ]
    parameter_table = Table(parameter_data, colWidths=[1.8 * inch, 4.8 * inch])
    parameter_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f1f5f9")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(parameter_table)
    story.append(Spacer(1, 14))

    story.append(Paragraph("2. Summary of Findings", styles["Heading"]))
    story.append(build_summary_table(vulnerabilities, styles))
    story.append(Spacer(1, 14))

    story.append(Paragraph("3. Risk Distribution", styles["Heading"]))
    story.append(build_risk_pie_chart(vulnerabilities))
    story.append(Spacer(1, 14))

    story.append(Paragraph("4. Alert Counts by Vulnerability Type", styles["Heading"]))
    if vulnerabilities:
        story.append(build_alert_type_table(vulnerabilities, styles))
    else:
        story.append(Paragraph("No vulnerabilities detected or scan time was insufficient.", styles["NormalText"]))

    story.append(Spacer(1, 16))
    story.append(Paragraph("5. Detailed Vulnerability Findings", styles["Heading"]))
    if vulnerabilities:
        for index, vuln in enumerate(vulnerabilities, start=1):
            story.extend(build_vulnerability_details(vuln, index, styles))
    else:
        story.append(Paragraph("No vulnerabilities detected or scan time was insufficient.", styles["NormalText"]))

    story.append(PageBreak())
    story.append(Paragraph("6. Appendix", styles["Heading"]))
    story.append(Paragraph(
        "Risk levels are categorized as High, Medium, Low, and Informational. "
        "CVSS values in this report are estimated from the detected risk level when an exact CVSS score is not provided by the scanner. "
        "CVE IDs are displayed when available in the alert details; otherwise N/A is shown.",
        styles["NormalText"]
    ))

    doc.build(story, onFirstPage=add_page_footer, onLaterPages=add_page_footer)
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"security_report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


# ---------------- STARTUP ----------------
init_db()
seed_admin()

if __name__ == '__main__':
    app.run(debug=True)
