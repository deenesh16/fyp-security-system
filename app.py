from flask import (
    Flask, render_template, request, jsonify, redirect,
    url_for, session, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from zapv2 import ZAPv2
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
from email.message import EmailMessage
import smtplib
import ssl
import time
import threading
import uuid
import sqlite3
import json
import secrets
import io
import os
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

# ---------------- APP / ENV CONFIG ----------------
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_a_random_secret_key")
DB_PATH = os.environ.get("DB_PATH", "/tmp/scan_history.db")

# ====== ADMIN ACCOUNT ======
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "deeneshdeenesh66@gmail.com")
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "DeeneshAdmin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@@123!")
# ===========================

# ====== EMAIL CONFIGURATION ======
MAIL_SENDER = os.environ.get("MAIL_USERNAME")
MAIL_APP_PASSWORD = os.environ.get("MAIL_PASSWORD")
MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "587"))
MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "True").lower() == "true"
# ================================

# ====== ZAP CONFIGURATION ======
# Put this in Render Environment for Flask app:
# ZAP_PROXY=http://zap-service-q0cp:8080
# ZAP_API_KEY=   leave empty because ZAP API key is disabled
ZAP_API_KEY = os.environ.get("ZAP_API_KEY", "")
ZAP_PROXY = os.environ.get("ZAP_PROXY", "http://zap-service-q0cp:8080")
# ================================

scan_tasks = {}

SCAN_MODES = {
    "quick": {
        "spider_timeout": 10,
        "ascan_timeout": 20,
        "label": "Quick Scan"
    },
    "full": {
        "spider_timeout": 25,
        "ascan_timeout": 60,
        "label": "Full Scan"
    }
}


# ---------------- DATABASE ----------------
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def column_exists(cursor, table_name, column_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = cursor.fetchall()
    return any(col["name"] == column_name for col in columns)


def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT UNIQUE,
            user_id INTEGER NOT NULL,
            target TEXT,
            scan_mode TEXT,
            status TEXT,
            total_findings INTEGER,
            vulnerabilities TEXT,
            created_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    """)

    if not column_exists(cursor, "scan_history", "created_at"):
        cursor.execute("ALTER TABLE scan_history ADD COLUMN created_at TEXT")

    conn.commit()
    conn.close()


def seed_admin():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE email = ?", (ADMIN_EMAIL,))
    existing = cursor.fetchone()

    if not existing:
        cursor.execute("""
            INSERT INTO users (username, email, password_hash, role, is_verified)
            VALUES (?, ?, ?, 'admin', 1)
        """, (
            ADMIN_USERNAME,
            ADMIN_EMAIL,
            generate_password_hash(ADMIN_PASSWORD)
        ))
        conn.commit()

    conn.close()


def save_scan_history(scan_id):
    task = scan_tasks.get(scan_id)
    if not task:
        return

    created_time = task.get("created_at", time.strftime("%Y-%m-%d %H:%M:%S"))

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT OR REPLACE INTO scan_history
        (scan_id, user_id, target, scan_mode, status, total_findings, vulnerabilities, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id,
        task["user_id"],
        task["target"],
        task["scan_mode"],
        task["status"] if not task["error"] else f"Error: {task['error']}",
        len(task["vulnerabilities"]),
        json.dumps(task["vulnerabilities"]),
        created_time
    ))

    conn.commit()
    conn.close()


def get_user_by_id(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_email(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_verify_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE verify_token = ?", (token,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_user_by_reset_token(token):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_all_users():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, is_verified FROM users ORDER BY id DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_all_history():
    conn = get_db_connection()
    cursor = conn.cursor()
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
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sh.*, u.username, u.email
        FROM scan_history sh
        JOIN users u ON sh.user_id = u.id
        WHERE sh.user_id = ?
        ORDER BY sh.id DESC
    """, (user_id,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_history_by_scan_id(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sh.*, u.username, u.email
        FROM scan_history sh
        JOIN users u ON sh.user_id = u.id
        WHERE sh.scan_id = ?
    """, (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return row


def delete_scan_by_id(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()


def delete_user_and_scans(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scan_history WHERE user_id = ?", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def calculate_risk_totals(history_rows):
    high = 0
    medium = 0
    low = 0
    info = 0

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

    return {
        "high": high,
        "medium": medium,
        "low": low,
        "info": info
    }


def apply_history_filters(rows, search_query="", mode_filter=""):
    filtered = []

    search_query = search_query.strip().lower()
    mode_filter = mode_filter.strip().lower()

    for row in rows:
        combined_text = " ".join([
            str(row["target"] if "target" in row.keys() else ""),
            str(row["status"] if "status" in row.keys() else ""),
            str(row["scan_mode"] if "scan_mode" in row.keys() else ""),
            str(row["username"] if "username" in row.keys() else ""),
            str(row["email"] if "email" in row.keys() else "")
        ]).lower()

        mode_match = True
        if mode_filter:
            mode_match = mode_filter in str(row["scan_mode"]).lower()

        search_match = True
        if search_query:
            search_match = search_query in combined_text

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
    order = {
        "high": 0,
        "medium": 1,
        "low": 2,
        "informational": 3,
        "info": 3
    }
    return order.get(risk, 4)


def sort_vulnerabilities(vulnerabilities):
    return sorted(
        vulnerabilities,
        key=lambda v: (
            risk_order_value(v.get("risk", "")),
            str(v.get("type", "")).lower()
        )
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

    if MAIL_USE_TLS and MAIL_PORT == 587:
        context = ssl.create_default_context()
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            server.starttls(context=context)
            server.login(MAIL_SENDER, MAIL_APP_PASSWORD)
            server.send_message(msg)
    else:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, context=context) as server:
            server.login(MAIL_SENDER, MAIL_APP_PASSWORD)
            server.send_message(msg)


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

        if get_user_by_email(email):
            return render_template("register.html", error="Email already registered.")

        verify_token = secrets.token_urlsafe(32)

        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, role, is_verified, verify_token)
                VALUES (?, ?, ?, 'user', 0, ?)
            """, (
                username,
                email,
                generate_password_hash(password),
                verify_token
            ))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return render_template("register.html", error="Username or email already exists.")
        conn.close()

        verify_link = url_for("verify_email", token=verify_token, _external=True)

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
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE users
        SET is_verified = 1, verify_token = NULL
        WHERE id = ?
    """, (user["id"],))
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
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET reset_token = ?
            WHERE id = ?
        """, (reset_token, user["id"]))
        conn.commit()
        conn.close()

        reset_link = url_for("reset_password", token=reset_token, _external=True)

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

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users
            SET password_hash = ?, reset_token = NULL
            WHERE id = ?
        """, (generate_password_hash(password), user["id"]))
        conn.commit()
        conn.close()

        return redirect(url_for("login"))

    return render_template("reset_password.html", token=token)


# ---------------- SCAN LOGIC ----------------
def get_zap_client(max_retries=10, delay_seconds=5):
    proxies = {
        "http": ZAP_PROXY,
        "https": ZAP_PROXY
    }

    last_error = None

    for attempt in range(1, max_retries + 1):
        try:
            app.logger.info(f"Checking ZAP connection attempt {attempt}/{max_retries} using proxy: {ZAP_PROXY}")

            zap = ZAPv2(
                apikey=ZAP_API_KEY,
                proxies=proxies
            )

            zap_version = zap.core.version
            app.logger.info(f"Connected to ZAP version: {zap_version}")
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
            spider_progress = int(zap.spider.status(spider_id))
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
            active_progress = int(zap.ascan.status(ascan_id))
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
                    "url": url,
                    "description": description,
                    "solution": solution
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


# ---------------- PDF HELPER ----------------
def draw_wrapped_text(pdf, text, x, y, max_width, font_name="Helvetica", font_size=10, line_gap=14):
    lines = simpleSplit(str(text), font_name, font_size, max_width)
    pdf.setFont(font_name, font_size)
    for line in lines:
        if y < 60:
            pdf.showPage()
            pdf.setFont(font_name, font_size)
            y = 800
        pdf.drawString(x, y, line)
        y -= line_gap
    return y


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

    if user["role"] == "admin":
        history_rows = get_all_history()
    else:
        history_rows = get_user_history(user["id"])

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

    total_users = len(users)
    total_scans = len(history_rows)
    risk_totals = calculate_risk_totals(history_rows)

    return render_template(
        "admin.html",
        users=users,
        history=history_rows,
        total_users=total_users,
        total_scans=total_scans,
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
        status = task["status"]
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
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    y = height - 50

    pdf.setTitle("Web Security Assessment Report")

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, "WEB APPLICATION SECURITY ASSESSMENT REPORT")
    y -= 30

    pdf.setFont("Helvetica", 11)
    y = draw_wrapped_text(pdf, f"Scan ID: {scan_id}", 50, y, 500)
    y = draw_wrapped_text(pdf, f"User: {username}", 50, y, 500)
    y = draw_wrapped_text(pdf, f"Scan Date/Time: {created_at}", 50, y, 500)
    y = draw_wrapped_text(pdf, f"Target URL: {target}", 50, y, 500)
    y = draw_wrapped_text(pdf, f"Scan Mode: {scan_mode}", 50, y, 500)
    y = draw_wrapped_text(pdf, f"Status: {status}", 50, y, 500)
    y = draw_wrapped_text(pdf, f"Total Findings: {len(vulnerabilities)}", 50, y, 500)
    y -= 10

    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "Detected Vulnerabilities")
    y -= 20

    if vulnerabilities:
        for i, vuln in enumerate(vulnerabilities, start=1):
            if y < 120:
                pdf.showPage()
                y = height - 50

            pdf.setFont("Helvetica-Bold", 12)
            pdf.drawString(50, y, f"Finding #{i}: {vuln['type']}")
            y -= 18

            pdf.setFont("Helvetica", 10)
            y = draw_wrapped_text(pdf, f"Risk: {vuln['risk']}", 60, y, 470)
            y = draw_wrapped_text(pdf, f"Affected URL: {vuln['url']}", 60, y, 470)
            y = draw_wrapped_text(pdf, f"Description: {vuln['description']}", 60, y, 470)
            y = draw_wrapped_text(pdf, f"Recommended Mitigation: {vuln['solution']}", 60, y, 470)
            y -= 10
    else:
        pdf.setFont("Helvetica", 10)
        y = draw_wrapped_text(pdf, "No vulnerabilities detected or scan time was insufficient.", 50, y, 500)

    pdf.save()
    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"scan_report_{scan_id}.pdf",
        mimetype="application/pdf"
    )


# ---------------- STARTUP ----------------
init_db()
seed_admin()

if __name__ == '__main__':
    app.run(debug=True)
