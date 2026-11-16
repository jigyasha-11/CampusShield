from flask import Flask, render_template, request, redirect, url_for
import re
import sqlite3
from datetime import datetime

app = Flask(__name__)

DATABASE = "campusshield.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            score INTEGER NOT NULL,
            status TEXT NOT NULL,
            scan_time TEXT NOT NULL,
            reported INTEGER DEFAULT 0
        )
    """)

    conn.commit()
    conn.close()


def analyse_content(content):
    text = content.lower().strip()
    score = 0
    reasons = []

    urgency_words = [
        "urgent", "immediately", "verify now", "act now",
        "account suspended", "limited time", "click now"
    ]

    credential_words = [
        "password", "otp", "pin", "cvv",
        "login details", "bank details", "verify account"
    ]

    scam_words = [
        "you won", "winner", "prize", "lottery",
        "free money", "claim reward", "payment required"
    ]

    for word in urgency_words:
        if word in text:
            score += 15
            reasons.append(f"Urgency indicator detected: '{word}'")

    for word in credential_words:
        if word in text:
            score += 25
            reasons.append(
                f"Sensitive information request detected: '{word}'"
            )

    for word in scam_words:
        if word in text:
            score += 20
            reasons.append(f"Possible scam indicator detected: '{word}'")

    if "http://" in text:
        score += 15
        reasons.append("Link uses HTTP instead of HTTPS")

    if re.search(r"(bit\.ly|tinyurl\.com|t\.co)", text):
        score += 20
        reasons.append("Shortened URL detected")

    if text.count("-") >= 3:
        score += 10
        reasons.append("Unusual URL/message pattern detected")

    score = min(score, 100)

    if score >= 60:
        status = "HIGH RISK"
        recommendation = (
            "Do not click the link or share any personal information. "
            "Verify the message through an official source."
        )

    elif score >= 25:
        status = "SUSPICIOUS"
        recommendation = (
            "Proceed with caution. Verify the sender and link "
            "before taking any action."
        )

    else:
        status = "SAFE"
        recommendation = (
            "No major phishing indicators were detected. "
            "Still verify unexpected messages before trusting them."
        )

    if not reasons:
        reasons.append("No common phishing indicators detected.")

    return score, status, reasons, recommendation


def save_scan(content, score, status):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scans (content, score, status, scan_time)
        VALUES (?, ?, ?, ?)
        """,
        (
            content,
            score,
            status,
            datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        )
    )

    scan_id = cursor.lastrowid

    conn.commit()
    conn.close()

    return scan_id


@app.route("/", methods=["GET", "POST"])
def home():
    result = None

    if request.method == "POST":
        content = request.form.get("content", "").strip()

        # Basic input validation
        if content and len(content) <= 2000:
            score, status, reasons, recommendation = analyse_content(content)

            scan_id = save_scan(content, score, status)

            result = {
                "id": scan_id,
                "score": score,
                "status": status,
                "reasons": reasons,
                "recommendation": recommendation
            }

    return render_template("index.html", result=result)


@app.route("/report/<int:scan_id>", methods=["POST"])
def report_threat(scan_id):
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE scans SET reported = 1 WHERE id = ?",
        (scan_id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("history"))


@app.route("/history")
def history():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM scans ORDER BY id DESC LIMIT 20"
    )

    scans = cursor.fetchall()
    conn.close()

    return render_template("history.html", scans=scans)


init_db()

if __name__ == "__main__":
    app.run(debug=True)