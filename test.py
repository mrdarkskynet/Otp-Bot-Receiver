#!/usr/bin/env python3
"""
safe_panel_notifier.py

Generic, safe template:
- logs in to a site using requests.Session()
- fetches message list (JSON or HTML)
- FORWARDS ONLY metadata (time, service, country, number) to Telegram
- WITHHOLDS SMS body when it appears to contain OTP/code-like content
"""

import os
import time
import re
import logging
import requests
import html
from dotenv import load_dotenv
import telebot

# load env from .env (optional)
load_dotenv()

# === CONFIG - move secrets to environment variables ===
LOGIN_URL = os.getenv("LOGIN_URL", "https://example.com/login")   # form action URL
DATA_URL  = os.getenv("DATA_URL", "https://example.com/messages") # endpoint returning messages (JSON preferred)
USERNAME  = os.getenv("PANEL_USER", "your_username")
PASSWORD  = os.getenv("PANEL_PASS", "your_password")
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
CHAT_ID   = int(os.getenv("TELEGRAM_CHAT_ID", "0"))               # e.g. -1001234567890 for groups
POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30"))            # seconds between polls

# Optional: cookie name or sessionid if you have a static cookie rather than login
# SESSION_COOKIE = os.getenv("SESSION_COOKIE", "")

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# OTP / sensitive detection (we only use this to WITHHOLD bodies)
OTP_PATTERN = re.compile(r'\b\d{3}-\d{3}\b|\b\d{4}\b|\b\d{5,6}\b')

# Keys considered sensitive (do not forward)
SENSITIVE_KEYS = {"otp", "code", "pin", "password", "token", "2fa", "secret", "auth"}

bot = telebot.TeleBot(BOT_TOKEN)

# Keep dedupe set for forwarded records (persist to file/db for long-running / restarts if needed)
sent_records = set()

def login(session: requests.Session) -> bool:
    """
    Generic login flow. Modify to match the panel's login form.
    If the login requires CSRF token, fetch it first and include in payload.
    Return True if login succeeded (session now authenticated).
    """
    logging.info("Attempting login to %s", LOGIN_URL)

    # Example: GET the login page to scrape CSRF token (if needed)
    try:
        r = session.get(LOGIN_URL, timeout=15)
        r.raise_for_status()
    except Exception as e:
        logging.exception("Failed to fetch login page: %s", e)
        return False

    # Example CSRF extraction (adjust regex / parsing as needed)
    csrf_token = None
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', r.text)
    if m:
        csrf_token = m.group(1)
        logging.debug("Found CSRF token")

    payload = {
        "username": USERNAME,
        "password": PASSWORD,
    }
    if csrf_token:
        payload["csrf_token"] = csrf_token

    # Adjust headers to mimic browser if necessary
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible)",
        "Referer": LOGIN_URL
    }

    try:
        login_resp = session.post(LOGIN_URL, data=payload, headers=headers, timeout=15)
        login_resp.raise_for_status()
    except Exception as e:
        logging.exception("Login POST failed: %s", e)
        return False

    # Determine success: check for redirect, presence of logout link, or specific JSON flag.
    # Customize these checks for your site.
    if "logout" in login_resp.text.lower() or login_resp.url != LOGIN_URL:
        logging.info("Login appears successful (found logout or redirect).")
        return True

    # If login returns JSON
    try:
        j = login_resp.json()
        if j.get("success") or j.get("logged_in"):
            logging.info("Login JSON indicates success.")
            return True
    except Exception:
        pass

    logging.warning("Login may have failed — inspect login response.")
    return False

def fetch_records(session: requests.Session):
    """
    Fetch message records. This template supports JSON endpoints returning
    a list under a key (e.g., 'aaData' or 'messages') or HTML tables.
    RETURN: iterable of record dicts with at least keys: time, number, service, country?, text?
    """
    logging.info("Fetching records from %s", DATA_URL)
    try:
        r = session.get(DATA_URL, timeout=20)
        r.raise_for_status()
    except Exception as e:
        logging.exception("Failed to fetch data: %s", e)
        return []

    # Try JSON
    try:
        j = r.json()
        # Common patterns: {"aaData": [...]} or {"messages": [...]}
        if isinstance(j, dict):
            records = j.get("aaData") or j.get("messages") or j.get("data") or j.get("result")
            if records is None:
                # Maybe the JSON itself is a list
                records = j if isinstance(j, list) else []
        else:
            records = j
    except Exception:
        records = None

    parsed = []
    if records:
        # Normalize records into dicts
        for rec in records:
            # The exact structure depends on the API. Here are a few common shapes:
            # - rec as list: [time, ?, number, service, country, text, ...]
            # - rec as dict: {"time": "...", "number":"...", "service":"...", "text":"..."}
            if isinstance(rec, dict):
                parsed.append({
                    "time": rec.get("time") or rec.get("datetime") or rec.get("0"),
                    "number": rec.get("number") or rec.get("msisdn") or rec.get("2"),
                    "service": rec.get("service") or rec.get("sender") or rec.get("3"),
                    "country": rec.get("country"),
                    "text": rec.get("text") or rec.get("message") or rec.get("5")
                })
            elif isinstance(rec, (list, tuple)):
                # best-effort mapping — adjust indexes to match your panel
                parsed.append({
                    "time": rec[0] if len(rec) > 0 else None,
                    "number": rec[2] if len(rec) > 2 else None,
                    "service": rec[3] if len(rec) > 3 else None,
                    "country": rec[4] if len(rec) > 4 else None,
                    "text": rec[5] if len(rec) > 5 else None
                })
    else:
        # Fallback: try basic HTML parsing (requires beautifulsoup4)
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            # This is highly site-specific — user must customize.
            table = soup.find("table")
            if table:
                for row in table.find_all("tr")[1:]:
                    cols = [td.get_text(strip=True) for td in row.find_all(["td","th"])]
                    parsed.append({
                        "time": cols[0] if len(cols) > 0 else None,
                        "number": cols[2] if len(cols) > 2 else None,
                        "service": cols[3] if len(cols) > 3 else None,
                        "country": cols[4] if len(cols) > 4 else None,
                        "text": cols[5] if len(cols) > 5 else None
                    })
        except Exception:
            logging.warning("No JSON data and HTML parsing not available or did not match.")

    return parsed

def contains_sensitive_text(s: str) -> bool:
    """Detect likely OTPs or codes in text. Returns True if sensitive."""
    if not s:
        return False
    if OTP_PATTERN.search(s):
        return True
    # also check for explicit sensitive key strings (if text includes 'OTP:' etc.)
    if re.search(r'\b(otp|code|pin|password|passcode)\b', s, re.IGNORECASE):
        return True
    return False

def send_safe_telegram(record):
    """
    Send only metadata to Telegram. If text is sensitive, DO NOT include the text.
    """
    t = record.get("time", "(no-time)")
    num = record.get("number", "(no-number)")
    svc = record.get("service", "(no-service)")
    ctry = record.get("country")
    txt = record.get("text")

    sensitive = contains_sensitive_text(txt)

    parts = [
        f"⏰ Time: {html.escape(str(t))}",
        f"📞 Number: {html.escape(str(num))}",
        f"🔧 Service: {html.escape(str(svc))}"
    ]
    if ctry:
        parts.append(f"🌍 Country: {html.escape(str(ctry))}")

    if sensitive:
        parts.append("⚠️ Message content withheld (contains possible sensitive code)")
    else:
        # If the text is short and NOT sensitive, you can optionally include a safe snippet
        if txt:
            s = str(txt)
            if len(s) <= 200 and not contains_sensitive_text(s):
                parts.append(f"💬 Message: {html.escape(s)}")

    # small unique id to help dedupe/debug
    uid = f"{t}|{num}|{svc}"
    parts.append(f"\n🔁 id: {html.escape(uid)}")

    text = "\n".join(parts)
    try:
        bot.send_message(CHAT_ID, text)
        logging.info("Sent metadata for id %s", uid)
    except Exception:
        logging.exception("Failed to send telegram message")

    return uid

def main_loop():
    with requests.Session() as session:
        # If you already have a persistent cookie, you can set it here:
        # session.cookies.set("PHPSESSID", SESSION_COOKIE, domain="example.com")

        if not login(session):
            logging.error("Login failed; exiting.")
            return

        logging.info("Starting polling loop. Poll interval: %s sec", POLL_INTERVAL)
        while True:
            try:
                records = fetch_records(session)
                for rec in records:
                    # compute a stable dedupe key
                    dedupe_key = f"{rec.get('time')}|{rec.get('number')}|{rec.get('service')}"
                    if dedupe_key in sent_records:
                        continue
                    uid = send_safe_telegram(rec)
                    sent_records.add(dedupe_key)
                # OPTIONAL: persist sent_records to disk periodically to survive restarts
            except Exception:
                logging.exception("Unhandled error in main loop")
            time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main_loop()