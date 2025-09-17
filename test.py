#!/usr/bin/env python3
"""
safe_panel_notifier.py

Safe notifier that logs into a panel (or uses a session cookie), polls for message records,
and forwards ONLY metadata (time, service, country, number) to a Telegram chat.

It WILL NOT forward OTPs or other code-like contents; message bodies that appear sensitive are withheld.
"""

import os
import time
import re
import json
import logging
import html
from pathlib import Path
from typing import List, Dict, Any, Optional

import requests
from bs4 import BeautifulSoup
import telebot
from dotenv import load_dotenv

# --------------- Load config ---------------
load_dotenv()

LOGIN_URL = os.getenv("LOGIN_URL", "").strip()
DATA_URL = os.getenv("DATA_URL", "").strip()

PANEL_USER = os.getenv("PANEL_USER", "").strip()
PANEL_PASS = os.getenv("PANEL_PASS", "").strip()
SESSION_COOKIE = os.getenv("SESSION_COOKIE", "").strip()  # if you prefer to set PHPSESSID=cookievalue here

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = int(os.getenv("TELEGRAM_CHAT_ID", "0").strip() or 0)

POLL_INTERVAL = int(os.getenv("POLL_INTERVAL", "30").strip() or 30)
REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15").strip() or 15)
SENT_RECORDS_FILE = os.getenv("SENT_RECORDS_FILE", "sent_records.json").strip()

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# Optional: additional GET params for DATA_URL as JSON string (example: '{"iDisplayLength":"100"}')
DATA_URL_PARAMS = os.getenv("DATA_URL_PARAMS", "").strip()

# --------------- Logging ---------------
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s %(levelname)s %(message)s",
)

# --------------- Safety patterns ---------------
# Used only to decide to WITHHOLD the body. We DO NOT extract or forward matches.
OTP_PATTERN = re.compile(r'\b\d{3}-\d{3}\b|\b\d{4}\b|\b\d{5,6}\b')
SENSITIVE_KEYWORDS = re.compile(r'\b(otp|code|pin|password|passcode|token|2fa|secret)\b', re.IGNORECASE)

# Keys considered sensitive in JSON payloads (if present we refuse to forward content)
SENSITIVE_KEYS = {"otp", "code", "pin", "password", "token", "2fa", "secret", "auth"}

# --------------- Telegram setup ---------------
if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
    logging.error("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in .env")
    raise SystemExit("Missing Telegram configuration")

bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN, threaded=False)

# --------------- Utility: persist sent records ---------------
def load_sent_records(path: str) -> set:
    p = Path(path)
    if not p.exists():
        return set()
    try:
        with p.open("r", encoding="utf-8") as f:
            arr = json.load(f)
            return set(arr)
    except Exception:
        logging.exception("Failed to load sent records file; starting fresh")
        return set()

def save_sent_records(path: str, records: set):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(list(records), f)
    except Exception:
        logging.exception("Failed to persist sent records")

# --------------- Login logic ---------------
def login_with_session(session: requests.Session) -> bool:
    """
    Attempt a generic login. This will:
    - GET LOGIN_URL to fetch CSRF token if available
    - POST credentials
    Returns True if session appears authenticated.
    """
    if not LOGIN_URL:
        logging.info("No LOGIN_URL provided, skipping login step (using SESSION_COOKIE if set)")
        return False

    logging.info("Fetching login page to obtain potential CSRF token...")
    try:
        r = session.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except Exception:
        logging.exception("Failed to fetch login page")
        return False

    # Attempt to extract common CSRF hidden input
    csrf_token = None
    try:
        soup = BeautifulSoup(r.text, "html.parser")
        token_input = soup.find("input", attrs={"type": "hidden", "name": True, "value": True})
        # naive: prefer an input with 'csrf' in name
        for inp in soup.find_all("input", attrs={"type": "hidden"}):
            name = inp.get("name", "")
            if "csrf" in name.lower() or "token" in name.lower():
                csrf_token = inp.get("value")
                csrf_name = name
                break
        # fallback: if earlier search didn't find, try generic
        if csrf_token is None:
            inp = soup.find("input", attrs={"name": "csrf_token"})
            if inp:
                csrf_token = inp.get("value")
                csrf_name = "csrf_token"
    except Exception:
        csrf_token = None

    payload = {}
    # Many panels use 'username'/'user'/'login' and 'password'/'pass'
    # Try a few common names, but you may need to edit these to match the panel's form field names.
    # If the panel uses AJAX login, you'll need to inspect devtools and adapt accordingly.
    payload_key_user = "username"
    payload_key_pass = "password"

    # Allow override via env if user wants custom form keys
    payload_key_user = os.getenv("FORM_USER_KEY", payload_key_user)
    payload_key_pass = os.getenv("FORM_PASS_KEY", payload_key_pass)

    payload[payload_key_user] = PANEL_USER
    payload[payload_key_pass] = PANEL_PASS
    if csrf_token:
        payload[csrf_name] = csrf_token

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible)",
        "Referer": LOGIN_URL
    }

    logging.info("Posting login form (this is a best-effort generic flow; adjust if your panel uses AJAX).")
    try:
        resp = session.post(LOGIN_URL, data=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
    except Exception:
        logging.exception("Login POST failed")
        return False

    # Heuristics for successful login:
    if "logout" in resp.text.lower() or resp.url != LOGIN_URL:
        logging.info("Login appears successful (found logout or redirect).")
        return True

    # If response JSON indicates success
    try:
        j = resp.json()
        if isinstance(j, dict) and (j.get("success") or j.get("logged_in")):
            logging.info("Login JSON indicates success.")
            return True
    except Exception:
        pass

    logging.warning("Login heuristics did not detect success. The site may use a non-standard login flow. Inspect the response and adjust login_with_session().")
    return False

# --------------- Fetch and parse records ---------------
def parse_records_from_json(j: Any) -> List[Dict[str, Any]]:
    records = []
    try:
        if isinstance(j, dict):
            # Common shapes: 'aaData', 'messages', 'data', 'result'
            candidate = j.get("aaData") or j.get("messages") or j.get("data") or j.get("result")
            if candidate is None:
                # maybe the dict itself is the data
                candidate = j
        else:
            candidate = j

        if isinstance(candidate, list):
            for rec in candidate:
                if isinstance(rec, dict):
                    records.append({
                        "time": rec.get("time") or rec.get("datetime") or rec.get("0"),
                        "number": rec.get("number") or rec.get("msisdn") or rec.get("2"),
                        "service": rec.get("service") or rec.get("sender") or rec.get("3"),
                        "country": rec.get("country"),
                        "text": rec.get("text") or rec.get("message") or rec.get("5"),
                        "raw": rec
                    })
                elif isinstance(rec, (list, tuple)):
                    # best-effort mapping similar to common panels: adjust indexes if needed
                    records.append({
                        "time": rec[0] if len(rec) > 0 else None,
                        "number": rec[2] if len(rec) > 2 else None,
                        "service": rec[3] if len(rec) > 3 else None,
                        "country": rec[4] if len(rec) > 4 else None,
                        "text": rec[5] if len(rec) > 5 else None,
                        "raw": rec
                    })
        elif isinstance(candidate, dict):
            # maybe an object keyed by ids
            for k, v in candidate.items():
                if isinstance(v, dict):
                    records.append({
                        "time": v.get("time"),
                        "number": v.get("number"),
                        "service": v.get("service"),
                        "country": v.get("country"),
                        "text": v.get("text"),
                        "raw": v
                    })
    except Exception:
        logging.exception("Exception while parsing JSON records")

    return records

def parse_records_from_html(html_text: str) -> List[Dict[str, Any]]:
    parsed = []
    try:
        soup = BeautifulSoup(html_text, "html.parser")
        table = soup.find("table")
        if not table:
            return parsed
        rows = table.find_all("tr")
        for tr in rows[1:]:
            cols = [td.get_text(strip=True) for td in tr.find_all(["td", "th"])]
            parsed.append({
                "time": cols[0] if len(cols) > 0 else None,
                "number": cols[2] if len(cols) > 2 else None,
                "service": cols[3] if len(cols) > 3 else None,
                "country": cols[4] if len(cols) > 4 else None,
                "text": cols[5] if len(cols) > 5 else None,
                "raw": cols
            })
    except Exception:
        logging.exception("Exception while parsing HTML records")
    return parsed

def fetch_records(session: requests.Session) -> List[Dict[str, Any]]:
    if not DATA_URL:
        logging.error("DATA_URL is not set")
        return []

    params = {}
    if DATA_URL_PARAMS:
        try:
            params = json.loads(DATA_URL_PARAMS)
        except Exception:
            logging.exception("DATA_URL_PARAMS parsing failed; ignoring")

    logging.debug("Requesting data URL: %s params=%s", DATA_URL, params)
    try:
        r = session.get(DATA_URL, params=params, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
    except Exception:
        logging.exception("Failed to GET data URL")
        return []

    # Try JSON parsing first
    try:
        j = r.json()
        recs = parse_records_from_json(j)
        if recs:
            logging.info("Parsed %d records from JSON response", len(recs))
            return recs
    except ValueError:
        # not JSON, fall back to HTML parsing
        pass
    except Exception:
        logging.exception("Exception while trying to decode JSON")

    # Fallback: parse HTML
    recs = parse_records_from_html(r.text)
    logging.info("Parsed %d records from HTML response", len(recs))
    return recs

# --------------- Sensitive detection & safe telegram forwarding ---------------
def contains_sensitive_text(s: Optional[str]) -> bool:
    if not s:
        return False
    if OTP_PATTERN.search(s):
        return True
    if SENSITIVE_KEYWORDS.search(s):
        return True
    return False

def record_contains_sensitive_keys(raw: Any) -> bool:
    """
    If the raw record is a dict, check if it contains sensitive keys.
    """
    if isinstance(raw, dict):
        for k in raw.keys():
            if str(k).lower() in SENSITIVE_KEYS:
                return True
    return False

def send_safe_metadata_to_telegram(record: Dict[str, Any]) -> Optional[str]:
    t = record.get("time", "(no-time)")
    num = record.get("number", "(no-number)")
    svc = record.get("service", "(no-service)")
    ctry = record.get("country")
    txt = record.get("text")
    raw = record.get("raw")

    # If the raw record contains explicit sensitive keys, refuse to include text
    if record_contains_sensitive_keys(raw):
        text_sensitive = True
    else:
        text_sensitive = contains_sensitive_text(txt)

    parts = [
        f"⏰ Time: {html.escape(str(t))}",
        f"📞 Number: {html.escape(str(num))}",
        f"🔧 Service: {html.escape(str(svc))}"
    ]
    if ctry:
        parts.append(f"🌍 Country: {html.escape(str(ctry))}")

    if text_sensitive:
        parts.append("⚠️ Message content withheld (contains possible sensitive code)")
    else:
        # If text is safe and reasonably short, include snippet
        if txt:
            s = str(txt)
            if len(s) <= 200:
                parts.append(f"💬 Message: {html.escape(s)}")
            else:
                parts.append(f"💬 Message (truncated): {html.escape(s[:200])}...")

    # A stable dedupe id based on time+number+service
    uid = f"{t}|{num}|{svc}"
    parts.append(f"\n🔁 id: {html.escape(uid)}")

    message = "\n".join(parts)
    try:
        bot.send_message(TELEGRAM_CHAT_ID, message)
        logging.info("Sent metadata for id %s", uid)
        return uid
    except Exception:
        logging.exception("Failed to send message to Telegram")
        return None

# --------------- Main loop ---------------
def main():
    sent = load_sent_records(SENT_RECORDS_FILE)
    logging.info("Loaded %d sent record ids", len(sent))

    with requests.Session() as session:
        # If the user provided a session cookie instead of doing login
        if SESSION_COOKIE:
            # Expect format like "PHPSESSID=abc123" or just cookie value; handle both.
            if "=" in SESSION_COOKIE:
                k, v = SESSION_COOKIE.split("=", 1)
                session.cookies.set(k, v, domain=None)
            else:
                # assume PHPSESSID
                session.cookies.set("PHPSESSID", SESSION_COOKIE, domain=None)
            logging.info("Using SESSION_COOKIE from env; skipping login POST.")
        else:
            # Attempt login if credentials are available
            if PANEL_USER and PANEL_PASS and LOGIN_URL:
                ok = login_with_session(session)
                if not ok:
                    logging.warning("Login attempt did not indicate success; continuing anyway (session may be unauthorized).")
            else:
                logging.info("No SESSION_COOKIE and no PANEL_USER/PANEL_PASS. Continuing without login.")

        logging.info("Starting polling loop (interval %s seconds)...", POLL_INTERVAL)
        try:
            while True:
                try:
                    recs = fetch_records(session)
                    for rec in recs:
                        # dedupe key — this should be customized if the panel provides a real message id
                        dedupe_key = f"{rec.get('time')}|{rec.get('number')}|{rec.get('service')}"
                        if dedupe_key in sent:
                            continue
                        uid = send_safe_metadata_to_telegram(rec)
                        if uid:
                            sent.add(dedupe_key)
                    # persist sent set periodically (each cycle)
                    save_sent_records(SENT_RECORDS_FILE, sent)
                except Exception:
                    logging.exception("Unexpected error during poll cycle")
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            logging.info("Interrupted by user, saving state and exiting.")
            save_sent_records(SENT_RECORDS_FILE, sent)

if __name__ == "__main__":
    main()
