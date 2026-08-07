#!/usr/bin/env python3
"""
apply-watch — poll job listing pages and alert the moment an Apply control appears.

Usage:
    python watcher.py --once          # single check (for cron / GitHub Actions / Lambda)
    python watcher.py                 # long-running loop (for EC2 / Fly / your laptop)
    python watcher.py --test-detect page.html   # run the detector against a saved page

Targets live in targets.json. Secrets live in environment variables (see .env.example).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import re
import smtplib
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path

import requests
from bs4 import BeautifulSoup

# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

ROOT = Path(__file__).resolve().parent
TARGETS_FILE = Path(os.getenv("TARGETS_FILE", ROOT / "targets.json"))
STATE_FILE = Path(os.getenv("STATE_FILE", ROOT / "state.json"))

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "45"))
JITTER_SECONDS = int(os.getenv("JITTER_SECONDS", "10"))
MAX_ALERTS = int(os.getenv("MAX_ALERTS", "3"))
ALERT_REPEAT_SECONDS = int(os.getenv("ALERT_REPEAT_SECONDS", "300"))
HEALTHCHECK_URL = os.getenv("HEALTHCHECK_URL", "")
HEARTBEAT_HOURS = float(os.getenv("HEARTBEAT_HOURS", "0"))
REQUEST_TIMEOUT = 25
MAX_BACKOFF = 900  # 15 min

USER_AGENT = os.getenv(
    "USER_AGENT",
    "apply-watch/1.0 (personal job-alert bot; contact: you@example.com)",
)

# Text that looks like "apply" but isn't the real apply button.
# Google Careers has "Apply filters", breadcrumbs, help links, etc.
NEGATIVE_TEXT = re.compile(
    r"apply\s+filter|clear\s+filter|how\s+to\s+apply|application\s+tips|"
    r"apply\s+to\s+other|already\s+applied|equal\s+opportunity",
    re.I,
)
POSITIVE_TEXT = re.compile(r"^\s*(apply(\s+now)?|apply\s+for\s+.*|start\s+application)\s*$", re.I)
POSITIVE_HREF = re.compile(r"(/apply|apply\?|applications/apply|/application/)", re.I)


@dataclass
class Target:
    name: str
    url: str
    # optional CSS selector override once you've inspected the real page
    selector: str | None = None
    render_js: bool = False
    headers: dict = field(default_factory=dict)


@dataclass
class Detection:
    found: bool
    evidence: str
    apply_url: str | None = None


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------


def fetch_static(target: Target, validators: dict | None = None) -> tuple[str | None, dict]:
    """Return (html, validators). html is None when the server says 304 Not Modified."""
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        **target.headers,
    }
    validators = validators or {}
    if validators.get("etag"):
        headers["If-None-Match"] = validators["etag"]
    if validators.get("last_modified"):
        headers["If-Modified-Since"] = validators["last_modified"]

    r = requests.get(target.url, headers=headers, timeout=REQUEST_TIMEOUT)
    if r.status_code == 304:
        return None, validators
    r.raise_for_status()
    fresh = {
        "etag": r.headers.get("ETag"),
        "last_modified": r.headers.get("Last-Modified"),
    }
    return r.text, fresh


def fetch_rendered(target: Target) -> str:
    """Only needed if the apply button is injected by JavaScript.

    Requires: pip install playwright && playwright install chromium
    """
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(user_agent=USER_AGENT)
        page.goto(target.url, wait_until="networkidle", timeout=45_000)
        html = page.content()
        browser.close()
    return html


def fetch(target: Target, validators: dict | None = None) -> tuple[str | None, dict]:
    if target.render_js:
        return fetch_rendered(target), {}
    return fetch_static(target, validators)


# --------------------------------------------------------------------------
# Detection
# --------------------------------------------------------------------------


def detect_apply(html: str, base_url: str = "", selector: str | None = None) -> Detection:
    soup = BeautifulSoup(html, "html.parser")

    # 1. Explicit selector wins, if you've given one.
    if selector:
        el = soup.select_one(selector)
        if el:
            href = el.get("href")
            return Detection(True, f"selector matched: {selector}", _abs(href, base_url))

    # 2. Anchors / buttons whose href points at an application flow.
    for el in soup.find_all(["a", "button"]):
        text = " ".join(el.get_text(" ", strip=True).split())
        href = el.get("href") or el.get("data-href") or ""
        aria = el.get("aria-label", "")

        blob = f"{text} {aria}"
        if NEGATIVE_TEXT.search(blob):
            continue

        href_hit = bool(href and POSITIVE_HREF.search(href))
        text_hit = bool(POSITIVE_TEXT.match(text) or POSITIVE_TEXT.match(aria))

        if href_hit or text_hit:
            reason = "href" if href_hit else "label"
            return Detection(True, f"{el.name} matched by {reason}: {text or aria or href}"[:200], _abs(href, base_url))

    return Detection(False, "no apply control found")


def _abs(href: str | None, base_url: str) -> str | None:
    if not href:
        return None
    if href.startswith("http"):
        return href
    if base_url and href.startswith("/"):
        from urllib.parse import urlsplit

        parts = urlsplit(base_url)
        return f"{parts.scheme}://{parts.netloc}{href}"
    return href


def content_fingerprint(html: str) -> str:
    """Hash of visible text only — ignores nonces/analytics junk that changes every load."""
    soup = BeautifulSoup(html, "html.parser")
    for tag in soup(["script", "style", "noscript"]):
        tag.decompose()
    text = " ".join(soup.get_text(" ", strip=True).split())
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------


def notify_ntfy(subject: str, body: str, click_url: str | None = None) -> None:
    """Free push notification, no signup. Install the ntfy app, subscribe to your topic."""
    topic = os.getenv("NTFY_TOPIC")
    if not topic:
        return
    headers = {
        "Title": subject,
        "Priority": "urgent",
        "Tags": "rotating_light",
    }
    if click_url:
        headers["Click"] = click_url
    try:
        r = requests.post(
            f"https://ntfy.sh/{topic}",
            data=body.encode("utf-8"),
            headers=headers,
            timeout=15,
        )
        r.raise_for_status()
        log("push sent")
    except Exception as e:  # noqa: BLE001
        log(f"ntfy failed: {e}")


def notify_call(body: str) -> None:
    """Actually rings your phone. Much harder to sleep through than a text."""
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_ = os.getenv("TWILIO_FROM")
    to_list = [n.strip() for n in os.getenv("TWILIO_CALL_TO", "").split(",") if n.strip()]
    if not (sid and token and from_ and to_list):
        return
    twiml = (
        "<Response><Say voice=\"alice\">"
        "The Google apply button is live. Repeat. The Google apply button is live. "
        "Check your messages now."
        "</Say></Response>"
    )
    for to in to_list:
        try:
            r = requests.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json",
                auth=(sid, token),
                data={"From": from_, "To": to, "Twiml": twiml},
                timeout=20,
            )
            r.raise_for_status()
            log(f"call placed to {to}")
        except Exception as e:  # noqa: BLE001
            log(f"call failed for {to}: {e}")


def notify_twilio(body: str) -> None:
    sid = os.getenv("TWILIO_ACCOUNT_SID")
    token = os.getenv("TWILIO_AUTH_TOKEN")
    from_ = os.getenv("TWILIO_FROM")
    to_list = [n.strip() for n in os.getenv("TWILIO_TO", "").split(",") if n.strip()]
    if not (sid and token and from_ and to_list):
        return
    for to in to_list:
        try:
            r = requests.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
                auth=(sid, token),
                data={"From": from_, "To": to, "Body": body[:1500]},
                timeout=20,
            )
            r.raise_for_status()
            log(f"sms sent to {to}")
        except Exception as e:  # noqa: BLE001
            log(f"twilio failed for {to}: {e}")


def notify_email(subject: str, body: str) -> None:
    host = os.getenv("SMTP_HOST")
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASSWORD")
    to_list = [a.strip() for a in os.getenv("EMAIL_TO", "").split(",") if a.strip()]
    if not (host and user and password and to_list):
        return
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = os.getenv("EMAIL_FROM", user)
    msg["To"] = ", ".join(to_list)
    msg.set_content(body)
    try:
        with smtplib.SMTP_SSL(host, int(os.getenv("SMTP_PORT", "465"))) as s:
            s.login(user, password)
            s.send_message(msg)
        log(f"email sent to {len(to_list)} recipient(s)")
    except Exception as e:  # noqa: BLE001
        log(f"email failed: {e}")


def notify_webhook(subject: str, body: str) -> None:
    """Slack or Discord incoming webhook."""
    url = os.getenv("WEBHOOK_URL")
    if not url:
        return
    payload = {"content": f"**{subject}**\n{body}", "text": f"*{subject}*\n{body}"}
    try:
        requests.post(url, json=payload, timeout=20).raise_for_status()
        log("webhook sent")
    except Exception as e:  # noqa: BLE001
        log(f"webhook failed: {e}")


def notify_all(subject: str, body: str, click_url: str | None = None) -> None:
    # Fastest and hardest-to-miss channels first. Email is last because SMTP
    # handshakes can take several seconds and delivery can lag by minutes.
    notify_ntfy(subject, body, click_url)
    notify_twilio(f"{subject}\n{body}")
    notify_call(body)
    notify_webhook(subject, body)
    notify_email(subject, body)


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except json.JSONDecodeError:
            log("state file corrupt, starting fresh")
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.write_text(json.dumps(state, indent=2))


def load_targets() -> list[Target]:
    raw = json.loads(TARGETS_FILE.read_text())
    return [Target(**t) for t in raw]


def log(msg: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
    print(f"[{stamp}] {msg}", flush=True)


# --------------------------------------------------------------------------
# Core check
# --------------------------------------------------------------------------


def check_target(target: Target, state: dict) -> None:
    prev = state.get(target.url, {})
    html, validators = fetch(target, prev.get("validators"))

    if html is None:
        # 304 Not Modified — page is byte-identical, nothing can have appeared.
        log(f"{target.name}: unchanged (304)")
        prev["last_checked"] = datetime.now(timezone.utc).isoformat()
        state[target.url] = prev
        return

    result = detect_apply(html, target.url, target.selector)
    fp = content_fingerprint(html)

    was_found = prev.get("found", False)
    alerts_sent = prev.get("alerts_sent", 0)
    last_alert = prev.get("last_alert", 0.0)
    now = time.time()

    if result.found:
        due = (now - last_alert) >= ALERT_REPEAT_SECONDS
        if alerts_sent < MAX_ALERTS and (alerts_sent == 0 or due):
            attempt = alerts_sent + 1
            subject = f"APPLY BUTTON LIVE ({attempt}/{MAX_ALERTS}): {target.name}"
            body = (
                f"{target.url}\n\n"
                f"Apply link: {result.apply_url or 'see page'}\n"
                f"Matched: {result.evidence}\n"
                f"GO NOW."
            )
            log(f"*** {subject} — {result.evidence}")
            notify_all(subject, body, result.apply_url or target.url)
            alerts_sent = attempt
            last_alert = now
        elif alerts_sent >= MAX_ALERTS:
            log(f"{target.name}: open, alert cap reached ({MAX_ALERTS}), staying quiet")
        else:
            wait = int(ALERT_REPEAT_SECONDS - (now - last_alert))
            log(f"{target.name}: open, next reminder in {wait}s")
    else:
        # Button vanished (or never appeared) — reset so a future opening re-alerts.
        alerts_sent = 0
        last_alert = 0.0
        if prev.get("fingerprint") and prev["fingerprint"] != fp:
            log(f"{target.name}: page changed but no apply control yet")
            if os.getenv("ALERT_ON_CHANGE", "").lower() in {"1", "true", "yes"}:
                notify_all(
                    f"Page changed: {target.name}",
                    f"{target.url}\nContent changed, still no apply button.",
                )
        else:
            log(f"{target.name}: no apply button")

    state[target.url] = {
        "name": target.name,
        "found": result.found,
        "alerts_sent": alerts_sent,
        "last_alert": last_alert,
        "validators": validators,
        "fingerprint": fp,
        "last_checked": datetime.now(timezone.utc).isoformat(),
        "last_evidence": result.evidence,
    }


def ping_healthcheck() -> None:
    """Tell an external monitor we're alive. If this stops, THEY alert you."""
    if not HEALTHCHECK_URL:
        return
    try:
        requests.get(HEALTHCHECK_URL, timeout=10)
    except Exception as e:  # noqa: BLE001
        log(f"healthcheck ping failed: {e}")


def maybe_heartbeat(state: dict) -> None:
    """Optional low-priority 'still watching' push so you know it's alive."""
    if HEARTBEAT_HOURS <= 0:
        return
    topic = os.getenv("NTFY_TOPIC")
    if not topic:
        return
    last = state.get("_heartbeat", 0.0)
    now = time.time()
    if now - last < HEARTBEAT_HOURS * 3600:
        return
    checked = sum(1 for k in state if not k.startswith("_"))
    try:
        requests.post(
            f"https://ntfy.sh/{topic}",
            data=f"Still watching {checked} listing(s). No apply button yet.".encode(),
            headers={"Title": "apply-watch heartbeat", "Priority": "min", "Tags": "heartbeat"},
            timeout=15,
        )
        state["_heartbeat"] = now
        log("heartbeat sent")
    except Exception as e:  # noqa: BLE001
        log(f"heartbeat failed: {e}")


def run_once() -> None:
    state = load_state()
    ok = True
    for target in load_targets():
        try:
            check_target(target, state)
        except Exception as e:  # noqa: BLE001
            ok = False
            log(f"{target.name}: check failed: {type(e).__name__}: {e}")
        time.sleep(random.uniform(1, 3))  # be polite between targets
    if ok:
        ping_healthcheck()
        maybe_heartbeat(state)
    save_state(state)


def print_status() -> int:
    """Human-readable 'is this thing working?' report."""
    state = load_state()
    entries = {k: v for k, v in state.items() if not k.startswith("_")}
    if not entries:
        print("No state yet — the script has never completed a check.")
        print("Run: python watcher.py --once")
        return 1

    now = datetime.now(timezone.utc)
    worst = 0.0
    for url, s in entries.items():
        checked = s.get("last_checked")
        age = None
        if checked:
            age = (now - datetime.fromisoformat(checked)).total_seconds()
            worst = max(worst, age)
        print(f"\n{s.get('name', url)}")
        print(f"  url          {url}")
        print(f"  apply button {'FOUND' if s.get('found') else 'not present'}")
        print(f"  alerts sent  {s.get('alerts_sent', 0)}/{MAX_ALERTS}")
        print(f"  last checked {int(age)}s ago" if age is not None else "  last checked never")
        print(f"  detector     {s.get('last_evidence', 'n/a')}")

    stale_after = max(POLL_SECONDS * 4, 600)
    print()
    if worst > stale_after:
        print(f"STALE — last check was {int(worst)}s ago. The watcher is probably not running.")
        print("  systemctl status apply-watch")
        return 1
    print(f"HEALTHY — checked {int(worst)}s ago.")
    return 0


def run_forever() -> None:
    failures = 0
    while True:
        try:
            run_once()
            failures = 0
        except Exception as e:  # noqa: BLE001
            failures += 1
            log(f"cycle failed ({failures}): {e}")
        base = POLL_SECONDS * (2 ** min(failures, 4)) if failures else POLL_SECONDS
        delay = min(base, MAX_BACKOFF) + random.uniform(0, JITTER_SECONDS)
        time.sleep(delay)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--once", action="store_true", help="run a single check and exit")
    ap.add_argument("--test-detect", metavar="HTML_FILE", help="run detector on a saved HTML file")
    ap.add_argument("--test-notify", action="store_true", help="send a test alert on all channels")
    ap.add_argument("--status", action="store_true", help="report whether the watcher is healthy")
    ap.add_argument("--snapshot", action="store_true", help="save each target's HTML to fixtures/ for inspection")
    args = ap.parse_args()

    if args.status:
        return print_status()

    if args.snapshot:
        out = ROOT / "fixtures"
        out.mkdir(exist_ok=True)
        for t in load_targets():
            slug = re.sub(r"[^a-z0-9]+", "-", t.name.lower()).strip("-")
            path = out / f"{slug}.html"
            html, _ = fetch(t)
            path.write_text(html or "")
            log(f"saved {path} ({path.stat().st_size} bytes)")
        return 0

    if args.test_detect:
        html = Path(args.test_detect).read_text()
        d = detect_apply(html)
        print(json.dumps({"found": d.found, "evidence": d.evidence, "apply_url": d.apply_url}, indent=2))
        return 0

    if args.test_notify:
        notify_all("apply-watch test", "If you got this, your channels work.")
        return 0

    if args.once:
        run_once()
    else:
        log(f"watching every ~{POLL_SECONDS}s. ctrl-c to stop.")
        run_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
