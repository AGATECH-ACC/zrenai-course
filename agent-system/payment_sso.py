"""One-use, PKCE-bound login handoff to the payment portal.

The browser never receives Supabase tokens or the backchannel signing secret.
The source session remains authoritative after the handoff.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from store import Problem

ROOT = Path(__file__).parent
BACKCHANNELS = {"/api/payment-sso/exchange", "/api/payment-sso/session"}


def config():
    secret = os.getenv("PAYMENT_SSO_SECRET", "")
    origin = os.getenv("PAYMENT_ORIGIN", "").rstrip("/")
    parsed = urlsplit(origin)
    if (len(secret) < 32 or parsed.scheme != "https" or not parsed.hostname
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise Problem("Token checkout sign-in is not configured.", 503)
    return secret, origin


def opaque(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise Problem("Invalid sign-in request.", 400)
    return value


def challenge(verifier):
    return base64.urlsafe_b64encode(hashlib.sha256(opaque(verifier).encode()).digest()).decode().rstrip("=")


def install(store):
    with store.tx() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS payment_login_codes (
            code_hash TEXT PRIMARY KEY,
            session_hash TEXT NOT NULL REFERENCES sessions(token_hash) ON DELETE CASCADE,
            state TEXT NOT NULL, challenge TEXT NOT NULL, expires_at INTEGER NOT NULL
        )""")


def identity(store, auth, session_hash):
    if not auth or not isinstance(session_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", session_hash):
        raise Problem("Please sign in to ZrenAI again.", 401)
    with store.connect() as db:
        row = db.execute("""SELECT s.expires_at,l.auth_id,ss.access_token
            FROM sessions s JOIN users u ON u.id=s.user_id
            JOIN supabase_links l ON l.user_id=u.id
            JOIN supabase_sessions ss ON ss.token_hash=s.token_hash
            WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
            (session_hash, int(time.time()))).fetchone()
    if not row:
        raise Problem("Please sign in to ZrenAI again.", 401)
    verified = auth.verified_user(row["access_token"])
    if verified["id"] != row["auth_id"]:
        raise Problem("Account identity has changed.", 401)
    return {"sub": verified["id"], "email": verified["email"],
            "expires_at": row["expires_at"], "session_handle": session_hash}


def issue(store, user, state, pkce_challenge):
    _, origin = config()
    state, pkce_challenge = opaque(state), opaque(pkce_challenge)
    code = secrets.token_urlsafe(32)
    with store.tx() as db:
        db.execute("DELETE FROM payment_login_codes WHERE expires_at<=?", (int(time.time()),))
        db.execute("INSERT INTO payment_login_codes VALUES(?,?,?,?,?)", (
            hashlib.sha256(code.encode()).hexdigest(), user["token_hash"], state,
            pkce_challenge, int(time.time()) + 60))
    return {"redirect_url": origin + "/accounts/sso/callback/?" + urlencode({"code": code, "state": state})}


def exchange(store, auth, data):
    digest = hashlib.sha256(opaque(data.get("code")).encode()).hexdigest()
    state, pkce = opaque(data.get("state")), challenge(data.get("verifier"))
    with store.connect() as db:
        row = db.execute("""SELECT session_hash FROM payment_login_codes
            WHERE code_hash=? AND state=? AND challenge=? AND expires_at>?""",
            (digest, state, pkce, int(time.time()))).fetchone()
    if not row:
        raise Problem("Sign-in link expired or already used. Please try again.", 401)
    result = identity(store, auth, row["session_hash"])
    with store.tx() as db:
        # DELETE RETURNING makes concurrent redemption safe on SQLite and Postgres.
        consumed = db.execute("""DELETE FROM payment_login_codes
            WHERE code_hash=? AND state=? AND challenge=? AND expires_at>?
            RETURNING session_hash""", (digest, state, pkce, int(time.time()))).fetchone()
        active = db.execute("""SELECT 1 FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>? AND u.active=1""",
            (row["session_hash"], int(time.time()))).fetchone()
        if not consumed or not active:
            raise Problem("Sign-in link expired or already used. Please try again.", 401)
    return result


def signed_message(timestamp, path, data):
    return (timestamp + "\n" + path + "\n" + json.dumps(data, sort_keys=True, separators=(",", ":"))).encode()


def backchannel(handler, path):
    secret, _ = config()
    if handler.command != "POST":
        raise Problem("POST required.", 405)
    data = handler.body()
    timestamp = handler.headers.get("X-ZrenAI-Time", "")
    signature = handler.headers.get("X-ZrenAI-Signature", "")
    if not re.fullmatch(r"\d{10}", timestamp) or abs(int(time.time()) - int(timestamp)) > 30:
        raise Problem("Invalid service authentication.", 401)
    expected = hmac.new(secret.encode(), signed_message(timestamp, path, data), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise Problem("Invalid service authentication.", 401)
    store, auth = handler.server.store, handler.server.auth
    result = exchange(store, auth, data) if path.endswith("/exchange") else identity(store, auth, data.get("session_handle"))
    handler.respond(200, result)


def browser_route(handler, mutation):
    path = urlsplit(handler.path).path
    if path == "/api/payment-sso/authorize" and mutation:
        config()
        if not handler.server.auth:
            raise Problem("Supabase sign-in is required.", 403)
        data = handler.body()
        user = handler.session()
        handler.guard(user)
        if hasattr(handler.server.store, "rate_limit"):
            handler.server.store.rate_limit("payment-sso", user["id"], 20, 60)
        handler.respond(200, issue(handler.server.store, user, data.get("state"), data.get("challenge")))
        return True
    files = {"/payments/authorize": "payment-sso.html", "/payment-sso.js": "payment-sso.js"}
    if path in files and not mutation:
        config()
        blob = (ROOT / "static" / files[path]).read_bytes()
        handler.send_response(200)
        handler.headers_common()
        handler.send_header("Content-Type", "text/html; charset=utf-8" if path == "/payments/authorize" else "text/javascript; charset=utf-8")
        handler.send_header("Content-Length", str(len(blob)))
        handler.end_headers()
        handler.wfile.write(blob)
        return True
    return False
