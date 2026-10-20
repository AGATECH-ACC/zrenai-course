#!/usr/bin/env python3
"""Local, authenticated agent and commission application; no third-party packages."""
import argparse
import csv
import hashlib
import io
import json
import logging
import mimetypes
import os
import secrets
import sqlite3
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit, parse_qs

from store import Store, Problem, password_ok, password_hash, text

ROOT = Path(__file__).resolve().parent


class AppServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, store, demo=False, auth=None):
        if demo and auth:
            raise ValueError("Demo mode must not connect to real Supabase Auth.")
        self.auth = auth
        if auth:
            auth.install(store)
        self.demo = demo
        self.cookie_name = "zr_demo_session" if demo else "zr_supabase_session" if auth else "zr_session"
        self.store = store
        self.failures = {}
        self.inquiry_requests = []
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    server_version = "Zhongren/1.0"

    def log_message(self, fmt, *args):
        # Never log bodies, passwords, cookies, or customer records.
        logging.info("%s %s", self.command, self.path.split("?")[0])

    def headers_common(self, nonce=None):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        inline = f" 'nonce-{nonce}'" if nonce else ""
        self.send_header("Content-Security-Policy", f"default-src 'self'; script-src 'self'{inline}; style-src 'self'{inline}; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")

    def respond(self, status, value, cookie=None):
        encoded = json.dumps(value, ensure_ascii=False).encode()
        self.send_response(status)
        self.headers_common()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(encoded)

    def check_origin(self):
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        host = self.headers.get("Host", "")
        if host not in allowed:
            raise Problem("此服务仅供本机访问。", 403)
        origin = self.headers.get("Origin")
        if origin and origin != "http://" + host:
            raise Problem("跨站请求已拒绝。", 403)
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            raise Problem("跨站请求已拒绝。", 403)

    def body(self):
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            raise Problem("请求必须为 JSON。", 415)
        size = int(self.headers.get("Content-Length", "0"))
        if size <= 0 or size > 65536:
            raise Problem("请求内容过大或为空。", 413)
        value = json.loads(self.rfile.read(size))
        if not isinstance(value, dict):
            raise Problem("请求格式错误。")
        return value

    def session(self, required=True, verify_provider=True):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
        except Exception:
            pass
        token = cookie.get(self.server.cookie_name)
        if token:
            digest = hashlib.sha256(token.value.encode()).hexdigest()
            with self.server.store.connect() as db:
                row = db.execute("SELECT u.id,u.username,u.kind,u.agent_id,s.csrf,s.token_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1", (digest, int(time.time()))).fetchone()
                if row:
                    user = dict(row)
                    if not self.server.auth or not verify_provider or self.server.auth.validate_session(self.server.store, user):
                        return user
        if required:
            raise Problem("请先登录。", 401)
        return None

    def guard(self, user, admin=False):
        if self.headers.get("X-CSRF-Token") != user["csrf"]:
            raise Problem("安全校验失效，请刷新后重试。", 403)
        if admin and user["kind"] != "admin":
            raise Problem("此操作需要管理员权限。", 403)

    def login(self, data):
        key = self.client_address[0]
        attempts = [t for t in self.server.failures.get(key, []) if t > time.time() - 300]
        if len(attempts) >= 10:
            raise Problem("登录尝试过多，请 5 分钟后重试。", 429)
        if self.server.auth:
            try:
                token, ttl = self.server.auth.login(self.server.store, data)
            except Problem:
                self.server.failures[key] = attempts + [time.time()]
                raise
            self.server.failures.pop(key, None)
            self.respond(200, {"ok": True}, self.server.cookie_name + "=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + str(ttl))
            return
        username = text(data.get("username"), "用户名", 60)
        with self.server.store.tx() as db:
            user = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
            if not user or not password_ok(data.get("password"), user["password_hash"]):
                self.server.failures[key] = attempts + [time.time()]
                raise Problem("账号或密码不正确。", 401)
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
            db.execute("DELETE FROM sessions WHERE expires_at<=?", (int(time.time()),))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), user["id"], csrf, int(time.time()) + 43200))
            self.server.store.audit(db, user["id"], "auth.login", user["id"], {})
        self.server.failures.pop(key, None)
        self.respond(200, {"ok": True}, self.server.cookie_name + "=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200")

    def change_password(self, user, data):
        if self.server.auth:
            self.server.auth.change_password(self.server.store, user, data)
            return
        encoded = password_hash(data.get("new_password"))
        with self.server.store.tx() as db:
            current = db.execute("SELECT password_hash FROM users WHERE id=?", (user["id"],)).fetchone()
            if not password_ok(data.get("current_password"), current["password_hash"]):
                raise Problem("当前密码不正确。", 403)
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (encoded, user["id"]))
            db.execute("DELETE FROM sessions WHERE user_id=? AND token_hash!=?", (user["id"], user["token_hash"]))
            self.server.store.audit(db, user["id"], "auth.password", user["id"], {})

    def do_GET(self):
        self.handle_request(False)

    def do_POST(self):
        self.handle_request(True)

    def handle_request(self, mutation):
        try:
            self.check_origin()
            path = urlsplit(self.path).path
            store = self.server.store
            if not mutation:
                if path == "/api/session":
                    user = self.session(False)
                    with store.connect() as db:
                        needs_setup = not self.server.auth and not bool(db.execute("SELECT 1 FROM users").fetchone())
                    self.respond(200, {"needs_setup": needs_setup, "demo": self.server.demo, "auth_provider": "supabase" if self.server.auth else "local", "user": {k: v for k, v in user.items() if k != "token_hash"} if user else None})
                    return
                if path == "/api/referral":
                    code = parse_qs(urlsplit(self.path).query).get("code", [""])[0]
                    self.respond(200, store.referral(code))
                    return
                if path == "/api/dashboard":
                    self.respond(200, store.dashboard(self.session()))
                    return
                if path.startswith("/api/export/"):
                    self.export(path.rsplit("/", 1)[1], self.session())
                    return
                if path.startswith("/api/"):
                    raise Problem("接口不存在。", 404)
                files = {
                    "/": ROOT.parent / "index.html",
                    "/admin": ROOT / "static" / "index.html",
                    "/admin/": ROOT / "static" / "index.html",
                    "/recommend": ROOT / "static" / "index.html",
                    "/app.js": ROOT / "static" / "app.js",
                    "/style.css": ROOT / "static" / "style.css",
                }
                if path not in files:
                    raise Problem("页面不存在。", 404)
                file = files[path]
                blob = file.read_bytes()
                nonce = None
                if path == "/":
                    # Keep the standalone website usable under the same strict CSP.
                    nonce = secrets.token_urlsafe(24)
                    blob = blob.replace(b"<style>", f'<style nonce="{nonce}">'.encode())
                    blob = blob.replace(b"<script>", f'<script nonce="{nonce}">'.encode())
                self.send_response(200)
                self.headers_common(nonce)
                self.send_header("Content-Type", (mimetypes.guess_type(str(file))[0] or "text/plain") + "; charset=utf-8")
                self.send_header("Content-Length", str(len(blob)))
                self.end_headers()
                self.wfile.write(blob)
                return
            data = self.body()
            if path == "/api/setup":
                if self.server.auth:
                    raise Problem("管理员邮箱由服务器授权，不允许网页创建管理员。", 403)
                store.setup(data)
                self.respond(201, {"ok": True})
                return
            if path == "/api/register" and self.server.auth:
                self.respond(200, self.server.auth.register(store, data))
                return
            if path == "/api/login":
                self.login(data)
                return
            if path == "/api/inquiries":
                self.server.inquiry_requests = [t for t in self.server.inquiry_requests if t > time.time() - 300]
                if len(self.server.inquiry_requests) >= 20:
                    raise Problem("提交过于频繁，请稍后重试。", 429)
                self.server.inquiry_requests.append(time.time())
                self.respond(201, store.create_inquiry(data))
                return
            user = self.session(verify_provider=path != "/api/logout")
            non_admin_paths = {"/api/logout", "/api/password", "/api/orders"}
            is_cancel = path.startswith("/api/orders/") and path.endswith("/cancel")
            is_followup = path.startswith("/api/inquiries/") and path.endswith("/followup")
            self.guard(user, admin=path not in non_admin_paths and not is_cancel and not is_followup)
            result = {"ok": True}
            if path == "/api/logout":
                if self.server.auth:
                    self.server.auth.logout(store, user)
                with store.tx() as db:
                    db.execute("DELETE FROM sessions WHERE token_hash=?", (user["token_hash"],))
                self.respond(200, result, self.server.cookie_name + "=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
                return
            if path == "/api/password":
                self.change_password(user, data)
            elif path == "/api/agents":
                if self.server.auth:
                    from supabase_auth import email_address
                    data = {**data, "username": email_address(data.get("username")), "password": secrets.token_urlsafe(32)}
                result = store.create_agent(data, user["id"])
                if self.server.auth:
                    result.pop("temporary_password", None)
                    result["auth_provider"] = "supabase"
            elif path == "/api/policy":
                result = store.save_policy(data, user["id"])
            elif path == "/api/orders":
                result = store.create_order(data, user)
            else:
                parts = path.strip("/").split("/")
                if len(parts) != 4 or parts[0] != "api":
                    raise Problem("接口不存在。", 404)
                _, resource, identifier, action = parts
                if resource == "inquiries" and action == "followup":
                    store.update_inquiry(identifier, data, user)
                elif resource == "orders" and action == "paid":
                    result = store.pay_order(identifier, data, user["id"])
                elif resource == "orders" and action == "tokens":
                    result = store.release_tokens(identifier, user["id"])
                elif resource == "orders" and action == "refund":
                    result = store.refund_order(identifier, data, user["id"])
                elif resource == "orders" and action == "cancel":
                    store.cancel_order(identifier, user)
                elif resource == "commissions" and action == "approve":
                    store.approve(identifier, user["id"])
                elif resource == "agents" and action == "status":
                    store.update_agent(identifier, data, user["id"])
                elif resource == "agents" and action == "payout":
                    result = store.payout(identifier, data, user["id"])
                else:
                    raise Problem("接口不存在。", 404)
            self.respond(200, result or {"ok": True})
        except Problem as e:
            self.respond(e.status, {"error": str(e)})
        except sqlite3.IntegrityError:
            self.respond(409, {"error": "账号、凭证或关联记录重复或无效，请核对。"})
        except (ValueError, TypeError, KeyError):
            self.respond(400, {"error": "输入格式不正确，请检查必填项与数字。"})
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            logging.exception("Request failed")
            self.respond(500, {"error": "操作未完成，数据已回滚。请检查服务日志。"})

    def export(self, kind, user):
        keys = {
            "orders": ["number", "agent_name", "product_name", "customer_name", "customer_account", "amount", "tax", "delivery_amount", "status", "paid_at", "payment_ref"],
            "commissions": ["id", "order_number", "agent_name", "level", "amount", "rate_bp", "kind", "status", "payout_id"],
            "payouts": ["id", "agent_name", "amount", "reference", "created_at"],
        }
        if kind not in keys:
            raise Problem("不支持的导出类型。", 404)
        rows = self.server.store.dashboard(user)[kind]
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow([key + "_MYR" if key in ("amount", "tax", "delivery_amount") else key for key in keys[kind]])
        for row in rows:
            values = []
            for key in keys[kind]:
                value = row.get(key, "")
                if key in ("amount", "tax", "delivery_amount"):
                    value = f"{value / 100:.2f}"
                elif isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                    value = "'" + value
                values.append(value)
            writer.writerow(values)
        blob = ("\ufeff" + buffer.getvalue()).encode()
        self.send_response(200)
        self.headers_common()
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="zhongren-{kind}.csv"')
        self.send_header("Content-Length", str(len(blob)))
        self.end_headers()
        self.wfile.write(blob)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int)
    parser.add_argument("--demo", action="store_true", help="启动隔离演示库并预置测试场景")
    parser.add_argument("--db")
    parser.add_argument("--supabase", action="store_true", help="Use Supabase email/password authentication")
    args = parser.parse_args()
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    port = args.port or (8789 if args.demo else 8787)
    database = args.db or str(ROOT / "data" / ("demo.sqlite3" if args.demo else "zhongren.sqlite3"))
    auth = None
    use_supabase = args.supabase or os.environ.get("AUTH_PROVIDER") == "supabase"
    if use_supabase:
        if args.demo:
            parser.error("--demo and --supabase cannot be used together")
        from supabase_auth import SupabaseAuth
        auth = SupabaseAuth(os.environ.get("SUPABASE_URL", ""), os.environ.get("SUPABASE_PUBLISHABLE_KEY", ""))
    if args.demo:
        from demo import seed_demo, ensure_demo_portal
        seed_demo(database)
        ensure_demo_portal(database)
    store = Store(database)
    if auth:
        auth.install(store)
        if os.environ.get("SUPABASE_ADMIN_EMAIL"):
            auth.bootstrap(store, os.environ["SUPABASE_ADMIN_EMAIL"])
    server = AppServer(("127.0.0.1", port), store, demo=args.demo, auth=auth)
    print(f"众仁网站：http://127.0.0.1:{port}/", flush=True)
    print(f"众仁代理与佣金系统{' · 演示' if args.demo else ''}：http://127.0.0.1:{port}/admin", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
