"""Supabase email/password authentication with server-held, short-lived sessions.

Only publishable keys are needed. Roles come from the application's explicit
allowlist, never editable Supabase user_metadata. No refresh tokens are retained.
"""
import hashlib
import json
import logging
import re
import secrets
import sqlite3
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
from uuid import UUID

from store import Problem, now, password_hash, uid


def email_address(value):
    value = str(value or '').strip().lower()
    if len(value) > 60 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', value):
        raise Problem('请填写有效的登录邮箱（最多 60 字符）。')
    return value


class SupabaseAuth:
    def __init__(self, url, publishable_key):
        url = str(url).rstrip('/')
        parsed = urlsplit(url)
        if (parsed.scheme != 'https' or not parsed.hostname or not parsed.hostname.endswith('.supabase.co')
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment or parsed.port):
            raise ValueError('SUPABASE_URL must be an HTTPS Supabase project URL.')
        if not str(publishable_key).startswith('sb_publishable_'):
            raise ValueError('Use a Supabase publishable key, never a service-role or secret key.')
        self.url, self.key = url, publishable_key

    def request(self, method, path, payload=None, access_token=None):
        headers = {'apikey': self.key, 'Content-Type': 'application/json'}
        if access_token:
            headers['Authorization'] = 'Bearer ' + access_token
        req = urllib.request.Request(self.url + '/auth/v1' + path,
                                     data=json.dumps(payload).encode() if payload is not None else None,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                blob = response.read(131072)
                return json.loads(blob) if blob else {}
        except urllib.error.HTTPError as error:
            # Never forward remote bodies (which may contain personal data/tokens).
            status = error.code
            error.close()
            if status == 429:
                raise Problem('Supabase 请求过于频繁，请稍后重试。', 429) from None
            if status >= 500:
                raise Problem('Supabase Auth 暂时不可用，请稍后重试。', 503) from None
            raise Problem('Supabase 验证失败，请检查邮箱、密码及邮箱确认状态。', 401) from None
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            raise Problem('无法连接 Supabase Auth，请稍后重试。', 503) from None

    def install(self, store):
        if hasattr(store, 'auth_schema_ready'):
            store.auth_schema_ready()
            return
        with store.tx() as db:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='demo_metadata'").fetchone():
                raise ValueError('Supabase authentication cannot use a seeded demo database.')
            db.execute('''CREATE TABLE IF NOT EXISTS supabase_links (
                user_id TEXT PRIMARY KEY REFERENCES users(id), auth_id TEXT NOT NULL UNIQUE)''')
            db.execute('''CREATE TABLE IF NOT EXISTS supabase_sessions (
                token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
                access_token TEXT NOT NULL)''')

    def bootstrap(self, store, email):
        email = email_address(email)
        with store.tx() as db:
            existing = db.execute('SELECT id,kind FROM users WHERE username=?', (email,)).fetchone()
            if existing:
                if existing['kind'] != 'admin':
                    raise ValueError('Bootstrap email already belongs to an agent; refusing role escalation.')
                return
            if db.execute("SELECT 1 FROM users WHERE kind='admin'").fetchone():
                raise ValueError('An administrator already exists. Explicit account migration is required.')
            identifier = uid('usr')
            db.execute("INSERT INTO users(id,username,password_hash,kind,created_at) VALUES(?,?,?,'admin',?)",
                       (identifier, email, password_hash(secrets.token_urlsafe(32)), now()))
            store.audit(db, 'system', 'auth.allowlist_admin', identifier, {})

    def register(self, store, data):
        email = email_address(data.get('username'))
        password = data.get('password')
        if not isinstance(password, str) or not 12 <= len(password) <= 200:
            raise Problem('密码长度须为 12–200 个字符。')
        with store.connect() as db:
            allowed = db.execute('SELECT id FROM users WHERE username=? AND active=1', (email,)).fetchone()
        if not allowed:
            raise Problem('此邮箱尚未获授权，请联系管理员开户。', 403)
        self.request('POST', '/signup', {'email': email, 'password': password})
        # A signup response never grants access, even if the project disables confirmation.
        return {'ok': True, 'message': '请检查邮箱完成 Supabase 验证，然后返回登录。已有账号请直接登录。'}

    def verified_user(self, access_token):
        identity = self.request('GET', '/user', access_token=access_token)
        try:
            UUID(identity.get('id', ''))
        except (ValueError, TypeError, AttributeError):
            raise Problem('Supabase 返回了无效身份。', 401)
        if not identity.get('email_confirmed_at') or identity.get('is_anonymous'):
            raise Problem('请先完成邮箱验证。', 401)
        return identity

    def sign_in(self, email, password):
        if not isinstance(password, str) or not 1 <= len(password) <= 200:
            raise Problem('请填写有效密码。')
        result = self.request('POST', '/token?grant_type=password', {'email': email, 'password': password})
        token = result.get('access_token')
        if not isinstance(token, str) or not token:
            raise Problem('Supabase 未返回有效登录会话。', 401)
        return result

    def login(self, store, data):
        email = email_address(data.get('username'))
        with store.connect() as db:
            allowed = db.execute('SELECT id FROM users WHERE username=? AND active=1', (email,)).fetchone()
        if not allowed:
            raise Problem('账号未获授权或已停用。', 403)
        remote = self.sign_in(email, data.get('password'))
        access = remote['access_token']
        identity = self.verified_user(access)
        if email_address(identity.get('email')) != email:
            raise Problem('Supabase 登录邮箱不匹配。', 401)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
        digest = hashlib.sha256(token.encode()).hexdigest()
        try:
            ttl = max(0, min(int(remote.get('expires_in', 0)), 3600))
        except (TypeError, ValueError):
            ttl = 0
        if not ttl:
            raise Problem('Supabase 会话已过期，请重新登录。', 401)
        with store.tx() as db:
            user = db.execute('SELECT id FROM users WHERE username=? AND active=1', (email,)).fetchone()
            if not user:
                raise Problem('账号已停用。', 403)
            linked = db.execute('SELECT auth_id FROM supabase_links WHERE user_id=?', (user['id'],)).fetchone()
            if linked and linked['auth_id'] != identity['id']:
                raise Problem('账号身份已变更，需管理员核实绑定。', 403)
            try:
                db.execute('INSERT OR IGNORE INTO supabase_links(user_id,auth_id) VALUES(?,?)', (user['id'], identity['id']))
                binding = db.execute('SELECT auth_id FROM supabase_links WHERE user_id=?', (user['id'],)).fetchone()
                if not binding or binding['auth_id'] != identity['id']:
                    raise Problem('Supabase 身份已绑定其他账号。', 403)
            except sqlite3.IntegrityError:
                raise Problem('Supabase 身份已绑定其他账号。', 403) from None
            db.execute('DELETE FROM sessions WHERE expires_at<=?', (int(time.time()),))
            db.execute('INSERT INTO sessions VALUES(?,?,?,?)', (digest, user['id'], csrf, int(time.time()) + ttl))
            db.execute('INSERT INTO supabase_sessions VALUES(?,?)', (digest, access))
            store.audit(db, user['id'], 'auth.login', user['id'], {'provider': 'supabase'})
        return token, ttl

    def validate_session(self, store, user):
        with store.connect() as db:
            row = db.execute('SELECT s.access_token,l.auth_id FROM supabase_sessions s JOIN supabase_links l ON l.user_id=? WHERE s.token_hash=?',
                             (user['id'], user['token_hash'])).fetchone()
        if not row:
            return False  # A legacy local session never authenticates Supabase mode.
        try:
            identity = self.verified_user(row['access_token'])
        except Problem as error:
            if error.status == 401:
                with store.tx() as db:
                    db.execute('DELETE FROM sessions WHERE token_hash=?', (user['token_hash'],))
                return False
            raise
        return identity['id'] == row['auth_id']

    def logout(self, store, user):
        with store.connect() as db:
            row = db.execute('SELECT access_token FROM supabase_sessions WHERE token_hash=?', (user['token_hash'],)).fetchone()
        try:
            if row:
                self.request('POST', '/logout?scope=local', {}, row['access_token'])
        except Problem:
            logging.warning('Supabase sign-out unavailable; local session revoked.')
        finally:
            with store.tx() as db:
                db.execute('DELETE FROM sessions WHERE token_hash=?', (user['token_hash'],))

    def change_password(self, store, user, data):
        new_password = data.get('new_password')
        if not isinstance(new_password, str) or not 12 <= len(new_password) <= 200:
            raise Problem('密码长度须为 12–200 个字符。')
        with store.connect() as db:
            row = db.execute('SELECT s.access_token,l.auth_id FROM supabase_sessions s JOIN supabase_links l ON l.user_id=? WHERE s.token_hash=?',
                             (user['id'], user['token_hash'])).fetchone()
        identity = self.verified_user(row['access_token'])
        fresh = self.sign_in(identity['email'], data.get('current_password'))
        try:
            if self.verified_user(fresh['access_token'])['id'] != row['auth_id']:
                raise Problem('当前身份不匹配。', 403)
            self.request('PUT', '/user', {'password': new_password}, fresh['access_token'])
            try:
                self.request('POST', '/logout?scope=global', {}, fresh['access_token'])
            except Problem:
                logging.warning('Supabase global sign-out unavailable after password update.')
            with store.tx() as db:
                db.execute('DELETE FROM sessions WHERE user_id=?', (user['id'],))
                store.audit(db, user['id'], 'auth.password', user['id'], {'provider': 'supabase'})
        finally:
            try:
                self.request('POST', '/logout?scope=local', {}, fresh['access_token'])
            except Problem:
                pass
