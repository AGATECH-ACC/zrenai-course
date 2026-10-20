"""Persistent business operations. Monetary values are integer MYR cents."""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
from pathlib import Path
from zoneinfo import ZoneInfo

THRESHOLD = 6_980_000
MAX_MONEY = 100_000_000_000


class Problem(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def business_year():
    return datetime.now(ZoneInfo("Asia/Kuala_Lumpur")).year


def uid(prefix):
    return prefix + "_" + secrets.token_hex(8)


def money(value):
    try:
        x = Decimal(str(value))
        if not x.is_finite() or x < 0 or x * 100 != (x * 100).to_integral_value():
            raise ValueError()
        result = int(x * 100)
        if result > MAX_MONEY:
            raise ValueError()
        return result
    except (InvalidOperation, ValueError, TypeError):
        raise Problem("金额必须为非负数，最多两位小数，且不超过 RM 1,000,000,000。")


def integer(value, low, high, label):
    if isinstance(value, bool) or str(value) != str(int(value)):
        raise Problem(label + "必须为整数。")
    result = int(value)
    if not low <= result <= high:
        raise Problem(label + "超出允许范围。")
    return result


def text(value, label, limit=160, required=True):
    value = str(value or "").strip()
    if (required and not value) or len(value) > limit:
        raise Problem(label + "不能为空或过长。")
    return value


def portion(cents, basis_points):
    return int((Decimal(cents) * basis_points / 10000).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def password_hash(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 200:
        raise Problem("密码长度须为 12–200 个字符。")
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return salt + ":" + digest


def password_ok(password, encoded):
    if not isinstance(password, str) or len(password) > 200:
        return False
    salt, digest = encoded.split(":")
    actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex()
    return hmac.compare_digest(actual, digest)


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password_hash TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('admin','agent')),
 agent_id TEXT UNIQUE, active INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
 csrf TEXT NOT NULL, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS agents (
 id TEXT PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, contact TEXT NOT NULL,
 parent_id TEXT REFERENCES agents(id), role TEXT NOT NULL CHECK(role IN ('sales','partner')),
 active INTEGER NOT NULL DEFAULT 1, personal_sales INTEGER NOT NULL DEFAULT 0,
 promoted_at TEXT, sales_year INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS products (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, family TEXT NOT NULL, price INTEGER,
 participants INTEGER, token_gift INTEGER NOT NULL, delivery_bp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS policies (
 id INTEGER PRIMARY KEY AUTOINCREMENT, config TEXT NOT NULL, created_at TEXT NOT NULL,
 actor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS customers (
 id TEXT PRIMARY KEY, account TEXT NOT NULL UNIQUE, name TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS orders (
 id TEXT PRIMARY KEY, number TEXT UNIQUE NOT NULL, agent_id TEXT NOT NULL REFERENCES agents(id),
 customer_id TEXT NOT NULL REFERENCES customers(id), product_id TEXT NOT NULL REFERENCES products(id),
 amount INTEGER NOT NULL CHECK(amount>0), tax INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL CHECK(status IN ('draft','paid','refunded','cancelled')),
 note TEXT NOT NULL, participants INTEGER NOT NULL, created_at TEXT NOT NULL,
 paid_at TEXT, refund_at TEXT, payment_ref TEXT, refund_ref TEXT, policy_id INTEGER REFERENCES policies(id),
 role_at_sale TEXT, delivery_amount INTEGER NOT NULL DEFAULT 0,
 gift_amount INTEGER NOT NULL DEFAULT 0, snapshot TEXT, created_by TEXT NOT NULL,
 request_key TEXT UNIQUE NOT NULL, sales_year INTEGER);
CREATE TABLE IF NOT EXISTS commissions (
 id TEXT PRIMARY KEY, order_id TEXT NOT NULL REFERENCES orders(id),
 agent_id TEXT NOT NULL REFERENCES agents(id), level INTEGER NOT NULL,
 amount INTEGER NOT NULL, rate_bp INTEGER NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','approved','paid','reversed')),
 kind TEXT NOT NULL CHECK(kind IN ('earning','clawback')),
 created_at TEXT NOT NULL, approved_at TEXT, payout_id TEXT, reversal_of TEXT UNIQUE,
 UNIQUE(order_id,agent_id,kind));
CREATE TABLE IF NOT EXISTS token_ledger (
 id TEXT PRIMARY KEY, customer_id TEXT NOT NULL REFERENCES customers(id),
 order_id TEXT NOT NULL REFERENCES orders(id), amount INTEGER NOT NULL,
 kind TEXT NOT NULL CHECK(kind IN ('gift','reversal')), created_at TEXT NOT NULL,
 UNIQUE(order_id,kind));
CREATE TABLE IF NOT EXISTS payouts (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id), amount INTEGER NOT NULL,
 reference TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL, actor TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor TEXT NOT NULL, action TEXT NOT NULL,
 entity_id TEXT NOT NULL, detail TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inquiries (
 id TEXT PRIMARY KEY, agent_id TEXT NOT NULL REFERENCES agents(id),
 product_id TEXT NOT NULL REFERENCES products(id), customer_name TEXT NOT NULL,
 contact TEXT NOT NULL, participants INTEGER NOT NULL, message TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new','contacted','converted','closed')),
 followup TEXT NOT NULL DEFAULT '', order_id TEXT UNIQUE REFERENCES orders(id),
 request_key TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS inquiries_agent ON inquiries(agent_id,created_at);
CREATE INDEX IF NOT EXISTS orders_agent ON orders(agent_id,created_at);
CREATE INDEX IF NOT EXISTS commission_agent_status ON commissions(agent_id,status);
CREATE INDEX IF NOT EXISTS agents_parent ON agents(parent_id);
"""

DEFAULT_POLICY = {
    "sales_bp": 2000, "partner_bp": 3000, "cap_bp": 3000,
    "threshold": THRESHOLD, "crossing": "before", "period": "annual", "year_role": "retain",
    "refund_sales": "subtract", "refund_role": "recompute",
    "sales_uplines": [], "partner_uplines": [],
    "delivery_scope": "pending", "token_trigger": "pending",
    "operations_confirmed": False,
    "note": "已确认直接佣金 20% / 30%、个人累计 RM 69,800、次单起按新身份、渠道上限 30%。按马来西亚自然年累计；退款回撤业绩并重算晋升身份。跨年清零业绩并保留合伙人；交付/Token 发放口径须在启用前确认。",
}


class ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback):
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class Store:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript(SCHEMA)
            db.execute("PRAGMA journal_mode=WAL")
            if not db.execute("SELECT 1 FROM policies").fetchone():
                db.execute("INSERT INTO policies(config,created_at,actor) VALUES(?,?,?)", (json.dumps(DEFAULT_POLICY), now(), "system"))
            products = [
                ("operator-1", "AI 操盘手 · 个人版", "operator", 398000, 1, 300, 1000),
                ("operator-5", "AI 操盘手 · 团队版", "operator", 698000, 5, 680, 1000),
                ("operator-10", "AI 操盘手 · 企业版", "operator", 998000, 10, 1000, 1000),
                ("architect-50", "AI 架构师 · 基础版", "architect", 9980000, 50, 0, 1000),
                ("architect-70", "AI 架构师 · 成长版", "architect", 11980000, 70, 0, 1000),
                ("architect-100", "AI 架构师 · 规模版", "architect", 13980000, 100, 0, 1000),
                ("architect-custom", "AI 架构师 · 专属定制", "architect", None, None, 0, 1000),
            ]
            db.executemany("INSERT OR IGNORE INTO products VALUES(?,?,?,?,?,?,?)", products)
        os.chmod(self.path, 0o600)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=15, factory=ClosingConnection)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @contextmanager
    def tx(self):
        db = self.connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def audit(self, db, actor, action, entity, detail):
        db.execute("INSERT INTO audit(actor,action,entity_id,detail,created_at) VALUES(?,?,?,?,?)",
                   (actor, action, entity, json.dumps(detail, ensure_ascii=False), now()))

    def policy(self, db):
        row = db.execute("SELECT * FROM policies ORDER BY id DESC LIMIT 1").fetchone()
        config = {**DEFAULT_POLICY, "id": row["id"], **json.loads(row["config"])}
        if any(config[key] == "pending" for key in ("year_role", "delivery_scope", "token_trigger")):
            config["operations_confirmed"] = False
        return config

    def setup(self, data):
        encoded = password_hash(data.get("password"))
        username = text(data.get("username"), "用户名", 60)
        with self.tx() as db:
            if db.execute("SELECT 1 FROM users").fetchone():
                raise Problem("管理员已创建，请登录。", 409)
            identifier = uid("usr")
            db.execute("INSERT INTO users(id,username,password_hash,kind,created_at) VALUES(?,?,?,'admin',?)", (identifier, username, encoded, now()))
            self.audit(db, identifier, "setup", identifier, {"username": username})

    def create_agent(self, data, actor):
        name = text(data.get("name"), "姓名", 80)
        contact = text(data.get("contact"), "联系方式", 120, False)
        username = text(data.get("username"), "登录账号", 60)
        password = data.get("password") or secrets.token_urlsafe(16)
        encoded = password_hash(password)
        parent_id = data.get("parent_id") or None
        role = data.get("role", "sales")
        if role not in ("sales", "partner"):
            raise Problem("无效代理角色。")
        if role == "partner":
            text(data.get("admission_reason"), "合伙人资格依据", 250)
        with self.tx() as db:
            if parent_id and not db.execute("SELECT 1 FROM agents WHERE id=? AND active=1", (parent_id,)).fetchone():
                raise Problem("推荐人不存在或已停用。")
            identifier, user_id = uid("agt"), uid("usr")
            code = "ZR" + secrets.token_hex(3).upper()
            db.execute("INSERT INTO agents(id,code,name,contact,parent_id,role,sales_year,created_at) VALUES(?,?,?,?,?,?,?,?)", (identifier, code, name, contact, parent_id, role, business_year(), now()))
            db.execute("INSERT INTO users(id,username,password_hash,kind,agent_id,created_at) VALUES(?,?,?,'agent',?,?)", (user_id, username, encoded, identifier, now()))
            self.audit(db, actor, "agent.create", identifier, {"name": name, "parent_id": parent_id, "role": role, "admission_reason": data.get("admission_reason", "")})
        return {"id": identifier, "code": code, "username": username, "temporary_password": password}

    def update_agent(self, agent_id, data, actor):
        with self.tx() as db:
            agent = db.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
            if not agent:
                raise Problem("代理不存在。", 404)
            active = 1 if data.get("active") else 0
            # Referral links are immutable: changing them would reassign future earnings silently.
            db.execute("UPDATE agents SET active=? WHERE id=?", (active, agent_id))
            db.execute("UPDATE users SET active=? WHERE agent_id=?", (active, agent_id))
            if not active:
                db.execute("DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE agent_id=?)", (agent_id,))
            self.audit(db, actor, "agent.status", agent_id, {"active": active})

    def save_policy(self, data, actor):
        with self.tx() as db:
            current = self.policy(db)
            if data.get("version") != current["id"]:
                raise Problem("规则已被其他操作更新，请刷新后重试。", 409)
            config = {k: v for k, v in current.items() if k != "id"}
            # Confirmed commercial terms remain explicit; configurable uplines are shares of cap headroom.
            for key in ("sales_uplines", "partner_uplines"):
                values = data.get(key, [])
                if not isinstance(values, list) or len(values) > 100:
                    raise Problem("最多设置 100 级上级奖励。")
                config[key] = [integer(v, 0, 3000, "上级奖励基点") for v in values]
            for role in ("sales", "partner"):
                if config[role + "_bp"] + sum(config[role + "_uplines"]) > config["cap_bp"]:
                    raise Problem("直接佣金与各级上级奖励之和不可超过渠道上限 30%。合伙人直佣已占满 30%。")
            if data.get("period") != "annual":
                raise Problem("已确认按自然年累计。")
            if data.get("year_role") not in ("pending", "retain", "recompute"):
                raise Problem("请选择跨年身份处理。")
            config["year_role"] = data["year_role"]
            if data.get("refund_role") not in ("retain", "recompute"):
                raise Problem("请选择退款后的身份处理。")
            config["refund_role"] = data["refund_role"]
            for key, choices in (("delivery_scope", ("pending", "all", "architect")), ("token_trigger", ("pending", "paid", "manual"))):
                if data.get(key) not in choices:
                    raise Problem("请选择交付费范围与 Token 发放时点。")
                config[key] = data[key]
            config["operations_confirmed"] = data.get("operations_confirmed") is True
            config["note"] = text(data.get("note"), "规则说明", 1000, False)
            config["period"] = "annual"
            if config["operations_confirmed"] and any(config[key] == "pending" for key in ("year_role", "delivery_scope", "token_trigger")):
                raise Problem("启用收款前须确认跨年身份、交付费范围与 Token 发放时点。")
            cursor = db.execute("INSERT INTO policies(config,created_at,actor) VALUES(?,?,?)", (json.dumps(config, ensure_ascii=False), now(), actor))
            self.audit(db, actor, "policy.publish", str(cursor.lastrowid), config)
        return {"version": cursor.lastrowid}

    def create_order(self, data, user):
        request_key = text(data.get("request_key"), "提交标识", 100)
        with self.tx() as db:
            old = db.execute("SELECT id,created_by FROM orders WHERE request_key=?", (request_key,)).fetchone()
            if old:
                if old["created_by"] != user["id"]:
                    raise Problem("提交标识已使用。", 409)
                return {"id": old["id"], "duplicate": True}
            inquiry = None
            if data.get("inquiry_id"):
                inquiry = db.execute("SELECT * FROM inquiries WHERE id=?", (data["inquiry_id"],)).fetchone()
                if not inquiry or (user["kind"] != "admin" and inquiry["agent_id"] != user["agent_id"]):
                    raise Problem("客户意向不存在。", 404)
                if inquiry["order_id"] or inquiry["status"] == "closed":
                    raise Problem("此意向已转订单或已关闭。", 409)
                data = {**data, "agent_id": inquiry["agent_id"], "product_id": inquiry["product_id"],
                        "customer_name": inquiry["customer_name"], "participants": inquiry["participants"]}
            agent_id = user["agent_id"] if user["kind"] == "agent" else data.get("agent_id")
            agent = db.execute("SELECT * FROM agents WHERE id=? AND active=1", (agent_id,)).fetchone()
            if not agent:
                raise Problem("请选择有效代理。")
            product = db.execute("SELECT * FROM products WHERE id=?", (data.get("product_id"),)).fetchone()
            if not product:
                raise Problem("课程不存在。")
            participants = integer(data.get("participants", 1), 1, 100000, "人数")
            if product["participants"] and participants > product["participants"]:
                raise Problem("人数超过套餐上限。")
            if product["id"] == "architect-custom" and participants <= 100:
                raise Problem("专属定制适用于超过 100 人。")
            if product["id"] == "architect-70" and participants < 50:
                raise Problem("成长版适用于 50–70 人；50 人边界请线下确认选档。")
            if product["id"] == "architect-100" and participants < 70:
                raise Problem("规模版适用于 70–100 人；70 人边界请线下确认选档。")
            amount = product["price"] if product["price"] is not None else money(data.get("amount"))
            if not amount:
                raise Problem("订单金额必须大于零。")
            if product["price"] is None and user["kind"] != "admin":
                raise Problem("定制报价需由管理员录入。", 403)
            account = text(data.get("customer_account"), "客户账户", 100).casefold()
            customer_name = text(data.get("customer_name"), "客户姓名", 100)
            customer = db.execute("SELECT * FROM customers WHERE account=?", (account,)).fetchone()
            if customer and customer["name"] != customer_name:
                raise Problem("该客户账户已存在，姓名不一致，请向管理员核实。")
            customer_id = customer["id"] if customer else uid("cus")
            if not customer:
                db.execute("INSERT INTO customers VALUES(?,?,?,?)", (customer_id, account, customer_name, now()))
            identifier = uid("ord")
            number = "ZR-" + datetime.now(timezone.utc).strftime("%Y%m%d") + "-" + secrets.token_hex(3).upper()
            db.execute("INSERT INTO orders(id,number,agent_id,customer_id,product_id,amount,status,note,participants,created_at,created_by,request_key) VALUES(?,?,?,?,?,?,'draft',?,?,?,?,?)",
                       (identifier, number, agent_id, customer_id, product["id"], amount, text(data.get("note"), "备注", 500, False), participants, now(), user["id"], request_key))
            if inquiry:
                db.execute("UPDATE inquiries SET status='converted',order_id=? WHERE id=?", (identifier, inquiry["id"]))
                self.audit(db, user["id"], "inquiry.convert", inquiry["id"], {"order_id": identifier})
            self.audit(db, user["id"], "order.create", identifier, {"number": number, "amount": amount, "agent_id": agent_id})
        return {"id": identifier, "number": number}

    def referral(self, code):
        code = text(code, "推广码", 30).upper()
        with self.connect() as db:
            agent = db.execute("SELECT code,name FROM agents WHERE code=? AND active=1", (code,)).fetchone()
            if not agent:
                raise Problem("推广码无效或已停用，请向推荐人核实。", 404)
            products = [dict(r) for r in db.execute("SELECT id,name,family,price,participants,token_gift FROM products ORDER BY rowid")]
            return {"agent": dict(agent), "products": products}

    def create_inquiry(self, data):
        code = text(data.get("code"), "推广码", 30).upper()
        key = text(data.get("request_key"), "提交标识", 100)
        name = text(data.get("customer_name"), "姓名 / 企业", 100)
        contact = text(data.get("contact"), "联系方式", 120)
        message = text(data.get("message"), "需求说明", 500, False)
        participants = integer(data.get("participants", 1), 1, 100000, "人数")
        if data.get("consent") is not True:
            raise Problem("请同意将购买意向和联系方式交给推荐代理跟进。")
        with self.tx() as db:
            agent = db.execute("SELECT id FROM agents WHERE code=? AND active=1", (code,)).fetchone()
            if not agent:
                raise Problem("推广码无效或已停用。", 404)
            product = db.execute("SELECT * FROM products WHERE id=?", (data.get("product_id"),)).fetchone()
            if not product:
                raise Problem("请选择有效课程。")
            minimum = {"architect-70": 50, "architect-100": 70, "architect-custom": 101}.get(product["id"], 1)
            if participants < minimum or (product["participants"] and participants > product["participants"]):
                raise Problem("人数不在所选套餐范围内，请选择适用课程。")
            old = db.execute("SELECT * FROM inquiries WHERE request_key=?", (key,)).fetchone()
            if old:
                if (old["agent_id"], old["product_id"], old["customer_name"], old["contact"], old["participants"], old["message"]) != (agent["id"], product["id"], name, contact, participants, message):
                    raise Problem("提交标识已使用，请刷新后重试。", 409)
                return {"ok": True}
            identifier = uid("inq")
            db.execute("INSERT INTO inquiries(id,agent_id,product_id,customer_name,contact,participants,message,request_key,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                       (identifier, agent["id"], product["id"], name, contact, participants, message, key, now()))
            self.audit(db, "visitor", "inquiry.create", identifier, {"agent_id": agent["id"], "code": code})
        return {"ok": True}

    def update_inquiry(self, identifier, data, user):
        status = data.get("status")
        if status not in ("new", "contacted", "closed"):
            raise Problem("无效跟进状态。")
        followup = text(data.get("followup"), "跟进记录", 1000, False)
        with self.tx() as db:
            row = db.execute("SELECT * FROM inquiries WHERE id=?", (identifier,)).fetchone()
            if not row or (user["kind"] != "admin" and row["agent_id"] != user["agent_id"]):
                raise Problem("客户意向不存在。", 404)
            if row["order_id"]:
                raise Problem("已转订单的意向不可更改状态，请查看关联订单。", 409)
            db.execute("UPDATE inquiries SET status=?,followup=? WHERE id=?", (status, followup, identifier))
            self.audit(db, user["id"], "inquiry.followup", identifier, {"status": status})

    def rollover(self, db):
        policy = self.policy(db)
        year = business_year()
        for agent in db.execute("SELECT * FROM agents WHERE sales_year<?", (year,)).fetchall():
            if policy["year_role"] == "pending":
                raise Problem("请先确认跨年后的身份处理。", 409)
            role = "sales" if agent["promoted_at"] and policy["year_role"] == "recompute" else agent["role"]
            db.execute("UPDATE agents SET personal_sales=0,sales_year=?,role=? WHERE id=?", (year, role, agent["id"]))
            self.audit(db, "system", "agent.year_rollover", agent["id"], {"year": year, "role": role})

    def pay_order(self, order_id, data, actor):
        reference = text(data.get("reference"), "收款凭证编号", 120)
        tax = money(data.get("tax", 0))
        with self.tx() as db:
            order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if not order:
                raise Problem("订单不存在。", 404)
            if order["status"] == "paid":
                if order["payment_ref"] == reference and order["tax"] == tax:
                    return {"id": order_id, "duplicate": True}
                raise Problem("订单已收款，不能更改凭证或税费。", 409)
            if order["status"] != "draft":
                raise Problem("只有待收款订单可确认收款。", 409)
            if db.execute("SELECT 1 FROM orders WHERE payment_ref=?", (reference,)).fetchone():
                raise Problem("此收款凭证已关联另一订单。", 409)
            policy = self.policy(db)
            if not policy["operations_confirmed"] or any(policy[key] == "pending" for key in ("year_role", "delivery_scope", "token_trigger")):
                raise Problem("请先在规则设置中确认累计周期、退款处理及交付/Token 发放口径，再启用收款。", 409)
            self.rollover(db)
            agent = db.execute("SELECT * FROM agents WHERE id=?", (order["agent_id"],)).fetchone()
            if not agent["active"]:
                raise Problem("该代理已停用。", 409)
            product = db.execute("SELECT * FROM products WHERE id=?", (order["product_id"],)).fetchone()
            role = agent["role"]
            delivery = portion(order["amount"], product["delivery_bp"]) if policy["delivery_scope"] == "all" or product["family"] == "architect" else 0
            gift = product["token_gift"] if policy["token_trigger"] == "paid" else 0
            rates = [policy[role + "_bp"]] + policy[role + "_uplines"]
            ancestors, current, seen = [], agent, set()
            for level, rate in enumerate(rates):
                if not current:
                    break
                if current["id"] in seen:
                    raise Problem("推荐关系出现循环，请先修复。", 409)
                seen.add(current["id"])
                if not current["active"] and rate:
                    raise Problem("收佣链存在已停用代理，请先审核推荐关系。", 409)
                if rate:
                    ancestors.append({"agent_id": current["id"], "level": level, "rate_bp": rate, "amount": portion(order["amount"], rate)})
                current = db.execute("SELECT * FROM agents WHERE id=?", (current["parent_id"],)).fetchone() if current["parent_id"] else None
            total = sum(row["amount"] for row in ancestors)
            # Guard rounding as well as rate cap; never silently clip a recipient's earnings.
            if total > portion(order["amount"], policy["cap_bp"]):
                raise Problem("佣金金额超过 30% 上限，请调整层级规则。", 409)
            if tax + delivery + total > order["amount"]:
                raise Problem("税费、交付与佣金合计超过成交金额。")
            timestamp = now()
            snapshot = {"policy": policy, "recipients": ancestors, "product": dict(product), "personal_sales_before": agent["personal_sales"]}
            db.execute("UPDATE orders SET status='paid',tax=?,paid_at=?,payment_ref=?,policy_id=?,role_at_sale=?,delivery_amount=?,gift_amount=?,snapshot=?,sales_year=? WHERE id=?",
                       (tax, timestamp, reference, policy["id"], role, delivery, gift, json.dumps(snapshot, ensure_ascii=False), business_year(), order_id))
            for row in ancestors:
                db.execute("INSERT INTO commissions(id,order_id,agent_id,level,amount,rate_bp,status,kind,created_at) VALUES(?,?,?,?,?,?,'pending','earning',?)",
                           (uid("com"), order_id, row["agent_id"], row["level"], row["amount"], row["rate_bp"], timestamp))
            if gift:
                db.execute("INSERT INTO token_ledger VALUES(?,?,?,?,?,?)", (uid("tok"), order["customer_id"], order_id, gift, "gift", timestamp))
            cumulative = agent["personal_sales"] + order["amount"]
            promoted = role == "sales" and cumulative >= policy["threshold"]
            db.execute("UPDATE agents SET personal_sales=?,role=?,promoted_at=CASE WHEN ? THEN ? ELSE promoted_at END WHERE id=?", (cumulative, "partner" if promoted else role, promoted, timestamp, agent["id"]))
            if promoted:
                self.audit(db, actor, "agent.promote", agent["id"], {"order_id": order_id, "personal_sales": cumulative, "effective": "next_order"})
            self.audit(db, actor, "order.paid", order_id, {"amount": order["amount"], "reference": reference, "policy_id": policy["id"], "promoted": promoted})
        return {"id": order_id, "promoted": promoted, "commission": total}

    def release_tokens(self, order_id, actor):
        with self.tx() as db:
            order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if not order or order["status"] != "paid":
                raise Problem("仅已收款且未退款订单可发放 Token。", 409)
            if order["gift_amount"]:
                return {"duplicate": True, "amount": order["gift_amount"]}
            snapshot = json.loads(order["snapshot"])
            gift = snapshot["product"]["token_gift"]
            if snapshot["policy"].get("token_trigger") != "manual" or not gift:
                raise Problem("此订单没有待手动发放的 Token。", 409)
            db.execute("INSERT INTO token_ledger VALUES(?,?,?,?,?,?)", (uid("tok"), order["customer_id"], order_id, gift, "gift", now()))
            db.execute("UPDATE orders SET gift_amount=? WHERE id=?", (gift, order_id))
            self.audit(db, actor, "token.release", order_id, {"amount": gift})
        return {"amount": gift}

    def cancel_order(self, order_id, user):
        with self.tx() as db:
            row = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if not row or (user["kind"] == "agent" and row["agent_id"] != user["agent_id"]):
                raise Problem("订单不存在。", 404)
            if row["status"] != "draft":
                raise Problem("仅待收款订单可取消。", 409)
            db.execute("UPDATE orders SET status='cancelled' WHERE id=?", (order_id,))
            self.audit(db, user["id"], "order.cancel", order_id, {})

    def refund_order(self, order_id, data, actor):
        reference = text(data.get("reference"), "退款凭证及原因", 250)
        with self.tx() as db:
            order = db.execute("SELECT * FROM orders WHERE id=?", (order_id,)).fetchone()
            if not order:
                raise Problem("订单不存在。", 404)
            if order["status"] == "refunded" and order["refund_ref"] == reference:
                return {"duplicate": True}
            if order["status"] != "paid":
                raise Problem("仅已收款订单可全额退款。", 409)
            policy = json.loads(order["snapshot"])["policy"]
            timestamp = now()
            agent = db.execute("SELECT * FROM agents WHERE id=?", (order["agent_id"],)).fetchone()
            self.rollover(db)
            agent = db.execute("SELECT * FROM agents WHERE id=?", (order["agent_id"],)).fetchone()
            new_sales = agent["personal_sales"] - (order["amount"] if order["sales_year"] == agent["sales_year"] else 0)
            role = agent["role"]
            # Manually admitted partners do not lose admission status on sales refunds.
            if policy["refund_role"] == "recompute" and agent["promoted_at"]:
                # Retained status can be supported by any qualifying year; a new-year
                # refund must not erase a still-valid previous-year qualification.
                year_filter = "" if policy["year_role"] == "retain" else " AND sales_year=" + str(business_year())
                qualified = db.execute(
                    "SELECT sales_year FROM orders WHERE agent_id=? AND status='paid' AND id!=?" + year_filter +
                    " GROUP BY sales_year HAVING SUM(amount)>=? LIMIT 1",
                    (agent["id"], order_id, policy["threshold"]),
                ).fetchone()
                role = "partner" if qualified else "sales"
            db.execute("UPDATE agents SET personal_sales=?,role=? WHERE id=?", (new_sales, role, agent["id"]))
            for commission in db.execute("SELECT * FROM commissions WHERE order_id=? AND kind='earning'", (order_id,)).fetchall():
                if commission["status"] == "paid":
                    db.execute("INSERT INTO commissions(id,order_id,agent_id,level,amount,rate_bp,status,kind,created_at,approved_at,reversal_of) VALUES(?,?,?,?,?,?,'approved','clawback',?,?,?)",
                               (uid("com"), order_id, commission["agent_id"], commission["level"], -commission["amount"], commission["rate_bp"], timestamp, timestamp, commission["id"]))
                else:
                    db.execute("UPDATE commissions SET status='reversed' WHERE id=?", (commission["id"],))
            if order["gift_amount"]:
                db.execute("INSERT INTO token_ledger VALUES(?,?,?,?,?,?)", (uid("tok"), order["customer_id"], order_id, -order["gift_amount"], "reversal", timestamp))
            db.execute("UPDATE orders SET status='refunded',refund_at=?,refund_ref=? WHERE id=?", (timestamp, reference, order_id))
            self.audit(db, actor, "order.refund", order_id, {"reference": reference, "amount": order["amount"], "role_after": role, "policy_id": order["policy_id"]})
        return {"id": order_id}

    def approve(self, commission_id, actor):
        with self.tx() as db:
            row = db.execute("SELECT * FROM commissions WHERE id=?", (commission_id,)).fetchone()
            if not row:
                raise Problem("佣金记录不存在。", 404)
            if row["status"] == "approved":
                return
            if row["status"] != "pending":
                raise Problem("此佣金不能审核。", 409)
            db.execute("UPDATE commissions SET status='approved',approved_at=? WHERE id=?", (now(), commission_id))
            self.audit(db, actor, "commission.approve", commission_id, {"amount": row["amount"]})

    def payout(self, agent_id, data, actor):
        reference = text(data.get("reference"), "银行付款凭证编号", 120)
        expected = money(data.get("amount"))
        with self.tx() as db:
            existing = db.execute("SELECT * FROM payouts WHERE reference=?", (reference,)).fetchone()
            if existing:
                if existing["agent_id"] == agent_id and existing["amount"] == expected:
                    return {"id": existing["id"], "duplicate": True}
                raise Problem("付款凭证编号已使用。", 409)
            agent = db.execute("SELECT * FROM agents WHERE id=? AND active=1", (agent_id,)).fetchone()
            if not agent:
                raise Problem("代理不存在或已停用。")
            entries = db.execute("SELECT * FROM commissions WHERE agent_id=? AND status='approved'", (agent_id,)).fetchall()
            amount = sum(row["amount"] for row in entries)
            if amount <= 0:
                raise Problem("没有可结算的正余额；退款追回应先抵扣。", 409)
            if expected != amount:
                raise Problem("可结算余额已变化，请刷新核对后重试。", 409)
            identifier = uid("pay")
            db.execute("INSERT INTO payouts VALUES(?,?,?,?,?,?)", (identifier, agent_id, amount, reference, now(), actor))
            db.executemany("UPDATE commissions SET status='paid',payout_id=? WHERE id=?", [(identifier, row["id"]) for row in entries])
            self.audit(db, actor, "payout.record", identifier, {"amount": amount, "reference": reference, "agent_id": agent_id})
        return {"id": identifier, "amount": amount}

    def dashboard(self, user):
        with self.tx() as db:
            if self.policy(db)["year_role"] != "pending":
                self.rollover(db)
            admin = user["kind"] == "admin"
            where = "" if admin else " WHERE a.id=?"
            params = () if admin else (user["agent_id"],)
            agents = [dict(r) for r in db.execute("SELECT a.*,p.name parent_name,u.username FROM agents a LEFT JOIN agents p ON p.id=a.parent_id LEFT JOIN users u ON u.agent_id=a.id" + where + " ORDER BY a.created_at DESC", params)]
            # Agents see only their own orders. Upline rewards expose a number, not buyer PII.
            where = "" if admin else " WHERE o.agent_id=?"
            orders = [dict(r) for r in db.execute("SELECT o.*,a.name agent_name,p.name product_name,c.name customer_name,c.account customer_account FROM orders o JOIN agents a ON a.id=o.agent_id JOIN products p ON p.id=o.product_id JOIN customers c ON c.id=o.customer_id" + where + " ORDER BY o.created_at DESC,o.rowid DESC", params)]
            for order in orders:
                order["snapshot"] = json.loads(order["snapshot"]) if order["snapshot"] else None
                # Other recipients and their IDs are not part of the seller's portal data.
                if not admin and order["snapshot"]:
                    order["snapshot"].pop("recipients", None)
            where = "" if admin else " WHERE c.agent_id=?"
            commissions = [dict(r) for r in db.execute("SELECT c.*,a.name agent_name,o.number order_number FROM commissions c JOIN agents a ON a.id=c.agent_id JOIN orders o ON o.id=c.order_id" + where + " ORDER BY c.created_at DESC,c.rowid DESC", params)]
            where = "" if admin else " WHERE p.agent_id=?"
            payouts = [dict(r) for r in db.execute("SELECT p.*,a.name agent_name FROM payouts p JOIN agents a ON a.id=p.agent_id" + where + " ORDER BY p.created_at DESC", params)]
            if admin:
                tokens = [dict(r) for r in db.execute("SELECT c.id,c.name,c.account,COALESCE(SUM(t.amount),0) balance FROM customers c LEFT JOIN token_ledger t ON t.customer_id=c.id GROUP BY c.id ORDER BY c.created_at DESC")]
                token_entries = [dict(r) for r in db.execute("SELECT t.*,c.account,o.number order_number FROM token_ledger t JOIN customers c ON c.id=t.customer_id JOIN orders o ON o.id=t.order_id ORDER BY t.created_at DESC,t.rowid DESC")]
            else:
                tokens, token_entries = [], []
            audit = [dict(r) for r in db.execute("SELECT a.*,u.username FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 200")] if admin else []
            policy = self.policy(db)
            products = [dict(r) for r in db.execute("SELECT * FROM products ORDER BY rowid")]
            where = "" if admin else " WHERE i.agent_id=?"
            inquiries = [dict(r) for r in db.execute("SELECT i.*,a.name agent_name,a.code,p.name product_name,o.number order_number FROM inquiries i JOIN agents a ON a.id=i.agent_id JOIN products p ON p.id=i.product_id LEFT JOIN orders o ON o.id=i.order_id" + where + " ORDER BY i.created_at DESC,i.rowid DESC", params)]
            return {"inquiries": inquiries, "agents": agents, "orders": orders, "commissions": commissions, "payouts": payouts,
                    "tokens": tokens, "token_entries": token_entries, "audit": audit, "policy": policy, "products": products}
