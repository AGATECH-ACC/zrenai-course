"""Seed a separate demo database through the same accounting operations as the app."""
import os
import sqlite3
import tempfile
from pathlib import Path

from store import Store, Problem, ClosingConnection

DEMO_PASSWORD = "ZhongrenDemo2026!"


def seed_demo(path):
    destination = Path(path).resolve()
    if destination.exists():
        with sqlite3.connect(destination, factory=ClosingConnection) as db:
            marker = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='demo_metadata'").fetchone()
            if not marker or not db.execute("SELECT 1 FROM demo_metadata WHERE version=1").fetchone():
                raise Problem("此数据库不是演示库，拒绝注入示例数据。")
        return False
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Build off to the side; interrupted seeding never leaves half a demo database.
    with tempfile.TemporaryDirectory(prefix=".demo-seed-", dir=destination.parent) as folder:
        store = Store(Path(folder) / "seed.sqlite3")
        store.setup({"username": "demo.admin", "password": DEMO_PASSWORD})
        with store.connect() as db:
            admin = dict(db.execute("SELECT * FROM users WHERE kind='admin'").fetchone())
            policy = store.policy(db)
        store.save_policy({
            "version": policy["id"], "period": "annual", "year_role": "retain",
            "refund_role": "recompute", "delivery_scope": "all", "token_trigger": "paid",
            "sales_uplines": [500], "partner_uplines": [], "operations_confirmed": True,
            "note": "仅限演示：假设全额到账发放每单一份 Token、所有课程交付费 10%、业务员订单直属上级奖励 5%。用于测试，不代表正式业务批准。",
        }, admin["id"])

        def agent(name, username, parent=None, role="sales"):
            return store.create_agent({"name": name, "username": username, "password": DEMO_PASSWORD,
                                       "parent_id": parent, "role": role,
                                       "admission_reason": "演示：已有合伙人资格" if role == "partner" else ""}, admin["id"])

        partner = agent("陈合伙人 · 演示", "demo.partner", role="partner")
        sales = agent("林晓 · 晋升测试", "demo.sales", partner["id"])
        refund = agent("王敏 · 退款降级", "demo.refund")
        payout = agent("张伟 · 已付佣金追回", "demo.payout")

        def order(owner, number, note, product="operator-5", paid=True):
            result = store.create_order({
                "request_key": number, "agent_id": owner["id"], "product_id": product,
                "participants": 1, "customer_account": number.lower() + "@demo.invalid",
                "customer_name": "演示客户 " + number, "note": note,
            }, admin)
            with store.tx() as db:
                db.execute("UPDATE orders SET number=? WHERE id=?", (number, result["id"]))
            if paid:
                store.pay_order(result["id"], {"reference": "DEMO-RECEIPT-" + number, "tax": "0"}, admin["id"])
            return result["id"]

        for i in range(1, 10):
            order(sales, f"DEMO-UP-{i:02}", "晋升前的历史成交：9 单合计 RM 62,820。")
        order(sales, "DEMO-UP-10", "先收款本单：累计达到 RM 69,800；本单直佣 20%，下一单开始 30%。", paid=False)
        order(sales, "DEMO-UP-11", "在 UP-10 收款后再收款本单，验证合伙人直佣 30%。", paid=False)
        for i in range(1, 11):
            order(refund, f"DEMO-REFUND-{i:02}", "任意一笔全额退款后，年度业绩从 RM 69,800 降至 RM 62,820，恢复业务员。")
        settled_order = order(payout, "DEMO-PAID-01", "此单 RM 796 佣金已审核并记录付款；退款会生成 -RM 796 待追回余额。", product="operator-1")
        for entry in store.dashboard(admin)["commissions"]:
            if entry["order_id"] == settled_order:
                store.approve(entry["id"], admin["id"])
        store.payout(payout["id"], {"reference": "DEMO-BANK-PAID-01", "amount": "796"}, admin["id"])
        order(payout, "DEMO-OFFSET-01", "退款 PAID-01 后，再收款并审核本单：RM 796 先抵扣追回，不可重复出款。", product="operator-1", paid=False)
        order(payout, "DEMO-OFFSET-02", "再收款及审核本单后，可结算净额变为 RM 796。", product="operator-1", paid=False)
        order(partner, "DEMO-PARTNER-01", "合伙人 RM 9,980 订单：直接佣金 RM 2,994（30%），交付 RM 998，Token 1,000。", product="operator-10")
        with store.tx() as db:
            db.execute("CREATE TABLE demo_metadata(version INTEGER PRIMARY KEY)")
            db.execute("INSERT INTO demo_metadata VALUES(1)")
            store.audit(db, admin["id"], "demo.seed", "demo-v1", {"agents": 4, "orders": 25, "synthetic": True})
        # Exclusive creation ensures --demo can never replace an existing real database.
        snapshot = Path(folder) / "complete.sqlite3"
        source, target = store.connect(), sqlite3.connect(snapshot)
        try:
            source.backup(target)
            assert target.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            target.execute("PRAGMA journal_mode=DELETE")
        finally:
            source.close()
            target.close()
        os.chmod(snapshot, 0o600)
        os.link(snapshot, destination)
    return True


def ensure_demo_portal(path):
    """Add the referral-workspace scenario once, preserving all existing demo activity."""
    with sqlite3.connect(path, factory=ClosingConnection) as db:
        marker = db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='demo_metadata'").fetchone()
        if not marker or not db.execute("SELECT 1 FROM demo_metadata WHERE version=1").fetchone():
            raise Problem("只能在已标记的演示库添加示例账号。")
    store = Store(path)
    with store.connect() as db:
        admin = db.execute("SELECT id FROM users WHERE username='demo.admin'").fetchone()
        existing = db.execute("SELECT a.id,a.code FROM agents a JOIN users u ON u.agent_id=a.id WHERE u.username='demo.subadmin'").fetchone()
    agent = dict(existing) if existing else store.create_agent({
        "name": "李欣 · 推广工作台", "username": "demo.subadmin", "password": DEMO_PASSWORD,
    }, admin["id"])
    def inquiry_once(values):
        with store.connect() as db:
            exists = db.execute("SELECT 1 FROM inquiries WHERE request_key=?", (values["request_key"],)).fetchone()
        if not exists:
            store.create_inquiry(values)

    inquiry_once({"code": agent["code"], "product_id": "operator-5", "customer_name": "示例客户 · 星禾团队",
                          "contact": "xinghe@demo.invalid", "participants": 5, "message": "想了解团队 AI 培训，请推荐适合的课程。",
                          "consent": True, "request_key": "DEMO-REFERRAL-TEAM"})
    inquiry_once({"code": agent["code"], "product_id": "architect-custom", "customer_name": "示例客户 · 远景企业",
                          "contact": "yuanjing@demo.invalid", "participants": 120, "message": "120 人，希望安排企业定制方案及报价。",
                          "consent": True, "request_key": "DEMO-REFERRAL-CUSTOM"})
    return agent
