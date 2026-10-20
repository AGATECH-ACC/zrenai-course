import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from demo import seed_demo, DEMO_PASSWORD
from store import Store, Problem, password_ok
from server import AppServer


class DemoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "demo.sqlite3"

    def tearDown(self):
        self.temp.cleanup()

    def test_seed_idempotence_and_interactive_scenarios(self):
        self.assertTrue(seed_demo(self.path))
        store = Store(self.path)
        with store.connect() as db:
            admin = dict(db.execute("SELECT * FROM users WHERE username='demo.admin'").fetchone())
            self.assertTrue(password_ok(DEMO_PASSWORD, admin["password_hash"]))
            agents = {r["username"]: dict(r) for r in db.execute("SELECT a.*,u.username FROM agents a JOIN users u ON u.agent_id=a.id")}
            orders = {r["number"]: dict(r) for r in db.execute("SELECT * FROM orders")}
            self.assertEqual(len(agents), 4)
            self.assertEqual(len(orders), 25)
            self.assertEqual(agents["demo.sales"]["personal_sales"], 6282000)
            self.assertEqual(agents["demo.refund"]["personal_sales"], 6980000)
            self.assertEqual(agents["demo.refund"]["role"], "partner")
            self.assertEqual(db.execute("PRAGMA integrity_check").fetchone()[0], "ok")
            self.assertFalse(db.execute("PRAGMA foreign_key_check").fetchall())
        self.assertFalse(seed_demo(self.path))
        self.assertEqual(len(store.dashboard(admin)["orders"]), 25)
        first = store.pay_order(orders["DEMO-UP-10"]["id"], {"reference": "TEST-10"}, admin["id"])
        self.assertTrue(first["promoted"])
        self.assertEqual(first["commission"], 174500)  # 20% direct + 5% demo-only upline.
        second = store.pay_order(orders["DEMO-UP-11"]["id"], {"reference": "TEST-11"}, admin["id"])
        self.assertEqual(second["commission"], 209400)
        store.refund_order(orders["DEMO-REFUND-10"]["id"], {"reference": "TEST-REFUND"}, admin["id"])
        store.refund_order(orders["DEMO-PAID-01"]["id"], {"reference": "TEST-CLAWBACK"}, admin["id"])
        with store.connect() as db:
            row = db.execute("SELECT * FROM agents WHERE id=?", (agents["demo.refund"]["id"],)).fetchone()
            self.assertEqual(row["role"], "sales")
            self.assertEqual(row["personal_sales"], 6282000)
            clawback = db.execute("SELECT * FROM commissions WHERE agent_id=? AND kind='clawback'", (agents["demo.payout"]["id"],)).fetchone()
            self.assertEqual(clawback["amount"], -79600)
        for number in ("DEMO-OFFSET-01", "DEMO-OFFSET-02"):
            store.pay_order(orders[number]["id"], {"reference": "TEST-" + number}, admin["id"])
            for entry in store.dashboard(admin)["commissions"]:
                if entry["order_id"] == orders[number]["id"]:
                    store.approve(entry["id"], admin["id"])
        settled = store.payout(agents["demo.payout"]["id"], {"reference": "TEST-NET-SETTLE", "amount": "796"}, admin["id"])
        self.assertEqual(settled["amount"], 79600)

    def test_refuses_real_database_and_separates_cookies(self):
        real = Store(self.path)
        with self.assertRaises(Problem):
            seed_demo(self.path)
        with real.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)
        live_server = AppServer(("127.0.0.1", 0), real)
        demo_server = AppServer(("127.0.0.1", 0), real, demo=True)
        try:
            self.assertNotEqual(live_server.cookie_name, demo_server.cookie_name)
        finally:
            live_server.server_close()
            demo_server.server_close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
