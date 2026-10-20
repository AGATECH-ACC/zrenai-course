import concurrent.futures
import hashlib
import http.client
import json
import sqlite3
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from store import Store, Problem, THRESHOLD, business_year
from server import AppServer


class BusinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "test.sqlite3")
        self.store.setup({"username": "admin", "password": "Test-only-password-42"})
        with self.store.connect() as db:
            self.admin = dict(db.execute("SELECT * FROM users WHERE kind='admin'").fetchone())
        self.enable()
        self.agent = self.store.create_agent({"name": "Test Agent", "username": "agent", "password": "Agent-only-password-42"}, self.admin["id"])
        self.count = 0

    def tearDown(self):
        self.temp.cleanup()

    def enable(self, **overrides):
        with self.store.connect() as db:
            p = self.store.policy(db)
        values = {"version": p["id"], "period": "annual", "year_role": "recompute", "refund_role": "recompute", "sales_uplines": [], "partner_uplines": [], "operations_confirmed": True, "delivery_scope": "all", "token_trigger": "paid", "note": "Test fixture only, not a business approval."}
        values.update(overrides)
        return self.store.save_policy(values, self.admin["id"])

    def order(self, agent=None, product="operator-5", **extra):
        self.count += 1
        values = {"agent_id": (agent or self.agent)["id"], "product_id": product, "participants": 1,
                  "customer_account": "customer-" + str(self.count), "customer_name": "Customer " + str(self.count), "request_key": "request-" + str(self.count)}
        values.update(extra)
        return self.store.create_order(values, self.admin)["id"]

    def pay(self, order):
        return self.store.pay_order(order, {"reference": "PAY-" + order, "tax": "0"}, self.admin["id"])

    def row(self, table, identifier):
        with self.store.connect() as db:
            return dict(db.execute("SELECT * FROM " + table + " WHERE id=?", (identifier,)).fetchone())

    def test_threshold_crossing_and_next_order(self):
        orders = []
        for i in range(10):
            order = self.order()
            result = self.pay(order)
            self.assertEqual(result["promoted"], i == 9)
            self.assertEqual(result["commission"], 139600)
            orders.append(order)
        agent = self.row("agents", self.agent["id"])
        self.assertEqual(agent["personal_sales"], THRESHOLD)
        self.assertEqual(agent["role"], "partner")
        self.assertEqual(self.row("orders", orders[-1])["role_at_sale"], "sales")
        self.assertEqual(self.pay(self.order())["commission"], 209400)
        self.assertEqual(sum(t["balance"] for t in self.store.dashboard(self.admin)["tokens"]), 11 * 680)

    def test_refund_demotes_and_reverses_tokens(self):
        ids = [self.order() for _ in range(10)]
        for identifier in ids:
            self.pay(identifier)
        self.store.refund_order(ids[-1], {"reference": "REFUND-1"}, self.admin["id"])
        agent = self.row("agents", self.agent["id"])
        self.assertEqual(agent["role"], "sales")
        self.assertEqual(agent["personal_sales"], 6282000)
        data = self.store.dashboard(self.admin)
        self.assertEqual(sum(t["balance"] for t in data["tokens"]), 9 * 680)
        self.assertTrue(all(c["status"] == "reversed" for c in data["commissions"] if c["order_id"] == ids[-1]))
        self.assertTrue(self.store.refund_order(ids[-1], {"reference": "REFUND-1"}, self.admin["id"])["duplicate"])

    def test_paid_refund_creates_clawback_and_offsets(self):
        first = self.order()
        self.pay(first)
        commission = self.store.dashboard(self.admin)["commissions"][0]
        self.store.approve(commission["id"], self.admin["id"])
        payout = self.store.payout(self.agent["id"], {"reference": "BANK-1", "amount": "1396"}, self.admin["id"])
        self.assertEqual(payout["amount"], 139600)
        self.store.refund_order(first, {"reference": "REFUND-PAID"}, self.admin["id"])
        with self.assertRaises(Problem):
            self.store.payout(self.agent["id"], {"reference": "BANK-2", "amount": "0"}, self.admin["id"])
        for _ in range(2):
            order = self.order()
            self.pay(order)
            for c in self.store.dashboard(self.admin)["commissions"]:
                if c["status"] == "pending":
                    self.store.approve(c["id"], self.admin["id"])
        self.assertEqual(self.store.payout(self.agent["id"], {"reference": "BANK-2", "amount": "1396"}, self.admin["id"])["amount"], 139600)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT SUM(amount) FROM commissions WHERE status='paid'").fetchone()[0], 279200)

    def test_concurrent_payment_exactly_once(self):
        order = self.order()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: self.pay(order), range(4)))
        self.assertEqual(sum(bool(x.get("duplicate")) for x in results), 3)
        self.assertEqual(self.row("agents", self.agent["id"])["personal_sales"], 698000)
        self.assertEqual(len(self.store.dashboard(self.admin)["commissions"]), 1)

    def test_annual_rollover_and_previous_year_refund(self):
        year = business_year()
        with patch("store.business_year", return_value=year - 1):
            old_agent = self.store.create_agent({"name": "Previous Year", "username": "old"}, self.admin["id"])
            ids = [self.order(agent=old_agent) for _ in range(10)]
            for identifier in ids:
                self.pay(identifier)
        self.store.dashboard(self.admin)
        current = self.row("agents", old_agent["id"])
        self.assertEqual(current["personal_sales"], 0)
        self.assertEqual(current["role"], "sales")
        fresh = self.order(agent=old_agent)
        self.pay(fresh)
        self.store.refund_order(ids[0], {"reference": "REFUND-OLD"}, self.admin["id"])
        self.assertEqual(self.row("agents", old_agent["id"])["personal_sales"], 698000)

    def test_upline_pool_and_cap(self):
        self.enable(sales_uplines=[500, 200])
        child = self.store.create_agent({"name": "Child", "username": "child", "parent_id": self.agent["id"]}, self.admin["id"])
        self.assertEqual(self.pay(self.order(agent=child))["commission"], 174500)
        commissions = self.store.dashboard(self.admin)["commissions"]
        self.assertEqual(sorted(c["amount"] for c in commissions), [34900, 139600])
        self.assertEqual(self.row("agents", self.agent["id"])["personal_sales"], 0)
        with self.assertRaises(Problem):
            self.enable(sales_uplines=[1100])
        with self.assertRaises(Problem):
            self.enable(partner_uplines=[100])

    def test_policy_snapshot_survives_edit(self):
        order = self.order()
        self.pay(order)
        original = self.row("orders", order)
        self.enable(sales_uplines=[500])
        self.assertEqual(self.row("orders", order)["snapshot"], original["snapshot"])
        self.store.refund_order(order, {"reference": "REVERSE"}, self.admin["id"])
        self.assertEqual(self.row("orders", order)["policy_id"], original["policy_id"])

    def test_draft_gate_and_rollback(self):
        self.enable(operations_confirmed=False)
        order = self.order()
        with self.assertRaises(Problem):
            self.pay(order)
        self.assertEqual(self.row("orders", order)["status"], "draft")
        self.assertEqual(self.row("agents", self.agent["id"])["personal_sales"], 0)
        self.assertEqual(len(self.store.dashboard(self.admin)["commissions"]), 0)

    def test_agent_scope_and_order_assignment(self):
        self.pay(self.order())
        other = self.store.create_agent({"name": "Other", "username": "other"}, self.admin["id"])
        with self.store.connect() as db:
            other_user = dict(db.execute("SELECT * FROM users WHERE agent_id=?", (other["id"],)).fetchone())
        own = self.store.create_order({"agent_id": self.agent["id"], "product_id": "operator-1", "participants": 1, "customer_account": "own", "customer_name": "Own", "request_key": "agent-request"}, other_user)
        self.assertEqual(self.row("orders", own["id"])["agent_id"], other["id"])
        dashboard = self.store.dashboard(other_user)
        self.assertEqual(len(dashboard["agents"]), 1)
        self.assertEqual(len(dashboard["orders"]), 1)
        self.assertEqual(dashboard["commissions"], [])
        self.assertEqual(dashboard["tokens"], [])
        self.assertEqual(dashboard["audit"], [])

    def test_custom_quote_and_fixed_prices(self):
        order = self.order(product="operator-1", amount="1")
        self.assertEqual(self.row("orders", order)["amount"], 398000)
        with self.assertRaises(Problem):
            self.order(product="architect-custom", participants=100, amount="200000")
        custom = self.order(product="architect-custom", participants=101, amount="200000")
        self.assertEqual(self.row("orders", custom)["amount"], 20000000)
        with self.assertRaises(Problem):
            self.order(product="architect-custom", participants=101, amount="0")

    def test_retained_partner_qualification_across_years(self):
        self.enable(year_role="retain")
        year = business_year()
        with patch("store.business_year", return_value=year - 1):
            previous = self.store.create_agent({"name": "Retained", "username": "retained"}, self.admin["id"])
            ids = [self.order(agent=previous) for _ in range(10)]
            for identifier in ids:
                self.pay(identifier)
        self.store.dashboard(self.admin)
        self.assertEqual(self.row("agents", previous["id"])["role"], "partner")
        self.assertEqual(self.row("agents", previous["id"])["personal_sales"], 0)
        current = self.order(agent=previous)
        self.assertEqual(self.pay(current)["commission"], 209400)
        self.store.refund_order(current, {"reference": "NEW-YEAR-REFUND"}, self.admin["id"])
        self.assertEqual(self.row("agents", previous["id"])["role"], "partner")
        self.store.refund_order(ids[0], {"reference": "QUALIFYING-YEAR-REFUND"}, self.admin["id"])
        self.assertEqual(self.row("agents", previous["id"])["role"], "sales")
        self.assertEqual(self.row("agents", previous["id"])["personal_sales"], 0)

    def test_manual_tokens_and_architect_only_delivery(self):
        self.enable(delivery_scope="architect", token_trigger="manual")
        order = self.order()
        self.pay(order)
        self.assertEqual(self.row("orders", order)["delivery_amount"], 0)
        self.assertEqual(self.row("orders", order)["gift_amount"], 0)
        self.assertEqual(self.store.release_tokens(order, self.admin["id"])["amount"], 680)
        self.assertTrue(self.store.release_tokens(order, self.admin["id"])["duplicate"])
        self.store.refund_order(order, {"reference": "MANUAL-REFUND"}, self.admin["id"])
        with self.assertRaises(Problem):
            self.store.release_tokens(order, self.admin["id"])
        self.assertEqual(sum(t["balance"] for t in self.store.dashboard(self.admin)["tokens"]), 0)
        enterprise = self.order(product="architect-50", participants=20)
        self.pay(enterprise)
        self.assertEqual(self.row("orders", enterprise)["delivery_amount"], 998000)

    def test_reopen_is_durable(self):
        order = self.order()
        self.pay(order)
        reopened = Store(self.store.path)
        self.assertEqual(reopened.dashboard(self.admin)["orders"][0]["status"], "paid")


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.temp.name) / "http.sqlite3")
        self.server = AppServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = None
        self.csrf = None

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, path, data=None, **overrides):
        client = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        headers = {"Content-Type": "application/json"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        if self.csrf:
            headers["X-CSRF-Token"] = self.csrf
        headers.update(overrides)
        client.request("GET" if data is None else "POST", path, None if data is None else json.dumps(data), headers)
        response = client.getresponse()
        blob = response.read()
        cookie = response.getheader("Set-Cookie")
        if cookie:
            self.cookie = cookie.split(";", 1)[0]
        client.close()
        return response.status, json.loads(blob) if response.getheader("Content-Type", "").startswith("application/json") else blob

    def setup_login(self):
        values = {"username": "admin", "password": "HTTP-test-password-42"}
        self.assertEqual(self.request("/api/setup", values)[0], 201)
        self.assertEqual(self.request("/api/login", values)[0], 200)
        status, session = self.request("/api/session")
        self.csrf = session["user"]["csrf"]
        self.assertNotIn("password_hash", session["user"])
        self.assertNotIn("token_hash", session["user"])

    def test_auth_csrf_origin_and_isolation(self):
        self.assertEqual(self.request("/api/dashboard")[0], 401)
        self.assertEqual(self.request("/api/setup", {"username": "x", "password": "x" * 12}, Origin="https://evil.example")[0], 403)
        self.setup_login()
        self.assertEqual(self.request("/api/agents", {"name": "Test", "username": "agent"}, **{"X-CSRF-Token": "bad"})[0], 403)
        status, created = self.request("/api/agents", {"name": "Test", "username": "agent"})
        self.assertEqual(status, 200)
        self.request("/api/logout", {})
        self.cookie = self.csrf = None
        self.assertEqual(self.request("/api/login", {"username": "agent", "password": created["temporary_password"]})[0], 200)
        self.csrf = self.request("/api/session")[1]["user"]["csrf"]
        self.assertEqual(self.request("/api/policy", {})[0], 403)
        self.assertEqual(self.request("/api/agents", {})[0], 403)
        self.assertEqual(self.request("/api/dashboard")[1]["audit"], [])
        self.assertEqual(self.request("/api/setup", {"username": "admin2", "password": "other-test-pass"})[0], 409)

    def test_csv_formula_injection_and_export_auth(self):
        self.assertEqual(self.request("/api/export/orders")[0], 401)
        self.setup_login()
        status, created = self.request("/api/agents", {"name": "=1+1", "username": "agent"})
        self.assertEqual(status, 200)
        self.request("/api/orders", {"agent_id": created["id"], "product_id": "operator-1", "participants": 1, "customer_name": "@formula", "customer_account": "+formula", "request_key": "csv-test"})
        status, blob = self.request("/api/export/orders")
        self.assertEqual(status, 200)
        self.assertIn("'=1+1", blob.decode())
        self.assertIn("'@formula", blob.decode())
        self.assertIn("'+formula", blob.decode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
