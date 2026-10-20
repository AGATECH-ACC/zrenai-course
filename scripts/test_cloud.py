"""Run existing business/HTTP regressions in a pre-provisioned disposable schema.

DATABASE_URL must use the restricted application role. Never uses production tables.
Provision zrenai_course_test_deploy with the same DDL before invoking this script.
"""
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'agent-system'), str(ROOT / 'agent-system/tests')]
import test_system
import test_referrals
import test_supabase_auth
from postgres_store import PostgresStore
from store import Store as SQLiteStore

SCHEMA = 'zrenai_course_test_deploy'
TABLES = ['supabase_sessions','sessions','supabase_links','inquiries','token_ledger',
          'commissions','payouts','orders','customers','agents','users','audit','policies','products','request_limits']
seen = set()


def factory(path):
    store = PostgresStore(os.environ['DATABASE_URL'], SCHEMA)
    store.path = path
    if str(path) not in seen:
        seen.add(str(path))
        with store.tx() as db:
            for table in TABLES:
                db.execute('DELETE FROM ' + table)
        with tempfile.TemporaryDirectory() as folder:
            fresh = SQLiteStore(Path(folder) / 'seed.sqlite3')
            with fresh.connect() as source, store.tx() as target:
                for row in source.execute('SELECT * FROM products'):
                    target.execute('INSERT INTO products VALUES(?,?,?,?,?,?,?)', tuple(row))
                row = source.execute('SELECT config,created_at,actor FROM policies').fetchone()
                target.execute('INSERT INTO policies(config,created_at,actor) VALUES(?,?,?)', tuple(row))
    return store


def main():
    test_system.Store = factory
    loader = unittest.TestLoader()
    suite = unittest.TestSuite([
        unittest.TestSuite(test_system.BusinessTests(name) for name in [
            'test_concurrent_payment_exactly_once',
            'test_threshold_crossing_and_next_order',
            'test_refund_demotes_and_reverses_tokens',
            'test_paid_refund_creates_clawback_and_offsets',
        ]),
        loader.loadTestsFromTestCase(test_system.HttpTests),
        test_referrals.ReferralTests('test_referral_ownership_conversion_and_admin_only_accounting'),
    ])
    for name in loader.getTestCaseNames(test_supabase_auth.SupabaseHttpTests):
        # Connection-close exception types are specifically a SQLite test.
        if 'connection' not in name:
            suite.addTest(test_supabase_auth.SupabaseHttpTests(name))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())


if __name__ == '__main__':
    main()
