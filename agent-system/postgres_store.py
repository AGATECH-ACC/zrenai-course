"""Postgres persistence for cloud deployment; SQLite remains the local/demo store."""
import hashlib
import re
import sqlite3
from contextlib import contextmanager
from decimal import Decimal
from pathlib import Path

import psycopg
from psycopg.rows import dict_row

from store import Store, Problem


class Row(dict):
    def __init__(self, values):
        # Postgres SUM(bigint) returns Decimal; amounts remain integer cents.
        super().__init__((k, int(v) if isinstance(v, Decimal) and v == v.to_integral_value() else v)
                         for k, v in values.items())

    def __getitem__(self, key):
        return list(self.values())[key] if isinstance(key, int) else super().__getitem__(key)


class Cursor:
    def __init__(self, cursor, lastrowid=None):
        self.cursor = cursor
        self.lastrowid = lastrowid

    def fetchone(self):
        row = self.cursor.fetchone()
        return Row(row) if row is not None else None

    def fetchall(self):
        return [Row(row) for row in self.cursor.fetchall()]

    def __iter__(self):
        return (Row(row) for row in self.cursor)

    @property
    def rowcount(self):
        return self.cursor.rowcount


class Connection:
    def __init__(self, dsn, schema):
        self.db = psycopg.connect(dsn, row_factory=dict_row, prepare_threshold=None,
                                  connect_timeout=10, sslmode='verify-full',
                                  sslrootcert=str(Path(__file__).parent / 'supabase-ca.crt'))
        # Transaction-local settings work with Supabase's transaction pooler.
        self.db.execute("SELECT set_config('search_path', %s, true)", (schema + ',pg_catalog',))
        self.db.execute("SET LOCAL statement_timeout = '15s'")
        self.db.execute("SET LOCAL lock_timeout = '10s'")

    def execute(self, query, params=()):
        if 'sqlite_master' in query:
            query = "SELECT 1 FROM information_schema.tables WHERE table_schema=current_schema() AND table_name='demo_metadata'"
        ignored = 'INSERT OR IGNORE' in query.upper()
        query = query.replace('INSERT OR IGNORE', 'INSERT')
        query = query.replace('ORDER BY rowid', "ORDER BY CASE family WHEN 'operator' THEN 0 ELSE 1 END, price NULLS LAST")
        query = re.sub(r'\b([a-z])\.rowid\b', r'\1.id', query)
        # All shared queries use bound values; no customer text is interpolated.
        query = query.replace('%', '%%').replace('?', '%s')
        if ignored:
            query += ' ON CONFLICT DO NOTHING'
        policy_insert = bool(re.match(r'\s*INSERT INTO policies\(', query, re.I))
        if policy_insert:
            query += ' RETURNING id'
        try:
            cursor = self.db.execute(query, params)
            lastrowid = cursor.fetchone()['id'] if policy_insert else None
            return Cursor(cursor, lastrowid)
        except psycopg.IntegrityError:
            # Shared handlers retain the same conflict response without exposing SQL.
            raise sqlite3.IntegrityError('Database constraint violation') from None

    def commit(self):
        self.db.commit()

    def executemany(self, query, rows):
        for values in rows:
            self.execute(query, values)

    def rollback(self):
        self.db.rollback()

    def close(self):
        self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self.rollback() if exc_type else self.commit()
        finally:
            self.close()


class PostgresStore(Store):
    def __init__(self, dsn, schema='zrenai_course'):
        if not dsn or not re.fullmatch(r'zrenai_course(?:_test_[a-z0-9]+)?', schema):
            raise ValueError('A database URL and an approved private schema are required.')
        self.dsn = dsn
        self.schema = schema

    def connect(self):
        return Connection(self.dsn, self.schema)

    def auth_schema_ready(self):
        with self.connect() as db:
            db.execute('SELECT user_id,auth_id FROM supabase_links LIMIT 0')
            db.execute('SELECT token_hash FROM supabase_sessions LIMIT 0')

    @contextmanager
    def tx(self):
        with self.connect() as db:
            # Preserve SQLite BEGIN IMMEDIATE semantics across serverless instances:
            # qualification, payment, refund and payout changes serialize atomically.
            db.execute('SELECT pg_advisory_xact_lock(hashtext(?))', (self.schema + ':business',))
            yield db

    def rate_limit(self, category, identifier, limit, seconds):
        bucket = hashlib.sha256((category + ':' + identifier).encode()).hexdigest()
        with self.connect() as db:
            row = db.execute('''INSERT INTO request_limits(bucket,hits,started_at)
                VALUES(?,1,EXTRACT(EPOCH FROM clock_timestamp())::bigint)
                ON CONFLICT(bucket) DO UPDATE SET
                hits=CASE WHEN request_limits.started_at<=EXTRACT(EPOCH FROM clock_timestamp())::bigint-?
                     THEN 1 ELSE request_limits.hits+1 END,
                started_at=CASE WHEN request_limits.started_at<=EXTRACT(EPOCH FROM clock_timestamp())::bigint-?
                     THEN EXTRACT(EPOCH FROM clock_timestamp())::bigint ELSE request_limits.started_at END
                RETURNING hits''', (bucket, seconds, seconds)).fetchone()
            db.execute('DELETE FROM request_limits WHERE started_at<EXTRACT(EPOCH FROM clock_timestamp())::bigint-86400')
        if row['hits'] > limit:
            raise Problem('请求过于频繁，请稍后重试。', 429)
