"""One-time import into an empty course schema. Never imports sessions or demo data."""
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'agent-system'))
from postgres_store import PostgresStore
from psycopg import sql

TABLES = ['users', 'agents', 'products', 'policies', 'customers', 'orders', 'payouts',
          'commissions', 'token_ledger', 'audit', 'inquiries', 'supabase_links']


def main():
    source = Path(sys.argv[1]).resolve()
    db = sqlite3.connect(source.as_uri() + '?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    try:
        if db.execute("SELECT 1 FROM sqlite_master WHERE name='demo_metadata'").fetchone():
            raise RuntimeError('Refusing to import demo data.')
        counts = {}
        target = PostgresStore(os.environ['DATABASE_URL'])
        with target.tx() as conn:
            for table in TABLES:
                if conn.db.execute(sql.SQL('SELECT 1 FROM {} LIMIT 1').format(sql.Identifier(table))).fetchone():
                    raise RuntimeError('Target must be completely empty: ' + table)
            for table in TABLES:
                if not db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (table,)).fetchone():
                    continue
                rows = db.execute('SELECT * FROM ' + table + ' ORDER BY rowid').fetchall()
                counts[table] = len(rows)
                for row in rows:
                    columns = list(row.keys())
                    query = sql.SQL('INSERT INTO {} ({}) VALUES ({})').format(
                        sql.Identifier(table), sql.SQL(',').join(map(sql.Identifier, columns)),
                        sql.SQL(',').join(sql.Placeholder() for _ in columns))
                    conn.db.execute(query, tuple(row))
        print(json.dumps(counts))
    finally:
        db.close()


if __name__ == '__main__':
    main()
