#!/bin/zsh
set -e
cd "$(dirname "$0")"
if [[ ! -f .env.supabase ]]; then
  echo '请复制 .env.example 为 .env.supabase，并配置管理员邮箱。'
  exit 1
fi
set -a
source ./.env.supabase
set +a
exec python3 server.py --supabase --port 8790 --db data/supabase.sqlite3
