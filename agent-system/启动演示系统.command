#!/bin/zsh
set -e
cd "$(dirname "$0")"
echo '演示环境：http://127.0.0.1:8789'
echo '账号 demo.admin / 密码 ZhongrenDemo2026!（仅演示库）'
exec python3 server.py --demo
