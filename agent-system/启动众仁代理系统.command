#!/bin/zsh
set -e
cd "$(dirname "$0")"
echo '打开 http://127.0.0.1:8787 使用众仁代理与佣金系统。'
echo '关闭此终端将停止服务，账务数据会保留。'
exec python3 server.py
