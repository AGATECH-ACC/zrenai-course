"""Create a consistent SQLite backup, including committed WAL data."""
import argparse
import os
import sqlite3
from pathlib import Path


def backup(source, destination):
    source, destination = Path(source).resolve(), Path(destination).resolve()
    if not source.is_file():
        raise ValueError("源数据库不存在。")
    if destination.exists():
        raise ValueError("目标已存在，请选择新文件名，避免覆盖备份。")
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    src = sqlite3.connect(source.as_uri() + "?mode=ro", uri=True)
    dst = sqlite3.connect(destination)
    try:
        src.backup(dst)
        if dst.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise ValueError("备份完整性检查未通过。")
    finally:
        src.close()
        dst.close()
    return destination


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("destination", help="新备份文件的路径")
    parser.add_argument("--source", default=str(Path(__file__).parent / "data" / "zhongren.sqlite3"))
    args = parser.parse_args()
    print("备份完成：", backup(args.source, args.destination))
