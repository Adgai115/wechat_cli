"""遍历已解密数据库里的消息（供 index / timeline 复用）。"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
from contextlib import closing

import zstandard as zstd

from ..core.messages import decompress_content

MD5_RE = re.compile(r'md5="([0-9a-f]{32})"')
IMG_MSG_TYPES = (3, 43)


def md5(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()


def iter_image_messages(cache, msg_db_keys):
    """yield (chat_hash, username, create_time, sender_id, local_type)"""
    for rel in msg_db_keys:
        path = cache.get(rel)
        if not path:
            continue
        with closing(sqlite3.connect(path)) as conn:
            try:
                id2user = {rid: un for rid, un in conn.execute("SELECT rowid, user_name FROM Name2Id")}
            except sqlite3.Error:
                continue
            user_of = {md5(u): u for u in id2user.values()}
            tables = [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'")]
            for table in tables:
                h = table[4:]
                user = user_of.get(h)
                if not user:
                    continue
                cols = [r[1] for r in conn.execute(f"PRAGMA table_info([{table}])")]
                if "message_content" not in cols:
                    continue
                try:
                    rows = conn.execute(
                        f"SELECT create_time, real_sender_id, local_type FROM [{table}] "
                        f"WHERE local_type IN (3, 43)").fetchall()
                except sqlite3.Error:
                    continue
                for ctime, sid, ltype in rows:
                    yield h, user, int(ctime or 0), sid, int(ltype if str(ltype).isdigit() else 0)


def iter_messages(cache, rel, user_hash):
    """返回某个会话的全部消息 [(create_time, sender_id, local_type, text)]"""
    path = cache.get(rel)
    if not path:
        return []
    out = []
    with closing(sqlite3.connect(path)) as conn:
        try:
            id2user = {rid: un for rid, un in conn.execute("SELECT rowid, user_name FROM Name2Id")}
        except sqlite3.Error:
            return []
        table = f"Msg_{user_hash}"
        try:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info([{table}])")]
        except sqlite3.Error:
            return []
        if not cols:
            return []
        ct = "WCDB_CT_message_content" if "WCDB_CT_message_content" in cols else "0"
        try:
            rows = conn.execute(
                f"SELECT create_time, real_sender_id, local_type, message_content, {ct} "
                f"FROM [{table}] ORDER BY create_time").fetchall()
        except sqlite3.Error:
            return []
        for ctime, sid, ltype, content, ctype in rows:
            txt = decompress_content(content, ctype) or ""
            out.append((int(ctime or 0), id2user.get(sid, str(sid)),
                        int(ltype) if str(ltype).isdigit() else 0, txt))
    return out
