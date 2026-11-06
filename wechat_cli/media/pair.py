"""媒体与消息配对。

关键事实：.dat 文件名与消息 XML 里的 md5 无关；但缓存目录
msg/attach/<32hex>/<yyyy-mm>/Img/ 的 <32hex> == md5(会话 username)。
因此用「同会话目录 + 时间就近」配对。
"""
from __future__ import annotations

import bisect
import csv
import json
import os
import re

from .scan import iter_image_messages

HASH_RE = re.compile(r"attach[\\/]([0-9a-f]{32})[\\/]")
CACHE_RE = re.compile(r"cache[\\/]\d{4}-\d{2}[\\/]Message[\\/]([0-9a-f]{32})[\\/]")


def load_media_index(images_dir):
    idx_path = os.path.join(images_dir, "_media_index.json")
    if not os.path.exists(idx_path):
        return []
    items = json.load(open(idx_path, encoding="utf-8"))
    for it in items:
        src = it.get("src", "")
        m = HASH_RE.search(src) or CACHE_RE.search(src)
        it["chat_hash"] = m.group(1) if m else None
    return [it for it in items if it.get("chat_hash")]


def pair(cache, msg_db_keys, media_items, tol=15):
    """返回 [{chat_hash, username, time, sender, type, file, delta}]"""
    buckets = {}
    for it in media_items:
        buckets.setdefault(it["chat_hash"], []).append(it)
    for v in buckets.values():
        v.sort(key=lambda x: x.get("mtime", 0))
        v.append({"mtime": float("inf"), "_sentinel": True})

    used = set()
    rows = []
    for h, user, ctime, sid, ltype in iter_image_messages(cache, msg_db_keys):
        bucket = buckets.get(h)
        if not bucket:
            continue
        times = [x["mtime"] for x in bucket]
        pos = bisect.bisect_left(times, ctime)
        best = None
        for cand in (pos - 1, pos, pos + 1):
            if 0 <= cand < len(bucket) - 1:
                m = bucket[cand]
                if id(m) in used:
                    continue
                d = abs(m["mtime"] - ctime)
                if d <= tol and (best is None or d < best[0]):
                    best = (d, m)
        if not best:
            continue
        d, m = best
        used.add(id(m))
        rows.append({"chat_hash": h, "username": user, "time": ctime,
                     "sender_id": sid, "type": ltype, "file": os.path.basename(m["dst"]),
                     "ext": m.get("ext", ""), "size": m.get("size", 0), "delta": int(d)})
    rows.sort(key=lambda r: r["time"])
    return rows


def write_csv(rows, path, names=None):
    names = names or {}
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["时间", "会话", "微信号", "发送者", "类型", "文件", "大小", "误差秒"])
        import time as _t
        for r in rows:
            ts = _t.strftime("%Y-%m-%d %H:%M:%S", _t.localtime(r["time"])) if r["time"] else ""
            w.writerow([ts, names.get(r["username"], r["username"]), r["username"],
                        names.get(r["sender_id"], r["sender_id"]),
                        "图片" if r["type"] == 3 else "视频", r["file"], r["size"], r["delta"]])
    return path
