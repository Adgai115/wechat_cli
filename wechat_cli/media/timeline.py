"""生成可浏览的聊天时间线 HTML（图片内联预览）。"""
from __future__ import annotations

import html
import os
import re
import time

from ..core.contacts import get_contact_names
from .scan import iter_messages

CSS = """
:root{color-scheme:light dark}
body{font:14px/1.6 -apple-system,"Segoe UI","Microsoft YaHei",sans-serif;margin:0;background:#f5f6f8;color:#222}
header{position:sticky;top:0;background:#fff;border-bottom:1px solid #e3e5e8;padding:12px 20px;z-index:9}
h1{font-size:16px;margin:0}.meta{color:#888;font-size:12px;margin-top:2px}
main{padding:16px 20px 60px;max-width:900px;margin:0 auto}
.msg{margin:6px 0;padding:6px 10px;background:#fff;border-radius:8px;border:1px solid #eceef1}
.t{color:#98a2b3;font-size:12px;margin-right:8px}
.b{white-space:pre-wrap;word-break:break-word}
img{max-width:260px;max-height:260px;border-radius:6px;border:1px solid #e3e5e8;display:block;margin-top:6px}
.day{margin:18px 0 6px;color:#667085;font-size:12px;font-weight:600}
a{color:#2f6feb;text-decoration:none}
"""


def _safe(name):
    return re.sub(r'[\\/:*?"<>|]', "_", name)[:80] or "chat"


def build(ctx, images_dir, outdir, pairing=None, limit=None):
    os.makedirs(outdir, exist_ok=True)
    names = get_contact_names(ctx.cache, ctx.decrypted_dir)
    pair_map = {}
    for r in (pairing or []):
        pair_map[(r["chat_hash"], r["time"])] = r["file"]

    index_rows = []
    total_msgs = 0
    total_imgs = 0
    for rel in ctx.msg_db_keys:
        parts = rel.replace("\\", "/").split("/")
        if len(parts) < 2 or not parts[-1].startswith("message_"):
            continue
        path = ctx.cache.get(rel)
        if not path:
            continue
        import sqlite3
        from contextlib import closing
        with closing(sqlite3.connect(path)) as conn:
            try:
                users = [u for (u,) in conn.execute("SELECT user_name FROM Name2Id")]
            except sqlite3.Error:
                continue
        import hashlib
        for user in users:
            h = hashlib.md5(user.encode()).hexdigest()
            msgs = iter_messages(ctx.cache, rel, h)
            if not msgs:
                continue
            disp = names.get(user, user)
            body, last_day, imgs = [], None, 0
            for ctime, sender, ltype, txt in msgs:
                day = time.strftime("%Y-%m-%d", time.localtime(ctime))
                tm = time.strftime("%H:%M:%S", time.localtime(ctime))
                if day != last_day:
                    body.append(f'<div class="day">{day}</div>')
                    last_day = day
                fname = pair_map.get((h, ctime))
                if ltype in (3, 43) and fname and os.path.exists(os.path.join(images_dir, fname)):
                    relsrc = os.path.relpath(os.path.join(images_dir, fname), outdir).replace("\\", "/")
                    body.append(f'<div class="msg"><span class="t">{tm}</span>'
                                f'<span class="b">{html.escape(names.get(sender, sender))}</span>'
                                f'<a href="{html.escape(relsrc)}" target="_blank">'
                                f'<img loading="lazy" src="{html.escape(relsrc)}" alt=""></a></div>')
                    imgs += 1
                elif ltype in (3, 43):
                    body.append(f'<div class="msg"><span class="t">{tm}</span>'
                                f'<span class="b">{html.escape(names.get(sender, sender))}：【图片】</span></div>')
                else:
                    if not txt:
                        continue
                    body.append(f'<div class="msg"><span class="t">{tm}</span>'
                                f'<span class="b">{html.escape(names.get(sender, sender))}：{html.escape(txt)}</span></div>')
            out_name = _safe(disp) + ".html"
            doc = (f'<!doctype html><meta charset="utf-8"><title>{html.escape(disp)}</title>'
                   f"<style>{CSS}</style>"
                   f'<header><h1>{html.escape(disp)}</h1>'
                   f'<div class="meta">{len(msgs)} 条消息 · {imgs} 张图片</div></header>'
                   f'<main>{"".join(body)}</main>')
            with open(os.path.join(outdir, out_name), "w", encoding="utf-8") as f:
                f.write(doc)
            index_rows.append((disp, len(msgs), imgs, out_name))
            total_msgs += len(msgs)
            total_imgs += imgs
        if limit and len(index_rows) >= limit:
            break

    index_rows.sort(key=lambda r: -r[1])
    rows = "".join(f'<tr><td><a href="{html.escape(fn)}">{html.escape(t)}</a></td>'
                   f"<td>{c}</td><td>{i}</td></tr>" for t, c, i, fn in index_rows)
    idx = (f'<!doctype html><meta charset="utf-8"><title>微信聊天记录</title>'
           f'<style>{CSS}table{{width:100%;border-collapse:collapse}}'
           f'td,th{{padding:6px 8px;border-bottom:1px solid #eceef1;text-align:left}}'
           f'th{{color:#667085;font-size:12px}}</style>'
           f'<header><h1>微信聊天记录</h1>'
           f'<div class="meta">{len(index_rows)} 个会话 · {total_msgs} 条消息 · {total_imgs} 张图片</div></header>'
           f'<main><table><thead><tr><th>会话</th><th>消息</th><th>图片</th></tr></thead>'
           f'<tbody>{rows}</tbody></table></main>')
    with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as f:
        f.write(idx)
    return len(index_rows), total_msgs, total_imgs
