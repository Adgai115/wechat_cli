"""media 命令组 — 图片/视频（V2 .dat）解密与导出。"""
from __future__ import annotations

import json
import os
import time

import click

from ..core.config import STATE_DIR
from ..media import dat as mdat
from ..media import pair as mpair
from ..media import timeline as mtimeline
from ..media.keyfind import find_image_key

MEDIA_KEYS_FILE = os.path.join(STATE_DIR, "media_keys.json")


def _load_media_keys():
    if os.path.exists(MEDIA_KEYS_FILE):
        try:
            return json.load(open(MEDIA_KEYS_FILE, encoding="utf-8"))
        except json.JSONDecodeError:
            return {}
    return {}


def _save_media_keys(data):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(MEDIA_KEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    return MEDIA_KEYS_FILE


@click.group("media")
def media():
    """图片/视频（V2 .dat）相关操作"""


@media.command("key")
@click.option("--watch", default=120, show_default=True, help="持续监听秒数（期间在微信里点开图片）")
@click.pass_context
def key_cmd(ctx, watch):
    """从微信内存抓取图片 AES key"""
    app = ctx.obj
    try:
        k = find_image_key(app.db_dir, watch=watch, log=click.echo)
    except RuntimeError as exc:
        click.echo(f"[!] {exc}", err=True)
        ctx.exit(1)
        return
    data = _load_media_keys()
    data["image_aes_key"] = k.decode("latin1")
    click.echo(f"[+] 已保存到 {_save_media_keys(data)}")


@media.command("decrypt")
@click.option("--out", default=None, help="输出目录（默认 <state>/images）")
@click.option("--limit", default=0, help="最多处理多少个文件（0=全部）")
@click.option("--key", default=None, help="AES key（默认读 media_keys.json）")
@click.option("--xor-key", default=None, type=int, help="XOR key（默认自动探测）")
def decrypt_cmd(out, limit, key, xor_key):
    """批量解密 V2 .dat 为可看图"""
    app = click.get_current_context().obj
    keys = _load_media_keys()
    aes = (key or keys.get("image_aes_key") or "").encode("latin1")[:16]
    if len(aes) != 16:
        click.echo("[!] 缺少图片 AES key，请先运行: wechat-cli media key", err=True)
        raise SystemExit(1)

    base = os.path.dirname(app.db_dir)
    files = mdat.find_dat_files(base)
    if not files:
        click.echo("[!] 没找到 .dat 文件", err=True)
        raise SystemExit(1)
    xk = xor_key if xor_key is not None else mdat.guess_xor_key(files)
    out = out or os.path.join(STATE_DIR, "images")
    os.makedirs(out, exist_ok=True)
    click.echo(f"[*] {len(files)} 个 .dat，xor=0x{xk:02x} -> {out}")

    index = []
    stat = {}
    todo = files[:limit] if limit else files
    for i, p in enumerate(todo, 1):
        try:
            body, ext = mdat.decrypt_file(p, aes, xk)
        except OSError:
            continue
        if not body or ext == ".bin":
            stat["skip"] = stat.get("skip", 0) + 1
            continue
        stem = os.path.splitext(os.path.basename(p))[0]
        dst = os.path.join(out, stem + ext)
        with open(dst, "wb") as f:
            f.write(body)
        stat[ext] = stat.get(ext, 0) + 1
        index.append({"src": p, "dst": dst, "ext": ext, "size": len(body),
                      "mtime": os.path.getmtime(p)})
        if i % 500 == 0:
            click.echo(f"   {i}/{len(todo)} {stat}")
    with open(os.path.join(out, "_media_index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, ensure_ascii=False)
    keys.update({"image_xor_key": xk})
    _save_media_keys(keys)
    click.echo(f"[=] 完成 {stat}，索引 {len(index)} 条")


@media.command("index")
@click.option("--images", default=None, help="解密输出目录")
@click.option("--out", default=None, help="CSV 输出路径")
@click.option("--tol", default=15, show_default=True, help="时间配对容差（秒）")
@click.pass_context
def index_cmd(ctx, images, out, tol):
    """把图片与聊天消息配对，输出 CSV"""
    app = ctx.obj
    images = images or os.path.join(STATE_DIR, "images")
    items = mpair.load_media_index(images)
    if not items:
        click.echo("[!] 没有媒体索引，请先运行 media decrypt", err=True)
        ctx.exit(1)
        return
    rows = mpair.pair(app.cache, app.msg_db_keys, items, tol=tol)
    from ..core.contacts import get_contact_names
    names = get_contact_names(app.cache, app.decrypted_dir)
    out = out or os.path.join(STATE_DIR, "媒体清单.csv")
    mpair.write_csv(rows, out, names)
    click.echo(f"[=] 配对 {len(rows)} 条 / 媒体 {len(items)} 个 -> {out}")


@media.command("html")
@click.option("--images", default=None, help="解密输出目录")
@click.option("--out", default=None, help="HTML 输出目录")
@click.option("--tol", default=15, show_default=True)
@click.option("--limit", default=0, help="最多生成多少个会话页面")
@click.pass_context
def html_cmd(ctx, images, out, tol, limit):
    """生成可浏览的聊天时间线 HTML"""
    app = ctx.obj
    images = images or os.path.join(STATE_DIR, "images")
    out = out or os.path.join(STATE_DIR, "timeline")
    items = mpair.load_media_index(images)
    rows = mpair.pair(app.cache, app.msg_db_keys, items, tol=tol) if items else []
    n, msgs, imgs = mtimeline.build(app, images, out, pairing=rows, limit=limit or None)
    click.echo(f"[=] {n} 个会话 / {msgs} 条消息 / {imgs} 张图片 -> {out}")
