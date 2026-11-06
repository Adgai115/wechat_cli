"""WeChat 4.x (>4.0.3.39) 密钥提取 —— 通过 Frida 注入页解密函数。

背景
----
微信 4.0.3.39 起，dbkey 在数据库初始化后即从内存擦除。传统做法（在进程内存里
搜 ``x'<hex_key><hex_salt>'`` 文本）在 4.1.11+ 已完全失效——内存里根本不存在
这个字符串，所以扫描必然是 0 命中。

本模块的做法
------------
1. 用字节签名定位 Weixin.dll 里的 SQLCipher 页解密函数（版本无关）；
2. 在该函数入口抓取 4 个参数指针附近的 256 字节；
3. 把抓到的内存里所有 32 字节窗口当作候选 AES-256 密钥；
4. 用目标库真实的 page1 验证：AES-256-CBC 解密 ``page[16:4016]``、IV 取
   ``page[4016:4032]``，得到的应当是合法页头（页大小 4096）；再整库解密并用
   sqlite3 打开确认，才认这个密钥。

因为验证用的是真实库文件，抓到的噪音数据不会污染结果。

用法
----
    from wechat_cli.keys.frida42 import capture_keys

    keys = capture_keys(db_dir, spawn=False, wait=60)   # attach 正在运行的微信
    keys = capture_keys(db_dir, spawn=True, wait=90)    # 重启微信，启动早期挂载

    # keys: {"message\\message_0.db": "54ba57...", ...}
"""
from __future__ import annotations

import os
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

PAGE = 4096
RESERVE = 80          # IV(16) + HMAC-SHA512(64)
SALT = 16
MAGIC = b"SQLite format 3\x00"

# 页解密函数开头的 16 字节（4.2.0.13 实测；该函数在 4.x 各版本结构稳定）
SIGNATURE = "48 89 CF 48 89 D6 4C 89 C2 4C 89 C9 4C 8B 44 24 28"

# 已知版本的直接偏移（签名扫描失败时兜底）
KNOWN_OFFSETS = {
    "4.2.0.13": 0x5B5A43D,
}

JS_TEMPLATE = r"""
var mod = null;
var targets = [];

function hookAt(addr, label) {
    try {
        Interceptor.attach(addr, {
            onEnter: function (a) {
                var rec = { t: 'hit', fn: label };
                for (var i = 0; i < 4; i++) {
                    try {
                        var p = a[i];
                        if (p.compare(0x10000) < 0) continue;
                        rec['a' + i] = Array.from(new Uint8Array(p.readByteArray(256)));
                    } catch (e) {}
                }
                send(rec);
            }
        });
        return true;
    } catch (e) {
        send({ t: 'hookfail', fn: label, m: e.message });
        return false;
    }
}

function go() {
    mod = Process.findModuleByName('Weixin.dll');
    if (mod === null) { setTimeout(go, 150); return; }

    var hooked = 0;
    try {
        var hits = Memory.scanSync(mod.base, mod.size, '%(sig)s');
        for (var i = 0; i < hits.length && i < 8; i++) {
            if (hookAt(hits[i].address, 'sig' + i)) hooked++;
        }
    } catch (e) {
        send({ t: 'scanfail', m: e.message });
    }

    if (hooked === 0) {
        %(fallback)s
    }
    send({ t: 'ready', pid: Process.id, hooked: hooked, base: mod.base.toString() });
}
go();
"""


# ---------------------------------------------------------------- 进程 / 模块

def weixin_pids():
    if os.name != "nt":
        raise RuntimeError("当前仅实现 Windows 的 4.x 抓取")
    out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq Weixin.exe", "/FO", "CSV", "/NH"],
                         capture_output=True, text=True).stdout
    pids = []
    for line in out.strip().splitlines():
        parts = line.strip('"').split('","')
        if len(parts) >= 5:
            try:
                pids.append(int(parts[1]))
            except ValueError:
                pass
    return pids


def _module_version(pid):
    """读取 Weixin.dll 的文件版本（用于兜底偏移）。"""
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-Process -Id {pid}).Modules | Where-Object {{$_.ModuleName -eq 'Weixin.dll'}} | "
             "Select-Object -First 1 -ExpandProperty FileVersionInfo | Select-Object -ExpandProperty FileVersion"],
            capture_output=True, text=True, timeout=25).stdout.strip()
        return out
    except Exception:
        return ""


# ---------------------------------------------------------------- 密钥验证

def _looks_like_page(pt):
    if len(pt) < 2:
        return False
    ps = int.from_bytes(pt[0:2], "big")
    return 512 <= ps <= 65536 and (ps & (ps - 1)) == 0


def _decrypt_first_page(key, blk):
    from Crypto.Cipher import AES
    iv = blk[PAGE - RESERVE: PAGE - RESERVE + 16]
    try:
        return AES.new(key, AES.MODE_CBC, iv).decrypt(blk[SALT: PAGE - RESERVE])
    except ValueError:
        return None


def _full_decrypt(src, dst, key):
    from Crypto.Cipher import AES
    pages = os.path.getsize(src) // PAGE
    with open(src, "rb") as fi, open(dst, "wb") as fo:
        first = fi.read(PAGE)
        pt = AES.new(key, AES.MODE_CBC, first[PAGE - RESERVE: PAGE - RESERVE + 16]).decrypt(first[SALT: PAGE - RESERVE])
        fo.write(MAGIC + pt + b"\x00" * RESERVE)
        for _ in range(2, pages + 1):
            blk = fi.read(PAGE)
            if len(blk) < PAGE:
                break
            pt = AES.new(key, AES.MODE_CBC, blk[PAGE - RESERVE: PAGE - RESERVE + 16]).decrypt(blk[: PAGE - RESERVE])
            fo.write(pt + b"\x00" * RESERVE)


def _validate(path):
    try:
        conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
        n = conn.execute("select count(*) from sqlite_master").fetchone()[0]
        conn.close()
        return n > 0
    except Exception:
        return False


def _db_files(db_dir):
    out = []
    for root, _dirs, files in os.walk(db_dir):
        for name in files:
            if name.endswith(".db") and not name.endswith(("-wal", "-shm")):
                p = os.path.join(root, name)
                if os.path.getsize(p) >= PAGE:
                    out.append((os.path.relpath(p, db_dir), p))
    out.sort()
    return out


def verify_candidates(db_dir, candidates, known=None, log=print):
    """把候选密钥与真实库文件对撞，返回 {rel_path: key_hex}。"""
    known = dict(known or {})
    dbs = _db_files(db_dir)
    pending = [(rel, p) for rel, p in dbs if rel not in known]
    log(f"[verify] 候选密钥 {len(candidates)} 个，待解库 {len(pending)} 个")

    found = {}
    for rel, path in pending:
        with open(path, "rb") as f:
            blk = f.read(PAGE)
        for key in candidates:
            pt = _decrypt_first_page(key, blk)
            if not pt or not _looks_like_page(pt):
                continue
            tmp = os.path.join(tempfile.gettempdir(), "wxcli_verify.db")
            try:
                _full_decrypt(path, tmp, key)
                if _validate(tmp):
                    found[rel] = key.hex()
                    log(f"  [OK] {rel}  key={key.hex()}")
                    break
            except Exception:
                pass
            finally:
                try:
                    os.remove(tmp)
                except OSError:
                    pass
    return found


# ---------------------------------------------------------------- Frida 抓取

def _collect_from(pid, candidates, wait=45, log=print, script_js=None):
    import frida

    pids_done = set()
    sessions = []

    def make_script(session):
        script = session.create_script(script_js)

        def on_message(msg, _data):
            if msg.get("type") != "send":
                return
            p = msg["payload"]
            t = p.get("t")
            if t == "ready":
                log(f"  [frida] pid={p.get('pid')} hooked={p.get('hooked')} base={p.get('base')}")
            elif t == "hit":
                for i in range(4):
                    blob = p.get(f"a{i}")
                    if not blob:
                        continue
                    raw = bytes(blob)
                    for off in range(0, len(raw) - 31, 4):
                        candidates.add(raw[off:off + 32])

        script.on("message", on_message)
        script.load()
        return script

    session = frida.attach(pid)
    make_script(session)
    sessions.append(session)
    pids_done.add(pid)
    log(f"  [frida] attached {pid}")

    t0 = time.time()
    while time.time() - t0 < wait:
        time.sleep(2)
        for p in weixin_pids():
            if p in pids_done:
                continue
            try:
                s = frida.attach(p)
                make_script(s)
                sessions.append(s)
                pids_done.add(p)
                log(f"  [frida] attached child {p}")
            except Exception:
                pass

    for s in sessions:
        try:
            s.detach()
        except Exception:
            pass


def capture_keys(db_dir, spawn=False, wait=60, log=print, known=None):
    """抓取微信 4.x 各库密钥。

    Args:
        db_dir: db_storage 目录
        spawn: True 则重启微信并在启动早期挂载（能覆盖启动时就打开的库，推荐）
        wait: 抓取窗口秒数
        known: 已知密钥，命中则跳过验证

    Returns:
        dict: {相对路径: 密钥 hex}
    """
    try:
        import frida  # noqa: F401
    except ImportError:
        raise RuntimeError("需要 frida：pip install frida")

    fallback = "hookAt(mod.base.add(0x%X), 'known');" % KNOWN_OFFSETS.get("4.2.0.13", 0x5B5A43D)
    js = JS_TEMPLATE % {"sig": SIGNATURE, "fallback": fallback}

    candidates = set()

    if spawn:
        import frida
        exe = r"D:\Program Files\Tencent\Weixin\Weixin.exe"
        if not os.path.exists(exe):
            raise RuntimeError(f"未找到微信可执行文件: {exe}")
        log("[*] 关闭微信 ...")
        subprocess.run(["taskkill", "/F", "/IM", "Weixin.exe"], capture_output=True)
        subprocess.run(["taskkill", "/F", "/IM", "WeixinUpdate.exe"], capture_output=True)
        time.sleep(3)
        pid = frida.spawn(exe)
        session = frida.attach(pid)
        script = session.create_script(js)

        def on_message(msg, _data):
            if msg.get("type") != "send":
                return
            p = msg["payload"]
            if p.get("t") == "hit":
                for i in range(4):
                    blob = p.get(f"a{i}")
                    if not blob:
                        continue
                    raw = bytes(blob)
                    for off in range(0, len(raw) - 31, 4):
                        candidates.add(raw[off:off + 32])

        script.on("message", on_message)
        script.load()
        frida.resume(pid)
        log(f"[*] 已启动微信 pid={pid}，抓取 {wait}s ...")
        time.sleep(wait)
        try:
            session.detach()
        except Exception:
            pass
    else:
        pids = weixin_pids()
        if not pids:
            raise RuntimeError("微信未运行；可改用 spawn=True")
        log(f"[*] attach 正在运行的微信 {pids}，抓取 {wait}s ...")
        _collect_from(pids[0], candidates, wait=wait, log=log, script_js=js)

    log(f"[*] 收集到候选窗口 {len(candidates)} 个，开始校验 ...")
    if not candidates:
        log("[!] 抓取窗口内没有捕获到页解密调用（微信空闲时不会解密页）。")
        log("    → attach 模式：抓取期间请打开/切换几个会话，让它读数据库；")
        log("    → 或改用 spawn 模式（--spawn），启动阶段会自动加载并解密各库。")
    found = verify_candidates(db_dir, candidates, known=known, log=log)
    merged = dict(known or {})
    merged.update(found)
    return merged
