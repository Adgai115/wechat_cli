"""从微信进程内存里找图片 AES key。

判据不依赖字符串特征：拿真实 .dat 的密文块做 AES-128-ECB 试解，
必须解出 JPEG/PNG/WEBP/WXGF 的**结构性魔数**（≥3 字节且后续字节合理）才算命中。

微信 4.x 的行为：图片 key 在您于客户端**点开大图**后才会出现，所以提供
watch 模式——开着监听，你在微信里点几张图，key 会被自动抓下来。
"""
from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re
import struct
import subprocess
import time

from Crypto.Cipher import AES

from .dat import MAGIC, parse_header

READABLE = {0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80}
RW_PROTECT = {0x04, 0x08, 0x40, 0x80}
MEM_COMMIT = 0x1000
PQI, PVR = 0x0400, 0x0010
RE_ALNUM = re.compile(rb"[a-zA-Z0-9]{16,64}")

kernel32 = ctypes.windll.kernel32


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_uint64), ("AllocationBase", ctypes.c_uint64),
                ("AllocationProtect", wt.DWORD), ("_p1", wt.DWORD),
                ("RegionSize", ctypes.c_uint64), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD), ("_p2", wt.DWORD)]


def weixin_pids():
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


def _regions(h, rw_only=True):
    regs, addr, mbi = [], 0, MBI()
    while addr < 0x7FFFFFFFFFFF:
        if kernel32.VirtualQueryEx(h, ctypes.c_uint64(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        ok = mbi.State == MEM_COMMIT and 0 < mbi.RegionSize <= 64 * 1024 * 1024
        if ok and (mbi.Protect in (RW_PROTECT if rw_only else READABLE)):
            regs.append((mbi.BaseAddress, mbi.RegionSize))
        nxt = mbi.BaseAddress + mbi.RegionSize
        if nxt <= addr:
            break
        addr = nxt
    return regs


def _read(h, addr, size):
    buf = ctypes.create_string_buffer(size)
    n = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h, ctypes.c_uint64(addr), buf, size, ctypes.byref(n)):
        return buf.raw[:n.value]
    return None


def _strong(pt: bytes) -> bool:
    if pt[:3] == b"\xff\xd8\xff" and pt[3] == 0xFF:
        return pt[4] in (0xDB, 0xC4) or 0xC0 <= pt[4] <= 0xCF or 0xE0 <= pt[4] <= 0xEF
    if pt[:8] == b"\x89PNG\r\n\x1a\n":
        return True
    if pt[:4] == b"RIFF" and pt[8:12] == b"WEBP":
        return True
    if pt[:4] in (b"wxgf", b"GIF8"):
        return True
    return False


def sample_blocks(db_dir, limit=6):
    """取若干 V2 样本的第一段密文（不同偏移都保留）。"""
    base = os.path.dirname(db_dir)
    files = []
    from .dat import find_dat_files
    for p in find_dat_files(base):
        try:
            with open(p, "rb") as f:
                head = f.read(64)
        except OSError:
            continue
        hdr = parse_header(head)
        if not hdr or hdr[0] < 16:
            continue
        files.append(head)
        if len(files) >= limit:
            break
    blocks = []
    for head in files:
        for off in (15, 16, 31, 32, 0, 8):
            blk = head[off:off + 16]
            if len(blk) == 16:
                blocks.append(blk)
    return blocks


def scan_once(blocks, deep=False, log=print):
    for pid in weixin_pids():
        h = kernel32.OpenProcess(PQI | PVR, False, pid)
        if not h:
            continue
        try:
            for base, size in _regions(h, rw_only=not deep):
                data = _read(h, base, size)
                if not data:
                    continue
                if deep:
                    step = 8
                    for off in range(0, len(data) - 15, step):
                        key = data[off:off + 16]
                        try:
                            c = AES.new(key, AES.MODE_ECB)
                        except ValueError:
                            continue
                        for blk in blocks:
                            if _strong(c.decrypt(blk)):
                                return key
                else:
                    for m in RE_ALNUM.finditer(data):
                        s = m.group()
                        for klen in (16, 32):
                            if len(s) < klen:
                                continue
                            try:
                                c = AES.new(s[:klen], AES.MODE_ECB)
                            except ValueError:
                                continue
                            for blk in blocks:
                                if _strong(c.decrypt(blk)):
                                    return s[:klen]
        finally:
            kernel32.CloseHandle(h)
    return None


def find_image_key(db_dir, watch=0, deep_every=4, log=print):
    """在微信内存里找图片 AES key。

    Args:
        db_dir: db_storage 目录
        watch: >0 时持续监听该秒数（期间在微信里点开图片即可被捕获）
    """
    blocks = sample_blocks(db_dir)
    if not blocks:
        raise RuntimeError("找不到可用于校验的 V2 样本")
    log(f"[*] 校验样本密文块 {len(blocks)} 个")

    round_no = 0
    t0 = time.time()
    while True:
        round_no += 1
        key = scan_once(blocks, deep=(round_no % deep_every == 0), log=log)
        if key:
            log(f"[+] 命中 AES key: {key.decode('latin1')!r} (hex {key.hex()})")
            return key
        if not watch or time.time() - t0 >= watch:
            raise RuntimeError("未在内存中找到图片密钥（请在微信里点开 2~3 张图片后重试）")
        log(f"    第 {round_no} 轮未命中，{int(watch - (time.time() - t0))}s 后重试 ...")
        time.sleep(4)
