"""微信 4.x V2 .dat 媒体解密。

结构（4.2.0.13 实测）:
    [0:6]    magic 07 08 56 32 08 07
    [6:10]   aes_size      (LE, 通常 1024)
    [10:14]  xor_size      (LE, 尾部 XOR 字节数)
    [14]     pad
    [15:]    AES-128-ECB 段 + 中间明文 + 尾部单字节 XOR

AES key 为 16 字节（登录后常驻内存，或点开图片后出现）；
XOR key 单字节，可从文件尾部（JPEG 的 FF D9 / PNG 的 IEND）反推。
"""
from __future__ import annotations

import os
import struct
from collections import Counter

from Crypto.Cipher import AES

MAGIC = b"\x07\x08V2\x08\x07"
PAGE_HDR = 15

SIGS = (
    (b"\xff\xd8\xff", ".jpg"),
    (b"\x89PNG\r\n\x1a\n", ".png"),
    (b"RIFF", ".webp"),
    (b"GIF87a", ".gif"),
    (b"GIF89a", ".gif"),
    (b"BM", ".bmp"),
    (b"wxgf", ".wxgf"),
)


def parse_header(data: bytes):
    if len(data) < 31 or data[:6] != MAGIC:
        return None
    aes_size, xor_size = struct.unpack_from("<LL", data, 6)
    return aes_size, xor_size, data[14]


def guess_xor_key(paths, limit: int = 80) -> int:
    counts = Counter()
    for p in list(paths)[:limit]:
        try:
            size = os.path.getsize(p)
            with open(p, "rb") as f:
                if f.read(6) != MAGIC:
                    continue
                f.seek(size - 2)
                tail = f.read(2)
            if len(tail) == 2:
                counts[tail[0] ^ 0xFF] += 1
        except OSError:
            continue
    return counts.most_common(1)[0][0] if counts else 0x70


def decrypt_bytes(data: bytes, aes_key: bytes, xor_key: int):
    """返回 (明文, 扩展名)；失败返回 (None, 原因)。"""
    hdr = parse_header(data)
    if not hdr:
        return None, "not-v2"
    aes_size, xor_size, _pad = hdr
    aligned = (aes_size + 15) // 16 * 16
    if PAGE_HDR + aligned > len(data):
        return None, "truncated"
    try:
        head = AES.new(aes_key, AES.MODE_ECB).decrypt(data[PAGE_HDR:PAGE_HDR + aligned])[:aes_size]
    except ValueError as exc:
        return None, f"aes:{exc}"
    rest = data[PAGE_HDR + aligned:]
    cut = max(0, len(rest) - min(xor_size, len(rest)))
    body = head + rest[:cut] + bytes(b ^ xor_key for b in rest[cut:])
    for sig, ext in SIGS:
        if body.startswith(sig):
            return body, ext
    return body, ".bin"


def decrypt_file(path: str, aes_key: bytes, xor_key: int):
    with open(path, "rb") as f:
        return decrypt_bytes(f.read(), aes_key, xor_key)


def find_dat_files(base_dir: str):
    """base_dir 为微信账号目录（db_storage 的父目录）。"""
    import glob

    pats = [
        os.path.join(base_dir, "msg", "attach", "*", "*", "Img", "*.dat"),
        os.path.join(base_dir, "cache", "*", "Message", "*", "*", "*.dat"),
        os.path.join(base_dir, "msg", "attach", "*", "*", "*.dat"),
    ]
    return sorted({p for pat in pats for p in glob.glob(pat)})
