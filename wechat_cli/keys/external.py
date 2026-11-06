"""外部密钥文件支持。

支持两种格式，二者都能被本模块读取：

1. ``db_keys.json`` —— 简洁格式（本版本新增，抓取脚本直接产出）::

       {"message\\\\message_0.db": "54ba571e...", ...}

2. ``all_keys.json`` —— 0.2.x 沿用的旧格式（带 salt / 大小）::

       {"message\\\\message_0.db": {"enc_key": "...", "salt": "...", "size_mb": 336.0}}

对外统一返回 ``{相对路径: enc_key_hex}``。
"""
from __future__ import annotations

import json
import os

from ..core.config import CONFIG_FILE, KEYS_FILE, STATE_DIR  # noqa: F401  (兼容性转发)


def read_keys_file(path):
    """读取密钥文件，返回 {rel_path: enc_key_hex}。"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"密钥文件不存在: {path}")
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)

    out = {}
    for rel, val in raw.items():
        if rel.startswith("_"):
            continue
        if isinstance(val, str):
            key = val.strip()
        elif isinstance(val, dict):
            key = (val.get("enc_key") or "").strip()
        else:
            continue
        if len(key) == 64:
            out[rel.replace("/", os.sep)] = key
    if not out:
        raise ValueError(f"密钥文件里没有可用的 enc_key: {path}")
    return out


def write_keys_file(keys, path):
    """把 {rel: hex} 写成简洁格式。"""
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({k: v for k, v in sorted(keys.items())}, f, indent=2, ensure_ascii=False)
    return path


def to_all_keys(keys, db_dir):
    """转换成 0.2.x 的 all_keys.json 结构，供既有的 DBCache 直接使用。"""
    out = {}
    for rel, key_hex in keys.items():
        path = os.path.join(db_dir, rel)
        salt, size_mb = "", 0.0
        try:
            with open(path, "rb") as f:
                salt = f.read(16).hex()
            size_mb = round(os.path.getsize(path) / 1048576, 1)
        except OSError:
            pass
        out[rel] = {"enc_key": key_hex, "salt": salt, "size_mb": size_mb}
    return out


def install_keys(keys, keys_file):
    """把密钥写成 all_keys.json，并返回写入的条数。"""
    os.makedirs(os.path.dirname(os.path.abspath(keys_file)), exist_ok=True)
    with open(keys_file, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2, ensure_ascii=False)
    return len(keys)
