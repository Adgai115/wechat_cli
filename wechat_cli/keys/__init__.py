"""密钥提取模块 — 按平台 / 策略分派。

0.3.0 起新增两条路径：
  * ``method="frida"``  —— 微信 4.0.3.39+ 唯一可行的方式（注入页解密函数）
  * ``keys_from=<path>`` —— 直接加载已抓到的密钥文件，完全不碰微信进程
原有的内存扫描（0.2.x 的 ``x'<hex>'`` 方案）保留为 ``method="memory"``，
在微信 4.1.11+ 上它必然 0 命中，仅对老版本有效。
"""
import platform


def extract_keys(db_dir, output_path, pid=None, method="auto", keys_from=None, spawn=False,
                 wait=60, log=print):
    """提取（或加载）微信数据库密钥并保存到 output_path。

    Args:
        db_dir: 微信数据库目录（db_storage）
        output_path: all_keys.json 输出路径
        pid: 可选，指定微信进程 PID
        method: "auto" | "frida" | "memory"
        keys_from: 直接读取的密钥文件（db_keys.json 或 all_keys.json）
        spawn: method="frida" 时是否重启微信以覆盖启动期加载的库
        wait: frida 抓取窗口秒数

    Returns:
        dict: {rel_path: enc_key_hex}
    """
    from . import external

    # 1) 直接用现成密钥，完全不接触微信进程
    if keys_from:
        keys = external.read_keys_file(keys_from)
        log(f"[+] 从 {keys_from} 载入 {len(keys)} 个库密钥")
        external.install_keys(external.to_all_keys(keys, db_dir), output_path)
        return keys

    # 2) Frida（4.x 推荐 / 唯一可行）
    if method in ("auto", "frida"):
        try:
            from .frida42 import capture_keys
        except Exception as exc:  # pragma: no cover
            if method == "frida":
                raise
            log(f"[!] 无法加载 frida 后端: {exc}")
        else:
            try:
                keys = capture_keys(db_dir, spawn=spawn, wait=wait, log=log)
            except Exception as exc:
                if method == "frida":
                    raise
                log(f"[!] frida 抓取失败: {exc}")
            else:
                if keys:
                    external.install_keys(external.to_all_keys(keys, db_dir), output_path)
                    return keys
                log("[!] frida 未取到任何密钥，回退到内存扫描")

    # 3) 老版本的内存扫描
    system = platform.system().lower()
    if system == "darwin":
        from .scanner_macos import extract_keys as _extract
    elif system == "windows":
        from .scanner_windows import extract_keys as _extract
    elif system == "linux":
        from .scanner_linux import extract_keys as _extract
    else:
        raise RuntimeError(f"不支持的平台: {platform.system()}")

    key_map = _extract(db_dir, output_path, pid=pid)
    keys = {rel: info["enc_key"] if isinstance(info, dict) else info
            for rel, info in key_map.items() if not rel.startswith("_")}
    return keys
