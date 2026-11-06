"""init 命令 — 初始化配置与密钥。

三种姿势：
  wechat-cli init                      # 自动（4.x 走 Frida 抓取）
  wechat-cli init --keys-from k.json   # 直接用已有密钥，完全不碰微信进程
  wechat-cli init --method memory      # 老版本：内存里搜 x'<hex>'（4.1.11+ 无效）
"""
import json
import os
import sys

import click

from ..core.config import STATE_DIR, CONFIG_FILE, KEYS_FILE, auto_detect_db_dir


@click.command()
@click.option("--db-dir", default=None, help="微信数据目录路径（默认自动检测）")
@click.option("--force", is_flag=True, help="强制重新提取密钥")
@click.option("--keys-from", default=None, metavar="PATH",
              help="直接加载密钥文件（db_keys.json / all_keys.json），不接触微信进程")
@click.option("--method", type=click.Choice(["auto", "frida", "memory"]), default="auto",
              help="密钥来源：auto=优先 frida；frida=注入抓取（4.x 唯一可行）；memory=老版本内存扫描")
@click.option("--spawn", is_flag=True, help="frida 抓取时重启微信，覆盖启动期就打开的库（推荐）")
@click.option("--wait", type=int, default=60, show_default=True, help="frida 抓取窗口秒数")
def init(db_dir, force, keys_from, method, spawn, wait):
    """初始化 wechat-cli：获取密钥并生成配置"""
    click.echo("WeChat CLI 初始化")
    click.echo("=" * 40)

    if os.path.exists(CONFIG_FILE) and os.path.exists(KEYS_FILE) and not force and not keys_from:
        click.echo(f"已初始化（配置: {CONFIG_FILE}）")
        click.echo("使用 --force 重新提取密钥，或 --keys-from 指定密钥文件")
        return

    os.makedirs(STATE_DIR, exist_ok=True)

    if db_dir is None:
        db_dir = auto_detect_db_dir()
        if db_dir is None:
            click.echo("[!] 未能自动检测到微信数据目录", err=True)
            click.echo("请通过 --db-dir 参数指定，例如:", err=True)
            click.echo("  wechat-cli init --db-dir D:\\...\\xwechat_files\\wxid_xxx\\db_storage", err=True)
            sys.exit(1)
        click.echo(f"[+] 检测到微信数据目录: {db_dir}")
    else:
        db_dir = os.path.abspath(db_dir)
        if not os.path.isdir(db_dir):
            click.echo(f"[!] 目录不存在: {db_dir}", err=True)
            sys.exit(1)
        click.echo(f"[+] 使用指定数据目录: {db_dir}")

    click.echo("\n开始获取密钥 ...")
    try:
        from ..keys import extract_keys
        keys = extract_keys(db_dir, KEYS_FILE, method=method, keys_from=keys_from,
                            spawn=spawn, wait=wait, log=click.echo)
    except RuntimeError as e:
        click.echo(f"\n[!] 密钥获取失败: {e}", err=True)
        click.echo("提示：微信 4.0.3.39+ 请用 --method frida（可加 --spawn），"
                   "或先用抓取工具产出 db_keys.json 再 --keys-from 载入。", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"\n[!] 密钥获取出错: {e}", err=True)
        sys.exit(1)

    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump({"db_dir": db_dir}, f, indent=2, ensure_ascii=False)

    click.echo("\n[+] 初始化完成!")
    click.echo(f"    配置: {CONFIG_FILE}")
    click.echo(f"    密钥: {KEYS_FILE}")
    click.echo(f"    可用密钥: {len(keys)} 个库")
    click.echo("\n现在可以使用:")
    click.echo("  wechat-cli sessions")
    click.echo("  wechat-cli history \"联系人\"")
