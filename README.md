# wechat-cli 0.3.0

微信本地数据查询 CLI（给 LLM / 自动化用）。本版本的核心变化：**支持微信 4.0.3.39+ / 4.2.x 的数据库密钥获取**，并让"日常读取"彻底摆脱进程注入。

---

## 为什么 0.2.4 在微信 4.2 上取不到密钥

0.2.x 的做法是在 `Weixin.exe` 进程内存里搜 `x'<64hex_key><32hex_salt>'` 这种文本。

微信从 **4.0.3.39** 起改了机制：dbkey 在数据库初始化完成后**立即从内存擦除**，内存里既没有那个文本，也没有长期驻留的裸密钥。于是：

- `wechat-cli init` → 0 命中 → 报"未能从任何微信进程中提取到密钥"
- 任何"扫内存找 key"的思路（含社区大多数工具）在 4.1.11+ 都已失效

这不是配置问题，是机制变了。

## 0.3.0 怎么解决

1. **签名定位**：用 16 字节特征码在 `Weixin.dll` 里定位 SQLCipher 的**页解密函数**
   （`48 89 CF 48 89 D6 4C 89 C2 4C 89 C9 4C 8B 44 24 28`），不依赖硬编码偏移。
2. **入口抓取**：Frida 挂在该函数入口，抓 4 个参数指针附近的 256 字节。轮密钥调度表就在其中。
3. **真库校验**：把抓到的内存里所有 32 字节窗口当候选密钥，用目标库**真实的 page1** 验证——
   `AES-256-CBC` 解密 `page[16:4016]`、IV 取 `page[4016:4032]`，须得到合法页头；
   再整库解密并用 sqlite3 打开确认。噪音数据不会被误判。
4. **离线复用**：校验通过的密钥写成 `all_keys.json`，之后所有命令直接读文件，**不再接触微信进程**。

## 加密参数（4.x 实测）

| 项 | 值 |
|---|---|
| 加密算法 | AES-256-CBC + HMAC-SHA512（SQLCipher 4） |
| 页大小 | 4096 |
| 保留区 | 80 字节 = IV(16) + HMAC(64) |
| page1 布局 | `[0:16]=salt`，`[16:4016]=密文`，`[4016:4032]=IV`，`[4032:4096]=HMAC` |
| page1 明文 | `SQLite format 3\0` + 解密出的 4000 字节 + 80 字节保留区 |

> 注意：`page[16:4016]` 解密出来的**首块是页头**（`10 00 02 02 50 40 20 20` = 页大小/版本/保留80/64/32/32），
> 不是 `SQLite format 3`。用 SQLite 魔数当判定条件会永远失败。

## 安装

```bash
pip install -e .            # 开发安装
pip install .[frida]        # 需要内置抓取能力时
```

依赖：`click`、`pycryptodome`、`zstandard`；抓取额外需要 `frida`。

## 用法

```bash
# 用已经抓好的密钥（完全不接触微信进程，推荐日常使用）
wechat-cli init --keys-from db_keys.json

# 首次 / 密钥失效：注入抓取（微信 4.x 唯一可行）
wechat-cli init --method frida --spawn --wait 90

# 老版本微信（< 4.0.3.39）：内存扫描仍然可用
wechat-cli init --method memory

# 查询
wechat-cli sessions --limit 20
wechat-cli history "群名" --limit 50
wechat-cli search "关键词" --chat "群名"
wechat-cli contacts --query "李"
wechat-cli export ...
```

## 密钥生命周期

密钥按库文件头 salt 派生，salt 不变则长期有效：

- 正常收发消息、重启、小版本升级 → salt 不变 → **老密钥继续可用**
- 数据库被重建 / 换账号 / 卸载重装 → salt 变 → 需要重新抓一次
- 新分片（如 `message_3.db`）出现 → 只需补抓一次

因此常规使用是：**密钥存文件、查询全离线**；只有 salt 变化时才需要一次注入。

## 安全性

- 抓取阶段只读寄存器 / 内存，**不写文件、不打补丁、不替换 DLL**，抓完立即 `detach`
- 解密阶段完全离线，只读数据库文件副本
- 已知风险：微信存在 anti-hook 检测，启动期注入偶发崩溃（重启即恢复，数据无损）；
  因此注入只在"刷新密钥"时进行
- `all_keys.json` / `db_keys.json` 等同于本地数据总钥匙，请单独加密或收紧权限

## 兼容性

| 微信版本 | 0.2.4 | 0.3.0 |
|---|---|---|
| < 4.0.3.39 | ✅ 内存扫描 | ✅ `--method memory` |
| 4.0.3.39 – 4.1.10 | ⚠️ 部分失效 | ✅ `--method frida` |
| 4.1.11+ / 4.2.x | ❌ 0 命中 | ✅ `--method frida`，实测 4.2.0.13 |

## License

MIT

## 命令名冲突说明（Windows）

如果你机器上装过 npm 全局包 `@canghe_ai/wechat-cli`，`wechat-cli` 这个名字会被它占用
（且该包缺平台二进制时直接报 `Cannot find module ...`）。因此本版本额外注册了 `wxcli` 别名：

```bash
wxcli --version      # 0.3.0
wxcli sessions       # 与 wechat-cli 完全等价
```

想恢复 `wechat-cli` 这个名字，先卸掉那个 npm 包：

```bash
npm uninstall -g @canghe_ai/wechat-cli
```