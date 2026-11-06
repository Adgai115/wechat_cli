# Changelog

## 0.3.0 — 2026-11-05

基于 0.2.4 的 fork，新增微信 4.x（4.0.3.39+，实测 4.2.0.13）支持。

### 新增
- `keys/frida42.py`：Frida 抓取后端
  - 16 字节签名定位页解密函数（版本无关，含 4.2.0.13 已知偏移兜底）
  - 函数入口抓取参数邻域内存，提取候选 32 字节密钥
  - 用真实库 page1 + 整库解密双重校验，杜绝误判
  - 支持 attach 运行中的微信 / spawn 启动期挂载
- `keys/external.py`：外部密钥文件支持
  - 读取 `db_keys.json`（简洁格式）与 `all_keys.json`（0.2.x 格式）
  - 自动转换为既有 `DBCache` 期望的 `all_keys.json` 结构
- `init` 新选项：`--keys-from` / `--method {auto,frida,memory}` / `--spawn` / `--wait`
- `python -m wechat_cli` 入口

### 变更
- `keys.extract_keys()` 新增 `method` / `keys_from` / `spawn` / `wait` 参数，默认 `auto`：
  优先 frida，失败回退内存扫描
- 版本号 0.2.4 → 0.3.0

### 修复
- 纠正 4.x 加密参数认知：page1 密文 `page[16:4016]` 解密后**首块为页头**（页大小 4096、
  保留区 80），明文 = `SQLite format 3\0` + 4000 字节 + 80 字节保留区；
  0.2.x 若用 SQLite 魔数作为密钥判定条件会永远失败
- 明确 dbkey 生命周期：4.0.3.39 起用完即擦除，内存搜索不可行

### 保留
- 0.2.x 的全部查询能力：`sessions` / `history` / `search` / `contacts` / `members` /
  `stats` / `unread` / `new-messages` / `favorites` / `export`
- 老的 `x'<hex>'` 内存扫描（`--method memory`），仅对 < 4.0.3.39 有效

### 实测
- Windows 10/11 + 微信 4.2.0.13 + Python 3.13
- 23 个库中 22 个取得密钥并成功解密（唯一缺失 `media_1.db` 为媒体索引）
- 306 个会话 / 555,979 条消息 / 11,696 联系人可正常查询

## 0.4.0 — 2026-11-06

### 新增
- `media` 命令组：`key` / `decrypt` / `index` / `html`
- `wechat_cli/media/dat.py` — V2 `.dat` 解析与解密（AES-128-ECB + 尾部 XOR）
- `wechat_cli/media/keyfind.py` — 从微信内存抓图片 AES key（结构魔数校验，支持 watch 轮询）
- `wechat_cli/media/pair.py` — 媒体与消息配对（`md5(会话)` 目录 + 时间就近）
- `wechat_cli/media/timeline.py` — 生成可浏览的聊天时间线 HTML
- `media_keys.json` 保存图片密钥

### 说明
- 图片 AES key 在微信 4.2 上通常登录后即驻留内存；若未命中，`media key --watch` 期间点开大图即可
- `.wxgf`（微信 HEVC 容器）可解出文件，但码流不完整导致画面残缺，默认只保留原文件
- 版本号 0.3.0 → 0.4.0

### 实测
- Windows + 微信 4.2.0.13：6082 个 `.dat` 解密成功（3759 jpg / 1204 png / 1119 wxgf）
- 配对 1588 条消息↔文件，时间中位误差 5 秒