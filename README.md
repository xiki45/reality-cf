# REALITY-CF · 节点发现

发现「**target 落在 Cloudflare 后面、且会把失败认证流量原样转发**」的 REALITY 节点
—— 也就是 Xray 官方文档描述的那类：*「你的服务器实际上就成了 Cloudflare 的端口转发器，被扫描后可能被滥用」*。

判定全程离线可复现：本地 mock 节点 → 双重握手 → 结论 + 证据字段。

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python main.py --sni images.apple.com --targets ips.txt --cf-domain your.domain.com
```

---

## 1. 原理（说清楚它到底在测什么）

REALITY 有个必需的 **SNI 白名单** `serverNames`（不是「空数组」），但对**没通过认证**的连接，
Xray 会把原始流量直接转发给 `target`。于是：

```
普通 REALITY 节点 (target = 苹果源站)
  客户端 --SNI=任意域名--> 节点 --原样转发--> 苹果源站
                                          └─ 收到的是苹果的证书，与你的 SNI 不匹配 → 丢弃

target 在 CF 后面的节点 (target = 某个 CF 站点)
  客户端 --SNI=任意域名--> 节点 --原样转发--> CF 边缘
                                          └─ CF 愿意为该 SNI 出证书 + 回 cf-ray → 命中
```

所以本工具测的是「**节点的 target 由 Cloudflare 承接**」这件事，不是「serverNames 没配」。

### 这个工具到底在找什么

找的是「**别人的机器，当前会把未认证流量转发给 Cloudflare**」。

- REALITY 对认证失败的连接不做任何检查，原样转发给 dest —— 所以任何人**不带任何凭证**
  就能借这台机器进 CF，把它当中转用。这是本项目的核心产出。
- 因此**判定标准只有 TLS 层三步验证**，与 `uuid/pbk/sid` 无关。
  客户端能不能当「用户」登录（`--verify-auth`）是另一件事，属于自用场景，不是这里的目标。
- 目标机器会轮换 dest 来反制（实测同一批 DMIT 机器 50 分钟内从 540 台掉到 2 台），
  所以产出必须带**新鲜度**，见下面的「保鲜与轮换监控」。

### ⚠️ 关键前提：一个目标只跟它自己的 SNI 配对

这是**最容易写错、也是旧版 README 写错的地方**：不能用固定一个 SNI（例如 `images.apple.com`）
去问所有节点。每个节点的 REALITY dest 各不相同，别人的 SNI 只会换来 `name_mismatch` ——
实测 1118 个真实节点用固定 SNI 扫描，命中 **0**，而 104 条落进「证书不匹配」。

正确做法是让每个目标带上它订阅里自己的 SNI：

```bash
reality-cf --links sub.txt --cf-domain probe.example.com        # 推荐：链接自带 SNI + 凭证
reality-cf --targets nodes.txt --cf-domain probe.example.com    # nodes.txt 用 host:port:sni 三列
```

### 三步验证（任一失败即丢弃，原因计入统计）

| 步骤 | 动作 | 通过条件 |
|------|------|----------|
| Step 1 | 用目标自己的 SNI 握手，读 DER 证书 | 证书 **SAN** 覆盖该 SNI（`*.apple.com` 只匹配一级；CN 仅在无 SAN 时回退） |
| Step 2 | 换 `--cf-domain` 再握手 + 发 `GET /` | 响应含 `cf-ray` 或 `server: cloudflare` |
| Step 3 | 用 RFC 2606 保留域 `.invalid` 随机 SNI 再试 | **不能**再回 CF 头，否则判定为蜜罐 / 无差别反代 |

`--cf-domain` 只是探针标记，**不需要是你自己的域名**，任何托管在 Cloudflare 的域名都行
（实测哪怕灰云未代理的域名，只要在 CF zone 内，CF 边缘照样出证书）。

### （可选，自用场景）认证复核 `--verify-auth`

> 只有你想拿这套凭证「当用户连上去」时才需要这一步。
> 对「找可白嫖的第三方中转」这个主目标，`auth_failed` **不代表不能用** ——
> 反而说明机器活着、REALITY 在跑，正是最适合借道的目标。

前三步只能证明「未认证流量被透传到 CF」，证明不了三件事：是不是 REALITY、凭证还有没有效、节点是否活着。
`--verify-auth` 会调用本机真实内核跑一次完整 REALITY 握手（X25519 + HKDF + AES-GCM short-id），
失败原因按语义分类：

| `auth_error` | 含义 | 该怎么处理 |
|---|---|---|
| `""`（`usable: true`） | 真 REALITY，凭证有效，能用 | 直接用 |
| `auth_failed` | 真 REALITY，但 `uuid`/`pbk`/`short-id` 已失效 | 换新鲜订阅 |
| `not_reality` | 端口返回了**真实证书** → 根本不是 REALITY，只是 TLS 反代 | 丢弃（这是前三步无法识别的假阳性） |
| `timeout` | 连不上 / 无响应 | 节点已死 |
| `eof` / `refused` | 被对端关闭 / 拒绝 | 节点已死或封了你的 IP |
| `no_credentials` | 目标是裸 IP，没有 uuid/pbk 可复核 | 改用 `--links` |

内核自动探测，顺序：Clash Party / Mihomo Party 的 sidecar mihomo → PATH 里的 mihomo → xray；
也可用 `--core PATH` 显式指定。

> **能力边界**：不跑 `--verify-auth` 时，`confidence=high` 的含义仅为
> 「**确认可被当 CF 反代使用**」，不等于「确认是 REALITY、确认能用」。

---

### 保鲜与轮换监控（本项目推荐的工作模式）

单次扫描的结果有保鲜期，别当快照用。持续复测：

```bash
# 每 10 分钟扫一轮，共 6 轮；每轮结束都刷新可用清单
reality-cf --ranges dmit.txt --ports 443 \
  --sni www.cloudflare.com --cf-domain www.cloudflare.com \
  --rounds 6 --recheck-interval 600 \
  --state relay_state.json --export live_relays.txt
```

产出：

- `live_relays.txt` —— 当前有效的 `ip:port:sni` 清单，边跑边刷新
- `relay_state.json` —— 每台的 `first_seen` / `last_seen` / `alive_rounds` / `dest_history`
- 控制台会列出「dest 发生过轮换」的机器 —— 它们通常会周期性把 dest 指回 CF，值得长期盯

`--active-rounds N` 可以只导出「连续 N 轮都成立」的稳定目标。

任何 CF 托管 zone 内的域名都能当 `--sni` 探针（不必是你自己的）。

---

## 2. 快速开始

### 安装

```bash
git clone https://github.com/xiki45/reality-cf.git && cd reality-cf
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# 之后可以直接用 wrapper
.venv/bin/python main.py --help
```

要求 **Python 3.10+**（代码用了 `X | None` 注解与 `argparse.BooleanOptionalAction`）。

### 四种目标来源（可任意组合）

```bash
# A0) 订阅分享链接 —— 首选：一条链接就带 host/port/SNI/uuid/pbk/sid，不盲扫
reality-cf --links sub.txt --cf-domain probe.example.com

# A) 自备 IP 清单 —— 不依赖任何第三方 API；三列格式可指定每行的 SNI
cat > nodes.txt <<'EOF'
1.2.3.4:443:images.apple.com
[2001:db8::1]:8443:www.cloudflare.com
5.6.7.8:8443
EOF
cat > ips.txt <<'EOF'
1.2.3.4
5.6.7.8:8443
# 注释行会被跳过
EOF
python3 main.py --sni images.apple.com --targets ips.txt --cf-domain my.domain.com

# B) TLS 账本目录 —— 放 *.json(.gz)，每条含 ip / port / server_name
python3 main.py --sni images.apple.com --ledger ./scans --cf-domain my.domain.com

# C) CT 日志 —— 只能枚举域名（不含 IP），单独用它扫不到第三方中转节点
python3 main.py --sni images.apple.com --cf-domain my.domain.com --no-ledger

# 交互菜单
python3 main.py
```

### 自动下载 TLS 账本（可选）

Rapid7 Sonar 现在的接口需要 API Key，且数据集动辄数 GB：

```bash
export SONAR_API_KEY=xxxxxxxx     # https://opendata.rapid7.com/apihelp/ 申请
python3 main.py --sni images.apple.com --auto-ledger --ledger-limit 1 --cf-domain my.domain.com
```

没有 key 时工具会明确提示并跳过该阶段，不会静默失败。

---

## 3. 参数

| 参数 | 说明 |
|------|------|
| `--sni` | 目标大厂 SNI，如 `images.apple.com` |
| `--sni-list FILE` | SNI 列表文件（一行一个），可重复 |
| `--cf-domain` | Step 2 用的 CF 域名，默认 `speed.cloudflare.com` |
| `--targets FILE` | 自备目标清单（`host` / `host:port` / `host:port:sni`），可重复 |
| `--ledger DIR` | TLS 账本目录 |
| `--ledger-cache DIR` | 账本缓存目录，默认 `./scans` |
| `--auto-ledger` / `--no-auto-ledger` | 是否自动下载账本（需 `SONAR_API_KEY`），默认关 |
| `--ledger-limit N` | 只下最新 N 个账本文件，默认 1 |
| `--assume-port N` | 账本里没有端口信息时假定的端口 |
| `--no-ct` | 跳过 CT 日志阶段 |
| `--no-ledger` | 跳过账本阶段 |
| `--ports` | 端口嗅探列表，默认 `443,8443,2053,2083,2087,2096` |
| `--concurrency` | 验证并发，默认 500（实测单机 ~15k target/s 上限在 500 并发附近） |
| `--timeout` | 单次握手超时秒，默认 3.0 |
| `--ct-retries` | crt.sh 重试次数，默认 3（指数退避，失败自动回退 certspotter） |
| `--output` | 输出文件，默认 `vuln_reality_cf_report.json` |
| `--format` | `json`（数组）或 `jsonl`（逐行，边跑边可读） |
| `--no-redundancy` | 关闭反蜜罐（不建议；只在你确认数据源干净时用） |

### 附录：自用节点参数（默认关闭，与借道无关）

这一组只服务「把节点当客户端登录」这个场景 —— 需要 REALITY 凭证仍然有效。
**对寻找可借道的中转没有任何帮助**：命中判据只看 TLS 层，不看能不能登录。

| 参数 | 说明 |
|---|---|
| `--links FILE` | `vless://` 链接文件（自带每节点 SNI 与凭证），可重复 |
| `--verify-auth` | 对命中节点用本机内核跑 REALITY 握手，判定凭证还能不能登录 |
| `--core PATH` | 客户端内核路径（默认自动探测 Clash Party / Mihomo Party / mihomo / xray） |
| `--auth-timeout N` | 认证复核单节点超时秒，默认 9.0 |
| `--auth-concurrency N` | 认证复核并发（每个并发起一个内核进程），默认 4 |
| `--min-usable N` | 凑够 N 个认证可用就提前结束（0 = 不限） |
| `--auth-cache FILE` | 认证结果缓存文件（默认 `auth_cache.json`，传空串关闭） |
| `--auth-cache-ttl N` | 缓存有效期秒（默认 6 小时，0 = 永不过期） |

---

## 4. 输出

```json
[
{
  "ip": "45.67.89.123",
  "port": 8443,
  "target_sni": "images.apple.com",
  "common_name": "images.apple.com",
  "matched_by": "SAN",
  "status": "AVAILABLE",
  "confidence": "high",
  "evidence": {
    "cf_domain": "my.domain.com",
    "http_status": "HTTP/1.1 200 OK",
    "cf_ray": "8f2c1a3b9d4e5f6g-HKG",
    "server": "cloudflare",
    "tls_version": "TLSv1.3",
    "cipher": "TLS_AES_256_GCM_SHA384",
    "alpn": null
  },
  "geo": {"country": "US", "city": "New York"},
  "timestamp": "2026-10-22T02:00:00"
}
]
```

结束时打印各阶段丢弃原因，0 命中时能直接定位是「证书不匹配」还是「没有 CF 特征头」：

```
──────── 验证统计 ────────
  目标总数        5
  命中            1
  连接/握手失败   1
  无证书          0
  证书不匹配 SNI  1
  Step2 握手失败  0
  无 CF 特征头    1
  判定为蜜罐      1
──────────────────────────
```

---

## 5. 自测

```bash
python3 tests/t_unit.py    # 31 项：主机名匹配 / 证书匹配 / 头解析 / 账本端口推断 / 落盘
python3 tests/t_e2e.py     # 21 项：六种 mock 节点场景 + 流式时序 + 统计计数
python3 tests/t_cli.py     # 17 项：真实命令行全链路（含 --cf-domain / jsonl / 统计）
```

mock 服务覆盖六种节点行为：正确节点、蜜罐、普通 TLS、非 CF 后端、证书不符、黑洞。
`cf_sni_filtered` 场景用服务端 `sni_callback` 模拟 SNI 白名单，是「应该命中」的正样本。

---

## 6. 常见问题

**Q: 为什么 Step 1 用 SAN 而不是 CN？**
A: 真实证书的 CN 经常和 SNI 不一致 —— `images.apple.com` 的 CN 是 `www.apple.com`，
`swdist.apple.com` 的 CN 是 `swcdn.apple.com`。按 CN 匹配会把它们全部误判为「不是该大厂的中继」。

**Q: 为什么 Step 1、Step 2 不能用同一个连接？**
A: SNI 只在握手时协商，一个连接换不了 SNI，必须新建 TCP 连接。

**Q: 证书怎么取？**
A: `writer.get_extra_info("ssl_object").getpeercert(binary_form=True)`。
走 `get_extra_info("peercert")` 拿到的是 dict 形态，`CERT_NONE` 下恒为 `{}`。

**Q: 没装 GeoIP 数据库？**
A: Geo 字段留空，不影响判定。装 `geoip2` 并把 `GeoLite2-City.mmdb` / `GeoLite2-ASN.mmdb`
放到 `/usr/share/GeoIP/`（或用 `GEOIP_DB` / `GEOIP_ASN_DB` 指定路径）即可。

**Q: 账本文件很大怎么办？**
A: 流式读取 + 线程池，内存占用与文件大小无关；实际耗时取决于磁盘与 gzip 解压速度。
`--assume-port` 用于账本记录里没有端口字段的情况。

**Q: 结果里 `confidence=medium` 是什么？**
A: 有 `server: cloudflare` 但没有 `cf-ray`。仍可作为 CF 反代使用，但证据弱一些。

---

## 7. 免责

本工具用于**自己的节点配置审计**与安全研究：检查你部署的 REALITY 节点是否因为
`target` 指向 CDN 后方而变成公共端口转发器。把别人的节点当代理用属于滥用他人资源，
由此产生的一切后果由使用者承担。
