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
  客户端 --SNI=你的CF域名--> 节点 --原样转发--> 苹果源站
                                              └─ 不认这个 SNI，握手失败 → 你什么也拿不到

target 在 CF 后面的节点 (target = 某个 CF 站点)
  客户端 --SNI=你的CF域名--> 节点 --原样转发--> CF 边缘 --认这个SNI--> 你的站点，带 cf-ray
                                              └─ 这台节点就成了 CF 的端口转发器
```

所以本工具测的不是「SNI 白名单没配」，而是「**节点的 target 位于 Cloudflare**」。
满足这一条的节点，任何人都能借它当 CF 反代用。

### 三步验证（任一失败即丢弃，原因计入统计）

| 步骤 | 动作 | 通过条件 |
|------|------|----------|
| Step 1 | 用大厂 SNI 握手，读 DER 证书 | 证书 **SAN** 覆盖该 SNI（`*.apple.com` 只匹配一级；CN 仅在无 SAN 时回退） |
| Step 2 | 换 `--cf-domain` 再握手 + 发 `GET /` | 响应含 `cf-ray` 或 `server: cloudflare` |
| Step 3 | 用 RFC 2606 保留域 `.invalid` 随机 SNI 再试 | **不能**再回 CF 头，否则判定为蜜罐 / 无差别反代 |

> **能力边界（务必知道）**：纯 TLS 层无法区分「REALITY 节点」和「普通 SNI 代理 / 端口转发」——
> REALITY 对未认证连接就是透传，客户端看到的是 target 的真证书。
> 因此输出里的 `confidence=high` 含义是「**确认可被当 CF 反代使用**」，不是「确认是 REALITY」。
> 要 100% 确认协议身份，需在节点上跑 `xray tls ping` 或对 inner protocol 做探测。

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

### 三种目标来源（可任意组合）

```bash
# A) 自备 IP 清单 —— 最可靠，不依赖任何第三方 API
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
| `--targets FILE` | 自备目标清单（`ip` 或 `ip:port`），可重复 |
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
