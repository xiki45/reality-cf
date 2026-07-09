# REALITY-CF 节点发现工具

## 这是什么

REALITY 协议虽然加密了 SNI，但 Xray-core 的 REALITY 配置中有一个常见配置特性：
`serverNames` 设为空数组 `[]`。这意味着服务端**没有限制允许的 SNI**，
任何 TLS 握手只要证书对得上，它都接受。

这就出现一个配置特性：你用苹果的证书做 REALITY，正常只应该苹果的 SNI 能通。
但其他人用**自己控制的 Cloudflare 域名**去握手，REALITY 服务端一样会透传给
目标服务器。因为目标服务器配了 CF CDN，它回了一个 `cf-ray` 头 ——
等于这个节点被"复用"，别人也能当 CF 反代用。

这个工具就是自动化发现这些节点的。

## 核心原理

```
正常 REALITY 节点:
  客户端 → [SNI=apple.com] → REALITY服务端 → 苹果服务器

配置特性 REALITY 节点:
  客户端 → [SNI=你的CF域名] → REALITY服务端 → Cloudflare → 返回 cf-ray
                                                    ↑
                                          这里不该通的！serverNames 没限制
```

## 为什么不盲扫

传统 CF 优选工具的做法是：拿几十万个 CIDR，masscan 扫 443，再逐个试。
问题：
- 全球 IPv4 扫完要几十小时
- 99.9% 的 IP 根本没有开 TLS，白白扫了
- 商业测绘 API 要钱

这个工具的做法是：
1. 从 **CT 日志**（crt.sh）查出哪些 IP 部署了指定大厂的证书
2. 从 **TLS 历史账本**（Rapid7 Project Sonar）捞出所有见过该 SNI 的 IP
3. 只在**已知有 TLS 服务**的 IP 上做验证

## 功能详解

### Phase 1A: CT 日志抓取

**做什么**：你给一个 SNI（如 `images.apple.com`），工具自动调用 crt.sh 的公开 API，
拉出该域名下所有子域名。每个子域名意味着有人申请过包含该域名的 SSL 证书。

**为什么有用**：REALITY 节点必须使用大厂的真实证书。这些证书在 crt.sh 有公开记录。
如果你看到一个陌生的 IP 拿着 `images.apple.com` 的证书，那它大概率是 REALITY 节点。

**DNS 解析**：拉出来的子域名（可能有几千个），用异步 DNS 批量解析成 IPv4。

**端口嗅探**：因为 crt.sh 只记录域名和 IP 的关系，不记录端口。REALITY 节点
不一定用 443——很多人用 8443、2053、2083 绕封锁。所以对每个 IP 额外做一次
轻量 TCP 三次握手探测，只测 CF 支持的 HTTPS 端口：

```
默认端口: 443, 8443, 2053, 2083, 2096, 2443
```

TCP 三次握手成功的 IP:PORT 进入验证队列。这个开销很小（只建连不发数据），
200 并发下秒级完成。

### Phase 1B: TLS 历史账本

**做什么**：Rapid7 的 Project Sonar 每两周扫一次全球 IPv4 的 TLS 握手，
记录下每台服务器返回的证书和 server_name。数据以 `port-443-tls.json.gz` 格式公开发布。

**比 CT 日志好在哪**：TLS 账本直接记录了 `server_name` 和 `ip:port` 的映射关系，
不需要 DNS 解析，不需要端口嗅探。而且有全端口数据——你可以同时加载
`port-443-tls.json.gz`、`port-8443-tls.json.gz`、`port-2053-tls.json.gz` 等。

**流式过滤**：这些文件动辄几 GB，不能全加载到内存。工具用 gzip 流式逐行读取，
只保留 `server_name` 匹配目标 SNI 的行，内存占用可控在几十 MB。

### Phase 2: 双重 TLS 交叉验证

这是整个工具的核心。队列中的每个 IP:PORT 都要过两道关，任何一道失败直接丢弃。

**Step 1 — REALITY 身份实锤**

用大厂 SNI（如 `images.apple.com`）向该 IP:PORT 发起 TLS 握手。关键配置：

```python
ctx.check_hostname = False   # 不验证证书域名（非官方 IP 拿不到正规证书）
ctx.verify_mode = ssl.CERT_NONE  # 不验证证书链
```

握手成功后，提取服务器返回的**二进制证书**（必须用 `binary_form=True` 拿 DER 格式，
不能用 `getpeercert()` 的字典格式——那个会丢失扩展字段）。

解析证书的 Common Name (CN)。如果 CN 确实包含目标大厂的域名，说明该端口
100% 部署了以该大厂为伪装对象的 REALITY 服务。

**Step 2 — CF 反代配置特性判定**

换一个 SNI——这次用你自己的 Cloudflare 域名（必须开了 CDN 小黄云）。
重新建连（不能复用 Step 1 的连接），再次 TLS 握手，然后发一个极简 HTTP 请求：

```http
GET / HTTP/1.1
Host: your-cf-domain.com
Connection: close
```

如果服务器响应头里出现了 `server: cloudflare` 或 `cf-ray:`，说明：
1. REALITY 服务端接受了这个非预设的 SNI（`serverNames` 没限制）
2. 流量被透传到了 Cloudflare（因为你域名开了 CDN）
3. Cloudflare 正常回包并打了 `cf-ray` 标记

→ 确认配置特性。

### Phase 3: 冗余检测 + 输出

**蜜罐检测**：安全厂商可能部署假节点来钓鱼。识别方法是——用一个随机垃圾域名
（如 `x7y8z9w1.org`）再次握手。正常的 REALITY 节点只有少数大厂证书，遇到
不认识的 SNI 会中断连接。而蜜罐对任何 SNI 都回 `server: cloudflare`。

**GeoIP 富化**：如果安装了 MaxMind GeoLite2 免费数据库，工具会自动给每个发现的
节点标记国家和城市。数据库放 `/usr/share/GeoIP/GeoLite2-City.mmdb`。

**输出**：
- 终端实时彩色打印（绿色 = 发现配置特性节点）
- 流式写入 JSON 文件（不用等全部跑完，边发现边写）

## 参数说明

| 参数 | 说明 |
|------|------|
| `--sni` | 单个目标 SNI。例如 `images.apple.com`。crt.sh 会拉出此域名下所有子域 |
| `--sni-list` | 多个 SNI 的列表文件，一行一个。和 `--sni` 可同时用 |
| `--cf-domain` | 你自己的 CF 域名。必须开启 CDN 小黄云。用于 Step 2 验证 |
| `--ledger` | TLS 账本目录。里面放 `port-443-tls.json.gz` 等文件。工具自动按端口匹配 |
| `--ports` | 伴随嗅探的端口列表。Phase 1A 用。默认 6 个 CF 常用端口 |
| `--concurrency` | 验证并发数。默认 500，VPS 配置好可以开 2000。受 ulimit 保护 |
| `--timeout` | 单次握手超时秒数。默认 3.0。网络差可调大到 5.0 |
| `--output` | 输出文件路径。默认 `vuln_reality_cf_report.json` |
| `--no-redundancy` | 关闭蜜罐检测。不推荐，除非你确定数据源干净 |

## 运行示例

```bash
# 最简用法：一个 SNI，你的 CF 域名
python3 main.py --sni images.apple.com --cf-domain my-cdn.899920.xyz

# 多 SNI 批量
python3 main.py --sni-list ./snis.txt --cf-domain my-cdn.899920.xyz

# 高并发 VPS 全速跑
python3 main.py --sni images.apple.com --cf-domain my-cdn.899920.xyz \
    --concurrency 2000 --timeout 2.5

# 配合 TLS 账本（最全覆盖）
python3 main.py --sni swdist.apple.com --cf-domain my-cdn.899920.xyz \
    --ledger /data/sonar-scans/

# 输出到指定文件
python3 main.py --sni images.apple.com --cf-domain my-cdn.899920.xyz \
    --output apple_nodes.json
```

## 输出格式

```
终端:
  ✅ 45.67.89.123:8443  images.apple.com  [US] 
  ✅ 142.248.139.188:443 images.apple.com  [JP] SoftBank

JSON:
[
  {
    "ip": "45.67.89.123",
    "port": 8443,
    "target_sni": "images.apple.com",
    "common_name": "images.apple.com",
    "status": "AVAILABLE",
    "geo": {"country": "US", "city": "New York", "asn": ""},
    "timestamp": "2026-07-08T22:00:00"
  }
]
```

## 系统要求

- Python 3.10+
- Linux 自动 `ulimit -n 65535`
- 不依赖 masscan、nmap
- 不需要 API Key

## 推荐 SNI

大厂的 CDN 域名，证书覆盖广、节点多：

```
images.apple.com
swdist.apple.com
swcdn.apple.com
updates.cdn-apple.com
download.microsoft.com
```

## 常见问题

**Q: 为什么 Step 1 和 Step 2 不能复用同一个 TLS 连接？**
A: TLS 握手时 SNI 已经确定，同一个连接不能换 SNI 再握一次。必须新建 TCP 连接。

**Q: 为什么证书解析必须用 binary_form？**
A: Python 的 `getpeercert()` 返回 dict，但 `verify_mode=CERT_NONE` 时 dict 可能为空或缺失字段。`binary_form=True` 直接拿 DER 二进制，用 `cryptography` 库解析最可靠。

**Q: 没装 GeoIP 数据库怎么办？**
A: 不影响运行，Geo 字段返回空。去 MaxMind 官网免费注册下载 GeoLite2-City.mmdb，放 `/usr/share/GeoIP/` 即可。

**Q: TLS 账本去哪下载？**
A: https://opendata.rapid7.com/sonar.ssl/ — 免费公开，每两周更新。
