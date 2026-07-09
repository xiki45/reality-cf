# REALITY-CF 漏洞精准抓取工具 — 完整开发计划

## 项目概述
不盲扫、不依赖商业测绘、支持全端口精准抓取。
基于 CT 日志 + TLS 历史账本，以 REALITY 大厂 SNI 为 Key 逆向提取全球 IP:PORT，
通过 CF TLS 交叉握手特征精准筛选存在配置漏洞的 REALITY 节点。

---

## Phase 1: 资产收集 (Asset Fetcher)

### A: CT 日志 + DNS (在线实时)
- crt.sh: https://crt.sh/?q=目标SNI&output=json
- 异步 DNS (aiodns / net.LookupHost)
- 伴随端口嗅探: [443, 8443, 2053, 2083, 2096, 2443]
- TCP 三次握手成功 → IP:PORT → 验证队列

### B: TLS 历史账本 (离线批量)
- Project Sonar / scans.io 的 .json.gz 数据集
- 流式读取，支持多端口账本
- 过滤: server_name 或 CN 匹配目标 SNI → IP:PORT → 队列

---

## Phase 2: 双重 TLS 交叉验证

高并发异步 (asyncio + Semaphore)，任一步失败即丢弃。

### Step 1: REALITY 身份实锤
- TCP 连接 → TLS 握手 server_hostname=大厂SNI
- check_hostname=False, verify_mode=CERT_NONE
- 获取 DER 二进制证书（binary_form=True）
- 解析 CN，匹配大厂 → 确认 REALITY

### Step 2: CF 反代漏洞判定
- 重新 TCP 连接
- TLS 握手 server_hostname=用户CF域名
- 发送 GET / HTTP/1.1 Host:用户CF域名
- 检查响应头: server:cloudflare / cf-ray → 确认漏洞

---

## Phase 3: 蜜罐过滤 + 结构化输出

### 反制: 蜜罐过滤
- 随机混淆 SNI (x7y8z9w1.org) 再次握手
- 若仍返回 server:cloudflare → 蜜罐，丢弃

### 富化
- GeoIP (MaxMind) → 国家/ASN/机房

### 输出
- 终端实时打印 + 流式写入 vuln_reality_cf_report.json/.txt

---

## 防坑准则
1. 文件描述符: resource.setrlimit(RLIMIT_NOFILE, (65535, 65535))
2. 依赖: cryptography, aiodns, colorama
3. 超时: asyncio.wait_for 包裹所有 I/O，2.5-4.0s
4. 证书: binary_form=True 取 DER，不用 dict 格式
5. 双握必须新建连接
6. CN 用 in 匹配（支持通配符）
