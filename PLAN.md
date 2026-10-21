# REALITY-CF 架构与路线图（v2）

## 目标

找出「target 落在 Cloudflare 后面、且把失败认证流量原样转发」的 REALITY 节点。
Xray 官方文档对该风险有明确描述：这类服务器实际上沦为 CF 的端口转发器，可被扫描滥用。

## 模块职责

```
main.py        编排：参数 → 收集 → 验证 → 输出 → 统计
  ├ fetcher.py     Phase 1  资产收集
  │   ├ fetch_ct_logs()        CT 日志（crt.sh + certspotter 兜底）→ DNS → 端口嗅探
  │   ├ fetch_tls_ledger()     账本流式过滤（线程池，端口四路推断）
  │   └ parse_targets_file()   自备清单（无外网依赖）
  ├ verifier.py    Phase 2/3 双重 TLS 验证
  │   ├ _tls_probe()           open_connection(ssl=...) + ssl_object 取 DER
  │   ├ cert_match()           SAN 优先 + RFC 6125 通配 + CN 回退
  │   ├ verify_single()        Step1 身份 / Step2 CF 特征 / Step3 反蜜罐
  │   └ verify_batch()         固定 worker + 有界队列，真流式
  ├ reporter.py    输出 + GeoIP + 统计展示（原子落盘、json/jsonl）
  └ ledger_dl.py   Sonar 账本下载（X-API-Key、sonarfile_set、manifest）
```

## 关键不变量（改动时别破坏）

1. **握手必须走 `asyncio.open_connection(ssl=ctx, server_hostname=sni)`**。
   `loop.start_tls(...)` 的参数是 `protocol`（不是 `protocol_factory`），且要传 Protocol 对象；
   `StreamWriter.start_tls()` 也返回 `None`，拿不到 SSL 对象。
2. **DER 证书只从 `get_extra_info("ssl_object").getpeercert(binary_form=True)` 取**。
   `get_extra_info("peercert")` 在 `CERT_NONE` 下恒为 `{}`。
3. **主机名匹配看 SAN，不看 CN**。真实证书 CN 与 SNI 经常不一致。
4. **SSLContext 进程级复用**，禁止在热路径里 `create_default_context()`（~5ms/次且阻塞事件循环）。
5. **两段握手必须各自新建连接**（SNI 在握手时固定）。
6. **反蜜罐探针只用保留域**（`.invalid`），避免随机域名撞上真实 CF 站点。
7. **任何阶段 0 结果都不能 `sys.exit(1)`**：要给出可操作的下一步。

## 已完成

- [x] 修掉 v1 的 5 个 P0 缺陷（握手 / DER / CN / `--cf-domain` / `--ledger` 覆盖）
- [x] 数据源降级策略：CT → certspotter → 账本 → 自备清单，任一路可用即可跑
- [x] 账本端口四路推断（记录字段 > 文件名 > manifest > `--assume-port`）
- [x] 吞吐从 200 target/s 提到 ~15k target/s（44 倍）
- [x] 真流式输出 + 原子落盘 + 各阶段丢弃原因统计
- [x] 69 项自动化测试（单元 31 / 端到端 21 / CLI 17），全部离线可复现

## 待办

- [ ] 账本 schema 适配层：对 Sonar certs 的嵌套结构做字段映射表（当前靠原始行子串匹配）
- [ ] `--resume`：大目标集中断后续跑（已完成的目标落盘去重）
- [ ] 结果复核：对命中节点做一次 `xray tls ping` 或 inner-protocol 探针，把「确认是 REALITY」与「只是 CF 反代」分开
- [ ] 输出 ASN 维度聚合（同一机房批量命中时便于判断是否同一运营者）
- [ ] CT 日志路径的替代设计：CT 只给域名，第三方 IP 发现要么靠账本，要么接商业测绘 API

## 相关文档

- `README.md`        使用说明与原理
- `../REALITY-CF-可行性检验报告.md`  v1 的可行性检验与证据
- `../修复说明.md`   本次修复的变更清单与验证结果
