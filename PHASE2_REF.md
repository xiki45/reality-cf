# Phase 2 实现备忘

v1 的这份参考代码已被合并进 `verifier.py`，此处只保留「踩过的坑」，避免后来者再踩。

## 三个必踩的坑（都实测过）

### 1. `loop.start_tls()` 的两个误区

```python
# ✗ 参数名不是 protocol_factory
await loop.start_tls(transport, protocol_factory=None, sslcontext=ctx, server_hostname=sni)
# TypeError: BaseEventLoop.start_tls() got an unexpected keyword argument 'protocol_factory'

# ✗ 位置参数传 None 也不行：握手"成功"但 _app_protocol=None，
#   后续 connection_lost 直接 AttributeError；数据也无法收发
await loop.start_tls(transport, None, ctx, server_hostname=sni)

# ✓ 用 Streams API，一步到位
reader, writer = await asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni)
```

`StreamWriter.start_tls()`（3.11+）虽然存在，但**返回 None**，拿不到 SSL 对象，别指望它。

### 2. `get_extra_info("peercert")` 拿不到 DER

`asyncio/sslproto.py::SSLProtocol._on_handshake_complete` 里写的是

```python
peercert = sslobj.getpeercert()      # 没有 binary_form
self._extra.update(peercert=peercert, ...)
```

`CERT_NONE` 下该调用返回 `{}`。`get_extra_info("peercert", binary_form=True)` 里的
`binary_form=True` 只是被当成 `default` 位置参数，不起作用。

```python
der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)   # ✓
```

### 3. CN 不等于 SNI

| SNI | 真实 CN |
|-----|---------|
| images.apple.com | www.apple.com |
| swdist.apple.com | swcdn.apple.com |
| download.microsoft.com | akamai.download.microsoft.com |

用 `sni in CN` 会把前两个直接判死。正确做法是解析 SAN，并按 RFC 6125 处理通配符
（`*.apple.com` 只匹配一级，不匹配裸域）。

## 性能红线

- `ssl.create_default_context()` ≈ **4.97 ms/次**，且是同步调用会阻塞事件循环。
  v1 每目标调 2~3 次 → 吞吐被压到 200 target/s。改成模块级复用后 ≈ 15k target/s。
- 单目标超时 3s、并发 500 是本机的吞吐拐点；并发拉到 2000 反而掉到 ~6.7k/s（本地 socket 过载）。

## 判定顺序（不要调换）

1. 证书 SAN 命中 target_sni → 否则这不是「该大厂的中继」，直接丢
2. 换 `--cf-domain` 再握手，能通且回 CF 特征头 → 否则 target 不在 CF 后面
3. 保留域随机 SNI 再试，**不能**回 CF 头 → 否则是蜜罐 / 无差别反代

顺序不能乱：先做 3 会给不存在的候选白跑一次握手；先做 2 而不做 1 会把
「任何非 CF 站点」当成命中。
