# Phase 2 核心验证器 — 参考代码

## 关键防坑点
1. verify_mode=CERT_NONE 时必须用 `get_extra_info('peercert', binary_form=True)` 获取 DER 二进制证书
2. 不能用 `getpeercert()` 的 dict 格式 —— 那会丢扩展字段
3. 双握手必须新建连接，不能复用
4. CN 匹配用 `target_sni in common_name` 而非精确相等（支持 *.apple.com 通配符）
5. 反蜜罐机制：随机混淆 SNI 验证，若仍回 CF 头则丢弃

## 异步架构
- asyncio + Semaphore 控制并发
- 单 IP 超时 3s，两步串行
- 任一步失败立即 return None
